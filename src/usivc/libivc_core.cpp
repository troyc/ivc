#include "libivc_core.h"

libivc_core::libivc_core() : mLog("libivc_core", LOGLEVEL) {
    mMonitor = new std::thread(&libivc_core::daemonMonitor, this);
}

libivc_core::~libivc_core() {
    ::close(mSock);
}

void
libivc_core::destroyClient(struct libivc_client *client) {
    uint32_t key = dom_port_key(client->remote_domid, client->port);
    mClients.remove(key);
}

struct libivc_client *
libivc_core::createClient(domid_t domid,
                          uint16_t port,
                          const grant_ref_t *grefs,
                          uint32_t num_grants,
                          evtchn_port_t evtport) {
    uint32_t key = dom_port_key(domid, port);
    try {
        std::lock_guard<std::mutex> lock(mClientLock);
        mClients[key] = std::make_shared<ivcClient>(domid,
                                                    port,
                                                    grefs,
                                                    num_grants,
                                                    evtport,
                                                    mEventController);
        return mClients[key]->client();
    } catch (std::exception &e) {
        LOG(mLog, ERROR) << "Failed to create new IVC Client: " << e.what();
    } catch (...) {
        LOG(mLog, ERROR) << "Failed to create new IVC Client: Unknown exception.";
    }

    return nullptr;
}

void
libivc_core::notifyRemote(struct libivc_client *client) {
    mEventController.notify(client->event_channel);
}

int
libivc_core::ivcRegisterCallbacks(struct libivc_client *client,
                                  libivc_client_event_fired eventCallback,
                                  libivc_client_disconnected disconnectCallback,
                                  void *opaque)
{
    if (!client || !client->context) {
        return -ENOENT;
    }

    ivcClient *c = (ivcClient *)client->context;
    c->setClientEventCallback(eventCallback);
    c->setClientDisconnectCallback(disconnectCallback);
    c->setClientData(opaque);

    return 0;
}

int
libivc_core::ivcRecv(struct libivc_client *client, char *dest, size_t destSize) {
    if (!client || !client->context) {
        return -ENOENT;
    }

    ivcClient *c = (ivcClient *)client->context;
    return c->recv(dest, destSize);
}

int
libivc_core::ivcSend(struct libivc_client *client, char *dest, size_t destSize) {
    if (!client || !client->context) {
        return -ENOENT;
    }

    ivcClient *c = (ivcClient *)client->context;
    int rc = c->send(dest, destSize);
    notifyRemote(client);
    return rc;
}

int
libivc_core::ivcAvailableData(struct libivc_client *client, size_t *dataSize) {
    if (!client || !client->context) {
        return -ENOENT;
    }

    ivcClient *c = (ivcClient *)client->context;
    *dataSize = c->availableData();
    return 0;
}

int
libivc_core::ivcAvailableSpace(struct libivc_client *client, size_t *dataSize) {
    if (!client || !client->context) {
        return -ENOENT;
    }

    ivcClient *c = (ivcClient *)client->context;
    *dataSize = c->availableSpace();
    return 0;
}

int
libivc_core::sendResponse(const libivc_message_t *msg, MESSAGE_TYPE_T type, uint16_t status)
{
    // copy in the incoming message data to the response
    libivc_message_t respMsg;
    memcpy(&respMsg, msg, sizeof (libivc_message_t));
    respMsg.status = status;
    respMsg.to_dom = msg->from_dom;
    respMsg.from_dom = msg->to_dom;
    respMsg.type = type;

    return this->daemonSend(&respMsg, sizeof (respMsg));
}

int
libivc_core::handleConnectMessage(const libivc_message_t *msg)
{
    if(!msg || (msg->to_dom != 0))
        return -EINVAL;

    uint32_t key = dom_port_key(msg->from_dom, msg->port);
    uint32_t anykey = dom_port_key(LIBIVC_DOMID_ANY, msg->port);
    int rc;

    // Have to provide a connected client here...
    if (mCallbackMap.contains(key)) {
        struct libivc_client *client = createClient(msg->from_dom,
                                                    msg->port,
                                                    msg->descriptor,
                                                    msg->num_grants,
                                                    msg->event_channel);
        if (client) {
            libivc_client_connected cb = (libivc_client_connected)mCallbackMap[key];
            rc = sendResponse(msg, ACK, 0);
            cb(mCallbackArgumentMap[key], client);
            return rc;
        }
        LOG(mLog, INFO) << "Failed to create client for dom" << msg->from_dom << ":" << msg->port;
    } else if (mCallbackMap.contains(anykey)) {
        struct libivc_client *client = createClient(msg->from_dom,
                                                    msg->port,
                                                    msg->descriptor,
                                                    msg->num_grants,
                                                    msg->event_channel);
        if (client) {
            libivc_client_connected cb = (libivc_client_connected)mCallbackMap[anykey];
            rc = sendResponse(msg, ACK, 0);
            cb(mCallbackArgumentMap[anykey], client);
            return rc;
        }
        LOG(mLog, INFO) << "Failed to create client for dom" << msg->from_dom << ":" << msg->port;
    } else {
        LOG(mLog, INFO) << "Connect call with no listening servers";
    }

    return sendResponse(msg, ACK, -ECONNREFUSED);
}

void
libivc_core::handleDisconnectMessage(const libivc_message_t *msg) {
    uint32_t key;

    key = dom_port_key(msg->from_dom, msg->port);
    if (mClients.contains(key)) {
        auto client = mClients[key]->client();

        if (client)
            destroyClient(client);
    }
}

void
libivc_core::daemonDisconnect()
{
    int rc;

    if (mSock < 0)
        return;

    do {
        rc = ::close(mSock);
        if (rc < 0 && errno == EINTR)
            // Retry on EINTR only.
            // Other errors are not recoverable.
            continue;
        break;
    } while (1);

    mSock = -1;
}

int
libivc_core::daemonConnect(const char *path)
{
    struct sockaddr_un un = {
        .sun_family = AF_UNIX,
        {}
    };
    int rc = 0;

    this->daemonDisconnect();

    mSock = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (mSock < 0)
        return -errno;

    ::strncpy(reinterpret_cast<char*>(&un.sun_path), path, sizeof (un.sun_path) - 1);
    if (::connect(mSock, reinterpret_cast<struct sockaddr *>(&un), sizeof (un)) < 0) {
        rc = -errno;
        this->daemonDisconnect();
    }

    return rc;
}

int libivc_core::daemonPoll()
{
    struct pollfd pfd = {
        .fd = mSock,
        .events = POLLIN,
        {}
    };
    int rc;

    rc = poll(&pfd, 1, -1);
    if (rc < 0)
        return -errno;
    if (rc == 0)
        return 0;
    if (pfd.revents != POLLIN)
        return -EIO;

    return rc;
}

ssize_t libivc_core::daemonRecv(void *msg, size_t size)
{
    std::lock_guard<std::mutex> lock(mClientLock);
    ssize_t rc;

    rc = ::recv(mSock, msg, size, 0);
    if (rc < 0)
        return -errno;
    if (rc == 0)
        return 0;
    if (rc != static_cast<ssize_t>(size))
        return -EIO;

    return rc;
}

ssize_t libivc_core::daemonSend(const void *msg, size_t size)
{
    std::lock_guard<std::mutex> lock(mClientLock);
    ssize_t rc;

    rc = ::send(mSock, msg, size, MSG_NOSIGNAL);
    if (rc < 0)
        return -errno;
    if (rc == 0)
        return 0;
    if (rc != static_cast<ssize_t>(size))
        return -EIO;

    return rc;
}

int libivc_core::daemonProcessMessage(const libivc_message_t *msg)
{
    switch (msg->type) {
    case CONNECT:
        return handleConnectMessage(msg);
    case DISCONNECT:
        handleDisconnectMessage(msg);
        return 0;
    case NOTIFY_ON_DEATH:
        for (auto &client : mClients)
            client->eventCallback();
        return 0;
    default:
        LOG(mLog, ERROR) << "Invalid message received from ivcDaemon (" << msg->type << ").";
        break;
    }

    return -EINVAL;
}

void
libivc_core::daemonMonitor()
{
    int rc;
    std::chrono::seconds timeout(2);

    do {
        rc = this->daemonConnect("/tmp/ivc_control");
        if (rc) {
            // ivcDaemon unavailable, retry.
            LOG(mLog, WARNING) << "Failed to connect to ivcDaemon(" << -rc << "). Retry in 2 seconds.";
            std::this_thread::sleep_for(timeout);
            continue;
        }

        do {
            libivc_message_t msg = {};

            rc = this->daemonRecv(&msg, sizeof (msg));
            if (rc <= 0) {
                // Error, incomplete msg, other-end closed.
                LOG(mLog, WARNING) << "Protocol corruption with ivcDaemon (" << -rc << "). Reset connection.";
                break;
            }

            rc = this->daemonProcessMessage(&msg);
            if (rc < 0) {
                // Error, other-end closed, connection reset...
                LOG(mLog, WARNING) << "Failed to send reply to ivcDaemon (" << -rc << "). Reset connection.";
                break;
            }
        } while (1);
    } while (1);
}

struct libivc_server *
libivc_core::registerServer(uint16_t port,
                            uint16_t domid,
                            uint64_t client_id,
                            libivc_client_connected cb,
                            void *opaque) {
    std::lock_guard<std::mutex> lock(mServerLock);

    uint32_t key = dom_port_key(domid, port);
    LOG(mLog, DEBUG) << "Domid: " << domid << "\nPort: " << port << "\nClient id: " << client_id << "\nKey: " << key << "\ncb: " <<  (void*)cb << "\nopaque: " << opaque;
    mCallbackMap[key] = (void *)cb;
    mCallbackArgumentMap[key] = opaque;

    return (struct libivc_server *)(uintptr_t)key;
}

void
libivc_core::shutdownServer(struct libivc_server *server) {
    std::lock_guard<std::mutex> lock(mServerLock);
    uint32_t key = (uint32_t)(((uintptr_t)server) & 0x00000000FFFFFFFFF);
    mCallbackMap[key] = nullptr;
    mCallbackArgumentMap[key] = nullptr;
}

struct libivc_server *
libivc_core::findServer(domid_t domid, uint16_t port) {
    uint32_t key = dom_port_key(domid, port);
    if(mCallbackMap[key]) {
        return (struct libivc_server *)(uintptr_t)key;
    }

    return nullptr;
}

uint32_t
libivc_core::dom_port_key(uint16_t domid, uint16_t port) {
    uint32_t key = ((((uint32_t)domid << 16) & 0xFFFF0000) | ((uint32_t)port & 0x0000FFFF));
    return key;
}

/*
 * Local variables:
 * mode: C++
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
