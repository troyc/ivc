#include "libivc_core.h"

libivc_core::libivc_core() : mLog("libivc_core", LOGLEVEL) {
    struct sockaddr_un address;
    mSock = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if(mSock < 0) {
        throw std::system_error(errno, std::generic_category(), "Failed to create socket");
    }

    const char *path = "/tmp/ivc_control";

    memset(&address, 0x00, sizeof(address));
    address.sun_family = AF_UNIX;
    ::strncpy((char*)&address.sun_path, path, 107);

    int res = ::connect(mSock, (struct sockaddr *)&address, sizeof(address));
    if(res) {
        throw std::system_error(errno, std::generic_category(), "Failed to connect socket");
    }
    mMonitor = new std::thread(&libivc_core::monitorCommands, this);
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
                          grant_ref_t *grefs,
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

void
libivc_core::sendResponse(libivc_message_t *msg, MESSAGE_TYPE_T type, uint8_t status)
{
    // copy in the incoming message data to the response
    libivc_message_t respMsg;
    memcpy(&respMsg, msg, sizeof (libivc_message_t));
    respMsg.status = (uint8_t) status;
    respMsg.to_dom = msg->from_dom;
    respMsg.from_dom = (uint16_t) msg->to_dom;
    respMsg.type = type;

    write((void *)&respMsg, sizeof(respMsg));
}

void
libivc_core::handleConnectMessage(libivc_message_t *msg) {
    if(!msg)
        return;

    if(msg->to_dom != 0)
        return;

    uint32_t key = dom_port_key(msg->from_dom, msg->port);
    uint32_t anykey = dom_port_key(LIBIVC_DOMID_ANY, msg->port);

    // Have to provide a connected client here...
    if(mCallbackMap.contains(key)) {
        struct libivc_client *client = createClient(msg->from_dom,
                                                    msg->port,
                                                    msg->descriptor,
                                                    msg->num_grants,
                                                    msg->event_channel);
        if (client) {
            libivc_client_connected cb = (libivc_client_connected)mCallbackMap[key];
            sendResponse(msg, ACK, 0);
            cb(mCallbackArgumentMap[key], client);
            return;
        }
    }

    if(mCallbackMap.contains(anykey)) {
        struct libivc_client *client = createClient(msg->from_dom,
                                                    msg->port,
                                                    msg->descriptor,
                                                    msg->num_grants,
                                                    msg->event_channel);
        if (client) {
            libivc_client_connected cb = (libivc_client_connected)mCallbackMap[anykey];
            sendResponse(msg, ACK, 0);
            cb(mCallbackArgumentMap[anykey], client);
            return;
        }
    }

    sendResponse(msg, ACK, -ECONNREFUSED);

    LOG(mLog, INFO) << "Connect call with no listening servers\n";
}

void
libivc_core::handleDisconnectMessage(libivc_message_t *msg) {
    uint32_t key;

    key = dom_port_key(msg->from_dom, msg->port);
    if (mClients.contains(key)) {
        auto client = mClients[key]->client();

        if (client)
            destroyClient(client);
    }
}

void
libivc_core::monitorCommands()
{
    struct pollfd pfd = {};

    pfd.fd = mSock;
    pfd.events = POLLIN;
    while (poll(&pfd, 1, -1)) {
        libivc_message_t msg = {};

        if (pfd.revents & POLLIN) {
            this->read((char*)&msg, sizeof(msg));
            switch (msg.type) {
                case CONNECT: {
                    handleConnectMessage(&msg);
                    break;
                }
                case DISCONNECT: {
                    handleDisconnectMessage(&msg);
                    break;
                }
                case NOTIFY_ON_DEATH: {
                    for(auto &client : mClients) {
                        client->eventCallback();
                    }
                    break;
                }
                break;
            default:
                break;
            }
        }
    }
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

    return (struct libivc_server *)key;
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
        return (struct libivc_server *)key;
    }

    return nullptr;
}

void
libivc_core::read(char *msg, uint32_t size) {
    std::lock_guard<std::mutex> lock(mClientLock);
    ::read(mSock, msg, size);
}

void
libivc_core::write(void *buf, uint32_t size) {
    std::lock_guard<std::mutex> lock(mClientLock);
    ::write(mSock, (const char*)buf, size);
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
