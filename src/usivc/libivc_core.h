#ifndef LIBIVC_CORE__H
#define LIBIVC_CORE__H

#include <QMap>
#include <QDebug>

#include <thread>
#include <iostream>
#include <memory>
#include <mutex>
#include <system_error>
#include <functional>

#include <xen/be/Log.hpp>
#include <xen/be/XenStore.hpp>
#include <xen/be/XenGnttab.hpp>
#include <xen/be/XenEvtchn.hpp>

extern "C" {
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <poll.h>
#include "libivc.h"
};

#include "ringbuf.h"

#define TRACE do { DLOG(mLog, DEBUG) << " --- [ " << __PRETTY_FUNCTION__ << ":" << __LINE__ << " ] ---"; } while(0)
//#define TRACE 
#define LOGLEVEL XenBackend::LogLevel::logDEBUG

static inline void dump_message(libivc_message_t *msg)
{
    std::cout << __PRETTY_FUNCTION__ << __LINE__ << '\n';
    std::cout << "Message type: ";
    switch(msg->type) {
    case CONNECT:
    {
        std::cout << "CONNECT\n";
        break;
    }
    case DISCONNECT:
    {
        std::cout << "DISCONNECT\n";
        break;
    }
    case NOTIFY_ON_DEATH:
    {
        std::cout << "NOTIFY_ON_DEATH\n";
        break;
    }
    case ACK:
    {
        std::cout << "ACK\n";
        break;
    }
    default:
    {
        std::cout << "INVALID\n";
        break;
    }
    }
  
    std::cout << "Source domid: " << msg->from_dom << '\n';
    std::cout << "Dest domid:   " << msg->to_dom << '\n';
    std::cout << "IVC Port:     " << msg->port << '\n';
    std::cout << "Evtchn Port:  " << msg->event_channel << '\n';
    std::cout << "Num grants:   " << msg->num_grants << '\n';
    std::cout << "Conn. id:     " << msg->connection_id << '\n';
}

static inline void dump_buf(uint32_t *buf, uint32_t len)
{
    for(int i = 0; i < len/(sizeof(uint32_t)); i++) {
        if(i % 16 == 0) {
            std::cout << '\n';
        }
        std::cout << std::hex << std::setfill('0') << std::setw(8) << buf[i] << " ";
    }

    std::cout << '\n' << std::dec;
}

class eventController {
public:
    eventController() : mLog("libivc", LOGLEVEL)
    {
        mHandle = xenevtchn_open(nullptr, 0);

        if (!mHandle)
        {
            throw std::system_error(errno, std::generic_category(), "Failed to open a handle to xenevtchn device");
        }

        mThread = std::thread(&eventController::eventThread, this);
    }

    ~eventController()
    {

    }

    xenevtchn_port_or_error_t openEventChannel(domid_t domid, evtchn_port_t port, std::function<void()> callback)
    {
        TRACE;
        std::lock_guard<std::mutex> lock(mLock);
        xenevtchn_port_or_error_t p = xenevtchn_bind_interdomain(mHandle, domid, port);
        if (p == -1) {
            throw std::system_error(errno, std::generic_category(), "Failed to open event channel.");
        }

        mCallbackMap[p] = callback;
        return p;
    }
    
    void closeEventChannel(evtchn_port_t port)
    {
        std::lock_guard<std::mutex> lock(mLock);
		xenevtchn_unbind(mHandle, port);
        mCallbackMap.remove(port);
    }

    void notify(evtchn_port_t port)
    {
        if (!mCallbackMap.contains(port)) {
            TRACE;
            return;
        }
        TRACE;
        if (xenevtchn_notify(mHandle, port) < 0)
        {
            throw std::system_error(errno, std::generic_category(), "Failed to notify event channel.");
        }
    }
    
    void eventThread()
    {
        struct pollfd pfd;
        pfd.fd = xenevtchn_fd(mHandle);
        pfd.events = POLLIN;
        
        for(;;) {
            TRACE;
            if(::poll(&pfd, 1, -1)) {
                TRACE;
                xenevtchn_port_or_error_t port = xenevtchn_pending(mHandle);

                if (port < 0) {
                    continue;
                }
                TRACE;
                if (xenevtchn_unmask(mHandle, port) < 0) {
                    continue;
                }
                TRACE;
                std::lock_guard<std::mutex> lock(mLock);
                if(mCallbackMap[port])
                    mCallbackMap[port]();
                TRACE;

                pfd.revents = 0;
            }
        }
    }
    
private:
    xenevtchn_handle *mHandle{nullptr};
    QMap<xenevtchn_port_or_error_t, std::function<void()>> mCallbackMap;

    std::mutex mLock;
    std::thread mThread;

    XenBackend::Log mLog;
};

class ivcClient {
public:
    ivcClient(domid_t domid, uint16_t port, grant_ref_t *grefs, uint32_t num_grants, evtchn_port_t evtport, eventController &e) : mLog("libivc", LOGLEVEL)
    {
        TRACE;
        mDomid = domid;
        mEvtchnPort = evtport;
        
        mEventCallback = std::function<void()>([&](){ eventCallback(); });
        XenBackend::XenGnttabBuffer interimBuffer(domid, grefs, 32);
        mMappedBuffer = std::make_shared<XenBackend::XenGnttabBuffer>(domid, (grant_ref_t *)interimBuffer.get(), num_grants);

        /* C interface */
        mClient = (struct libivc_client *)malloc(sizeof(struct libivc_client));
        memset((void*)mClient, 0x00, sizeof(struct libivc_client));
        mClient->buffer = mMappedBuffer->get();
        mClient->size = mMappedBuffer->size();
        mClient->domid = domid;
        mClient->port = port;
        mClient->evtport = e.openEventChannel(domid, evtport, mEventCallback);
        
        mRingbuffer = std::make_shared<ringbuf>((uint8_t*)mClient->buffer, 4096 * num_grants, true);
    }
    
    ~ivcClient()
    {
        TRACE;
        mRingbuffer = nullptr;
        if(mRingbuffer.use_count()) {
            LOG(mLog, ERROR) << "BUG: mRingbuffer has open references.\n";
        }
        
        mEventCallback = nullptr;

        mClient->port = 0;
        mClient->domid = 0;
        mClient->buffer = nullptr;
        mClient->size = 0;
        free(mClient);

        mMappedBuffer = nullptr;
        if(mMappedBuffer.use_count()) {
            LOG(mLog, ERROR) << "BUG: mMappedBuffer has open references.\n";
        }
    }

    void eventCallback()
    {
        if (!mRingbuffer->bytesAvailableRead()) {
            return;
        }
        
        if(mClient && mClient->event_cb) {
            mClient->event_cb(mClient->arg, mClient);
            mPendingCallback = false;
        } else {
            mPendingCallback = true;
        }
    }

    bool pendingCallback() { return mPendingCallback; }
#define RETRY_COUNT 5
    
    int recv(char *buf, uint32_t len)
    {
        int rc = mRingbuffer->bytesAvailableRead();
        int retry = 0;
        while (rc < len && retry++ < RETRY_COUNT) {
            rc = mRingbuffer->bytesAvailableRead();
            usleep(250*1000);
        }

        if (rc < len) {
            return -ENODATA;
        }
        
        rc = mRingbuffer->read((uint8_t*)buf, len);

        return len == rc ? 0 : -ENODATA;
    }

    int send(char *buf, uint32_t len)
    {
        int rc = mRingbuffer->write((uint8_t*)buf, len);
        
        return rc;
    }

    int availableData()
    {
        return mRingbuffer->bytesAvailableRead();
    }

    int availableSpace()
    {
        return mRingbuffer->bytesAvailableWrite();
    }
    
    struct libivc_client *client()
    {
        TRACE;
        return mClient;
    }
           
private:
    std::shared_ptr<XenBackend::XenGnttabBuffer> mMappedBuffer{nullptr};
    struct libivc_client *mClient{nullptr};
    std::function<void()> mEventCallback{nullptr};
    std::shared_ptr<ringbuf> mRingbuffer{nullptr};

    bool mPendingCallback{false};
    
    domid_t mDomid{0};
    evtchn_port_t mEvtchnPort{0};
    
    XenBackend::Log mLog;
};


class libivc_core {
public:
    libivc_core() : mLog("libivc_core", LOGLEVEL)
    {
        std::cout << "libivc_core : " << __PRETTY_FUNCTION__ << '\n';
        TRACE;
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

        mSockFp = fdopen(mSock, "w+");
        if (!mSockFp) {
            throw std::system_error(errno, std::generic_category(), "Failed to create file pointer to socket");
        }
        
        mMonitor = new std::thread(&libivc_core::monitorCommands, this);
    }
    virtual ~libivc_core()
    {
        TRACE;
        ::close(mSock);
    }

    void destroyClient(struct libivc_client *client)
    {
        TRACE;
        uint32_t key = dom_port_key(client->domid, client->port);
        mClients.remove(key);
    }
    
    struct libivc_client *createClient(domid_t domid, uint16_t port, grant_ref_t *grefs, uint32_t num_grants, evtchn_port_t evtport)
    {
        TRACE;
        uint32_t key = dom_port_key(domid, port);
        try {
            std::lock_guard<std::mutex> lock(mClientLock);
            mClients[key] = std::make_shared<ivcClient>(domid, port, grefs, num_grants, evtport, mEventController);
            return mClients[key]->client();
        } catch (...) {
            return nullptr;
        }
    }

    void notifyRemote(struct libivc_client *client)
    {
        TRACE;
        uint32_t key = dom_port_key(client->domid, client->port);
        mEventController.notify(client->evtport);
    }

    int ivcRegisterCallbacks(struct libivc_client *client, libivc_client_event_fired eventCallback, libivc_client_disconnected disconnectCallback, void *opaque)
    {
        TRACE;
        uint32_t key = dom_port_key(client->domid, client->port);
        client->event_cb = eventCallback;
        client->disconnect_cb = disconnectCallback;
        client->arg = opaque;

        if(mClients[key]->pendingCallback()) {
            mClients[key]->eventCallback();
        }
        
        return 0;
    }
    
    int ivcRecv(struct libivc_client *client, char *dest, size_t destSize)
    {
        uint32_t key = dom_port_key(client->domid, client->port);
        return mClients[key]->recv(dest, destSize);
    }

    int ivcSend(struct libivc_client *client, char *dest, size_t destSize)
    {
        TRACE;
        uint32_t key = dom_port_key(client->domid, client->port);
        int rc = mClients[key]->send(dest, destSize);
        notifyRemote(client);
        return rc;
    }

    int ivcAvailableData(struct libivc_client *client, size_t *dataSize)
    {
        uint32_t key = dom_port_key(client->domid, client->port);
        *dataSize = mClients[key]->availableData();
        return 0;
    }

    int ivcAvailableSpace(struct libivc_client *client, size_t *dataSize)
    {
        TRACE;
        uint32_t key = dom_port_key(client->domid, client->port);
        *dataSize = mClients[key]->availableSpace();
        return 0;
    }   
    
    void sendResponse(libivc_message_t *msg, MESSAGE_TYPE_T type, uint8_t status)
    {
        TRACE;
        // copy in the incoming message data to the response
        libivc_message_t respMsg{0};
        memcpy(&respMsg, msg, sizeof (libivc_message_t));
        respMsg.status = (uint8_t) status;
        respMsg.to_dom = msg->from_dom;
        respMsg.from_dom = (uint16_t) msg->to_dom;
        respMsg.type = type;

        write((void *)&respMsg, sizeof(respMsg));
    }
    
    void handleConnectMessage(libivc_message_t *msg)
    {
        std::lock_guard<std::mutex> lock(mServerLock);
        TRACE;
        if(!msg)
            return;
  
        if(msg->to_dom != 0)
            return;

        uint32_t key = dom_port_key(msg->from_dom, msg->port);
        uint32_t anykey = dom_port_key(LIBIVC_DOMID_ANY, msg->port);
        
        // Have to provide a connected client here...
        if(mCallbackMap.contains(key)) {
            struct libivc_client *client = createClient(msg->from_dom, msg->port, msg->descriptor, msg->num_grants, msg->event_channel);
            if (client) {
                mCallbackMap[key](mCallbackArgumentMap[key], client);
                sendResponse(msg, ACK, 0);
                return;
            }
        }

        if(mCallbackMap.contains(anykey)) {
            struct libivc_client *client = createClient(msg->from_dom, msg->port, msg->descriptor, msg->num_grants, msg->event_channel);
            if (client) {
                mCallbackMap[anykey](mCallbackArgumentMap[anykey], client);
                sendResponse(msg, ACK, 0);
                return;
            }
        }

        sendResponse(msg, ACK, -ECONNREFUSED);
        
        std::cout << "Connect call with no listening servers\n";
    }

    void handleDisconnectMessage(libivc_message_t *msg)
    {
        TRACE;
        uint32_t key = dom_port_key(msg->from_dom, msg->port);
        destroyClient(mClients[key]->client());
    }

    void monitorCommands()
    {
        TRACE;
        struct pollfd fd;
        memset(&fd, 0x00, sizeof(fd));
        int ret = 0;

        fd.fd = mSock; 
        fd.events = POLLIN;
        while(poll(&fd, 1, -1)) {
            libivc_message_t msg{0};

            if(fd.revents & POLLIN) {
                read((char *)&msg, sizeof(msg));
                switch(msg.type) {
                case CONNECT:
                {
                    handleConnectMessage(&msg);
                    break;
                }
                case DISCONNECT:
                {
                    handleDisconnectMessage(&msg);
                    std::cout << "DISCONNECT\n";
                    break;
                }
                case NOTIFY_ON_DEATH:
                {
                    for(auto &client : mClients) {
                        client->eventCallback();
                    }
                    break;
                }
                default:
                {
                    break;
                }
                }
            }
        }
    }
    
    struct libivc_server *registerServer(uint16_t port,
                                         uint16_t domid,
                                         uint64_t client_id,
                                         libivc_client_connected cb,
                                         void *opaque)
    {
        std::lock_guard<std::mutex> lock(mServerLock);
        TRACE;
        uint32_t key = dom_port_key(domid, port);
        LOG(mLog, DEBUG) << "Domid: " << domid << " Port: " << port << " Client id: " << client_id << " Key: " << key;
        mCallbackMap[key] = cb;
        mCallbackArgumentMap[key] = opaque;

        return (struct libivc_server *)key;
    }

    void shutdownServer(struct libivc_server *server)
    {
        TRACE;
        uint32_t key = (uint32_t)(((uintptr_t)server) & 0x00000000FFFFFFFFF);
        mCallbackMap[key] = nullptr;
        mCallbackArgumentMap[key] = nullptr;            
    }

    struct libivc_server *findServer(domid_t domid, uint16_t port)
    {
        TRACE;
        uint32_t key = dom_port_key(domid, port);
        if(mCallbackMap[key]) {
            return (struct libivc_server *)key;
        }

        return nullptr;
    }
    
    void read(char *msg, uint32_t size)
    {
        std::lock_guard<std::mutex> lock(mClientLock);
        ::read(mSock, msg, size);
    }
  
    void write(void *buf, uint32_t size)
    {
        TRACE;
        std::lock_guard<std::mutex> lock(mClientLock);
        ::write(mSock, (const char*)buf, size);
        ::fflush(mSockFp);
    }
  
private:
    uint32_t dom_port_key(uint16_t domid, uint16_t port)
    {
        uint32_t key = ((((uint32_t)domid << 16) & 0xFFFF0000) | ((uint32_t)port & 0x0000FFFF));
        return key;
    }
    
    int mSock{-1};
    
    QMap<uint32_t, std::shared_ptr<ivcClient>> mClients;
    QMap<uint32_t, libivc_client_connected> mCallbackMap;
    QMap<uint32_t, void *> mCallbackArgumentMap;
    FILE *mSockFp{nullptr};

    std::thread *mMonitor{nullptr};
    std::mutex mServerLock;
    std::mutex mClientLock;
    XenBackend::Log mLog;

    eventController mEventController;
};
/*
 * Local variables:
 * mode: C++
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */  
#endif
