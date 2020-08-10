#ifndef LIBIVC_CORE__H
#define LIBIVC_CORE__H

#include <QMap>
#include <QDebug>

#include <thread>
#include <chrono>
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
#include <libivc.h>
#include <libivc_private.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
};

#include "ringbuf.h"
#include "ivc_client.h"

#define TRACE do { DLOG(mLog, DEBUG) << " --- [ " << __PRETTY_FUNCTION__ << ":" << __LINE__ << " ] ---"; } while(0)


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
    std::cout << "Msg_start:    " << (intptr_t)msg->msg_start << '\n';
    std::cout << "Msg_end:      " << (intptr_t)msg->msg_end << '\n';

//    std::cout << "Conn. id:     " << msg->connection_id << '\n';
}

static inline void dump_buf(uint32_t *buf, uint32_t len)
{
    for(unsigned int i = 0; i < len/(sizeof(uint32_t)); i++) {
        if(i % 16 == 0) {
            std::cout << '\n';
        }
        std::cout << std::hex << std::setfill('0') << std::setw(8) << buf[i] << " ";
    }

    std::cout << '\n' << std::dec;
}

class libivc_core {
public:
    libivc_core();
    virtual ~libivc_core();

    void destroyClient(struct libivc_client *client);
    struct libivc_client *createClient(domid_t domid,
                                       uint16_t port,
                                       const grant_ref_t *grefs,
                                       uint32_t num_grants,
                                       evtchn_port_t evtport);
    void notifyRemote(struct libivc_client *client);
    int ivcRegisterCallbacks(struct libivc_client *client,
                             libivc_client_event_fired eventCallback,
                             libivc_client_disconnected disconnectCallback,
                             void *opaque);
    int ivcRecv(struct libivc_client *client, char *dest, size_t destSize);
    int ivcSend(struct libivc_client *client, char *dest, size_t destSize);
    int ivcAvailableData(struct libivc_client *client, size_t *dataSize);
    int ivcAvailableSpace(struct libivc_client *client, size_t *dataSize);

    int sendResponse(const libivc_message_t *msg, MESSAGE_TYPE_T type, uint8_t status);
    int handleConnectMessage(const libivc_message_t *msg);
    void handleDisconnectMessage(const libivc_message_t *msg);
    struct libivc_server *registerServer(uint16_t port,
                                         uint16_t domid,
                                         uint64_t client_id,
                                         libivc_client_connected cb,
                                         void *opaque);
    void shutdownServer(struct libivc_server *server);
    struct libivc_server *findServer(domid_t domid, uint16_t port);
private:
    void daemonDisconnect();
    int daemonConnect(const char *path);
    int daemonPoll();
    ssize_t daemonRecv(void *msg, size_t size);
    ssize_t daemonSend(const void *msg, size_t size);
    int daemonProcessMessage(const libivc_message_t *msg);
    void daemonMonitor();

    uint32_t dom_port_key(uint16_t domid, uint16_t port);

    int mSock{-1};

    QMap<uint32_t, std::shared_ptr<ivcClient>> mClients;
    QMap<uint32_t, void *> mCallbackMap;
    QMap<uint32_t, void *> mCallbackArgumentMap;

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
