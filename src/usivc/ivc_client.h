#ifndef IVC_CLIENT__H
#define IVC_CLIENT__H

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
#include "libivc_private.h"
};

#include "event_controller.h"
#include "ringbuf.h"

class ivcClient {
public:
    ivcClient(domid_t domid,
              uint16_t port,
              grant_ref_t *grefs,
              uint32_t num_grants,
              evtchn_port_t evtport,
              eventController &e);
    ~ivcClient();

    void eventCallback();
    bool pendingCallback();
    void setClientEventCallback(std::function<void(void *, libivc_client *)> fn);
    void setClientDisconnectCallback(std::function<void(void *, libivc_client *)> fn);
    void setClientData(void *opaque);
    
    int recv(char *buf, uint32_t len);
    int send(char *buf, uint32_t len);
    int availableData();
    int availableSpace();
    struct libivc_client *client();           
private:
    std::shared_ptr<XenBackend::XenGnttabBuffer> mMappedBuffer{nullptr};
    struct libivc_client *mClient{nullptr};
    std::function<void(void *, libivc_client *)> mClientEventCallback{nullptr};
    std::function<void(void *, libivc_client *)> mClientDisconnectCallback{nullptr};
    std::function<void()> mEventCallback{nullptr};
    std::shared_ptr<ringbuf> mRingbuffer{nullptr};

    bool mPendingCallback{false};
    
    domid_t mDomid{0};
    evtchn_port_t mEvtchnPort{0};
    
    XenBackend::Log mLog;
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
#endif // IVC_CLIENT__H
