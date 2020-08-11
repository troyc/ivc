#ifndef GUESTCONTROLLER__H
#define GUESTCONTROLLER__H

#include <iostream>
#include <memory>
#include <mutex>

#include <xen/be/Log.hpp>
#include <xen/be/XenStore.hpp>
#include <xen/be/XenGnttab.hpp>
#include <xen/be/XenEvtchn.hpp>

#include <QObject>

#include "ringbuf.h"

#include "libivc_core.h"
#define IVC_FRONTEND_IVC_PATH "/local/domain/%d/data/ivc"
#define IVC_FRONTEND_DEVICE_PATH "/local/domain/%d/data"
#define IVC_FRONTEND_IVC_NODE "ivc"
#define IVC_MAX_PATH 256
#define IVC_FRONTEND_RO_PAGE "frontend-page-ro"
#define IVC_FRONTEND_RW_PAGE "frontend-page-rw"
#define IVC_FRONTEND_EVENT_CHANNEL "frontend-event"
#define IVC_FRONTEND_STATUS "frontend-status"
#define IVC_BACKEND_STATUS "backend-status"

#define IVC_GRANTS_PER_MESSAGE 25
#define IVC_POSIX_SHARE_NAME_SIZE 50
#define IVC_STATUS_SIZE 25
#define IVC_BUFFER_SIZE PAGE_SIZE
#define IVC_DOM_ID 0
#define IVC_PORT 0
#define IVC_MAGIC 0xD00D

#define _TRACE() pr_info("%s : %d\n", __func__, __LINE__)

typedef enum BACKEND_STATUS {
    DISCONNECTED, CONNECTED, FAILED
} BACKEND_STATUS_T;

class GuestController : public QObject {
    Q_OBJECT
public:
    GuestController(XenBackend::XenStore &xs, domid_t domid);
    virtual ~GuestController();
    void forwardMessage(libivc_message_t *msg);
signals:
    void guestReady(grant_ref_t gref, evtchn_port_t port, int feState);
    void guestNotReady();
    void clientMessage(libivc_message_t msg);
    void controlEventReady();
private slots:
    void processControlEvent();
    
private:
    void initializeGuest(grant_ref_t gref, evtchn_port_t port, int feState);
  
    void frontendCallback(const std::string &path);
    XenBackend::XenStore::WatchCallback mFrontendCallback;
    XenBackend::XenStore &mXs;
    domid_t mDomid;

    std::mutex mLock;
    bool mInitialized{false};
  
    std::shared_ptr<ringbuf> mRb{nullptr};

    grant_ref_t mControlGref{0};
    std::shared_ptr<XenBackend::XenGnttabBuffer> mControlBuffer{nullptr};  
    evtchn_port_t mControlPort{0};
    std::shared_ptr<XenBackend::XenEvtchn> mControlEvent{nullptr};
    XenBackend::XenEvtchn::Callback mControlCallback;
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
#endif //GUESTCONTROLLER__H
