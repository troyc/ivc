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
    bool mClearWatch{false};

    std::mutex mLock;
    bool mInitialized{false};
  
    std::shared_ptr<ringbuf> mRb{nullptr};

    grant_ref_t mControlGref{0};
    std::shared_ptr<XenBackend::XenGnttabBuffer> mControlBuffer{nullptr};  
    evtchn_port_t mControlPort{0};
    std::shared_ptr<XenBackend::XenEvtchn> mControlEvent{nullptr};
    XenBackend::XenEvtchn::Callback mControlCallback;
    XenBackend::Log mLog;

    struct ringbuffer_t *ringbuffer{nullptr};
};
#endif //GUESTCONTROLLER__H
/*
 * Local variables:
 * mode: C++
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
