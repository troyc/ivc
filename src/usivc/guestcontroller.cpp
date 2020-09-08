#include "guestcontroller.h"
#include <xen/be/XenGnttab.hpp>
#include <QTimer>
#include <QFile>

Q_DECLARE_METATYPE(libivc_message_t);

GuestController::GuestController(XenBackend::XenStore &xs,
                                 domid_t domid) : mXs(xs),
                                                  mDomid(domid),
                                                  mLog("ivcd", LOGLEVEL)
{
    TRACE;
    qRegisterMetaType<libivc_message_t>();
    QObject::connect(this, &GuestController::guestReady, this, &GuestController::initializeGuest);
    QObject::connect(this, &GuestController::controlEventReady, this, &GuestController::processControlEvent, Qt::QueuedConnection);
    mFrontendCallback = std::function<void(const std::string &)>
        ([&](const std::string path){ frontendCallback(path); });
    mXs.writeUint(mXs.getDomainPath(mDomid) + "/data/ivc/backend-status", DISCONNECTED);
    mXs.setWatch(mXs.getDomainPath(mDomid) + "/data/ivc", mFrontendCallback);
}

GuestController::~GuestController()
{
    TRACE;
    if(mClearWatch) {
        mXs.clearWatch(mXs.getDomainPath(mDomid) + "/data/ivc");
    }
}

void GuestController::forwardMessage(libivc_message_t *msg)
{
    if(mRb) {
        int bytesWritten = mRb->write((uint8_t*)msg, sizeof(*msg));

        if(mControlEvent && mRb->getEventEnabled()) {
            mControlEvent->notify();
        }
    }
}

void GuestController::processControlEvent()
{
    libivc_message_t msg;
    libivc_message_t rsp;
    int bytesRead = 0;
    memset(&msg, 0x00, sizeof(msg));

    if(!mRb) {
        return;
    }

    bytesRead = mRb->read((uint8_t*)&msg, sizeof(msg));
    if(bytesRead != sizeof(msg)) {
        bytesRead = mRb->read((uint8_t*)&msg, sizeof(msg));
    }

    if(bytesRead == sizeof(msg)) {
        emit clientMessage(msg);
    } else {
        return;
    }

    memcpy(&rsp, &msg, sizeof(rsp));
    rsp.to_dom = msg.from_dom;
    rsp.from_dom = msg.to_dom;
    rsp.type = ACK;
    rsp.status = 0;
    forwardMessage(&rsp);
}

void GuestController::initializeGuest(grant_ref_t gref, evtchn_port_t port, int feState)
{
    libivc_message_t rsp;
    mControlGref = gref;
    mControlPort = port;

    if (feState != READY)
        return;

    if(!mControlGref) {
        return;
    }
    
    if(!mControlBuffer.get()) {
        mControlBuffer = std::make_shared<XenBackend::XenGnttabBuffer>(mDomid, mControlGref, PROT_READ|PROT_WRITE);
    }

    if (!mRb) {
        mRb = std::make_shared<ringbuf>((uint8_t*) mControlBuffer->get(), 4096);
    }

    if(!mControlEvent.get()) {
        mControlEvent = std::make_shared<XenBackend::XenEvtchn>(mDomid,
                                                                port,
                                                                [this]{ processControlEvent(); },
                                                                [this](const std::exception& e) {
                                                                    LOG(mLog, ERROR) << e.what();
                                                                });
    }

    try {
        mControlEvent->start();
    } catch(...) {}

    mXs.writeUint(mXs.getDomainPath(mDomid) + "/data/ivc/backend-status", CONNECTED);
}

void GuestController::frontendCallback(const std::string &path)
{
    std::lock_guard<std::mutex> lock(mLock);
    unsigned int feState = 0, beState = 0;
    grant_ref_t gref = 0;
    evtchn_port_t port = 0;

    if(mXs.checkIfExist(path + "/" + "frontend-page-rw")) {
        gref = mXs.readUint(path + "/" + "frontend-page-rw");
    }

    if(mXs.checkIfExist(path + "/" + "frontend-event")) {
        port = mXs.readUint(path + "/" + "frontend-event");
    }

    if(mXs.checkIfExist(path + "/" + "frontend-status")) {
        feState = mXs.readUint(path + "/" + "frontend-status");
    }

    if(mXs.checkIfExist(path + "/" + "backend-status")) {
        beState = mXs.readUint(path + "/" + "backend-status");
    }

    if (gref && port && feState == READY && beState != CONNECTED) {
        initializeGuest(gref, port, feState);
    }
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
