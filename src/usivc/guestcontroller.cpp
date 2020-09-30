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
    mXs.clearWatch(mXs.getDomainPath(mDomid) + "/data/ivc");
}

void GuestController::forwardMessage(libivc_message_t *msg)
{
    if (mRb == nullptr)
        return;

    if (mRb->write_packet((uint8_t*)msg, sizeof (*msg)) != sizeof (*msg)) {
        DLOG(mLog, DEBUG) << "Failed to write packet to dom"
            << msg->to_dom << ":" << msg->port << ".";
        return;
    }

    // Not initialized until "GuestReady" fires.
    if (mControlEvent == nullptr)
       return;

    // XXX: There is no buffering, so what happens if EventEnabled is
    // re-enabled later? Nothing fires the event again afaict.
    if (mRb->getEventEnabled())
        mControlEvent->notify();
}

void GuestController::processControlEvent()
{
    libivc_message_t msg;

    if (mRb == nullptr) {
        DLOG(mLog, DEBUG) << "Failed to process control event: ring-buffer not initialized.";
        return;
    }

    memset(&msg, 0, sizeof (msg));
    if (mRb->read_packet((uint8_t*)&msg, sizeof (msg)) != sizeof (msg)) {
        DLOG(mLog, DEBUG) << "Failed to read control packet.";
        return;
    }

    emit clientMessage(msg);
}

void GuestController::initializeGuest(grant_ref_t gref, evtchn_port_t port, int feState)
{
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
