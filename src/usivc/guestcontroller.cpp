#include "guestcontroller.h"
#include <xen/be/XenGnttab.hpp>
#include <QTimer>
#include <QFile>

GuestController::GuestController(XenBackend::XenStore &xs,
                                 domid_t domid) : mXs(xs),
                                                  mDomid(domid),
                                                  mLog("ivcd", LOGLEVEL)
{
    TRACE;
    QObject::connect(this, &GuestController::guestReady, this, &GuestController::initializeGuest, Qt::QueuedConnection);
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
    TRACE;

    if(mRb) {    
        int bytesWritten = mRb->write((uint8_t*)msg, sizeof(*msg));
    }

    if(mControlEvent) {
//        mControlEvent->notify();
    }
}

void GuestController::processControlEvent()
{
    TRACE;
    libivc_message_t msg;
    int bytesRead = 0;
    memset(&msg, 0x00, sizeof(msg));

    bytesRead = mRb->read((uint8_t*)&msg, sizeof(msg));
    if(bytesRead == sizeof(msg)) {
        LOG(mLog, INFO) << " Read control message, expected : " << sizeof(msg) << "b, got: " << bytesRead << "b";
        emit clientMessage(msg);
    }
}

void GuestController::initializeGuest(grant_ref_t gref, evtchn_port_t port, int feState)
{
    TRACE;
    mControlGref = gref;
    mControlPort = port;

    if (feState != READY)
        return;
  
    if(!mControlBuffer.get()) {
        mControlBuffer = std::make_shared<XenBackend::XenGnttabBuffer>(mDomid, gref, PROT_READ|PROT_WRITE);
    }

    if (!ringbuffer) {
        mRb = std::make_shared<ringbuf>((uint8_t*) mControlBuffer->get(), 4096);
    }
  
    if(!mControlEvent.get()) {
        QTimer *checkMessages = new QTimer();
        QObject::connect(checkMessages, SIGNAL(timeout()), this, SIGNAL(controlEventReady()));
        checkMessages->start(1000);
        mControlEvent = std::make_shared<XenBackend::XenEvtchn>(mDomid,
                                                                port,
                                                                [this]{ LOG(mLog, INFO) << " GOT AN EVENT --- YEEEEEW!"; QTimer::singleShot(250, this, SLOT(processControlEvent())); },
                                                                [this](const std::exception& e) {
                                                                    LOG(mLog, ERROR) << e.what();
                                                                });
        mControlEvent->start();
    }

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
        DLOG(mLog, DEBUG) << "FE State: " << feState;
    }

    if(mXs.checkIfExist(path + "/" + "backend-status")) {
        beState = mXs.readUint(path + "/" + "backend-status");
    }
  
    if (gref && port && feState == READY && beState != CONNECTED) {
        emit guestReady(gref, port, feState);
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
