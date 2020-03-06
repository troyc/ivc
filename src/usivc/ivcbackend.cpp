#include "ivcbackend.h"
#include <QFile>

IvcBackend::IvcBackend() :
    mManager(mXs),
    mLog("ivcd", LOGLEVEL)    
{
    TRACE;
    QObject::connect(&mManager, &GuestManager::addGuest, this, &IvcBackend::addGuest, Qt::QueuedConnection);
    QObject::connect(&mManager, &GuestManager::removeGuest, this, &IvcBackend::removeGuest, Qt::QueuedConnection);

    QObject::connect(&mProcessServer, &QLocalServer::newConnection, this, &IvcBackend::addProcess);

    QFile::remove("/tmp/ivc_control");
    mProcessServer.listen("/tmp/ivc_control");

    mTimer = new QTimer();
    QObject::connect(mTimer, SIGNAL(timeout()), this, SLOT(pollForEvents()));
}

IvcBackend::~IvcBackend()
{
    TRACE;
    QFile::remove("/tmp/ivc_control");
}

void IvcBackend::addGuest(domid_t domid)
{
    TRACE;
    mGuestControllers[domid] = new GuestController(mXs, domid);
    QObject::connect(mGuestControllers[domid], &GuestController::clientMessage,
                     this, &IvcBackend::processClientRequest);
}

void IvcBackend::removeGuest(domid_t domid)
{
    TRACE;
    GuestController *g = mGuestControllers[domid];
    if(g) {
        g->disconnect();
        mGuestControllers.remove(domid);
        delete g;
    }
}

void IvcBackend::addProcess()
{
    TRACE;
    if(!mProcessServer.hasPendingConnections()) {
        return;
    }

    QLocalSocket *sock = mProcessServer.nextPendingConnection();
    QObject::connect(sock, &QLocalSocket::readyRead, this, &IvcBackend::processServerRequests);
    mSockets.append(sock);
    mTimer->start(16);
}

void IvcBackend::processServerRequests()
{
    TRACE;
    for(auto &sock : mSockets) {
        libivc_message_t msg;
        memset(&msg, 0x00, sizeof(msg));
        
        if(sock->bytesAvailable() >= sizeof(msg)) {
            sock->read((char *)&msg, sizeof(msg));
            if(mGuestControllers[msg.to_dom]) {
                mGuestControllers[msg.to_dom]->forwardMessage(&msg);
            }
        }
    }
}

void IvcBackend::pollForEvents()
{
    libivc_message_t msg;
    msg.type = NOTIFY_ON_DEATH;
    processClientRequest(msg);
}

void IvcBackend::processClientRequest(libivc_message_t msg)
{
    if(msg.type != CONNECT && msg.type != DISCONNECT && msg.type != NOTIFY_ON_DEATH) {
        return;
    }
    TRACE;

    for(auto &sock : mSockets) {
        sock->write((char *)&msg, sizeof(msg));
        sock->flush();
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
