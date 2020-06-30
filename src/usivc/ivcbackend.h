#ifndef IVCBACKEND__H
#define IVCBACKEND__H

#include <QMap>
#include <QObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QTimer>

#include <xen/be/Log.hpp>
#include <xen/be/XenStore.hpp>

#include "guestmanager.h"
#include "guestcontroller.h"

#include "libivc_core.h"

Q_DECLARE_METATYPE(libivc_message_t);

class IvcBackend : public QObject {
  Q_OBJECT
 public:
  IvcBackend();
  ~IvcBackend();

public slots:
  void addGuest(domid_t domid);
  void removeGuest(domid_t domid);

  void addProcess();

  void processClientRequest(libivc_message_t msg);
  void processServerRequests();
 private:
  
  XenBackend::XenStore mXs;

  QLocalServer mProcessServer;
  
  GuestManager mManager;
  QMap<domid_t, GuestController*> mGuestControllers;
  QMap<QLocalSocket *, struct libivc_server *> mSocketMap;
  QList<QLocalSocket *> mSockets;

  XenBackend::Log mLog;
};

#endif //IVCBACKEND__H
