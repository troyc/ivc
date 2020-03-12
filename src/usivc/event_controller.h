#ifndef EVENT_CONTROLLER__H
#define EVENT_CONTROLLER__H

#include <QMap>

#include <thread>
#include <iostream>
#include <memory>
#include <mutex>
#include <system_error>
#include <functional>

#include <xen/be/Log.hpp>
#include <xen/be/XenEvtchn.hpp>

extern "C" {
#include <unistd.h>
#include <poll.h>
#include "libivc.h"
};

class eventController {
public:
    eventController();
    ~eventController();

    xenevtchn_port_or_error_t openEventChannel(domid_t domid, evtchn_port_t port, std::function<void()> callback);
    void closeEventChannel(evtchn_port_t port);
    void notify(evtchn_port_t port);
    void eventThread();  
private:
    xenevtchn_handle *mHandle{nullptr};
    QMap<xenevtchn_port_or_error_t, std::function<void()>> mCallbackMap;

    std::mutex mLock;
    std::thread mThread;

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
#endif //EVENT_CONTROLLER__H
