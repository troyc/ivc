#include "event_controller.h"

eventController::eventController() : mLog("libivc", LOGLEVEL)
{
  mHandle = xenevtchn_open(nullptr, 0);

  if (!mHandle)
    {
      throw std::system_error(errno, std::generic_category(), "Failed to open a handle to xenevtchn device");
    }

  mThread = std::thread(&eventController::eventThread, this);
}

eventController::~eventController()
{

}

xenevtchn_port_or_error_t
eventController::openEventChannel(domid_t domid, evtchn_port_t port, std::function<void()> callback)
{
        
  std::lock_guard<std::mutex> lock(mLock);
  xenevtchn_port_or_error_t p = xenevtchn_bind_interdomain(mHandle, domid, port);
  if (p == -1) {
    throw std::system_error(errno, std::generic_category(), "Failed to open event channel.");
  }

  mCallbackMap[p] = callback;
  return p;
}
    
void
eventController::closeEventChannel(evtchn_port_t port)
{
  std::lock_guard<std::mutex> lock(mLock);
  xenevtchn_unbind(mHandle, port);
  mCallbackMap.remove(port);
}

void
eventController::notify(evtchn_port_t port)
{
  if (!mCallbackMap.contains(port)) {
            
    return;
  }
        
  if (xenevtchn_notify(mHandle, port) < 0)
    {
      throw std::system_error(errno, std::generic_category(), "Failed to notify event channel.");
    }
}
    
void
eventController::eventThread()
{
  struct pollfd pfd;
  pfd.fd = xenevtchn_fd(mHandle);
  pfd.events = POLLIN;
        
  for(;;) {
            
    if(::poll(&pfd, 1, -1)) {
                
      xenevtchn_port_or_error_t port = xenevtchn_pending(mHandle);

      if (port < 0) {
	continue;
      }
                
      if (xenevtchn_unmask(mHandle, port) < 0) {
	continue;
      }
                
      std::lock_guard<std::mutex> lock(mLock);
      if(mCallbackMap[port])
	mCallbackMap[port]();
                

      pfd.revents = 0;
    }
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
