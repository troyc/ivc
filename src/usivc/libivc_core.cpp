#include "libivc_core.h"

libivc_core::libivc_core() : mLog("libivc_core", LOGLEVEL) {
  struct sockaddr_un address;
  mSock = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if(mSock < 0) {
    throw std::system_error(errno, std::generic_category(), "Failed to create socket");
  }

  const char *path = "/tmp/ivc_control";
    
  memset(&address, 0x00, sizeof(address));
  address.sun_family = AF_UNIX;
  ::strncpy((char*)&address.sun_path, path, 107);

  int res = ::connect(mSock, (struct sockaddr *)&address, sizeof(address));
  if(res) {
    throw std::system_error(errno, std::generic_category(), "Failed to connect socket");
  }

  mSockFp = fdopen(mSock, "w+");
  if (!mSockFp) {
    throw std::system_error(errno, std::generic_category(), "Failed to create file pointer to socket");
  }
        
  mMonitor = new std::thread(&libivc_core::monitorCommands, this);
}

libivc_core::~libivc_core() {
  ::close(mSock);
}

libivc_core::destroyClient(struct libivc_client *client) {
  uint32_t key = dom_port_key(client->domid, client->port);
  mClients.remove(key);
}

struct libivc_client *
libivc_core::createClient(domid_t domid,
			  uint16_t port,
			  grant_ref_t *grefs,
			  uint32_t num_grants,
			  evtchn_port_t evtport) {
  uint32_t key = dom_port_key(domid, port);
  try {
    std::lock_guard<std::mutex> lock(mClientLock);
    mClients[key] = std::make_shared<ivcClient>(domid,
						port,
						grefs,
						num_grants,
						evtport,
						mEventController);
    return mClients[key]->client();
  } catch (...) {
    return nullptr;
  }
}

void
libivc_core::notifyRemote(struct libivc_client *client) {
  uint32_t key = dom_port_key(client->domid, client->port);
  mEventController.notify(client->evtport);
}

int
libivc_core::ivcRegisterCallbacks(struct libivc_client *client,
                             libivc_client_event_fired eventCallback,
                             libivc_client_disconnected disconnectCallback,
                             void *opaque)
{
  uint32_t key = dom_port_key(client->domid, client->port);
  client->event_cb = eventCallback;
  client->disconnect_cb = disconnectCallback;
  client->arg = opaque;

  if(mClients[key]->pendingCallback()) {
    mClients[key]->eventCallback();
  }
        
  return 0;
}

int
libivc_core::ivcRecv(struct libivc_client *client, char *dest, size_t destSize) {
  uint32_t key = dom_port_key(client->domid, client->port);
  return mClients[key]->recv(dest, destSize);
}

int
libivc_core::ivcSend(struct libivc_client *client, char *dest, size_t destSize) {
  uint32_t key = dom_port_key(client->domid, client->port);
  int rc = mClients[key]->send(dest, destSize);
  notifyRemote(client);
  return rc;
}

int
libivc_core::ivcAvailableData(struct libivc_client *client, size_t *dataSize) {
  uint32_t key = dom_port_key(client->domid, client->port);
  *dataSize = mClients[key]->availableData();
  return 0;
}

int
libivc_core::ivcAvailableSpace(struct libivc_client *client, size_t *dataSize) {
  uint32_t key = dom_port_key(client->domid, client->port);
  *dataSize = mClients[key]->availableSpace();
  return 0;
}   

void
libivc_core::sendResponse(libivc_message_t *msg, MESSAGE_TYPE_T type, uint8_t status)
{
  // copy in the incoming message data to the response
  libivc_message_t respMsg{0};
  memcpy(&respMsg, msg, sizeof (libivc_message_t));
  respMsg.status = (uint8_t) status;
  respMsg.to_dom = msg->from_dom;
  respMsg.from_dom = (uint16_t) msg->to_dom;
  respMsg.type = type;

  write((void *)&respMsg, sizeof(respMsg));
}

void
libivc_core::handleConnectMessage(libivc_message_t *msg) {
  std::lock_guard<std::mutex> lock(mServerLock);
        
  if(!msg)
    return;
  
  if(msg->to_dom != 0)
    return;

  uint32_t key = dom_port_key(msg->from_dom, msg->port);
  uint32_t anykey = dom_port_key(LIBIVC_DOMID_ANY, msg->port);
        
  // Have to provide a connected client here...
  if(mCallbackMap.contains(key)) {
    struct libivc_client *client = createClient(msg->from_dom,
						msg->port,
						msg->descriptor,
						msg->num_grants,
						msg->event_channel);
    if (client) {
      mCallbackMap[key](mCallbackArgumentMap[key], client);
      sendResponse(msg, ACK, 0);
      return;
    }
  }

  if(mCallbackMap.contains(anykey)) {
    struct libivc_client *client = createClient(msg->from_dom,
						msg->port,
						msg->descriptor,
						msg->num_grants,
						msg->event_channel);
    if (client) {
      mCallbackMap[anykey](mCallbackArgumentMap[anykey], client);
      sendResponse(msg, ACK, 0);
      return;
    }
  }

  sendResponse(msg, ACK, -ECONNREFUSED);

  LOG(mLog, INFO) << "Connect call with no listening servers\n";
}

void
libivc_core::handleDisconnectMessage(libivc_message_t *msg) {       
  uint32_t key = dom_port_key(msg->from_dom, msg->port);
  destroyClient(mClients[key]->client());
}

void
libivc_core::monitorCommands()
{
  struct pollfd fd;
  memset(&fd, 0x00, sizeof(fd));
  int ret = 0;

  fd.fd = mSock; 
  fd.events = POLLIN;
  while(poll(&fd, 1, -1)) {
    libivc_message_t msg{0};

    if(fd.revents & POLLIN) {
      read((char *)&msg, sizeof(msg));
      switch(msg.type) {
      case CONNECT:
	{
	  handleConnectMessage(&msg);
	  break;
	}
      case DISCONNECT:
	{
	  handleDisconnectMessage(&msg);
	  break;
	}
      case NOTIFY_ON_DEATH:
	{
	  for(auto &client : mClients) {
	    client->eventCallback();
	  }
	  break;
	}
      default:
	{
	  break;
	}
      }
    }
  }
}
    
struct libivc_server *
libivc_core::registerServer(uint16_t port,
			    uint16_t domid,
			    uint64_t client_id,
			    libivc_client_connected cb,
			    void *opaque) {
  std::lock_guard<std::mutex> lock(mServerLock);
        
  uint32_t key = dom_port_key(domid, port);
  LOG(mLog, DEBUG) << "Domid: " << domid << " Port: " << port << " Client id: " << client_id << " Key: " << key;
  mCallbackMap[key] = cb;
  mCallbackArgumentMap[key] = opaque;

  return (struct libivc_server *)key;
}

void
libivc_core::shutdownServer(struct libivc_server *server) {
  uint32_t key = (uint32_t)(((uintptr_t)server) & 0x00000000FFFFFFFFF);
  mCallbackMap[key] = nullptr;
  mCallbackArgumentMap[key] = nullptr;            
}

struct libivc_server *
libivc_core::findServer(domid_t domid, uint16_t port) {
  uint32_t key = dom_port_key(domid, port);
  if(mCallbackMap[key]) {
    return (struct libivc_server *)key;
  }

  return nullptr;
}

void
libivc_core::read(char *msg, uint32_t size) {
  std::lock_guard<std::mutex> lock(mClientLock);
  ::read(mSock, msg, size);
}
  
void
libivc_core::write(void *buf, uint32_t size) {
  std::lock_guard<std::mutex> lock(mClientLock);
  ::write(mSock, (const char*)buf, size);
  ::fflush(mSockFp);
}

uint32_t
libivc_core::dom_port_key(uint16_t domid, uint16_t port) {
  uint32_t key = ((((uint32_t)domid << 16) & 0xFFFF0000) | ((uint32_t)port & 0x0000FFFF));
  return key;
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
