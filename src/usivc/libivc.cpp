#include "libivc_core.h"
#include "libivc.h"

libivc_core *c = nullptr;

int libivc_init()
{
  if(!c) {
    c = new libivc_core();
  }
}

int libivc_clear_ringbuffer(struct libivc_client *client)
{
	std::cout << "DING DING DING DING !!!!\n";
}

int libivc_connect(struct libivc_client **ivc, uint16_t remote_dom_id, uint16_t remote_port, uint32_t numPages)
{

}

int libivc_connect_with_id(struct libivc_client **ivc, uint16_t remote_dom_id, uint16_t remote_port, uint32_t numPages, uint64_t connection_id)
{

}

int libivc_disable_events(struct libivc_client *client)
{

}

int libivc_enable_events(struct libivc_client *client)
{

}

int libivc_getAvailableData(struct libivc_client *client, size_t *dataSize)
{
  return c->ivcAvailableData(client, dataSize);
}

int libivc_getAvailableSpace(struct libivc_client *client, size_t *space)
{
  return c->ivcAvailableSpace(client, space);
}

int libivc_getLocalBuffer(struct libivc_client *ivc, char **buffer)
{
  if(buffer && ivc) {
    *buffer = (char *)ivc->buffer;
    return 0;
  }

  if (buffer) {
    *buffer = NULL;
  }
  
  return -EINVAL; 
}

int libivc_getLocalBufferSize(struct libivc_client *ivc, size_t *buffSize)
{
  if(buffSize && ivc) {
    *buffSize = ivc->size;
    return 0;
  }
  
  return -EINVAL; 
}

int libivc_getRemoteDomId(struct libivc_client *ivc, uint16_t *dom)
{
  if(dom && ivc) {
    *dom = ivc->domid;
    return 0;
  }
  return -EINVAL; 
}

int libivc_notify_remote(struct libivc_client *client)
{
  c->notifyRemote(client);
  return 0;
}

int libivc_read(struct libivc_client *ivc, char *dest, size_t destSize, size_t *actualSize)
{

}

int libivc_reconnect(struct libivc_client * client, uint16_t remote_dom_id, uint16_t remote_port)
{

}

int libivc_recv(struct libivc_client *ivc, char *dest, size_t destSize)
{
  return c->ivcRecv(ivc, dest, destSize);
}

int libivc_register_event_callbacks(struct libivc_client *client, libivc_client_event_fired eventCallback, libivc_client_disconnected disconnectCallback, void *opaque)
{
  return c->ivcRegisterCallbacks(client, eventCallback, disconnectCallback, opaque);
}

int libivc_remote_events_enabled(struct libivc_client *client, uint8_t *enabled)
{

}

int libivc_send(struct libivc_client *ivc, char *src, size_t srcSize)
{
  int rc = c->ivcSend(ivc, src, srcSize);
  //  c->notifyRemote(ivc);

  return rc == srcSize ? 0 : -ENOSPC;
}
int libivc_start_listening_server(struct libivc_server **server, uint16_t listening_port, uint16_t listen_for_domid, uint64_t listen_for_client_id, libivc_client_connected connectCallback, void *opaque)
{
  libivc_init();
  *server = c->registerServer(listening_port, listen_for_domid, listen_for_client_id, connectCallback, opaque);
  return 0;
}

int libivc_write(struct libivc_client *ivc, char *src, size_t srcLength, size_t *actualLength)
{

}

uint8_t libivc_isOpen(struct libivc_client *ivc)
{
  return 1;
}

void libivc_disconnect(struct libivc_client *client)
{
  c->destroyClient(client);
}

void libivc_shutdownIvcServer(struct libivc_server *server)
{
  c->shutdownServer(server);
}

struct libivc_server *libivc_find_listening_server(uint16_t connecting_domid, uint16_t port, uint64_t connection_id)
{
  return c->findServer(connecting_domid, port);
}
