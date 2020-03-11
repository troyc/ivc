#include "ivc_client.h"

ivcClient::ivcClient(domid_t domid,
		     uint16_t port,
		     grant_ref_t *grefs,
		     uint32_t num_grants,
		     evtchn_port_t evtport,
		     eventController &e) : mLog("libivc", LOGLEVEL) {
  mDomid = domid;
  mEvtchnPort = evtport;
        
  mEventCallback = std::function<void()>([&](){ eventCallback(); });
  XenBackend::XenGnttabBuffer interimBuffer(domid, grefs, 32);
  mMappedBuffer = std::make_shared<XenBackend::XenGnttabBuffer>(domid, (grant_ref_t *)interimBuffer.get(), num_grants);

  /* C interface */
  mClient = (struct libivc_client *)malloc(sizeof(struct libivc_client));
  memset((void*)mClient, 0x00, sizeof(struct libivc_client));
  mClient->buffer = mMappedBuffer->get();
  mClient->size = mMappedBuffer->size();
  mClient->domid = domid;
  mClient->port = port;
  mClient->evtport = e.openEventChannel(domid, evtport, mEventCallback);
        
  mRingbuffer = std::make_shared<ringbuf>((uint8_t*)mClient->buffer, 4096 * num_grants, true);
}

ivcClient::~ivcClient() {
  mRingbuffer = nullptr;
  if(mRingbuffer.use_count()) {
    LOG(mLog, ERROR) << "BUG: mRingbuffer has open references.\n";
  }
        
  mEventCallback = nullptr;

  mClient->port = 0;
  mClient->domid = 0;
  mClient->buffer = nullptr;
  mClient->size = 0;
  free(mClient);

  mMappedBuffer = nullptr;
  if(mMappedBuffer.use_count()) {
    LOG(mLog, ERROR) << "BUG: mMappedBuffer has open references.\n";
  }
}

void
ivcClient::eventCallback() {
  if (!mRingbuffer->bytesAvailableRead()) {
    return;
  }
        
  if(mClient && mClient->event_cb) {
    mClient->event_cb(mClient->arg, mClient);
    mPendingCallback = false;
  } else {
    mPendingCallback = true;
  }
}

bool
ivcClient::pendingCallback() {
  return mPendingCallback;
}

#define RETRY_COUNT 5
    
int
ivcClient::recv(char *buf, uint32_t len) {
  int rc = mRingbuffer->bytesAvailableRead();
  int retry = 0;
  while (rc < len && retry++ < RETRY_COUNT) {
    rc = mRingbuffer->bytesAvailableRead();
    usleep(250*1000);
  }

  if (rc < len) {
    return -ENODATA;
  }
        
  rc = mRingbuffer->read((uint8_t*)buf, len);

  return len == rc ? 0 : -ENODATA;
}

int
ivcClient::send(char *buf, uint32_t len) {
  int rc = mRingbuffer->write((uint8_t*)buf, len);
        
  return rc;
}

int
ivcClient::availableData() {
  return mRingbuffer->bytesAvailableRead();
}

int
ivcClient::availableSpace() {
  return mRingbuffer->bytesAvailableWrite();
}
    
struct
ivcClient::libivc_client *client() {
  return mClient;
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
