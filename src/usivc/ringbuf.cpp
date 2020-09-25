#include "ringbuf.h"

ringbuf::ringbuf(uint8_t *buf, uint64_t len, bool server)
{
  int rc = 0;

  mWriteChannel = server ? SERVER_TO_CLIENT_CHANNEL : CLIENT_TO_SERVER_CHANNEL;
  mReadChannel = server ? CLIENT_TO_SERVER_CHANNEL : SERVER_TO_CLIENT_CHANNEL;
  
  memset((void*)&mRb, 0x00, sizeof(ringbuffer_t));
  memset((void*)&mChannels[0], 0x00, sizeof(struct ringbuffer_channel_t));
  memset((void*)&mChannels[1], 0x00, sizeof(struct ringbuffer_channel_t));

  mRb.buffer = (char *)buf;
  mRb.length = len;
  mRb.num_channels = 2;
  mRb.channels = &mChannels[0];

  rc = ringbuffer_channel_create(&mChannels[mReadChannel], len/2);
  if (rc < 0) {
    throw;
  }
        
  rc = ringbuffer_channel_create(&mChannels[mWriteChannel], len/2);
  if (rc < 0) {
    throw;
  }

  rc = ringbuffer_use(&mRb);
  if(rc < 0) {
    throw;
  }

  ringbuffer_set_flags(&mChannels[mReadChannel], server ? CLIENT_SIDE_TX_EVENT_FLAG : SERVER_SIDE_TX_EVENT_FLAG);
  
  //  dump_headers();
}

ringbuf::~ringbuf()
{
}

bool
ringbuf::getEventEnabled() {
  return ((ringbuffer_get_flags(&mChannels[mWriteChannel]) & SERVER_SIDE_TX_EVENT_FLAG) != 0);
}

int32_t
ringbuf::write(uint8_t *buf, uint32_t len)
{
  // if we're a server we write on 1, as is tradition
  std::lock_guard<std::mutex> lock(mWriteLock);
  int bytesWritten = write_channel(mWriteChannel, buf, len);

  return bytesWritten;
}

int32_t  
ringbuf::bytesAvailableWrite()
{
  std::lock_guard<std::mutex> lock(mWriteLock);
  return ringbuffer_bytes_available_write(&mRb.channels[mWriteChannel]);
}

int32_t
ringbuf::read(uint8_t *buf, uint32_t len)
{
  // if we're a server we read on 0, as is tradition
  std::lock_guard<std::mutex> lock(mReadLock);
  return read_channel(mReadChannel, buf, len);
}

int32_t
ringbuf::bytesAvailableRead()
{
  std::lock_guard<std::mutex> lock(mReadLock);
  return ringbuffer_bytes_available_read(&mRb.channels[mReadChannel]); 
}

void
ringbuf::dump_headers()
{
  std::cout << "-- Read Channel --\n";
  std::cout << "\tbuffer_length:\t\t" << mRb.channels[mReadChannel].buffer_length << "\n";
  std::cout << "\theader_length:\t\t" << mRb.channels[mReadChannel].header_length << "\n";
  std::cout << "\theader ptr:\t\t" << mRb.channels[mReadChannel].header << "\n";
  std::cout << "\t\tHeader lloc: " << mRb.channels[mReadChannel].header->lloc << "\n";
  std::cout << "\t\tHeader lloc ptr: " << (void*)&mRb.channels[mReadChannel].header->lloc << "\n";
  std::cout << "\t\tHeader rloc: " << mRb.channels[mReadChannel].header->rloc << "\n";
  std::cout << "\t\tHeader rloc ptr: " << (void*)&mRb.channels[mReadChannel].header->rloc << "\n";
  std::cout << "\tbody_length:\t\t" << mRb.channels[mReadChannel].body_length << "\n";
  std::cout << "\t\tBody ptr: " << (void*)mRb.channels[mReadChannel].body << "\n";
  
  std::cout << "-- Write Channel --\n";
  std::cout << "\tbuffer_length:\t\t" << mRb.channels[mWriteChannel].buffer_length << "\n";
  std::cout << "\theader_length:\t\t" << mRb.channels[mWriteChannel].header_length << "\n";
  std::cout << "\theader ptr:\t\t" << mRb.channels[mWriteChannel].header << "\n";
  std::cout << "\t\tHeader lloc: " << mRb.channels[mWriteChannel].header->lloc << "\n";
  std::cout << "\t\tHeader lloc ptr: " << (void*)&mRb.channels[mWriteChannel].header->lloc << "\n";
  std::cout << "\t\tHeader rloc: " << mRb.channels[mWriteChannel].header->rloc << "\n";
  std::cout << "\t\tHeader rloc ptr: " << (void*)&mRb.channels[mWriteChannel].header->rloc << "\n";
  std::cout << "\tbody_length:\t\t" << mRb.channels[mWriteChannel].body_length << "\n";
  std::cout << "\t\tBody ptr: " << (void*)mRb.channels[mWriteChannel].body << "\n";
}

int32_t
ringbuf::read_channel(uint8_t channel_index, uint8_t *buf, uint32_t length)
{
  if(!buf) {
    return -ENODEV;
  }

  return ringbuffer_read(&mRb.channels[channel_index], (char*)buf, length);
}

  
int32_t
ringbuf::write_channel(uint8_t channel_index, uint8_t *buf, uint32_t length)
{
  int rc = 0;
  if(!buf) {
    return -ENODEV;
  }

  rc = ringbuffer_write(&mRb.channels[channel_index], (char*)buf, length);

  // return bytes read or negative number for error
  return rc;
}


