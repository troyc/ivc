#ifndef RINGBUF__H
#define RINGBUF__H

extern "C" {
#include <ringbuffer.h>
}

#include <iostream>

#define CLIENT_TO_SERVER_CHANNEL 0
#define SERVER_TO_CLIENT_CHANNEL 1

#define LOGLEVEL XenBackend::LogLevel::logDEBUG

class ringbuf {
public:
    ringbuf(uint8_t *buf, uint64_t len, bool server = true)
    {
        int rc = 0;
        memset((void*)&mRb, 0x00, sizeof(ringbuffer_t));
        mRb.buffer = (char *)buf;
        mRb.length = len;
        mRb.num_channels = 2;
        mRb.channels = mChannels;
        rc = ringbuffer_channel_create(&mChannels[server ? CLIENT_TO_SERVER_CHANNEL : SERVER_TO_CLIENT_CHANNEL], len/2);
        if (rc < 0) {
            throw;
        }
        
        rc = ringbuffer_channel_create(&mChannels[server ? SERVER_TO_CLIENT_CHANNEL : CLIENT_TO_SERVER_CHANNEL], len/2);
        if (rc < 0) {
            throw;
        }

        rc = ringbuffer_use(&mRb);
        if(rc < 0) {
            throw;
        }
 
        mServer = server;
    }
    ~ringbuf()
    {
    }

    int32_t write(uint8_t *buf, uint32_t len)
    {
        // if we're a server we write on 1, as is tradition
        std::lock_guard<std::mutex> lock(mWriteLock);
        int bytesWritten = write_channel(mServer ? SERVER_TO_CLIENT_CHANNEL : CLIENT_TO_SERVER_CHANNEL, buf, len);
        xen_wmb();
        return bytesWritten;
    }

    int32_t bytesAvailableWrite()
    {
        xen_rmb();
        std::lock_guard<std::mutex> lock(mWriteLock);
        return ringbuffer_bytes_available_write(&mRb.channels[mServer ? SERVER_TO_CLIENT_CHANNEL : CLIENT_TO_SERVER_CHANNEL]);
    }

    int32_t read(uint8_t *buf, uint32_t len)
    {
        // if we're a server we read on 0, as is tradition
        xen_rmb();
        std::lock_guard<std::mutex> lock(mReadLock);
        return read_channel(mServer ? CLIENT_TO_SERVER_CHANNEL : SERVER_TO_CLIENT_CHANNEL, buf, len);
    }
    
    int32_t bytesAvailableRead()
    {
        xen_rmb();
        std::lock_guard<std::mutex> lock(mReadLock);
        return ringbuffer_bytes_available_read(&mRb.channels[mServer ? CLIENT_TO_SERVER_CHANNEL : SERVER_TO_CLIENT_CHANNEL]); 
    }
  
private:
    int32_t read_channel(uint8_t channel_index, uint8_t *buf, uint32_t length)
    {
        if(!buf) {
            return -ENODEV;
        }

        return ringbuffer_read(&mRb.channels[channel_index], (char*)buf, length);
    }
  
    int32_t write_channel(uint8_t channel_index, uint8_t *buf, uint32_t length)
    {
        int rc = 0;
        if(!buf) {
            return -ENODEV;
        }

        rc = ringbuffer_write(&mRb.channels[channel_index], (char*)buf, length);

        // return bytes read or negative number for error
        return rc;
    }
   
    struct ringbuffer_t mRb;
    struct ringbuffer_channel_t mChannels[2];
    
    std::mutex mReadLock;
    std::mutex mWriteLock;
    bool mServer;
};

#endif //RINGBUF__H
/*
 * Local variables:
 * mode: C++
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */  
