#ifndef RINGBUF__H
#define RINGBUF__H

extern "C" {
#include <ringbuffer.h>
#include <string.h>
#include <libivc_private.h>
}
#include <iostream>
#include <mutex>
#include <xen/be/RingBufferBase.hpp>
#define CLIENT_TO_SERVER_CHANNEL 0
#define SERVER_TO_CLIENT_CHANNEL 1

#define LOGLEVEL XenBackend::LogLevel::logDEBUG

class ringbuf {
public:
    ringbuf(uint8_t *buf, uint64_t len, bool server = true);
    ~ringbuf();

    bool getEventEnabled();
    
    int32_t write(uint8_t *buf, uint32_t len);
    int32_t bytesAvailableWrite();

    int32_t read(uint8_t *buf, uint32_t len);    
    int32_t bytesAvailableRead();
    void dump_headers();
    
private:
    uint8_t mWriteChannel;
    uint8_t mReadChannel;
    int32_t read_channel(uint8_t channel_index, uint8_t *buf, uint32_t length);
    int32_t write_channel(uint8_t channel_index, uint8_t *buf, uint32_t length);   
    struct ringbuffer_t mRb;
    struct ringbuffer_channel_t mChannels[2];
    
    std::mutex mReadLock;
    std::mutex mWriteLock;
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
