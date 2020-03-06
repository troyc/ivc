#ifndef __ringBuffer_h__
#define __ringBuffer_h__

// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

#ifdef __cplusplus
extern "C" {
#endif

#define RB_ENABLE_EVENTS 0x01

#ifdef KERNEL
#ifdef _WIN32
#include <ntddk.h>
    typedef UINT8 uint8_t;
    typedef UINT16 uint16_t;
    typedef UINT32 uint32_t;
    typedef UINT64 uint64_t;
	typedef INT16 int16_t;
#define MEM_TAG 'cviP'
#define malloc(x) ExAllocatePoolWithTag(NonPagedPool, x, MEM_TAG)
#define free(x) ExFreePoolWithTag(x,MEM_TAG)
#else
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/types.h>

#define malloc(x) vzalloc(x)
#define free(x) vfree(x)
#endif
#else
#include <stdint.h>
#endif

#ifndef min
#define min(a,b) ((a) < (b) ? a : b)
#endif

    struct ring_buffer;
    typedef struct ring_buffer ring_buffer_t;

    /**
     * Wraps the given pointers and initializes indexes for reading/writing on the local buffer.
     * @param localBuffer pointer to read/write memory owned by the local process.
     * @param localBuffLength length of buffer, must be able to cover the size of the internal ring buffer header.
     * @param remoteBuffer Read only pointer to memory from another domain/process. it's assumed the remote process/domain has setup the indexes and size.
     * @param size of the remote buffer, it needs to be large enough to hold the internal ring buffer header.
     * @return ring_buffer_t used for reading/writing, and space calls.
     */
    ring_buffer_t*
    ringBuffer_wrap(void *localBuffer, uint32_t localBuffLength, void *remoteBuffer,
                    uint32_t remoteBuffLength);

    /**
     * Sets the writable side indexes and lengths to zero, and frees up the structs associated with the
     * ringbuffer.
     * @param rb ring buffer created by ringBuffer_wrap
     */
    void ringBuffer_free(ring_buffer_t *rb);

    /**
     * reads data from the ring buffer into target, up to max amount targetSize or
     * available data from buffer if less than target size.
     * @param buffer the buffer created by the ringBuffer_wrap call.
     * @param target the target to write the data into.
     * @param targetSize the size of the target buffer.
     * @return size of data written into target.
     */
    size_t
    ringBuffer_read(ring_buffer_t *buffer, char *target, size_t targeSize);

    /**
     * Copies data from src to the buffer
     * @param buffer the ring buffer created by ringBuffer_wrap
     * @param src source of data to be written
     * @param srcLength length of data to write.
     * @param failOnShortage if set to non-zero, will not write data to buffer if there isn't enough space.,
     * otherwise it will write as much data as possible.
     * @return number of bytes written to buffer, or zero on failure.
     */
    size_t
    ringBuffer_write(ring_buffer_t *buffer, char *src, size_t srcLength, uint8_t failOnShortage);

    /**
     * Returns the amount of data available to read from the buffer.
     * @param buffer ring buffer created by ringBuffer_wrap.
     * @return number of bytes that can be read from the buffer.
     */
    size_t
    ringBuffer_available(ring_buffer_t *buffer);

    /**
     * Returns the number of bytes available for writing to the buffer.
     * @param buffer ring buffer created by ringBuffer_wrap.
     * @return number of bytes free for writing into the ring.
     */
    size_t
    ringBuffer_space(ring_buffer_t *buffer);

    /**
     * Sets the flags field in the ringbuffer. Other than predefined flags in this
     * header you are free to use this section for whatever you need
     * @param buffer the buffer to set the flags on.
     * @param flags value to set.
     */
    void ringBuffer_setFlags(ring_buffer_t *buffer, uint32_t flags);

    /**
     * retrieve flags set on the ring buffer.  If it's a channel buffer, will
     * return flags set by opposite end of channel.
     * @param buffer The ring buffer to read flags from.
     * @return The flags field of the ring buffer.
     */
    uint32_t ringBuffer_getFlags(ring_buffer_t *buffer);

    /**
     * @brief get the size of the data buffer after subtracting the header the api uses on top
     * of allocated memory for indexes and flags.
     * @param buffer the ringbuffer created by the wrap call.
     * @return size of data buffer, or zero if an issue.
     */
    size_t ringBuffer_getBufferSize(ring_buffer_t *buffer);

    /**
     * @brief Utility function to get how large the header is that is laid on top of memory when wrapped.
     * Since the details are hidden in the C program, sizeof(ring_buffer_t) does not return the true size.
     * @return real size of the internal structs used to store indexes and flags.
     */
    size_t ringBuffer_getHeaderSize(void);

#ifdef __cplusplus
}
#endif

#endif

