#ifndef __RINGBUFFER_H__
#define __RINGBUFFER_H__

// 
// OpenXT Ring Buffer for the Inter-VM Communications (IVC) Library
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
// Author: Rian Quinn      <quinnr@ainfosec.com>
//

/**
 *
 * Ring Buffer Design
 * ------------------
 *
 * Each ring buffer that you create using this library is divided up into a
 * a set of channels. Each channels allows for reading / writing.
 *
 * -----------------------------------------------------------------------------
 * |               |                             |                             |
 * |   Channel 1   |          Channel 2          |          Channel 3          |
 * |               |                             |                             |
 * -----------------------------------------------------------------------------
 *
 * In other words, each ring buffer is really a collection of smaller ring
 * buffers (called a channel). Each channel can be a different size, and the
 * total number of channels is arbitrary.
 *
 * The ring buffer itself only requires a single char buffer, and some
 * information about how to divide up that buffer for each channel.
 *
 *
 *
 * Setup
 * -----
 *
 * To create a ringbuffer, you need to first create each channel. Once each
 * channel is setup, you can then setup the ring buffer itself, which will
 * divide up the character buffer for each channel.
 *
 * @code
 *
 *  int c;
 *  char buffer[BUFFER_LENGTH];
 *  struct ringbuffer_t ringbuffer;
 *  struct ringbuffer_channel_t channels[NUM_CHANNELS];
 *
 *  ringbuffer.buffer = buffer;
 *  ringbuffer.length = BUFFER_LENGTH;
 *  ringbuffer.num_channels = NUM_CHANNELS;
 *  ringbuffer.channels = channels;
 *
 *  for (c = 0; c < NUM_CHANNELS; c++)
 *      ringbuffer_channel_create(&channels[c], CHANNEL_LENGTH);
 *
 *  ringbuffer_create(&ringbuffer);
 *
 * @endcode
 *
 *
 *
 * Teardown
 * --------
 *
 * The memory that is used by this ringbuffer is defined externally, which
 * means that it is perfectly ok to teardown the memory however you wish.
 * Normally this would means zeroing out the buffers (to prevent potentially
 * restricted data from being left in memory), and then clear out the channels.
 *
 * An alternative, is to simply run the following
 *
 * @code
 *
 * ringbuffer_destroy(&ringbuffer);
 *
 * @endcode
 *
 * Once you have destroyed the ringbuffer, you can free the memory as needed.
 *
 *
 *
 * Reading / Writing
 * -----------------
 *
 * Reading and writing to the ring buffer is very similar to the Linux read
 * and write functions. You need to provide the channel that you wish to
 * read / write too, and you need to provide your data buffer and length.
 *
 * @code
 *
 * int i;
 * bool result;
 * char data[LENGTH];
 *
 * for(i = 0; i < LENGTH; i++)
 *     data[i] = 0xA;
 *
 * ringbuffer_write(channels[0], data, LENGTH);
 *
 * for(i = 0; i < LENGTH; i++)
 *     data[i] = 0;
 *
 * ringbuffer_read(channels[0], data, LENGTH);
 *
 * result = true;
 * for(i = 0; i < LENGTH; i++)
 *     result &= (data[i] == 0xA);
 *
 * if(result == true)
 *     printf("success\n");
 * else
 *     printf("failure\n");
 *
 * @endcode
 *
 *
 *
 * Optimizations
 * -------------
 *
 * This ringbuffer was written in such a way that it only requires stdint.h and
 * errno.h. This provides a cleaner approach to compiling in different
 * environments, were functions like memcpy do not exist. The memcpy's that this
 * code use, are written using basic for loops, and care attention was taken
 * to make sure that they are easy for a compiler to detect. When compiling
 * this code, be sure to enable optimizations as the compiler will replace the
 * for loops with native memcpy's automatically.
 *
 * Also, if this code needs to be modified, be sure that the modifications
 * don't interrupt the compiler's ability to detect them as memcpy's.
 */

#ifndef KERNEL
#include <stdint.h>
#elif __linux
#include <linux/types.h>
#define malloc(x) vzalloc(x)
#define free(x) vfree(x)
#endif
#ifdef _WIN32
#ifdef KERNEL
#include <ntddk.h>
#define malloc(x) ExAllocatePoolWithTag(NonPagedPool, (size_t)x, (ULONG)'blah')
#define free(x) ExFreePoolWithTag(x, (ULONG)'blah')
typedef UINT8 uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
typedef INT32 int32_t;
typedef INT16 int16_t;
typedef INT64 int64_t;
#endif
#endif
#pragma pack(push, 1)

/**
 * Ringbuffer Header
 *
 * This is the header that is used by each channel. Note that this structure
 * should not be used directly, and is considered private.
 *
 * @var lloc left pointer in the channel's ring buffer.
 * @var rloc right pointer in the channel's ring buffer.
 */
struct ringbuffer_header_t
{
    int32_t lloc;
    int32_t rloc;

    int32_t reserved1;
    int32_t reserved2;
    int32_t reserved3;
    int32_t reserved4;
};

/**
 * Ringbuffer Channel
 *
 * This is the structure that defines a channel. Note that this structure
 * should not be used directly, and is considered private. The user will need
 * to create one of these structure for each channel that will be used, but
 * should not attempt to access the structures variables directly.
 *
 * @var buffer a pointer to the buffer used by this channel
 * @var buffer_length the total length of the buffer used by this channel
 * @var header a pointer to the header used by this channel
 * @var header_length the total length of the header used by this channel
 * @var body a pointer to the body used by this channel
 * @var body_length the total length of the body used by this channel
 */
struct ringbuffer_channel_t
{
    char *buffer;
    int32_t buffer_length;

    struct ringbuffer_header_t *header;
    int32_t header_length;

    char *body;
    int32_t body_length;
};

/**
 * Ringbuffer
 *
 * The following structure is used by the user to define the parameters
 * of the ring buffer. This structure should be created and filled in prior
 * to calling ringbuffer_channel_create.
 *
 * @var buffer a pointer to the buffer that should be used by the ring
 *      buffer. Note that the length of this buffer should be at least
 *      (channel length) * num_channels.
 * @var length the length of the buffer in bytes
 * @var num_channels the number of channels this ring buffer will use
 * @var channels a pointer to an array of channels.
 */
struct ringbuffer_t
{
    char *buffer;
    int32_t length;

    int32_t num_channels;
    struct ringbuffer_channel_t *channels;
};

typedef void (*print_fn)(const char *fmt, ...);
void dump_ringbuffer(struct ringbuffer_t *ringbuffer, print_fn fn);
void dump_ringbuffer_channel(struct ringbuffer_channel_t *channel, print_fn fn);

/**
 * Creates a ringbuffer channel. The channel structure itself should be
 * allocated prior to calling this function.
 *
 * Note that a portion of the channel's buffer that is defined by the length
 * field is consumed by the channel's header. Once the channel is created, you
 * can use the ringbuffer_channel_length function to get the size of the
 * channel that will actually be available for reading / writing.
 *
 * @param channel a pointer to the channel to create.
 * @param length the length in bytes that this channel should use.
 * @return -EINVAL if NULL is provided for the channel
 *         -EINVAL if no length is provided
 *         -EINVAL if the length provided is too small
 *         0 on success
 */
int ringbuffer_channel_create(struct ringbuffer_channel_t *channel, int32_t length);

/**
 * Destroys a ringbuffer channel. This function can be called manually but is
 * not needed if ringbuffer_destroy is called, as it will call this function
 * for you.
 *
 * @param channel a pointer to the channel to destory.
 * @return -EINVAL if NULL is provided for the channel
 *         0 on success
 */
int ringbuffer_channel_destroy(struct ringbuffer_channel_t *channel);

/**
 * Gets the available length of the channel for reading and writing. When you
 * create a channel, you must provide a length. A portion of the buffer that
 * the channel will use (defined by this length field) will however be
 * consumed by the header that the channel must use. This function exists so
 * that the user can identify how much space is left to be used for reading
 * and writing.
 *
 * @param channel a pointer to the channel.
 * @return -EINVAL if NULL is provided for the channel
 *         LENGTH in bytes on success
 */
int32_t ringbuffer_channel_length(struct ringbuffer_channel_t *channel);

/**
 * Creates a ringbuffer. Note that the ringbuffer structure should be allocated
 * and filled in prior to calling this function.
 *
 * @param handle a pointer to the ringbuffer
 * @return -EINVAL if NULL is proivded for the ringbuffer
 *         -EINVAL if NULL is provided for the buffer
 *         -EINVAL if 0 is provided for the buffer length
 *         -EINVAL if 0 is provided for the number of channels
 *         -EINVAL if NULL is provided for the channel array
 *         -ENODEV if a channel in the channel array is not properly created
 *         -ENOMEM if the buffer is too small for the channels provided
 *         0 on success
 */
int ringbuffer_create(struct ringbuffer_t *handle);

/**
 * Uses an existing ringbuffer; intended for conecting to a pre-existing
 * ringbuffer; e.g. one on othe other side of a shared memory collection.
 *
 * @param handle a pointer to the ringbuffer
 * @return -EINVAL if NULL is proivded for the ringbuffer
 *         -EINVAL if NULL is provided for the buffer
 *         -EINVAL if 0 is provided for the buffer length
 *         -EINVAL if 0 is provided for the number of channels
 *         -EINVAL if NULL is provided for the channel array
 *         -ENODEV if a channel in the channel array is not properly created
 *         -ENOMEM if the buffer is too small for the channels provided
 *         0 on success
 */
int ringbuffer_use(struct ringbuffer_t *handle);

/**
 * Destroys a ringbuffer.
 *
 * @param handle a pointer to the ringbuffer
 * @return -EINVAL if NULL is proivded for the ringbuffer
 *         0 on success
 */
int ringbuffer_destroy(struct ringbuffer_t *handle);

/**
 * Read from the ringbuffer
 *
 * Note that the user should ensure that the buffer is at least "length"
 * bytes in size.
 *
 * Note that it is possible that this function will not read the requested
 * "length" number of bytes if the total number of bytes available is less
 * than "length". Use ringbuffer_bytes_available_read to identify how many
 * bytes are available prior to reading.
 *
 * @param channel a pointer to the channel
 * @param buffer a pointer to a character buffer to read data into
 * @param length the number of bytes to read
 * @return -EINVAL if NULL is provided for the channel
 *         -EINVAL if NULL is provided for the buffer
 *         -ENODEV if the channel proivded is not properly created
 *         -EFBIG if the length provided is larger than the channel's buffer
 *         BYTES read on success
 */
int32_t ringbuffer_read(struct ringbuffer_channel_t *channel, char *buffer, int32_t length);

/**
 * Write to the ringbuffer
 *
 * Note that the user should ensure that the buffer is at least "length"
 * bytes in size.
 *
 * Note that it is possible that this function will not write the requested
 * "length" number of bytes if the total number of bytes available is less
 * than "length". Use ringbuffer_bytes_available_write to identify how many
 * bytes are available prior to writing.
 *
 * @param channel a pointer to the channel
 * @param buffer a pointer to a character buffer to write data from
 * @param length the number of bytes to write
 * @return -EINVAL if NULL is provided for the channel
 *         -EINVAL if NULL is provided for the buffer
 *         -ENODEV if the channel proivded is not properly created
 *         -EFBIG if the length provided is larger than the channel's buffer
 *         BYTES read on success
 */
int32_t ringbuffer_write(struct ringbuffer_channel_t *channel, char *buffer, int32_t length);

/**
 * Bytes Available to Read from the Ringbuffer
 *
 * @param channel a pointer to the channel
 * @return -EINVAL if NULL is provided for the channel
 *         -ENODEV if the channel proivded is not properly created
 *         BYTES available on success
 */
int32_t ringbuffer_bytes_available_read(struct ringbuffer_channel_t *channel);

/**
 * Bytes Available to Write to the Ringbuffer
 *
 * @param channel a pointer to the channel
 * @return -EINVAL if NULL is provided for the channel
 *         -ENODEV if the channel proivded is not properly created
 *         BYTES available on success
 */
int32_t ringbuffer_bytes_available_write(struct ringbuffer_channel_t *channel);

/**
 * Set flags on a ringbuffer channel.
 *
 * @param channel a pointer to the channel
 * @param flags value to set flags to
 */
void ringbuffer_set_flags(struct ringbuffer_channel_t *channel, uint32_t flags);

/**
 * Get flags on a ringbuffer channel.
 *
 * @param channel a pointer to the channel
 */
int32_t ringbuffer_get_flags(struct ringbuffer_channel_t *channel);

void ringbuffer_clear_buffer(struct ringbuffer_channel_t *channel);
#pragma pack(pop)
#endif
