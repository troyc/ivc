// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

// ============================================================================
// Includes
// ============================================================================
#include <ringbuffer.h>

#define ENOMEM 12
#define ENODEV 19
#define EINVAL 22
#define EFBIG  27

#define INT_MAX 2147483647

#if defined(__linux__)
 #if defined(__i386__) || defined(__x86_64__)
  #define ring_mb() asm volatile ("mfence" : : : "memory")
 #else /* !__i386__ || !__x86_64__ */
  #define ring_mb()
  #warning "Memory barriers not implemented for this architecture."
 #endif
#elif defined(_WIN32)
 #if defined(KERNEL)
  #include <wdm.h>
  #define ring_mb() KeMemoryBarrier()
 #else /* !KERNEL */
  #include <windows.h>
  #define ring_mb() MemoryBarrier()
 #endif
#endif

// ============================================================================
// Channel Functions
// ============================================================================

int ringbuffer_channel_create(struct ringbuffer_channel_t *channel, int32_t length)
{
    int32_t struct_size = sizeof(struct ringbuffer_header_t);

    if(channel == 0) return -EINVAL;

    ringbuffer_channel_destroy(channel);

    if(length <= struct_size) return -EINVAL;
    if(length >= INT_MAX / 2) return -EINVAL;

    channel->buffer = 0;
    channel->buffer_length = length;
    channel->header = 0;
    channel->header_length = struct_size;
    channel->body = 0;
    channel->body_length = channel->buffer_length - channel->header_length;

    return 0;
}

int ringbuffer_channel_destroy(struct ringbuffer_channel_t *channel)
{
    if(channel == 0) return -EINVAL;

    channel->buffer = 0;
    channel->buffer_length = 0;
    channel->header = 0;
    channel->header_length = 0;
    channel->body = 0;
    channel->body_length = 0;

    return 0;
}

int32_t ringbuffer_channel_length(struct ringbuffer_channel_t *channel)
{
    if(channel == 0) return -EINVAL;

    return channel->body_length;
}

// ============================================================================
// Ringbuffer Functions
// ============================================================================

int ringbuffer_use(struct ringbuffer_t *handle)
{
    char *buffer = 0;

    int32_t i = 0;
    int32_t total = 0;

    if(handle == 0) return -EINVAL;
    if(handle->buffer == 0) return -EINVAL;
    if(handle->length == 0) return -EINVAL;
    if(handle->num_channels == 0) return -EINVAL;
    if(handle->channels == 0) return -EINVAL;

    for(i = 0; i < handle->num_channels; i++)
    {
        if(handle->channels[i].buffer_length == 0) return -ENODEV;
        if(handle->channels[i].header_length == 0) return -ENODEV;
        if(handle->channels[i].body_length == 0) return -ENODEV;

        total += handle->channels[i].buffer_length;
    }

    if(total > handle->length) return -ENOMEM;

    buffer = handle->buffer;

    for(i = 0; i < handle->num_channels; i++)
    {
        handle->channels[i].buffer = buffer;
        handle->channels[i].header = (struct ringbuffer_header_t *)buffer;
        handle->channels[i].body = buffer + handle->channels[i].header_length;

        buffer += handle->channels[i].buffer_length;
    }


    return 0;
}

int ringbuffer_create(struct ringbuffer_t *handle)
{
    int rc;
    int32_t i = 0;

    rc = ringbuffer_use(handle);
    if(rc) return rc;

    for(i = 0; i < handle->length; i++)
        handle->buffer[i] = 0;

    return 0;
}

int ringbuffer_destroy(struct ringbuffer_t *handle)
{
    int32_t i = 0;

    if(handle == 0) return -EINVAL;

    if(handle->channels != 0)
    {
        for(i = 0; i < handle->num_channels; i++)
            ringbuffer_channel_destroy(&handle->channels[i]);
    }

    for(i = 0; i < handle->length; i++)
        handle->buffer[i] = 0;

    return 0;
}


static inline
int32_t bytes_available_read(unsigned int rloc, unsigned int lloc, unsigned int length)
{
    if (rloc >= lloc)
        return rloc - lloc;
    else
        return length - lloc + rloc;
}

static inline
int32_t bytes_available_write(unsigned int rloc, unsigned int lloc, unsigned int length)
{
    if (rloc >= lloc)
        return length - rloc + lloc - 1;
    else
        return lloc - rloc - 1;
}

int32_t ringbuffer_read(struct ringbuffer_channel_t *channel, char *buffer, int32_t length)
{
    int32_t bytes_available, bytes_to_read;
    int32_t lloc, rloc;

    if(channel == 0) return -EINVAL;
    if(buffer == 0) return -EINVAL;
    if(channel->header == 0) return -ENODEV;
    if(channel->body == 0) return -ENODEV;
    if(length > channel->body_length - 1) return -EFBIG;

    lloc = channel->header->lloc;
    rloc = channel->header->rloc;
    ring_mb(); // Read indexes before consuming data.

    bytes_available = bytes_available_read(rloc, lloc, channel->body_length);
    bytes_to_read = (bytes_available < length) ? bytes_available : length;

    if(bytes_to_read <= 0) return bytes_to_read;

    if(lloc + bytes_to_read <= channel->body_length)
    {
        int32_t i = 0;
        char *read_buffer = channel->body + lloc;
        char *write_buffer = buffer;

        for(i = 0; i < bytes_to_read; i++)
            write_buffer[i] = read_buffer[i];
    }
    else
    {
        int32_t i = 0;
        int32_t len1 = channel->body_length - lloc;
        int32_t len2 = bytes_to_read - len1;
        char *read_buffer1 = channel->body + lloc;
        char *read_buffer2 = channel->body;
        char *write_buffer1 = buffer;
        char *write_buffer2 = buffer + len1;

        for(i = 0; i < len1; i++)
            write_buffer1[i] = read_buffer1[i];

        for(i = 0; i < len2; i++)
            write_buffer2[i] = read_buffer2[i];
    }
    ring_mb(); // Update read-index only when data has been consumed.
    channel->header->lloc = (lloc + bytes_to_read) % channel->body_length;
    return length;
}

int32_t ringbuffer_write(struct ringbuffer_channel_t *channel, char *buffer, int32_t length)
{
    int32_t bytes_available, bytes_to_write;
    int32_t rloc, lloc;

    if(channel == 0) return -EINVAL;
    if(buffer == 0) return -EINVAL;
    if(channel->header == 0) return -ENODEV;
    if(channel->body == 0) return -ENODEV;
    if(length > channel->body_length - 1) return -EFBIG;

    rloc = channel->header->rloc;
    lloc = channel->header->lloc;
    ring_mb(); // Read indexes before writing data.

    bytes_available = bytes_available_write(rloc, lloc, channel->body_length);
    bytes_to_write = (bytes_available > length) ? length : bytes_available;

    if(bytes_to_write <= 0) return bytes_to_write;

    if(rloc + bytes_to_write <= channel->body_length)
    {
        int32_t i = 0;
        char *read_buffer = buffer;
        char *write_buffer = channel->body + rloc;

        for(i = 0; i < bytes_to_write; i++)
            write_buffer[i] = read_buffer[i];
    }
    else
    {
        int32_t i = 0;
        int32_t len1 = channel->body_length - rloc;
        int32_t len2 = bytes_to_write - len1;
        char *read_buffer1 = buffer;
        char *read_buffer2 = buffer + len1;
        char *write_buffer1 = channel->body + rloc;
        char *write_buffer2 = channel->body;

        for(i = 0; i < len1; i++)
            write_buffer1[i] = read_buffer1[i];

        for(i = 0; i < len2; i++)
            write_buffer2[i] = read_buffer2[i];
    }

    ring_mb(); // Update write-index only when data is available.
    channel->header->rloc = (rloc + bytes_to_write) % channel->body_length;
    return bytes_to_write;
}

void ringbuffer_clear_buffer(struct ringbuffer_channel_t *channel)
{
    if (channel == 0) return;
    if (channel->header == 0) return;

    ring_mb(); // Read write-index before update.
    channel->header->lloc = channel->header->rloc;
    ring_mb(); // Update read-index before it is read again.
}

int32_t ringbuffer_bytes_available_read(struct ringbuffer_channel_t *channel)
{
    unsigned int rloc, lloc;

    if(channel == 0) return -EINVAL;
    if(channel->header == 0) return -ENODEV;

    rloc = channel->header->rloc;
    lloc = channel->header->lloc;

    return bytes_available_read(rloc, lloc, channel->body_length);
}

int32_t ringbuffer_bytes_available_write(struct ringbuffer_channel_t *channel)
{
    unsigned int rloc, lloc;

    if (channel == 0) return -EINVAL;
    if (channel->header == 0) return -ENODEV;

    rloc = channel->header->rloc;
    lloc = channel->header->lloc;

    return bytes_available_write(rloc, lloc, channel->body_length);
}

void ringbuffer_set_flags(struct ringbuffer_channel_t *channel, uint32_t flags)
{
    if(channel == 0) return;
    if(channel->header == 0) return;

    channel->header->reserved1 = flags;
}

int32_t ringbuffer_get_flags(struct ringbuffer_channel_t *channel)
{
    int32_t flags;

    if(channel == 0) return -EINVAL;
    if(channel->header == 0) return -ENODEV;

    return channel->header->reserved1;
}
