// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

/*
 * The simplest possible example I can think of for sharing memory and using a ring buffer between a server
 * and a client. In this case POSIX.
 */
#include <stdio.h>
#include <stdlib.h>

#include <privilege.h>
#include <unistd.h>
#include <string.h>
#include <ringbuffer.h>
#include <pthread.h>

#define MEM_SIZE 4096

typedef struct domInfo
{
    uint32_t remoteDomId;
    uint32_t port;
} domInfo_t;

char *inbound = NULL;
char *outbound = NULL;
SHARE_TYPE_T inboundType;
size_t inboundSize = 0;
size_t inSize;
ring_buffer_t *channel = NULL;
pthread_mutex_t lock;
uint8_t keepWorking = 0;
uint8_t isEchoing = 0;
int port;

static void
printUsage(void)
{
    printf("Usage: \n");
    printf("\tsudo ./server -p <listener port number>\n");
}

void*
echoChannelData(void *info)
{
    int numRead = 0;
    int numWritten = 0;
    unsigned char data[1024];
    domInfo_t *domInfo = (domInfo_t *) info;
    uint32_t flags = 0;

    printf("Unsetting channel flags.\n");
    ringBuffer_setFlags(channel, 0);

    printf("In echoChannelData\n");
    while(keepWorking)
    {
        if(ringBuffer_available(channel))
        {
            memset(data, 0, 1024);
            numWritten = 0;

            numRead = ringBuffer_read(channel, data, 1024);

            // echo back to ringbuffer.
            while(numWritten < numRead)
            {
                numWritten += ringBuffer_write(channel, data + numWritten,
                                               numRead - numWritten, 0);
                flags = ringBuffer_getFlags(channel);
                if(flags & RB_ENABLE_EVENTS)
                {
                    printf("[ivc]: firing remote event.\n");
                    fireRemoteEvent(domInfo->remoteDomId, domInfo->port);
                }
            }
        }
    }
    free(domInfo);
    domInfo = NULL;
}


// callback used by register port listener.  Whenever someone tries to connect,  this gets called.
static void
eventHandler(uint32_t remoteDomId, uint32_t port, MESSAGE_TYPE_T messageType)
{
    int rc;
    // the CONNECT message is a client has share memory to us.  we will map that memory in
    // to make sure it's successful and then share back to them.  When we map memory in,
    // we don't know or care what type it is at this point,  just that it's ready.
    if(messageType == CONNECT)
    {
        printf("Connection request received from %d:%d\n", remoteDomId, port);
        // send a call to the driver to map in the remotely shared memory.
        // inbound memory may only be read,  never written
        rc = mapRemoteMemory(&inbound, &inboundSize, &inboundType, remoteDomId, port);
        printf("Mapped in %d bytes of memory from remote call rc = %d.\n", inboundSize, rc);

        if(rc == SUCCESS)
        {
            printf("Sharing memory to client %d:%d, type %s\n", remoteDomId,
                   port, inboundType == GRANT ? "Grant" : "Posix");
            // we will request that the driver share back some memory to the remote connection.
            rc = allocSharedMem(&outbound, inboundSize, remoteDomId, port, inboundType);
            // make sure we could allocate it and share it back.
            if(rc == SUCCESS)
            {
                printf("memory granted, creating ring buffer channel.\n");
                // we now have our inbound buffer which is read only from the map,
                // and our outbound buffer which is read/write which we own ourselves from the allocSharedMem call.
                // We may now create a ring buffer from it.
                channel = ringBuffer_wrap(outbound, inboundSize, inbound, inboundSize);
                // if the channel is NULL,  either we are out of memory,  or our sizes are bad.
                if(channel == NULL)
                {
                    printf("Error, out of memory or MEM_SIZE is too small!\n");
                    return;
                }
                printf("Setting enable events flags.\n");
                ringBuffer_setFlags(channel, RB_ENABLE_EVENTS);
            }
            else
            {
                printf("Failed to share memory to %d:%d\n", remoteDomId, port);
            }
        }

    }
    // DISCONNECT means the remote connection is being ended.  We need to unmap the remote memory,  and free our share.
    else if(messageType == DISCONNECT)
    {
        printf("Disconnect from %d:%d\n", remoteDomId, port);
        keepWorking = 0;
        rc = unmapRemoteMemory(&inbound, remoteDomId, port);
        if(outbound)
        {
            rc = freeSharedMemory(remoteDomId, port);
        }
        channel = NULL;
        isEchoing = 0;
    }
    // the client fired an event,  which for this demo tells us to read the ring buffer.
    else if(messageType == EVENT)
    {
        pthread_mutex_lock(&lock);
        if(!isEchoing && channel != NULL)
        {
            isEchoing = 1;
            domInfo_t *domInfo = malloc(sizeof(domInfo_t));
            if(!domInfo)
            {
                printf("out of memory.\n");
                exit(0);
            }
            domInfo->remoteDomId = remoteDomId;
            domInfo->port = port;
            pthread_t echoThread;
            keepWorking = 1;
            pthread_create(&echoThread, NULL, echoChannelData, (void *) domInfo);
            pthread_detach(echoThread);
        }
        pthread_mutex_unlock(&lock);
    }
}

int
main(int argc, char **argv)
{
    int rc = 0;
    extern char *optarg;
    extern int optind, optopt;

    if(pthread_mutex_init(&lock, NULL) != 0)
    {
        printf("Mutex init failed.\n");
        return 1;
    }

    optind = opterr = 0;

    // get the command line options and parse them.
    while((rc = getopt(argc, argv, "p:")) != -1)
    {
        printf("rc = %c\n", rc);
        switch(rc)
        {
            case 'p':
                port = atoi(optarg);
                break;
            default:
                printUsage();
                return -1;
        }
    }

    if(port < 1)
    {
        printUsage();
        return -1;
    }

    // open the driver,  or nothing works.
    rc = openDriver();
    if(rc != SUCCESS)
    {
        return -1;
    }

    // register a port listener on port 10.
    // when the client connects to the server on port 10
    // the event handler will share a buffer back to the client
    // so that a ring buffer can be setup between the two.
    printf("Opening listener on port %d.\n", port);
    rc = registerPortListener(eventHandler, port);

    if(rc != SUCCESS)
    {
        return -2;
    }

    printf("Enter X to quit the server....\n");
    while(getchar() != 'X')
    {
        sleep(1);
    }

    rc = unregisterPortListener(10);
    rc = closeDriver();
    return 0;
}

