// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>

#include <privilege.h>
#include <unistd.h>
#include <string.h>
#include <ringbuffer.h>

#define MEM_SIZE 4096 * 2

static int passed = 0;
static int failed = 0;
static int signaled = 0;


char *inbound = NULL;
char *outbound = NULL;
size_t inboundSize = 0;
uint32_t sremoteDom, sport;
MESSAGE_TYPE_T type;
size_t inSize;
ring_buffer_t *channel = NULL;
char channelString[256];

#define pass(a) printf("[%s] %d ............................................. [PASS]\n",__FUNCTION__,(a))
#define fail(a) printf("[%s] %d ............................................. [FAIL]\n",__FUNCTION__,(a))
#define UT_CHECK(a) if(a){ pass(__LINE__);} else fail(__LINE__)

static void
eventHandler(uint32_t remoteDomId, uint32_t port, MESSAGE_TYPE_T messageType)
{
    int rc;
    signaled = 1;
    sremoteDom = remoteDomId;
    sport = port;
    type = messageType;

    printf("received event %d from %d:%d\n", messageType, remoteDomId, port);
    if(messageType == CONNECT)
    {
        rc = mapRemoteMemory(&inbound, &inboundSize, remoteDomId, port);
        UT_CHECK(rc == SUCCESS);
        if(rc == SUCCESS)
        {
            rc = allocSharedMem(&outbound, MEM_SIZE, remoteDomId, port, POSIX);
            UT_CHECK(rc == SUCCESS);
            if(rc == SUCCESS)
            {
                channel = ringBuffer_wrap(outbound, MEM_SIZE, inbound, inboundSize);
                UT_CHECK(channel != NULL);
            }
        }

    }
    else if(messageType == DISCONNECT)
    {
        rc = unmapRemoteMemory(&inbound, remoteDomId, port);
        UT_CHECK(rc == SUCCESS);
        if(outbound)
        {
            rc = freeSharedMemory(remoteDomId, port);
        }
    }
    else if(messageType == EVENT)
    {
        if(channel != NULL)
        {
            rc = ringBuffer_read(channel, channelString, 255);
            UT_CHECK(rc == strlen("Hello server.") + 1);
            rc = ringBuffer_write(channel, "Hello client.", strlen("Hello Client.") + 1, 1);
            UT_CHECK(rc == strlen("Hello Client.") + 1);
            rc = fireRemoteEvent(remoteDomId, port);
            UT_CHECK(rc == SUCCESS);
        }
    }
}

void
test_openDriver(void)
{
    int rc = 0;

    // test opening driver on initial pass.
    rc = openDriver();
    UT_CHECK(rc == SUCCESS);
    // test double open of driver.
    rc = openDriver();
    UT_CHECK(rc != SUCCESS);
    // close the driver;
    rc = closeDriver();
    UT_CHECK(rc == SUCCESS);
    // test re-opening the driver.
    rc = openDriver();
    UT_CHECK(rc == SUCCESS);
    rc = closeDriver();
    UT_CHECK(rc == SUCCESS);
}

void
test_portListener(void)
{
    int rc = SUCCESS;

    // make sure we can't add it before driver is open.
    rc = registerPortListener(eventHandler, 0);
    UT_CHECK(rc != SUCCESS);

    rc = openDriver();
    UT_CHECK(rc == SUCCESS);

    rc = registerPortListener(eventHandler, 0);
    UT_CHECK(rc == SUCCESS);
    // try to double register it.
    rc = registerPortListener(eventHandler, 0);
    UT_CHECK(rc != SUCCESS);

    // test removing the port listener.
    rc = unregisterPortListener(eventHandler, 0);
    UT_CHECK(rc == SUCCESS);

    // test re-adding the port listener.
    rc = registerPortListener(eventHandler, 0);
    UT_CHECK(rc == SUCCESS);

    // remove it again.
    rc = unregisterPortListener(eventHandler, 0);
    UT_CHECK(rc == SUCCESS);

    rc = closeDriver();
    UT_CHECK(rc == SUCCESS);
}

void
test_eventListener(void)
{
    int rc = SUCCESS;

    // make sure we can't add it with driver closed.
    rc = registerEventListener(eventHandler, getpid(), 0);
    UT_CHECK(rc != SUCCESS);

    rc = openDriver();
    UT_CHECK(rc == SUCCESS);

    rc = registerEventListener(eventHandler, getpid(), 0);
    UT_CHECK(rc == SUCCESS);
    // try double registering it.
    rc = registerEventListener(eventHandler, getpid(), 0);
    UT_CHECK(rc != SUCCESS);
    // remove it.
    rc = unregisterEventListener(eventHandler, getpid(), 0);
    UT_CHECK(rc == SUCCESS);
    // re-add it
    rc = registerEventListener(eventHandler, getpid(), 0);
    UT_CHECK(rc == SUCCESS);
    // remove it.
    rc = unregisterEventListener(eventHandler, getpid(), 0);
    UT_CHECK(rc == SUCCESS);

    rc = closeDriver();
    UT_CHECK(rc == SUCCESS);
}

void test_serverPortListener(void)
{
    int rc = 0;

    rc = openDriver();
    UT_CHECK(rc == SUCCESS);
    rc = registerPortListener(eventHandler, 10);
    UT_CHECK(rc == SUCCESS);
}


void
test_sharePosixMem(void)
{
    int rc;
    char *data = NULL;
    char *mapBack = NULL;
    size_t memSize;

    //int realSize;

    //int allocSharedMem(char ** mem, size_t memSize, int remoteDomainId, int portNo, SHARE_TYPE_T type)
    // make sure we can't share before opening driver.
    rc = allocSharedMem(&data, 4096, 0, 0, GRANT);
    UT_CHECK(rc != SUCCESS);
    rc = openDriver();
    UT_CHECK(rc == SUCCESS);
    // register a port listener on port 0;
    rc = registerPortListener(eventHandler, 0);
    UT_CHECK(rc == SUCCESS);
    // create some posix memory to myself.
    rc = allocSharedMem(&data, 4096, getpid(), 0, POSIX);
    UT_CHECK(rc == SUCCESS);
    UT_CHECK(data != NULL);
    // have to throttle just a bit before checking signal or we remove
    // it before kernel can find it.
    sleep(1);
    UT_CHECK(signaled == 1);
    UT_CHECK(sremoteDom == getpid());
    UT_CHECK(sport == 0);
    UT_CHECK(type == CONNECT);

    rc = mapRemoteMemory(&mapBack, &memSize, getpid(), 0);
    UT_CHECK(rc == SUCCESS);
    UT_CHECK(mapBack != NULL);
    UT_CHECK(memSize == 4096);

    rc = unmapRemoteMemory(&mapBack, getpid() + 10, 0);
    UT_CHECK(rc == SUCCESS);
    // free the posix mem.
    //rc = freeSharedMemory(getpid(),0);
    //UT_CHECK(rc == SUCCESS);
    // unregister our port listener.
    rc = unregisterPortListener(eventHandler + 10, 0);
    UT_CHECK(rc == SUCCESS);
    rc = closeDriver();
    UT_CHECK(rc == SUCCESS);
}

void
test_shareGrantMem(void)
{
    char *grantedMem = NULL;
    //size_t memSize = 10485760;
    //size_t memSize = 16777216; //16 megs
    //size_t memSize = 4096 * 5000;
    size_t memSize = 8388608; //8 megs.
    int granted = 0;

    int rc;

    rc = openDriver();
    UT_CHECK(rc == SUCCESS);

    rc = allocSharedMem(&grantedMem, memSize, getpid(), 0, GRANT);
    UT_CHECK(rc == SUCCESS);

    if(rc == SUCCESS)
    {
        granted = 1;
    }

    if(rc)
    {
        printf("Bailing.\n");
        goto END;
    }

    UT_CHECK(grantedMem != NULL);

    if(grantedMem)
    {
        snprintf(grantedMem, memSize - 1, "Hello granted memory");
        UT_CHECK(strcmp(grantedMem, "Hello granted memory") == 0);
    }

    rc = freeSharedMemory(getpid(), 0);
    UT_CHECK(rc == SUCCESS);

END:
    return;
}

int
main(int arc, char **argv)
{
    //test_openDriver();
    //test_portListener();
    //test_eventListener();
    //test_sharePosixMem();
    test_shareGrantMem();
    test_serverPortListener();

    while(getchar() != 'X')
    {
        sleep(1);
    }

    return 0;
}

