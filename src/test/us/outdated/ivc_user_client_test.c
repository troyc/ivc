// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <privilege.h>

#include <ringbuffer.h>
#include <string.h>
#define MEM_SIZE 4096 * 2

static uint8_t driverOpened = 0;
uint32_t remoteDomId = -1, port = -1, type = -1;
size_t inSize;
char *outMem, *inMem;
ring_buffer_t *channel = NULL;
char channelString[256];

#define pass(a) printf("[%s] %d ............................................. [PASS]\n",__FUNCTION__,(a))
#define fail(a) printf("[%s] %d ............................................. [FAIL]\n",__FUNCTION__,(a))
#define UT_CHECK(a) if(a){ pass(__LINE__);} else fail(__LINE__)

void eventListenerHandler(uint32_t remoteDomId, uint32_t port, MESSAGE_TYPE_T type)
{
    int rc;

    printf("Recevied event type %d from %d:%d\n", type, remoteDomId, port);
    if(type == CONNECT)
    {
        rc = mapRemoteMemory(&inMem, &inSize, remoteDomId, port);
        UT_CHECK(rc == SUCCESS);
        if(rc == SUCCESS)
        {
            channel = ringBuffer_wrap(outMem, MEM_SIZE, inMem, inSize);
            UT_CHECK(channel != NULL);
            if(channel != NULL)
            {
                rc = ringBuffer_write(channel, "Hello server.", strlen("Hello server.") + 1, 1);
                UT_CHECK(rc == strlen("Hello server.") + 1);
                rc = fireRemoteEvent(remoteDomId, port);
                UT_CHECK(rc == SUCCESS);
            }
        }
    }
    else if(type == DISCONNECT)
    {
        unmapRemoteMemory(&inMem, remoteDomId, port);
    }
    else if(type == EVENT)
    {
        if(channel != NULL)
        {
            rc = ringBuffer_read(channel, channelString, 255);
            UT_CHECK(rc == strlen("Hello Client.") + 1);
        }
    }

}

void test_openDriver(void)
{
    int rc;

    rc = openDriver();
    if(rc == SUCCESS)
    {
        driverOpened = 1;
    }
    UT_CHECK(rc == SUCCESS);
}


void test_closeDriver(void)
{
    int rc = 1;

    if(driverOpened)
    {
        rc = closeDriver();
    }

    UT_CHECK(rc == SUCCESS);
}

void test_posixShareMem(void)
{
    int rc;

    rc = allocSharedMem(&outMem, MEM_SIZE, getpid(), port, POSIX);
    UT_CHECK(rc == SUCCESS);
}

void test_posixUnshareMem(void)
{
    int rc;

    rc = freeSharedMemory(getpid(), port);
    UT_CHECK(rc == SUCCESS);
}

void test_registerEventDriver(void)
{
    int rc;

    rc = registerEventListener(eventListenerHandler, remoteDomId, port);
    UT_CHECK(rc == SUCCESS);
}


void printUsage(char *prog)
{
    fprintf(stderr, "Usage: %s [-d remote domain id] [-p port number] [-s <0 for grant, 1 for posix share>]\n", prog);
    fprintf(stderr, "\tPosix share only requires port number.\n");
    fprintf(stderr, "\tExample: sudo LD_LIBRARY_PATH=../../us bin/client -s0 -d19 -p80\n");
    fprintf(stderr, "\t\tShares grant memory to domain 19 on port 80.\n");
    fprintf(stderr, "\tExample: sudo LD_LIBRARY_PATH=../../us bin/client -s1 -p80\n");
    fprintf(stderr, "\t\tShares posix memory to local domain on port 80.\n");
}

int
main(int argc, char *argv[])
{
    int flags = -1, opt = -1;
    int numIterations;

    while((opt = getopt(argc, argv, "d::p:s:")) != -1)
    {
        switch(opt)
        {
            case 'd':
                remoteDomId = atoi(optarg);
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 's':
                type = atoi(optarg);
                break;
            default:
                printUsage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    printf("remote domain = %d port = %d share type = %d\n", remoteDomId, port, type);

    if((type < 0 || type > 1) || (port < 0) || (type == 0 && remoteDomId < 0))
    {
        printUsage(argv[0]);
        exit(EXIT_FAILURE);
    }

    test_openDriver();
    if(! driverOpened)
    {
        printf("Failed to open driver. testing aborted.\n");
        return -1;
    }

    if(type == 1)
    {
        remoteDomId = getpid();
    }
    test_registerEventDriver();

    if(type == 1)
    {
        test_posixShareMem();
    }

    while(getchar() != 'X')
    {
        sleep(1);
    }
    if(type == 1)
    {
        test_posixUnshareMem();
    }
    test_closeDriver();
    return EXIT_SUCCESS;
}
