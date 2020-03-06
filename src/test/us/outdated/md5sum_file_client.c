// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <privilege.h>
#include <ringbuffer.h>
#include <string.h>

#ifdef __linux
#include <unistd.h>
#include <openssl/md5.h>
#include <pthread.h>
MD5_CTX mdContext;
MD5_CTX inContext;
pthread_mutex_t lock;
#define THREAD_RET void*
#else
#include <Windows.h>
#include <WinCrypt.h>
#include <process.h>
#include "wingetopt.h"
#define MD5_DIGEST_LENGTH 16
#define sleep Sleep
HCRYPTPROV hProv = 0;
HCRYPTHASH hHash = 0;
HANDLE lock;
DWORD dwLength = MD5_DIGEST_LENGTH;
#define THREAD_RET void
#endif

unsigned char infileCSum[MD5_DIGEST_LENGTH];
unsigned char c[MD5_DIGEST_LENGTH];
size_t inSize;
SHARE_TYPE_T inShareType;
char *outMem = NULL, *inMem = NULL;
ring_buffer_t *channel = NULL;
char channelString[256];
int remoteDomId, port;
uint8_t shareType;
char *fileName;
size_t fileSize = 0;
uint32_t buffSize = 0;
uint32_t numIterations = 1;
size_t bytes;

int totalRead = 0;
int currRead = 0;
int i;
int keepWorking = 1;
int reading = 0;

static void
printUsage(void)
{
    printf("Usage: \n");
    printf("\tsudo ./client -t <p for posix, g for grant> -r <dom id, required for grant> -p <port number> -f <filename> -i <num iterations> -b <ring buffer size>\n");
}

// write the file to the simple_server to be echoed back to us.
THREAD_RET
writeFileToServer(void *unused)
{
    int i = 0;
    FILE *file;
    int totalWritten = 0;
    int buffWritten = 0;
    unsigned char fdata[1024];
    int rc;
    uint32_t space = 0;
    uint32_t flags = 0;

    printf("In write file.\n");
    memset(fdata, 0, 1024);
    // reopen the file.
    file = fopen(fileName, "rb");
    // read the file in and write to the ring buffer.
    while((bytes = fread(fdata, 1, 1024, file)) != 0)
    {
        while(buffWritten < bytes)
        {
            // if a write was short we need to add to the position of the data from last
            // write and subtract from size being written.
            i = ringBuffer_write(channel, fdata + buffWritten, (uint32_t)(bytes - buffWritten), 0);
            if(i > 0)
            {
                buffWritten += i;
                totalWritten += i;
            }

            space = ringBuffer_space(channel);

            if(space == 0)
            {
                flags = ringBuffer_getFlags(channel);
                if(flags & RB_ENABLE_EVENTS)
                {
                    rc = fireRemoteEvent(remoteDomId, port);
                    if(rc != SUCCESS)
                    {
                        printf("Failing to fire remote event to %d:%d\n", remoteDomId, port);
                        exit(-1);
                    }
                }
            }
        }
        buffWritten = 0;
    }
    fclose(file);
}

void
launchWriteThread(void)
{
    int rc = 0;
#ifdef __linux
    pthread_t writeThread;
    rc = pthread_create(&writeThread, NULL, writeFileToServer, NULL);
    if(rc)
    {
        printf("Failed to launch write thread.\n");
        return;
    }
    else
    {
        pthread_detach(writeThread);
    }
#else
    _beginthread(writeFileToServer, 0, NULL);
#endif
}

THREAD_RET
readFileFromServer(void *unused)
{
    int totalRead = 0;
    uint32_t avail = 0;
    unsigned char data[1024];
    int totalIterations = numIterations;

    // go into polling mode.
    ringBuffer_setFlags(channel, 0);

    printf("in read file.\n");
    while(keepWorking)
    {
        if(totalRead == 0)
        {
#ifdef __linux
            MD5_Init(&inContext);
#else
            if(!CryptAcquireContext(&hProv, NULL, NULL,
                                    PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
            {
                int rc = GetLastError();
                printf("CryptAcquireContext failed. 0x%0x\n", rc);
                exit(-1);
            }

            if(!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
            {
                int rc = GetLastError();
                printf("CryptCreateHash failed. 0x%0x\n", rc);
                CryptReleaseContext(hProv, 0);
                exit(-1);
            }
#endif
        }

        avail = ringBuffer_available(channel);

        while(avail > 0)
        {
            memset(data, 0, 1024);
            currRead = ringBuffer_read(channel, data, 1024);
            avail = ringBuffer_available(channel);

            totalRead += currRead;
            if(currRead > 0)
            {
#ifdef __linux
                MD5_Update(&inContext, data, currRead);
#else
                if(!CryptHashData(hHash, data, currRead, 0))
                {
                    int rc = GetLastError();
                    printf("CrypHashData failed 0x%0x\n", rc);
                    CryptDestroyHash(hHash);
                    CryptReleaseContext(hProv, 0);
                    exit(0);
                }
#endif
            }
        }

        if(totalRead == fileSize)
        {
#ifdef __linux
            MD5_Final(infileCSum, &inContext);
#endif
            printf("Iteration[%d]: ", totalIterations - numIterations + 1);

            for(i = 0; i < MD5_DIGEST_LENGTH; i++)
            {
                printf("%02x", c[i]);
            }

            printf("\t");
            for(i = 0; i < MD5_DIGEST_LENGTH; i++)
            {
                printf("%02x", infileCSum[i]);
            }

            if(strncmp(infileCSum, c, MD5_DIGEST_LENGTH) == 0)
            {
                printf("\tChecksums match\n");
            }
            else
            {
                printf("\t*****Checksum fail******\n");
            }

            numIterations--;
            if(numIterations > 0 && keepWorking)
            {
                launchWriteThread();
            }
            totalRead = 0;
#ifdef WIN32
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
#endif
        }
    }
}

void
eventListenerHandler(uint32_t remoteDomId, uint32_t port, MESSAGE_TYPE_T type)
{
    int rc;
    // the CONNECT event will be the remote server acknowledging the connection and sharing back
    // the read only buffer to us.
    if(type == CONNECT)
    {
        // map in their shared memory.
        printf("Got connect from remote.\n");
        printf("mapping in remote memory.\n");
        rc = mapRemoteMemory(&inMem, &inSize, &inShareType, remoteDomId, port);
        printf("rc from map = %d inMem = %p\n", rc, inMem);

        if(rc == SUCCESS)
        {
            // we now have the two halves of the bi-directional ringbuffer. wrap the pointers
            // and make sure we don't get a null return.
            printf("Creating ringbuffer.\n");
            channel = ringBuffer_wrap(outMem, buffSize, inMem, (uint32_t)inSize);
            if(channel != NULL)
            {
                ringBuffer_setFlags(channel, RB_ENABLE_EVENTS);
                printf("Launching write thread.\n");
                printf("space in rb = %d, avail = %d\n", ringBuffer_space(channel),
                       ringBuffer_available(channel));
                launchWriteThread();
            }
        }
    }
    // the server is disconnecting us.
    else if(type == DISCONNECT)
    {
        // the server disconnected before we did.
        printf("The remote server has disconnected us.\n");
        unmapRemoteMemory(&inMem, remoteDomId, port);
        numIterations = -1;
        keepWorking = 0;
    }
    // the remote server notified us to read our buffer.
    else if(type == EVENT)
    {
#ifdef __linux
        pthread_mutex_lock(&lock);
        if(!reading)
        {
            pthread_t readThread;
            pthread_create(&readThread, NULL, readFileFromServer, NULL);
            pthread_detach(readThread);
            reading = 1;
        }
        pthread_mutex_unlock(&lock);
#else
        WaitForSingleObject(lock, INFINITE);
        if(!reading)
        {
            _beginthread(readFileFromServer, 0, NULL);
            reading = 1;
        }
        ReleaseMutex(lock);
#endif

    }
}

int
main(int argc, char *argv[])
{
    int rc;
    extern char *optarg;
    extern int optind, optopt;
    FILE *file;
    int i;
    unsigned char data[1024];

    memset(data, 0, 1024);

#ifdef __linux
    if(pthread_mutex_init(&lock, NULL) != 0)
    {
        printf("Mutex init failed.\n");
        return 1;
    }
#else
    lock = CreateMutex(NULL, FALSE, NULL);
    if(lock == NULL)
    {
        printf("Mutex init failed.\n");
        return 1;
    }
#endif

    optind = opterr = 0;

    // get the command line options and parse them.
    while((rc = getopt(argc, argv, "t:r:p:f:i:b:")) != -1)
    {
        printf("rc = %c\n", rc);
        printf("optarg = %s\n", optarg);
        switch(rc)
        {
                // share type, p for POSIX, g for GRANT
            case 't':
                if(strcmp(optarg, "p") == 0)
                {
                    shareType = 0;
                }
                else if(strcmp(optarg, "g") == 0)
                {
                    shareType = 1;
                }
                else
                {
                    printUsage();
                    return -1;
                }
                break;
                // remote domain id arg
            case 'r':
                remoteDomId = atoi(optarg);
                break;
                // port number server is listening on.
            case 'p':
                port = atoi(optarg);
                break;
                // number of iterations to send data back and forth
            case 'i':
                numIterations = atoi(optarg);
                break;
                // size of ring buffer
            case 'b':
                buffSize = atoi(optarg);
                break;
                // file to use as test case.
            case 'f':
                fileName = optarg;
                break;
                // error
            default:
                printUsage();
                return -1;
        }
    }

    if(buffSize < 1 || numIterations < 1)
    {
        printUsage();
        return -1;
    }

    // generate the initial MD5 checksum for the file.
    file = fopen(fileName, "rb");
    if(file == NULL)
    {
        printf("%s could not be opened.\n", fileName);
        return -1;
    }

#ifdef __linux
    MD5_Init(&mdContext);
#else
    if(!CryptAcquireContext(&hProv, NULL, NULL,
                            PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        int rc = GetLastError();
        printf("CryptAcquireContext failed. 0x%0x\n", rc);
        return -1;
    }

    if(!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        int rc = GetLastError();
        printf("CryptCreateHash failed. 0x%0x\n", rc);
        CryptReleaseContext(hProv, 0);
        return -1;
    }
#endif

    while((bytes = fread(data, 1, 1024, file)) != 0)
    {
        fileSize += bytes;
#ifdef __linux
        MD5_Update(&mdContext, data, bytes);
#else
        if(!CryptHashData(hHash, data, (DWORD)bytes, 0))
        {
            int rc = GetLastError();
            printf("CryptHashData failed. %d\n", rc);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return -1;
        }
#endif
    }

    fclose(file);
#ifdef __linux
    MD5_Final(c, &mdContext);
#else
    if(!CryptGetHashParam(hHash, HP_HASHVAL, c, &dwLength, 0))
    {
        int rc = GetLastError();
        if(rc == ERROR_MORE_DATA);
        printf("CryptGetHashParam failed. %d dwLength = %d\n", rc, dwLength);
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
#endif

    printf("File size = %d\n", fileSize);
    printf("MD5 Checksum for file is: ");
    for(i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        printf("%02x", c[i]);
    }

    printf("\n");

    rc = openDriver();
    if(rc != SUCCESS)
    {
        printf("Failed to open driver, check that it's installed and you are running with sufficient privs.\n");
        return -1;
    }

    if(shareType == 0)
    {
#ifdef __linux
        remoteDomId = getpid();
#else
        printf("Posix shares not supported in Windows.\n");
        return 1;
#endif
    }

    // register an event listener so we can get notifications back from the server.
    rc = registerEventListener(eventListenerHandler, remoteDomId, port);
    if(rc != SUCCESS)
    {
        printf("Failed to register event listener,  bailing\n");
        closeDriver();
        return -2;
    }

    // create an outbound share to the remote server,  we can read and write to the outbound,  they may only read from it.
    rc = allocSharedMem(&outMem, buffSize, remoteDomId, port, shareType ? GRANT : POSIX);
    if(rc != SUCCESS)
    {
        printf("Failed to share memory.\n");
        return -3;
    }

    while(numIterations > 0)
    {
        sleep(1);
    }

    // end our share to the remote server.
    freeSharedMemory(remoteDomId, port);
    // close the driver.
    closeDriver();
#ifdef _WIN32
    CloseHandle(lock);
#endif
    return EXIT_SUCCESS;
}
