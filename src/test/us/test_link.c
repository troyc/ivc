// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

#include <libivc.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#ifdef __linux
#include <pthread.h>
#endif

static struct libivc_server *server = NULL;
static struct libivc_client *nextNode = NULL;
static uint8_t isHead = 0;
static uint8_t poll = 0;

void
client_disconnected(void *opaque, struct libivc_client *client)
{
    poll = 0;
    sleep(1);
    libivc_disconnect(client);
}

void*
poll_and_send_data(void *arg)
{
    size_t avail = 0;
    struct libivc_client *client = NULL;
    char *buff = NULL;
    int buffOffset = 0;
    size_t buffSize = 0;
    int rc;

    libivc_checkp(arg);

    client = (struct libivc_client *) arg;
    libivc_assert(libivc_isOpen(client));

    // allocate a buffer as big as the remote buffer. Going for speed on this one.
    libivc_assert_goto((rc = libivc_getRemoteBufferSize(client, &buffSize)) == SUCCESS, ERROR);
    buff = (char *) malloc(buffSize);
    libivc_checkp_goto(buff, ERROR);

    while(poll)
    {
        if(!nextNode)
        {
            sleep(1);
            continue;
        }
        libivc_assert_goto((rc = libivc_getAvailableData(client, &avail)) == SUCCESS, ERROR);
        if(avail > 0)
        {

        }
    }

    goto END;
ERROR:
    libivc_disconnect(client);
    if(buff)
    {

        free(buff);
    }
END:
    return NULL;
}

/*
 * Callback when remote dom fires an event to this dom clients port
 * Kicks off a thread to begin polling and writing data to the next node
 */
void
client_event_fired(void *opaque, struct libivc_client *client)
{
    int rc;

    libivc_info("Remote event fired to client.\n");
    // disable remote events while we go polling.
    libivc_disable_events(client);
    poll = 1;
#ifdef __linux
    pthread_attr_t attribs;
    pthread_t pollThread;

    pthread_attr_init(&attribs);
    libivc_info("Launching polling thread.\n");
    libivc_assert((rc = pthread_create(&pollThread, &attribs, poll_and_send_data, client)) == SUCCESS);
    // detach the thread so that it automatically cleans up OS resources on exit.
    // if you don't do this, or don't do clean them up later, you can run out of
    // the ability to run threads.
    pthread_detach(pollThread);
#endif
}

void
client_connected(void *opaque, struct libivc_client *newClient)
{

    uint16_t remoteDom, port;
    int rc;

    libivc_getRemoteDomId(newClient, &remoteDom);
    libivc_getport(newClient, &port);

    printf("New Client connected from %u:%u\n", remoteDom, port);
    libivc_register_event_callbacks(newClient, client_event_fired, client_disconnected, opaque);
}

int
main(int argc, char **argv)
{
    int rc = 0;

    libivc_assert((rc = libivc_startIvcServer(&server, 10, client_connected, NULL)) == SUCCESS);

    libivc_assert((rc = libivc_connect(&nextNode, 6, 10, 1)) == SUCCESS);

    printf("Enter 'X' followed by enter to exit.\n");
    while(getchar() != 'X')
    {
        sleep(1);
    }

    libivc_disconnect(nextNode);

    libivc_shutdownIvcServer(server);
}

