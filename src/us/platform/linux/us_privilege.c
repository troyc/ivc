// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <libivc_private.h>
#include <libivc.h>
#include <platform_defs.h>
#include <libivc_debug.h> // for libivc_<debug> prints
#include <sys/ioctl.h> // for ioctls
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/poll.h>
#include <sys/shm.h>
#include <unistd.h>
#include <sys/types.h>

#define DRIVER_PATH "/dev/ivc"
static int driverFd = -1;

// create the function prototypes for the required platform callbacks that ivc needs.
int
us_register_server_listener(struct libivc_server *server);

int
us_unregister_server_listener(struct libivc_server * server);

int
us_notify_remote(struct libivc_client * ivc);

int
us_ivc_connect(struct libivc_client *ivc);

int
us_ivc_reconnect(struct libivc_client *ivc, uint16_t new_domid, uint16_t new_port);

int
us_ivc_disconnect(struct libivc_client * ivc);

int
libivc_platform_init(platform_functions_t * pf);

void
populate_cli(struct libivc_client_ioctl_info *cli_info, struct libivc_client *client);

void
update_client(struct libivc_client_ioctl_info *cli_info, struct libivc_client *client);

void
populate_serv(struct libivc_server_ioctl_info *serv_info, struct libivc_server *server);


/**
 *  Set fields in the client_info struct to pass with ioctl.
 *  @param cli_info  Specialized struct to hold client information for ioctl
 *  @param client  The libivc_client
 */
void
populate_cli(struct libivc_client_ioctl_info *cli_info, struct libivc_client *client)
{

    cli_info->port = client->port;
    cli_info->client_notify_event = client->client_notify_event;
    cli_info->client_disconnect_event = client->client_disconnect_event;
    cli_info->buffer = client->buffer;
    cli_info->num_pages = client->num_pages;
    cli_info->remote_domid = client->remote_domid;
    cli_info->server_side = client->server_side;
    cli_info->callback_list = client->callback_list;
    cli_info->opaque = client->opaque;
    cli_info->connection_id = client->connection_id;
}

void
update_client(struct libivc_client_ioctl_info *cli_info, struct libivc_client *client)
{

    client->port = cli_info->port;
    client->client_notify_event = cli_info->client_notify_event;
    client->client_disconnect_event = cli_info->client_disconnect_event;
    client->buffer = cli_info->buffer;
    client->num_pages = cli_info->num_pages;
    client->remote_domid = cli_info->remote_domid;
    client->server_side = cli_info->server_side;
    client->callback_list = cli_info->callback_list;
    client->opaque = cli_info->opaque;
    client->connection_id = cli_info->connection_id;
}

void populate_serv(struct libivc_server_ioctl_info *serv_info, struct libivc_server *server)
{
    serv_info->port = server->port;
    serv_info->limit_to_domid = server->limit_to_domid;
    serv_info->limit_to_connection_id = server->limit_to_connection_id;
    serv_info->client_connect_event = server->client_connect_event;
    serv_info->opaque = server->opaque;
}

//************************* Function implementations. **************************

/**
 * Initializes the function callbacks to the LINUX userspace APIs and opens the
 * driver.
 * @param pf The libivc core platform struct 
 * @return SUCCESS, or appropriate error number.
 */
int
libivc_platform_init(platform_functions_t * pf)
{

    // check the pointer and return if NULL;
    libivc_checkp(pf, INVALID_PARAM);

    pf->connect = us_ivc_connect;
    pf->disconnect = us_ivc_disconnect;
    pf->reconnect = us_ivc_reconnect;
    pf->notifyRemote = us_notify_remote;
    pf->registerServerListener = us_register_server_listener;
    pf->unregisterServerListener = us_unregister_server_listener;
    // if the driver hasn't been open, open it.
    if (driverFd < 0)
    {
    // open the driver up
    libivc_assert((driverFd = open(DRIVER_PATH, O_RDWR)) > -1, IVC_UNAVAILABLE);
    }
    return SUCCESS;
}

void map_finish_cb(struct libivc_client *client)
{
    int rc = 0;
    struct libivc_client_ioctl_info *cli_info;
    cli_info = (struct libivc_client_ioctl_info *) malloc(sizeof(struct libivc_client_ioctl_info));
    populate_cli(cli_info, client);
    rc = ioctl(driverFd, IVC_PV_MMAP_STAGE2, cli_info);
    update_client(cli_info, client);
    free(cli_info);
}

/**
 * Thread monitoring client for event and disconnect notifications, which in turn
 * notifies callbacks.
 * @param arg Non null pointer to libivc_client being watched.
 * @return NULL
 */
static void*
us_client_listen(void *arg)
{
    struct libivc_client *client = NULL;
    struct pollfd fds[2];
    uint64_t eventData = 0;
    ssize_t dataSize;
    list_head_t *pos = NULL, *temp = NULL;
    callback_node_t * callbacks = NULL;
    uint8_t fireEvent = 0, fireDisconnect = 0;
    uint64_t junk;

    libivc_checkp(arg, NULL);
    client = (struct libivc_client *) arg;

    while (libivc_isOpen(client) &&
       client->client_disconnect_event >= 0 &&
       client->client_notify_event >= 0)
    {
        fds[0].fd = client->client_notify_event;
        fds[1].fd = client->client_disconnect_event;

        fds[0].events = fds[1].events = POLLIN;
        poll(fds, 2, 5); //we time out so we can shut down when required.

        fireEvent = fds[0].revents & POLLIN;
        // if it was set, need to read it to set back to zero.
        if (fireEvent)
        {
            read(client->client_notify_event, &junk, sizeof (uint64_t));
        }

        fireDisconnect = fds[1].revents & POLLIN;
        // if it was set, read it to zero it back out.
        if (fireDisconnect)
        {
            libivc_info("Got disconnect for %u:%u\n", client->remote_domid, client->port);
            read(client->client_disconnect_event, &junk, sizeof (uint64_t));
        }

        // if either was set, notify any callbacks
        if (fireEvent || fireDisconnect)
        {
            list_for_each_safe(pos, temp, &client->callback_list)
            {
                callbacks = container_of(pos, callback_node_t, node);
                if (fireEvent && callbacks->eventCallback)
                {
                    callbacks->eventCallback(client->opaque, client);
                }
                if (fireDisconnect && callbacks->disconnectCallback)
                {
                    callbacks->disconnectCallback(client->opaque, client);
                }
            }
        }
    }
}

/**
 * Monitors the event handle for the server and handles getting the connection
 * and calling the connection callback for the user.
 * @param arg The server to be monitored
 * @return NULL
 */
void*
us_server_listen(void * arg)
{
    struct libivc_server *server = (struct libivc_server*) arg;
    struct pollfd fds[1];
    uint64_t eventData = 0;
    ssize_t dataSize;
    struct libivc_client *client = NULL;
    struct libivc_client_ioctl_info *cli_info = NULL;
    pthread_t clientThread;
    pthread_attr_t attribs;
    int rc;

    // make sure we were not passed a null arg.
    libivc_checkp(server, NULL);
    // check that the event fd is valid
    libivc_assert(server->client_connect_event > 0, NULL);

    while (server->running)
    {
        // set the eventfd in our polling array.
        fds[0].fd = server->client_connect_event;
        fds[0].events = POLLIN;

        //
        // This method below is a very ugly holdover from the original IVC, 
        // and features some horrid hacks (e.g. using a client IOCTL information
        // structure to conver server detail!).
        //
        // This should be one of the first things on the chopping block during
        // the cleanup effort, but it doesn't make sense to spend time cleaning
        // it up now. =(
        //
        poll(fds, 1, 5); //we time out so we can shut down when required.
        if (fds[0].revents & POLLIN)
        {
            libivc_info("Got a connection event.\n");
            // read resets the eventfd counter to zero
            dataSize = read(fds[0].fd, &eventData, sizeof (uint64_t));
            // allocate the client which will receive data from the IVC driver.
            client = (struct libivc_client *) malloc(sizeof (struct libivc_client));
            cli_info = (struct libivc_client_ioctl_info *) malloc(sizeof (struct libivc_client_ioctl_info));
            // this would be rare to fail, but always check.
            libivc_checkp_goto(client, CLIENT_ERROR);
            libivc_checkp_goto(cli_info, CLIENT_ERROR);
            memset(client, 0, sizeof (struct libivc_client));
            memset(cli_info, 0, sizeof (struct libivc_client_ioctl_info));
            client->port = server->port;
            client->remote_domid = server->limit_to_domid;
            client->connection_id = server->limit_to_connection_id;
            rc = ACCESS_DENIED;
            client->client_disconnect_event = eventfd(0, 0);
            libivc_assert_goto(client->client_disconnect_event > 0, CLIENT_ERROR);
            client->client_notify_event = eventfd(0, 0);
            libivc_assert_goto(client->client_notify_event > 0, CLIENT_ERROR);

            mutex_init(&client->mutex);
            INIT_LIST_HEAD(&client->callback_list);
            INIT_LIST_HEAD(&client->node);

            populate_cli(cli_info, client);
            rc = ioctl(driverFd, IVC_SERVER_ACCEPT, cli_info);
            libivc_assert_goto(rc == SUCCESS, CLIENT_ERROR);
            update_client(cli_info, client);

            map_finish_cb(client); // once for local

            // Set up the ringbuffer.
            client->ringbuffer = malloc(sizeof(client->ringbuffer[0]));
            client->ringbuffer->buffer = client->buffer;
            client->ringbuffer->length = client->num_pages*PAGE_SIZE;
            client->ringbuffer->num_channels = 2;
            client->ringbuffer->channels = malloc(2*sizeof(client->ringbuffer->channels[0]));
            ringbuffer_channel_create(&client->ringbuffer->channels[0], (client->num_pages * PAGE_SIZE)/2);
            ringbuffer_channel_create(&client->ringbuffer->channels[1], (client->num_pages * PAGE_SIZE)/2);
            ringbuffer_use(client->ringbuffer);

            pthread_attr_init(&attribs);
            libivc_assert_goto((rc = pthread_create(&client->client_event_thread, &attribs, us_client_listen, client)) == SUCCESS, CLIENT_ERROR);

            list_add(&client->node, &server->client_list);
            libivc_info("Added %u:%u to server list.\n",client->remote_domid, client->port);
            server->connect_cb(server->opaque, client);
            goto END;
        CLIENT_ERROR:
            if (client)
            {
            if (client->client_disconnect_event > 0)
            {
                close(client->client_disconnect_event);
                client->client_disconnect_event = 0;
            }
            if (client->client_notify_event > 0)
            {
                close(client->client_notify_event);
                client->client_notify_event = 0;
            }

            free(client);
            client = NULL;
            }
        END:
            free(cli_info);
            continue;
        }

    }
}

/**
 * Sets up a listener for incoming connections from remote domains by passing down to the 
 * ivc driver as well as running thread to monitor events from the driver.
 * @param server - server with port number set that it wants to listen on.
 * @return SUCCESS, or appropriate error number.
 */
int
us_register_server_listener(struct libivc_server * server)
{
    int rc = SUCCESS;
    pthread_attr_t attr; // use for default attributes.
    struct libivc_server_ioctl_info *serv_info = NULL;
    libivc_info("in %s\n", __FUNCTION__);

    // check that the pointer isn't NULL
    libivc_checkp(server, INVALID_PARAM);
    // make sure the driver is open.
    libivc_assert(driverFd > -1, IVC_UNAVAILABLE);
    // make sure the server doesn't have an event fd already open.
    libivc_assert(server->client_connect_event == 0, ADDRESS_IN_USE);
    // create an event fd that can be used for connection polling.
    libivc_assert((server->client_connect_event = eventfd(0, 0)) > -1, ACCESS_DENIED);
    
    libivc_info("Registering server with driver on port %d, eventfd = %d\n", server->port, server->client_connect_event);
    serv_info = (struct libivc_server_ioctl_info *) malloc(sizeof(struct libivc_server_ioctl_info));
    populate_serv(serv_info, server);
    libivc_assert_goto((rc = ioctl(driverFd, IVC_REG_SVR_LSTNR, serv_info)) == SUCCESS, ERROR);
    libivc_info("Ioctl returned %d\n", rc);
    server->port = serv_info->port;
    server->client_connect_event = serv_info->client_connect_event;

    server->running = 1;
    // launch a thread which will monitor the driver for connection events and 
    // service callbacks to the user of the API
    pthread_attr_init(&attr);
    libivc_assert_goto((rc = pthread_create(&server->listener_thread, &attr, us_server_listen, server)) == SUCCESS, ERROR);
    rc = SUCCESS;
    goto END;
ERROR:
    libivc_info("In error handler of %s, rc = %d\n", __FUNCTION__, rc);
    if (server->client_connect_event > 0)
    {
    close(server->client_connect_event);
    server->client_connect_event = 0;
    }
END:
    if(serv_info != NULL)
        free(serv_info);
    return rc;
}

/**
 * Stops the connection thread and sends and ioctl to the driver to clean up the listening port.
 * @param server
 * @return SUCCESS or appropriate error number.
 */
int
us_unregister_server_listener(struct libivc_server * server)
{
    int rc = SUCCESS;
    struct libivc_server_ioctl_info *serv_info = NULL;
    //list_head_t *pos = NULL, *temp = NULL;
    //list_head_t *cPos = NULL, *cTemp = NULL;
    //struct libivc_client *client = NULL;
    //callback_node_t *node = NULL;
    
    libivc_checkp(server, INVALID_PARAM);
    server->running = 0; // set to 0 so that the connection thread exits cleanly.
    // we need to prevent callbacks from ocurring on any POSIX clients under us or 
    // some nasty side effects start to happen.
/*
    list_for_each_safe(pos,temp,&server->libIvcClients)
    {
    client = container_of(pos,struct libivc_client,listHead);
    list_for_each_safe(cPos,cTemp,&client->callback_list)
    {
        node = container_of(pos,callback_node_t,listHead);
        node->disconnectCallback = NULL;
        node->eventCallback = NULL;
    }
    }
*/

    //Wait for our listener_thread thread to recognize that we've terminated its
    //connection and terminate. We can't continue until this thread aborts, as it
    //contains references to our server object!
    pthread_join(server->listener_thread, NULL);

    serv_info = (struct libivc_server_ioctl_info *) malloc(sizeof(struct libivc_server_ioctl_info));
    populate_serv(serv_info, server);
    rc = ioctl(driverFd, IVC_UNREG_SVR_LSTNR, serv_info);
    close(server->client_connect_event);
    if(serv_info != NULL)
        free(serv_info);
    return rc;
}

/**
 * Sends client down to driver so it can perform event notification.
 * @param ivc Non null client describing IVC connection.
 * @return SUCCESS or appropriate error number.
 */
int
us_notify_remote(struct libivc_client * client)
{
    int rc = INVALID_PARAM;
    struct libivc_client_ioctl_info *cli_info;
    cli_info = (struct libivc_client_ioctl_info *) malloc(sizeof(struct libivc_client_ioctl_info));
    libivc_checkp(client, rc);
    libivc_checkp(cli_info, rc);
    memset(cli_info, 0, sizeof (struct libivc_client_ioctl_info));
    populate_cli(cli_info, client);
    rc = ioctl(driverFd, IVC_NOTIFY_REMOTE, cli_info);
    free(cli_info);
    return rc;
}

/**
 * Connects the client to the remote domain
 * @param client Non null pointer to client describing connection parameters.
 * @return SUCCESS or appropriate error number.
 */
int
us_ivc_connect(struct libivc_client *client)
{
    int rc = INVALID_PARAM;
    pthread_t clientThread;
    pthread_attr_t attribs;
    pid_t myPid;
    int shmfd;
    char shmPath[50];
    struct libivc_client_ioctl_info *cli_info = NULL;
    //struct libivc_client_ioctl_info *cli_info;
    //TODO:implement cli_info here eventually
    // make sure client is not null
    libivc_checkp(client, rc);
    // make sure we haven't already opened event descriptors for it.
    libivc_assert(client->client_disconnect_event == 0 && client->client_notify_event == 0, rc);
    // open the event fds
    client->client_disconnect_event = eventfd(0, 0);
    libivc_assert(client->client_disconnect_event > -1, ACCESS_DENIED);
    client->client_notify_event = eventfd(0, 0);
    libivc_assert_goto(client->client_notify_event > -1, ERROR);

    libivc_info("Sending to driver for connection to %u\n",client->remote_domid);
    cli_info = (struct libivc_client_ioctl_info *) malloc(sizeof(struct libivc_client_ioctl_info));
    populate_cli(cli_info, client);
    libivc_assert_goto((rc = ioctl(driverFd, IVC_CONNECT, cli_info)) == SUCCESS, ERROR);
    update_client(cli_info, client);
    pthread_attr_init(&attribs);
    libivc_info("Launching client event thread for %u:%u.\n", client->remote_domid, client->port);

    libivc_assert_goto((rc = pthread_create(&client->client_event_thread, &attribs, us_client_listen, client)) == SUCCESS, ERROR);
    goto END;
ERROR:
    libivc_info("In error handler of %s\n", __FUNCTION__);
    if (libivc_isOpen(client))
    {
        libivc_disconnect(client);
    }

    if (client->client_disconnect_event > -1)
    {
        close(client->client_disconnect_event);
    }
    if (client->client_notify_event > -1)
    {
        close(client->client_notify_event);
        client->client_notify_event = 0;
    }

END:
    if(cli_info != NULL)
    free(cli_info);
    return rc;
}

/**
 * Reconnects the client to the remote domain.
 * @param client Non null pointer to client to be reconnected.
 * @param 
 * @return SUCCESS or appropriate error number.
 *
 */
int
us_ivc_reconnect(struct libivc_client *client, uint16_t new_domid, uint16_t new_port)
{
    int rc = INVALID_PARAM;
    pthread_t clientThread;
    pthread_attr_t attribs;
    pid_t myPid;
    int shmfd;
    char shmPath[50];

    struct libivc_client_ioctl_info *cli_info = NULL;
    libivc_checkp(client, rc);

    libivc_info("Sending to driver for connection to %u\n",client->remote_domid);

    cli_info = (struct libivc_client_ioctl_info *) malloc(sizeof(struct libivc_client_ioctl_info));

    /// Populate the ioctl, including reconnect-specific fields.
    populate_cli(cli_info, client);
    cli_info->new_domid = new_domid;
    cli_info->new_port  = new_port;

    libivc_assert_goto((rc = ioctl(driverFd, IVC_RECONNECT, cli_info)) == SUCCESS, ERROR);
    update_client(cli_info, client);


    goto END;
ERROR:
    libivc_info("In error handler of %s\n", __FUNCTION__);

END:
    if(cli_info != NULL)
    free(cli_info);
    return rc;
}


/**
 * Disconnects the client and closes event descriptors
 * @param client - NON null pointer describing the connected client.
 * @return SUCCESS or appropriate error number.
 */
int
us_ivc_disconnect(struct libivc_client * client)
{
    int rc = INVALID_PARAM;
    char shmPath[50];
    struct libivc_client_ioctl_info *cli_info = NULL;
    libivc_checkp(client, rc);

    cli_info = (struct libivc_client_ioctl_info *) malloc(sizeof(struct libivc_client_ioctl_info));


    libivc_info("Disconnecting %d:%d\n", client->remote_domid, client->port);
    if (client->ringbuffer)
    {
        // ringBuffer_free(client->ringbuffer);
        client->ringbuffer = NULL;
    }

    if (client->buffer)
    {
        populate_cli(cli_info, client);

        // Call our specialized munmap. This internally results in an
        // munmap, but allows us to hook into the munmap even on systems
        // without MMU notifiers.
        rc = ioctl(driverFd, IVC_MUNMAP, cli_info);
        client->buffer = NULL;
    }

    if (client->client_disconnect_event > 0)
    {
        close(client->client_disconnect_event);
        client->client_disconnect_event = 0;
    }

    if (client->client_notify_event > 0)
    {
        close(client->client_notify_event);
        client->client_notify_event = 0;
    }

    //Wait for our listener_thread thread to recognize that we've terminated its
    //connection and terminate. We can't continue until this thread aborts, as it
    //contains references to our client object!
    pthread_join(client->client_event_thread, NULL);

    populate_cli(cli_info, client);
    rc = ioctl(driverFd, IVC_DISCONNECT, cli_info);

    if(cli_info != NULL)
        free(cli_info);
    return rc;
}
