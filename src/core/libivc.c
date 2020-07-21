// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

#ifndef KERNEL
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <list.h>
#include <string.h>
#else
#include <platform.h>
#endif

#define IVC_DOM_ID 0
#define IVC_PORT 0

#include <libivc.h>
#include <libivc_types.h>
#include <libivc_private.h>
#include <ringbuffer.h>
#include <libivc_debug.h>

LIST_HEAD(ivcServerList);
LIST_HEAD(ivcClients);

/**
 * Locks for the client and server lists. Must be held when reading or modifying
 * the list of servers.
 */
mutex_t ivc_client_list_lock;
mutex_t ivc_server_list_lock;

/**
 * Initializes the libivc library by setting up platform function callbacks, etc.
 * @return SUCCESS or appropriate error number.
 */
static int
libivc_init(void);

static uint8_t initialized = 0;
static pplatform_functions_t platformAPI = NULL;


/**
 * Finds an IVC client by its connection information.
 *
 * @param domid The remote domid for the connection to be located.
 * @param port The remote port for the connection to be located.
 * @param connection_id The remote connection ID for the connection to be located.
 *
 * @return A reference to the relevant client, if one was found, or NULL otherwise.
 *    The returned client has been internally reference counted, and should be freed
 *    with libivc_put_client when no longer needed.
 */
struct libivc_client *lookup_ivc_client(uint16_t domid, uint16_t port, uint64_t connection_id)
{
    struct libivc_client *client = NULL;

    if (!initialized)
    {
        libivc_init();
    }

    FIND_CLIENT_SLIST(client,
        (client->remote_domid == domid && client->port == port && client->connection_id == connection_id));

    return client;
}


/**
 * Initializes the libivc library by setting up platform function callbacks, etc.
 * @return SUCCESS or appropriate error number.
 */

int
libivc_init(void)
{
    int rc;

    if (initialized)
    {
        return SUCCESS;
    }

    // IVC can't work on systems where the page size is smaller than its message size.
    // Validate this. To be cross-platform, we assert this at runtime, though this would be
    // much nicer with C11's static_assert.
    libivc_assert(sizeof(libivc_message_t) <= PAGE_SIZE, ENOSYS);

    libivc_debug_init();
    INIT_LIST_HEAD(&ivcServerList);
    INIT_LIST_HEAD(&ivcClients);
    mutex_init(&ivc_server_list_lock);
    mutex_init(&ivc_client_list_lock);

    platformAPI = (pplatform_functions_t) malloc(sizeof (platform_functions_t));
    libivc_checkp(platformAPI, OUT_OF_MEM);
    memset(platformAPI, 0, sizeof (platform_functions_t));

    rc = libivc_platform_init(platformAPI);
    libivc_assert(rc == SUCCESS, rc);
    libivc_assert((platformAPI->connect != NULL && platformAPI->disconnect != NULL &&
          platformAPI->notifyRemote != NULL &&
          platformAPI->registerServerListener != NULL &&
          platformAPI->unregisterServerListener != NULL), INVALID_PARAM);
    initialized = 1;
    return SUCCESS;
}

/**
 * Sets up a listener for incoming connections from remote domains.
 * @param server - pointer to receive ivc server object.
 * @param listening_port - port to listen for incoming connections on.
 * @param client_callback - callback to be notified of new client connections that have been fully established.
 * @return SUCCESS, or appropriate error number.
 */
#ifdef _WIN32
__pragma(warning(push))
__pragma(warning(disable : 4127))
#endif

int
libivc_startIvcServer(struct libivc_server ** server, uint16_t listening_port, 
              libivc_client_connected connectCallback, void *opaque)
{
    return libivc_start_listening_server(server, listening_port, LIBIVC_DOMID_ANY,
        LIBIVC_ID_ANY, connectCallback, opaque);
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_startIvcServer);
#endif
#endif
#ifdef _WIN32

__pragma(warning(pop))
#endif


/**
 * Sets up a listener for incoming connections from remote domains.
 *
 * @param server - pointer to receive ivc server object.
 * @param listening_port - port to listen for incoming connections on.
 * @param listen_for_domid - the domain ID that the server should listen for, or LIBIVC_DOMID_ANY to 
 *    accept connections from any domain
 * @param listen_for_connection_id - the connection ID that the server should listen for, or 
 *    LIBIVC_ID_ANY to accept connections no matter the specified connection id
 * @param client_callback - callback to be notified of new client connections that have been fully established.
 * @param opaque - A user-specified object that will be passed to any relevant callbacks.
 * @return SUCCESS, or appropriate error number.
 */
#ifdef _WIN32
__pragma(warning(push))
__pragma(warning(disable : 4127))
#endif
int
libivc_start_listening_server(struct libivc_server **server, 
    uint16_t listening_port, uint16_t listen_for_domid, uint64_t listen_for_connection_id, 
    libivc_client_connected connectCallback, void *opaque)
{
    int rc;
    struct libivc_server * iserver = NULL;
    struct libivc_server *otherServer = NULL;

    libivc_checkp(server, INVALID_PARAM);
    libivc_assert(connectCallback != NULL, INVALID_PARAM);

    if (!initialized)
    {
        libivc_assert((rc = libivc_init()) == SUCCESS, rc);
    }

    // If another server has already set up a listener that would prevent us from
    // receiving any connections (i.e. a more general listener), error out.
    //
    // Note that we can create more general servers than those that already exist,
    // and we'll only get the clients that don't match the existing criteria.
    //
    // Perhaps someday we'll enhance this to allow more specific clients to take
    // precedence over general ones? We'll have to discuss this and see how that
    // should work.
    otherServer = libivc_find_listening_server(listen_for_domid, listening_port, listen_for_connection_id);
    if(otherServer)
    {
        libivc_put_server(otherServer);
        return ADDRESS_IN_USE;
    }


    iserver = (struct libivc_server *) malloc(sizeof (struct libivc_server));
    libivc_checkp(iserver, OUT_OF_MEM);
    memset(iserver, 0, sizeof (struct libivc_server));
    iserver->opaque = opaque;

    *server = iserver;

    // Increase the server's reference count, ensuring it's marked as used.
    libivc_get_server(iserver);

    INIT_LIST_HEAD(&iserver->client_list);
    INIT_LIST_HEAD(&iserver->node);
    mutex_init(&iserver->client_mutex);
    iserver->connect_cb = connectCallback;
    iserver->port = listening_port;
    iserver->limit_to_domid = listen_for_domid;
    iserver->limit_to_connection_id = listen_for_connection_id;

    libivc_assert_goto((rc = platformAPI->registerServerListener(iserver)) == SUCCESS, ERR);

    mutex_lock(&ivc_server_list_lock);
    list_add(&iserver->node, &ivcServerList);
    mutex_unlock(&ivc_server_list_lock);

    rc = SUCCESS;
    goto END;

ERR:
    if (iserver)
    {
        free(iserver);
        *server = iserver = NULL;
    }

END:
    return rc;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_start_listening_server);
#endif
#endif
#ifdef _WIN32

__pragma(warning(pop))
#endif


/**
 * Stop listening on the specified port, and close all connections associated with
 * the given port.  The server is freed at this point, so no further attempts should
 * be used to reference it in any way.
 * @param server to shutdown.
 */
void
libivc_shutdownIvcServer(struct libivc_server * server)
{
    mutex_lock(&ivc_server_list_lock);
    __libivc_shutdown_server(server);
    mutex_unlock(&ivc_server_list_lock);
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_shutdownIvcServer);
#endif
#endif


/**
 * Stop listening on the specified port, and close all connections associated with
 * the given port.  The server is freed at this point, so no further attempts should
 * be used to reference it in any way.
 *
 * This version assumes the server list lock is held.
 *
 * @param server to shutdown.
 */
void
__libivc_shutdown_server(struct libivc_server * server)
{
    list_head_t *pos = NULL, *temp = NULL;
    struct libivc_client *client = NULL;

    libivc_checkp(server);
    server->running = 0;

    mutex_lock(&server->client_mutex);
    list_for_each_safe(pos, temp, &server->client_list)
    {
        client = container_of(pos, struct libivc_client, node);
        __libivc_disconnect(client, false);
    }
    platformAPI->unregisterServerListener(server);
    mutex_unlock(&server->client_mutex);

    mutex_destroy(&server->client_mutex);
    list_del(&server->node);

    // Give up our reference on the server.
    libivc_put_server(server);

    server = NULL;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(__libivc_shutdown_server);
#endif
#endif


/**
 * Claims a reference to an IVC server, incrementing its internal reference count.
 */
void
libivc_get_server(struct libivc_server *server)
{
    libivc_checkp(server);
    atomic_inc(&server->ref_count);
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_get_server);
#endif
#endif


/**
 * Releases a reference to an IVC server, decrementing its internal reference count.
 * If no one holds a reference to the server after this function, it will automatically be freed.
 */
void
libivc_put_server(struct libivc_server *server)
{
    libivc_checkp(server);
    if(atomic_dec_and_test(&server->ref_count))
    {
        memset(server, 0, sizeof (struct libivc_server));
        free(server);
    }
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_put_server);
#endif
#endif



/**
 * Claims a reference to an IVC client, incrementing its internal reference count.
 */
void
libivc_get_client(struct libivc_client *client)
{
    libivc_checkp(client);
    atomic_inc(&client->ref_count);
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_get_client);
#endif
#endif


/**
 * Releases a reference to an IVC client, decrementing its internal reference count.
 * If no one holds a reference to the client after this function, it will automatically be freed.
 */
void
libivc_put_client(struct libivc_client *client)
{
    libivc_checkp(client);
    if(atomic_dec_and_test(&client->ref_count))
    {
        if(client->ringbuffer) {
            if(client->ringbuffer->channels)
                free(client->ringbuffer->channels);

            free(client->ringbuffer);
        }

        memset(client, 0, sizeof (struct libivc_client));
        free(client);
    }
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_put_client);
#endif
#endif


/**
 * Returns the outgoing (write) channel for the given IVC client.
 */
static void * outgoing_channel_for(struct libivc_client *client)
{
    size_t channel_number = client->server_side ? SERVER_TO_CLIENT_CHANNEL : CLIENT_TO_SERVER_CHANNEL;
    return &client->ringbuffer->channels[channel_number];
}


/**
 * Returns the incoming (read) channel for the given IVC client.
 */
static void * incoming_channel_for(struct libivc_client *client)
{
    size_t channel_number = client->server_side ? CLIENT_TO_SERVER_CHANNEL : SERVER_TO_CLIENT_CHANNEL;
    return &client->ringbuffer->channels[channel_number];
}


/**
 * Client style connection to a remote domain listening for connections.
 * @param ivc - pointer to receive created connection into
 * @param remote_dom_id - remote domain to connect to.
 * @param remote_port - remote port to connect to.
 * @param memSize - size of buffer to share. Should be a PAGE size multiple.  If not,
 *          the size will be adjusted by the driver and you will be able to get 
 *          the adjusted size by using the utility functions on the returned struct.
 * @param channeled - 0 if just a single buffer shared to the remote domain, otherwise
 *            this connection expects a return share from the remote domain.
 * @return SUCCESS or appropriate error number.
 */
#ifdef _WIN32
__pragma(warning(push))
__pragma(warning(disable : 4127))
#endif

int
libivc_connect(struct libivc_client **ivc, uint16_t remote_dom_id, uint16_t remote_port, uint32_t numPages)
{
    return libivc_connect_with_id(ivc, remote_dom_id, remote_port, numPages, LIBIVC_ID_NONE);
}

#ifdef _WIN32
__pragma(warning(pop))
#endif

#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_connect_with_id);
#endif
#endif




/**
 * Client style connection to a remote domain listening for connections.
 * @param ivc - pointer to receive created connection into
 * @param remote_dom_id - remote domain to connect to.
 * @param remote_port - remote port to connect to.
 * @param memSize - size of buffer to share. Should be a PAGE size multiple.  If not,
 *          the size will be adjusted by the driver and you will be able to get 
 *          the adjusted size by using the utility functions on the returned struct.
 * @param channeled - 0 if just a single buffer shared to the remote domain, otherwise
 *            this connection expects a return share from the remote domain.
 * @return SUCCESS or appropriate error number.
 */
#ifdef _WIN32

__pragma(warning(push))
__pragma(warning(disable : 4127))
#endif
int
libivc_connect_with_id(struct libivc_client **ivc, uint16_t remote_dom_id, uint16_t remote_port, 
        uint32_t numPages, uint64_t connection_id)
{
    int rc = INVALID_PARAM;
    struct libivc_client * client = NULL;
#ifdef KERNEL
#ifdef _WIN32
    if (list_empty(&ivcClients))
    {
        libivc_assert_goto((rc = ks_platform_load()) == STATUS_SUCCESS, ERR);
    }
#endif
#endif

    libivc_info("connecting to %hu%hu %u %llu====>\n", remote_dom_id, remote_port, numPages, connection_id);

    if(remote_dom_id == IVC_DOM_ID && remote_port == IVC_PORT)
    {
        libivc_error("Cannot connect to bootstrap port from userspace.\n");
        return INVALID_PARAM;
    }
    
    if (!initialized)
    {
        libivc_assert((rc = libivc_init()) == SUCCESS, rc);
    }

    libivc_checkp(ivc, INVALID_PARAM);
    libivc_assert(numPages > 0, INVALID_PARAM);

    client = (struct libivc_client *) malloc(sizeof (struct libivc_client));
    libivc_checkp(client, OUT_OF_MEM);
    memset(client, 0, sizeof (struct libivc_client));

    client->remote_domid = remote_dom_id;
    client->port = remote_port;
    client->num_pages = numPages;
    client->connection_id = connection_id;

    // Increment our client's reference count.
    libivc_get_client(client);

    INIT_LIST_HEAD(&client->callback_list);

    mutex_init(&client->mutex);
    INIT_LIST_HEAD(&client->node);

    mutex_lock(&ivc_client_list_lock);
    list_add(&client->node, &ivcClients);
    mutex_unlock(&ivc_client_list_lock);

    libivc_assert_goto((rc = platformAPI->connect(client)) == SUCCESS, ERR);
    libivc_checkp_goto(client->buffer, ERR);

    client->ringbuffer = malloc(sizeof(client->ringbuffer[0]));
    libivc_assert_goto(client->ringbuffer != NULL, ERR);

    client->ringbuffer->buffer = client->buffer;
    client->ringbuffer->length = client->num_pages*PAGE_SIZE;
    client->ringbuffer->num_channels = 2;
    client->ringbuffer->channels = malloc(2*sizeof(client->ringbuffer->channels[0]));
    libivc_assert_goto(client->ringbuffer->channels != NULL, ERR);

    ringbuffer_channel_create(&client->ringbuffer->channels[0], (client->num_pages * PAGE_SIZE)/2);
    ringbuffer_channel_create(&client->ringbuffer->channels[1], (client->num_pages * PAGE_SIZE)/2);
    ringbuffer_use(client->ringbuffer);


    rc = SUCCESS;
    goto END;
ERR:
    if (client)
    {
        if(client->ringbuffer)
        {
            if(client->ringbuffer->channels)
            {
                free(client->ringbuffer->channels);
            }

            free(client->ringbuffer);
        }

        list_del(&client->node);
        mutex_destroy(&client->mutex);
        libivc_put_client(client);
        client = NULL;
    }
END:
    *ivc = client;

    libivc_info("%d <====\n", rc);
    return rc;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_connect);
#endif
#endif
#ifdef _WIN32

__pragma(warning(pop))
#endif


/**
 * Returns any connection identifier associated with the given display,
 * or LIBIVC_ID_NONE if no connection information could be queried.
 *
 * @param client The client for which the connection identifier is desired.
 * @return The relevant connection ID, or LIBIVC_ID_NONE if none
 *    could be accessed. Should be the same on both sides of an IVC
 *    connection.
 */
#ifdef _WIN32

__pragma(warning(push))
__pragma(warning(disable : 4127))
#endif
uint64_t
libivc_get_connection_id(struct libivc_client * client)
{
    libivc_checkp(client, LIBIVC_ID_NONE);
    return client->connection_id;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_get_connection_id);
#endif
#endif
#ifdef _WIN32
__pragma(warning(pop))
#endif


/**
 * Reconnects an existing client to a server. This is effectively the same logic and
 * behavior as a new connection, but the existing granted pages are retained.
 *
 * @param ivc - pointer to the client to be reconnected
 * @param remote_dom_id - remote domain to connect to.
 * @param remote_port - remote port to connect to.
 * @return SUCCESS or appropriate error number.
 */
#ifdef _WIN32

__pragma(warning(push))
__pragma(warning(disable : 4127))
#endif
int
libivc_reconnect(struct libivc_client * client, uint16_t remote_dom_id, uint16_t remote_port)
{
    int rc = INVALID_PARAM;

    if(remote_dom_id == IVC_DOM_ID && remote_port == IVC_PORT)
    {
        libivc_error("Cannot connect to bootstrap port from userspace.\n");
        return INVALID_PARAM;
    }

    //If we're working with an older version of the platform API
    //that doesn't support reconnect, bail out.
    if(!platformAPI->reconnect)
    {
        libivc_error("Platform API does not (yet) support reconnect.\n");
        return NOT_IMPLEMENTED;
    }

    libivc_checkp(client, INVALID_PARAM);
    libivc_assert(initialized, INVALID_PARAM);
    libivc_assert(client->num_pages > 0, INVALID_PARAM);

    mutex_lock(&client->mutex);

    libivc_assert_goto((rc = platformAPI->reconnect(client, remote_dom_id, remote_port)) == SUCCESS, ERR);
    libivc_checkp_goto(client->buffer, ERR);

    if(client->ringbuffer == NULL) {
        client->ringbuffer = malloc(sizeof(*(client->ringbuffer)));    
    }
    
    libivc_assert_goto(client->ringbuffer != NULL, ERR);

    client->ringbuffer->buffer = client->buffer;
    client->ringbuffer->length = client->num_pages*PAGE_SIZE;
    client->ringbuffer->num_channels = 2;
    
    if(client->ringbuffer->channels == NULL) {
        client->ringbuffer->channels = malloc(2*sizeof(*(client->ringbuffer->channels)));    
    }
    libivc_assert_goto(client->ringbuffer->channels != NULL, ERR);

    ringbuffer_channel_create(&client->ringbuffer->channels[0], (client->num_pages * PAGE_SIZE)/2);
    ringbuffer_channel_create(&client->ringbuffer->channels[1], (client->num_pages * PAGE_SIZE)/2);
    ringbuffer_use(client->ringbuffer);
    
    rc = SUCCESS;
    libivc_assert(client->ringbuffer != NULL, INTERNAL_ERROR);
    goto END;
ERR:
END:
    mutex_unlock(&client->mutex);
    return rc;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_reconnect);
#endif
#endif
#ifdef _WIN32
__pragma(warning(pop))
#endif


/**
 * Disconnects the ivc struct and notifies the remote of it if possible.
 * This version assumes the IVC client and server list locks are held.
 *
 * @param ivc - the connected ivc struct.
 */
void
__libivc_disconnect(struct libivc_client *client, bool from_public_api)
{
    list_head_t *pos = NULL, *temp = NULL;
    callback_node_t *callback = NULL;
    struct libivc_server *server = NULL;


    libivc_assert(initialized);

#ifndef KERNEL
    if(client->remote_domid == IVC_DOM_ID && client->port == IVC_PORT)
    {
        libivc_error("Userspace trying to shutdown driver.\n");
        return;
    }
#endif

    libivc_checkp(client);
    mutex_lock(&client->mutex);

    // If this is a server-side client, ensure that we hold the servers' client
    // list mutex before deleting this client.
    if(client->server_side && from_public_api)
    {
        // Find the server that this client belongs to.
        server = __libivc_find_listening_server(client->remote_domid, client->port, client->connection_id);

        // If we found a server, lock its client-list mutex.
        if(server)
        {
            mutex_lock(&server->client_mutex);
            list_del(&client->node);
        }
        else
        {
            libivc_warn("Trying to shut down a server-side client, but couldn't find its server!\n");
            libivc_warn("This may indicate a bookkeeping issue.\n");
        }
    }
    else
    {
        list_del(&client->node);
    }

    list_for_each_safe(pos, temp, &client->callback_list)
    {
        callback = container_of(pos, callback_node_t, node);
        list_del(pos);
        memset(callback, 0, sizeof (callback_node_t));
        free(callback);
        callback = NULL;
    }

    // If we obtained a server, release its client list mutex,
    // and relinquish our reference to the server.
    if(server)
    {
        mutex_unlock(&server->client_mutex);
        libivc_put_server(server);
    }
    mutex_unlock(&client->mutex);
    mutex_destroy(&client->mutex);
    platformAPI->disconnect(client);

    libivc_put_client(client);
    client = NULL;

#ifdef KERNEL
#ifdef _WIN32
    if (list_empty(&ivcClients))
    {
        ks_platform_unload();
    }
#endif
#endif
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(__libivc_disconnect);
#endif
#endif


/**
 * Disconnects the ivc struct and notifies the remote of it if possible.
 * @param ivc - the connected ivc struct.
 */
void
libivc_disconnect(struct libivc_client *client)
{
    mutex_lock(&ivc_client_list_lock);
    mutex_lock(&ivc_server_list_lock);
    __libivc_disconnect(client, true);
    mutex_unlock(&ivc_server_list_lock);
    mutex_unlock(&ivc_client_list_lock);
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_disconnect);
#endif
#endif


/**
 * Determines if ivc is connected based on parameters at time of connect.
 * @param ivc - ivc struct describing connection.
 * @return 1 if connect, 0 otherwise.
 */
uint8_t
libivc_isOpen(struct libivc_client *ivc)
{
    libivc_checkp(ivc, 0);

    return ivc->buffer != NULL;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_isOpen);
#endif
#endif

/**
 * Write as many bytes as possible up to srcLength from src to the ivc buffer 
 * and return how many bytes were successfully written in actualLength.
 * @param ivc - a connected ivc struct.
 * @param src - non null character buffer to copy from.
 * @param srcLength - size of the src buffer.
 * @param actualLength - number of bytes that were actually written.
 * @return SUCCESS or appropriate error number.
 */
int
libivc_write(struct libivc_client *ivc, char *src, size_t srcSize, size_t * actualLength)
{
    libivc_checkp(ivc, INVALID_PARAM);
    libivc_checkp(src, INVALID_PARAM);
    libivc_checkp(actualLength, INVALID_PARAM);

    libivc_assert(srcSize > 0, INVALID_PARAM);
    libivc_checkp(ivc->buffer, ACCESS_DENIED);
    libivc_checkp(ivc->ringbuffer, ACCESS_DENIED);

    mutex_lock(&ivc->mutex);
    *actualLength = ringbuffer_write(outgoing_channel_for(ivc), src, srcSize);
    mutex_unlock(&ivc->mutex);
    return SUCCESS;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_write);
#endif
#endif

/**
 * Try to write EXACTLY srcSize bytes to the ivc channel.  If they can't be written
 * because the buffer is full, 0 is returned. (Packet style send)
 * @param ivc - A connected ivc struct.
 * @param src - source buffer to write to the ivc connection.
 * @param srcSize - size of the source buffer and exact amount to write.
 * @return SUCCESS or appropriate error number.
 */
int
libivc_send(struct libivc_client *ivc, char *src, size_t srcSize)
{
    size_t actual = 0;
    uint8_t event_enabled = 0;
    int rc;
    struct ringbuffer_channel_t *channel = NULL;
    libivc_checkp(ivc, INVALID_PARAM);
    libivc_checkp(src, INVALID_PARAM);
    libivc_assert(srcSize > 0, INVALID_PARAM);
    libivc_checkp(ivc->ringbuffer, INVALID_PARAM);

    channel = outgoing_channel_for(ivc);

    libivc_assert(ringbuffer_bytes_available_write(channel) >= (ssize_t)srcSize, NO_SPACE);
    mutex_lock(&ivc->mutex);
    actual = ringbuffer_write(channel, src, srcSize);
    mutex_unlock(&ivc->mutex);

    rc = srcSize == actual ? SUCCESS : NO_SPACE;

    libivc_remote_events_enabled(ivc, &event_enabled);

    if (event_enabled) 
    {
        libivc_notify_remote(ivc);
    }

    return rc;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_send);
#endif
#endif

/**
 * Read as many bytes as possible up to destSize into buffer dest, returns how
 * many bytes were read.
 * @param ivc - connected libivc struct.
 * @param dest - destination buffer to read data into
 * @param destSize - maximum number of bytes to read.
 * @param actualSize - pointer to receive actual bytes read.
 * @return SUCCESS or appropriate error number.
 */
int
libivc_read(struct libivc_client *ivc, char *dest, size_t destSize, size_t * actualSize)
{
    struct ringbuffer_channel_t *channel = NULL;
    libivc_checkp(ivc, INVALID_PARAM);
    libivc_checkp(ivc->ringbuffer, INVALID_PARAM);
    libivc_checkp(dest, INVALID_PARAM);
    libivc_checkp(actualSize, INVALID_PARAM);
    libivc_assert(destSize > 0, INVALID_PARAM);
 
    channel = incoming_channel_for(ivc);

    mutex_lock(&ivc->mutex);
    *actualSize = ringbuffer_read(channel, dest, destSize);
    mutex_unlock(&ivc->mutex);
    return SUCCESS;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_read);
#endif
#endif

/**
 * Read exactly destSize bytes from ivc, failing if there are less than the specified
 * amount available. (Packet style receive)
 * @param ivc - connected ivc struct.
 * @param dest - destination buffer to write to.
 * @param destSize - size of dest, and the exact number of bytes required to read.
 * @return SUCCESS, or appropriate error number.
 */
int
libivc_recv(struct libivc_client *ivc, char *dest, size_t destSize)
{
    struct ringbuffer_channel_t *channel = NULL;
    size_t read;

    libivc_checkp(ivc, INVALID_PARAM);
    libivc_checkp(ivc->ringbuffer, INVALID_PARAM);
    libivc_checkp(dest, INVALID_PARAM);

    libivc_assert(destSize > 0, INVALID_PARAM);

    channel = incoming_channel_for(ivc);

    libivc_assert(ringbuffer_bytes_available_read(channel) >= (ssize_t)destSize, NO_DATA_AVAIL);

    mutex_lock(&ivc->mutex);
    read = ringbuffer_read(channel, dest, destSize);
    mutex_unlock(&ivc->mutex);

    return read == destSize ? SUCCESS : NO_DATA_AVAIL;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_recv);
#endif
#endif

/**
* Write as many bytes as possible up to srcLength from src to the ivc buffer
* and return how many bytes were successfully written in actualLength, without
* locking the client. Intended for use in Windows at IRQL levels higher than
* APC_LEVEL, in which the client's FastMutex may not be used. It's up to the
* user to enforce mutual exclusion in these cases.
* @param ivc - a connected ivc struct.
* @param src - non null character buffer to copy from.
* @param srcLength - size of the src buffer.
* @param actualLength - number of bytes that were actually written.
* @return SUCCESS or appropriate error number.
*/
int
libivc_unsafe_write(struct libivc_client *ivc, char *src, size_t srcSize, size_t * actualLength)
{
	libivc_checkp(ivc, INVALID_PARAM);
	libivc_checkp(src, INVALID_PARAM);
	libivc_checkp(actualLength, INVALID_PARAM);

	libivc_assert(srcSize > 0, INVALID_PARAM);
	libivc_checkp(ivc->buffer, ACCESS_DENIED);
	libivc_checkp(ivc->ringbuffer, ACCESS_DENIED);

	*actualLength = ringbuffer_write(outgoing_channel_for(ivc), src, srcSize);
	return SUCCESS;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_unsafe_write);
#endif
#endif

/**
* Try to write EXACTLY srcSize bytes to the ivc channel, without locking the
* client. If they can't be written because the buffer is full, 0 is returned.
* Intended for use in Windows at IRQL levels higher than APC_LEVEL, in which
* the client's FastMutex may not be used. It's up to the user to enforce mutual
* exclusion in these cases.
* FIXME: remote not notified (since that's not safe to do at DISPATCH_LEVEL).
* @param ivc - A connected ivc struct.
* @param src - source buffer to write to the ivc connection.
* @param srcSize - size of the source buffer and exact amount to write.
* @return SUCCESS or appropriate error number.
*/
int
libivc_unsafe_send(struct libivc_client *ivc, char *src, size_t srcSize)
{
	size_t actual = 0;
	// uint8_t event_enabled = 0;
	int rc;
	struct ringbuffer_channel_t *channel = NULL;
	libivc_checkp(ivc, INVALID_PARAM);
	libivc_checkp(src, INVALID_PARAM);
	libivc_assert(srcSize > 0, INVALID_PARAM);
	libivc_checkp(ivc->ringbuffer, INVALID_PARAM);

	channel = outgoing_channel_for(ivc);

	libivc_assert(ringbuffer_bytes_available_write(channel) >= (ssize_t)srcSize, NO_SPACE);
	actual = ringbuffer_write(channel, src, srcSize);

	rc = srcSize == actual ? SUCCESS : NO_SPACE;

	/*libivc_remote_events_enabled(ivc, &event_enabled);

	if (event_enabled)
	{
		libivc_notify_remote(ivc);
	}*/

	return rc;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_unsafe_send);
#endif
#endif

/**
* Read as many bytes as possible up to destSize into buffer dest, without
* locking the client. Returns how many bytes were read. Intended for use in
* Windows at IRQL levels higher than APC_LEVEL, in which the client's FastMutex
* may not be used. It's up to the user to enforce mutual exclusion in these
* cases.
* @param ivc - connected libivc struct.
* @param dest - destination buffer to read data into
* @param destSize - maximum number of bytes to read.
* @param actualSize - pointer to receive actual bytes read.
* @return SUCCESS or appropriate error number.
*/
int
libivc_unsafe_read(struct libivc_client *ivc, char *dest, size_t destSize, size_t * actualSize)
{
	struct ringbuffer_channel_t *channel = NULL;
	libivc_checkp(ivc, INVALID_PARAM);
	libivc_checkp(ivc->ringbuffer, INVALID_PARAM);
	libivc_checkp(dest, INVALID_PARAM);
	libivc_checkp(actualSize, INVALID_PARAM);
	libivc_assert(destSize > 0, INVALID_PARAM);

	channel = incoming_channel_for(ivc);

	*actualSize = ringbuffer_read(channel, dest, destSize);
	return SUCCESS;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_unsafe_read);
#endif
#endif

/**
* Read exactly destSize bytes from ivc, without locking the client. Fails if
* there are less than the specified amount available. Intended for use in
* Windows at IRQL levels higher than APC_LEVEL, in which the client's FastMutex
* may not be used. It's up to the user to enforce mutual exclusion in these
* cases.
* @param ivc - connected ivc struct.
* @param dest - destination buffer to write to.
* @param destSize - size of dest, and the exact number of bytes required to read.
* @return SUCCESS, or appropriate error number.
*/
int
libivc_unsafe_recv(struct libivc_client *ivc, char *dest, size_t destSize)
{
	struct ringbuffer_channel_t *channel = NULL;
	size_t read;

	libivc_checkp(ivc, INVALID_PARAM);
	libivc_checkp(ivc->ringbuffer, INVALID_PARAM);
	libivc_checkp(dest, INVALID_PARAM);

	libivc_assert(destSize > 0, INVALID_PARAM);

	channel = incoming_channel_for(ivc);

	libivc_assert(ringbuffer_bytes_available_read(channel) >= (ssize_t)destSize, NO_DATA_AVAIL);

	read = ringbuffer_read(channel, dest, destSize);
	return read == destSize ? SUCCESS : NO_DATA_AVAIL;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_unsafe_recv);
#endif
#endif

/**
 * Returns the remote domain id associated with the connection.
 * @param ivc - connected ivc struct.
 * @param dom - pointer to receive domain id value into.
 * @return SUCCESS or appropriate error number.
 */
int
libivc_getRemoteDomId(struct libivc_client *ivc, uint16_t * dom)
{
    libivc_checkp(ivc, INVALID_PARAM);
    libivc_checkp(dom, INVALID_PARAM);
    *dom = ivc->remote_domid;
    return SUCCESS;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_getRemoteDomId);
#endif
#endif

/**
 * return the port number for a connection.
 * @param ivc - connected ivc struct.
 * @param port - pointer to receive value into.
 * @return SUCCESS or appropriate error number.
 */
int
libivc_getport(struct libivc_client *ivc, uint16_t * port)
{
    libivc_checkp(ivc, INVALID_PARAM);
    libivc_checkp(port, INVALID_PARAM);

    *port = ivc->port;
    return SUCCESS;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_getport);
#endif
#endif

/**
 * returns the local buffer that can be read and written to.  The buffer will be 
 * offset by the number of bytes required to store the ring buffer header.
 * @param ivc - connected ivc struct.
 * @param buffer - pointer to receive buffer pointer
 * @return SUCCESS or appropriate error number.
 */
int
libivc_getbuffer(struct libivc_client *ivc, char ** buffer)
{
    libivc_checkp(ivc, INVALID_PARAM);
    libivc_checkp(buffer, INVALID_PARAM);
    *buffer = NULL;

    libivc_checkp(ivc->buffer, ACCESS_DENIED);
    *buffer = ivc->buffer; // offset for ring header, otherwise it can be clobbered.
    return SUCCESS;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_getbuffer);
#endif
#endif

/**
 * Returns the size of the local buffer minus any space required for ring buffer
 * headers.
 * @param ivc - connected ivc struct.
 * @param buffSize - parameter to receive buffer size into.
 * @return SUCCESS or appropriate error number.
 */
int
libivc_getbufferSize(struct libivc_client *ivc, size_t * buffSize)
{
    libivc_checkp(ivc, INVALID_PARAM);
    libivc_checkp(buffSize, INVALID_PARAM);
    *buffSize = 0;

    libivc_checkp(ivc->buffer, ACCESS_DENIED);
    *buffSize = (ivc->num_pages * PAGE_SIZE);
    return SUCCESS;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_getbufferSize);
#endif
#endif

/**
 * Returns the READ ONLY remote buffer, offset by any ringbuffer headers, or NULL if not connected.
 * @param ivc - connected ivc struct.
 * @param remoteBuffer - pointer to receive address of buffer into.
 * @return SUCCESS or appropriate error number.
 */
int
libivc_getRemoteBuffer(struct libivc_client *ivc, char ** remoteBuffer)
{
    libivc_checkp(ivc, INVALID_PARAM);
    libivc_checkp(remoteBuffer, INVALID_PARAM);
    *remoteBuffer = NULL;

    libivc_checkp(ivc->buffer, ACCESS_DENIED);
    *remoteBuffer = ivc->buffer;
    return SUCCESS;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_getRemoteBuffer);
#endif
#endif

/**
 * Returns the READ ONLY remote buffer, offset by any ringbuffer headers, or NULL if not connected.
 * @param ivc - connected ivc struct.
 * @param remoteBuffer - pointer to receive address of buffer into.
 * @return SUCCESS or appropriate error number.
 */
int
libivc_getLocalBuffer(struct libivc_client *ivc, char ** remoteBuffer)
{
    libivc_checkp(ivc, INVALID_PARAM);
    libivc_checkp(remoteBuffer, INVALID_PARAM);
    *remoteBuffer = NULL;

    libivc_checkp(ivc->buffer, ACCESS_DENIED);
    *remoteBuffer = ivc->buffer;
    return SUCCESS;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_getLocalBuffer);
#endif
#endif

/**
 * Returns the size of the remote buffer minus the ring buffer headers, or null if not connected.
 * @param ivc - connected ivc struct.
 * @param buffSize - pointer to receive size into.
 * @return SUCCESS or appropriate error number.
 */
int
libivc_getRemoteBufferSize(struct libivc_client *ivc, size_t * buffSize)
{
    libivc_checkp(ivc, INVALID_PARAM);
    libivc_checkp(buffSize, INVALID_PARAM);
    *buffSize = 0;

    libivc_checkp(ivc->buffer, NOT_CONNECTED);
    *buffSize = (ivc->num_pages * PAGE_SIZE);
    return SUCCESS;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_getRemoteBufferSize);
#endif
#endif

/**
 * Returns the size of the remote buffer minus the ring buffer headers, or null if not connected.
 * @param ivc - connected ivc struct.
 * @param buffSize - pointer to receive size into.
 * @return SUCCESS or appropriate error number.
 */
int
libivc_getLocalBufferSize(struct libivc_client *ivc, size_t * buffSize)
{
    return libivc_getRemoteBufferSize(ivc, buffSize);
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_getLocalBufferSize);
#endif
#endif

/**
 * Register function pointers to be notified of events callback style. NULLs may
 * be passed if you are not interested in a particular type of event.
 * @param client The ivc client of interest.
 * @param eventCallback when a remote event has been fired to this clients port
 * @param disconnectCallback when the remote domain wants to disconnect this client.
 * @return SUCCESS, or appropriate error message.
 */
#ifdef _WIN32

__pragma(warning(push))
__pragma(warning(disable : 4127))
#endif
int
libivc_register_event_callbacks(struct libivc_client *client,
                libivc_client_event_fired eventCallback,
                libivc_client_disconnected disconnectCallback,
                void *opaque)
{
    callback_node_t * callbacks = NULL;

    libivc_checkp(client, INVALID_PARAM);
    libivc_assert(eventCallback != NULL || disconnectCallback != NULL, INVALID_PARAM);
    
    callbacks = (callback_node_t *) malloc(sizeof (callback_node_t));
    libivc_checkp(callbacks, OUT_OF_MEM);
    memset(callbacks, 0, sizeof (callback_node_t));
    
    callbacks->disconnectCallback = disconnectCallback;
    callbacks->eventCallback = eventCallback;
    
    client->opaque = opaque;

    INIT_LIST_HEAD(&callbacks->node);
    
    list_add(&callbacks->node, &client->callback_list);
    if(libivc_isOpen(client))
    {
        libivc_enable_events(client);
    }
    else
    {
        libivc_info("Tried to enable events on client that wasn't open\n");
    }
    
    return SUCCESS;
}

#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_register_event_callbacks);
#endif
#endif
#ifdef _WIN32

__pragma(warning(pop))
#endif

/**
 * Retrieves how much space is available to write into the buffer.
 * @param client Non null pointer to client being used to write to.
 * @param space Non null pointer to receive space.
 * @return SUCCESS or appropriate error number.
 */
int
libivc_getAvailableSpace(struct libivc_client *client, size_t * space)
{
    libivc_checkp(client, INVALID_PARAM);
    libivc_checkp(space, INVALID_PARAM);
    libivc_checkp(client->ringbuffer, INVALID_PARAM); // shouldn't ever happen.

    *space = ringbuffer_bytes_available_write(outgoing_channel_for(client));
    return SUCCESS;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_getAvailableSpace);
#endif
#endif


/**
 * Retrieves the amount of data available to read from the client connection.
 * @param client - non null pointer to client.
 * @param dataSize - non null pointer to receive data.
 * @return SUCCESS or appropriate error.
 */
int
libivc_getAvailableData(struct libivc_client *client, size_t *dataSize)
{
    libivc_checkp(client, INVALID_PARAM);
    libivc_checkp(dataSize, INVALID_PARAM);
    libivc_checkp(client->ringbuffer, INVALID_PARAM); // shouldn't ever happen.

    *dataSize = ringbuffer_bytes_available_read(incoming_channel_for(client));

    return SUCCESS;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_getAvailableData);
#endif
#endif

int
libivc_clear_ringbuffer(struct libivc_client *client)
{
    libivc_checkp(client, INVALID_PARAM);
    libivc_checkp(client->ringbuffer, INVALID_PARAM); // shouldn't ever happen.
    mutex_lock(&client->mutex);
    ringbuffer_clear_buffer(incoming_channel_for(client));
    mutex_unlock(&client->mutex);
    return SUCCESS;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_clear_ringbuffer);
#endif
#endif



/**
 * When the remote side sends or writes data to this client, tell it not to
 * fire remote events to us.  Usually you would do this when polling on data.
 * @param client Non null pointer to client.
 * @return SUCCESS or appropriate error number.
 */
int
libivc_disable_events(struct libivc_client *client)
{
    int32_t flags = 0;
    int64_t target_flag;
    void * channel;

    libivc_checkp(client, INVALID_PARAM);
    libivc_checkp(client->ringbuffer, INVALID_PARAM);

    // We want to control events fired _at_ us-- so we're going to
    // adjust the flags on the channel we receive on.
    target_flag = client->server_side ? CLIENT_SIDE_TX_EVENT_FLAG : SERVER_SIDE_TX_EVENT_FLAG;
    channel = incoming_channel_for(client);

    // Adjust the event flag on the relevant channel.
    flags = ringbuffer_get_flags(channel);
    flags &= ~target_flag;
    ringbuffer_set_flags(channel, flags);

    return SUCCESS;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_disable_events);
#endif
#endif

/**
 * Let the remote domain know that you wish to receive events when it sends or
 * writes data in the ring buffer.
 * @param client Non null pointer to the client
 * @return SUCCESS or appropriate error number.
 */
int
libivc_enable_events(struct libivc_client *client)
{
    int32_t flags = 0;
    int32_t target_flag;
    void * channel;

    libivc_checkp(client, INVALID_PARAM);
    libivc_checkp(client->ringbuffer, INVALID_PARAM);

    // We want to control events fired _at_ us-- so we're going to
    // adjust the flags on the channel we receive on.
    target_flag = client->server_side ? CLIENT_SIDE_TX_EVENT_FLAG : SERVER_SIDE_TX_EVENT_FLAG;
    channel = incoming_channel_for(client);

    // Adjust the event flag on the relevant channel.
    flags = ringbuffer_get_flags(channel);
    flags |= target_flag;
    ringbuffer_set_flags(channel, flags);

    return SUCCESS;
}
#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_enable_events);
#endif
#endif

int
libivc_remote_events_enabled(struct libivc_client *client, uint8_t *enabled)
{
    int64_t flags;
    int64_t target_flag;

    libivc_checkp(client, INVALID_PARAM);
    libivc_checkp(enabled, INVALID_PARAM);
    libivc_checkp(client->ringbuffer, INVALID_PARAM);

    // We're interested in whether we should send event at
    // the _remote_ channel-- so we're going to check the
    // channel we write in.
    target_flag = client->server_side ? SERVER_SIDE_TX_EVENT_FLAG : CLIENT_SIDE_TX_EVENT_FLAG;

    // Read whether events are currently enabled for the relevant channel.
    flags = ringbuffer_get_flags(outgoing_channel_for(client)) & target_flag;
    *enabled = (flags != 0);

    return SUCCESS;
}

/**
 * Fires a XEN event to the remote domain.
 * @param client Non null pointer to client connected to remote.
 * @return SUCCESS or appropriate error message.
 */
int
libivc_notify_remote(struct libivc_client *client)
{
    libivc_checkp(client, INVALID_PARAM);
    if (!initialized)
    {
        libivc_init();
    }

    return platformAPI->notifyRemote(client);
}

#ifdef KERNEL
#ifdef __linux
EXPORT_SYMBOL(libivc_notify_remote);
#endif
#endif

/**
 * Locates a server on within this IVC instance that will accept connections with
 * the for a client with the given domain ID, port, and connection ID.
 *
 * @param connecting_domid The domain ID for the domain that wishes to connect
 *    to this server.
 * @param port The IVC prot on which the remote wishes to connect.
 * @param connection_id The connection ID for the remote that wishes to connect.
 *
 * @return A server object, if one is willing to accept these clients, or NULL
 *    if no such client exists. This server has been internally reference
 *    counted, and should be released by calling libivc_put_server when done.
 *
 */
struct libivc_server *
libivc_find_listening_server(uint16_t connecting_domid, uint16_t port, uint64_t connection_id)
{
    struct libivc_server * server = NULL;

    if (!initialized)
    {
        libivc_init();
    }

    mutex_lock(&ivc_server_list_lock);
    server = __libivc_find_listening_server(connecting_domid, port, connection_id);
    mutex_unlock(&ivc_server_list_lock);

    return server;
}


/**
 * Locates a server on within this IVC instance that will accept connections with
 * the for a client with the given domain ID, port, and connection ID.
 *
 * This version assumes the server list lock is already held; it its not
 * recommended for external use unless you know what you're doing.
 *
 * @param connecting_domid The domain ID for the domain that wishes to connect
 *    to this server.
 * @param port The IVC prot on which the remote wishes to connect.
 * @param connection_id The connection ID for the remote that wishes to connect.
 *
 * @return A server object, if one is willing to accept these clients, or NULL
 *    if no such client exists. This server has been internally reference
 *    counted, and should be released by calling libivc_put_server when done.
 *
 */
struct libivc_server *
__libivc_find_listening_server(uint16_t connecting_domid, uint16_t port, uint64_t connection_id)
{
    struct libivc_server * server = NULL;
    list_head_t *pos = NULL, *temp = NULL;

    // Search for an IVC server that will accept our client.
    list_for_each_safe(pos, temp, &ivcServerList)
    {
        bool listening_for_us, listening_for_any;
        server = container_of(pos, struct libivc_server, node);

        // If this server's port isn't ours, it can't be listening for us.
        if(server->port != port)
        {
            continue;
        }

        listening_for_us  = server->limit_to_domid == connecting_domid;
        listening_for_any = server->limit_to_domid == LIBIVC_DOMID_ANY;

        // If this server is listening for another domain ID, it's not a match.
        if(!listening_for_us && !listening_for_any)
        {
             continue;
        }

        listening_for_us  = server->limit_to_connection_id == connection_id;
        listening_for_any = server->limit_to_connection_id == LIBIVC_ID_ANY;

        // If this server is listening for another connection ID, it's not a match.
        if(!listening_for_us && !listening_for_any)
        {
             continue;
        }

        // Get a reference to this server.
        libivc_get_server(server);

        // If all of our checks have passed, we've found our server!
        return server;

    }

    // If we didn't find a server, return NULL.
    return NULL;
}
