// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

#include <platform.h>
#include "ivc_ioctl_defs.h"
#ifdef __linux
#include <xenback.h>
#endif
#include <libivc.h>
#include <libivc_debug.h>
#include <libivc_private.h>

#ifndef KERNEL
#include <list.h>
#endif

#include <ks_ivc_core.h>

static struct libivc_client *ivcXenClient = NULL;
int domId = -1;

int
libivc_platform_init(platform_functions_t *pf)
{
    int rc = SUCCESS;

    libivc_checkp(pf, INVALID_PARAM);

    pf->connect = ks_ivc_core_connect;
    pf->disconnect = ks_ivc_core_disconnect;
    pf->reconnect = ks_ivc_core_reconnect;
    pf->notifyRemote = ks_ivc_core_notify_remote;
    pf->registerServerListener = ks_ivc_core_reg_svr_lsnr;
    pf->unregisterServerListener = ks_ivc_core_unreg_svr_lsnr;
    return rc;
}

/**
 * Notification when backend fires a ring event.
 * @param irq - not used.
 */
static void
ks_ivc_core_backend_event(int irq)
{
    libivc_message_t inMessage;
    size_t messageSize = 0;
    int rc = INVALID_PARAM;
    UNUSED(irq);

    memset(&inMessage, 0, sizeof (libivc_message_t));

    libivc_disable_events(ivcXenClient);
    rmb();
    libivc_getAvailableData(ivcXenClient, &messageSize);

    libivc_assert_goto(messageSize >= sizeof (libivc_message_t), END);
    do 
    {
        rmb();
        libivc_assert_goto((rc = libivc_recv(ivcXenClient, (char *) &inMessage,
                                             sizeof (libivc_message_t))) == SUCCESS, END);

        rc = INVALID_PARAM;
        libivc_assert_goto(inMessage.to_dom == domId, END);
        libivc_assert_goto(inMessage.msg_start == HEADER_START &&
                           inMessage.msg_end == HEADER_END, END);
        if (inMessage.type == CONNECT) 
        {
            rc = ks_ivc_core_handle_connect_msg(&inMessage);
        } 
        else if (inMessage.type == DISCONNECT) 
        {
            ks_ivc_core_handle_disconnect_msg(&inMessage);
        }
        else if (inMessage.type == DOMAIN_DEAD)
        {
            ks_ivc_core_handle_domain_death_notification(&inMessage); 
        }
        libivc_getAvailableData(ivcXenClient, &messageSize);
    } while (messageSize >= sizeof (libivc_message_t));
END:
    // turn back on events from backend.
    libivc_enable_events(ivcXenClient);
}

int
ks_ivc_core_init(void)
{
    int rc = SUCCESS;
    xenbus_transaction_t trans;
    char path[IVC_MAX_PATH];

    libivc_info("In %s\n", __FUNCTION__);

    // make sure the path will always have a proper string termination.
    memset(path, '\0', IVC_MAX_PATH);

    libivc_info("Getting our domain id.\n");
    libivc_assert((rc = ks_ivc_core_get_domain_id()) > 0, rc);
    ivcXenClient = (struct libivc_client *) ks_platform_alloc(sizeof (struct libivc_client));
    libivc_checkp(ivcXenClient, OUT_OF_MEM);
    memset(ivcXenClient, 0, sizeof (struct libivc_client));

    mutex_init(&ivcXenClient->mutex);
    ivcXenClient->num_pages = 1;
    ivcXenClient->connection_id = LIBIVC_ID_NONE;

    libivc_assert_goto((rc = ks_platform_alloc_shared_mem(1, IVC_DOM_ID,
                             &ivcXenClient->buffer,
                             &ivcXenClient->mapped_grants)) == SUCCESS, ERROR);

    ivcXenClient->ringbuffer = ks_platform_alloc(sizeof(ivcXenClient->ringbuffer[0]));
    ivcXenClient->ringbuffer->buffer = ivcXenClient->buffer;
    ivcXenClient->ringbuffer->length = ivcXenClient->num_pages*PAGE_SIZE;
    ivcXenClient->ringbuffer->num_channels = 2;
    ivcXenClient->ringbuffer->channels = ks_platform_alloc(2*sizeof(ivcXenClient->ringbuffer->channels[0]));
    ringbuffer_channel_create(&ivcXenClient->ringbuffer->channels[0], PAGE_SIZE/2);
    ringbuffer_channel_create(&ivcXenClient->ringbuffer->channels[1], PAGE_SIZE/2);
    ringbuffer_use(ivcXenClient->ringbuffer);

    libivc_enable_events(ivcXenClient);

    //If this is the initial Xen domain, then don't set up any further connection to
    //the backend.
    if(xen_initial_domain())
    {
        return SUCCESS;
    }

    libivc_assert_goto((rc = ks_platform_createUnboundEvtChn(ivcXenClient->remote_domid,
                             &ivcXenClient->event_channel)) == SUCCESS,
                       ERROR);
#ifdef _WIN32
    snprintf(path, IVC_MAX_PATH, IVC_MAX_PATH - 1, IVC_FRONTEND_IVC_PATH, domId);
#else
    snprintf(path, IVC_MAX_PATH - 1, IVC_FRONTEND_IVC_PATH, domId);
#endif
    do 
    {
        rc = ks_platform_start_xenbus_transaction(&trans);
        if (rc == SUCCESS) 
        {
            rc = ks_platform_xenstore_write_int(path, IVC_FRONTEND_RW_PAGE,
                grant_ref_from_mapped_grant_ref_t(ivcXenClient->mapped_grants[0]), trans);
            rc = ks_platform_xenstore_write_int(path, IVC_FRONTEND_EVENT_CHANNEL,
                                                ivcXenClient->event_channel, trans);
            rc = ks_platform_xenstore_printf(trans, path, IVC_FRONTEND_STATUS, "%d", READY);
        }
        rc = ks_platform_end_xenbus_transaction(trans);
    } while (rc == ERROR_AGAIN);

    if (rc != SUCCESS) 
    {
        rc = IVC_UNAVAILABLE;
        libivc_error("Failed to write out backend driver connection data. rc = %d\n", rc);
        goto ERROR;
    }

    // now bind the event channel to the backend driver to a callback so we can
    // be notified of data.
    libivc_assert_goto((rc = ks_platform_bind_event_callback(ivcXenClient->event_channel,
                             &ivcXenClient->irq_port,
                             ks_ivc_core_backend_event)) == SUCCESS, ERROR);
    goto END;

ERROR:
    libivc_error("Failed to setup frontend driver.\n");
    if (ivcXenClient) 
    {
        if (ivcXenClient->event_channel) 
        {
            ks_platform_closeEvtChn(ivcXenClient->event_channel);
        }

        if (ivcXenClient->ringbuffer) 
        {
            // TODO: Tear down Rian's ringbuffer code here
            // ringBuffer_free(ivcXenClient->ringbuffer);
        }



        if (ivcXenClient->buffer) 
        {
            ks_platform_free_shared_mem(ivcXenClient->buffer);
        }

        free(ivcXenClient);
        ivcXenClient = NULL;
    }
END:
    return rc;
}

int
ks_ivc_core_uninit(void)
{
    int rc = SUCCESS;
    char path[IVC_MAX_PATH];
#ifdef __linux
    if (xen_initial_domain()) 
    {
        xenback_teardown();
    } 
    else 
    {
#endif
        memset(path, '\0', IVC_MAX_PATH);
#ifdef _WIN32
        snprintf(path, IVC_MAX_PATH, IVC_MAX_PATH - 1, IVC_FRONTEND_DEVICE_PATH, domId);
#else
        snprintf(path, IVC_MAX_PATH - 1, IVC_FRONTEND_IVC_PATH, domId);
#endif
        if (ivcXenClient) 
        {
            ks_platform_unbind_event_callback(ivcXenClient->irq_port);
            ks_platform_closeEvtChn(ivcXenClient->event_channel);
            ks_platform_free_shared_mem(ivcXenClient->buffer);
            ks_platform_free(ivcXenClient);
            ivcXenClient = NULL;
        }

        ks_platform_xenstore_rm(path, IVC_FRONTEND_IVC_NODE);
#ifdef __linux
    }
#endif

#ifdef __linux
    _TRACE();

#endif
    return rc;
}

int
ks_ivc_core_get_domain_id(void)
{
#ifdef __linux
    xenbus_transaction_t trans;
    int rc = ERROR_AGAIN;

    memset(&trans, 0, sizeof (xenbus_transaction_t));
    if (xen_initial_domain()) 
    {
        domId = 0;
    } 
    else 
    {
        if (domId < 1) 
        {
            do 
            {
                libivc_info("Starting xenbus transaction.\n");
                rc = ks_platform_start_xenbus_transaction(&trans);
                if (rc == SUCCESS) 
                {
                    libivc_info("Reading xenstore domid.\n");
                    rc = ks_platform_read_int(trans, "domid", "", &domId);
                }
                rc = ks_platform_end_xenbus_transaction(trans);
            } while (rc == ERROR_AGAIN);
        }
    }

    return domId;
#else
    int rc = ERROR_AGAIN;

    if (xen_initial_domain()) 
    {
        domId = 0;
    } 
    else 
    {
        if (domId < 1) 
        {
            libivc_info("Reading xenstore domid.\n");
            rc = ks_platform_read_int(NULL, NULL, "domid", &domId);
            if (rc != SUCCESS)
            {
                libivc_error("Failed to read domid!\n");
                return -1;
            }
        }
    }

    return domId;
#endif
}

/**
 * Sends a packet to the IVC backend, requesting that the remote be automatically
 * notified if we go down. This should be called on each new connection, to allow
 * proper resource cleanup.
 *
 * @param client The client whose rsemote should be notified.
 * @param targetComm The internal client that connects us to the IVC backend.
 */
static int
ks_ivc_request_remote_notification_on_death(struct libivc_client *client, struct libivc_client *targetComm)
{
    libivc_message_t message;

    libivc_checkp(client, -EINVAL);
    libivc_checkp(targetComm, -EINVAL)

    //... and build a domain death notification request.
    memset(&message, 0, sizeof(libivc_message_t));
    message.type          = NOTIFY_ON_DEATH;
    message.msg_start     = HEADER_START;
    message.msg_end       = HEADER_END;
    message.to_dom        = IVC_DOM_ID;
    message.from_dom      = (uint16_t)domId;
    message.target_domain = client->remote_domid;

    //Finally, send the messsage.
    libivc_send(targetComm, (char *)&message, sizeof(libivc_message_t));

    return SUCCESS;
}


/**
 * Packs all of the grants for a relevant client into a message, so they
 * can be communicated to another domain via the backend. Note that this
 * involves creation of a temporary shared channel, which _must_ be freed
 *
 * @param client The client whose grants are to be communicated.
 * @param message The message to be populated with connection information.
 * @return A collection of granted memory representing a channel, 
 *      which must be freed with ks_ivc_core_close_grant_channel,
 *      or NULL on failure.
 */
static grant_ref_t * 
ks_ivc_core_open_grant_channel(struct libivc_client *client, libivc_message_t * message)
{
    int rc;
    uint32_t grantIndex = 0;

    // arrays to hold all grant references.
    grant_ref_t *channel;
    mapped_grant_ref_t *channel_grants = NULL;

    // 5/18/15 DRS - Dumbing it down, share 32 pages of memory that will store
    // all the grant references for the large memory buffer.  this is to remove
    // the number of points that can be causing the old methods to break
    // share memory to remote domain to store our local buffer grant refs.
    // (our read/write, their read only)
    libivc_assert((rc = ks_platform_alloc_shared_mem(NUM_GRANT_REFS,
                        client->remote_domid, 
                        (char **) &channel, &channel_grants)) == SUCCESS,
                        NULL);
    memset(channel, 0, NUM_GRANT_REFS * PAGE_SIZE);

    // We could probably scale back from the 32 pages every time, and do
    // something a little smarter
    for (grantIndex = 0; grantIndex < client->num_pages; grantIndex++) 
    {
        channel[grantIndex] = grant_ref_from_mapped_grant_ref_t(client->mapped_grants[grantIndex]);
    }

    for (grantIndex = 0; grantIndex < NUM_GRANT_REFS; grantIndex++) 
    {
        message->descriptor[grantIndex] = grant_ref_from_mapped_grant_ref_t(channel_grants[grantIndex]);
    }

    return channel;
}

/**
 *
 */
static void
ks_ivc_core_close_grant_channel(grant_ref_t * channel)
{
    libivc_checkp(channel);

    // Clear out the existing grant channel, so the grant refs don't
    // exist in the page pool. This makes debugging a whole lot less
    // confusing.
    memset(channel, 0x00, NUM_GRANT_REFS * PAGE_SIZE);

    // And tear down the grant channel.
    ks_platform_free_shared_mem((char *) channel);
}


static int
ks_ivc_send_connect_message(struct libivc_client *client)
{
#ifdef __linux
    unsigned long timeout = 0;
#else
	LARGE_INTEGER TimeOut;
	ULONG ticks;
	LARGE_INTEGER CurTime;
#endif
  
    grant_ref_t *channel = NULL;
    libivc_message_t message;
    int rc = INVALID_PARAM;
    MESSAGE_TYPE_T respType = MNONE; // will be set to the response message type.
    uint16_t status = SUCCESS;
    size_t avail = 0;
    struct libivc_client *targetComm = NULL;

    // make sure the client isn't NULL.
    libivc_checkp(client, INVALID_PARAM);

    // make sure no garbage is being sent across in the message.
    memset(&message, 0, sizeof (libivc_message_t));

    message.from_dom = (uint16_t) domId;
    message.to_dom = client->remote_domid;
    message.connection_id = client->connection_id;
    message.port = client->port;
    message.msg_start = HEADER_START;
    message.msg_end = HEADER_END;
    message.type = CONNECT;
    message.event_channel = client->event_channel;
    message.num_grants = client->num_pages;

    // If we're trying to connect to another client in the same domain,
    // we can send over the connect message directly.
    if(message.to_dom == message.from_dom) 
    {
        // In leiu of grant references, send over the in-kernel address of the
        // memory we'll be sharing. 
        message.kernel_address = (uintptr_t)client->buffer; 
        rc = ks_ivc_core_handle_connect_msg(&message);
        return rc;
    }


    if (!xen_initial_domain()) 
    {
        targetComm = ivcXenClient;
    }
#ifdef __linux
    else 
    {
        targetComm = ks_platform_get_domu_comm(client->remote_domid);
    }
#endif

    libivc_checkp(targetComm, INTERNAL_ERROR);
    libivc_checkp(targetComm->ringbuffer, INTERNAL_ERROR);

    //'clear' the ringbuffer
	//Prior to establishing a connection, we should clear the buffer of
	//any leftover messages. This is primarily to support the Windows case
	//where a hotplug event occurs while the VM is asleep. The xenevtchn
	//doesn't properly propogate the disconnect event on wakeup. As a result
	//when we try to establish another connection, instead of reading back an ACK or NACK
	//we read the leftover disconnect, which causes issues.
    libivc_clear_ringbuffer(targetComm);
    
    // Otherwise, we should have grants that we want to communicate to a
    // remote domain. Open a chnanel for us to communicate them.
    //
    libivc_checkp(client->mapped_grants, INVALID_PARAM);
    channel = ks_ivc_core_open_grant_channel(client, &message); 

    libivc_disable_events(targetComm);
    libivc_assert((rc = libivc_send(targetComm, (char *) &message,
                                    sizeof (libivc_message_t))) == SUCCESS, rc);
    wmb();
    avail = 0;
    memset(&message, 0, sizeof (libivc_message_t));
#ifdef __linux
    timeout = jiffies + SEND_TIMEOUT;
#else
	//set timeout to 3 seconds
	ticks = (3 * 10000000) / KeQueryTimeIncrement();
	KeQueryTickCount(&TimeOut);
	TimeOut.QuadPart += ticks;
#endif

    while (avail < sizeof (libivc_message_t)) 
    {
        rmb();
        libivc_getAvailableData(targetComm, &avail);
        if (avail < sizeof (libivc_message_t)) 
        {
            msleep(10); // give the system a chance to do something else.
        }
#ifdef __linux
        if (time_after(jiffies, timeout)) 
#else
        KeQueryTickCount(&CurTime);
        if (TimeOut.QuadPart < CurTime.QuadPart)
#endif
        {
            libivc_warn("Timed out waiting for connection response.\n");
            rc = TIMED_OUT;
            goto END;
        }
    }

    rmb();
    libivc_assert_goto((rc = libivc_recv(targetComm, (char *) &message,
                                         sizeof (libivc_message_t))) == SUCCESS, END);
    // We have different cases to handle on the message back.
    // 1. On a channeled message, we expect an ACK message back and status SUCCESS
    //    if we initiated the connection.
    // 2. On a chance the remote domain isn't up, we expect an ACK back from the backend driver
    //    and a status of CONNECTION_REFUSED
    // 3. On the chance that the remote dom fails or isn't listening, we expect an ACK
    //    and an appropriate status set in the status field. IE: CONNECTION_REFUSED
    // 2 and 3 will be treated as the same.
    respType = (MESSAGE_TYPE_T) message.type;
    if (respType == ACK) 
    {
        status = message.status;
        if (status != SUCCESS) 
        { // cases 2 and 3.
            libivc_error("Connection attempt failed, status back was %d\n", status);
            rc = status;
            goto END;
        } 
        else 
        {
            rc = SUCCESS;
        
            //Finally, ask the xen backend to notify the other side if we go down.
            //This ensures they're notified if we die violently and don't have a chance
            //to send a disconnect ourselves.
            ks_ivc_request_remote_notification_on_death(client, targetComm);
        }
    } 
    else 
    {
        libivc_warn("An unexpected message type was sent back on the connection request. Type = %d\n", respType);
        rc = INTERNAL_ERROR;
        goto END;
    }

END:
    if (channel) 
    {
        ks_ivc_core_close_grant_channel(channel);
        channel = NULL;
    }

    libivc_enable_events(targetComm);

    return rc;
}

static int
ks_ivc_core_unpack_msg_grants(grant_ref_t *descGrant, uint16_t from_dom, uint16_t from_port, 
    uint64_t from_connection_id, char **kAddress, uint32_t num_grants, file_context_t *f)
{
    grant_ref_t *grants = NULL;
    int rc;

    // 5/18/15 DRS, changed to fixed number of grant ref descriptors pages coming in with message.
    // the message we receive will contain 2 arrays for each leg of the channel of a fixed size NUM_GRANT_REFS.
    // these references are memory that needs to be mapped in to get the rest of the grant references from the
    // main shared memory.
    // dump out our descriptors

    libivc_assert((rc = ks_platform_map_grants(from_dom, from_port, from_connection_id,
                        descGrant, NUM_GRANT_REFS, (char **) &grants, NULL)) == SUCCESS, rc);

    libivc_checkp_goto(grants, ERROR);
    // the memory mapped in should now contain grant references to the real memory the remote wants to share.
    libivc_assert_goto((rc = ks_platform_map_grants(from_dom, from_port, from_connection_id, grants, num_grants, kAddress, f)) == SUCCESS, ERROR);

    goto EXIT;
ERROR:
    libivc_info("Failed to map in memory, rc = %d\n", rc);

EXIT:
    if (grants) 
    {
        ks_platform_unmap_remote_grants( (char *) grants);
    }

    return rc;
}


/**
 * Notifies the given client that an event has been received.
 *
 * @param client The client to be notified
 * @param SUCCESS or an appropriate error number
 */ 
int
ks_ivc_core_notify_event_received(struct libivc_client *client)
{
    list_head_t *cpos = NULL, *ctmp = NULL; // client list iterators
    callback_node_t *callback = NULL;
    uint8_t calledback = 0;

    libivc_checkp(client, -EINVAL);

    // if it's associated with a user space process, notify it.
    if (client->context != NULL) 
    {
        ks_platform_notify_us_client_event(client);
        calledback = 1; // so we can know below we actually notified someone.
    } 
    else 
    {
        if (!list_empty(&client->callback_list)) 
        {
            list_for_each_safe(cpos, ctmp, &client->callback_list) 
            {
                callback = container_of(cpos, callback_node_t, node);
                if (callback->eventCallback != NULL) 
                {
                    callback->eventCallback(client->opaque, client);
                    calledback = 1;
                }
            }
        }
    }

    return SUCCESS;
}

static void
ks_ivc_client_remote_event_fired(int irq)
{
    struct libivc_client *client = NULL;

    FIND_CLIENT_CLIST(client, (client->irq_port == (uint32_t)irq));

    if (client == NULL) 
        FIND_CLIENT_SLIST(client, (client->irq_port == (uint32_t)irq));


    ks_ivc_core_notify_event_received(client);
    libivc_put_client(client);
}


/**
 * called when an inbound message to connect is received by handling an event
 * triggered by the backend XEN driver.
 * @param msg - The message containing information on the connection.
 * to the outbound client. Otherwise in case of a server listening, it should be NULL
 * @return SUCCESS or appropriate error number.
 */
int
ks_ivc_core_handle_connect_msg(libivc_message_t *msg)
{
    int rc = INVALID_PARAM;
    struct libivc_client *newClient = NULL;
    struct libivc_client *responseClient = NULL;
    struct libivc_server *server = NULL;
    libivc_message_t respMessage;

    libivc_info("Received inbound connection request.\n");
    memset(&respMessage, 0, sizeof (libivc_message_t));

    //the message at least has to be NON null.
    libivc_checkp(msg, INVALID_PARAM);
    libivc_assert_goto(msg->num_grants > 0, ERROR);

    // copy in the incoming message data to the response
    memcpy(&respMessage, msg, sizeof (libivc_message_t));
    respMessage.status = (uint8_t) rc;
    respMessage.to_dom = respMessage.from_dom;
    respMessage.from_dom = (uint16_t) domId;
    respMessage.type = ACK;

    // who are we sending the response to?
    if (!xen_initial_domain()) 
    {
        responseClient = ivcXenClient;
    }
#ifdef __linux
    else 
    {
        responseClient = ks_platform_get_domu_comm(msg->from_dom);
    }
#endif

    if (ks_ivc_check_for_equiv_client(msg->from_dom, msg->port, msg->connection_id, 1)) {
        rc = CONNECTION_REFUSED;
        goto ERROR;
    }

    // Find a server willing to accept connections from this domain, port, and with the provided
    // connection ID-- which is really just an extension of the port, but without the connotation
    // of definining a service.
    server = libivc_find_listening_server(msg->from_dom, msg->port, msg->connection_id);

    rc = CONNECTION_REFUSED;
    libivc_checkp_goto(server, ERROR);

    mutex_lock(&server->client_mutex);

    newClient = (struct libivc_client *) ks_platform_alloc(sizeof (struct libivc_client));
    rc = OUT_OF_MEM;
    libivc_checkp_goto(newClient, ERROR);
    memset(newClient, 0, sizeof (struct libivc_client));

    newClient->remote_domid = msg->from_dom;
    newClient->port = msg->port;
    newClient->server_side = 1;
    newClient->num_pages = msg->num_grants;
    newClient->connection_id = msg->connection_id;

    // Track a reference to this new client.
    libivc_get_client(newClient);

#ifdef _WIN32
    __pragma(warning(push))
    __pragma(warning(disable : 4127))
#endif
    INIT_LIST_HEAD(&newClient->node);
    INIT_LIST_HEAD(&newClient->callback_list);
#ifdef _WIN32
    __pragma(warning(pop))
#endif

    mutex_init(&newClient->mutex);
    newClient->buffer = NULL;

    // If this request came from another domain, map in the remote memory, and
    // bind to their provided event channel.
    if(newClient->remote_domid != domId)
    {
        libivc_assert_goto((rc = ks_ivc_core_unpack_msg_grants(msg->descriptor, msg->from_dom, msg->port, msg->connection_id, &newClient->buffer,
                                     newClient->num_pages, server->context)) == SUCCESS, ERROR);

        libivc_assert_goto((rc = ks_platform_bind_interdomain_evt(msg->from_dom, msg->event_channel,
                                 &newClient->irq_port,
                                 ks_ivc_client_remote_event_fired)) == SUCCESS, ERROR);
        respMessage.status = SUCCESS;
    } 
    // Otherwise, map in the local memory-- but skip event channel creation,
    // as we can communicate events directly.
    else {
        libivc_assert_goto((rc = ks_platform_map_local_memory((void *)msg->kernel_address, msg->port, &newClient->buffer,
                                     newClient->num_pages, server->context)) == SUCCESS, ERROR);
    }

    rc = INTERNAL_ERROR;

    // If we're connecting to another domain, send back an ACK.
    if(msg->from_dom != msg->to_dom) {
        libivc_checkp_goto(responseClient, ERROR);
        libivc_disable_events(responseClient);
        libivc_assert_goto((rc = libivc_send(responseClient, (char *) &respMessage,
                                             sizeof (libivc_message_t))) == SUCCESS, ERROR);
    }

    list_add(&newClient->node, &server->client_list);
    mutex_unlock(&server->client_mutex);

    server->connect_cb(server->opaque, newClient);
    libivc_put_server(server);
    return SUCCESS;

ERROR:
    if (newClient != NULL) 
    {
        list_del(&newClient->node);
        if (newClient->buffer) 
        {
            if(newClient->remote_domid != domId)
                ks_platform_unmap_remote_grants(newClient->buffer);
            else
                ks_platform_unmap_local_memory(newClient->buffer);
        }

        libivc_put_client(newClient);
        newClient = NULL;
    }

    respMessage.status = (uint8_t) rc;
    if (responseClient)
    {
        libivc_send(responseClient, (char *) &respMessage, sizeof (libivc_message_t));
    }

    if(server) {
        mutex_unlock(&server->client_mutex);
        libivc_put_server(server);
    }

    return rc;
}

/**
 * Notifies an IVC client that its local or remote counterpart has disconnected.
 * Assumes that the caller holds a reference on the client, or the client list lock
 * (for a client-side client) or server client-list lock (for a server-side client).
 *
 * @param client The client that should receive the notication.
 */
int ks_ivc_core_notify_disconnect(struct libivc_client *client)
{
    list_head_t *cpos = NULL, *ctmp = NULL; // client list iterators
    uint8_t calledback = 0;
    callback_node_t *callback = NULL;

    libivc_checkp(client, INVALID_PARAM);

    if (client->context != NULL) 
    {
        ks_platform_notify_us_client_disconnect(client);
        calledback = 1; // so we can know below we actually notified someone.
    } 
    else 
    {
        // kernel space callback.
        if (!list_empty(&client->callback_list)) 
        {
            list_for_each_safe(cpos, ctmp, &client->callback_list) 
            {
                callback = container_of(cpos, callback_node_t, node);
                if (callback->disconnectCallback != NULL) 
                {
                    callback->disconnectCallback(client->opaque, client);
                    calledback = 1;
                    return SUCCESS;
                }
            }
        }
    }

    if (!calledback) 
    {
        libivc_info("weird, client disconnected but nobody is watching.\n");
        libivc_info("dom: %u, port: %u\n", client->remote_domid, client->port);
    }

    return SUCCESS;
}

/**
 * Triggered by a remote message coming in requesting to disconnect a client.
 * @param msg - message describing client that wants to disconnect.
 * @return SUCCESS or appropriate error number.
 */
int
ks_ivc_core_handle_disconnect_msg(libivc_message_t *msg)
{
    struct libivc_client *client = NULL;
    int rc;

    libivc_checkp(msg, INVALID_PARAM);
    libivc_info("Got a disconnect message from %u:%u.\n", msg->from_dom, msg->port);

    FIND_CLIENT_CLIST(client, (
          (client->remote_domid  == msg->from_dom)          &&
          (client->port          == msg->port)              &&
          (client->connection_id == msg->connection_id)));

    if (client == NULL)
    {
        FIND_CLIENT_SLIST(client, (
          (client->remote_domid  == msg->from_dom)          &&
          (client->port          == msg->port)              &&
          (client->connection_id == msg->connection_id)));
    }

    rc = ks_ivc_core_notify_disconnect(client);
    libivc_put_client(client);

    return rc;
}


/**
 * Triggered by a backend notification that a remote domain has died.
 * @param msg - message describing the domain that has gone down
 * @return SUCCESS or appropriate error number.
 */
int
ks_ivc_core_handle_domain_death_notification(libivc_message_t *msg)
{
    struct list_head *cpos, *ctemp;
    struct list_head *spos, *stemp;
    struct libivc_client *client = NULL;
    struct libivc_server *server = NULL;

    libivc_checkp(msg, INVALID_PARAM);

    mutex_lock(&ivc_client_list_lock);

    // Notify each of the standalone clients targeting the relevant domain that the 
    // given domain has gone down.
    list_for_each_safe(cpos, ctemp, &ivcClients)
    {
        client = container_of(cpos, struct libivc_client, node);
        if(client->remote_domid == msg->target_domain)
        {
            ks_ivc_core_notify_disconnect(client);
        }
    }

    mutex_unlock(&ivc_client_list_lock);

    mutex_lock(&ivc_server_list_lock);

    // Notify each of server-side clients targeting the relevant domain that the given
    // domain has gone down.
    list_for_each_safe(spos, stemp, &ivcServerList)
    {
        server = container_of(spos, struct libivc_server, node);

        mutex_lock(&server->client_mutex);
        list_for_each_safe(cpos, ctemp, &server->client_list)
        {
            client = container_of(cpos, struct libivc_client, node);
            if(client->remote_domid == msg->target_domain)
            {
                ks_ivc_core_notify_disconnect(client);
            }
        }
        mutex_unlock(&server->client_mutex);
    }

    mutex_unlock(&ivc_server_list_lock);

    return SUCCESS;
}

/**
 * Driver level connect function called when libivc_connect is ready to hand off to platform.
 * @param client The ivc client trying to make the connection.
 * @return SUCCESS or appropriate error number.
 */
int
ks_ivc_core_connect(struct libivc_client *client)
{
    int rc = SUCCESS;

    libivc_checkp(client, INVALID_PARAM);
    libivc_assert(client->num_pages > 0, INVALID_PARAM);

    // calls that are equivalent in both.
    // allocate and share the memory to the remote domain.

    // Don't allow dom0 to connect to any other domain. 
    //
    // e.g. dom0 can connect to itself, and can act as a server, but cannot 
    // connect not to other domains, as we don't want it granting out its
    // memory.
    // 
    // BTK: Note this is a policy thing, never share control domain's memory out
    if ((domId == IVC_DOM_ID) && (client->remote_domid != IVC_DOM_ID)) {
        libivc_info("Rejected connection that would have dom0 grant out memory.");
        return CONNECTION_REFUSED;
    }
        
    // If we're communicating with a domain other than ourselves, allocate an event
    // channel to communicate IVC events.
    if(client->remote_domid != domId) {
        // if the remote domain doesn't exist, creating the event channel will fail
        // as soon as you try to create an event channel.
        // we need to create an unbound event channel to the remote domain.
        

        libivc_assert_goto((rc = ks_platform_createUnboundEvtChn(client->remote_domid,
                                 &client->event_channel)) == SUCCESS,
                           ERROR);
        libivc_assert_goto((rc = ks_platform_bind_event_callback(client->event_channel,
                                 &client->irq_port,
                                 ks_ivc_client_remote_event_fired)) == SUCCESS, ERROR);
    } else {
        client->irq_port = 0;
    }

    // Allocate shared memory. This will be either:
    // - Granted memory, if this is an inter-VM client; or
    // - A big block of kernel virtual memory, if this is a IVC client being used
    //   on the same VM.
    libivc_assert_goto((rc = ks_platform_alloc_shared_mem(client->num_pages,
                             client->remote_domid, &client->buffer, &client->mapped_grants)) == SUCCESS, ERROR);

    // Send a connection request to the local or remote domain. 
    libivc_assert_goto((rc = ks_ivc_send_connect_message(client)) == SUCCESS, ERROR);

    rc = SUCCESS;
    goto END;

ERROR:
    if (client->buffer) 
    {
        ks_platform_free_shared_mem(client->buffer);
    }

    if (client->irq_port > 0) 
    {
        ks_platform_unbind_event_callback(client->irq_port);
        client->event_channel = 0;
        client->irq_port = 0;
    }
    else if (client->event_channel)
    {
        ks_platform_closeEvtChn(client->event_channel);
        client->event_channel = 0;
    }

END:
    return rc;
}

/**
 * Driver-level reconnect handler.
 */
int
ks_ivc_core_reconnect(struct libivc_client *client, uint16_t new_domid, uint16_t new_port)
{
    int rc = SUCCESS;

    libivc_info("In %s\n", __FUNCTION__);
    libivc_checkp(client, INVALID_PARAM);
    libivc_assert(client->buffer, INVALID_PARAM);

    // Apply the new domain ID, and new port information.
    client->remote_domid = new_domid;
    client->port = new_port;

    // Tear down any existing event channels. We'll bring up new event channels, 
    // if necessary.
    if(client->event_channel) {
        ks_platform_unbind_event_callback(client->irq_port);
        ks_platform_closeEvtChn(client->event_channel);
    }

    // If this a remote reconnection, re-forge the event connection.
    if(client->remote_domid != domId)
    {
        libivc_assert_goto((rc = ks_platform_createUnboundEvtChn(client->remote_domid,
                                 &client->event_channel)) == SUCCESS, ERROR);

        libivc_assert_goto((rc = ks_platform_bind_event_callback(client->event_channel,
                                 &client->irq_port,
                                 ks_ivc_client_remote_event_fired)) == SUCCESS, ERROR);
    }

    // Finally, send out our reconnect to the remote domain.
    libivc_info("Sending reconnect message.\n");
    rc = ks_ivc_send_connect_message(client);


    if(rc == SUCCESS)
    {
        return rc;
    }

ERROR:


    if (client->irq_port > 0)
    {
        ks_platform_unbind_event_callback(client->irq_port);
        client->event_channel = 0;
        client->irq_port = 0;
    }
    else if (client->event_channel)
    {
        ks_platform_closeEvtChn(client->event_channel);
        client->event_channel = 0;
    }

    return rc;
}



int
ks_ivc_core_notify_remote(struct libivc_client *client)
{
    libivc_checkp(client, INVALID_PARAM);

    return ks_platform_fire_remote_event(client);
}

int
ks_ivc_core_disconnect(struct libivc_client *client)
{
    int rc = SUCCESS;
    struct libivc_client *msgTarget = NULL;
    libivc_message_t disMessage;

    libivc_checkp(client, INVALID_PARAM);

    // If this message is being transmitted to a remote recipient,
    // notify the remote.
    if(domId != client->remote_domid)
    {
        // send a message to the remote domain to notify them we're closing.
        if (!xen_initial_domain()) 
        {
            msgTarget = ivcXenClient;
        }
#ifdef __linux
        else 
        {
            msgTarget = ks_platform_get_domu_comm(client->remote_domid);
        }
#endif

        memset(&disMessage, 0, sizeof (libivc_message_t));
        
        disMessage.from_dom = (uint16_t) ks_ivc_core_get_domain_id();
        disMessage.to_dom = client->remote_domid;
        disMessage.connection_id = client->connection_id;
        disMessage.msg_start = HEADER_START;
        disMessage.msg_end = HEADER_END;
        disMessage.type = DISCONNECT;
        disMessage.port = client->port;

        rc = libivc_send(msgTarget, (char *) &disMessage, sizeof (libivc_message_t));
    }
    // Otherwise, if we're talking to another context in the same
    // domain, find and notify our counterpart.
    else {
        rc = ks_platform_notify_local_disconnect(client);
    }



    if (client->irq_port) 
    {
        ks_platform_unbind_event_callback(client->irq_port);
        client->irq_port = 0;
    }
    else if (client->event_channel)
    {
        ks_platform_closeEvtChn(client->event_channel);
        client->event_channel = 0;
    }
    

    if (client->buffer && !client->server_side) 
    {
        ks_platform_free_shared_mem(client->buffer);
    } 
    else if (client->buffer && (client->remote_domid == domId)) 
    {
        ks_platform_unmap_local_memory(client->buffer);
    } 
    else if(client->buffer)
    {
        ks_platform_unmap_remote_grants(client->buffer);
    }

    client->buffer = NULL;
    return rc;
}

/**
 * No extra processing is required within the driver core outside of what
 * libivc already does.  Only here because it's a required function pointer.
 * @param server unused
 * @return SUCCESS
 */
int
ks_ivc_core_reg_svr_lsnr(struct libivc_server *server)
{
    UNUSED(server);

    return SUCCESS;
}

/**
 * No extra processing is required within the driver core outside of what
 * libivc already does.  Only here because it's a required function pointer.
 * @param server unused
 * @return SUCCESS
 */

int
ks_ivc_core_unreg_svr_lsnr(struct libivc_server *server)
{
    UNUSED(server);

    return SUCCESS;
}

/**
 * Utility method that given a userspace IVC server returns the internally stored one.
 * @param externalServer Non null userspace representation of the ivc server.
 * @return internal server, or NULL if no match found.
 */
static struct libivc_server *
ks_ivc_core_find_internal_server(struct libivc_server_ioctl_info *externalServer,
    file_context_t *context)
{
    struct libivc_server * server = NULL;
    libivc_checkp(externalServer, NULL);

    FIND_SERVER_SLIST(server,
       (server->port                   == externalServer->port)                    &&
       (server->limit_to_domid         == externalServer->limit_to_domid)          &&
       (server->limit_to_connection_id == externalServer->limit_to_connection_id)  &&
       (server->context                == context));

    return server;
}

/**
 * Utility method that given the userspace representation of the connected client
 * returns the internally stored one.  You never want to trust anything that comes
 * from the user space.
 * @param externalClient The user space representation of the client.
 * @return the internal client, or NULL if not found.
 */
struct libivc_client *
ks_ivc_core_find_internal_client(struct libivc_client_ioctl_info *externalClient)
{
    struct libivc_client *client = NULL;
    libivc_checkp(externalClient, NULL);

    // check the client list first.
    FIND_CLIENT_CLIST(client, (
        (client->remote_domid  == externalClient->remote_domid)   &&
        (client->port          == externalClient->port)           && 
        (client->connection_id == externalClient->connection_id)  &&
        (client->server_side   == externalClient->server_side)));

    if(client)
        return client;

    FIND_CLIENT_SLIST(client, (
        (client->remote_domid  == externalClient->remote_domid)   &&
        (client->port          == externalClient->port)           && 
        (client->connection_id == externalClient->connection_id)  &&
        (client->server_side   == externalClient->server_side)));

    return client;
}

/**
 * Utility function that checks for the existence of a logically equivalent
 * client. Used to prevent multiple equivalent clients from connecting at
 * once, which confuses IVC and leads to yucky segfaults.
 *
 * @param domid The remote domid
 * @param port The port connected over
 * @param conn_id The connection id
 * @param server_side Whether the client exists under a server
 * @return true if client exists, false otherwise.
 */
bool
ks_ivc_check_for_equiv_client(uint16_t domid, uint16_t port, uint64_t conn_id, uint8_t server_side)
{
    struct libivc_client_ioctl_info * client_info;
    bool ret;

    client_info = (struct libivc_client_ioctl_info *) malloc(sizeof(struct libivc_client_ioctl_info));
    client_info->remote_domid = domid;
    client_info->port = port;
    client_info->connection_id = conn_id;
    client_info->server_side = server_side;

    if (ks_ivc_core_find_internal_client(client_info) != NULL) {
        libivc_error("A client with remote_domid %d, port %d, and connection id %d already exists.",
                        domid, port, conn_id);
        libivc_error("Not accepting new connection.");
        ret = true;
    } else {
        ret = false;
    }

    free(client_info);
    return ret;
}

/**
 * Services IOCTLs coming from user space for ivc client related operations.
 * @param ioctlNum The ioctl number.
 * @param client - non null pointer to user space client payload.
 * @param context - non null pointer to user space file context.
 * @return SUCCESS or appropriate error number.
 */
int
ks_ivc_core_client_ioctl(uint8_t ioctlNum, struct libivc_client_ioctl_info *client,
                         file_context_t *context)
{
    int rc = INVALID_PARAM;
    list_head_t *pos = NULL, *temp = NULL;
#ifdef _WIN32
    NTSTATUS status;
#endif

    // never trust anything coming from user space, look up our own internal
    // representation of the connected client.
    struct libivc_client *internalClient = NULL;
    struct libivc_server *internalServer = NULL; // for the accept ioctl
    struct libivc_server_ioctl_info externalServer; // just used to find the internal one.

    // sanity check the parameters
    libivc_checkp(client, rc);
    libivc_checkp(context, rc);
    libivc_assert(ioctlNum <= IVC_RECONNECT_IOCTL, INVALID_PARAM);

    switch (ioctlNum) 
    {
        case IVC_CONNECT_IOCTL: 
        case IVC_RECONNECT_IOCTL:
        {

            if(ioctlNum == IVC_CONNECT_IOCTL) {
                // perform the driver level connection to the remote domain.
                libivc_assert((rc = libivc_connect_with_id(&internalClient, client->remote_domid,
                                                   client->port, client->num_pages, client->connection_id)) == SUCCESS, rc);
                libivc_checkp(internalClient, INTERNAL_ERROR);
            } else {
                internalClient = ks_ivc_core_find_internal_client(client);
                libivc_checkp(internalClient, INTERNAL_ERROR);

                // Call our reconnect method on the internal server. This
                // automatically adjusts its remote domid/port to match the new
                // values...
                rc = libivc_reconnect(internalClient, client->new_domid, client->new_port);
                libivc_put_client(internalClient);
                libivc_assert(rc == SUCCESS, rc);

                // ... and adjust the userspace client's domid and port. (These
                // values will be returned to the userspace side, and it will
                // use them to apply its client's internal state.
                client->remote_domid = client->new_domid;
                client->port = client->new_port;
            }

#ifdef _WIN32 // setup references to user space events, this MUST be done withing the context 
              //of the user space process.
            status = ObReferenceObjectByHandle( client->client_disconnect_event, 
                                                SYNCHRONIZE, *ExEventObjectType, UserMode,
                                                &internalClient->client_disconnect_event, NULL);
            if(NT_SUCCESS(status))
            {

                status = ObReferenceObjectByHandle(client->client_notify_event,
                                                SYNCHRONIZE, 
                                                *ExEventObjectType, UserMode, 
                                                &internalClient->client_notify_event, NULL);

                //If client_notify_event reference failed, deference client_disconnect_event
                if(!NT_SUCCESS(status))
                {
                    if(internalClient->client_disconnect_event)
                    {
                        ObDereferenceObject(internalClient->client_disconnect_event);
                        internalClient->client_disconnect_event = NULL;
                    }

                }
            }
#endif
            // need to map to userspace.
            libivc_checkp(internalClient->buffer, INTERNAL_ERROR);
            libivc_info("Mapping %p to user space.\n", internalClient->buffer);
            rc = ks_platform_map_to_userspace(internalClient->buffer, &client->buffer,
                                              client->num_pages * PAGE_SIZE, context);

            if (rc != SUCCESS) 
            {
                // close the connection, it's useless if the client can't get to it.
                libivc_error("Failed to map addresses to user space, closing connection.\n");
                libivc_disconnect(internalClient);
                return rc;
            }

            internalClient->context = context;

#ifdef __linux // linux specific fields for user space event notifications.  
            internalClient->client_disconnect_event = client->client_disconnect_event;
            internalClient->client_notify_event = client->client_notify_event;
#endif

        }
        break;
        case IVC_DISCONNECT_IOCTL: 
        {
            internalClient = ks_ivc_core_find_internal_client(client);
            libivc_checkp(internalClient, INVALID_PARAM);

#ifdef _WIN32
            if (internalClient->client_disconnect_event) 
            {
                ObDereferenceObject(internalClient->client_disconnect_event);
                internalClient->client_disconnect_event = NULL;
            }

            if (internalClient->client_notify_event) 
            {
                ObDereferenceObject(internalClient->client_notify_event);
            }
#endif
            libivc_disconnect(internalClient);
            libivc_put_client(internalClient);

            break;
        }
        case IVC_NOTIFY_REMOTE_IOCTL: 
        {
            internalClient = ks_ivc_core_find_internal_client(client);
            libivc_checkp(internalClient, INVALID_PARAM);
            rc = ks_platform_fire_remote_event(internalClient);
            libivc_put_client(internalClient);
            return rc;
        }
        case IVC_SERVER_ACCEPT_IOCTL:
        {
            memset(&externalServer, 0, sizeof (struct libivc_server_ioctl_info));
            externalServer.port = client->port;
            externalServer.limit_to_domid = client->remote_domid;
            externalServer.limit_to_connection_id = client->connection_id;
            internalServer = ks_ivc_core_find_internal_server(&externalServer, context);
            libivc_checkp(internalServer, INVALID_PARAM); // nobody listening on this port.

            // only the process that owns the server may accept from it.
            if(internalServer->context != context) {
                libivc_error("Trying to accept on another process' server!\n");
                goto accept_done;
            }

            mutex_lock(&internalServer->client_mutex);
            list_for_each_safe(pos, temp, &internalServer->client_list) 
            {
                internalClient = container_of(pos, struct libivc_client, node);
                if (internalClient->remote_domid == IVC_DOM_ID && internalClient->port == IVC_PORT) 
                {
                    libivc_error("Bootstrap connection is associated with a server!\n");
                    continue;
                }

                // Note: we don't need to up the reference count, here, as we
                // hold the relevant server's client mutex, and thus have its
                // reference on the internal client.

                if (internalClient->context == NULL) 
                {
                    internalClient->context = context;

                    // if this isn't channeled, there may not be a local buffer to map.
                    if (internalClient->buffer != NULL) 
                    {
                        libivc_assert_goto((rc = ks_platform_map_to_userspace(internalClient->buffer, 
                                            &client->buffer,
                                            internalClient->num_pages * PAGE_SIZE,
                                            context)) == SUCCESS, lock_done);
                        client->num_pages = internalClient->num_pages;
                    }

                    client->remote_domid = internalClient->remote_domid;
                    client->port = internalClient->port;
                    client->server_side = internalClient->server_side = 1;
                    client->opaque = internalClient->opaque;
                    client->connection_id = internalClient->connection_id;
#ifdef __linux // linux specific fields for user space event notifications.  
                    internalClient->client_disconnect_event = client->client_disconnect_event;
                    internalClient->client_notify_event = client->client_notify_event;
#endif
                    libivc_info("Successfully accepted client %u:%u -- id: %u\n", client->remote_domid, client->port, (unsigned int)client->connection_id);
                    rc = SUCCESS;
                }
            }
        lock_done:
            mutex_unlock(&internalServer->client_mutex);
        accept_done:
            libivc_put_server(internalServer);
            break;
        }
        default:
        {
            rc = INVALID_PARAM;
        }
    }

    return rc;
}

static void
ks_ivc_core_us_connectCallback(void *opaque, struct libivc_client *newClient)
{
    struct libivc_server *server = NULL;
    (void)opaque;
    libivc_checkp(newClient);

    // Find the server that was listening for our new client...
    server = libivc_find_listening_server(newClient->remote_domid, newClient->port, newClient->connection_id);
    libivc_checkp(server);

    // ... and notify it that a client has connected.
    ks_platform_notify_us_client_connect(server);

    libivc_put_server(server);
}


static void closeServer(struct libivc_server *server)
{
    libivc_checkp(server);
    libivc_info("Shutting down dangling server left behind by closed process.\n");
#ifdef _WIN32
    if (server->client_connect_event) 
    {
        ObDereferenceObject(server->client_connect_event);
        server->client_connect_event = NULL;
    }
#endif
    libivc_shutdownIvcServer(server);
}

static void closeClient(struct libivc_client *client)
{
    libivc_info("Closing dangling client connection related to process.\n");
#ifdef _WIN32
    if (client->client_disconnect_event) 
    {
        ObDereferenceObject(client->client_disconnect_event);
        client->client_disconnect_event = NULL;
    }
    if (client->client_notify_event) 
    {
        ObDereferenceObject(client->client_notify_event);
        client->client_notify_event = NULL;
    }
#endif
    libivc_disconnect(client);
}

/**
 * Services IOCTLs coming from user space for ivc server related operations.
 * @param ioctlNum - The IOCTL number as defined in ivc_ioctl_defs.h
 * @param server - non null pointer to user space server payload.
 * @param context - non null pointer to user space file context.
 * @return SUCCESS or appropriate error number.
 */
int
ks_ivc_core_server_ioctl(uint8_t ioctlNum, struct libivc_server_ioctl_info *server,
                         file_context_t *context)
{
    int rc = INVALID_PARAM;
    struct libivc_server *internalServer = NULL;
#ifdef _WIN32
    NTSTATUS status;
#endif

    // sanity check all parameters.
    libivc_checkp(server, rc);
    libivc_checkp(context, rc);
    libivc_assert(ioctlNum >= IVC_REG_SVR_LSNR_IOCTL && ioctlNum <= IVC_UNREG_SVR_LSNR_IOCTL, rc);

    switch (ioctlNum) {
        case IVC_REG_SVR_LSNR_IOCTL: 
        {
            rc = libivc_start_listening_server(&internalServer, server->port,
                server->limit_to_domid, server->limit_to_connection_id,
                ks_ivc_core_us_connectCallback, server->opaque);

            libivc_assert(rc == SUCCESS, rc);
            internalServer->context = context;
            internalServer->client_connect_event = server->client_connect_event;
#ifdef _WIN32
            status = ObReferenceObjectByHandle(server->client_connect_event, SYNCHRONIZE, *ExEventObjectType, UserMode, &internalServer->client_connect_event, NULL);
            if (!NT_SUCCESS(status)) 
            {
                libivc_info("Failed to get valid reference to handle for server connect event.\n");
                libivc_shutdownIvcServer(internalServer);
                rc = INTERNAL_ERROR;
            }
#endif
            return rc;
            break;
        }
        case IVC_UNREG_SVR_LSNR_IOCTL:
        {
            internalServer = ks_ivc_core_find_internal_server(server, context);
            libivc_put_server(internalServer);
            closeServer(internalServer);
            break;
        }
        default:
        {
            rc = INVALID_PARAM;
            break;
        }
    }

    return rc;
}

/**
 * Notifies the IVC core that a user space process has terminated and it needs to
 * undo any closing operations that weren't previously cleaned up correctly.
 * @param context - non null pointer to user space file context
 * @return SUCCESS or appropriate error number.
 */
int
ks_ivc_core_file_closed(file_context_t *context)
{
    struct libivc_server *server = NULL;
    struct libivc_client *client = NULL;

    libivc_checkp(context, INVALID_PARAM);

    ITER_SERVER_IN_LIST(server, &ivcServerList, closeServer, (server->context == context));
    ITER_CLIENT_IN_LIST(client, &ivcClients, closeClient, (client->context == context));

    return SUCCESS;
}
