// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

/*
 * File:   libivc.h
 * Public interface to the IVC API.  IVC standing for Inter-V.M. communications.
 * This essentially takes the existing ideas behind libxenvchan, and the XEN
 * grantdev and grantalloc drivers and mashes them all together.
 */

#ifndef LIBIVC_H
#define	LIBIVC_H

#ifdef	__cplusplus
extern "C"
{
#endif

#ifndef KERNEL
#include <stdio.h>
#include <stdint.h>
#else
#ifdef _WIN32
#include <ntddk.h>
#include "wintypes.h"
#endif
#endif

#define TAG "[ivc]:"

#include <libivc_types.h>
#include <libivc_debug.h>

struct libivc_client;
struct libivc_server;


/**
 * Each IVC connection can be started with or without specifying a connection
 * ID, which exists only for the convenience of the listening server.
 *
 * By default, the connection ID is LIBIVC_ID_NONE.
 */
static const uint64_t LIBIVC_ID_NONE = 0xFFFFFFFFFFFFFFFF;
static const uint64_t LIBIVC_ID_ANY  = 0xFFFFFFFFFFFFFFFF;

static const uint16_t LIBIVC_DOMID_ANY = 0xFFFF;


struct libivc_client *lookup_ivc_client(uint16_t domid, uint16_t port, uint64_t connection_id);

    /**
     * Register function pointers to be notified of events callback style. NULLs may
     * be passed if you are not interested in a particular type of event.
     * @param client The ivc client of interest.
     * @param eventCallback when a remote event has been fired to this clients port
     * @param disconnectCallback when the remote domain wants to disconnect this client.
     * @return SUCCESS, or appropriate error message.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_register_event_callbacks(struct libivc_client *client,
                                    libivc_client_event_fired eventCallback,
                                    libivc_client_disconnected disconnectCallback,
                                    void *opaque);

    /**
     * Client style connection to a remote domain listening for connections.
     * @param ivc - pointer to receive created connection into
     * @param remote_dom_id - remote domain to connect to.
     * @param remote_port - remote port to connect to.
     * @param memSize - size of buffer to share. Should be a PAGE size multiple.  If not,
     *		    the size will be adjusted by the driver and you will be able to get
     *		    the adjusted size by using the utility functions on the returned struct.
     * @return SUCCESS or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_connect(struct libivc_client **ivc, uint16_t remote_dom_id, uint16_t remote_port, uint32_t numPages);

    /**
     * Client style connection to a remote domain listening for connections. This variant
     * also accepts a connection ID, which is useful for disambiguating or namespacing incoming
     * clients.
     *
     * @param ivc - pointer to receive created connection into
     * @param remote_dom_id - remote domain to connect to.
     * @param remote_port - remote port to connect to.
     * @param memSize - size of buffer to share. Should be a PAGE size multiple.  If not,
     *		    the size will be adjusted by the driver and you will be able to get
     *		    the adjusted size by using the utility functions on the returned struct.
     * @param connection_id A unique number identifying the originator of the connection. 
     *        The driver will not allow more than one connection to exist with the same domain, port,
     *        and connection ID.
     *
     * @return SUCCESS or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_connect_with_id(struct libivc_client **ivc, uint16_t remote_dom_id, uint16_t remote_port, 
            uint32_t numPages, uint64_t connection_id);


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
	__declspec(dllexport)
#endif
    int
    libivc_reconnect(struct libivc_client * client, uint16_t remote_dom_id, uint16_t remote_port);


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
	__declspec(dllexport)
#endif
    uint64_t
    libivc_get_connection_id(struct libivc_client * client);



    /**
     * Sets up a listener for incoming connections from remote domains, and accepts any incoming
     * connections on the relevant port.
     *
     * @param server - pointer to receive ivc server object.
     * @param listening_port - port to listen for incoming connections on.
     * @param client_callback - callback to be notified of new client connections that have been fully established.
     * @param opaque - A user-specified object that will be passed to any relevant callbacks.
     * @return SUCCESS, or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_startIvcServer(struct libivc_server **server, uint16_t listening_port,
                          libivc_client_connected connectCallback, void *opaque);


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
	__declspec(dllexport)
#endif
    int
    libivc_start_listening_server(struct libivc_server **server, 
        uint16_t listening_port, uint16_t listen_for_domid, uint64_t listen_for_client_id, 
        libivc_client_connected connectCallback, void *opaque);


    /**
     * Blocks until something is ready for the user to read.
     * @param client
     * @return SUCCESS, or appropriate error number.
     */
    /*int
    libivc_wait_ready_read(struct libivc_client *client); */

    /**
     * Blocks until enough space is ready for the caller to write into buffer
     * @param client - connected client to write to.
     * @param size - space required for writing.
     * @return SUCCESS or appropriate error number.
     */
    /*int
    libivc_wait_ready_write(struct libivc_client *client, uint32_t size); */

    /**
     * Stop listening on the specified port, and close all connections associated with
     * the given port.
     * @param server to shutdown.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    void
    libivc_shutdownIvcServer(struct libivc_server *server);


    /**
     * Disconnects the ivc struct and notifies the remote of it if possible.
     * @param ivc - the connected ivc struct.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    void
    libivc_disconnect(struct libivc_client *client);


    /**
     * Determines if ivc is connected based on parameters at time of connect.
     * @param ivc - ivc struct describing connection.
     * @return 1 if connect, 0 otherwise.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    uint8_t
    libivc_isOpen(struct libivc_client *ivc);

    /**
     * Write as many bytes as possible up to srcLength from src to the ivc buffer
     * and return how many bytes were successfully written.
     * @param ivc - a connected ivc struct.
     * @param src - non null character buffer to copy from.
     * @param srcLength - size of the src buffer.
     * @param actualLength - number of bytes that were actually written.
     * @return SUCCESS or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_write(struct libivc_client *ivc, char *src, size_t srcLength, size_t *actualLength);

    /**
     * Try to write EXACTLY srcSize bytes to the ivc channel.  If they can't be written
     * because the buffer is full, 0 is returned. (Packet style send)
     * @param ivc - A connected ivc struct.
     * @param src - source buffer to write to the ivc connection.
     * @param srcSize - size of the source buffer and exact amount to write.
     * @return SUCCESS or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_send(struct libivc_client *ivc, char *src, size_t srcSize);

    /**
     * Read as many bytes as possible up to destSize into buffer dest, returns how
     * many bytes were read.
     * @param ivc - connected libivc struct.
     * @param dest - destination buffer to read data into
     * @param destSize - maximum number of bytes to read.
     * @param actualSize - pointer to receive actual bytes read.
     * @return SUCCESS or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_read(struct libivc_client *ivc, char *dest, size_t destSize, size_t *actualSize);

    /**
     * Read exactly destSize bytes from ivc, failing if there are less than the specified
     * amount available. (Packet style receive)
     * @param ivc - connected ivc struct.
     * @param dest - destination buffer to write to.
     * @param destSize - size of dest, and the exact number of bytes required to read.
     * @return SUCCESS, or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_recv(struct libivc_client *ivc, char *dest, size_t destSize);

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
#ifdef _WIN32
	__declspec(dllexport)
#endif
	int
	libivc_unsafe_write(struct libivc_client *ivc, char *src, size_t srcSize, size_t * actualLength);

	/**
	* Try to write EXACTLY srcSize bytes to the ivc channel, without locking the
	* client. If they can't be written because the buffer is full, 0 is returned.
	* Intended for use in Windows at IRQL levels higher than APC_LEVEL, in which
	* the client's FastMutex may not be used. It's up to the user to enforce mutual
	* exclusion in these cases.
	* @param ivc - A connected ivc struct.
	* @param src - source buffer to write to the ivc connection.
	* @param srcSize - size of the source buffer and exact amount to write.
	* @return SUCCESS or appropriate error number.
	*/
#ifdef _WIN32
	__declspec(dllexport)
#endif
	int
	libivc_unsafe_send(struct libivc_client *ivc, char *src, size_t srcSize);

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
#ifdef _WIN32
	__declspec(dllexport)
#endif
	int
	libivc_unsafe_read(struct libivc_client *ivc, char *dest, size_t destSize, size_t * actualSize);

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
#ifdef _WIN32
	__declspec(dllexport)
#endif
	int
	libivc_unsafe_recv(struct libivc_client *ivc, char *dest, size_t destSize);

    /**
     * Returns the remote domain id associated with the connection.
     * @param ivc - connected ivc struct.
     * @param dom - pointer to receive domain id value into.
     * @return SUCCESS or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_getRemoteDomId(struct libivc_client *ivc, uint16_t *dom);

    /**
     * return the port number for a connection.
     * @param ivc - connected ivc struct.
     * @param port - pointer to receive value into.
     * @return SUCCESS or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif

    int
    libivc_getport(struct libivc_client *ivc, uint16_t *port);

    /**
     * returns the local buffer that can be read and written to.  If it's a channeled
     * connection, the buffer will be offset by the number of bytes required to store
     * the ring buffer header.
     * @param ivc - connected ivc struct.
     * @param buffer - pointer to receive buffer pointer
     * @return SUCCESS or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_getLocalBuffer(struct libivc_client *ivc, char **buffer);

    /**
     * Returns the size of the local buffer minus any space required for ring buffer
     * headers.
     * @param ivc - connected ivc struct.
     * @param buffSize - parameter to receive buffer size into.
     * @return SUCCESS or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_getLocalBufferSize(struct libivc_client *ivc, size_t *buffSize);

    /**
     * Returns the READ ONLY remote buffer, offset by any ringbuffer headers, or NULL if not connected.
     * @param ivc - connected ivc struct.
     * @param remoteBuffer - pointer to receive address of buffer into.
     * @return SUCCESS or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_getRemoteBuffer(struct libivc_client *ivc, char **remoteBuffer);

    /**
     * Returns the size of the remote buffer minus the ring buffer headers, or null if not connected.
     * @param ivc - connected ivc struct.
     * @param buffSize - pointer to receive size into.
     * @return SUCCESS or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_getRemoteBufferSize(struct libivc_client *ivc, size_t *buffSize);

    /**
     * Retrieves how much space is available to write into the buffer.
     * @param client Non null pointer to client being used to write to.
     * @param space Non null pointer to receive space.
     * @return SUCCESS or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_getAvailableSpace(struct libivc_client *client, size_t *space);

    /**
     * Retrieves the amount of data available to read from the client connection.
     * @param client - non null pointer to client.
     * @param dataSize - non null pointer to receive data.
     * @return SUCCESS or appropriate error.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_getAvailableData(struct libivc_client *client, size_t *dataSize);

    /**
     * When the remote side sends or writes data to this client, tell it not to
     * fire remote events to us.  Usually you would do this when polling on data.
     * @param client Non null pointer to client.
     * @return SUCCESS or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_disable_events(struct libivc_client *client);

    /**
     * Let the remote domain know that you wish to receive events when it sends or
     * writes data in the ring buffer.
     * @param client Non null pointer to the client
     * @return SUCCESS or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_enable_events(struct libivc_client *client);

    /**
     * Checks to see if the remote side has enabled or disabled events.  If the client doesn't
     * have a remote buffer due to not being channeled, it will error.
     * @param client - the client to check.
     * @param enabled - pointer to receive value into. non zero if enabled.
     * @return SUCCESS or appropriate error number.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_remote_events_enabled(struct libivc_client *client, uint8_t *enabled);

    /**
     * Fires a XEN event to the remote domain.
     * @param client Non null pointer to client connected to remote.
     * @return SUCCESS or appropriate error message.
     */
#ifdef _WIN32
	__declspec(dllexport)
#endif
    int
    libivc_notify_remote(struct libivc_client *client);



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
#ifdef _WIN32
	__declspec(dllexport)
#endif
  struct libivc_server *
  libivc_find_listening_server(uint16_t connecting_domid, uint16_t port, uint64_t connection_id);



  /**
   * Claims a reference to an IVC server, incrementing its internal reference count.
   */
#ifdef _WIN32
	__declspec(dllexport)
#endif
void
libivc_get_server(struct libivc_server *server);

  /**
   * Releases a reference to an IVC server, decrementing its internal reference count.
   * If no one holds a reference to the server after this function, it will automatically be freed.
   */
#ifdef _WIN32
	__declspec(dllexport)
#endif
void
libivc_put_server(struct libivc_server *server);


  /**
   * Claims a reference to an IVC client, incrementing its internal reference count.
   */
#ifdef _WIN32
	__declspec(dllexport)
#endif
void
libivc_get_client(struct libivc_client *client);

  /**
   * Releases a reference to an IVC client, decrementing its internal reference count.
   * If no one holds a reference to the client after this function, it will automatically be freed.
   */
#ifdef _WIN32
	__declspec(dllexport)
#endif
void
libivc_put_client(struct libivc_client *client);

#ifdef _WIN32
    __declspec(dllexport)
#endif
int
libivc_clear_ringbuffer(struct libivc_client *client);
#ifdef	__cplusplus
}
#endif

#endif	/* LIBIVC_H */
