// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

/*
 * File:   libivc_private.h
 * Author: user
 *
 * Created on April 2, 2015, 11:47 AM
 */

#ifndef LIBIVC_PRIVATE_H
#define LIBIVC_PRIVATE_H

//#define DEBUG_KERNEL_LOCKS

#ifdef  __cplusplus
extern "C"
{
#endif
#include <ringbuffer.h>
#include <libivc_types.h>
#include <libivc.h>
#ifdef __linux
#ifndef KERNEL
#include <list.h>
#include <pthread.h>
#include <sys/user.h> // for PAGE_SIZE
typedef pthread_mutex_t mutex_t;
#define mutex_init(x) pthread_mutex_init((x),NULL)
#define mutex_destroy(x) pthread_mutex_destroy((x))
#define mutex_lock(x) pthread_mutex_lock((x))
#define mutex_unlock(x) pthread_mutex_unlock((x))

// Userland implementation of the kernel atomics;
// should work with most linux compilers
// (gcc, intel, and clang are verified to work).

typedef struct {
    volatile int counter;
} atomic_t;

static inline int atomic_dec_and_test(atomic_t * target)
{
       return !(__sync_sub_and_fetch(&target->counter, 1));
}

static inline void atomic_inc(atomic_t * target)
{
       (void)__sync_fetch_and_add(&target->counter, 1);
}

typedef uint32_t grant_ref_t;
typedef uint32_t evtchn_port_t;
#else
#include <stdarg.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <asm/atomic.h>
#ifdef DEBUG_KERNEL_LOCKS
#define mutex_lock(t) do { libivc_info("LOCK\t%s %s:%d\n", #t, __PRETTY_FUNCTION__, __LINE__); mutex_lock(t); } while(0)
#define mutex_unlock(t) do { libivc_info("UNLOCK\t%s %s:%d\n", #t, __PRETTY_FUNCTION__, __LINE__); mutex_unlock(t); } while(0)
#endif


typedef struct list_head list_head_t;
typedef struct mutex mutex_t;
#endif
#else
#ifdef KERNEL
#define mutex_init(x) ExInitializeFastMutex((x))
#define mutex_lock(x) ExAcquireFastMutex((x))
#define mutex_unlock(x) ExReleaseFastMutex((x))
#define mutex_destroy(x) (x)


#endif

/**
 * Atomic increment/decrement functions.
 */
static void atomic_inc(atomic_t * target)
{
	InterlockedIncrement(target);
}


static BOOLEAN atomic_dec_and_test(atomic_t * target)
{
	return (InterlockedDecrement(target) == 0);
}


#include <list.h>
#ifndef KERNEL
#include <Windows.h>
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define mutex_t HANDLE

__inline void
mutex_init(mutex_t *x)
{
    *x = CreateMutex(NULL, FALSE, NULL);
    libivc_assert(*x != INVALID_HANDLE_VALUE);
}

__inline void
mutex_lock(mutex_t *x)
{
    DWORD res;
    res = WaitForSingleObject(*x, INFINITE);
    libivc_assert(res == WAIT_OBJECT_0);
}

__inline void
mutex_unlock(mutex_t *x)
{
    libivc_assert(ReleaseMutex(*x));
}

__inline void
mutex_destroy(mutex_t *x)
{
    libivc_assert(CloseHandle(*x));
}



#endif
#endif  // __linux

#ifdef KERNEL
#ifdef __linux
#include <xen/grant_table.h>
#include <xen/events.h>

#define grant_ref_from_mapped_grant_ref_t(x) (x)
#define mapped_grant_ref_t grant_ref_t

#else
typedef FAST_MUTEX mutex_t;

#include <gnttab_interface.h>

typedef struct {
    ULONG ref;
    PXENBUS_GNTTAB_ENTRY entry;
    PXENBUS_GNTTAB_CACHE cache;
    BOOLEAN valid;
} mapped_grant_ref_t;

#define grant_ref_from_mapped_grant_ref_t(x) (x.ref)

typedef ULONG grant_ref_t;

#endif
#else
#ifdef __linux
#define mapped_grant_ref_t grant_ref_t
#endif
#ifdef _WIN32
typedef uint32_t grant_ref_t;
typedef HANDLE mutex_t;
typedef PVOID mapped_grant_ref_t;
#endif
#endif
#ifdef _WIN32
typedef ULONG evtchn_port_t;
#endif
extern list_head_t ivcServerList;
extern list_head_t ivcClients;
extern mutex_t ivc_server_list_lock;
extern mutex_t ivc_client_list_lock;

typedef struct grant_share_descriptor {
    uint32_t numGrants;
    grant_ref_t *grants;
    uint8_t readOnly;
    char *kAddress;
    uint16_t remoteDomainId;
} grant_share_descriptor_t;

// the grants will be passed in the shared memory itself.  The first page of memory
// will contain this struct header to let the remote domain know how to map it in.
#define HEADER_START 0xDEAD
#define HEADER_END 0xBEEF

#define SERVER_SIDE_TX_EVENT_FLAG 0x80
#define CLIENT_SIDE_TX_EVENT_FLAG 0x01

#define CLIENT_TO_SERVER_CHANNEL 0
#define SERVER_TO_CLIENT_CHNANEL 1

#pragma pack(push,1)

typedef struct grant_mem_header {
    uint16_t header_start;
    uint32_t num_grants;
    uint16_t header_end;
} grant_mem_header_t;
#pragma pack(pop)

#define NUM_GRANT_REFS 32
#pragma pack(push,1)


#ifdef _WIN32

__pragma(warning(push))
__pragma(warning(disable : 4201))
#endif


/**
 * The primary messaging type for backend data exchange. 
 *
 * If you modify this, be sure that the total of all data included in the package
 * can fit inside of a single page.
 */
typedef struct libivc_message {
    uint16_t msg_start;         // validation field for message format start             2
    uint16_t from_dom;          // who it's coming from.                                 2
    uint16_t to_dom;            // who it's going to.                                    2
    uint16_t port;              // the "port" associated with the message.               2
    uint32_t event_channel;     // the event channel number.                             4
    uint8_t type;               // type of message. MESSAGE_TYPE_T                       1
    uint32_t num_grants;        // how many grants are coming in if CONNECT message.     4
    uint64_t connection_id;     // the self-reported ID for the relevant connection      8

    // The main body of the message, which is either:
    // - A collection of grant references, for the inter-VM case, or
    // - An kernel virtual address of the target buffer, if this is
    //   a connection occurring on the same VM.
    union {                                                                          //128
        grant_ref_t descriptor[NUM_GRANT_REFS];
        uintptr_t kernel_address;
    };

    //Per-packet data fields.                                                            2
    union {
        int16_t status;         // if an ACK to a message, the remote status of sending it.
        uint16_t target_domain; // notification parmater, if this is related to a domain-death notification
    };

    uint16_t msg_end;           // validation field for message format end               2
} libivc_message_t;

#ifdef _WIN32
__pragma(warning(pop))
#endif

#pragma pack(pop)

struct libivc_client_ioctl_info {

    uint16_t remote_domid; // remote domain id connected to.
    uint16_t port; // remote "port" number connected to.
    uint32_t num_pages; // number of pages for local buffer.
    uint8_t server_side; // if this is a client under a server, set to non zero.
    list_head_t callback_list; // list of callbacks that have been registered.
    void *opaque;
#ifdef __linux
    int client_disconnect_event; // event fd for client disconnecting.
    int client_notify_event; // event fd for general event notification.
#else
    HANDLE client_disconnect_event; // event handle for client disconnecting.
    HANDLE client_notify_event; // event handle for general event notification.
#endif
    char *buffer;  // the locally allocated data buffer address.
    uint64_t connection_id; // the specified-on-creation connection ID

    // The new domid/port, to be applied after a reconnect. Used only by
    // the reconnect IOCTLs.
    uint16_t new_domid;
    uint16_t new_port;
};

/**
 * The main internal structure that is passed around between libivc and the platform.
 * Each platform will need to add fields to it if required here.
 */
struct libivc_client {
    list_head_t node;                 // used when being stored in global or server-side client list (depends on server_side).
    uint16_t remote_domid;            // remote domain id connected to.
    uint16_t port;                    // remote "port" number connected to.
    uint32_t num_pages;               // number of pages for local buffer.
    char *buffer;                     // the locally allocated data buffer address.
    struct ringbuffer_t *ringbuffer;  // pointer to ring buffer
    mapped_grant_ref_t *mapped_grants;              // grant refs for local memory. kernel only
    mutex_t mutex;                    // for locking on client when reading/writing/modifying.
    evtchn_port_t event_channel;      // event channel for remote events. kernel only
    uint32_t irq_port;                // after binding to an irq callback, we need to track the local port.
    list_head_t callback_list;        // list of callbacks that have been registered.
    uint8_t server_side;              // if this is a client under a server, set to non zero.
    void *opaque;                     // For API users to store per client data
    void *context;                    // the user space context. kernel only.
    uint64_t connection_id;           // a user-specified piece of information tha helps the client/server to identify the connection

    atomic_t ref_count;               // holds the current reference count for this object

#ifdef __linux
    int client_disconnect_event;    // event fd for client disconnecting.
    int client_notify_event;        // event fd for general event notification.

#ifndef KERNEL
    pthread_t client_event_thread;  // thread that polls on client eventfds
#endif

#else
    HANDLE client_disconnect_event; // event handle for client disconnecting.
    HANDLE client_notify_event; // event handle for general event notification.
#endif
};

struct libivc_server_ioctl_info {
	uint16_t port;
  uint16_t limit_to_domid;
  uint64_t limit_to_connection_id;
    void *opaque;
#ifdef __linux
    int client_connect_event; // event fd for connection available.
#else
	HANDLE client_connect_event;
#endif
};

/**
 * The server side of the connections.  The server is responsible for listening on a
 * given port, and handling connection events from the driver, then notifiying the
 * user of the new connection after completion (autochanneling if required) via
 * the callback function.
 */
struct libivc_server {
    list_head_t node;                       // for tracking in list of servers.
    uint16_t port;                          // port listening to.
    uint16_t limit_to_domid;                // if not LIBIVC_DOMID_ANY, only connections from this domid will be accepted
    uint64_t limit_to_connection_id;        // if not LIBIVC_ID_ANY, only connections with this connection ID will be accepted
    list_head_t client_list;                // list of clients connected to this port.
    uint8_t running;                        // non zero if running.
    libivc_client_connected connect_cb;     // callback to user for connections
    mutex_t client_mutex;                   // lock for libivcclients
    void *context;                          // if owned by a user space process, not null in KERNEL.
    void *opaque;
    atomic_t ref_count;                     // holds the current reference count for this object

#ifdef __linux
    int client_connect_event; // event fd for connection available.
#ifndef KERNEL
    pthread_t listener_thread; //thread that awaits server connections
#endif
#else
    HANDLE client_connect_event; // event for connection available.
#endif
};
typedef struct libivc_client libivc__client_t, *plibivc_client_t;
typedef struct libivc_server libivc_server_t, *plibivc_server_t;

typedef int (*platform_register_server_listener)(struct libivc_server *);
typedef int (*platform_unregister_server_listener)(struct libivc_server *);
typedef int (*platform_notify_remote)(struct libivc_client *);
typedef int (*platform_connect)(struct libivc_client *);
typedef int (*platform_reconnect)(struct libivc_client *, uint16_t new_domid, uint16_t new_port);
typedef int (*platform_disconnect)(struct libivc_client *);

typedef struct platform_functions {
    platform_register_server_listener registerServerListener;
    platform_unregister_server_listener unregisterServerListener;
    platform_notify_remote notifyRemote;
    platform_connect connect;
    platform_disconnect disconnect;
    platform_reconnect reconnect;
} platform_functions_t, *pplatform_functions_t;

/**
 * The platform specific libraries are responsible for setting up the appropriate
 * function pointers to handle platform/ring layer specific details
 * @param pf non null pointer to platform_functions_t with null function pointers initially.
 * @return SUCCESS or appropriate error number.
 */
extern int
libivc_platform_init(platform_functions_t *pf);



/**
 * Disconnects the ivc struct and notifies the remote of it if possible.
 * This version assumes the IVC client and server list locks are held.
 *
 * @param ivc - the connected ivc struct.
 * @param from_public_api - true if this function is being called from the
 *    public API; indicates that the relevant server's client lock is not
 *    held
 */
void
__libivc_disconnect(struct libivc_client *client, bool from_public_api);


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
__libivc_find_listening_server(uint16_t connecting_domid, uint16_t port, uint64_t connection_id);


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
__libivc_shutdown_server(struct libivc_server * server);


typedef struct callback_node {
    list_head_t node;
    libivc_client_event_fired eventCallback;
    libivc_client_disconnected disconnectCallback;
} callback_node_t;

#define __FIND_CLIENT_CLIST(client, x) \
    do                                                                      \
    {                                                                       \
        list_head_t *cpos = NULL, *ctmp = NULL;                             \
        list_for_each_safe(cpos, ctmp, &ivcClients)                         \
        {                                                                   \
            client = container_of(cpos, struct libivc_client, node);        \
            if(x)                                                           \
            {                                                               \
                libivc_get_client(client);                                  \
                break;                                                      \
            }                                                               \
            else                                                            \
            {                                                               \
                client = NULL;                                              \
            }                                                               \
        }                                                                   \
    } while(0)


#define FIND_CLIENT_CLIST(client, x) \
    do                                                                      \
    {                                                                       \
        mutex_lock(&ivc_client_list_lock);                                  \
        __FIND_CLIENT_CLIST(client, x);                                     \
        mutex_unlock(&ivc_client_list_lock);                                \
    } while(0)


//
// TODO: Make lock safe after verifying nothing here will cause deadlock.
//
#define ITER_CLIENT_IN_LIST(client, list, fn, cond) \
    do                                                                      \
    {                                                                       \
        list_head_t *cpos = NULL, *ctmp = NULL;                             \
        list_for_each_safe(cpos, ctmp, list)                                \
        {                                                                   \
            client = container_of(cpos, struct libivc_client, node);        \
            if(client && cond)                                              \
            {                                                               \
                fn(client);                                                 \
            }                                                               \
        }                                                                   \
    } while(0)

#define __FIND_CLIENT_SLIST(client, x) \
    do                                                                      \
    {                                                                       \
        struct libivc_server *server = NULL;                                \
        list_head_t *cpos = NULL, *ctmp = NULL;                             \
        list_head_t *spos = NULL, *stmp = NULL;                             \
        list_for_each_safe(spos, stmp, &ivcServerList)                      \
        {                                                                   \
            server = container_of(spos, struct libivc_server, node);        \
            mutex_lock(&server->client_mutex);                              \
            list_for_each_safe(cpos, ctmp, &server->client_list)            \
            {                                                               \
                client = container_of(cpos, struct libivc_client, node);    \
                if(x)                                                       \
                {                                                           \
                    libivc_get_client(client);                              \
                    break;                                                  \
                }                                                           \
                else                                                        \
                {                                                           \
                    client = NULL;                                          \
                }                                                           \
            }                                                               \
            mutex_unlock(&server->client_mutex);                            \
            if (client != NULL)                                             \
            {                                                               \
                break;                                                      \
            }                                                               \
        }                                                                   \
    } while(0)


#define FIND_CLIENT_SLIST(client, x) \
    do {                                                                    \
        mutex_lock(&ivc_server_list_lock);                                  \
        __FIND_CLIENT_SLIST(client, x);                                     \
        mutex_unlock(&ivc_server_list_lock);                                \
    } while(0)



#define FIND_SERVER_SLIST(server, x) \
    do                                                                      \
    {                                                                       \
        list_head_t *pos = NULL, *temp = NULL;                              \
        mutex_lock(&ivc_server_list_lock);                                  \
        list_for_each_safe(pos, temp, &ivcServerList)                       \
        {                                                                   \
            server = container_of(pos, struct libivc_server, node);         \
            if(x)                                                           \
            {                                                               \
                libivc_get_server(server);                                  \
                break;                                                      \
            }                                                               \
            else                                                            \
            {                                                               \
                server = NULL;                                              \
            }                                                               \
        }                                                                   \
        mutex_unlock(&ivc_server_list_lock);                                \
    } while(0)

//
// TODO: Make lock safe after verifying nothing here will cause deadlock.
//
#define ITER_SERVER_IN_LIST(server, list, fn, cond) \
    do                                                                      \
    {                                                                       \
        list_head_t *pos = NULL, *temp = NULL;                              \
        list_for_each_safe(pos, temp, list)                                 \
        {                                                                   \
            server = container_of(pos, struct libivc_server, node);         \
            if(server && cond)                                              \
            {                                                               \
                fn(server);                                                 \
            }                                                               \
        }                                                                   \
    } while(0)

#ifdef  __cplusplus
}
#endif

#endif  /* LIBIVC_PRIVATE_H */

