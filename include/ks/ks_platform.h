// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

/*
 * File:   ks_platform.h
 * Author: user
 *
 * Created on January 8, 2015, 1:39 PM
 */

#ifndef KS_PLATFORM_H
#define KS_PLATFORM_H

#ifdef  __cplusplus
extern "C"
{
#endif

#include <libivc_private.h>

#ifdef __linux

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <xen/grant_table.h>
#include <xen/xenbus.h>
#include <xen/events.h>
#include <linux/delay.h>
#include <linux/rcupdate.h>
#include <linux/eventfd.h>
#include <linux/fdtable.h>
#include <linux/jiffies.h>
#include <linux/mmu_notifier.h>

// time out value for sending/receiving messages between domains.
// each HZ = 1 second.  Slow running domains may require more time to
// respond.
#define SEND_TIMEOUT HZ * 6

#ifndef false
#define false 0
#endif
#ifndef true
#define true 1
#endif

#define KERNEL_GNTMAP 0
#define USER_GNTMAP 1

typedef struct xenbus_watch xenbus_watch_t;
typedef struct xenbus_transaction xenbus_transaction_t;
typedef struct list_head list_head_t;
typedef struct mutex mutex_t;

// per process handle back to user space and required information needed.

typedef struct file_context {
    struct task_struct *task;
    struct file *file;
    void *mapInfo;
    void *private;
    void *desc;
    void *mappedMem;
    struct mmu_notifier mn;
    struct mm_struct *mm;
} file_context_t;

#else
#pragma once

#include <wdftypes.h>
#include <ntstrsafe.h>
#include <wdm.h>
#include <evtchn_interface.h>
#include <store_interface.h>

#define snprintf _snprintf_s

typedef struct file_context {
    WDFFILEOBJECT file; // handle to process that opened the driver.
} file_context_t;

#endif
typedef void (*event_channel_callback)(int irq);

typedef struct {
    list_head_t listHead;
    int irq;
#ifdef _WIN32
    /* TODO: semantics of "port" and "event_channel" backwards */
    PXENBUS_EVTCHN_CHANNEL winPort;
    KDPC dpc;
#endif
    atomic_t ref_count;
    evtchn_port_t event_channel;
    event_channel_callback callback;
} event_channel_info_t;

#ifdef _WIN32
typedef PXENBUS_STORE_TRANSACTION xenbus_transaction_t;
#endif

/**
 * Allocate memory and return a pointer to it.
 * @param memSize size of memory to allocate
 * @return a pointer to the allocated memory, or NULL if we are all out.
 */
void *
ks_platform_alloc(size_t memSize);

/**
 * Free previously allocated memory.
 * @param mem the memory previously allocated.
 */
void
ks_platform_free(void *mem);

/**
 * Allocates memory for sharing to a remote domain and grants it.
 * @param numPages The number of pages to share
 * @param remoteDomId The remote domain id being shared to.
 * @param readOnly Non zero for read only memory to the remote dom.
 * @param mem Pointer to receive address into.
 * @param grantRefs pointer to receive list of grant refs into.  Should not be
 * modified outside of platform itself.
 * @return SUCCESS or appropriate error message.
 */
int
ks_platform_alloc_shared_mem(uint32_t numPages, uint16_t remoteDomId,
                             char **mem, mapped_grant_ref_t **grantRefs);


/**
 * Free the shared memory previously created by ks_platform_alloc_shared_mem.
 * @param mem - Non NULL pointer returned in ks_platform_alloc_shared_mem
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_free_shared_mem(char *mem);

/**
 * given a xen event channel port number, bind it to a local irq number
 * and a callback that will be called when the event is fired in the platform driver.
 * @param port - the remote xen event channel number.
 * @param localIrq - Pointer to receive the local number bound to .
 * @param callback - the callback that will be triggered on the event firing.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_bind_event_callback(evtchn_port_t port, uint32_t *localIrq,
                                event_channel_callback callback);

/**
 * Given a remote domains inter-domain event channel, binds it to a local irq
 * for event notifications and when triggered calls the event callback.
 * @param remoteDomId - Id of remote domain
 * @param port - event channel port number.
 * @param localIrq - NON null pointer to receive the local irq number.
 * @param callback - function to be called back when event fires.
 * @return SUCCESS, or appropriate error number.
 */
int
ks_platform_bind_interdomain_evt(uint16_t remoteDomId, evtchn_port_t port,
                                 uint32_t *localIrq, event_channel_callback callback);


/**
 * End event notifications on the localIrq which was bound to in
 * ks_platform_bind_event_callback.
 * @param localIrq - localIrq returned from ks_platform_bind_event_callback
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_unbind_event_callback(int localIrq);

/**
 * Create an unbound inter-domain channel for communication with a given domain.
 * @param remoteDomId remote domain to create channel to.
 * @param eventPort variable to receive event port
 * @return SUCCESS, or appropriate error number.
 */
int
ks_platform_createUnboundEvtChn(uint16_t remoteDomId, evtchn_port_t *eventPort);

/**
 * Closes a previously open channel.
 * @param eventChannel channel created by ks_platform_createUnboundEvtChn.
 * @return SUCCESS, or appropriate error number.
 */
int
ks_platform_closeEvtChn(evtchn_port_t eventChannel);

/**
 * Platform specific wrapper around starting a xenbus transaction.
 * @param trans - Non null pointer to a transaction struct
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_start_xenbus_transaction(xenbus_transaction_t *trans);

/**
 * Platform specific wrapper around ending a xenbus transaction.
 * @param trans - xenbus transaction to end (not a pointer).
 * @return SUCCESS, or appropriate error number.
 */
int
ks_platform_end_xenbus_transaction(xenbus_transaction_t trans);

/**
 * Reads an integer value from the xenstore
 * @param trans - xenbus transaction that was previously started.
 * @param path - path where node being read exists.
 * @param node - the node or name of value to read.
 * @param value - pointer to receive value into.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_read_int(xenbus_transaction_t trans, char *path, char *node,
                     int *value);


/**
 * Writes an int value to node under path.
 * @param path - base path where node will be written
 * @param node - node or name of value being written.
 * @param value - the value
 * @param trans - transaction that has been started.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_xenstore_write_int(const char *path, const char *node,
                               int value, xenbus_transaction_t trans);

/**
 * Printf style writing to xenstore.
 * @param trans - transaction that was started.
 * @param path - path which node will be written to.
 * @param node - node or name value will be written to.
 * @param fmt - printf style format
 * @param ... - variable args required by the format.
 * @return SUCCESS or appropriate error number
 */
int
ks_platform_xenstore_printf(xenbus_transaction_t trans, const char *path,
                            const char *node, const char *fmt, ...);

/**
 * Removes a path/node from xenstore.
 * @param path - the path to remove
 * @param node - a specific node under the path to remove.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_xenstore_rm(const char *path, const char *node);

/*
 * Maps in memory grants from the local domain
 * @param kernel_address The address of the object requesting mapping.
 * @param grants - array of grant references from remote domain
 * @param numGrants - number of grant references in grants array
 * @param mem - pointer to receive virtually contigous address.
 * @param readOnly - non zero for writable, but ensure the remote shared
 * it that way unless you like VMs freezing.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_map_local_memory(void * kernel_address, uint16_t port, 
                      char **mem, uint32_t numPages, file_context_t *f);

/**
 * Maps in memory grants from a remote domain
 * @param domId - domain id of remote domain
 * @param grants - array of grant references from remote domain
 * @param numGrants - number of grant references in grants array
 * @param mem - pointer to receive virtually contigous address.
 * @param readOnly - non zero for writable, but ensure the remote shared
 * it that way unless you like VMs freezing.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_map_grants(uint16_t domId, uint16_t port, uint64_t connection_id,
                       grant_ref_t *grants, uint32_t numGrants, char **mem, file_context_t *f);

/**
 * Unmaps and releases memory from a remote domain.
 * @param mem - memory address returned from ks_platform_map_grants.
 * @return - SUCCESS or appropriate error number.
 */
int
ks_platform_unmap_remote_grants(char *mem);


/**
 * Unmaps and releases memory shared from the same domain.
 * @param mem - memory address returned from ks_platform_map_grants.
 * @return - SUCCESS or appropriate error number.
 */
int
ks_platform_unmap_local_memory(char *mem);


/**
 * Fires a XEN event specified by the dom id in client.
 * @param client - non null pointer to object that describes connection.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_fire_remote_event(struct libivc_client *client);

/**
 * Remove the xenstore path/node specified by <path> <node>
 * @param path Base path to remove
 * @param node name of node to remove.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_xenstore_rm(const char *path, const char *node);

/**
 * Maps a kernel space address to userspace
 * @param kAddress Kernel address
 * @param uAddress pointer to receive user space address
 * @param memSize Size of memory that is being shared.
 * @param context the userspace file context.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_map_to_userspace(char *kAddress, char **uAddress,
                             size_t memSize, file_context_t *context);

/**
 * Notifies a user space server listener that a new client has connected.
 * @param server NON null server to notify.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_notify_us_client_connect(struct libivc_server *server);

/**
 * Notifies a user space ivc client that a remote event was fired to it.
 * @param client - NON null ivc client to notify.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_notify_us_client_event(struct libivc_client *client);

/**
 * Notifies a user space ivc client that a remote wants to disconnect.
 * @param client - NON null ivc client to notify.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_notify_us_client_disconnect(struct libivc_client *client);

/**
 * Finds the opposite side of a local IVC connection.
 * 
 * @param client The client for which the opposite side should be located.
 * @return The corresponding libivc_client for the given client, or NULL if none exists.
 */
struct libivc_client * 
ks_platform_find_local_counterpart(struct libivc_client * client);


/**
 * Notifies any connected local clients that the provided local client 
 * has disconnceted.
 *
 * @param disconnecting_client The client whose counterparts should be notified.
 * @return SUCCESS, or an appropriate error code
 */
int 
ks_platform_notify_local_disconnect(struct libivc_client * disconnecting_client);




#ifdef  __cplusplus
}
#endif

#endif  /* KS_PLATFORM_H */

