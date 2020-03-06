// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

/*
 * File:   ks_ivc_core.h
 * Author: user
 *
 * Created on January 8, 2015, 3:02 PM
 */

#ifndef KS_IVC_CORE_H
#define KS_IVC_CORE_H

#ifdef  __cplusplus
extern "C"
{
#endif

#include <ks_platform.h>

#define IVC_FRONTEND_IVC_PATH "/local/domain/%d/data/ivc"
#define IVC_FRONTEND_DEVICE_PATH "/local/domain/%d/data"
#define IVC_FRONTEND_IVC_NODE "ivc"
#define IVC_MAX_PATH 256
#define IVC_FRONTEND_RO_PAGE "frontend-page-ro"
#define IVC_FRONTEND_RW_PAGE "frontend-page-rw"
#define IVC_FRONTEND_EVENT_CHANNEL "frontend-event"
#define IVC_FRONTEND_STATUS "frontend-status"
#define IVC_BACKEND_STATUS "backend-status"

#define IVC_GRANTS_PER_MESSAGE 25
#define IVC_POSIX_SHARE_NAME_SIZE 50
#define IVC_STATUS_SIZE 25
#define IVC_BUFFER_SIZE PAGE_SIZE
#define IVC_DOM_ID 0
#define IVC_PORT 0
#define IVC_MAGIC 0xD00D

#define _TRACE() pr_info("%s : %d\n", __func__, __LINE__)

typedef enum BACKEND_STATUS {
    DISCONNECTED, CONNECTED, FAILED
} BACKEND_STATUS_T;

// Really should use more info here
struct libivc_client *ks_ivc_core_get_client(uint32_t clientNo);

int
ks_ivc_core_connect(struct libivc_client *client);

int
ks_ivc_core_reconnect(struct libivc_client *client, uint16_t new_domid, uint16_t new_port);

int
ks_ivc_core_disconnect(struct libivc_client *client);

int
ks_ivc_core_notify_remote(struct libivc_client *client);

int
ks_ivc_core_reg_svr_lsnr(struct libivc_server *server);

int
ks_ivc_core_unreg_svr_lsnr(struct libivc_server *server);

int
ks_ivc_core_init(void);

int
ks_ivc_core_uninit(void);

int
ks_ivc_core_get_domain_id(void);

/**
 * called when an inbound message to connect is received by handling an event
 * triggered by the backend XEN driver.
 * @param msg - The message containing information on the connection.
 * @return SUCCESS or appropriate error number.
 */
int
ks_ivc_core_handle_connect_msg(libivc_message_t *msg);

/**
 * Triggered by a remote message coming in requesting to disconnect a client.
 * @param msg - message describing client that wants to disconnect.
 * @return SUCCESS or appropriate error number.
 */
int
ks_ivc_core_handle_disconnect_msg(libivc_message_t *msg);


/**
 * Triggered by a backend notification that a remote domain has died.
 * @param msg - message describing the domain that has gone down
 * @return SUCCESS or appropriate error number.
 */
int
ks_ivc_core_handle_domain_death_notification(libivc_message_t *msg);


/**
 * Services IOCTLs coming from user space for ivc client related operations.
 * @param ioctlNum The ioctl number.
 * @param client - non null pointer to user space client payload.
 * @param context - non null pointer to user space file context.
 * @return SUCCESS or appropriate error number.
 */
int
ks_ivc_core_client_ioctl(uint8_t ioctlNum, struct libivc_client_ioctl_info *client, file_context_t *context);

/**
 * Services IOCTLs coming from user space for ivc server related operations.
 * @param ioctlNum - The IOCTL number as defined in ivc_ioctl_defs.h
 * @param server - non null pointer to user space server payload.
 * @param context - non null pointer to user space file context.
 * @return SUCCESS or appropriate error number.
 */
int
ks_ivc_core_server_ioctl(uint8_t ioctlNum, struct libivc_server_ioctl_info *server, file_context_t *context);

/**
 * Notifies the IVC core that a user space process has terminated and it needs to
 * undo any closing operations that weren't previously cleaned up correctly.
 * @param context - non null pointer to user space file context
 * @return SUCCESS or appropriate error number.
 */
int
ks_ivc_core_file_closed(file_context_t *context);

/**
 * Notifies the given client that an event has been received.
 *
 * @param client The client to be notified
 * @param SUCCESS or an appropriate error number
 */ 
int
ks_ivc_core_notify_event_received(struct libivc_client *client);

/**
 * Notifies an IVC client that its local or remote counterpart has disconnected.
 *
 * @param client The client that should receive the notication.
 */
int ks_ivc_core_notify_disconnect(struct libivc_client *client);

int
ks_ivc_pack_grants(struct libivc_client *client);

struct libivc_client *
ks_ivc_core_find_internal_client(struct libivc_client_ioctl_info *externalClient);

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
ks_ivc_check_for_equiv_client(uint16_t domid, uint16_t port, uint64_t conn_id, uint8_t server_side);

#ifdef  __cplusplus
}
#endif

#endif  /* KS_IVC_CORE_H */

