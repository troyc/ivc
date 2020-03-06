// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

#include <linux/types.h>
#include <ks_ivc_core.h>

int ks_priv_grant_shared_mem(char **mem, uint32_t requestedSize, size_t *allocatedSize,
                             uint32_t remoteDomId, uint32_t remotePort);

int ks_priv_end_grant_shared_mem(uint32_t remoteDomId, uint32_t remotePort);

int ks_priv_map_remote_mem(uint32_t remoteDomId, uint32_t port, char **mem, size_t *memSize);

int ks_priv_unmap_remote_mem(uint32_t remoteDomId, uint32_t port);

int ks_priv_fire_remote_event(uint32_t remoteDomId, uint32_t port);

int ks_priv_register_port_listener(uint32_t port, remoteListenerCallback callback);

int ks_priv_register_event_listener(uint32_t remoteDomId, uint32_t port, remoteListenerCallback callback);

int ks_priv_unregister_port_listener(uint32_t port);

int ks_priv_unregister_event_listener(uint32_t remoteDomId, uint32_t port);
