// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

/*
 * File:   platform.h
 * Author: user
 *
 * Created on January 8, 2015, 12:05 PM
 */

#ifndef PLATFORM_H
#define PLATFORM_H
#ifdef  __cplusplus
extern "C"
{
#endif

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <asm/uaccess.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <xen/xen.h>
#include <xen/xenbus.h>
#include <xen/grant_table.h>
#include <xen/events.h>
#include <xen/page.h>
#include <xen/balloon.h>
#include <linux/version.h>
#include <linux/security.h>
#include <linux/delay.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/task.h>
#endif
#include <compatibility.h>

#ifndef list_head_t
typedef struct list_head list_head_t;
#endif

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif
struct libivc_client *
ks_platform_get_domu_comm(uint16_t domId);

typedef struct shareable_mem_alloc {
    list_head_t listHead; // used in list of shared pages.
    uint32_t numPages; // the number of pages being shared.
    struct page **pages; // a list of shared pages.
    grant_ref_t *grantHandles; // matching grant refs to each page.
    void *kAddress; //the virtually contiguous address to the pages.
    uint16_t remoteDomId;
    void *context;
} shareable_mem_alloc_t;

typedef struct mapped_mem_descriptor {
    unsigned long id;
    list_head_t listHead; // used in list of mapped memory
    uint32_t numGrants; // the number of grants the remote domain shared to us.
    struct page **pages; // the xen ballooned pages.
    grant_handle_t *grantHandles; //the handle to the mapped memory.  Needed for unmapping.
    grant_ref_t *grefs;
    void *kAddress; // the virtually contiguous kernel address to the pages.
    uint16_t remoteDomId;
    uint16_t port;
    uint64_t connection_id;
    void *vma;
    bool vma_created;
    void *context;
    struct gnttab_map_grant_ref *mapOps;
    struct gnttab_map_grant_ref *kmapOps;
    struct gnttab_unmap_grant_ref *unmapOps;
    struct gnttab_unmap_grant_ref *kunmapOps;
} mapped_mem_descriptor_t;

extern uint32_t next_mapped_mem_id;

void shareable_mem_alloc_constructor(shareable_mem_alloc_t **share, uint32_t numPages);
void shareable_mem_alloc_destructor(shareable_mem_alloc_t **share);
void mapped_mem_descriptor_constructor(mapped_mem_descriptor_t **desc, uint32_t numPages);
void mapped_mem_descriptor_destructor(mapped_mem_descriptor_t **desc);

/**
 * By default, only allow the guest to create enough simultaneous events
 * to tie up half of the CPUs on the system. This helps to prevent the guest
 * from denial-of-service'ing the guest by sending IVC events.
 */
#define MAX_ACTIVE_WORKQUEUE_THREADS max(num_online_cpus() / 2, 1U)

/**
 * Prior to kernel version 4.0, gnttab_unmap_refs accepted a kmapOp
 * as its second argument, and dynamically constructed a kunmapOp.
 *
 * In later versions, it accepts a kunmapOp directly. These helpers
 * allow us to work with either version.
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0) && !BACKPORT_GRANT_MECHANISM)
    static inline gnttab_kunmap_grant_ref_t * kunmap_ops_for(mapped_mem_descriptor_t * mappedMem)
    {
        return mappedMem->kmapOps;
    }
#else
    static inline gnttab_kunmap_grant_ref_t * kunmap_ops_for(mapped_mem_descriptor_t * mappedMem)
    {
        return mappedMem->kunmapOps;
    }
#endif


#ifdef  __cplusplus
}
#endif

#endif  /* PLATFORM_H */

