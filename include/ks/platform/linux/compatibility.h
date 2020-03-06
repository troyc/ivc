// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

/**
 * Compatibility functions for IVC
 *
 * These functions enable IVC to work with older kernels. We should have at
 * least some support for kernels down starting with the 3.x series.
 */

#ifndef IVC_COMPATIBILITY_H
#define IVC_COMPATIBILITY_H

#include <stdarg.h>
#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <asm/uaccess.h>
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
#include <linux/version.h>
#include <linux/security.h>
#include <linux/delay.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/task.h>
#endif


/**
 * Prior to kernel version 4.0, gnttab_unmap_refs accepted a kmapOp
 * as its second argument, and dynamically constructed a kunmapOp.
 *
 * In later versions, it accepts a kunmapOp directly. These helpers
 * allow us to work with either version.
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0) && !BACKPORT_GRANT_MECHANISM)
    typedef struct gnttab_map_grant_ref gnttab_kunmap_grant_ref_t;
	int gnttab_alloc_pages(int nr_pages, struct page **pages);
#else
    typedef struct gnttab_unmap_grant_ref gnttab_kunmap_grant_ref_t;
#endif



/**
 * Provide a single interface for unmapping grant references that we can apply
 * for all kernel versions in the 3.x series. This allows us to smooth out the
 * argument differences across kerenl versions.
 */
int ivc_gnttab_unmap_refs(struct gnttab_unmap_grant_ref * unmap_ops,
    gnttab_kunmap_grant_ref_t * kunmap_ops, struct page ** pages, unsigned int count);


/**
 * If we're using a Linux Kernel less than version 4.0, define the additional
 * Xen interface pieces we'll be using.
 */
#ifndef XENFEAT_gnttab_map_avail_bits

  /*
   * If set, GNTTABOP_map_grant_ref honors flags to be placed into guest kernel
   * available pte bits.
   */
  #define XENFEAT_gnttab_map_avail_bits      7
  
  /*
   * Bits to be placed in guest kernel available PTE bits (architecture
   * dependent; only supported when XENFEAT_gnttab_map_avail_bits is set).
   */
  #define _GNTMAP_guest_avail0    (16)
  #define GNTMAP_guest_avail_mask ((uint32_t)~0 << _GNTMAP_guest_avail0)


#endif

/**
 * GNTST_egain is not defined in some versions, but has a Xen-specific mean.
 * We include its definition here for Xen compatibility.
 */
#ifndef GNTST_eagain
#define GNTST_eagain          (-12) /* Operation not done; try again. */
#endif


/**
 * The VM_DONTDUMP flag is not defined in early kernel versions.
 * In those versions, it's not necessary, so we'll set to a flag with
 * no effect.
 */
#ifndef VM_DONTDUMP
#define VM_DONTDUMP           0
#endif

/*
 On x86, several PTE bits are avialable to the OS; and are 
 named avail0, avail1, etc. Linux uses avail0 to indicate that
 a PTE is special, and thus requires special page handling.
 We give that a less confusing name, so it's clear(er) what\
 we're doing.
*/
#ifdef CONFIG_X86
#define _XEN_PG_SPECIAL _GNTMAP_guest_avail0
#else
#define _XEN_PG_SPECIAL 0
#endif



/**
 * A lot of the memory management functions we use were first available
 * in linux 3.4.0. We provide our own approximations in compatibility.c, to 
 * ensure that we can use the same code across kernel versions.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)

    /**
     * normally in linux/mm.h
     */
    unsigned long vm_mmap(struct file *file, unsigned long addr,
            unsigned long len, unsigned long prot,
            unsigned long flag, unsigned long offset);
    int vm_munmap(unsigned long start, size_t len);

    inline void page_mapcount_reset(struct page *page);

    /**
     * normally in xen/grant_table.h 
     */
    void gnttab_batch_map(struct gnttab_map_grant_ref *batch, unsigned count);

    
    /**
     * normally in linux/mm.h
     */
    void kvfree(const void *addr);

#endif

#endif // IVC_COMPATIBILITY_H
