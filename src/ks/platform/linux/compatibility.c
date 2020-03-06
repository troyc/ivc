// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

/**
 * Compatibility functions for IVC
 *
 * These functions enable IVC to work with older kernels.
 */

#include <platform.h>

/**
 * Unfortunately, there's been a /lot/ of churn on the arguments to gnttab_unmap_refs.
 *
 * Different kernel versions support a variety of features-- and require a variety of
 * arguments. We try to use the minimum supported set we can, but this is still messy.
 *
 * For now, we need to support down to 3.2, but this is awful, and should be reconsidered
 * when a lot of this is redone. Really, we need to either find a way to not use kmap_ops,
 * or we need to emulate the relevant functionality on older kernels. Ick!
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)

    int ivc_gnttab_unmap_refs(struct gnttab_unmap_grant_ref * unmap_ops,
        gnttab_kunmap_grant_ref_t * kunmap_ops, struct page ** pages, unsigned int count)
    {
        //
        // TODO: Simulate the normal kernel's handling of kunmap_ops.
        //
        if(kunmap_ops)
        {
            //Note that libivc_error can't be used from platform.h.
            //(Those macros depend on this file!)
            printk(KERN_ERR "Using an unsupported case-- provided kernel unmapping ops on a kernel\n");
            printk(KERN_ERR "too old to use them!");
            return -EINVAL;
        }

        return gnttab_unmap_refs(unmap_ops, pages, count);
    }

#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)

    int ivc_gnttab_unmap_refs(struct gnttab_unmap_grant_ref * unmap_ops,
        gnttab_kunmap_grant_ref_t * kunmap_ops, struct page ** pages, unsigned int count)
    {
        if(kunmap_ops)
        {
            printk(KERN_ERR "[ivc] Using an unsupported case-- provided kernel unmapping ops on a kernel\n");
            printk(KERN_ERR "[ivc] too old to use them!");
            return -EINVAL;
        }

        return gnttab_unmap_refs(unmap_ops, pages, count, true);
    }

#else

    int ivc_gnttab_unmap_refs(struct gnttab_unmap_grant_ref * unmap_ops,
        gnttab_kunmap_grant_ref_t * kunmap_ops, struct page ** pages, unsigned int count)
    {
        return gnttab_unmap_refs(unmap_ops, kunmap_ops, pages, count);
    }

#endif



/**
 * A lot of the memory management functions we use were first available
 * in linux 3.4.0. We provide our own approximations here, to ensure that
 * we can use the same code across kernel versions.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)

    /**
     * from mm/util.c; unmodified
     */
    int vm_munmap(unsigned long start, size_t len)
    {
         int ret;
         struct mm_struct *mm = current->mm;

         down_write(&mm->mmap_sem);
         ret = do_munmap(mm, start, len);
         up_write(&mm->mmap_sem);
         return ret;
    }


    /**
     * from mm/util.c; modified to use security_file_mmap in lieu of 
     * security_mmap_file
     */
    static long vm_mmap_pgoff(struct file *file, unsigned long addr,
            unsigned long len, unsigned long prot,
            unsigned long flag, unsigned long pgoff)
    {
        unsigned long ret;
        struct mm_struct *mm = current->mm;

        ret = security_file_mmap(file, prot, prot, flag, addr, 0);
        if (!ret) {
                down_write(&mm->mmap_sem);
                ret = do_mmap_pgoff(file, addr, len, prot, flag, pgoff);
                up_write(&mm->mmap_sem);
        }
        return ret;
    }


    /**
     * from mm/util.c; unmodified
     */
    unsigned long vm_mmap(struct file *file, unsigned long addr,
            unsigned long len, unsigned long prot,
            unsigned long flag, unsigned long offset)
    {
        if (unlikely(offset + PAGE_ALIGN(len) < offset))
                return -EINVAL;
        if (unlikely(offset & ~PAGE_MASK))
                return -EINVAL;

        return vm_mmap_pgoff(file, addr, len, prot, flag, offset >> PAGE_SHIFT);
    }


    /**
     * from drivers/xen/grant-table.c; max_delay converted from a define
     * to an inline constant
     */
    static inline void
    gnttab_retry_eagain_gop(unsigned int cmd, void *gop, int16_t *status,
                                                    const char *func)
    {
            const int max_delay = 256;
            unsigned delay = 1;

            do {
                    BUG_ON(HYPERVISOR_grant_table_op(cmd, gop, 1));
                    if (*status == GNTST_eagain)
                            msleep(delay++);
            } while ((*status == GNTST_eagain) && (delay < max_delay));

            if (delay >= max_delay) {
                    printk(KERN_ERR "%s: %s eagain grant\n", func, current->comm);
                    *status = GNTST_bad_page;
            }
    }


    /**
     * from drivers/xen/grant-table.c; unmodified
     */
    void gnttab_batch_map(struct gnttab_map_grant_ref *batch, unsigned count)
    {
            struct gnttab_map_grant_ref *op;

            if (HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, batch, count))
                    BUG();
            for (op = batch; op < batch + count; op++)
                    if (op->status == GNTST_eagain)
                            gnttab_retry_eagain_gop(GNTTABOP_map_grant_ref, op,
                                                    &op->status, __func__);
    }


    /**
     * from linux/mm.h; unmodified
     */
    inline void page_mapcount_reset(struct page *page)
    {
            atomic_set(&(page)->_mapcount, -1);
    }

    /**
     * from mm/util.c; unmodified
     */
    void kvfree(const void *addr)
    {
        if (is_vmalloc_addr(addr))
            vfree(addr);
        else
            kfree(addr);
    }

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)

	int gnttab_alloc_pages(int nr_pages, struct page **pages)
	{
		return alloc_xenballooned_pages(nr_pages, pages, false);
	}
#endif
