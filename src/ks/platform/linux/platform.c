// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

/**
 *
 * program: platform.c
 * linux specific platform driver for the inter-vm communications (ivc) handling.
 * any functions declared in the ks_platform.h need to be implemented in the platform
 * drivers as well as the initial connection to ivc.
 */
#include <platform.h>
#include <libivc.h>
#include <libivc_private.h>
#include <libivc_debug.h>
#include <ivc_ioctl_defs.h>
#include <ks_ivc_core.h>
#include <asm-generic/ioctl.h>
#include <ivc_ioctl_defs.h>
#include <common_defs.h>
#include <linux/mempolicy.h>
#include <linux/file.h>
#include <linux/rmap.h>
#include <asm/xen/page.h>
#include <asm/tlbflush.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/task.h>
#endif

typedef struct mmap_info
{
    uint32_t id;
    list_head_t node;

    uint32_t numPages;
    struct page **pages;
    void *private;
} mmap_info_t;

static LIST_HEAD(sharedMemoryList);
static LIST_HEAD(mmapInfoList);

static DEFINE_MUTEX(mmapInfoMutex);

static struct workqueue_struct *eventWorkQueue = NULL;
static mutex_t eventMutex;
static list_head_t eventCallbacks;

// Determine if the we have to use PTE mode for our mappings; this is
// mostly commonly the case in Xen PV domains.
static bool use_ptemod;

extern int domId;

typedef struct
{
    struct work_struct work;
    event_channel_info_t *info;
} event_channel_work_t;

/**
 * Counter that tracks the next available mappedMem ID "cookie".
 * This number is used as a locally unique identifier for a mappedMemory object.
 */
uint32_t next_mmap_cookie = 1;

static int ks_platform_munmap(struct libivc_client *client, file_context_t *f);

/**
 * Generic LINUX handler to fire an eventfd for a given userspace task.
 * @param fd - the user space eventfd number.
 * @param task - the task associated with the userspace process
 * @return SUCCESS or appropriate error number.
 */
static int
_ks_platform_notify_us_event(int fd, struct task_struct *task)
{
    int rc = INVALID_PARAM;
    struct eventfd_ctx *fdContext = NULL;
    struct file *efd_file = NULL;

    // need a valid event fd
    libivc_assert(fd > -1, rc);
    // need a valid task struct.
    libivc_checkp(task, rc);
    libivc_checkp(task->files, rc);

    // locate the event file descriptor for the process.
    rcu_read_lock();
    efd_file = fcheck_files(task->files, fd);
    rcu_read_unlock();

    libivc_checkp(efd_file, ACCESS_DENIED);
    fdContext = eventfd_ctx_fileget(efd_file);
    libivc_checkp(fdContext, ACCESS_DENIED);
    eventfd_signal(fdContext, 1);
    eventfd_ctx_put(fdContext);
    return SUCCESS;
}


static shareable_mem_alloc_t *find_shareable_mem_by_kaddr(char *kAddress)
{
    list_head_t *pos = NULL;
    shareable_mem_alloc_t *memAlloc = NULL;

    // locate the previously shared memory.
    list_for_each(pos, &sharedMemoryList)
    {
        memAlloc = container_of(pos, shareable_mem_alloc_t, listHead);

        if(memAlloc->kAddress == kAddress)
        {

            break; // found it.
        }
        else
        {
            memAlloc = NULL; // wasn't a match.
        }
    }

    return memAlloc;
}

/**
 * Finds an MMAP info structure by its unique ID number.
 *
 * @param id The ID number for the relevant mmap info object.
 */
static mmap_info_t * __find_mmap_info_by_id(unsigned long id)
{
    list_head_t *pos = NULL;
    mmap_info_t *mmap_info = NULL;

    list_for_each(pos, &mmapInfoList)
    {
        mmap_info_t * entry = container_of(pos, mmap_info_t, node);

        if(entry->id == id) {
            mmap_info = entry;
            break;
        }
    }

    return mmap_info;
}



/**
 * Returns an MMAP "cookie" that can be passed to mmap to uniquely identify the
 * relevant mmap_info.
 *
 * (Note that this isn't the cleanest way of doing things, but this is done in
 *  several other pieces of the kernel-- most notably DRM.)
 */
static unsigned long cookie_for_mmap_info(mmap_info_t * mmap_info)
{
    return mmap_info->id << PAGE_SHIFT;
}

int ivc_unmap_refs_with_noncontiguous_ops(struct gnttab_unmap_grant_ref *unmap_ops,
    gnttab_kunmap_grant_ref_t * kunmap_ops, struct page ** pages, unsigned int count)
{

    const unsigned int ops_per_page = (PAGE_SIZE / sizeof(struct gnttab_unmap_grant_ref));

    int rc = 0;
    unsigned int i;

    // For as long as we can batch map, attempt to batch map.
    for(i = 0; i < count; i += ops_per_page)
    {
        int count_this_iteration = min(count - i, ops_per_page);

        rc |= ivc_gnttab_unmap_refs(unmap_ops, kunmap_ops, pages, count_this_iteration);

        unmap_ops += ops_per_page;
        pages += ops_per_page;

        if(kunmap_ops)
          kunmap_ops += ops_per_page;
    }

    return rc;
}


/**
 * Allocate memory and return a pointer to it.
 * @param memSize size of memory to allocate
 * @return a pointer to the allocated memory, or NULL if we are all out.
 */
void *
ks_platform_alloc(size_t memSize)
{
    libivc_assert(memSize > 0, NULL);
    return vzalloc(memSize);
}

/**
 * Free previously allocated memory.
 * @param mem the memory previously allocated.
 */
void
ks_platform_free(void *mem)
{
    libivc_checkp(mem);
    return vfree(mem);
}

static int
ks_platform_grant_out_memory(shareable_mem_alloc_t * memAlloc)
{
    int grant_ref;
    int pageIndex = 0;

    // allocate storage for the grant refs.
    memAlloc->grantHandles = vzalloc(memAlloc->numPages * sizeof(grant_ref_t));
    libivc_checkp(memAlloc->grantHandles, OUT_OF_MEM);

    for(pageIndex = 0; pageIndex < memAlloc->numPages; pageIndex++)
    {
        grant_ref = gnttab_grant_foreign_access(memAlloc->remoteDomId, pfn_to_mfn(page_to_pfn(memAlloc->pages[pageIndex])), 0 /*readOnly*/);

        // the grant call returns negative numbers for errors.
        if(grant_ref < 0)
        {
            libivc_info("Granting memory failed. rc = %d\n", grant_ref);
            return ACCESS_DENIED;
        }
        else
        {
            if(pageIndex == 0 || pageIndex == memAlloc->numPages - 1)    
                libivc_info("ALLOC_GRANT_REF, rc = %d\n", grant_ref);
            
            // the grant handle is required to end the foreign mapping.
            memAlloc->grantHandles[pageIndex] = grant_ref;
        }
    }

    return SUCCESS;
}


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
                             char **mem, grant_ref_t **grantRefs)
{
    int pageIndex = 0;
    shareable_mem_alloc_t *memAlloc = NULL;
    int rc = OUT_OF_MEM;

    // check out pointer and pages
    libivc_checkp(mem, INVALID_PARAM);
    libivc_assert(numPages > 0, INVALID_PARAM);

    // create the struct to hold our pages and data for later retrieval.
    memAlloc = (shareable_mem_alloc_t *) vzalloc(sizeof(shareable_mem_alloc_t));
    libivc_checkp(memAlloc, OUT_OF_MEM);

    memAlloc->remoteDomId = remoteDomId;
    memAlloc->numPages = numPages;

    // Allocate memory to store the page array.
    memAlloc->pages = vzalloc(numPages * sizeof(memAlloc->pages[0]));
    rc = OUT_OF_MEM;
    libivc_checkp_goto(memAlloc->pages, ERROR);

    // Allocate the pages to be shared.
    for(pageIndex = 0; pageIndex < memAlloc->numPages; pageIndex++)
    {
        memAlloc->pages[pageIndex] = alloc_page(GFP_KERNEL | __GFP_ZERO);
        libivc_checkp_goto(memAlloc->pages[pageIndex], ERROR);
    }

    //If we're trying to map memory to a remote domain, set up grants.
    if(remoteDomId != domId)
    {
        rc = ks_platform_grant_out_memory(memAlloc);
        
        if(rc)
            goto ERROR;
    } 
    // Otherwise, mark each of the pages as used internally.
    else 
    {

        // Mark the pages as used.
        for(pageIndex = 0; pageIndex < memAlloc->numPages; pageIndex++)
        {
            get_page(memAlloc->pages[pageIndex]);
        }
    }

    // If we're trying to share more than one page, create a virtually-contiguous
    // block of memory for each of the requested pages.
    if(numPages > 1)
    {
        memAlloc->kAddress = vmap(memAlloc->pages, memAlloc->numPages,
                                  VM_READ | VM_WRITE | VM_SHARED, PAGE_SHARED);
        libivc_checkp_goto(memAlloc->kAddress, ERROR);
    }
    // Otherwise, grab the kernel address for our single page directly.
    else
    {
        memAlloc->kAddress = pfn_to_kaddr(page_to_pfn(memAlloc->pages[0]));
    }

    // hand the virtual address to caller.
    *mem = memAlloc->kAddress;
    *grantRefs = memAlloc->grantHandles;

    // add it to our list so we can retrieve it during the free call.
    INIT_LIST_HEAD(&memAlloc->listHead);
    list_add(&memAlloc->listHead, &sharedMemoryList);

    rc = SUCCESS;
    goto END;
ERROR:
    if(memAlloc)
    {
        if(memAlloc->grantHandles)
        {
            for(pageIndex = 0; pageIndex < numPages; pageIndex++)
            {
                if(memAlloc->grantHandles[pageIndex] > 0)
                {
                    gnttab_end_foreign_access(memAlloc->grantHandles[pageIndex], 1, 0);
                    memAlloc->grantHandles[pageIndex] = 0;
                }
            }
            vfree(memAlloc->grantHandles);
            memAlloc->grantHandles = NULL;
        }

        if(memAlloc->pages)
        {
            for(pageIndex = 0; pageIndex < numPages; pageIndex++)
            {
                if(memAlloc->pages[pageIndex] != NULL)
                {
                    __free_page(memAlloc->pages[pageIndex]);
                    memAlloc->pages[pageIndex] = NULL;
                }
            }
            vfree(memAlloc->pages);
            memAlloc->pages = NULL;
        }
        vfree(memAlloc);
    }
END:
    return rc;
}

/**
 * Free the shared memory previously created by ks_platform_alloc_shared_mem.
 * @param mem - Non NULL pointer returned in ks_platform_alloc_shared_mem
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_free_shared_mem(char *mem)
{
    int rc = INVALID_PARAM;
    list_head_t *pos = NULL, *temp = NULL;
    shareable_mem_alloc_t *allocMem = NULL;
    int pageIndex = 0;

    libivc_checkp(mem, rc);

    list_for_each_safe(pos, temp, &sharedMemoryList)
    {
        allocMem = container_of(pos, shareable_mem_alloc_t, listHead);
        if(allocMem->kAddress == mem)
        {
            // found it , remove from list and jump out of loop.
            list_del(pos);
            break;
        }
        else
        {
            allocMem = NULL;
        }
    }
    // if it wasn't found, return the INVALID_PARAM error
    libivc_checkp(allocMem, rc);

    // undo the vmap.
    if(allocMem->numPages > 1)
    {
        vunmap(allocMem->kAddress);
    }

    mem = allocMem->kAddress = NULL;


    // We're now finished using the relevant colection of pages, ad we're ready to release them.
    for(pageIndex = 0; pageIndex < allocMem->numPages; pageIndex++)
    {

        // If we had granted out memory in association with this buffer,
        // terminate the grants.
        if(allocMem->grantHandles) {
            // end the access and free the allocated page when the remote domain releases the memory.
            // note that the memory needs to be cleanly unmapped from user space on both sides
            // and not have any references to it in use.
            gnttab_end_foreign_access(allocMem->grantHandles[pageIndex], 0, (unsigned long) page_address(allocMem->pages[pageIndex]));
            allocMem->grantHandles[pageIndex] = 0;

        } 
        // Otherwise, this was a local mapping; release our reference on the pages.
        else {
            // If we're the last person using this page, free it.
            if(put_page_testzero(allocMem->pages[pageIndex])) {
                __free_page(allocMem->pages[pageIndex]);
            }
        }

        allocMem->pages[pageIndex] = NULL;
    }

    if(allocMem->grantHandles)
        vfree(allocMem->grantHandles);

    allocMem->grantHandles = NULL;
    vfree(allocMem->pages);
    allocMem->pages = NULL;
    vfree(allocMem);
    allocMem = NULL;
    return SUCCESS;
}

/**
 * Create an unbound inter-domain channel for communication with a given domain.
 * @param remoteDomId remote domain to create channel to.
 * @param eventPort variable to receive event port
 * @return SUCCESS, or appropriate error number.
 */
int
ks_platform_createUnboundEvtChn(uint16_t remoteDomId, evtchn_port_t *eventPort)
{
    int rc = SUCCESS;
    struct evtchn_alloc_unbound op;

    libivc_checkp(eventPort, INVALID_PARAM);

    memset(&op, 0, sizeof(struct evtchn_alloc_unbound));
    // tell the hypervisor the from domain (us) and to domain for the event channel
    op.dom = DOMID_SELF;
    op.remote_dom = remoteDomId;

    // create the event channel.
    rc = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &op);

    if(rc != SUCCESS)
    {
        return ACCESS_DENIED;
    }
    *eventPort = op.port;
    // if we made it here, the event channel succeeded.
    return rc;
}

/**
 * Closes a previously open channel.
 * @param event_channel channel created by ks_platform_createUnboundEvtChn.
 * @return SUCCESS, or appropriate error number.
 */
int
ks_platform_closeEvtChn(evtchn_port_t event_channel)
{
    int rc;
    struct evtchn_close closeOp;

    memset(&closeOp, 0, sizeof(struct evtchn_close));
    closeOp.port = event_channel;
    rc = HYPERVISOR_event_channel_op(EVTCHNOP_close, &closeOp);
    return rc;
}

/**
 * Platform specific wrapper around starting a xenbus transaction.
 * @param trans - Non null pointer to a transaction struct
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_start_xenbus_transaction(xenbus_transaction_t *trans)
{
    int rc;

    if(!trans)
    {
        return INVALID_PARAM;
    }

    rc = xenbus_transaction_start(trans);
    if(rc == -EAGAIN)
    {
        rc = ERROR_AGAIN;
    }

    if(rc == -EACCES)
    {
        rc = ACCESS_DENIED;
    }

    return rc;
}

/**
 * Platform specific wrapper around ending a xenbus transaction.
 * @param trans - xenbus transaction to end (not a pointer).
 * @return SUCCESS, or appropriate error number.
 */
int
ks_platform_end_xenbus_transaction(xenbus_transaction_t trans)
{
    int rc;

    rc = xenbus_transaction_end(trans, 0);

    if(rc == -EAGAIN)
    {
        rc = ERROR_AGAIN;
    }

    if(rc == -EACCES)
    {
        rc = ACCESS_DENIED;
    }

    return rc;
}

/**
 * Reads an integer value from the xenstore
 * @param trans - xenbus transaction that was previously started.
 * @param path - path where node being read exists.
 * @param node - the node or name of value to read.
 * @param value - pointer to receive value into.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_read_int(xenbus_transaction_t trans, char *path, char *node, int *value)
{
    int rc;

    // make sure the pointers aren't NULL
    libivc_checkp(path, INVALID_PARAM);
    libivc_checkp(node, INVALID_PARAM);
    libivc_checkp(value, INVALID_PARAM);
    rc = xenbus_scanf(trans, path, node, "%d", value);
    if(rc > 0)
    {
        return SUCCESS;
    }
    else if(rc == -EAGAIN)
    {
        return ERROR_AGAIN;
    }
    else
    {
        return ACCESS_DENIED;
    }
}

/**
 * Writes an int value to node under path.
 * @param path - base path where node will be written
 * @param node - node or name of value being written.
 * @param value - the value
 * @param trans - transaction that has been started.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_xenstore_write_int(const char *path, const char *node, int value,
                               xenbus_transaction_t trans)
{
    int rc;

    // make sure the pointers are not NULL
    libivc_checkp(path, INVALID_PARAM);
    libivc_checkp(node, INVALID_PARAM);

    // try to print to the path.
    rc = xenbus_printf(trans, path, node, "%d", value);

    // turn the code into something the ivc core understands.
    if(rc == -EAGAIN)
    {
        rc = ERROR_AGAIN;
    }
    if(rc == -EACCES)
    {
        rc = ACCESS_DENIED;
    }

    return rc;
}

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
                            const char *node, const char *fmt, ...)
{
    char value[IVC_MAX_PATH];
    va_list args;
    int rc;

    memset(value, '\0', IVC_MAX_PATH);
    va_start(args, fmt);
    vsnprintf(value, IVC_MAX_PATH - 1, fmt, args);
    rc = xenbus_write(trans, path, node, value);
    if(rc != SUCCESS)
    {
        if(rc == -EAGAIN)
        {
            rc = ERROR_AGAIN;
        }
        else
        {
            rc = ACCESS_DENIED;
        }
    }
    return rc;
}

/**
 * Worker callback that is gets scheduled back in the process context when
 * the XEN interrupt handler is fired.  This allows locking, sleeping, etc.
 * @param work Work struct created in interrupt handler.
 */
static void
ks_platform_notify_event_callback(struct work_struct *work)
{
    //the actual struct that was passed to the callback.
    event_channel_work_t *ework = (event_channel_work_t *) work;
    // the information required to perform callbacks
    event_channel_info_t *info = NULL;

    // pointer sanity checks.
    libivc_checkp(ework);
    libivc_checkp(ework->info);
    info = ework->info;

    // do the callback.
    info->callback(info->irq);

    // Decrease our total reference count on the information structure.
    if(atomic_dec_and_test(&info->ref_count))
        vfree(info);

    // free up the work struct that was created in the interrupt handler.
    ework->info = NULL;
    kvfree((void *) work);
}


/**
 * Worker callback that is gets scheduled back in the process context when
 * a local connection wants to send an event.
 *
 * @param work Work struct created by the opposite-side local client.
 */
static void
ks_platform_send_local_event(struct work_struct *work)
{
    // Interpret the work structure as our custom structure type...
    event_channel_work_t *ework = (event_channel_work_t *) work;

    // ... ensure that we have all the information we need...
    libivc_checkp(ework);
    libivc_checkp(ework->info);

    // ... and fire off the event on the relevant client.
    ks_ivc_core_notify_event_received((struct libivc_client *)ework->info);
    libivc_put_client((struct libivc_client *)ework->info);

    kvfree(work);
}

/**
 * Worker callback that is gets scheduled back in the process context when
 * a local connection is broken.
 *
 * @param work Work struct created by the opposite-side local client.
 */
static void
ks_platform_send_local_disconnect(struct work_struct *work)
{
    // Interpret the work structure as our custom structure type...
    event_channel_work_t *ework = (event_channel_work_t *) work;

    // ... ensure that we have all the information we need...
    libivc_checkp(ework);
    libivc_checkp(ework->info);

    // ... and fire off the event on the relevant client.
    ks_ivc_core_notify_disconnect((struct libivc_client *)ework->info);
    libivc_put_client((struct libivc_client *)ework->info);

    kvfree(work);
}


/**
 * Interrupt handler called when a XEN event is fired.
 * @param irq - The irq that is associated with the XEN event.
 * @param data - data associated with the event.
 * @return IRQ_HANDLED, always.
 */
static irqreturn_t
ks_platform_event_interrupt_handler(int irq, void *data)
{
    event_channel_work_t *work = NULL;
    event_channel_info_t *info = (event_channel_info_t *) data;

    // pointer sanity checks.
    libivc_checkp(data, IRQ_HANDLED);

    // Mark the IRQ information structure as used, ensuring that
    // it's not free'd if the IRQ is torn down while we still have
    // an outstanding event.
    atomic_inc(&info->ref_count);

    // create the object to be scheduled back in the process context.
    // in interrupt context, need to make sure kmalloc doesn't sleep.
    work = kzalloc(sizeof(event_channel_work_t), GFP_ATOMIC);

    if(!work) {
      libivc_error("Out of memory: could not allocate event handler work!\n");
      return IRQ_HANDLED;
    }

    // make sure no bad data is in the struct.
    memset(work, 0, sizeof(event_channel_work_t));

    // assigned the information needed to fire the callback
    work->info = info;
    // initialize it with the callback to run in the process thread context.
    INIT_WORK((struct work_struct *) work, ks_platform_notify_event_callback);
    // schedule the work to be done in the process context.
    queue_work(eventWorkQueue, (struct work_struct *) work);

    return IRQ_HANDLED;
}

static int
_ks_platform_bind_event_callback(uint16_t remoteDomId, evtchn_port_t port, uint32_t *localIrq,
                                 event_channel_callback callback, uint8_t interDomain)
{
    int rc = INVALID_PARAM;
    event_channel_info_t *info = NULL;

    // parameter sanity checks.
    libivc_assert(port > 0, rc);
    libivc_checkp(localIrq, rc);
    libivc_checkp(callback, rc);

    info = vzalloc(sizeof(event_channel_info_t));
    libivc_checkp(info, OUT_OF_MEM);

    // Mark our event information as referenced, as we'll be passing it into
    // event queues. This is okay, as we effectively consider this read-only.
    atomic_inc(&info->ref_count);

    info->event_channel = port;
    info->callback = callback;
    if(interDomain)
    {
        info->irq = bind_interdomain_evtchn_to_irqhandler(remoteDomId, port,
                    ks_platform_event_interrupt_handler,
                    0, "libivc", info);
    }
    else
    {
        info->irq = bind_evtchn_to_irqhandler(port, ks_platform_event_interrupt_handler,
                                              0, "libivc", info);
    }



    if(info->irq <= 0)
    {
        libivc_error("Failed to bind event port %d to irq. rc = %d\n", port, info->irq);
        vfree(info);
        info = NULL;
        rc = ACCESS_DENIED;
    }
    else
    {
        mutex_lock(&eventMutex);
        list_add(&info->listHead, &eventCallbacks);
        mutex_unlock(&eventMutex);
        rc = SUCCESS;
        *localIrq = info->irq;
    }

    return rc;
}

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
                                event_channel_callback callback)
{
    return _ks_platform_bind_event_callback(0, port, localIrq, callback, 0);
}

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
                                 uint32_t *localIrq, event_channel_callback callback)
{
    return _ks_platform_bind_event_callback(remoteDomId, port, localIrq, callback, 1);
}

/**
 * End event notifications on the localIrq which was bound to in
 * ks_platform_bind_event_callback.
 * @param localIrq - localIrq returned from ks_platform_bind_event_callback
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_unbind_event_callback(int localIrq)
{
    int rc = SUCCESS;
    list_head_t *pos = NULL, *temp = NULL;
    event_channel_info_t *info = NULL;

    // prevent mutation of the event list while we traverse it.
    mutex_lock(&eventMutex);
    // find the irq in our list and remove it.

    list_for_each_safe(pos, temp, &eventCallbacks)
    {
        info = list_entry(pos, event_channel_info_t, listHead);
        if(info->irq == localIrq)
        {
            list_del(pos);
            break;
        }
        else
        {
            info = NULL;
        }
    }
    // allow others to access the list now.
    mutex_unlock(&eventMutex);

    // if it was found, unbind the interrupt and free up allocated resources.
    if(info != NULL)
    {
        unbind_from_irqhandler(localIrq, info);

        // Decrease our total reference count on the object.
        if(atomic_dec_and_test(&info->ref_count))
            vfree(info);

        info = NULL;
        rc = SUCCESS;
    }
    else
    {
        // bogus irq number.
        rc = INVALID_PARAM;
    }
    return rc;
}

/**
 * Maps in memory grants from a remote domain
 * @param domId - domain id of remote domain
 * @param port - the port at which we're connecting to the remote domain
 * @param connection_id - the connection with which we're connecting to the remote domain
 * @param grants - array of grant references from remote domain
 * @param numGrants - number of grant references in grants array
 * @param mem - pointer to receive virtually contigous address.
 * @param readOnly - non zero for writable, but ensure the remote shared
 * it that way unless you like VMs freezing.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_map_grants(uint16_t remoteDomId, uint16_t port, uint64_t connection_id, 
                       grant_ref_t *grants, uint32_t numGrants, char **mem, file_context_t *f)
{
    (void) remoteDomId;
    (void) port;
    (void) connection_id;
    (void) grants;
    (void) numGrants;
    (void) mem;
    (void) f;
    
    return -EPROTONOSUPPORT;
}

//
// This method shouldn't be necessary, and will definitely
// go away if we switch to backing-store-free mappings.
//
// It will definitely go away if we move to 4.0 and use
// gnttab_alloc_pages.
//
void clean_up_xenballooned_pages(int nr_pages, struct page **pages)
{
    int i;

    for(i = 0; i < nr_pages; ++i) {
        page_mapcount_reset(pages[i]);
        ClearPagePrivate(pages[i]);
    }
}

/**
 * Unmaps and releases memory from a remote domain.
 * @param mem - memory address returned from ks_platform_map_grants.
 * @return - SUCCESS or appropriate error number.
 */
int
ks_platform_unmap_remote_grants(char *mem)
{
    return -EINVAL;
}

/**
 * Finds the opposite side of a local IVC connection.
 * 
 * @param client The client for which the opposite side should be located.
 * @return The corresponding libivc_client for the given client, or NULL if none exists.
 */
struct libivc_client * 
__ks_platform_find_local_counterpart(struct libivc_client * client)
{
    struct libivc_client *counterpart = NULL;
    libivc_checkp(client, NULL);

    __FIND_CLIENT_CLIST(counterpart, (
        (client->remote_domid  == counterpart->remote_domid)   &&
        (client->port          == counterpart->port)           && 
        (client->connection_id == counterpart->connection_id)  &&
        (client->server_side   != counterpart->server_side)));

    if(counterpart)
      return counterpart;

    __FIND_CLIENT_SLIST(counterpart, (
        (client->remote_domid  == counterpart->remote_domid)   &&
        (client->port          == counterpart->port)           && 
        (client->connection_id == counterpart->connection_id)  &&
        (client->server_side   != counterpart->server_side)));

    if(counterpart)
      return counterpart;

    return NULL;
}


/**
 * Finds the opposite side of a local IVC connection.
 * 
 * @param client The client for which the opposite side should be located.
 * @return The corresponding libivc_client for the given client, or NULL if none exists.
 */
struct libivc_client * 
ks_platform_find_local_counterpart(struct libivc_client * client)
{
    struct libivc_client * counterpart;

    mutex_lock(&ivc_client_list_lock);
    mutex_lock(&ivc_server_list_lock);
    counterpart = __ks_platform_find_local_counterpart(client);
    mutex_unlock(&ivc_server_list_lock);
    mutex_unlock(&ivc_client_list_lock);

    return counterpart;
}


/**
 * Notifies any connected local clients that the provided local client 
 * has disconnceted.
 *
 * @param disconnecting_client The client whose counterparts should be notified.
 * @return SUCCESS, or an appropriate error code
 */
int ks_platform_notify_local_disconnect(struct libivc_client * disconnecting_client)
{
    //FIXME: Abstract and serialize!
    struct libivc_client *target;
    event_channel_work_t *work;
    file_context_t *context;

    libivc_checkp(disconnecting_client, -EINVAL);

    // Try to find the client on the other side of this local connection.
    target = __ks_platform_find_local_counterpart(disconnecting_client);

    // If we don't have a counterpart, we're done!
    if(!target)
        return SUCCESS;

    context = disconnecting_client->context;
    if(context && context->task)
        libivc_info("Event sent from: %s\n", context->task->comm);

    context = target->context;
    if(context && context->task)
        libivc_info("And being sent to: %s\n", context->task->comm);

    // Create a unit of work that will handle the event callback...
    work = kzalloc(sizeof(event_channel_work_t), GFP_KERNEL);
    libivc_checkp(work, OUT_OF_MEM);

    // ... and populate it with information about the client to be notified.
    INIT_WORK((struct work_struct *) work, ks_platform_send_local_disconnect);
    work->info = (void *)target;

    // Schedule the event to processed by our worker queue.
    queue_work(eventWorkQueue, (struct work_struct *) work);

    return SUCCESS;
}


/**
 * Sends an event notification to the _local_ client on the other end
 * of a same-domain IVC connection.
 *
 * @param client The client /sending/ the notification.
 */
static void notify_local_counterpart(struct libivc_client * client)
{
    struct libivc_client *target;
    event_channel_work_t *work;

    libivc_checkp(client);

    target = ks_platform_find_local_counterpart(client);
    libivc_checkp(target);

    // Create a unit of work that will handle the event callback...
    work = kzalloc(sizeof(event_channel_work_t), GFP_KERNEL);
    libivc_checkp(work);

    // ... and populate it with information about the client to be notified.
    INIT_WORK((struct work_struct *) work, ks_platform_send_local_event);
    work->info = (void *)target;

    // Schedule the event to processed by our worker queue.
    queue_work(eventWorkQueue, (struct work_struct *) work);
}


/**
 * Fires a XEN event specified by the dom id in client.
 * @param client - non null pointer to object that describes connection.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_fire_remote_event(struct libivc_client *client)
{
    libivc_checkp(client, INVALID_PARAM);

    if(client->remote_domid == domId)
    {
        notify_local_counterpart(client);
    }
    else if(xen_initial_domain() && client->irq_port > 0)
    {
        notify_remote_via_irq(client->irq_port);
    }
    else if(client->event_channel == 0 && client->irq_port > 0)
    {
        notify_remote_via_irq(client->irq_port);
    }
    else if(client->event_channel > 0)
    {
        notify_remote_via_evtchn(client->event_channel);
    }
    else
    {
        libivc_error("Tried to notify a remote, but didn't have a method of firing an event!\n");
        return INVALID_PARAM;
    }

    return SUCCESS;
}

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
                             size_t memSize, file_context_t *context)
{
    shareable_mem_alloc_t *memAlloc;
    mmap_info_t *mmap_info = NULL;
    void *addr = NULL; // return from vm_mmap
    int rc = INVALID_PARAM;
    unsigned long cookie;

    // sanity check the variables.
    libivc_checkp(uAddress, rc);
    libivc_assert(memSize > 0, rc);
    libivc_checkp(context, rc);
    *uAddress = NULL; // to make sure bad pointers aren't set.

    memAlloc = find_shareable_mem_by_kaddr(kAddress);

    if(memAlloc)
    {
        memAlloc->context = context;
    }

    // if the match wasn't found, return error code.
    libivc_assert(!(memAlloc == NULL), INVALID_PARAM);
    mmap_info = vzalloc(sizeof(mmap_info_t));
    libivc_checkp(mmap_info, OUT_OF_MEM);

    mmap_info->id = next_mmap_cookie++;
    mmap_info->numPages = memAlloc->numPages;
    mmap_info->pages = memAlloc->pages;

    if(xen_hvm_domain()) libivc_checkp(mmap_info->pages, INTERNAL_ERROR);
    libivc_assert(mmap_info->numPages > 0, INTERNAL_ERROR);

    // set the process context pointers mapInfo to the memAlloc so that
    // mmap can get a handle to the pages that are being mapped.
    context->mapInfo = mmap_info;

    mutex_lock(&mmapInfoMutex);
    list_add(&mmap_info->node, &mmapInfoList);

    if(xen_pv_domain() || xen_hvm_domain())
    {
        // Bring the deferred information along if necessary
        cookie = cookie_for_mmap_info(mmap_info);
        addr = (void *) vm_mmap(context->file, 0, mmap_info->numPages * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, cookie);
    }
    else
    {
        libivc_info("Unsupported domain type\n");
    }

    list_del(&mmap_info->node);
    mutex_unlock(&mmapInfoMutex);

    vfree(mmap_info);
    if(IS_ERR(addr))
    {
        libivc_error("Failed to map kernel address to user space.\n");
        rc = ADDRESS_NOT_AVAIL;
    }
    else
    {
        *uAddress = (char *) addr;
        rc = SUCCESS;
    }

    return rc;
}

/**
 * The kernel modules init/driver entry
 * @param node unused.
 * @param file The user space process file handle that opened us.
 * @return SUCCESS, or appropriate error number.
 */
static int
ks_platform_open(struct inode *node, struct file *file)
{
    int rc = SUCCESS;
    file_context_t *context = NULL;

    libivc_checkp(file, INVALID_PARAM);

    // all calls to the driver from user space pass the same struct file in which
    // we can store our own information in.  Allocate space for that
    // data that will be passed around.
    context = vzalloc(sizeof(file_context_t));
    // make sure we are not out of memory.
    if(!context)
    {
        return -ENOMEM;
    }

    // set the private data that we can refer to later.
    file->private_data = context;
    // get the process task so we can use it for mmap and signals.
    context->task = current;

    // incrememnt the count on the task so that it doesn't get wiped out underneath us
    // by the OS.

    get_task_struct(context->task);
    // a little circular, but handy when passing to other functions.
    context->file = file;
    // let the user space know we are successful
    return rc;
}

/**
 * Called whenever a process closes a handle to the driver or crashes.
 * @param inode unused.
 * @param file the user space file handle that originally opened us.
 * @return SUCCESS or error no.
 */
static int
ks_platform_release(struct inode *inode, struct file *file)
{
    int rc = SUCCESS;
    file_context_t *context = NULL;
    libivc_checkp(file, -INVALID_PARAM);

    libivc_info("Driver detected file closing.\n");
    // get the context information set during the open.
    context = file->private_data;
    // notify the core that the user space has closed (or crashed)
    rc = ks_ivc_core_file_closed(context);
    // decrement the usage count on the task so the OS can clean up the struct.
    put_task_struct(context->task);
    // what we created, we destroy.
    vfree(context);
    // no dangling false pointers.
    file->private_data = context = NULL;
    // let the user space know it was successful.
    return rc;
}

/**
 * Function called when user space sends IOCTL to the driver.
 * @param f The user space file handle that opened the driver.
 * @param cmd The IOCTL command.
 * @param payload The payload, which should be of type ivcIoctl_t
 * @return SUCCESS, or appropriate error number in platform specific way.
 */
static long
ks_platform_ioctl(struct file *f, unsigned int cmd, unsigned long payload)
{
    int err = SUCCESS;
    file_context_t *context = NULL;
    struct libivc_client_ioctl_info usClient;
    struct libivc_server_ioctl_info usServer;
    int rc;
    memset(&usClient, 0, sizeof(struct libivc_client_ioctl_info));
    memset(&usServer, 0, sizeof(struct libivc_server_ioctl_info));

    libivc_checkp(f, -EINVAL);
    context = (file_context_t *) f->private_data;
    libivc_checkp(context, -EINVAL);
    context->private = f;
    libivc_assert(_IOC_TYPE(cmd) == IVC_DRIVER_IOC_MAGIC, -EINVAL);
    libivc_assert(_IOC_NR(cmd) <= IVC_RECONNECT_IOCTL, -EINVAL);

    if(_IOC_DIR(cmd) & _IOC_READ)
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
        err = !access_ok((void *) payload, _IOC_SIZE(cmd));
#else
	err = !access_ok(VERIFY_WRITE, (void *) payload, _IOC_SIZE(cmd));
#endif
    }
    else if(_IOC_DIR(cmd) & _IOC_WRITE)
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
        err = !access_ok((void *) payload, _IOC_SIZE(cmd));
#else
	err = !access_ok(VERIFY_READ, (void *) payload, _IOC_SIZE(cmd));
#endif
    }

    libivc_assert(err == false, -EPERM);

    switch(_IOC_NR(cmd))
    {
        case IVC_CONNECT_IOCTL:
        case IVC_RECONNECT_IOCTL:
        case IVC_DISCONNECT_IOCTL:
        case IVC_NOTIFY_REMOTE_IOCTL:
        case IVC_SERVER_ACCEPT_IOCTL:
        case IVC_PV_MMAP_STAGE2_IOCTL:
        case IVC_MUNMAP_IOCTL:
        {
            // safely copy data from user space ioctl to our kernel space.
            libivc_assert((rc = copy_from_user((void *) &usClient, (void *) payload,
                                               (unsigned long) sizeof(struct libivc_client_ioctl_info))) == SUCCESS, -EINVAL);

            if(_IOC_NR(cmd) == IVC_MUNMAP_IOCTL)
            {
                struct libivc_client *client = ks_ivc_core_find_internal_client(&usClient);
                libivc_assert(client != NULL, -EINVAL);

                err = ks_platform_munmap(client, context);

                usClient.buffer = NULL;
                usClient.num_pages = 0;
            }
            else
            {
                // send to core for processing
                err = ks_ivc_core_client_ioctl(_IOC_NR(cmd), &usClient, context);
            }

            if(err == SUCCESS)
            {
                libivc_assert((copy_to_user((struct libivc_client_ioctl_info *) payload, &usClient,
                                            sizeof(struct libivc_client_ioctl_info))) == SUCCESS, -EACCES);
            }
        }
        break;
        case IVC_REG_SVR_LSNR_IOCTL:
        case IVC_UNREG_SVR_LSNR_IOCTL:
        {
            // safely copy data from user space ioctl to our kernel space.
            libivc_assert((copy_from_user((void *) &usServer, (void *) payload,
                                          sizeof(struct libivc_server_ioctl_info))) == SUCCESS, -EINVAL);
            // send to core for processing
            err = ks_ivc_core_server_ioctl(_IOC_NR(cmd), &usServer, context);
            if(err == SUCCESS)
            {
                // copy data back to user space safely.
                libivc_assert((copy_to_user((struct libivc_server *) payload, &usServer,
                                            sizeof(struct libivc_server_ioctl_info))) == SUCCESS, -EACCES);
            }
        }
        break;
        default:
            err = -EINVAL;
    }

    return -err;
}

/**
 * Callback which handles mapping memory into user space.  This should not be called
 * directly from user space via its own mmap.  The flow should be an IOCTL to
 * allocate shared mem or map remote mem, which then calls vm_mmap, which in turn
 * calls this.
 * @param filp Usespace file handle that opened us.
 * @param vma area we are mapping into.
 * @return SUCCESS or appropriate platform specific error number.
 */
static int
ks_platform_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int rc = SUCCESS;
    int i, mapping_id;
    mmap_info_t *mmap_info;

    //this shouldn't fail, but always check anyway....
    libivc_checkp(filp, -EINVAL);
    libivc_checkp(vma, -EINVAL);
    libivc_checkp(filp->private_data, -EINVAL);

    libivc_info("in mmap\n");

    // Like DRM, we pass in an ID number ("cookie") in the offset field of
    // our mmap calls. This offset number allow us to find the information
    // related to this particular mmap call.
    //
    // A cleaner method would be to have a single fopen()-- and thus a
    // single context-- per mapping, but that's not what we have right
    // now. Perhaps in the future?
    mapping_id = vma->vm_pgoff;
    vma->vm_pgoff = 0;

    // don't allow remapping of memory to different sizes
    vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;

    // don't cache data in the pages
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

    // Find information about the relevant guest mapping.
    mmap_info = __find_mmap_info_by_id(mapping_id);

    // if the mmap_info wasn't set, then we shouldn't be mmapping anything.
    libivc_checkp(mmap_info, -EINVAL);

    // make sure the user space process has enough space to map into.
    if((vma->vm_end - vma->vm_start) < (mmap_info->numPages * PAGE_SIZE))
    {
        printk(KERN_WARNING "[ivc]: Not enough space to map in memory.\n");
        return -ENOSPC;
    }

    libivc_checkp(mmap_info->pages, -EINVAL);

    for(i = 0; i < mmap_info->numPages; i++)
    {
        // on success, this should return SUCCESS (0)
        // if it's anything but zero, something went wrong.  Should only happen if
        // user space process crashed.
        libivc_assert((rc = vm_insert_page(vma, vma->vm_start + i * PAGE_SIZE,
                                           mmap_info->pages[i])) == SUCCESS, -EACCES);
    }

    return rc;
}

/**
 * Unmaps a collection of IVC memory from the userspace,
 * releasing a userspace mmap.
 *
 * @param client The client for which the connection exists; may be internal
 *    or external, as long as its buffer points to the region to be unmapped.
 * @param f The file context for the active client; determines the virtual
 *    memory space in which this exists.
 *
 * @return SUCCESSS, or an appropriate error code
 */
static int
ks_platform_munmap(struct libivc_client *client, file_context_t *f)
{
    // Tear the VMA out from under the userspace, which should no longer
    // be using it (as it either called munmap, or is a dying process).
    if(client->buffer)
        vm_munmap((uintptr_t)client->buffer, client->num_pages * PAGE_SIZE);

    return SUCCESS;
}


/**
 * Linux kernel module struct which describes what functions/callbacks are available
 * to a user space process that opens the driver.
 */
static const struct file_operations ivc_fops =
{
    .owner = THIS_MODULE, // ivc
    .open = ks_platform_open, // called when user space opens the driver
    .release = ks_platform_release, // called when user space closes or crashes.
    .unlocked_ioctl = ks_platform_ioctl, // called during ioctl to driver.
    .mmap = ks_platform_mmap, // called when mapping memory from driver.
};

/**
 * Linux character device description.
 */
static struct miscdevice ivc_dev =
{
    // don't care what minor number we have. let the kernel decide.
    MISC_DYNAMIC_MINOR,
    // name ourselves /dev/ivc
    "ivc",
    // our file ops
    &ivc_fops
};

/**
 * Linux kernel driver entry point.  Determines if it's a backend (Dom0) or frontend
 * (Domu) and calls appropriate initialization functions.
 * @return SUCCESS or appropriate platform error.
 */
static int __init
ks_platform_ivc_init(void)
{
    int rc;

    libivc_debug_init();

    // Determine if we should rely on Xen to set up PTEs. This is required
    // for most PV guests, which don't have permissions to modify their
    // own page tables.
    use_ptemod = !xen_feature(XENFEAT_auto_translated_physmap);

    // register this device with the LINUX os.
    libivc_assert((rc = misc_register(&ivc_dev)) == SUCCESS, rc);

    // initialize an empty list for the event callbacks.
    INIT_LIST_HEAD(&eventCallbacks);
    // initialize the mutex that is used to lock the above list.
    mutex_init(&eventMutex);

    // create the work queue which will be used for moving calls from an
    // interrupt context to a kernel threaded process context.
    eventWorkQueue = alloc_workqueue("eventWorkQueue", WQ_MEM_RECLAIM | WQ_UNBOUND, MAX_ACTIVE_WORKQUEUE_THREADS);

    // initialize the generic driver core
    if(!xen_initial_domain())
    {
        libivc_assert_goto((rc = ks_ivc_core_init()) == SUCCESS, ERROR);
    }
    goto END;
ERROR:
    misc_deregister(&ivc_dev);
END:
    return rc;
}
// tell the Linux OS what our entry point is when loading the module.
module_init(ks_platform_ivc_init);

/**
 * Callback that occurs when driver is being removed.
 */
static void __exit
ks_platform_ivc_exit(void)
{
    _TRACE();
    ks_ivc_core_uninit();
    _TRACE();
    libivc_debug_fini();
    // unregister ourselves with the OS so that it can properly clean up
    // and allow the driver to be reloaded if needed.
    _TRACE();
    misc_deregister(&ivc_dev);
    _TRACE();
}

// tell LINUX what to call when we are unloaded.
module_exit(ks_platform_ivc_exit);
// give LINUX some information that can be displayed when querying the module.
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Assured Information Security, Inc.");
MODULE_DESCRIPTION("SecureView Inter-VM Communications device.");
MODULE_VERSION("dev");

int
ks_platform_xenstore_rm(const char *path, const char *node)
{
    xenbus_transaction_t trans;
    int rc = INVALID_PARAM;

    libivc_checkp(path, rc);
    libivc_checkp(node, rc);

    do
    {
        rc = xenbus_transaction_start(&trans);
        rc |= xenbus_rm(trans, path, node);
        rc |= xenbus_transaction_end(trans, 0);
    }
    while(rc == -EAGAIN);

    if(rc < 0)
    {
        rc = ACCESS_DENIED;
    }
    return rc;
}

/**
 * Notifies a user space server listener that a new client has connected.
 * @param server NON null server to notify.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_notify_us_client_connect(struct libivc_server *server)
{
    file_context_t *context = NULL;

    libivc_checkp(server, INVALID_PARAM);
    libivc_checkp(server->context, INVALID_PARAM);
    libivc_assert(server->client_connect_event > 0, INVALID_PARAM);
    context = (file_context_t *) server->context;
    libivc_checkp(context, INVALID_PARAM);

    return _ks_platform_notify_us_event(server->client_connect_event, context->task);
}

/**
 * Notifies a user space ivc client that a remote event was fired to it.
 * @param client - NON null ivc client to notify.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_notify_us_client_event(struct libivc_client *client)
{
    int rc = INVALID_PARAM;
    file_context_t *context = NULL;

    libivc_checkp(client, rc);
    libivc_assert(client->client_notify_event > -1, rc);
    libivc_checkp(client->context, rc);

    context = (file_context_t *) client->context;
    return _ks_platform_notify_us_event(client->client_notify_event, context->task);
}

/**
 * Notifies a user space ivc client that a remote wants to disconnect.
 * @param client - NON null ivc client to notify.
 * @return SUCCESS or appropriate error number.
 */
int
ks_platform_notify_us_client_disconnect(struct libivc_client *client)
{
    int rc = INVALID_PARAM;
    file_context_t *context = NULL;

    libivc_checkp(client, rc);
    libivc_assert(client->client_disconnect_event > -1, rc);
    libivc_checkp(client->context, rc);

    context = (file_context_t *) client->context;
    libivc_checkp(context, rc);
    return _ks_platform_notify_us_event(client->client_disconnect_event, context->task);
}
