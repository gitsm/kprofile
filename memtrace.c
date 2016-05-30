/* 
 * 
 *  Author: Sridharan Muthuswamy (sm)
 *  Date: May 23, 2016
 *
 *  This module traces vmalloc() memory allocs and vfree() memory frees. 
 *  kreprobes are planted at vmalloc function address to capture the return 
 *  value (allocated block address) and jprobes are planted at vfree function
 *  address to capture the function arguement (allocated block address to free).
 *  
 *  All vmalloc()-ed block addresses are added to a linear linked-list. On a vfree()
 *  the list is traversed to search and delete the block address. There is no size
 *  limitation for this linked list. A maximum of 512 (hardcoded) memory trace stats
 *  are copied from the linked list to an array for exporting to user space via the 
 *  sysfs interface.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include "profiler.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sridharan Muthuswamy");

static char func_vmalloc[NAME_MAX] = "vmalloc";
static char func_vfree[NAME_MAX] = "vfree";

extern kmp_stats_t kmp_stats[MEM_TRACE_MAX];
extern void *vmalloc_instp;
extern rwlock_t memleak_list_lock;
extern struct list_head memleak_list_head;

/* per-instance private data */
struct kmp_data_t {
        ktime_t entry_stamp;
};

static void func_vmalloc_record(void *ptr) 
{
        memleak_list_t *node = (memleak_list_t *)kmalloc(sizeof(memleak_list_t), GFP_KERNEL);
        unsigned long flags;
        int i;

        if (node) {
             node->memp = ptr;
             INIT_LIST_HEAD(&node->list_member);
             write_lock_irqsave(&memleak_list_lock, flags);
             list_add(&node->list_member, &memleak_list_head);
             write_unlock_irqrestore(&memleak_list_lock, flags);
             for(i=0;i<MEM_TRACE_MAX; i++) {
                  if (!kmp_stats[i].addr) {
                        kmp_stats[i].addr = node->memp;
                        break;
                  }
             }
        }
        else {
              printk(KERN_ERR "Memory trace node alloc failure\n");
        }
}

/* Here we use the entry_hanlder to timestamp function entry */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        struct kmp_data_t *data;

        if (!current->mm)
                return 1;       /* skip kernel threads */

        data = (struct kmp_data_t *)ri->data;
        data->entry_stamp = ktime_get();
        return 0;
}

/*
 * Return-probe handler: Log the return value and duration. Duration may turn
 * out to be zero consistently, depending upon the granularity of time
 * accounting on the platform.
 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        void *ptr = (void *)regs_return_value(regs);
        struct kmp_data_t *data = (struct kmp_data_t *)ri->data;
        s64 delta;
        ktime_t now;

        now = ktime_get();
        delta = ktime_to_ns(ktime_sub(now, data->entry_stamp));
        printk(KERN_INFO "%s returned ptr=%p and took %lld ns to execute\n",
                  func_vmalloc, ptr, (long long)delta);
        func_vmalloc_record(ptr);
        return 0;
}

static struct kretprobe kretprobe = {
        .handler                = ret_handler,
        .entry_handler          = entry_handler,
        .data_size              = sizeof(struct kmp_data_t),
        /* Probe up to 20 instances concurrently. */
        .maxactive              = 20,
};

static void func_vfree_find_and_delete(const void *ptr) 
{
        struct list_head *iter;
        memleak_list_t *node=NULL;
        unsigned long flags;
        int i;

        write_lock_irqsave(&memleak_list_lock, flags);
        list_for_each(iter, &memleak_list_head) {
              node = list_entry(iter, memleak_list_t, list_member);
              if (node->memp == ptr) {
                   list_del(&node->list_member);
                   write_unlock_irqrestore(&memleak_list_lock, flags);
                   goto node_free;
              }
        }
        write_unlock_irqrestore(&memleak_list_lock, flags);
        return;

node_free:
        if (node)
            kfree(node);
        for(i=0;i<MEM_TRACE_MAX; i++) {
             if (kmp_stats[i].addr == ptr) {
                   kmp_stats[i].addr = 0;
                   break;
             }
        }
}

/* Proxy routine having the same arguments as actual vfree routine */
static void jvfree(const void *addr)
{
	printk(KERN_DEBUG "jprobe: vfree(addr=%p)\n",addr);
        func_vfree_find_and_delete(addr);
        jprobe_return();
}

static struct jprobe jprobe = {
	.entry = (kprobe_opcode_t *) jvfree
};

static int __init memtrace_init(void)
{
        int ret;

        /* kretprobe initialization */

        kretprobe.kp.symbol_name = func_vmalloc;
        if ((ret = register_kretprobe(&kretprobe)) <0) {
                printk(KERN_ERR "register_kretprobe failed, returned %d\n",ret);
        }
        else {
                printk(KERN_INFO "Planted return probe at %s: %p\n",
                       kretprobe.kp.symbol_name, kretprobe.kp.addr);
                vmalloc_instp = kretprobe.kp.addr;
        }

        /* jprobe initialization */

        jprobe.kp.addr = (kprobe_opcode_t *)kallsyms_lookup_name(func_vfree);
        if (!jprobe.kp.addr) {
		printk(KERN_ERR "Couldn't find %s to plant jprobe\n",func_vfree);
	}
	else if ((ret = register_jprobe(&jprobe)) <0) {
		printk(KERN_ERR "register_jprobe failed for %s, returned %d\n",func_vfree,ret);
	}
        else {
	        printk(KERN_INFO "Planted jprobe at %p, handler addr %p\n",
	                jprobe.kp.addr, jprobe.entry);
        }

        rwlock_init(&memleak_list_lock);
        INIT_LIST_HEAD(&memleak_list_head);
        memset(&kmp_stats, 0, sizeof(kmp_stats));
        return 0;
}

static void __exit memtrace_exit(void)
{
        unregister_kretprobe(&kretprobe);
        printk(KERN_INFO "kretprobe at %p unregistered\n",
                kretprobe.kp.addr);

        /* nmissed > 0 suggests that maxactive was set too low. */
        printk(KERN_INFO "Missed probing %d instances of %s\n",
                kretprobe.nmissed, kretprobe.kp.symbol_name);

        unregister_jprobe(&jprobe);
	printk(KERN_INFO "jprobe at %p unregistered\n", 
                 jprobe.kp.addr);
}

module_init(memtrace_init);
module_exit(memtrace_exit);
