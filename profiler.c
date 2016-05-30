/* 
 *
 * Author: Sridharan Muthuswamy (sm)
 * Date: May 23, 2016
 *
 * This module sets up the sysfs framework for 
 *     - exporting stats such as average invocation time of syscalls in nanoseconds
 *        and number of times syscalls were invoked 
 *     - exporting potential memory leak stats (memory block address allocated but not 
 *       freed) and the instruction pointer of the function that allocated this chunk
 *       of memory (vmalloc in this case)
 *     - configuring the memory scan start and end addresses within which to search for 
 *       blocks with unfreed pointers
 * The module uses kprobes to trace syscalls by planting kprobes at specified syscall 
 * function addresses. The syscall functions to trace are provided by the user through 
 * module params at insmod. There is support for tracing of upto 16 systems. This is not  
 * a limitation of the design but more so a number to demonstrate that the feature works.
 *
 * Note: Memory traces using kretprobes and jprobes are accomplished in memtrace.c. 
 *       Memory leaks using vmalloc are simulated in memleaks.c
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stat.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include "profiler.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sridharan Muthuswamy");

krp_stats_t krp_stats[NUM_ARGS];
kmp_stats_t kmp_stats[MEM_TRACE_MAX];
static struct kprobe kp[NUM_ARGS];

rwlock_t memleak_list_lock;
struct list_head memleak_list_head;
void *vmalloc_instp;

EXPORT_SYMBOL(kmp_stats);
EXPORT_SYMBOL(memleak_list_lock);
EXPORT_SYMBOL(memleak_list_head);
EXPORT_SYMBOL(vmalloc_instp);

static dev_t dev;
static struct cdev cdev;
static char *funcs[NUM_ARGS];
static int argc = 0;
struct device *pdevice;
static struct class *pclass = NULL;
static void *scan_start_addr;
static void *scan_end_addr;

module_param_array(funcs, charp, &argc, 0000);
MODULE_PARM_DESC(funcs, "An array of system calls (max 16)");


static inline void *string_to_void_ptr(const char *buf) 
{
       int i, j, shift, l=strlen(buf);
       unsigned int k = 0;
       if (l == 9) l--; /* BUG WAR: buffer sometimes includes '\n' */
       for(i=0; i<l; i++) {
            if (buf[i]>='0' && buf[i]<='9')
                  j = buf[i]-'0';
            else if (buf[i]>='a' && buf[i]<='f')
                  j = buf[i]-'a'+10;
            else if (buf[i]>='A' && buf[i]<='F')
                  j = buf[i]-'A'+10;
            else 
                  j = 0; /* should not happen */
            shift = 4*(l-1-i);
            k |= (j << shift);
       }
       return (void *)k;
}

static ssize_t sys_read_stats(struct device *dev, struct device_attribute *attr, char *buf)
{
       int i, len=0;

       printk(KERN_DEBUG "%s\n",__func__);
       for(i=0; i<argc; i++) {
          if (krp_stats[i].addr && krp_stats[i].count) {
              sprintf(&buf[len], "%s:%lu:%lu\n",krp_stats[i].func,
                      (long)krp_stats[i].avg_time/krp_stats[i].count, 
                      krp_stats[i].count);
              len+=strlen(buf);
          }
       }
       return len;
}

static ssize_t sys_read_memleaks(struct device *dev, struct device_attribute *attr, char *buf)
{
        int i, len = 0;
        for(i=0; i<MEM_TRACE_MAX; i++) {
             if (kmp_stats[i].addr && kmp_stats[i].addr >= scan_start_addr &&
                 kmp_stats[i].addr <= scan_end_addr) {
                   sprintf(&buf[len],"%p:%s:%p\n",kmp_stats[i].addr,
                          "<possible leak or not freed yet>",vmalloc_instp);
                   len+=strlen(buf);
              }
        }
        return len;
}

static ssize_t sys_write_scan_start_addr(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{      
       scan_start_addr=(buf) ? string_to_void_ptr(buf) : NULL;
       printk(KERN_DEBUG "%s: scan start addr = %p\n",__func__,scan_start_addr);
       return count;
}

static ssize_t sys_write_scan_end_addr(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
       scan_end_addr=(buf) ? string_to_void_ptr(buf) : NULL;
       printk(KERN_DEBUG "%s: scan end addr = %p\n",__func__,scan_end_addr);
       return count;
}

static DEVICE_ATTR(stats, S_IRUGO, sys_read_stats, NULL);
static DEVICE_ATTR(memleaks, S_IRUGO, sys_read_memleaks, NULL);
static DEVICE_ATTR(scan_start_addr, S_IWUGO, NULL, sys_write_scan_start_addr);
static DEVICE_ATTR(scan_end_addr, S_IWUGO, NULL, sys_write_scan_end_addr);

/* kprobe pre_handler: called just before the probed instruction is executed */
int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
       int i;

       printk(KERN_DEBUG "%s: p->addr=0x%p\n",__func__,p->addr);
       /* linear search; TODO: hash_table lookup */
       for(i=0; i<argc; i++) {
           if ((void *)p->addr == krp_stats[i].addr) {
               krp_stats[i].entry_stamp = ktime_get();
               break; 
           }
       }
       return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
       int i;
       ktime_t now;

       printk(KERN_DEBUG "%s: p->addr=0x%p\n",__func__,p->addr);
       /* linear search; TODO: hash_table lookup */
       for(i=0; i<argc; i++) {
             if ((void *)p->addr == krp_stats[i].addr) {
                 now = ktime_get();
                 krp_stats[i].avg_time += ktime_to_ns(ktime_sub(now, krp_stats[i].entry_stamp));
                 krp_stats[i].count += 1;
                 break; 
              }
        }
        return;
}

/* fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
       printk(KERN_DEBUG "%s: p->addr=0x%p, trap #%dn",__func__,p->addr,trapnr);
       /* Return 0 because we don't handle the fault */
       return 0;
}

static int __init profiler_init(void)
{
       int i, ret;

       printk(KERN_INFO "%s\n",__func__);
       alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
       pclass = class_create(THIS_MODULE, CLASS_NAME);
       pdevice = device_create(pclass, NULL, dev, NULL, DEVICE_NAME);
       cdev_init(&cdev, NULL);
       cdev_add(&cdev, dev, 1);

       if ((ret = device_create_file(pdevice, &dev_attr_stats)) < 0)
             printk(KERN_INFO "Failed to create read sysfs endpoint /stats\n");

       if ((ret = device_create_file(pdevice, &dev_attr_memleaks)) < 0)
             printk(KERN_INFO "Failed to create read sysfs endpoint /memleaks\n");

       if ((ret = device_create_file(pdevice, &dev_attr_scan_start_addr)) < 0)
             printk(KERN_INFO "Failed to create write sysfs endpoint /scan_start_addr\n");

       if ((ret = device_create_file(pdevice, &dev_attr_scan_end_addr)) < 0)
             printk(KERN_INFO "Failed to create write sysfs endpoint /scan_end_addr\n");

        /* KRP - profiling system calls */

        argc = (argc > NUM_ARGS) ? NUM_ARGS : argc;

        for(i=0; i<argc; i++) {
             memset(&krp_stats[i], 0, sizeof(krp_stats_t));
             kp[i].pre_handler = handler_pre;
             kp[i].post_handler = handler_post;
             kp[i].fault_handler = handler_fault;
             kp[i].addr = (kprobe_opcode_t *)kallsyms_lookup_name(funcs[i]);
             /* register the kprobe now */
             if (!kp[i].addr) {
	          printk(KERN_ERR "Couldn't find %s to plant kprobe\n", funcs[i]);
                  continue;
             }
             if ((ret = register_kprobe(&kp[i]) < 0)) {
                  printk(KERN_ERR "register_kprobe failed for %s, returned %d\n",funcs[i],ret);
                  continue;
             }
             printk(KERN_INFO "kprobe for %s registered\n",funcs[i]);

             /* init krp stats structure */
             printk(KERN_INFO "funcs[%d]=%s\n",i,funcs[i]);
             krp_stats[i].addr = (void *)kp[i].addr;
             strcpy(krp_stats[i].func, funcs[i]);
        }
        return 0;
}

static void __exit profiler_exit(void)
{  
        int i;

        printk(KERN_INFO "%s\n",__func__);
        device_remove_file(pdevice, &dev_attr_stats);
        device_remove_file(pdevice, &dev_attr_memleaks);
        device_remove_file(pdevice, &dev_attr_scan_start_addr);
        device_remove_file(pdevice, &dev_attr_scan_end_addr);
        cdev_del(&cdev);
        unregister_chrdev_region(dev, 1);
        device_destroy(pclass, dev);
        class_destroy(pclass);
        for(i=0; i<argc; i++) {
              unregister_kprobe(&kp[i]);
              printk(KERN_INFO "kprobe for %s unregistered\n",funcs[i]);
        }
}

module_init(profiler_init);
module_exit(profiler_exit);
