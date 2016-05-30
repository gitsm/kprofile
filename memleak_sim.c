/* 
 * 
 * Author: Sridharan Muthuswamy (sm)
 * Date: May 23, 2016
 * 
 * This module simulates 16 vmalloc()-ed memory leaks on a module load.
 * The vmallo()-ed addresses are freed on a module unload. The memory 
 * leak can be simulated to any arbitrary value (this test hardcodes it 
 * to 16). 
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sridharan Muthuswamy");

#define MAX_MEM_LEAK 16
void *ptr[MAX_MEM_LEAK];

static int __init memleak_init(void)
{
       int i;
   
       for(i=0; i<MAX_MEM_LEAK; i++) {
             ptr[i] = vmalloc(PAGE_SIZE);
       }
       return 0;
}

static void __exit memleak_exit(void)
{ 
       int i;

       for(i=0; i<MAX_MEM_LEAK; i++) {
             if (ptr[i])  
                   vfree(ptr[i]);
       }
}

module_init(memleak_init);
module_exit(memleak_exit);
