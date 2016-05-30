#ifndef _PROFILER_H
#define _PROFILER_H

#define NUM_ARGS 16
#define MEM_TRACE_MAX 512

#define CLASS_NAME "linux"
#define DEVICE_NAME "profiler"

typedef struct krp_stats_t {
       void *addr;
       char func[NAME_MAX];
       ktime_t entry_stamp;
       unsigned long count;
       s64 avg_time;
} krp_stats_t;

typedef struct kmp_stats_t {
       void *addr;
} kmp_stats_t;

typedef struct memleak_node_t {
       void *memp;
       struct list_head list_member;
} memleak_list_t; 

#endif
