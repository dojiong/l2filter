/*
 * l2filter l2filter_main.c
 * author: lo <lodevil@live.cn>
 * 
 */

#include <linux/netfilter.h>
#include "filter.h"
#include "user_comm.h"

void msg_input(int pid, unsigned char *data, int size) {
    user_comm_unicast(pid, data, size);
}

static int __init l2filter_init (void) {
    int ret;

    filter_init();

    ret = user_comm_init(msg_input);
    if (ret) {
        printk(KERN_ERR "l2filter: user_comm init fail\n");
        return ret;
    }
    
    printk(KERN_INFO "l2filter inited\n");
    return 0;
}

static void __exit l2filter_exit(void) {
    user_comm_exit();
    clear_filters();
    printk(KERN_INFO "l2filter exit\n");
}

module_init(l2filter_init);
module_exit(l2filter_exit);

