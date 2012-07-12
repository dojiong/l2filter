/*
 * l2filter l2filter_main.c
 * author: lo <lodevil@live.cn>
 * 
 */

#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include "filter.h"
#include "user_comm.h"

static unsigned int hook_function(unsigned int hooknum,
                   struct sk_buff *skb,
                   const struct net_device *in,
                   const struct net_device *out,
                   int (*okfn)(struct sk_buff *)) {
    

    return NF_ACCEPT;
}

static void user_msg_input(int pid, unsigned char *data, int size) {
    user_comm_unicast(pid, data, size);
}

static struct nf_hook_ops _nfho = {
    .hook = hook_function,
    .hooknum = NF_BR_PRE_ROUTING,
    .pf = NFPROTO_UNSPEC,
    .priority = NF_BR_PRI_FIRST
};

static int __init l2filter_init (void) {
    int ret;

    filter_init();

    ret = user_comm_init(user_msg_input);
    if (ret) {
        printk(KERN_ERR "l2filter: user_comm init fail\n");
        return ret;
    }

    ret = nf_register_hook(&_nfho);
    if (ret) {
        printk(KERN_ERR "l2filter: register hook fail!\n");
        user_comm_exit();
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

