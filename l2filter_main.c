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
    if (filter_size > 0) {
        return filter_skb(skb, in, out);
    } else {
        printk(KERN_INFO "no filter installed\n");
    }
    return NF_ACCEPT;
}

static void user_msg_input(int pid, unsigned char *data, int size) {
    if (data[0] == 'A') {
        if (add_filter(data + 1, size - 1)) {
            user_comm_unicast(pid, "fail", 4);
        } else {
            user_comm_unicast(pid, "ok", 2);
        }
    } else if (data[0] == 'C') {
        clear_filters();
        user_comm_unicast(pid, "ok", 2);
    }
}

static struct nf_hook_ops _nfho = {
    .hook = hook_function,
    .hooknum = NF_BR_PRE_ROUTING,
    .pf = NFPROTO_BRIDGE,
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
    nf_unregister_hook(&_nfho);
    printk(KERN_INFO "l2filter hook unregistered\n");

    user_comm_exit();
    printk(KERN_INFO "l2filter user_comm exited\n");

    clear_filters();
    printk(KERN_INFO "l2filter filters cleared\n");
    
    printk(KERN_INFO "l2filter exit\n");
}

module_init(l2filter_init);
module_exit(l2filter_exit);

