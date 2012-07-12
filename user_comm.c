/*
 * l2filter user_comm.c
 * author: lo <lodevil@live.cn>
 * 
 */

#include "user_comm.h"
#include <linux/seq_file_net.h>
#include <linux/mutex.h>

static DEFINE_MUTEX(nl_mutex);
static struct sock *_sock;
static msg_input_func _msg_input;
static void _nl_input(struct sk_buff *skb);

int user_comm_init(msg_input_func input_func) {
    _sock = netlink_kernel_create(&init_net, NETLINK_L2FILTER, 0,
        _nl_input, NULL, THIS_MODULE);
    if (_sock == NULL) return -1;
    _msg_input = input_func;
    return 0;
}

void user_comm_exit(void) {
    if (_sock) netlink_kernel_release(_sock);
}

int user_comm_unicast(int pid, void *data, int size) {
    struct nlmsghdr *nlh;
    struct sk_buff *skb;

    skb = alloc_skb(NLMSG_SPACE(size), GFP_ATOMIC);
    if (skb == NULL) return -1;
    nlh = NLMSG_PUT(skb, 0, 0, 0, size);
    memcpy(NLMSG_DATA(nlh), data, size);
    return netlink_unicast(_sock, skb, pid, MSG_DONTWAIT);

nlmsg_failure:
    kfree_skb(skb);
    printk(KERN_ERR "l2filter: error unicast NLMSG_PUT fail\n");
    return -1;
}

int user_comm_broadcast(void *data, int size) {
    struct nlmsghdr *nlh;
    struct sk_buff *skb;

    skb = alloc_skb(NLMSG_SPACE(size), GFP_ATOMIC);
    if (skb == NULL) return -1;
    nlh = NLMSG_PUT(skb, 0, 0, 0, size);
    memcpy(NLMSG_DATA(nlh), data, size);
    return netlink_broadcast(_sock, skb, 0, 1, GFP_ATOMIC);

nlmsg_failure:
    kfree_skb(skb);
    printk(KERN_ERR "l2filter: error broadcast NLMSG_PUT fail\n");
    return -1;
}

static void __nl_input(struct sk_buff *skb) {
    int nlmsglen, skblen;
    struct nlmsghdr *nlh;

    skblen = skb->len;
    if (skblen < sizeof(*nlh)) {
        printk(KERN_INFO "l2filter: user_comm invalid size: %d\n", skblen);
        return;
    }

    nlh = nlmsg_hdr(skb);
    nlmsglen = nlh->nlmsg_len;
    if (nlmsglen < sizeof(*nlh) || skblen < nlmsglen) {
        printk(KERN_INFO "l2filter: user_comm invalid size2: %d\n", nlmsglen);
        return;
    }
    _msg_input(nlh->nlmsg_pid, NLMSG_DATA(nlh), nlh->nlmsg_len - NLMSG_HDRLEN);
}

static void _nl_input(struct sk_buff *skb) {
    mutex_lock(&nl_mutex);
    __nl_input(skb);
    mutex_unlock(&nl_mutex);
}