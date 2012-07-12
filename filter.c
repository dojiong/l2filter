/*
 * l2filter filter.c
 * author: lo <lodevil@live.cn>
 * 
 */

#include "filter.h"
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/mutex.h>
#include "dump.h"
#include "user_comm.h"

#define MIN_FILTER_ITEM_SIZE (1 + 1 + 2 + 2 + 1)
#define MIN_FILTER_SIZE (1 + 1 + 1 + MIN_FILTER_ITEM_SIZE)

static int _add_filter(unsigned char *data, int size);
static void _clear_filters(void);
static int _filter_skb(struct sk_buff *skb,
    const struct net_device *in, const struct net_device *out);

static DEFINE_MUTEX(filter_chain_mutex);
static struct filter filter_head;
static struct filter *filter_tail;
int filter_size;

void filter_init(void) {
    mutex_lock(&filter_chain_mutex);
    filter_head.items = NULL;
    filter_head.next = NULL;
    filter_tail = &filter_head;
    filter_size = 0;
    mutex_unlock(&filter_chain_mutex);
}

int add_filter(unsigned char *data, int size) {
    int ret;
    mutex_lock(&filter_chain_mutex);
    ret = _add_filter(data, size);
    mutex_unlock(&filter_chain_mutex);
    return ret;
}

void clear_filters(void) {
    mutex_lock(&filter_chain_mutex);
    _clear_filters();
    mutex_unlock(&filter_chain_mutex);
}

int filter_skb(struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out) {
    int ret;
    mutex_lock(&filter_chain_mutex);
    ret = _filter_skb(skb, in, out);
    mutex_unlock(&filter_chain_mutex);
    return ret;
}

inline int _build_match_item(unsigned char *data,
        int max_size, struct match_item *item) {
    //item: BBHHs (uint8, uint8, uint16, uint16, string)
    //      md target start_or_dev, mt_size, mt
    int item_size;
    item->md = data[0];
    if (item->md >= kMaxMathMethod) return -1;

    item->target = data[1];
    if (item->target >= kMaxTarget) return -1;

    item->start = *(unsigned short*)(data + 1 + 1);
    if (item->target == kTargetDev && item->is_dev_in > 1) return -1;

    item->size = *(unsigned short*)(data + 1 + 1 + 2);
    item_size = 1 + 1 + 2 + 2 + item->size;
    if (item_size > max_size) return -1;
    if (item->size > 256) return -1;

    memcpy(item->mt, data + 1 + 1 + 2 + 2, item->size);

    return item_size;
}

static int _add_filter(unsigned char *data, int size) {
    //filter: BBB[item] (uint8 uint8 uint8 [item])
    //      tmp_filter.total_items, combine method
    int  i, rem_size;
    unsigned char *cur_item;
    struct filter tmp_filter;

    if (size < MIN_FILTER_ITEM_SIZE) return -1;

    tmp_filter.total_items = data[0];
    if (tmp_filter.total_items < 1 || tmp_filter.total_items > 8 ||
        (2 + MIN_FILTER_ITEM_SIZE * tmp_filter.total_items) > size) return -1;

    tmp_filter.combine_md = data[1];
    if (tmp_filter.combine_md >= kMaxCombineMethod) return -1;

    tmp_filter.process_mask = data[2];
    if ((tmp_filter.process_mask & ALL_PROCESS_MASK) == 0) return -1;

    rem_size = size - 3;
    cur_item = data + 3;
    tmp_filter.items = (struct match_item*)kmalloc(
        tmp_filter.total_items * sizeof(struct match_item), GFP_KERNEL);
    if (tmp_filter.items == NULL) return -1;
    for (i = 0; i < tmp_filter.total_items; ++i) {
        int item_size = _build_match_item(
            cur_item, rem_size, &tmp_filter.items[i]);
        if (item_size < MIN_FILTER_ITEM_SIZE)  {
            kfree(tmp_filter.items);
            return item_size;
        }

        rem_size -= item_size;
        cur_item += item_size;
    }

    tmp_filter.next = NULL;
    filter_tail->next = (struct filter*)kmalloc(
        sizeof(struct filter), GFP_KERNEL);
    if (filter_tail->next == NULL) {
        kfree(tmp_filter.items);
        return -1;
    }
    filter_tail = filter_tail->next;
    memcpy(filter_tail, &tmp_filter, sizeof(struct filter));
    filter_size++;

    return 0;
}

static void _clear_filters(void) {
    struct filter *cur = &filter_head;

    while (cur->next) {
        struct filter *to_free = cur;
        kfree(cur->items);
        cur = cur->next;
        kfree(to_free);
    }
    filter_size = 0;
}

inline int _run_match_item(struct match_item *item, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out) {
    switch (item->target) {
        case kTargetMAC: {
            if (skb_mac_header_was_set(skb) &&
                    skb->mac_len >= item->start + item->size) {
                if (memcmp(
                        skb_mac_header(skb) + item->start,
                        item->mt, item->size
                        )?kNotEqual:kEqual == item->md) {
                    return 1;
                }
            }
            break;
        }
        case kTargetL2: {
            if (skb->len >= item->start + item->size) {
                if (memcmp(skb->data + item->start,
                    item->mt, item->size
                    )?kNotEqual:kEqual == item->md) {
                    return 1;
                }
            }
            break;
        }
        case kTargetDev: {
            if (item->is_dev_in) {
                if (in &&
                        strncmp(in->name, item->mt, item->size
                        )?kNotEqual:kEqual == item->md) {
                    return 1;
                }
            } else {
                if (out &&
                        strncmp(out->name, item->mt, item->size
                        )?kNotEqual:kEqual == item->md) {
                    return 1;
                }
            }
            break;
        }
        default:
            break;
    }
    return 0;
}

inline int _process_skb(int mask, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out) {
    if (mask & kProcessLog) {
        printk(KERN_INFO "l2filter log: %s\n", dump(skb->data, skb->len));
    }

    if (mask & kProcessBroadcast) {
        user_comm_broadcast(skb->data, skb->len);
    }

    if (mask & kProcessDrop) {
        return NF_DROP;
    }

    return NF_ACCEPT;
}

static int _filter_skb(struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out) {
    struct filter *cur = &filter_head;
    int i;

    while (cur->next) {
        int matched;

        cur = cur->next;
        matched = cur->combine_md == kCombineAnd?1:0;

        for (i = 0; i < cur->total_items; ++i) {
            int ret = _run_match_item(&cur->items[i], skb, in, out);
            if (cur->combine_md == kCombineAnd) {
                if (!ret) {
                    matched = 0;
                    break;
                }
            } else {
                if (ret) {
                    matched = 1;
                    break;
                }
            }
        }

        if (matched) {
            int ret = _process_skb(cur->process_mask, skb, in, out);
            if (ret != NF_ACCEPT) {
                return ret;
            }
        }
    }

    return NF_ACCEPT;
}