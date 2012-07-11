/*
 * l2filter filter.c
 * author: lo <lodevil@live.cn>
 * 
 */

#include "filter.h"
 #include <linux/netfilter.h>
#include <linux/mutex.h>

#define MIN_FILTER_ITEM_SIZE (1 + 1 + 2 + 2 + 1)
#define MIN_FILTER_SIZE (1 + 1 + 1 + MIN_FILTER_ITEM_SIZE)

static DEFINE_MUTEX(filter_chain_mutex);
static filter filter_head;
static filter *filter_tail;

int __build_match_item(
    unsigned char *data, int max_size, struct match_item *item);
int __add_filter(unsigned char *data, int size);
int __clear_filters();
int __filter_skb(struct sk_buff *skb,
    const struct net_device *in, const struct net_device *out);

void filter_init(void) {
    mutex_lock(filter_chain_mutex);
    filter_head.items = NULL;
    filter_head.next = NULL;
    filter_tail = &filter_head;
    mutex_unlock(filter_chain_mutex);
}

int add_filter(unsigned char *data, int size) {
    mutex_lock(filter_chain_mutex);
    int ret = __add_filter(data, size);
    mutex_unlock(filter_chain_mutex);
    return ret;
}

int clear_filters(void) {
    mutex_lock(filter_chain_mutex);
    int ret = __clear_filters();
    mutex_unlock(filter_chain_mutex);
    return ret;
}

int filter_skb(struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out) {
    mutex_lock(filter_chain_mutex);
    int ret = __filter_skb(skb, in, out);
    mutex_unlock(filter_chain_mutex);
    return ret;
}

inline int __build_match_item(unsigned char *data,
        int max_size, struct match_item *item) {
    //item: BBHHs (uint8, uint8, uint16, uint16, string)
    //      md target start_or_dev, mt_size, mt
    item->md = data[0];
    if (item->md >= kMaxMathMethod) return -1;

    item->target = data[1];
    if (item->target >= kMaxTarget) return -1;

    item->start = *(unsigned short*)(data + 1 + 1);
    if (item->target == kDev && item->is_dev_in > 1) return -1;

    item->size = *(unsigned short*)(data + 1 + 1 + 2);
    if ((1 + 1 + 2 + 2 + item->size) > max_size) return -1;
    if (item->size > 256) return -1;

    memcpy(item->mt, data + 1 + 1 + 2 + 2, item->size);
}

int __add_filter(unsigned char *data, int size) {
    //filter: BBB[item] (uint8 uint8 uint8 [item])
    //      item_count, combine method
    int item_count, i, rem_size;
    unsigned char *cur_item;
    struct filter tmp_filter;

    if (size < MIN_FILTER_ITEM_SIZE) return -1;

    item_count = data[0];
    if (item_count < 1 || item_count > 4 ||
        (2 + MIN_FILTER_ITEM_SIZE * item_count) > size) return -1;

    tmp_filter.combine_md = data[1];
    if (tmp_filter.combine_md >= kMaxCombineMethod) return -1;

    tmp_filter.process_mask = data[2];
    if ((tmp_filter.process_mask & ALL_PROCESS_MASK) == 0) return -1;

    rem_size = size - 3;
    cur_item = data + 3;
    tmp_filter.items = (struct match_item*)kmalloc(
        item_count * sizeof(struct match_item), GFP_KERNEL);
    if (tmp_filter.item == NULL) return -1;
    for (i = 0; i < item_count; ++i) {
        int item_size = __build_match_item(cur_item, max_size, &tmp_filter[i]);
        if (item_size < 0)  {
            kfree(tmp_filter.items);
            return item_size;
        }

        rem_size -= item_size;
        cur_item += item_size;
    }

    tmp_filter.next = NULL;
    filter_tail->next = (struct filter*)kmalloc(
        size(struct filter), GFP_KERNEL);
    if (filter_tail->next == NULL) {
        kfree(tmp_filter.items);
        return -1;
    }
    filter_tail = filter_tail->next;
    memcpy(filter_tail, &tmp_filter, sizeof(struct filter));

    return 0;
}

int __clear_filters() {
    return 0;
}

int __filter_skb(struct sk_buff *skb,
    const struct net_device *in, const struct net_device *out) {
    return 0;
}