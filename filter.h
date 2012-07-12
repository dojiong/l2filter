/*
 * l2filter filter.h
 * author: lo <lodevil@live.cn>
 * 
 */

/*
 * filter syntax
 * 1. value syntax
 *     max_length of value is 256
 *     1.1 hex: '0x1234'
 *     1.2 string: '"hello"'
 *     1.4 hex array: '[12:34:56]' '[12,34,56]'
 *     1.4 hex string: '"\x12\x34\x56"'
 *     1.5 constants: 'eth0' 'ARP' 'PPPOE_SES'
 * 2. mac header filters
 *     2.1 source mac: 'mac.src==[00:11:22:33:44:55]'
 *     2.2 destination mac: 'mac.dst!=[00:11:22:33:44:55]'
 * 3. layer2 filters
 *     3.1 protocol: 'l2.protocol==ARP' 'l2.protocol=0x0806'
 * 4. string match
 *     4.1 char match: 'mac[6]==0x12'
 *     4.2 fixed size match: 'mac[12:14]!=0x0806'
 *     4.3 startswith match: 'l2[13:]^="username"'
 * 5. device match
 *     5.1 in dev: 'in=vnet0'
 *     5.2 out dev: 'out!=eth0'
 * 6. filter combination
 *     max 8
 *     6.1 and: '&& mac[6]=0x12 l2[12:]^="username"'
 *     6.1 or: '|| mac[6]=0x12 l2[12:]^="username"'
 * 7. filter process method
 *     7.1 dump to log: 'mac[6]==0x12 $ [log]'
 *     7.2 broadcast: 'mac[6]==0x12 $ [broadcast]'
 *     7.3 drop: 'mac[6]==0x12 $ [drop]'
 *     7.4 multi methods: 'mac[6]==0x12 $ [log, drop]'
 * 8. filter compile
 *     l2filter only accept compiled filter
 */

#include <linux/netfilter.h>

enum MATCH_METHOD {
    kEqual = 0,
    kNotEqual,
    kMaxMathMethod
};

enum MATCH_TARGET {
    kMAC = 0,
    kL2,
    kDev,
    kMaxTarget
};

enum COMBINE_METHOD {
    kCombineAnd = 0,
    kCombineOr,
    kMaxCombineMethod
};

enum PROCESS_METHOD {
    kProcessDrop = 1,
    kProcessBroadcast = 2,
    kProcessLog = 4
};

#define ALL_PROCESS_MASK (kProcessDrop | kProcessBroadcast | kProcessLog)

struct match_item {
    /*
     * binary format(py struct): BBHHs (uint8, uint8, uint16, uint16, string)
     */
    int md;
    int target;
    union {
        int start;
        int is_dev_in;
    };
    int size;
    unsigned char mt[256];
};

struct filter {
    /*
     * binary format: BBB[match_item] (total_items, combine, mask, [items])
     */
    int total_items;
    int combine_md;
    int process_mask;
    struct match_item *items;
    struct filter *next;
};

extern int filter_size;
void filter_init(void);
int add_filter(unsigned char *data, int size);
void clear_filters(void);
int filter_skb(struct sk_buff *skb,
    const struct net_device *in, const struct net_device *out);