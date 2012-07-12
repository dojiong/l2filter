/*
 * l2filter user_comm.h
 * author: lo <lodevil@live.cn>
 * 
 */

#ifndef __LO_L2FILTER_USER_COMM_H
#define __LO_L2FILTER_USER_COMM_H

#include <linux/netlink.h>

#define NETLINK_L2FILTER 23

typedef void (*msg_input_func)(int pid, unsigned char *data, int size);

int user_comm_init(msg_input_func input_func);
void user_comm_exit(void);
int user_comm_unicast(int pid, void *data, int size);
int user_comm_broadcast(void *data, int size);

#endif
