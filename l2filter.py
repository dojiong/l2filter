#!/usr/bin/python
#-*- coding:utf8 -*-

from socket import *
import struct
import os

NETLINK_L2FILTER = 23


class L2Filter(object):
    def __init__(self):
        self.sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_L2FILTER)
        self.sock.bind((os.getpid(), 1))

    def send(self, data, type=0, flags=0, seq=0):
        hdr = struct.pack('IHHII',
            16 + len(data), type, flags, seq, os.getpid())
        _data = hdr + data
        #print 'to send:', repr(_data)
        return self.sock.send(_data)

    def recv(self):
        data = self.sock.recv(65535)
        if len(data) < 16:
            return None
        size, type, flags, seq, pid = struct.unpack('IHHII', data[:16])
        if len(data) < size:
            return None
        return data[16:size]

if __name__ == '__main__':
    l2f = L2Filter()
    l2f.send('lodevil')
    print l2f.recv()
