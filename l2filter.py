#!/usr/bin/python
#-*- coding:utf8 -*-

from socket import *
import struct
import os

NETLINK_L2FILTER = 23

kEqual = 0
kNotEqual = 1
kMaxMathMethod = 2

kTargetL2Protocol = 0
kTargetMAC = 1
kTargetL2 = 2
kTargetDev = 3
kMaxTarget = 4

kCombineAnd = 0
kCombineOr = 1
kMaxCombineMethod = 2

kProcessDrop = 1
kProcessBroadcast = 2
kProcessLog = 4


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


def mkItem(md, target, start_or_dev, size, mt):
    return struct.pack('BBHH', md, target, start_or_dev, size) + mt


def mkFilter(combine, mask, items):
    if isinstance(items, basestring):
        items = [items]
    count = len(items)
    return struct.pack('BBB', count, combine, mask) + ''.join(items)

if __name__ == '__main__':
    l2f = L2Filter()
    s = mkFilter(kCombineAnd, kProcessLog | kProcessDrop,
        [mkItem(kEqual, kTargetL2Protocol, 0, 2, '\x88\x64'),
            mkItem(kEqual, kTargetL2, 6, 2, '\xC0\x23'),
            mkItem(kEqual, kTargetL2, 13, 1, '~')])
    print repr(s)
    l2f.send(s)
    print l2f.recv()
#BBB[BBHHs]
