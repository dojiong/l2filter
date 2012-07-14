#!/usr/bin/python
#-*- coding:utf8 -*-

from socket import *
import struct
import os
import copy

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


class Match(object):
    def __init__(self, item, start=0, end=None, val=None):
        self.item = item
        self.start = start
        self.end = end
        self.md = kEqual
        if val is not None:
            self._set_val(val)
        else:
            self.size = 1

    def _set_val(self, val):
        if isinstance(val, unicode):
            val = val.encode('utf8')
        elif isinstance(val, (int, long)):
            val = self._num2str(val)
        elif not isinstance(val, str):
            val = str(val)
        if self.end and self.end - self.start != len(val):
            raise ValueError('size not match')
        self.val = val
        self.size = len(val)

    def equal(self, val):
        self.md = kEqual
        self._set_val(val)
        return self.item

    def not_equal(self, val):
        self.md = kNotEqual
        self._set_val(val)
        return self.item

    @staticmethod
    def _num2str(num):
        bytes = []
        while num:
            bytes.append(num & 0xFF)
            num >>= 8
        bytes.reverse()
        return ''.join(map(chr, bytes))


class FilterItem(object):
    def __init__(self, val=None, target=kTargetL2):
        self._match = Match(self, val=val)
        self._target = target

    def __invert__(self):
        new_item = copy.deepcopy(self)
        if self._match.md == kEqual:
            new_item._match.md = kNotEqual
        else:
            new_item._match.md = kEqual
        return new_item

    def __setitem__(self, k, v):
        m = self[k]
        m.equal(v)

    def __getitem__(self, k):
        if isinstance(k, int):
            if k > 256:
                raise ValueError('index too large')
            self._match.start = k
            self._match.end = k + 1
        elif isinstance(k, slice):
            if k.start >= k.stop or k.stop - k.start > 256 or k.step != None:
                raise ValueError('invalid slice')
            self._match.start = k.start
            self._match.end = k.stop
        else:
            raise ValueError('invalid key')
        return self._match

    def compile(self):
        return struct.pack('BBHH',
            self._match.md, self._target,
            self._match.start, self._match.size) + self._match.val


class MAC(FilterItem):
    def __init__(self):
        super(MAC, self).__init__(target=kTargetMAC)


class L2(FilterItem):
    def __init__(self):
        super(L2, self).__init__(target=kTargetL2)


class L2Protocol(FilterItem):
    def __init__(self, protocol):
        super(L2Protocol, self).__init__(
            protocol, target=kTargetL2Protocol)


class Dev(FilterItem):
    def __init__(self, name):
        super(Dev, self).__init__(name, target=kTargetDev)


class Filter(object):
    def __init__(self, combine=kCombineAnd):
        self._items = []
        self._combine = kCombineAnd
        self._items = []
        self._process = kProcessLog

    def set_process(self, mask):
        self._process = mask

    def add_process(self, process):
        self._process |= process

    def add_item(self, *args):
        cls = (MAC, L2, L2Protocol, Dev)
        if any([not isinstance(item, cls) for item in args]):
            raise ValueError('invalud filter item')
        self._items.extend(args)

    def compile(self, combine=None):
        if combine is None:
            combine = self._combine
        bins = ''.join([item.compile() for item in self._items])
        return struct.pack('BBB',
            len(self._items), combine, self._process) + bins


class L2Filter(object):
    def __init__(self):
        self.sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_L2FILTER)
        self.sock.bind((os.getpid(), 1))

    def _send(self, data, type=0, flags=0, seq=0):
        hdr = struct.pack('IHHII',
            16 + len(data), type, flags, seq, os.getpid())
        _data = hdr + data
        return self.sock.send(_data)

    def _recv(self):
        data = self.sock.recv(65535)
        if len(data) < 16:
            return None
        size, type, flags, seq, pid = struct.unpack('IHHII', data[:16])
        if len(data) < size:
            return None
        return data[16:size]

    def add_filter(self, f):
        if not isinstance(f, Filter):
            raise ValueError('invalid filter')
        self._send('A' + f.compile())
        return self._recv() == 'ok'

    def clear_filters(self):
        self._send('C')
        return self._recv() == 'ok'


def mkItem(md, target, start_or_dev, size, mt):
    return struct.pack('BBHH', md, target, start_or_dev, size) + mt


def mkFilter(combine, mask, items):
    if isinstance(items, basestring):
        items = [items]
    count = len(items)
    return struct.pack('BBB', count, combine, mask) + ''.join(items)

if __name__ == '__main__':
    #l2f = L2Filter()
    lfilter = Filter()
    lfilter.add_item(L2Protocol(0x8864),
        L2()[6:8].equal(0xC023),
        L2()[13].equal('~'))
    lfilter.set_process(kProcessLog | kProcessDrop)
    s = mkFilter(kCombineAnd, kProcessLog | kProcessDrop,
        [mkItem(kEqual, kTargetL2Protocol, 0, 2, '\x88\x64'),
            mkItem(kEqual, kTargetL2, 6, 2, '\xC0\x23'),
            mkItem(kEqual, kTargetL2, 13, 1, '~')])
    print lfilter.compile() == s
    print repr(lfilter.compile())
    print repr(lfilter.compile(kCombineOr))
#BBB[BBHHs]
