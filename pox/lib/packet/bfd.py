#!/usr/bin/python
#
# Copyright(C) 2015 Waltz Networks Inc.
#
# ===============================================================================
# RFC 5880 bidirectional failure detection (BFD) header
# https://tools.ietf.org/html/rfc5880
#
#                        BFD Packet Format
#
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       My Discriminator                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                      Your Discriminator                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Desired Min TX Interval                    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                   Required Min RX Interval                    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                 Required Min Echo RX Interval                 |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

import struct
from packet_utils import *
from packet_utils import TruncatedException as Trunc

from packet_base import packet_base

from pox.lib.addresses import IPAddr,IPAddr6,EthAddr

class bfd(packet_base):
    """ bfd packet struct """
    BFD_VERSION = 1
    SERVER_PORT = 3785
    MIN_LEN = 24

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)
        self.prev = prev

        self.vers_diag = bfd.BFD_VERSION << 5
        self.flags = 0
        self.mult = 0
        self.length = bfd.MIN_LEN
        self.my_disc = 0
        self.your_disc = 0
        self.min_tx = 0
        self.min_rx = 0
        self.min_rx_echo = 0

        if raw is not None:
            self.parse(raw)

    def __str__(self):
        s = '[BFD %s:%s]' %(self.my_disc, self.your_disc)
        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < bfd.MIN_LEN:
            self.msg('(bfd parse) warning BFD packet data too short to parse, data len' % dlen)
            return
        (self.vers_diag, self.flags, self.mult, self.length, self.my_disc, \
                self.your_disc, self.min_tx, self.min_rx, self.min_rx_echo) \
                = struct.unpack('!BBBBIIIII', raw[:bfd.MIN_LEN])

        self.parsed = True

    def hdr(self, payload):
        buf = struct.pack('!BBBBIIIII', self.vers_diag, self.flags, self.mult, \
                self.length, self.my_disc, self.your_disc, self.min_tx, \
                self.min_rx, self.min_rx_echo)
        return buf


