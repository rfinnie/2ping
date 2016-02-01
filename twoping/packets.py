#!/usr/bin/env python

# 2ping - A bi-directional ping utility
# Copyright (C) 2015 Ryan Finnie
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

from __future__ import print_function, division
import random
import hmac
import time
from . import crc32
from .utils import twoping_checksum, int_to_bytearray, bytearray_to_int
import hashlib


class Extended():
    id = None

    def __init__(self):
        self.data = bytearray()

    def __repr__(self):
        if self.id is None:
            return '<Extended: %d bytes>' % len(self.data)
        else:
            id_hex = ''.join(['%02x' % x for x in int_to_bytearray(self.id, 2)])
            return '<Extended (0x%s): %d bytes>' % (id_hex, len(self.data))

    def load(self, data):
        self.data = data

    def dump(self):
        return self.data


class ExtendedText(Extended):
    def __init__(self):
        self.text = bytearray()

    def __repr__(self):
        return '<Text (Generic): %s>' % str(self.text)

    def load(self, data):
        self.text = data

    def dump(self, max_length=None):
        if (max_length is not None) and (max_length < len(self.text)):
            return None
        return self.text


class ExtendedVersion(ExtendedText):
    id = 0x3250564e

    def __repr__(self):
        return '<Version: %s>' % str(self.text)


class ExtendedNotice(ExtendedText):
    id = 0xa837b44e

    def __repr__(self):
        return '<Notice: %s>' % str(self.text)


class ExtendedWallClock(Extended):
    id = 0x64f69319

    def __init__(self):
        self.time_us = 0

    def __repr__(self):
        return '<Wall Clock: %s>' % time.strftime('%c', time.gmtime(self.time_us / 1000000.0))

    def load(self, data):
        self.time_us = bytearray_to_int(data[0:8])

    def dump(self, max_length=None):
        if (max_length is not None) and (max_length < 8):
            return None
        return int_to_bytearray(self.time_us, 8)


class ExtendedMonotonicClock(Extended):
    id = 0x771d8dfb

    def __init__(self):
        self.generation = 0
        self.time_us = 0

    def __repr__(self):
        return '<Monotonic Clock: %0.9f, gen %d>' % ((self.time_us / 1000000.0), self.generation)

    def load(self, data):
        self.generation = bytearray_to_int(data[0:2])
        self.time_us = bytearray_to_int(data[2:10])

    def dump(self, max_length=None):
        if (max_length is not None) and (max_length < 10):
            return None
        return int_to_bytearray(self.generation, 2) + int_to_bytearray(self.time_us, 8)


class ExtendedRandom(Extended):
    id = 0x2ff6ad68

    def __init__(self):
        self.is_hwrng = False
        self.is_os = False
        self.random_data = bytearray()

    def __repr__(self):
        return '<Random: %s (%d), HWRNG %s, OS %s>' % (
            repr(self.random_data),
            len(self.random_data),
            repr(self.is_hwrng),
            repr(self.is_os),
        )

    def load(self, data):
        flags = bytearray_to_int(data[0:2])
        self.is_hwrng = bool(flags & 0x0001)
        self.is_os = bool(flags & 0x0002)
        self.random_data = data[2:]

    def dump(self, max_length=None):
        random_data = self.random_data
        if len(random_data) == 0:
            return None
        if max_length is not None:
            if max_length < 3:
                return None
            if max_length < (len(random_data) - 2):
                random_data = random_data[0:max_length-2]
        flags = 0
        if self.is_hwrng:
            flags = flags | 0x0001
        if self.is_os:
            flags = flags | 0x0002
        return int_to_bytearray(flags, 2) + random_data


class Opcode():
    id = None

    def __init__(self):
        self.data = bytearray()

    def __repr__(self):
        if self.id is None:
            return '<Opcode: %d bytes>' % len(self.data)
        else:
            id_hex = ''.join(['%02x' % x for x in int_to_bytearray(self.id, 2)])
            return '<Opcode (0x%s): %d bytes>' % (id_hex, len(self.data))

    def load(self, data):
        self.data = data

    def dump(self):
        return self.data


class OpcodeReplyRequested(Opcode):
    id = 0x0001

    def __init__(self):
        pass

    def __repr__(self):
        return '<Reply Requested>'

    def load(self, data):
        pass

    def dump(self, max_length=None):
        return bytearray()


class OpcodeInReplyTo(Opcode):
    id = 0x0002

    def __init__(self):
        self.message_id = bytearray()

    def __repr__(self):
        message_id_hex = ''.join(['%02x' % x for x in self.message_id])
        return '<In Reply To: 0x%s>' % message_id_hex

    def load(self, data):
        self.message_id = data[0:6]

    def dump(self, max_length=None):
        if (max_length is not None) and (max_length < 6):
            return None
        return self.message_id


class OpcodeRTTEnclosed(Opcode):
    id = 0x0004

    def __init__(self):
        self.rtt_us = 0

    def __repr__(self):
        return '<RTT Enclosed: %d us>' % self.rtt_us

    def load(self, data):
        self.rtt_us = bytearray_to_int(data[0:4])

    def dump(self, max_length=None):
        if (max_length is not None) and (max_length < 4):
            return None
        return int_to_bytearray(self.rtt_us, 4)


class OpcodeMessageIDList(Opcode):
    def __init__(self):
        self.message_ids = []

    def __repr__(self):
        ids = ['0x%s' % ''.join(['%02x' % x for x in y]) for y in self.message_ids]
        return '<ID List (Generic): [%s] (%d)>' % (', '.join(ids), len(self.message_ids))

    def load(self, data):
        self.message_ids = []
        pos = 2
        for i in xrange(bytearray_to_int(data[0:2])):
            self.message_ids.append(data[pos:pos+6])
            pos += 6

    def dump(self, max_length=None):
        if (max_length is not None):
            if (max_length < 8):
                return None
            output_ids = self.message_ids[0:int((max_length - 2) / 6)]
        else:
            output_ids = self.message_ids

        out = int_to_bytearray(len(output_ids), 2)
        for i in output_ids:
            out += i
        return out


class OpcodeInvestigationSeen(OpcodeMessageIDList):
    id = 0x0008

    def __repr__(self):
        ids = ['0x%s' % ''.join(['%02x' % x for x in y]) for y in self.message_ids]
        return '<Investigation Seen: [%s] (%d)>' % (', '.join(ids), len(self.message_ids))


class OpcodeInvestigationUnseen(OpcodeMessageIDList):
    id = 0x0010

    def __repr__(self):
        ids = ['0x%s' % ''.join(['%02x' % x for x in y]) for y in self.message_ids]
        return '<Investigation Unseen: [%s] (%d)>' % (', '.join(ids), len(self.message_ids))


class OpcodeInvestigate(OpcodeMessageIDList):
    id = 0x0020

    def __repr__(self):
        ids = ['0x%s' % ''.join(['%02x' % x for x in y]) for y in self.message_ids]
        return '<Investigate: [%s] (%d)>' % (', '.join(ids), len(self.message_ids))


class OpcodeCourtesyExpiration(OpcodeMessageIDList):
    id = 0x0040

    def __repr__(self):
        ids = ['0x%s' % ''.join(['%02x' % x for x in y]) for y in self.message_ids]
        return '<Courtesy Expiration: [%s] (%d)>' % (', '.join(ids), len(self.message_ids))


class OpcodeHMAC(Opcode):
    id = 0x0080

    def __init__(self):
        self.key = bytearray()
        self.digest_index = None
        self.hash = bytearray()

        self.digest_map = {
            1: (hashlib.md5, 16),
            2: (hashlib.sha1, 20),
            3: (hashlib.sha1, 30),
            4: (crc32, 4),
        }

    def __repr__(self):
        return '<HMAC>'

    def load(self, data):
        self.digest_index = bytearray_to_int(data[0:2])
        self.hash = data[2:]

    def dump(self, max_length=None):
        if self.digest_index is not None:
            (hasher, size) = self.digest_map[self.digest_index]
            return int_to_bytearray(self.digest_index, 2) + bytearray(size)
        return None


class OpcodeHostLatency(Opcode):
    id = 0x0100

    def __init__(self):
        self.delay_us = 0

    def __repr__(self):
        return '<Host Latency: %d us>' % self.delay_us

    def load(self, data):
        self.delay_us = bytearray_to_int(data[0:4])

    def dump(self, max_length=None):
        if (max_length is not None) and (max_length < 4):
            return None
        return int_to_bytearray(self.delay_us, 4)


class OpcodeExtended(Opcode):
    id = 0x8000

    def __init__(self):
        self.segments = {}
        self.segment_data_positions = {}

    def __repr__(self):
        return '<Extended: %s>' % repr(sorted(self.segments.values(), key=lambda x: x.id))

    def load(self, data):
        self.segments = {}
        self.segment_data_positions = {}

        pos = 0
        known_segments = (
            ExtendedVersion,
            ExtendedNotice,
            ExtendedMonotonicClock,
            ExtendedWallClock,
            ExtendedRandom,
        )

        while pos < len(data):
            flag = bytearray_to_int(data[pos:pos+4])
            pos += 4
            segment_data_length = bytearray_to_int(data[pos:pos+2])
            pos += 2
            self.segment_data_positions[flag] = (pos, segment_data_length)
            segment_handler = None
            for seg in known_segments:
                if flag == seg.id:
                    segment_handler = seg
                    break
            if segment_handler is None:
                segment_handler = Extended
                segment_handler.id = flag
            self.segments[flag] = segment_handler()
            self.segments[flag].load(data[pos:(pos+segment_data_length)])
            pos += segment_data_length

    def dump(self, max_length=None):
        if (max_length is not None) and (max_length < 6):
            return None
        out = bytearray()
        pos = 0
        for segment in self.segments.values():
            if max_length is None:
                segment_max_length = None
            else:
                segment_max_length = max_length - pos - 6
            segment_data = segment.dump(max_length=segment_max_length)
            if segment_data is None:
                continue
            out += int_to_bytearray(segment.id, 4)
            pos += 4
            out += int_to_bytearray(len(segment_data), 2)
            pos += 2
            out += segment_data
            pos += len(segment_data)
        if len(out) == 0:
            return None
        return out


class Packet():
    def __repr__(self):
        return '<Packet (0x%s): %s>' % (
            ''.join(['%02x' % x for x in self.message_id]),
            repr(sorted(self.opcodes.values(), key=lambda x: x.id))
        )

    def __init__(self):
        self.message_id = bytearray()
        self.opcodes = {}
        self.min_length = 0
        self.max_length = 1024
        self.padding_pattern = bytearray(1)
        self.opcode_data_positions = {}

    def load(self, data):
        magic_number = data[0:2]
        if magic_number != bytearray((0x32, 0x50)):
            raise Exception('Invalid magic number')
        checksum = bytearray_to_int(data[2:4])
        if checksum:
            if twoping_checksum(data[0:2] + bytearray(2) + data[4:]) != checksum:
                raise Exception('Invalid checksum')
        self.message_id = data[4:10]
        opcode_flags = bytearray_to_int(data[10:12])
        self.opcodes = {}

        pos = 12
        known_opcodes = (
            OpcodeReplyRequested,
            OpcodeInReplyTo,
            OpcodeRTTEnclosed,
            OpcodeInvestigationSeen,
            OpcodeInvestigationUnseen,
            OpcodeInvestigate,
            OpcodeCourtesyExpiration,
            OpcodeHMAC,
            OpcodeHostLatency,
            OpcodeExtended,
        )
        for flag in (2 ** x for x in xrange(16)):
            if not opcode_flags & flag:
                continue
            opcode_data_length = bytearray_to_int(data[pos:pos+2])
            pos += 2
            self.opcode_data_positions[flag] = (pos, opcode_data_length)
            opcode_handler = None
            for oc in known_opcodes:
                if flag == oc.id:
                    opcode_handler = oc
                    break
            if opcode_handler is None:
                opcode_handler = Opcode
                opcode_handler.id = flag
            self.opcodes[flag] = opcode_handler()
            self.opcodes[flag].load(data[pos:(pos+opcode_data_length)])
            pos += opcode_data_length

    def dump(self):
        auth_pos_begin = 0
        auth_pos_end = 0
        if not self.message_id:
            self.message_id = bytearray([random.randint(0, 255) for x in xrange(6)])
        opcode_datas = {}
        packet_length = 12
        for flag in (
            OpcodeHMAC.id,
            OpcodeReplyRequested.id,
            OpcodeInReplyTo.id,
            OpcodeRTTEnclosed.id,
            OpcodeInvestigationSeen.id,
            OpcodeInvestigationUnseen.id,
            OpcodeInvestigate.id,
            OpcodeHostLatency.id,
            OpcodeCourtesyExpiration.id,
            OpcodeExtended.id,
        ):
            if flag not in self.opcodes:
                continue
            if (packet_length + 2) > self.max_length:
                break
            res = self.opcodes[flag].dump(max_length=(self.max_length - packet_length - 2))
            if res is None:
                continue
            opcode_datas[flag] = res
            res_len = len(res)
            packet_length += res_len + 2
        opcode_flags = 0
        opcode_data = bytearray()
        packet_length = 12
        for flag in sorted(opcode_datas.keys()):
            res = opcode_datas[flag]
            res_len = len(res)
            if flag == OpcodeHMAC.id:
                auth_pos_begin = packet_length + 4
                auth_pos_end = auth_pos_begin + (res_len - 2)
            opcode_flags = opcode_flags | flag
            opcode_data += int_to_bytearray(res_len, 2)
            opcode_data += res
            packet_length += res_len + 2
        out = bytearray((0x32, 0x50)) + bytearray(2) + self.message_id + int_to_bytearray(opcode_flags, 2) + opcode_data
        if len(out) < self.min_length:
            target_padding = self.min_length - len(out)
            padding = (self.padding_pattern * int(target_padding / len(self.padding_pattern) + 1))[0:target_padding]
            out += padding
        if (OpcodeHMAC.id in self.opcodes) and auth_pos_begin:
            out[auth_pos_begin:auth_pos_end] = self.calculate_hash(self.opcodes[OpcodeHMAC.id], out)
        out[2:4] = int_to_bytearray(twoping_checksum(out), 2)
        return out

    def calculate_hash(self, opcode, payload):
        (hasher, size) = opcode.digest_map[opcode.digest_index]
        return bytearray(hmac.new(opcode.key, payload, hasher).digest())
