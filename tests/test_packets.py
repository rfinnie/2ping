#!/usr/bin/env python

import unittest
from twoping import packets


class TestPacketsOpcodes(unittest.TestCase):
    def test_opcode_unknown(self):
        data = bytearray('Unknown data')
        opcode = packets.Opcode()
        opcode.load(data)
        self.assertEqual(opcode.id, None)
        self.assertEqual(opcode.dump(), data)

    def test_opcode_reply_requested(self):
        data = bytearray()
        opcode = packets.OpcodeReplyRequested()
        opcode.load(data)
        self.assertEqual(opcode.id, 0x0001)
        self.assertEqual(opcode.dump(), data)

    def test_opcode_in_reply_to(self):
        data = bytearray(b'\x01\x02\x03\x04\x05\x06')
        opcode = packets.OpcodeInReplyTo()
        opcode.load(data)
        self.assertEqual(opcode.id, 0x0002)
        self.assertEqual(opcode.dump(), data)

    def test_opcode_rtt_enclosed(self):
        data = bytearray(b'\x12\x34\x56\x78')
        opcode = packets.OpcodeRTTEnclosed()
        opcode.load(data)
        self.assertEqual(opcode.id, 0x0004)
        self.assertEqual(opcode.dump(), data)

    def test_opcode_investigation_seen(self):
        data = bytearray(b'\x01\x02\x03\x04\x05\x06\x11\x12\x13\x14\x15\x16')
        opcode = packets.OpcodeInvestigationSeen()
        opcode.load(data)
        self.assertEqual(opcode.id, 0x0008)
        self.assertEqual(opcode.dump(), data)

    def test_opcode_investigation_unseen(self):
        data = bytearray(b'\x01\x02\x03\x04\x05\x06\x11\x12\x13\x14\x15\x16')
        opcode = packets.OpcodeInvestigationUnseen()
        opcode.load(data)
        self.assertEqual(opcode.id, 0x0010)
        self.assertEqual(opcode.dump(), data)

    def test_opcode_investigate(self):
        data = bytearray(b'\x01\x02\x03\x04\x05\x06\x11\x12\x13\x14\x15\x16')
        opcode = packets.OpcodeInvestigate()
        opcode.load(data)
        self.assertEqual(opcode.id, 0x0020)
        self.assertEqual(opcode.dump(), data)

    def test_opcode_courtesy_expiration(self):
        data = bytearray(b'\x01\x02\x03\x04\x05\x06\x11\x12\x13\x14\x15\x16')
        opcode = packets.OpcodeCourtesyExpiration()
        opcode.load(data)
        self.assertEqual(opcode.id, 0x0040)
        self.assertEqual(opcode.dump(), data)

    def test_opcode_hmac(self):
        data = bytearray(b'\x00\x04\x01\x02\x03\x04')
        # The dump always includes a zeroed hash area
        data_out = bytearray(b'\x00\x04\x00\x00\x00\x00')
        opcode = packets.OpcodeHMAC()
        opcode.load(data)
        self.assertEqual(opcode.id, 0x0080)
        self.assertEqual(opcode.dump(), data_out)

    def test_opcode_host_latency(self):
        data = bytearray(b'\x12\x34\x56\x78')
        opcode = packets.OpcodeHostLatency()
        opcode.load(data)
        self.assertEqual(opcode.id, 0x0100)
        self.assertEqual(opcode.dump(), data)

    def test_opcode_extended(self):
        data = bytearray(b'\x32\x50\x56\x4e\x00\x12Test 2ping version')
        opcode = packets.OpcodeExtended()
        opcode.load(data)
        self.assertEqual(opcode.id, 0x8000)
        self.assertEqual(opcode.dump(), data)

    def test_extended_unknown(self):
        data = bytearray('Unknown extended data')
        opcode = packets.Extended()
        opcode.load(data)
        self.assertEqual(opcode.id, None)
        self.assertEqual(opcode.dump(), data)

    def test_extended_version(self):
        data = bytearray('Test 2ping version')
        opcode = packets.ExtendedVersion()
        opcode.load(data)
        self.assertEqual(opcode.id, 0x3250564e)
        self.assertEqual(opcode.dump(), data)

    def test_extended_notice(self):
        data = bytearray('Notice announcement')
        opcode = packets.ExtendedNotice()
        opcode.load(data)
        self.assertEqual(opcode.id, 0xa837b44e)
        self.assertEqual(opcode.dump(), data)

    def test_extended_wallclock_load(self):
        opcode = packets.ExtendedWallClock()
        opcode.load(bytearray(b'\x00\x03\x63\x73\xe7\x7a\xc2\x20'))
        self.assertEqual(opcode.id, 0x64f69319)
        self.assertEqual(opcode.time_us, int(953774386.102816 * 1000000))

    def test_extended_wallclock_dump(self):
        opcode = packets.ExtendedWallClock()
        opcode.time_us = int(1454187789.993266 * 1000000)
        self.assertEqual(opcode.id, 0x64f69319)
        self.assertEqual(opcode.dump(), bytearray(b'\x00\x05\x2a\x93\x7a\xa8\xc5\x32'))

    def test_extended_monotonicclock_load(self):
        opcode = packets.ExtendedMonotonicClock()
        opcode.load(bytearray(b'\x7d\x67\x00\x03\x63\x73\xe7\x7a\xc2\x20'))
        self.assertEqual(opcode.id, 0x771d8dfb)
        self.assertEqual(opcode.generation, 32103)
        self.assertEqual(opcode.time_us, int(953774386.102816 * 1000000))

    def test_extended_monotonicclock_dump(self):
        opcode = packets.ExtendedMonotonicClock()
        opcode.generation = 9311
        opcode.time_us = int(1454187789.993266 * 1000000)
        self.assertEqual(opcode.id, 0x771d8dfb)
        self.assertEqual(opcode.dump(), bytearray(b'\x24\x5f\x00\x05\x2a\x93\x7a\xa8\xc5\x32'))

    def test_extended_random_load(self):
        random_data = bytearray(b'\xf1\xfd\xf8\x9c\xe3\x9a\x87\x14')
        opcode = packets.ExtendedRandom()
        opcode.load(bytearray(bytearray(b'\x00\x03') + random_data))
        self.assertEqual(opcode.id, 0x2ff6ad68)
        self.assertEqual(opcode.is_hwrng, True)
        self.assertEqual(opcode.is_os, True)
        self.assertEqual(opcode.random_data, random_data)

    def test_extended_random_dump(self):
        random_data = bytearray(b'\xbc\xde\xdc\xe5\xa8\x9a\xbd\x14')
        opcode = packets.ExtendedRandom()
        opcode.is_hwrng = True
        opcode.random_data = random_data
        self.assertEqual(opcode.id, 0x2ff6ad68)
        self.assertEqual(opcode.dump(), bytearray(b'\x00\x01') + random_data)

    def test_extended_battery_load(self):
        opcode = packets.ExtendedBattery()
        opcode.load(bytearray(b'\x00\x7b\xcc\xcc'))
        self.assertEqual(opcode.id, 0x88a1f7c7)
        self.assertEqual(opcode.battery_id, 123)
        self.assertEqual(opcode.battery_percent, 80.0)

    def test_extended_battery_dump(self):
        opcode = packets.ExtendedBattery()
        opcode.battery_id = 123
        opcode.battery_percent = 80.0
        self.assertEqual(opcode.id, 0x88a1f7c7)
        self.assertEqual(opcode.dump(), bytearray(b'\x00\x7b\xcc\xcc'))


class TestPacketsReference(unittest.TestCase):
    ''' Test protocol reference packets

    These tests replicate the reference packets included as examples in
    the 2ping protocol specification.
    '''
    def test_reference_1a(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xa0\x01')
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x2d\xae\x00\x00\x00\x00\xa0\x01\x00\x00'))

    def test_reference_2a(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xa0\x01')
        packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x2d\xad\x00\x00\x00\x00\xa0\x01\x00\x01\x00\x00'))

    def test_reference_2b(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xb0\x01')
        packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
        packet.opcodes[packets.OpcodeInReplyTo.id].message_id = bytearray('\x00\x00\x00\x00\xa0\x01')
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x7d\xa4\x00\x00\x00\x00\xb0\x01\x00\x02\x00\x06\x00\x00\x00\x00\xa0\x01'))

    def test_reference_3a(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xa0\x01')
        packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x2d\xad\x00\x00\x00\x00\xa0\x01\x00\x01\x00\x00'))

    def test_reference_3b(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xb0\x01')
        packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
        packet.opcodes[packets.OpcodeInReplyTo.id].message_id = bytearray('\x00\x00\x00\x00\xa0\x01')
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x7d\xa3\x00\x00\x00\x00\xb0\x01\x00\x03\x00\x00\x00\x06\x00\x00\x00\x00\xa0\x01'))

    def test_reference_3c(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xa0\x02')
        packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
        packet.opcodes[packets.OpcodeInReplyTo.id].message_id = bytearray('\x00\x00\x00\x00\xb0\x01')
        packet.opcodes[packets.OpcodeRTTEnclosed.id] = packets.OpcodeRTTEnclosed()
        packet.opcodes[packets.OpcodeRTTEnclosed.id].rtt_us = 12345
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x4d\x62\x00\x00\x00\x00\xa0\x02\x00\x06\x00\x06\x00\x00\x00\x00\xb0\x01\x00\x04\x00\x00\x30\x39'))

    def test_reference_4a(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xa0\x01')
        packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x2d\xad\x00\x00\x00\x00\xa0\x01\x00\x01\x00\x00'))

    def test_reference_4b(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xa0\x02')
        packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        packet.opcodes[packets.OpcodeInvestigate.id] = packets.OpcodeInvestigate()
        packet.opcodes[packets.OpcodeInvestigate.id].message_ids.append(bytearray('\x00\x00\x00\x00\xa0\x01'))
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x8d\x81\x00\x00\x00\x00\xa0\x02\x00\x21\x00\x00\x00\x08\x00\x01\x00\x00\x00\x00\xa0\x01'))

    def test_reference_4c(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xb0\x02')
        packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
        packet.opcodes[packets.OpcodeInReplyTo.id].message_id = bytearray('\x00\x00\x00\x00\xa0\x02')
        packet.opcodes[packets.OpcodeInvestigationSeen.id] = packets.OpcodeInvestigationSeen()
        packet.opcodes[packets.OpcodeInvestigationSeen.id].message_ids.append(bytearray('\x00\x00\x00\x00\xa0\x01'))
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\xdd\x8e\x00\x00\x00\x00\xb0\x02\x00\x0b\x00\x00\x00\x06\x00\x00\x00\x00\xa0\x02\x00\x08\x00\x01\x00\x00\x00\x00\xa0\x01'))

    def test_reference_4d(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xa0\x03')
        packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
        packet.opcodes[packets.OpcodeInReplyTo.id].message_id = bytearray('\x00\x00\x00\x00\xb0\x02')
        packet.opcodes[packets.OpcodeRTTEnclosed.id] = packets.OpcodeRTTEnclosed()
        packet.opcodes[packets.OpcodeRTTEnclosed.id].rtt_us = 12345
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x4d\x60\x00\x00\x00\x00\xa0\x03\x00\x06\x00\x06\x00\x00\x00\x00\xb0\x02\x00\x04\x00\x00\x30\x39'))

    def test_reference_5a(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xa0\x01')
        packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x2d\xad\x00\x00\x00\x00\xa0\x01\x00\x01\x00\x00'))

    def test_reference_5b(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xa0\x02')
        packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        packet.opcodes[packets.OpcodeInvestigate.id] = packets.OpcodeInvestigate()
        packet.opcodes[packets.OpcodeInvestigate.id].message_ids.append(bytearray('\x00\x00\x00\x00\xa0\x01'))
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x8d\x81\x00\x00\x00\x00\xa0\x02\x00\x21\x00\x00\x00\x08\x00\x01\x00\x00\x00\x00\xa0\x01'))

    def test_reference_5c(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xb0\x01')
        packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
        packet.opcodes[packets.OpcodeInReplyTo.id].message_id = bytearray('\x00\x00\x00\x00\xa0\x02')
        packet.opcodes[packets.OpcodeInvestigationUnseen.id] = packets.OpcodeInvestigationUnseen()
        packet.opcodes[packets.OpcodeInvestigationUnseen.id].message_ids.append(bytearray('\x00\x00\x00\x00\xa0\x01'))
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\xdd\x87\x00\x00\x00\x00\xb0\x01\x00\x13\x00\x00\x00\x06\x00\x00\x00\x00\xa0\x02\x00\x08\x00\x01\x00\x00\x00\x00\xa0\x01'))

    def test_reference_5d(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xa0\x03')
        packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
        packet.opcodes[packets.OpcodeInReplyTo.id].message_id = bytearray('\x00\x00\x00\x00\xb0\x01')
        packet.opcodes[packets.OpcodeRTTEnclosed.id] = packets.OpcodeRTTEnclosed()
        packet.opcodes[packets.OpcodeRTTEnclosed.id].rtt_us = 12345
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x4d\x61\x00\x00\x00\x00\xa0\x03\x00\x06\x00\x06\x00\x00\x00\x00\xb0\x01\x00\x04\x00\x00\x30\x39'))

    def test_reference_6a(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xa0\x01')
        packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x2d\xad\x00\x00\x00\x00\xa0\x01\x00\x01\x00\x00'))

    def test_reference_6b(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xa0\x02')
        packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x2d\xac\x00\x00\x00\x00\xa0\x02\x00\x01\x00\x00'))

    def test_reference_6c(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xa0\x03')
        packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x2d\xab\x00\x00\x00\x00\xa0\x03\x00\x01\x00\x00'))

    def test_reference_6d(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xb0\x02')
        packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
        packet.opcodes[packets.OpcodeInReplyTo.id].message_id = bytearray('\x00\x00\x00\x00\xa0\x03')
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x7d\xa0\x00\x00\x00\x00\xb0\x02\x00\x03\x00\x00\x00\x06\x00\x00\x00\x00\xa0\x03'))

    def test_reference_6e(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xa0\x04')
        packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
        packet.opcodes[packets.OpcodeInReplyTo.id].message_id = bytearray('\x00\x00\x00\x00\xb0\x02')
        packet.opcodes[packets.OpcodeRTTEnclosed.id] = packets.OpcodeRTTEnclosed()
        packet.opcodes[packets.OpcodeRTTEnclosed.id].rtt_us = 12823
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x4b\x81\x00\x00\x00\x00\xa0\x04\x00\x06\x00\x06\x00\x00\x00\x00\xb0\x02\x00\x04\x00\x00\x32\x17'))

    def test_reference_6f(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xa0\x0a')
        packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        packet.opcodes[packets.OpcodeInvestigate.id] = packets.OpcodeInvestigate()
        packet.opcodes[packets.OpcodeInvestigate.id].message_ids.append(bytearray('\x00\x00\x00\x00\xa0\x01'))
        packet.opcodes[packets.OpcodeInvestigate.id].message_ids.append(bytearray('\x00\x00\x00\x00\xa0\x02'))
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\xed\x6f\x00\x00\x00\x00\xa0\x0a\x00\x21\x00\x00\x00\x0e\x00\x02\x00\x00\x00\x00\xa0\x01\x00\x00\x00\x00\xa0\x02'))

    def test_reference_6g(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xb0\x06')
        packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
        packet.opcodes[packets.OpcodeInReplyTo.id].message_id = bytearray('\x00\x00\x00\x00\xa0\x0a')
        packet.opcodes[packets.OpcodeInvestigationSeen.id] = packets.OpcodeInvestigationSeen()
        packet.opcodes[packets.OpcodeInvestigationSeen.id].message_ids.append(bytearray('\x00\x00\x00\x00\xa0\x01'))
        packet.opcodes[packets.OpcodeInvestigationUnseen.id] = packets.OpcodeInvestigationUnseen()
        packet.opcodes[packets.OpcodeInvestigationUnseen.id].message_ids.append(bytearray('\x00\x00\x00\x00\xa0\x02'))
        packet.opcodes[packets.OpcodeInvestigate.id] = packets.OpcodeInvestigate()
        packet.opcodes[packets.OpcodeInvestigate.id].message_ids.append(bytearray('\x00\x00\x00\x00\xb0\x02'))
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x8d\x3b\x00\x00\x00\x00\xb0\x06\x00\x3b\x00\x00\x00\x06\x00\x00\x00\x00\xa0\x0a\x00\x08\x00\x01\x00\x00\x00\x00\xa0\x01\x00\x08\x00\x01\x00\x00\x00\x00\xa0\x02\x00\x08\x00\x01\x00\x00\x00\x00\xb0\x02'))

    def test_reference_6h(self):
        packet = packets.Packet()
        packet.message_id = bytearray('\x00\x00\x00\x00\xa0\x0b')
        packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
        packet.opcodes[packets.OpcodeInReplyTo.id].message_id = bytearray('\x00\x00\x00\x00\xb0\x06')
        packet.opcodes[packets.OpcodeRTTEnclosed.id] = packets.OpcodeRTTEnclosed()
        packet.opcodes[packets.OpcodeRTTEnclosed.id].rtt_us = 13112
        packet.opcodes[packets.OpcodeInvestigationSeen.id] = packets.OpcodeInvestigationSeen()
        packet.opcodes[packets.OpcodeInvestigationSeen.id].message_ids.append(bytearray('\x00\x00\x00\x00\xb0\x02'))
        self.assertEqual(packet.dump(), bytearray(b'\x32\x50\x9a\x41\x00\x00\x00\x00\xa0\x0b\x00\x0e\x00\x06\x00\x00\x00\x00\xb0\x06\x00\x04\x00\x00\x33\x38\x00\x08\x00\x01\x00\x00\x00\x00\xb0\x02'))


if __name__ == '__main__':
    unittest.main()
