#!/usr/bin/env python3

# 2ping - A bi-directional ping utility
# Copyright (C) 2010-2021 Ryan Finnie
# SPDX-License-Identifier: GPL-2.0+

from twoping import packets


def h(input):
    return " ".join("{:02x}".format(x) for x in input)


print("### Example 1")
print()
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xa0\x01"
print("    CLIENT: {}".format(h(packet.dump())))
print()

print("### Example 2")
print()
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xa0\x01"
packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
print("    CLIENT: {}".format(h(packet.dump())))
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xb0\x01"
packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
packet.opcodes[packets.OpcodeInReplyTo.id].message_id = b"\x00\x00\x00\x00\xa0\x01"
print("    SERVER: {}".format(h(packet.dump())))
print()

print("### Example 3")
print()
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xa0\x01"
packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
print("    CLIENT: {}".format(h(packet.dump())))
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xb0\x01"
packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
packet.opcodes[packets.OpcodeInReplyTo.id].message_id = b"\x00\x00\x00\x00\xa0\x01"
print("    SERVER: {}".format(h(packet.dump())))
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xa0\x02"
packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
packet.opcodes[packets.OpcodeInReplyTo.id].message_id = b"\x00\x00\x00\x00\xb0\x01"
packet.opcodes[packets.OpcodeRTTEnclosed.id] = packets.OpcodeRTTEnclosed()
packet.opcodes[packets.OpcodeRTTEnclosed.id].rtt_us = 12345
print("    CLIENT: {}".format(h(packet.dump())))
print()

print("### Example 4")
print()
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xa0\x01"
packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
print("    CLIENT: {}".format(h(packet.dump())))
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xa0\x02"
packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
packet.opcodes[packets.OpcodeInvestigate.id] = packets.OpcodeInvestigate()
packet.opcodes[packets.OpcodeInvestigate.id].message_ids.append(
    b"\x00\x00\x00\x00\xa0\x01"
)
print("    CLIENT: {}".format(h(packet.dump())))
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xb0\x02"
packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
packet.opcodes[packets.OpcodeInReplyTo.id].message_id = b"\x00\x00\x00\x00\xa0\x02"
packet.opcodes[packets.OpcodeInvestigationSeen.id] = packets.OpcodeInvestigationSeen()
packet.opcodes[packets.OpcodeInvestigationSeen.id].message_ids.append(
    b"\x00\x00\x00\x00\xa0\x01"
)
print("    SERVER: {}".format(h(packet.dump())))
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xa0\x03"
packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
packet.opcodes[packets.OpcodeInReplyTo.id].message_id = b"\x00\x00\x00\x00\xb0\x02"
packet.opcodes[packets.OpcodeRTTEnclosed.id] = packets.OpcodeRTTEnclosed()
packet.opcodes[packets.OpcodeRTTEnclosed.id].rtt_us = 12345
print("    CLIENT: {}".format(h(packet.dump())))
print()

print("### Example 5")
print()
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xa0\x01"
packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
print("    CLIENT: {}".format(h(packet.dump())))
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xa0\x02"
packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
packet.opcodes[packets.OpcodeInvestigate.id] = packets.OpcodeInvestigate()
packet.opcodes[packets.OpcodeInvestigate.id].message_ids.append(
    b"\x00\x00\x00\x00\xa0\x01"
)
print("    CLIENT: {}".format(h(packet.dump())))
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xb0\x01"
packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
packet.opcodes[packets.OpcodeInReplyTo.id].message_id = b"\x00\x00\x00\x00\xa0\x02"
packet.opcodes[
    packets.OpcodeInvestigationUnseen.id
] = packets.OpcodeInvestigationUnseen()
packet.opcodes[packets.OpcodeInvestigationUnseen.id].message_ids.append(
    b"\x00\x00\x00\x00\xa0\x01"
)
print("    SERVER: {}".format(h(packet.dump())))
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xa0\x03"
packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
packet.opcodes[packets.OpcodeInReplyTo.id].message_id = b"\x00\x00\x00\x00\xb0\x01"
packet.opcodes[packets.OpcodeRTTEnclosed.id] = packets.OpcodeRTTEnclosed()
packet.opcodes[packets.OpcodeRTTEnclosed.id].rtt_us = 12345
print("    CLIENT: {}".format(h(packet.dump())))
print()

print("### Example 6")
print()
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xa0\x01"
packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
print("    CLIENT: {}".format(h(packet.dump())))
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xa0\x02"
packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
print("    CLIENT: {}".format(h(packet.dump())))
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xa0\x03"
packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
print("    CLIENT: {}".format(h(packet.dump())))
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xb0\x02"
packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
packet.opcodes[packets.OpcodeInReplyTo.id].message_id = b"\x00\x00\x00\x00\xa0\x03"
print("    SERVER: {}".format(h(packet.dump())))
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xa0\x04"
packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
packet.opcodes[packets.OpcodeInReplyTo.id].message_id = b"\x00\x00\x00\x00\xb0\x02"
packet.opcodes[packets.OpcodeRTTEnclosed.id] = packets.OpcodeRTTEnclosed()
packet.opcodes[packets.OpcodeRTTEnclosed.id].rtt_us = 12823
print("    CLIENT: {}".format(h(packet.dump())))
print("    ... etc")
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xa0\x0a"
packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
packet.opcodes[packets.OpcodeInvestigate.id] = packets.OpcodeInvestigate()
packet.opcodes[packets.OpcodeInvestigate.id].message_ids.append(
    b"\x00\x00\x00\x00\xa0\x01"
)
packet.opcodes[packets.OpcodeInvestigate.id].message_ids.append(
    b"\x00\x00\x00\x00\xa0\x02"
)
print("    CLIENT: {}".format(h(packet.dump())))
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xb0\x06"
packet.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
packet.opcodes[packets.OpcodeInReplyTo.id].message_id = b"\x00\x00\x00\x00\xa0\x0a"
packet.opcodes[packets.OpcodeInvestigationSeen.id] = packets.OpcodeInvestigationSeen()
packet.opcodes[packets.OpcodeInvestigationSeen.id].message_ids.append(
    b"\x00\x00\x00\x00\xa0\x01"
)
packet.opcodes[
    packets.OpcodeInvestigationUnseen.id
] = packets.OpcodeInvestigationUnseen()
packet.opcodes[packets.OpcodeInvestigationUnseen.id].message_ids.append(
    b"\x00\x00\x00\x00\xa0\x02"
)
packet.opcodes[packets.OpcodeInvestigate.id] = packets.OpcodeInvestigate()
packet.opcodes[packets.OpcodeInvestigate.id].message_ids.append(
    b"\x00\x00\x00\x00\xb0\x02"
)
print("    SERVER: {}".format(h(packet.dump())))
packet = packets.Packet()
packet.message_id = b"\x00\x00\x00\x00\xa0\x0b"
packet.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
packet.opcodes[packets.OpcodeInReplyTo.id].message_id = b"\x00\x00\x00\x00\xb0\x06"
packet.opcodes[packets.OpcodeRTTEnclosed.id] = packets.OpcodeRTTEnclosed()
packet.opcodes[packets.OpcodeRTTEnclosed.id].rtt_us = 13112
packet.opcodes[packets.OpcodeInvestigationSeen.id] = packets.OpcodeInvestigationSeen()
packet.opcodes[packets.OpcodeInvestigationSeen.id].message_ids.append(
    b"\x00\x00\x00\x00\xb0\x02"
)
print("    CLIENT: {}".format(h(packet.dump())))
print()
