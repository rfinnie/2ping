local twoping = Proto("2ping","2ping Protocol")

local mac_digests = {
    [0] = "Private",
    [1] = "HMAC-MD5",
    [2] = "HMAC-SHA1",
    [3] = "HMAC-SHA256",
    [4] = "HMAC-CRC32",
    [5] = "HMAC-SHA512"
}

local encrypted_methods = {
    [0] = "Private",
    [1] = "HKDF-AES256-CBC"
}

local extended_ids = {
    [0x3250564e] = "Program version",
    [0x2ff6ad68] = "Random data",
    [0x64f69319] = "Wall clock",
    [0x771d8dfb] = "Monotonic clock",
    [0x88a1f7c7] = "Battery levels",
    [0xa837b44e] = "Notice text"
}

local pf_magic_number = ProtoField.new   ("Magic number", "2ping.magic_number", ftypes.UINT16, nil, base.HEX)
local pf_checksum = ProtoField.new   ("Checksum", "2ping.checksum", ftypes.UINT16, nil, base.HEX)
local pf_message_id = ProtoField.new   ("Message ID", "2ping.message_id", ftypes.ETHER)
local pf_opcode_flags = ProtoField.new   ("Opcode flags", "2ping.opcode_flags", ftypes.UINT16, nil, base.HEX)

local pf_opcode_flag_reply_requested = ProtoField.bool  ("2ping.opcode_flags.reply_requested", "Reply requested", 16, nil, 0x0001)
local pf_opcode_flag_in_reply_to = ProtoField.bool  ("2ping.opcode_flags.in_reply_to", "In reply to", 16, nil, 0x0002)
local pf_opcode_flag_rtt_enclosed = ProtoField.bool  ("2ping.opcode_flags.rtt_enclosed", "RTT enclosed", 16, nil, 0x0004)
local pf_opcode_flag_investigation_replied = ProtoField.bool  ("2ping.opcode_flags.investigation_replied", "Investigation (replied)", 16, nil, 0x0008)
local pf_opcode_flag_investigation_lost = ProtoField.bool  ("2ping.opcode_flags.investigation_lost", "Investigation (lost)", 16, nil, 0x0010)
local pf_opcode_flag_investigation_request = ProtoField.bool  ("2ping.opcode_flags.investigation_request", "Investigation request", 16, nil, 0x0020)
local pf_opcode_flag_courtesy_expiration = ProtoField.bool  ("2ping.opcode_flags.courtesy_expiration", "Courtesy expiration", 16, nil, 0x0040)
local pf_opcode_flag_mac = ProtoField.bool  ("2ping.opcode_flags.mac", "Message authentication code", 16, nil, 0x0080)
local pf_opcode_flag_host_latency = ProtoField.bool  ("2ping.opcode_flags.host_latency", "Host processing latency", 16, nil, 0x0100)
local pf_opcode_flag_encrypted = ProtoField.bool  ("2ping.opcode_flags.encrypted", "Encrypted packet", 16, nil, 0x0200)
local pf_opcode_flag_extended = ProtoField.bool  ("2ping.opcode_flags.extended", "Extended segments", 16, nil, 0x8000)

local pf_segment_length = ProtoField.new   ("Length", "2ping.segment.length", ftypes.UINT16)

local pf_reply_requested = ProtoField.new   ("Reply requested", "2ping.reply_requested", ftypes.NONE)

local pf_in_reply_to = ProtoField.new   ("In reply to", "2ping.in_reply_to", ftypes.STRING)
local pf_in_reply_to_message_id = ProtoField.new   ("Message ID", "2ping.in_reply_to.message_id", ftypes.ETHER)

local pf_rtt_enclosed = ProtoField.new   ("RTT enclosed", "2ping.rtt_enclosed", ftypes.UINT32)
local pf_rtt_enclosed_rtt = ProtoField.new   ("RTT (μs)", "2ping.rtt_enclosed.rtt", ftypes.UINT32)

local pf_investigation_replied = ProtoField.new   ("Investigation (replied)", "2ping.investigation_replied", ftypes.STRING)
local pf_investigation_replied_count = ProtoField.new   ("Message ID count", "2ping.investigation_replied.count", ftypes.UINT16)
local pf_investigation_replied_message_id = ProtoField.new   ("Message ID", "2ping.investigation_replied.message_id", ftypes.ETHER)

local pf_investigation_lost = ProtoField.new   ("Investigation (lost)", "2ping.investigation_lost", ftypes.STRING)
local pf_investigation_lost_count = ProtoField.new   ("Message ID count", "2ping.investigation_lost.count", ftypes.UINT16)
local pf_investigation_lost_message_id = ProtoField.new   ("Message ID", "2ping.investigation_lost.message_id", ftypes.ETHER)

local pf_investigation_request = ProtoField.new   ("Investigation request", "2ping.investigation_request", ftypes.STRING)
local pf_investigation_request_count = ProtoField.new   ("Message ID count", "2ping.investigation_request.count", ftypes.UINT16)
local pf_investigation_request_message_id = ProtoField.new   ("Message ID", "2ping.investigation_request.message_id", ftypes.ETHER)

local pf_courtesy_expiration = ProtoField.new   ("Courtesy expiration", "2ping.courtesy_expiration", ftypes.STRING)
local pf_courtesy_expiration_count = ProtoField.new   ("Message ID count", "2ping.courtesy_expiration.count", ftypes.UINT16)
local pf_courtesy_expiration_message_id = ProtoField.new   ("Message ID", "2ping.courtesy_expiration.message_id", ftypes.ETHER)

local pf_mac = ProtoField.new   ("Message authentication code", "2ping.mac", ftypes.STRING)
local pf_mac_digest = ProtoField.uint16   ("2ping.mac.digest", "Digest", base.DEC, mac_digests)
local pf_mac_hash = ProtoField.new   ("Hash", "2ping.mac.hash", ftypes.BYTES)

local pf_host_latency = ProtoField.new   ("Host processing latency", "2ping.host_latency", ftypes.UINT32)
local pf_host_latency_delay = ProtoField.new   ("Delay (μs)", "2ping.host_latency.delay", ftypes.UINT32)

local pf_encrypted = ProtoField.new   ("Encrypted packet", "2ping.encrypted", ftypes.STRING)
local pf_encrypted_method = ProtoField.uint16   ("2ping.encrypted.method", "Method", base.DEC, encrypted_methods)
local pf_encrypted_data = ProtoField.new   ("Data", "2ping.encrypted.data", ftypes.BYTES)

local pf_unknown = ProtoField.new   ("Unknown", "2ping.unknown", ftypes.STRING)
local pf_unknown_data = ProtoField.new   ("Data", "2ping.unknown.data", ftypes.BYTES)

local pf_extended = ProtoField.new   ("Extended segments", "2ping.extended", ftypes.STRING)
local pf_extended_count = ProtoField.new   ("Count", "2ping.extended.count", ftypes.UINT16)

local pf_extended_id = ProtoField.uint32   ("2ping.extended.id", "ID", base.HEX, extended_ids)

local pf_version = ProtoField.new   ("Program version", "2ping.version", ftypes.STRING)
local pf_version_text = ProtoField.new   ("Text", "2ping.version.text", ftypes.STRING)

local pf_notice = ProtoField.new   ("Notice text", "2ping.notice", ftypes.STRING)
local pf_notice_text = ProtoField.new   ("Text", "2ping.notice.text", ftypes.STRING)

local pf_random = ProtoField.new   ("Random data", "2ping.random", ftypes.STRING)
local pf_random_data = ProtoField.new   ("Data", "2ping.random.data", ftypes.BYTES)
local pf_random_flag_hardware = ProtoField.bool  ("2ping.random.hardware", "Hardware RNG", 16, nil, 0x0001)
local pf_random_flag_os = ProtoField.bool  ("2ping.random.os", "Operating system RNG", 16, nil, 0x0002)

local pf_wallclock = ProtoField.new   ("Wall clock", "2ping.wallclock", ftypes.ABSOLUTE_TIME)
local pf_wallclock_time = ProtoField.new   ("Time", "2ping.wallclock.time", ftypes.ABSOLUTE_TIME)

local pf_monotonic = ProtoField.new   ("Monotonic clock", "2ping.monotonic", ftypes.ABSOLUTE_TIME)
local pf_monotonic_generation = ProtoField.new   ("Generation", "2ping.monotonic.generation", ftypes.UINT16)
local pf_monotonic_time = ProtoField.new   ("Time", "2ping.monotonic.time", ftypes.ABSOLUTE_TIME)

local pf_battery_levels = ProtoField.new   ("Battery levels", "2ping.battery_levels", ftypes.STRING)
local pf_battery_levels_count = ProtoField.new   ("Battery count", "2ping.battery_levels.count", ftypes.UINT16)
local pf_battery_levels_id = ProtoField.new   ("Battery ID", "2ping.battery_levels.id", ftypes.UINT16)
local pf_battery_levels_level = ProtoField.new   ("Battery level", "2ping.battery_levels.level", ftypes.UINT16)

local pf_padding = ProtoField.new   ("Padding", "2ping.padding", ftypes.BYTES)

twoping.fields = {
    pf_magic_number,
    pf_checksum,
    pf_message_id,
    pf_opcode_flags,
    pf_opcode_flag_reply_requested,
    pf_opcode_flag_in_reply_to,
    pf_opcode_flag_rtt_enclosed,
    pf_opcode_flag_investigation_replied,
    pf_opcode_flag_investigation_lost,
    pf_opcode_flag_investigation_request,
    pf_opcode_flag_courtesy_expiration,
    pf_opcode_flag_mac,
    pf_opcode_flag_host_latency,
    pf_opcode_flag_encrypted,
    pf_opcode_flag_extended,
    pf_segment_length,
    pf_reply_requested,
    pf_in_reply_to,
    pf_in_reply_to_message_id,
    pf_rtt_enclosed,
    pf_rtt_enclosed_rtt,
    pf_investigation_replied,
    pf_investigation_replied_count,
    pf_investigation_replied_message_id,
    pf_investigation_lost,
    pf_investigation_lost_count,
    pf_investigation_lost_message_id,
    pf_investigation_request,
    pf_investigation_request_count,
    pf_investigation_request_message_id,
    pf_courtesy_expiration,
    pf_courtesy_expiration_count,
    pf_courtesy_expiration_message_id,
    pf_mac,
    pf_mac_digest,
    pf_mac_hash,
    pf_host_latency,
    pf_host_latency_delay,
    pf_encrypted,
    pf_encrypted_method,
    pf_encrypted_data,
    pf_unknown,
    pf_unknown_data,
    pf_extended,
    pf_extended_count,
    pf_extended_segment,
    pf_extended_id,
    pf_version,
    pf_version_text,
    pf_notice,
    pf_notice_text,
    pf_random,
    pf_random_data,
    pf_random_flag_hardware,
    pf_random_flag_os,
    pf_wallclock,
    pf_wallclock_time,
    pf_monotonic,
    pf_monotonic_generation,
    pf_monotonic_time,
    pf_battery_levels,
    pf_battery_levels_count,
    pf_battery_levels_id,
    pf_battery_levels_level,
    pf_padding,
}

local reply_requested_field = Field.new("2ping.opcode_flags.reply_requested")
local in_reply_to_field = Field.new("2ping.opcode_flags.in_reply_to")
local rtt_enclosed_field = Field.new("2ping.opcode_flags.rtt_enclosed")
local investigation_replied_field = Field.new("2ping.opcode_flags.investigation_replied")
local investigation_lost_field = Field.new("2ping.opcode_flags.investigation_lost")
local investigation_request_field = Field.new("2ping.opcode_flags.investigation_request")
local courtesy_expiration_field = Field.new("2ping.opcode_flags.courtesy_expiration")
local mac_field = Field.new("2ping.opcode_flags.mac")
local host_latency_field = Field.new("2ping.opcode_flags.host_latency")
local encrypted_field = Field.new("2ping.opcode_flags.encrypted")
local extended_field = Field.new("2ping.opcode_flags.extended")

local function shift_opcode_data(buf)
    local data_length = buf:range(0,2):uint()
    local opcode_range = buf:range(0,data_length+2)
    local data_range = opcode_range:range(0,0)
    if data_length > 0 then
        data_range = opcode_range:range(2)
    end
    local remaining_buf = buf:range(0,0)
    if data_length+2 < buf:len() then
        remaining_buf = buf:range(data_length+2)
    end
    return opcode_range, data_range, remaining_buf
end

local function process_common_message_id_list(tree, opcode_range, data_range, pf, pf_count, pf_message_id)
        local num_message_ids = data_range:range(0,2):uint()
        local local_tree = tree:add(pf, opcode_range)
        local_tree:add(pf_segment_length, opcode_range:range(0,2))
        local_tree:add(pf_count, data_range:range(0,2))
        local local_pos = 2
        for i=1,num_message_ids,1 do
            local_tree:add(pf_message_id, data_range:range(local_pos,6))
            local_pos = local_pos + 6
        end
        if num_message_ids == 1 then
            local_tree:append_text(tostring(data_range:range(2):ether()))
        else
            local_tree:append_text(num_message_ids)
            local_tree:append_text(" IDs")
        end
end

function twoping.dissector(tvbuf,pktinfo,root)
    pktinfo.cols.protocol:set("2PING")
    local pktlen = tvbuf:reported_length_remaining()
    local tree = root:add(twoping, tvbuf:range(0,pktlen))
    tree:add(pf_magic_number, tvbuf:range(0,2))
    tree:add(pf_checksum, tvbuf:range(2,2))
    tree:add(pf_message_id, tvbuf:range(4,6))

    local flagrange = tvbuf:range(10,2)
    local flag_tree = tree:add(pf_opcode_flags, flagrange)

    local opcode_remaining = tvbuf:range(12)

    flag_tree:add(pf_opcode_flag_reply_requested, flagrange)
    if reply_requested_field()() then
        local opcode_range, data_range, remaining_buf = shift_opcode_data(opcode_remaining)
        opcode_remaining = remaining_buf
        local reply_requested_tree = tree:add(pf_reply_requested, opcode_range)
        reply_requested_tree:add(pf_segment_length, opcode_range:range(0,2))
    end

    flag_tree:add(pf_opcode_flag_in_reply_to, flagrange)
    if in_reply_to_field()() then
        local opcode_range, data_range, remaining_buf = shift_opcode_data(opcode_remaining)
        opcode_remaining = remaining_buf
        local in_reply_to_tree = tree:add(pf_in_reply_to, opcode_range, tostring(data_range:ether()))
        in_reply_to_tree:add(pf_segment_length, opcode_range:range(0,2))
        in_reply_to_tree:add(pf_in_reply_to_message_id, data_range)
    end

    flag_tree:add(pf_opcode_flag_rtt_enclosed, flagrange)
    if rtt_enclosed_field()() then
        local opcode_range, data_range, remaining_buf = shift_opcode_data(opcode_remaining)
        opcode_remaining = remaining_buf
        local rtt_enclosed_tree = tree:add(pf_rtt_enclosed, opcode_range, data_range:uint(), nil, "μs")
        rtt_enclosed_tree:add(pf_segment_length, opcode_range:range(0,2))
        rtt_enclosed_tree:add(pf_rtt_enclosed_rtt, data_range)
    end

    flag_tree:add(pf_opcode_flag_investigation_replied, flagrange)
    if investigation_replied_field()() then
        local opcode_range, data_range, remaining_buf = shift_opcode_data(opcode_remaining)
        opcode_remaining = remaining_buf
        process_common_message_id_list(tree, opcode_range, data_range, pf_investigation_replied, pf_investigation_replied_count, pf_investigation_replied_message_id)
    end

    flag_tree:add(pf_opcode_flag_investigation_lost, flagrange)
    if investigation_lost_field()() then
        local opcode_range, data_range, remaining_buf = shift_opcode_data(opcode_remaining)
        opcode_remaining = remaining_buf
        process_common_message_id_list(tree, opcode_range, data_range, pf_investigation_lost, pf_investigation_lost_count, pf_investigation_lost_message_id)
    end

    flag_tree:add(pf_opcode_flag_investigation_request, flagrange)
    if investigation_request_field()() then
        local opcode_range, data_range, remaining_buf = shift_opcode_data(opcode_remaining)
        opcode_remaining = remaining_buf
        process_common_message_id_list(tree, opcode_range, data_range, pf_investigation_request, pf_investigation_request_count, pf_investigation_request_message_id)
    end

    flag_tree:add(pf_opcode_flag_courtesy_expiration, flagrange)
    if courtesy_expiration_field()() then
        local opcode_range, data_range, remaining_buf = shift_opcode_data(opcode_remaining)
        opcode_remaining = remaining_buf
        process_common_message_id_list(tree, opcode_range, data_range, pf_courtesy_expiration, pf_courtesy_expiration_count, pf_courtesy_expiration_message_id)
    end

    flag_tree:add(pf_opcode_flag_mac, flagrange)
    if mac_field()() then
        local opcode_range, data_range, remaining_buf = shift_opcode_data(opcode_remaining)
        opcode_remaining = remaining_buf
        local mac_tree = tree:add(pf_mac, opcode_range, tostring(data_range:range(2):bytes()):lower())
        mac_tree:add(pf_segment_length, opcode_range:range(0,2))
        mac_tree:add(pf_mac_digest, data_range:range(0,2))
        mac_tree:add(pf_mac_hash, data_range:range(2))
    end

    flag_tree:add(pf_opcode_flag_host_latency, flagrange)
    if host_latency_field()() then
        local opcode_range, data_range, remaining_buf = shift_opcode_data(opcode_remaining)
        opcode_remaining = remaining_buf
        local host_latency_tree = tree:add(pf_host_latency, opcode_range, data_range:uint(), nil, "μs")
        host_latency_tree:add(pf_segment_length, opcode_range:range(0,2))
        host_latency_tree:add(pf_host_latency_delay, data_range)
    end

    flag_tree:add(pf_opcode_flag_encrypted, flagrange)
    if encrypted_field()() then
        local opcode_range, data_range, remaining_buf = shift_opcode_data(opcode_remaining)
        opcode_remaining = remaining_buf
        local encrypted_tree = tree:add(pf_encrypted, opcode_range, tostring(data_range:range(2):bytes()):lower())
        encrypted_tree:add(pf_segment_length, opcode_range:range(0,2))
        encrypted_tree:add(pf_encrypted_method, data_range:range(0,2))
        encrypted_tree:add(pf_encrypted_data, data_range:range(2))
    end

    for bitpos=5,1,-1 do
        if flagrange:bitfield(bitpos,1) == 1 then
            local opcode_range, data_range, remaining_buf = shift_opcode_data(opcode_remaining)
            opcode_remaining = remaining_buf
            local unknown_tree = tree:add(pf_unknown, opcode_range, tostring(data_range:bytes()):lower(), nil, data_range:len(), "bytes")
            unknown_tree:add(pf_segment_length, opcode_range:range(0,2))
            unknown_tree:add(pf_unknown_data, data_range)
        end
    end

    flag_tree:add(pf_opcode_flag_extended, flagrange)
    if extended_field()() then
        local opcode_range, data_range, remaining_buf = shift_opcode_data(opcode_remaining)
        opcode_remaining = remaining_buf
        local extended_tree = tree:add(pf_extended, opcode_range)
        extended_tree:add(pf_segment_length, opcode_range:range(0,2))

        local extended_range = data_range
        local num_extended_segments = 0
        while( extended_range:len() > 0 ) do
            num_extended_segments = num_extended_segments + 1
            local id_range = extended_range:range(0,4)
            local length_range = extended_range:range(4,2)
            local extended_id = id_range:uint()
            local extended_length = length_range:uint()
            local segment_range = extended_range:range(0,extended_length+6)
            local segment_data_range = segment_range:range(6)
            if extended_range:len() <= extended_length+6 then
                extended_range = extended_range:range(0,0)
            else
                extended_range = extended_range:range(extended_length+6)
            end

            if extended_id == 0x3250564e then
                local version_text = segment_data_range:string()
                local extended_segment_tree = tree:add(pf_version, segment_range, version_text)
                extended_segment_tree:add(pf_extended_id, id_range)
                extended_segment_tree:add(pf_segment_length, length_range)
                extended_segment_tree:add(pf_version_text, segment_data_range)
            elseif extended_id == 0xa837b44e then
                local notice_text = segment_data_range:string()
                local extended_segment_tree = tree:add(pf_notice, segment_range, notice_text)
                extended_segment_tree:add(pf_extended_id, id_range)
                extended_segment_tree:add(pf_segment_length, length_range)
                extended_segment_tree:add(pf_notice_text, segment_data_range)
            elseif extended_id == 0x2ff6ad68 then
                local extended_segment_tree = tree:add(pf_random, segment_range, tostring(segment_data_range:range(2):bytes()):lower(), nil, segment_data_range:len()-2, "bytes")
                extended_segment_tree:add(pf_extended_id, id_range)
                extended_segment_tree:add(pf_segment_length, length_range)
                extended_segment_tree:add(pf_random_flag_hardware, segment_data_range:range(0,2))
                extended_segment_tree:add(pf_random_flag_os, segment_data_range:range(0,2))
                extended_segment_tree:add(pf_random_data, segment_data_range:range(2))
            elseif extended_id == 0x64f69319 then
                local usecs = segment_data_range:range(0,8):uint64()
                local secs = (usecs / 1000000):tonumber()
                local nsecs = (usecs % 1000000):tonumber() * 1000
                local nstime = NSTime.new(secs, nsecs)
                local extended_segment_tree = tree:add(pf_wallclock, segment_range, nstime)
                extended_segment_tree:add(pf_extended_id, id_range)
                extended_segment_tree:add(pf_segment_length, length_range)
                extended_segment_tree:add(pf_wallclock_time, segment_data_range:range(0,8), nstime)
            elseif extended_id == 0x771d8dfb then
                local usecs = segment_data_range:range(2,8):uint64()
                local secs = (usecs / 1000000):tonumber()
                local nsecs = (usecs % 1000000):tonumber() * 1000
                local nstime = NSTime.new(secs, nsecs)
                local extended_segment_tree = tree:add(pf_monotonic, segment_range, nstime)
                extended_segment_tree:add(pf_extended_id, id_range)
                extended_segment_tree:add(pf_segment_length, length_range)
                extended_segment_tree:add(pf_monotonic_generation, segment_data_range:range(0,2))
                extended_segment_tree:add(pf_monotonic_time, segment_data_range:range(2,8), nstime)
            elseif extended_id == 0x88a1f7c7 then
                local num_batteries = segment_data_range:range(0,2):uint()
                local extended_segment_tree = tree:add(pf_battery_levels, segment_range, "")
                extended_segment_tree:add(pf_extended_id, id_range)
                extended_segment_tree:add(pf_segment_length, length_range)
                extended_segment_tree:add(pf_battery_levels_count, segment_data_range:range(0,2))
                local local_pos = 2
                for i=1,num_batteries,1 do
                    extended_segment_tree:add(pf_battery_levels_id, segment_data_range:range(local_pos,2))
                    extended_segment_tree:add(pf_battery_levels_level, segment_data_range:range(local_pos+2,2))
                    local_pos = local_pos + 4
                end
                if num_batteries == 1 then
                    extended_segment_tree:append_text(tostring(segment_data_range:range(4,2):uint()))
                else
                    extended_segment_tree:append_text(num_batteries)
                    extended_segment_tree:append_text(" batteries")
                end
            else
                local extended_segment_tree = tree:add(pf_unknown, segment_range, tostring(segment_data_range:bytes()):lower(), nil, segment_data_range:len(), "bytes")
                extended_segment_tree:add(pf_extended_id, id_range)
                extended_segment_tree:add(pf_segment_length, length_range)
                extended_segment_tree:add(pf_unknown_data, segment_data_range)
            end
        end

        local segments_count_tree = extended_tree:add(pf_extended_count, data_range, num_extended_segments)
        segments_count_tree:set_generated()

        extended_tree:append_text(num_extended_segments)
        if num_extended_segments == 1 then
            extended_tree:append_text(" segment")
        else
            extended_tree:append_text(" segments")
        end
    end

    if opcode_remaining:len() > 0 then
        tree:add(pf_padding, opcode_remaining)
    end

    local info_append = ""
    if reply_requested_field()() or in_reply_to_field()() then
        if reply_requested_field()() and in_reply_to_field()() then
            info_append = info_append .. " [RR,IRT]"
        elseif reply_requested_field()() then
            info_append = info_append .. " [RR]"
        elseif in_reply_to_field()() then
            info_append = info_append .. " [IRT]"
        end
    end
    if investigation_request_field()() or investigation_replied_field()() or investigation_lost_field()() then
        local inv_append = " ["
        local inv_printed = false
        if investigation_request_field()() then
            if inv_printed then
                inv_append = inv_append .. ","
            end
            inv_append = inv_append .. "?"
            inv_printed = true
        end
        if investigation_replied_field()() then
            if inv_printed then
                inv_append = inv_append .. ","
            end
            inv_append = inv_append .. ">"
            inv_printed = true
        end
        if investigation_lost_field()() then
            if inv_printed then
                inv_append = inv_append .. ","
            end
            inv_append = inv_append .. "<"
            inv_printed = true
        end
        inv_append = inv_append .. "]"
        info_append = info_append .. inv_append
    end
    info_append = info_append .. " ID=" .. tostring(tvbuf:range(4,6):ether())
    pktinfo.cols.info:append(info_append)
end

local function heur_dissect_twoping(tvbuf,pktinfo,root)
    if tvbuf:len() < 12 then
        return false
    end

    if tvbuf:range(0,2):uint() ~= 0x3250 then
        return false
    end

    twoping.dissector(tvbuf,pktinfo,root)
    pktinfo.conversation = twoping

    return true
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(15998,twoping)
twoping:register_heuristic("udp",heur_dissect_twoping)
