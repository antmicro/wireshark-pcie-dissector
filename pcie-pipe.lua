-- Wireshark dissector plugin for PCIe/IP
--
-- Copyright 2023 Antmicro <www.antmicro.com>
-- Copyright 2023 Meta
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

local data_dis = Dissector.get("data")

-------------------------------------------------------------------------
-- TLP                                                                 --
-------------------------------------------------------------------------
local p_tlp = Proto("pcie.tlp", "PCIe TLP")

local fmttp_map = {
	[0x00] = "MRd : Memory Read Request",
	[0x20] = "MRd : Memory Read Request",
	[0x40] = "MWr : Memory Write Request",
	[0x60] = "MWr : Memory Write Request",
	[0x02] = "IORd: I/O Read Request",
	[0x42] = "IOWr: I/O Write Request",
	[0x0A] = "Cpl : Completion without Data",
	[0x4A] = "CplD: Completion with Data",
}

p_tlp.fields.fmttp = ProtoField.uint8("pcie.tlp.fmttp", "TLP Type", base.HEX, fmttp_map)
p_tlp.fields.type  = ProtoField.uint8("pcie.tlp.type", "Type",  base.BIN, nil, 0x1F)
p_tlp.fields.fmt   = ProtoField.uint8("pcie.tlp.fmt", "Fmt",    base.BIN, nil, 0xE0, "Format")
p_tlp.fields.h1    = ProtoField.uint24("pcie.tlp.h1", "Header", base.HEX)
p_tlp.fields.t9    = ProtoField.uint24("pcie.tlp.t9", "T9",     base.DEC, nil, 0x00800000)
p_tlp.fields.tc    = ProtoField.uint24("pcie.tlp.tc", "TC",     base.DEC, nil, 0x00700000, "Traffic class")
p_tlp.fields.t8    = ProtoField.uint24("pcie.tlp.t8", "T8",     base.DEC, nil, 0x00080000)
p_tlp.fields.attr  = ProtoField.uint24("pcie.tlp.attr", "Attr", base.BIN, nil, 0x00043000, "Attributes")
p_tlp.fields.ln    = ProtoField.uint24("pcie.tlp.ln", "LN",     base.DEC, nil, 0x00020000, "Lightweight notification")
p_tlp.fields.th    = ProtoField.uint24("pcie.tlp.th", "TH",     base.DEC, nil, 0x00010000, "TLP Hints")
p_tlp.fields.td    = ProtoField.uint24("pcie.tlp.td", "TD",     base.DEC, nil, 0x00008000, "TLP Digest")
p_tlp.fields.ep    = ProtoField.uint24("pcie.tlp.ep", "EP",     base.DEC, nil, 0x00004000, "Error poisoned")
p_tlp.fields.at    = ProtoField.uint24("pcie.tlp.at", "AT",     base.BIN, nil, 0x00000C00)
p_tlp.fields.len_value = ProtoField.uint24("pcie.tlp.len_value", "Length", base.DEC, nil, 0x3FF,
                                           "Length from TLP header")
p_tlp.fields.length = ProtoField.uint16("pcie.tlp.length", "Calculated length", base.DEC, nil, nil,
                                        "Calculated TLP packet payload length")

p_tlp.fields.rq_id = ProtoField.uint16("pcie.tlp.rq_id", "Requester ID", base.HEX)
p_tlp.fields.tag   = ProtoField.uint8("pcie.tlp.tag", "Tag", base.HEX)
p_tlp.fields.last_be = ProtoField.uint8("pcie.tlp.last_be", "Last BE", base.HEX, nil, 0xf0)
p_tlp.fields.first_be = ProtoField.uint8("pcie.tlp.first_be", "First BE", base.HEX, nil, 0x0f)

p_tlp.fields.comp_id = ProtoField.uint16("pcie.tlp.comp_id", "Completer ID", base.HEX)
p_tlp.fields.status = ProtoField.uint16("pcie.tlp.status", "Status", base.HEX, nil, 0xE000)
p_tlp.fields.bcm = ProtoField.uint16("pcie.tlp.bcm", "BCM", base.HEX, nil, 0x1000, "Bridge control mechanism")
p_tlp.fields.byte_count = ProtoField.uint16("pcie.tlp.byte_count", "Byte count", base.HEX, nil, 0x0FFF)
p_tlp.fields.lower_addr = ProtoField.uint8("pcie.tlp.lower_addr", "Lower address", base.HEX, nil, 0x7F)

p_tlp.fields.bus_no = ProtoField.uint16("pcie.tlp.bus_no", "Bus number", base.HEX, nil, 0xFF00)
p_tlp.fields.dev_no = ProtoField.uint16("pcie.tlp.dev_no", "Dev. number", base.HEX, nil, 0x00F8, "Device number")
p_tlp.fields.fun_no = ProtoField.uint16("pcie.tlp.fun_no", "Fun. number", base.HEX, nil, 0x0007, "Function number")

p_tlp.fields.res_frame = ProtoField.framenum("pcie.tlp.res_frame", "Response frame", base.NONE, frametype.RESPONSE)
p_tlp.fields.req_frame = ProtoField.framenum("pcie.tlp.req_frame", "Request frame", base.NONE, frametype.REQUEST)

p_tlp.fields.addr  = ProtoField.uint64("pcie.tlp.addr", "Address", base.HEX)

local function dissect_pcieid(field, range, tree)
	local subtree = tree:add(field, range)
	subtree:add(p_tlp.fields.bus_no, range)
	subtree:add(p_tlp.fields.dev_no, range)
	subtree:add(p_tlp.fields.fun_no, range)
end

local function pretty_pcieid(range)
	local id = range:uint()
	return string.format('%02x:%02x.%x', bit.rshift(id, 8), bit.band(bit.rshift(id, 3), 0x7F), bit.band(id, 0x0007))
end

local req_to_frame = {}
local reqframe_to_resframe = {}

local function dissect_tlp(buf, pkt, tree)
	local fmt = bit.rshift(buf(0, 1):uint(), 5)
	local le = 3 + bit.band(fmt, 1)
	local hdrtree = tree:add(p_tlp, buf(0, le * 4))
	local h0 = buf(0, 1)
	local tptree = hdrtree:add(p_tlp.fields.fmttp, h0)
	tptree:add(p_tlp.fields.fmt, h0)
	tptree:add(p_tlp.fields.type, h0)
	local h1 = buf(1, 3)
	local h1tree = hdrtree:add(p_tlp.fields.h1, h1)
	h1tree:add(p_tlp.fields.t9, h1)
	h1tree:add(p_tlp.fields.tc, h1)
	h1tree:add(p_tlp.fields.t8, h1)
	h1tree:add(p_tlp.fields.attr, h1)
	h1tree:add(p_tlp.fields.ln, h1)
	h1tree:add(p_tlp.fields.th, h1)
	h1tree:add(p_tlp.fields.td, h1)
	h1tree:add(p_tlp.fields.ep, h1)
	h1tree:add(p_tlp.fields.at, h1)
	h1tree:add(p_tlp.fields.len_value, h1)
	local length = bit.band(buf(2, 2):uint() - 1, 0x3FF) + 1
	h1tree:add(p_tlp.fields.length, h1, length)
	if bit.band(fmt, 2) == 0 then
		-- Read/Cpl
		length = 0
	end

	if bit.band(buf(0, 1):uint(), 0x1e) ~= 0x0a then
		-- Read/Write
		dissect_pcieid(p_tlp.fields.rq_id, buf(4, 2), hdrtree)
		hdrtree:add(buf(4, 2), "Decoded requester:", pretty_pcieid(buf(4, 2)))
		hdrtree:add(p_tlp.fields.tag, buf(6, 1))
		local req_uniq = buf(4, 3):uint()
		req_to_frame[req_uniq] = pkt.number

		hdrtree:add(p_tlp.fields.last_be, buf(7, 1))
		hdrtree:add(p_tlp.fields.first_be, buf(7, 1))
		local addr = buf(8, 4)
		if le == 4 then
			addr = buf(8, 8)
		end
		pkt.cols.info:set(string.format(
			'%.4s %s @ %08x',
			fmttp_map[h0:uint()], pretty_pcieid(buf(4, 2)), addr:uint()
		))
		hdrtree:add(p_tlp.fields.addr, addr)

		if reqframe_to_resframe[pkt.number] ~= nil then
			hdrtree:add(p_tlp.fields.res_frame, buf(4, 3), reqframe_to_resframe[pkt.number])
		else
			hdrtree:add(buf(4, 3), "Warning: missing response")
		end
	else
		-- Completion
		dissect_pcieid(p_tlp.fields.comp_id, buf(4, 2), hdrtree)
		pkt.cols.src:append(pretty_pcieid(buf(4, 2)))
		hdrtree:add(buf(4, 2), "Decoded completer:", pretty_pcieid(buf(4, 2)))
		hdrtree:add(p_tlp.fields.status, buf(6, 2))
		hdrtree:add(p_tlp.fields.bcm, buf(6, 2))
		hdrtree:add(p_tlp.fields.byte_count, buf(6, 2))
		dissect_pcieid(p_tlp.fields.rq_id, buf(8, 2), hdrtree)
		pkt.cols.info:set(string.format(
			'%.4s %s -> %s',
			fmttp_map[h0:uint()], pretty_pcieid(buf(4, 2)), pretty_pcieid(buf(8, 2))
		))
		hdrtree:add(buf(8, 2), "Decoded requester:", pretty_pcieid(buf(8, 2)))
		hdrtree:add(p_tlp.fields.tag, buf(10, 1))

		local req_frame = req_to_frame[buf(8, 3):uint()]
		hdrtree:add(p_tlp.fields.req_frame, buf(8, 3), req_frame)
		reqframe_to_resframe[req_frame] = pkt.number

		hdrtree:add(p_tlp.fields.lower_addr, buf(11, 1))
	end

	data_dis:call(buf(4 * le, 4 * length):tvb(), pkt, tree)
	return (le + length) * 4
end

local p_dltlp = Proto("pcie.dltlp", "PCIe DL TLP")

p_dltlp.fields.seqno = ProtoField.uint16("pcie.dl.tlp_seqno", "Seq num", base.HEX, nil, 0x0FFF)
p_dltlp.fields.lcrc = ProtoField.uint32("pcie.dl.tlp_lcrc", "LCRC", base.HEX)

local dl_seq_to_frame = {}

local function dissect_dltlp(buf, pkt, tree)
	local dlhdr = buf(0, 2)
	local subtree = tree:add(p_dltlp, dlhdr)
	subtree:add(p_dltlp.fields.seqno, dlhdr)
	dl_seq_to_frame[bit.band(dlhdr:uint(), 0x0FFF)] = pkt.number
	local n = dissect_tlp(buf(2):tvb(), pkt, tree)
	subtree:add(p_dltlp.fields.lcrc, buf(2 + n, 4))
	return 6 + n
end

-------------------------------------------------------------------------
-- DLLP                                                                --
-------------------------------------------------------------------------
local p_dllp = Proto("pcie.dllp", "PCIe DLLP")

local dlltp_map = {
	{0x00, 0x00, "Ack"},
	{0x01, 0x01, "MRInit"},
	{0x02, 0x02, "Data_Link_Feature"},
	{0x10, 0x10, "Nak"},
	{0x20, 0x20, "PM_Enter_L1"},
	{0x21, 0x21, "PM_Enter_L23"},
	{0x23, 0x23, "PM_Active_State_Request_L1"},
	{0x24, 0x24, "PM_Request_Ack"},
	{0x30, 0x30, "Vendor-specific"},
	{0x31, 0x31, "NOP"},

	{0x40, 0x47, "InitFC1-P"},
	{0x50, 0x57, "InitFC1-NP"},
	{0x60, 0x67, "InitFC1-Cpl"},
	{0x70, 0x77, "MRInitFC1"},

	{0x80, 0x87, "UpdateFC-P"},
	{0x90, 0x97, "UpdateFC-NP"},
	{0xA0, 0xA7, "UpdateFC-Cpl"},
	{0xB0, 0xB7, "MRUpdateFC"},

	{0xC0, 0xC7, "InitFC2-P"},
	{0xD0, 0xD7, "InitFC2-NP"},
	{0xE0, 0xE7, "InitFC2-Cpl"},
	{0xF0, 0xF7, "MRInitFC2"},
}

p_dllp.fields.type = ProtoField.uint8("pcie.dllp.type", "Type", base.HEX + base.RANGE_STRING, dlltp_map)
p_dllp.fields.seq_num = ProtoField.uint24("pcie.dllp.seq_num", "Seq num", base.HEX, nil, 0x000FFF)
p_dllp.fields.tlp_frame = ProtoField.framenum("pcie.dllp.tlp_frame", "Acked frame", base.NONE, frametype.ACK)

p_dllp.fields.vcid = ProtoField.uint8("pcie.dllp.vcid", "VC ID", base.DEC, nil, 0x07)
p_dllp.fields.hdr_scale = ProtoField.uint24("pcie.dllp.hdr_scale", "Hdr scale", base.DEC, nil, 0xC00000)
p_dllp.fields.hdrfc = ProtoField.uint24("pcie.dllp.hdrfc", "HdrFC", base.HEX, nil, 0x3FC000)
p_dllp.fields.data_scale = ProtoField.uint24("pcie.dllp.data_scale", "Data scale", base.DEC, nil, 0x003000)
p_dllp.fields.datafc = ProtoField.uint24("pcie.dllp.datafc", "DataFC", base.HEX, nil, 0x000FFF)

p_dllp.fields.crc16 = ProtoField.uint16("pcie.dllp.crc16", "CRC16", base.HEX)

local function dissect_dllp(buf, pkt, tree)
	local subtree = tree:add(p_dllp, buf(0, 6))
	subtree:add(p_dllp.fields.type, buf(0, 1))
	-- local contents = subtree:add(buf(1, 3), "Contents")
	local tp = buf(0, 1):uint()
	local data = buf(1, 3)
	if bit.band(tp, 0xC0) ~= 0 and bit.band(tp, 0x08) == 0 then
		subtree:add(p_dllp.fields.vcid, buf(0, 1))
		subtree:add(p_dllp.fields.hdr_scale, data)
		subtree:add(p_dllp.fields.hdrfc, data)
		subtree:add(p_dllp.fields.data_scale, data)
		subtree:add(p_dllp.fields.datafc, data)
	elseif bit.band(tp, 0xEF) == 0 then
		subtree:add(p_dllp.fields.seq_num, data)
		local seq = bit.band(data:uint(), 0x000FFF)
		subtree:add(p_dllp.fields.tlp_frame, data, dl_seq_to_frame[seq])
	else
		data_dis:call(data:tvb(), pkt, subtree)
	end
	subtree:add(p_dllp.fields.crc16, buf(4, 2))
	return 6
end

-------------------------------------------------------------------------
-- PCIe                                                                --
-------------------------------------------------------------------------
-- local thrift_encap_table = DissectorTable.get("thrift.method_names")
local tcp_encap_table = DissectorTable.get("tcp.port")

local p_pcie = Proto("pcie", "PCIe/IP")

local pcie_protos = {
	[2] = "dllp",
	[3] = "tlp",
}

p_pcie.fields.proto = ProtoField.uint8("pcie.protocol", "Protocol", base.DEC, pcie_protos)

local protos = {
	[2] = dissect_dllp,
	[3] = dissect_dltlp,
}

function p_pcie.dissector(buf, pkt, tree)
	pkt.cols.protocol = "PCIe/IP"
	local subtree = tree:add(p_pcie, buf(0, 1))
	subtree:add(p_pcie.fields.proto, buf(0, 1))

	local proto_id = buf(0, 1):uint()
	local subdissector = protos[proto_id]
	if subdissector ~= nil then
		pkt.cols.info:set(pcie_protos[proto_id])
		subdissector(buf(1):tvb(), pkt, tree)
	else
		data_dis:call(buf(1):tvb(), pkt, tree)
	end
end

tcp_encap_table:add(2115, p_pcie)
