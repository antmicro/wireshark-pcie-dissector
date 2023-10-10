local data_dis = Dissector.get("data")

-------------------------------------------------------------------------
-- TLP                                                                 --
-------------------------------------------------------------------------
p_tlp = Proto("pcie.tlp", "PCIe TLP")

local fmttp_map = {
	[0x00] = "MRd: Memory Read Request",
	[0x20] = "MRd: Memory Read Request",
	[0x40] = "MWr: Memory Write Request",
	[0x60] = "MWr: Memory Write Request",
	[0x02] = "IORd: I/O Read Request",
	[0x42] = "IOWr: I/O Write Request",
	[0x0A] = "Cpl: Completion without Data",
	[0x4A] = "CplD: Completion with Data",
}

p_tlp.fields.fmttp = ProtoField.uint8("pcie.tlp.fmttp", "TLP Type", base.HEX, fmttp_map)
p_tlp.fields.type  = ProtoField.uint8("pcie.tlp.type", "Type",  base.BIN, NULL, 0x1F)
p_tlp.fields.fmt   = ProtoField.uint8("pcie.tlp.fmt", "Fmt",    base.BIN, NULL, 0xE0, "Format")
p_tlp.fields.h1    = ProtoField.uint24("pcie.tlp.h1", "Header", base.HEX)
p_tlp.fields.t9    = ProtoField.uint24("pcie.tlp.t9", "T9",     base.DEC, NULL, 0x00800000)
p_tlp.fields.tc    = ProtoField.uint24("pcie.tlp.tc", "TC",     base.DEC, NULL, 0x00700000, "Traffic class")
p_tlp.fields.t8    = ProtoField.uint24("pcie.tlp.t8", "T8",     base.DEC, NULL, 0x00080000)
p_tlp.fields.attr  = ProtoField.uint24("pcie.tlp.attr", "Attr", base.BIN, NULL, 0x00043000, "Attributes")
p_tlp.fields.ln    = ProtoField.uint24("pcie.tlp.ln", "LN",     base.DEC, NULL, 0x00020000, "Lightweight notification")
p_tlp.fields.th    = ProtoField.uint24("pcie.tlp.th", "TH",     base.DEC, NULL, 0x00010000, "TLP Hints")
p_tlp.fields.td    = ProtoField.uint24("pcie.tlp.td", "TD",     base.DEC, NULL, 0x00008000, "TLP Digest")
p_tlp.fields.ep    = ProtoField.uint24("pcie.tlp.ep", "EP",     base.DEC, NULL, 0x00004000, "Error poisoned")
p_tlp.fields.at    = ProtoField.uint24("pcie.tlp.at", "AT",     base.BIN, NULL, 0x00000C00)
p_tlp.fields.len_value = ProtoField.uint24("pcie.tlp.len_value", "Length", base.DEC, NULL, 0x3FF, "Length from TLP header")
p_tlp.fields.length = ProtoField.uint16("pcie.tlp.length", "Calculated length", base.DEC, NULL, NULL, "Calculated TLP packet payload length")
p_tlp.fields.addr  = ProtoField.uint64("pcie.tlp.addr", "Address", base.HEX)

function dissect_tlp(buf, pkt, tree)
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
		length = 0
	end
	local addr = buf(8, 4)
	if le == 4 then
		addr = buf(8, 8)
	end
	hdrtree:add(p_tlp.fields.addr, addr)
	data_dis:call(buf(4 * le, 4 * length):tvb(), pkt, tree)
	return (le + length) * 4
end

p_dltlp = Proto("pcie.dltlp", "PCIe DL TLP")

p_dltlp.fields.seqno = ProtoField.uint16("pcie.dl.tlp_seqno", "Type", base.HEX, NULL, 0x0FFF)
p_dltlp.fields.lcrc = ProtoField.uint32("pcie.dl.tlp_lcrc", "LCRC", base.HEX)

function dissect_dltlp(buf, pkt, tree)
	local subtree = tree:add(p_dltlp, buf(0, 2))
	subtree:add(p_dltlp.fields.seqno, buf(0, 2))
	local n = dissect_tlp(buf(2):tvb(), pkt, tree)
	subtree:add(p_dltlp.fields.lcrc, buf(2 + n, 4))
	return 6 + n
end

-------------------------------------------------------------------------
-- DLLP                                                                --
-------------------------------------------------------------------------
p_dllp = Proto("pcie.dllp", "PCIe DLLP")

p_dllp.fields.type = ProtoField.uint8("pcie.dllp.type", "Type", base.HEX)
p_dllp.fields.crc16 = ProtoField.uint16("pcie.dllp.crc16", "CRC16", base.HEX)

function dissect_dllp(buf, pkt, tree)
	local subtree = tree:add(p_dllp, buf(0, 6))
	subtree:add(p_dllp.fields.type, buf(0, 1))
	local contents = subtree:add(buf(1, 3), "Contents")
	subtree:add(p_dllp.fields.crc16, buf(4, 2))
	return 6
end

-------------------------------------------------------------------------
-- PCIe                                                                --
-------------------------------------------------------------------------
-- local thrift_encap_table = DissectorTable.get("thrift.method_names")
local tcp_encap_table = DissectorTable.get("tcp.port")

p_pcie = Proto("pcie", "PCIe/IP")

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
	subtree:add(p_pcie.fields.proto, buf(0,1))

	local proto_id = buf(0,1):uint()
	local subdissector = protos[proto_id]
	if subdissector ~= nil then
		pkt.cols.info:set(pcie_protos[proto_id])
		subdissector(buf(1):tvb(), pkt, tree)
	else
		data_dis:call(buf(1):tvb(), pkt, tree)
	end
end

tcp_encap_table:add(2115, p_pcie)
