local data_dis = Dissector.get("data")

-------------------------------------------------------------------------
-- TLP                                                                 --
-------------------------------------------------------------------------
p_tlp = Proto("pcie.tlp", "PCIe TLP")

local fmttp_class = {
	[0x00] = "MRd: Memory Read Request",
	[0x20] = "MRd: Memory Read Request",
	[0x40] = "MWr: Memory Write Request",
	[0x60] = "MWr: Memory Write Request",
	[0x02] = "IORd: I/O Read Request",
	[0x42] = "IOWr: I/O Write Request",
}

local f_tlp_fmttp = ProtoField.uint8("pcie.tlp.fmttp", "TLP Type", base.HEX, fmttp_class)
local f_tlp_type  = ProtoField.uint8("pcie.tlp.type", "Type",  base.BIN, NULL, 0x1F)
local f_tlp_fmt   = ProtoField.uint8("pcie.tlp.fmt", "Fmt",    base.BIN, NULL, 0xE0)
local f_tlp_type  = ProtoField.uint8("pcie.tlp.type", "Type",  base.BIN, NULL, 0x1F)
local f_tlp_h1    = ProtoField.uint24("pcie.tlp.h1", "Header", base.HEX)
local f_tlp_t9    = ProtoField.uint24("pcie.tlp.t9", "T9",     base.DEC, NULL, 0x00800000)
local f_tlp_tc    = ProtoField.uint24("pcie.tlp.tc", "TC",     base.DEC, NULL, 0x00700000)
local f_tlp_t8    = ProtoField.uint24("pcie.tlp.t8", "T8",     base.DEC, NULL, 0x00080000)
local f_tlp_attr  = ProtoField.uint24("pcie.tlp.attr", "Attr", base.BIN, NULL, 0x00043000)
local f_tlp_ln    = ProtoField.uint24("pcie.tlp.ln", "LN",     base.DEC, NULL, 0x00020000)
local f_tlp_th    = ProtoField.uint24("pcie.tlp.th", "TH",     base.DEC, NULL, 0x00010000)
local f_tlp_td    = ProtoField.uint24("pcie.tlp.td", "TD",     base.DEC, NULL, 0x00008000)
local f_tlp_ep    = ProtoField.uint24("pcie.tlp.ep", "EP",     base.DEC, NULL, 0x00004000)
local f_tlp_at    = ProtoField.uint24("pcie.tlp.at", "AT",     base.BIN, NULL, 0x00000C00)
local f_tlp_length = ProtoField.uint24("pcie.tlp.length", "Length", base.DEC, NULL, 0x3FF)
local f_tlp_addr  = ProtoField.uint64("pcie.tlp.addr", "Address", base.HEX)

p_tlp.fields = { f_tlp_fmttp, f_tlp_fmt, f_tlp_type, f_tlp_h1, f_tlp_t9, f_tlp_tc, f_tlp_t8, f_tlp_attr, f_tlp_ln, f_tlp_th, f_tlp_td, f_tlp_ep, f_tlp_at, f_tlp_length, f_tlp_addr }

function dissect_tlp(buf, pkt, tree)
	local fmt = bit.rshift(buf(0, 1):uint(), 5)
	local le = 3 + bit.band(fmt, 1)
	local hdrtree = tree:add(p_tlp, buf(0, le * 4))
	local h0 = buf(0, 1)
	local tptree = hdrtree:add(f_tlp_fmttp, h0)
	tptree:add(f_tlp_fmt, h0)
	tptree:add(f_tlp_type, h0)
	local h1 = buf(1, 3)
	local h1tree = hdrtree:add(f_tlp_h1, h1)
	h1tree:add(f_tlp_t9, h1)
	h1tree:add(f_tlp_tc, h1)
	h1tree:add(f_tlp_t8, h1)
	h1tree:add(f_tlp_attr, h1)
	h1tree:add(f_tlp_ln, h1)
	h1tree:add(f_tlp_th, h1)
	h1tree:add(f_tlp_td, h1)
	h1tree:add(f_tlp_ep, h1)
	h1tree:add(f_tlp_at, h1)
	h1tree:add(f_tlp_length, h1)
	local length = bit.band(buf(2, 2):uint() - 1, 0x3FF) + 1
	if bit.band(fmt, 2) == 0 then
		length = 0
	end
	local addr = buf(8, 4)
	if le == 4 then
		addr = buf(8, 8)
	end
	hdrtree:add(f_tlp_addr, addr)
	data_dis:call(buf(4 * le, 4 * length):tvb(), pkt, tree)
	return (le + length) * 4
end

p_dltlp = Proto("pcie.dltlp", "PCIe DL TLP")

local f_dltlp_seqno = ProtoField.uint16("pcie.dl.tlp_seqno", "Type", base.HEX, NULL, 0x0FFF)
local f_dltlp_lcrc = ProtoField.uint32("pcie.dl.tlp_lcrc", "LCRC", base.HEX)

p_dltlp.fields = { f_dltlp_seqno, f_dltlp_lcrc }

function dissect_dltlp(buf, pkt, tree)
	local subtree = tree:add(p_dltlp, buf(0, 2))
	subtree:add(f_dltlp_seqno, buf(0, 2))
	local n = dissect_tlp(buf(2):tvb(), pkt, tree)
	subtree:add(f_dltlp_lcrc, buf(2 + n, 4))
	return 6 + n
end

-------------------------------------------------------------------------
-- DLLP                                                                --
-------------------------------------------------------------------------
p_dllp = Proto("pcie.dllp", "PCIe DLLP")

local f_dllp_type = ProtoField.uint8("pcie.dllp.type", "Type", base.HEX)
local f_dllp_crc16 = ProtoField.uint16("pcie.dllp.crc16", "CRC16", base.HEX)

p_dllp.fields = { f_dllp_type, f_dllp_crc16 }

function dissect_dllp(buf, pkt, tree)
	local subtree = tree:add(p_dllp, buf(0, 6))
	subtree:add(f_dllp_type, buf(0, 1))
	local contents = subtree:add(buf(1, 3), "Contents")
	subtree:add(f_dllp_crc16, buf(4, 2))
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

local f_proto = ProtoField.uint8("pcie.protocol", "Protocol", base.DEC, pcie_protos)
-- local f_data = ProtoField.text("pcie.data", "Data", base.DEC, pcie_protos)

p_pcie.fields = { f_proto }

local protos = {
	[2] = dissect_dllp,
	[3] = dissect_dltlp,
}

function p_pcie.dissector(buf, pkt, tree)
	pkt.cols.protocol = "PCIe/IP"
	local subtree = tree:add(p_pcie, buf(0, 1))
	subtree:add(f_proto, buf(0,1))

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
