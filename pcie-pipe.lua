-------------------------------------------------------------------------
-- TLP                                                                 --
-------------------------------------------------------------------------
p_dltlp = Proto("pcie.dltlp", "PCIe DL TLP")

function dissect_dltlp(buf, pkt, tree)
	local subtree = tree:add(p_dltlp, buf(0, 2))
	subtree:add(buf(0, 1), "first byte")
end

-------------------------------------------------------------------------
-- DLLP                                                                --
-------------------------------------------------------------------------
p_dllp = Proto("pcie.dllp", "PCIe DLLP")

local f_dllp_type = ProtoField.uint8("pcie.dllp.type", "Type", base.HEX)
local f_dllp_crc16 = ProtoField.uint8("pcie.dllp.crc16", "CRC16", base.HEX)

p_dllp.fields = { f_dllp_type, f_dllp_crc16 }

function dissect_dllp(buf, pkt, tree)
	local subtree = tree:add(p_dllp, buf(0, 6))
	subtree:add(f_dllp_type, buf(0, 1))
	local contents = subtree:add(buf(1, 3), "Contents")
	subtree:add(f_dllp_crc16, buf(4, 2))
end

-------------------------------------------------------------------------
-- PCIe                                                                --
-------------------------------------------------------------------------

local thrift_encap_table = DissectorTable.get("thrift.method_names")
local tcp_encap_table = DissectorTable.get("tcp.port")

p_pcie = Proto("pcie", "PCIe/IP")

local pcie_protos = {
	[2] = "dllp",
	[3] = "tlp",
}

local f_proto = ProtoField.uint8("pcie.protocol", "Protocol", base.DEC, pcie_protos)
-- local f_data = ProtoField.text("pcie.data", "Data", base.DEC, pcie_protos)

p_pcie.fields = { f_proto }

local data_dis = Dissector.get("data")

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
