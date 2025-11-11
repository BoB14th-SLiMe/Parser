#include "GenericParser.h"
#include "../UnifiedWriter.h"  // ← 추가!
#include <sstream>

GenericParser::GenericParser(const std::string& name) : m_name(name) {}
GenericParser::~GenericParser() {}

std::string GenericParser::getName() const {
    return m_name;
}

bool GenericParser::isProtocol(const PacketInfo& info) const {
    if (info.protocol == 6) {  // TCP
        if (m_name == "ethernet_ip") return info.src_port == 44818 || info.dst_port == 44818;
        if (m_name == "iec104") return info.src_port == 2404 || info.dst_port == 2404;
        if (m_name == "mms") return info.src_port == 102 || info.dst_port == 102;
        if (m_name == "opc_ua") return info.src_port == 4840 || info.dst_port == 4840;
    }
    else if (info.protocol == 17) {  // UDP
        if (m_name == "dhcp") return info.src_port == 67 || info.dst_port == 67 || 
                                       info.src_port == 68 || info.dst_port == 68;
        if (m_name == "bacnet") return info.src_port == 47808 || info.dst_port == 47808;
    }
    return false;
}

void GenericParser::parse(const PacketInfo& info) {
    std::string direction = "unknown";
    
    UnifiedRecord record = createUnifiedRecord(info, direction);
    record.len = std::to_string(info.payload_size);
    
    std::stringstream details_ss;
    details_ss << R"({"len":)" << info.payload_size << "}";
    record.details_json = details_ss.str();
    
    addUnifiedRecord(record);
}