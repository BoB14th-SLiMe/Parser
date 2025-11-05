#include "BaseProtocolParser.h"
#include <sstream>
#include <iomanip>
#include <iostream>

std::string BaseProtocolParser::mac_to_string(const uint8_t* mac) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        ss << std::setw(2) << static_cast<int>(mac[i]) << (i < 5 ? ":" : "");
    }
    return ss.str();
}

BaseProtocolParser::~BaseProtocolParser() {}

std::string BaseProtocolParser::escape_csv(const std::string& s) {
    if (s.find_first_of(",\"\n") == std::string::npos) {
        return s;
    }
    std::string result = "\"";
    for (char c : s) {
        if (c == '"') {
            result += "\"\"";
        } else {
            result += c;
        }
    }
    result += "\"";
    return result;
}

UnifiedRecord BaseProtocolParser::createUnifiedRecord(const PacketInfo& info, const std::string& direction) {
    UnifiedRecord record;
    record.timestamp = info.timestamp;
    record.protocol = getName();
    record.smac = info.src_mac;
    record.dmac = info.dst_mac;
    record.sip = info.src_ip;
    record.sp = std::to_string(info.src_port);
    record.dip = info.dst_ip;
    record.dp = std::to_string(info.dst_port);
    record.sq = std::to_string(info.tcp_seq);
    record.ak = std::to_string(info.tcp_ack);
    record.fl = std::to_string((int)info.tcp_flags);
    record.dir = direction;
    return record;
}

void BaseProtocolParser::addUnifiedRecord(const UnifiedRecord& record) {
    if (m_unified_writer) {
        m_unified_writer->addRecord(record);
    }
}