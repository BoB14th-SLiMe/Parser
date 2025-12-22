#include "BaseProtocolParser.h"
#include "../UnifiedWriter.h"
#include "../AssetManager.h"
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
    if (s.empty()) return "";
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

    // For UDP packets, set sq/ak/fl to 0 (to match wireshark_parser)
    if (info.protocol == 17) {  // IPPROTO_UDP
        record.sq = "0";
        record.ak = "0";
        record.fl = "0";
    } else {
        // Use relative sequence/ack numbers for TCP packets
        record.sq = std::to_string(info.tcp_relative_seq);
        record.ak = std::to_string(info.tcp_relative_ack);

        // TCP flags를 16진수로 출력 (Python과 일치: 0x0018 형식)
        std::stringstream ss_flags;
        ss_flags << "0x" << std::setfill('0') << std::setw(4) << std::hex << static_cast<int>(info.tcp_flags);
        record.fl = ss_flags.str();
    }

    record.dir = direction;

    // 자산 정보 추가 - Python과 일치 (src_asset, dst_asset만)
    if (m_asset_manager) {
        std::string src_device = m_asset_manager->getDeviceName(info.src_ip);
        std::string dst_device = m_asset_manager->getDeviceName(info.dst_ip);

        if (!src_device.empty()) {
            record.src_asset = src_device;
        }
        if (!dst_device.empty()) {
            record.dst_asset = dst_device;
        }
    }

    return record;
}

void BaseProtocolParser::addUnifiedRecord(const UnifiedRecord& record) {
    // 파일 출력
    if (m_unified_writer) {
        m_unified_writer->addRecord(record);
    }
    
    // 또는 직접 백엔드 전송
    if (m_direct_backend_callback) {
        m_direct_backend_callback(record);
    }
}