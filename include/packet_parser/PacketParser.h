#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <fstream>
#include <string>
#include <map>
#include <set>

// 통신 흐름 프로파일링을 위한 구조체
struct ProtocolProfile {
    long packet_count = 0;
    long total_bytes = 0;
};

class PacketParser {
public:
    PacketParser(const std::string& output_dir = "output/");
    ~PacketParser();
    void parse(const u_char* packet, int packet_len);
    void save_profiles();

private:
    std::string m_output_dir;
    std::map<std::string, std::ofstream> m_file_streams;
    std::map<std::string, ProtocolProfile> m_profiles;

    // --- OT 프로토콜 DPI 헬퍼 함수들 ---
    bool is_modbus_signature(const u_char* payload, int size);
    bool is_dnp3_signature(const u_char* payload, int size);
    bool is_s7_signature(const u_char* payload, int size);
    bool is_mms_signature(const u_char* payload, int size);
    bool is_ethernet_ip_signature(const u_char* payload, int size);
    bool is_iec104_signature(const u_char* payload, int size);
    bool is_opcua_signature(const u_char* payload, int size);
    bool is_bacnet_signature(const u_char* payload, int size);
    bool is_ls_xgt_signature(const u_char* payload, int size);
    
    // (핵심 추가) 네트워크 관리 프로토콜 DPI 헬퍼 함수들
    bool is_dhcp_signature(const u_char* payload, int size);
    bool is_dns_signature(const u_char* payload, int size);


    // --- 유틸리티 함수들 ---
    std::string format_payload_to_hex(const u_char* payload, int size);
    std::ofstream& get_file_stream(const std::string& protocol);
};

#endif // PACKET_PARSER_H

