#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <fstream>
#include <string>
#include <map>
#include <set>
#include <chrono>

// 통신 흐름 프로파일링을 위한 구조체
struct ProtocolProfile {
    long packet_count = 0;
    long total_bytes = 0;
};

// 요청 패킷의 정보를 저장할 구조체
struct RequestInfo {
    std::string request_payload;
    std::chrono::steady_clock::time_point timestamp; // 요청 수신 시간 기록
    std::string protocol;
};


class PacketParser {
public:
    PacketParser(const std::string& output_dir = "output/");
    ~PacketParser();
    // pcap_pkthdr를 받아 패킷의 수신 시간을 알 수 있도록 함
    void parse(const struct pcap_pkthdr* header, const u_char* packet);
    void save_profiles();

private:
    std::string m_output_dir;
    std::map<std::string, std::ofstream> m_file_streams;
    std::map<std::string, ProtocolProfile> m_profiles;

    // 매핑된 결과를 저장할 파일 스트림
    std::ofstream m_mapped_stream;
    
    // 타임아웃 시간 설정 (밀리초 단위)
    const std::chrono::milliseconds m_timeout;

    // (수정) 프로토콜별로 매핑된 결과 파일을 관리하는 맵
    std::map<std::string, std::ofstream> m_mapped_protocol_streams;

    std::map<std::string, std::map<uint32_t, RequestInfo>> m_pending_requests;

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
    
    // 네트워크 관리 프로토콜 DPI 헬퍼 함수들
    bool is_dhcp_signature(const u_char* payload, int size);
    bool is_dns_signature(const u_char* payload, int size);

    // --- 유틸리티 함수들 ---
    std::string format_payload_to_hex(const u_char* payload, int size);
    std::ofstream& get_file_stream(const std::string& protocol);
    std::string get_canonical_flow_id(const std::string& ip1, uint16_t port1, const std::string& ip2, uint16_t port2);
    

    std::ofstream& get_mapped_stream(const std::string& protocol);
};

#endif // PACKET_PARSER_H