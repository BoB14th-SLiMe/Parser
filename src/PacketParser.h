#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <fstream>
#include <string>
#include <map>
#include <set>
#include <chrono>

struct ProtocolProfile {
    long packet_count = 0;
    long total_bytes = 0;
};

// 파싱된 Modbus 정보를 담는 구조체. MBAP 헤더 + 요약 정보.
struct ModbusInfo {
    uint16_t transaction_id = 0;
    uint16_t protocol_id = 0;
    uint16_t length = 0;
    uint8_t unit_id = 0;
    std::string details;
};

// 요청 정보를 담는 구조체
struct RequestInfo {
    std::string protocol;
    std::chrono::steady_clock::time_point timestamp;
    ModbusInfo modbus_info; // Modbus 파싱 결과 저장
    std::string generic_payload;
};

class PacketParser {
public:
    PacketParser(const std::string& output_dir = "output/");
    ~PacketParser();
    void parse(const struct pcap_pkthdr* header, const u_char* packet);
    void save_profiles();

private:
    std::string m_output_dir;
    std::map<std::string, std::ofstream> m_file_streams;
    std::map<std::string, ProtocolProfile> m_profiles;
    const std::chrono::milliseconds m_timeout;
    std::map<std::string, std::ofstream> m_mapped_protocol_streams;
    std::map<std::string, std::map<uint32_t, RequestInfo>> m_pending_requests;

    bool is_modbus_signature(const u_char* payload, int size);
    bool is_s7_signature(const u_char* payload, int size);

    std::string format_payload_to_hex(const u_char* payload, int size);
    std::string get_canonical_flow_id(const std::string& ip1, uint16_t port1, const std::string& ip2, uint16_t port2);
    std::ofstream& get_mapped_stream(const std::string& protocol);
    ModbusInfo parse_modbus_payload(const u_char* payload, int payload_size, bool is_request);
};

#endif // PACKET_PARSER_H

