#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <fstream>
#include <string>
#include <map>
#include <chrono>
#include <vector>

// Wireshark의 'modbus_request_info_t'와 유사한 구조체.
// 응답을 파싱하는 데 필요한 요청의 핵심 정보를 저장합니다.
struct ModbusRequestInfo {
    uint16_t transaction_id = 0;
    uint8_t function_code = 0;
    uint16_t start_address = 0;
    uint16_t quantity = 0;
};

// 대기 중인 요청의 전체 정보를 담는 구조체
struct RequestInfo {
    std::string protocol;
    std::chrono::steady_clock::time_point timestamp;
    ModbusRequestInfo modbus_info; // Modbus 요청의 상세 정보
};

class PacketParser {
public:
    PacketParser(const std::string& output_dir = "output/");
    ~PacketParser();
    void parse(const struct pcap_pkthdr* header, const u_char* packet);

private:
    std::string m_output_dir;
    const std::chrono::milliseconds m_timeout;
    std::map<std::string, std::ofstream> m_mapped_protocol_streams;
    // (구조 변경) Key: flow_id, Value: <Transaction ID, RequestInfo>
    // ACK 번호 대신 Transaction ID로 요청을 직접 찾도록 변경
    std::map<std::string, std::map<uint16_t, RequestInfo>> m_pending_requests_modbus;


    bool is_modbus_signature(const u_char* payload, int size);
    std::string get_canonical_flow_id(const std::string& ip1, uint16_t port1, const std::string& ip2, uint16_t port2);
    std::ofstream& get_mapped_stream(const std::string& protocol);

    // Wireshark 로직을 기반으로 재작성된 파싱 헬퍼 함수
    std::string parse_modbus_pdu(const u_char* pdu, int pdu_len, bool is_request, const ModbusRequestInfo* req_info);
};

#endif // PACKET_PARSER_H

