#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <fstream>
#include <string>
#include <map>
#include <chrono>
#include <vector>

// --- Modbus Structures ---
struct ModbusRequestInfo {
    uint16_t transaction_id = 0;
    uint8_t function_code = 0;
    uint16_t start_address = 0;
    uint16_t quantity = 0;
};

// --- S7comm Structures ---
struct S7CommItem {
    uint8_t transport_size = 0;
    uint16_t length = 0;
    uint16_t db_number = 0;
    uint8_t area = 0;
    uint32_t address = 0;
};

struct S7CommRequestInfo {
    uint16_t pdu_ref = 0;
    uint8_t function_code = 0;
    std::vector<S7CommItem> items;
};

// --- General RequestInfo ---
struct RequestInfo {
    std::string protocol;
    std::chrono::steady_clock::time_point timestamp;
    ModbusRequestInfo modbus_info;
    S7CommRequestInfo s7comm_info;
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
    
    // Protocol-specific pending requests
    std::map<std::string, std::map<uint16_t, RequestInfo>> m_pending_requests_modbus;
    std::map<std::string, std::map<uint16_t, RequestInfo>> m_pending_requests_s7comm;


    bool is_modbus_signature(const u_char* payload, int size);
    bool is_s7comm_signature(const u_char* payload, int size);

    std::string get_canonical_flow_id(const std::string& ip1, uint16_t port1, const std::string& ip2, uint16_t port2);
    std::ofstream& get_mapped_stream(const std::string& protocol);

    // Protocol-specific parsers
    std::string parse_modbus_pdu(const u_char* pdu, int pdu_len, bool is_request, const ModbusRequestInfo* req_info);
    std::string parse_s7comm_pdu(const u_char* pdu, int pdu_len, bool is_request, const S7CommRequestInfo* req_info);
};

#endif // PACKET_PARSER_H

