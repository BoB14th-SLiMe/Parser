#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <map>
// Windows에서는 pcap.h가 timeval을 정의하므로, sys/time.h는 비-Windows 환경에서만 포함합니다.
#ifndef _WIN32
#include <sys/time.h>
#endif
#include "./protocols/IProtocolParser.h"
#include "./protocols/ArpParser.h"
#include "./protocols/TcpSessionParser.h"

// --- 수정: JSONL과 CSV 파일 스트림을 함께 관리하기 위한 구조체 ---
struct FileStreams {
    std::ofstream jsonl_stream;
    std::ofstream csv_stream;
};

class PacketParser {
public:
    PacketParser(const std::string& output_dir = "output/");
    ~PacketParser();
    void parse(const struct pcap_pkthdr* header, const u_char* packet);

private:
    std::string m_output_dir;
    // --- 수정: FileStreams 구조체를 사용하도록 맵 타입 변경 ---
    std::map<std::string, FileStreams> m_output_streams;
    
    std::vector<std::unique_ptr<IProtocolParser>> m_protocol_parsers;
    std::unique_ptr<ArpParser> m_arp_parser;
    std::unique_ptr<TcpSessionParser> m_tcp_session_parser;

    std::map<std::string, struct timeval> m_flow_start_times;

    std::string get_canonical_flow_id(const std::string& ip1, uint16_t port1, const std::string& ip2, uint16_t port2);
    // --- 추가: 누락된 함수 선언 ---
    void initialize_output_streams(const std::string& protocol);
};

#endif // PACKET_PARSER_H

