#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <map>
#include <sys/time.h>
#include "./protocols/IProtocolParser.h"
#include "./protocols/ArpParser.h"
#include "./protocols/TcpSessionParser.h" // TcpSessionParser 헤더 포함

class PacketParser {
public:
    PacketParser(const std::string& output_dir = "output/");
    ~PacketParser();
    void parse(const struct pcap_pkthdr* header, const u_char* packet);

private:
    std::string m_output_dir;
    std::map<std::string, std::ofstream> m_output_streams;
    
    // IP 기반 프로토콜 파서 목록 (IProtocolParser 상속)
    std::vector<std::unique_ptr<IProtocolParser>> m_protocol_parsers;
    // 독립적인 파서들
    std::unique_ptr<ArpParser> m_arp_parser;
    std::unique_ptr<TcpSessionParser> m_tcp_session_parser;

    // 세션별 시작 시간을 기록하기 위한 맵
    std::map<std::string, struct timeval> m_flow_start_times;

    std::string get_canonical_flow_id(const std::string& ip1, uint16_t port1, const std::string& ip2, uint16_t port2);
    void initialize_output_stream(const std::string& protocol);
};

#endif // PACKET_PARSER_H

