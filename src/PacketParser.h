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
#include "./protocols/TcpSessionParser.h"

class PacketParser {
public:
    PacketParser(const std::string& output_dir = "output/");
    ~PacketParser();
    void parse(const struct pcap_pkthdr* header, const u_char* packet);

private:
    std::string m_output_dir;
    // .jsonl과 .csv 출력을 위한 별도의 파일 스트림
    std::map<std::string, std::ofstream> m_json_streams;
    std::map<std::string, std::ofstream> m_csv_streams;
    
    std::vector<std::unique_ptr<IProtocolParser>> m_protocol_parsers;
    std::unique_ptr<ArpParser> m_arp_parser;
    std::unique_ptr<TcpSessionParser> m_tcp_session_parser;

    std::map<std::string, struct timeval> m_flow_start_times;

    std::string get_canonical_flow_id(const std::string& ip1, uint16_t port1, const std::string& ip2, uint16_t port2);
    // CSV 헤더를 쓰기 위한 함수 시그니처 수정
    void initialize_output_stream(const std::string& protocol, const std::string& csv_header);
};

#endif // PACKET_PARSER_H

