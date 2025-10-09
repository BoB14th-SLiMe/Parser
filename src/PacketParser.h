#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <map>
#include "./protocols/IProtocolParser.h" // 새로운 인터페이스 포함

class PacketParser {
public:
    PacketParser(const std::string& output_dir = "output/");
    ~PacketParser();
    void parse(const struct pcap_pkthdr* header, const u_char* packet);

private:
    std::string m_output_dir;
    
    // 프로토콜 이름을 키로 사용하는 파일 스트림 맵
    std::map<std::string, std::ofstream> m_output_streams;

    // 사용 가능한 모든 프로토콜 파서 목록
    std::vector<std::unique_ptr<IProtocolParser>> m_protocol_parsers;

    std::string get_canonical_flow_id(const std::string& ip1, uint16_t port1, const std::string& ip2, uint16_t port2);
    void initialize_output_stream(const std::string& protocol);
};

#endif // PACKET_PARSER_H
