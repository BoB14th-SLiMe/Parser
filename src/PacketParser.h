#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <map>
#ifndef _WIN32
#include <sys/time.h>
#endif
#include "./protocols/IProtocolParser.h"
#include "./protocols/ArpParser.h"
#include "./protocols/TcpSessionParser.h"
#include "AssetManager.h" // AssetManager 포함

// JSONL과 CSV 파일 스트림을 함께 관리하기 위한 구조체
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
    std::map<std::string, FileStreams> m_output_streams;
    
    AssetManager m_assetManager; // AssetManager 멤버

    std::vector<std::unique_ptr<IProtocolParser>> m_protocol_parsers;
    

    std::map<std::string, struct timeval> m_flow_start_times;

    std::string get_canonical_flow_id(const std::string& ip1, uint16_t port1, const std::string& ip2, uint16_t port2);
    void initialize_output_streams(const std::string& protocol);
    
    std::string escape_csv(const std::string& s);
};

#endif // PACKET_PARSER_H
