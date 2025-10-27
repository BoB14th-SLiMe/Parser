#include "PacketParser.h"
#include "./network/network_headers.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <ctime>
#include <memory>
#include <cstring>
#include <vector>
#include <tuple>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

// All protocol parser headers
#include "./protocols/ModbusParser.h"
#include "./protocols/S7CommParser.h"
#include "./protocols/XgtFenParser.h"
#include "./protocols/Dnp3Parser.h"
#include "./protocols/DnsParser.h"
#include "./protocols/GenericParser.h"
#include "./protocols/UnknownParser.h"
#include "./protocols/ArpParser.h"
#include "./protocols/TcpSessionParser.h"

static std::string mac_to_string_helper(const uint8_t* mac) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        ss << std::setw(2) << static_cast<int>(mac[i]) << (i < 5 ? ":" : "");
    }
    return ss.str();
}

static std::string format_timestamp(const struct timeval& ts) {
    char buf[sizeof "2011-10-08T07:07:09.000000Z"];
    char buft[sizeof "2011-10-08T07:07:09"];
    time_t sec = ts.tv_sec;
    struct tm gmt;

    #ifdef _WIN32
        gmtime_s(&gmt, &sec);
    #else
        gmtime_r(&sec, &gmt);
    #endif

    strftime(buft, sizeof buft, "%Y-%m-%dT%H:%M:%S", &gmt);
    snprintf(buf, sizeof buf, "%.*s.%06dZ", (int)sizeof(buft) - 1, buft, (int)ts.tv_usec);
    return std::string(buf);
}

PacketParser::PacketParser(const std::string& output_dir)
    : m_output_dir(output_dir),
      m_assetManager("assets/자산IP.csv", "assets/유선_Input.csv", "assets/유선_Output.csv") { 
    #ifdef _WIN32
        _mkdir(m_output_dir.c_str());
    #else
        mkdir(m_output_dir.c_str(), 0755);
    #endif

    m_protocol_parsers.push_back(std::make_unique<ArpParser>());
    m_protocol_parsers.push_back(std::make_unique<TcpSessionParser>());
    
    m_protocol_parsers.push_back(std::make_unique<ModbusParser>(m_assetManager));
    m_protocol_parsers.push_back(std::make_unique<S7CommParser>(m_assetManager));
    m_protocol_parsers.push_back(std::make_unique<XgtFenParser>(m_assetManager));
    m_protocol_parsers.push_back(std::unique_ptr<Dnp3Parser>(new Dnp3Parser()));
    m_protocol_parsers.push_back(std::make_unique<GenericParser>("dhcp"));
    m_protocol_parsers.push_back(std::unique_ptr<DnsParser>(new DnsParser()));
    m_protocol_parsers.push_back(std::make_unique<GenericParser>("ethernet_ip"));
    m_protocol_parsers.push_back(std::make_unique<GenericParser>("iec104"));
    m_protocol_parsers.push_back(std::make_unique<GenericParser>("mms"));
    m_protocol_parsers.push_back(std::make_unique<GenericParser>("opc_ua"));
    m_protocol_parsers.push_back(std::make_unique<GenericParser>("bacnet"));
    m_protocol_parsers.push_back(std::make_unique<UnknownParser>());

    for (const auto& parser : m_protocol_parsers) {
        initialize_output_streams(parser->getName());
        parser->setOutputStream(&m_output_streams[parser->getName()].jsonl_stream, &m_output_streams[parser->getName()].csv_stream);
    }
}

PacketParser::~PacketParser() {
    for (auto& pair : m_output_streams) {
        if (pair.second.jsonl_stream.is_open()) pair.second.jsonl_stream.close();
        if (pair.second.csv_stream.is_open()) pair.second.csv_stream.close();
    }
}

void PacketParser::initialize_output_streams(const std::string& protocol) {
    if (m_output_streams.find(protocol) == m_output_streams.end()) {
        FileStreams streams;
        std::string jsonl_filename = m_output_dir + "/" + protocol + ".jsonl";
        std::string csv_filename = m_output_dir + "/" + protocol + ".csv";
        
        streams.jsonl_stream.open(jsonl_filename, std::ios_base::trunc);
        streams.csv_stream.open(csv_filename, std::ios_base::trunc);

        if (!streams.jsonl_stream.is_open()) {
            std::cerr << "Error: Could not open output file " << jsonl_filename << std::endl;
        }
        if (!streams.csv_stream.is_open()) {
            std::cerr << "Error: Could not open output file " << csv_filename << std::endl;
        }
        m_output_streams[protocol] = std::move(streams);
    }
}

std::string PacketParser::get_canonical_flow_id(const std::string& ip1_str, uint16_t port1, const std::string& ip2_str, uint16_t port2) {
    std::string ip1 = ip1_str, ip2 = ip2_str;
    if (ip1 > ip2 || (ip1 == ip2 && port1 > port2)) {
        std::swap(ip1, ip2);
        std::swap(port1, port2);
    }
    return ip1 + ":" + std::to_string(port1) + "-" + ip2 + ":" + std::to_string(port2);
}

std::string PacketParser::escape_csv(const std::string& s) {
    if (s.find_first_of(",\"\n") == std::string::npos) {
        return s;
    }
    std::string result = "\"";
    for (char c : s) {
        if (c == '"') {
            result += "\"\"";
        } else {
            result += c;
        }
    }
    result += "\"";
    return result;
}

void PacketParser::parse(const struct pcap_pkthdr* header, const u_char* packet) {
    if (!packet || header->caplen < sizeof(EthernetHeader)) return;

    const EthernetHeader* eth_header = (const EthernetHeader*)(packet);
    uint16_t eth_type = ntohs(eth_header->eth_type);
    const u_char* l3_payload = packet + sizeof(EthernetHeader);
    int l3_payload_size = header->caplen - sizeof(EthernetHeader);

    std::string src_mac_str = mac_to_string_helper(eth_header->src_mac);
    std::string dst_mac_str = mac_to_string_helper(eth_header->dest_mac);

    // ARP 패킷 처리
    if (eth_type == 0x0806) {
        PacketInfo info;
        info.timestamp = format_timestamp(header->ts);
        info.src_mac = src_mac_str;
        info.dst_mac = dst_mac_str;
        info.eth_type = eth_type;
        info.payload = l3_payload;
        info.payload_size = l3_payload_size;

        for (const auto& parser : m_protocol_parsers) {
            if (parser->getName() == "arp") {
                parser->parse(info);
                break; // ARP는 단독 처리
            }
        }
        return;
    }

    // IPv4 패킷 처리
    if (eth_type == 0x0800) {
        if (l3_payload_size < sizeof(IPHeader)) return;
        const IPHeader* ip_header = (const IPHeader*)(l3_payload);
        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

        const u_char* l4_payload = l3_payload + (ip_header->hl * 4);
        int l4_payload_size = l3_payload_size - (ip_header->hl * 4);

        // TCP 패킷 처리
        if (ip_header->p == IPPROTO_TCP) {
            if (l4_payload_size < sizeof(TCPHeader)) return;
            const TCPHeader* tcp_header = (const TCPHeader*)(l4_payload);
            const u_char* l7_payload = l4_payload + (tcp_header->off * 4);
            int l7_payload_size = l4_payload_size - (tcp_header->off * 4);

            PacketInfo info;
            info.timestamp = format_timestamp(header->ts);
            info.src_mac = src_mac_str;
            info.dst_mac = dst_mac_str;
            info.eth_type = eth_type;
            info.src_ip = src_ip_str;
            info.dst_ip = dst_ip_str;
            info.src_port = ntohs(tcp_header->sport);
            info.dst_port = ntohs(tcp_header->dport);
            info.protocol = IPPROTO_TCP; // Set protocol for TCP
            info.tcp_seq = ntohl(tcp_header->seq);
            info.tcp_ack = ntohl(tcp_header->ack);
            info.tcp_flags = tcp_header->flags;
            info.payload = l7_payload;
            info.payload_size = l7_payload_size;
            info.flow_id = get_canonical_flow_id(info.src_ip, info.src_port, info.dst_ip, info.dst_port);

            bool handled_by_specific_app_parser = false;
            for (const auto& parser : m_protocol_parsers) {
                const auto& name = parser->getName();
                // tcp_session, unknown, arp는 여기서 처리하지 않음
                if (name == "tcp_session" || name == "unknown" || name == "arp") {
                    continue;
                }

                if (parser->isProtocol(info)) {
                    parser->parse(info);
                    handled_by_specific_app_parser = true;
                    break; // 특정 프로토콜이 파싱되면 더 이상 다른 파서 실행 안 함
                }
            }

            if (!handled_by_specific_app_parser) {
                // 특정 애플리케이션 프로토콜이 처리하지 않은 경우, tcp_session으로 처리
                for (const auto& parser : m_protocol_parsers) {
                    if (parser->getName() == "tcp_session") {
                        parser->parse(info);
                        break;
                    }
                }
            }
        }
        // UDP 패킷 처리
        else if (ip_header->p == IPPROTO_UDP) {
            if (l4_payload_size < sizeof(UDPHeader)) return;
            const UDPHeader* udp_header = (const UDPHeader*)(l4_payload);
            const u_char* l7_payload = l4_payload + sizeof(UDPHeader);
            int l7_payload_size = l4_payload_size - sizeof(UDPHeader);

            PacketInfo info;
            info.timestamp = format_timestamp(header->ts);
            info.src_mac = src_mac_str;
            info.dst_mac = dst_mac_str;
            info.eth_type = eth_type;
            info.src_ip = src_ip_str;
            info.dst_ip = dst_ip_str;
            info.src_port = ntohs(udp_header->sport);
            info.dst_port = ntohs(udp_header->dport);
            info.protocol = IPPROTO_UDP; // Set protocol for UDP
            info.payload = l7_payload;
            info.payload_size = l7_payload_size;
            info.flow_id = get_canonical_flow_id(info.src_ip, info.src_port, info.dst_ip, info.dst_port);

            // 2. 특정 애플리케이션 계층 프로토콜 파서 처리
            bool specific_app_protocol_found = false;
            for (const auto& parser : m_protocol_parsers) {
                const auto& name = parser->getName();
                // tcp_session, unknown, arp는 여기서 처리하지 않음
                if (name == "tcp_session" || name == "unknown" || name == "arp") {
                    continue;
                }

                if (parser->isProtocol(info)) {
                    parser->parse(info);
                    specific_app_protocol_found = true;
                    break; // 특정 프로토콜이 파싱되면 더 이상 다른 파서 실행 안 함
                }
            }

            // 3. 특정 애플리케이션 계층 프로토콜이 파싱되지 않았을 때만 UnknownParser 실행
            if (!specific_app_protocol_found) {
                for (const auto& parser : m_protocol_parsers) {
                    if (parser->getName() == "unknown") {
                        parser->parse(info);
                        break;
                    }
                }
            }
        }
    }
}