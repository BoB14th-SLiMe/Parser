#include "PacketParser.h"
#include "./network/network_headers.h"
#include <iostream>
#include <netinet/in.h>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <algorithm>
#include <ctime>
#include <memory>
#include <cstring>
#include <time.h>

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

// Helper function to format timestamp to ISO 8601
static std::string format_timestamp(const struct timeval& ts) {
    char buf[sizeof "2011-10-08T07:07:09.123456Z"];
    char buft[sizeof "2011-10-08T07:07:09Z"];
    struct tm t;
    gmtime_r(&ts.tv_sec, &t);
    strftime(buft, sizeof buft, "%Y-%m-%dT%H:%M:%SZ", &t);
    // --- MODIFICATION: Cast ts.tv_usec to long to fix format warning ---
    snprintf(buf, sizeof buf, "%.*s.%06ldZ", (int)sizeof(buft) - 2, buft, (long)ts.tv_usec);
    return buf;
}

// Helper function for CSV escaping
static std::string escape_csv(const std::string& s) {
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

PacketParser::PacketParser(const std::string& output_dir)
    : m_output_dir(output_dir) {
    mkdir(m_output_dir.c_str(), 0755);

    m_arp_parser = std::unique_ptr<ArpParser>(new ArpParser());
    m_tcp_session_parser = std::unique_ptr<TcpSessionParser>(new TcpSessionParser());
    initialize_output_stream("arp", "@timestamp,d");
    initialize_output_stream("tcp_session", "@timestamp,sip,sp,dip,dp,d");
    
    m_protocol_parsers.push_back(std::unique_ptr<ModbusParser>(new ModbusParser()));
    m_protocol_parsers.push_back(std::unique_ptr<S7CommParser>(new S7CommParser()));
    m_protocol_parsers.push_back(std::unique_ptr<XgtFenParser>(new XgtFenParser()));
    m_protocol_parsers.push_back(std::unique_ptr<Dnp3Parser>(new Dnp3Parser()));
    m_protocol_parsers.push_back(std::unique_ptr<DnsParser>(new DnsParser()));
    m_protocol_parsers.push_back(std::unique_ptr<GenericParser>(new GenericParser("ethernet_ip")));
    m_protocol_parsers.push_back(std::unique_ptr<GenericParser>(new GenericParser("iec104")));
    m_protocol_parsers.push_back(std::unique_ptr<GenericParser>(new GenericParser("mms")));
    m_protocol_parsers.push_back(std::unique_ptr<GenericParser>(new GenericParser("opc_ua")));
    m_protocol_parsers.push_back(std::unique_ptr<GenericParser>(new GenericParser("bacnet")));
    m_protocol_parsers.push_back(std::unique_ptr<GenericParser>(new GenericParser("dhcp")));
    m_protocol_parsers.push_back(std::unique_ptr<UnknownParser>(new UnknownParser()));

    const std::string ip_csv_header = "@timestamp,sip,sp,dip,dp,sq,ak,fl,d";
    for (const auto& parser : m_protocol_parsers) {
        initialize_output_stream(parser->getName(), ip_csv_header);
        parser->setOutputStream(&m_json_streams[parser->getName()], &m_csv_streams[parser->getName()]);
    }
}

PacketParser::~PacketParser() {
    for (auto& pair : m_json_streams) {
        if (pair.second.is_open()) pair.second.close();
    }
    for (auto& pair : m_csv_streams) {
        if (pair.second.is_open()) pair.second.close();
    }
}

void PacketParser::initialize_output_stream(const std::string& protocol, const std::string& csv_header) {
    if (m_json_streams.find(protocol) == m_json_streams.end()) {
        std::string json_filename = m_output_dir + protocol + ".jsonl";
        m_json_streams[protocol].open(json_filename);
        if (!m_json_streams[protocol].is_open()) {
            std::cerr << "Error: Could not open output file " << json_filename << std::endl;
        }
    }
    if (m_csv_streams.find(protocol) == m_csv_streams.end()) {
        std::string csv_filename = m_output_dir + protocol + ".csv";
        m_csv_streams[protocol].open(csv_filename);
        if (!m_csv_streams[protocol].is_open()) {
             std::cerr << "Error: Could not open output file " << csv_filename << std::endl;
        }
        if (m_csv_streams[protocol].is_open() && !csv_header.empty()) {
            m_csv_streams[protocol] << csv_header << std::endl;
        }
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

void PacketParser::parse(const struct pcap_pkthdr* header, const u_char* packet) {
    if (!packet || header->caplen < sizeof(EthernetHeader)) return;

    // --- Timestamp Formatting ---
    // ElasticSearch 형식(@timestamp)에 맞는 타임스탬프 문자열을 미리 생성합니다.
    std::stringstream time_ss;
    struct tm *ltime;
    char timestr[40];
    ltime = localtime(&header->ts.tv_sec);
    // ISO 8601 형식과 유사하게 변경 (e.g., "YYYY-MM-DDTHH:MM:SS.microsZ")
    strftime(timestr, sizeof(timestr), "%Y-%m-%dT%H:%M:%S", ltime);
    time_ss << timestr << "." << std::setw(6) << std::setfill('0') << header->ts.tv_usec << "Z";
    std::string timestamp_str = time_ss.str();


    const EthernetHeader* eth_header = (const EthernetHeader*)(packet);
    uint16_t eth_type = ntohs(eth_header->eth_type);
    const u_char* l3_payload = packet + sizeof(EthernetHeader);
    int l3_payload_size = header->caplen - sizeof(EthernetHeader);
    std::string timestamp_str = format_timestamp(header->ts);

    if (eth_type == 0x0806) { // ARP (Layer 2)
        // --- MODIFICATION: Corrected ArpParser call to match its 2-argument signature ---
        std::string details_json = m_arp_parser->parse(l3_payload, l3_payload_size);
        
        std::ofstream& json_out = m_json_streams["arp"];
        if (json_out.is_open()) {
            json_out << "{\"@timestamp\":\"" << timestamp_str << "\",\"d\":" << details_json << "}\n";
        }
        std::ofstream& csv_out = m_csv_streams["arp"];
        if (csv_out.is_open()) {
            csv_out << timestamp_str << "," << escape_csv(details_json) << "\n";
        }
    }
    else if (eth_type == 0x0800) { // IPv4 (Layer 3)
        if (l3_payload_size < sizeof(IPHeader)) return;
        const IPHeader* ip_header = (const IPHeader*)(l3_payload);
        
        const int ip_header_length = ip_header->hl * 4;
        char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

        if (ip_header->p == IPPROTO_TCP || ip_header->p == IPPROTO_UDP) {
            const u_char* payload;
            int payload_size;
            uint16_t src_port = 0, dst_port = 0;
            uint32_t tcp_seq = 0, tcp_ack = 0;
            uint8_t tcp_flags = 0;

            if (ip_header->p == IPPROTO_TCP) {
                 if (l3_payload_size < ip_header_length + sizeof(TCPHeader)) return;
                 const TCPHeader* tcp_header = (const TCPHeader*)(l3_payload + ip_header_length);
                 const int tcp_header_length = tcp_header->off * 4;
                 payload = (const u_char*)tcp_header + tcp_header_length;
                 payload_size = ntohs(ip_header->len) - (ip_header_length + tcp_header_length);
                 src_port = ntohs(tcp_header->sport);
                 dst_port = ntohs(tcp_header->dport);
                 tcp_seq = ntohl(tcp_header->seq);
                 tcp_ack = ntohl(tcp_header->ack);
                 tcp_flags = tcp_header->flags;
            } else { // UDP
                struct UDPHeader { uint16_t sport, dport, len, check; };
                if (l3_payload_size < ip_header_length + sizeof(UDPHeader)) return;
                const UDPHeader* udp_header = (const UDPHeader*)(l3_payload + ip_header_length);
                payload = (const u_char*)udp_header + sizeof(UDPHeader);
                payload_size = ntohs(udp_header->len) - sizeof(UDPHeader);
                src_port = ntohs(udp_header->sport);
                dst_port = ntohs(udp_header->dport);
            }

            std::string flow_id = get_canonical_flow_id(src_ip_str, src_port, dst_ip_str, dst_port);
            
            if (payload_size <= 0 && ip_header->p == IPPROTO_TCP) {
                std::string details_json = m_tcp_session_parser->parse(tcp_seq, tcp_ack, tcp_flags);
                
                std::ofstream& json_out = m_json_streams["tcp_session"];
                if (json_out.is_open()) {
                    json_out << "{\"@timestamp\":\"" << timestamp_str << "\","
                               << "\"sip\":\"" << src_ip_str << "\",\"sp\":" << src_port << ","
                               << "\"dip\":\"" << dst_ip_str << "\",\"dp\":" << dst_port << ","
                               << "\"d\":" << details_json << "}\n";
                }
                std::ofstream& csv_out = m_csv_streams["tcp_session"];
                if (csv_out.is_open()) {
                    csv_out << timestamp_str << ","
                            << src_ip_str << "," << src_port << ","
                            << dst_ip_str << "," << dst_port << ","
                            << escape_csv(details_json) << "\n";
                }
                return;
            }

            bool matched = false;
            PacketInfo info = {
                timestamp_str, flow_id, src_ip_str, src_port, dst_ip_str, dst_port,
                payload, payload_size, tcp_seq, tcp_ack, tcp_flags
            };

            for (const auto& parser : m_protocol_parsers) {
                if (parser->getName() != "unknown" && parser->isProtocol(payload, payload_size)) {
                    parser->parse(info);
                    matched = true;
                    break;
                }
            }

            if (!matched) {
                 m_protocol_parsers.back()->parse(info);
            }
        }
    }
}
