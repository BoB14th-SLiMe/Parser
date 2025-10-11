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
#include <vector>
#include <tuple>

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

// --- Helper Function: Format timestamp to ISO 8601 string ---
static std::string format_timestamp(const struct timeval& ts) {
    char buf[sizeof "2011-10-08T07:07:09.000000Z"];
    char buft[sizeof "2011-10-08T07:07:09"];
    strftime(buft, sizeof buft, "%Y-%m-%dT%H:%M:%S", gmtime(&ts.tv_sec));
    snprintf(buf, sizeof buf, "%.*s.%06dZ", (int)sizeof(buft) - 1, buft, (int)ts.tv_usec);
    return std::string(buf);
}

PacketParser::PacketParser(const std::string& output_dir)
    : m_output_dir(output_dir) {
    mkdir(m_output_dir.c_str(), 0755);

    m_arp_parser = std::unique_ptr<ArpParser>(new ArpParser());
    m_tcp_session_parser = std::unique_ptr<TcpSessionParser>(new TcpSessionParser());
    initialize_output_streams("arp");
    initialize_output_streams("tcp_session");
    
    m_protocol_parsers.push_back(std::unique_ptr<IProtocolParser>(new ModbusParser()));
    m_protocol_parsers.push_back(std::unique_ptr<IProtocolParser>(new S7CommParser()));
    m_protocol_parsers.push_back(std::unique_ptr<IProtocolParser>(new XgtFenParser()));
    m_protocol_parsers.push_back(std::unique_ptr<IProtocolParser>(new Dnp3Parser()));
    m_protocol_parsers.push_back(std::unique_ptr<IProtocolParser>(new GenericParser("dhcp")));
    m_protocol_parsers.push_back(std::unique_ptr<IProtocolParser>(new DnsParser()));
    m_protocol_parsers.push_back(std::unique_ptr<IProtocolParser>(new GenericParser("ethernet_ip")));
    m_protocol_parsers.push_back(std::unique_ptr<IProtocolParser>(new GenericParser("iec104")));
    m_protocol_parsers.push_back(std::unique_ptr<IProtocolParser>(new GenericParser("mms")));
    m_protocol_parsers.push_back(std::unique_ptr<IProtocolParser>(new GenericParser("opc_ua")));
    m_protocol_parsers.push_back(std::unique_ptr<IProtocolParser>(new GenericParser("bacnet")));
    m_protocol_parsers.push_back(std::unique_ptr<IProtocolParser>(new UnknownParser()));

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
        
        streams.jsonl_stream.open(jsonl_filename, std::ios_base::app);
        streams.csv_stream.open(csv_filename, std::ios_base::app);

        if (!streams.jsonl_stream.is_open()) {
            std::cerr << "Error: Could not open output file " << jsonl_filename << std::endl;
        }
        if (!streams.csv_stream.is_open()) {
            std::cerr << "Error: Could not open output file " << csv_filename << std::endl;
        } else {
            streams.csv_stream.seekp(0, std::ios::end);
            if (streams.csv_stream.tellp() == 0) {
                 streams.csv_stream << "@timestamp,sip,sp,dip,dp,sq,ak,fl,d\n";
            }
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

static std::string escape_csv(const std::string& s) {
    std::string escaped = s;
    size_t pos = 0;
    while ((pos = escaped.find("\"", pos)) != std::string::npos) {
        escaped.replace(pos, 1, "\"\"");
        pos += 2;
    }
    return escaped;
}

void PacketParser::parse(const struct pcap_pkthdr* header, const u_char* packet) {
    if (!packet || header->caplen < sizeof(EthernetHeader)) return;

    const EthernetHeader* eth_header = (const EthernetHeader*)(packet);
    uint16_t eth_type = ntohs(eth_header->eth_type);
    const u_char* l3_payload = packet + sizeof(EthernetHeader);
    int l3_payload_size = header->caplen - sizeof(EthernetHeader);

    if (eth_type == 0x0806) { // ARP (Layer 2)
        auto arp_data = m_arp_parser->parse(header, l3_payload, l3_payload_size);
        const std::string& timestamp_str = arp_data.first;
        const std::string& details_json = arp_data.second;

        if (!timestamp_str.empty()) {
            if (m_output_streams["arp"].jsonl_stream.is_open()) {
                m_output_streams["arp"].jsonl_stream << "{\"@timestamp\":\"" << timestamp_str << "\",\"d\":" << details_json << "}\n";
            }
            if (m_output_streams["arp"].csv_stream.is_open()) {
                // --- 수정: ARP에 대해 빈 컬럼을 포함하여 CSV 형식 통일 ---
                m_output_streams["arp"].csv_stream << timestamp_str << ",,,,,,,,\"" << escape_csv(details_json) << "\"\n";
            }
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
            
            std::string timestamp_str = format_timestamp(header->ts);

            if (payload_size <= 0 && ip_header->p == IPPROTO_TCP) {
                std::string details_json = m_tcp_session_parser->parse(tcp_seq, tcp_ack, tcp_flags);

                if (m_output_streams["tcp_session"].jsonl_stream.is_open()) {
                     m_output_streams["tcp_session"].jsonl_stream << "{\"@timestamp\":\"" << timestamp_str << "\","
                        << "\"sip\":\"" << src_ip_str << "\",\"sp\":" << src_port << ","
                        << "\"dip\":\"" << dst_ip_str << "\",\"dp\":" << dst_port << ","
                        << "\"sq\":" << tcp_seq << ",\"ak\":" << tcp_ack << ",\"fl\":" << (int)tcp_flags << ","
                        << "\"d\":" << details_json << "}\n";
                }
                if (m_output_streams["tcp_session"].csv_stream.is_open()) {
                    m_output_streams["tcp_session"].csv_stream 
                        << timestamp_str << "," << src_ip_str << "," << src_port << "," << dst_ip_str << "," << dst_port << ","
                        << tcp_seq << "," << tcp_ack << "," << (int)tcp_flags << ",\"" 
                        << escape_csv(details_json) << "\"\n";
                }
                return;
            }

            bool matched = false;
            for (const auto& parser : m_protocol_parsers) {
                const std::string& parser_name = parser->getName();
                if (parser_name == "dns" && (src_port != 53 && dst_port != 53)) {
                    continue;
                }
                if (parser_name == "dhcp" && !((src_port == 67 && dst_port == 68) || (src_port == 68 && dst_port == 67))) {
                    continue;
                }

                if (parser_name != "unknown" && parser->isProtocol(payload, payload_size)) {
                    std::string flow_id = get_canonical_flow_id(src_ip_str, src_port, dst_ip_str, dst_port);
                    PacketInfo info = {
                        timestamp_str, flow_id, src_ip_str, src_port, dst_ip_str, dst_port,
                        payload, payload_size, tcp_seq, tcp_ack, tcp_flags
                    };
                    parser->parse(info);
                    matched = true;
                    break;
                }
            }

            if (!matched) {
                 std::string flow_id = get_canonical_flow_id(src_ip_str, src_port, dst_ip_str, dst_port);
                 m_protocol_parsers.back()->parse({timestamp_str, flow_id, src_ip_str, src_port, dst_ip_str, dst_port,
                        payload, payload_size, tcp_seq, tcp_ack, tcp_flags});
            }
        }
    }
}

