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

PacketParser::PacketParser(const std::string& output_dir, int time_interval, int num_threads)
    : m_output_dir(output_dir),
      m_time_interval(time_interval),
      m_assetManager("assets/자산IP.csv", "assets/유선_Input.csv", "assets/유선_Output.csv"),
      m_stop_flag(false),
      m_packets_processed(0),
      m_packets_queued(0) {
    
    #ifdef _WIN32
        _mkdir(m_output_dir.c_str());
    #else
        mkdir(m_output_dir.c_str(), 0755);
    #endif

    // 스레드 수 결정 (0이면 CPU 코어의 절반, 최소 1개, 최대 8개)
    if (num_threads <= 0) {
        unsigned int hw_threads = std::thread::hardware_concurrency();
        m_num_threads = std::max(1u, std::min(8u, hw_threads / 2));
    } else {
        m_num_threads = std::min(num_threads, 16); // 최대 16개로 제한
    }
    
    std::cout << "[INFO] Using " << m_num_threads << " worker threads" << std::endl;

    // 시간 기반 통합 CSV 작성기 초기화
    if (m_time_interval > 0) {
        m_time_writer = std::make_unique<TimeBasedCsvWriter>(m_output_dir, m_time_interval);
        std::cout << "[INFO] Time-based CSV writer initialized with " << m_time_interval << " minute intervals" << std::endl;
    }

    // 출력 스트림 초기화
    std::vector<std::string> protocols = {
        "arp", "tcp_session", "modbus_tcp", "s7comm", "xgt-fen", 
        "dnp3", "dhcp", "dns", "ethernet_ip", "iec104", 
        "mms", "opc_ua", "bacnet", "unknown"
    };
    
    for (const auto& protocol : protocols) {
        initialize_output_streams(protocol);
    }

    // 워커별 파서 생성
    m_worker_parsers.resize(m_num_threads);
    for (int i = 0; i < m_num_threads; ++i) {
        createParsersForWorker(i);
    }
}

void PacketParser::createParsersForWorker(int worker_id) {
    auto& parsers = m_worker_parsers[worker_id];
    
    parsers.push_back(std::make_unique<ArpParser>());
    parsers.push_back(std::make_unique<TcpSessionParser>());
    parsers.push_back(std::make_unique<ModbusParser>(m_assetManager));
    parsers.push_back(std::make_unique<S7CommParser>(m_assetManager));
    parsers.push_back(std::make_unique<XgtFenParser>(m_assetManager));
    parsers.push_back(std::make_unique<Dnp3Parser>());
    parsers.push_back(std::make_unique<GenericParser>("dhcp"));
    parsers.push_back(std::make_unique<DnsParser>());
    parsers.push_back(std::make_unique<GenericParser>("ethernet_ip"));
    parsers.push_back(std::make_unique<GenericParser>("iec104"));
    parsers.push_back(std::make_unique<GenericParser>("mms"));
    parsers.push_back(std::make_unique<GenericParser>("opc_ua"));
    parsers.push_back(std::make_unique<GenericParser>("bacnet"));
    parsers.push_back(std::make_unique<UnknownParser>());

    // 각 파서에 출력 스트림 설정
    for (const auto& parser : parsers) {
        auto& streams = m_output_streams[parser->getName()];
        parser->setOutputStream(&streams.jsonl_stream, &streams.csv_stream);
    }
}

PacketParser::~PacketParser() {
    std::cout << "[INFO] PacketParser destructor called" << std::endl;
    stopWorkers();
    
    // 스트림 닫기
    for (auto& pair : m_output_streams) {
        if (pair.second.jsonl_stream.is_open()) {
            pair.second.jsonl_stream.close();
        }
        if (pair.second.csv_stream.is_open()) {
            pair.second.csv_stream.close();
        }
    }
    
    std::cout << "[INFO] Total packets processed: " << m_packets_processed.load() << std::endl;
    std::cout << "[INFO] PacketParser cleanup complete" << std::endl;
}

void PacketParser::startWorkers() {
    std::cout << "[INFO] Starting " << m_num_threads << " worker threads..." << std::endl;
    
    for (int i = 0; i < m_num_threads; ++i) {
        m_workers.emplace_back(&PacketParser::workerThread, this, i);
    }
    
    std::cout << "[INFO] Worker threads started" << std::endl;
}

void PacketParser::stopWorkers() {
    if (m_workers.empty()) return;
    
    std::cout << "[INFO] Stopping worker threads..." << std::endl;
    
    m_stop_flag = true;
    m_queue_cv.notify_all();
    
    for (auto& worker : m_workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    m_workers.clear();
    std::cout << "[INFO] Worker threads stopped" << std::endl;
}

void PacketParser::waitForCompletion() {
    std::cout << "[INFO] Waiting for queue to empty..." << std::endl;
    
    while (true) {
        {
            std::lock_guard<std::mutex> lock(m_queue_mutex);
            if (m_packet_queue.empty()) {
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // 진행 상황 출력
        size_t queued = m_packets_queued.load();
        size_t processed = m_packets_processed.load();
        if (queued > 0) {
            double progress = (double)processed / queued * 100.0;
            std::cout << "\r[INFO] Progress: " << processed << "/" << queued 
                      << " (" << std::fixed << std::setprecision(1) << progress << "%)    " << std::flush;
        }
    }
    
    std::cout << std::endl;
    std::cout << "[INFO] All packets processed" << std::endl;
}

void PacketParser::workerThread(int worker_id) {
    while (true) {
        std::shared_ptr<PacketData> packet_data;
        
        {
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            m_queue_cv.wait(lock, [this] { 
                return m_stop_flag.load() || !m_packet_queue.empty(); 
            });
            
            if (m_stop_flag.load() && m_packet_queue.empty()) {
                break;
            }
            
            if (!m_packet_queue.empty()) {
                packet_data = m_packet_queue.front();
                m_packet_queue.pop();
            }
        }
        
        if (packet_data) {
            parsePacket(&packet_data->header, packet_data->packet.data(), worker_id);
            m_packets_processed++;
        }
    }
}

void PacketParser::initialize_output_streams(const std::string& protocol) {
    if (m_output_streams.find(protocol) == m_output_streams.end()) {
        std::string jsonl_filename = m_output_dir + "/" + protocol + ".jsonl";
        std::string csv_filename = m_output_dir + "/" + protocol + ".csv";
        
        // emplace를 사용하여 직접 생성
        auto result = m_output_streams.emplace(std::piecewise_construct,
                                                std::forward_as_tuple(protocol),
                                                std::forward_as_tuple());
        
        FileStreams& streams = result.first->second;
        
        streams.jsonl_stream.open(jsonl_filename, std::ios_base::trunc);
        streams.csv_stream.open(csv_filename, std::ios_base::trunc);

        if (!streams.jsonl_stream.is_open()) {
            std::cerr << "Error: Could not open output file " << jsonl_filename << std::endl;
        }
        if (!streams.csv_stream.is_open()) {
            std::cerr << "Error: Could not open output file " << csv_filename << std::endl;
        }
    }
}

void PacketParser::generateUnifiedCsv() {
    if (m_time_interval <= 0 || !m_time_writer) {
        return;
    }
    
    std::cout << "[INFO] Generating unified CSV from individual protocol files..." << std::endl;
    
    std::vector<std::string> protocols = {
        "arp", "tcp_session", "modbus_tcp", "s7comm", "xgt-fen", 
        "dnp3", "dhcp", "dns", "ethernet_ip", "iec104", 
        "mms", "opc_ua", "bacnet", "unknown"
    };
    
    int total_records = 0;
    for (const auto& protocol : protocols) {
        std::string csv_filename = m_output_dir + "/" + protocol + ".csv";
        std::ifstream csv_file(csv_filename);
        
        if (!csv_file.is_open()) {
            continue;
        }
        
        std::string line;
        bool first_line = true;
        int protocol_records = 0;
        
        while (std::getline(csv_file, line)) {
            if (first_line) {
                first_line = false;
                continue;
            }
            
            if (line.empty() || line.find_first_not_of(" \t\r\n") == std::string::npos) {
                continue;
            }
            
            m_time_writer->addRecord(protocol, line);
            protocol_records++;
            total_records++;
        }
        
        csv_file.close();
        
        if (protocol_records > 0) {
            std::cout << "[INFO] Loaded " << protocol_records << " records from " << protocol << ".csv" << std::endl;
        }
    }
    
    std::cout << "[INFO] Total records loaded: " << total_records << std::endl;
    std::cout << "[INFO] Flushing unified CSV files..." << std::endl;
    
    m_time_writer->flush();
    
    std::cout << "[INFO] Unified CSV generation complete" << std::endl;
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
    // 패킷을 큐에 추가 (멀티스레딩)
    auto packet_data = std::make_shared<PacketData>(header, packet);
    
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        m_packet_queue.push(packet_data);
        m_packets_queued++;
    }
    
    m_queue_cv.notify_one();
}

// PacketParser.cpp 중 parsePacket 함수의 TCP/UDP 처리 부분 수정

void PacketParser::parsePacket(const struct pcap_pkthdr* header, const u_char* packet, int worker_id) {
    if (!packet || header->caplen < sizeof(EthernetHeader)) return;

    const EthernetHeader* eth_header = (const EthernetHeader*)(packet);
    uint16_t eth_type = ntohs(eth_header->eth_type);
    const u_char* l3_payload = packet + sizeof(EthernetHeader);
    int l3_payload_size = header->caplen - sizeof(EthernetHeader);

    std::string src_mac_str = mac_to_string_helper(eth_header->src_mac);
    std::string dst_mac_str = mac_to_string_helper(eth_header->dest_mac);

    auto& parsers = m_worker_parsers[worker_id];

    // ARP 패킷 처리
    if (eth_type == 0x0806) {
        PacketInfo info;
        info.timestamp = format_timestamp(header->ts);
        info.src_mac = src_mac_str;
        info.dst_mac = dst_mac_str;
        info.eth_type = eth_type;
        info.payload = l3_payload;
        info.payload_size = l3_payload_size;

        for (const auto& parser : parsers) {
            if (parser->getName() == "arp") {
                std::lock_guard<std::mutex> lock(m_output_streams["arp"].mutex);
                parser->parse(info);
                break;
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
            
            // TCP 헤더 길이 계산 (off는 32비트 워드 단위)
            int tcp_header_len = tcp_header->off * 4;
            const u_char* l7_payload = l4_payload + tcp_header_len;
            int l7_payload_size = l4_payload_size - tcp_header_len;

            PacketInfo info;
            info.timestamp = format_timestamp(header->ts);
            info.src_mac = src_mac_str;
            info.dst_mac = dst_mac_str;
            info.eth_type = eth_type;
            info.src_ip = src_ip_str;
            info.dst_ip = dst_ip_str;
            info.src_port = ntohs(tcp_header->sport);
            info.dst_port = ntohs(tcp_header->dport);
            info.protocol = IPPROTO_TCP;
            
            // TCP 필드 파싱 (네트워크 바이트 오더를 호스트 바이트 오더로 변환)
            info.tcp_seq = ntohl(tcp_header->seq);
            info.tcp_ack = ntohl(tcp_header->ack);
            info.tcp_flags = tcp_header->flags;
            
            info.payload = l7_payload;
            info.payload_size = l7_payload_size;
            info.flow_id = get_canonical_flow_id(info.src_ip, info.src_port, info.dst_ip, info.dst_port);

            // 디버그 출력 (필요시 활성화)
            // std::cout << "[DEBUG] TCP Packet: seq=" << info.tcp_seq 
            //           << " ack=" << info.tcp_ack 
            //           << " flags=" << (int)info.tcp_flags 
            //           << " port=" << info.dst_port << std::endl;

            bool handled_by_specific_app_parser = false;
            for (const auto& parser : parsers) {
                const auto& name = parser->getName();
                if (name == "tcp_session" || name == "unknown" || name == "arp") {
                    continue;
                }

                if (parser->isProtocol(info)) {
                    std::lock_guard<std::mutex> lock(m_output_streams[name].mutex);
                    parser->parse(info);
                    handled_by_specific_app_parser = true;
                    break;
                }
            }

            if (!handled_by_specific_app_parser) {
                for (const auto& parser : parsers) {
                    if (parser->getName() == "tcp_session") {
                        std::lock_guard<std::mutex> lock(m_output_streams["tcp_session"].mutex);
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
            info.protocol = IPPROTO_UDP;
            // UDP는 TCP 필드가 없으므로 0으로 설정
            info.tcp_seq = 0;
            info.tcp_ack = 0;
            info.tcp_flags = 0;
            info.payload = l7_payload;
            info.payload_size = l7_payload_size;
            info.flow_id = get_canonical_flow_id(info.src_ip, info.src_port, info.dst_ip, info.dst_port);

            bool specific_app_protocol_found = false;
            for (const auto& parser : parsers) {
                const auto& name = parser->getName();
                if (name == "tcp_session" || name == "unknown" || name == "arp") {
                    continue;
                }

                if (parser->isProtocol(info)) {
                    std::lock_guard<std::mutex> lock(m_output_streams[name].mutex);
                    parser->parse(info);
                    specific_app_protocol_found = true;
                    break;
                }
            }

            if (!specific_app_protocol_found) {
                for (const auto& parser : parsers) {
                    if (parser->getName() == "unknown") {
                        std::lock_guard<std::mutex> lock(m_output_streams["unknown"].mutex);
                        parser->parse(info);
                        break;
                    }
                }
            }
        }
    }
}