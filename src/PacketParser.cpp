#include "PacketParser.h"
#include "./network/network_headers.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <ctime>
#include <memory>
#include <cstring>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

// 프로토콜 파서 헤더
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

PacketParser::PacketParser(const CaptureConfig& config)
    : m_config(config),
      m_output_dir("output/"),
      m_assetManager("assets/자산IP.csv", "assets/유선_Input.csv", "assets/유선_Output.csv"),
      m_stop_flag(false),
      m_capturing(false),
      m_packets_captured(0),
      m_packets_processed(0),
      m_redis_sent(0),
      m_elasticsearch_sent(0),
      m_errors(0),
      m_pcap_handle(nullptr) {
    
    #ifdef _WIN32
        _mkdir(m_output_dir.c_str());
    #else
        mkdir(m_output_dir.c_str(), 0755);
    #endif

    // 스레드 수 결정
    if (m_config.num_threads <= 0) {
        unsigned int hw_threads = std::thread::hardware_concurrency();
        m_num_threads = std::max(1u, std::min(8u, hw_threads / 2));
    } else {
        m_num_threads = std::min(m_config.num_threads, 16);
    }
    
    std::cout << "[INFO] Using " << m_num_threads << " worker threads" << std::endl;

    // Redis 초기화
    if (m_config.enable_redis) {
        RedisCacheConfig redis_config;
        redis_config.host = "127.0.0.1";
        redis_config.port = 6379;
        m_redis_cache = std::make_unique<RedisCache>(redis_config);
        
        if (m_redis_cache->connect()) {
            std::cout << "[INFO] Redis connected" << std::endl;
        } else {
            std::cerr << "[WARN] Redis connection failed" << std::endl;
            m_config.enable_redis = false;
        }
    }

    // Elasticsearch 초기화
    if (m_config.enable_elasticsearch) {
        ElasticsearchConfig es_config;
        es_config.host = "localhost";
        es_config.port = 9200;
        es_config.bulk_size = 100;
        m_elasticsearch = std::make_unique<ElasticsearchClient>(es_config);
        
        if (m_elasticsearch->connect()) {
            std::cout << "[INFO] Elasticsearch connected" << std::endl;
        } else {
            std::cerr << "[WARN] Elasticsearch connection failed" << std::endl;
            m_config.enable_elasticsearch = false;
        }
    }

    // 출력 스트림 초기화 (JSONL만)
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

    // JSONL 스트림 및 Redis/ES 설정
    for (const auto& parser : parsers) {
        auto& streams = m_output_streams[parser->getName()];
        parser->setOutputStream(&streams.jsonl_stream, nullptr);
        
        if (auto* base_parser = dynamic_cast<BaseProtocolParser*>(parser.get())) {
            if (m_redis_cache) {
                base_parser->setRedisCache(m_redis_cache.get());
            }
            if (m_elasticsearch) {
                base_parser->setElasticsearch(m_elasticsearch.get());
            }
        }
    }
}

PacketParser::~PacketParser() {
    std::cout << "[INFO] PacketParser destructor called" << std::endl;
    stopCapture();
    stopWorkers();
    
    for (auto& pair : m_output_streams) {
        if (pair.second.jsonl_stream.is_open()) {
            pair.second.jsonl_stream.close();
        }
    }
    
    std::cout << "[INFO] Total packets processed: " << m_packets_processed.load() << std::endl;
}

bool PacketParser::startCapture() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    m_pcap_handle = pcap_open_live(
        m_config.interface.c_str(),
        m_config.snaplen,
        1,
        100,
        errbuf
    );
    
    if (!m_pcap_handle) {
        std::cerr << "[ERROR] Failed to open interface " << m_config.interface 
                  << ": " << errbuf << std::endl;
        return false;
    }
    
    if (!m_config.filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(m_pcap_handle, &fp, m_config.filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "[ERROR] Failed to compile filter: " << pcap_geterr(m_pcap_handle) << std::endl;
            return false;
        }
        if (pcap_setfilter(m_pcap_handle, &fp) == -1) {
            std::cerr << "[ERROR] Failed to set filter: " << pcap_geterr(m_pcap_handle) << std::endl;
            return false;
        }
        pcap_freecode(&fp);
        std::cout << "[INFO] BPF filter applied: " << m_config.filter << std::endl;
    }
    
    std::cout << "[INFO] Started capturing on interface: " << m_config.interface << std::endl;
    
    startWorkers();
    
    m_capturing = true;
    m_session_start = std::chrono::steady_clock::now();
    m_capture_thread = std::thread(&PacketParser::captureLoop, this);
    m_rolling_thread = std::thread(&PacketParser::rollingManager, this);
    
    return true;
}

void PacketParser::captureLoop() {
    struct pcap_pkthdr* header;
    const u_char* packet;
    
    while (m_capturing.load()) {
        int result = pcap_next_ex(m_pcap_handle, &header, &packet);
        
        if (result == 1) {
            m_packets_captured++;
            parse(header, packet);
        } else if (result == 0) {
            continue;
        } else if (result == -1) {
            std::cerr << "[ERROR] pcap_next_ex failed: " 
                      << pcap_geterr(m_pcap_handle) << std::endl;
            m_errors++;
            break;
        } else if (result == -2) {
            break;
        }
    }
    
    std::cout << "[INFO] Capture loop ended" << std::endl;
}

void PacketParser::rollingManager() {
    while (m_capturing.load()) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(
            now - m_session_start
        ).count();
        
        if (elapsed >= m_config.rolling_interval_minutes) {
            std::cout << "\n[INFO] ====== " << m_config.rolling_interval_minutes 
                      << "-minute session completed ======" << std::endl;
            std::cout << "[INFO] Packets captured: " << m_packets_captured.load() << std::endl;
            std::cout << "[INFO] Packets processed: " << m_packets_processed.load() << std::endl;
            std::cout << "[INFO] Redis sent: " << m_redis_sent.load() << std::endl;
            std::cout << "[INFO] Elasticsearch sent: " << m_elasticsearch_sent.load() << std::endl;
            std::cout << "[INFO] Rotating output files..." << std::endl;
            
            rotateOutputFiles();
            
            m_packets_captured = 0;
            m_packets_processed = 0;
            m_redis_sent = 0;
            m_elasticsearch_sent = 0;
            
            m_session_start = std::chrono::steady_clock::now();
            std::cout << "[INFO] ====== New " << m_config.rolling_interval_minutes 
                      << "-minute session started ======\n" << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(60));
    }
}

void PacketParser::rotateOutputFiles() {
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    
    std::stringstream timestamp_ss;
    timestamp_ss << std::put_time(&tm, "%Y%m%d_%H%M%S");
    std::string timestamp = timestamp_ss.str();
    
    for (auto& pair : m_output_streams) {
        std::lock_guard<std::mutex> lock(pair.second.mutex);
        
        if (pair.second.jsonl_stream.is_open()) {
            pair.second.jsonl_stream.close();
        }
        
        std::string filename = m_output_dir + "/" + pair.first + "_" + timestamp + ".jsonl";
        pair.second.jsonl_stream.open(filename, std::ios_base::trunc);
        
        if (!pair.second.jsonl_stream.is_open()) {
            std::cerr << "[ERROR] Failed to open " << filename << std::endl;
        }
    }
}

void PacketParser::stopCapture() {
    if (!m_capturing.load()) return;
    
    std::cout << "[INFO] Stopping capture..." << std::endl;
    
    m_capturing = false;
    
    if (m_rolling_thread.joinable()) {
        m_rolling_thread.join();
    }
    
    if (m_capture_thread.joinable()) {
        m_capture_thread.join();
    }
    
    if (m_pcap_handle) {
        pcap_breakloop(m_pcap_handle);
        pcap_close(m_pcap_handle);
        m_pcap_handle = nullptr;
    }
    
    waitForCompletion();
    
    if (m_elasticsearch && m_elasticsearch->isConnected()) {
        m_elasticsearch->flushBulk();
    }
    
    std::cout << "[INFO] Capture stopped" << std::endl;
}

void PacketParser::startWorkers() {
    std::cout << "[INFO] Starting " << m_num_threads << " worker threads..." << std::endl;
    
    for (int i = 0; i < m_num_threads; ++i) {
        m_workers.emplace_back(&PacketParser::workerThread, this, i);
    }
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
}

void PacketParser::waitForCompletion() {
    while (true) {
        {
            std::lock_guard<std::mutex> lock(m_queue_mutex);
            if (m_packet_queue.empty()) {
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
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
        
        auto result = m_output_streams.emplace(std::piecewise_construct,
                                                std::forward_as_tuple(protocol),
                                                std::forward_as_tuple());
        
        FileStreams& streams = result.first->second;
        streams.jsonl_stream.open(jsonl_filename, std::ios_base::trunc);

        if (!streams.jsonl_stream.is_open()) {
            std::cerr << "[ERROR] Could not open " << jsonl_filename << std::endl;
        }
    }
}

std::string PacketParser::get_canonical_flow_id(const std::string& ip1_str, uint16_t port1, 
                                                 const std::string& ip2_str, uint16_t port2) {
    std::string ip1 = ip1_str, ip2 = ip2_str;
    if (ip1 > ip2 || (ip1 == ip2 && port1 > port2)) {
        std::swap(ip1, ip2);
        std::swap(port1, port2);
    }
    return ip1 + ":" + std::to_string(port1) + "-" + ip2 + ":" + std::to_string(port2);
}

void PacketParser::parse(const struct pcap_pkthdr* header, const u_char* packet) {
    auto packet_data = std::make_shared<PacketData>(header, packet);
    
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        m_packet_queue.push(packet_data);
    }
    
    m_queue_cv.notify_one();
}

void PacketParser::parsePacket(const struct pcap_pkthdr* header, const u_char* packet, int worker_id) {
    if (!packet || header->caplen < sizeof(EthernetHeader)) return;

    const EthernetHeader* eth_header = (const EthernetHeader*)(packet);
    uint16_t eth_type = ntohs(eth_header->eth_type);
    const u_char* l3_payload = packet + sizeof(EthernetHeader);
    int l3_payload_size = header->caplen - sizeof(EthernetHeader);

    std::string src_mac_str = mac_to_string_helper(eth_header->src_mac);
    std::string dst_mac_str = mac_to_string_helper(eth_header->dest_mac);

    auto& parsers = m_worker_parsers[worker_id];

    // ARP 처리
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

    // IPv4 처리
    if (eth_type == 0x0800) {
        if (static_cast<size_t>(l3_payload_size) < sizeof(IPHeader)) return;
        const IPHeader* ip_header = (const IPHeader*)(l3_payload);
        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

        const u_char* l4_payload = l3_payload + (ip_header->hl * 4);
        int l4_payload_size = l3_payload_size - (ip_header->hl * 4);

        // TCP 처리 (수정: TCP 헤더 길이 계산)
        if (ip_header->p == IPPROTO_TCP) {
            if (static_cast<size_t>(l4_payload_size) < sizeof(TCPHeader)) return;
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
            info.tcp_seq = ntohl(tcp_header->seq);
            info.tcp_ack = ntohl(tcp_header->ack);
            info.tcp_flags = tcp_header->flags;
            info.payload = l7_payload;
            info.payload_size = l7_payload_size;
            info.flow_id = get_canonical_flow_id(info.src_ip, info.src_port, info.dst_ip, info.dst_port);

            bool handled = false;
            for (const auto& parser : parsers) {
                const auto& name = parser->getName();
                if (name == "tcp_session" || name == "unknown" || name == "arp") continue;

                if (parser->isProtocol(info)) {
                    std::lock_guard<std::mutex> lock(m_output_streams[name].mutex);
                    parser->parse(info);
                    handled = true;
                    break;
                }
            }

            if (!handled) {
                for (const auto& parser : parsers) {
                    if (parser->getName() == "tcp_session") {
                        std::lock_guard<std::mutex> lock(m_output_streams["tcp_session"].mutex);
                        parser->parse(info);
                        break;
                    }
                }
            }
        }
        // UDP 처리
        else if (ip_header->p == IPPROTO_UDP) {
            if (static_cast<size_t>(l4_payload_size) < sizeof(UDPHeader)) return;
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
            info.tcp_seq = 0;
            info.tcp_ack = 0;
            info.tcp_flags = 0;
            info.payload = l7_payload;
            info.payload_size = l7_payload_size;
            info.flow_id = get_canonical_flow_id(info.src_ip, info.src_port, info.dst_ip, info.dst_port);

            bool handled = false;
            for (const auto& parser : parsers) {
                const auto& name = parser->getName();
                if (name == "tcp_session" || name == "unknown" || name == "arp") continue;

                if (parser->isProtocol(info)) {
                    std::lock_guard<std::mutex> lock(m_output_streams[name].mutex);
                    parser->parse(info);
                    handled = true;
                    break;
                }
            }

            if (!handled) {
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

PacketParser::Statistics PacketParser::getStatistics() const {
    return {
        m_packets_captured.load(),
        m_packets_processed.load(),
        m_redis_sent.load(),
        m_elasticsearch_sent.load(),
        m_errors.load()
    };
}