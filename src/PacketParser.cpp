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

PacketParser::PacketParser(const std::string& output_dir, 
                          int time_interval, 
                          int num_threads,
                          const RedisCacheConfig* redis_config,
                          const ElasticsearchConfig* es_config,
                          bool disable_file_output)
    : m_output_dir(output_dir),
      m_time_interval(time_interval),
      m_num_threads(0),
      m_disable_file_output(disable_file_output),
      m_assetManager("assets/자산IP.csv", "assets/유선_Input.csv", "assets/유선_Output.csv"),
      m_unified_writer(nullptr),
      m_redis_cache(nullptr),
      m_elasticsearch(nullptr),
      m_use_redis(redis_config != nullptr),
      m_use_elasticsearch(es_config != nullptr),
      m_stop_flag(false),
      m_packets_processed(0),
      m_packets_queued(0) {
    
    #ifdef _WIN32
        _mkdir(m_output_dir.c_str());
    #else
        mkdir(m_output_dir.c_str(), 0755);
    #endif

    // 스레드 수 결정
    if (num_threads <= 0) {
        unsigned int hw_threads = std::thread::hardware_concurrency();
        m_num_threads = std::max(1u, std::min(8u, hw_threads / 2));
    } else {
        m_num_threads = std::min(num_threads, 16);
    }
    
    std::cout << "[INFO] Using " << m_num_threads << " worker threads" << std::endl;

    // UnifiedWriter 초기화 (파일 출력이 필요한 경우만)
    if (!m_disable_file_output) {
        m_unified_writer = std::make_unique<UnifiedWriter>(m_output_dir, m_time_interval);
        std::cout << "[INFO] UnifiedWriter initialized with " << m_time_interval 
                  << " minute intervals" << std::endl;
    } else {
        std::cout << "[INFO] File output disabled - realtime mode only" << std::endl;
    }

    // Redis 초기화
    if (m_use_redis) {
        m_redis_cache = std::make_unique<RedisCache>(*redis_config);
        if (m_redis_cache->connect()) {
            std::cout << "[INFO] Redis connection established" << std::endl;
        } else {
            std::cerr << "[WARN] Redis connection failed" << std::endl;
            m_use_redis = false;
        }
    }
    
    // Elasticsearch 초기화
    if (m_use_elasticsearch) {
        m_elasticsearch = std::make_unique<ElasticsearchClient>(*es_config);
        if (m_elasticsearch->connect()) {
            std::cout << "[INFO] Elasticsearch connection established" << std::endl;
        } else {
            std::cerr << "[WARN] Elasticsearch connection failed" << std::endl;
            m_use_elasticsearch = false;
        }
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

    // AssetManager 설정 (모든 파서에)
    for (const auto& parser : parsers) {
        parser->setAssetManager(&m_assetManager);
    }

    // 파일 출력이 활성화된 경우만 UnifiedWriter 설정
    if (!m_disable_file_output && m_unified_writer) {
        for (const auto& parser : parsers) {
            parser->setUnifiedWriter(m_unified_writer.get());
        }

        // 첫 번째 워커만 백엔드 콜백 설정
        if (worker_id == 0) {
            m_unified_writer->setBackendCallback(
                [this](const UnifiedRecord& record) {
                    this->sendToBackends(record);
                }
            );
        }
    } else {
        // 파일 출력 없이 직접 백엔드로 전송
        for (const auto& parser : parsers) {
            // DummyWriter를 설정하거나 직접 콜백 설정
            parser->setDirectBackendCallback(
                [this](const UnifiedRecord& record) {
                    this->sendToBackends(record);
                }
            );
        }
    }
}

PacketParser::~PacketParser() {
    std::cout << "[INFO] PacketParser destructor called" << std::endl;
    stopWorkers();
    
    // Redis & Elasticsearch 연결 해제
    if (m_redis_cache) {
        m_redis_cache->disconnect();
    }
    if (m_elasticsearch) {
        m_elasticsearch->disconnect();
    }
    
    std::cout << "[INFO] Total packets processed: " << m_packets_processed.load() << std::endl;
    std::cout << "[INFO] PacketParser cleanup complete" << std::endl;
}

void PacketParser::sendToBackends(const UnifiedRecord& record) {
    try {
        // Elasticsearch로 즉시 전송 (기존과 동일)
        if (m_use_elasticsearch && m_elasticsearch->isConnected()) {
            json es_doc;
            es_doc["@timestamp"] = record.timestamp;
            es_doc["protocol"] = record.protocol;
            es_doc["src_ip"] = record.sip;
            es_doc["dst_ip"] = record.dip;
            
            // 포트 파싱
            try {
                es_doc["src_port"] = record.sp.empty() ? 0 : std::stoi(record.sp);
                es_doc["dst_port"] = record.dp.empty() ? 0 : std::stoi(record.dp);
            } catch (const std::exception& e) {
                std::cerr << "[WARN] Port parsing error: " << e.what() << std::endl;
                es_doc["src_port"] = 0;
                es_doc["dst_port"] = 0;
            }
            
            es_doc["src_mac"] = record.smac;
            es_doc["dst_mac"] = record.dmac;
            es_doc["direction"] = record.dir;
            
            // protocol_details 파싱 (details_json이 있는 경우만)
            if (!record.details_json.empty()) {
                try {
                    es_doc["protocol_details"] = json::parse(record.details_json);
                } catch (const std::exception& e) {
                    std::cerr << "[WARN] JSON parsing error: " << e.what() << std::endl;
                    es_doc["protocol_details"] = json::object();
                }
            } else {
                es_doc["protocol_details"] = json::object();
            }
            
            // 프로토콜별 중요 필드 추출 (기존과 동일)
            if (record.protocol == "modbus") {
                if (!record.modbus_fc.empty()) es_doc["modbus_function"] = record.modbus_fc;
                if (!record.modbus_addr.empty()) es_doc["modbus_address"] = record.modbus_addr;
                if (!record.modbus_description.empty()) es_doc["description"] = record.modbus_description;
            } else if (record.protocol == "s7comm") {
                if (!record.s7_fn.empty()) es_doc["s7_function"] = record.s7_fn;
                if (!record.s7_description.empty()) es_doc["description"] = record.s7_description;
            } else if (record.protocol == "xgt_fen") {
                if (!record.xgt_cmd.empty()) es_doc["xgt_command"] = record.xgt_cmd;
                if (!record.xgt_description.empty()) es_doc["description"] = record.xgt_description;
            }
            
            // 자산 정보 추가 (기존과 동일)
            if (m_use_redis && m_redis_cache->isConnected()) {
                AssetInfo src_asset = m_redis_cache->getAssetInfo(record.sip);
                AssetInfo dst_asset = m_redis_cache->getAssetInfo(record.dip);
                
                if (!src_asset.asset_id.empty()) {
                    es_doc["src_asset"] = src_asset.toJson();
                }
                if (!dst_asset.asset_id.empty()) {
                    es_doc["dst_asset"] = dst_asset.toJson();
                }
            }
            
            if (m_elasticsearch->addToBulk(record.protocol, es_doc)) {
                // 1000개마다 한번씩 로그 출력
                static std::atomic<int> es_add_count{0};
                int count = ++es_add_count;
                if (count % 1000 == 0) {
                    std::cout << "[Elasticsearch] ✓ Queued " << count << " documents to bulk" << std::endl;
                }
            } else {
                std::cerr << "[WARN] Failed to add to Elasticsearch bulk" << std::endl;
            }
        }
        
        // ★ Redis Stream으로 전송 - 프로토콜명을 키로 사용
        if (m_use_redis && m_redis_cache->isConnected()) {
            ParsedPacketData redis_data;
            redis_data.timestamp = record.timestamp;
            redis_data.protocol = record.protocol;

            // JSONL 형식과 동일한 짧은 필드명 사용
            redis_data.smac = record.smac;
            redis_data.dmac = record.dmac;
            redis_data.sip = record.sip;
            redis_data.sp = record.sp;
            redis_data.dip = record.dip;
            redis_data.dp = record.dp;
            redis_data.sq = record.sq;
            redis_data.ak = record.ak;
            redis_data.fl = record.fl;
            redis_data.dir = record.dir;

            // 자산 정보 추가
            redis_data.src_asset_id = record.src_asset_id;
            redis_data.src_asset_name = record.src_asset_name;
            redis_data.src_asset_group = record.src_asset_group;
            redis_data.src_asset_location = record.src_asset_location;
            redis_data.dst_asset_id = record.dst_asset_id;
            redis_data.dst_asset_name = record.dst_asset_name;
            redis_data.dst_asset_group = record.dst_asset_group;
            redis_data.dst_asset_location = record.dst_asset_location;

            // protocol_details 파싱 (details_json이 있는 경우만)
            if (!record.details_json.empty()) {
                try {
                    redis_data.protocol_details = json::parse(record.details_json);
                } catch (const std::exception& e) {
                    redis_data.protocol_details = json::object();
                }
            } else {
                redis_data.protocol_details = json::object();
            }

            std::string stream_name = RedisKeys::protocolStream(record.protocol);
            if (m_redis_cache->pushToStream(stream_name, redis_data)) {
                // 1000개마다 한번씩 로그 출력
                static std::atomic<int> redis_success_count{0};
                int count = ++redis_success_count;
                if (count % 1000 == 0) {
                    std::cout << "[Redis] ✓ Sent " << count << " records to streams" << std::endl;
                }
            } else {
                std::cerr << "[WARN] Failed to push to Redis stream: " << stream_name << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] sendToBackends exception: " << e.what() << std::endl;
    }
}

void PacketParser::startWorkers() {
    std::cout << "[INFO] Starting " << m_num_threads << " worker threads..." << std::endl;
    
    for (int i = 0; i < m_num_threads; ++i) {
        m_workers.emplace_back(&PacketParser::workerThread, this, i);
    }
    
    // Elasticsearch 실시간 flush 스레드
    if (m_use_elasticsearch) {
        m_workers.emplace_back(&PacketParser::realtimeFlushThread, this);
    }
    
    std::cout << "[INFO] Worker threads started" << std::endl;
}

void PacketParser::realtimeFlushThread() {
    std::cout << "[INFO] Realtime flush thread started" << std::endl;
    
    auto last_flush = std::chrono::steady_clock::now();
    const auto flush_interval = std::chrono::milliseconds(100);  // 100ms마다 체크
    
    while (!m_stop_flag.load()) {
        std::this_thread::sleep_for(flush_interval);
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_flush);
        
        // 100ms마다 또는 버퍼가 가득 찼을 때 flush
        if (elapsed >= flush_interval) {
            if (m_elasticsearch && m_elasticsearch->isConnected()) {
                m_elasticsearch->flushBulk();
            }
            last_flush = now;
        }
    }
    
    // 종료 시 마지막 flush
    if (m_elasticsearch && m_elasticsearch->isConnected()) {
        m_elasticsearch->flushBulk();
    }
    
    std::cout << "[INFO] Realtime flush thread stopped" << std::endl;
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

void PacketParser::generateUnifiedOutput() {
    if (m_disable_file_output || !m_unified_writer) {
        std::cout << "[INFO] File output disabled - skipping file generation" << std::endl;
        return;
    }
    
    std::cout << "[INFO] Generating unified output files..." << std::endl;
    m_unified_writer->flush();
    std::cout << "[INFO] Unified output generation complete" << std::endl;
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
    auto packet_data = std::make_shared<PacketData>(header, packet);
    
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        m_packet_queue.push(packet_data);
        m_packets_queued++;
    }
    
    m_queue_cv.notify_one();
}

void PacketParser::parsePacket(const struct pcap_pkthdr* header, const u_char* packet, int worker_id) {
    if (!packet || static_cast<size_t>(header->caplen) < sizeof(EthernetHeader)) return;

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
                parser->parse(info);
                break;
            }
        }
        return;
    }

    // IPv4 패킷 처리
    if (eth_type == 0x0800) {
        // size_t로 캐스팅하여 경고 제거
        if (static_cast<size_t>(l3_payload_size) < sizeof(IPHeader)) return;
        
        const IPHeader* ip_header = (const IPHeader*)(l3_payload);
        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

        // Use IP Total Length to calculate actual payload size (not captured buffer size)
        // This prevents garbage data in ACK packets from being counted as payload
        uint16_t ip_total_len = ntohs(ip_header->len);
        int ip_header_len = ip_header->hl * 4;

        const u_char* l4_payload = l3_payload + ip_header_len;
        int l4_payload_size = ip_total_len - ip_header_len;

        // TCP 패킷 처리
        if (ip_header->p == IPPROTO_TCP) {
            // size_t로 캐스팅하여 경고 제거
            if (static_cast<size_t>(l4_payload_size) < sizeof(TCPHeader)) return;
            
            const TCPHeader* tcp_header = (const TCPHeader*)(l4_payload);
            
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

            bool handled_by_specific_app_parser = false;
            for (const auto& parser : parsers) {
                const auto& name = parser->getName();
                if (name == "tcp_session" || name == "unknown" || name == "arp") {
                    continue;
                }

                if (parser->isProtocol(info)) {
                    parser->parse(info);
                    handled_by_specific_app_parser = true;
                    break;
                }
            }

            if (!handled_by_specific_app_parser) {
                for (const auto& parser : parsers) {
                    if (parser->getName() == "tcp_session") {
                        parser->parse(info);
                        break;
                    }
                }
            }
        }
        // UDP 패킷 처리
        else if (ip_header->p == IPPROTO_UDP) {
            // size_t로 캐스팅하여 경고 제거
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

            bool specific_app_protocol_found = false;
            for (const auto& parser : parsers) {
                const auto& name = parser->getName();
                if (name == "tcp_session" || name == "unknown" || name == "arp") {
                    continue;
                }

                if (parser->isProtocol(info)) {
                    parser->parse(info);
                    specific_app_protocol_found = true;
                    break;
                }
            }

            if (!specific_app_protocol_found) {
                for (const auto& parser : parsers) {
                    if (parser->getName() == "unknown") {
                        parser->parse(info);
                        break;
                    }
                }
            }
        }
    }
}