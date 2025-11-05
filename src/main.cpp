#include <iostream>
#include <pcap.h>
#include <csignal>
#include <cstring>
#include "./PacketParser.h"

#ifdef _WIN32
#include <winsock2.h>

class WinSockInit {
public:
    WinSockInit() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "WSAStartup failed." << std::endl;
            exit(1);
        }
    }
    ~WinSockInit() {
        WSACleanup();
    }
};
#endif

// 전역 변수로 PacketParser 포인터 저장 (시그널 핸들러에서 접근)
PacketParser* g_parser = nullptr;
pcap_t* g_handle = nullptr;

void signal_handler(int signum) {
    std::cout << "\n[INFO] Interrupt signal (" << signum << ") received. Stopping capture..." << std::endl;
    if (g_handle) {
        pcap_breakloop(g_handle);
    }
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet) {
    PacketParser* parser = reinterpret_cast<PacketParser*>(user_data);
    parser->parse(header, packet);
}

void print_usage(const char* program_name) {
    std::cerr << "Usage: " << program_name << " [OPTIONS]" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Options:" << std::endl;
    std::cerr << "  -f <pcap_file>     : Parse existing pcap file (offline mode)" << std::endl;
    std::cerr << "  -i <interface>     : Capture from network interface (live mode)" << std::endl;
    std::cerr << "  -t <minutes>       : Time interval for file rotation (default: 30)" << std::endl;
    std::cerr << "  -n <threads>       : Number of worker threads (default: auto)" << std::endl;
    std::cerr << "  -o <output_dir>    : Output directory (default: output)" << std::endl;
    std::cerr << "  -h                 : Show this help message" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Examples:" << std::endl;
    std::cerr << "  # Live capture mode (30 minute intervals)" << std::endl;
    std::cerr << "  " << program_name << " -i eth0" << std::endl;
    std::cerr << std::endl;
    std::cerr << "  # Live capture with custom interval (60 minutes)" << std::endl;
    std::cerr << "  " << program_name << " -i eth0 -t 60" << std::endl;
    std::cerr << std::endl;
    std::cerr << "  # Offline mode (parse existing pcap)" << std::endl;
    std::cerr << "  " << program_name << " -f capture.pcap -t 30" << std::endl;
    std::cerr << std::endl;
    std::cerr << "  # List available interfaces" << std::endl;
    std::cerr << "  " << program_name << " -i list" << std::endl;
}

void list_interfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return;
    }
    
    std::cout << "Available network interfaces:" << std::endl;
    std::cout << "-----------------------------" << std::endl;
    
    int i = 0;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        std::cout << ++i << ". " << d->name;
        if (d->description) {
            std::cout << " (" << d->description << ")";
        }
        std::cout << std::endl;
    }
    
    pcap_freealldevs(alldevs);
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    WinSockInit winSockInit;
#endif

    // 기본 설정
    std::string input_file;
    std::string interface;
    std::string output_dir = "output";
    int time_interval = 30;  // 기본 30분
    int num_threads = 0;
    bool live_mode = false;
    
    // 명령줄 인자 파싱
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "-f" && i + 1 < argc) {
            input_file = argv[++i];
        } else if (arg == "-i" && i + 1 < argc) {
            interface = argv[++i];
            live_mode = true;
        } else if (arg == "-t" && i + 1 < argc) {
            time_interval = std::atoi(argv[++i]);
        } else if (arg == "-n" && i + 1 < argc) {
            num_threads = std::atoi(argv[++i]);
        } else if (arg == "-o" && i + 1 < argc) {
            output_dir = argv[++i];
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // 인터페이스 목록 출력 요청
    if (live_mode && interface == "list") {
        list_interfaces();
        return 0;
    }
    
    // 입력 검증
    if (!live_mode && input_file.empty()) {
        std::cerr << "Error: Either -f (file) or -i (interface) must be specified" << std::endl;
        print_usage(argv[0]);
        return 1;
    }
    
    if (time_interval <= 0) {
        std::cerr << "Error: Time interval must be positive" << std::endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = nullptr;
    
    // pcap 핸들 생성
    if (live_mode) {
        std::cout << "========================================" << std::endl;
        std::cout << "Live Capture Mode" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "Interface: " << interface << std::endl;
        std::cout << "Time interval: " << time_interval << " minutes" << std::endl;
        std::cout << "Output directory: " << output_dir << std::endl;
        std::cout << "========================================" << std::endl;
        
        // 실시간 캡처
        handle = pcap_open_live(interface.c_str(), 65536, 1, 1000, errbuf);
        if (handle == nullptr) {
            std::cerr << "Error opening interface " << interface << ": " << errbuf << std::endl;
            std::cerr << "Hint: Try running with sudo/administrator privileges" << std::endl;
            std::cerr << "      Or use '-i list' to see available interfaces" << std::endl;
            return 2;
        }
    } else {
        std::cout << "========================================" << std::endl;
        std::cout << "Offline Mode" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "Input file: " << input_file << std::endl;
        std::cout << "Time interval: " << time_interval << " minutes" << std::endl;
        std::cout << "Output directory: " << output_dir << std::endl;
        std::cout << "========================================" << std::endl;
        
        // pcap 파일 읽기
        handle = pcap_open_offline(input_file.c_str(), errbuf);
        if (handle == nullptr) {
            std::cerr << "Error opening pcap file " << input_file << ": " << errbuf << std::endl;
            return 2;
        }
    }
    
    g_handle = handle;
    
    // 시그널 핸들러 등록 (Ctrl+C)
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // PacketParser 생성 (항상 time_interval 사용)
    PacketParser parser(output_dir, time_interval, num_threads);
    g_parser = &parser;
    
    // 워커 스레드 시작
    parser.startWorkers();
    
    std::cout << "[INFO] Starting packet capture..." << std::endl;
    if (live_mode) {
        std::cout << "[INFO] Press Ctrl+C to stop" << std::endl;
    }
    
    // 패킷 캡처 시작
    int result = pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&parser));
    
    if (result == -1) {
        std::cerr << "[ERROR] pcap_loop() failed: " << pcap_geterr(handle) << std::endl;
    } else if (result == -2) {
        std::cout << "[INFO] Capture stopped by user" << std::endl;
    }
    
    std::cout << "[INFO] Packet capture complete. Processing remaining packets..." << std::endl;
    
    // 모든 패킷 처리 대기
    parser.waitForCompletion();
    
    // 워커 스레드 종료
    parser.stopWorkers();
    
    std::cout << "[INFO] Generating output files..." << std::endl;
    
    // 통합 CSV/JSONL 생성
    parser.generateUnifiedOutput();
    
    std::cout << "[INFO] Output files generated in '" << output_dir << "/' directory" << std::endl;
    std::cout << "[INFO] Format: output_YYYYMMDD_HHMM.csv and output_YYYYMMDD_HHMM.jsonl" << std::endl;
    
    pcap_close(handle);
    return 0;
}