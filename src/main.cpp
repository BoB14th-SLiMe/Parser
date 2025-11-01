#include <iostream>
#include <pcap.h>
#include "./PacketParser.h"
#include <cstring>

// Windows 환경에서 Winsock 초기화를 위한 코드
#ifdef _WIN32
#include <winsock2.h>

// WSAStartup/WSACleanup을 자동으로 처리하기 위한 RAII 클래스
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


void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet) {
    PacketParser* parser = reinterpret_cast<PacketParser*>(user_data);
    parser->parse(header, packet);
}

void print_usage(const char* program_name) {
    std::cerr << "Usage: " << program_name << " <pcap_file> [time_interval] [num_threads]" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Arguments:" << std::endl;
    std::cerr << "  pcap_file      : Path to the pcap file to parse" << std::endl;
    std::cerr << "  time_interval  : (Optional) Time interval in minutes for unified CSV output" << std::endl;
    std::cerr << "                   If not specified or 0, creates individual protocol CSV files" << std::endl;
    std::cerr << "                   If specified (e.g., 30), creates unified CSV files per time slot" << std::endl;
    std::cerr << "  num_threads    : (Optional) Number of worker threads (default: CPU cores / 2)" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Examples:" << std::endl;
    std::cerr << "  " << program_name << " capture.pcap           # Individual CSVs, auto threads" << std::endl;
    std::cerr << "  " << program_name << " capture.pcap 30        # Unified CSVs, auto threads" << std::endl;
    std::cerr << "  " << program_name << " capture.pcap 30 4      # Unified CSVs, 4 threads" << std::endl;
}

int main(int argc, char* argv[]) {
    // Windows 환경일 경우, main 함수 시작 시 Winsock을 초기화합니다.
    #ifdef _WIN32
        WinSockInit winSockInit;
    #endif

    if (argc < 2 || argc > 4) {
        print_usage(argv[0]);
        return 1;
    }

    // 시간 간격 파라미터 파싱
    int time_interval = 0;
    if (argc >= 3) {
        time_interval = std::atoi(argv[2]);
        if (time_interval < 0) {
            std::cerr << "Error: time_interval must be a positive number" << std::endl;
            return 1;
        }
    }
    
    // 스레드 수 파라미터 파싱
    int num_threads = 0; // 0이면 자동 설정
    if (argc >= 4) {
        num_threads = std::atoi(argv[3]);
        if (num_threads < 0) {
            std::cerr << "Error: num_threads must be a positive number" << std::endl;
            return 1;
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open pcap file " << argv[1] << ": " << errbuf << std::endl;
        return 2;
    }

    // PacketParser 객체 생성 (시간 간격, 스레드 수 전달)
    PacketParser parser("output", time_interval, num_threads);
    
    std::cout << "Parsing pcap file: " << argv[1] << std::endl;
    if (time_interval > 0) {
        std::cout << "Mode: Unified CSV output with " << time_interval << "-minute intervals" << std::endl;
    } else {
        std::cout << "Mode: Individual protocol CSV files" << std::endl;
    }
    
    // 워커 스레드 시작
    parser.startWorkers();
    
    // 패킷 읽기 (메인 스레드에서 수행)
    std::cout << "Reading packets..." << std::endl;
    if (pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&parser)) < 0) {
        std::cerr << "pcap_loop() failed: " << pcap_geterr(handle) << std::endl;
    }
    
    std::cout << "Packet reading complete. Processing remaining packets..." << std::endl;
    
    // 모든 패킷이 처리될 때까지 대기
    parser.waitForCompletion();
    
    // 워커 스레드 종료
    parser.stopWorkers();
    
    std::cout << "Packet parsing complete." << std::endl;
    
    // 통합 CSV 생성 (time_interval > 0인 경우에만)
    if (time_interval > 0) {
        std::cout << "Generating unified CSV files..." << std::endl;
        parser.generateUnifiedCsv();
    }
    
    if (time_interval > 0) {
        std::cout << "Unified CSV files are in 'output/' directory." << std::endl;
        std::cout << "Format: output_YYYYMMDD_HHMM.csv" << std::endl;
    } else {
        std::cout << "Individual protocol CSV files are in 'output/' directory." << std::endl;
    }
    
    pcap_close(handle);
    return 0;
}