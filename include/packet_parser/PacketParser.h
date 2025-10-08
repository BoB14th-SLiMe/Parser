#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <fstream>
#include <string>

class PacketParser {
public:
    // 생성자: 출력 파일들을 열고 헤더를 쓴다.
    PacketParser(const std::string& tcp_filename, const std::string& udp_filename);
    
    // 소멸자: 파일 스트림을 안전하게 닫는다.
    ~PacketParser();

    // 패킷 파싱 메인 함수
    void parse(const u_char* packet);

private:
    std::ofstream m_tcp_csv_file;
    std::ofstream m_udp_csv_file;

    // 데이터를 CSV 형식의 한 줄로 변환하는 헬퍼 함수
    std::string format_payload_to_hex(const u_char* payload, int size);
};

#endif // PACKET_PARSER_H