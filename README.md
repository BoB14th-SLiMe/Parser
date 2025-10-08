⚡ C++ 고성능 패킷 파서 (High-Performance Packet Parser)이 프로젝트는 **C++**를 사용하여 .pcap 파일로부터 네트워크 패킷을 고속으로 읽어와 분석하는 고성능 파서입니다. CMake를 통해 크로스 플랫폼 빌드를 지원하며, libpcap 라이브러리를 활용하여 패킷을 캡처하고 처리합니다.🎯 TCP 프로토콜을 기준으로 주요 헤더 정보와 데이터(Payload)를 추출하여, 후속 분석이 용이하도록 CSV 파일로 저장하는 것을 목표로 합니다.✨ 주요 기능⚡ 고속 처리: C++의 포인터 연산과 구조체 매핑을 통해 메모리에서 직접 패킷을 파싱하여 시스템 오버헤드를 최소화하고 처리 속도를 극대화했습니다.📦 계층적 파싱: Ethernet, IP, TCP 헤더를 순차적으로 분석하여 정확한 데이터 오프셋을 계산합니다.📊 구조화된 데이터 추출: 각 TCP 세션의 핵심 정보(출발지/목적지 IP 및 포트)와 전체 데이터그램(Payload)을 추출합니다.📝 CSV 출력: 파싱된 결과를 src_ip,src_port,dst_ip,dst_port,datagram 형식의 CSV 파일로 저장하여 Excel, Python Pandas 등 다양한 도구에서 쉽게 활용할 수 있습니다.🛠️ 크로스 플랫폼 빌드: CMake를 사용하여 macOS, Linux 등 다양한 운영체제에서 손쉽게 빌드하고 실행할 수 있습니다.🚀 실행 방법1. 사전 요구사항 설치컴파일을 위해 CMake와 libpcap 라이브러리가 필요합니다.macOS (Homebrew)brew install cmake libpcap
Ubuntu/Debiansudo apt-get update
sudo apt-get install cmake libpcap-dev
2. 저장소 클론git clone [Your-Repository-URL]
cd [repository-name]
3. 빌드프로젝트 최상위 디렉토리에서 아래 명령어를 실행하여 빌드합니다.# 1. 빌드 디렉토리 생성 및 CMake 설정
cmake -B build

# 2. 컴파일 실행
cmake --build build
4. 파서 실행build 디렉토리 안에 생성된 parser 실행 파일을 통해 .pcap 파일을 분석합니다.# output 디렉토리 생성 (최초 1회)
mkdir -p output

# 파서 실행 (예: test_data/sample.pcap 파일을 분석)
./build/parser test_data/sample.pcap
실행이 완료되면 output/tcp_packets.csv 파일이 생성됩니다.📊 출력 결과 예시output/tcp_packets.csv 파일에는 아래와 같은 형식으로 데이터가 저장됩니다. datagram 필드는 16진수(Hex) 문자열로 인코딩됩니다.src_ip,src_port,dst_ip,dst_port,datagram
192.168.0.10,54321,172.217.25.4,443,170303005d0303...
172.217.25.4,443,192.168.0.10,54321,170303011a0303...
...
이 CSV 파일을 Wireshark와 함께 활용하면 특정 패킷의 페이로드를 추적하고 분석하는 데 매우 유용합니다.🛠️ 기술 스택주요 언어: C++ (C++11)빌드 시스템: CMake핵심 라이브러리: libpcap분석 도구: Wireshark (pcap 생성 및 검증), 모든 스프레드시트 프로그램 (CSV 확인)📁 프로젝트 구조header_parser/
├── build/                  # 컴파일 결과물이 저장되는 디렉토리
├── include/
│   └── packet_parser/
│       ├── network_headers.h # 네트워크 헤더 구조체 정의
│       └── PacketParser.h    # PacketParser 클래스 선언
├── output/                 # CSV 출력 파일이 저장되는 디렉토리
│   └── tcp_packets.csv
├── src/
│   ├── PacketParser.cpp    # PacketParser 클래스 구현
│   └── main.cpp            # 프로그램 시작점
├── test_data/              # 테스트용 pcap 파일
│   └── sample.pcap
├── .gitignore
├── CMakeLists.txt          # CMake 빌드 스크립트
└── README.md
💡 동작 원리이 파서는 구조체 매핑(Struct Mapping) 이라는 C/C++의 고전적이면서도 강력한 기법을 사용합니다.구조체 정의: network_headers.h에 Ethernet, IP, TCP 헤더와 동일한 메모리 레이아웃을 갖는 C++ 구조체를 #pragma pack(1) 지시자와 함께 정의합니다.포인터 캐스팅: .pcap 파일에서 읽어온 원본 패킷 데이터(raw byte array)의 메모리 주소를 위에서 정의한 구조체의 포인터로 형 변환(casting)합니다.데이터 접근: 형 변환된 포인터를 통해 -> 연산자를 사용하여 각 헤더 필드(IP 주소, 포트 등)에 직접 접근합니다. 이 방식은 불필요한 메모리 복사를 제거하여 최고의 성능을 보장합니다.🎯 사용 사례네트워크 트래픽 통계 분석: 대용량 pcap 파일에서 특정 조건의 트래픽 통계를 신속하게 추출보안 로그 분석: 침해사고 분석 시 특정 IP나 포트와 관련된 페이로드를 일괄 추출하여 분석프로토콜 학습: 네트워크 프로토콜의 실제 구조를 코드를 통해 깊이 있게 학습하기 위한 교육 자료맞춤형 모니터링 도구 개발: 특정 패턴의 패킷을 감지하는 커스텀 IDS/IPS의 프로토타입 개발📞 문의 및 기여프로젝트에 대한 질문이나 개선 아이디어가 있다면 언제든지 GitHub Issue를 등록해주세요. Pull Request는 언제나 환영합니다!