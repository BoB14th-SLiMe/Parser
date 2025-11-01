# TCP Datagram Parser

이 파서는 pcap 파일을 읽어, 각 프로토콜(Modbus, S7Comm, DNP3 등)을 식별하고,
실시간으로 페이로드 데이터를 분석하여 정규화(flattened) 및 **확장(exploded)**된
최종 csv 파일과 원본 jsonl 파일을 output/ 디렉토리에 생성합니다.

별도의 Python 후처리 스크립트가 필요 없습니다.

## 빌드 방법

### macOS / Linux

```
rm -rf build 
cmake -B build
cmake --build build
```

### Windows (x86/x64)

1. CMake를 설치합니다.

2. Npcap SDK를 다운로드하여 설치합니다.
    - 중요: 설치 과정에서 "SDK" 설치 옵션을 반드시 체크해야 합니다.

3. C++ 컴파일러를 설치합니다.
    - (예: Visual Studio Community에서 "C++를 사용한 데스크톱 개발" 워크로드 설치)

4. 컴파일러와 CMake의 경로가 설정된 터미널(예: "x64 Native Tools Command Prompt for VS")을 엽니다.

5. 아래 명령어를 실행합니다:

```
rm -rf build
cmake -B build
cmake --build build
```

## 사용법
빌드가 완료되면 build/ 디렉토리(또는 Windows의 경우 build/Debug/ 또는 build/Release/)에
parser (또는 parser.exe) 실행 파일이 생성됩니다.

파싱할 pcap 파일을 인자로 전달하여 실행합니다.

```
# macOS / Linux
./build/parser test_data/sample.pcap

# Windows
./build/Debug/parser.exe test_data/sample.pcap
```
결과물은 output/ 디렉토리에 프로토콜별 .csv와 .jsonl 파일로 저장됩니다.
(예: output/s7comm.csv, output/modbus_tcp.csv)

streams.csv_stream.std::ostream::rdbuf(m_capture_buffers[protocol].get());