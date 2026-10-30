# ICS Packet Parser (C++)

고성능 산업 제어 시스템(ICS) 네트워크 패킷 파서

## 📋 개요

C++로 구현된 고성능 패킷 파서로, 산업 제어 시스템(ICS/OT) 네트워크 트래픽을 실시간으로 분석하고 Redis 및 Elasticsearch로 전송합니다.

### 주요 특징

- 🚀 **고성능**: 50,000+ pps 처리 능력
- 🔄 **실시간 처리**: 비동기 Redis/Elasticsearch 전송
- 📊 **표준 출력**: 47-field CSV 형식 + JSONL 형식
- 🔌 **다중 프로토콜**: 10+ 산업용 프로토콜 지원
- 📈 **확장 가능**: 멀티스레드, 연결 풀링, 벌크 인덱싱
- 🎯 **2가지 모드**: 학습 모드 (PCAP → CSV) / 운영 모드 (실시간 캡처)

## 🎯 지원 프로토콜

### ICS/SCADA 프로토콜
- **XGT/FEnet** (포트 2004, 2005) - LS Electric PLC 프로토콜
- **Modbus TCP** (포트 502) - 범용 PLC 프로토콜
- **S7comm** (포트 102) - Siemens PLC 프로토콜
- **DNP3** - SCADA 프로토콜
- **MMS** - Manufacturing Message Specification

### 네트워크 프로토콜
- **DNS** (포트 53) - Domain Name System
- **ARP** - Address Resolution Protocol
- **DHCP** - Dynamic Host Configuration Protocol
- **TCP/UDP** - 전송 계층 프로토콜

### CSV 출력에 나타나는 protocol 값

파서는 패킷을 분석하여 다음 프로토콜 중 하나로 분류합니다:

#### 주요 ICS 프로토콜 (완전 파싱)
- `xgt_fen` - LS Electric PLC (XGT/FEnet)
- `modbus` - Modbus TCP
- `s7comm` - Siemens S7comm

#### 네트워크 프로토콜
- `arp` - Address Resolution Protocol
- `dns` - Domain Name System
- `dhcp` - Dynamic Host Configuration Protocol

#### 기타 프로토콜
- `tcp_session` - TCP 세션 (ICS 프로토콜 미식별)
- `mms` - Manufacturing Message Specification
- `tcp` - 일반 TCP 트래픽
- `udp` - 일반 UDP 트래픽
- `unknown` - 프로토콜 미식별

**실제 attack_01.pcap 분석 결과:**
```
xgt_fen:      62,861 packets (58.6%)
modbus:       20,433 packets (19.0%)
s7comm:       11,453 packets (10.7%)
tcp_session:   6,135 packets (5.7%)
mms:           5,727 packets (5.3%)
arp:             492 packets (0.5%)
dhcp:             54 packets (0.1%)
unknown:         191 packets (0.2%)
---
Total:       107,346 records
```

### 프로토콜 상세

#### XGT/FEnet
- ✅ 연속 블록(Continuous Block) 읽기 지원
- ✅ Multi-row 출력 (각 WORD마다 별도 행 생성)
- ✅ Request-Response 매칭 (invoke_id 기반)
- ✅ 주소 변환 (%DB001194 → D597)
- ✅ 자산 매핑 및 설명 자동 추가

## 🏗️ 아키텍처

```
┌─────────────────────────────────────────────────────────────┐
│                     ICS Packet Parser (C++)                  │
├─────────────────────────────────────────────────────────────┤
│  PCAP Capture (libpcap)                                      │
│       ↓                                                       │
│  PacketParser (멀티스레드)                                   │
│       ↓                                                       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Protocol Parsers                                     │   │
│  │  • XgtFenParser    • ModbusParser   • S7CommParser   │   │
│  │  • Dnp3Parser      • DnsParser      • ArpParser      │   │
│  └──────────────────────────────────────────────────────┘   │
│       ↓                                                       │
│  UnifiedWriter (시간 기반 CSV 출력)                          │
│       ↓                                                       │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │  RedisCache      │  │ Elasticsearch    │                 │
│  │  (비동기, 풀링)  │  │ (벌크 인덱싱)    │                 │
│  └──────────────────┘  └──────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
```

### 핵심 컴포넌트

#### 1. PacketParser
- libpcap 기반 패킷 캡처
- 프로토콜 자동 감지 및 라우팅
- 멀티스레드 패킷 처리

#### 2. Protocol Parsers
- **XgtFenParser**: XGT/FEnet 프로토콜 (continuous block multi-row 지원)
- **ModbusParser**: Modbus TCP (request-response 매칭)
- **S7CommParser**: Siemens S7comm
- **기타**: DNP3, DNS, ARP, Generic, Unknown

#### 3. UnifiedWriter
- 시간 기반 CSV 파일 생성 (청크 단위)
- JSONL 형식 동시 출력
- Python 파서와 동일한 47-field 형식

#### 4. RedisCache
- **연결 풀**: 8개 연결 (설정 가능)
- **비동기 writer**: 2개 스레드 (설정 가능)
- **Stream 기반**: `stream:protocol:{protocol}`
- **통계 카운터**: `stats:count:{protocol}`

#### 5. ElasticsearchClient
- **벌크 인덱싱**: 100개 문서 배치 (설정 가능)
- **자동 flush**: 1000ms 간격 (설정 가능)
- **일별 인덱스**: `ics-packets-{protocol}-{YYYY.MM.DD}`
- **스레드 안전**: CURL 멀티스레딩 지원

## 📦 설치

### 의존성

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    libpcap-dev \
    libcurl4-openssl-dev \
    libhiredis-dev \
    nlohmann-json3-dev

# CentOS/RHEL
sudo yum install -y \
    gcc-c++ \
    cmake \
    libpcap-devel \
    libcurl-devel \
    hiredis-devel \
    json-devel

# macOS (Homebrew)
brew install cmake pkg-config libpcap hiredis nlohmann-json
```

### 빌드

```bash
cd Parser

# Clean build
make clean && make

# 또는 CMake 직접 사용
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

#### macOS 빌드

Homebrew의 libpcap은 keg-only라 pkg-config가 찾지 못하고, `CMakeLists.txt`가 라이브러리 이름만 링크하므로 경로를 직접 지정해야 합니다.

```bash
PKG_CONFIG_PATH=/opt/homebrew/opt/libpcap/lib/pkgconfig \
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_EXE_LINKER_FLAGS="-L/opt/homebrew/opt/libpcap/lib -L/opt/homebrew/lib"
cmake --build build -j
```

### Docker

```bash
# 이미지 빌드
docker build -t ics-packet-parser .

# 실행 (호스트 네트워크 모드)
docker run --rm --network host \
    -v $(pwd)/output:/app/output \
    -v $(pwd)/assets:/app/assets \
    ics-packet-parser -i eth0
```

## 🚀 사용법

Parser는 **2가지 운영 모드**를 지원합니다:

### 1️⃣ 학습 모드 (Training Mode)

**목적**: PCAP 파일을 읽어 CSV/JSONL 형식으로 변환

**특징**:
- ✅ 오프라인 분석
- ✅ CSV + JSONL 동시 출력
- ✅ 시간 기반 청크 분할 지원
- ✅ Redis/Elasticsearch 비활성화 (파일 출력만)

**기본 사용법**:
```bash
# 단일 파일 출력 (output_all.csv + output_all.jsonl)
./parser -p input.pcap -o output

# 시간 기반 청크 분할 (30분 단위)
./parser -p input.pcap -o output -r 30

# 실제 예시
./parser -p pcap/attack_01.pcap -o output
```

**출력 파일**:
- `output_all.csv` - 47개 필드 전체 (빈 값도 포함)
- `output_all.jsonl` - 값이 있는 필드만 (빈 값 제외)

### 2️⃣ 운영 모드 (Operation Mode)

**목적**: 실시간 네트워크 트래픽 캡처 및 Redis/Elasticsearch 전송

**특징**:
- ✅ 실시간 패킷 캡처
- ✅ Redis Stream 전송 (프로토콜별)
- ✅ Elasticsearch 벌크 인덱싱 (일별 인덱스)
- ✅ 비동기 처리 (고성능)
- ✅ 선택적 CSV 출력 (옵션)

**기본 사용법**:
```bash
# Redis + Elasticsearch (실시간 전송)
sudo ./parser -i eth0 \
    --redis-host 127.0.0.1 \
    --es-host 192.168.4.140

# Redis만 사용
sudo ./parser -i eth0 --disable-es

# Elasticsearch만 사용
sudo ./parser -i eth0 --disable-redis

# 실시간 + CSV 출력 (동시)
sudo ./parser -i eth0 -o output
```

**주의**: root 권한 필요 (또는 CAP_NET_RAW 권한)

### 명령줄 옵션

```
입력 옵션 (택일):
  -p, --pcap <file>         PCAP 파일 경로 (학습 모드)
  -i, --interface <name>    네트워크 인터페이스 (운영 모드)

출력 옵션:
  -o, --output <dir>        출력 디렉토리 (기본: ./output)
  -r, --rolling <minutes>   파일 분할 간격 (0=단일 파일, 기본: 0)
  --realtime                실시간 모드 (파일 출력 없음, Redis/ES만)

성능 옵션:
  --threads <num>           워커 스레드 수 (0=자동, 기본: 8)
  -f, --filter <bpf>        BPF 필터 문자열

Redis 옵션 (운영 모드):
  --redis-host <host>       Redis 호스트 (기본: 127.0.0.1)
  --redis-port <port>       Redis 포트 (기본: 6379)
  --redis-password <pass>   Redis 비밀번호
  --disable-redis           Redis 비활성화

Elasticsearch 옵션 (운영 모드):
  --es-host <host>          Elasticsearch 호스트 (기본: 192.168.4.140)
  --es-port <port>          Elasticsearch 포트 (기본: 9200)
  --es-user <user>          Elasticsearch 사용자명
  --es-password <pass>      Elasticsearch 비밀번호
  --es-bulk-size <size>     벌크 인덱싱 크기 (기본: 100)
  --disable-es              Elasticsearch 비활성화

기타:
  -h, --help                도움말 출력
```

### 사용 예제

```bash
# 학습 모드: PCAP 파일 분석
./parser -p attack_01.pcap -o output

# 학습 모드: 30분 단위 청크
./parser -p normal_traffic.pcap -o output -r 30

# 운영 모드: 실시간 캡처 (Redis + ES)
sudo ./parser -i eth0

# 운영 모드: BPF 필터 적용
sudo ./parser -i eth0 -f "port 502 or port 2004"

# 운영 모드: 스레드 수 조정
sudo ./parser -i eth0 --threads 16

# 운영 모드: 파일 출력 없이 실시간 전송만
sudo ./parser -i eth0 --realtime
```

## ⚙️ 설정

### Redis 설정

```cpp
RedisCacheConfig config;
config.host = "127.0.0.1";
config.port = 6379;
config.pool_size = 8;              // 연결 풀 크기
config.async_writers = 2;           // 비동기 writer 스레드 수
config.async_queue_size = 10000;    // 비동기 큐 크기
config.max_stream_length = 100000;  // 최대 스트림 길이
```

### Elasticsearch 설정

```cpp
ElasticsearchConfig config;
config.host = "192.168.4.140";
config.port = 9200;
config.index_prefix = "ics-packets";
config.bulk_size = 100;             // 벌크 인덱싱 크기
config.flush_interval_ms = 1000;    // 자동 flush 간격 (ms)
config.use_https = false;
```

### 자산 매핑

자산 매핑 CSV 파일을 `assets/` 디렉토리에 배치:

```
assets/
├── 자산IP.csv              # IP → 자산 이름 매핑
├── 유선_Input.csv          # Input 레지스터 매핑
└── 유선_Output.csv         # Output 레지스터 매핑
```

## 📊 출력 형식

### CSV 출력 (47 필드)

표준 ICS 패킷 분석 형식:

```csv
@timestamp,protocol,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,src_asset,dst_asset,
arp.op,arp.smac,arp.sip,arp.tmac,arp.tip,
dns.tid,dns.fl,dns.qc,dns.ac,
dnp3.len,dnp3.ctrl,dnp3.dest,dnp3.src,
len,
modbus.tid,modbus.fc,modbus.bc,modbus.addr,modbus.qty,modbus.regs.addr,modbus.regs.val,modbus.translated_addr,modbus.description,
s7comm.ros,s7comm.fn,s7comm.ic,s7comm.db,s7comm.addr,s7comm.len,s7comm.description,
xgt_fen.prid,xgt_fen.companyId,xgt_fen.plcinfo,xgt_fen.cpuinfo,xgt_fen.source,xgt_fen.len,xgt_fen.fenetpos,xgt_fen.cmd,xgt_fen.dtype,xgt_fen.blkcnt,xgt_fen.errstat,xgt_fen.vars,xgt_fen.datasize,xgt_fen.data,xgt_fen.translated_addr,xgt_fen.description
```

**실제 예시** (attack_01.pcap):
```csv
2025-11-10T08:43:40.425150Z,xgt_fen,00:05:14:07:4d:6d,00:0b:29:74:0f:7b,192.168.10.80,49159,192.168.10.15,2004,2445164425,865801331,24,request,,,,,,,,,,,,,,,,21,,,,,,,,,,,,,,,,,43008,LSIS-XGT,0,160,51,21,0,84,20,1,0,%DB001194,2,,,
```

### JSONL 출력

빈 필드를 제외한 JSON Lines 형식 (숫자 필드는 number 타입):

**출력 예시**:
```json
{"@timestamp":"2025-11-10T08:43:40.425150Z","protocol":"xgt_fen","smac":"00:05:14:07:4d:6d","dmac":"00:0b:29:74:0f:7b","sip":"192.168.10.80","dip":"192.168.10.15","sp":49159,"dp":2004,"sq":2445164425,"ak":865801331,"fl":24,"dir":"request","len":21,"xgt_fen.prid":43008,"xgt_fen.companyId":"LSIS-XGT","xgt_fen.plcinfo":0,"xgt_fen.cpuinfo":160,"xgt_fen.source":51,"xgt_fen.len":21,"xgt_fen.fenetpos":0,"xgt_fen.cmd":84,"xgt_fen.dtype":20,"xgt_fen.blkcnt":1,"xgt_fen.errstat":0,"xgt_fen.vars":"%DB001194","xgt_fen.datasize":2}
```

**특징**:
- 빈 필드 자동 제외
- 숫자 필드는 JSON number 타입
- 한 줄에 하나의 패킷 (JSON Lines 형식)

### Redis Stream

프로토콜별 스트림에 저장:

```
stream:protocol:xgt_fen
stream:protocol:modbus
stream:protocol:s7comm
...
```

각 엔트리는 단일 "data" 필드에 JSON 문자열 저장:

```json
{
  "data": "{\"@timestamp\":\"...\",\"protocol\":\"xgt_fen\",...}"
}
```

### Elasticsearch 인덱스

일별, 프로토콜별 인덱스:

```
ics-packets-xgt_fen-2025.12.08
ics-packets-modbus-2025.12.08
ics-packets-s7comm-2025.12.08
```

## 📊 성능 및 검증

### 실제 테스트 결과 (attack_01.pcap)

**파일 정보**:
- 입력: 7.1MB PCAP (75,065 packets)
- 출력: 107,346 records (23MB CSV + 45MB JSONL)

**프로토콜 분석**:
```
xgt_fen:      62,861 packets (58.6%)
modbus:       20,433 packets (19.0%)
s7comm:       11,453 packets (10.7%)
tcp_session:   6,135 packets (5.7%)
mms:           5,727 packets (5.3%)
arp:             492 packets (0.5%)
dhcp:             54 packets (0.1%)
unknown:         191 packets (0.2%)
```

### 주요 기능

✅ **XGT Continuous Block**: Multi-row 출력 (각 WORD마다 별도 행)
✅ **Modbus Multi-register**: 각 레지스터마다 별도 행
✅ **Redis Stream**: 프로토콜별 분류 `stream:protocol:{protocol}`
✅ **Elasticsearch**: 일별 인덱스 `ics-packets-{protocol}-{YYYY.MM.DD}`
✅ **자산 매핑**: CSV 파일 기반 자동 매핑
✅ **주소 변환**: XGT (%DB → D), Modbus (300001+, 400001+), S7comm (DB,addr)

### 성능 특성

| 항목 | 성능 |
|------|------|
| 처리량 | 약 100,000 pps (threads=1, 학습 모드) |
| 메모리 | 입력 크기에 비례해 증가 (아래 알려진 이슈 참고) |
| 지연시간 (Redis) | <0.5ms (비동기) |
| 지연시간 (ES) | <5ms (벌크) |

### 벤치마크 (wireshark_parser 대비)

`capture.pcap` (1,938,179 packets, 181 MiB), Apple M3 Pro / 18 GB, 학습 모드(`-p`, 롤링 없음), C++은 5회 중앙값.

| 케이스 | 시간 | CPU | 최대 RSS | 처리량 |
|---|---|---|---|---|
| C++ `--threads 1` | 18.97s | 23.1s | 9,139 MiB | 102,158 pps |
| C++ `--threads 2` | 15.79s | 23.1s | 8,037 MiB | 122,750 pps |
| C++ `--threads 4` | 14.99s | 26.3s | 8,028 MiB | 129,337 pps |
| wireshark_parser (`train.py`) | 458.57s | 645.1s | 1,143 MiB | 4,227 pps |

- 출력 행 수는 양쪽 모두 2,772,932로 동일하며, `--threads 1` 기준 필드 일치율은 94.2%입니다.
- 남은 차이: `modbus.translated_addr`를 C++은 요청 행에도 채우고 Python은 응답 행에만 채움(158,913행), C++이 `unknown`으로 분류한 713행을 tshark는 `udp`/`dns` 등으로 분류.

### ⚠️ 알려진 이슈

1. **`--threads` ≥ 2에서 출력이 부정확함**
   - 모든 워커가 하나의 큐에서 임의의 패킷을 가져가지만, 요청 정보를 저장하는 프로토콜 파서는 워커별로 따로 있습니다.
   - 같은 세션의 요청과 응답이 다른 워커로 가면 XGT 응답의 `xgt_fen.vars`/`xgt_fen.translated_addr`가 비고, Modbus `modbus.regs.addr`가 틀어집니다. (`--threads 4`에서 약 53만 행)
   - 정확한 결과가 필요하면 `--threads 1`을 사용하세요. 수정 방향: 5-tuple 해시로 세션별 워커 고정 배정.
2. **메모리가 입력 크기에 비례해 증가함** (대용량 PCAP에서 OOM 가능)
   - 롤링 없이(`-r 0`) 실행하면 `UnifiedWriter`가 모든 레코드를 메모리에 보관했다가 종료 시 한 번에 기록합니다.
   - 패킷 큐(`m_packet_queue`)에 상한이 없어 파싱보다 읽기가 빠르면 패킷 사본이 쌓입니다.
   - 약 194만 패킷에서 8~9 GiB를 사용합니다. 대용량 PCAP은 `-r` 롤링 옵션 사용을 권장합니다. 수정 방향: bounded queue + 주기적 flush.

## 📈 성능 최적화

### 컴파일 옵션

```bash
# 최적화 빌드 (기본)
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# 프로파일링
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
```

### 런타임 최적화

```bash
# Redis 연결 풀 증가
./parser -i eth0 --redis-pool-size 16

# Elasticsearch 벌크 크기 증가
./parser -i eth0 --es-bulk-size 500

# CPU 코어 고정 (NUMA 시스템)
taskset -c 0-7 ./parser -i eth0
```

## 🐛 디버깅

### 로그 레벨

```cpp
// 코드에서 로그 레벨 조정
std::cout << "[INFO] ..." << std::endl;   // 일반 정보
std::cerr << "[WARN] ..." << std::endl;   // 경고
std::cerr << "[ERROR] ..." << std::endl;  // 에러
```

### 일반적인 문제

#### "Permission denied" (캡처 실패)
```bash
# sudo로 실행하거나 CAP_NET_RAW 권한 부여
sudo setcap cap_net_raw,cap_net_admin=eip ./parser
./parser -i eth0
```

#### "Redis connection failed"
```bash
# Redis 서버 확인
redis-cli ping

# 방화벽 확인
sudo ufw allow 6379/tcp
```

#### "Elasticsearch connection failed"
```bash
# Elasticsearch 서버 확인
curl http://192.168.4.140:9200

# 인덱스 템플릿 확인
curl http://192.168.4.140:9200/_cat/indices?v
```

## 📁 프로젝트 구조

```
Parser/
├── src/
│   ├── main.cpp                    # 메인 엔트리포인트
│   ├── PacketParser.cpp/h          # 패킷 파서 메인
│   ├── UnifiedWriter.cpp/h         # CSV/JSONL 출력
│   ├── TimeBasedCsvWriter.cpp/h    # 시간 기반 CSV
│   ├── RedisCache.cpp/h            # Redis 클라이언트
│   ├── ElasticsearchClient.cpp/h   # Elasticsearch 클라이언트
│   ├── AssetManager.cpp/h          # 자산 매핑 관리
│   ├── protocols/                  # 프로토콜 파서
│   │   ├── BaseProtocolParser.cpp/h
│   │   ├── XgtFenParser.cpp/h      # XGT/FEnet
│   │   ├── ModbusParser.cpp/h      # Modbus TCP
│   │   ├── S7CommParser.cpp/h      # S7comm
│   │   ├── Dnp3Parser.cpp/h        # DNP3
│   │   ├── DnsParser.cpp/h         # DNS
│   │   └── ArpParser.cpp/h         # ARP
│   └── network/
│       └── network_headers.h       # 네트워크 헤더 정의
├── assets/                         # 자산 매핑 CSV
├── output/                         # 출력 디렉토리
├── CMakeLists.txt                  # CMake 빌드 설정
├── Dockerfile                      # Docker 이미지
└── README.md                       # 본 문서
```

## 🔗 관련 기술

- **libpcap**: 패킷 캡처 라이브러리
- **Redis**: 실시간 데이터 스트리밍
- **Elasticsearch**: 로그 인덱싱 및 검색
- **nlohmann/json**: C++ JSON 라이브러리

## 📝 라이선스

Industrial Control Systems Network Packet Parser

## 🤝 기여

버그 리포트, 기능 요청, Pull Request를 환영합니다!

### 새 프로토콜 추가

1. `src/protocols/` 에 새 파서 클래스 생성
2. `BaseProtocolParser` 상속
3. `isProtocol()` 및 `parse()` 구현
4. `CMakeLists.txt` 에 소스 파일 추가
5. `PacketParser.cpp` 에 파서 등록

## 📞 지원

문제가 발생하면 다음을 확인하세요:

1. 의존성이 모두 설치되었는지 확인
2. PCAP 파일 또는 네트워크 인터페이스가 유효한지 확인
3. Redis/Elasticsearch 서버가 실행 중인지 확인
4. 로그 메시지에서 상세 에러 정보 확인

---

**현재 버전**: 1.0.0
**최종 업데이트**: 2025-12-08
**출력 형식**: 47-field CSV + JSONL
