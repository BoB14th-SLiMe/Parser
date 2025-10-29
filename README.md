# C++ Realtime Parser

## 📋 개요

OT 보안 모니터링 시스템의 실시간 패킷 파싱 및 전처리 엔진입니다.

---

## 🏗️ 디렉토리 구조

```
RealtimeParser/
├── build/              # C++ 빌드 결과물
│   └── parser          # 실행 바이너리 (필수!)
├── src/                # C++ 소스 코드 (빌드용)
├── include/            # 헤더 파일
├── Dockerfile          # Docker 이미지 빌드
├── .dockerignore       # Docker 빌드 제외 파일
├── config.json         # Parser 설정 파일
└── README.md           # 이 문서
```

---

## 🚀 빠른 시작

### 1. Parser 바이너리 빌드

```bash
# RealtimeParser 디렉토리로 이동
cd RealtimeParser

# C++ 빌드 (예시)
mkdir -p build
cd build
cmake ..
make
# 결과: RealtimeParser/build/parser 생성됨
```

### 2. 바이너리 확인

```bash
# parser 바이너리가 있는지 확인
ls -lh RealtimeParser/build/parser

# 실행 권한 부여
chmod +x RealtimeParser/build/parser
```

### 3. Docker Compose로 실행

```bash
# 프로젝트 루트로 이동
cd ..

# 전체 스택 시작
docker-compose up -d

# Parser만 시작
docker-compose up -d cpp-parser

# 로그 확인
docker-compose logs -f cpp-parser
```

---

## ⚙️ 설정 파일 (config.json)

### Redis 설정
```json
{
  "redis": {
    "host": "redis",
    "port": 6379,
    "stream_name": "packet_stream"
  }
}
```

### Kafka 설정
```json
{
  "kafka": {
    "bootstrap_servers": "kafka:29092",
    "topics": {
      "threat_events": "threat-events",
      "dos_alerts": "dos-alerts"
    }
  }
}
```

### JSONL 출력 설정
```json
{
  "output": {
    "jsonl": {
      "enabled": true,
      "output_dir": "/data/parser-output",
      "file_prefix": "packets",
      "rotation_size_mb": 100,
      "rotation_interval_min": 60
    }
  }
}
```

---

## 🔧 Docker 이미지 빌드

### 로컬 빌드 (테스트용)

```bash
# RealtimeParser 디렉토리에서
docker build -t ot-security-parser .

# 실행
docker run --rm -it \
  -e REDIS_HOST=redis \
  -e KAFKA_BOOTSTRAP_SERVERS=kafka:29092 \
  ot-security-parser
```

### Docker Compose 빌드 (권장)

```bash
# 프로젝트 루트에서
docker-compose build cpp-parser

# 실행
docker-compose up -d cpp-parser
```

---

## 📊 출력 형식

### Redis Stream
```json
{
  "timestamp": "2025-01-03T10:00:00Z",
  "src_ip": "192.168.1.10",
  "dst_ip": "192.168.1.20",
  "protocol": "TCP",
  "src_port": 12345,
  "dst_port": 80,
  "bytes": 1024
}
```

### Kafka Topics
- **threat-events**: 위협 탐지 이벤트
- **dos-alerts**: DoS 공격 알람
- **raw-packets**: 원시 패킷 메타데이터

### JSONL 파일
```jsonl
{"timestamp":"2025-01-03T10:00:00Z","src_ip":"192.168.1.10","dst_ip":"192.168.1.20","protocol":"TCP","port":80}
{"timestamp":"2025-01-03T10:00:01Z","src_ip":"192.168.1.11","dst_ip":"192.168.1.21","protocol":"UDP","port":53}
```

---

## 🔍 모니터링

### 로그 확인
```bash
# Docker 로그
docker-compose logs -f cpp-parser

# Parser 내부 로그
docker exec -it ot-security-cpp-parser tail -f /app/logs/parser.log
```

### 출력 파일 확인
```bash
# JSONL 파일 목록
docker exec -it ot-security-cpp-parser ls -lh /data/parser-output/

# 파일 내용 확인
docker exec -it ot-security-cpp-parser head -n 10 /data/parser-output/*.jsonl
```

### Redis Stream 확인
```bash
docker exec -it ot-security-redis redis-cli

# Stream 길이
127.0.0.1:6379> XLEN packet_stream

# 최근 데이터
127.0.0.1:6379> XREAD COUNT 5 STREAMS packet_stream 0
```

---

## 🐛 트러블슈팅

### 1. Parser 바이너리가 없음

**증상**:
```
ERROR: failed to solve: failed to compute cache key: failed to calculate checksum of ref
```

**해결**:
```bash
# 바이너리 확인
ls -lh RealtimeParser/build/parser

# 없으면 빌드
cd RealtimeParser
mkdir -p build && cd build
cmake .. && make
```

### 2. Redis 연결 실패

**로그**:
```
[ERROR] Failed to connect to Redis: Connection refused
```

**해결**:
```bash
# Redis 상태 확인
docker-compose ps redis

# Redis 재시작
docker-compose restart redis

# Parser 재시작
docker-compose restart cpp-parser
```

### 3. Kafka 연결 실패

**로그**:
```
[ERROR] Kafka broker connection failed
```

**해결**:
```bash
# Kafka 상태 확인
docker-compose ps kafka

# Zookeeper부터 재시작
docker-compose restart zookeeper kafka cpp-parser
```

### 4. 권한 문제

**증상**:
```
permission denied: /app/parser
```

**해결**:
```bash
# 실행 권한 부여
chmod +x RealtimeParser/build/parser

# 이미지 재빌드
docker-compose build cpp-parser
docker-compose up -d cpp-parser
```

---

## 🎯 네트워크 모드

### 옵션 1: 브리지 네트워크 (기본)
```yaml
# docker-compose.yml
cpp-parser:
  networks:
    - ot-security-network
```
- ✅ 안전한 컨테이너 간 통신
- ❌ 호스트 네트워크 인터페이스 접근 불가

### 옵션 2: 호스트 네트워크 (패킷 캡처용)
```yaml
cpp-parser:
  network_mode: "host"
  privileged: true
  cap_add:
    - NET_ADMIN
    - NET_RAW
```
- ✅ 실제 네트워크 인터페이스 캡처 가능
- ⚠️ 보안 위험 증가

---

## 📈 성능 최적화

### 1. 배치 크기 조정
```json
{
  "parser": {
    "batch_size": 500,  // 기본 100 → 500
    "flush_interval_ms": 500  // 기본 1000 → 500
  }
}
```

### 2. 리소스 제한
```yaml
# docker-compose.yml
deploy:
  resources:
    limits:
      cpus: '4.0'      # 2.0 → 4.0
      memory: 4G       # 2G → 4G
```

### 3. JSONL 파일 로테이션
```json
{
  "output": {
    "jsonl": {
      "rotation_size_mb": 50,    // 100MB → 50MB (더 자주 로테이션)
      "rotation_interval_min": 30  // 60분 → 30분
    }
  }
}
```

---

## 🔒 보안 고려사항

### 최소 권한
```yaml
# 패킷 캡처가 필요 없는 경우
cpp-parser:
  privileged: false
  # cap_add 제거
```

### 읽기 전용 설정
```yaml
cpp-parser:
  volumes:
    - ./RealtimeParser/config.json:/app/config.json:ro
  read_only: true
  tmpfs:
    - /tmp
    - /app/logs
```

### 네트워크 격리
```yaml
cpp-parser:
  networks:
    - ot-security-network  # 내부 네트워크만
```

---

## 📚 참고 문서

- [Docker Compose 가이드](../README-DOCKER.md)
- [Elasticsearch 연동](../ELASTICSEARCH-INTEGRATION.md)
- [빠른 시작](../QUICK-START.md)

---

## 🔄 업데이트

### Parser 바이너리 업데이트

```bash
# 1. 새로운 parser 빌드
cd RealtimeParser/build
make clean && make

# 2. Docker 이미지 재빌드
cd ../..
docker-compose build cpp-parser

# 3. 컨테이너 재시작
docker-compose up -d cpp-parser

# 4. 로그 확인
docker-compose logs -f cpp-parser
```

### 설정 파일만 업데이트

```bash
# 1. config.json 수정
nano RealtimeParser/config.json

# 2. 컨테이너 재시작 (이미지 재빌드 불필요)
docker-compose restart cpp-parser
```

---

## 💡 개발 팁

### 로컬 테스트
```bash
# Parser를 로컬에서 직접 실행
cd RealtimeParser/build
./parser --config ../config.json
```

### 디버그 모드
```json
{
  "logging": {
    "level": "debug",  // info → debug
    "file": "/app/logs/parser.log"
  }
}
```

### PCAP 재생 모드
```bash
# PCAP 파일로 테스트
docker run --rm -it \
  -v $(pwd)/test.pcap:/test.pcap \
  ot-security-parser \
  /app/parser --replay /test.pcap
```

---

## ⚡ 빠른 명령어

```bash
# 빌드
docker-compose build cpp-parser

# 시작
docker-compose up -d cpp-parser

# 로그
docker-compose logs -f cpp-parser

# 재시작
docker-compose restart cpp-parser

# 중지
docker-compose stop cpp-parser

# 제거
docker-compose down cpp-parser
```
