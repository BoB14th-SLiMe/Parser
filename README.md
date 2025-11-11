# 실시간 Parser 사용 가이드

## 개요

실시간 Parser는 네트워크 인터페이스에서 패킷을 실시간으로 캡처하여 Elasticsearch와 Redis로 전송합니다.

---

## 빠른 시작

### 1. 실시간 파서 실행 (sudo 필요)

```bash
cd /home/ryuoo0/security/Parser

# 기본 실행 (veth1 인터페이스, Elasticsearch: 100.126.141.58)
sudo ./scripts/start_realtime_parser.sh

# 커스텀 설정
sudo ./scripts/start_realtime_parser.sh veth1 100.126.141.58 9200 ./realtime_output 1 4
```

### 2. 파라미터

| 순서 | 파라미터 | 설명 | 기본값 |
|------|----------|------|--------|
| 1 | `interface` | 네트워크 인터페이스 | `veth1` |
| 2 | `es_host` | Elasticsearch 호스트 | `100.126.141.58` |
| 3 | `es_port` | Elasticsearch 포트 | `9200` |
| 4 | `output_dir` | 출력 디렉토리 | `./realtime_output` |
| 5 | `rolling_min` | 파일 분할 간격 (분) | `1` |
| 6 | `threads` | 워커 스레드 수 | `4` |

---

## 테스트 환경

### 현재 테스트 설정

```
tcpreplay (veth0) → veth1 → Parser → Elasticsearch
```

- **트래픽 소스**: `tcpreplay -i veth0 ./dummy_data/file.pcap`
- **캡처 인터페이스**: `veth1`
- **데이터 크기**: 약 1시간 30분 분량의 패킷

### tcpreplay 상태 확인

```bash
# tcpreplay 실행 중인지 확인
ps aux | grep tcpreplay | grep -v grep

# 출력 예시:
# root    83235 99.9 0.0 12676 8364 pts/39 R+ 21:37 3:39 tcpreplay -i veth0 ./dummy_data/file.pcap
```

---

## 실행 방법

### 방법 1: 스크립트 사용 (권장)

```bash
cd /home/ryuoo0/security/Parser
sudo ./scripts/start_realtime_parser.sh veth1 100.126.141.58
```

### 방법 2: 직접 실행

```bash
cd /home/ryuoo0/security/Parser

export ELASTICSEARCH_HOST=100.126.141.58
export ELASTICSEARCH_PORT=9200

sudo -E ./build/parser \
    --interface veth1 \
    --output realtime_output \
    --rolling 1 \
    --threads 4
```

### 방법 3: 백그라운드 실행

```bash
sudo -E nohup ./build/parser \
    --interface veth1 \
    --output realtime_output \
    --rolling 1 \
    --threads 4 \
    > realtime_parser.log 2>&1 &

echo $! > parser.pid

# 로그 확인
tail -f realtime_parser.log

# 중지
sudo kill $(cat parser.pid)
```

---

## 데이터 확인

### 실시간 모니터링

```bash
# 1. Elasticsearch 문서 수 확인 (주기적으로 실행)
watch -n 2 'curl -s "http://100.126.141.58:9200/ics-packets-*/_count?pretty" | grep count'

# 2. 최신 데이터 확인
curl -X GET "http://100.126.141.58:9200/ics-packets-*/_search?size=5&sort=@timestamp:desc&pretty" \
  | jq '.hits.hits[] | ._source | {time: .["@timestamp"], protocol: .protocol, src: .src_ip, dst: .dst_ip}'

# 3. 프로토콜별 통계 (실시간)
curl -X GET "http://100.126.141.58:9200/ics-packets-*/_search?size=0&pretty" \
  -H 'Content-Type: application/json' \
  -d '{"aggs": {"protocols": {"terms": {"field": "protocol.keyword"}}}}' \
  | jq '.aggregations.protocols.buckets[] | {protocol: .key, count: .doc_count}'
```

### Parser 상태 확인

```bash
# 1. 프로세스 확인
ps aux | grep parser | grep -v grep

# 2. 네트워크 인터페이스 통계
sudo tcpdump -i veth1 -c 10 -nn

# 3. 출력 파일 확인
ls -lh realtime_output/

# 4. Redis 데이터 확인
redis-cli llen stream:protocol:modbus_tcp
```

---

## 권한 문제 해결

### 문제: "Operation not permitted"

```
[ERROR] Could not open device veth1: You don't have permission to perform this capture
```

**해결책 1: sudo 사용 (권장)**
```bash
sudo ./scripts/start_realtime_parser.sh
```

**해결책 2: Capabilities 부여**
```bash
# Parser에 raw socket 권한 부여
sudo setcap cap_net_raw,cap_net_admin=eip ./build/parser

# 확인
getcap ./build/parser

# 실행 (sudo 불필요)
./build/parser --interface veth1 --output output --rolling 1
```

**해결책 3: 사용자를 pcap 그룹에 추가**
```bash
sudo usermod -a -G pcap $USER
# 로그아웃 후 다시 로그인 필요
```

---

## 성능 튜닝

### 고성능 캡처 설정

```bash
# 1. 더 많은 워커 스레드 (CPU 코어 수에 맞춰)
sudo ./scripts/start_realtime_parser.sh veth1 100.126.141.58 9200 ./output 1 8

# 2. BPF 필터 사용 (특정 프로토콜만)
sudo -E ./build/parser \
    --interface veth1 \
    --filter "tcp port 502 or tcp port 102" \
    --output output \
    --rolling 1

# 3. 실시간 모드 (파일 출력 없음)
sudo -E ./build/parser \
    --interface veth1 \
    --realtime \
    --threads 8
```

### 버퍼 크기 조정

환경 변수로 Elasticsearch bulk size 조정:
```bash
export ES_BULK_SIZE=100  # 더 큰 배치 (기본: 50)
export ES_BULK_FLUSH_INTERVAL_MS=500  # 더 느린 flush (기본: 1000ms)

sudo -E ./build/parser --interface veth1 --output output --rolling 1
```

---

## 모니터링 대시보드

### 실시간 통계 스크립트

```bash
#!/bin/bash
# realtime_stats.sh - 실시간 통계 출력

ES_HOST="100.126.141.58"
ES_PORT="9200"

while true; do
    clear
    echo "=== ICS Packet Parser - Real-time Statistics ==="
    echo "Time: $(date)"
    echo ""

    # 총 문서 수
    TOTAL=$(curl -s "http://$ES_HOST:$ES_PORT/ics-packets-*/_count" | jq -r '.count')
    echo "Total packets: $TOTAL"
    echo ""

    # 프로토콜별
    echo "Protocol distribution:"
    curl -s "http://$ES_HOST:$ES_PORT/ics-packets-*/_search?size=0" \
        -H 'Content-Type: application/json' \
        -d '{"aggs": {"protocols": {"terms": {"field": "protocol.keyword"}}}}' \
        | jq -r '.aggregations.protocols.buckets[] | "  \(.key): \(.doc_count)"'

    echo ""
    echo "Press Ctrl+C to exit"
    sleep 5
done
```

```bash
chmod +x realtime_stats.sh
./realtime_stats.sh
```

---

## 예상 결과

### 정상 실행 시 로그

```
======================================================================
===   OT Security Monitoring System - Packet Parser   ===
======================================================================

[Config] Configuration:
  Input Mode: Live Capture
  Network Interface: veth1
  ...

[Elasticsearch] Configured: bulk_size=50, flush_interval=1000ms
[Elasticsearch] Connected to 100.126.141.58:9200
[INFO] Elasticsearch connection established

[PCAP] Opening interface: veth1
[INFO] Realtime flush thread started

[Elasticsearch] Buffer full (50 docs), flushing...
[Elasticsearch] ✓ Flushed 50 documents
[Elasticsearch] Auto-flushing 23 documents...
[Elasticsearch] ✓ Flushed 23 documents
...
```

### Elasticsearch 데이터

```bash
$ curl "http://100.126.141.58:9200/ics-packets-*/_count?pretty"
{
  "count" : 5230,  # 실시간으로 증가
  ...
}

$ curl "http://100.126.141.58:9200/_cat/indices/ics-packets-*?v"
health index                             docs.count
yellow ics-packets-modbus_tcp-2025.11.11      2341
yellow ics-packets-s7comm-2025.11.11           892
yellow ics-packets-xgt-fen-2025.11.11         1523
...
```

---

## 트러블슈팅

### 1. 데이터가 들어오지 않음

**체크리스트:**
```bash
# 1. tcpreplay가 실행 중인지 확인
ps aux | grep tcpreplay

# 2. veth1에서 패킷이 보이는지 확인
sudo tcpdump -i veth1 -c 10 -nn

# 3. Parser 로그 확인
tail -f realtime_parser.log

# 4. Elasticsearch 연결 확인
curl http://100.126.141.58:9200
```

### 2. Parser가 즉시 종료됨

```bash
# 권한 확인
sudo ./scripts/start_realtime_parser.sh

# 인터페이스 확인
ip link show veth1

# 로그 확인
tail -50 realtime_parser.log
```

### 3. 너무 많은 로그

```bash
# Elasticsearch flush 로그 줄이기
# ElasticsearchClient.cpp에서 로그 레벨 조정 필요
```

---

## 비교: PCAP vs 실시간

| 특징 | PCAP 파일 파싱 | 실시간 캡처 |
|------|----------------|-------------|
| 권한 | 일반 사용자 OK | sudo 필요 |
| 속도 | 빠름 (I/O 한계) | 네트워크 속도 |
| 테스트 | 반복 가능 | 일회성 |
| 사용처 | 분석, 재현 | 모니터링, 탐지 |
| 파일 출력 | 필수 아님 | 필수 아님 |

---

## 다음 단계

### 1. 자동 시작 (systemd)

```bash
# /etc/systemd/system/ics-parser.service
[Unit]
Description=ICS Packet Parser
After=network.target

[Service]
Type=simple
User=root
Environment="ELASTICSEARCH_HOST=100.126.141.58"
Environment="ELASTICSEARCH_PORT=9200"
WorkingDirectory=/home/ryuoo0/security/Parser
ExecStart=/home/ryuoo0/security/Parser/build/parser --interface veth1 --output /data/realtime --rolling 5 --threads 4
Restart=always

[Install]
WantedBy=multi-user.target

# 활성화
sudo systemctl daemon-reload
sudo systemctl enable ics-parser
sudo systemctl start ics-parser
```

### 2. Kibana 대시보드

- 실시간 프로토콜 분포
- 자산 간 통신 맵
- 이상 트래픽 탐지
- 알람 설정

---

## 참고 문서

- [Elasticsearch 가이드](ELASTICSEARCH_QUICK_GUIDE.md)
- [Parser 스크립트](scripts/README.md)
- [Main README](README.md)
