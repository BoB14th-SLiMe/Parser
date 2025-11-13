#!/bin/bash
set -e

echo "========================================"
echo "  Parser Container Starting..."
echo "========================================"

# 환경 변수 기본값 설정
INTERFACE="${NETWORK_INTERFACE:-${INTERFACE:-any}}"
OUTPUT_DIR="${OUTPUT_DIR:-/data/output}"
ROLLING_MIN="${ROLLING_INTERVAL:-${ROLLING_MIN:-5}}"
THREADS="${PARSER_THREADS:-${THREADS:-4}}"
PCAP_FILE="${PCAP_FILE:-}"
ELASTICSEARCH_HOST="${ELASTICSEARCH_HOST:-localhost}"
ELASTICSEARCH_PORT="${ELASTICSEARCH_PORT:-9200}"
REDIS_HOST="${REDIS_HOST:-localhost}"
REDIS_PORT="${REDIS_PORT:-6379}"

echo "Configuration:"
echo "  Network Interface: $INTERFACE"
echo "  Output Directory: $OUTPUT_DIR"
echo "  Rolling Interval: $ROLLING_MIN min"
echo "  Worker Threads: $THREADS"
echo "  Elasticsearch: $ELASTICSEARCH_HOST:$ELASTICSEARCH_PORT"
echo "  Redis: $REDIS_HOST:$REDIS_PORT"

# 출력 디렉토리 생성
mkdir -p "$OUTPUT_DIR"

# Assets 디렉토리 확인
if [ ! -d "/app/assets" ]; then
    echo "Warning: /app/assets directory not found"
fi

# Elasticsearch 연결 대기
echo "Waiting for Elasticsearch to be ready..."
max_retries=30
retry=0
while [ $retry -lt $max_retries ]; do
    if curl -s "http://$ELASTICSEARCH_HOST:$ELASTICSEARCH_PORT" > /dev/null 2>&1; then
        echo "Elasticsearch is ready!"
        break
    fi
    retry=$((retry + 1))
    echo "Waiting for Elasticsearch... ($retry/$max_retries)"
    sleep 2
done

if [ $retry -eq $max_retries ]; then
    echo "Warning: Elasticsearch connection timeout, continuing anyway..."
fi

# Redis 연결 대기 (선택적)
if command -v redis-cli > /dev/null 2>&1; then
    echo "Checking Redis connection..."
    if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping > /dev/null 2>&1; then
        echo "Redis is ready!"
    else
        echo "Warning: Redis not accessible, continuing anyway..."
    fi
fi

echo "========================================"
echo "  Starting Parser..."
echo "========================================"

# PCAP 파일이 지정된 경우
if [ -n "$PCAP_FILE" ]; then
    echo "Running in PCAP mode: $PCAP_FILE"
    exec parser \
        --pcap "$PCAP_FILE" \
        --output "$OUTPUT_DIR" \
        --threads "$THREADS"
else
    # 실시간 캡처 모드
    echo "Running in real-time capture mode on $INTERFACE"
    exec parser \
        --interface "$INTERFACE" \
        --output "$OUTPUT_DIR" \
        --rolling "$ROLLING_MIN" \
        --threads "$THREADS"
fi
