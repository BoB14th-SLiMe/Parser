#!/bin/bash
set -e

# ============================================
# OT Security Parser - Docker Entrypoint
# ============================================

echo "======================================================================="
echo "===   OT Security Monitoring System - Packet Parser   ==="
echo "======================================================================="
echo ""

# 환경 변수 기본값 설정
NETWORK_INTERFACE=${NETWORK_INTERFACE:-any}
PARSER_MODE=${PARSER_MODE:-realtime}
BPF_FILTER=${BPF_FILTER:-}
OUTPUT_DIR=${OUTPUT_DIR:-/data/output}
ROLLING_INTERVAL=${ROLLING_INTERVAL:-0}
PARSER_THREADS=${PARSER_THREADS:-0}

# Elasticsearch 설정
export ELASTICSEARCH_HOST=${ELASTICSEARCH_HOST:-localhost}
export ELASTICSEARCH_PORT=${ELASTICSEARCH_PORT:-9200}
export ELASTICSEARCH_USERNAME=${ELASTICSEARCH_USERNAME:-}
export ELASTICSEARCH_PASSWORD=${ELASTICSEARCH_PASSWORD:-}
export ELASTICSEARCH_INDEX_PREFIX=${ELASTICSEARCH_INDEX_PREFIX:-ics-packets}
export ELASTICSEARCH_USE_HTTPS=${ELASTICSEARCH_USE_HTTPS:-false}
export ES_BULK_SIZE=${ES_BULK_SIZE:-100}
export ES_BULK_FLUSH_INTERVAL_MS=${ES_BULK_FLUSH_INTERVAL_MS:-100}

# Redis 설정
export REDIS_HOST=${REDIS_HOST:-localhost}
export REDIS_PORT=${REDIS_PORT:-6379}
export REDIS_PASSWORD=${REDIS_PASSWORD:-}
export REDIS_DB=${REDIS_DB:-0}
export REDIS_POOL_SIZE=${REDIS_POOL_SIZE:-8}
export REDIS_ASYNC_WRITERS=${REDIS_ASYNC_WRITERS:-2}
export REDIS_ASYNC_QUEUE_SIZE=${REDIS_ASYNC_QUEUE_SIZE:-10000}
export REDIS_TIMEOUT_MS=${REDIS_TIMEOUT_MS:-1000}

# 로그 레벨
export LOG_LEVEL=${LOG_LEVEL:-INFO}

# 명령어 구성
CMD="parser -i ${NETWORK_INTERFACE}"

# 모드 설정
if [ "${PARSER_MODE}" = "realtime" ]; then
    CMD="${CMD} --realtime"
else
    CMD="${CMD} -o ${OUTPUT_DIR}"
fi

# BPF 필터 추가
if [ ! -z "${BPF_FILTER}" ]; then
    CMD="${CMD} -f \"${BPF_FILTER}\""
fi

# 롤링 간격 (분)
if [ "${ROLLING_INTERVAL}" -gt 0 ]; then
    CMD="${CMD} --rolling ${ROLLING_INTERVAL}"
fi

# 스레드 수
if [ "${PARSER_THREADS}" -gt 0 ]; then
    CMD="${CMD} --threads ${PARSER_THREADS}"
fi

echo "[Config] Configuration:"
echo "  Network Interface: ${NETWORK_INTERFACE}"
echo "  Mode: ${PARSER_MODE}"
echo "  Output Directory: ${OUTPUT_DIR}"
echo "  Rolling Interval: ${ROLLING_INTERVAL} minutes"
echo "  Worker Threads: ${PARSER_THREADS} (0=auto)"
echo ""
echo "[Config] Elasticsearch:"
echo "  Host: ${ELASTICSEARCH_HOST}:${ELASTICSEARCH_PORT}"
echo "  Index Prefix: ${ELASTICSEARCH_INDEX_PREFIX}"
echo "  Bulk Size: ${ES_BULK_SIZE}"
echo "  Flush Interval: ${ES_BULK_FLUSH_INTERVAL_MS} ms"
echo ""
echo "[Config] Redis:"
echo "  Host: ${REDIS_HOST}:${REDIS_PORT}"
echo "  Database: ${REDIS_DB}"
echo "  Pool Size: ${REDIS_POOL_SIZE}"
echo "  Async Writers: ${REDIS_ASYNC_WRITERS}"
echo ""
echo "[Config] Command: ${CMD}"
echo ""
echo "[Init] Starting Parser..."
echo ""

# Parser 실행
eval exec ${CMD}
