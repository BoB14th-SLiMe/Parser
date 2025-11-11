FROM ubuntu:24.04

# 기본 환경 설정
ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Seoul

# 필수 런타임 라이브러리 설치
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libcurl4 \
    libhiredis-dev \
    nlohmann-json3-dev \
    libstdc++6 \
    curl \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# 작업 디렉토리 생성
WORKDIR /app

# 빌드된 바이너리 복사
COPY build/parser /usr/local/bin/parser

# 실행 권한 부여
RUN chmod +x /usr/local/bin/parser

# Assets 디렉토리 복사 (옵션)
COPY assets /app/assets

# 출력 디렉토리 생성
RUN mkdir -p /data/output

# 볼륨 설정
VOLUME ["/data/output", "/app/assets"]

# 헬스체크
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD pgrep -f parser || exit 1

# 엔트리포인트 스크립트 생성
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# 환경 변수 기본값 설정\n\
NETWORK_INTERFACE=${NETWORK_INTERFACE:-any}\n\
PARSER_MODE=${PARSER_MODE:-realtime}\n\
BPF_FILTER=${BPF_FILTER:-}\n\
OUTPUT_DIR=${OUTPUT_DIR:-/data/output}\n\
ROLLING_INTERVAL=${ROLLING_INTERVAL:-0}\n\
\n\
# Elasticsearch 설정\n\
export ELASTICSEARCH_HOST=${ELASTICSEARCH_HOST:-localhost}\n\
export ELASTICSEARCH_PORT=${ELASTICSEARCH_PORT:-9200}\n\
export ELASTICSEARCH_USERNAME=${ELASTICSEARCH_USERNAME:-}\n\
export ELASTICSEARCH_PASSWORD=${ELASTICSEARCH_PASSWORD:-}\n\
export ELASTICSEARCH_INDEX_PREFIX=${ELASTICSEARCH_INDEX_PREFIX:-ics-packets}\n\
\n\
# Redis 설정\n\
export REDIS_HOST=${REDIS_HOST:-localhost}\n\
export REDIS_PORT=${REDIS_PORT:-6379}\n\
export REDIS_PASSWORD=${REDIS_PASSWORD:-}\n\
export REDIS_DB=${REDIS_DB:-0}\n\
\n\
# 로그 레벨\n\
export LOG_LEVEL=${LOG_LEVEL:-INFO}\n\
\n\
# 명령어 구성\n\
CMD="parser -i ${NETWORK_INTERFACE}"\n\
\n\
# 모드 설정\n\
if [ "${PARSER_MODE}" = "realtime" ]; then\n\
    CMD="${CMD} --realtime"\n\
fi\n\
\n\
# BPF 필터 추가\n\
if [ ! -z "${BPF_FILTER}" ]; then\n\
    CMD="${CMD} -f \"${BPF_FILTER}\""\n\
fi\n\
\n\
# 롤링 간격 (분)\n\
if [ "${ROLLING_INTERVAL}" -gt 0 ]; then\n\
    CMD="${CMD} --rolling ${ROLLING_INTERVAL}"\n\
fi\n\
\n\
# 출력 디렉토리\n\
if [ ! -z "${OUTPUT_DIR}" ]; then\n\
    CMD="${CMD} -o ${OUTPUT_DIR}"\n\
fi\n\
\n\
echo "[INFO] Starting Parser..."\n\
echo "[INFO] Network Interface: ${NETWORK_INTERFACE}"\n\
echo "[INFO] Mode: ${PARSER_MODE}"\n\
echo "[INFO] Elasticsearch: ${ELASTICSEARCH_HOST}:${ELASTICSEARCH_PORT}"\n\
echo "[INFO] Redis: ${REDIS_HOST}:${REDIS_PORT}"\n\
echo "[INFO] Command: ${CMD}"\n\
echo ""\n\
\n\
# Parser 실행\n\
eval exec ${CMD}\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]