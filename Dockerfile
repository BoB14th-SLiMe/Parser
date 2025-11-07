# ============================================
# C++ Parser - Dockerfile
# ============================================
# RealtimeParser/build/parser 바이너리를 실행하는 경량 이미지
# Ubuntu 24.04 사용 (GLIBC 2.38+ 지원)

FROM ubuntu:24.04

# 필수 런타임 라이브러리 설치
RUN apt-get update && apt-get install -y \
    libstdc++6 \
    libgcc-s1 \
    libc6 \
    ca-certificates \
    libhiredis-dev \
    librdkafka-dev \
    libpcap-dev \
    libcurl4 \
    libssl3 \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# hiredis 심볼릭 링크 생성 (버전 호환성)
RUN if [ ! -f /usr/lib/x86_64-linux-gnu/libhiredis.so.1.1.0 ] && [ ! -f /usr/lib/aarch64-linux-gnu/libhiredis.so.1.1.0 ]; then \
    if [ -f /usr/lib/x86_64-linux-gnu/libhiredis.so ]; then \
        ln -sf /usr/lib/x86_64-linux-gnu/libhiredis.so /usr/lib/x86_64-linux-gnu/libhiredis.so.1.1.0; \
    elif [ -f /usr/lib/aarch64-linux-gnu/libhiredis.so ]; then \
        ln -sf /usr/lib/aarch64-linux-gnu/libhiredis.so /usr/lib/aarch64-linux-gnu/libhiredis.so.1.1.0; \
    fi \
    fi

# 작업 디렉토리 생성
WORKDIR /app

# 빌드된 parser 바이너리 복사
COPY build/parser /app/parser

COPY assets/ /app/assets/

# 설정 파일 복사
COPY config.json /app/config.json

# 실행 권한 부여
RUN chmod +x /app/parser

# 로그 디렉토리 생성
RUN mkdir -p /app/logs

# 출력 디렉토리 생성
RUN mkdir -p /app/data/parser-output

# 환경 변수 설정 (docker-compose.yml에서 덮어쓰기 가능)
ENV REDIS_HOST=redis
ENV REDIS_PORT=6379
ENV KAFKA_BOOTSTRAP_SERVERS=kafka:29092
ENV OUTPUT_DIR=/app/data/parser-output
# NETWORK_INTERFACE는 docker-compose.yml에서 설정
ENV BPF_FILTER=""
ENV ROLLING_INTERVAL=0

# Entrypoint 스크립트 생성
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
echo "========================================"\n\
echo "Real-time ICS Packet Capture & Analysis"\n\
echo "========================================"\n\
echo ""\n\
echo "Checking network interfaces..."\n\
# 기본값 설정 (환경 변수가 없는 경우)\n\
: ${NETWORK_INTERFACE:=any}\n\
\n\
echo "[INFO] Target interface: $NETWORK_INTERFACE"\n\
\n\
# 네트워크 인터페이스 존재 확인\n\
if [ "$NETWORK_INTERFACE" != "any" ] && ! ip link show "$NETWORK_INTERFACE" > /dev/null 2>&1; then\n\
    echo "[WARN] Interface $NETWORK_INTERFACE not found. Available interfaces:"\n\
    ip link show | grep -E "^[0-9]+:" | awk "{print \\$2}" | sed "s/:$//" | sed "s/@.*//" || true\n\
    echo ""\n\
    echo "[INFO] Falling back to interface: any"\n\
    NETWORK_INTERFACE="any"\n\
fi\n\
\n\
# Parser 실행\n\
ARGS=("$NETWORK_INTERFACE")\n\
\n\
if [ -n "$BPF_FILTER" ]; then\n\
    ARGS+=(--filter "$BPF_FILTER")\n\
fi\n\
\n\

echo "Starting parser with arguments: ${ARGS[@]}"\n\
echo "========================================"\n\
echo ""\n\
\n\
exec /app/parser "${ARGS[@]}"\n\
' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# 실행
ENTRYPOINT ["/app/entrypoint.sh"]
