# ============================================
# Stage 1: Builder
# ============================================
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Seoul

# 빌드 도구 및 라이브러리 설치
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libpcap-dev \
    libcurl4-openssl-dev \
    libhiredis-dev \
    nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# 소스 코드 복사
COPY CMakeLists.txt ./
COPY src ./src
COPY include ./include

# 빌드
RUN mkdir -p build && \
    cd build && \
    cmake .. && \
    cmake --build . -j$(nproc)

# ============================================
# Stage 2: Runtime
# ============================================
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Seoul

# 런타임 라이브러리만 설치
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

WORKDIR /app

# 빌드된 바이너리 복사
COPY --from=builder /build/build/parser /usr/local/bin/parser
RUN chmod +x /usr/local/bin/parser

# Assets 디렉토리 복사
COPY assets /app/assets

# 출력 디렉토리 생성
RUN mkdir -p /data/output

# 볼륨 설정
VOLUME ["/data/output", "/app/assets"]

# 헬스체크
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD pgrep -f parser || exit 1

# 엔트리포인트
COPY entrypoint-docker.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
