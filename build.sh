#!/bin/sh
# 在服务器上更新渡口：拉最新代码，重新构建镜像并重启容器。
# 数据在 data 卷里，重建容器不会丢。第一次部署仍需先运行 init-token，见 README。
set -eu
cd "$(dirname "$0")"

# compose.yaml 里声明为 external 的网络，compose 不会自动创建。
SHARED_NETWORK=postgres_default

if [ ! -c /dev/net/tun ]; then
    echo "没有 /dev/net/tun：先在 VPS 产品里启用 TUN。" >&2
    exit 1
fi

if ! docker network inspect "$SHARED_NETWORK" >/dev/null 2>&1; then
    echo "没有 Docker 网络 $SHARED_NETWORK：先启动 postgres 那边的 compose 项目，" >&2
    echo "或者运行 docker network create $SHARED_NETWORK。" >&2
    exit 1
fi

echo "拉取最新代码…"
git pull --ff-only

echo "重新构建并启动…"
docker compose up -d --build
docker compose ps
