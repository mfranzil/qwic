docker network create -d bridge --gateway=192.168.50.1 --subnet=192.168.50.1/24 quic-bridge
printf "br-"
docker network ls -f name=quic-bridge -q
