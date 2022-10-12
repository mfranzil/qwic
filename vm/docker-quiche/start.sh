sudo docker ps -a -f name=quiche -q | xargs docker stop 2>/dev/null | xargs docker rm || true
sudo docker run -d -it --network=quic-bridge --publish 4444:22 --name quiche quiche-qwic bash