#!/bin/bash

CURL_VERSION="7.83.1"
LLVM_VERSION="12"

apt-get update

apt-get install -y python3-pip \
    linux-headers-generic linux-headers-$(uname -r) \
    bison build-essential cmake flex git libedit-dev \
    libllvm${LLVM_VERSION} llvm-${LLVM_VERSION}-dev \
    libclang-${LLVM_VERSION}-dev python zlib1g-dev \
    libelf-dev libfl-dev python3-distutils unzip \
    git autoconf libtool pkg-config \
    arping netperf iperf3 tshark sloccount sysstat 
# Remove obnoxious warnings for unsafe directories
# git config --global --add safe.directory /home/vagrant/bcc/libbpf-tools/bpftool/libbpf

# Build and install BCC
cd /home/vagrant
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd

pip3 install pyroute2 numpy

apt-get purge -y curl
# build openssl
git clone --depth 1 -b OpenSSL_1_1_1k+quic https://github.com/quictls/openssl/
cd openssl
./config enable-tls1_3 --prefix=/usr/local
make -j `lscpu | awk /"^Core"/'{print$NF}'`
make install_sw
cd ../
# build nghttp3
git clone https://github.com/ngtcp2/nghttp3
cd nghttp3
autoreconf -i
./configure --prefix=/usr/local --enable-lib-only
make -j `lscpu | awk /"^Core"/'{print$NF}'`
make install
cd ../
# build ngtcp2
git clone https://github.com/ngtcp2/ngtcp2
cd ngtcp2
autoreconf -i
./configure PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib/pkgconfig LDFLAGS="-Wl,-rpath,/usr/local/lib" --prefix=/usr/local
make -j `lscpu | awk /"^Core"/'{print$NF}'`
make install
cd ../
# build curl
git clone https://github.com/curl/curl
cd curl
./buildconf
LDFLAGS="-Wl,-rpath,/usr/local/lib" ./configure --with-ssl=/usr/local --with-nghttp3=/usr/local --with-ngtcp2=/usr/local --enable-alt-svc
make -j `lscpu | awk /"^Core"/'{print$NF}'`
make install
cd ../

# Install pyshark
git clone https://github.com/KimiNewt/pyshark.git
cd pyshark/src
python3 setup.py install
cd ../../

rm -rf openssl nghttp3 ngtcp2 curl

# Install rust
sudo -u vagrant -i bash -c 'curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
