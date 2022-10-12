#!/bin/bash
source $HOME/.cargo/env

# Install quiche
git clone --recursive https://github.com/mfranzil/quiche
cargo build --examples
cd apps
mkdir -p src/bin/root
echo "<html><body><h1>Hello, world</h1></body></html>" > src/bin/root/index.html
cargo install --path .
cd $HOME