#!/bin/bash

cargo clean
UNAME=`uname -s`

if [[ $UNAME == "Linux" ]]
then
OPENSSL_STATIC=yes
OPENSSL_INCLUDE_DIR=/usr/include/
OPENSSL_LIB_DIR=/usr/local/lib64/
else
export OPENSSL_LIB_DIR=/usr/local/include/node/openssl
export OPENSSL_INCLUDE_DIR=/usr/local/opt/openssl@1.1/include
export OPENSSL_STATIC=yes
fi

cargo build --release
