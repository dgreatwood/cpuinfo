#!/bin/bash

if [ ! -d "/usr/local/include/libcpuinfo" ]
then
    sudo mkdir "/usr/local/include/libcpuinfo"
fi

sudo cp -a build/libcpuinfo.a /usr/local/lib/libcpuinfo-dumpall.a
sudo cp -a src/cpuinfotobuff.h /usr/local/include/libcpuinfo/libcpuinfo-dumpall.h
