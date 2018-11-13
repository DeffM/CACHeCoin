#!/bin/sh
CPUNUM=`grep -c ^processor /proc/cpuinfo`
qmake RELEASE=1 USE_QRCODE=1
make -j $CPUNUM
cd src
make STATIC=1 -j $CPUNUM -f makefile.unix
cd ..
mkdir cachecoin
cp CACHE-Project-qt cachecoin/
cp src/cacheprojectd cachecoin/
zip -r ~/cachecoin.zip cachecoin/
rm -rf cachecoin/
