#!/bin/bash
if [ ! -d "./sparsepp" ]; then
  git clone https://github.com/greg7mdp/sparsepp
  mv ./sparsepp ./sparsepp.github
  cp -R ./sparsepp.github/sparsepp ./
  rm -rf ./sparsepp.github
fi
if [ ! -d "./sparsehash" ]; then
  git clone https://github.com/sparsehash/sparsehash
  cd sparsehash
  ./configure
  make
  cd ..
  mv ./sparsehash ./sparsehash.github
  cp -R ./sparsehash.github/src/sparsehash ./
  rm -rf ./sparsehash.github
fi
g++ -std=c++11 -O3 -fno-strict-aliasing -DNDEBUG -o metric_limits main.cpp -I./ -I../../userspace/libsanalyzer -I../../../sysdig/userspace/libsinsp -L../../../sysdig/build/release/userspace/libsinsp -lsinsp
