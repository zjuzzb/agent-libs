pushd ..
./bootstrap-agent
cd build/release/userspace/dragent
make install
cd /opt/draios
./make_msi.sh
popd
cp /opt/draios/dragent.msi ./