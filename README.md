How to build and run agent from a branch:

**Ubuntu**
```
sudo apt-get install build-essential  
sudo apt-get install dh-autoreconf  
sudo apt-get install g++-multilib  

git clone https://github.com/draios/agent  
git clone https://github.com/draios/sysdig  
git clone https://github.com/draios/falco  

cd agent  

git checkout [your-branch-here]  

./bootstrap-sysdig  
./bootstrap-falco  
./bootstrap-agent  

sudo make -C build/release install  

[create and edit /opt/draios/etc/dragent.yaml]  

sudo insmod build/release/driver/sysdigcloud-probe.ko  
sudo /opt/draios/bin/dragent  
```
