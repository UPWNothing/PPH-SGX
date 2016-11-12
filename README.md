# PPH-SGX
#Contains SGX Implementation over PPH

##Download and boot ubuntu 14.04


**sudo apt-get update
sudo apt-get install git
git clone https://github.com/PolyPasswordHasher/PolyPasswordHasher-C.git
sudo apt-get install openssl
sudo apt-get install libtool
sudo apt-get install check
sudo apt-get install libssl-dev
cd PolyPasswordHasher-C
autoreconf --install
./configure
make
sudo make install //this will install library and copy the headers to /usr/local
**

##Move to PPHTest Directory
**make**
//To run
**export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
./polypasswordhasher_example.out**