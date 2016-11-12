# PPH-SGX
#Contains SGX Implementation over PPH

##Download and boot ubuntu 14.04

###Commands to build and install PPH:
To run the node server:

	$ sudo apt-get update
  
	$ sudo apt-get install git
	
	$ git clone https://github.com/PolyPasswordHasher/PolyPasswordHasher-C.git
	
	$ sudo apt-get install openssl
	
	$ sudo apt-get install libtool
	
	$ sudo apt-get install check
	
	$ sudo apt-get install libssl-dev
	
	$ cd PolyPasswordHasher-C
	
	$ autoreconf --install
	
	$ ./configure
	
	$ make
	
	$ sudo make install //this will install library and copy the headers to /usr/local**


###Commands to build PPH TEST APP:

	$ cd ../PPH-SGX
	$ make
	
###To run test app:

	$ export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
	$ ./polypasswordhasher_example.out
