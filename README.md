# libdigidoc

 * License: LGPL 2.1
 * &copy; Estonian Information System Authority

Dependencies
---------------------------
You need the following dependent librarys to build libdigidoc:
- openssl - https://www.openssl.org/ - Apache style license
- libxml2 - http://xmlsoft.org/ - MIT license
- zlib - http://www.zlib.net/ - zlib license
- iconv - https://www.gnu.org/software/libiconv/ - LGPL license
- doxygen - http://www.stack.nl/~dimitri/doxygen/ - doxygen license


Full documentation
----------------------------
For documentation please see in doc folder SK-CDD-PRG-GUIDE
Contact for assistance by email abi@id.ee or http://www.id.ee

## Building
[![Build Status](https://travis-ci.org/open-eid/libdigidoc.svg?branch=master)](https://travis-ci.org/open-eid/libdigidoc)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/724/badge.svg)](https://scan.coverity.com/projects/724)

### Ubuntu

1. Install dependencies

        sudo apt-get install cmake libxml2-dev libssl-dev

2. Fetch the source

        git clone --recursive https://github.com/open-eid/libdigidoc
        cd libdigidoc

3. Configure

        mkdir build
        cd build
        cmake ..

4. Build

        make

5. Install

        sudo make install

6. Execute

        /usr/local/bin/cdigidoc
        
### OSX

1. Install dependencies from [http://www.cmake.org](http://www.cmake.org)

2. Fetch the source

        git clone --recursive https://github.com/open-eid/libdigidoc
        cd libdigidoc

3. Configure

        mkdir build
        cd build
        cmake ..

4. Build

        make

5. Install

        sudo make install

6. Execute

        /usr/local/bin/cdigidoc

### Windows

1. Install dependencies from
    * [Visual Studio Express 2013 for Windows Desktop](http://www.visualstudio.com/en-us/products/visual-studio-express-vs.aspx)
	* [Libxml2](http://xmlsoft.org/downloads.html)
	* [OpenSSL Win32 binaries](https://slproweb.com/products/Win32OpenSSL.html) or [OpenSSL source](https://www.openssl.org/source/)
	* [ZLib source](http://zlib.net/zlib128.zip)
2. Fetch the source

        git clone --recursive https://github.com/open-eid/libdigidoc
        cd libdigidoc

3. Configure

        mkdir build
        cd build
        cmake ..

4. Build

        make

5. Execute

        libdigidoc/cdigidoc.exe
	
### Fedora 24

1. Install dependencies

        sudo dnf install cmake libxml2-devel doxygen enca-devel zlib-devel opencryptoki-devel
	-install libiconv from source http://savannah.gnu.org/projects/libiconv/ 
	  or get it from https://pkgs.org/fedora-24/forensics-x86_64/libiconv-1.14-3.fc24.x86_64.rpm.html
	-build and install openssl0.9.8 from https://github.com/openssl/openssl/archive/OpenSSL_0_9_8zh.tar.gz 
	  or ensure 0.9.8 interfaces are available by configuring with --api=0.9.8 see 
	  https://wiki.openssl.org/index.php/1.1_API_Changes and https://github.com/rbsec/sslscan/issues/108  

2. Complete rest of steps as for Ubuntu.  Be sure to add correct paths to openssl 0.9.8 in the configure step using cmake.

## Support
Official builds are provided through official distribution point [installer.id.ee](https://installer.id.ee). If you want support, you need to be using official builds. Contact for assistance by email [abi@id.ee](mailto:abi@id.ee) or [www.id.ee](http://www.id.ee).

Source code is provided on "as is" terms with no warranty (see license for more information). Do not file Github issues with generic support requests.
