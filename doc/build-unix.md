Copyright (c) 2018-2019 'CACHE'Project Developers
Copyright (c) 2009-2014 Bitcoin Developers


UNIX BUILD NOTES
====================



Base build dependencies
-----------------------

Run the following commands to install required packages:


##### Debian/Ubuntu:
```bash
$ sudo apt-get install build-essential libssl-dev libboost-all-dev libdb5.3 libdb5.3-dev libdb5.3++-dev libtool automake libevent-dev bsdmainutils -y
$ sudo apt-get install git ntp make g++ gcc autoconf cpp ngrep iftop sysstat autotools-dev pkg-config libminiupnpc-dev libzmq3-dev -y
$ sudo apt-get install libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler libqrencode-dev -y
```

Set USE_QRCODE to control this:
 USE_QRCODE=0   (the default) No QRCode support - libqrcode not required
 USE_QRCODE=1   QRCode support enabled

Set USE_UPNP to a different value to control this:
 USE_UPNP=-    No UPnP support - miniupnp not required
 USE_UPNP=0    (the default) UPnP support turned off by default at runtime
 USE_UPNP=1    UPnP support turned on by default at runtime

Set USE_IPV6 to a different value to control this:
 USE_IPV6=-    No IPV6 support
 USE_IPV6=0    (the default) IPV6 support turned off by default at runtime
 USE_IPV6=1    IPV6 support turned on by default at runtime

##### build CACHE-Project-qt
```bash
$ cd CACHeCoin && qmake -qt=qt4 "USE_QRCODE=1" "USE_UPNP=1" "USE_IPV6=1" *.pro && make
```

##### build cacheprojectd
```bash
$ cd src && make -f makefile.unix
```


##### Fedora:
```bash
$
```


##### Arch Linux:
```bash
$
```


##### FreeBSD/OpenBSD:
```bash
$
```



Security
--------

To help make your cacheproject installation more secure by making certain attacks impossible to
exploit even if a vulnerability is found, you can take the following measures:

* Position Independent Executable
    Build position independent code to take advantage of Address Space Layout Randomization
    offered by some kernels. An attacker who is able to cause execution of code at an arbitrary
    memory location is thwarted if he doesn't know where anything useful is located.
    The stack and heap are randomly located by default but this allows the code section to be
    randomly located as well.

    On an Amd64 processor where a library was not compiled with -fPIC, this will cause an error
    such as: "relocation R_X86_64_32 against `......' can not be used when making a shared object;"

    To build with PIE, use:
    ```bash
    $ make -f makefile.unix ... -e PIE=1
    ```

    To test that you have built PIE executable, install scanelf, part of paxutils, and use:
    ```bash
    $ scanelf -e ./cacheproject
    ```

    The output should contain:
     TYPE
    ET_DYN

* Non-executable Stack
    If the stack is executable then trivial stack based buffer overflow exploits are possible if
    vulnerable buffers are found. By default, cacheproject should be built with a non-executable stack
    but if one of the libraries it uses asks for an executable stack or someone makes a mistake
    and uses a compiler extension which requires an executable stack, it will silently build an
    executable without the non-executable stack protection.

    To verify that the stack is non-executable after compiling use:
    ```bash
    $ scanelf -e ./cacheproject
    ```

    the output should contain:
    STK/REL/PTL
    RW- R-- RW-

    The STK RW- means that the stack is readable and writeable but not executable.
