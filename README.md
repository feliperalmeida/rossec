# rossec

**WARNING: This library is EXPERIMENTAL. DO NOT use it on production. Do not use unless you know what you are doing. Also, this library alone DOES NOT provide security to ROS messages exchanges.**

This is the official repository of rossec.

rossec is a library developed to provide cryptography on messages exchanges using [ROS](http://www.ros.org).

rossec encapsulates implementations of Advanced Encryption Standard (AES), a well-known and NIST approved block cipher specified in [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf).

For confidentiality purposes, rossec provides the use of [Chiper Block Chaining (CBC)](http://www.itl.nist.gov/fipspubs/fip81.htm). For both confidentiality and authenticity, rossec operates the cipher in [Galios Counter Mode (GCM)](http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf).

Licensed under GNU GPLv2. Check [LICENSE](/LICENSE) for more info.

## Installing

* Build & Install [Crypto++](http://www.cryptopp.com/wiki/Linux#Build_and_Install_the_Library)
* Clone this repo on your catkin\_workspace: `git clone https://github.com/frda/rossec.git`
* Make: `catkin_make install`
* Use it :)

## Developing

* Include the library into your C++ project
* Use and construct proper algorithm given your security requisites
* Define and set shared secret key
  * **Warning: please make sure key is safely protected**
* Encrypt and decrypt messages

## Usage examples

Make sure you have [roscore](http://wiki.ros.org/roscore) up and running.

* In one tab, run: `rosrun rossec_tests rossec_pub_AESCBC`
* In another one, run: `rosrun rossec_tests rossec_listen_AESCBC`

For more information and other examples, please see [rossec_tests](/rossec_tests/src) folder.

## Contributing

Please, feel free to create a pull request and submit your changes :)
