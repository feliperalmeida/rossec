#include "ros/ros.h"
#include "std_msgs/String.h"

#include <sstream>
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include "rossec/rossec.h"

using namespace std;

void streamCallback(const std_msgs::String::ConstPtr& msg)
{
    string cipher;
    int ciphersize = msg->data.size();

    cipher.resize(ciphersize);

    for(int i = 0; i < ciphersize; i++)
        cipher[i] = msg->data[i];

    /*
     * Hardcoded key
     * This is only an usage example. Please make sure you properly protect your key.
     */
    int keySize = rossec::AESGCM::DEFAULT_KEYLENGTH;

    byte key[keySize];
    for(int i = 0; i < keySize; i++)
        key[i] = i;

    rossec::AESGCM* c = new rossec::AESGCM(key);

    string recovered = c->decryptString(cipher);

    cout << "[ROSSec::AESGCM] cipher text: " << c->getHexString(cipher) << endl;

    cout << "[ROSSec::AESGCM] recovered text: " << recovered << endl << endl;

}

int main(int argc, char **argv)
{
    ros::init(argc, argv, "listener");

    ros::NodeHandle n;

    ros::Subscriber sub = n.subscribe("gcm_stream", 1000, streamCallback);

    ros::spin();

    return 0;
}
