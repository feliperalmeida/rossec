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

int main(int argc, char **argv)
{
    ros::init(argc, argv, "talker");

    ros::NodeHandle n;

    ros::Publisher chatter_pub = n.advertise<std_msgs::String>("cbc_stream", 1000);

    ros::Rate loop_rate(1);

    int count = 0;

    /*
    * Hardcoded key
    * This is only an usage example. Please make sure you properly protect your key.
    */
    int keySize = rossec::AESCBC::DEFAULT_KEYLENGTH;

    byte key[keySize];
    for(int i = 0; i < keySize; i++)
        key[i] = i;

    rossec::AESCBC* c = new rossec::AESCBC(key);

    //c->setKey(key);

    while (ros::ok())
    {

        std_msgs::String msg;

        std::stringstream ss;
        ss << "hello world " << count;

        msg.data = c->encryptString(ss.str());

        //ROS_INFO("%s", msg.data.c_str());

        cout << "[ROSSec::AESCBC] plain text: " << ss.str() << endl;

        cout << "[ROSSec::AESCBC] cipher text: " << c->getHexString(msg.data) << endl << endl;

        // Attacking first bytes
        if( msg.data.size() > 1 )
        {
            msg.data[ 0 ] |= 0x0F;
            msg.data[ 1 ] |= 0x0F;
            msg.data[ 2 ] |= 0x0F;
        }

        chatter_pub.publish(msg);

        ros::spinOnce();

        loop_rate.sleep();

        ++count;
    }

    return 0;
}

