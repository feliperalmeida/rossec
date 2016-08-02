#include "ros/ros.h"
#include "std_msgs/String.h"

#include <sstream>
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

using namespace std;

void streamCallback(const std_msgs::String::ConstPtr& msg)
{
    cout << "[Eavesdropper::CBCSTREAM] I heard: " << msg->data << endl << endl;
}

int main(int argc, char **argv)
{
    ros::init(argc, argv, "eavesdropper");

    ros::NodeHandle n;

    ros::Subscriber sub = n.subscribe("cbc_stream", 1000, streamCallback);

    ros::spin();

    return 0;
}
