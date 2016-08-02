cmake_minimum_required(VERSION 2.8.3)
project(rossec_tests)

find_package(catkin REQUIRED COMPONENTS
  roscpp
  std_msgs
  rossec
)

###################################
## catkin specific configuration ##
###################################
## The catkin_package macro generates cmake config files for your package
## Declare things to be passed to dependent projects
## INCLUDE_DIRS: uncomment this if you package contains header files
## LIBRARIES: libraries you create in this project that dependent projects also need
## CATKIN_DEPENDS: catkin_packages dependent projects also need
## DEPENDS: system dependencies of this project that dependent projects also need
catkin_package(
#  INCLUDE_DIRS include
#  LIBRARIES rossec_tests
#  CATKIN_DEPENDS roscpp std_msgs
#  DEPENDS system_lib
)

include_directories(
  ${catkin_INCLUDE_DIRS}
)

add_executable(rossec_pub_AESGCM src/pubAESGCM.cpp)
target_link_libraries(rossec_pub_AESGCM ${catkin_LIBRARIES})
install(TARGETS rossec_pub_AESGCM
    RUNTIME DESTINATION ${CATKIN_PACKAGE_BIN_DESTINATION}
)

add_executable(rossec_listen_AESGCM src/listenAESGCM.cpp)
target_link_libraries(rossec_listen_AESGCM ${catkin_LIBRARIES})
install(TARGETS rossec_listen_AESGCM
    RUNTIME DESTINATION ${CATKIN_PACKAGE_BIN_DESTINATION}
)

add_executable(rossec_pub_AESCBC src/pubAESCBC.cpp)
target_link_libraries(rossec_pub_AESCBC ${catkin_LIBRARIES})
install(TARGETS rossec_pub_AESCBC
    RUNTIME DESTINATION ${CATKIN_PACKAGE_BIN_DESTINATION}
)

add_executable(rossec_listen_AESCBC src/listenAESCBC.cpp)
target_link_libraries(rossec_listen_AESCBC ${catkin_LIBRARIES})
install(TARGETS rossec_listen_AESCBC
    RUNTIME DESTINATION ${CATKIN_PACKAGE_BIN_DESTINATION}
)

add_executable(rossec_pub_AESCBC_simulated_attack src/attack_pubAESCBC.cpp)
target_link_libraries(rossec_pub_AESCBC_simulated_attack ${catkin_LIBRARIES})
install(TARGETS rossec_pub_AESCBC_simulated_attack
    RUNTIME DESTINATION ${CATKIN_PACKAGE_BIN_DESTINATION}
)

add_executable(rossec_pub_AESGCM_simulated_attack src/attack_pubAESGCM.cpp)
target_link_libraries(rossec_pub_AESGCM_simulated_attack ${catkin_LIBRARIES})
install(TARGETS rossec_pub_AESGCM_simulated_attack
    RUNTIME DESTINATION ${CATKIN_PACKAGE_BIN_DESTINATION}
)

add_executable(rossec_eavesdropper_CBC_stream src/listen_cbcstream.cpp)
target_link_libraries(rossec_eavesdropper_CBC_stream ${catkin_LIBRARIES})
install(TARGETS rossec_eavesdropper_CBC_stream
    RUNTIME DESTINATION ${CATKIN_PACKAGE_BIN_DESTINATION}
)

add_executable(rossec_eavesdropper_GCM_stream src/listen_gcmstream.cpp)
target_link_libraries(rossec_eavesdropper_GCM_stream ${catkin_LIBRARIES})
install(TARGETS rossec_eavesdropper_GCM_stream
    RUNTIME DESTINATION ${CATKIN_PACKAGE_BIN_DESTINATION}
)
