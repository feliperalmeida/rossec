cmake_minimum_required(VERSION 2.8.3)
project(rossec)

catkin_package(
  LIBRARIES ${PROJECT_NAME}
  INCLUDE_DIRS include
  DEPENDS cryptopp
)

include_directories(
  ${catkin_INCLUDE_DIRS}
)

include_directories(include)

add_library(${PROJECT_NAME}
  src/AESGCM.cpp src/AESCBC.cpp)

target_link_libraries(${PROJECT_NAME} cryptopp)

install(TARGETS ${PROJECT_NAME}
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib)

install(DIRECTORY include/
        DESTINATION include
        FILES_MATCHING PATTERN "*.h"
	PATTERN ".git" EXCLUDE)

#############
## Testing ##
#############

## Add gtest based cpp test target and link libraries
# catkin_add_gtest(${PROJECT_NAME}-test test/test_rossec_tests.cpp)
# if(TARGET ${PROJECT_NAME}-test)
#   target_link_libraries(${PROJECT_NAME}-test ${PROJECT_NAME})
# endif()

## Add folders to be run by python nosetests
# catkin_add_nosetests(test)
