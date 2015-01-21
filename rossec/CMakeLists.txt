cmake_minimum_required(VERSION 2.8.3)
project(rossec)

find_package(catkin REQUIRED COMPONENTS
  roscpp
  std_msgs
)

catkin_package(
  LIBRARIES ${PROJECT_NAME}
  INCLUDE_DIRS include
  )

include_directories(
  ${catkin_INCLUDE_DIRS}
)

include_directories(include)

add_library(${PROJECT_NAME}
  src/AESGCM.cpp src/AESCBC.cpp)

#add_library(${PROJECT_NAME}
  #src/AESCBC.cpp)

target_link_libraries(${PROJECT_NAME} cryptopp)

install(TARGETS ${PROJECT_NAME}
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib)

install(DIRECTORY include/
        DESTINATION include
        FILES_MATCHING PATTERN "*.h"
	PATTERN ".git" EXCLUDE)

