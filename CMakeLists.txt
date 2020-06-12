﻿# CMakeList.txt: 顶层 CMake 项目文件，在此处执行全局配置
# 并包含子项目。
#
cmake_minimum_required (VERSION 2.8)

project ("SilverPatcher")

SET(CMAKE_SYSTEM_NAME Linux)

# 使用变量设置编译标志
SET(CMAKE_C_COMPILER g++)
set(CMAKE_VERBOSE_MAKEFILE ON)
if(CMAKE_COMPILER_IS_GNUCXX)
   set(CMAKE_CXX_FLAGS "-std=c++11 ${CMAKE_CXX_FLAGS}")
endif(CMAKE_COMPILER_IS_GNUCXX)

FILE(GLOB SRC_LIST *.cpp)
include_directories(/usr/local/include)
LINK_DIRECTORIES(/usr/local/lib)
ADD_EXECUTABLE(SilverPatcher ${SRC_LIST})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -lLIEF)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -lCJsonObject)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -lcapstone)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -lkeystone)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -ldyninstAPI)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -lpatchAPI)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -linstructionAPI)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -lboost_system)
