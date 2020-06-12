# CMakeList.txt: 顶层 CMake 项目文件，在此处执行全局配置
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

#查找依赖库
find_library(LIEF_LIB LIEF)
if(NOT LIEF_LIB)
   message(FATAL_ERROR "LIEF not properly installed.")
endif()
find_library(DYNINST_LIB dyninstAPI)
if(NOT DYNINST_LIB)
   message(FATAL_ERROR "Dyninst not properly installed.")
endif()
find_library(CAPSTONE_LIB capstone)
if(NOT CAPSTONE_LIB)
   message(FATAL_ERROR "capstone not properly installed.")
endif()
find_library(KEYSTONE_LIB keystone)
if(NOT KEYSTONE_LIB)
   message(FATAL_ERROR "keystone not properly installed.")
endif()
find_library(CJSONOBJECT_LIB CJsonObject)
if(NOT CJSONOBJECT_LIB)
   message(FATAL_ERROR "CJsonObject not properly installed.")
endif()

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

