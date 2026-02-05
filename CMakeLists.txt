cmake_minimum_required(VERSION 3.10)
project(IDFixer)

add_library(idfixer SHARED main.cpp)

target_link_libraries(idfixer log)
