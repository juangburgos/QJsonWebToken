cmake_minimum_required(VERSION 3.16)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)

add_library(QJsonWebToken STATIC
    qjsonwebtoken.h qjsonwebtoken.cpp
)

target_link_libraries(QJsonWebToken PRIVATE Qt${QT_VERSION_MAJOR}::Core)

target_include_directories(QJsonWebToken INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
