cmake_minimum_required(VERSION 3.16)
project(ChatGPTKDE LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Network)

qt_standard_project_setup()

qt_add_executable(ChatGPTKDE
    main.cpp
    mainwindow.h
    mainwindow.cpp
    resources.qrc
)

target_compile_definitions(ChatGPTKDE PRIVATE
    CHATGPTKDE_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)
target_link_libraries(ChatGPTKDE PRIVATE Qt6::Widgets Qt6::Network)
