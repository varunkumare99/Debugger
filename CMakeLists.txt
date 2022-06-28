cmake_minimum_required(VERSION 2.8.9)
project(debugger)

add_compile_options(-std=c++14)

add_executable(hello examples/hello.cpp)
set_target_properties(hello PROPERTIES COMPILE_FLAGS "-g -O0")

add_executable(variable examples/variables.cpp)
set_target_properties(variable PROPERTIES COMPILE_FLAGS "-gdwarf-2 -O0")

add_executable(stack_unwind examples/stack_unwinding.cpp)
set_target_properties(stack_unwind PROPERTIES COMPILE_FLAGS "-g -O0")

include_directories(include)

file(GLOB SOURCES "src/*.cpp")

add_executable(debugger ${SOURCES})

target_link_libraries(debugger PRIVATE
    ${PROJECT_SOURCE_DIR}/ext/liblinenoise++.so
    ${PROJECT_SOURCE_DIR}/ext/libelf++.so.0
    ${PROJECT_SOURCE_DIR}/ext/libdwarf++.so.0
)

