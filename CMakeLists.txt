cmake_minimum_required(VERSION 3.21)
project(sniff)

find_package(Protobuf REQUIRED)
include_directories(${Protobuf_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
set(CMAKE_CXX_STANDARD 20)

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS proto/filters.proto)
# protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS EXPORT_MACRO DLL_EXPORT
# proto/filter.proto) protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS DESCRIPTORS
# PROTO_DESCS proto/filter.proto)

set(__root ${CMAKE_CURRENT_SOURCE_DIR})
aux_source_directory(${__root} __files)

add_executable(${PROJECT_NAME} ${__files} ${PROTO_SRCS} ${PROTO_HDRS})
# add_subdirectory(${__root}/src)

target_include_directories(
  ${PROJECT_NAME} PUBLIC "$<BUILD_INTERFACE:${__root}/include>"
                         "$<INSTALL_INTERFACE:include>")

target_link_libraries(${PROJECT_NAME} ${Protobuf_LIBRARIES})
