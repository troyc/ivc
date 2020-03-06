cmake_minimum_required (VERSION 2.6)

project (client_server_test)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")

include_directories (${PROJECT_BINARY_DIR}/../../../include/us ${PROJECT_BINARY_DIR}/../../../include/core 
					 ${PROJECT_BINARY_DIR}/../../../src/ringbuffer/include ${PROJECT_BINARY_DIR}/../../../include/us/platform/linux)

link_directories(${PROJECT_BINARY_DIR}/../../us/lib)
message ("cxx Flags: " ${CMAKE_CXX_FLAGS})

add_executable(test_link test_link.c)
target_link_libraries(test_link ivc pthread)

#Build the example "inter-domain pipe" server.
add_executable(ivc-pipe-server ivc-pipe-server.c)
target_link_libraries(ivc-pipe-server ivc)

#Build the example "inter-domain pipe" client.
add_executable(ivc-pipe-client ivc-pipe-client.c)
target_link_libraries(ivc-pipe-client ivc)

install(
  TARGETS test_link ivc-pipe-server ivc-pipe-client
  RUNTIME DESTINATION bin
)
