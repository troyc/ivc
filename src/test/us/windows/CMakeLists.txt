cmake_minimum_required (VERSION 2.6)

project (win_client_server)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")

include_directories (${PROJECT_BINARY_DIR}/../../../../include/us/platform/windows ${PROJECT_BINARY_DIR}/../../../../include/core  ${PROJECT_BINARY_DIR}/../../../../src/ringbuffer/include ${PROJECT_BINARY_DIR}/../../../../include/ks/platform/windows)

link_directories(${PROJECT_BINARY_DIR}/../../../us/platform/windows/lib)
message ("cxx Flags: " ${CMAKE_CXX_FLAGS})

#Build the example "inter-domain pipe" server.
add_executable(ivc-pipe-server-win ivc-pipe-server-win.c)
target_link_libraries(ivc-pipe-server-win ivc)

#Build the example "inter-domain pipe" client.
add_executable(ivc-pipe-client-win ivc-pipe-client-win.c)
target_link_libraries(ivc-pipe-client-win ivc)

install(
  TARGETS ivc-pipe-server-win ivc-pipe-client-win
  RUNTIME DESTINATION bin
)
