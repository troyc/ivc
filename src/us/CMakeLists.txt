cmake_minimum_required (VERSION 2.6)

project (libivc_us)

set(INCLUDE_BASE ../../include)
set(OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR}/lib)

set(LIBRARY_OUTPUT_PATH ${OUTPUT_PATH})
set(LIBRARY_OUTPUT_PATH_DEBUG ${OUTPUT_PATH})
set(LIBRARY_OUTPUT_PATH_RELEASE ${OUTPUT_PATH})
set(LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_PATH})

set(srcs ${CMAKE_CURRENT_SOURCE_DIR}/../core/libivc.c ${CMAKE_CURRENT_SOURCE_DIR}/../core/libivc_debug.c ${CMAKE_CURRENT_SOURCE_DIR}/../data-structures/ringbuffer.c)
set(hdrs ${INCLUDE_BASE}/core ${INCLUDE_BASE}/us ${INCLUDE_BASE}/us/platform ${CMAKE_CURRENT_SOURCE_DIR}/../data-structures)
set(hdr_files ${INCLUDE_BASE}/core/list.h ${INCLUDE_BASE}/core/libivc.h ${INCLUDE_BASE}/core/libivc_private.h ${INCLUDE_BASE}/core/ivc_ioctl_defs.h
    ${INCLUDE_BASE}/core/libivc_types.h)

# add in the platform specific files which implement the userland driver logic

if(WIN32)
	list(APPEND srcs platform/windows/us_platform.c)
	list(APPEND hdrs ${INCLUDE_BASE}/us/platform/windows)
	list(APPEND hdr_files ${INCLUDE_BASE}/us/platform/windows/us_platform.h)
else()
	list(APPEND srcs platform/linux/us_privilege.c)
	list(APPEND hdrs ${INCLUDE_BASE}/us/platform/linux)
        list(APPEND hdr_files ${INCLUDE_BASE}/us/platform/linux/common_defs.h ${INCLUDE_BASE}/us/platform/linux/platform_defs.h)
        find_package(Threads)
        find_library(RT rt)
        set (IVC_LIBRARIES ${RT})
endif()

include_directories(${hdrs})

add_library(ivc SHARED ${srcs} ${hdr_files})
set_target_properties(ivc PROPERTIES VERSION 1.0 SOVERSION 1)
target_link_libraries (ivc PUBLIC ${CMAKE_THREAD_LIBS_INIT} ${IVC_LIBRARIES} )


#Also generate installation commands for libivc...
install(
  TARGETS ivc
  LIBRARY DESTINATION lib
)

#... and its header files.
install(
  FILES 
    "${INCLUDE_BASE}/core/libivc.h" 
    "${INCLUDE_BASE}/core/libivc_types.h" 
    "${INCLUDE_BASE}/core/libivc_debug.h" 
  DESTINATION include
)
