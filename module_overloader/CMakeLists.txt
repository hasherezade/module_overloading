cmake_minimum_required (VERSION 2.8)

project ( module_overloader )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

option( CLASSIC_HOLLOWING "Use Classic DLL Hollowing" OFF )

if(CLASSIC_HOLLOWING)
    add_compile_definitions(CLASSIC_HOLLOWING)
endif()

# include libpeconv headers:
include_directories ( ${PECONV_DIR}/include )

set (srcs
	util.cpp
)

# general headers - they will be used for both EXE and DLL:
set (hdrs
	util.h
)

add_executable ( ${PROJECT_NAME} ${exe_hdrs} ${srcs} ${rsrc} main.cpp )

# link with libpeconv.lib
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )

#dependencies:
add_dependencies( ${PROJECT_NAME} libpeconv )
