cmake_minimum_required (VERSION 2.8)

project ( module_overloader )

# This option allows you to choose if you want to build a DLL or EXE:
option(BUILD_AS_DLL "Build the project as a DLL" OFF)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# include libpeconv headers:
include_directories ( ${PECONV_DIR}/include )

set (srcs
	util.cpp
)

# general headers - they will be used for both EXE and DLL:
set (hdrs
	util.h
)

set (rsrc
#put your resources here
)

add_executable ( ${PROJECT_NAME} ${exe_hdrs} ${srcs} ${rsrc} main.cpp )


# link with libpeconv.lib
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )

#dependencies:
add_dependencies( ${PROJECT_NAME} libpeconv )
