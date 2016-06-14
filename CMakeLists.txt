project(nullx)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -W -Wall -Wextra -fstack-protector-all -g")

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/debian/changelog" DEBCHANGELOG)

# version string: 0.3.12
# nullx major 0
# nullx minor 3.12
string(REGEX MATCH "([0-9]+\\.[0-9]+\\.[0-9]+)" DEBFULLVERSION "${DEBCHANGELOG}")
string(REGEX MATCH "([0-9]+)" NULLA_VERSION_MAJOR "${DEBFULLVERSION}")
string(REGEX MATCH "([0-9]+\\.[0-9]+$)" NULLA_VERSION_MINOR "${DEBFULLVERSION}")

include(cmake/locate_library.cmake)

LOCATE_LIBRARY(AVCODEC "libavcodec/avcodec.h" "avcodec" "ffmpeg")
LOCATE_LIBRARY(AVFORMAT "libavformat/avformat.h" "avformat" "ffmpeg")
LOCATE_LIBRARY(AVFILTER "libavfilter/avfilter.h" "avfilter" "ffmpeg")
LOCATE_LIBRARY(AVUTIL "libavutil/error.h" "avutil" "ffmpeg")
LOCATE_LIBRARY(GLOG "glog/logging.h" "glog")
LOCATE_LIBRARY(SWARM "swarm/http_response.hpp" "swarm")
LOCATE_LIBRARY(SWRESAMPLE "libswresample/swresample.h" "swresample" "ffmpeg")
LOCATE_LIBRARY(THEVOID "thevoid/server.hpp" "thevoid")

find_package(Boost COMPONENTS system thread filesystem program_options REQUIRED)
find_package(Elliptics REQUIRED)
find_package(Nulla REQUIRED)
find_package(Ribosome REQUIRED)

include_directories(
	"${CMAKE_CURRENT_SOURCE_DIR}/include"
	${AVCODEC_INCLUDE_DIRS}
	${AVFORMAT_INCLUDE_DIRS}
	${AVFILTER_INCLUDE_DIRS}
	${AVUTIL_INCLUDE_DIRS}
	${Boost_INCLUDE_DIRS}
	${ELLIPTICS_INCLUDE_DIRS}
	${GLOG_INCLUDE_DIRS}
	${NULLA_INCLUDE_DIRS}
	${RIBOSOME_INCLUDE_DIRS}
	${SWARM_INCLUDE_DIRS}
	${SWRESAMPLE_INCLUDE_DIRS}
	${THEVOID_INCLUDE_DIRS}
)

link_directories(
	${AVCODEC_LIBRARY_DIRS}
	${AVFORMAT_LIBRARY_DIRS}
	${AVFILTER_LIBRARY_DIRS}
	${AVUTIL_LIBRARY_DIRS}
	${Boost_LIBRARY_DIRS}
	${ELLIPTICS_LIBRARY_DIRS}
	${GLOG_LIBRARY_DIRS}
	${NULLA_LIBRARY_DIRS}
	${SWRESAMPLE_LIBRARY_DIRS}
	${RIBOSOME_LIBRARY_DIRS}
	${THEVOID_LIBRARY_DIRS}
)

add_subdirectory(src)
#add_subdirectory(tests)

file(GLOB headers "${CMAKE_CURRENT_SOURCE_DIR}/include/nullx/*.hpp")
install(FILES ${headers} DESTINATION include/nullx)
