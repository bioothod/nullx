add_executable(nullx_server server.cpp transcode_controller.cpp transcode.cpp)
target_link_libraries(nullx_server
	${AVCODEC_LIBRARIES}
	${AVFORMAT_LIBRARIES}
	${AVFILTER_LIBRARIES}
	${AVUTIL_LIBRARIES}
	${Boost_LIBRARIES}
	${ELLIPTICS_LIBRARIES}
	${GLOG_LIBRARIES}
	${NULLA_LIBRARIES}
	${RIBOSOME_LIBRARIES}
	${SWARM_LIBRARIES}
	${SWRESAMPLE_LIBRARIES}
	${THEVOID_LIBRARIES}
)

add_executable(nullx_transcoder transcode.cpp transcode_example.cpp)
target_link_libraries(nullx_transcoder
	${AVCODEC_LIBRARIES}
	${AVFORMAT_LIBRARIES}
	${AVFILTER_LIBRARIES}
	${AVUTIL_LIBRARIES}
	${Boost_LIBRARIES}
	${GLOG_LIBRARIES}
	${SWRESAMPLE_LIBRARIES}
)

install(TARGETS
	nullx_server
	nullx_transcoder
    RUNTIME DESTINATION bin COMPONENT runtime)
