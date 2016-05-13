add_executable(nullx_server server.cpp)
target_link_libraries(nullx_server
	${Boost_LIBRARIES}
	${CRYPTOPP_LIBRARIES}
	${EBUCKET_LIBRARIES}
	${ELLIPTICS_LIBRARIES}
	${GREYLOCK_LIBRARIES}
	${MSGPACK_LIBRARIES}
	${RIBOSOME_LIBRARIES}
	${SWARM_LIBRARIES}
	${THEVOID_LIBRARIES}
)

install(TARGETS
	nullx_server
    RUNTIME DESTINATION bin COMPONENT runtime)
