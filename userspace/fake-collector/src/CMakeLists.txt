


add_library(fake-collector-core STATIC
	fake_collector.cpp
)

add_executable(fake-collector
	main.cpp
)

target_link_libraries(fake-collector
	fake-collector-core
	pthread
)

install(TARGETS fake-collector
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
	COMPONENT fake-collector)
