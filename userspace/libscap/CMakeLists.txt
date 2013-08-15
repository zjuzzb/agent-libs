include_directories(${PROJECT_SOURCE_DIR}/common)

add_library(scap STATIC 
	scap.c 
	scap_event.c 
	scap_fds.c 
	scap_iflist.c 
	scap_savefile.c 
	scap_event.c 
	scap_procs.c 
	${PROJECT_SOURCE_DIR}/driver/event_table.c
	${PROJECT_SOURCE_DIR}/driver/syscall_info_table.c)

add_subdirectory(tests/01-open)
add_subdirectory(tests/02-validatebuffer)
#add_subdirectory(tests/03-checktimestamps)
add_subdirectory(tests/04-dumpevents)
add_subdirectory(tests/05-printplatform)
add_subdirectory(tests/06-stopcapture)
add_subdirectory(tests/07-withoutlsof)
