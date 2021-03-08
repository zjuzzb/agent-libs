foreach(
    eventfile
    all_events.txt create_deployment_in_namespace_foo.txt
    create_deployment_in_namespace_my_namespace.txt create_namespace.txt create_service.txt
    create_namespace_foo.txt
    create_secret.txt
)

    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/${eventfile} ${CMAKE_CURRENT_BINARY_DIR}/${eventfile} COPYONLY
    )

endforeach(eventfile)
