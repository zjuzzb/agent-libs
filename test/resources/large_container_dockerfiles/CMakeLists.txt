foreach(dockerfile Dockerfile.long_labels)

    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/${dockerfile} ${CMAKE_CURRENT_BINARY_DIR}/${dockerfile}
        COPYONLY
    )

endforeach(dockerfile)
