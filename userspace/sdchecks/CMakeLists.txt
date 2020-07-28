set(PYTHON27 "Python-2.7.16")
set(PYTHON26 "Python-2.6.9")
set(PYTHON38 "Python-3.8.3")
set(PYTHON37 "Python-3.7.3")
set(PYTHON36 "Python-3.6.9")
set(PYTHON35 "Python-3.5.9")

add_custom_target(
    sdchecks-deps ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/deps
            ${CMAKE_CURRENT_BINARY_DIR}/deps2.7
            ${CMAKE_CURRENT_BINARY_DIR}/deps3
            ${CMAKE_CURRENT_BINARY_DIR}/deps3.5
            ${CMAKE_CURRENT_BINARY_DIR}/deps3.6
            ${CMAKE_CURRENT_BINARY_DIR}/deps3.7
            ${CMAKE_CURRENT_BINARY_DIR}/deps3.8
            ${CMAKE_CURRENT_BINARY_DIR}/deps2.6
)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/deps
    COMMAND
        ${CMAKE_COMMAND} -E env
        PATH="${DRAIOS_DEPENDENCIES_DIR}/postgresql-9.4.15/target/bin:$ENV{PATH}"
        ${DRAIOS_DEPENDENCIES_DIR}/${PYTHON27}/target/bin/python
        ${DRAIOS_DEPENDENCIES_DIR}/${PYTHON27}/target/bin/pip install -I
        --target=${CMAKE_CURRENT_BINARY_DIR}/deps --upgrade -r
        ${CMAKE_CURRENT_SOURCE_DIR}/requirements.txt
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/requirements.txt
)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/deps2.7
    COMMAND
        ${CMAKE_COMMAND} -E env
        PATH="${DRAIOS_DEPENDENCIES_DIR}/postgresql-9.4.15/target/bin:$ENV{PATH}"
        ${DRAIOS_DEPENDENCIES_DIR}/${PYTHON27}/target/bin/python
        ${DRAIOS_DEPENDENCIES_DIR}/${PYTHON27}/target/bin/pip install -I
        --target=${CMAKE_CURRENT_BINARY_DIR}/deps2.7 --upgrade -r
        ${CMAKE_CURRENT_SOURCE_DIR}/requirements-native-2.7.txt
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/requirements-native-2.7.txt
)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/deps3
    COMMAND
        ${CMAKE_COMMAND} -E env
        PATH="${DRAIOS_DEPENDENCIES_DIR}/postgresql-9.4.15/target/bin:$ENV{PATH}"
        ${DRAIOS_DEPENDENCIES_DIR}/${PYTHON37}/target/bin/python3
        ${DRAIOS_DEPENDENCIES_DIR}/${PYTHON37}/target/bin/pip3 install -I
        --target=${CMAKE_CURRENT_BINARY_DIR}/deps3 --upgrade -r
        ${CMAKE_CURRENT_SOURCE_DIR}/requirements-native-3.txt
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/requirements-native-3.txt
)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/deps3.5
    COMMAND
        ${CMAKE_COMMAND} -E env
        PATH="${DRAIOS_DEPENDENCIES_DIR}/postgresql-9.4.15/target/bin:$ENV{PATH}"
        ${DRAIOS_DEPENDENCIES_DIR}/${PYTHON35}/target/bin/python3
        ${DRAIOS_DEPENDENCIES_DIR}/${PYTHON35}/target/bin/pip3 install -I
        --target=${CMAKE_CURRENT_BINARY_DIR}/deps3.5 --upgrade -r
        ${CMAKE_CURRENT_SOURCE_DIR}/requirements-native-3.5.txt
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/requirements-native-3.5.txt
)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/deps3.6
    COMMAND
        ${CMAKE_COMMAND} -E env
        PATH="${DRAIOS_DEPENDENCIES_DIR}/postgresql-9.4.15/target/bin:$ENV{PATH}"
        ${DRAIOS_DEPENDENCIES_DIR}/${PYTHON36}/target/bin/python3
        ${DRAIOS_DEPENDENCIES_DIR}/${PYTHON36}/target/bin/pip3 install -I
        --target=${CMAKE_CURRENT_BINARY_DIR}/deps3.6 --upgrade -r
        ${CMAKE_CURRENT_SOURCE_DIR}/requirements-native-3.6.txt
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/requirements-native-3.6.txt
)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/deps3.7
    COMMAND
        ${CMAKE_COMMAND} -E env
        PATH="${DRAIOS_DEPENDENCIES_DIR}/postgresql-9.4.15/target/bin:$ENV{PATH}"
        ${DRAIOS_DEPENDENCIES_DIR}/${PYTHON37}/target/bin/python3
        ${DRAIOS_DEPENDENCIES_DIR}/${PYTHON37}/target/bin/pip3 install -I
        --target=${CMAKE_CURRENT_BINARY_DIR}/deps3.7 --upgrade -r
        ${CMAKE_CURRENT_SOURCE_DIR}/requirements-native-3.7.txt
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/requirements-native-3.7.txt
)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/deps3.8
    COMMAND
        ${CMAKE_COMMAND} -E env
        PATH="${DRAIOS_DEPENDENCIES_DIR}/postgresql-9.4.15/target/bin:$ENV{PATH}"
        ${DRAIOS_DEPENDENCIES_DIR}/${PYTHON38}/target/bin/python3
        ${DRAIOS_DEPENDENCIES_DIR}/${PYTHON38}/target/bin/pip3 install -I
        --target=${CMAKE_CURRENT_BINARY_DIR}/deps3.8 --upgrade -r
        ${CMAKE_CURRENT_SOURCE_DIR}/requirements-native-3.8.txt
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/requirements-native-3.8.txt
)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/deps2.6
    COMMAND
        ${CMAKE_COMMAND} -E env
        PATH="${DRAIOS_DEPENDENCIES_DIR}/postgresql-9.4.15/target/bin:$ENV{PATH}"
        ${DRAIOS_DEPENDENCIES_DIR}/${PYTHON26}/target/bin/python
        ${DRAIOS_DEPENDENCIES_DIR}/${PYTHON26}/target/bin/pip install -I
        --target=${CMAKE_CURRENT_BINARY_DIR}/deps2.6 --upgrade -r
        ${CMAKE_CURRENT_SOURCE_DIR}/requirements-native-2.6.txt
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/requirements-native-2.6.txt
)

install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.py
    PATTERN LICENSE
    PATTERN tests.py EXCLUDE
    PATTERN resources EXCLUDE
)

install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.py
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.pth
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.so
)

install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps2.7/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps2.7
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.py
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps2.7/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps2.7
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.pth
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps2.7/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps2.7
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.so
)


install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps2.7/psycopg2/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps2.7/psycopg2/
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.so*
)

install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.py
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.pth
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.so
)

install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3.5/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3.5
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.py
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3.5/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3.5
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.pth
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3.5/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3.5
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.so
)


install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3.5/psycopg2/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3.5/psycopg2/
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.so*
)

install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3.6/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3.6
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.py
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3.6/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3.6
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.pth
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3.6/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3.6
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.so
)


install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3.6/psycopg2/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3.6/psycopg2/
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.so*
)

install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3.7/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3.7
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.py
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3.7/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3.7
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.pth
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3.7/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3.7
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.so
)


install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3.7/psycopg2/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3.7/psycopg2/
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.so*
)

install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3.8/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3.8
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.py
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3.8/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3.8
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.pth
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3.8/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3.8
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.so
)

install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps3.8/psycopg2/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps3.8/psycopg2/
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.so*
)

install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps2.6/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps2.6
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.py
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps2.6/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps2.6
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.pth
)
install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps2.6/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps2.6
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.so
)

install(
    DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps2.6/psycopg2/
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python-deps2.6/psycopg2/
    COMPONENT agent-slim
    FILES_MATCHING
    PATTERN *.so*
)

install(
    FILES ${DRAIOS_DEPENDENCIES_DIR}/postgresql-9.4.15/target/lib/libpq.so.5.7
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/
    COMPONENT agent-slim
    RENAME libpq.so.5
)
install(
    PROGRAMS sdchecks
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    COMPONENT agent-slim
)
