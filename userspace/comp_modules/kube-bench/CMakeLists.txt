add_custom_target(kubectl ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/kubectl)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/kubectl
	COMMAND curl -so ${CMAKE_CURRENT_BINARY_DIR}/kubectl -LO https://storage.googleapis.com/kubernetes-release/release/v1.9.6/bin/linux/amd64/kubectl)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/kubectl
	DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/comp_modules/kube-bench
	COMPONENT agent)

add_custom_target(kube_bench ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/kube-bench)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/kube-bench
	COMMAND curl -so ${CMAKE_CURRENT_BINARY_DIR}/kube-bench-0.0.17.tar.gz https://s3.amazonaws.com/download.draios.com/dependencies/kube-bench-0.0.17.tar.gz
	COMMAND tar -zxf ${CMAKE_CURRENT_BINARY_DIR}/kube-bench-0.0.17.tar.gz)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/kube-bench-0.0.17/kube-bench
	DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/comp_modules/kube-bench
	COMPONENT agent)

install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/kube-bench-0.0.17/cfg
	DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/comp_modules/kube-bench
	COMPONENT agent)
