foreach(messagefile
		all_policy_types.txt
		baseline.txt
		multiple_falco_variants.txt
		multiple_falco_variants_v2.txt
		multiple_falco_files_override.txt
		multiple_falco_files_override_v2.txt
		multiple_falco_files.txt
		multiple_falco_files_v2.txt
		custom_falco_files_override.txt
		custom_falco_files_override_v2.txt
		custom_falco_files.txt
		custom_falco_files_v2.txt
		falco_old_rules_message.txt
		falco_old_new_rules_message.txt)

	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/${messagefile}
		${CMAKE_CURRENT_BINARY_DIR}/${messagefile}
		COPYONLY)

endforeach(messagefile)

foreach(policyfile
		all_policy_v2_types.txt
		v2_policy_dont_match_container.txt
		v2_policy_dont_match_container_multi.txt)

	add_custom_target(resources-${policyfile} ALL
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${policyfile})

	add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${policyfile}
		COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/add_fastengine_rules.sh ${CMAKE_CURRENT_SOURCE_DIR}/${policyfile}.in ${CMAKE_CURRENT_SOURCE_DIR}/all_policy_v2_types-rules.js ${CMAKE_CURRENT_BINARY_DIR}/${policyfile}
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/add_fastengine_rules.sh ${CMAKE_CURRENT_SOURCE_DIR}/${policyfile}.in ${CMAKE_CURRENT_SOURCE_DIR}/all_policy_v2_types-rules.js)

	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${policyfile}
		DESTINATION ${CMAKE_INSTALL_PREFIX}/test/resources/security_policies_messages
		COMPONENT tests)

endforeach(policyfile)



