foreach(messagefile
		all_policy_types.txt
		baseline.txt
		multiple_falco_variants.txt
		multiple_falco_files_override.txt
		multiple_falco_files.txt
		custom_falco_files_override.txt
		custom_falco_files.txt
		falco_old_rules_message.txt
		falco_old_new_rules_message.txt)

	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/${messagefile}
		${CMAKE_CURRENT_BINARY_DIR}/${messagefile}
		COPYONLY)

endforeach(messagefile)     


