#!/bin/bash

POLICIES_FILE=$1
RULES_JS_FILE=$2
OUTPUT_FILE=$3

cat $POLICIES_FILE > $OUTPUT_FILE

FLATTENED_JS=$(cat $RULES_JS_FILE | tr -d "\n" | sed 's/\"/\\"/g')

cat << EOF >> $OUTPUT_FILE
fastengine_files {
  tag: "v.1.2.3"
  files {
    filename: "fastengine_rules.yaml"
    json_content: "${FLATTENED_JS}"
  }
}
EOF

