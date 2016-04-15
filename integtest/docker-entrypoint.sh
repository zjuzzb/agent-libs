#!/bin/sh
echo "* Generating env_data ..." && bash agent_runner.sh && echo "* Running tests ..." && py.test -v test.py