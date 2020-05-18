from stat import *

from sdchecks import AppCheckInstance, Config, YamlConfig
import pytest
import os

@pytest.fixture
def yaml():
    return YamlConfig(["resources/first.yaml", "resources/second.yaml", "resources/third.yaml"])

@pytest.fixture
def yaml_not_exists():
    return YamlConfig(["resources/first.yaml", "resources/not_exists.yaml", "resources/third.yaml"])

def test_yaml_get_single(yaml, yaml_not_exists):
    assert yaml.get_single("key", "subkey", 10) == 90
    assert yaml_not_exists.get_single("key", "subkey", 10) == 10

def test_yaml_get_merged_sequence(yaml, yaml_not_exists):
    assert len(yaml.get_merged_sequence("array_not_exists")) == 0
    assert yaml.get_merged_sequence("array_empty") == [ { "first": 1}, ]
    assert yaml_not_exists.get_merged_sequence("array") == [ { "first": 1}, { "third": 3}]
    assert yaml.get_merged_sequence("array") == [ { "first": 1}, { "second": 2}, { "third": 3}]


def test_get_custom_directory(tmp_path):
    #
    # Test setup
    #
    my_custom_check_dir = str(tmp_path / "my_custom_check")
    default_custom_check_dir = str(tmp_path / "lib/python/checks.custom.d")
    os.mkdir(my_custom_check_dir)
    os.makedirs(default_custom_check_dir)
    check = {
        "name": "voltdb"
    }

    proc_data = {
        "pid":1234,
        "vpid": 1,
        "conf_vals": "",
        "ports": ""
    }

    os.mkdir(str(tmp_path / "etc"))
    f = open(str(tmp_path) + "/etc/dragent.yaml", 'w')
    f.write("prometheus: {key1: val1, key2: val2}\napp_checks_custom_directory: %s\n" % my_custom_check_dir)
    f.close()

    script_content = """
from checks import AgentCheck
class MyCustomCheck(AgentCheck):
    def check(self, instance):
            self.gauge(\"maramo\", 10)"""

    f = open(my_custom_check_dir + "/voltdb.py", 'w')
    f.write(script_content)
    f.close()

    f = open(default_custom_check_dir + "/voltdb.py", 'w')
    f.write(script_content)
    f.close()
    #
    #
    #

    config = Config(str(tmp_path))

    ac = AppCheckInstance(check, proc_data, config, container_support=False)

    assert ac._get_custom_directory(default_custom_check_dir, my_custom_check_dir) == my_custom_check_dir

    # Custom check does not exist
    os.remove(my_custom_check_dir + "/voltdb.py")
    os.remove(my_custom_check_dir + "/voltdb.pyc")
    os.rmdir(my_custom_check_dir)
    assert ac._get_custom_directory(default_custom_check_dir, my_custom_check_dir) == default_custom_check_dir
