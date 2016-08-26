from sdchecks import YamlConfig
import pytest

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