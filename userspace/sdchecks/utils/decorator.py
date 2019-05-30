from functools import wraps


def required_config(*config_params):
    """Ensures that required parameters are present in config_params"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            instance_params = dict(args[1])
            missing_configs = []
            for arg in config_params:
                if arg not in args[1]:
                    missing_configs.append(arg)
            if missing_configs:
                raise Exception("Mandatory config(s) %s is/are missing in dragent.yaml file for %s,"
                                " please add missing config(s)." % (tuple(missing_configs), instance_params.get('name')))
            return func(*args, **kwargs)
        return wrapper
    return decorator
