import os
from os import path
import pkg_resources

__folder__ = path.abspath(path.dirname(__file__))


class DummyPlugin(object):
    def __init__(self, config=None):
        self.config = config or {}

    def configure(self, config):
        return config

    def check_test_vector_params(self, applies_to, test_params):
        return test_params

    def check_test_vector(self, test_result):
        return test_result

    def check_report(self, report):
        return report


def get_plugins():
    plugins = {}
    for plugin_name in os.listdir(__folder__):
        plugin_name = path.splitext(plugin_name)[0]
        if plugin_name in ["__init__", "__pycache__"]:
            continue

        plugins[plugin_name] = pkg_resources.EntryPoint(
            plugin_name, "{module}.{plugin}".format(module=__name__, plugin=plugin_name),
            dist=pkg_resources.Distribution()
        )

    for entry_point in pkg_resources.iter_entry_points('f5_waf_tester.plugins'):
        plugins[entry_point.name] = entry_point

    return plugins
