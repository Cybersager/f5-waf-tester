import json
import string
import logging
from os import path
import requests_raw as requests
from collections import defaultdict
from multiprocessing.pool import ThreadPool
from .plugins import DummyPlugin, get_plugins
from .__version__ import __title__, __version__
from .utils import regex_parser, generate_test_id
from requests.compat import urlparse, urljoin, quote_plus
from .config import CONFIG_TEMPLATE, DEFAULT_CONFIG_PATH, DEFAULT_TESTS_PATH, prompt_config, validate_tests

requests.monkey_patch_all()


class F5WAFTester(object):
    def __init__(self, configuration_path=DEFAULT_CONFIG_PATH, tests_path=DEFAULT_TESTS_PATH):
        self.logger = logging.getLogger(__name__)

        self.config_path = configuration_path
        self.config = CONFIG_TEMPLATE.copy()
        if path.exists(self.config_path):
            with open(configuration_path) as cf:
                self.config = json.load(cf)

        self.tests_path = tests_path
        with open(tests_path) as tf:
            self.tests = json.load(tf)

        self.pool = ThreadPool(self.config.get("threads"))
        self.report = None
        self.request_args = self.get_global_request_args()
        self.test_id = generate_test_id()
        self.plugin = self.load_plugin(plugin_name=self.config.get("plugin"))

    def load_plugin(self, plugin_name=None):
        plugin = DummyPlugin()
        if plugin_name:
            plugin = get_plugins().get(self.config.get("plugin"))
            plugin = plugin.load().WAFTesterPlugin(config=self.config["plugins"].get(plugin_name))
        return plugin

    def get_global_request_args(self):
        proxies = None
        proxy_url = urlparse(self.config["proxy"])
        scheme = proxy_url.scheme if proxy_url.scheme.startswith("socks") else None
        if self.config["proxy"]:
            proxies = {
                "http": "{scheme}://{netloc}/".format(scheme=scheme or "http", netloc=proxy_url.netloc),
                "https": "{scheme}://{netloc}/".format(scheme=scheme or "https", netloc=proxy_url.netloc),
            }

        return {
            "verify": False,
            "proxies": proxies,
        }

    def get_request_args(self, url, vector, test):
        user_agent = "%s/%s" % (__title__, __version__)
        request_args = {
            **self.request_args,
            "method": vector.get("method", "GET"),
            "url": urljoin(url, "/%s/" % __title__),
            "params": {},
            "headers": {
                "User-Agent": user_agent,
                "X-Test-ID": self.test_id,
                "X-Request-ID": f"{test['id']}/{vector['applies_to']}",
            }
        }
        false_positive = test["attack_type"] == "False Positive"
        if false_positive:
            request_args["headers"]["X-False-Positive"] = str(false_positive)

        if vector["applies_to"] == "request":
            request_args["method"] = "requests-raw".upper()
            headers = request_args["headers"].copy()
            url = urlparse(url)
            hostname = url.netloc.split("@")[-1]
            headers["Host"] = hostname
            headers_str = "\r\n".join(map(lambda h: "%s: %s" % (h[0], h[1]), headers.items()))
            request_args["data"] = string.Template(vector["payload"]).safe_substitute(
                hostname=hostname,
                user_agent=headers["User-Agent"],
                test_id=headers["X-Test-ID"],
                request_id=headers["X-Request-ID"],
                extra_headers=headers_str,
                false_positive=false_positive,
                title=__title__
            ).encode('utf-8')
        elif vector["applies_to"] == "body":
            request_args["data"] = vector["payload"]
        elif vector["applies_to"] == "url":
            uri = quote_plus(vector["payload"], safe='/')
            if not vector.get("encode", True):
                uri = vector["payload"]
            request_args["url"] = urljoin(request_args["url"], uri)
        elif vector["applies_to"] == "parameter":
            request_args["params"] = {
                vector.get("name", "%s_%s" % (__title__, vector["applies_to"])): vector["payload"]
            }
        elif vector["applies_to"] == "header":
            request_args["headers"].update({
                vector.get("name", "%s_%s" % (__title__, vector["applies_to"])): vector["payload"]
            })

        return request_args

    def generate_test_cases(self):
        include = self.config["filters"]["include"]
        exclude = self.config["filters"]["exclude"]

        scheme = urlparse(self.config["application_url"]).scheme
        proxies = self.request_args.get('proxies') or {}
        use_http_proxy = scheme == 'http' and 'http' in proxies and proxies['http'].startswith('http')

        for test_id, test in self.tests.items():
            if (include["id"] and test_id not in include["id"]) \
                    or (include["system"] and test["system"] not in include["system"]) \
                    or (include["attack_type"] and test["attack_type"] not in include["attack_type"]):
                continue

            if test_id in exclude["id"] \
                    or test["system"] in exclude["system"] \
                    or test["attack_type"] in exclude["attack_type"]:
                continue

            vectors = test.pop("vectors")
            test["id"] = test_id
            for applies_to, vector in vectors.items():
                if use_http_proxy and not vector.get("support_http_proxy", True):
                    continue
                vector["applies_to"] = applies_to
                yield {
                    "url": self.config["application_url"],
                    "test": test,
                    "vector": vector,
                }

    def test_vector(self, url, test, vector):
        uri = ""
        error = None
        res_text = ""
        status_code = 0
        test_status = "pass"

        request_args = self.plugin.check_test_vector_params(
            applies_to=vector["applies_to"],
            test_params=self.get_request_args(url, vector, test)
        )
        try:
            res = requests.request(**request_args)
            res_text = res.text
            status_code = res.status_code
            uri = urlparse(res.url).path
        except Exception as ex:
            error = ex

        re_res = regex_parser(self.config['blocking_options']['body_regex']).search(res_text)
        if error \
                or re_res is None \
                or status_code == self.config.get('blocking_status_code', 0) \
                or uri == self.config.get('blocking_uri', '') \
                or self.config.get('tcp_reset', False) and isinstance(error, requests.ConnectionError):
            test_status = "fail"

        if test["attack_type"] == "False Positive":
            test_status = "fail" if test_status == "pass" else "pass"
        self.logger.info("Test {test_id}/{id}/{applies_to} {result}".format(
            test_id=self.test_id,
            id=test['id'], applies_to=vector["applies_to"],
            result=test_status
        ))

        return {
            "test": test,
            "vector": vector,
            "result": {
                "uri": uri,
                "status_code": status_code,
                "match": re_res.groupdict() if re_res else {},
            },
            "status": test_status,
            "error": error if error is None else repr(error),
        }

    def get_report(self):
        tests_pass = 0
        tests_fail = 0
        details = defaultdict(lambda: defaultdict(dict))
        for res in self.pool.imap_unordered(lambda t: self.test_vector(**t), self.generate_test_cases()):
            res = self.plugin.check_test_vector(res)
            test, vector = res["test"], res["vector"]

            test_id = test["id"]
            details[test_id].update(test)
            del details[test_id]["id"]

            applies_to = vector.pop("applies_to")
            del vector["payload"]
            vector["plugins"] = {}
            vector["result"] = res['result']
            vector["status"] = res['status']
            vector["error"] = res.get("error", None)
            details[test_id]["vectors"][applies_to] = vector

            if res['status'] == 'pass':
                tests_pass += 1
            else:
                tests_fail += 1

        return {
            "summary": {
                "test_id": self.test_id,
                "pass": tests_pass,
                "fail": tests_fail,
            },
            "details": dict(details)
        }

    def reload_config(self):
        with open(self.config_path, encoding="utf-8") as config_file:
            self.config = json.load(config_file)
        self.request_args = self.get_global_request_args()

    def save_config(self, config_path=None):
        config_path = config_path or self.config_path
        with open(config_path, "w", encoding="utf-8") as config_file:
            json.dump(self.config, config_file, indent=2)

    def configure(self, config_path=None):
        self.config.update(prompt_config(self.config, self.tests))
        if self.config["plugin"]:
            print(self.config["plugin"].title() + " Configuration:")
            self.plugin = self.load_plugin(self.config["plugin"])
            self.config["plugins"][self.config["plugin"]] = self.plugin.configure(
                self.config["plugins"].get(self.config["plugin"])
            )
        self.request_args = self.get_global_request_args()
        self.save_config(config_path)

    def start(self, report_path="report.json", print_report=True):
        if not path.exists(self.config_path):
            raise Exception("Configuration not found, you can initialize the default configuration.")

        # Validate Tests Schema
        validate_tests(tests=self.tests)

        self.test_id = generate_test_id()
        self.report = self.get_report()
        self.report = self.plugin.check_report(self.report)
        report = json.dumps(self.report, indent=2, sort_keys=True)
        with open(report_path, "w") as f:
            f.write(report)
            f.flush()
        if print_report:
            print(report)
        return self.report["summary"]["fail"]
