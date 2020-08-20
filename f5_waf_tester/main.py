import sys
import logging
from . import __version__, F5WAFTester
from .config import DEFAULT_CONFIG_PATH, DEFAULT_TESTS_PATH
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument("-v", "--version", action="version", version="%(prog)s {ver}".format(ver=__version__))

    parser.add_argument("-i", "--init",
                        help="Initialize Configuration.",
                        action='store_true')

    parser.add_argument("-c", "--config",
                        help="Configuration File Path.",
                        default=DEFAULT_CONFIG_PATH)
    parser.add_argument("-t", "--tests",
                        help="Tests File Path.",
                        default=DEFAULT_TESTS_PATH)
    parser.add_argument("-r", "--report",
                        help="Report File Save Path.",
                        default="report.json")

    sys_args = vars(parser.parse_args(args=args))

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s",
                        datefmt="%d-%m-%y %H:%M:%S")
    logging.getLogger("requests.packages.urllib3.connectionpool").disabled = True

    f5_waf_tester = F5WAFTester(
        configuration_path=sys_args["config"],
        tests_path=sys_args["tests"]
    )
    if sys_args["init"]:
        return f5_waf_tester.configure()

    sys.exit(f5_waf_tester.start(report_path=sys_args["report"]))
