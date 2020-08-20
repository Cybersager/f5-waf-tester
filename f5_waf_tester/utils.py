import re
import os
import binascii
import functools


def generate_test_id(size=16):
    return binascii.hexlify(os.urandom(size // 2)).decode()


def regex_parser(regex_string):
    re_res = re.search(r"^/(?P<pattern>.*)/(?P<flags>[AaIiLlMmSsXx]*)$", regex_string)
    if not re_res:
        raise Exception("Bad Regular Expression String")

    flags = 0
    flag_list = list(map(lambda f: getattr(re, f.upper(), None), re_res.group('flags')))
    if flag_list:
        flags = functools.reduce(lambda f1, f2: f1 | f2, filter(None, flag_list))

    return re.compile(re_res.group('pattern'), flags)
