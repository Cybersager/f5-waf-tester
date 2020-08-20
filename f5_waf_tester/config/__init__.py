import json
import inquirer
import jsonschema
from os import path
from ..plugins import get_plugins
from requests.utils import urlparse
from inquirer.themes import term, Theme

__folder__ = path.abspath(path.dirname(__file__))

DEFAULT_CONFIG_PATH = path.join(__folder__, "config.json")
DEFAULT_TESTS_PATH = path.join(__folder__, "tests.json")

CONFIG_TEMPLATE = {
    "threads": 25,
    "application_url": "",
    "proxy": "",
    "blocking_options": {
        "body_regex": "/Your support ID is: (?P<support_id>\\d+)/is",
        "status_code": 0,
        "redirect_uri": "",
        "tcp_reset": False
    },
    "filters": {
        "include": {
            "id": [],
            "system": [],
            "attack_type": []
        },
        "exclude": {
            "id": [],
            "system": [],
            "attack_type": []
        }
    },
    "plugin": "",
    "plugins": {
    }
}


class Style(Theme):
    def __init__(self):
        super(Style, self).__init__()
        self.Question.mark_color = term.red + term.bold
        self.Question.brackets_color = term.normal
        self.Question.default_color = term.normal
        self.Editor.opening_prompt_color = term.bright_black
        self.Checkbox.selection_color = term.color_rgb(0x7f, 0x00, 0x00) + term.bold
        self.Checkbox.selection_icon = '>'
        self.Checkbox.selected_icon = 'X'
        self.Checkbox.selected_color = term.red
        self.Checkbox.unselected_color = term.normal
        self.Checkbox.unselected_icon = 'o'
        self.List.selection_color = term.red
        self.List.selection_cursor = '>'
        self.List.unselected_color = term.normal


def validate_tests(tests):
    tests_schema_path = path.abspath(path.join(__folder__, "tests.schema.json"))
    with open(tests_schema_path, encoding='utf-8') as tests_schema_file:
        tests_schema = json.load(tests_schema_file)

    return jsonschema.validate(tests, tests_schema, cls=jsonschema.Draft7Validator)


def get_choices(tests):
    systems = set()
    test_ids = set()
    attack_types = set()
    for test_id, test in tests.items():
        systems.add(test['system'])
        attack_types.add(test['attack_type'])
        test_ids.add((
            "[%s] %s" % (test_id, test['name']),
            test_id
        ))
    return sorted(systems), sorted(test_ids), sorted(attack_types)


def validate_url(_, value):
    if not value:
        return True
    url = urlparse(value)
    return url.scheme and url.netloc


def prompt_config(config, tests):
    systems, test_ids, attack_types = get_choices(tests)
    plugins = get_plugins()
    print("Configuration: ")
    answers = inquirer.prompt([
        inquirer.Text(
            name='application_url',
            message='Application URL',
            default=config['application_url'],
            validate=validate_url,
        ),
        inquirer.Text(
            name='proxy',
            message='Proxy URL',
            default=config['proxy'],
            validate=validate_url,
        ),
        inquirer.Text(
            name='threads',
            message='Number Of Threads',
            default=str(config['threads']),
            validate=lambda _, value: value.isdecimal()
        ),
    ], theme=Style())
    answers['threads'] = int(answers['threads'])

    print()
    print("Blocking Configuration: ")
    answers['blocking_options'] = inquirer.prompt([
        inquirer.Text(
            name='body_regex',
            message='Blocking Page Regex',
            default=config['blocking_options']['body_regex']
        ),
        inquirer.Text(
            name='status_code',
            message='Blocking Status Code',
            default=str(config['blocking_options']['status_code']),
            validate=lambda _, value: value.isdecimal()
        ),
        inquirer.Text(
            name='redirect_uri',
            message='Blocking Page URI',
            default=config['blocking_options']['redirect_uri']
        ),
        inquirer.Confirm(
            name='tcp_reset',
            message='Blocking TCP Reset',
            default=config['blocking_options']['tcp_reset']
        ),
    ], theme=Style())
    answers['blocking_options']['status_code'] = int(answers['blocking_options']['status_code'])

    print()
    print("Test Filter Configuration: ")
    answers['filters'] = {
        "include": inquirer.prompt([
            inquirer.Checkbox(
                name='id',
                message='Include IDs',
                choices=test_ids,
                default=config['filters']['include']['id']
            ),
            inquirer.Checkbox(
                name='system',
                message='Include Systems',
                choices=systems,
                default=config['filters']['include']['system']
            ),
            inquirer.Checkbox(
                name='attack_type',
                message='Include Attack Types',
                choices=attack_types,
                default=config['filters']['include']['attack_type']
            ),
        ], theme=Style()),
        "exclude": inquirer.prompt([
            inquirer.Checkbox(
                name='id',
                message='Exclude IDs',
                choices=test_ids,
                default=config['filters']['exclude']['id']
            ),
            inquirer.Checkbox(
                name='system',
                message='Exclude Systems',
                choices=systems,
                default=config['filters']['exclude']['system']
            ),
            inquirer.Checkbox(
                name='attack_type',
                message='Exclude Attack Types',
                choices=attack_types,
                default=config['filters']['exclude']['attack_type']
            ),
        ], theme=Style()),
    }

    if plugins:
        print()
        print("Plugin Configuration: ")
        answers.update(
            inquirer.prompt([
                inquirer.List(
                    name='plugin',
                    message='Plugin',
                    choices=[''] + list(plugins.keys()),
                    default=config['plugin']
                )
            ], theme=Style())
        )

    return answers
