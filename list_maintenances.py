import argparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tabulate import tabulate
from datetime import datetime
import pytz
import re
import logging
from colorama import init, Fore, Style, Back
from dotenv import load_dotenv
import os

load_dotenv()

# Initialize colorama
init(autoreset=True)


class ColorFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            record.msg = f"{Fore.GREEN}{record.msg}{Style.RESET_ALL}"
        elif record.levelno == logging.ERROR:
            record.msg = f"{Fore.RED}{record.msg}{Style.RESET_ALL}"
        return super().format(record)


# Create a custom logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create handlers
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

# Create formatters and add them to handlers
formatter = ColorFormatter('%(levelname)s: %(message)s')
console_handler.setFormatter(formatter)

# Add handlers to the logger
logger.addHandler(console_handler)

# Constants
BASE_URL = 'https://api.opsgenie.com'
MAINTENANCE_URL = f'{BASE_URL}/v1/maintenance'
POLICIES_URL = f'{BASE_URL}/v2/policies'
RETRY_STRATEGY = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
)


def requests_session():
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=RETRY_STRATEGY)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


HEADERS = lambda api_key: {
    "Authorization": f"GenieKey {api_key}",
    "Content-Type": "application/json"
}

session = requests_session()


def list_maintenance(api_key, maintenance_type='all'):
    """
    List maintenance schedules in Opsgenie.
    """
    url = f'{MAINTENANCE_URL}?type={maintenance_type}'
    maintenances = []
    try:
        while url:
            response = session.get(url, headers=HEADERS(api_key))
            response.raise_for_status()
            data = response.json()
            maintenances.extend(data.get('data', []))
            url = data.get('paging', {}).get('next')
        return maintenances
    except requests.RequestException as e:
        logger.error(f"Failed to list maintenance schedules: {e}")
        return []


def filter_maintenances(api_key, maintenances, customer=None, environment=None, extra_properties=None):
    """
    Filter maintenance schedules based on customer, environment, and extra properties.
    """

    def check_extra_properties(policy_conditions, extra_properties):
        """
        Helper function to check extra properties conditions.
        """
        if extra_properties is None or extra_properties == {}:
            return True

        for key, (operator, is_not, operator_str, value) in extra_properties.items():
            match_found = False
            for condition in policy_conditions:
                if condition['field'] == 'extra-properties' and condition['key'] == key:
                    if (condition.get('operation') == operator_str and
                        condition.get('expectedValue') == value and
                        condition.get('not', False) == is_not):
                        match_found = True
                        break
            if not match_found:
                return False

        return True

    filtered_maintenances = []

    for maintenance in maintenances:
        if 'id' in maintenance:
            policy_id = get_policy_id_from_maintenance(api_key, maintenance['id'])
            if policy_id is None:
                continue
            policy_data = get_policy_data(api_key, policy_id)
            policy_conditions = policy_data['data']['filter']['conditions']

            all_conditions_met = True

            for condition in policy_conditions:
                if condition['field'] == 'extra-properties':
                    if condition['key'] == 'customer' and not (
                            condition['expectedValue'] == customer or customer is None):
                        all_conditions_met = False
                        break
                    elif condition['key'] == 'environment' and not (
                            condition['expectedValue'] == environment or environment is None):
                        all_conditions_met = False
                        break

            # Check extra properties only if all other conditions are met
            if all_conditions_met and not check_extra_properties(policy_conditions, extra_properties):
                all_conditions_met = False

            if all_conditions_met:
                maintenance['conditions'] = policy_conditions
                filtered_maintenances.append(maintenance)

    return filtered_maintenances


def get_policy_id_from_maintenance(api_key, maintenance_id):
    url = f'{MAINTENANCE_URL}/{maintenance_id}'

    try:
        response = session.get(url, headers=HEADERS(api_key))
        response.raise_for_status()
        maintenance = response.json()
        if maintenance['data']['rules'] == []:
            return None
        policy_id = maintenance['data']['rules'][0]['entity']['id']
        return policy_id
    except requests.RequestException as e:
        raise f"Failed to get maintenance: {e}"


def get_policy_data(api_key, policy_id):
    url = f'{POLICIES_URL}/{policy_id}'

    try:
        response = session.get(url, headers=HEADERS(api_key))
        response.raise_for_status()
        policy = response.json()
        return policy
    except requests.RequestException as e:
        raise f"Failed to get policy: {e}"


def parse_extra_properties(extra_list):
    """
    Parse extra properties from a list of key[operator]=value strings.

    :param extra_list: List of extra properties in key[operator]=value format
    :return: Dictionary of extra properties with operators
    """
    extra_properties = {}
    pattern = re.compile(
        r'^(?P<key>\w+)(?P<operator>!=|~=|\^=|\$=|\*=|!~=|!\^=|!\$=|!\*=|=empty|!empty|=)?(?P<value>.*)$')

    for extra in extra_list:
        match = pattern.match(extra)
        if not match:
            raise ValueError(f"Invalid extra property format: '{extra}'. Use key[operator]value format.")

        key = match.group('key')
        operator = match.group('operator')
        value = match.group('value')

        if key == 'env':
            key = 'environment'

        # Convert operator to the required format
        is_not, operator_str = operator_to_string(operator)
        extra_properties[key] = (operator, is_not, operator_str, value)

    return extra_properties


def operator_to_string(operator):
    """
    Convert operator to string representation.

    :param operator: Operator
    :return: Tuple (is_not, string representation of operator)
    """
    is_not = operator.startswith('!')
    if is_not:
        operator = operator[1:]

    if operator == '=':
        return is_not, 'equals'
    elif operator == '!=':
        return is_not, 'equals'  # Negated in the first part of the tuple
    elif operator == '*=':
        return is_not, 'contains'
    elif operator == '^=':
        return is_not, 'starts-with'
    elif operator == '$=':
        return is_not, 'ends-with'
    elif operator == '~=':
        return is_not, 'matches'
    elif operator == '=empty':
        return is_not, 'is-empty'
    elif operator == 'empty':
        return is_not, 'is-empty'
    else:
        raise ValueError(f"Unknown operator: {operator}")


def parse_description(description):

    regex = re.compile(r',\s*(?![^()]*\))')
    parts = regex.split(description)

    properties = {}
    for part in parts:
        if '=' in part:
            key, value = part.split('=', 1)
            properties[key.strip()] = value.strip()

    return properties


def dict_from_maintenance(maintenance):

    dict_maintenance = {
        'startDate': maintenance['time']['startDate'],
        'endDate': maintenance['time']['endDate'],
    }
    for condition in maintenance['conditions']:
        if condition['not']:
            dict_maintenance[f'{condition["key"]}\nnot\n{condition["operation"]}'] = condition['expectedValue']
            continue
        dict_maintenance[f'{condition["key"]}\n{condition["operation"]}'] = condition['expectedValue']
    return dict_maintenance


def main():
    """
    Main function to parse arguments and list maintenance schedules.
    """
    parser = argparse.ArgumentParser(
        description='List maintenance schedules in Opsgenie based on customer, environment, and extra properties.')
    parser.add_argument('-k', type=str, help='Opsgenie API key', default=None)
    parser.add_argument('-c', type=str, help='Customer name (optional)', default=None)
    parser.add_argument('-e', type=str, help='Environment (optional)', default=None)
    parser.add_argument(
        '-q', action='append', help=(
            'Query for extra properties in key[operator]=value format. '
            'Supported operators: '
            '"key=value" for equality, '
            '"key!=value" for inequality, '
            '"key~=value" for regex match, '
            '"key!~=value" for regex non-match, '
            '"key^=value" for startswith, '
            '"key!^=value" for not startswith, '
            '"key$=value" for endswith, '
            '"key!$=value" for not endswith, '
            '"key*=value" for contains, '
            '"key!*=value" for not contains, '
            '"key=empty" for is empty, '
            '"key!empty" for is not empty. '
        ),
        default=[]
    )

    args = parser.parse_args()

    api_key = args.k
    if not api_key:
        api_key = os.getenv('API_KEY')

    customer = args.c
    env = args.e
    # Parse extra properties
    try:
        extra_properties = parse_extra_properties(args.q)
    except ValueError as e:
        logger.error(f"Extra properties error: {e}")
        return

    # List maintenance schedules
    maintenances = list_maintenance(api_key)

    # Filter active maintenances
    active_maintenances = [maintenance for maintenance in maintenances if maintenance['status'] == 'active']

    filtered_maintenances = filter_maintenances(api_key, active_maintenances, customer, env, extra_properties)

    if filtered_maintenances:
        logger.info(f"Found {len(filtered_maintenances)} active maintenance schedules matching the criteria.")

        # Parse descriptions and prepare table data
        table = []

        for maintenance in filtered_maintenances:
            parsed_description = parse_description(maintenance['description'])
            dict_maintenance = dict_from_maintenance(maintenance)
            if parsed_description['comment']:
                dict_maintenance['comment'] = parsed_description['comment'][1:-1]
            # Strings de data e hora
            start = dict_maintenance['startDate']
            end = dict_maintenance['endDate']

            # Converter as strings em objetos datetime com fuso horário UTC
            start_datetime = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ")
            start_datetime = start_datetime.replace(tzinfo=pytz.UTC)

            end_datetime = datetime.strptime(end, "%Y-%m-%dT%H:%M:%SZ")
            end_datetime = end_datetime.replace(tzinfo=pytz.UTC)

            dict_maintenance['startDate'] = start_datetime.strftime("%d/%m %H:%M") + " UTC"
            dict_maintenance['endDate'] = end_datetime.strftime("%d/%m %H:%M") + " UTC"

            now = datetime.now(pytz.UTC)
            time_difference = end_datetime - now

            # Dias, horas, minutos e segundos da diferença
            days = time_difference.days
            hours, remainder = divmod(time_difference.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)

            formatted_difference = " ".join(
                f"{value}{unit}" for value, unit in zip([days, hours, minutes], ["D", "h", "min"]) if
                value > 0
            )

            dict_maintenance['duration'] = formatted_difference
            table.append(dict_maintenance)

        # Define the column order
        columns = ['startDate', 'endDate', 'duration', 'comment']
        # Add any other columns from the parsed descriptions
        all_columns = set(columns)
        for row in table:
            all_columns.update(row.keys())
        all_columns = sorted(all_columns)  # Ensure the columns are in a consistent order

        # Sort columns to match the desired order
        column_order = [col for col in columns if col in all_columns] + [col for col in all_columns if
                                                                                      col not in columns]

        formatted_table = []
        for row in table:
            formatted_row = [row.get(col, '') for col in column_order]
            formatted_table.append(formatted_row)

        print(tabulate(formatted_table, headers=column_order, tablefmt="fancy_grid", stralign="center"))

    else:
        logger.info("No active maintenance schedules matched the criteria.")


if __name__ == '__main__':
    main()
