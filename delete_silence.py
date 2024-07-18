import argparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tabulate import tabulate
from datetime import datetime
import pytz
import re
import logging
from colorama import init, Fore, Style
from dotenv import load_dotenv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

# Carregando variáveis de ambiente do arquivo .env
load_dotenv()

# Inicializando colorama
init(autoreset=True)

class ColorFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            record.msg = f"{Fore.GREEN}{record.msg}{Style.RESET_ALL}"
        elif record.levelno == logging.ERROR:
            record.msg = f"{Fore.RED}{record.msg}{Style.RESET_ALL}"
        return super().format(record)

# Criando um logger personalizado
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
formatter = ColorFormatter('%(levelname)s: %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Constantes
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

def list_maintenance(api_key, maintenance_type='non-expired'):
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

def get_policy_id_from_maintenance(api_key, maintenance_id):
    url = f'{MAINTENANCE_URL}/{maintenance_id}'

    try:
        response = session.get(url, headers=HEADERS(api_key))
        response.raise_for_status()
        maintenance = response.json()
        if not maintenance['data'].get('rules'):
            return None
        policy_id = maintenance['data']['rules'][0]['entity']['id']
        return policy_id
    except requests.RequestException as e:
        logger.error(f"Failed to get maintenance: {e}")
        return None

@lru_cache(maxsize=128)
def get_policy_data(api_key, policy_id):
    url = f'{POLICIES_URL}/{policy_id}'

    try:
        response = session.get(url, headers=HEADERS(api_key))
        response.raise_for_status()
        policy = response.json()
        return policy
    except requests.RequestException as e:
        logger.error(f"Failed to get policy: {e}")
        return None

def filter_maintenances(api_key, maintenances, customer=None, environment=None, extra_properties=None):
    def check_extra_properties(policy_conditions, extra_properties):
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

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {}
        for maintenance in maintenances:
            if 'id' in maintenance:
                policy_id = get_policy_id_from_maintenance(api_key, maintenance['id'])
                if policy_id:
                    futures[executor.submit(get_policy_data, api_key, policy_id)] = maintenance

        for future in as_completed(futures):
            maintenance = futures[future]
            try:
                policy_data = future.result()
                if not policy_data:
                    continue
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

                if all_conditions_met and not check_extra_properties(policy_conditions, extra_properties):
                    all_conditions_met = False

                if all_conditions_met:
                    maintenance['policyId'] = policy_id
                    maintenance['conditions'] = policy_conditions
                    filtered_maintenances.append(maintenance)

            except Exception as e:
                logger.error(f"Error processing maintenance {maintenance['id']}: {e}")

    return filtered_maintenances

def parse_extra_properties(extra_list):
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

        is_not, operator_str = operator_to_string(operator)
        extra_properties[key] = (operator, is_not, operator_str, value)

    return extra_properties

def operator_to_string(operator):
    is_not = operator.startswith('!')
    if is_not:
        operator = operator[1:]

    if operator == '=':
        return is_not, 'equals'
    elif operator == '!=':
        return is_not, 'equals'
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

def cancel_maintenance(api_key, maintenance_id):
    """
    Cancel a maintenance schedule in Opsgenie.
    """
    url = f'{MAINTENANCE_URL}/{maintenance_id}/cancel'
    try:
        response = session.post(url, headers=HEADERS(api_key))
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to cancel maintenance schedule {maintenance_id}: {e}")
        return None

def disable_alert_policy(api_key, policy_id):
    """
    Disable an alert policy in Opsgenie.
    """
    url = f'{POLICIES_URL}/{policy_id}/disable'
    try:
        response = session.post(url, headers=HEADERS(api_key))
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to disable alert policy {policy_id}: {e}")
        return None


def delete_alert_policy(api_key, policy_id):
    """
    Delete an alert policy in Opsgenie.
    """
    url = f'{POLICIES_URL}/{policy_id}'
    try:
        response = session.delete(url, headers=HEADERS(api_key))
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to delete alert policy {policy_id}: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description='List maintenance schedules in Opsgenie based on customer, environment, and extra properties.')
    parser.add_argument('-k', type=str, help='Opsgenie API key', default=None)
    parser.add_argument('-c', type=str, required=True, help='Customer name (optional)', default=None)
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

    api_key = args.k or os.getenv('API_KEY')
    customer = args.c
    env = args.e

    try:
        extra_properties = parse_extra_properties(args.q)
    except ValueError as e:
        logger.error(f"Extra properties error: {e}")
        return

        # Construct confirmation message
    extra_props_str = ', '.join(f"{key}{operator}{value}" for key, (operator, is_not, operator_str, value) in extra_properties.items())
    env_part = f", environment '{args.e}'" if args.e else ''
    confirmation_message = f"{Fore.BLUE}Do you really want to delete silence for customer '{args.c}'{env_part} with extra properties ({extra_props_str})? [yes/no]: {Style.RESET_ALL}"
    confirmation = input(confirmation_message).strip().lower()

    if confirmation != 'yes' and confirmation != 'y':
        print("Operation cancelled.")
        return

    maintenances = list_maintenance(api_key)
    active_maintenances = [maintenance for maintenance in maintenances if maintenance['status'] == 'active']
    filtered_maintenances = filter_maintenances(api_key, active_maintenances, customer, env, extra_properties)

    if filtered_maintenances == []:
        logger.info("No active maintenance schedules found.")
        return

    logger.info(f"Found {len(filtered_maintenances)} active maintenance schedules matching the criteria.")

    for maintenance in filtered_maintenances:
        maintenance_id = maintenance['id']
        policy_id = maintenance['policyId']

        cancel_response = cancel_maintenance(api_key, maintenance_id)
        if cancel_response:
            logger.info(f"Cancelled maintenance: {cancel_response}")

        disable_response = disable_alert_policy(api_key, policy_id)
        if disable_response:
            logger.info(f"Disabled policy: {disable_response}")

        delete_response = delete_alert_policy(api_key, policy_id)
        if delete_response:
            logger.info(f"Deleted policy: {delete_response}")


if __name__ == '__main__':
    main()
