import argparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging
from colorama import init, Fore, Style
from dotenv import load_dotenv
import os
import re

load_dotenv()

api_key = os.getenv('API_KEY')

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
POLICIES_URL = f'{BASE_URL}/v2/policies'
MAINTENANCE_URL = f'{BASE_URL}/v1/maintenance'
RETRY_STRATEGY = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "DELETE"]
)


def requests_session():
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=RETRY_STRATEGY)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


session = requests_session()

HEADERS = lambda api_key: {
    "Authorization": f"GenieKey {api_key}",
    "Content-Type": "application/json"
}


def list_alert_policies(api_key):
    """
    List all alert policies in Opsgenie.
    """
    url = f'{POLICIES_URL}/alert'
    policies = []
    try:
        while url:
            response = session.get(url, headers=HEADERS(api_key))
            response.raise_for_status()
            data = response.json()
            policies.extend(data.get('data', []))
            url = data.get('paging', {}).get('next')
        return policies
    except requests.RequestException as e:
        logger.error(f"Failed to list alert policies: {e}")
        return []


def get_policy_data(api_key, policy_id):
    url = f'{POLICIES_URL}/{policy_id}'

    try:
        response = session.get(url, headers=HEADERS(api_key))
        response.raise_for_status()
        policy = response.json()
        return policy
    except requests.RequestException as e:
        raise f"Failed to get policy: {e}"


def disable_alert_policy(api_key, policy_id, dry_run=False):
    """
    Disable an alert policy in Opsgenie.
    """
    url = f'{POLICIES_URL}/{policy_id}/disable'
    if dry_run:
        logger.info(f"DRY RUN: Would disable alert policy {policy_id}")
        return None
    try:
        response = session.post(url, headers=HEADERS(api_key))
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to disable alert policy {policy_id}: {e}")
        return None


def delete_alert_policy(api_key, policy_id, dry_run=False):
    """
    Delete an alert policy in Opsgenie.
    """
    url = f'{POLICIES_URL}/{policy_id}'
    if dry_run:
        logger.info(f"DRY RUN: Would delete alert policy {policy_id}")
        return None
    try:
        response = session.delete(url, headers=HEADERS(api_key))
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to delete alert policy {policy_id}: {e}")
        return None


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


def cancel_maintenance(api_key, maintenance_id, dry_run=False):
    """
    Cancel a maintenance schedule in Opsgenie.
    """
    url = f'{MAINTENANCE_URL}/{maintenance_id}/cancel'
    if dry_run:
        logger.info(f"DRY RUN: Would cancel maintenance schedule {maintenance_id}")
        return None
    try:
        response = session.post(url, headers=HEADERS(api_key))
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to cancel maintenance schedule {maintenance_id}: {e}")
        return None


def parse_description(description):
    parts = description.split(',')
    return {part.split('=')[0]: part.split('=')[1] for part in parts if '=' in part}


def filter_policies(policies, customer=None, environment=None, extra_properties=None):
    """
    Filter alert policies based on `policyDescription` field.
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
    filtered_policies = []
    for policy in policies:
        policy_id = policy.get('id')
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
            filtered_policies.append(policy)
    return filtered_policies


def process_alert_policies(api_key, customer, env, extra_properties, dry_run):
    """
    Process (disable and delete) alert policies based on provided filters.
    """
    policies = list_alert_policies(api_key)
    filtered_policies = filter_policies(policies, customer, env, extra_properties)

    if filtered_policies:
        logger.info(f"Found {len(filtered_policies)} alert policies to disable and delete.")
        for policy in filtered_policies:
            policy_id = policy['id']
            disable_response = disable_alert_policy(api_key, policy_id, dry_run)
            delete_response = delete_alert_policy(api_key, policy_id, dry_run)
            if delete_response:
                logger.info(f"Deleted policy: {delete_response}")
    else:
        logger.info("No alert policies matched the criteria.")


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
                maintenance['policy'] = policy_id
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


def process_maintenances(api_key, customer, env, extra_properties, dry_run):
    """
    Process (cancel) maintenance schedules based on provided filters.
    """
    # List maintenance schedules
    maintenances = list_maintenance(api_key)

    # Filter active maintenances
    active_maintenances = [maintenance for maintenance in maintenances if maintenance['status'] == 'active']

    filtered_maintenances = filter_maintenances(api_key, active_maintenances, customer, env, extra_properties)

    if filtered_maintenances:
        logger.info(f"Found {len(filtered_maintenances)} maintenance schedules to cancel.")
        for maintenance in filtered_maintenances:
            cancel_response = cancel_maintenance(api_key, maintenance['id'], dry_run)
            if cancel_response:
                logger.info(f"Cancelled maintenance: {cancel_response}")
    else:
        logger.info("No active maintenance schedules matched the criteria.")

    return filtered_maintenances


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


def main():
    """
    Main function to parse arguments and cancel policies and maintenance schedules.
    """
    parser = argparse.ArgumentParser(description='Cancel policies and maintenance schedules in Opsgenie based on customer, environment, and extra properties.')
    parser.add_argument('-k', type=str, help='Opsgenie API key', default=None)
    parser.add_argument('-c', type=str, required=True, help='Customer name')
    parser.add_argument('-e', type=str, help='Environment name')
    parser.add_argument('-q', action='append', help='Extra properties in key=value format', default=[])
    parser.add_argument('--dry-run', action='store_true', help='Perform a dry run without making any changes')

    args = parser.parse_args()

    api_key = args.k
    if not api_key:
        api_key = os.getenv('API_KEY')

    customer = args.c
    env = args.e
    extra_properties = parse_extra_properties(args.q)
    dry_run = args.dry_run

    # Confirmation prompt
    extra_props_str = ', '.join(f"{key}='{value}'" for key, value in extra_properties.items())
    env_part = f", environment '{env}'" if env else ''
    confirmation = input(f"{Fore.BLUE}Are you sure you want to cancel all silences for customer '{customer}'{env_part} with extra properties ({extra_props_str})? (yes/y or no/n): {Style.RESET_ALL}")
    if confirmation.lower() not in ['yes', 'y']:
        logger.info("Operation cancelled by user.")
        return

    # Process maintenance schedules
    filtered_maintenances = process_maintenances(api_key, customer, env, extra_properties, dry_run)

    # Process alert policies
    process_alert_policies(api_key, customer, env, extra_properties, dry_run)


if __name__ == '__main__':
    main()
