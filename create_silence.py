import argparse
import requests
from datetime import datetime, timedelta
import re
import pytz
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import HTTPError, ConnectionError, Timeout, RequestException
import logging
from colorama import init, Fore, Style
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

# Define retry strategy
RETRY_STRATEGY = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "DELETE"]
)


def requests_session():
    """
    Create and configure a requests session with retry strategy.
    """
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=RETRY_STRATEGY)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def create_policy(customer, api_key, extra_properties):
    """
    Create a policy in Opsgenie.

    :param customer: Customer name
    :param api_key: Opsgenie API key
    :param extra_properties: Dictionary of extra properties for conditions
    :return: Response from Opsgenie API
    """
    policy_payload = {
        "name": generate_policy_name(customer, extra_properties),
        "policyDescription": generate_description(customer, extra_properties),
        "type": "alert",
        "enabled": False,
        "filter": {
            "type": "match-all-conditions",
            "conditions": generate_conditions(customer, extra_properties)
        },
        "continue": True,
        "message": "{{message}} - SILENCE",
        "tags": ["silence"]
    }

    headers = {
        "Authorization": f"GenieKey {api_key}",
        "Content-Type": "application/json"
    }

    try:
        session = requests_session()
        response = session.post('https://api.opsgenie.com/v2/policies', json=policy_payload, headers=headers)
        response.raise_for_status()
        return response.json()
    except (HTTPError, ConnectionError, Timeout, RequestException) as err:
        if '409' in str(err):
            return None
        logger.error(f"Request error occurred: {err}")
        return {"error": str(err)}
    except Exception as err:
        logger.error(f"Unexpected error occurred: {err}")
        return {"error": str(err)}


def create_maintenance(policy_id, customer, api_key, start_time, end_time, extra_properties):
    """
    Create a maintenance window in Opsgenie.

    :param policy_id: Policy ID
    :param customer: Customer name
    :param api_key: Opsgenie API key
    :param start_time: Start time for the maintenance window
    :param end_time: End time for the maintenance window
    :param extra_properties: Dictionary of extra properties for description
    :return: Response from Opsgenie API
    """
    maintenance_payload = {
        "description": generate_description(customer, extra_properties),
        "time": {
            "type": "schedule",
            "startDate": start_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "endDate": end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        },
        "rules": [
            {
                "state": "enabled",
                "entity": {
                    "id": policy_id,
                    "type": "policy"
                }
            }
        ]
    }

    headers = {
        "Authorization": f"GenieKey {api_key}",
        "Content-Type": "application/json"
    }

    try:
        session = requests_session()
        response = session.post('https://api.opsgenie.com/v1/maintenance', json=maintenance_payload, headers=headers)
        response.raise_for_status()
        return response.json()
    except (HTTPError, ConnectionError, Timeout, RequestException) as err:
        logger.error(f"Request error occurred: {err}")
        return {"error": str(err)}
    except Exception as err:
        logger.error(f"Unexpected error occurred: {err}")
        return {"error": str(err)}


def parse_duration(duration_str):
    """
    Parse duration string to timedelta.

    :param duration_str: Duration string (e.g., '1h', '2d', '1w')
    :return: timedelta object
    """
    match = re.match(r'(\d+)([hwd])', duration_str)
    if not match:
        raise ValueError("Invalid duration format. Please use 'h' for hours, 'd' for days, or 'w' for weeks.")

    value, unit = match.groups()
    value = int(value)

    if unit == 'h':
        return timedelta(hours=value)
    elif unit == 'd':
        return timedelta(days=value)
    elif unit == 'w':
        return timedelta(weeks=value)


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


def generate_policy_name(customer, extra_properties):
    """
    Generate policy name based on customer and extra properties.

    :param customer: Customer name
    :param extra_properties: Dictionary of extra properties
    :return: Policy name
    """
    parts = [f'customer-{customer}']
    if 'environment' in extra_properties:
        parts.append(f'environment-{extra_properties["environment"]}')

    for key in extra_properties:
        if key == 'environment' or key == 'comment':
            continue
        operator, is_not, operator_str, value = extra_properties[key]
        if operator == '=empty':
            parts.append(f'{key}-{operator_str}')
            continue
        if operator == '!empty':
            parts.append(f'{key}-not-empty')
            continue
        parts.append(f'{key}-{value}')

    return '_'.join(parts)


def generate_description(customer, extra_properties):
    """
    Generate policy description based on customer and extra properties.

    :param customer: Customer name
    :param extra_properties: Dictionary of extra properties
    :return: Policy description
    """
    parts = [f'customer={customer}']
    if 'environment' in extra_properties:
        parts.append(f'environment={extra_properties["environment"]}')
    for key in extra_properties:
        if key == 'environment' or key == 'comment':
            continue
        operator, is_not, operator_str, value = extra_properties[key]
        parts.append(f'{key}{operator}{value}')
    if 'comment' in extra_properties:
        parts.append(f'comment={extra_properties["comment"]}')

    return ','.join(parts)


def generate_conditions(customer, extra_properties):
    """
    Generate conditions for the policy filter.

    :param customer: Customer name
    :param extra_properties: Dictionary of extra properties
    :return: List of conditions
    """
    conditions = [
        {
            "field": "extra-properties",
            "key": "customer",
            "operation": "equals",
            "expectedValue": customer
        },
    ]
    for key in extra_properties:
        if key == 'environment':
            conditions.append({
                "field": "extra-properties",
                "key": key,
                "operation": "equals",
                "expectedValue": extra_properties[key]
            })
            continue
        if key == 'comment':
            continue

        operator, is_not, operation, value = extra_properties[key]
        conditions.append({
            "field": "extra-properties",
            "key": key,
            "not": is_not,
            "operation": operation,
            "expectedValue": value
        })

    return conditions


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


def list_policies(api_key):
    """
    Get all policies in Opsgenie.

    :param api_key: Opsgenie API key
    :return: List of policies
    """
    headers = {
        "Authorization": f"GenieKey {api_key}"
    }

    try:
        session = requests_session()
        response = session.get('https://api.opsgenie.com/v2/policies/alert', headers=headers)
        response.raise_for_status()
        return response.json()
    except (HTTPError, ConnectionError, Timeout, RequestException) as err:
        logger.error(f"Request error occurred: {err}")
        return {"error": str(err)}
    except Exception as err:
        logger.error(f"Unexpected error occurred: {err}")
        return {"error": str(err)}


def check_same_name_policy_exists(api_key, customer, extra_properties):
    """
    Check if a policy exists in Opsgenie based on customer and extra properties.

    :param api_key: Opsgenie API key
    :param customer: Customer name
    :param extra_properties: Dictionary of extra properties
    :return: True if the policy exists, False otherwise
    """
    policy_name = generate_policy_name(customer, extra_properties)
    policies = list_policies(api_key)
    for policy in policies['data']:
        if policy.get('name') == policy_name:
            return policy.get('id')

    return None


def delete_alert_policy(api_key, policy_id):
    """
    Delete an alert policy in Opsgenie.
    """
    url = f'https://api.opsgenie.com/v2/policies/{policy_id}'
    headers = {
        "Authorization": f"GenieKey {api_key}"
    }
    try:
        session = requests_session()
        response = session.delete(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to delete alert policy {policy_id}: {e}")
        return None


def main():
    """
    Main function to parse arguments and create the policy and maintenance window.
    """
    # Define the argument parser
    parser = argparse.ArgumentParser(description='Adds a silence tag in Opsgenie alerts based on conditions. It can '
                                                 'be customized for different durations and matchers.')
    parser.add_argument('-k', type=str, help='Opsgenie API key', default=None)
    parser.add_argument('-c', type=str, required=True, help='Customer name')
    parser.add_argument('-e', type=str, help='Environment (optional)', default=None)
    parser.add_argument('-d', type=str, help='Duration of the silence starting from now (e.g. -d 1h).', default='1h')
    parser.add_argument('-t', type=str, help='Text for the silence comment (optional).', default=None)
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

    # Parse the arguments
    args = parser.parse_args()

    api_key = args.k
    if not api_key:
        api_key = os.getenv('API_KEY')

    # Parse extra properties
    try:
        extra_properties = parse_extra_properties(args.q)
    except ValueError as e:
        logger.error(f"Extra properties error: {e}")
        return

    # Construct confirmation message
    extra_props_str = ', '.join(f"{key}{operator}{value}" for key, (operator, is_not, operator_str, value) in extra_properties.items())
    env_part = f", environment '{args.e}'" if args.e else ''
    confirmation_message = f"{Fore.BLUE}Do you really want to create silence for customer '{args.c}'{env_part} with extra properties ({extra_props_str})? [yes/no]: {Style.RESET_ALL}"
    confirmation = input(confirmation_message).strip().lower()

    if args.e:
        extra_properties['environment'] = args.e

    if args.t:
        extra_properties['comment'] = f"({args.t})"

    if confirmation != 'yes' and confirmation != 'y':
        print("Operation cancelled.")
        return

    # Parse the duration
    try:
        duration = parse_duration(args.d)
    except ValueError as e:
        logger.error(f"Duration parsing error: {e}")
        return

    # Calculate start and end times for the maintenance window
    now = datetime.now(pytz.UTC)
    start_time = now
    end_time = now + duration

    # Create the policy
    policy_response = create_policy(args.c, api_key, extra_properties)
    if policy_response:
        if 'error' in policy_response:
            logger.error(f"Error creating policy: {policy_response['error']}")
            return

    if not policy_response:
        policy_id = check_same_name_policy_exists(api_key, args.c, extra_properties)

        if not policy_id:
            logger.error("Policy creation failed: Policy with the same name not found.")
            return

        delete_response = delete_alert_policy(api_key, policy_id)
        if 'error' in delete_response:
            logger.error(f"Error deleting policy: {delete_response['error']}")
            return

        logger.info(f"Policy deleted successfully: {delete_response}")

        policy_response = create_policy(args.c, api_key, extra_properties)
        if 'error' in policy_response:
            logger.error(f"Error creating policy: {policy_response['error']}")
            return

    policy_id = policy_response.get('data', {}).get('id')

    if not policy_id:
        logger.error("Policy creation failed: Policy ID not returned.")
        return

    logger.info(f"Policy created successfully with ID: {policy_id}")

    # Create the maintenance window
    maintenance_response = create_maintenance(policy_id, args.c, api_key, start_time, end_time, extra_properties)
    if 'error' in maintenance_response:
        logger.error(f"Error creating maintenance window: {maintenance_response['error']}")
        return

    logger.info(f"Maintenance window created successfully with ID: {maintenance_response.get('data', {}).get('id')}")


if __name__ == "__main__":
    main()
