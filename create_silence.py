import argparse
import requests
from datetime import datetime, timedelta
import re
import pytz
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import HTTPError, ConnectionError, Timeout, RequestException

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
        "policyDescription": generate_policy_description(customer, extra_properties),
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

    logger.info(f"Creating policy with payload: {policy_payload}")
    logger.info(f"Request headers: {headers}")

    try:
        session = requests_session()
        response = session.post('https://api.opsgenie.com/v2/policies', json=policy_payload, headers=headers)
        response.raise_for_status()
        return response.json()
    except (HTTPError, ConnectionError, Timeout, RequestException) as err:
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
        "description": generate_maintenance_description(customer, extra_properties),
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

    logger.info(f"Creating maintenance with payload: {maintenance_payload}")
    logger.info(f"Request headers: {headers}")

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
    Parse extra properties from a list of key=value strings.

    :param extra_list: List of extra properties in key=value format
    :return: Dictionary of extra properties
    """
    extra_properties = {}
    for extra in extra_list:
        try:
            key, value = extra.split('=', 1)
            if key == 'env':
                key = 'environment'
            extra_properties[key] = value
        except ValueError:
            raise ValueError(f"Invalid extra property format: '{extra}'. Use key=value format.")

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

    for key, value in extra_properties.items():
        if key != 'environment':
            parts.append(f'{key}-{value}')

    return '_'.join(parts)


def generate_policy_description(customer, extra_properties):
    """
    Generate policy description based on customer and extra properties.

    :param customer: Customer name
    :param extra_properties: Dictionary of extra properties
    :return: Policy description
    """
    parts = [f'customer={customer}']
    if 'environment' in extra_properties:
        parts.append(f'environment={extra_properties["environment"]}')

    for key, value in extra_properties.items():
        if key != 'environment':
            parts.append(f'{key}={value}')

    return ','.join(parts)


def generate_maintenance_description(customer, extra_properties):
    """
    Generate maintenance description based on customer and extra properties.

    :param customer: Customer name
    :param extra_properties: Dictionary of extra properties
    :return: Maintenance description
    """
    parts = [f'customer={customer}']
    if 'environment' in extra_properties:
        parts.append(f'environment={extra_properties["environment"]}')

    for key, value in extra_properties.items():
        if key != 'environment':
            parts.append(f'{key}={value}')

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
        }
    ]

    for key, value in extra_properties.items():
        if key == 'env':
            key = 'environment'
        conditions.append({
            "field": "extra-properties",
            "key": key,
            "operation": "equals",
            "expectedValue": value
        })

    return conditions


def main():
    """
    Main function to parse arguments and create the policy and maintenance window.
    """
    # Define the argument parser
    parser = argparse.ArgumentParser(description='Adds a silence tag in Opsgenie alerts based on conditions. It can '
                                                 'be customized for different durations and matchers.')
    parser.add_argument('-k', type=str, required=True, help='Opsgenie API key')
    parser.add_argument('-c', type=str, required=True, help='Customer name')
    parser.add_argument('-e', type=str, help='Environment (optional)', default=None)
    parser.add_argument('-q', action='append', help='Query for extra properties in key=value format', default=[])
    parser.add_argument('-d', type=str, help='Duration of the silence starting from now (e.g. -d 1h).', default='1h')

    # Parse the arguments
    args = parser.parse_args()

    # Parse extra properties
    try:
        extra_properties = parse_extra_properties(args.q)
    except ValueError as e:
        logger.error(f"Extra properties error: {e}")
        return

    # Construct confirmation message
    extra_props_str = ', '.join(f"{key}='{value}'" for key, value in extra_properties.items())
    env_part = f", environment '{args.e}'" if args.e else ''
    confirmation_message = f"Do you really want to create silence for customer '{args.c}'{env_part} with extra properties ({extra_props_str})? [yes/no]: "
    confirmation = input(confirmation_message).strip().lower()

    if args.e:
        extra_properties['environment'] = args.e

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
    policy_response = create_policy(args.c, args.k, extra_properties)
    if 'error' in policy_response:
        logger.error(f"Error creating policy: {policy_response['error']}")
        return

    policy_id = policy_response.get('data', {}).get('id')
    if not policy_id:
        logger.error("Policy creation failed: Policy ID not returned.")
        return

    logger.info(f"Policy created successfully with ID: {policy_id}")

    # Create the maintenance window
    maintenance_response = create_maintenance(policy_id, args.c, args.k, start_time, end_time, extra_properties)
    if 'error' in maintenance_response:
        logger.error(f"Error creating maintenance window: {maintenance_response['error']}")
        return

    logger.info(f"Maintenance window created successfully: {maintenance_response}")


if __name__ == "__main__":
    main()
