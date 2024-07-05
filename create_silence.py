import argparse
import requests
from datetime import datetime, timedelta
import re
import pytz
import logging
from requests.exceptions import HTTPError, ConnectionError, Timeout, RequestException

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_policy(customer, env=None, query=None, api_key=None):
    """
    Create a policy in Opsgenie.

    :param customer: Customer name
    :param env: Optional environment name
    :param query: Optional query for alert name or job name
    :param api_key: Opsgenie API key
    :return: Response from Opsgenie API
    """

    # Create the policy payload
    policy_payload = {
        "name": generate_policy_name(customer, env, query),
        "type": "alert",
        "enabled": "false",
        "filter": {
            "type": "match-all-conditions",
            "conditions": generate_conditions(customer, env, query)
        },
        "continue": True,
        "message": "{{message}} - SILENCE",
        "tags": ["silence"]
    }

    # Set the headers for authorization and content type
    headers = {
        "Authorization": f"GenieKey {api_key}",
        "Content-Type": "application/json"
    }

    # Log the payload and headers
    logger.info(f"Request payload: {policy_payload}")
    logger.info(f"Request headers: {headers}")

    try:
        response = requests.post('https://api.opsgenie.com/v2/policies', json=policy_payload, headers=headers)
        response.raise_for_status()
    except HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err}")
        return {"error": str(http_err)}
    except ConnectionError as conn_err:
        logger.error(f"Connection error occurred: {conn_err}")
        return {"error": str(conn_err)}
    except Timeout as timeout_err:
        logger.error(f"Timeout error occurred: {timeout_err}")
        return {"error": str(timeout_err)}
    except RequestException as req_err:
        logger.error(f"Request error occurred: {req_err}")
        return {"error": str(req_err)}
    except Exception as err:
        logger.error(f"Unexpected error occurred: {err}")
        return {"error": str(err)}

    try:
        return response.json()
    except ValueError as json_err:
        logger.error(f"Error parsing JSON response: {json_err}")
        return {"error": str(json_err)}


def create_maintenance(policy_id, customer, env, query, api_key, start_time, end_time):
    """
    Create a maintenance window in Opsgenie.

    :param policy_id: Policy ID
    :param customer: Customer name
    :param env: Optional environment name
    :param query: Optional query for alert name or job name
    :param api_key: Opsgenie API key
    :param start_time: Start time for the maintenance window
    :param end_time: End time for the maintenance window
    :return: Response from Opsgenie API
    """

    # Create the maintenance payload
    maintenance_payload = {
        "description": generate_maintenance_description(customer, env, query),
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

    # Set the headers for authorization and content type
    headers = {
        "Authorization": f"GenieKey {api_key}",
        "Content-Type": "application/json"
    }

    # Log the payload and headers
    logger.info(f"Request payload: {maintenance_payload}")
    logger.info(f"Request headers: {headers}")

    try:
        response = requests.post('https://api.opsgenie.com/v1/maintenance', json=maintenance_payload, headers=headers)
        response.raise_for_status()
    except HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err}")
        return {"error": str(http_err)}
    except ConnectionError as conn_err:
        logger.error(f"Connection error occurred: {conn_err}")
        return {"error": str(conn_err)}
    except Timeout as timeout_err:
        logger.error(f"Timeout error occurred: {timeout_err}")
        return {"error": str(timeout_err)}
    except RequestException as req_err:
        logger.error(f"Request error occurred: {req_err}")
        return {"error": str(req_err)}
    except Exception as err:
        logger.error(f"Unexpected error occurred: {err}")
        return {"error": str(err)}

    try:
        return response.json()
    except ValueError as json_err:
        logger.error(f"Error parsing JSON response: {json_err}")
        return {"error": str(json_err)}


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


def generate_policy_name(customer, env, query):
    """
    Generate policy name based on customer, environment, and alert name.

    :param customer: Customer name
    :param env: Optional environment name
    :param query: Optional query for alert name or job name
    :return: Policy name
    """
    parts = [f'c_{customer}']
    if env:
        parts.append(f'e_{env}')
    if query:
        parts.append(f'a_{query}')
    parts.append('Policy')
    return '_'.join(parts)


def generate_maintenance_description(customer, env, query):
    """
    Generate maintenance description based on customer, environment, and alert name.

    :param customer: Customer name
    :param env: Optional environment name
    :param query: Optional query for alert name or job name
    :return: Maintenance description
    """
    parts = [f'c_{customer}']
    if env:
        parts.append(f'e_{env}')
    if query:
        parts.append(f'a_{query}')
    parts.append('Maintenance')
    return '_'.join(parts)


def generate_conditions(customer, env, query):
    """
    Generate conditions for the policy filter.

    :param customer: Customer name
    :param env: Optional environment name
    :param query: Optional query for alert name or job name
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

    if env:
        conditions.append({
            "field": "extra-properties",
            "key": "environment",
            "operation": "equals",
            "expectedValue": env
        })

    if query:
        conditions.append({
            "field": "extra-properties",
            "key": "alertname",
            "operation": "equals",
            "expectedValue": query
        })
        conditions.append({
            "field": "extra-properties",
            "key": "job",
            "operation": "equals",
            "expectedValue": query
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
    parser.add_argument('-q', type=str, help='Query for alert name or job name (optional)', default=None)
    parser.add_argument('-d', type=str, help='Duration of the silence starting from now (e.g. -d 1h).', default='1h')

    try:
        # Parse the arguments
        args = parser.parse_args()
    except argparse.ArgumentError as arg_err:
        logger.error(f"Argument parsing error: {arg_err}")
        return

    # Call the function with the provided arguments
    response_policy = create_policy(args.c, args.e, args.q, args.k)
    logger.info(f"Policy creation response: {response_policy}")

    if 'error' in response_policy or 'data' not in response_policy or 'id' not in response_policy['data']:
        logger.error("Error creating policy. Exiting.")
        return

    policy_id = response_policy['data']['id']
    logger.info(f"Created policy ID: {policy_id}")

    # Define the UTC timezone
    utc_tz = pytz.utc

    # Get the current time in UTC timezone
    now = datetime.now(utc_tz)

    # Calculate end time
    try:
        end_time = now + parse_duration(args.d)
    except ValueError as dur_err:
        logger.error(f"Duration parsing error: {dur_err}")
        return

    # Create maintenance
    response_maintenance = create_maintenance(policy_id, args.c, args.e, args.q, args.k, now, end_time)
    logger.info(f"Maintenance creation response: {response_maintenance}")

    if 'error' in response_maintenance:
        logger.error("Error creating maintenance.")
    else:
        logger.info("Successfully created maintenance.")


if __name__ == '__main__':
    main()
