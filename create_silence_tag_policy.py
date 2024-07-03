import argparse
import requests
from datetime import datetime, timedelta
import re
import pytz
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_policy(customer, env, alert_name=None, api_key=None, duration='1h'):
    """
    Create a policy in Opsgenie.

    :param customer: Customer name
    :param env: Environment name
    :param alert_name: Optional alert name
    :param api_key: Opsgenie API key
    :param duration: Duration the policy will be enabled (e.g., '1h', '2d', '1w')
    :return: Response from Opsgenie API
    """
    # Define the CEST Amsterdam timezone
    amsterdam_tz = pytz.timezone('Europe/Amsterdam')

    # Get the current time in CEST Amsterdam timezone
    now = datetime.now(amsterdam_tz)

    # Calculate end time
    end_time = now + parse_duration(duration)

    # Create the policy payload
    policy_payload = {
        "name": generate_policy_name(customer, env, alert_name),
        "type": "alert",
        "enabled": True,
        "filter": {
            "type": "match-all-conditions",
            "conditions": generate_conditions(customer, env, alert_name)
        },
        "timeRestriction": {
            "type": "time-of-day",
            "restrictions": [
                {
                    "startDay": now.strftime('%A')[:3].upper(),
                    "endDay": end_time.strftime('%A')[:3].upper(),
                    "startHour": now.hour,
                    "endHour": end_time.hour,
                    "startMin": now.minute,
                    "endMin": end_time.minute
                }
            ]
        },
        "tags": ["silence"]
    }

    # Set the headers for authorization and content type
    headers = {
        "Authorization": f"GenieKey {api_key}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post('https://api.opsgenie.com/v1/policies', json=policy_payload, headers=headers)
        response.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Failed to create policy: {e}")
        return {"error": str(e)}

    return response.json()


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


def generate_policy_name(customer, env, alert_name):
    """
    Generate policy name based on customer, environment, and alert name.

    :param customer: Customer name
    :param env: Environment name
    :param alert_name: Optional alert name
    :return: Policy name
    """
    return f"{customer}_{env}_{alert_name}_Policy" if alert_name else f"{customer}_{env}_Policy"


def generate_conditions(customer, env, alert_name):
    """
    Generate conditions for the policy filter.

    :param customer: Customer name
    :param env: Environment name
    :param alert_name: Optional alert name
    :return: List of conditions
    """
    conditions = [
        {
            "field": "extra-properties",
            "key": "customer",
            "operation": "equals",
            "expectedValue": customer
        },
        {
            "field": "extra-properties",
            "key": "environment",
            "operation": "equals",
            "expectedValue": env
        }
    ]

    if alert_name:
        conditions.append({
            "field": "extra-properties",
            "key": "alertname",
            "operation": "equals",
            "expectedValue": alert_name
        })

    return conditions


def main():
    """
    Main function to parse arguments and create the policy.
    """
    # Define the argument parser
    parser = argparse.ArgumentParser(description='Create a policy in Opsgenie')
    parser.add_argument('customer', type=str, help='Customer name')
    parser.add_argument('env', type=str, help='Environment')
    parser.add_argument('--alert-name', type=str, help='Alert name (optional)', default=None)
    parser.add_argument('--api-key', type=str, required=True, help='Opsgenie API key')
    parser.add_argument('--duration', type=str, help='Duration the policy will be enabled (e.g., 1h, 2d, 1w)',
                        default='1h')

    # Parse the arguments
    args = parser.parse_args()

    # Call the function with the provided arguments
    result = create_policy(args.customer, args.env, args.alert_name, args.api_key, args.duration)

    # Print the result
    logger.info(result)


if __name__ == '__main__':
    main()
