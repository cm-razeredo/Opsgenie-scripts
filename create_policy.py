import argparse
import requests
from datetime import datetime, timedelta
import re
import pytz


# Define the function to create a policy in Opsgenie
def create_policy(customer, env, alert_name=None, api_key=None, duration='1h'):
    # Define the CEST Amsterdam timezone
    amsterdam_tz = pytz.timezone('Europe/Amsterdam')

    # Get the current time in CEST Amsterdam timezone
    now = datetime.now(amsterdam_tz)

    # Create the policy payload based on the provided parameters
    policy_payload = {
        "name": f"{customer}_{env}_Policy",
        "type": "alert",
        "enabled": True,
        "filter": {
            "type": "match-all-conditions",
            "conditions": [
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
        },
        "timeRestriction": {
            "type": "time-of-day",
            "restrictions": [
                {
                    "startDay": now.strftime('%A')[:3].upper(),
                    "endDay": (now + parse_duration(duration)).strftime('%A')[:3].upper(),
                    "startHour": now.hour,
                    "endHour": (now + parse_duration(duration)).hour,
                    "startMin": now.minute,
                    "endMin": (now + parse_duration(duration)).minute
                }
            ]
        }
    }

    # Add condition for alert name if provided
    if alert_name:
        policy_payload["filter"]["conditions"].append({
            "field": "extra-properties",
            "key": "alertname",
            "operation": "equals",
            "expectedValue": alert_name
        })

        policy_payload["name"] = f"{customer}_{env}_{alert_name}_Policy"

    # Set the headers for authorization and content type
    headers = {
        "Authorization": f"GenieKey {api_key}",
        "Content-Type": "application/json"
    }

    response = requests.post('https://api.opsgenie.com/v1/policies', json=policy_payload, headers=headers)
    return response.json()


# Function to parse duration string to timedelta
def parse_duration(duration_str):
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


# Define the argument parser
parser = argparse.ArgumentParser(description='Create a policy in Opsgenie')
parser.add_argument('customer', type=str, help='Customer name')
parser.add_argument('env', type=str, help='Environment')
parser.add_argument('--alert-name', type=str, help='Alert name (optional)', default=None)
parser.add_argument('--api-key', type=str, required=True, help='Opsgenie API key')
parser.add_argument('--duration', type=str, help='Duration the policy will be enabled (e.g., 1h, 2d, 1w)', default='1h')

# Parse the arguments
args = parser.parse_args()

# Call the function with the provided arguments
result = create_policy(args.customer, args.env, args.alert_name, args.api_key, args.duration)

# Print the result
print(result)

# Note: To run this script, you would use a command like:
# python script.py customer_name environment_name --alert-name alert_name --api-key your_api_key --duration 1h
# If the duration is not specified, it will default to 1 hour.
