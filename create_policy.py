import argparse
import requests


# Define the function to create a policy in Opsgenie
def create_policy(customer, env, alert_name=None, api_key=None):
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


# Define the argument parser
parser = argparse.ArgumentParser(description='Create a policy in Opsgenie')
parser.add_argument('customer', type=str, help='Customer name')
parser.add_argument('env', type=str, help='Environment')
parser.add_argument('--alert-name', type=str, help='Alert name (optional)', default=None)
parser.add_argument('--api-key', type=str, required=True, help='Opsgenie API key')

# Parse the arguments
args = parser.parse_args()

# Call the function with the provided arguments
result = create_policy(args.customer, args.env, args.alert_name, args.api_key)

# Print the result
print(result)

# Note: To run this script, you would use a command like:
# python script.py customer_name environment_name --alert-name alert_name --api-key your_api_key
