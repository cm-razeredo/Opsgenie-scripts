import argparse
import requests
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def list_enabled_policies(api_key):
    """
    List all enabled alert policies in Opsgenie.

    :param api_key: Opsgenie API key
    :return: List of enabled policies
    """
    # Set the headers for authorization and content type
    headers = {
        "Authorization": f"GenieKey {api_key}",
        "Content-Type": "application/json"
    }

    try:
        # Send a GET request to list policies
        response = requests.get('https://api.opsgenie.com/v1/policies', headers=headers)
        response.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Failed to list policies: {e}")
        return {"error": str(e)}

    # Filter enabled policies
    enabled_policies = [policy for policy in response.json().get('data', []) if policy.get('enabled')]

    return enabled_policies


def main():
    """
    Main function to parse arguments and list enabled policies.
    """
    # Define the argument parser
    parser = argparse.ArgumentParser(description='List all enabled alert policies in Opsgenie')
    parser.add_argument('--api-key', type=str, required=True, help='Opsgenie API key')

    # Parse the arguments
    args = parser.parse_args()

    # Call the function with the provided arguments
    enabled_policies = list_enabled_policies(args.api_key)

    # Print the result
    for policy in enabled_policies:
        logger.info(f"Policy Name: {policy.get('name')}, Enabled: {policy.get('enabled')}")


if __name__ == '__main__':
    main()
