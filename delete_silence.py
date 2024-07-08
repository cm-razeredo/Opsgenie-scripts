import argparse
import requests
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def list_alert_policies(api_key, team_id=None):
    """
    List all alert policies in Opsgenie.
    """
    url = 'https://api.opsgenie.com/v2/policies/alert'
    if team_id:
        url += f'?teamId={team_id}'

    headers = {
        "Authorization": f"GenieKey {api_key}",
        "Content-Type": "application/json"
    }

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json().get('data', [])


def disable_alert_policy(api_key, policy_id):
    """
    Disable an alert policy in Opsgenie.
    """
    url = f'https://api.opsgenie.com/v2/policies/{policy_id}/disable'
    headers = {
        "Authorization": f"GenieKey {api_key}"
    }
    print(url)
    response = requests.post(url, headers=headers)
    response.raise_for_status()
    return response.json()


def delete_alert_policy(api_key, policy_id):
    """
    Delete an alert policy in Opsgenie.
    """
    url = f'https://api.opsgenie.com/v2/policies/{policy_id}'
    headers = {
        "Authorization": f"GenieKey {api_key}"
    }

    response = requests.delete(url, headers=headers)
    response.raise_for_status()
    return response.json()


def list_maintenance(api_key, maintenance_type='all'):
    """
    List maintenance schedules in Opsgenie.
    """
    url = f'https://api.opsgenie.com/v1/maintenance?type={maintenance_type}'
    headers = {
        "Authorization": f"GenieKey {api_key}",
        "Content-Type": "application/json"
    }

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json().get('data', [])


def cancel_maintenance(api_key, maintenance_id):
    """
    Cancel a maintenance schedule in Opsgenie.
    """
    url = f'https://api.opsgenie.com/v1/maintenance/{maintenance_id}/cancel'
    headers = {
        "Authorization": f"GenieKey {api_key}"
    }

    response = requests.post(url, headers=headers)
    response.raise_for_status()
    return response.json()


def delete_maintenance(api_key, maintenance_id):
    """
    Delete a maintenance schedule in Opsgenie.
    """
    url = f'https://api.opsgenie.com/v1/maintenance/{maintenance_id}'
    headers = {
        "Authorization": f"GenieKey {api_key}"
    }

    response = requests.delete(url, headers=headers)
    response.raise_for_status()
    return response.json()


def main():
    """
    Main function to parse arguments and delete policies and maintenance schedules.
    """
    parser = argparse.ArgumentParser(description='Delete policies and maintenance schedules in Opsgenie based on customer, environment, and query.')
    parser.add_argument('-k', type=str, required=True, help='Opsgenie API key')
    parser.add_argument('-c', type=str, required=True, help='Customer name')
    parser.add_argument('-e', type=str, help='Environment (optional)', default=None)
    parser.add_argument('-q', type=str, help='Query for alert name or job name (optional)', default=None)
    parser.add_argument('-t', type=str, help='Team ID (optional)', default=None)

    args = parser.parse_args()

    api_key = args.k
    customer = args.c
    env = args.e
    query = args.q
    team_id = args.t

    # Delete matching maintenance schedules
    maintenances = list_maintenance(api_key)
    maintenances = [maintenance for maintenance in maintenances if maintenance['status'] == 'active']
    if customer:
        maintenances = [maintenance for maintenance in maintenances if f'c_{customer}' in maintenance['description']]
    if env:
        maintenances = [maintenance for maintenance in maintenances if f'e_{env}' in maintenance['description']]
    if query:
        maintenances = [maintenance for maintenance in maintenances if f'q_{query}' in maintenance['description']]
    if maintenances:
        print(maintenances)
        for maintenance in maintenances:
            logger.info(f"Cancelling maintenance: {maintenance['description']} (ID: {maintenance['id']})")
            maintenance_cancel_response = cancel_maintenance(api_key, maintenance['id'])
            logger.info(maintenance_cancel_response)

    print("===============================================================")
    # Delete matching alert policies
    policies = list_alert_policies(api_key, team_id)
    if customer:
        policies = [policy for policy in policies if f'c_{customer}_' in policy['name']]
    if env:
        policies = [policy for policy in policies if f'e_{env}_' in policy['name']]
    if query:
        policies = [policy for policy in policies if f'q_{query}_' in policy['name']]
    if policies:
        print(policies)
        for policy in policies:
            logger.info(f"Disabling policy: {policy['name']} (ID: {policy['id']})")
            policy_disable_response = disable_alert_policy(api_key, policy['id'])
            logger.info(policy_disable_response)
            logger.info(f"Deleting policy: {policy['name']} (ID: {policy['id']})")
            policy_delete_response = delete_alert_policy(api_key, policy['id'])
            logger.info(policy_delete_response)

    maintenances = list_maintenance(api_key)
    if customer:
        maintenances = [maintenance for maintenance in maintenances if f'c_{customer}_' in maintenance['description']]
    if env:
        maintenances = [maintenance for maintenance in maintenances if f'e_{env}_' in maintenance['description']]
    if query:
        maintenances = [maintenance for maintenance in maintenances if f'q_{query}_' in maintenance['description']]
    if maintenances:
        print(maintenances)
        for maintenance in maintenances:
            logger.info(f"Deleting maintenance: {maintenance['description']} (ID: {maintenance['id']})")
            maintenance_delete_response = delete_maintenance(api_key, maintenance['id'])
            logger.info(maintenance_delete_response)


if __name__ == '__main__':
    main()
