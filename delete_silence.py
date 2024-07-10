import argparse
import requests
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
BASE_URL = 'https://api.opsgenie.com'
ALERT_POLICY_URL = f'{BASE_URL}/v2/policies'
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
    url = f'{ALERT_POLICY_URL}/alert'
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

def get_alert_policy(api_key, policy_id):
    """
    Get an alert policy by ID in Opsgenie.
    """
    url = f'{ALERT_POLICY_URL}/{policy_id}'
    try:
        response = session.get(url, headers=HEADERS(api_key))
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to get alert policy {policy_id}: {e}")
        return None

def disable_alert_policy(api_key, policy_id, dry_run=False):
    """
    Disable an alert policy in Opsgenie.
    """
    url = f'{ALERT_POLICY_URL}/{policy_id}/disable'
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
    url = f'{ALERT_POLICY_URL}/{policy_id}'
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


def filter_entities(entities, customer=None, environment=None, extra_properties=None):
    """
    Filter entities (policies or maintenance schedules) based on customer, environment, and extra properties.
    """
    filtered_entities = []
    for entity in entities:
        if 'description' in entity:
            properties_dict = parse_description(entity['description'])
            if (customer == properties_dict.get('customer') and
                    (environment is None or environment == properties_dict.get('environment')) and
                    (extra_properties is None or all(
                        properties_dict.get(key) == value for key, value in extra_properties.items()))):
                filtered_entities.append(entity)

    return filtered_entities


def filter_policies(policies, customer=None, environment=None, extra_properties=None):
    """
    Filter alert policies based on `policyDescription` field.
    """
    filtered_policies = []
    for policy in policies:
        policy_id = policy.get('id')
        policy_info = get_alert_policy(api_key, policy_id)
        if policy_info and 'policyDescription' in policy_info['data']:
            properties_dict = parse_description(policy_info['data']['policyDescription'])
            if (customer == properties_dict.get('customer') and
                    (environment is None or environment == properties_dict.get('environment')) and
                    (extra_properties is None or all(
                        properties_dict.get(key) == value for key, value in extra_properties.items()))):
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
            logger.info(f"Disabling policy: {policy['name']} (ID: {policy_id})")
            disable_response = disable_alert_policy(api_key, policy_id, dry_run)
            if disable_response:
                logger.info(f"Disabled policy: {disable_response}")
            delete_response = delete_alert_policy(api_key, policy_id, dry_run)
            if delete_response:
                logger.info(f"Deleted policy: {delete_response}")
    else:
        logger.info("No alert policies matched the criteria.")

def process_maintenances(api_key, customer, env, extra_properties, dry_run):
    """
    Process (cancel) maintenance schedules based on provided filters.
    """
    maintenances = list_maintenance(api_key)
    active_maintenances = [maintenance for maintenance in maintenances if maintenance['status'] == 'active']
    filtered_maintenances = filter_entities(active_maintenances, customer, env, extra_properties)

    if filtered_maintenances:
        logger.info(f"Found {len(filtered_maintenances)} maintenance schedules to cancel.")
        for maintenance in filtered_maintenances:
            logger.info(f"Cancelling maintenance: {maintenance['description']} (ID: {maintenance['id']})")
            cancel_response = cancel_maintenance(api_key, maintenance['id'], dry_run)
            if cancel_response:
                logger.info(f"Cancelled maintenance: {cancel_response}")
    else:
        logger.info("No active maintenance schedules matched the criteria.")

def parse_extra_properties(extra_list):
    """
    Parse extra properties from a list of key=value strings.
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

def main():
    """
    Main function to parse arguments and cancel policies and maintenance schedules.
    """
    parser = argparse.ArgumentParser(description='Cancel policies and maintenance schedules in Opsgenie based on customer, environment, and extra properties.')
    parser.add_argument('-k', type=str, required=True, help='Opsgenie API key')
    parser.add_argument('-c', type=str, required=True, help='Customer name')
    parser.add_argument('-e', type=str, help='Environment name')
    parser.add_argument('-q', action='append', help='Extra properties in key=value format', default=[])
    parser.add_argument('--dry-run', action='store_true', help='Perform a dry run without making any changes')

    args = parser.parse_args()

    global api_key
    api_key = args.k
    customer = args.c
    env = args.e
    extra_properties = parse_extra_properties(args.q)
    dry_run = args.dry_run

    # Confirmation prompt
    extra_props_str = ', '.join(f"{key}='{value}'" for key, value in extra_properties.items())
    env_part = f", environment '{env}'" if env else ''
    confirmation = input(f"Are you sure you want to cancel all silences for customer '{customer}'{env_part} with extra properties ({extra_props_str})? (yes/y or no/n): ")
    if confirmation.lower() not in ['yes', 'y']:
        logger.info("Operation cancelled by user.")
        return

    # Process maintenance schedules
    process_maintenances(api_key, customer, env, extra_properties, dry_run)

    logger.info("===============================================================")

    # Process alert policies
    process_alert_policies(api_key, customer, env, extra_properties, dry_run)


if __name__ == '__main__':
    main()
