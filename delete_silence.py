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
ALERT_POLICY_URL = f'{BASE_URL}/v2/policies/alert'
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


HEADERS = lambda api_key: {
    "Authorization": f"GenieKey {api_key}",
    "Content-Type": "application/json"
}

session = requests_session()


def list_alert_policies(api_key, team_id=None):
    """
    List all alert policies in Opsgenie.
    """
    url = ALERT_POLICY_URL
    if team_id:
        url += f'?teamId={team_id}'

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


def disable_alert_policy(api_key, policy_id, dry_run=False):
    """
    Disable an alert policy in Opsgenie.
    """
    url = f'{BASE_URL}/v2/policies/{policy_id}/disable'

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
    url = f'{BASE_URL}/v2/policies/{policy_id}'

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


def filter_entities(entities, customer=None, env=None, query=None):
    """
    Filter entities (policies or maintenance schedules) based on customer, environment, and query.
    """
    if customer:
        entities = [entity for entity in entities if f'c_{customer}' in entity.get('description', '') or f'c_{customer}' in entity.get('name', '')]
    if env:
        entities = [entity for entity in entities if f'e_{env}' in entity.get('description', '') or f'e_{env}' in entity.get('name', '')]
    if query:
        entities = [entity for entity in entities if f'q_{query}' in entity.get('description', '') or f'q_{query}' in entity.get('name', '')]
    return entities


def process_maintenances(api_key, customer, env, query, dry_run):
    """
    Process (cancel and delete) maintenance schedules based on provided filters.
    """
    maintenances = list_maintenance(api_key)
    active_maintenances = [maintenance for maintenance in maintenances if maintenance['status'] == 'active']
    filtered_maintenances = filter_entities(active_maintenances, customer, env, query)

    if filtered_maintenances:
        logger.info(f"Found {len(filtered_maintenances)} maintenance schedules to cancel.")
        for maintenance in filtered_maintenances:
            logger.info(f"Cancelling maintenance: {maintenance['description']} (ID: {maintenance['id']})")
            cancel_response = cancel_maintenance(api_key, maintenance['id'], dry_run)
            if cancel_response:
                logger.info(f"Cancelled maintenance: {cancel_response}")
    else:
        logger.info("No active maintenance schedules matched the criteria.")


def process_alert_policies(api_key, customer, env, query, team_id, dry_run):
    """
    Process (disable and delete) alert policies based on provided filters.
    """
    policies = list_alert_policies(api_key, team_id)
    filtered_policies = filter_entities(policies, customer, env, query)

    if filtered_policies:
        logger.info(f"Found {len(filtered_policies)} alert policies to disable and delete.")
        for policy in filtered_policies:
            logger.info(f"Disabling policy: {policy['name']} (ID: {policy['id']})")
            disable_response = disable_alert_policy(api_key, policy['id'], dry_run)
            if disable_response:
                logger.info(f"Disabled policy: {disable_response}")
            delete_response = delete_alert_policy(api_key, policy['id'], dry_run)
            if delete_response:
                logger.info(f"Deleted policy: {delete_response}")
    else:
        logger.info("No alert policies matched the criteria.")


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
    parser.add_argument('--dry-run', action='store_true', help='Perform a dry run without making any changes')

    args = parser.parse_args()

    api_key = args.k
    customer = args.c
    env = args.e
    query = args.q
    team_id = args.t
    dry_run = args.dry_run

    # Confirmation prompt
    confirmation = input(f"Are you sure you want to delete all silences for customer '{customer}', environment '{env}', and query '{query}'? (yes/y or no/n): ")
    if confirmation.lower() not in ['yes', 'y']:
        logger.info("Operation cancelled by user.")
        return

    # Process maintenance schedules
    process_maintenances(api_key, customer, env, query, dry_run)

    logger.info("===============================================================")

    # Process alert policies
    process_alert_policies(api_key, customer, env, query, team_id, dry_run)


if __name__ == '__main__':
    main()
