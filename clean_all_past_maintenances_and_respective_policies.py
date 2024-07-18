import argparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tabulate import tabulate
from datetime import datetime
import pytz
import re
import logging
from colorama import init, Fore, Style
from dotenv import load_dotenv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

# Carregando variáveis de ambiente do arquivo .env
load_dotenv()

# Inicializando colorama
init(autoreset=True)

class ColorFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            record.msg = f"{Fore.GREEN}{record.msg}{Style.RESET_ALL}"
        elif record.levelno == logging.ERROR:
            record.msg = f"{Fore.RED}{record.msg}{Style.RESET_ALL}"
        return super().format(record)

# Criando um logger personalizado
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
formatter = ColorFormatter('%(levelname)s: %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Constantes
BASE_URL = 'https://api.opsgenie.com'
MAINTENANCE_URL = f'{BASE_URL}/v1/maintenance'
POLICIES_URL = f'{BASE_URL}/v2/policies'
RETRY_STRATEGY = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
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

def list_maintenance(api_key, maintenance_type='all'):
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

def get_policy_id_from_maintenance(api_key, maintenance_id):
    url = f'{MAINTENANCE_URL}/{maintenance_id}'

    try:
        response = session.get(url, headers=HEADERS(api_key))
        response.raise_for_status()
        maintenance = response.json()
        if not maintenance['data'].get('rules'):
            return None
        policy_id = maintenance['data']['rules'][0]['entity']['id']
        return policy_id
    except requests.RequestException as e:
        logger.error(f"Failed to get maintenance: {e}")
        return None


def filter_maintenances(api_key, maintenances):
    filtered_maintenances = []
    for maintenance in maintenances:
        if 'id' in maintenance:
            policy_id = get_policy_id_from_maintenance(api_key, maintenance['id'])
            if policy_id:
                maintenance['policyId'] = policy_id

        filtered_maintenances.append(maintenance)
    return filtered_maintenances


def delete_maintenance(api_key, maintenance_id):
    """
    Cancel a maintenance schedule in Opsgenie.
    """
    url = f'{MAINTENANCE_URL}/{maintenance_id}'
    try:
        response = session.delete(url, headers=HEADERS(api_key))
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to delete maintenance schedule {maintenance_id}: {e}")
        return None


def delete_alert_policy(api_key, policy_id):
    """
    Delete an alert policy in Opsgenie.
    """
    url = f'{POLICIES_URL}/{policy_id}'
    try:
        response = session.delete(url, headers=HEADERS(api_key))
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to delete alert policy {policy_id}: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description='List maintenance schedules in Opsgenie based on customer, environment, and extra properties.')
    parser.add_argument('-k', type=str, help='Opsgenie API key', default=None)

    args = parser.parse_args()

    api_key = args.k or os.getenv('API_KEY')

    confirmation_message = f"{Fore.RED}Do you really want to clean all past maintenances and their respective policies? [yes/no]: {Style.RESET_ALL}"
    confirmation = input(confirmation_message).strip().lower()

    if confirmation != 'yes' and confirmation != 'y':
        print("Operation cancelled.")
        return

    maintenances = list_maintenance(api_key)
    past_and_cancelled_maintenances = [maintenance for maintenance in maintenances if maintenance['status'] == 'cancelled' or maintenance['status'] == 'past']
    filtered_maintenances = filter_maintenances(api_key, past_and_cancelled_maintenances)

    if filtered_maintenances == []:
        logger.info("No past maintenance to clean.")
        return

    logger.info(f"Found {len(filtered_maintenances)} past maintenances.")

    for maintenance in filtered_maintenances:
        maintenance_id = maintenance['id']
        policy_id = maintenance.get('policyId')

        delete_response = delete_maintenance(api_key, maintenance_id)
        if delete_response:
            logger.info(f"Deleted maintenance: {delete_response}")

        if policy_id:
            delete_response = delete_alert_policy(api_key, policy_id)
            if delete_response:
                logger.info(f"Deleted policy: {delete_response}")


if __name__ == '__main__':
    main()
