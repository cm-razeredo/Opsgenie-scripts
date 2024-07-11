import argparse
import requests
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tabulate import tabulate
from datetime import datetime
import pytz
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
BASE_URL = 'https://api.opsgenie.com'
MAINTENANCE_URL = f'{BASE_URL}/v1/maintenance'
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


def filter_maintenances(maintenances, customer=None, environment=None, extra_properties=None):
    """
    Filter maintenance schedules based on customer, environment, and extra properties.
    """
    filtered_maintenances = []

    for mantainance in maintenances:
        if 'description' in mantainance:
            properties_dict = parse_description(mantainance['description'])
            if 'comment' in properties_dict:
                properties_dict['comment'] = properties_dict['comment'][1:-1]
            if ((customer is None or customer == properties_dict.get('customer')) and (environment is None or environment == properties_dict.get('environment')) and (extra_properties is None or all(properties_dict.get(key) == value for key, value in extra_properties.items()))):
                filtered_maintenances.append(mantainance)

    return filtered_maintenances


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


def parse_description(description):

    regex = re.compile(r',\s*(?![^()]*\))')
    parts = regex.split(description)

    properties = {}
    for part in parts:
        if '=' in part:
            key, value = part.split('=', 1)
            properties[key.strip()] = value.strip()

    return properties


def main():
    """
    Main function to parse arguments and list maintenance schedules.
    """
    parser = argparse.ArgumentParser(
        description='List maintenance schedules in Opsgenie based on customer, environment, and extra properties.')
    parser.add_argument('-k', type=str, required=True, help='Opsgenie API key')
    parser.add_argument('-c', type=str, help='Customer name (optional)', default=None)
    parser.add_argument('-e', type=str, help='Environment (optional)', default=None)
    parser.add_argument('-q', action='append', help='Extra properties in key=value format', default=[])

    args = parser.parse_args()

    api_key = args.k
    customer = args.c
    env = args.e
    extra_properties = parse_extra_properties(args.q)

    # List maintenance schedules
    maintenances = list_maintenance(api_key)

    # Filter active maintenances
    active_maintenances = [maintenance for maintenance in maintenances if maintenance['status'] == 'active']
    filtered_maintenances = filter_maintenances(active_maintenances, customer, env, extra_properties)

    if filtered_maintenances:
        logger.info(f"Found {len(filtered_maintenances)} active maintenance schedules matching the criteria.")

        # Parse descriptions and prepare table data
        table = []
        for maintenance in filtered_maintenances:
            parsed_description = parse_description(maintenance['description'])
            if parsed_description['comment']:
                parsed_description['comment'] = parsed_description['comment'][1:-1]
            # Strings de data e hora
            start = maintenance['time']['startDate']
            end = maintenance['time']['endDate']

            # Converter as strings em objetos datetime com fuso horário UTC
            start_datetime = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ")
            start_datetime = start_datetime.replace(tzinfo=pytz.UTC)

            end_datetime = datetime.strptime(end, "%Y-%m-%dT%H:%M:%SZ")
            end_datetime = end_datetime.replace(tzinfo=pytz.UTC)

            parsed_description['startDate'] = start_datetime.strftime("%d/%m/%Y %H:%M:%S") + " (UTC)"
            parsed_description['endDate'] = end_datetime.strftime("%d/%m/%Y %H:%M:%S") + " (UTC)"

            now = datetime.now(pytz.UTC)
            time_difference = end_datetime - now

            # Dias, horas, minutos e segundos da diferença
            days = time_difference.days
            hours, remainder = divmod(time_difference.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)

            formatted_difference = " ".join(
                f"{value}{unit}" for value, unit in zip([days, hours, minutes, seconds], ["D", "h", "min", "s"]) if
                value > 0
            )

            parsed_description['Duration'] = formatted_difference

            table.append(parsed_description)

        # Define the column order
        columns = ['startDate', 'endDate', 'Duration', 'customer', 'environment']
        # Add any other columns from the parsed descriptions
        all_columns = set(columns)
        for row in table:
            all_columns.update(row.keys())
        all_columns = sorted(all_columns)  # Ensure the columns are in a consistent order

        # Sort columns to match the desired order
        column_order = [col for col in columns if col in all_columns] + [col for col in all_columns if
                                                                                      col not in columns]

        formatted_table = []
        for row in table:
            formatted_row = [row.get(col, '') for col in column_order]
            formatted_table.append(formatted_row)

        print(tabulate(formatted_table, headers=column_order, tablefmt="grid"))
    else:
        logger.info("No active maintenance schedules matched the criteria.")


if __name__ == '__main__':
    main()
