#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import ipaddress
import re
import sys
import pandas as pd
import time
import random
import argparse
import json
import os
import requests
import zipfile
from io import BytesIO
from tqdm import tqdm
import threading
import multiprocessing


def save_result(name, dataframe, index=True):

    # .to_excel('{}.xlsx'.format(name), float_format="%.0f")
    # if 'date_time' in dataframe.columns:
    #    dataframe['date_time'] = dataframe.pd.strftime('%H:%M:%S')

    dataframe.to_csv(path_or_buf='{}.csv'.format(name),
                     sep=';',
                     na_rep='',
                     float_format="%.0f",
                     columns=None,
                     header=True,
                     index=index,
                     index_label=None,
                     mode='w',
                     encoding=None,
                     compression=None,
                     quoting=None,
                     quotechar='"',
                     lineterminator='\n',
                     chunksize=None,
                     doublequote=True,
                     escapechar=None,
                     decimal=',',
                     date_format="%Y-%m-%dT%H:%M:%S%z")


def generate_random_ips(count):
    ip_list = []
    for _ in range(count):
        ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
        ip_list.append(ipaddress.ip_address(ip))

    return ip_list


def load_dataframe_from_pickle(pickle_file):
    """
    Load a Pandas DataFrame from a pickle file.

    Args:
    - pickle_file (str): Path to the pickle file.

    Return:
    - pandas.DataFrame: The loaded DataFrame.
    """
    try:
        # Load the DataFrame from the pickle file
        df = pd.read_pickle(pickle_file)
        print(f"DataFrame loaded successfully from {pickle_file}")

    except Exception as e:
        print(f"Error loading DataFrame from {pickle_file}: {e}")
        sys.exit(0)
    return df


def progress_bar(progress, total, bar_length=20):
    percent = 100 * (progress / float(total))
    filled_length = int(bar_length * progress // total)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    print(f'\r|{bar}| {percent:.2f}%', end='\r')
    if progress == total:
        print()


def get_ip_addresses():
    item_to_search = []
    user_input = input("Enter IP addresses, networks or network ranges, "
                       "separated by new lines (press Enter twice to finish):")

    for line in user_input.split('\n'):
        line = line.strip().replace(",", "").replace("\"", "")
        if line:  # Skip empty lines
            try:
                # Try parsing the input as an IP address
                ip_obj = ipaddress.ip_address(line)
                item_to_search.append(ip_obj)
                print(f"Added IP address: {ip_obj}")

            except ValueError:
                try:
                    # Try parsing the input as a network or network range
                    ip_network = ipaddress.ip_network(line)
                    item_to_search.append(ip_network)
                    print(f"Added network/range: {ip_network}")

                except ValueError:
                    print(f"Invalid input: {line}")
                    sys.exit(0)

    return item_to_search


def count_files_with_name(zip_data, file_name):
    count = 0
    with zipfile.ZipFile(zip_data) as zip_file:
        for info in zip_file.infolist():
            if info.filename.endswith(file_name):
                count += 1
    return count


def download_data_source(url):

    print(f"Try to fetch source: {url}")

    response = requests.get(url, stream=True)

    if response.status_code == 200:
        total_size = int(response.headers.get('content-length', 0))
        block_size = 1024 * 1024  # 1 Megabyte
        progress_bar = tqdm(total=total_size, unit='iB', unit_scale=True)

        file_data = bytearray()

        for chunk in response.iter_content(chunk_size=block_size):
            if chunk:
                file_data.extend(chunk)
                progress_bar.update(len(chunk))

        progress_bar.close()
        print("File downloaded successfully.")

        return file_data

        # Do something with file_data (e.g., store it in a database, process
        # it, etc.)
    else:
        print(f"Error downloading file. Status code: {response.status_code}")


def create_directory(path):
    try:
        os.makedirs(path, exist_ok=True)
        print(f"Directory '{path}' created successfully.")
    except OSError as e:
        print(f"Error creating directory '{path}': {e.strerror}")
        sys.exit(1)


def generate_list_asn_range(zip_data):

    loop = 0
    list_ipv4 = []
    list_ipv6 = []

    file_name = 'aggregated.json'
    num_files = count_files_with_name(zip_data, file_name)

    print(f"Number of files with name '{file_name}' in archive: {num_files}")

    with zipfile.ZipFile(zip_data) as zip_file:
        # Loop through directories and files
        for path in zip_file.namelist():
            # Check if the path is a file named "aggregated.json"
            if path.endswith('/aggregated.json'):
                # Read the contents of the file
                with zip_file.open(path) as f:
                    loop += 1

                    progress_bar(loop, num_files)

                    data = json.load(f)

                    asn_number = data['asn']
                    try:
                        asn_handle = data['handle']
                    except KeyError:
                        asn_handle = None
                    try:
                        asn_description = data['description']
                    except KeyError:
                        asn_description = None
                    ipv4_subnets = data['subnets']['ipv4']
                    ipv6_subnets = data['subnets']['ipv6']

                    if len(ipv4_subnets) > 0:
                        for subnet in ipv4_subnets:
                            ipv4_network = ipaddress.ip_network(subnet)

                            list_ipv4.append([asn_number, asn_handle,
                                              asn_description, int(
                                                  ipv4_network[0]),
                                              int(ipv4_network[-1]), subnet])

                    if len(ipv6_subnets) > 0:
                        for subnet in ipv6_subnets:
                            ipv6_network = ipaddress.ip_network(subnet)

                            list_ipv6.append([asn_number, asn_handle,
                                              asn_description, int(
                                                  ipv6_network[0]),
                                              int(ipv6_network[-1]), subnet])

    return list_ipv4, list_ipv6


def count_folders(directory):
    """
    Count the number of folders in a given directory.

    Args:
        directory (str): Path to the directory to count folders in.

    Returns:
        int: Number of folders in the directory.
    """
    folder_count = 0

    # Iterate over the entries in the directory
    for entry in os.listdir(directory):
        # Construct the full path of the entry
        entry_path = os.path.join(directory, entry)

        # Check if the entry is a directory
        if os.path.isdir(entry_path):
            folder_count += 1

    return folder_count

def generate_list_asn_from_folder(directory_path, num_folder_start=None,
                                  num_folder_stop=None):

    main_dir = directory_path
    num_folder_start = int(num_folder_start)
    num_folder_stop = int(num_folder_stop)
    loop = 0
    list_ipv4 = []
    list_ipv6 = []

    for root, dirs, files in os.walk(main_dir):

        pattern = r'\d+$'  # Match one or more digits at the end of the string
        match = re.search(pattern, root)
        if match:
            num_folder = int(match.group())
        else:
            num_folder = None

        if num_folder >= num_folder_start and num_folder > num_folder_stop:

            for file in files:

                if file == 'aggregated.json':
                    loop += 1

                    # progress_bar(loop, num_folders)
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r') as f:
                        data = json.load(f)

                        asn_number = data['asn']
                        try:
                            asn_handle = data['handle']
                        except KeyError:
                            asn_handle = None
                        try:
                            asn_description = data['description']
                        except KeyError:
                            asn_description = None
                        ipv4_subnets = data['subnets']['ipv4']
                        ipv6_subnets = data['subnets']['ipv6']

                        if len(ipv4_subnets) > 0:
                            for subnet in ipv4_subnets:
                                ipv4_network = ipaddress.ip_network(subnet)

                                list_ipv4.append([asn_number, asn_handle,
                                                  asn_description, int(
                                                      ipv4_network[0]),
                                                  int(ipv4_network[-1]),
                                                  subnet])

                        if len(ipv6_subnets) > 0:
                            for subnet in ipv6_subnets:
                                ipv6_network = ipaddress.ip_network(subnet)

                                list_ipv6.append([asn_number, asn_handle,
                                                  asn_description, int(
                                                      ipv6_network[0]),
                                                  int(ipv6_network[-1]),
                                                  subnet])
    return list_ipv4, list_ipv6


def generate_list_rir_range(zip_data):

    loop = 0
    list_ipv4 = []
    list_ipv6 = []

    file_name = 'aggregated.json'
    num_files = count_files_with_name(zip_data, file_name)

    print(f"Number of files with name '{file_name}' in archive: {num_files}")

    with zipfile.ZipFile(zip_data) as zip_file:
        # Loop through directories and files
        for path in zip_file.namelist():
            # Check if the path is a file named "aggregated.json"
            if path.endswith('/aggregated.json'):
                # Read the contents of the file
                with zip_file.open(path) as f:
                    loop += 1

                    progress_bar(loop, num_files)

                    data = json.load(f)

                    country = data['country']
                    country_code = data['country-code']
                    ipv4_subnets = data['subnets']['ipv4']
                    ipv6_subnets = data['subnets']['ipv6']

                    if len(ipv4_subnets) > 0:
                        for subnet in ipv4_subnets:
                            ipv4_network = ipaddress.ip_network(subnet)

                            list_ipv4.append([country, country_code, int(
                                ipv4_network[0]),
                                              int(ipv4_network[-1]), subnet])

                    if len(ipv6_subnets) > 0:
                        for subnet in ipv6_subnets:
                            ipv6_network = ipaddress.ip_network(subnet)
                            list_ipv6.append([country, country_code, int(
                                ipv6_network[0]),
                                              int(ipv6_network[-1]), subnet])
    return [list_ipv4, list_ipv6]


def refresh_database(offline=False):

    print("Refreshing database...")
    start_time = time.time()

    url_asn = "https://github.com/ipverse/asn-ip/archive/refs/heads/master.zip"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    asn_directory_path = os.path.join(script_dir, "source", "asn-ip", "as")

    url_rir = "https://github.com/ipverse/rir-ip/archive/refs/heads/master.zip"
    country_directory_path = os.path.join(script_dir, "source", "rir-ip",
                                          "country")

    list_ipv4 = []
    list_ipv6 = []

    # create dir to store database
    create_directory("db")

    # Load the ZIP archive into memory
    # with open('asn-ip-master.zip', 'rb') as f:
    #    zip_data = BytesIO(f.read())
    if offline is True:

        num_folders = count_folders(asn_directory_path)

        print("Load ASN database")
        print("Nombre de dossier: {}".format(num_folders))

        num_cores = multiprocessing.cpu_count()
        threads = []

        # Create a new thread for each subfolder
        thread = threading.Thread(target=generate_list_asn_from_folder, args=(
            asn_directory_path, 0, num_folders))
        threads.append(thread)
        thread.start()

        # Wait for all threads to complete and collect results
        for thread in threads:
            thread.join()

            list_ipv4.append(thread.result[0])
            list_ipv6.append(thread.result[1])

        list_ipv4, list_ipv6 = generate_list_asn_from_folder(
            asn_directory_path)
    else:
        # get asn info from github repo
        file_content = download_data_source(url_asn)
        zip_data = BytesIO(file_content)
        list_ipv4, list_ipv6 = generate_list_asn_range(zip_data)

    df_ipv4 = pd.DataFrame(list_ipv4, columns=['asn', 'handle', 'description',
                                               'ip_start', 'ip_end', 'subnet'])
    df_ipv6 = pd.DataFrame(list_ipv6, columns=['asn', 'handle', 'description',
                                               'ip_start', 'ip_end', 'subnet'])

    print("Write ASN database")
    df_ipv4.to_pickle(os.path.join("db", "asn_ipv4.pkl"))
    df_ipv6.to_pickle(os.path.join("db", "asn_ipv6.pkl"))

    file_content = download_data_source(url_rir)
    zip_data = BytesIO(file_content)

    list_ipv4, list_ipv6 = generate_list_rir_range(zip_data)

    df_ipv4 = pd.DataFrame(list_ipv4, columns=['country', 'country-code',
                                               'ip_start', 'ip_end', 'subnet'])
    df_ipv6 = pd.DataFrame(list_ipv6, columns=['country', 'country-code',
                                               'ip_start', 'ip_end', 'subnet'])

    print("Write Country database")
    df_ipv4.to_pickle(os.path.join("db", "country_ipv4.pkl"))
    df_ipv6.to_pickle(os.path.join("db", "country_ipv6.pkl"))

    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Exctution time {execution_time:.6f} seconds")


def search_data():
    print("Searching data...")
    # Example usage
    items_to_search = get_ip_addresses()

    # items_to_search = generate_random_ips(1000)

    print(items_to_search)

    start_time = time.time()

    # Example usage
    df_asn_ipv4 = load_dataframe_from_pickle("asn_ipv4.pkl")
    df_asn_ipv6 = load_dataframe_from_pickle("asn_ipv6.pkl")
    df_country_ipv4 = load_dataframe_from_pickle("country_ipv4.pkl")
    df_country_ipv6 = load_dataframe_from_pickle("country_ipv6.pkl")

    list_results = []

    num_items = len(items_to_search)
    loop = 0

    for item in items_to_search:

        progress_bar(loop, num_items)
        loop += 1
        df_result_asn = []
        if isinstance(item, ipaddress.IPv4Address) or isinstance(
                item, ipaddress.IPv4Network):
            df_asn = df_asn_ipv4
            df_country = df_country_ipv4

        else:
            df_asn = df_asn_ipv6
            df_country = df_country_ipv6

        if isinstance(item, ipaddress.IPv4Address) or isinstance(
                item, ipaddress.IPv6Address):

            # search through pandas df
            item_to_search = int(item)
            df_result_asn = df_asn[(df_asn["ip_start"] <= item_to_search) & (
                df_asn["ip_end"] >= item_to_search)]

        if isinstance(item, ipaddress.IPv4Network) or isinstance(
                item, ipaddress.IPv6Network):
            item_to_search_start = int(item[0])
            item_to_search_end = int(item[1])

            df_result_asn = df_asn[(
                (df_asn["ip_start"] >= item_to_search_start) &
                (df_asn["ip_start"] <= item_to_search_end)) |
                ((df_asn["ip_end"] >= item_to_search_start) &
                 (df_asn["ip_end"] <= item_to_search_end)) |
                ((df_asn["ip_start"] <= item_to_search_start) &
                 (df_asn["ip_end"] >= item_to_search_end))]

        # loop through asn result and get country for each line
        if len(df_result_asn) == 0:
            subnet = "None"
            country = "None"
            country_code = "None"
            asn = "None"
            handle = "None"
            description = "None"
        else:
            for index, row in df_result_asn.iterrows():
                subnet = row['subnet']

                asn = row["asn"]
                description = row["description"]
                handle = row["handle"]

                ip_network = ipaddress.ip_network(subnet)
                item_to_search_start = int(ip_network[0])
                item_to_search_end = int(ip_network[1])

                df_result_country = df_country[((
                    df_country["ip_start"] >= item_to_search_start) &
                    (df_country["ip_start"] <= item_to_search_end)) |
                    ((df_country["ip_end"] >= item_to_search_start) &
                     (df_country["ip_end"] <= item_to_search_end)) |
                    ((df_country["ip_start"] <= item_to_search_start) &
                     (df_country["ip_end"] >= item_to_search_end))]

                if len(df_result_country) == 1:

                    for index, row in df_result_country.iterrows():
                        country = row["country"]
                        country_code = row["country-code"]
                else:
                    country = "None"
                    country_code = "None"

        list_results.append([item, subnet, country, country_code, asn, handle,
                             description])

    df_consolidated = pd.DataFrame(list_results, columns=['item',
                                                          'subnet',
                                                          'country',
                                                          'country_code',
                                                          'asn',
                                                          'handle',
                                                          'description'])

    df_consolidated.to_csv('res-asn-country.csv', index=False)
    save_result("res-asn-country", df_consolidated)

    df_group_by_asn_country = df_consolidated.groupby([
        'country',
        'country_code',
        'asn', 'handle',
        'description'])["item"].count().reset_index(name='count')
    save_result("res-asn-country-groupby", df_group_by_asn_country)
    print("write res-asn-country-groupby.csv file")

    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Exctution time {execution_time:.6f} seconds")


def export_db():

    df_asn_ipv4 = load_dataframe_from_pickle("asn_ipv4.pkl")
    df_asn_ipv6 = load_dataframe_from_pickle("asn_ipv6.pkl")
    df_country_ipv4 = load_dataframe_from_pickle("country_ipv4.pkl")
    df_country_ipv6 = load_dataframe_from_pickle("country_ipv6.pkl")

    # Get the current working directory
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Specify the directory name you want to check/create
    dir_name = "output"

    # Construct the full path to the directory
    dir_path = os.path.join(script_dir, dir_name)

    # Check if the directory exists
    if not os.path.exists(dir_path):
        # If the directory doesn't exist, create it
        try:
            os.makedirs(dir_path)
            print(f"Directory '{dir_path}' created successfully.")
        except OSError as e:
            print(f"Error creating directory '{dir_path}': {e}")
    else:
        print(f"Directory '{dir_path}' already exists.")

    file_name_asn_ipv4 = os.path.join(dir_path, "asn_ipv4.csv")
    file_name_asn_ipv6 = os.path.join(dir_path, "asn_ipv6.csv")
    file_name_country_ipv4 = os.path.join(dir_path, "country_ipv4.csv")
    file_name_country_ipv6 = os.path.join(dir_path, "country_ipv6.csv")

    df_asn_ipv4.to_csv(file_name_asn_ipv4, columns=["asn", "handle",
                                                    "description", "subnet"],
                       index=False)
    df_asn_ipv6.to_csv(file_name_asn_ipv6, columns=["asn", "handle",
                                                    "description",
                                                    "subnet"], index=False)

    df_country_ipv4.to_csv(file_name_country_ipv4, columns=["country",
                                                            "country-code",
                                                            "subnet"],
                           index=False)
    df_country_ipv6.to_csv(file_name_country_ipv6, columns=["country",
                                                            "country-code",
                                                            "subnet"],
                           index=False)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description=""
                                     "Simple to fetch and lookup asn and rir "
                                     "db")
    parser.add_argument("--refresh-db", action="store_true", help=""
                        "Refresh the database.")
    parser.add_argument("--offline", action="store_true", help=""
                        "Refresh the database.")
    parser.add_argument("--search", action="store_true", help=""
                        "Search for data.")
    parser.add_argument("--export-db-csv", action="store_true", help=""
                        "Export ASN and RIR db into csv files.")
    args = parser.parse_args()

    if args.refresh_db and args.offline is False:
        refresh_database()

    if args.refresh_db and args.offline:
        refresh_database()

    if args.search:
        search_data()

    if args.export_db_csv:
        export_db()

    if not args.refresh_db and not args.search and not args.export_db_csv:
        print("No action specified. Use --refresh-db, --export-db-csv or "
              "--search to perform an action.")
