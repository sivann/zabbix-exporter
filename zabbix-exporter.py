import requests
import json
import time
from datetime import datetime, timedelta
import pandas as pd
import configparser
import argparse
import sys
import re

# Maps Zabbix Item Value Type (from item.get) to History Type (for history.get)
# 0: float, 3: unsigned int. These cover most performance metrics.
VALUE_TYPE_MAP = {
    '0': 0,  # Numeric (float)
    '1': 1,  # Character
    '2': 2,  # Log
    '3': 3,  # Numeric (unsigned)
    '4': 4,  # Text
}


class ZabbixExporter:
    """
    A class to handle all interactions with the Zabbix API for exporting data.
    Uses a persistent API token for authentication.
    """
    def __init__(self, api_url, token):
        self.api_url = api_url
        self.token = token
        
        if not self.token:
            print("FATAL: API token is missing. Please check your zabbix-exporter.ini file.")
            exit(1)

        print("Exporter initialized. Using API Token in request payload.")


    def _api_call(self, method, params):
        """Generic function to handle Zabbix JSON-RPC API calls."""
        # Place the auth token inside the payload. This is the correct method as confirmed by the curl test.
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": int(time.time()),
            "auth": self.token
        }

        try:
            # Use the 'json' parameter to let the requests library handle headers.
            # This is the most reliable way to ensure Content-Type is set correctly.
            response = requests.post(self.api_url, json=payload, verify=True)
            response.raise_for_status()

            data = response.json()
            if 'error' in data:
                print(f"Zabbix API Error in method '{method}': {data['error']['message']} - {data['error']['data']}")
                return None
            return data.get('result')

        except requests.exceptions.HTTPError as errh:
            print(f"Http Error: {errh}")
        except requests.exceptions.ConnectionError as errc:
            print(f"Error Connecting: {errc}")
        except requests.exceptions.Timeout as errt:
            print(f"Timeout Error: {errt}")
        except requests.exceptions.RequestException as err:
            print(f"An unexpected error occurred: {err}")
        except json.JSONDecodeError:
            print(f"Failed to decode JSON response: {response.text}")
        return None

    def get_item_details(self, item_names):
        """
        Retrieves itemid, hostid, name, and value_type for a list of item names.
        """
        print(f"\n1. Searching for {len(item_names)} items by exact name...")
        params = {
            "output": ["itemid", "hostid", "name", "key_", "value_type"],
            "selectHosts": ["host"],
            "filter": {"name": item_names},
        }
        return self._process_item_results(params, search_field='name', search_values=item_names)

    def get_item_details_by_key(self, item_keys):
        """
        Retrieves itemid, hostid, name, and value_type for a list of item keys.
        """
        print(f"\n1. Searching for {len(item_keys)} items by exact key...")
        params = {
            "output": ["itemid", "hostid", "name", "key_", "value_type"],
            "selectHosts": ["host"],
            "filter": {"key_": item_keys},
        }
        return self._process_item_results(params, search_field='key_', search_values=item_keys)

    def get_item_details_by_regex(self, item_name_regex):
        """
        Retrieves item details for items whose names match a regular expression.
        """
        print(f"\n1. Searching for items matching regex: '{item_name_regex}'...")
        try:
            regex = re.compile(item_name_regex, re.IGNORECASE)
        except re.error as e:
            print(f"ERROR: Invalid regular expression: {e}")
            return {}

        params = {
            "output": ["itemid", "hostid", "name", "key_", "value_type"],
            "selectHosts": ["host"],
        }
        all_items = self._api_call("item.get", params)
        if not all_items:
            return {}

        # Filter all returned items by the regex
        matched_items = [item for item in all_items if regex.search(item.get('name', ''))]
        if not matched_items:
            print(f"!! WARNING: No items found matching the regex '{item_name_regex}'.")
            return {}

        return self._process_item_results(None, pre_filtered_items=matched_items)

    def get_item_details_by_key_regex(self, item_key_regex):
        """
        Retrieves item details for items whose keys match a regular expression.
        """
        print(f"\n1. Searching for items matching key regex: '{item_key_regex}'...")
        try:
            # Keys are often case-sensitive and have special characters, so no IGNORECASE by default.
            regex = re.compile(item_key_regex)
        except re.error as e:
            print(f"ERROR: Invalid regular expression: {e}")
            return {}

        params = {
            "output": ["itemid", "hostid", "name", "key_", "value_type"],
            "selectHosts": ["host"],
        }
        all_items = self._api_call("item.get", params)
        if not all_items:
            return {}

        # Filter all returned items by the regex on the key
        matched_items = [item for item in all_items if regex.search(item.get('key_', ''))]
        if not matched_items:
            print(f"!! WARNING: No items found matching the key regex '{item_key_regex}'.")
            return {}

        return self._process_item_results(None, pre_filtered_items=matched_items)


    def _process_item_results(self, params, search_field=None, search_values=None, pre_filtered_items=None):
        """Helper function to process results from item.get calls."""
        if pre_filtered_items is not None:
            result = pre_filtered_items
        else:
            result = self._api_call("item.get", params)

        if not result:
            return {}

        found_items = {}
        for item in result:
            full_name = item.get('name')
            item_key = item.get('key_')
            item_details = {
                'itemid': item['itemid'],
                'host': item['hosts'][0]['host'] if item.get('hosts') else 'N/A',
                'name': full_name,
                'key_': item_key,
                'history_type': VALUE_TYPE_MAP.get(item['value_type'])
            }
            found_items[item['itemid']] = item_details
            print(f"  -> Found '{full_name}' (Key: {item_key}) on host [{item_details['host']}]")

        if search_field and search_values:
            # Use the item's `name` or `key_` from the returned details for matching
            found_values = {details[search_field] for details in found_items.values()}
            missing_values = [value for value in search_values if value not in found_values]
            if missing_values:
                print(f"\n!! WARNING: The following items ({search_field.replace('_', '')}) were not found: {missing_values}")

        return found_items

    def get_history_data(self, item_id, history_type, time_from, time_till):
        """
        Retrieves raw history data for a single item.
        """
        history_data = []

        params = {
            "output": "extend",
            "history": history_type,
            "itemids": item_id,
            "time_from": time_from,
            "time_till": time_till,
            "sortfield": "clock",
            "sortorder": "ASC",
            "limit": 50000
        }

        result = self._api_call("history.get", params)
        if result:
            history_data.extend(result)

        return history_data


    def export_items_to_csv(self, item_details, date_from_str, date_to_str, output_filename, delimiter=','):
        """
        Main function to orchestrate the data fetching and export.
        """
        DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
        try:
            if ' ' not in date_from_str:
                date_from_str += " 00:00:00"
            if ' ' not in date_to_str:
                date_to_str += " 23:59:59"
            dt_from = datetime.strptime(date_from_str, DATE_FORMAT)
            dt_to = datetime.strptime(date_to_str, DATE_FORMAT)
            time_from = int(time.mktime(dt_from.timetuple()))
            time_till = int(time.mktime(dt_to.timetuple()))
        except ValueError:
            print(f"ERROR: Invalid date format. Please use '{DATE_FORMAT}' or 'YYYY-MM-DD'.")
            return

        print(f"\n2. Fetching history from {date_from_str} to {date_to_str}...")
        all_data = []
        for item_id, details in item_details.items():
            item_name = details['name']
            item_key = details['key_']
            host_name = details['host']
            history_type = details['history_type']

            if history_type is None:
                print(f"!! SKIPPING: '{item_name}' - Unknown or unsupported value type.")
                continue

            print(f"  -> Fetching data for [{host_name}] {item_name}...")
            history = self.get_history_data(item_id, history_type, time_from, time_till)
            for row in history:
                row['item_name'] = item_name
                row['item_key'] = item_key
                row['host'] = host_name
                row['datetime'] = datetime.fromtimestamp(int(row['clock'])).strftime(DATE_FORMAT)
                all_data.append(row)
            print(f"      (Retrieved {len(history)} data points)")

        if not all_data:
            print("\nExport completed, but no data points were retrieved for the given period.")
            return

        print(f"\n3. Total data points retrieved: {len(all_data)}")
        df = pd.DataFrame(all_data)
        final_columns = ['datetime', 'host', 'item_name', 'item_key', 'itemid', 'value', 'clock']
        df = df.reindex(columns=final_columns)

        try:
            df.to_csv(output_filename, index=False, encoding='utf-8', sep=delimiter)
            print(f"\n✅ SUCCESS: Data successfully exported to: '{output_filename}'")
        except Exception as e:
            print(f"\nFATAL ERROR: Could not write to CSV file. Error: {e}")

    def list_items_by_host(self, host_name):
        """Lists all items for a given host."""
        print(f"Searching for host '{host_name}'...")
        host_params = {"filter": {"host": [host_name]}}
        hosts = self._api_call("host.get", host_params)

        if not hosts:
            print(f"ERROR: Host '{host_name}' not found.")
            return

        host_id = hosts[0]['hostid']
        print(f"Found host '{host_name}' (ID: {host_id}). Listing items...")
        item_params = {"output": ["name", "key_"], "hostids": host_id, "sortfield": "name"}
        items = self._api_call("item.get", item_params)

        if items:
            print("-" * 50)
            for item in items:
                print(f"Name: {item['name']}\n  Key: {item['key_']}\n")
            print(f"Found {len(items)} items for host '{host_name}'.")
        else:
            print(f"No items found for host '{host_name}'.")

    def list_graphs(self):
        """Lists all available classic graphs."""
        print("Fetching all classic graphs...")
        params = {"output": ["name", "graphid"], "sortfield": "name"}
        graphs = self._api_call("graph.get", params)

        if graphs:
            print("-" * 50)
            for graph in graphs:
                print(f"Graph Name: {graph['name']} (ID: {graph['graphid']})")
            print(f"\nFound {len(graphs)} classic graphs.")
        else:
            print("No classic graphs found.")

    def list_items_by_graph(self, graph_name):
        """Lists all items within a specific classic graph."""
        print(f"Searching for classic graph '{graph_name}'...")
        params = {"filter": {"name": [graph_name]}, "selectItems": ["name", "key_"]}
        graphs = self._api_call("graph.get", params)

        if not graphs:
            print(f"ERROR: Classic graph '{graph_name}' not found.")
            return

        graph = graphs[0]
        items = graph.get('items', [])
        if items:
            print(f"Found classic graph '{graph_name}'. Listing its items...")
            print("-" * 50)
            for item in items:
                print(f"Name: {item['name']}\n  Key: {item['key_']}\n")
            print(f"Classic graph '{graph_name}' contains {len(items)} items.")
        else:
            print(f"Classic graph '{graph_name}' found, but it contains no items.")
            
    def list_dashboards(self):
        """Lists all available dashboards."""
        print("Fetching all dashboards...")
        params = {"output": ["name", "dashboardid"], "sortfield": "name"}
        dashboards = self._api_call("dashboard.get", params)

        if dashboards:
            print("-" * 50)
            for board in dashboards:
                print(f"Dashboard Name: {board['name']} (ID: {board['dashboardid']})")
            print(f"\nFound {len(dashboards)} dashboards.")
        else:
            print("No dashboards found.")

    def list_widgets_by_dashboard(self, dashboard_name, debug_mode=False):
        """Lists all graph widgets and their items within a specific dashboard."""
        # Step 1: Find the dashboard by name to get its ID.
        print(f"Searching for dashboard '{dashboard_name}'...")
        find_params = {
            "output": ["dashboardid"],
            "filter": {"name": [dashboard_name]}
        }
        dashboards = self._api_call("dashboard.get", find_params)

        if not dashboards:
            print(f"ERROR: Dashboard '{dashboard_name}' not found or no permissions.")
            return

        dashboard_id = dashboards[0]['dashboardid']
        print(f"Found dashboard '{dashboard_name}' (ID: {dashboard_id}). Fetching widgets...")

        # Step 2: Use the dashboard ID to get its pages, which contain the widgets.
        widget_params = {
            "dashboardids": [dashboard_id],
            "selectPages": "extend"
        }
        dashboard_details_list = self._api_call("dashboard.get", widget_params)
        
        if not dashboard_details_list:
            print(f"ERROR: Could not retrieve details for dashboard ID '{dashboard_id}'.")
            return
            
        dashboard_details = dashboard_details_list[0]
        
        widgets = []
        if dashboard_details.get('pages'):
            for page in dashboard_details['pages']:
                if page.get('widgets'):
                    widgets.extend(page['widgets'])
        
        if not widgets:
            print(f"Dashboard '{dashboard_name}' contains no widgets.")
            return

        if debug_mode:
            print("\n--- RAW WIDGET DATA (DEBUG MODE) ---")
            print(json.dumps(widgets, indent=4))
            print("--- END RAW WIDGET DATA ---")
            return
            
        # Identify all possible graph-like widgets from the raw data.
        graph_widget_types = ['svggraph', 'graphprototype']
        graph_widgets = [w for w in widgets if w.get('type') in graph_widget_types]

        if not graph_widgets:
            print(f"No graph widgets of types {graph_widget_types} found on dashboard '{dashboard_name}'.")
            return

        print(f"\nFound {len(graph_widgets)} graph widget(s) on '{dashboard_name}':")
        print("-" * 50)

        # --- Data Gathering Phase ---
        # We need to collect all item names and graph IDs to fetch their details in batch API calls.
        
        item_names_to_find = set()
        graph_ids_to_find = set()
        widget_data_map = {} # Maps widgetid to the data it contains (item names or graph id)

        for widget in graph_widgets:
            widget_id = widget['widgetid']
            widget_type = widget['type']
            widget_data_map[widget_id] = {'type': widget_type, 'name': widget.get('name', 'Untitled Widget'), 'content': []}

            if widget_type == 'svggraph':
                # For svggraph, the items are stored by name in the 'fields'
                widget_item_names = []
                for field in widget.get('fields', []):
                    field_name = field.get('name', '')
                    if field_name.startswith('ds.') and '.items.' in field_name:
                        item_name = field.get('value')
                        if item_name:
                            widget_item_names.append(item_name)
                
                if widget_item_names:
                    item_names_to_find.update(widget_item_names)
                    widget_data_map[widget_id]['content'] = widget_item_names

            elif widget_type == 'graphprototype':
                # For graphprototype, it references a classic graph by its ID
                for field in widget.get('fields', []):
                    if field.get('name', '').startswith('graphid.'):
                        graph_id = field.get('value')
                        if graph_id:
                            graph_ids_to_find.add(graph_id)
                            widget_data_map[widget_id]['content'] = graph_id
                            break # Assume one graph per widget

        # --- API Fetching Phase ---
        # Now, make the batch API calls to get details for everything we found.

        item_details_by_name = {}
        if item_names_to_find:
            item_params = {
                "output": ["name", "key_"],
                "selectHosts": ["host"],
                "filter": {"name": list(item_names_to_find)}
            }
            item_results = self._api_call("item.get", item_params)
            if item_results:
                item_details_by_name = {item['name']: item for item in item_results}

        graph_items_by_id = {}
        if graph_ids_to_find:
            graph_params = {
                "output": ["name"],
                "graphids": list(graph_ids_to_find),
                "selectItems": ["name", "key_"]
            }
            graph_results = self._api_call("graph.get", graph_params)
            if graph_results:
                graph_items_by_id = {graph['graphid']: graph.get('items', []) for graph in graph_results}


        # --- Output Rendering Phase ---
        # Finally, loop through the widgets again and print the details we fetched.
        
        has_content = False
        for widget in graph_widgets:
            widget_id = widget['widgetid']
            data = widget_data_map[widget_id]
            print(f"\nWidget: {data['name']}")

            if data['type'] == 'svggraph':
                item_names_in_widget = data['content']
                if not item_names_in_widget:
                    print("  (No items configured for this widget)")
                    continue
                
                has_content = True
                for item_name in item_names_in_widget:
                    detail = item_details_by_name.get(item_name)
                    if detail:
                        host = detail['hosts'][0]['host'] if detail.get('hosts') else 'N/A'
                        print(f"  -> Item: [{host}] {detail['name']}")
                        print(f"     Key: {detail['key_']}")
                    else:
                        print(f"  -> Item: {item_name} (Details not found, check permissions)")
            
            elif data['type'] == 'graphprototype':
                graph_id = data['content']
                items_in_graph = graph_items_by_id.get(graph_id)
                if not items_in_graph:
                    print(f"  (Could not find items for referenced graph ID: {graph_id})")
                    continue
                
                has_content = True
                for item in items_in_graph:
                    # 'graph.get' with 'selectItems' doesn't return host info, so we can't display it here.
                    print(f"  -> Item: {item['name']}")
                    print(f"     Key: {item['key_']}")

        if not has_content:
             print("\nGraph widgets found, but they do not contain any configured or discoverable items.")


def get_args():
    """Parses command-line arguments for the script."""
    parser = argparse.ArgumentParser(description="Export or list data from Zabbix.")
    subparsers = parser.add_subparsers(dest='command', help='Available commands', required=True)

    parser_export = subparsers.add_parser('export', help='Export item history to CSV')
    item_group = parser_export.add_mutually_exclusive_group(required=True)
    # New arguments for keys are the primary method
    item_group.add_argument('--keys', help="Comma-separated list of exact Zabbix Item Keys to export.")
    item_group.add_argument('--keys-regex', help="Regular expression to select items by key for export.")
    # Legacy arguments for names
    item_group.add_argument('--items', help="[Legacy] Comma-separated list of exact Zabbix Item Names to export.")
    item_group.add_argument('--items-regex', help="[Legacy] Regular expression to select items by name for export.")
    parser_export.add_argument('--start-date', default=None, help="Start date ('YYYY-MM-DD'). Defaults to yesterday.")
    parser_export.add_argument('--end-date', default=None, help="End date ('YYYY-MM-DD'). Defaults to today.")
    parser_export.add_argument('--output', default="zabbix_metrics_export.csv", help="Output CSV filename.")
    parser_export.add_argument('--delimiter', default=',', help="Delimiter for the output CSV file (default: ',').")

    parser_list = subparsers.add_parser('list', help='List Zabbix configuration elements')
    list_subparsers = parser_list.add_subparsers(dest='list_target', help='What to list', required=True)
    
    parser_list_items = list_subparsers.add_parser('items', help='List items for a specific host')
    parser_list_items.add_argument('--host', required=True, help='Host name to list items for.')

    list_subparsers.add_parser('graphs', help='List all classic graphs')
    
    parser_list_graph_items = list_subparsers.add_parser('graph-items', help='List items in a specific classic graph')
    parser_list_graph_items.add_argument('--graph-name', required=True, help='Name of the classic graph.')

    list_subparsers.add_parser('dashboards', help='List all dashboards')
    
    parser_list_dashboard_widgets = list_subparsers.add_parser('dashboard-widgets', help='List graph widgets and their items from a dashboard')
    parser_list_dashboard_widgets.add_argument('--dashboard-name', required=True, help='Name of the dashboard.')
    parser_list_dashboard_widgets.add_argument('--debug', action='store_true', help='Print raw widget data for debugging.')

    return parser.parse_args()


# --- Main Execution ---
if __name__ == "__main__":
    CONFIG_FILE = "zabbix-exporter.ini"
    config = configparser.ConfigParser()
    args = get_args()

    if not config.read(CONFIG_FILE):
        print(f"ERROR: Config file '{CONFIG_FILE}' not found.")
        exit(1)

    try:
        loaded_api_url = config.get('Zabbix', 'api_url')
        loaded_api_token = config.get('Zabbix', 'api_token')
    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        print(f"ERROR: Missing configuration in '{CONFIG_FILE}'. Ensure 'api_url' and 'api_token' are set. Detail: {e}")
        exit(1)

    exporter = ZabbixExporter(loaded_api_url, loaded_api_token)

    if args.command == 'export':
        # --- Date Handling ---
        today_str = datetime.now().strftime('%Y-%m-%d')
        yesterday_str = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
        
        START_DATE = args.start_date
        END_DATE = args.end_date

        if not START_DATE and not END_DATE:
            START_DATE = yesterday_str
            END_DATE = today_str
            print(f"Defaulting to date range: {START_DATE} to {END_DATE}")
        elif START_DATE and not END_DATE:
            END_DATE = today_str
            print(f"End date not specified, defaulting to today. Using date range: {START_DATE} to {END_DATE}")
        elif not START_DATE and END_DATE:
            # If only end date is given, default start date to the day before the end date.
            end_dt = datetime.strptime(END_DATE, '%Y-%m-%d')
            start_dt = end_dt - timedelta(days=1)
            START_DATE = start_dt.strftime('%Y-%m-%d')
            print(f"Start date not specified, defaulting to 1 day before end date. Using date range: {START_DATE} to {END_DATE}")
        else: # Both are defined
            print(f"Using custom date range: {START_DATE} to {END_DATE}")
        
        # --- Item Selection ---
        item_details = {}
        # Prioritize new key-based arguments
        if args.keys:
            TARGET_ITEM_KEYS = [key.strip() for key in args.keys.split(',')]
            item_details = exporter.get_item_details_by_key(TARGET_ITEM_KEYS)
        elif args.keys_regex:
            item_details = exporter.get_item_details_by_key_regex(args.keys_regex)
        elif args.items:
            TARGET_ITEM_NAMES = [item.strip() for item in args.items.split(',')]
            item_details = exporter.get_item_details(TARGET_ITEM_NAMES)
        elif args.items_regex:
            item_details = exporter.get_item_details_by_regex(args.items_regex)

        if not item_details:
            print("\nExport failed: No valid items found or API failed.")
            exit(1)
            
        exporter.export_items_to_csv(item_details, START_DATE, END_DATE, args.output, delimiter=args.delimiter)

    elif args.command == 'list':
        if args.list_target == 'items':
            exporter.list_items_by_host(args.host)
        elif args.list_target == 'graphs':
            exporter.list_graphs()
        elif args.list_target == 'graph-items':
            exporter.list_items_by_graph(args.graph_name)
        elif args.list_target == 'dashboards':
            exporter.list_dashboards()
        elif args.list_target == 'dashboard-widgets':
            exporter.list_widgets_by_dashboard(args.dashboard_name, debug_mode=args.debug)


