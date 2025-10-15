### Find a list of items in a modern graph in a dashboard:

python zabbix-exporter.py list dashboard-widgets --dashboard-name "Site Statistics" 

### Export by key "pki.sslcertcount[s]"

python zabbix-exporter.py export --keys 'pki.sslcertcount[s]' --start-date '2025-10-01' --end-date '2025-10-25'


```
 python zabbix-exporter.py --help
usage: zabbix-exporter.py [-h] {export,list} ...

Export or list data from Zabbix.

positional arguments:
  {export,list}  Available commands
    export       Export item history to CSV
    list         List Zabbix configuration elements

options:
  -h, --help     show this help message and exit

usage: zabbix-exporter.py list [-h] {items,graphs,graph-items,dashboards,dashboard-widgets} ...

positional arguments:
  {items,graphs,graph-items,dashboards,dashboard-widgets}
                        What to list
    items               List items for a specific host
    graphs              List all classic graphs
    graph-items         List items in a specific classic graph
    dashboards          List all dashboards
    dashboard-widgets   List graph widgets and their items from a dashboard

options:
  -h, --help            show this help message and exit

usage: zabbix-exporter.py export [-h]
                                 (--keys KEYS | --keys-regex KEYS_REGEX | --items ITEMS | --items-regex ITEMS_REGEX)
                                 [--start-date START_DATE] [--end-date END_DATE] [--output OUTPUT]
                                 [--delimiter DELIMITER]

options:
  -h, --help            show this help message and exit
  --keys KEYS           Comma-separated list of exact Zabbix Item Keys to export.
  --keys-regex KEYS_REGEX
                        Regular expression to select items by key for export.
  --items ITEMS         [Legacy] Comma-separated list of exact Zabbix Item Names to export.
  --items-regex ITEMS_REGEX
                        [Legacy] Regular expression to select items by name for export.
  --start-date START_DATE
                        Start date ('YYYY-MM-DD'). Defaults to yesterday.
  --end-date END_DATE   End date ('YYYY-MM-DD'). Defaults to today.
  --output OUTPUT       Output CSV filename.
  --delimiter DELIMITER
                        Delimiter for the output CSV file (default: ',').
```
