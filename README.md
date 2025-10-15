# Find a list of items in a modern graph in a dashboard:

python zabbix-exporter.py list dashboard-widgets --dashboard-name "Site Statistics" 

# Export by key "pki.sslcertcount[s]"

python zabbix-exporter.py export --keys 'pki.sslcertcount[s]' --start-date '2025-10-01' --end-date '2025-10-25'
