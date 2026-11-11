"""Collect local Windows network data and compare it with a desired state.
Run: python collect_host.py
Requires: pip install psutil jsonschema
Only reads local configuration. Review output before sharing it.
"""
import datetime
import ipaddress
import json
import pathlib
import socket
import subprocess
import psutil
from jsonschema import Draft202012Validator

ROOT = pathlib.Path(__file__).resolve().parent
TOP = 'student-host:host'

def powershell(command):
    result = subprocess.run(['powershell', '-NoProfile', '-Command', command + ' | ConvertTo-Json -Depth 8'], capture_output=True, text=True, check=True)
    data = json.loads(result.stdout)
    return data if isinstance(data, list) else ([data] if data else [])

def main():
    adapters = powershell('Get-NetAdapter | Select-Object Name, Status, MacAddress, InterfaceDescription')
    ipifs = powershell('Get-NetIPInterface | Select-Object InterfaceAlias, AddressFamily, NlMtu')
    addresses = powershell('Get-NetIPAddress | Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength')
    routes = powershell('Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object NextHop, RouteMetric, InterfaceMetric')
    dns = powershell('Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses')
    mtus = {x['InterfaceAlias']: x['NlMtu'] for x in ipifs if str(x['AddressFamily']) in ('2', 'IPv4')}
    items = []
    for a in adapters:
        name = a['Name']
        description = (a.get('InterfaceDescription') or '').lower()
        kind = 'wifi' if 'wi-fi' in name.lower() or 'wireless' in description else ('virtual' if any(k in description for k in ('virtual', 'hyper-v', 'vmware', 'virtualbox')) or 'vethernet' in name.lower() else 'ethernet')
        item = {'name': name, 'type': kind, 'oper-status': 'up' if a['Status'] == 'Up' else 'down'}
        mac = a.get('MacAddress')
        if mac:
            item['mac'] = mac.replace('-', ':').lower()
        if name in mtus:
            item['mtu'] = mtus[name]
        for family, field in ((2, 'ipv4'), (23, 'ipv6')):
            vals = [f"{x['IPAddress']}/{x['PrefixLength']}" for x in addresses if x['InterfaceAlias'] == name and str(x['AddressFamily']) in (str(family), 'IPv4' if family == 2 else 'IPv6')]
            if vals:
                item[field] = vals
        items.append(item)
    gateways = [x for x in routes if x.get('NextHop') and x['NextHop'] != '0.0.0.0']
    gateways.sort(key=lambda x: (x.get('RouteMetric') or 0) + (x.get('InterfaceMetric') or 0))
    wifi_dns = next((x.get('ServerAddresses') or [] for x in dns if x['InterfaceAlias'] == 'Wi-Fi'), [])
    host = {'hostname': socket.gethostname(), 'os': 'windows', 'collected-at': datetime.datetime.now().astimezone().isoformat(timespec='seconds'), 'interface': items}
    if gateways:
        host['default-gateway'] = gateways[0]['NextHop']
    if wifi_dns:
        host['dns-server'] = wifi_dns
    observed = {TOP: host}
    (ROOT / 'observed.json').write_text(json.dumps(observed, indent=2), encoding='utf-8')
    schema = json.loads((ROOT / 'host_schema.json').read_text(encoding='utf-8'))
    errors = sorted(Draft202012Validator(schema).iter_errors(observed), key=lambda e: str(list(e.absolute_path)))
    print('SCHEMA VALIDATION:', 'VALID' if not errors else f'{len(errors)} ERROR(S)')
    for e in errors:
        print('ERROR /' + '/'.join(map(str, e.absolute_path)) + ': ' + e.message)
    intended_path = ROOT / 'intended.json'
    if intended_path.exists():
        desired = json.loads(intended_path.read_text(encoding='utf-8'))[TOP]
        print('DRIFT REPORT:')
        differences = []
        for key, expected in desired.items():
            if key == 'interface':
                actual_by_name = {i['name']: i for i in host['interface']}
                for want in expected:
                    actual = actual_by_name.get(want['name'])
                    if actual is None:
                        differences.append(f"interface {want['name']}: missing")
                        continue
                    for field, value in want.items():
                        if field != 'name' and actual.get(field) != value:
                            differences.append(f"interface {want['name']} / {field}: intended {value!r}, observed {actual.get(field)!r}")
            elif host.get(key) != expected:
                differences.append(f'{key}: intended {expected!r}, observed {host.get(key)!r}')
        print('\n'.join(differences) if differences else 'No drift in checked fields')
    else:
        print('No intended.json yet; drift comparison skipped.')
    print('Saved observed.json. Redact MACs, public IPs and identifying hostname before sharing.')

if __name__ == '__main__':
    main()
