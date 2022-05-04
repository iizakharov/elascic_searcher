import codecs
import csv
import re

import pynetbox as pynetbox

from elasticapp.utils import get_data_from_ipam
from netbox_gettr.settings import IPAM_TOKEN, IPAM_URL


def connect():
    token = IPAM_TOKEN
    url = IPAM_URL
    nb = pynetbox.api(
        url,
        token=token
    )
    return nb


def checker(name, item):
    str_text = ''
    count = 0
    filename, file_extension = name.split('.')
    nb = connect()
    res = {}
    if file_extension == 'csv':
        file_reader = csv.DictReader(codecs.iterdecode(item, 'utf-8'), delimiter=',')
        for row in file_reader:
            count += 1
            try:
                q = nb.ipam.ip_addresses.get(address=row['IP'])
            except:  # noqa: E722
                q = None
            if q is None:
                res[count] = {
                    'ip': row['IP'],
                    'port': 'нет в IPAM',
                    'tenant': 'нет в IPAM',
                    'tenant_url': '#',
                    'ip_url': '#',
                }
            else:
                res[count] = {
                    'ip': row['IP'],
                    'port': row['Port'],
                    'tenant': q.tenant,
                    'tenant_url': (q.tenant.url).replace('/api/', '/'),
                    'ip_url': (q.url).replace('/api/', '/')
                }
    elif file_extension == 'txt':
        for line in item:
            str_text = str_text + line.decode()
        str_text = str_text.split('\n')
        for ip in str_text:
            count += 1
            if ip == '':
                continue
            ip = ip.strip()
            q = nb.ipam.ip_addresses.get(address=ip)
            res[count] = {
                'ip': ip,
                'port': None,
                'tenant': q.tenant,
                'tenant_url': (q.tenant.url).replace('/api/', '/'),
                'ip_url': (q.url).replace('/api/', '/')
            }
    return res


def data_parser(data):
    res = {}
    _res = []
    reg = re.compile(r'(([0-9]{1,3}[\.]){3}[0-9]{1,3})')
    if '\n' in data:
        data = data.split('\n')
    elif '\r' in data:
        data = data.split('\r')
    elif reg.search(data) is not None:
        _res.append(data)
    for row in data:
        if reg.search(row) is not None:
            names = reg.search(row)
            ip = names.group()
            _res.append(ip)
    count = 0
    for ip in _res:
        count += 1
        if ip == '':
            continue
        data = get_data_from_ipam(ip)
        res[count] = data
    return res
