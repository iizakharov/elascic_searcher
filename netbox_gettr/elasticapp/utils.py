import json
import re
from copy import deepcopy
from datetime import timedelta, datetime
import pynetbox
from elasticsearch import NotFoundError, Elasticsearch

from netbox_gettr.settings import ELK_URL, ELK_USER, ELK_PASS, IPAM_TOKEN, IPAM_URL
from .workbook import ElkFilter, FORM, ElkMassIpFilter


def connect_elk():
    user = ELK_USER
    pssw = ELK_PASS
    url = ELK_URL

    es = Elasticsearch(
        [url],
        http_auth=(user, pssw),
        scheme='http',
        timeout=20
    )
    return es


def connect_ipam():
    print('Connecting to ipsm.mchs.ru')
    nb = pynetbox.api(
        IPAM_URL,
        token=IPAM_TOKEN
    )
    return nb


def try_repeat(func):
    def wrapper(*args, **kwargs):
        count = 5
        while count:
            try:
                return func(*args, **kwargs)
            except NotFoundError:
                count = 0
            except Exception as e:
                print(e)
                print('ReConnect...')
                count -= 1
    return wrapper


@try_repeat
def get_hits(es, index, form):
    try:
        data = es.search(index=index, body=form, size=2000)
        if data['hits']['hits'].__len__() == 0:
            return False
        hits = data['hits']['hits']
        return hits
    except NotFoundError:
        hits = 'Out of index'
        return hits
    except Exception as e:
        # print(f'По {index} информация не получена')
        raise Exception(e)


def string_to_list(string: str):
    res = None
    if '\n' in string:
        if ',' in string:
            _string = string.replace(',', '\n')
            res = _string.split('\n')
        else:
            res = string.split('\n')
    elif ',' in string:
        res = string.split(',')
    else:
        res = string.split()
    step = 0
    while step != len(res):
        if '' == res[step]:
            res.pop(step)
            continue
        res[step] = res[step].strip()
        step += 1

    return res


def check_ip_in_arr(arr: str):
    ips_arr = string_to_list(arr)
    correct_arr = []
    reg = re.compile(r'([0-9]{1,3}[\.][0-9]{1,3}[\.][0-9]{1,3}[\.][0-9]{1,3})')
    for item in range(len(ips_arr)):
        if re.match(reg, ips_arr[item]):
            ip = re.match(reg, ips_arr[item])
            correct_arr.append(ip.group())
    return correct_arr


def del_extra_fields(obj: dict, labels: list):
    """
    function for '<eny>_convert' dict
    """
    # print(json.dumps(obj, ensure_ascii=False, indent=4))
    not_none_label = False
    length = len(labels)
    for label in labels:
        length -= 1
        if not_none_label:
            del obj[label]
            continue
        if obj[label] is None or obj[label] == '':
            if length < 1:
                break
            del obj[label]
            continue
        else:
            not_none_label = label

    return obj


def logstash_convert(obj: dict):
    _obj = deepcopy(obj)
    labels_timezone = ['data.timezone', 'field_usr_fname.timezone', 'roles.timezone', 'os.version']
    labels_fio = ['roles.fio', 'work_unit.name_long', 'work_unit.name_full', 'work_unit.name', 'field_usr_mname.mail',
                  "roles.1"]
    labels_organization = ['COOKIES.docflow_org_name', 'work_unit.org_unit', 'host.hostname']
    labels_ip = ['variables.HTTP_X_REAL_IP', 'user.HTTP_X_REAL_IP']
    labels_requests = ['variables.request_uri', 'message_json.request_uri']

    arr_labels = [labels_timezone, labels_fio, labels_organization, labels_ip, labels_requests]
    for label in arr_labels:
        _obj = del_extra_fields(_obj, label)
    # print(json.dumps(obj, ensure_ascii=False, indent=4))
    return _obj


def kasper_convert(obj: dict):
    _obj = deepcopy(obj)
    labels_target = ["input.attack_target_ip", "attack_target_ip", "sd.attack_target_ip", "event.hip",
                     "log.attack_target_ip"]
    labels_source = ['input.attack_source_ip', 'ecs.attack_source_ip', 'attack_source_ip', 'agent.attack_source_ip',
                     "log.attack_source_ip", "sd.attack_source_ip"]
    labels_region = ["region", "sd.region", "ecs.region", "agent_in_host.region", "input.region"]

    arr_labels = [labels_target, labels_source, labels_region]
    for label in arr_labels:
        _obj = del_extra_fields(_obj, label)
    return _obj


def osquery_ioc_convert(obj: dict):
    _obj = deepcopy(obj)
    labels_hostname = ["all_connections.hostname", "message.hostname", "hostname"]
    return del_extra_fields(_obj, labels_hostname)


def osquery_po(obj: dict):
    _obj = deepcopy(obj)
    labels_hostname = ["all_connections.hostname", "message.hostname"]
    labels_avz = ["all_connections.avz_install", "message.avz_install", "avz_install"]
    labels_szi = ["szi_install", "message.szi_install", "all_connections.szi_install"]
    labels_ya = ["yandex_version", "message.yandex_version"]
    labels_dallas = ["dallas_version", "message.dallas_version"]
    labels_kasper = ["all_connections.kaspersky_version", "message.kaspersky_version"]
    labels_codemane = ["all_connections.codename", "message.codename"]

    arr_labels = [labels_hostname, labels_avz, labels_szi, labels_ya, labels_dallas, labels_kasper, labels_codemane]
    for label in arr_labels:
        _obj = del_extra_fields(_obj, label)
    return _obj


def parse_json(obj, gen=0):
    new_dict = {}
    for key, value in obj.items():
        if key == 'message':
            try:
                value = json.loads(json.dumps(value, ensure_ascii=False))
                value = json.loads(value)
            except:  # noqa: E722
                print()
        if not isinstance(value, dict):
            if key in new_dict.keys():
                new_dict[f'{key}_{gen}'] = value
            else:
                new_dict[key] = value
        else:
            gen += 1
            new_dict.update(parse_json(value, gen))
    return new_dict


def new_parse_json(obj, gen=0, title=None):
    new_dict = {}
    for key, value in obj.items():
        if key == 'message':
            try:
                value = json.loads(json.dumps(value, ensure_ascii=False))
                value = json.loads(value)
            except:  # noqa: E722
                pass
        if not isinstance(value, dict):
            if '@timestamp' in key:
                new_dict['@timestamp'] = value
                continue
            if key in new_dict.keys():
                if title is not None:
                    new_dict[f'{title}_{key}'] = value
                else:
                    new_dict[key] = value
            else:
                if title is not None:
                    new_dict[f'{title}.{key}'] = value
                else:
                    new_dict[key] = value
        else:
            title = key
            gen += 1
            new_dict.update(new_parse_json(value, gen, title))

    return new_dict


def check_timedelta(old_request, new_request):
    rd = datetime.strptime(new_request['@timestamp'], '%Y-%m-%d %H:%M')
    od = datetime.strptime(old_request['@timestamp'], '%Y-%m-%d %H:%M')
    if old_request['@timestamp'] == new_request['@timestamp'] and old_request['etdn'] == new_request['etdn']:
        return True
    elif rd - od < timedelta(seconds=600):
        return True
    return False


def oqsuery_convert(obj: dict, index: str):
    _index = index.split('-')[0]
    form = deepcopy(FORM)
    count = 0
    for key, value in obj.items():
        count += 1
        if key in FORM[_index].keys():
            form[_index][key] = value
        if key in FORM['po'].keys():
            form['po'][key] = value

    return form[_index], form['po']


def convert(obj: dict, index: str, ioc=False):
    _index = index.split('-')[0]
    if ioc and _index == 'osquery':
        _index = 'osquery_ioc'
    form = deepcopy(FORM)
    count = 0
    for key, value in obj.items():
        count += 1
        if key in FORM[_index].keys():
            form[_index][key] = value
    # print(form[_index])
    # print('*'*50)
    return form[_index]


def search(item, days, index_name, any_filter=False):  # noqa: C901
    es = connect_elk()
    a = ElkFilter(item, days, index_name)
    result = {}
    items = []
    count = 0
    for index in a.indexes:
        if any_filter:
            hits = get_hits(es, index, a.get_index_form(any_filter=True))
        else:
            hits = get_hits(es, index, a.get_index_form())
        if not hits:
            print(f'{index} - нет вхождений')
            continue
        elif hits == 'Out of index':
            break
        print(index, 'Done!')
        for hit in hits:
            _id = hit['_id']
            old_result = deepcopy(result)
            result = new_parse_json(hit['_source'])
            result['index_id'] = _id
            # change date
            date = result['@timestamp'].split('.')[0]
            date = datetime.strptime(date, '%Y-%m-%dT%H:%M:%S')
            result['@timestamp'] = datetime.strftime(date, '%Y-%m-%d %H:%M')

            if old_result != {}:
                if a.check_timedelta(old_result, result):
                    continue
            for k, val in result.items():
                if item in str(val):
                    count += 1
                    # print(json.dumps(result, ensure_ascii=False, indent=4))
                    items.append(result)
                    break
    if count == 0:
        items = None
    else:
        print('Колличество совпадений: ', count)
    return items


def txt_parse(name, item):
    str_text = ''
    filename, file_extension = name.split('.')
    res = []
    if file_extension == 'txt':
        for line in item:
            str_text = str_text + line.decode()
        str_text = str_text.split('\n')
        for ip in str_text:
            if ip == '':
                continue
            res.append(ip)
    return res


def ioc_search(ips: str, days, index_name):  # noqa: C901
    ips_arr = check_ip_in_arr(ips)
    es = connect_elk()
    a = ElkMassIpFilter(ips_arr, days, index_name)
    result = {}
    items = []
    count = 0
    for index in a.indexes:
        hits = get_hits(es, index, a.get_index_form())
        if not hits:
            print(f'{index} - нет вхождений')
            continue
        elif hits == 'Out of index':
            break
        print(index, 'Done!')
        for hit in hits:
            _id = hit['_id']
            old_result = deepcopy(result)
            result = new_parse_json(hit['_source'])
            result['index_id'] = _id
            # change date
            date = result['@timestamp'].split('.')[0]
            date = datetime.strptime(date, '%Y-%m-%dT%H:%M:%S')
            result['@timestamp'] = datetime.strftime(date, '%Y-%m-%d %H:%M')

            if old_result != {}:
                if a.check_timedelta(old_result, result):
                    continue
            for k, val in result.items():
                if len(ips_arr) <= 1:
                    if ips_arr[0] in str(val):
                        count += 1
                        items.append(result)
                        break
                else:
                    for ip in ips_arr:
                        if ip in str(val):
                            count += 1
                            items.append(result)
                            break
    return items


def get_hostmane_ipam(hostname):
    nb = connect_ipam()
    dev_dict = {}
    try:
        devise = nb.dcim.devices.filter(q=hostname)
        for attr in devise:
            name = attr.name
            ip = attr.primary_ip
            tenant = attr.tenant
            site = attr.site
            os = attr.custom_fields['OS']
            dev_dict = {
                'name': name if name else None,
                'ip': ip if ip else None,
                'tenant': tenant if tenant else None,
                'site': site if site else None,
                'os': os if os else None,
                'tenant_url': (tenant.url).replace('/api/', '/') if tenant is not None else '',
                'ip_url': (ip.url).replace('/api/', '/') if ip is not None else '',
                'name_url': (attr.url).replace('/api/', '/') if attr.url is not None else '',
                'site_url': (site.url).replace('/api/', '/') if site is not None else '',
            }
    except Exception:
        dev_dict = {
            'name': hostname,
            'ip': 'нет в IPAM',
            'tenant': 'нет в IPAM',
            'site': 'нет в IPAM',
            'os': 'нет в IPAM',
            'tenant_url': '',
            'ip_url': '',
            'name_url': '',
            'site_url': '',
        }

    return dev_dict


def get_data_from_ipam(ip, connect=None):  # noqa: C901
    if connect is None:
        nb = connect_ipam()
    else:
        nb = connect
    tenant = None
    region = None
    prefix = None
    aggregate = None
    try:
        q = nb.ipam.ip_addresses.get(address=ip)
        try:
            prefix = nb.ipam.prefixes.get(q=ip)
        except:  # noqa: E722
            prefixes = nb.ipam.prefixes.filter(q=ip)
            for item in prefixes:
                prefix = item
                break
        aggregate = nb.ipam.aggregates.get(q=prefix.prefix)
        try:
            tenant = nb.tenancy.tenants.get(name=q.tenant)
        except:  # noqa: E722
            try:
                tenant_name = None
                for attr in aggregate:
                    if tenant_name is not None:
                        break
                    if 'tenant' in attr:
                        tenant_name = aggregate.tenant.name
                        break
                    else:
                        for attr in prefix:
                            if 'tenant' in attr:
                                tenant_name = prefix.tenant.name
                                break
                tenant = nb.tenancy.tenants.get(name=tenant_name)
            except:  # noqa: E722
                print('Учреждения не закреплено за адресом')
        for address in nb.dcim.sites.filter(tenant_id=tenant.id):
            addresses = address
            if addresses.region is None:
                continue
            else:
                region = addresses.region
                break
    except:  # noqa: E722
        aggregate = nb.ipam.aggregates.get(q=ip)
        q = None
    if q is None:
        res = {
            'ip': ip,
            'prefix': prefix if prefix is not None else '-',
            'aggregate': aggregate if aggregate is not None else '-',
            'region': region if region is not None else '-',
            'tenant': tenant if tenant is not None else '-',
            'tenant_url': (tenant.url).replace('/api/', '/') if tenant is not None else '#',
            'ip_url': '#',
            'prefix_url': (prefix.url).replace('/api/', '/') if prefix is not None else '#',
            'aggregate_url': (aggregate.url).replace('/api/', '/') if aggregate is not None else '#',
            'region_url': (region.url).replace('/api/', '/') if region is not None else '#',
        }
    else:
        res = {
            'ip': ip,
            'prefix': prefix,
            'aggregate': aggregate,
            'region': region,
            'tenant': tenant,
            'tenant_url': (tenant.url).replace('/api/', '/') if tenant is not None else '#',
            'ip_url': (q.url).replace('/api/', '/') if q is not None else '#',
            'prefix_url': (prefix.url).replace('/api/', '/') if prefix is not None else '#',
            'aggregate_url': (aggregate.url).replace('/api/', '/') if aggregate is not None else '#',
            'region_url': (region.url).replace('/api/', '/') if region is not None else '#',
        }
    return res
