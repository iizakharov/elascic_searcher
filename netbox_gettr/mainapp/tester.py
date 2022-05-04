# import operator

import pynetbox


def connect():
    token = "25c6ee2fe7dcf54f1af218a4dbaca235de9b5813"
    url = 'http://10.24.131.204:80'
    print('Connecting to ipsm.mchs.ru')

    nb = pynetbox.api(
        url,
        token=token
    )
    return nb


def get_data_from_ipam(ip):  # noqa: C901
    nb = connect()
    tenant = None
    region = None
    prefix = None
    aggregate = None
    try:
        q = nb.ipam.ip_addresses.get(address=ip)
        prefix = nb.ipam.prefixes.get(q=ip)
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
            region = addresses.region
            break

        print()
    except:  # noqa: E722
        aggregate = nb.ipam.aggregates.get(q=ip)
        q = None
    if q is None:
        res = {
            'ip': ip,
            'prefix': prefix if prefix is not None else 'нет в IPAM',
            'aggregate': aggregate if aggregate is not None else 'нет в IPAM',
            'region': region if region is not None else 'нет в IPAM',
            'tenant': tenant if tenant is not None else 'нет в IPAM',
            'tenant_url': '#',
            'ip_url': '#',
            'prefix_url': '#',
            'aggregate_url': '#',
            'region_url': '#',
        }
    else:
        res = {
            'ip': ip,
            'prefix': prefix,
            'aggregate': aggregate,
            'region': region,
            'tenant': tenant,
            'tenant_url': (tenant.url).replace('/api/', '/'),
            'ip_url': (q.url).replace('/api/', '/'),
            'prefix_url': (prefix.url).replace('/api/', '/'),
            'aggregate_url': (aggregate.url).replace('/api/', '/'),
            'region_url': (region.url).replace('/api/', '/'),
        }
    return res


if __name__ == '__main__':
    # ip = "10.115.140.197"
    ip = '10.48.0.209'
    # res = get_data_from_ipam(ip)
    # print(res)
    di = {
        "15": {
            "@timestamp": "2021-06-21 11:12",
            "region": "48-GU",
            "attack_target_ip": "10.49.9.47",
            "attack_source_ip": "10.49.9.121",
            "p2": "TCP",
            "p1": "Intrusion.Win.MS17-010.o",
            "hdn": "PC402-2",
            "p4": "445",
            "etdn": "Обнаружена сетевая атака"
        },
        "16": {
            "@timestamp": "2021-06-21 11:35",
            "region": "48-GU",
            "attack_target_ip": "10.49.9.53",
            "attack_source_ip": "10.49.9.121",
            "p2": "TCP",
            "p1": "Intrusion.Win.MS17-010.o",
            "hdn": "KIRINA404",
            "p4": "445",
            "etdn": "Обнаружена сетевая атака"
        },
        "17": {
            "@timestamp": "2021-06-21 11:31",
            "region": "48-GU",
            "attack_target_ip": "10.49.9.132",
            "attack_source_ip": "10.49.9.121",
            "p2": "TCP",
            "p1": "Intrusion.Win.MS17-010.o",
            "hdn": "PC313-1",
            "p4": "445",
            "etdn": "Обнаружена сетевая атака"
        }
    }

    my_list1 = [{"name": "Adwaita", "roll": 100}, {"name": "Aadrika", "roll": 234}, {"name": "Sakya", "roll": 23}]
    print("The list is sorted by roll: ")
    print(sorted(di, key=lambda i: i['@timestamp']))
    print("\r")
    print("The list is sorted by name and roll: ")
    print(sorted(my_list1, key=lambda i: (i['@timestamp'], i['region'])))
    print("\r")
    print("The list is sorted by roll in descending order: ")
    print(sorted(my_list1, key=lambda i: i['@timestamp'], reverse=True))
