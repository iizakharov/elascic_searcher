from datetime import timedelta, datetime

from elasticapp.utils import get_hits, new_parse_json
from elasticapp.workbook import Incidents


def make_index(days):
    index_arr = []
    for day in range(days):
        delta = timedelta(days=day)
        now = datetime.now()
        date = now - delta
        index_arr.append('osquery' + date.strftime('-%Y.%m.%d'))
    return index_arr


def get_incidents(indexes, filter_name, es):
    a = Incidents(filter_name)
    result = {}
    items = []
    for index in indexes:
        hits = get_hits(es, index, a.get_index_form())
        if not hits:
            print(f'{index} - нет вхождений')
            continue
        elif hits == 'Out of index':
            break
        print(index, 'Done!')
        for hit in hits:
            _id = hit['_id']
            result = new_parse_json(hit['_source'])
            result['index_id'] = _id
            # change date
            date = result['@timestamp'].split('.')[0]
            date = datetime.strptime(date, '%Y-%m-%dT%H:%M:%S')
            result['@timestamp'] = datetime.strftime(date, '%Y-%m-%d %H:%M')

            items.append(result)
    return items
