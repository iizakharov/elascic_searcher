from copy import deepcopy

from django.shortcuts import render

from elasticapp.utils import connect_elk
from elasticapp.workbook import INCIDENTS_FORM
from incidents.utils import get_incidents, make_index


def main(request):
    context = {
        'title': 'Инциденты',
        'result': None
    }
    indexes = make_index(3)
    result = {
        'mssec': {},
        'intranet': {},
        'messenger': {}
    }
    es = connect_elk()
    for filter_name in result.keys():
        res = get_incidents(indexes, filter_name, es)
        if not res:
            continue
        for i in range(len(res)):
            form = deepcopy(INCIDENTS_FORM[filter_name])
            for key, val in res[i].items():
                if key in form.keys():
                    form[key] = val
            result[filter_name][i + 1] = form
        # print(json.dumps(result, ensure_ascii=False, indent=4))
        context[filter_name] = result[filter_name]
        context['result'] = True

    return render(request, 'incidents/incidents.html', context)
