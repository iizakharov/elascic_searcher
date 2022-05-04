#  from django.contrib.auth.decorators import login_required
# from django.http import HttpResponseRedirect
import json

from django.shortcuts import render
# from django.urls import reverse
from django.views.generic import DetailView

from .forms import SearcherForm, MacHistoryForm, HostnameForm, IocForm
from mainapp.models import Document
from .utils import search, convert, get_data_from_ipam, get_hostmane_ipam, oqsuery_convert, ioc_search, \
    logstash_convert, kasper_convert, osquery_ioc_convert, osquery_po


# @login_required
def main(request):
    title = 'Глобальный поиск'
    context = {
        'title': title,
        'searcher_form': SearcherForm()
    }
    return render(request, 'elasticapp/searcher.html', context)


# @login_required
def report(request):
    context = {
        'title': 'Отчет',
        'ipam_data': None,
        'po': None
    }
    all_index = {
        "osquery": {
            'data': None,
            'po': None
        },
        "logstash": None,
        "kasper": None,
        "dhcp": None
    }
    if request.method == 'POST':
        if request.POST.get('ip', False) and request.POST.get('days', False):
            ip = request.POST['ip']
            days = int(request.POST['days'])
            context['result'] = True
        else:
            ip, days = None, None

        context["ipam_data"] = get_data_from_ipam(ip)
        for index_name in all_index.keys():
            res = {}
            _res = {}
            data = search(ip, days, index_name)
            if not data:
                continue
            else:
                step = 0
                for obj in data:
                    step += 1
                    if 'osquery' in index_name:
                        res[step], _ = oqsuery_convert(obj, index_name)
                        _res[step] = osquery_po(_)
                        all_index[index_name]['data'], all_index[index_name]['po'] = res, _res
                    elif 'logstash' in index_name:
                        res[step] = convert(obj, index_name)
                        # print(json.dumps(res, ensure_ascii=False, indent=4))
                        # res[step] = logstash_convert(res[step])
                    elif 'kasper' in index_name:
                        res[step] = convert(obj, index_name)
                        # print(json.dumps(res, ensure_ascii=False, indent=4))
                        res[step] = kasper_convert(res[step])
                    else:
                        res[step] = convert(obj, index_name)
                        all_index[index_name] = res

                if 'osquery' in index_name and all_index['osquery']['po'] is not None:
                    context[index_name], context['po'] = res, _res
                else:
                    context[index_name] = res

        return render(request, 'elasticapp/report.html', context)

    return render(request, 'elasticapp/report.html', context)


# @login_required
def mac_search(request):
    title = 'Поиск MAC адреса'
    input_form = MacHistoryForm()
    context = {
        'title': title,
        'mac_history_form': input_form
    }
    return render(request, 'elasticapp/mac_search.html', context)


# @login_required
def mac_history(request):
    index_name = 'dhcp'
    context = {
        'title': 'История MAC',
    }
    if request.method == 'POST':
        if request.POST.get('mac', False) and request.POST.get('days', False):
            mac = request.POST['mac']
            days = int(request.POST['days'])
            context['result'] = mac
        else:
            mac, days = None, None

        history_data = {mac: {}}
        ip_set = []
        data = search(mac, days, index_name)
        step = 0
        for obj in data:
            step += 1
            _res = convert(obj, index_name)
            time = _res['@timestamp']
            history_data[mac][time] = {
                'ip': _res['IP_Address'] if _res['IP_Address'] else None,
                'Hostname': _res["hostname"] if _res["hostname"] else None,
            }
            ip_set.append(_res['IP_Address'])
        count = len(set(ip_set))
        # print(json.dumps(history_data, ensure_ascii=False, indent=4))
        context[index_name] = history_data
        context['count'] = count

        return render(request, 'elasticapp/mac_history.html', context)

    return render(request, 'elasticapp/mac_history.html', context)


# @login_required
def hostname_search(request):
    title = 'Поиск по Hostname'
    input_form = HostnameForm()
    context = {
        'title': title,
        'hostname_form': input_form
    }
    return render(request, 'elasticapp/hostname_search.html', context)


# @login_required
def hostname_result(request):
    context = {
        'title': 'Отчет',
        'ipam_data': None
    }
    all_index = {
        "osquery": None,
        "logstash": None,
        "kasper": None,
        "dhcp": None
    }
    if request.method == 'POST':
        if request.POST.get('hostname', False) and request.POST.get('days', False):
            hostname = request.POST['hostname']
            days = int(request.POST['days'])
            context['result'] = True
        else:
            hostname, days = None, None

        context["ipam_data"] = get_hostmane_ipam(hostname)
        for index_name in all_index.keys():
            res = {}
            data = search(hostname, days, index_name, any_filter=True)
            if not data:
                continue
            else:
                step = 0
                for obj in data:
                    step += 1
                    res[step] = convert(obj, index_name)
                    # print(json.dumps(res, ensure_ascii=False, indent=4))
                    all_index[index_name] = res
                context[index_name] = res
        # print(json.dumps(context, ensure_ascii=False, indent=4))
        return render(request, 'elasticapp/report_hostname.html', context)

    return render(request, 'elasticapp/report_hostname.html', context)


def ioc_ip_search(request):
    title = 'Поиск IOC по IP'
    input_form = IocForm()
    context = {
        'title': title,
        'ioc_input_form': input_form
    }
    return render(request, 'elasticapp/ioc_search.html', context)


def ioc_result(request):
    context = {
        'title': 'Отчет IOC',
    }
    all_index = {
        "osquery": None,
        "filebeat": None,
    }
    if request.method == 'POST':
        if request.POST.get('data', False) and request.POST.get('days', False):
            data = request.POST['data']
            days = int(request.POST['days'])
            context['result'] = True

            for index_name in all_index.keys():
                res = {}
                _data = ioc_search(data, days, index_name)
                if not _data:
                    continue
                else:
                    step = 0
                    for obj in _data:
                        step += 1
                        # print(json.dumps(obj, ensure_ascii=False, indent=4))
                        res[step] = convert(obj, index_name, ioc=True)
                        if 'filebeat' not in index_name:
                            res[step] = osquery_ioc_convert(res[step])
                        all_index[index_name] = res

                    context[index_name] = res

        elif request.FILES.get('document', False) and request.POST.get('days', False):
            document = request.FILES['document']  # noqa: F841
            # result = checker(document.name, document)

        return render(request, 'elasticapp/ioc_report.html', context)

    return render(request, 'elasticapp/ioc_report.html', context)


class RequestDetailView(DetailView):
    """Страница ljrevtynf"""
    model = Document
    queryset = Document.objects.all()
    slug_field = 'url'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = context['document'].uploaded_at
        print(context)
        return context
