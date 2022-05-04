from django.shortcuts import render
from django.views.generic import DetailView

from elasticapp.utils import get_data_from_ipam, search, oqsuery_convert, osquery_po, convert, logstash_convert, \
    kasper_convert
from .forms import DocumentForm
from .models import Document
from .utils import data_parser, checker


def main(request):
    context = {
        'title': 'Гавная',
    }
    return render(request, 'mainapp/index.html', context)


def ip_search(request):
    title = 'Поиск по IP'
    input_form = DocumentForm()
    context = {
        'title': title,
        'input_form': input_form
    }
    return render(request, 'mainapp/ip_search.html', context)


def create_report(request):
    title = 'Отчет'
    result = []
    if request.method == 'POST':
        if request.POST.get('data', False):
            data = request.POST['data']
            result = data_parser(data)
        else:
            data = None
        if request.FILES.get('document', False):
            document = request.FILES['document']
            result = checker(document.name, document)

        else:
            document = None

        context = {
            'result': result,
            'title': title
        }

        return render(request, 'mainapp/report.html', context)

    context = {
        'title': title
    }
    return render(request, 'mainapp/report.html', context)


def SearchView(request):
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


class DocumentDetailView(DetailView):
    """Страница ljrevtynf"""
    model = Document
    queryset = Document.objects.all()
    slug_field = 'url'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = context['document'].uploaded_at
        print(context)
        return context
