from django.urls import path
import mainapp.views as mainapp
import elasticapp.views as elasticapp

app_name = 'mainapp'

urlpatterns = [
    path('', mainapp.main, name='index'),
    path('ip-serach', mainapp.ip_search, name='ip_search'),
    path('create_report', mainapp.create_report, name='create_report'),
    path('document/<int:pk>', mainapp.DocumentDetailView.as_view(), name='document'),
    path('search', elasticapp.report, name='search_form'),
    # path('search', mainapp.SearchView, name='search_form'),
]
