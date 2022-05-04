from django.urls import path
import elasticapp.views as elasticapp

app_name = 'elasticapp'

urlpatterns = [
    path('searcher/', elasticapp.main, name='main'),
    path('report', elasticapp.report, name='report'),
    path('request/<int:pk>', elasticapp.RequestDetailView.as_view(), name='request'),
    path('mac/', elasticapp.mac_search, name='mac'),
    path('mac_history/', elasticapp.mac_history, name='mac_history'),
    path('mac/<int:pk>', elasticapp.RequestDetailView.as_view(), name='mac_address'),
    path('hostname/', elasticapp.hostname_search, name='hostname'),
    path('hostname/result', elasticapp.hostname_result, name='hostname_result'),
    path('ioc/', elasticapp.ioc_ip_search, name='ioc'),
    path('ioc/result', elasticapp.ioc_result, name='ioc_result'),


]
