from django.urls import path
import incidents.views as incidents

app_name = 'incidents'

urlpatterns = [
    path('', incidents.main, name='main'),
    # path('report', incidents.report, name='report'),


]
