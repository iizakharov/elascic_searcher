from django import forms
from .models import Searcher, MacHistory, Hostname, Ioc


class SearcherForm(forms.ModelForm):
    class Meta:
        model = Searcher
        fields = ('ip', 'days')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            # self.fields[field_name].label = ''
            self.fields[field_name].widget.attrs.update(
                {
                    'class': 'form-control',
                    'name': field_name
                 }
            )
        self.fields['ip'].label = 'IP адрес'
        self.fields['days'].label = 'За какое колличество дней показать результат:'


class MacHistoryForm(forms.ModelForm):
    class Meta:
        model = MacHistory
        fields = ('mac', 'days')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            self.fields[field_name].widget.attrs.update(
                {
                    'class': 'form-control',
                    'name': field_name
                 }
            )
        self.fields['mac'].label = 'MAC адрес'
        self.fields['days'].label = 'За какое колличество дней показать результат:'


class HostnameForm(forms.ModelForm):
    class Meta:
        model = Hostname
        fields = ('hostname', 'days')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            self.fields[field_name].widget.attrs.update(
                {
                    'class': 'form-control',
                    'name': field_name
                 }
            )
        self.fields['hostname'].label = 'Hostname'
        self.fields['days'].label = 'За какое колличество дней показать результат:'


class IocForm(forms.ModelForm):
    class Meta:
        model = Ioc
        fields = ('data', 'document', 'days')
        widgets = {
            'data': forms.Textarea(attrs={'rows': 10, 'cols': 10}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            self.fields[field_name].widget.attrs.update(
                {
                    'class': 'form-control',
                    'name': field_name
                }
            )

        self.fields['document'].widget.attrs.update(
            {
                'class': 'form-control-file',
                'accept': ".txt, .csv"
            }
        )

        self.fields['data'].label = 'Список IP'
        self.fields['document'].label = 'Файл со списком IP'
        self.fields['days'].label = 'За какое колличество дней показать результат:'
