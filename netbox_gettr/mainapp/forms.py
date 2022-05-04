from django import forms
from .models import Document, Search


class DocumentForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ('data', 'document')
        widgets = {
            'data': forms.Textarea(attrs={'rows': 10, 'cols': 10}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            self.fields[field_name].label = ''
            self.fields[field_name].widget.attrs.update(
                {'class': 'form-control'})

        self.fields['document'].widget.attrs.update(
            {
                'name': 'document',
                'class': 'form-control-file',
                'accept': ".txt, .csv"
            }
        )

        self.fields['data'].widget.attrs.update(
            {
                'name': 'data',
            }
        )


class SearchForm(forms.ModelForm):
    class Meta:
        model = Search
        # fields = ('ip', 'days')
        fields = "__all__"
        widgets = {
            'ip': forms.TextInput(attrs={
                'id': 'ip',
                'class': 'form-control mr-sm-2',
                'placeholder': 'ip адрес...'
            }),
            # 'days': forms.IntegerField(attrs={
            #     'id': 'days',
            #     'class': 'form-control',
            # })
        }
        labels = {
            'ip': '',
            'days': ''
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            if field_name == 'ip':
                continue
            self.fields[field_name].widget.attrs.update(
                {
                    'class': 'search-days',
                    'name': field_name
                }
            )
