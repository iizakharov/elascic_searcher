from django.db import models
from django.urls import reverse


class Document(models.Model):
    name = models.CharField(verbose_name='Название', max_length=250, blank=True)
    data = models.TextField(verbose_name="Список IP", blank=True, null=True)
    document = models.FileField(upload_to='documents/', blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('main:document', kwargs={'pk': self.pk})


class Search(models.Model):
    """Поиск в шапке"""
    ip = models.CharField('IP адрес', max_length=15, name='ip')
    days = models.IntegerField('Колличество дней', default=1, name='days')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip


class Document1(models.Model):
    docfile = models.FileField(upload_to='documents')


class DocumentEntry(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    field = models.CharField(max_length=250, default="TEST")
