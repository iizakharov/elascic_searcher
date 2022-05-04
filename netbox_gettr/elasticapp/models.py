from django.db import models
from django.urls import reverse


class Searcher(models.Model):
    name = models.CharField(verbose_name='Название запроса', max_length=250, blank=True)
    ip = models.CharField(verbose_name="IP адрес", max_length=15, null=True, name='ip')
    days = models.IntegerField('Колличество дней', null=True, name='days')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.uploaded_at

    def get_absolute_url(self):
        return reverse('main:request', kwargs={'pk': self.pk})

    def save(self, *args, **kwargs):
        self.name = f'{self.ip}_{self.uploaded_at}'
        super().save(*args, **kwargs)


class MacHistory(models.Model):
    name = models.CharField(verbose_name='Название запроса', max_length=250, blank=True)
    mac = models.CharField(verbose_name="MAC адрес", max_length=15, null=True, name='mac')
    days = models.IntegerField('Колличество дней', null=True, name='days')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.uploaded_at

    def get_absolute_url(self):
        return reverse('main:mac_address', kwargs={'pk': self.pk})

    def save(self, *args, **kwargs):
        self.name = f'{self.mac}_{self.uploaded_at}'
        super().save(*args, **kwargs)


class Hostname(models.Model):
    name = models.CharField(verbose_name='Название запроса', max_length=250, blank=True)
    hostname = models.CharField(verbose_name="Hostname", max_length=100, null=True, name='hostname')
    days = models.IntegerField('Колличество дней', null=True, name='days')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.uploaded_at

    def get_absolute_url(self):
        return reverse('main:hostname', kwargs={'pk': self.pk})

    def save(self, *args, **kwargs):
        self.name = f'{self.hostname}_{self.uploaded_at}'
        super().save(*args, **kwargs)


class Ioc(models.Model):
    name = models.CharField(verbose_name='Название', max_length=250, blank=True)
    data = models.TextField(verbose_name="Список IP", blank=True, null=True)
    document = models.FileField(upload_to='documents/', blank=True, null=True)
    days = models.IntegerField('Колличество дней', null=True, name='days')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('main:ioc', kwargs={'pk': self.pk})

    def save(self, *args, **kwargs):
        self.name = f'{self.uploaded_at}'
        super().save(*args, **kwargs)
