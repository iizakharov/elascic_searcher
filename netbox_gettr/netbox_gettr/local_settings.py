from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = ''
DEBUG = True
ALLOWED_HOSTS = ['*']
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': str(BASE_DIR / 'db.sqlite3'),
    }
}
ELK_USER = ''
ELK_PASS = ''
ELK_URL = ''
IPAM_TOKEN = ""
IPAM_URL = ''
