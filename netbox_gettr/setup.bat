pip install -r requirements.txt
pause
python manage.py makemigrations
pause
python manage.py migrate
pause
python manage.py runserver 0.0.0.0:8002
pause