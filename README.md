# Django_Microsoft_and_Google_SSO
Setup Single Sign-On (SSO) with Django

# Uses
### Clone the repo and go to `Django_Microsoft_and_Google_SSO` folder
```bash
git clone https://github.com/Shoony0/Django_Microsoft_and_Google_SSO.git
cd Django_Microsoft_and_Google_SSO
```

### Create and activate the env
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Migrate the tables
```bash
python manage.py migrate
```

### Run the Django Server
```bash
python manage.py runserver
```

### For Microsoft SSO Login URL
```bash
http://localhost:8000/api/auth/microsoft/login/
```

### For Google SSO Login URL
```bash
http://localhost:8000/api/auth/google/login/
```
