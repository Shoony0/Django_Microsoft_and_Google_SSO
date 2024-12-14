from django.urls import path
from .views import microsoft_login, microsoft_callback, google_login, google_callback


urlpatterns = [
    path('auth/microsoft/login/', microsoft_login, name='microsoft_login'), # http://localhost:8000/api/auth/microsoft/login/
    path('auth/microsoft/callback/', microsoft_callback, name='microsoft_callback'),
    path("auth/google/login/", google_login, name="google_login"), # http://localhost:8000/api/auth/google/login/
    path("auth/google/callback/", google_callback, name="google_callback"),
]
