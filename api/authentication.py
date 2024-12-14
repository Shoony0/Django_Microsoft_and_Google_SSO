from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
import requests
from google.oauth2 import id_token
import google.auth.transport.requests
from django.conf import settings


class MicrosoftAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None

        try:
            token = auth_header.split(' ')[1]
            user_info_url = "https://graph.microsoft.com/v1.0/me"
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get(user_info_url, headers=headers)

            if response.status_code != 200:
                raise AuthenticationFailed("Invalid token")

            user_info = response.json()
            return (user_info, None)  # You can replace `None` with a User instance if necessary

        except Exception as e:
            raise AuthenticationFailed("Authentication failed")
        
class GoogleAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None

        try:
            token = auth_header.split(' ')[1]
            client_id = settings.GOOGLE_CLIENT_ID
            id_info = id_token.verify_oauth2_token(token, google.auth.transport.requests.Request(), client_id)
            if id_info["email_verified"]:
                return (id_info, None)  # You can replace `None` with a User instance if necessary
            else:
                raise ValueError("Authentication failed")

        except Exception as e:
            raise AuthenticationFailed("Authentication failed")