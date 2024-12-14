import urllib.parse
from django.http import HttpResponseRedirect
from django.conf import settings
from django.http import JsonResponse
from django.contrib.auth import get_user_model # If used custom user model
User = get_user_model()
import requests
from google.oauth2 import id_token
import google.auth.transport.requests
from rest_framework.views import APIView
from rest_framework.response import Response
from .authentication import MicrosoftAuthentication, GoogleAuthentication
from rest_framework.permissions import IsAuthenticated

from rest_framework_simplejwt.tokens import RefreshToken  # Optional, if using JWTs

def microsoft_login(request):
    auth_url = f"{settings.MICROSOFT_AUTHORITY}/oauth2/v2.0/authorize"
    params = {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
        "response_mode": "query",
        "scope": " ".join(settings.MICROSOFT_SCOPES),
        "state": "560008",  # Optional: Add your own state handling here
    }
    login_url = f"{auth_url}?{urllib.parse.urlencode(params)}"
    return HttpResponseRedirect(login_url)


def microsoft_callback(request):
    code = request.GET.get('code', None)
    if not code:
        return JsonResponse({"error": "No code provided"}, status=400)

    # Exchange code for access token
    token_url = f"{settings.MICROSOFT_AUTHORITY}/oauth2/v2.0/token"
    data = {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "scope": " ".join(settings.MICROSOFT_SCOPES),
        "code": code,
        "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
        "grant_type": "authorization_code",
        "client_secret": settings.MICROSOFT_CLIENT_SECRET,
    }
    response = requests.post(token_url, data=data)
    # Log the response for debugging
    print(f"Token response status: {response.status_code}")
    print(f"Token response body: {response.text}")

    if response.status_code != 200:
        return JsonResponse({"error": "Failed to fetch token"}, status=response.status_code)

    token_data = response.json()
    access_token = token_data.get("access_token")

    # Use the access token to fetch user info
    user_info_url = "https://graph.microsoft.com/v1.0/me"
    headers = {"Authorization": f"Bearer {access_token}"}
    user_info_response = requests.get(user_info_url, headers=headers)


    if user_info_response.status_code != 200:
        return JsonResponse({"error": "Failed to fetch user info"}, status=user_info_response.status_code)
    
    user_info = user_info_response.json()
    

    # Check if the user already exists, otherwise create one
    user, created = User.objects.get_or_create(email=user_info["mail"], defaults={
        "first_name": user_info["givenName"],
        "last_name": user_info["surname"],
        "username": user_info["mail"].split('@')[0],  # Optional: derive username
    })
    user.set_password("test1234")
    user.save()

    # Optional: Generate a token (e.g., JWT or session)
    refresh = RefreshToken.for_user(user)

    print(f"user_details: {user.__dict__}")

    # Here you can handle user creation or authentication in Django
    return JsonResponse({"user": user_info, "access_token": str(access_token), "refresh": str(refresh)})




def google_login(request):
    auth_url = f"{settings.GOOGLE_AUTHORITY}/v2/auth"
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "response_type": "code",
        "access_type": "offline",
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "scope": " ".join(settings.GOOGLE_SCOPES),
        "include_granted_scopes": "true",  
        "state": "560008",  # state_parameter_passthrough_value
    }
    login_url = f"{auth_url}?{urllib.parse.urlencode(params)}"
    return HttpResponseRedirect(login_url)


def google_callback(request):
    code = request.GET.get('code', None)
    print('request.GET')
    print(request.GET)
    if not code:
        return JsonResponse({"error": "No code provided"}, status=400)
    
    client_id = settings.GOOGLE_CLIENT_ID
    # Exchange code for access token
    token_url = f"{settings.GOOGLE_AUTHORITY}/token"

    data = {
        "client_id": client_id,
        "scope": " ".join(settings.GOOGLE_SCOPES),
        "code": code,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
    }

    response = requests.post(token_url, data=data)
    print("Done")
    # Log the response for debugging
    print(f"Token response status: {response.status_code}")
    print(f"Token response body: {response.text}")

    if response.status_code != 200:
        return JsonResponse({"error": "Failed to fetch token"}, status=response.status_code)

    token_data = response.json()
    token = token_data.get("id_token")

    try:
        id_info = id_token.verify_oauth2_token(token, google.auth.transport.requests.Request(), client_id)
    except ValueError:
        return JsonResponse({"error": "Failed to fetch user info"}, status=id_info.status_code)
    
    print(f"{id_info = }")
    # Extract user information from the token
    email = id_info.get("email")
    first_name = id_info.get("given_name", "")
    last_name = id_info.get("family_name", "")

    # Check if the user already exists, otherwise create one
    user, created = User.objects.get_or_create(email=email, defaults={
        "first_name": first_name,
        "last_name": last_name,
        "username": email.split('@')[0],  # Optional: derive username
    })
    user.set_password("test1234")
    user.save()

    # Optional: Generate a token (e.g., JWT or session)
    refresh = RefreshToken.for_user(user)


    print(f"user_details: {user.__dict__}")

    # Here you can handle user creation or authentication in Django
    return JsonResponse({"user": id_info, "access_token": token, "refresh": str(refresh)})
    
    



class MicrosoftProtectedView(APIView):
    authentication_classes = [MicrosoftAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "You are authenticated", "user": request.user})


class GoogleProtectedView(APIView):
    authentication_classes = [GoogleAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "You are authenticated", "user": request.user})


