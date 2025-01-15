# Develop a RESTful API for Authentication

### Objective

Develop a REST API for a user authentication and authorization system using Django and Django REST Framework. The system should support user registration, authentication, token refresh, logout, and allow users to retrieve and update their personal information.

To install the dependencies and tools for this project, we will use the [uv package manager](https://docs.astral.sh/uv/). First, we will initialize a new project then to add all the necessary dependencies.

```
uv init
uv add django djangorestframework pyjwt django-constance
```
After initializing the project and adding the dependencies, our `pyproject.toml` file should look like this:

```
[project]
name = "school-django-auth"
version = "0.1.0"
description = "Add your description here"
readme = "README.md"
requires-python = ">=3.13"
dependencies = [
    "django-constance>=4.1.3",
    "django>=5.1.4",
    "djangorestframework>=3.15.2",
    "pyjwt>=2.10.1",
]
```
With the help of `uv` package manager, we can start a new Django project and create an app. Use following commands:
```
uv run django-admin startproject auth_project
cd auth_project
uv run manage.py startapp auth_api
```
After running these commands, the project structure should look like this:
```
├── auth_project
│   ├── auth_api
│   │   ├── admin.py
│   │   ├── apps.py
│   │   ├── __init__.py
│   │   ├── `migrations`
│   │   │   └── __init__.py
│   │   ├── models.py
│   │   ├── tests.py
│   │   └── views.py
│   ├── auth_project
│   │   ├── asgi.py
│   │   ├── __init__.py
│   │   ├── settings.py
│   │   ├── urls.py
│   │   └── wsgi.py
│   └── manage.py
├── hello.py
├── pyproject.toml
├── README.md
└── uv.lock

```
Update `settings.py` by adding `rest_framework` and `auth_api` to the `INSTALLED_APPS` and `CONSTANCE_CONFIG` variable
```
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'rest_framework',
    'auth_app',
]

CONSTANCE_CONFIG = {
    'ACCESS_TOKEN_LIFETIME': (30, 'Access token lifetime in seconds'),
    'REFRESH_TOKEN_LIFETIME': (30 * 24 * 60 * 60, 'Refresh token lifetime in seconds'),  # 30 days
}
```
Create a model for **Refresh Token** in `auth_api/models.py`:
```
import uuid
from django.conf import settings
from django.db import models

class RefreshToken(models.Model):
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="refresh_tokens")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_valid(self):
        from django.utils.timezone import now
        return now() < self.expires_at
```
Create serializers for user registration, login, and profile management in `auth_api/serializers.py`:
```
from django.contrib.auth.models import User
from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(email=validated_data['email'], password=validated_data['password'])
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
```
Implement **views** for the API endpoints in `auth_api/views.py`:
```
import jwt
import datetime
from django.conf import settings
from django.utils.timezone import now, timedelta
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from constance import config
from .models import RefreshToken
from .serializers import UserSerializer, RegisterSerializer, LoginSerializer

def create_access_token(user):
    return jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + timedelta(seconds=config.ACCESS_TOKEN_LIFETIME)
    }, settings.SECRET_KEY, algorithm='HS256')

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(email=serializer.validated_data['email'], password=serializer.validated_data['password'])
            if user:
                access_token = create_access_token(user)
                refresh_token = RefreshToken.objects.create(
                    user=user,
                    expires_at=now() + timedelta(seconds=config.REFRESH_TOKEN_LIFETIME)
                )
                return Response({
                    'access_token': access_token,
                    'refresh_token': str(refresh_token.token)
                }, status=status.HTTP_200_OK)
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class RefreshView(APIView):
    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        try:
            token_obj = RefreshToken.objects.get(token=refresh_token)
            if token_obj.is_valid():
                new_access_token = create_access_token(token_obj.user)
                new_refresh_token = RefreshToken.objects.create(
                    user=token_obj.user,
                    expires_at=now() + timedelta(seconds=config.REFRESH_TOKEN_LIFETIME)
                )
                token_obj.delete()
                return Response({
                    'access_token': new_access_token,
                    'refresh_token': str(new_refresh_token.token)
                })
        except RefreshToken.DoesNotExist:
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        try:
            token_obj = RefreshToken.objects.get(token=refresh_token)
            token_obj.delete()
            return Response({'success': 'User logged out.'}, status=status.HTTP_200_OK)
        except RefreshToken.DoesNotExist:
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserSerializer(request.user).data)

    def put(self, request):
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
```
Set up URLs in `auth_api/urls.py`:
```
from django.urls import path
from .views import RegisterView, LoginView, RefreshView, LogoutView, ProfileView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('refresh/', RefreshView.as_view(), name='refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('me/', ProfileView.as_view(), name='profile'),
]
```
Include these in project's `urls.py`:
```
from django.urls import path, include

urlpatterns = [
    path('api/', include('auth_api.urls')),
]
```
### Putting Our Code into Action
To set up our database with the models we've defined, we need to perform two steps: create `migrations` and apply `migrations`.

**Create Migrations:**

**Migrations** are files that Django generates to describe the changes in your models (e.g., creating or updating database tables).
To create `migrations`, run the following command:
```
uv run manage.py makemigrations
```
This command inspects your models and generates the migration files needed to apply these changes to the database.
Apply Migrations:

Once the migration files are created, we need to apply them to the database. This step ensures that the database schema matches the model definitions.
To apply the `migrations`, run:
```
uv run manage.py migrate
```
For this simple development purpose, we are using the sqlite database, which is lightweight and requires no additional configuration.