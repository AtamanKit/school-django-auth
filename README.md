# Develop a RESTful API for Authentication

### Objective
Imagine you're building a secure gateway for an application using Django and Django REST Framework. Your mission is to create a REST API that handles user authentication and authorization. Here's what it will do:

It will warmly welcome new users by allowing them to register. Once they're part of the system, they can log in with ease. For added security, users will have the ability to refresh their tokens to stay authenticated.

If a user decides to take a break, they can log out anytime. The system focuses on keeping the process simple, secure, and user-friendly, ensuring a smooth experience for all users.

To install the dependencies and tools for this project, we will use the [uv package manager](https://docs.astral.sh/uv/). First, we will initialize a new project then to add all the necessary dependencies.

```

uv init
uv add django djangorestframework pyjwt django-constance redis

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
    "redis>=5.2.1",
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

Update `settings.py` by adding `rest_framework` and `auth_api` to the `INSTALLED_APPS`:

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

```

To enable authentication and permissions in our Django application, we need to configure the Django REST Framework settings. These settings specify the authentication method and the default permissions for API access.

Add the following code to `settings.py`:

```

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'auth_api.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}

```

As you probably noticed, the **django-constance** and **redis** dependencies have been added to the project. Well, **Django-Constance** is a powerful tool that allows you to manage dynamic configuration settings directly in your Django application without the need for database migrations. When combined with **Redis**, a high-performance in-memory data store, it ensures fast and efficient storage and retrieval of these configurations.

**Redis** interacts with **Django-Constance** by serving as the backend where configuration values are stored. This setup makes updates to configurations instantaneous and highly scalable, perfect for dynamic, high-demand applications.

To configure token lifetimes dynamically, add the following to your `settings.py`:

```

CONSTANCE_CONFIG = {
    'ACCESS_TOKEN_LIFETIME': (30 * 60 * 60, 'Access token lifetime in seconds'),
    'REFRESH_TOKEN_LIFETIME': (30 * 24 * 60 * 60, 'Refresh token lifetime in seconds'),
}

```

### What It Does:
**Access tokens** and **refresh tokens** are essential components of modern authentication systems, particularly when working with stateless APIs. Here's a quick overview:

**Access Tokens** are used to authenticate API requests on behalf of a user, typically short-lived for security purposes (e.g., the `ACCESS_TOKEN_LIFETIME` in this example is set to 30 hours). They are passed with each API request, usually in the Authorization header to prove the user’s identity and permissions. If compromised, it’s only valid for a short time, minimizing potential damage.

**Refresh Tokens** are used to obtain new access tokens without requiring the user to log in again, they are longer-lived than access tokens (e.g., the `REFRESH_TOKEN_LIFETIME` here is 30 days).

To implement **refresh tokens** in our Django app, we’ll add a model to store them. Open `auth_api/models.py` and add the following code:

```

import uuid
from django.conf import settings

class RefreshToken(models.Model):
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='refresh_tokens')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_valid(self):
        from django.utils.timezone import now
        return now() < self.expires_at

```

To build a Django application that requires more flexibility in managing users than the default `User` model offers, we will use a `custom user` model. This approach allows you to define exactly how users should be represented and authenticated in your application.

In `auth_api/models.py`, add the following code:

```

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from django.db import models


# Custom user creation
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, username='', **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if not extra_fields.get('is_staff'):
            raise ValueError(_('Superuser must have is_staff=True'))
        if not extra_fields.get('is_superuser'):
            raise ValueError(_('Superuser must have is_superuser=True'))

        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, blank=True, default='')
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

```

### What’s Going On Here?
**CustomUserManager**: Think of this as the "manager" for creating users. It defines the rules for adding both regular users and superusers, ensuring everything is set up correctly.
**CustomUser**: This is the heart of your user model. Instead of relying on usernames, it uses email as the unique identifier (USERNAME_FIELD). It's a more modern and flexible way to manage user accounts.

With this setup, you can easily add or adjust fields like first_name, last_name, or any other details specific to your app's needs.

The complete code of `auth_api/models.py` should look like this:

```

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils.translation import gettext_lazy as _
import uuid
from django.conf import settings
from django.db import models


# Custom user creation
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, username='', **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if not extra_fields.get('is_staff'):
            raise ValueError(_('Superuser must have is_staff=True'))
        if not extra_fields.get('is_superuser'):
            raise ValueError(_('Superuser must have is_superuser=True'))

        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, blank=True, default='')
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email


# Refresh token class
class RefreshToken(models.Model):
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='refresh_tokens')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_valid(self):
        from django.utils.timezone import now
        return now() < self.expires_at

```

To use a custom user model in your Django application, you need to tell Django which model to use. This is done by setting the `AUTH_USER_MODEL` configuration in `settings.py`.

Add the following line to your `settings.py`:

```

AUTH_USER_MODEL = 'auth_api.CustomUser'

```

To handle JWT-based authentication in our application, we’ll create a custom authentication class. This class will verify tokens included in API requests and authenticate users based on them.

Create a new file, `auth_api/authentication.py`, and insert the following code:

```

import jwt
from django.conf import settings
from .models import CustomUser
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None

        try:
            prefix, token = auth_header.split()
            if prefix != 'Bearer':
                raise AuthenticationFailed('Invalid token prefix')

            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=['HS256'])
            user = CustomUser.objects.get(id=payload['user_id'])
            return (user, None)
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token expired!!!!!!')
        except jwt.DecodeError:
            raise AuthenticationFailed('Invalid token')
        except (jwt.InvalidTokenError, CustomUser.DoesNotExist):
            raise AuthenticationFailed('Invalid credentials')

```

In the following we will create serializers to handle user data and authentication workflows in a Django REST Framework (DRF) application. Serializers simplify the process of converting complex data, such as Django models, into JSON format for APIs and validating incoming data.

Here’s what each serializer does:

* `UserSerializer`: Used for retrieving and displaying basic user details like id, username, and email.
* `RegisterSerializer`: Manages user registration by accepting email and password, ensuring passwords remain secure and write-only.
* `LoginSerializer`: Validates user login credentials by checking the provided email and password.

These serializers form the backbone of your API’s user management system, making it easier to interact with the `CustomUser` model.

Create a file `auth_api/serializers.py` and insert:

```

from .models import CustomUser
from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email']


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            validated_data['email'], validated_data['password'])

        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

```

Now let's move to the implementation of the API views for user authentication and profile management. These views will handle key operations such as user registration, login, token refresh, logout, and profile updates, forming the core of our authentication system.

Here’s a breakdown of the key components:

* `create_access_token`: A helper function that generates a JWT access token with a specific expiration time, dynamically fetched from django-constance settings.
* `RegisterView`: Handles user registration. It validates incoming data, saves the new user, and returns their details upon successful registration.
* `LoginView`: Authenticates users using their email and password. On success, it issues an access token and a refresh token, enabling seamless session management.
* `RefreshView`: Allows users to renew their access token using a valid refresh token. It generates new tokens and invalidates the old refresh token.
* `LogoutView`: Logs users out by deleting their refresh token, ensuring the session is terminated securely.
* `ProfileView`: Provides authenticated users with the ability to view (GET) or update (PUT) their profile information.:

```

import jwt
import datetime
from django.conf import settings
from django.utils.timezone import now, timedelta
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import authenticate
from constance import config
from .models import RefreshToken
from .serializers import UserSerializer, RegisterSerializer, LoginSerializer


def create_access_token(user):
    print(f"ACCESS_TOKEN_LIFETIME: {config.ACCESS_TOKEN_LIFETIME}")
    return jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.now(datetime.timezone.utc) + timedelta(seconds=config.ACCESS_TOKEN_LIFETIME)
    }, settings.SECRET_KEY, algorithm='HS256')


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(UserSerializer(user).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(
                email=serializer.validated_data['email'], password=serializer.validated_data['password'])
            if user:
                access_token = create_access_token(user)
                refresh_token = RefreshToken.objects.create(
                    user=user,
                    expires_at=now() + timedelta(seconds=config.REFRESH_TOKEN_LIFETIME)
                )

                return Response({
                    'access_token': access_token,
                    'refresh_token': refresh_token.token
                }, status=status.HTTP_200_OK)

        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class RefreshView(APIView):
    permission_classes = [AllowAny]

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
    permission_classes = [AllowAny]

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
        serializer = UserSerializer(
            request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

```

Create a file `auth_api/urls.py` and define the URL routing for the application:

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
### Database creation
To set up our database with the models we've defined, we need to perform two steps: create `migrations` and apply `migrations`.

**Create Migrations:**  
**Migrations** are files that Django generates to describe the changes in your models (e.g., creating or updating database tables).
To create `migrations`, run the following command:

```

uv run manage.py makemigrations

```

This command inspects your models and generates the migration files needed to apply these changes to the database.

### Apply Migrations:

Once the migration files are created, we need to apply them to the database. This step ensures that the database schema matches the model definitions.
To apply the `migrations`, run:

```

uv run manage.py migrate

```

For this simple development purpose, we are using the sqlite database, which is lightweight and requires no additional configuration.

### Putting Our Code into Action
First let's start the server. Using the `uv` manager the, open the terminal and write:

```

uv run manage.py runserver

```

The output will be:

```

Watching for file changes with StatReloader
Performing system checks...

System check identified no issues (0 silenced).
January 22, 2025 - 10:45:42
Django version 5.1.4, using settings 'auth_project.settings'
Starting development server at http://127.0.0.1:8000/
Quit the server with CONTROL-C.

```

Remember, at the beginning, we talked about **Redis**, a necessary dependency for **Django Constance** to work. Depending on your system (Ubuntu or WSL), the installation process would look like this:

```

sudo apt update
sudo apt install redis

```

Check on Ubuntu if the **Redis** server is running:

```

sudo systemctl status redis

```

It should be in `active` status. If it is not active, start it with:

```

sudo systemctl start redis

```

If you are an WSL user, start the service in another terminal window by running:

```

redis-server

```

Open yet another terminal window, and let's verify our endpoinds

**User registration**

```

curl -X POST http://localhost:8000 -d '{"email": "first@example.com", "password": "securepassword"}' -H "Content-Type: application/json"

```