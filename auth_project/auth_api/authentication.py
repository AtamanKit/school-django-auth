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
