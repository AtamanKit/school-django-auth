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
    return jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + timedelta(seconds=config.ACCESS_TOKEN_LIFETIME)
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
        serializer = UserSerializer(
            request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
