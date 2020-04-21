from rest_framework import generics
from rest_framework import permissions as base_permissions

import api.permissions as permissions
from api.models import User, Jog, AuthRole
from api.serializers import UserSerializer, JogSerializer, AuthRoleSerializer

class UserList(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsCreatingHasAccessOrNoAccess]

class JogList(generics.ListCreateAPIView):
    queryset = Jog.objects.all()
    serializer_class = JogSerializer
    permission_classes = [base_permissions.IsAuthenticatedOrReadOnly]

class AuthRoleList(generics.ListCreateAPIView):
    queryset = AuthRole.objects.all()
    serializer_class = AuthRoleSerializer
    permission_classes = [permissions.IsAtLeastManagerOrNoAccess]

class UserDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [base_permissions.IsAuthenticatedOrReadOnly]

class JogDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Jog.objects.all()
    serializer_class = JogSerializer
    permission_classes = [base_permissions.IsAuthenticatedOrReadOnly]

class AuthRoleDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = AuthRole.objects.all()
    serializer_class = AuthRoleSerializer
    permission_classes = [permissions.IsAtLeastManagerOrNoAccess]



