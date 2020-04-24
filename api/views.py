from rest_framework import generics

from api import permissions
from api.models import User, Jog, AuthRole
from api.serializers import UserSerializer, JogSerializer, AuthRoleSerializer

class UserList(generics.ListCreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsCreatingHasAccessOrNoAccess]

    def get_queryset(self):
        logged_user = self.request.user
        logged_user_role = AuthRole.get_auth_role(logged_user.pk)
        print(logged_user_role)
        if logged_user_role == AuthRole.RoleTypes.ADMIN:
            return User.objects.all()

        queryset = User.objects.filter(pk__exact=logged_user.pk)
        if logged_user_role == AuthRole.RoleTypes.MANAGER:
            queryset_extra = User.objects.filter(authrole__role__lt=logged_user_role)
            queryset = queryset.union(queryset_extra)

        return queryset

class JogList(generics.ListCreateAPIView):
    serializer_class = JogSerializer
    permission_classes = [permissions.HasAccessOrNoAccess]

    def get_queryset(self):
        logged_user = self.request.user
        logged_user_role = AuthRole.get_auth_role(logged_user.pk)

        if logged_user_role == AuthRole.RoleTypes.ADMIN:
            return Jog.objects.all()

        queryset = Jog.objects.filter(user_id__exact=logged_user.pk)
        if logged_user_role == AuthRole.RoleTypes.MANAGER:
            queryset_extra = Jog.objects.filter(user_id__authrole__role__lt=logged_user_role)
            queryset = queryset.union(queryset_extra)

        return queryset

class AuthRoleList(generics.ListCreateAPIView):
    serializer_class = AuthRoleSerializer
    permission_classes = [permissions.HasAccessOrNoAccess]

    def get_queryset(self):
        logged_user = self.request.user
        logged_user_role = AuthRole.get_auth_role(logged_user.pk)

        if logged_user_role == AuthRole.RoleTypes.ADMIN:
            return AuthRole.objects.all()

        queryset = AuthRole.objects.filter(user_id__exact=logged_user.pk)
        if logged_user_role == AuthRole.RoleTypes.MANAGER:
            queryset_extra = AuthRole.objects.filter(role__lt=logged_user_role)
            queryset = queryset.union(queryset_extra)

        return queryset

class UserDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.HasAccessOrNoAccess]

class JogDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Jog.objects.all()
    serializer_class = JogSerializer
    permission_classes = [permissions.HasAccessOrNoAccess]

class AuthRoleDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = AuthRole.objects.all()
    serializer_class = AuthRoleSerializer
    permission_classes = [permissions.HasAccessOrNoAccess]



