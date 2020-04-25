import abc
import datetime
from django.db.models import Q
from rest_framework import status, serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import generics
from api.query_filter_parser import QueryFilterParser

from api import permissions
from api.models import User, Jog, AuthRole
from api.serializers import UserSerializer, JogSerializer, AuthRoleSerializer


class FilteredModelList(generics.ListCreateAPIView, abc.ABC):
    """Abstract class that is used to easily filter your querysets."""

    @abc.abstractmethod
    def get_base_queryset(self):
        pass

    def get_queryset(self):
        """Filters the base queryset by transforming the given filter statements into Q statements and applying them"""

        queryset = self.get_base_queryset()
        filter = self.request.query_params.get('filter', None)

        if filter:
            q_statements = QueryFilterParser().parse_query_filter(filter)
            queryset_filter = self.model.objects.filter(eval(q_statements))
            queryset = queryset.intersection(queryset_filter)

        return queryset


class UserList(FilteredModelList):
    """Model used for retrieving user lists"""

    serializer_class = UserSerializer
    permission_classes = [permissions.IsCreatingOrAuthElseNoAccess]
    model = User

    def get_base_queryset(self):
        logged_user = self.request.user
        logged_user_role = AuthRole.get_auth_role(logged_user.pk)

        if logged_user_role == AuthRole.RoleTypes.ADMIN:
            return User.objects.all()

        queryset = User.objects.filter(pk__exact=logged_user.pk)
        if logged_user_role == AuthRole.RoleTypes.MANAGER:
            queryset_extra = User.objects.filter(authrole__role__lt=logged_user_role)
            queryset = queryset.union(queryset_extra)

        return queryset


class JogList(FilteredModelList):
    """Model used for retrieving jog lists"""

    serializer_class = JogSerializer
    permission_classes = [permissions.IsCreatingOrReadingOrStaffElseNoAccess]
    model = Jog

    def get_base_queryset(self):
        logged_user = self.request.user
        logged_user_role = AuthRole.get_auth_role(logged_user.pk)

        if logged_user_role == AuthRole.RoleTypes.ADMIN:
            return Jog.objects.all()

        queryset = Jog.objects.filter(user_id__exact=logged_user.pk)
        if logged_user_role == AuthRole.RoleTypes.MANAGER:
            queryset_extra = Jog.objects.filter(user_id__authrole__role__lt=logged_user_role)
            queryset = queryset.union(queryset_extra)

        return queryset


class AuthRoleList(FilteredModelList):
    """Model used for retrieving auth role lists"""

    serializer_class = AuthRoleSerializer
    permission_classes = [permissions.IsCreatingOrReadingOrStaffElseNoAccess]
    model = AuthRole

    def get_base_queryset(self):
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
    """Model used for retrieving details of a user"""

    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsCreatingOrReadingOrStaffElseNoAccess]


class JogDetail(generics.RetrieveUpdateDestroyAPIView):
    """Model used for retrieving details of a jog"""

    queryset = Jog.objects.all()
    serializer_class = JogSerializer
    permission_classes = [permissions.IsCreatingOrReadingOrStaffElseNoAccess]


class AuthRoleDetail(generics.RetrieveUpdateDestroyAPIView):
    """Model used for retrieving details of an auth role"""

    queryset = AuthRole.objects.all()
    serializer_class = AuthRoleSerializer
    permission_classes = [permissions.IsCreatingOrReadingOrStaffElseNoAccess]


class WeeklyReportDetail(APIView):
    """Model used for retrieving details of jog weekly reports"""

    permission_classes = [permissions.IsCreatingOrReadingOrStaffElseNoAccess]

    def get_queryset(self, date_start, date_end, user_id):
        queryset = Jog.objects.filter(user_id__exact=user_id) \
                              .filter(date__gte=date_start) \
                              .filter(date__lte=date_end)

        return queryset

    def get_week_averages(self, jogs):
        """
        Given the user's jogs in a week, calculates the average distance and speed

        Args:
             jogs

        Returns:
            (int, int): average_distance
        """
        total_distance = 0
        total_speed = 0

        for jog in jogs:  # type: Jog
            total_distance += jog.distance
            total_speed += jog.distance / jog.time if jog.time else 0

        return total_distance / 7, total_speed / 7

    def validate(self, user_id):
        """
        Checks whether the current user has access to the given user's weekly rpeort

        Args:
             user_id (int): user_id for which we are retrieving the weekly report

        Returns:
            bool: whether user should be granted access or not
        """
        current_user = self.request.user

        if current_user.pk == user_id:
            return True

        current_user_role = AuthRole.get_auth_role(current_user.pk)
        if current_user_role == AuthRole.RoleTypes.ADMIN:
            return True
        elif current_user_role == AuthRole.RoleTypes.USER:
            raise Exception("Can only view for yourself.")

        user_role = AuthRole.get_auth_role(user_id)

        if user_role != AuthRole.RoleTypes.USER:
            raise Exception("Cannot view for user with same or higher auth role.")

    def get(self, request, format=None):
        """
        Given a user_id (default: current_user) and a date (default: today) calculates and returns the jogs' summary.

        Args:
            request: request to be processed
            format

        Returns:
            Response: either exception if user does not have access to report or the report
        """
        user_id = request.query_params.get('user_id', request.user.pk)

        try:
            self.validate(user_id)
        except Exception as e:
            exception = {"detail": str(e)}
            return Response(exception, status=status.HTTP_400_BAD_REQUEST)

        date = request.query_params.get('date', datetime.datetime.now())
        monday = (date - datetime.timedelta(days=date.weekday())).strftime('%Y-%m-%d')
        sunday = (date + datetime.timedelta(days=6-date.weekday())).strftime('%Y-%m-%d') # date.weekday() is 0 indexed

        queryset = self.get_queryset(monday, sunday, user_id)
        average_distance, average_speed = self.get_week_averages(queryset)

        json = {
            "count": 1,
            "next": None,
            "previous": None,
            "results": [
                {
                    'user_id': user_id,
                    "week": monday,
                    "average_speed": average_speed,
                    "average_distance": average_distance,
                }
            ]
        }

        return Response(json, status=status.HTTP_200_OK)

