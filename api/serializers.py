import datetime
from rest_framework import serializers
from django.contrib.auth.models import User

from api.models import AuthRole, Jog
from api.weather_api import WeatherAPI

class AuthRoleSerializer(serializers.ModelSerializer):
    HIGHER_ROLE_ERROR = 'Cannot create higher role'

    class Meta:
        model = AuthRole
        fields = ('id', 'user_id', 'role')

    def validate(self, data):
        role_to_create = data.get('role', '')
        current_user = self.context['request'].user
        current_role = AuthRole.get_auth_role(current_user.pk)

        if current_role < role_to_create:
            raise serializers.ValidationError(self.HIGHER_ROLE_ERROR)

        return data

    def create(self, validated_data):
        profile = AuthRole.objects.create(**validated_data)
        return profile

    def update(self, instance: AuthRole, validated_data):
        instance.user_id = validated_data.get('user_id', instance.user_id)
        instance.role = validated_data.get('role', instance.role)
        instance.save()
        return instance


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email', 'username', 'password')

    def create(self, validated_data):
        password = validated_data['password']
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        auth_role = AuthRole.objects.update_or_create(user_id=user)
        return user

    def update(self, instance: User, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.email = validated_data.get('email', instance.email)
        instance.username = validated_data.get('username', instance.username)

        password = validated_data.get('password', None)
        if password:
            instance.set_password(password)

        instance.save()
        return instance

class JogSerializer(serializers.ModelSerializer):
    weather = serializers.CharField(required=False)

    HIGHER_ROLE_ERROR = "Cannot create for user with same or higher auth role"
    OTHER_USER_ERROR = "Can only create jogs for yourself"

    class Meta:
        model = Jog
        fields = ('id', 'user_id', 'date', 'distance', 'time', 'location', 'weather')


    def validate(self, data):
        user = data.get('user_id', '')
        current_user = self.context['request'].user

        if not isinstance(user, User):
            user = User.objects.get(pk=user)

        if current_user.pk == user.pk:
            return data

        role_user_to_edit = AuthRole.get_auth_role(user.pk)
        current_user_role = AuthRole.get_auth_role(current_user.pk)

        if current_user_role == AuthRole.RoleTypes.ADMIN:
            return data

        if current_user_role == AuthRole.RoleTypes.USER:
            raise serializers.ValidationError(self.OTHER_USER_ERROR)

        if current_user_role <= role_user_to_edit:
            raise serializers.ValidationError(self.HIGHER_ROLE_ERROR)

        return data

    def create(self, validated_data):
        validated_data['weather'] = self.get_weather(validated_data)
        jog = Jog.objects.create(**validated_data)
        return jog

    def get_weather(self, validated_data):
        weather = WeatherAPI().get_weather(validated_data['location'], validated_data['date'])
        return weather






