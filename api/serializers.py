from rest_framework import serializers
from rest_framework_jwt.settings import api_settings
from django.contrib.auth.models import User
from api.models import AuthRole, Jog


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email', 'username', 'password')


class ProfileSerializer(serializers.HyperlinkedModelSerializer):
    user = UserSerializer(required=True)

    class Meta:
        model = AuthRole
        fields = ('user_id', 'role')

    def create(self, validated_data):
        user_data = validated_data.pop('user')
        user = User.objects.create_user(**user_data)
        profile, created = AuthRole.objects.update_or_create(user=user)
        return profile


class JogSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Jog
        fields = ('id', 'user_id', 'date', 'distance', 'time', 'location')

    def create(self, validated_data):
        jog = Jog.objects.create(**validated_data)
        return jog