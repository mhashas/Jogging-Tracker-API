from rest_framework import serializers
from django.contrib.auth.models import User
from api.models import AuthRole, Jog


class AuthRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuthRole
        fields = ('id', 'user_id', 'role')

    def create(self, validated_data):
        pass
        user_data = validated_data.pop('user_id')
        user = User.objects.create_user(**user_data)
        profile, created = AuthRole.objects.update_or_create(user_id=user)
        return profile

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email', 'username', 'password')

    def create(self, validated_data):
        password = validated_data.pop('password')
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
        instance.password = validated_data.get('password', instance.password)

        instance.save()
        return instance

class JogSerializer(serializers.ModelSerializer):
    user_id = serializers.ReadOnlyField(source='user_id.pk')

    class Meta:
        model = Jog
        fields = ('id', 'user_id', 'date', 'distance', 'time', 'location')

    def create(self, validated_data):
        jog = Jog.objects.create(**validated_data)
        return jog
