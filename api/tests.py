from django.http import HttpRequest
from rest_framework import serializers
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework.test import force_authenticate, APIRequestFactory, APITestCase

import random
import string
import json

from api.models import User, AuthRole, Jog
from api.views import UserList, UserDetail, JogList, JogDetail, AuthRoleDetail, AuthRoleList
from api.serializers import UserSerializer, AuthRoleSerializer, JogSerializer


class SerializerTest(APITestCase):

    USER_DATA = {'first_name': 'user', 'last_name': 'user', 'email': 'user@user.com', 'password': 'user' , 'username': 'user'}
    MANAGER_DATA = {'first_name': 'manager', 'last_name': 'manager', 'email': 'manager@manager.com', 'password': 'manager', 'username': 'manager'}
    ADMIN_DATA = {'first_name': 'admin', 'last_name': 'admin', 'email': 'admin@admin.com', 'password': 'admin', 'username': 'admin'}
    TEST_DATA = {'first_name': 'test', 'last_name': 'test', 'email': 'test@test.com', 'password': 'test', 'username': 'test'}

    def create_manager(self, data=None):
        data = data if data else self.MANAGER_DATA
        manager = UserSerializer().create(data)
        manager_role = AuthRole.objects.get(user_id__exact=manager.pk)
        manager_role.role = AuthRole.RoleTypes.MANAGER
        manager_role.save()

        return manager

    def create_admin(self, data=None):
        data = data if data else self.ADMIN_DATA
        admin = UserSerializer().create(data)
        admin_role = AuthRole.objects.get(user_id__exact=admin.pk)
        admin_role.role = AuthRole.RoleTypes.ADMIN
        admin_role.save()

        return admin

class UserSerializerTest(SerializerTest):

    def setUp(self):
        self.serializer = UserSerializer()

    def test_user_creation(self):
        user = self.serializer.create(self.USER_DATA)
        auth_role = AuthRole.get_auth_role(user.pk)

        self.assertIsInstance(user, User)
        self.assertEqual(auth_role, AuthRole.RoleTypes.USER, msg='Auth role is user')
        self.assertEqual(user.first_name, self.USER_DATA.get('first_name'))
        self.assertEqual(user.last_name, self.USER_DATA.get('last_name'))
        self.assertEqual(user.email, self.USER_DATA.get('email'))
        self.assertEqual(user.username, self.USER_DATA.get('username'))
        self.assertEqual(user.check_password(self.USER_DATA.get('password')), True)

    def test_user_update(self):
        manager = self.create_manager()
        manager = self.serializer.update(manager, self.TEST_DATA) # type: User
        manager_role = AuthRole.get_auth_role(manager.pk)

        self.assertIsInstance(manager, User)
        self.assertEqual(manager_role, AuthRole.RoleTypes.MANAGER, msg='Auth role is manager')
        self.assertEqual(manager.first_name, self.TEST_DATA.get('first_name'))
        self.assertEqual(manager.last_name, self.TEST_DATA.get('last_name'))
        self.assertEqual(manager.email, self.TEST_DATA.get('email'))
        self.assertEqual(manager.username, self.TEST_DATA.get('username'))
        self.assertEqual(manager.check_password(self.TEST_DATA.get('password')), True)

class AuthRoleSerializerTest(SerializerTest):

    def setUp(self):
        self.serializer = AuthRoleSerializer()
        self.serializer.context['request'] = HttpRequest()
        self.user = UserSerializer().create(self.USER_DATA)

    def test_create(self):
        auth_role = AuthRole.objects.get(user_id__exact=self.user.pk)
        self.assertEqual(auth_role.role, AuthRole.RoleTypes.USER)

    def test_update(self):
        auth_role = AuthRole.objects.get(user_id__exact=self.user.pk)
        role = AuthRole.RoleTypes.ADMIN

        data = {'user_id': self.user, 'role': role}
        auth_role = self.serializer.update(auth_role, data) # type: AuthRole

        self.assertEqual(auth_role.role, role)
        self.assertEqual(auth_role.user_id.pk, self.user.pk)

    def test_creating_user_gives_him_user_role(self):
        user = UserSerializer().create(self.TEST_DATA)
        auth_role = AuthRole.get_auth_role(user.pk)

        self.assertEqual(auth_role, AuthRole.RoleTypes.USER, msg='Auth role is user')

    def test_user_cannot_make_his_role_higher(self):
        self.serializer.context['request'].user = self.user
        data = {'role': AuthRole.RoleTypes.ADMIN}
        self.assertRaisesMessage(serializers.ValidationError, self.serializer.HIGHER_ROLE_ERROR, self.serializer.validate, data)

class JogSerializerTest(SerializerTest):

    def setUp(self):
        self.serializer = JogSerializer()
        self.serializer.context['request'] = HttpRequest()
        self.user = UserSerializer().create(self.USER_DATA)

    def test_jog_creation(self):
        data = {'date': '2020-04-23', 'location': 'Amsterdam', 'weather': 'Sunny', 'user_id': self.user}
        jog = self.serializer.create(data)

        self.assertEqual(jog.date, data.get('date'))
        self.assertEqual(jog.location, data.get('location'))
        self.assertEqual(jog.weather, data.get('weather'))
        self.assertEqual(jog.user_id.pk, self.user.pk)

    def test_jog_update(self):
        data = {'date': '2020-04-23', 'location': 'Amsterdam', 'weather': 'Sunny', 'user_id': self.user}
        jog = self.serializer.create(data)
        new_data = {'location': 'London', 'weather': 'Rainy'}
        jog = self.serializer.update(jog, new_data)

        self.assertEqual(jog.date, data.get('date'))
        self.assertEqual(jog.location, new_data.get('location'))
        self.assertEqual(jog.weather, new_data.get('weather'))
        self.assertEqual(jog.user_id.pk, self.user.pk)

    def test_user_can_CRUD_jog_for_himself(self):
        user = UserSerializer().create(self.TEST_DATA)
        self.serializer.context['request'].user = user
        data = {'date': '04-23-2020', 'location': 'Amsterdam', 'weather': 'Sunny', 'user_id': user}
        self.assertEqual(data, self.serializer.validate(data))

    def test_user_cannot_CRUD_jog_for_other_user(self):
        user = UserSerializer().create(self.TEST_DATA)
        self.serializer.context['request'].user = user
        data = {'date': '04-23-2020', 'location': 'Amsterdam', 'weather': 'Sunny', 'user_id': self.user}
        self.assertRaisesMessage(serializers.ValidationError, self.serializer.OTHER_USER_ERROR, self.serializer.validate, data)

    def test_manager_can_CRUD_jog_for_user(self):
        manager = self.create_manager()
        self.serializer.context['request'].user = manager
        data = {'date': '04-23-2020', 'location': 'Amsterdam', 'weather': 'Sunny', 'user_id': self.user}
        self.assertEqual(data, self.serializer.validate(data))

    def test_manager_cant_CRUD_jog_for_manager(self):
        manager = self.create_manager()
        second_manager = self.create_manager(self.TEST_DATA)

        self.serializer.context['request'].user = manager
        data = {'date': '04-23-2020', 'location': 'Amsterdam', 'weather': 'Sunny', 'user_id': second_manager}
        self.assertRaisesMessage(serializers.ValidationError, self.serializer.HIGHER_ROLE_ERROR, self.serializer.validate, data)

    def test_manager_cant_CRUD_jog_for_admin(self):
        manager = self.create_manager()
        admin = self.create_admin()

        self.serializer.context['request'].user = manager
        data = {'date': '04-23-2020', 'location': 'Amsterdam', 'weather': 'Sunny', 'user_id': admin}
        self.assertRaisesMessage(serializers.ValidationError, self.serializer.HIGHER_ROLE_ERROR, self.serializer.validate, data)

    def test_admin_can_CRUD_jog_for_user(self):
        admin = self.create_admin()
        self.serializer.context['request'].user = admin
        data = {'date': '04-23-2020', 'location': 'Amsterdam', 'weather': 'Sunny', 'user_id': self.user}
        self.assertEqual(data, self.serializer.validate(data))

    def test_admin_can_CRUD_jog_for_manager(self):
        admin = self.create_admin()
        manager = self.create_manager()
        self.serializer.context['request'].user = admin
        data = {'date': '04-23-2020', 'location': 'Amsterdam', 'weather': 'Sunny', 'user_id': manager}
        self.assertEqual(data, self.serializer.validate(data))

    def test_admin_can_CRUD_jog_for_admin(self):
        admin = self.create_admin()
        second_admin = self.create_admin(self.TEST_DATA)
        self.serializer.context['request'].user = admin
        data = {'date': '04-23-2020', 'location': 'Amsterdam', 'weather': 'Sunny', 'user_id': second_admin}
        self.assertEqual(data, self.serializer.validate(data))

class UserAPIViewTest(SerializerTest):

    def signup_view(self, data=None):
        if data is None:
            data = self.TEST_DATA

        request = APIRequestFactory().post('/api/user', data=data)
        response = UserList.as_view()(request)

        return response

    def test_signup_view(self, data=None):
        response = self.signup_view(data=data)
        self.assertEqual(response.status_code, 201)

    def login(self, data=None):
        if data is None:
            data = self.TEST_DATA

        self.signup_view(data)
        request = APIRequestFactory().post('/api/token-auth', data=data)
        response = obtain_auth_token(request).render()
        content = response.content.decode()
        content = eval(content)

        return response, content['token']

    def test_login(self, data=None):
        response, token = self.login(data)
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(token)

class BaseAPITokenTest(SerializerTest):

    def get_user_header(self, data=None):
        UserAPIViewTest().signup_view(data=data)
        _, token = UserAPIViewTest().login(data=data)
        user = User.objects.get(first_name__exact=data.get('first_name'))

        self.user = user
        self.token = token

        return user, token

    def get_manager_header(self, data=None):
        user, token = self.get_user_header(data=data)
        auth_role = AuthRole.objects.get(user_id__exact=user.pk)

        auth_role.role = AuthRole.RoleTypes.MANAGER
        auth_role.save()

        return user, token

    def get_admin_header(self, data=None):
        user, token = self.get_user_header(data=data)
        auth_role = AuthRole.objects.get(user_id__exact=user.pk)

        auth_role.role = AuthRole.RoleTypes.ADMIN
        auth_role.save()

        return user, token

class JogAPIViewTest(BaseAPITokenTest):

    def create_jog_without_logging_in(self, user_data=None):
        if user_data is None:
            user_data = self.TEST_DATA

        user, token = self.get_user_header(user_data)
        jog_data = {'date': '23-04-2020', 'location': 'Amsterdam', 'weather': 'Sunny', 'user_id': user.pk}

        request = APIRequestFactory().post('api/jogs', data=jog_data)

        response = JogList.as_view()(request).render()
        content = eval(response.content.decode())

        return content

    def test_create_jog_without_logging_in(self, user_data=None):
        content = self.create_jog_without_logging_in(user_data)
        self.assertEqual(content['detail'], 'Authentication credentials were not provided.')

    def user_create_jog(self, user_data=None):
        if user_data is None:
            user_data = self.TEST_DATA

        user, token = self.get_user_header(user_data)
        jog_data = {'date': '23-04-2020', 'location': 'Amsterdam', 'weather': 'Sunny', 'user_id': user.pk}

        request = APIRequestFactory().post('api/jogs', data=jog_data)
        force_authenticate(request, user=user, token=token)

        response = JogList.as_view()(request).render()
        content = eval(response.content.decode())

        return response, content

    def test_user_create_jog(self, user_data=None):
        response, content = self.user_create_jog(user_data)
        self.assertEqual(response.status_code, 201)
        self.assertIsNotNone(content['id'])

    def user_get_jog(self, user_data=None):
        _, content = self.user_create_jog(user_data)
        jog_id = content['id']

        request = APIRequestFactory().get('api/jogs/', content_type='application/json')
        force_authenticate(request, self.user, self.token)

        response = JogDetail.as_view()(request, pk=jog_id).render()
        content = eval(response.content.decode())
        return response, content

    def test_user_get_jog(self, user_data=None):
        response, content = self.user_get_jog(user_data)
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(content['id'])

    def user_update_jog(self, user_data=None):
        _, content = self.user_create_jog(user_data)
        jog_id = content['id']

        body = {'location': 'test',
                'distance': 7,
                'time': 7,
                'user_id': self.user.pk,
                'date': '20-04-2020',
                }

        request = APIRequestFactory().put('api/jogs/', data=json.dumps(body), content_type='application/json')
        force_authenticate(request, self.user, self.token)

        response = JogDetail.as_view()(request, pk=jog_id).render()
        content = eval(response.content.decode())
        return response, content

    def test_user_update_jog(self, user_data=None):
        response, content = self.user_update_jog(user_data)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(content['location'], 'test')
        self.assertEqual(content['distance'], 7)
        self.assertEqual(content['time'], 7)

    def user_delete_jog(self, user_data=None):
        _, content = self.user_create_jog(user_data)
        jog_id = content['id']

        request = APIRequestFactory().delete('api/jogs/', content_type='application/json')
        force_authenticate(request, self.user, self.token)

        response = JogDetail.as_view()(request, pk=jog_id).render()
        return response

    def test_user_delete_jog(self, user_data=None):
        response = self.user_delete_jog(user_data)
        self.assertEqual(response.status_code, 204)


class EndToEndTesting(BaseAPITokenTest):

    def test_app_flow_user(self):
        data = self.USER_DATA

        UserAPIViewTest().test_signup_view(data)
        UserAPIViewTest().test_login(data)

        JogAPIViewTest().test_create_jog_without_logging_in(data)
        JogAPIViewTest().test_user_create_jog(data)
        JogAPIViewTest().test_user_get_jog(data)
        JogAPIViewTest().test_user_update_jog(data)
        JogAPIViewTest().test_user_delete_jog(data)
    










