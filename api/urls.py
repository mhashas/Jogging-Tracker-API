from django.urls import path
from django.conf.urls import include
from rest_framework import routers
from api.views import UserViewSet, JogViewSet

router = routers.DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'jogs', JogViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework'))
]
