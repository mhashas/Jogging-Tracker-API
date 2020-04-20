from django.urls import path
from django.conf.urls import include
from rest_framework.urlpatterns import format_suffix_patterns
from api.views import UserList, JogList, AuthRoleList, UserDetail, JogDetail, AuthRoleDetail


urlpatterns = [
    path('user/', UserList.as_view()),
    path('user/<int:pk>', UserDetail.as_view()),
    path('jogs/', JogList.as_view()),
    path('jogs/<int:pk>', JogDetail.as_view()),
    path('auth_role/', AuthRoleList.as_view()),
    path('auth_role/<int:pk>', AuthRoleDetail.as_view()),
    path('api-auth/', include('rest_framework.urls')),
]

urlpatterns = format_suffix_patterns(urlpatterns)

