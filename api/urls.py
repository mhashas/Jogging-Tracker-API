from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework.urlpatterns import format_suffix_patterns
from api.views import UserList, JogList, AuthRoleList, UserDetail, JogDetail, AuthRoleDetail, WeeklyReportDetail


urlpatterns = [
    path('user/', UserList.as_view()),
    path('user/<int:pk>', UserDetail.as_view()),
    path('jogs/', JogList.as_view()),
    path('jogs/<int:pk>', JogDetail.as_view()),
    path('weekly_report/', WeeklyReportDetail.as_view()),
    path('auth_role/', AuthRoleList.as_view()),
    path('auth_role/<int:pk>', AuthRoleDetail.as_view()),
    path('token-auth/', obtain_auth_token, name='api_token_auth'),
]

urlpatterns = format_suffix_patterns(urlpatterns)

