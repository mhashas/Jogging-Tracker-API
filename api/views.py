from rest_framework import permissions, viewsets
from rest_framework.pagination import PageNumberPagination
from django.http import HttpResponse

from api.serializers import ProfileSerializer, UserSerializer, JogSerializer
from api.models import User, Jog

def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")

class StandardPagination(PageNumberPagination):
    page_size = 2
    page_size_query_description = 'page_size'
    max_page_size = 100

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

class JogViewSet(viewsets.ModelViewSet):
    queryset = Jog.objects.all()
    serializer_class = JogSerializer
    permission_classes = [permissions.IsAuthenticated]


