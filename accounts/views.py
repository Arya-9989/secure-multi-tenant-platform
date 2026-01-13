from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated

from .models import User
from .serializers import UserCreateSerializer, UserListSerializer
from .permissions import IsOrganizationUser


class UserViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated, IsOrganizationUser]

    def get_queryset(self):
        user = self.request.user

        if user.role == 'SUPER_ADMIN':
            return User.objects.all()

        return User.objects.filter(organization=user.organization)

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        return UserListSerializer

    def perform_create(self, serializer):
        serializer.save(organization=self.request.user.organization)
