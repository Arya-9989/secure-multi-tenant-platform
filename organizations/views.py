from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated

from .models import Organization
from .serializers import OrganizationSerializer
from accounts.permissions import IsSuperAdmin


class OrganizationViewSet(ModelViewSet):
    """
    Organization management – SUPER_ADMIN only
    """
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    permission_classes = [IsAuthenticated, IsSuperAdmin]
