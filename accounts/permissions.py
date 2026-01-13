from rest_framework.permissions import BasePermission


class IsSuperAdmin(BasePermission):
    """
    Allows access only to platform super admins
    """
    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.role == 'SUPER_ADMIN'
        )


class IsOrganizationUser(BasePermission):
    """
    Allows access to ORG_ADMIN and SUPER_ADMIN
    """
    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.role in ['ORG_ADMIN', 'SUPER_ADMIN']
        )
