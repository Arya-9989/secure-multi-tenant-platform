from auditlogs.models import AuditLog

class AuditLogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Skip admin & unauthenticated requests
        if (
            request.user.is_authenticated
            and hasattr(request.user, 'organization')
            and request.user.organization is not None
            and not request.path.startswith('/admin')
        ):
            AuditLog.objects.create(
                user=request.user,
                organization=request.user.organization,
                action=f"{request.method} {request.path}",
                ip_address=request.META.get('REMOTE_ADDR', '')
            )

        return response
