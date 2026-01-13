class OrganizationQuerySetMixin:
    """
    Ensures all queries are scoped to user's organization
    """

    def get_queryset(self):
        qs = super().get_queryset()
        return qs.filter(organization=self.request.user.organization)
