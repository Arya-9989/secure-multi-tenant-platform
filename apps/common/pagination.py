from rest_framework.pagination import CursorPagination, PageNumberPagination


class DefaultPagination(PageNumberPagination):
    page_size = 25
    page_size_query_param = "page_size"
    max_page_size = 100


class CreatedAtCursorPagination(CursorPagination):
    """Stable pagination for append-only, high-volume tables (no OFFSET scans)."""

    ordering = ("-created_at", "-id")
    page_size = 50
    page_size_query_param = "page_size"
    max_page_size = 200
