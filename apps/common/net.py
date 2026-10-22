from __future__ import annotations

import ipaddress

from django.conf import settings
from django.http import HttpRequest


def get_client_ip(request: HttpRequest) -> str | None:
    """Return the client IP, trusting ``X-Forwarded-For`` only behind known proxies.

    With ``NUM_PROXIES = N`` the N-th address from the right of the
    ``X-Forwarded-For`` chain is used (the one appended by our outermost
    trusted proxy), matching DRF's throttling identity. With ``N = 0`` the
    header is ignored because any client can forge it.
    """
    candidate: str = request.META.get("REMOTE_ADDR", "")
    num_proxies: int = settings.NUM_PROXIES
    if num_proxies > 0:
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        chain = [part.strip() for part in forwarded.split(",") if part.strip()]
        if chain:
            candidate = chain[-min(num_proxies, len(chain))]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None
