"""
Dashboard HTTP routes (package facade).

All endpoints are registered on a single APIRouter that ``core.api_server``
includes onto the FastAPI ``app`` at import time. Handlers reach shared
state, helpers, and the Smith-supervision functions through the package
(the ``_api`` alias) so the dashboard's tests can patch any of them.

Split from the former ``routes.py`` monolith for the <300-lines-per-file
convention. The import surface is identical — ``import core.api_server.routes``
still exposes ``router`` and every handler. Each route submodule below MUST be
imported here so its ``@router`` decorators execute and the endpoints register;
a missing import = a silently-missing endpoint.
"""
from __future__ import annotations

# Shared router + the Smith wake helper (patched by tests as
# ``core.api_server.routes._wake_smith_if_idle``).
from ._common import router, _wake_smith_if_idle  # noqa: F401

# Import every route submodule so its @router decorators run at import time.
from . import dashboard_routes  # noqa: E402,F401
from . import findings_routes  # noqa: E402,F401
from . import scan_state_routes  # noqa: E402,F401
from . import wishlist_routes  # noqa: E402,F401
from . import setup_gate_routes  # noqa: E402,F401
from . import triage_routes  # noqa: E402,F401
from . import smith_routes  # noqa: E402,F401
from . import misc_routes  # noqa: E402,F401

# Re-export handler functions for consumers/tests that import them by name.
from .dashboard_routes import (  # noqa: E402,F401
    dashboard_ui,
    healthz,
    logo,
    favicon,
    favicon_png,
)
from .findings_routes import (  # noqa: E402,F401
    api_findings,
    api_session,
    api_cost,
    api_coverage,
    api_get_threat_model,
    api_patch_finding,
    api_delete_finding,
)
from .scan_state_routes import (  # noqa: E402,F401
    api_clear,
    api_cleanup_tunnels,
    api_intervention,
    api_intervention_respond,
    api_steer,
)
from .wishlist_routes import (  # noqa: E402,F401
    api_wishlist,
    api_wishlist_fulfill,
    api_wishlist_dismiss,
)
from .setup_gate_routes import (  # noqa: E402,F401
    api_setup_gate_elect,
    api_setup_gate_recheck,
)
from .triage_routes import (  # noqa: E402,F401
    api_complete,
    api_triage,
    api_triage_cancel,
    api_force_stop,
)
from .smith_routes import (  # noqa: E402,F401
    api_smith_status,
    api_smith_clients,
    api_watchdog_status,
    api_restart_smith,
)
from .misc_routes import (  # noqa: E402,F401
    api_qa,
    api_steering,
    api_adjudication_log,
    api_metrics,
    api_quicklog,
    api_logs,
)
