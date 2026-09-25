from __future__ import annotations

from typing import Annotated, Optional

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    status,
)
from fastapi.middleware.cors import (
    CORSMiddleware,
)

from .config import settings
from .db import database_cursor
from .onboarding_agent import (
    OnboardingAgentConfigurationError,
    OnboardingAgentResponseError,
    generate_onboarding_draft,
    load_registered_target_context,
)
from .onboarding_service import (
    OnboardingConfigurationError,
    OnboardingConflictError,
    OnboardingServiceError,
    OnboardingTargetConnectionError,
    OnboardingValidationError,
    activate_onboarding,
    list_active_onboarding_actions,
)
from .repository import (
    analytics_overview,
    approve_remediation_request,
    create_remediation_request,
    create_review,
    dashboard_metrics,
    get_incident,
    get_incident_by_batch,
    get_sop,
    inject_test_batch,
    list_closed_reviews,
    list_incidents,
    list_remediation_actions,
    list_remediation_requests,
    list_sops,
    promote_closed_review,
    reject_remediation_request,
    resolve_manual_remediation,
    update_closed_review,
    update_sop,
)
from .schemas import (
    OnboardingActionCatalogResponse,
    OnboardingActivationRequest,
    OnboardingActivationResponse,
    OnboardingAssistantRequest,
    OnboardingAssistantResponse,
    RemediationDecisionRequest,
    RemediationManualResolutionRequest,
    RemediationRequestCreate,
    ReviewRequest,
    SopUpdateRequest,
)
from .test_cases import TEST_CASES


app = FastAPI(
    title="RCA Agent Dashboard API",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(
        settings.cors_origins,
    ),
    allow_credentials=False,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
    ],
    allow_headers=[
        "Content-Type",
    ],
)


def current_engineer() -> str:
    """
    Return the prototype engineer identity supplied by
    backend configuration.
    """

    if settings.dev_user_role not in {
        "engineer",
        "admin",
    }:
        raise HTTPException(
            status_code=(
                status.HTTP_403_FORBIDDEN
            ),
            detail=(
                "Engineer access is required"
            ),
        )

    return settings.dev_user_name


Engineer = Annotated[
    str,
    Depends(current_engineer),
]


def current_admin() -> str:
    """
    Return the prototype administrator identity supplied
    by backend configuration.
    """

    if settings.dev_user_role != "admin":
        raise HTTPException(
            status_code=(
                status.HTTP_403_FORBIDDEN
            ),
            detail=(
                "Admin access is required"
            ),
        )

    return settings.dev_user_name


Admin = Annotated[
    str,
    Depends(current_admin),
]


# ============================================================
# Health, dashboard and analytics
# ============================================================


@app.get("/api/health")
def health() -> dict:
    try:
        with database_cursor() as (
            _,
            cursor,
        ):
            cursor.execute(
                "SELECT 1 AS healthy"
            )
            cursor.fetchone()

        return {
            "api": "online",
            "database": "online",
            "orchestrator": "unknown",
            "note": (
                "An orchestrator heartbeat is not "
                "available in the current agent code."
            ),
        }

    except Exception as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "Database is unavailable"
            ),
        ) from exc


@app.get("/api/dashboard/metrics")
def metrics() -> dict:
    return dashboard_metrics()


@app.get("/api/analytics")
def analytics(
    days: int = Query(
        default=30,
        ge=7,
        le=365,
    ),
    limit: int = Query(
        default=10,
        ge=5,
        le=25,
    ),
) -> dict:
    """
    Return operational analytics for the selected date
    window.
    """

    return analytics_overview(
        days=days,
        limit=limit,
    )


# ============================================================
# Admin onboarding
# ============================================================


@app.get(
    "/api/admin/onboarding/targets"
)
def onboarding_targets(
    admin: Admin,
) -> dict:
    """
    Return registered SSH and database target metadata.

    Credentials and encrypted secret payloads are never
    returned.
    """

    _ = admin

    try:
        return (
            load_registered_target_context()
        )

    except (
        OnboardingAgentConfigurationError
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=str(exc),
        ) from exc


@app.post(
    "/api/admin/onboarding/assistant",
    response_model=(
        OnboardingAssistantResponse
    ),
)
def onboarding_assistant(
    request: OnboardingAssistantRequest,
    admin: Admin,
) -> OnboardingAssistantResponse:
    """
    Generate and validate an onboarding draft.

    This endpoint does not save or activate the DAG,
    SOP, target, credential, or selected remediation
    action.
    """

    _ = admin

    try:
        return generate_onboarding_draft(
            request
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_ENTITY
            ),
            detail=str(exc),
        ) from exc

    except (
        OnboardingAgentConfigurationError
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=str(exc),
        ) from exc

    except (
        OnboardingAgentResponseError
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_502_BAD_GATEWAY
            ),
            detail=str(exc),
        ) from exc


@app.get(
    "/api/admin/onboarding/actions",
    response_model=(
        OnboardingActionCatalogResponse
    ),
)
def onboarding_actions(
    admin: Admin,
    component_id: Optional[str] = Query(
        default=None,
        max_length=255,
    ),
    target_id: Optional[str] = Query(
        default=None,
        max_length=128,
    ),
) -> OnboardingActionCatalogResponse:
    """
    List existing remediation actions available during
    onboarding.

    Only actions that are ACTIVE and require engineer
    approval are returned. Results may be filtered by
    DAG/component and target.
    """

    _ = admin

    try:
        return list_active_onboarding_actions(
            component_id=component_id,
            target_id=target_id,
        )

    except (
        OnboardingConfigurationError
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=str(exc),
        ) from exc

    except OnboardingServiceError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=str(exc),
        ) from exc


@app.post(
    "/api/admin/onboarding/activate",
    response_model=(
        OnboardingActivationResponse
    ),
    status_code=(
        status.HTTP_201_CREATED
    ),
)
def activate_onboarding_bundle(
    request: OnboardingActivationRequest,
    admin: Admin,
) -> OnboardingActivationResponse:
    """
    Validate and activate one administrator-reviewed
    onboarding bundle.

    Depending on the selected target mode, activation
    may:

    - Reuse an existing SSH target.
    - Reuse an existing database target.
    - Register a new SSH target and encrypted
      credentials.
    - Register a new read-only database target and
      encrypted credential.
    - Save the authoritative investigation SOP.
    - Register the DAG and exception types.
    - Link an existing ACTIVE approval-required
      remediation action.
    - Write an onboarding audit event.

    All persistent changes are performed in one
    database transaction.
    """

    try:
        return activate_onboarding(
            request=request,
            activated_by=admin,
        )

    except (
        OnboardingValidationError
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_ENTITY
            ),
            detail=str(exc),
        ) from exc

    except OnboardingConflictError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=str(exc),
        ) from exc

    except (
        OnboardingTargetConnectionError
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_ENTITY
            ),
            detail=str(exc),
        ) from exc

    except (
        OnboardingConfigurationError
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=str(exc),
        ) from exc

    except OnboardingServiceError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=str(exc),
        ) from exc


# ============================================================
# Controlled test cases
# ============================================================


@app.get("/api/test-cases")
def test_case_catalog() -> dict:
    return {
        "enabled": (
            settings.enable_test_injection
        ),
        "items": list(TEST_CASES),
    }


@app.post(
    "/api/test-cases/{test_case_id}/inject",
    status_code=(
        status.HTTP_201_CREATED
    ),
)
def inject_test_case(
    test_case_id: str,
    engineer: Engineer,
) -> dict:
    if not settings.enable_test_injection:
        raise HTTPException(
            status_code=(
                status.HTTP_403_FORBIDDEN
            ),
            detail=(
                "Test injection is disabled. Set "
                "ENABLE_TEST_INJECTION=true in "
                "backend/.env and restart FastAPI."
            ),
        )

    result = inject_test_batch(
        test_case_id
    )

    if result is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Unknown test case",
        )

    result["injected_by"] = engineer
    return result


# ============================================================
# Incidents
# ============================================================


@app.get("/api/incidents")
def incidents(
    pipeline_status: Optional[str] = Query(
        default=None,
        max_length=50,
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
) -> dict:
    return {
        "items": list_incidents(
            pipeline_status,
            limit,
            offset,
        )
    }



#The static by-batch route must be declared before the
#dynamic /api/incidents/{incident_id} route.

@app.get("/api/incidents/by-batch")
def incident_detail_by_batch(
    site_code: str = Query(
        min_length=1,
        max_length=64,
    ),
    err_batch_no: str = Query(
        min_length=1,
        max_length=255,
    ),
) -> dict:
    """
    Resolve an externally supplied source error batch
    into its corresponding live RCA incident.

    The source identity is the combination of
    site_code and err_batch_no. The internal
    incident_id remains the primary key used by the
    review and remediation workflows.
    """

    normalized_site_code = (
        site_code.strip().upper()
    )
    normalized_batch_number = (
        err_batch_no.strip()
    )

    if not normalized_site_code:
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_ENTITY
            ),
            detail="site_code cannot be empty",
        )

    if not normalized_batch_number:
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_ENTITY
            ),
            detail=(
                "err_batch_no cannot be empty"
            ),
        )

    incident = get_incident_by_batch(
        normalized_site_code,
        normalized_batch_number,
    )

    if incident is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                "No imported RCA incident was found "
                "for the supplied site and error "
                "batch number"
            ),
        )

    return incident


@app.get(
    "/api/incidents/{incident_id}"
)
def incident_detail(
    incident_id: int,
) -> dict:
    incident = get_incident(
        incident_id
    )

    if incident is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Incident not found",
        )

    return incident


# ============================================================
# Remediation actions and requests
# ============================================================


@app.get(
    "/api/remediations/actions"
)
def remediation_actions(
    component_id: Optional[str] = Query(
        default=None,
        max_length=255,
    ),
) -> dict:
    return {
        "items": (
            list_remediation_actions(
                component_id
            )
        )
    }


@app.get("/api/remediations")
def remediations(
    incident_id: Optional[int] = Query(
        default=None,
        ge=1,
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
) -> dict:
    return {
        "items": (
            list_remediation_requests(
                incident_id,
                limit,
            )
        )
    }


@app.post(
    "/api/incidents/"
    "{incident_id}/remediations",
    status_code=(
        status.HTTP_201_CREATED
    ),
)
def request_remediation(
    incident_id: int,
    request: RemediationRequestCreate,
    engineer: Engineer,
) -> dict:
    try:
        result = (
            create_remediation_request(
                incident_id,
                request.action_id,
                request.request_reason,
                engineer,
                request.idempotency_key,
            )
        )

    except (
        ValueError,
        RuntimeError,
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=str(exc),
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Incident not found",
        )

    return result


@app.post(
    "/api/remediations/"
    "{remediation_id}/approve"
)
def approve_remediation(
    remediation_id: int,
    decision: RemediationDecisionRequest,
    engineer: Engineer,
) -> dict:
    try:
        result = (
            approve_remediation_request(
                remediation_id,
                engineer,
                decision.comment,
            )
        )

    except (
        ValueError,
        RuntimeError,
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=str(exc),
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                "Remediation request not found"
            ),
        )

    return result


@app.post(
    "/api/remediations/"
    "{remediation_id}/reject"
)
def reject_remediation(
    remediation_id: int,
    decision: RemediationDecisionRequest,
    engineer: Engineer,
) -> dict:
    try:
        result = (
            reject_remediation_request(
                remediation_id,
                engineer,
                decision.comment,
            )
        )

    except (
        ValueError,
        RuntimeError,
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=str(exc),
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                "Remediation request not found"
            ),
        )

    return result


@app.post(
    "/api/remediations/"
    "{remediation_id}/resolve-manual"
)
def resolve_manual_remediation_request(
    remediation_id: int,
    resolution: (
        RemediationManualResolutionRequest
    ),
    engineer: Engineer,
) -> dict:
    try:
        result = (
            resolve_manual_remediation(
                remediation_id,
                resolution.outcome,
                engineer,
                resolution.comment,
            )
        )

    except (
        ValueError,
        RuntimeError,
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=str(exc),
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                "Remediation request not found"
            ),
        )

    return result


# ============================================================
# Closed incidents and engineer reviews
# ============================================================


@app.get("/api/closed-incidents")
def closed_incidents(
    limit: int = Query(
        default=500,
        ge=1,
        le=500,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
) -> dict:
    return {
        "items": list_closed_reviews(
            limit,
            offset,
        )
    }


@app.post(
    "/api/closed-incidents/"
    "{review_id}/promote"
)
def promote_closed_incident(
    review_id: int,
    engineer: Engineer,
) -> dict:
    try:
        result = (
            promote_closed_review(
                review_id,
                engineer,
            )
        )

    except (
        ValueError,
        RuntimeError,
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=str(exc),
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                "Closed incident review not found"
            ),
        )

    return result


@app.put(
    "/api/closed-incidents/{review_id}"
)
def edit_closed_incident(
    review_id: int,
    review: ReviewRequest,
    engineer: Engineer,
) -> dict:
    try:
        result = (
            update_closed_review(
                review_id,
                review.decision,
                review.final_root_cause,
                review.selected_actions,
                review.comment,
                engineer,
                (
                    review
                    .promote_to_knowledge_base
                ),
            )
        )

    except (
        ValueError,
        RuntimeError,
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=str(exc),
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                "Closed incident review not found"
            ),
        )

    return result


@app.post(
    "/api/incidents/"
    "{incident_id}/reviews",
    status_code=(
        status.HTTP_201_CREATED
    ),
)
def review_incident(
    incident_id: int,
    review: ReviewRequest,
    engineer: Engineer,
) -> dict:
    try:
        result = create_review(
            incident_id,
            review.decision,
            review.final_root_cause,
            review.selected_actions,
            review.comment,
            engineer,
            (
                review
                .promote_to_knowledge_base
            ),
        )

    except (
        ValueError,
        RuntimeError,
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=str(exc),
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Incident not found",
        )

    return result


# ============================================================
# Investigation SOP management
# ============================================================


@app.get("/api/sops")
def sops() -> dict:
    return {
        "items": list_sops()
    }


@app.get("/api/sops/{dag_id}")
def sop_detail(
    dag_id: str,
) -> dict:
    sop = get_sop(
        dag_id
    )

    if sop is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="SOP not found",
        )

    return sop


@app.put("/api/sops/{dag_id}")
def save_sop(
    dag_id: str,
    update: SopUpdateRequest,
    engineer: Engineer,
) -> dict:
    try:
        result = update_sop(
            dag_id,
            update.investigation_sop,
            update.expected_hash,
            update.change_note,
            engineer,
        )

    except RuntimeError as exc:
        if str(exc) == "SOP_CHANGED":
            raise HTTPException(
                status_code=(
                    status.HTTP_409_CONFLICT
                ),
                detail=(
                    "The SOP changed after you "
                    "opened it. Reload before "
                    "saving."
                ),
            ) from exc

        raise

    if result is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="SOP not found",
        )

    return result
