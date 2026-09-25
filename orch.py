"""Move imported incidents through the Proposer and Verifier pipeline."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any, Optional

import mysql.connector
from dotenv import load_dotenv

try:
    from .proposer import ProposedRcaDossier, run_proposer_agent
    from .verifier_agent import run_verifier_agent
except ImportError:
    from proposer import ProposedRcaDossier, run_proposer_agent
    from verifier_agent import run_verifier_agent


# Always load agents/.env, regardless of the current working directory.
ENV_FILE = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=ENV_FILE, override=False)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
LOGGER = logging.getLogger("rca.orchestrator")


DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
    "connection_timeout": 5,
    "charset": "utf8mb4",
    "collation": "utf8mb4_unicode_ci",
    "use_unicode": True,
}

POLL_SECONDS = int(os.getenv("ORCHESTRATOR_POLL_SECONDS", "10"))
BETWEEN_INCIDENTS_SECONDS = int(
    os.getenv("ORCHESTRATOR_BETWEEN_INCIDENTS_SECONDS", "2")
)


class IncidentStateConflict(RuntimeError):
    """Raised when an incident was changed by another process."""


def _validate_configuration() -> None:
    missing = [
        name
        for name in ("DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME")
        if not os.getenv(name)
    ]
    if missing:
        raise RuntimeError(
            "Missing required environment variables: " + ", ".join(missing)
        )
    if POLL_SECONDS < 1:
        raise RuntimeError("ORCHESTRATOR_POLL_SECONDS must be at least 1")
    if BETWEEN_INCIDENTS_SECONDS < 0:
        raise RuntimeError(
            "ORCHESTRATOR_BETWEEN_INCIDENTS_SECONDS cannot be negative"
        )


def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


def _claim_next_incident() -> Optional[dict[str, Any]]:
    """Atomically move one NEW incident to ANALYZING and return its data."""

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        connection.start_transaction()
        cursor.execute(
            """
            SELECT
                incident_id,
                site_code,
                err_batch_no,
                source_system,
                component_id,
                exception_type,
                error_message
            FROM live_incidents
            WHERE pipeline_status = 'NEW'
            ORDER BY incident_id
            LIMIT 1
            FOR UPDATE
            """
        )
        incident = cursor.fetchone()
        if incident is None:
            connection.rollback()
            return None

        cursor.execute(
            """
            UPDATE live_incidents
            SET pipeline_status = 'ANALYZING'
            WHERE incident_id = %s
              AND pipeline_status = 'NEW'
            """,
            (incident["incident_id"],),
        )
        if cursor.rowcount != 1:
            connection.rollback()
            return None

        connection.commit()
        return incident
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()


def _parse_proposer_output(proposer_output: str) -> ProposedRcaDossier:
    """Validate the Proposer's strict JSON contract before saving it."""

    return ProposedRcaDossier.model_validate_json(proposer_output)


def _save_proposal_and_get_sop(
    incident_id: int,
    component_id: str,
    dossier: ProposedRcaDossier,
) -> str:
    """Save the complete proposal, advance state, and load the SOP.

    The API normalizer expects ``ai_proposed_root_cause`` to contain the
    complete strict Proposer JSON. Keeping the dossier intact preserves the
    confidence score and historical-match flag for the dashboard while
    ``ai_proposed_fix`` remains populated for backwards compatibility.
    """

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    serialized_dossier = dossier.model_dump_json()
    try:
        cursor.execute(
            """
            UPDATE live_incidents
            SET pipeline_status = 'AWAITING_VERIFICATION',
                ai_proposed_root_cause = %s,
                ai_proposed_fix = %s
            WHERE incident_id = %s
              AND pipeline_status = 'ANALYZING'
            """,
            (
                serialized_dossier,
                dossier.proposed_actionable_fix,
                incident_id,
            ),
        )
        if cursor.rowcount != 1:
            raise IncidentStateConflict(
                "Incident is no longer in ANALYZING state"
            )

        cursor.execute(
            """
            SELECT investigation_sop
            FROM t_sops_master
            WHERE DAG_id = %s
            LIMIT 1
            """,
            (component_id,),
        )
        sop_record = cursor.fetchone()
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()

    if sop_record is None:
        return ""
    return str(sop_record.get("investigation_sop") or "").strip()


def _save_verifier_result(incident_id: int, verifier_output: str) -> None:
    """Save the completed diagnostic report and mark the pipeline complete."""

    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            UPDATE live_incidents
            SET pipeline_status = 'VERIFIED',
                ai_verifier_result = %s
            WHERE incident_id = %s
              AND pipeline_status = 'AWAITING_VERIFICATION'
            """,
            (verifier_output, incident_id),
        )
        if cursor.rowcount != 1:
            raise IncidentStateConflict(
                "Incident is no longer awaiting verification"
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()


def _mark_incident_error(incident_id: int) -> None:
    """Move an owned in-flight incident to ERROR without exposing secrets."""

    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            UPDATE live_incidents
            SET pipeline_status = 'ERROR',
                ai_verifier_result = %s
            WHERE incident_id = %s
              AND pipeline_status IN ('ANALYZING', 'AWAITING_VERIFICATION')
            """,
            (
                "## Pipeline Error\n\n"
                "The orchestrator stopped safely. Inspect the orchestrator "
                "logs before retrying this incident.",
                incident_id,
            ),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        LOGGER.exception(
            "Could not move incident %s to ERROR",
            incident_id,
        )
    finally:
        cursor.close()
        connection.close()


def process_incident() -> bool:
    """Process one NEW incident; return False only when no work was claimed."""

    incident = _claim_next_incident()
    if incident is None:
        return False

    incident_id = int(incident["incident_id"])
    component_id = str(incident["component_id"])
    LOGGER.info(
        "Claimed incident %s for site=%s batch=%s component=%s",
        incident_id,
        incident.get("site_code"),
        incident.get("err_batch_no"),
        component_id,
    )

    try:
        proposer_output = run_proposer_agent(
            source_system=str(incident["source_system"]),
            component_id=component_id,
            exception_type=str(incident.get("exception_type") or ""),
            error_message=incident.get("error_message") or "",
        )
        dossier = _parse_proposer_output(proposer_output)

        raw_sop_text = _save_proposal_and_get_sop(
            incident_id,
            component_id,
            dossier,
        )
        LOGGER.info(
            "Incident %s moved to AWAITING_VERIFICATION",
            incident_id,
        )
        if not raw_sop_text:
            LOGGER.warning(
                "No strict SOP exists in t_sops_master for component %s; "
                "the Verifier will return an inconclusive report",
                component_id,
            )

        verifier_output = run_verifier_agent(
            incident_error_message=incident.get("error_message") or "",
            proposed_rca=dossier.proposed_root_cause,
            proposed_fix=dossier.proposed_actionable_fix,
            raw_db_sop=raw_sop_text,
        )
        _save_verifier_result(incident_id, verifier_output)
        LOGGER.info(
            "Incident %s moved to VERIFIED",
            incident_id,
        )
        return True
    except Exception:
        LOGGER.exception("Pipeline failed for incident %s", incident_id)
        _mark_incident_error(incident_id)
        return True


def run_forever() -> None:
    """Continuously process imported incidents until interrupted."""

    _validate_configuration()
    LOGGER.info("RCA Pipeline Orchestrator started")
    LOGGER.info("Listening for NEW incidents")

    while True:
        try:
            processed = process_incident()
        except Exception:
            LOGGER.exception(
                "Orchestrator polling failed; retrying after %s seconds",
                POLL_SECONDS,
            )
            processed = False
        time.sleep(
            BETWEEN_INCIDENTS_SECONDS if processed else POLL_SECONDS
        )


if __name__ == "__main__":
    try:
        run_forever()
    except KeyboardInterrupt:
        LOGGER.info("Orchestrator shut down manually")
