import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.shared.db_models import AuditLogEntryModel
from vaultkey.shared.domain import AuditAction, AuditSeverity


class AuditWriter:
    async def append(
        self,
        session: AsyncSession,
        organization_id: UUID,
        actor_id: UUID | None,
        action: AuditAction,
        severity: AuditSeverity,
        resource_path: str | None = None,
        details: dict[str, str] | None = None,
    ) -> AuditLogEntryModel:
        previous = await self._latest_hash(session, organization_id)
        entry = AuditLogEntryModel(
            organization_id=organization_id,
            actor_id=actor_id,
            action=action.value,
            severity=severity.value,
            resource_path=resource_path,
            details_json=details or {},
            previous_hash=previous,
            entry_hash="",
        )
        entry.entry_hash = self._compute_hash(entry)
        session.add(entry)
        await session.flush()
        return entry

    async def _latest_hash(self, session: AsyncSession, organization_id: UUID) -> str | None:
        result = await session.execute(
            select(AuditLogEntryModel)
            .where(AuditLogEntryModel.organization_id == organization_id)
            .order_by(AuditLogEntryModel.created_at.desc())
            .limit(1)
        )
        latest = result.scalar_one_or_none()
        return latest.entry_hash if latest else None

    def _compute_hash(self, entry: AuditLogEntryModel) -> str:
        payload = {
            "organization_id": str(entry.organization_id),
            "actor_id": str(entry.actor_id) if entry.actor_id else None,
            "action": entry.action,
            "severity": entry.severity,
            "resource_path": entry.resource_path,
            "details": entry.details_json,
            "previous_hash": entry.previous_hash,
            "created_at": datetime.now(UTC).isoformat(),
        }
        raw = json.dumps(payload, sort_keys=True).encode()
        return hashlib.sha256(raw).hexdigest()
