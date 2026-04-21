import csv
import io
import json
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.audit.writer import AuditWriter
from vaultkey.shared.db_models import AuditLogEntryModel
from vaultkey.shared.domain import AuditAction, AuditLogEntryRead, AuditSeverity


class AuditChainService:
    def __init__(self) -> None:
        self._writer = AuditWriter()

    async def verify_chain(self, session: AsyncSession, organization_id: UUID) -> bool:
        result = await session.execute(
            select(AuditLogEntryModel)
            .where(AuditLogEntryModel.organization_id == organization_id)
            .order_by(AuditLogEntryModel.created_at.asc())
        )
        entries = list(result.scalars())
        previous: str | None = None
        for entry in entries:
            if entry.previous_hash != previous:
                return False
            recomputed = self._writer._compute_hash(entry)
            if recomputed != entry.entry_hash:
                return False
            previous = entry.entry_hash
        return True

    async def export_csv(
        self,
        session: AsyncSession,
        organization_id: UUID,
        since: datetime | None = None,
    ) -> str:
        query = select(AuditLogEntryModel).where(AuditLogEntryModel.organization_id == organization_id)
        if since is not None:
            query = query.where(AuditLogEntryModel.created_at >= since)
        result = await session.execute(query.order_by(AuditLogEntryModel.created_at.asc()))
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["id", "action", "severity", "resource_path", "created_at", "entry_hash"])
        for entry in result.scalars():
            writer.writerow([
                str(entry.id),
                entry.action,
                entry.severity,
                entry.resource_path or "",
                entry.created_at.isoformat(),
                entry.entry_hash,
            ])
        return buffer.getvalue()

    async def export_json(
        self,
        session: AsyncSession,
        organization_id: UUID,
    ) -> str:
        result = await session.execute(
            select(AuditLogEntryModel)
            .where(AuditLogEntryModel.organization_id == organization_id)
            .order_by(AuditLogEntryModel.created_at.asc())
        )
        rows = [
            AuditLogEntryRead(
                id=e.id,
                organization_id=e.organization_id,
                actor_id=e.actor_id,
                action=AuditAction(e.action),
                severity=AuditSeverity(e.severity),
                resource_path=e.resource_path,
                details=e.details_json,
                entry_hash=e.entry_hash,
                previous_hash=e.previous_hash,
                created_at=e.created_at,
            ).model_dump(mode="json")
            for e in result.scalars()
        ]
        return json.dumps(rows, indent=2)
