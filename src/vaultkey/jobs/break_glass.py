from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.audit.writer import AuditWriter
from vaultkey.shared.db_models import BreakGlassRequestModel
from vaultkey.shared.domain import AuditAction, AuditSeverity, BreakGlassRequestCreate


class BreakGlassService:
    def __init__(self) -> None:
        self._audit = AuditWriter()

    async def request_access(
        self,
        session: AsyncSession,
        organization_id: UUID,
        requester_id: UUID,
        data: BreakGlassRequestCreate,
    ) -> BreakGlassRequestModel:
        expires = datetime.now(UTC) + timedelta(minutes=data.ttl_minutes)
        model = BreakGlassRequestModel(
            organization_id=organization_id,
            requester_id=requester_id,
            secret_path=data.secret_path,
            reason=data.reason,
            status="pending",
            expires_at=expires,
        )
        session.add(model)
        await session.flush()
        return model

    async def approve(
        self,
        session: AsyncSession,
        request_id: UUID,
        approver_id: UUID,
        organization_id: UUID,
    ) -> BreakGlassRequestModel:
        result = await session.execute(
            select(BreakGlassRequestModel).where(BreakGlassRequestModel.id == request_id)
        )
        model = result.scalar_one()
        model.status = "approved"
        model.approved_by = approver_id
        await self._audit.append(
            session,
            organization_id,
            approver_id,
            AuditAction.BREAK_GLASS_GRANT,
            AuditSeverity.HIGH,
            model.secret_path,
            {"request_id": str(request_id)},
        )
        return model

    async def deny(self, session: AsyncSession, request_id: UUID) -> BreakGlassRequestModel:
        result = await session.execute(
            select(BreakGlassRequestModel).where(BreakGlassRequestModel.id == request_id)
        )
        model = result.scalar_one()
        model.status = "denied"
        return model
