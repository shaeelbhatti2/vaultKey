from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.shared.db_models import RotationPolicyModel


class ExpiryAlertService:
    async def secrets_expiring_within(
        self,
        session: AsyncSession,
        days: int = 30,
    ) -> list[RotationPolicyModel]:
        deadline = datetime.now(UTC) + timedelta(days=days)
        result = await session.execute(
            select(RotationPolicyModel).where(
                RotationPolicyModel.next_due_at.is_not(None),
                RotationPolicyModel.next_due_at <= deadline,
            )
        )
        return list(result.scalars())

    async def overdue(self, session: AsyncSession) -> list[RotationPolicyModel]:
        now = datetime.now(UTC)
        result = await session.execute(
            select(RotationPolicyModel).where(
                RotationPolicyModel.next_due_at.is_not(None),
                RotationPolicyModel.next_due_at < now,
            )
        )
        return list(result.scalars())
