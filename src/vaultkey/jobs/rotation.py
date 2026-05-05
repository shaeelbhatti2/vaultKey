from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vaultkey.shared.db_models import RotationPolicyModel, SecretModel


class RotationPolicyService:
    async def attach_policy(
        self,
        session: AsyncSession,
        secret_id: UUID,
        interval_days: int,
        notify_before_days: int = 7,
    ) -> RotationPolicyModel:
        existing = await session.execute(
            select(RotationPolicyModel).where(RotationPolicyModel.secret_id == secret_id)
        )
        policy = existing.scalar_one_or_none()
        now = datetime.now(UTC)
        next_due = now + timedelta(days=interval_days)
        if policy is None:
            policy = RotationPolicyModel(
                secret_id=secret_id,
                interval_days=interval_days,
                notify_before_days=notify_before_days,
                last_rotated_at=now,
                next_due_at=next_due,
            )
            session.add(policy)
        else:
            policy.interval_days = interval_days
            policy.notify_before_days = notify_before_days
            policy.next_due_at = next_due
        await session.flush()
        return policy

    async def mark_rotated(self, session: AsyncSession, secret_id: UUID) -> RotationPolicyModel:
        result = await session.execute(
            select(RotationPolicyModel).where(RotationPolicyModel.secret_id == secret_id)
        )
        policy = result.scalar_one()
        now = datetime.now(UTC)
        policy.last_rotated_at = now
        policy.next_due_at = now + timedelta(days=policy.interval_days)
        return policy


async def check_rotation_policies(session: AsyncSession) -> list[UUID]:
    now = datetime.now(UTC)
    result = await session.execute(
        select(RotationPolicyModel).where(RotationPolicyModel.next_due_at <= now)
    )
    return [p.secret_id for p in result.scalars()]
