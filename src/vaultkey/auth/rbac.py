from uuid import UUID

from vaultkey.shared.domain import RoleName


ROLE_HIERARCHY: dict[RoleName, int] = {
    RoleName.READONLY: 1,
    RoleName.AUDITOR: 2,
    RoleName.OPERATOR: 3,
    RoleName.ADMIN: 4,
    RoleName.OWNER: 5,
}


SCOPE_MAP: dict[str, RoleName] = {
    "read:secrets": RoleName.READONLY,
    "write:secrets": RoleName.OPERATOR,
    "admin": RoleName.ADMIN,
}


class AuthorizationError(Exception):
    pass


def role_at_least(actual: RoleName, required: RoleName) -> bool:
    return ROLE_HIERARCHY[actual] >= ROLE_HIERARCHY[required]


def scopes_allow(scopes: list[str], required: str) -> bool:
    if "admin" in scopes:
        return True
    if required in scopes:
        return True
    if required == "read:secrets" and "write:secrets" in scopes:
        return True
    return False


class PermissionChecker:
    def require_role(self, actual: RoleName, required: RoleName) -> None:
        if not role_at_least(actual, required):
            raise AuthorizationError("insufficient role")

    def require_scope(self, scopes: list[str], required: str) -> None:
        if not scopes_allow(scopes, required):
            raise AuthorizationError("insufficient scope")

    def can_read_path(self, role: RoleName, path_prefix: str, secret_path: str) -> bool:
        normalized = secret_path.strip("/")
        prefix = path_prefix.strip("/")
        if not normalized.startswith(prefix):
            return False
        return role_at_least(role, RoleName.READONLY)

    def can_write_path(self, role: RoleName, path_prefix: str, secret_path: str, can_write: bool) -> bool:
        if not can_write:
            return False
        normalized = secret_path.strip("/")
        prefix = path_prefix.strip("/")
        if not normalized.startswith(prefix):
            return False
        return role_at_least(role, RoleName.OPERATOR)
