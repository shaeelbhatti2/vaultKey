from vaultkey.api.app import create_app


def test_health_endpoint() -> None:
    app = create_app()
    assert app.title == "VaultKey"
