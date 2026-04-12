import json
import os
from pathlib import Path

import httpx
import typer
from rich.console import Console

app = typer.Typer(name="vaultkey", help="VaultKey secrets manager CLI", no_args_is_help=True)
console = Console()
CONFIG_DIR = Path.home() / ".vaultkey"
CONFIG_FILE = CONFIG_DIR / "config"


def _ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)


def _load_config() -> dict[str, str]:
    if not CONFIG_FILE.exists():
        return {}
    return json.loads(CONFIG_FILE.read_text())


def _save_config(data: dict[str, str]) -> None:
    _ensure_config_dir()
    CONFIG_FILE.write_text(json.dumps(data, indent=2))
    os.chmod(CONFIG_FILE, 0o600)


@app.callback()
def main() -> None:
    pass


@app.command("login")
def login_cmd(
    api_url: str = typer.Option("http://localhost:8090", prompt=True),
    email: str = typer.Option(..., prompt=True),
    password: str = typer.Option(..., prompt=True, hide_input=True),
) -> None:
    with httpx.Client(base_url=api_url, timeout=30.0) as client:
        response = client.post("/auth/login", json={"email": email, "password": password})
        response.raise_for_status()
        token = response.json()["access_token"]
    cfg = _load_config()
    cfg["api_url"] = api_url
    cfg["access_token"] = token
    _save_config(cfg)
    console.print("[green]logged in[/green]")


@app.command("logout")
def logout_cmd() -> None:
    cfg = _load_config()
    cfg.pop("access_token", None)
    _save_config(cfg)
    console.print("[yellow]logged out[/yellow]")


@app.command("version")
def version_cmd() -> None:
    typer.echo("vaultkey 0.1.0")
