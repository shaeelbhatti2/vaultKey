import os
import subprocess
import sys

import httpx
import typer
from rich.console import Console

from vaultkey.cli.main import _load_config, app

console = Console()
run_app = typer.Typer(help="Run command with injected secrets")
app.add_typer(run_app, name="run")


@run_app.command("exec")
def run_exec(
    env_name: str = typer.Option("dev", "--env"),
    environment_id: str = typer.Option(...),
    prefix: str = typer.Option(""),
    command: list[str] = typer.Argument(...),
) -> None:
    cfg = _load_config()
    token = cfg.get("access_token")
    if not token:
        raise typer.Exit(code=1)
    headers = {"Authorization": f"Bearer {token}"}
    base_url = cfg.get("api_url", "http://localhost:8090")
    with httpx.Client(base_url=base_url, headers=headers, timeout=30.0) as client:
        response = client.get("/v1/secrets", params={"environment_id": environment_id, "prefix": prefix})
        response.raise_for_status()
        items = response.json()["items"]
        env_vars: dict[str, str] = {}
        for item in items:
            detail = client.get(
                f"/v1/secrets/{item['path']}",
                params={"environment_id": environment_id},
            )
            detail.raise_for_status()
            key = item["path"].replace("/", "_").upper()
            env_vars[key] = detail.json()["payload"]
    merged = os.environ.copy()
    merged.update(env_vars)
    console.print(f"[cyan]injecting {len(env_vars)} vars for {env_name}[/cyan]")
    result = subprocess.run(command, env=merged)
    raise typer.Exit(code=result.returncode)
