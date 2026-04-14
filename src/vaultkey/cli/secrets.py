import json
from uuid import UUID

import httpx
import typer
from rich.console import Console
from rich.table import Table

from vaultkey.cli.main import CONFIG_FILE, _load_config, app

console = Console()
secrets_app = typer.Typer(help="Secret operations")
app.add_typer(secrets_app, name="secret")


def _client() -> httpx.Client:
    cfg = _load_config()
    token = cfg.get("access_token")
    if not token:
        raise typer.Exit(code=1)
    headers = {"Authorization": f"Bearer {token}"}
    return httpx.Client(base_url=cfg.get("api_url", "http://localhost:8090"), headers=headers, timeout=30.0)


@secrets_app.command("list")
def list_cmd(
    environment_id: UUID = typer.Option(...),
    prefix: str = typer.Option(""),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    with _client() as client:
        response = client.get("/v1/secrets", params={"environment_id": str(environment_id), "prefix": prefix})
        response.raise_for_status()
        data = response.json()
    if json_out:
        typer.echo(json.dumps(data, indent=2))
        return
    table = Table(title="Secrets")
    table.add_column("Path")
    table.add_column("Version")
    for item in data["items"]:
        table.add_row(item["path"], str(item["current_version"]))
    console.print(table)


@secrets_app.command("get")
def get_cmd(
    path: str,
    environment_id: UUID = typer.Option(...),
    version: int | None = typer.Option(None),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    params: dict[str, str | int] = {"environment_id": str(environment_id)}
    if version is not None:
        params["version"] = version
    with _client() as client:
        response = client.get(f"/v1/secrets/{path}", params=params)
        response.raise_for_status()
        data = response.json()
    if json_out:
        typer.echo(json.dumps(data, indent=2))
    else:
        console.print(f"[bold]{data['path']}[/bold] v{data['version']}")


@secrets_app.command("set")
def set_cmd(
    path: str,
    value: str = typer.Option(..., prompt=True, hide_input=True),
    environment_id: UUID = typer.Option(...),
) -> None:
    with _client() as client:
        response = client.post(
            f"/v1/secrets/{path}",
            params={"environment_id": str(environment_id)},
            json={"payload": value},
        )
        response.raise_for_status()
    console.print(f"[green]set {path}[/green]")


@secrets_app.command("delete")
def delete_cmd(path: str, environment_id: UUID = typer.Option(...)) -> None:
    with _client() as client:
        response = client.delete(f"/v1/secrets/{path}", params={"environment_id": str(environment_id)})
        response.raise_for_status()
    console.print(f"[red]deleted {path}[/red]")
