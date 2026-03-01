import typer

app = typer.Typer(name="vaultkey", help="VaultKey secrets manager CLI", no_args_is_help=True)


@app.callback()
def main() -> None:
    pass


@app.command("version")
def version_cmd() -> None:
    typer.echo("vaultkey 0.1.0")
