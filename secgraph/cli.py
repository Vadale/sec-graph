"""Command-line interface for sec-graph."""
from __future__ import annotations

import typer

app = typer.Typer(
    help="sec-graph - local taint/data-flow security map built on graphify."
)


@app.command()
def analyze(path: str, out_dir: str = "graphify-out") -> None:
    """Analyze PATH: build graph.json (taint.json + secgraph.html come later)."""
    # Lazy import so `view`/`serve`/`--help` never pay graphify's import cost, and so
    # the quarantine wall stays put: the CLI imports the adapter, never graphify.
    from secgraph import graphify_adapter

    try:
        result = graphify_adapter.run_graphify(path, out_dir)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    typer.echo(
        f"Wrote {result.graph_json} "
        f"({result.n_nodes} nodes, {result.n_edges} edges, {result.n_calls} calls)"
    )


@app.command()
def view() -> None:
    """Open the interactive layered map (secgraph.html)."""
    raise NotImplementedError("ROADMAP.md Phase 5")


@app.command()
def serve() -> None:
    """Start the MCP server for LLM triage (run alongside `graphify --mcp`)."""
    raise NotImplementedError("ROADMAP.md Phase 6")


if __name__ == "__main__":
    app()
