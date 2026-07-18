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
def scan(path: str) -> None:
    """Scan PATH for intraprocedural taint findings (source -> sink). Phase 2."""
    # No graphify needed: this drives the IR + taint engine directly.
    from secgraph.taint import scan_project

    findings = scan_project(path)
    for f in findings:
        typer.echo(
            f"{f.severity.upper():8} {f.cwe or '-':7} {f.source_file}: "
            f"{f.source_id}@L{f.source_line} -> {f.sink_id}@L{f.sink_line} "
            f"[{','.join(f.layers)}] ({f.confidence})"
        )
    typer.echo(f"{len(findings)} finding(s).")


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
