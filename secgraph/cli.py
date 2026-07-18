"""Command-line interface for sec-graph."""
from __future__ import annotations

import typer

app = typer.Typer(
    help="sec-graph - local taint/data-flow security map built on graphify."
)


@app.command()
def analyze(path: str) -> None:
    """Analyze PATH: build graph.json + taint.json + secgraph.html."""
    raise NotImplementedError("WP0 / ROADMAP.md Phase 0")


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
