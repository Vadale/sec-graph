"""Command-line interface for sec-graph."""
from __future__ import annotations

import typer

app = typer.Typer(
    help="sec-graph - local taint/data-flow security map built on graphify."
)


@app.command()
def analyze(
    path: str,
    out_dir: str = "graphify-out",
    sarif: list[str] = typer.Option(None, "--sarif", help="Ingest findings from a SARIF file (repeatable)."),
    semgrep_json: list[str] = typer.Option(None, "--semgrep-json", help="Ingest semgrep --json output (repeatable)."),
) -> None:
    """Analyze PATH: graph.json (annotated) + taint.json + secgraph.html. With --sarif/--semgrep-json,
    ingest external SAST findings (the taint engine is skipped); otherwise run the built-in engine."""
    # Lazy import so `scan`/`view`/`--help` never pay graphify's import cost.
    from secgraph.project import analyze_ingest, analyze_project

    try:
        if sarif or semgrep_json:
            r = analyze_ingest(path, out_dir, sarif, semgrep_json)
        else:
            r = analyze_project(path, out_dir)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    if "report" in r:                                        # ingest mode: the binding report
        rep, b = r["report"], r["binding"]
        tools = sorted({t for inp in rep.inputs for t in inp["tools"]}) or ["?"]
        bound = b["span"] + b["nearest-def"] + b["file"]
        typer.echo(f"Ingested {rep.n_findings} finding(s) from {', '.join(tools)} — "
                   f"bound {bound}/{rep.n_findings} (span {b['span']}, nearest-def {b['nearest-def']}, "
                   f"file {b['file']}), {b['none']} unbound")
        for d in rep.dropped[:3]:
            typer.secho(f"  dropped: {d['uri']} ({d['reason']})", fg=typer.colors.YELLOW)
    typer.echo(f"Wrote {r['graph_json']}")
    typer.echo(f"      {r['taint_json']}")
    typer.echo(f"      {r['html']}   ({r['findings']} finding(s), {r['unguarded']} unguarded)")


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


@app.command(name="callgraph-stats")
def callgraph_stats(path: str) -> None:
    """Measure call resolution over PATH (ADR-007 KILL-GATE metrics: PCR / UNK / TRR)."""
    from secgraph.callgraph import binding_rate, build_index, resolve_all_sites, trr
    from secgraph.ir import build_project_ir
    from secgraph.rules import default_rules_dir, load_rules
    from secgraph.taint import run_project_full

    rules = load_rules(default_rules_dir())
    modules = build_project_ir(path)
    index = build_index(modules)
    _sites, rows = resolve_all_sites(modules, index, {}, rules)
    stats = binding_rate(rows)
    _findings, tainted = run_project_full(modules, rules)
    t = trr(rows, tainted)

    for cat in sorted(stats["counts"]):
        typer.echo(f"  {cat:18} {stats['counts'][cat]}")
    typer.echo(f"call sites: {stats['total']}  (method-call sites: {stats['method_sites']})")
    typer.echo(
        f"PCR (project-call resolution): {stats['PCR']:.1%}  "
        f"[bound={stats['bound']}, unresolved-project={stats['unresolved_project']}]"
    )
    typer.echo(
        f"UNK (unknown-receiver / method sites): {stats['UNK']:.1%}  "
        f"[unknown-receiver={stats['unknown_receiver']}]"
    )
    typer.echo(
        f"TRR (taint-relevant resolution): {t['TRR']:.1%}  "
        f"[{t['resolved']}/{t['tainted_sites']} tainted-path sites resolved]"
    )


@app.command()
def view(out_dir: str = "graphify-out") -> None:
    """Open the interactive layered map (secgraph.html) in a browser."""
    import webbrowser
    from pathlib import Path

    html = Path(out_dir) / "secgraph.html"
    if not html.exists():
        typer.secho(f"error: {html} not found - run `secgraph analyze <path>` first",
                    fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    webbrowser.open(html.resolve().as_uri())
    typer.echo(f"Opened {html}")


@app.command()
def serve(out_dir: str = "graphify-out") -> None:
    """Start the MCP server (stdio) exposing taint paths for LLM triage. Run `secgraph analyze`
    first; run this alongside `graphify --mcp`."""
    from pathlib import Path

    taint = Path(out_dir) / "taint.json"
    if not taint.exists():
        typer.secho(f"error: {taint} not found - run `secgraph analyze <path>` first",
                    fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    from secgraph.mcp_server import build_server

    build_server(out_dir).run()


if __name__ == "__main__":
    app()
