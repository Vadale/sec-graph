"""sec-graph MCP server (ROADMAP §13/§15): a thin FastMCP wrapper over ``TaintView`` exposing the
read-only triage tools + the canned defensive triage prompts. Runs over stdio, alongside
``graphify --mcp`` (entity-level questions stay with graphify; data-flow paths are ours). The
analysis is already done and deterministic -- this server never runs an LLM or the taint engine.
"""
from __future__ import annotations

from pathlib import Path

from .mcp_view import TaintView

# §15.1 -- defensive framing is mandatory.
SYSTEM_PROMPT = """\
You are a defensive application-security assistant helping a developer audit and FIX their own
code, over a static data-flow tool (sec-graph) via MCP.

Rules of engagement:
- Purpose is defensive: find, explain, and remediate. Never produce a weaponized exploit or
  instructions to attack systems the user doesn't own.
- Ground every claim in the provided slice and provenance. If evidence is insufficient, say so and
  request a specific tool call (get_function_taint, get_path_slice) instead of guessing.
- Prefer get_path_slice over reading whole files. Stay token-frugal.
- Distinguish CONFIRMED (visible in the slice) from PLAUSIBLE (depends on unseen code). Respect
  confidence/provenance; a truncated path means an unresolved call -- flag the assumption."""


def _fmt_windows(slice_: dict) -> str:
    if "error" in slice_:
        return f"(no slice: {slice_['error']})"
    out: list[str] = []
    for w in slice_.get("windows", []):
        stale = "  [STALE: file changed since analysis]" if w.get("stale") else ""
        out.append(f"# {w['role']} -- {w['file']}:{w['line']}{stale}")
        for ln in w.get("code", []):
            out.append(f"{'>' if ln['mark'] else ' '} {ln['n']:>5}  {ln['text']}")
    return "\n".join(out)


def render_path_prompt(view: TaintView, path_id: str) -> str:
    """§15.2 -- the per-path 'sniper' triage prompt, parameterized by path_id."""
    s = view.get_path_slice(path_id)
    if "error" in s:
        return f"No such path {path_id!r}. Call list_paths first."
    return f"""\
Triage this data-flow path for exploitability.

Layers: {', '.join(s['layers'])}   Confidence: {s['confidence']}   Unguarded: {s['unguarded']}   \
Guards: {', '.join(s['guards']) or 'none'}   CWE: {s['cwe']}

Path slice (source -> sink, minimal lines):
{_fmt_windows(s)}

Answer concisely:
1. Is the source genuinely attacker-controlled here? Why.
2. Does anything on the path actually sanitize the value for this sink? If a helper is opaque, say
   what you'd need to confirm.
3. Verdict: CONFIRMED / PLAUSIBLE / FALSE-POSITIVE + one-line justification.
4. Severity (reasoned), factoring whether an auth barrier is crossed (Unguarded above).
5. Minimal idiomatic fix at the right hop. Prefer the structural fix (e.g. a parameterized query)
   over masking the symptom."""


def render_layer_prompt(view: TaintView, layer: str) -> str:
    """§15.3 -- the layer-explanation prompt, parameterized by layer."""
    prov = view.explain_layer(layer)
    if prov.get("error"):
        return f'No layer "{layer}" in this project. Known layers: {prov.get("known", [])}.'
    ask = ("List the top 3 riskiest tagged nodes and what to check for each."
           if prov.get("tagged_nodes")
           else f"This layer is a path-level property (no nodes carry it directly); explain the "
                f"{prov.get('path_count', 0)} affected path(s) and what a developer should check.")
    return f"""\
Explain, for a developer, what the "{layer}" layer shows in this project and why it was tagged,
using only this deterministic provenance (do not invent nodes absent from it):

{prov}

{ask}"""


def build_server(out_dir: Path | str):
    """Build the FastMCP server backed by the artifacts in ``out_dir`` (graph.json + taint.json)."""
    from mcp.server.fastmcp import FastMCP

    view = TaintView(out_dir)
    mcp = FastMCP("sec-graph")

    @mcp.tool()
    def list_paths(layer: str | None = None, min_confidence: str | None = None,
                   file: str | None = None, limit: int = 50, offset: int = 0) -> dict:
        """Ranked data-flow path summaries (unguarded + high-severity first). Filter by security
        `layer` (e.g. credentials, dangerous-sink), `min_confidence` (low|medium|high), or `file`.
        Coarse discovery -- follow up with get_path_slice for the code."""
        return view.list_paths(layer, min_confidence, file, limit, offset)

    @mcp.tool()
    def get_path_slice(path_id: str, context_lines: int = 3) -> dict:
        """The minimal, hash-verified source->sink code windows for one path (the token-efficient
        payload). Flags a window `stale` if its file changed since analysis."""
        return view.get_path_slice(path_id, context_lines)

    @mcp.tool()
    def find_unguarded_sinks(layer: str | None = None) -> dict:
        """Paths reaching a dangerous sink with no auth barrier detected on the path (guards == [])."""
        return view.find_unguarded_sinks(layer)

    @mcp.tool()
    def explain_layer(layer: str) -> dict:
        """Deterministic rule/dictionary provenance for a security layer + the nodes it tagged."""
        return view.explain_layer(layer)

    @mcp.tool()
    def get_function_taint(node_id: str) -> dict:
        """Taint summary for one graphify entity node: its layers + the paths passing through it."""
        return view.get_function_taint(node_id)

    @mcp.prompt()
    def triage_system() -> str:
        """The defensive triage system prompt to open a session with."""
        return SYSTEM_PROMPT

    @mcp.prompt()
    def triage_path(path_id: str) -> str:
        """The per-path triage prompt (embeds the minimal slice)."""
        return render_path_prompt(view, path_id)

    @mcp.prompt()
    def explain_layer_prompt(layer: str) -> str:
        """A prompt to explain one layer from its deterministic provenance."""
        return render_layer_prompt(view, layer)

    return mcp
