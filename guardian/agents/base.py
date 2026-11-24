"""One agent engine shared by all five agents (provider-agnostic, works on Claude, Gemini and Groq).

Protocol - the model replies with ONE JSON object:
    {"tool": "<name>", "args": {...}, "why": "..."}   -> we run the read-only tool, result becomes evidence E<n>
    {"final": {...}}                                  -> the agent's answer (then checked by the symbolic verifier)
Only the tools listed for that agent can run; anything else returns an error to the model.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

PROTOCOL = """
Reply with exactly ONE JSON object, either
  {"tool": "<tool name>", "args": {...}, "why": "<one sentence>"}
or
  {"final": <your answer in the required format>}
Use only facts returned by tools or given in the case. Every tool result and the case itself have evidence ids
(E1, E2, ...); cite them in "evidence_refs". Never invent package names, versions, CVEs or file paths.
If the evidence is insufficient, say so and lower your confidence - escalating is better than guessing."""


@dataclass
class Agent:
    name: str
    title: str
    mission: str
    output_format: str
    tools: list = field(default_factory=list)
    max_steps: int = 4

    def system(self, tool_docs: dict) -> str:
        tools = "\n".join(f"  {t}{tool_docs.get(t, '')}" for t in self.tools) or "  (none - answer directly with final)"
        return (f"You are the {self.title} of a Software Supply Chain Guardian (a multi-agent system).\n"
                f"{self.mission}\n\nRequired final format:\n{self.output_format}\n\nTools:\n{tools}\n{PROTOCOL}")

    def run(self, router, case: dict, toolbox, purpose: str) -> dict:
        """-> {"agent", "output" (raw final or None), "steps", "evidence", "provider", "error"}"""
        result = {"agent": self.name, "output": None, "steps": [], "evidence": {}, "provider": "rules", "error": ""}
        if hasattr(router, "for_agent"):
            router = router.for_agent(self.name.split("_")[0] if self.name.startswith("lead") else self.name)
        if not router.enabled:
            result["error"] = "no LLM configured"
            return result
        evidence = {"E1": {"tool": "case", "result": case}}
        transcript = [f"CASE (evidence E1):\n{json.dumps(case, default=str)[:6000]}"]
        system = self.system(toolbox.docs)
        for step in range(self.max_steps):
            last = step == self.max_steps - 1
            msg, meta = router.ask_json(system, "\n\n".join(transcript)[-14000:] +
                                        ("\n\nNo more tool calls: reply with final now." if last else ""),
                                        purpose=f"{self.name}: {purpose} (step {step + 1})")
            if msg is None:
                result["error"] = "; ".join(meta.get("errors", []))[:300] or "LLM unavailable"
                break
            result["provider"] = f"{meta['provider']}:{meta['model']}"
            final = _as_final(msg)
            if final is not None:
                result["output"], result["evidence"] = final, evidence
                return result
            name = str(msg.get("tool", ""))
            args = msg.get("args") if isinstance(msg.get("args"), dict) else {}
            if name not in self.tools:
                res = {"error": f"tool '{name}' is not available to the {self.title}"}
            else:
                res = toolbox.run(name, args)
            eid = f"E{len(evidence) + 1}"
            evidence[eid] = {"tool": name, "args": args, "result": res}
            result["steps"].append({"step": step + 1, "tool": name, "args": args, "why": msg.get("why", ""), "evidence_id": eid})
            transcript.append(f"You called {name}({json.dumps(args)}) because: {msg.get('why', '')}\n"
                              f"{eid} = {json.dumps(res, default=str)[:3000]}")
        result["evidence"] = evidence
        if not result["error"]:
            # Steps used up (weaker models keep asking for tools): one closing call that offers no tools at all,
            # so the agent must decide from the evidence it already gathered. The verifier still checks the answer.
            closing = (f"You are the {self.title} of a Software Supply Chain Guardian (a multi-agent system).\n{self.mission}\n\n"
                       f"Required final format:\n{self.output_format}\n\nYou have no tools left. Reply with exactly ONE JSON "
                       'object {"final": <your answer in the required format>}, citing evidence ids (E1, E2, ...) '
                       "from the transcript. If the evidence is insufficient, say so and lower your confidence.")
            msg, meta = router.ask_json(closing, "\n\n".join(transcript)[-14000:] + "\n\nGive your final answer now.",
                                        purpose=f"{self.name}: {purpose} (closing)")
            final = _as_final(msg) if msg is not None else None
            if final is not None:
                result["provider"] = f"{meta['provider']}:{meta['model']}"
                result["output"] = final
                result["steps"].append({"step": len(result["steps"]) + 1, "tool": "(closing answer)", "args": {},
                                        "why": "step limit reached: answered from the evidence gathered", "evidence_id": ""})
                return result
            result["error"] = "no final answer within the step limit"
        return result


def _as_final(msg) -> dict | list | None:
    """Accept the final answer in the shapes models actually send: {"final": {...}}, a tool call named "final",
    or the answer object itself without the wrapper (no "tool" key)."""
    if not isinstance(msg, dict):
        return None
    if isinstance(msg.get("final"), (dict, list)):
        return msg["final"]
    if str(msg.get("tool", "")).lower() in ("final", "final_answer", "answer") and isinstance(msg.get("args"), dict):
        return msg["args"]
    if "tool" not in msg and msg and not set(msg) <= {"why", "args"}:
        return msg
    return None
