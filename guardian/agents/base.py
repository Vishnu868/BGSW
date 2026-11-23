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
            if isinstance(msg.get("final"), (dict, list)):
                result["output"], result["evidence"] = msg["final"], evidence
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
            result["error"] = "no final answer within the step limit"
        return result
