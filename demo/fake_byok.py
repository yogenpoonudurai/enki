#!/usr/bin/env python3
"""Fake OpenAI-compatible endpoint for testing enki BYOK end to end.

Serves POST /v1/chat/completions on 127.0.0.1, records the request body, and
returns a schema-valid triage result referencing real finding IDs.
No external network calls, no real key.
"""
import http.server
import json
import os
import re
import sys

LOG_PATH = os.environ.get("ENKI_FAKE_BYOK_LOG", "/tmp/enki-byok-request.json")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        req = json.loads(self.rfile.read(length))
        messages = req.get("messages", [])
        system = next((m["content"] for m in messages if m.get("role") == "system"), "")
        user = next((m["content"] for m in messages if m.get("role") == "user"), "")

        payload = {}
        match = re.search(r"<<<ENKI_DATA\n(.*)\nENKI_DATA>>>", user, re.S)
        if match:
            payload = json.loads(match.group(1))

        findings = payload.get("findings", [])
        system_ctx = payload.get("system") or {}
        firewalls = system_ctx.get("firewall_tools") or []
        tool = firewalls[0] if firewalls else "the OS firewall"

        top = []
        if findings:
            first = findings[0]
            top.append({
                "finding_id": first["id"],
                "rule_id": first["rule_id"],
                "priority": 1,
                "why": "Highest-risk finding in this scan.",
                "fix_steps": [
                    f"Use {tool} or rebind the service to loopback." if "AEP" in first["rule_id"]
                    else "Apply the suggested remediation, then re-run enki.",
                    "Restart the service if its bind address changed.",
                    "Verify with: enki scan",
                ],
                "recommended_action": "manual",
                "action_verified": True,
            })
            for f in findings[1:]:
                action = (f.get("remediation") or {}).get("action")
                if action:
                    top.append({
                        "finding_id": f["id"],
                        "rule_id": f["rule_id"],
                        "priority": 2,
                        "why": "Stored credential can be read by other local users.",
                        "fix_steps": [f"Run enki fix --apply for {f['rule_id']}, then rotate the key."],
                        "recommended_action": action,
                        "action_verified": True,
                    })
                    break

        out = {
            "summary": "BYOK smoke test: triage returned with local system context.",
            "top": top,
        }
        with open(LOG_PATH, "w", encoding="utf-8") as fh:
            json.dump({"system_prompt": system, "payload": payload, "raw_user": user}, fh, indent=2)

        body = json.dumps({
            "model": "fake-byok-model",
            "choices": [{"message": {"content": json.dumps(out)}}],
            "usage": {"prompt_tokens": 900, "completion_tokens": 120},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18999
    http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
