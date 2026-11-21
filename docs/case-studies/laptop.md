# Case study: a developer laptop running three AI runtimes

*Illustrative scenario. Commands are real and reproducible.*

## The setup

A staff engineer works on a 14-inch laptop (macOS or Linux) with:

- Ollama for local models, launched with `OLLAMA_HOST=0.0.0.0`
- LM Studio and ComfyUI for experiments
- Claude Code and Cursor, with a handful of MCP servers
- a `.env` file per side project
- a few `.pt` checkpoints downloaded from the web

Nothing here is unusual. That is the point: none of it is covered by the
container scanner or the dependency bot.

## What enki found

```bash
enki scan
```

Representative output:

```
POSTURE 34/100 · AT RISK · 1 critical, 6 high, 4 medium, 1 low

CRITICAL AEP-001  Ollama exposed on 0.0.0.0:11434
         service: Ollama · probe: GET /api/tags → 200 (no auth) · CORS reflects origins
HIGH     MCP-001  Unpinned MCP server package "@upstash/context7-mcp"
HIGH     MCP-003  MCP server "openai-helper" embeds a credential
HIGH     AGT-001  Agent runs with bypassPermissions
HIGH     AGT-004  Agent may modify ~/.ssh
HIGH     SEC-001  OpenAI API key in .env (tracked by git)
MEDIUM   SEC-003  Credential file readable by other users
MEDIUM   MDL-001  4 pickle-based weight files in ~/models/vision
```

The posture score is the point of leverage: the laptop looks fine in a
terminal and a firewall scan from outside, yet any device on the coffee-shop
network can enumerate models through `11434`.

## The fix flow

```bash
enki fix                    # dry run: what would change, and how risky it is
```

```
[1] SAFE     chmod 0600 ~/.config/ai/.env                    SEC-001
[2] SAFE     chmod 0600 ~/.claude.json                       SEC-003
[3] MODERATE remove permissions.defaultMode from ~/.claude/settings.json  AGT-001
[4] RISKY    Bind Ollama to 127.0.0.1 or block inbound TCP/11434  AEP-001
             run: sudo ufw deny 11434/tcp
```

- SAFE actions apply immediately:

  ```bash
  enki fix --apply
  ```

- MODERATE edits are comment-preserving, backed up, and confirmed:

  ```bash
  enki fix --apply --include-moderate
  # Apply "Disable bypassPermissions..."? [y/N]
  ```

- RISKY actions are printed, never run. Firewall changes and rebinding are the
  operator's call. Rebinding is the better fix:

  ```bash
  # unset OLLAMA_HOST, or launch with OLLAMA_HOST=127.0.0.1
  ```

- Undo is byte-identical:

  ```bash
  enki undo
  ```

The TUI provides the same flow: `enki` → `f` → `1` applies, `y` confirms a
config edit, `u` undoes, `a` applies all SAFE actions.

## Preventing the repeat

- Pin every MCP package (`@scope/pkg@1.2.3`) and review upgrades.
- Keep provider keys in the OS keychain, not `.env`; add `.env` to
  `.gitignore`.
- Never launch local inference on `0.0.0.0`; if remote access is needed, put an
  authenticated proxy in front.
- Convert `.pt`/`.pkl` weights to safetensors when possible.

## Reproduce it

```bash
make build
./demo/run.sh        # starts a fake exposed Ollama on 0.0.0.0:11434
```

Then point `enki` at a project directory with a `.env` and an MCP config to see
the configuration findings.

## Takeaway

Most AI "incidents" on a laptop are plumbing: a bind address, a floating
package, a copied key, an auto-approve flag. enki turns them into a short,
reviewable list with reversible fixes — before the laptop joins a hostile
network.
