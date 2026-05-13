# PEEK QA Prompts

End-to-end AI-orchestrated QA suite. Each prompt is hand-delivered to Claude Code; operator runs ONE prompt and reviews results.

## Files

| File | Role | Runtime |
|---|---|---|
| `end-to-end-qa.prompt` | Top-level orchestrator. Invokes peek-deploy + hellbox-qa. | 80–110 min |
| `peek-deploy.prompt` | Provisions EC2 + deploys PEEK via deploy/deploy.sh. | 12–20 min |
| `hellbox-qa.prompt` | Provisions hellbox + scan/remediate/scan loop. | 70–90 min |
| `setup-hellbox-v3.sh` | The hellbox builder (runs on hellbox EC2 via SSH). | 10–15 min |
| `remediate-hellbox.sh` | In-place hellbox hardening (runs on hellbox EC2 via SSH). | 3–5 min |

## How to use

### Full end-to-end (no existing PEEK)
Hand `end-to-end-qa.prompt` to Claude Code. It runs the full pipeline.

### Hellbox-only (existing PEEK)
Two options:
1. Hand `end-to-end-qa.prompt` with `SKIP_PEEK_DEPLOY=skip` and `EXISTING_PEEK_URL` set.
2. Hand `hellbox-qa.prompt` directly with `PEEK_API_URL` set in its config block.

### Just deploy PEEK (no hellbox)
Hand `peek-deploy.prompt` to Claude Code.

## State file convention

All three prompts share `tmp/peek-qa-state-<UTC timestamp>.json`. peek-deploy creates it; hellbox-qa appends to it; end-to-end-qa is just a wrapper.

## Teardown

Manual by design. After reviewing scan reports, instruct Claude Code:

> "Read tmp/peek-qa-state-<TIMESTAMP>.json and terminate the PEEK and hellbox EC2 instances."

The state file contains both instance IDs and the AWS region. Security groups (`peek-prod-sg`, `peek-hellbox-qa`) are reusable; leave them.
