# HIVEBREACH Lessons Library (Self-Learning)

> Confirmed techniques, accumulated across engagements. Each entry is a **verified** technique with the engagement that proved it. New entries are appended by the self-learning pipeline (`tools/self-learn.py` or manual PR) after a finding passes R2 (deterministic PoC) and R5 (sandbox).

## How to Add a Lesson

1. Only add techniques that were **confirmed** (not tentative) with a reproduced PoC.
2. One entry per technique per environment class.
3. Redact all real credentials/PII (R8). Use `<REDACTED>`.
4. Link the MITRE ATT&CK ID and the relevant skill file.

## Lesson Entry Format

```markdown
### [TECHNIQUE NAME] — [ENGAGEMENT ID]
- **Date:** YYYY-MM-DD
- **Environment:** [web|api|cloud|network|mobile|ad|ics|container|ai]
- **MITRE ATT&CK:** T####
- **Skill Playbook:** skills/<category>/<file>.md
- **How it was found:** <1-2 lines>
- **Payload/PoC (redacted):**
  ```bash
  <command or payload>
  ```
- **Observable evidence:** <what proved it>
- **Lessons learned:** <avoided pitfall, bypass, or efficiency gain>
```

---

<!-- LESSONS START -->

<!-- LESSONS END -->

## Compounding Loop

- New confirmed technique → add lesson → skills/ library referenced → future agents load lesson via hivebreach router → technique reused → faster, deeper coverage.
- The `instinct/pattern-extractor` module auto-detects candidate lessons from session logs; `instinct/skill-generator` can scaffold new skill playbooks from patterns that recur across 2+ engagements.
- Review cadence: after every engagement, the orchestrator runs `tools/self-learn.py` to propose lessons; the operator approves before commit.
