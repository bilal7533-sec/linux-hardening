# Architecture

```text
CLI: natural-language request
              |
              v
   AI bridge (OpenAI / Claude / Gemini)
   - asks for JSON planning only
   - never receives permission to run tools
              |
              v
  local schema + target + RFC1918 scope validation
              |
              v
       scanner adapter controller
         |          |          |
        Nmap      Nuclei    testssl.sh
         |          |          |
         +---- logs/raw artifacts ----+
                                     |
                                     v
                     inventory and run metadata
                                     |
                                     v
                         human validation/report
```

## Trust boundaries

- The LLM is an untrusted planner. It returns only a target and a fixed set of action labels.
- The local application validates the target against the configured private scope, applies the host budget and checks whether each adapter is enabled.
- Execution is a separate operator decision and requires the CLI execution flags and `authorized: true` in the local scope file.
- Scanner output is untrusted evidence. This MVP does not pass results back to the model for automated conclusions.
- A hosted AI provider receives the prompt text. Avoid sending secrets or sensitive organizational data.

## Adapter contract for future tools

Every future adapter must include a stable identifier, supported versions, explicit enablement, narrowly defined arguments (no shell interpolation), scope validation, timeout and rate/concurrency limits, cancellation behavior, parser fixtures, normalized finding schema and documented licensing/source provenance. An adapter must not run just because its binary is installed.
