# Security policy

## Reporting a vulnerability

Please report security issues privately through this repository's **Security →
Advisories → New draft security advisory** flow. Do not open a public issue for
a vulnerability that could expose wallet recovery material, authorize an
unintended transaction, alter deterministic execution, or break replica
verification.

Include the affected commit, operating system, exact reproduction steps, and
the smallest safe test case you can provide. Never include a real recovery
phrase, spending key, wallet file, agent token, or funded transaction secret.

## Supported code

Until tagged releases begin, only the current `main` branch receives security
fixes.

## Security boundaries

- Recovery material remains in the local wallet process.
- The browser extension contains no wallet keys.
- The agent listener has a separate token and method allowlist. It cannot
  export or import keys, change settings, create mandates, transfer, withdraw,
  or bind destinations.
- Agent mandates are verified during deterministic Zyn execution so replicas
  reproduce the authorization decision.
- The local HTTP wallet binds to loopback by default and requires the `X-Zyn`
  header for writes.

These properties are covered by tests, but the project has not had an
independent security audit.
