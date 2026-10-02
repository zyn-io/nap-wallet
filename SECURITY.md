# Security policy

## Reporting a vulnerability

Report security issues privately through this repository's **Security →
Advisories → New draft security advisory**. Do not open a public issue for
anything that could expose recovery words or keys, approve a transaction the
holder did not see, or let a site act without approval.

Include the commit, browser, exact steps, and the smallest safe test case.
Never include a real recovery phrase, key, or funded wallet.

## Supported code

Only the latest release and `main` receive fixes.

## Boundaries

- Recovery words and keys are made on the device. A wallet kept in the browser
  is sealed under the holder's password; the extension holds unlocked keys in
  session storage and forgets them after 15 minutes idle.
- Sites never receive keys. They reach Nap through Nap Connect, and every
  request that moves value or signs is shown in Nap's own window to approve.
- Each approval names the asking site and the network, and shows the amounts
  the chain will use.

These are covered by tests. The project has not had an independent security
audit.
