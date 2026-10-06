# publish-lab-action

The one way CyberCTF labs register with the catalogue. A lab repository calls this action from its
publish workflow; the action reads the lab's `.ctf/metadata.json` and generated `.isoloom/` tree,
validates them, and calls `publishLab` on CyberBackend.

It is public so public lab repos can use it; the backend and token endpoints are passed in from organization secrets, so they live in no repo or log, not even here.

## Use it

In a lab repo, `.github/workflows/publish.yml`:

```yaml
name: Register lab
on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: production        # required: the approval gate (see Protection)
    steps:
      - uses: actions/checkout@v4
      - uses: isoloom/isoloom@v0.7.2
      - run: isoloom generate       # so providers are derived from a current tree
      - uses: CyberCTF/publish-lab-action@v1
        with:
          client_id: ${{ secrets.CYBERAUTH_CLIENT_ID }}
          client_secret: ${{ secrets.CYBERAUTH_CLIENT_SECRET }}
          backend_url: ${{ secrets.CYBERBACKEND_URL }}
          token_url: ${{ secrets.CYBERAUTH_TOKEN_URL }}
```

`CYBERAUTH_CLIENT_ID` / `CYBERAUTH_CLIENT_SECRET` are **organization** secrets (set once for CyberCTF,
scoped to the lab repos), so rotation is one place and there is no per-repo copy. The endpoints are
defaults baked into this action and are masked in logs; lab repos never carry them.

## Protection against a malicious lab

A push to a lab repo must not be able to publish on its own. Two controls:

- **Approval gate.** The publish job targets a GitHub **Environment** (`production`) with **required
  reviewers**. A push starts the workflow but the publish waits for a maintainer to approve. Set this
  up once per lab repo (Settings -> Environments -> `production` -> required reviewers), or via an org
  ruleset. The org secrets should be environment-scoped to `production` so they are only available
  after approval.
- **Untrusted input.** The action treats the lab's own files as hostile and cannot be steered by them:
  - The GraphQL call is fully parameterised and every request body is a native object; nothing from
    the repo is ever interpolated into a shell command or a query string (the action is Node, not a
    shell script).
  - `repository` and `commit` come from the trusted GitHub context, never from metadata.
  - `slug` is pinned to the repository name, so a repo can only (re)publish its own lab and can never
    overwrite another lab's slug.
  - Only the calling owner (`CyberCTF` by default) may publish; another owner is refused.
  - `providers` are derived from the generated tree against a fixed allowlist; unknown directory names
    are ignored, and `metadata.providers` may only narrow the set, never add a target.
  - Every string is length-bounded and rejected if it contains control characters; `category`,
    `evidence_kind` and `capabilities` must be enum-style tokens; `difficulty` must be 1..5.
  - Credentials, the token and the endpoints are masked in the log.

## Future hardening

Move from the org secret to keyless **GitHub OIDC**: the lab's workflow mints a short-lived OIDC
token and CyberAuth federates it (verifying the issuer and that the repo is under CyberCTF), so no
long-lived secret is stored anywhere. Needs a one-time CyberAuth change to trust GitHub's OIDC.
