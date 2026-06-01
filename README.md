# podmaker-bridge

Loopback HTTP daemon that exposes the operator's locally
installed credential CLIs (aws-vault, pass, sops, op, bw,
gcloud, az) to the PodMaker SaaS web UI over
`http://127.0.0.1:7766`. CORS-locked to the SaaS
origin, optional bearer token.

Distinct from
[podmaker-sh/vault-bridge-agent](https://github.com/podmaker-sh/vault-bridge-agent),
which is the customer-side outbound proxy for remote vault
calls. This one is for the operator's own machine —
autofill cloud / DNS credential forms without copy-pasting
from a terminal.

Source of truth lives in the private monorepo at
`podmaker-sh/podmaker` under `apps/podmaker-bridge`.
This repo is a read-only mirror, refreshed on every push
to monorepo `main`.

## Install (operator workstation)

```sh
go install podmaker.sh/apps/podmaker-bridge/cmd/podmaker-bridge@latest
podmaker-bridge
```

## Issues + PRs

File against this mirror — forwarded to the monorepo by
maintainers.
