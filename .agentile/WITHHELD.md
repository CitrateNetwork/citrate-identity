# Withheld from public release

For transparency: the development record in this `.agentile/` directory is published with
client identities, individual names (other than the founder), infrastructure addresses,
vendor names, and business/financial figures redacted for confidentiality — the intent is
to show *how* we build, not to disclose the business or its partners.

One document was withheld entirely, because its core is legal-confidential rather than
engineering:

- `planset/adr/COUNSEL_REVIEW_PACKET.md` — a counsel-routing cover sheet of pre-decisional
  legal sign-off questions and a named compliance signatory. Its **engineering** substance
  (auto-verify defensibility, KMS/liveness residual-risk handling, IAL2 assertion, custody
  separation-of-duties) is fully published in the redacted `ADR-AV-1..5` in this directory.

Questions: security@citrate.ai.

Also excluded (operational deploy records, not narrative — the engineering story is in
the ADRs above): `deploys/*/DEPLOY_LOG.md` (5 files). Infra addresses were redacted, but
raw per-deploy logs are kept out of the public record by policy.
