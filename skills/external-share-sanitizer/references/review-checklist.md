# External-sharing semantic review

Use this checklist after the deterministic scanner. The scanner cannot decide whether a provider, customer, person, project, or operational detail is identifying in the current business context.

## 1. Direct secrets and access material

- API keys, access keys, tokens, passwords, authorization headers, cookies, private keys, signed URLs, connection strings, and temporary credentials.
- Credentials hidden in command history, screenshots, document properties, worksheet cells, speaker notes, comments, filenames, or embedded objects.
- If a live credential appears, do not reproduce it in the manifest. State only its category and location, and recommend rotation when exposure may have occurred.

## 2. Provider and source attribution

- Company, product, model-family, platform, region, endpoint, hostname, SDK, error-code, and documentation names.
- Resource, deployment, endpoint, group, tenant, project, channel, account, or billing identifiers that a service operator could correlate with logs.
- Distinctive response fields, error wording, routing behavior, or model limitations that indirectly identify the source.
- Decide whether each attribution fact is necessary for the recipient to reproduce the problem. Generalize or remove it otherwise.

## 3. People, customers, and internal context

- Names, usernames, emails, phone numbers, organization names, account IDs, user IDs, chat IDs, request IDs, trace IDs, and source filenames.
- Local paths, device/user names, workspace names, timestamps, time zones, repository remotes, internal hosts, environment labels, and deployment topology.
- Business status, commercial terms, quota, balances, test periods, safety settings, or unpublished features.
- Screenshots and media may contain identity or operational data that text scanning cannot see.

## 4. Minimal reproducible package

Retain only what the recipient needs to diagnose the current issue:

- Expected behavior, actual behavior, protocol/operation, sanitized request shape, sanitized response/error shape, and relevant version information.
- Remove unrelated successful cases, duplicated payloads, billing details, historical conversations, and broad environment dumps.
- Replace stable identifiers consistently so cross-reference remains possible without revealing the original value.
- Do not invent evidence. Mark omitted, unknown, or unverified facts explicitly.

## 5. Responsibility classification

When the deliverable attributes a problem, classify each item as:

- `platform`: evidence shows the local gateway, adapter, validation, routing, or reporting layer caused it.
- `upstream`: evidence shows the provider returned or enforced the behavior.
- `shared/interaction`: both layers contribute or protocol translation is involved.
- `unknown`: available evidence cannot distinguish the cause.
- `not a defect`: invalid input, unsupported media, quota, permissions, or an unmet prerequisite.

Include evidence and confidence. Do not turn absence of evidence into a definitive upstream or platform conclusion.

## 6. Change manifest schema

For each change, record:

| Field | Content |
| --- | --- |
| Relative location | File and line, section, sheet/cell, slide, XML part, or visual region |
| Category | Credential, identity, provider, resource ID, path, metadata, business context, or unrelated data |
| Action | Removed, generalized, replaced consistently, retained, or requires manual review |
| Reason | Disclosure risk and why the retained evidence is sufficient |
| Verification | Scanner rule, visual check, document-property check, or human semantic review |

Never place the original sensitive value in this manifest.

## 7. Stop gates

Return `blocked` or `needs changes` when:

- A live credential or reusable signed URL remains.
- A PDF, image, embedded object, database, or unknown binary has not received format-specific review.
- The sanitized copy cannot reproduce the problem without reintroducing identifying data and the user has not chosen the tradeoff.
- Responsibility is being stated more strongly than the evidence supports.
- The requested external send, upload, publication, or visibility change has not been explicitly authorized.
