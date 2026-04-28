# News fragments

Every PR touching `src/pycoraza/**` or `pyproject.toml` must ship a
news fragment here. Format:

```
news/<slug>.<type>.md
```

Where `<type>` is one of:

- `security` — Security impact (bypass fix, hardening).
- `feature` — New API or new supported behavior.
- `change` — Behavior change (flag, default, config semantics).
- `fix` — Bug fix with no public API change.
- `removal` — Removed API or supported behavior.
- `legal` — Licensing / attribution / NOTICE changes.
- `misc` — Internal only; no user-visible change.

Example:

```
news/add-starlette-middleware.feature.md
```

Content is one or two sentences in plain English, imperative mood.
`towncrier build --version X.Y.Z` collapses these into `CHANGELOG.md`
at release time.
