# Real-world benchmark corpus

`realworld.json` contains pinned public-source cases. The harness fetches each
file from `raw.githubusercontent.com` at the pinned commit, verifies its SHA256,
and never redistributes the content. Public files are selected examples, not a
random sample.

`ecosystem/` contains real npm registry lockfiles generated with:

```sh
npm init -y
npm install lodash@4.17.20 --package-lock-only --ignore-scripts --no-audit --no-fund
npm install lodash@4.17.21 --package-lock-only --ignore-scripts --no-audit --no-fund
```

They are labeled against a pinned lodash advisory in the benchmark harness.
No credentials or live secrets are stored here.
