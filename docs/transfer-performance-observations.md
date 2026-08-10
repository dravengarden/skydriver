# Transfer performance observations

This document describes how to collect reproducible transfer measurements. It
does not contain results from a private deployment; contributors should keep
environment-specific measurements outside the public repository unless they
have been intentionally anonymized and reviewed.

## Measurement rules

- Record the client, commit, driver kind, object size, block or part size, and
  concurrency for every run.
- Measure upload, download, interruption, and resume separately.
- Use a disposable test directory and a short-lived VFS token.
- Record UTC start and finish times, elapsed time, retries, and the exact
  verification result. Do not record tokens, filenames containing personal
  data, provider credentials, or private URLs.
- Repeat each configuration enough times to distinguish a stable change from
  network variance.

The live acceptance scripts emit timing fields for diagnosis, but timing is
advisory. It is not an integrity proof, quota measurement, billing record, or
authorization signal.

## Running a measurement

Build the release client through the pinned development shell, then provide a
deployment URL and a disposable token explicitly:

```bash
nix develop -c cargo build -p skydriver-cli --release --locked
export SKYDRIVER_CONTROL_URL='https://dev.skydriver.example'
export SKYDRIVER_VFS_TOKEN='<short-lived test token>'
SKYDRIVER_R2_LIVE_TEST=1 nix develop -c tests/r2-live.sh
```

The live tests are skipped by the normal test command unless their opt-in
environment variable is set. Any failed cleanup must be retried and the token
must be revoked before comparing another run.
