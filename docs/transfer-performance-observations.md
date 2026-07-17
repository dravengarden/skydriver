# Transfer performance observations

This document is an append-only record of real Carrack transfer observations.
It is not a throughput guarantee, provider benchmark, billing record, or basis
for weakening integrity checks. Add a dated subsection for future runs instead
of replacing earlier results.

Every accepted sample must still complete the encoded identity, frame AEAD,
plaintext length, plaintext Merkle, publication, resume, and logical-removal
checks in the live acceptance script. A timeout or incomplete JSON result is a
failed acceptance even when earlier transfer stages emitted sampled telemetry.

## 2026-07-17 development environment

### Measurement context

- Client host: `hawk`, through its then-current network path.
- Control plane: `https://dev.carrack.stormbird.xyz`.
- Client version: `0.3.6`; baseline code revision `69ae9ad`.
- Source: incompressible random bytes generated from `/dev/urandom`.
- Encryption: `carrack-vfs-aes256gcm-hkdfsha256-v1`.
- The measurements include control-plane calls, encryption or decryption,
  provider I/O, complete hashing, and local publication unless explicitly
  identified as sampled provider telemetry.
- Each successful script compared the downloaded SHA-256 with the source,
  exercised interrupted resume, logically removed the VFS entry, and confirmed
  that the test directory was empty. Physical deletion remains owned by normal
  server-side grace and GC.
- Temporary acceptance tokens were scoped only to the test directory and
  selected dev drivers, then revoked. No operator or VFS master key changed.

### Successful baseline samples

| Driver | Plaintext | Requested pipeline | Stage | Elapsed | Plaintext bytes/s |
|---|---:|---|---|---:|---:|
| `r2-default` | 134,217,728 B | 8 MiB parts, concurrency 8 | upload | 67,052 ms | 2,001,699 |
| `r2-default` | 134,217,728 B | 8 MiB parts, concurrency 8 | download | 183,590 ms | 731,074 |
| `r2-default` | 134,217,728 B | 8 MiB parts, concurrency 8 | interrupted resume | 35,610 ms | 3,769,118 |
| `aliyun-dev` | 33,554,432 B | requested 4 MiB, concurrency 4 | upload | 143,018 ms | 234,617 |
| `aliyun-dev` | 33,554,432 B | requested 4 MiB, concurrency 4 | download | 4,326 ms | 7,758,035 |
| `aliyun-dev` | 33,554,432 B | requested 4 MiB, concurrency 4 | interrupted resume | 62,944 ms | 533,091 |

The Aliyun driver was revision 6 with a configured provider upload part size of
20 MiB. Its compiled capability intentionally serializes parts within one file;
the requested concurrency can still apply across independent files. The
official provider contract requires parts of one file to be uploaded in order.
See Alibaba Cloud's [PDS file upload guidance](https://www.alibabacloud.com/help/doc-detail/175888.html).

The R2 completion telemetry retained both large downloads. Their aggregate was
268,436,480 encoded bytes, 213,642 provider milliseconds, 214,679 total
telemetry milliseconds, and zero retries. The R2 upload telemetry recorded
134,218,240 encoded bytes, 63,436 provider milliseconds, 65,598 total telemetry
milliseconds, and zero retries. In this sample, provider/network time therefore
dominated R2 transfer time; D1, cryptography, verification, and publication were
not the primary bottleneck.

The 32 MiB Aliyun operations were below the 64 MiB always-sample threshold and
did not enter the deterministic one-in-ten small-transfer sample. Their absence
from analytics is expected and must not be interpreted as zero activity.

### Failed R2 tuning sample

The same 128 MiB R2 acceptance was repeated with requested 16 MiB parts and
concurrency 4. Upload and the first download completed, but interrupted resume
exceeded the 300-second per-operation timeout. The script exited with status
124 and emitted no success document, so this configuration is a failed
acceptance rather than a partial success.

Sampled completion telemetry before the timeout recorded:

| Stage | Encoded bytes | Provider ms | Total telemetry ms | Retries |
|---|---:|---:|---:|---:|
| upload | 134,218,240 | 46,123 | 48,234 | 0 |
| download | 134,218,240 | 240,727 | 241,272 | 0 |

The upload was faster than the baseline observation while the download was
slower and resume did not finish inside the safety budget. One mixed result is
not evidence for changing SDK defaults. The test entry was nevertheless
logically removed, the directory was confirmed empty, and the temporary token
was revoked.

### Failed repeated baseline

After hardening the live harness at code revision `7522a84`, the original 128
MiB, 8 MiB parts, concurrency 8 configuration was repeated without changing
the 300-second per-operation safety budget. This time the upload stage timed
out and the script reported `R2 live upload failed with exit status 124`.

No success document or transfer completion telemetry was emitted, so no
throughput is assigned to this run and the failure cannot be localized further
than the end-to-end upload stage. The VFS test directory remained empty, the
redacted management snapshot showed no active Put or upload operation, and the
temporary token was revoked. Provider multipart residue, if any, remains
subject to the normal fenced server cleanup path rather than client deletion.

The same requested configuration therefore produced one complete success and
one upload timeout on the same date. This observed variance is stronger
evidence against changing defaults from isolated samples; future comparison
should first collect several successful and failed baseline attempts under a
named network path.

### Host and egress correlation

The following read-only correlation was performed after the runs against
hawk's retained VictoriaMetrics and VictoriaLogs data. The windows are wider
than the individual stage boundaries because the first acceptance harness did
not persist exact start timestamps for every stage. Network values are whole
host `lan0` rates, not Carrack process accounting.

| Correlation window (CST) | CPU mean / max | Memory used mean / max | Busiest disk mean / max | `lan0` receive mean / max | `lan0` transmit mean / max |
|---|---:|---:|---:|---:|---:|
| Successful baseline, 19:30-19:43 | 14.13% / 27.51% | 19.38% / 21.55% | 2.60% / 5.03% | 60.91 / 115.61 Mbit/s | 7.66 / 23.37 Mbit/s |
| Failed tuning sample, 20:05-20:17 | 1.88% / 9.37% | 17.46% / 18.22% | 1.86% / 15.14% | 5.29 / 22.29 Mbit/s | 5.55 / 22.68 Mbit/s |
| Failed repeated baseline, 20:30-20:36 | 14.20% / 41.00% | 18.94% / 20.48% | 1.64% / 4.05% | 1.22 / 2.47 Mbit/s | 6.34 / 17.58 Mbit/s |

None of the windows shows host memory or disk saturation. CPU headroom also
remained substantial, including during the repeated baseline timeout. Host
resource exhaustion is therefore not a supported explanation for either
failed acceptance.

Omega had started at 16:33:27 CST, before all three windows, and subsequently
reported zero service restarts. Its logs show no matching connection error in
the successful baseline window. During the failed tuning window they show
seven five-second `i/o timeout` failures in the selected proxy underlay while
opening connections to the Cloudflare endpoint. During the failed repeated
baseline window they show no explicit connection failure even though traffic
continued through the same transparent proxy path.

This evidence establishes that the failed tuning sample overlapped a degraded
egress path. It does not establish that every slow stage was caused by omega,
nor does the absence of an error log prove a healthy long-lived connection.
The repeated baseline timeout remains unlocalized between the end-to-end
network path and provider. Future live runs should persist stage start and end
timestamps plus an opaque run identifier so process-scoped telemetry can be
correlated without relying on widened windows or whole-host traffic.

### R2 many-small-file sync sample

A separate run used the client binary from revision `2c1f5eb` plus the
fail-fast preflight in `tests/r2-small-sync-live.sh`. The dev token was rooted
at `/speed-test`, limited to `r2-default`, and granted only `content.read`,
`content.write`, `directory.list`, `driver.use`, and `entry.delete`. The first
attempt correctly failed before provider I/O because an older speed-test token
did not contain the independently required `driver.use` action. No file was
published, its temporary directory was removed, and the harness was changed to
require one successful synchronous Put before starting concurrent uploads.

The successful run had opaque run ID `e504ef80abd38f85` and used 64 independent
encrypted VFS versions of the same 1 MiB incompressible source. Upload file
concurrency was 8. Cold and warm sync file concurrency was 16, with one provider
range per file. Every cold-sync output was compared with the source SHA-256.
The warm sync revalidated every local file through its complete Merkle pass.

| Stage (UTC) | Shape | Elapsed | Aggregate plaintext rate |
|---|---|---:|---:|
| Setup upload, 15:17:09-15:19:44 | 64 files; 67,108,864 B; includes encrypted provider upload and complete readback | 155,454 ms | 431,696 B/s |
| Cold sync, 15:19:44-15:21:00 | 64 downloaded and verified files; 67,108,864 B | 76,181 ms | 880,913 B/s |
| Warm sync, 15:21:00-15:21:03 | 64 locally rehashed files; provider bytes 0 | 2,588 ms | 24.73 files/s |

The script logically removed all 64 entries and the temporary directory. A
separate authenticated listing confirmed that the directory was absent after
cleanup. Physical R2 deletion remains subject to server-owned grace and GC.

Low-cost analytics for the exact token, `r2-default`, download direction, and
the containing hour retained approximately one in ten small transfers. Seven
actual sampled completions were weighted to 70 transfers and 73,401,440 bytes.
Their weighted averages were 8,837.9 provider milliseconds and 17,434.4 total
telemetry milliseconds per transfer, with zero retries; provider time was
50.7% of total telemetry time.

This sampled ratio is directional evidence, not an exact decomposition of the
64-file run. `total_ms` starts before the download-plan request and also includes
bounded plan/payload queueing, decryption, plaintext verification, and local
publication. The difference between `total_ms` and `provider_ms` therefore
cannot be assigned to Worker or D1 latency, and this run does not justify a
download-plan batch endpoint. Download telemetry v2 now measures plan, client
queue, provider, and verification/publication intervals separately. Its
coverage counter excludes legacy v1 samples from phase averages; a later
repeated live run is required before accepting a protocol optimization.

### Interpretation boundary

- These are practical end-to-end observations, not isolated provider limits.
- A configuration decision needs multiple same-size samples under identified
  network conditions. Compare medians and tails, not one fastest run.
- Client defaults must not adapt from a single transfer. Any future adaptive
  controller must use explicit throttle evidence, stable driver-specific
  policy, bounded memory and concurrency, and the identical checksum chain.
- Aliyun single-file upload concurrency must remain one. Throughput for many
  files can instead use the bounded file-level pipeline.
- R2 tuning should next compare repeated 8 MiB/concurrency 8 baselines before
  trying another matrix point; the observed variance is larger than the local
  processing overhead.
