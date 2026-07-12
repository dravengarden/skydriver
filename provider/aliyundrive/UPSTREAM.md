# OpenList alignment

Carrack's Aliyun Drive provider is a narrow, provider-interface adaptation of
the current OpenList `aliyundrive_open` driver. Carrack cannot import that
driver directly because its callable model, stream, and driver contracts are
Go `internal` packages.

Initial alignment baseline:

- Repository: `github.com/OpenListTeam/OpenList`
- Commit: `eb48671`
- Paths: `drivers/aliyundrive_open`, `drivers/base`
- Checked: 2026-07-11

The intentionally retained behaviours are:

- official `openapi.alipan.com` file APIs;
- OpenList-compatible `api.oplist.org` OAuth renewal as an explicit token
  source, without an OpenList server;
- per-operation request limits below the documented account/application caps;
- 20 MiB sequential upload parts with at most 10,000 parts;
- short-lived download URLs whose `206`, byte span, resolved total size, and
  declared body length must prove the exact requested range;
- one token refresh after an explicit expiry response, while throttling,
  authorization loss, and quota errors remain caller-visible;
- no internal-upload hostname rewrite outside Beijing ECS.

Upstream changes must be reviewed rather than copied mechanically. Carrack's
content-addressed object keys, bounded-memory streaming, credential storage,
and idempotency rules remain Carrack-owned.
