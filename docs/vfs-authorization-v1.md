# Carrack VFS Authorization V1

## Decision

V1 uses fixed actions, direct principals, flat groups, inherited allow-only
directory ACLs, and attenuated bearer tokens. It does not embed a general RBAC
or policy-language engine. Named roles are UI and API presets expanded into
fixed action grants when written; changing a preset later cannot silently
change an existing ACL.

This model keeps the common case small while retaining the properties Carrack
needs: directory boundaries, least-privilege AI tokens, immediate revocation,
driver restrictions, snapshot pinning, and administrators who do not
implicitly receive content plaintext.

## Fixed actions

```text
directory.list
content.read
content.write
entry.delete
snapshot.publish
acl.manage
token.issue
driver.use
driver.manage
gc.run
audit.read
system.manage
```

Actions never imply other actions. In particular, `system.manage`,
`driver.manage`, `acl.manage`, and `token.issue` do not imply `content.read`.
An operation that needs several capabilities checks each one. For example, a
cross-directory move checks read and delete on the source, write on the
destination, and driver use for every selected location.

## Principals, groups, and presets

A principal is a human or service identity. A client runtime maps to exactly
one service principal. Groups contain principals directly; V1 deliberately
does not support nested groups.

Recommended presets expand as follows:

| Preset | Actions |
|---|---|
| Viewer | `directory.list`, `content.read` |
| Editor | Viewer plus `content.write`, `entry.delete` |
| Publisher | Editor plus `snapshot.publish` |
| Security administrator | `directory.list`, `acl.manage`, `token.issue`, `audit.read` |
| Storage operator | `driver.use`, `driver.manage`, `audit.read` |
| Janitor | `driver.use`, `gc.run`, `audit.read` |
| System administrator | `acl.manage`, `token.issue`, `driver.manage`, `gc.run`, `audit.read`, `system.manage` |

Content access can be granted alongside an administrative preset, but is never
hidden inside one.

## Directory ACL evaluation

An ACL row grants one exact action to one principal or group on one directory.
Evaluation begins at the target directory and walks toward the filesystem root.
The first directory whose `acl_inherits` value is false is included, then the
walk stops. A matching grant at any visited directory allows the action.

There are no deny rows. To make a subtree narrower, break inheritance at its
root and grant only the desired subjects there. This avoids deny precedence,
nested-role ordering, and policy conflicts while still creating a real
authorization boundary.

The directory parent graph must be acyclic. A missing node, cycle, excessive
depth, disabled principal, or malformed ACL fails closed.

## Token attenuation

A bearer token binds exactly one principal and can only narrow current ACL
authority. Its immutable scope contains:

- one directory subtree root;
- an explicit nonempty action subset;
- an optional driver-instance allowlist;
- an optional immutable snapshot ID;
- an expiry and revocation state;
- an optional parent token for audit and further attenuation.

Every request re-evaluates the principal's current ACL. Removing a grant,
disabling a principal, breaking inheritance, revoking the token, or expiring it
takes effect without waiting for token expiry. Possession of an earlier key or
credential grant cannot be erased from client memory, so grant windows remain
short.

A child token must use the same principal, a descendant directory root, a
subset of parent actions and drivers, the same or narrower snapshot, and an
expiry no later than its parent. Token creation verifies these constraints in
one D1 transaction. Token secrets are random 256-bit values; D1 stores only a
SHA-256 verifier. Tokens, verifiers, credentials, and directory keys never
enter audit details or R2 catalog metadata.

AI skills should normally receive short-lived service-principal tokens scoped
to one subtree and only the exact actions needed. A token with `acl.manage` or
`token.issue` is an explicit management credential and should not also carry
content access unless the workflow genuinely requires both.

## Driver and control-plane boundary

`driver.use` authorizes receiving a short-lived credential grant for an allowed
driver and directory placement policy. `driver.manage` authorizes driver
configuration but does not expose payload bytes or directory keys.

The control plane evaluates policy, allocates opaque names, and grants metadata,
keys, and credentials. It never opens a VFS payload object. Go clients and
janitors perform provider I/O under the granted scope.
