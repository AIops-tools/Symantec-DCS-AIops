<!-- mcp-name: io.github.AIops-tools/symantec-dcs-aiops -->

# Symantec Data Center Security AIops

Independent audited MCP server, CLI and skill for management status, assets, alerts, events, policies, reports, roles, users and syslog. This initial release exposes 35 read-only tools. MCP and CLI call the same governed functions; API credentials remain in environment variables, TLS verification is on, and every call records a local audit event.

> Community-maintained project. Not affiliated with or endorsed by Broadcom or Symantec; product names are their owners’ trademarks.

## Configure

```sh
export SYMANTEC_DCS_URL="..."
export SYMANTEC_DCS_USERNAME="..."
export SYMANTEC_DCS_PASSWORD="..."
```

`SYMANTEC_DCS_URL` must be the management console HTTPS origin (normally `https://host:4443`), without a path. Optional `SYMANTEC_DCS_CA_BUNDLE` points to a trusted CA bundle; `SYMANTEC_DCS_TIMEOUT` defaults to 30 seconds. Audit state defaults to `~/.symantec-dcs-aiops/` and can be relocated with `SYMANTEC_DCS_AIOPS_HOME`.

See the [operations catalog](docs/OPERATIONS.md) for the complete tool list, scope and deferred operations.

## Use

```sh
uvx --from symantec-dcs-aiops==0.1.0 symantec-dcs-aiops status server
uvx --from symantec-dcs-aiops==0.1.0 symantec-dcs-aiops-mcp
```

Use assets with a sort key to page through inventory; inspect asset-errors, alert-rules, events and policy-violations before making conclusions. See [verification](docs/VERIFICATION.md) for the exact evidence and unverified live behavior. No state-changing operations are exposed.
