# Operations catalog

All listed operations are read-only and route through the same audited MCP/CLI implementation. A tool count describes interface coverage, not live verification.

## Service and assets

| MCP tool | Purpose |
|---|---|
| `dcs_status` | Read a DCS service status component. |
| `dcs_assets` | List a bounded page of assets. |
| `dcs_asset` | Read one managed asset. |
| `dcs_asset_errors` | Read recent asset error events. |
| `dcs_asset_stats` | Read asset totals and offline counts. |
| `dcs_asset_tags` | Read asset tags. |
| `dcs_asset_policies` | List policies assigned to an asset. |
| `dcs_asset_history` | Read asset change history. |
| `dcs_licenses` | List license inventory. |

## Alerts and events

| MCP tool | Purpose |
|---|---|
| `dcs_alerts` | List a bounded page of alerts. |
| `dcs_alert_rules` | List a bounded page of alert rules. |
| `dcs_alert_stats` | Read alert rule totals. |
| `dcs_events` | List a bounded page of security events. |
| `dcs_event_stats` | Read event counts. |
| `dcs_alert_details` | Read alert rule details. |
| `dcs_alert_notifications` | List recent alert notifications. |

## Policies and security groups

| MCP tool | Purpose |
|---|---|
| `dcs_policies` | List DCS policies with an explicit output cap. |
| `dcs_policy` | Read one DCS policy. |
| `dcs_policy_violations` | Read policy violations. |
| `dcs_policy_settings` | Read policy settings. |
| `dcs_policy_library` | List library policies. |
| `dcs_security_groups` | List security groups. |
| `dcs_security_group` | Read one security group. |
| `dcs_security_group_stats` | Read security group counts. |
| `dcs_tags` | List policy and asset tags. |

## Reports, roles and configuration

| MCP tool | Purpose |
|---|---|
| `dcs_reports` | List report definitions. |
| `dcs_report_stats` | Read report counts. |
| `dcs_report_jobs` | List report job states. |
| `dcs_report_job` | Read one report job state. |
| `dcs_roles` | List RBAC roles. |
| `dcs_role` | Read one RBAC role. |
| `dcs_role_users` | List users assigned to a role. |
| `dcs_users` | List management users. |
| `dcs_syslogs` | List syslog destinations. |
| `dcs_server_registry` | List registered servers. |

## Limits and next work

The documented GET /v1/sa/securitygroups/reapply route can trigger a change, so it is excluded despite its HTTP method. Report downloads and certificate exports require content and credential handling. Configuration writes require live result and rollback proof.

API paths and response examples are from the official Broadcom documentation listed below. No tenant or appliance has been supplied for live verification; consult [VERIFICATION.md](VERIFICATION.md).

- [dcs_status_6110](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/dcs_status_6110.md)
- [dcs_assets_6110](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/dcs_assets_6110.md)
- [dcs_license_6110](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/dcs_license_6110.md)
- [dcs_alerts_6110](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/dcs_alerts_6110.md)
- [dcs_events_6110](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/dcs_events_6110.md)
- [dcs_policy_6110](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/dcs_policy_6110.md)
- [dcs_security_groups_6110](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/dcs_security_groups_6110.md)
- [dcs_reports_6110](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/dcs_reports_6110.md)
- [dcs_reports_job_6110](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/dcs_reports_job_6110.md)
- [dcs_roles_6110](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/dcs_roles_6110.md)
- [dcs_users_6110](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/dcs_users_6110.md)
- [dcs_syslog_6110](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/dcs_syslog_6110.md)
- [dcs_server_6110](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/dcs_server_6110.md)
- [dcs_tags_6110](https://apidocs.securitycloud.symantec.com/resources/configs/_markdown/dcs_tags_6110.md)
