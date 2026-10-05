# Configuration Snippets

Only the parts I added or changed. Everything else is the Wazuh default.

## Wazuh server: `/var/ossec/etc/ossec.conf`

Archive all events (inside `<global>`):

```xml
<logall>yes</logall>
<logall_json>yes</logall_json>
```

I also enabled archives in `filebeat.yml` and created the `wazuh-archives-4.x` index pattern in the dashboard.

Active response, linked to custom rule 100101:

```xml
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100101</rules_id>
</active-response>
```

## Windows agent: `ossec.conf`

Collect Sysmon events:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Real-time file integrity monitoring (inside `<syscheck>`):

```xml
<directories realtime="yes">C:\companydata</directories>
```

## Linux agent: `/var/ossec/etc/ossec.conf`

Real-time file integrity monitoring (inside `<syscheck>`):

```xml
<directories realtime="yes">/opt/company-data</directories>
```
