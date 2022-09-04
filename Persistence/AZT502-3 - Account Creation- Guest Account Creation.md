# AZT502.3 - Account Creation: Guest Account Creation

## Tactics and Techniques

- Persistence
  - [T1136.003 - Create Account: Cloud Account](https://attack.mitre.org/techniques/T1136/003/)

## Azure Threat Research Matrix

- [AZT502.3 - Account Creation: SGuest Account Creation](https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/AZT502/AZT502-3/)

## Prerequisites

Enable the Azure Active Directory connector in Microsoft Sentinel

## KQL

## Create Guest Account

```Kusto
AuditLogs
| where OperationName == "Add user"
| extend InitiatedBy = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend GuestInvited = tostring(TargetResources[0].userPrincipalName)
| extend UserType = tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[11].newValue))[0])
| project TimeGenerated, InitiatedBy, GuestInvited, UserType
| where GuestInvited has "#EXT#"
```
