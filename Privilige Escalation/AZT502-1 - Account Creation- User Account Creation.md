# AZT502.1 - Account Creation: User Account Creation

## Tactics and Techniques

- Persistence
  - [T1136.003 - Create Account: Cloud Account](https://attack.mitre.org/techniques/T1136/003/)

## Azure Threat Research Matrix

- [AZT502.1 - Account Creation: User Account Creation](https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/AZT502/AZT502-1/)

## Prerequisites

Enable the Azure Active Directory connector in Microsoft Sentinel

## KQL

## Account Creation

```Kusto
AuditLogs
| where OperationName == "Add user"
| where Result == "success"
| extend InitiatedByipAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated,InitiatedByUser,InitiatedByipAddress,TargetUser,Result, OperationName
```
