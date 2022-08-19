# AZT501.1 - Account Manipulation: User Account Manipulation

## Tactics and Techniques

- Persistence
  - [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)

## Azure Threat Research Matrix

- [AZT501.1 - Account Manipulation: User Account Manipulation](https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/AZT501/AZT501-1/)

## Prerequisites

Enable the Azure Active Directory connector in Microsoft Sentinel

## KQL

## Passowrd Update

```Kusto
AuditLogs
| where ActivityDisplayName == "Change user password" or OperationName == "Reset password (by admin)" or ActivityDisplayName == "Reset user password"
| extend InitiatedByipAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated,InitiatedByUser,InitiatedByipAddress,TargetUser,Result, OperationName
```

## Enable Account

```Kusto
AuditLogs
| where ActivityDisplayName == "Enable account"
| extend InitiatedByipAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated,InitiatedByUser,InitiatedByipAddress,TargetUser,Result, OperationName
```

## Restpre the Account

```Kusto
AuditLogs
| where OperationName == "Restore user"
| extend InitiatedByipAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend RestoreduserPrincipalName = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated,InitiatedByUser,InitiatedByipAddress,RestoreduserPrincipalName,Result,OperationName
```
