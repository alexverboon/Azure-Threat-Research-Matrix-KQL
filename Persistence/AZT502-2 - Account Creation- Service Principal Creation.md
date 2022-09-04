# AZT502.2 - Account Creation: Service Principal Creation

## Tactics and Techniques

- Persistence
  - [T1136.003 - Create Account: Cloud Account](https://attack.mitre.org/techniques/T1136/003/)

## Azure Threat Research Matrix

- [AZT502.2 - Account Creation: Service Principal Creation](https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/AZT502/AZT502-2/)

## Prerequisites

Enable the Azure Active Directory connector in Microsoft Sentinel

## KQL

## Application Creation

```Kusto
AuditLogs
| where OperationName == "Add application"
| extend InitiatedByipAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend ApplicationName = tostring(TargetResources[0].displayName)
| extend ApplicationId = tostring(TargetResources[0].id)
| project TimeGenerated,InitiatedByUser,InitiatedByipAddress,ApplicationName, ApplicationId,Result, OperationName
```

## Application Owner configuration

```Kusto
let AzureADIdentityInfo = IdentityInfo
| where isnotempty( AccountObjectId)
| where TimeGenerated > ago(180d)
| distinct AccountObjectId, AccountDisplayName
| project AccountObjectId, AccountDisplayName;
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName == "Add owner to application" or OperationName == "Add owner to service principal"
| extend InitiatedByipAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend OwnerId = tostring(TargetResources[0].id)
| extend App = tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue)))
| join kind=leftouter AzureADIdentityInfo
on $left. OwnerId == $right.AccountObjectId
| project TimeGenerated,App,InitiatedByUser,InitiatedByipAddress,OwnerId,AccountObjectId, AccountDisplayName, Result, OperationName
```

## Service Principal Creation

```Kusto
AuditLogs
| where ActivityDisplayName == "Add service principal"
| extend InitiatedByipAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend ServicePrincipalName = tostring(TargetResources[0].displayName)
| extend ApplicationId = tostring(TargetResources[0].id)
| project TimeGenerated,InitiatedByUser,InitiatedByipAddress,ServicePrincipalName, ApplicationId,Result, OperationName

```
