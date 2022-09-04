# AZT501.2 - Account Manipulation: Service Principal Manipulation

## Tactics and Techniques

- Persistence
  - [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)

## Azure Threat Research Matrix

- [AZT501.2 - Account Manipulation: Service Principal Manipulation](https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/AZT501/AZT501-2/)

## Prerequisites

Enable the Azure Active Directory connector in Microsoft Sentinel

## KQL

## Enable Service Principal

```Kusto
AuditLogs
| where OperationName == "Update service principal"
| extend InitiatedBy = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend App = tostring(TargetResources[0].displayName)
| extend Setting = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].displayName)
| extend Value = tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].newValue))[0])
| where parse_json(tostring(TargetResources[0].modifiedProperties))[0].displayName == "AccountEnabled"
| where parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].newValue))[0] == true
| project TimeGenerated, App, InitiatedBy, Setting, Value

```

## Service Principal update credentials

```Kusto
AuditLogs
| where OperationName == "Update application – Certificates and secrets management "
| extend App = tostring(TargetResources[0].displayName)
| extend InitiatedBy = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| project TimeGenerated, App, InitiatedBy, OperationName
```

## Service Principal Update owner

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
