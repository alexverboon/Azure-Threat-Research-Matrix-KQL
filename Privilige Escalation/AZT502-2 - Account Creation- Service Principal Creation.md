# AZT502.2 - Account Creation: Service Principal Creation

## Tactics and Techniques

- Persistence
  - [T1136.003 - Create Account: Cloud Account](https://attack.mitre.org/techniques/T1136/003/)

## Azure Threat Research Matrix

- [AZT502.2 - Account Creation: Service Principal Creation](https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/AZT502/AZT502-2/)

## Prerequisites

Enable the Azure Active Directory connector in Microsoft Sentinel

## KQL

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
