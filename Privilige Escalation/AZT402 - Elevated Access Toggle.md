# AZT402 - Elevated Access Toggle

## Tactics and Techniques

- Privilege Escalation
  - [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)

## Azure Threat Research Matrix

- [AZT402 - Elevated Access Toggle](https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/AZT402/AZT402/)

## Prerequisites

If you want to use the below KQL query, you need to enable forwarding of logs to Microsoft Sentinel. For more details see [Microsoft Sentinel – Detect Elevate Access Activity in Azure by Leveraging M365D Integration](https://samilamppu.com/2022/04/08/detect-elevate-access-activity-in-azure-with-microsoft-sentinel-native-capabilities/)

If you cannot forward these logs to Microsoft Sentinel, setup an activity policy in Microsoft Defender for Cloud Apps as described
in this blog post. - [Monitor Elevate Access Activity In Azure](https://samilamppu.com/2020/06/18/monitor-elevated-global-admin-account-usage/)

## KQL

```Kusto
CloudAppEvents
| where ApplicationId == '12260'and Application == 'Microsoft Azure'
| where parse_json(tostring(parse_json(tostring(RawEventData.authorization)).evidence)).roleDefinitionId == "b21f0835cd464e508cf8e297ff563cb1"
| where RawEventData.operationName == "Microsoft.Authorization/elevateAccess/action"
| where parse_json(tostring(parse_json(tostring(RawEventData.authorization)).evidence)).roleAssignmentScope == "/"
| where parse_json(tostring(parse_json(tostring(RawEventData.authorization)).evidence)).roleAssignmentId == "b507cd211c194747a82e1c2e8584c6da"
| extend ClientIPAddress = parse_json(tostring(RawEventData.httpRequest)).clientIpAddress
| extend RoleAssignmentScope = parse_json(tostring(parse_json(tostring(RawEventData.authorization)).evidence)).roleAssignmentScope
| extend RoleAssignmentId = parse_json(tostring(parse_json(tostring(RawEventData.authorization)).evidence)).roleAssignmentId
```
