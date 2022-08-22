# AZT403.1 - Local Resource Hijack: Cloud Shell .IMG

## Tactics and Techniques

- Privilege Escalation
  - [T1037 - Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037/)

## Azure Threat Research Matrix

- [AZT403.1 - Local Resource Hijack: Cloud Shell .IMG](https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/AZT403/AZT403-1/)

## Prerequisites

Enable strage account file logging within the diagnostic settings and forward the logs to Microsoft Sentinel. For more information, see [Diagnostic Settings](https://docs.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage?tabs=azure-portal).

## KQL

```Kusto
// Cloud Shell - console img File upload / download activities
StorageFileLogs 
| where ServiceType == "file"
| where OperationName has_any("CreateFile","GetFile")
| extend Path = tostring(parse_url(Uri).Path)
| extend FileAttributes = parse_path(Path)
| extend Filename = tostring(FileAttributes.Filename)
| extend FileExtension = tostring(FileAttributes.Extension)
| extend StorageAccount = AccountName
| extend IPAddress = CallerIpAddress
| where FileExtension contains "img" and Path contains "cloudconsole"
```




