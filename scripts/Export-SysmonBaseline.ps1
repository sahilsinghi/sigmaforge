<#
.SYNOPSIS
  Export Sysmon, Security and System events from a lab Windows VM as SigmaForge JSONL.

.DESCRIPTION
  Run this on a Windows VM with Sysmon installed that has been *used normally* for a few
  days (browsing, Office, updates, admin tasks - no attack tooling). The output is the
  benign baseline SigmaForge measures noise against. Copy it into tests/benign/real/
  (git-ignored: it can be large) or publish it somewhere the nightly drift workflow can
  download it from (secret BENIGN_EXPORT_URL).

  Only use machines and data you own. Do not export production or case data.

.EXAMPLE
  .\Export-SysmonBaseline.ps1 -Days 3 -OutFile C:\export\benign-ws01.jsonl
#>
[CmdletBinding()]
param(
  [int]$Days = 3,
  [string]$OutFile = ".\benign-$env:COMPUTERNAME.jsonl",
  [string[]]$Channels = @(
    'Microsoft-Windows-Sysmon/Operational',
    'Security',
    'System'
  ),
  [int]$MaxEventsPerChannel = 500000
)

$ErrorActionPreference = 'Stop'
$since = (Get-Date).AddDays(-$Days)
$writer = [System.IO.StreamWriter]::new($OutFile, $false, [System.Text.UTF8Encoding]::new($false))
$total = 0
try {
  foreach ($channel in $Channels) {
    Write-Host "Exporting $channel since $since ..."
    $events = Get-WinEvent -FilterHashtable @{ LogName = $channel; StartTime = $since } `
      -MaxEvents $MaxEventsPerChannel -ErrorAction SilentlyContinue
    foreach ($ev in $events) {
      $xml = [xml]$ev.ToXml()
      $doc = [ordered]@{
        'EventID'    = [int]$ev.Id
        'Channel'    = $ev.LogName
        'Computer'   = $ev.MachineName
        '@timestamp' = $ev.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
      }
      if ($xml.Event.EventData) {
        foreach ($d in $xml.Event.EventData.Data) {
          if ($d.Name) { $doc[$d.Name] = [string]$d.'#text' }
        }
      }
      if ($xml.Event.UserData) {
        foreach ($node in $xml.Event.UserData.SelectNodes('.//*[not(*)]')) {
          if (-not $doc.Contains($node.LocalName)) { $doc[$node.LocalName] = $node.InnerText }
        }
      }
      $writer.WriteLine(($doc | ConvertTo-Json -Compress -Depth 3))
      $total++
    }
  }
}
finally {
  $writer.Close()
}
Write-Host "Wrote $total events to $OutFile"
Write-Host "Next: gzip it, copy to tests/benign/real/ and run 'sigmaforge test'."
