$ErrorActionPreference = "Continue"

# Get time script was run
$dateTime = Get-Date -format yyyy.MM.dd-HHmm

# XML search filter location
$XML_LOCATION = $PSScriptRoot + "\Filters"
# Event log backup folder
$EVENT_LOCATION = $PSScriptRoot + "\EventLogs"
# Event report location
$dataBackupFolder = $EVENT_LOCATION + ("\" + $env:COMPUTERNAME)
New-Item $dataBackupFolder -type directory
$dataBackupFolder += ("\" + $dateTime)
New-Item $dataBackupFolder -type directory

$EventList = @()

# Choose if run on live logs or backup logs
$title = "Log Chooser"
$message = "Analyzing live logs or archived logs?"

$liveLogs = New-Object System.Management.Automation.Host.ChoiceDescription "&Live", "Analyze current local Windows Logs."
$archiveLogs = New-Object System.Management.Automation.Host.ChoiceDescription "&Archive", "Analyze Windows logs from archive location."
$options = [System.Management.Automation.Host.ChoiceDescription[]]($liveLogs, $archiveLogs)
$selection1 = $Host.UI.PromptForChoice($title, $message, $options, 0)

Switch ($selection1) {
    0 { }
    1 {
        $app = New-Object -COM Shell.Application
        $dir = $app.BrowseForFolder( 0, "Select Directory", 0)
        $path = $dir.Self.Path
    }
}


#
# Get all event filters from file, read events from log, write events to report
#

# Get Each XML search filter file
Get-ChildItem -include *.xml -Path $XML_LOCATION -recurse | ForEach-Object {
    [xml] $Filter_XML = Get-Content $_.FullName
    $Family_Name = $Filter_XML.Family.ID
    Write-Host $Family_Name
    $EventList = $Filter_XML.Family.event

    ForEach ($Event in $EventList) {
        Write-Host $Event.Name
        $events += @(Get-WinEvent -FilterHashtable @{logname=$Event.LogName; providername=$Event.Provider; ID=$Event.ID} -Force)
    }
    
    $events | Select-Object TimeCreated, MachineName, LogName, LevelDisplayName, Level, ProviderName, ContainerLog, ID, Message | Sort-Object TimeCreated | Out-GridView -Title $Family_Name
    $familyXML = $events | Select-Object TimeCreated, MachineName, LogName, LevelDisplayName, Level, ProviderName, ContainerLog, ID, Message | ConvertTo-Xml
    $familyXML.Save(($dataBackupFolder + "\" + $Family_Name + ".xml"))

    Clear-Variable -Name events
    Clear-Variable -Name Event
}

#
# Pass The Hash Detection
#

Write-Host "Pass the Hash Detection"
$PtHEvents = Get-WinEvent -FilterHashtable @{logname="System"; ID=4624; LogonType=3; AuthenticationPackageName="NTLM"}  -Oldest | Where-Object { $_.TargetUserName -ne "ANONYMOUS LOGON" -and $_.TargetDomainName -ne $env:UserDomain }
$PtHEvents | Select-Object TimeCreated, MachineName, LogName, LevelDisplayName, Level, ProviderName, ContainerLog, ID, Message | Sort-Object TimeCreated | Out-GridView -Title "Pass the Hash"
$PtHXML = $PtHEvents | Select-Object TimeCreated, MachineName, LogName, LevelDisplayName, Level, ProviderName, ContainerLog, ID, Message | ConvertTo-Xml
$PtHXML.Save(($dataBackupFolder + "\Pass_the_Hash.xml"))

#
# Special popup reports
#

# Remote Desktop Use
Write-Host "RDP Usage"
$RDPEvents = Get-WinEvent -FilterHashtable @{logname="Security"; ID=4624; LogonType=10}  -Oldest
$RDPEvents += Get-WinEvent -FilterHashtable @{logname="Security"; ID=4634; LogonType=10}  -Oldest
$RDPEvents | Select-Object TimeCreated, MachineName, LogName, LevelDisplayName, Level, ProviderName, ContainerLog, ID, Message | Sort-Object TimeCreated | Out-GridView -Title "Remote Desktop Use"
$RDPXML = $RDPEvents | Select-Object TimeCreated, MachineName, LogName, LevelDisplayName, Level, ProviderName, ContainerLog, ID, Message | ConvertTo-Xml
$RDPXML.Save(($dataBackupFolder + "\RDP_Events.xml"))

<#

To-Do 
    get user log on data
    correlate log on events with log off events
    create output gridview and xml report

# User access timeframes (Only effective on Domain Controllers)

# Event ID 4768 (Successful Log On)

If ( (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4 ) {
    New-Variable -Name accountUsage -Value (Import-Clixml -Path ($dataBackupFolder + "\Account Usage.xml"))

}
#>


#
# Clear and/or Archive Event Logs
#

$LogDir = $dataBackupFolder + "\RawLogs"
New-Item $LogDir -type directory

$applog = $LogDir + "\Application.evtx"
$syslog = $LogDir + "\System.evtx"
$seclog = $LogDir + "\Security.evtx"

$title = "Event Log Actions"
$message = "Would you like to clear and/or backup event logs or quit?"

$evtBackup = New-Object System.Management.Automation.Host.ChoiceDescription "&Backup", "Perform Event log backup."
$evtClearBackup = New-Object System.Management.Automation.Host.ChoiceDescription "&Clear", "Perform Event log backup AND clear."
$evtQuit = New-Object System.Management.Automation.Host.ChoiceDescription "&Quit", "Perform no action and exit program."
$options = [System.Management.Automation.Host.ChoiceDescription[]]($evtBackup, $evtClearBackup, $evtQuit)
$selection2 = $Host.UI.PromptForChoice($title, $message, $options, 0)

Switch ($selection2) {
    0 {
        wevtutil epl Application $applog
        wevtutil epl System $syslog
        wevtutil epl Security $seclog
    }
    1 {
        wevtutil cl Application /bu:"$applog"
        wevtutil cl System /bu:"$syslog"
        wevtutil cl Security /bu:"$seclog"
    }
    2 { break }
}