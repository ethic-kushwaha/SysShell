##-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
function Get-OSInfo{
echo "Opearting System Info"
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property Name,Description,CSName,Caption, Version,BuildNumber,CimClass, BuildType, OSType, RegisteredUser, OSArchitecture,ServicePackMajorVersion, ServicePackMinorVersion


echo "----------------------------------------------------------------------------------------------------------------------------------------------`n`n"

if (Get-Service | Where-Object {$_.DisplayName -eq "Windows Defender Firewall"} | Select-Object {$_.Status -eq "Running"}){echo "Window Defender Enabled`n";gcim -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
}else{echo "Window Defender Disabled"}
}

#-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


function Get-SecurityEvent {
     param ( $eventid,
        $start,
        $end
        )
        $filters = @{LogName = "Security"}
        if ($eventid -ne $null) {
        $filters.ID = $eventid
        }
        if ($start -ne $null) {
        $filters.StartTime = $start
        }
        if ($end -ne $null) {
        $filters.EndTime = $end
        }
    Get-WinEvent -FilterHashtable $filters
#Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime="01-Nov-23 3:57:44 PM"; EndTime="01-Nov-23 5:03:22 PM";Id=4624}  | Where-Object{ $_.properties[8].value -eq 5} | Format-List
#Get-SecurityEvent 4625 "5/6/2021 00:00:00" "5/7/2021 00:00:00" | Format-List TimeCreated, @{Label = "Logon Type"; Expression ={$_.properties[10].value}}, @{Label = "Status"; Expression = {'{0:X8}' -f $_.properties[7].value}}, @{Label = "Substatus"; Expression = {'{0:X8}' -f$_.properties[9].value}}, @{Label = "Target User Name"; Expression ={$_.properties[5].value}}, @{Label = "Workstation Name"; Expression ={$_.properties[13].value}}, @{Label = "IP Address"; Expression ={$_.properties[19].value}}
}


#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------



#Get-SysmonEvent 1 $null "01-Nov-23 3:57:44 PM" | Where-Object {$_.properties[3].value -eq 2032 } | Format-List
function Get-SysmonEvent{
        param (
        $eventid,
        $start,
        $end
    )
    #Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"
    $filter = @{LogName = "Microsoft-Windows-Sysmon/Operational"}

    if($eventid -ne $null){
        $filter.ID= $eventid    
    }
    if($start -ne $null){
        $filter.StartTime=$start
    }
    if($end -ne $null){
        $filter.EndTime=$end
    }
    Get-WinEvent -FilterHashtable $filter
    #Get-WinEvent -FilterHashtable @{LogName = "Microsoft-Windows-Sysmon/Operational" ;id=5;StartTime="01-Nov-23 3:57:44 PM"; EndTime="01-Nov-23 5:03:22 PM"}


}


#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------