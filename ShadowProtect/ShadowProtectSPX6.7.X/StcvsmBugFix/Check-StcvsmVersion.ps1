<#
.SYNOPSIS
    This function will check the version of the stcvsm.sys driver
.DESCRIPTION
    This function will check the version of the stcvsm.sys driver. This was intended to support
    endpoints running ShadowProtect SPX 6.7.X in order to determine if they had the patched driver.
.PARAMETER ComputerName
    This is currently not used. Future support for pipeline/remote execution planned
.EXAMPLE
    PS C:\Windows\system32> Check-StcvsmVersion

    ComputerName SPXVersion StcvsmVersion PatchedDriverPresent
    ------------ ---------- ------------- --------------------
    FILESRV01    6.7.4      2.2.73.0.36   True

.NOTES
    Version:        1.0
    Author:         Lucas
    Creation Date:  08/30/2018
#>
Function Check-StcvsmVersion {
#Region - Parameters
    [CmdletBinding()]
    Param (
        [parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            Position = 0)]
        [String[]]$ComputerName = $env:computername
    )
#EndRegion - Parameters
#Region - Begin Block
    begin {
        $AllVersionChecks = @()
    }
#EndRegion - Begin Block
#Region - Process Block
    process {
        # BEGIN - Check SPX Version
        $SPXVersion = (Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -like 'StorageCraft ShadowProtect SPX' } | Select-Object -ExpandProperty DisplayVersion)
        if ([string]::IsNullOrWhitespace($SpxVersion)) {            
            $Item = New-Object PSObject
            $Item | Add-Member -type NoteProperty -Name 'ComputerName' -Value $($ComputerName)
            $Item | Add-Member -type NoteProperty -Name 'SpxVersion' -Value 'MISSING'
            $Item | Add-Member -type NoteProperty -Name 'StcvsmVersion' -Value 'MISSING'
            $Item | Add-Member -type NoteProperty -Name 'PatchedDriverPresent' -Value 'MISSING'
            $AllVersionChecks += $Item
        } elseif ($SpxVersion -like '6.7.*') {
        # END - Check SPX Version    
            # BEGIN - Collect Driver Version
            $DriverPath = "$env:systemroot\system32\drivers\"
            if (!(Test-path "$DriverPath\stcvsm.sys")) {
                $Item = New-Object PSObject
                $Item | Add-Member -type NoteProperty -Name 'ComputerName' -Value $($ComputerName)
                $Item | Add-Member -type NoteProperty -Name 'SpxVersion' -Value $SPXVersion
                $Item | Add-Member -type NoteProperty -Name 'StcvsmVersion' -Value 'MISSING'
                $Item | Add-Member -type NoteProperty -Name 'PatchedDriverPresent' -Value 'MISSING'
                $AllVersionChecks += $Item
            } Else {
                $DriverVersion = (Get-ItemProperty "$driverpath\stcvsm.sys" | Select-Object -ExpandProperty versioninfo).productversion
            }
            # END - Collect Driver Version
            # BEGIN - Build Endpoint Results
            If ($DriverVersion -eq '2.2.73.0.36') {
                $Item = New-Object PSObject
                $Item | Add-Member -type NoteProperty -Name 'ComputerName' -Value $($ComputerName)
                $Item | Add-Member -type NoteProperty -Name 'SpxVersion' -Value $SPXVersion
                $Item | Add-Member -type NoteProperty -Name 'StcvsmVersion' -Value $DriverVersion
                $Item | Add-Member -type NoteProperty -Name 'PatchedDriverPresent' -Value $true
                $AllVersionChecks += $Item
            } else {
                $Item = New-Object PSObject
                $Item | Add-Member -type NoteProperty -Name 'ComputerName' -Value $($ComputerName)
                $Item | Add-Member -type NoteProperty -Name 'SpxVersion' -Value $SPXVersion
                $Item | Add-Member -type NoteProperty -Name 'StcvsmVersion' -Value $DriverVersion
                $Item | Add-Member -type NoteProperty -Name 'PatchedDriverPresent' -Value $False
                $AllVersionChecks += $Item
            }
        } elseif ($SpxVersion -notlike '6.7.*') {
            $Item = New-Object PSObject
            $Item | Add-Member -type NoteProperty -Name 'ComputerName' -Value $($ComputerName)
            $Item | Add-Member -type NoteProperty -Name 'SpxVersion' -Value $SPXVersion
            $Item | Add-Member -type NoteProperty -Name 'StcvsmVersion' -Value $DriverVersion
            $Item | Add-Member -type NoteProperty -Name 'PatchedDriverPresent' -Value 'Not Applicable To Detected SPX Version'
            $AllVersionChecks += $Item
            # END - Build Endpoint Results
        }
    }
#EndRegion - Process Block
#Region - End Block
    end {
        $TableProperties = @(
            @{ Label = 'ComputerName'; Expression = { $_.ComputerName }; Alignment = 'Left' }
            @{ Label = 'SPXVersion'; Expression = { $_.SPXVersion }; Alignment = 'Left' }
            @{ Label = 'StcvsmVersion'; Expression = { $_.StcvsmVersion }; Alignment = 'Left' }
            @{ Label = 'PatchedDriverPresent'; Expression = { $_.PatchedDriverPresent }; Alignment = 'Left' }
        )
        $AllVersionChecks | Format-Table -Property $TableProperties -AutoSize
    }
#EndRegion - End Block
}
