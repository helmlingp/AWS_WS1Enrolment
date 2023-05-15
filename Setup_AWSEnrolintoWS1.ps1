<#
.Synopsis
    Creates script, downloads AirwatchAgent.msi and creates a Scheduled Task to enrol an AWS Workspaces Desktop into Workspace ONE.
 .NOTES
    Created:   	    October 2022
    Created by:	    Phil Helmling, @philhelmling
    Organization:   VMware, Inc.
    Filename:       Setup_AWSEnrolintoWS1.ps1
    GitHub:         https://github.com/helmlingp/AWS_WS1Enrolment
.DESCRIPTION
    Creates script, downloads AirwatchAgent.msi and called by %WINDIR%\Setup\Scripts\SetupComplete.cmd on first logon
    Specifically:
    * Creates %WINDIR%\Setup\Scripts\EnrolintoWS1.ps1
    * Creates %WINDIR%\Setup\Scripts\SetupComplete.cmd
    * Downloads the latest AirWatchAgent.msi to %WINDIR%\Setup\Scripts folder if -Download switch is utilised
    AirwatchAgent.msi can also be downloaded manually from https://getwsone.com or to utilise the same version seeded into the console goto
    https://<DS_FQDN>/agents/ProtectionAgent_AutoSeed/AirwatchAgent.msi to download it, substituting <DS_FQDN> with the FQDN for the Device Services Server.
    
    SetupComplete.cmd runs on first user logon after OOBE and calls EnrolintoWS1.ps1 passing Workspace ONE environment and staging user credentials as parameters.
    Seeded into Base AMI VM used to create AWS Workspace
    Enrols a AWS Workspaces Desktop into WS1

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    VMWARE,INC. BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
    IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    
.REQUIREMENTS
    * AirWatchAgent.msi in the current folder or -Download switch
    * Run on AWS base AMI VM used to create AWS Workspace 

.PARAMETER Server
Server URL for the Workspace ONE UEM DS Server to enrol to

.PARAMETER username
An Workspace ONE UEM staging user

.PARAMETER password
The Workspace ONE UEM staging user password

.PARAMETER OGName
The display name of the Organization Group. You can find this at the top of the console, normally your company's name

.PARAMETER Download
OPTIONAL: Specify if wanting to download the latest version of AirwatchAgent.msi available from https://getwsone.com

.EXAMPLE
  .\Setup_EnrolintoWS1.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_URL -OGName DESTINATION_OG_NAME -Download
#>
param (
    [Parameter(Mandatory=$false)][string]$username,
    [Parameter(Mandatory=$false)][string]$password,
    [Parameter(Mandatory=$false)][string]$OGName,
    [Parameter(Mandatory=$false)][string]$Server,
    [switch]$Download
)

function Write-Log2{
    [CmdletBinding()]
    Param(
      [string]$Message,
      [Alias('LogPath')][Alias('LogLocation')][string]$Path=$Local:Path,
      [Parameter(Mandatory=$false)][ValidateSet("Success","Error","Warn","Info")][string]$Level="Info"
    )
  
    $ColorMap = @{"Success"="Green";"Error"="Red";"Warn"="Yellow"};
    $FontColor = "White";
    If($ColorMap.ContainsKey($Level)){$FontColor = $ColorMap[$Level];}
    $DateNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $Path -Value ("$DateNow`t($Level)`t$Message")
    Write-Host "$DateNow::$Level`t$Message" -ForegroundColor $FontColor;
}

function Invoke-DownloadAirwatchAgent {
    try {
        [Net.ServicePointManager]::SecurityProtocol = 'Tls11,Tls12'
        $url = "https://packages.vmware.com/wsone/AirwatchAgent.msi"
        $output = "$current_path\$agent"
        $Response = Invoke-WebRequest -Uri $url -OutFile $output
        # This will only execute if the Invoke-WebRequest is successful.
        $StatusCode = $Response.StatusCode
    } catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        Write-Log2 -Path "$logLocation" -Message "Failed to download AirwatchAgent.msi with StatusCode $StatusCode" -Level Error
    }
}

function Build-EnrolScript {
    #Create EnrolintoWS1.ps1 Script that does enrolment
    $EnrolintoWS1 = @'
    <#
    .Synopsis
        Enrols a persistent VDI desktop into WS1
    .NOTES
        Created:   	    November 2021
        Updated:        October 2022 
        Created by:	    Phil Helmling, @philhelmling
        Organization:   VMware, Inc.
        Filename:       EnrolintoWS1.ps1
        GitHub:         https://github.com/helmlingp/AWS_WS1Enrolment
    .DESCRIPTION
        **This script does not need to be edited**
        %WINDIR%\Setup\Scripts\EnrolintoWS1.ps1 called by %WINDIR%\Setup\Scripts\SetupComplete.cmd on first logon
        Seeded into Base AMI VM used to create AWS Workspace
        Enrols a AWS Workspaces Desktop into WS1
        Requires AirWatchAgent.msi in the %WINDIR%\Setup\Scripts folder

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
        VMWARE,INC. BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
        IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
        CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    .EXAMPLE
    .\EnrolintoWS1.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_URL -OGName DESTINATION_OG_NAME -Hostname SetupHostname
    #>
    param (
    [Parameter(Mandatory=$true)][string]$username,
    [Parameter(Mandatory=$true)][string]$password,
    [Parameter(Mandatory=$true)][string]$OGName,
    [Parameter(Mandatory=$true)][string]$Server,
    [Parameter(Mandatory=$true)][string]$Hostname
    )

    function Write-Log2{
    [CmdletBinding()]
    Param
    (
        [string]$Message,
        [Alias('LogPath')][Alias('LogLocation')][string]$Path=$Local:Path,
        [Parameter(Mandatory=$false)][ValidateSet("Success","Error","Warn","Info")][string]$Level="Info"
    )
        $ColorMap = @{"Success"="Green";"Error"="Red";"Warn"="Yellow"};
        $FontColor = "White";
        If($ColorMap.ContainsKey($Level)){$FontColor = $ColorMap[$Level];}
        $DateNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Add-Content -Path $Path -Value ("$DateNow     ($Level)     $Message")
        Write-Host "$DateNow::$Level`t$Message" -ForegroundColor $FontColor;
    }
    $current_path = $PSScriptRoot;
    if($PSScriptRoot -eq ""){
        #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
        $current_path = Get-Location
    } 
    $DateNow = Get-Date -Format "yyyyMMdd_hhmm"
    $scriptName = $MyInvocation.MyCommand.Name
    $logLocation = "$current_path\$scriptName_$DateNow.log"

    #Variables
    $currenthostname=[System.Net.Dns]::GetHostName()
    $destfolder = "$env:WINDIR\Setup\Scripts";
    $enrollmentcomplete = $false;
    $keypath = "Registry::HKLM\SOFTWARE\AIRWATCH\EnrollmentStatus"
    Write-Log2 -Path "$logLocation" -Message "Starting EnrolintoWS1 Process" -Level Success

    if ($Hostname -ne $currenthostname){
    while ($enrollmentcomplete -ne $true) {
        Write-Log2 -Path "$logLocation" -Message "Starting Workspace ONE enrollment" -Level Info
        Start-Process msiexec.exe -ArgumentList "/i","$destfolder\AirwatchAgent.msi","/qn","ENROLL=Y","SERVER=$Server","LGNAME=$OGName","USERNAME=$username","PASSWORD=$password","ASSIGNTOLOGGEDINUSER=Y","/log $current_path\AWAgent.log";

        do {start-sleep 60} until ((Get-ItemPropertyValue -Path $keypath -Name "Status" -ErrorAction SilentlyContinue) -eq 'Completed')

        start-sleep 60;
        Write-Log2 -Path "$logLocation" -Message "Workspace ONE enrollment complete" -Level Success
        $enrollmentcomplete = $true;
    } else {
        Write-Log2 -Path "$logLocation" -Message "This is the Orginal Workspace, Enrolling terminated" -Level Info
    }

'@
    return $EnrolintoWS1
}

function Build-SetupComplete {
    #SetupComplete that runs automatically by Windows after machine is SYSPREP'd and first user logon
    $SetupComplete = @"
    echo Off
    rem Use this batch file to call a script to enrol a Windows Desktop into Workspace ONE UEM
    rem Replace USERNAME, PASSWORD, DESTINATION_SERVER_URL, DESTINATION_OG_NAME parameters
    rem November 2021

    set LOCALAPPDATA=%USERPROFILE%\AppData\Local
    powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -File "%~dp0EnrolintoWS1.ps1" -username $script:username -password $script:password -Server $script:Server -OGName $script:OGName -Hostname $script:hostname
"@
    return $SetupComplete
}

function Main {
    #Setup Logging
    Write-Log2 -Path "$logLocation" -Message "==============Start Setup_EnrolintoWS1==============" -Level Success

    if (!(Test-Path -LiteralPath $deploypath)) {
        try {
        New-Item -Path $deploypath -ItemType Directory -ErrorAction Stop | Out-Null #-Force
        }
        catch {
        Write-Error -Message "Unable to create directory '$deploypath'. Error was: $_" -ErrorAction Stop
        }
        "Successfully created directory '$deploypath'."
    }

    #Ask for WS1 tenant and staging credentials if not already provided
    if ([string]::IsNullOrEmpty($script:Server)){
        $Username = Read-Host -Prompt 'Enter the Staging Username'
        $password = Read-Host -Prompt 'Enter the Staging User Password'
        $Server = Read-Host -Prompt 'Enter the Workspace ONE UEM Device Services Server URL'
        $OGName = Read-Host -Prompt 'Enter the Organizational Group Name'
    }
    Write-Log2 -Path "$logLocation" -Message "Workspace ONE environment details obtained" -Level Info

    #Test for blank passord as...
    if ([string]::IsNullOrEmpty($password)){
        $password = "."
    }

    #Create SetupComplete.cmd and EnrolintoWS1.ps1 Scripts
    $FileName = "$destfolder\EnrolintoWS1.ps1"
    $EnrolintoWS1 = Build-EnrolScript
    If (Test-Path -Path $FileName){Remove-Item $FileName -force;Write-Log2 -Path "$logLocation" -Message "removed existing EnrolintoWS1.ps1" -Level Warn}
    New-Item -Path $destfolder -ItemType "file" -Name "EnrolintoWS1.ps1" -Value $EnrolintoWS1 -Force -Confirm:$false
    Write-Log2 -Path "$logLocation" -Message "create new EnrolintoWS1.ps1" -Level Info
    $FileName = "$destfolder\SetupComplete.cmd"
    $SetupComplete = Build-SetupComplete
    If (Test-Path -Path $FileName){Remove-Item $FileName -force;Write-Log2 -Path "$logLocation" -Message "removed existing SetupComplete.cmd" -Level Warn}
    New-Item -Path $destfolder -ItemType "file" -Name "SetupComplete.cmd" -Value $SetupComplete -Force -Confirm:$false
    Write-Log2 -Path "$logLocation" -Message "create new SetupComplete.cmd" -Level Info

    #Download latest AirwatchAgent.msi
    if($Download){
        #Download AirwatchAgent.msi if -Download switch used, otherwise requires AirwatchAgent.msi to be deployed in the ZIP.
        Invoke-DownloadAirwatchAgent
        Start-Sleep -Seconds 10
        if(Test-Path -Path "$agentpath\$agent" -PathType Leaf){
            Copy-Item -Path "$current_path\$agent" -Destination "$agentpath\$agent" -Force
            Write-Log2 -Path "$logLocation" -Message "Copied $agent to $agentpath" -Level Info
        } else {
            Write-Log2 -Path "$logLocation" -Message "Agent not available to copy to $destfolder" -Level Info
        }
    } else {
        #Copy AirwatchAgent.msi to %WINDIR%\Setup\Scripts
        $airwatchagent = Get-ChildItem -Path $current_path -Include $agent -Recurse -ErrorAction SilentlyContinue
        if($airwatchagent){
            Copy-Item -Path $airwatchagent -Destination "$destfolder\$agent" -Force
            Write-Log2 -Path "$logLocation" -Message "copy $agent to $destfolder" -Level Info
        } else {
            Write-Log2 -Path "$logLocation" -Message "Agent not available to copy to $destfolder" -Level Error
        }
    }

    Write-Log2 -Path "$logLocation" -Message "Created Task set to run approx 5 minutes after next logon" -Level Info
    Write-Log2 -Path "$logLocation" -Message "==============Completed Setup_EnrolintoWS1==============" -Level Success
}

#Enable Debug Logging
$Debug = $false

#Variables
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $current_path = Get-Location
} 

if($IsMacOS -or $IsLinux){$delimiter = "/"}else{$delimiter = "\"}
$DateNow = Get-Date -Format "yyyyMMdd_hhmm"
$scriptName = $MyInvocation.MyCommand.Name
$scriptBaseName = (Get-Item $scriptName).Basename
$logLocation = "$current_path"+"$delimiter"+"$scriptBaseName"+"_$DateNow.log"

$destfolder = "$env:WINDIR\Setup\Scripts";
$agent = "AirwatchAgent.msi";
$AWSenrolintoWS1script = "EnrolintoWS1.ps1"
$deploypathscriptName = "$destfolder\$AWSenrolintoWS1script"

$Hostname=[System.Net.Dns]::GetHostName()

if($Debug){
  write-host "Current Path: $current_path"
  write-host "LogLocation: $LogLocation"
}

#Call Main function
Main
