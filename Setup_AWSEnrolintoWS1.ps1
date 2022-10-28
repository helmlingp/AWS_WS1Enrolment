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
    Creates script, downloads AirwatchAgent.msi and creates a Scheduled Task to enrol an AWS Workspaces Desktop into Workspace ONE.
    Specifically:
    * Creates %WINDIR%\Setup\Scripts\EnrolintoWS1.ps1 calls EnrolintoWS1.ps1 
    * Creates Windows Scheduled Task to run EnrolintoWS1.ps1 passing Workspace ONE environment and staging user credentials as parameters.
    * Downloads the latest AirWatchAgent.msi to %WINDIR%\Setup\Scripts folder if -Download switch is utilised
    AirwatchAgent.msi can also be downloaded manually from https://getwsone.com or to utilise the same version seeded into the console goto
    https://<DS_FQDN>/agents/ProtectionAgent_AutoSeed/AirwatchAgent.msi to download it, substituting <DS_FQDN> with the FQDN for the Device Services Server.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    VMWARE,INC. BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
    IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    
.REQUIREMENTS
    * AirWatchAgent.msi in the current folder or -Download switch
    * WS1 enrollment credentials and server details
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

Function Test-Folder {
    param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Path
  )
    
    if (!(Test-Path -LiteralPath $Path)) {
        try{
            New-Item -Path $Path -ItemType "Directory" -ErrorAction Ignore -Force #| Out-Null
        }
        catch {
            Write-Error -Message "Unable to create directory '$Path'. Error was: $_" -ErrorAction Stop
        }
        "Successfully created directory '$Path'."
    }
}

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

function Invoke-CreateTask{
  $arg = "-ep Bypass -File $deploypathscriptName -username $username -password $password -Server $Server -OGName $OGName"
  
  $TaskName = "$AWSenrolintoWS1script"
  Try{
      $A = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe" -Argument $arg 
      $T = New-ScheduledTaskTrigger -AtLogOn -RandomDelay 60
      $P = New-ScheduledTaskPrincipal "System" -RunLevel Highest
      #$P = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\System" -LogonType ServiceAccount -RunLevel Highest
      $S = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -StartWhenAvailable -Priority 5
      $S.CimInstanceProperties['MultipleInstances'].Value=3
      $D = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S

      Register-ScheduledTask -InputObject $D -TaskName $Taskname -Force -ErrorAction Stop
      Write-Log2 -Path "$logLocation" -Message "Create Task $Taskname" -Level Info
  } Catch {
      #$e = $_.Exception.Message;
      #Write-Host "Error: Job creation failed.  Validate user rights."
      Write-Log2 -Path "$logLocation" -Message "Error: Job creation failed.  Validate user rights." -Level Info
  }
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
$deploypathscriptName = "$destfolder"+"$delimiter"+"$AWSenrolintoWS1script"

if($Debug){
  write-host "Current Path: $current_path"
  write-host "LogLocation: $LogLocation"
}

function Main {

  Test-Folder -Path $destfolder
  Write-Log2 -Path "$logLocation" -Message "Setup_AWSEnrolintoWS1.ps1 Started" -Level Success
  
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
      GitHub:         
  .DESCRIPTION
      **This script does not need to be edited**
      
      Called by a Windows Scheduled Task
      Enrols a AWS Workspaces Desktop into WS1
      Scheduled Task provides parameters for enrolment 
      Requires AirWatchAgent.msi in the C:\Recovery\OEM folder
  
      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
      IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
      FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
      VMWARE,INC. BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
      IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
      CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  
  .EXAMPLE
    .\EnrolintoWS1.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_URL -OGName DESTINATION_OG_NAME
  #>
  param (
    [Parameter(Mandatory=$true)][string]$username,
    [Parameter(Mandatory=$true)][string]$password,
    [Parameter(Mandatory=$true)][string]$OGName,
    [Parameter(Mandatory=$true)][string]$Server
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
  $destfolder = "$env:WINDIR\Setup\Scripts";
  $enrollmentcomplete = $false;
  $keypath = "Registry::HKLM\SOFTWARE\AIRWATCH\EnrollmentStatus"
  Write-Log2 -Path "$logLocation" -Message "Starting EnrolintoWS1 Process" -Level Success
  
  while ($enrollmentcomplete -ne $true) {
      Write-Log2 -Path "$logLocation" -Message "Starting Workspace ONE enrollment" -Level Info
      Start-Process msiexec.exe -ArgumentList "/i","$destfolder\AirwatchAgent.msi","/qn","ENROLL=Y","SERVER=$Server","LGNAME=$OGName","USERNAME=$username","PASSWORD=$password","ASSIGNTOLOGGEDINUSER=Y","/log $current_path\AWAgent.log";
  
      do {start-sleep 60} until ((Get-ItemPropertyValue -Path $keypath -Name "Status" -ErrorAction SilentlyContinue) -eq 'Completed')
  
      start-sleep 60;
      Write-Log2 -Path "$logLocation" -Message "Workspace ONE enrollment complete" -Level Success
      $enrollmentcomplete = $true;
  }
  
  #Remove Task so it doesn't run again
  Unregister-ScheduledTask -TaskName "EnrolintoWS1.ps1" -confirm:$false -ErrorAction SilentlyContinue
'@
  $FileName = "$destfolder\$AWSenrolintoWS1script"
  If (Test-Path -Path $FileName){Remove-Item $FileName -force;Write-Log2 -Path "$logLocation" -Message "removed existing $AWSenrolintoWS1script" -Level Warn}
  New-Item -Path $destfolder -ItemType "file" -Name $AWSenrolintoWS1script -Value $EnrolintoWS1 -Force -Confirm:$false
  Write-Log2 -Path "$logLocation" -Message "created new $AWSenrolintoWS1script" -Level Info

  #Download latest AirwatchAgent.msi
  if($Download){
      #Download AirwatchAgent.msi if -Download switch used, otherwise requires AirwatchAgent.msi to be deployed in the ZIP.
      Invoke-DownloadAirwatchAgent
      Start-Sleep -Seconds 10
  }
  #Copy AirwatchAgent.msi to %WINDIR%\Setup\Scripts
  $airwatchagent = Get-ChildItem -Path $current_path -Include $agent -Recurse -ErrorAction SilentlyContinue
  if($airwatchagent){
      Copy-Item -Path $airwatchagent -Destination "$destfolder$delimiter$agent" -Force
      Write-Log2 -Path "$logLocation" -Message "copy AirwatchAgent.msi to $destfolder" -Level Info
  }

  #Create Scheduled Task upon first logon in SYSTEM context
  Invoke-CreateTask
  Write-Log2 -Path "$logLocation" -Message "Created Task set to run at next logon" -Level Info
  Write-Log2 -Path "$logLocation" -Message "Completed Setup_EnrolintoWS1" -Level Success
}

#Call Main function
Main