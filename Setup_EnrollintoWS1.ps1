<#
.Synopsis
    The Setup_EnrolintoWS1.ps1 script optioinally downloads the latest AirwatchAgent.msi, installs the AirwatchAgent.msi 
    without enrollment credentials, creates a script (EnrolintoWS1.ps1) locally and creates a Windows Scheduled Task 
    that executes script on first logon, passing Workspace ONE environment and staging user credentials as parameters
    to enrol a Persistent VDI Desktop into Workspace ONE.
 .NOTES
    Created:   	    October 2022
    Updated:        April 2025
    Created by:	    Phil Helmling
    Organization:   Omnissa, LLC
    Filename:       Setup_EnrolintoWS1.ps1
    GitHub:         https://github.com/helmlingp/AWS_WS1Enrolment
.DESCRIPTION
    The Setup_EnrolintoWS1.ps1 script optioinally downloads the latest AirwatchAgent.msi, installs the AirwatchAgent.msi 
    without enrollment credentials, creates a script (EnrolintoWS1.ps1) locally and creates a Windows Scheduled Task 
    that executes script on first logon, passing Workspace ONE environment and staging user credentials as parameters
    to enrol a Persistent VDI Desktop into Workspace ONE.

    The Setup_EnrolintoWS1.ps1 script should be run on the Base AWS AMI VM when used to create AWS Workspace VMs, or within the 
    Azure Base Image when used to create Horizon Cloud on Azure pools.

    ** Note: **
    - Silent enrolment requires AAD P1 license and "Airwatch by VMware" MDM app configured for AAD joined machines or ADDS 
    (on-premises) domain joined machines. HUB will prompt for credentials with all other configurations.
    - Downloads the latest AirWatchAgent.msi to %WINDIR%\Setup\Scripts folder using -Download switch. AirwatchAgent.msi can also be 
    downloaded manually from https://getwsone.com or to utilise the same version seeded into the console goto 
    https://<DS_FQDN>/agents/ProtectionAgent_AutoSeed/AirwatchAgent.msi to download it, substituting <DS_FQDN> with the FQDN for the 
    Device Services Server.

.DISCLAIMER    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    OMNISSA LLC. BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
    IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    
.REQUIREMENTS
    - AirWatchAgent.msi in the %WINDIR%\Setup\Scripts folder or in the current folder or use the -Download switch
    - WS1 enrollment credentials and server details
    - Run on AWS base AMI VM used to create AWS Workspace or Azure Base Image used to create a HCoA Pool

.USAGE
    Open a Administrator: Powershell Console
    run `Set-ExecutionPolicy bypass` to allow the script to run
    Download the Setup_EnrolintoWS1.ps1 from this repository and from within the powershell console change to that directory
    run `.\Setup_EnrolintoWS1.ps1 -Server DESTINATION_SERVER_URL -OGName DESTINATION_OG_NAME -Username USERNAME -Password PASSWORD -Download`

    If wanting to use a specific version of Workspace ONE Intelligent Hub (AirwatchAgent.msi), place the AirwatchAgent.msi in the same folder as the Setup_EnrolintoWS1.ps1 script.

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
  .\Setup_EnrolintoWS1.ps1 -Server DESTINATION_SERVER_URL -OGName DESTINATION_OG_NAME -Username USERNAME -Password PASSWORD -Download
#>
param (
    [Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Server Name")] [Alias('Server')] [String] $ServerName="cn135.awmdm.com",
    [Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="GroupID")] [Alias('OG')] [Alias('OGName')] [String] $GroupID="GroupID",
    [Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Staging User Name")] [String] $UserName="staginguser",
    [Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Staging User Password")] [String] $Password="stagingpassword",
    [Parameter(Mandatory=$false,ValueFromPipeline=$true,HelpMessage="LogPath")] [String] $LogPath="$env:ProgramData\AirWatch\UnifiedAgent\Logs",
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

function Write-Log {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)] [ValidateNotNullOrEmpty()] [Alias("LogContent")] [string] $Message,
        [Parameter(Mandatory=$false)] [Alias('LogPath')] [Alias('LogLocation')] [string] $Path=$Script:LogPath,
        [Parameter(Mandatory=$false)] [ValidateSet("Success","Error","Warn","Info")] [string] $Level="Info",
        [Parameter(Mandatory=$false)] [switch]$NoClobber
    )

    Begin
    {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'

        if(!$LogPath){
            $LogPath = $PSScriptRoot;
            if($null -eq $PSScriptRoot){
                #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
                $LogPath = Get-Location
            }
        }
		write-host "LogPath: $LogPath"
		if($null -eq $IsWindows){
			if($env:OS -eq "Windows_NT"){
				$delimiter = "\"
			}else{
				$delimiter = "/"
			}
		} else {
			$delimiter = "\"
		}
        $DateNow = Get-Date -Format "yyyyMMdd"
        $scriptName = split-path $MyInvocation.PSCommandPath -Leaf
        $scriptBaseName = $scriptName.TrimEnd(".ps1")
        $Local:NewLogFileName = "$scriptBaseName"+"_"+"$DateNow"+".log"
        $Local:NewLogFile = "$LogPath"+"$delimiter"+"$Local:NewLogFileName"

        if (!(Test-Path $Local:NewLogFile)) {
            # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
            New-Item -Path $Local:NewLogFile -Force -ItemType File
        }
		$Local:LogFile = $Local:NewLogFile

        $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.ffffZ"

        $ColorMap = @{"Success"="Green";"Error"="Red";"Warn"="Yellow"}
        $FontColor = "White"
        If($ColorMap.ContainsKey($Level)){
            $FontColor = $ColorMap[$Level]
        }
    }
    Process
    {
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Local:LogFile) -AND $NoClobber) {
            Write-Error "Log file $Local:LogFile already exists, and you specified NoClobber. Either delete the file or specify a different LogPath."
            Return
        }

        # Write message with Date Level and Message
        Add-Content -Path $Local:LogFile -Value ("$timestamp`t$Level`t$Message")
        Write-Host "$Level`:`t$Message" -ForegroundColor $FontColor
    }
    End
    {

    }
}

function Invoke-DownloadAirwatchAgent {
    try {
        [Net.ServicePointManager]::SecurityProtocol = 'Tls11,Tls12'
        $url = "https://packages.omnissa.com/wsone/AirwatchAgent.msi"
        $output = "$current_path\$agent"
        $Response = Invoke-WebRequest -Uri $url -OutFile $output
        # This will only execute if the Invoke-WebRequest is successful.
        $StatusCode = $Response.StatusCode
    } catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        Write-Log -Path "$logLocation" -Message "Failed to download AirwatchAgent.msi with StatusCode $StatusCode" -Level Error
    }
}

function Invoke-CreateTask{
    #$hostname=hostname
    $arg = "-ep Bypass -File $FileName -Server $ServerName -GroupID $GroupID -UserName $Username -Password $Password -Hostname $Hostname"
    
    $TaskName = "EnrolintoWS1.ps1"
    Try{
        $A = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe" -Argument $arg 
        $T = New-ScheduledTaskTrigger -AtLogOn -RandomDelay 60
        $P = New-ScheduledTaskPrincipal "System" -RunLevel Highest
        #$P = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\System" -LogonType ServiceAccount -RunLevel Highest
        $S = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -StartWhenAvailable -Priority 5
        $S.CimInstanceProperties['MultipleInstances'].Value=3
        $D = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S
  
        Register-ScheduledTask -InputObject $D -TaskName $Taskname -Force -ErrorAction Stop
        Write-Log "Create Task $Taskname" -Level Info
    } Catch {
        #$e = $_.Exception.Message;
        #Write-Host "Error: Job creation failed.  Validate user rights."
        Write-Log "Error: Job creation failed.  Validate user rights." -Level Info
    }
}

function Build-EnrollScript {
    #Create EnrolintoWS1.ps1 Script that does enrolment
    $EnrollintoWS1 = @'
<#
.Synopsis
    Enrolls a persistent VDI desktop or AWS Workspaces "desktop" into WS1
.NOTES
    Created:   	    November 2021
    Updated:        April 2025
    Created by:	    Phil Helmling
    Organization:   Omnissa, LLC
    Filename:       EnrollintoWS1.ps1
    
.DESCRIPTION
    **This script does not need to be edited**

    - Called by a Windows Scheduled Task
    - Seeded into Base AMI VM when used to create AWS Workspace VMs or within the Azure Base Image 
        when used to create Horizon Cloud on Azure pools
    - Enrols a persistent VDI into WS1
    - Requires AirWatchAgent.msi in the %WINDIR%\Setup\Scripts folder

.EXAMPLE
.\EnrollintoWS1.ps1 -Server DESTINATION_SERVER_URL GroupID DESTINATION_OG_NAME -Username USERNAME -Password PASSWORD  -Hostname SetupHostname
#>
param (
    [Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Server Name")] [String] $ServerName="cn135.awmdm.com",
    [Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="GroupID")] [String] $GroupID="GroupID",
    [Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Staging User Name")] [String] $UserName="staginguser",
    [Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Staging User Password")] [String] $Password="stagingpassword",
    [Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Hostname of Setup Machine")] [string] $Hostname,
    [Parameter(Mandatory=$false,ValueFromPipeline=$true,HelpMessage="LogPath")] [String] $LogPath="$env:ProgramData\AirWatch\UnifiedAgent\Logs"
)

function Write-Log {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)] [ValidateNotNullOrEmpty()] [Alias("LogContent")] [string] $Message,
        [Parameter(Mandatory=$false)] [Alias('LogPath')] [Alias('LogLocation')] [string] $Path=$Script:LogPath,
        [Parameter(Mandatory=$false)] [ValidateSet("Success","Error","Warn","Info")] [string] $Level="Info",
        [Parameter(Mandatory=$false)] [switch]$NoClobber
    )

    Begin
    {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'

        if(!$LogPath){
            $LogPath = $PSScriptRoot;
            if($null -eq $PSScriptRoot){
                #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
                $LogPath = Get-Location
            }
        }
		write-host "LogPath: $LogPath"
		if($null -eq $IsWindows){
			if($env:OS -eq "Windows_NT"){
				$delimiter = "\"
			}else{
				$delimiter = "/"
			}
		} else {
			$delimiter = "\"
		}
        $DateNow = Get-Date -Format "yyyyMMdd"
        $scriptName = split-path $MyInvocation.PSCommandPath -Leaf
        $scriptBaseName = $scriptName.TrimEnd(".ps1")
        $Local:NewLogFileName = "$scriptBaseName"+"_"+"$DateNow"+".log"
        $Local:NewLogFile = "$LogPath"+"$delimiter"+"$Local:NewLogFileName"

        if (!(Test-Path $Local:NewLogFile)) {
            # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
            New-Item -Path $Local:NewLogFile -Force -ItemType File
        }
		$Local:LogFile = $Local:NewLogFile

        $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.ffffZ"

        $ColorMap = @{"Success"="Green";"Error"="Red";"Warn"="Yellow"}
        $FontColor = "White"
        If($ColorMap.ContainsKey($Level)){
            $FontColor = $ColorMap[$Level]
        }
    }
    Process
    {
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Local:LogFile) -AND $NoClobber) {
            Write-Error "Log file $Local:LogFile already exists, and you specified NoClobber. Either delete the file or specify a different LogPath."
            Return
        }

        # Write message with Date Level and Message
        Add-Content -Path $Local:LogFile -Value ("$timestamp`t$Level`t$Message")
        Write-Host "$Level`:`t$Message" -ForegroundColor $FontColor
    }
    End
    {

    }
}

#Variables
$currentHostname=[System.Net.Dns]::GetHostName()
$HubRegistryMainPath = "HKLM:\SOFTWARE\AIRWATCH"
$EnrollmentRegistryPath = "$($HubRegistryMainPath)\EnrollmentStatus"
$installDir = (Get-ItemProperty -Path $HubRegistryMainPath -Name "INSTALLDIR" -ErrorAction SilentlyContinue).INSTALLDIR
$exePath = "$installDir\AgentUI\AWProcessCommands.exe"
$arguments = "ENROLL --Server=$ServerName --OG=$GroupID --Username=$UserName --Password=$Password --ASSIGNTOLOGGEDINUSER"
$osType = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).InstallationType
$executeScript = $false

Write-Log "Starting EnrolintoWS1 Process" -Level Success
#Do not run this script in base image VM
if ($Hostname -ne $currentHostname){
    
    #Check if HUBW installed
    if ($null -eq $installDir) {
        Write-Log "INSTALLDIR not found in registry. Script execution aborted." -Level Error
    } else {
        if (!(Test-Path -Path $EnrollmentRegistryPath)) {
            Write-Log "Registry path $EnrollmentRegistryPath does not exist. Triggering HUB CLI." -Level Warn
            $executeScript = $true
        } else {
            $status = (Get-ItemProperty -Path $EnrollmentRegistryPath -Name "Status" -ErrorAction SilentlyContinue).Status
            if ($osType -eq "Server" -and $status -ne "Completed") {
                Write-Log "Server Not Enrolled. Triggering HUB CLI."
                $executeScript = $true
            } elseif ($status -eq "InProgress" -or $status -eq "Completed") {
                Write-Log "Enrollment skipped as EnrollmentStatus is '$status'." -Level Warn
                #exit 1
            } else {
                Write-Log "EnrollmentStatus is '$status'. Triggering HUB CLI."
                $executeScript = $true
            }
        }
    }
    

    if ($executeScript) {
        try {

            $process = Start-Process -FilePath $exePath -ArgumentList $arguments -NoNewWindow -Wait -PassThru
            do {start-sleep 60} until ((Get-ItemProperty -Path $EnrollmentRegistryPath -Name $registryValue -ErrorAction SilentlyContinue).Status -eq 'Completed')
            
            if ($process.ExitCode -eq 0) {
                Write-Log "Enrollment with HUB CLI Completed." -Level Success
            
                #Remove Task so it doesn't run again
                Unregister-ScheduledTask -TaskName "EnrolintoWS1.ps1" -confirm:$false -ErrorAction SilentlyContinue
                exit 0
            }
            else {
                Write-Log "Warning: HUB CLI failed with exit code $($process.ExitCode)." -Level Error
                exit $($process.ExitCode)
            }
        }
        catch {
            Write-Log "Error: Script encountered an error: $_" -Level Error
        }
    }

}

'@
    return $EnrollintoWS1
}

function Invoke-InstallAgent {

    try {
        Write-Log "Installing AirwatchAgent" -Level Info
        $process = Start-Process msiexec.exe -ArgumentList "/i","$destfolder\$agent","/quiet","UI=Headless","PROVISIONHUB=Y","ENABLEBETAFEATURES=Y" -NoNewWindow -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Log "Hub Install Completed." -Level Success
            #exit 0
        }
        else {
            Write-Log "Warning: HUB Install failed with exit code $($process.ExitCode)." -Level Error
            exit $($process.ExitCode)
        }
    }
    catch {
        Write-Log "Error: Script encountered an error: $_" -Level Error
        #exit 1
    }
}


function Main {
    #Setup Logging
    Test-Folder -Path $destfolder
    Write-Log "Setup_EnrolintoWS1.ps1 Started" -Level Success

    #Ask for WS1 tenant and staging credentials if not already provided
    if ([string]::IsNullOrEmpty($script:Server)){
        $ServerName = Read-Host -Prompt 'Enter the Workspace ONE UEM Device Services Server URL'
        $GroupID = Read-Host -Prompt 'Enter the Organizational Group ID'
        $UserName = Read-Host -Prompt 'Enter the Staging Username'
        $Password = Read-Host -Prompt 'Enter the Staging User Password'
    }
    Write-Log "Workspace ONE environment details obtained" -Level Info

    #Test for blank passord as...
    if ([string]::IsNullOrEmpty($password)){
        $password = "."
    }

    #Create EnrolintoWS1.ps1 Script that does enrolment, triggered on first logon by Scheduled Task called EnrolintoWS1.ps1
    $FileName = "$destfolder\EnrollintoWS1.ps1"
    $EnrollintoWS1 = Build-EnrollScript
    If (Test-Path -Path $FileName){Remove-Item $FileName -force;Write-Log "removed existing EnrollintoWS1.ps1" -Level Warn}
    New-Item -Path $destfolder -ItemType "file" -Name "EnrollintoWS1.ps1" -Value $EnrollintoWS1 -Force -Confirm:$false
    Write-Log "create new EnrollintoWS1.ps1" -Level Info

    #Download latest AirwatchAgent.msi
    if($Download){
        #Download AirwatchAgent.msi if -Download switch used, otherwise requires AirwatchAgent.msi to be deployed in the ZIP.
        Invoke-DownloadAirwatchAgent
        Start-Sleep -Seconds 10
        if(Test-Path -Path "$current_path\$agent" -PathType Leaf){
            Copy-Item -Path "$current_path\$agent" -Destination "$destfolder\$agent" -Force
            Write-Log "Copied $agent to $destfolder" -Level Info
        } else {
            Write-Log "Agent not available to copy to $destfolder. Ensure AirwatchAgent.msi is copied to $agentpath\$agent." -Level Info
        }
    } else {
        #Copy AirwatchAgent.msi to %WINDIR%\Setup\Scripts
        $airwatchagent = Get-ChildItem -Path $current_path -Include $agent -Recurse -ErrorAction SilentlyContinue
        if($airwatchagent){
            Copy-Item -Path $airwatchagent -Destination "$destfolder\$agent" -Force
            Write-Log "copy $agent to $destfolder" -Level Info
        } else {
            Write-Log "Agent not available to copy to $destfolder. Ensure AirwatchAgent.msi is copied to $agentpath\$agent." -Level Error
        }
    }

    #Install Agent
    if(Test-Path -Path "$destfolder\$agent") {
        Invoke-InstallAgent
    }

    #Create Scheduled Task upon first logon in SYSTEM context
    Write-Log "Creating Task to run Enrollment at next logon" -Level Info
    Invoke-CreateTask
    
    Write-Log "Completed Setup_EnrolintoWS1.ps1" -Level Success
}

#Variables
$destfolder = "$env:WINDIR\Setup\Scripts"
$agent = "AirwatchAgent.msi"
$Hostname=[System.Net.Dns]::GetHostName()

#Call Main function
Main
