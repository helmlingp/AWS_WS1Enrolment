# HZCloud_WS1Enrolment
Creates script, downloads AirwatchAgent.msi and creates a Scheduled Task to enrol an AWS Workspaces Desktop into Workspace ONE.
Specifically:
* Creates %WINDIR%\Setup\Scripts\EnrolintoWS1.ps1 calls EnrolintoWS1.ps1 
* Creates Windows Scheduled Task to run EnrolintoWS1.ps1 passing Workspace ONE environment and staging user credentials as parameters.
* Downloads the latest AirWatchAgent.msi to %WINDIR%\Setup\Scripts folder if -Download switch is utilised AirwatchAgent.msi can also be downloaded manually   from https://getwsone.com or to utilise the same version seeded into the console goto https://<DS_FQDN>/agents/ProtectionAgent_AutoSeed/AirwatchAgent.msi   to download it, substituting <DS_FQDN> with the FQDN for the Device Services Server.
