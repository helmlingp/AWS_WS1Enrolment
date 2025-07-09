# Horizon Cloud & AWS Workspaces WS1 Enrolment

The `Setup_EnrollintoWS1.ps1` script optionally downloads the latest AirwatchAgent.msi, installs the AirwatchAgent.msi without enrollment credentials in deferred enrollment mode, creates a script (`EnrollintoWS1.ps1`) locally and creates a Windows Scheduled Task that executes script on first logon, passing Workspace ONE environment and staging user credentials as parameters to enrol a Persistent VDI Desktop into Workspace ONE.

The Setup_EnrolintoWS1.ps1 script should be run on the Base AWS AMI VM when used to create AWS Workspace VMs, or within the Azure Base Image when used to create Horizon Cloud on Azure pools. This script can also be run on a Windows 10/11 VMs used as the Golden Master for Horizon 8 deployments.

The `EnrollintoWS1.ps1` script will be executed by a Windows Scheduled Task on first logon of the user.

Requires Intelligent Hub for Windows 2505 build 8965 or newer as this uses the new DEFERENROLLMENT=Y parameter.

** Note: **
- Silent enrollment of EntraID joined machines requires AAD P1 license and "Airwatch by VMware" MDM app configured for AAD joined machines or ADDS (on-premises) domain joined machines. HUB will prompt for credentials with all other configurations.
- Downloads the latest AirWatchAgent.msi to %WINDIR%\Setup\Scripts folder using -Download switch. AirwatchAgent.msi can also be downloaded manually from https://getwsone.com or to utilise the same version seeded into the console goto `https://<DS_FQDN>/agents/ProtectionAgent_AutoSeed/AirwatchAgent.msi` to download it, substituting `<DS_FQDN>` with the FQDN for the Device Services Server. Place the AirwatchAgent.msi in the same folder as the `Setup_EnrollintoWS1.ps1` script.

# Disclaimer
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    OMNISSA LLC. BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
    IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Usage
- Open a Administrator: Powershell Console
- run `Set-ExecutionPolicy bypass` to allow the script to run
- Download the `Setup_EnrollintoWS1.ps1` from this repository and from within the powershell console change to that directory
- run `.\Setup_EnrollintoWS1.ps1 -Server DESTINATION_SERVER_URL -OGName DESTINATION_OG_NAME -username USERNAME -password PASSWORD -Download`

If wanting to use a specific version of Workspace ONE Intelligent Hub (AirwatchAgent.msi), place the AirwatchAgent.msi in the same folder as the `Setup_EnrollintoWS1.ps1` script.
