###################################################################################
#
#    Script:    WINTri.ps1
#    Version:   2.0
#    Author:    Dan Saunders
#    Contact:   dcscoder@gmail.com
#    Purpose:   Windows Cyber Security Incident Response Script (PowerShell)
#    Usage:     .\WINTri.ps1
#
#    This program is free software: you can redistribute it and / or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <https://www.gnu.org/licenses/>.
#
###################################################################################

$Script = "WINTri_"
$Version = "v2.0"

########## Startup ##########

Write-Host "

          ___      ____      ___ ________  ____    __  __________
          \  \    /    \    /  /|__    __||    \  |  ||___    ___| ______  __
           \  \  /  /\  \  /  /    |  |   |  \  \ |  |    |  |    |   ___||__|
            \  \/  /  \  \/  /   __|  |__ |  |\  \|  |    |  |    |  /    |  |
             \____/    \____/   |________||__| \_____|    |__|    |__|    |__|


	Script / Skript: WINTri.ps1 - $Version - Author / Autor: Dan Saunders dcscoder@gmail.com`n`n"

Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Please Note:

Hi $env:USERNAME, script running on $env:ComputerName, please do not touch!

Bitte beachten Sie:

Hallo $env:USERNAME, skript lauft auf $env:ComputerName, bitte nicht beruhren!

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor yellow -BackgroundColor black

# Check Privileges
$Admin=[Security.Principal.WindowsIdentity]::GetCurrent()
if ((New-Object Security.Principal.WindowsPrincipal $Admin).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $False)
{
    Write-Host "`n"
    Write-Warning "You have insufficient permissions. Run this script with local Administrator privileges."
    Write-Warning "Sie haben unzureichende Berechtigungen. Führen Sie dieses Skript mit lokalen Administratorrechten aus."
    Write-Host "`n"
    exit
}

########## Admin ##########

# Destination
$Destination = $PSScriptRoot
# System Date/Time
$Timestamp = ((Get-Date).ToString('_yyyyMMdd_HHmmss'))
# Computer Name
$Endpoint = $env:ComputerName
# Triage
$Name = $Script+$Endpoint+$Timestamp
$Triage = $Name
# Stream Events
Start-Transcript $Destination\$Triage\WINTri.log -Append | Out-Null

# Exchange Install path
function Get-ExchangeInstallPath {
    $Path = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
    if ($Null -eq $Path) {
        $Path = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v14\Setup -ErrorAction SilentlyContinue).MsiInstallPath
    }

    return $Path
}

$ExchangePath = Get-ExchangeInstallPath

# Script Progress
$Activity1 = "Task / Aufgabe (1 / 10)"
$Id1 = 1
$Task1 = "Admin task running / Admin-Aufgabe lauft."
Write-Progress -Id $Id1 -Activity $Activity1 -Status $Task1

# Directory Structure
New-Item $Destination\$Triage\Registry -ItemType Directory | Out-Null
New-Item $Destination\$Triage\Configuration -ItemType Directory | Out-Null
# User Folders
Get-ChildItem -Path C:\Users -Directory -Force | Select-Object -ExpandProperty Name | Out-File $Destination\$Triage\Configuration\User_Folders.txt
$UserFolders = Get-Content $Destination\$Triage\Configuration\User_Folders.txt
foreach ($UserFolder in $UserFolders)
{
	New-Item $Destination\$Triage\Registry\$UserFolder -ItemType Directory | Out-Null
	}
	
########## Memory ##########

# Script Progress
$Activity2 = "Task / Aufgabe (2 / 10)"
$Id2 = 2
$Task2 = "Gather memory process information / Sammeln von Speicherprozessinformationen."
Write-Progress -Id $Id2 -Activity $Activity2 -Status $Task2

# Directory Structure
New-Item $Destination\$Triage\Memory -ItemType Directory | Out-Null
# Process List
Get-WmiObject -Class win32_process | Select-Object -Property creationdate, processname, parentprocessid, processid, sessionid, commandline | Export-Csv $Destination\$Triage\Memory\Process_List.csv
# Process + Services
tasklist /svc | Out-File $Destination\$Triage\Memory\Process_Services.txt
# Process + Loaded DLL
tasklist /m | Out-File $Destination\$Triage\Memory\Process_Loaded_DLL.txt
# Process + Owners
tasklist /v | Out-File $Destination\$Triage\Memory\Process_Owners.txt

########## Registry ##########

# Script Progress
$Activity3 = "Task / Aufgabe (3 / 10)"
$Id3 = 3
$Task3 = "Gather registry information / Sammeln von Registerinformationen."
Write-Progress -Id $Id3 -Activity $Activity3 -Status $Task3

# Local Groups
try
{
    Get-LocalGroup | select * | Out-File $Destination\$Triage\Registry\Local_Groups.txt
}
catch
{

}
# Local Users
try
{
    Get-LocalUser | select * | Out-File $Destination\$Triage\Registry\Local_Users.txt
}
catch
{

}
# Local Admins
try
{
    net localgroup administrators | Out-File $Destination\$Triage\Registry\Local_Admins.txt
}
catch
{

}
# Domain Admins
try
{
    net group "domain admins" /domain | Out-File $Destination\$Triage\Registry\Domain_Admins.txt
}
catch
{

}
# Enterprise Admins
try
{
    net group "enterprise admins" /domain | Out-File $Destination\$Triage\Registry\Enterprise_Admins.txt
}
catch
{

}
# System Hives
reg save HKLM\SYSTEM $Destination\$Triage\Registry\SYSTEM | Out-Null
reg save HKLM\SOFTWARE $Destination\$Triage\Registry\SOFTWARE | Out-Null
reg save HKLM\SAM $Destination\$Triage\Registry\SAM | Out-Null
reg save HKLM\SECURITY $Destination\$Triage\Registry\SECURITY | Out-Null
# Local System Hive
reg save HKU\.DEFAULT $Destination\$Triage\Registry\.DEFAULT | Out-Null
# NTUSER.DAT Hives
$UserFolders = Get-Content $Destination\$Triage\Configuration\User_Folders.txt
foreach ($UserFolder in $UserFolders)
{
    esentutl /y /vss "C:\Users\$UserFolder\NTUSER.DAT" /d "$Destination\$Triage\Registry\$UserFolder\NTUSER.DAT" | Out-Null
	}
# UsrClass
$UserFolders = Get-Content $Destination\$Triage\Configuration\User_Folders.txt
foreach ($UserFolder in $UserFolders)
{
    esentutl /y /vss "C:\Users\$UserFolder\AppData\Local\Microsoft\Windows\UsrClass.dat" /d "$Destination\$Triage\Registry\$UserFolder\UsrClass.dat" | Out-Null
    }

########## Logs ##########

# Script Progress
$Activity4 = "Task / Aufgabe (4 / 10)"
$Id4 = 4
$Task4 = "Gather log information / Sammeln von Protokollinformationen."
Write-Progress -Id $Id4 -Activity $Activity4 -Status $Task4

# Directory Structure
New-Item $Destination\$Triage\Logs\winevt -ItemType Directory | Out-Null
New-Item $Destination\$Triage\Logs\USB -ItemType Directory | Out-Null
New-Item $Destination\$Triage\Logs\ETW -ItemType Directory | Out-Null
New-Item $Destination\$Triage\Logs\PowerShell -ItemType Directory | Out-Null
# Windows Event Logs
Copy-Item C:\Windows\System32\winevt\Logs\*.evtx $Destination\$Triage\Logs\winevt
# USB Device Connections
Copy-Item C:\Windows\inf\setupapi.dev.log $Destination\$Triage\Logs\USB
# Windows Update Log
Copy-Item C:\Windows\Logs\WindowsUpdate\*.etl $Destination\$Triage\Logs\ETW
# PowerShell History
$UserFolders = Get-Content $Destination\$Triage\Configuration\User_Folders.txt
foreach ($UserFolder in $UserFolders)
{
        robocopy "C:\Users\$UserFolder\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine" "$Destination\$Triage\Logs\PowerShell\ConsoleHost_history-$UserFolder" ConsoleHost_history.txt /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\Logs\PowerShell\ConsoleHost_history-$UserFolder.txt | Out-Null
    }
# Firewall Logs
if (Test-Path C:\Windows\System32\LogFiles\Firewall)
{
    New-Item $Destination\$Triage\Logs\Firewall -ItemType Directory | Out-Null
    robocopy "C:\Windows\System32\LogFiles\Firewall" "$Destination\$Triage\Logs\Firewall\" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\Logs\Firewall\Firewall.txt | Out-Null
}
# Internet Information Services (IIS) Logs
if (Test-Path C:\inetpub\logs\LogFiles)
{
    New-Item $Destination\$Triage\Logs\IIS -ItemType Directory | Out-Null
    robocopy "C:\inetpub\logs\LogFiles" "$Destination\$Triage\Logs\IIS\" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\Logs\IIS\IIS_Folders.txt | Out-Null
}
# Exchange Logging
if (Test-Path "$ExchangePath\Logging\")
{
    New-Item $Destination\$Triage\Logs\Exchange -ItemType Directory | Out-Null
    robocopy "$ExchangePath\Logging" "$Destination\$Triage\Logs\Exchange\" /E /copyall /ZB /TS /r:4 /w:15 /FP /NP /log+:$Destination\$Triage\Logs\Exchange\Exchange_Folders.txt | Out-Null
}
# User Access Logging (UAL)
if (Test-Path C:\Windows\System32\LogFiles\Sum)
{
    New-Item $Destination\$Triage\Logs\UAL -ItemType Directory | Out-Null
    robocopy "C:\Windows\System32\LogFiles\Sum" "$Destination\$Triage\Logs\Sum\" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\Logs\UAL\UAL.txt | Out-Null
}

########## Network ##########

# Script Progress
$Activity5 = "Task / Aufgabe (5 / 10)"
$Id5 = 5
$Task5 = "Gather network information / Sammeln von Netzwerkinformationen."
Write-Progress -Id $Id5 -Activity $Activity5 -Status $Task5

# Directory Structure
New-Item $Destination\$Triage\Network -ItemType Directory | Out-Null
# DNS Entries
Copy-Item C:\Windows\System32\drivers\etc\hosts $Destination\$Triage\Network
# Network Settings
Copy-Item C:\Windows\System32\drivers\etc\networks $Destination\$Triage\Network
# IP Configuration
ipconfig /all | Out-File $Destination\$Triage\Network\ipconfig_all.txt
# Local DNS
ipconfig /displaydns | Out-File $Destination\$Triage\Network\ipconfig_dns.txt
# DNS Client Cache
Get-DnsClientCache | Out-File $Destination\$Triage\Network\DNS_Client_Cache.txt
# ARP Table
arp -a | Out-File $Destination\$Triage\Network\ARP_Table.txt
# Netstat
netstat -naob | Out-File $Destination\$Triage\Network\netstat.txt
# Routing Table
netstat -rn | Out-File $Destination\$Triage\Network\Routing_Table.txt
# Listening Ports
netstat -an| findstr LISTENING | Out-File $Destination\$Triage\Network\Listening_Ports.txt
# Open Connections
netstat -ano | Out-File $Destination\$Triage\Network\Open_Connections.txt
# Wireless Profiles
netsh wlan show profiles | Out-File $Destination\$Triage\Network\Wireless_Profiles.txt
# Firewall Configuration
netsh firewall show config | Out-File $Destination\$Triage\Network\Firewall_Configuration.txt
# Firewall Profile Properties
netsh advfirewall show allprofiles | Out-File $Destination\$Triage\Network\Firewall_Profile_Properties.txt
# Firewall Rules
netsh advfirewall firewall show rule name=all | Out-File $Destination\$Triage\Network\Firewall_Rules.txt

########## Configuration ##########

# Script Progress
$Activity6 = "Task / Aufgabe (6 / 10)"
$Id6 = 6
$Task6 = "Gather configuration information / Sammeln von Konfigurationsinformationen."
Write-Progress -Id $Id6 -Activity $Activity6 -Status $Task6

# Screenshot (https://gallery.technet.microsoft.com/scriptcenter/eeff544a-f690-4f6b-a586-11eea6fc5eb8)
Function Take-ScreenShot {   
#Requires -Version 2 
        [cmdletbinding( 
                SupportsShouldProcess = $True, 
                DefaultParameterSetName = "screen", 
                ConfirmImpact = "low" 
        )] 
Param ( 
       [Parameter( 
            Mandatory = $False, 
            ParameterSetName = "screen", 
            ValueFromPipeline = $True)] 
            [switch]$screen, 
       [Parameter( 
            Mandatory = $False, 
            ParameterSetName = "window", 
            ValueFromPipeline = $False)] 
            [switch]$activewindow, 
       [Parameter( 
            Mandatory = $False, 
            ParameterSetName = "", 
            ValueFromPipeline = $False)] 
            [string]$file,  
       [Parameter( 
            Mandatory = $False, 
            ParameterSetName = "", 
            ValueFromPipeline = $False)] 
            [string] 
            [ValidateSet("bmp","jpeg","png")] 
            $imagetype = "bmp", 
       [Parameter( 
            Mandatory = $False, 
            ParameterSetName = "", 
            ValueFromPipeline = $False)] 
            [switch]$print                        
        
) 
# C# code 
$code = @' 
using System; 
using System.Runtime.InteropServices; 
using System.Drawing; 
using System.Drawing.Imaging; 
namespace ScreenShotDemo 
{ 
  /// <summary> 
  /// Provides functions to capture the entire screen, or a particular window, and save it to a file. 
  /// </summary> 
  public class ScreenCapture 
  { 
    /// <summary> 
    /// Creates an Image object containing a screen shot the active window 
    /// </summary> 
    /// <returns></returns> 
    public Image CaptureActiveWindow() 
    { 
      return CaptureWindow( User32.GetForegroundWindow() ); 
    } 
    /// <summary> 
    /// Creates an Image object containing a screen shot of the entire desktop 
    /// </summary> 
    /// <returns></returns> 
    public Image CaptureScreen() 
    { 
      return CaptureWindow( User32.GetDesktopWindow() ); 
    }     
    /// <summary> 
    /// Creates an Image object containing a screen shot of a specific window 
    /// </summary> 
    /// <param name="handle">The handle to the window. (In windows forms, this is obtained by the Handle property)</param> 
    /// <returns></returns> 
    private Image CaptureWindow(IntPtr handle) 
    { 
      // get te hDC of the target window 
      IntPtr hdcSrc = User32.GetWindowDC(handle); 
      // get the size 
      User32.RECT windowRect = new User32.RECT(); 
      User32.GetWindowRect(handle,ref windowRect); 
      int width = windowRect.right - windowRect.left; 
      int height = windowRect.bottom - windowRect.top; 
      // create a device context we can copy to 
      IntPtr hdcDest = GDI32.CreateCompatibleDC(hdcSrc); 
      // create a bitmap we can copy it to, 
      // using GetDeviceCaps to get the width/height 
      IntPtr hBitmap = GDI32.CreateCompatibleBitmap(hdcSrc,width,height); 
      // select the bitmap object 
      IntPtr hOld = GDI32.SelectObject(hdcDest,hBitmap); 
      // bitblt over 
      GDI32.BitBlt(hdcDest,0,0,width,height,hdcSrc,0,0,GDI32.SRCCOPY); 
      // restore selection 
      GDI32.SelectObject(hdcDest,hOld); 
      // clean up 
      GDI32.DeleteDC(hdcDest); 
      User32.ReleaseDC(handle,hdcSrc); 
      // get a .NET image object for it 
      Image img = Image.FromHbitmap(hBitmap); 
      // free up the Bitmap object 
      GDI32.DeleteObject(hBitmap); 
      return img; 
    } 
    /// <summary> 
    /// Captures a screen shot of the active window, and saves it to a file 
    /// </summary> 
    /// <param name="filename"></param> 
    /// <param name="format"></param> 
    public void CaptureActiveWindowToFile(string filename, ImageFormat format) 
    { 
      Image img = CaptureActiveWindow(); 
      img.Save(filename,format); 
    } 
    /// <summary> 
    /// Captures a screen shot of the entire desktop, and saves it to a file 
    /// </summary> 
    /// <param name="filename"></param> 
    /// <param name="format"></param> 
    public void CaptureScreenToFile(string filename, ImageFormat format) 
    { 
      Image img = CaptureScreen(); 
      img.Save(filename,format); 
    }     
    
    /// <summary> 
    /// Helper class containing Gdi32 API functions 
    /// </summary> 
    private class GDI32 
    { 
       
      public const int SRCCOPY = 0x00CC0020; // BitBlt dwRop parameter 
      [DllImport("gdi32.dll")] 
      public static extern bool BitBlt(IntPtr hObject,int nXDest,int nYDest, 
        int nWidth,int nHeight,IntPtr hObjectSource, 
        int nXSrc,int nYSrc,int dwRop); 
      [DllImport("gdi32.dll")] 
      public static extern IntPtr CreateCompatibleBitmap(IntPtr hDC,int nWidth, 
        int nHeight); 
      [DllImport("gdi32.dll")] 
      public static extern IntPtr CreateCompatibleDC(IntPtr hDC); 
      [DllImport("gdi32.dll")] 
      public static extern bool DeleteDC(IntPtr hDC); 
      [DllImport("gdi32.dll")] 
      public static extern bool DeleteObject(IntPtr hObject); 
      [DllImport("gdi32.dll")] 
      public static extern IntPtr SelectObject(IntPtr hDC,IntPtr hObject); 
    } 
 
    /// <summary> 
    /// Helper class containing User32 API functions 
    /// </summary> 
    private class User32 
    { 
      [StructLayout(LayoutKind.Sequential)] 
      public struct RECT 
      { 
        public int left; 
        public int top; 
        public int right; 
        public int bottom; 
      } 
      [DllImport("user32.dll")] 
      public static extern IntPtr GetDesktopWindow(); 
      [DllImport("user32.dll")] 
      public static extern IntPtr GetWindowDC(IntPtr hWnd); 
      [DllImport("user32.dll")] 
      public static extern IntPtr ReleaseDC(IntPtr hWnd,IntPtr hDC); 
      [DllImport("user32.dll")] 
      public static extern IntPtr GetWindowRect(IntPtr hWnd,ref RECT rect); 
      [DllImport("user32.dll")] 
      public static extern IntPtr GetForegroundWindow();       
    } 
  } 
} 
'@ 
#User Add-Type to import the code 
add-type $code -ReferencedAssemblies 'System.Windows.Forms','System.Drawing' 
#Create the object for the Function 
$capture = New-Object ScreenShotDemo.ScreenCapture 
 
#Take screenshot of the entire screen 
If ($Screen) { 
    Write-Verbose "Taking screenshot of entire desktop" 
    #Save to a file 
    If ($file) { 
        If ($file -eq "") { 
            $file = "$pwd\image.bmp" 
            } 
        Write-Verbose "Creating screen file: $file with imagetype of $imagetype" 
        $capture.CaptureScreenToFile($file,$imagetype) 
        } 
    ElseIf ($print) { 
        $img = $Capture.CaptureScreen() 
        $pd = New-Object System.Drawing.Printing.PrintDocument 
        $pd.Add_PrintPage({$_.Graphics.DrawImage(([System.Drawing.Image]$img), 0, 0)}) 
        $pd.Print() 
        }         
    Else { 
        $capture.CaptureScreen() 
        } 
    } 
}
Take-ScreenShot -screen -file $Destination\$Triage\Configuration\Desktop_Screenshot.png -imagetype png
# Operating System Information
systeminfo | Out-File $Destination\$Triage\Configuration\System_Information.txt
# System Date/Time
Get-Date -Format "yyyyMMdd HHmmss K" | Out-File $Destination\$Triage\Configuration\System_Date_Time_Z.txt
# Environment Variables
Get-ChildItem ENV: | Format-Table @{Expression={$_.Name};Label="$ENV:ComputerName ENV:Variable"}, Value -AutoSize -Wrap | Out-File $Destination\$Triage\Configuration\Environment_Variables.txt
# AntiVirus Product
Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct | Out-File $Destination\$Triage\Configuration\AntiVirus_Product.txt
# Anti Malware Health Status
Get-WmiObject -namespace root\Microsoft\SecurityClient -Class AntimalwareHealthStatus | Out-File $Destination\$Triage\Configuration\Anti_Malware_Health_Status.txt
# Hotfixes
Get-HotFix | Out-File $Destination\$Triage\Configuration\Hotfixes.txt
# Disk Management
Get-WmiObject -Class Win32_LogicalDisk | Out-File $Destination\$Triage\Configuration\Disk_Drives.txt
# Server Message Block (SMB) Shares
Get-SmbShare | Out-File $Destination\$Triage\Configuration\SMB_Shares.txt
# Scheduled Tasks
schtasks /query /fo CSV /v > $Destination\$Triage\Configuration\Scheduled_Tasks.csv
# WMI Filters
Get-WMIObject -Namespace root\Subscription -Class __EventFilter | Export-Csv $Destination\$Triage\Configuration\WMI_Filters.csv
# WMI Consumers
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer | Export-Csv $Destination\$Triage\Configuration\WMI_Consumers.csv
# WMI Bindings
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Export-Csv $Destination\$Triage\Configuration\WMI_Bindings.csv
# Volume Shadow Copy Service (VSC/VSS)
C:\windows\system32\vssadmin list shadows | Out-File $Destination\$Triage\Configuration\VSC.txt
# Group Policy
gpresult /R /Z | Out-File $Destination\$Triage\Configuration\Group_Policy.txt

########## File System ##########

# Script Progress
$Activity7 = "Task / Aufgabe (7 / 10)"
$Id7 = 7
$Task7 = "Gather file system information / Sammeln von Dateisysteminformationen."
Write-Progress -Id $Id7 -Activity $Activity7 -Status $Task7

# Directory Structure
New-Item $Destination\$Triage\FileSystem -ItemType Directory | Out-Null
# Alternate Data Streams
try
{
   Get-ChildItem "C:\" -recurse | foreach {Get-Item $_.FullName -stream *} | where stream -ne ':$DATA' | Out-File $Destination\$Triage\FileSystem\Alternate_Data_Streams.txt
}
catch
{

}
# Perflogs Directory Listing
if (Test-Path C:\Perflogs)
{
    Get-ChildItem -Force -Recurse C:\Perflogs\* | Format-Table Name, FullName, Length, CreationTimeUtc, LastWriteTimeUtc, LastAccessTimeUtc | Out-File $Destination\$Triage\FileSystem\C_Perflogs.txt
}
# Root Temp Directory Listing
if (Test-Path C:\Temp)
{
    Get-ChildItem -Force -Recurse C:\Temp\* | Format-Table Name, FullName, Length, CreationTimeUtc, LastWriteTimeUtc, LastAccessTimeUtc | Out-File $Destination\$Triage\FileSystem\C_Temp_Dir.txt
}
# Windows Temp Directory Listing
if (Test-Path C:\Windows\Temp)
{
    Get-ChildItem -Force -Recurse C:\Windows\Temp\* | Format-Table Name, FullName, Length, CreationTimeUtc, LastWriteTimeUtc, LastAccessTimeUtc | Out-File $Destination\$Triage\FileSystem\C_Windows_Temp_Dir.txt
}
# AppData Temp Directory Listing
$UserFolders = Get-Content $Destination\$Triage\Configuration\User_Folders.txt
foreach ($UserFolder in $UserFolders) {
    if (Test-Path(("C:\Users\$UserFolder\AppData\Local\Temp\"))) {
        Get-ChildItem -Force -Recurse ("C:\Users\$UserFolder\AppData\Local\Temp\*") | Format-Table Name, FullName, Length, CreationTimeUtc, LastWriteTimeUtc, LastAccessTimeUtc | Out-File $Destination\$Triage\FileSystem\C_Users_AppData_Temp_Dir_$UserFolder.txt
    }
}
# Downloads Directory Listing
$UserFolders = Get-Content $Destination\$Triage\Configuration\User_Folders.txt
foreach ($UserFolder in $UserFolders) {
    if (Test-Path(("C:\Users\$UserFolder\Downloads\"))) {
        Get-ChildItem -Force -Recurse ("C:\Users\$UserFolder\Downloads\*") | Format-Table Name, FullName, Length, CreationTimeUtc, LastWriteTimeUtc, LastAccessTimeUtc | Out-File $Destination\$Triage\FileSystem\C_Users_Downloads_Dir_$UserFolder.txt
    }
}
# Named Pipes
if ($PSVersionTable.PSVersion.Major -ge 5) {
    # More detail with PowerShell version >= 5
    Get-ChildItem -Path "\\.\pipe\" | Sort Length | Format-Table FullName, Length, IsReadOnly, Exists, CreationTime, LastWriteTime, LastAccessTime | Out-File $Destination\$Triage\FileSystem\Named_PIPES.txt
}
else {
    # Any other versions
    [System.IO.Directory]::GetFiles("\\.\pipe\") | Out-File $Destination\$Triage\FileSystem\Named_PIPES.txt
}

########## Operating System ##########

# Script Progress
$Activity8 = "Task / Aufgabe (8 / 10)"
$Id8 = 8
$Task8 = "Gather system information / Sammeln von Systeminformationen."
Write-Progress -Id $Id8 -Activity $Activity8 -Status $Task8

# Directory Structure
New-Item $Destination\$Triage\OS\Jumplists -ItemType Directory | Out-Null
New-Item $Destination\$Triage\OS\LNK -ItemType Directory | Out-Null
New-Item $Destination\$Triage\OS\Programs -ItemType Directory | Out-Null
New-Item $Destination\$Triage\OS\Programs\StartupFiles -ItemType Directory | Out-Null
New-Item $Destination\$Triage\OS\BITSAdmin -ItemType Directory | Out-Null
New-Item $Destination\$Triage\OS\RDPCache -ItemType Directory | Out-Null
New-Item $Destination\$Triage\OS\SRUM -ItemType Directory | Out-Null
New-Item $Destination\$Triage\OS\WinNotifications -ItemType Directory | Out-Null
New-Item $Destination\$Triage\OS\WinTimeline -ItemType Directory | Out-Null
New-Item $Destination\$Triage\OS\CryptnetURLCache -ItemType Directory | Out-Null
# Installed Programs
WMIC Product List Full /format:csv | Out-File $Destination\$Triage\OS\Programs\Installed_Programs.csv
# Startup Programs
Get-WmiObject -Class "Win32_startupCommand" | Select-Object -Property Name, Command, User, Location | Export-Csv $Destination\$Triage\OS\Programs\Startup_Programs.csv -NoTypeInformation
# Startup Files
Copy-Item C:\Windows\System32\WDI\LogFiles\StartupInfo\*.xml $Destination\$Triage\OS\Programs\StartupFiles
# Server Message Block (SMB) Sessions
if (Get-Command Get-SmbSession -ErrorAction SilentlyContinue){
    New-Item $Destination\$Triage\OS\SMB -ItemType Directory | Out-Null
    Get-SmbSession | Format-Table -AutoSize -Wrap | Out-File $Destination\$Triage\OS\SMB\SMB_Sessions.txt
}
# BITSAdmin Job Que
bitsadmin /list | Out-File $Destination\$Triage\OS\\BITSAdmin\BITSAdmin_Job_Que.txt
# RDP Cache
$UserFolders = Get-Content $Destination\$Triage\Configuration\User_Folders.txt
foreach ($UserFolder in $UserFolders)
{
    robocopy "C:\Users\$UserFolder\AppData\Local\Microsoft\Terminal Server Client\Cache" "$Destination\$Triage\OS\RDPCache\RDPCache-$UserFolder" *.bin /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\OS\RDPCache\RDPCache-$UserFolder.txt | Out-Null
    }
# System Resource Usage Monitor (SRUM)
Copy-Item C:\Windows\System32\sru\SRUDB.dat $Destination\$Triage\OS\SRUM
# Windows Notifications
$UserFolders = Get-Content $Destination\$Triage\Configuration\User_Folders.txt
foreach ($UserFolder in $UserFolders)
{
    robocopy "C:\Users\$UserFolder\AppData\Local\Microsoft\Windows\Notifications" "$Destination\$Triage\OS\WinNotifications\WinNotifications-$UserFolder" wpndatabase.* /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\OS\WinNotifications\WinNotifications-$UserFolder.txt | Out-Null
    robocopy "C:\Users\$UserFolder\AppData\Local\Microsoft\Windows\Notifications\wpnidm" "$Destination\$Triage\OS\WinNotifications\WinNotificationsPics-$UserFolder" *.jpg /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\OS\WinNotifications\WinNotificationsPics-$UserFolder.txt | Out-Null
}
# Prefetch
if (Test-Path C:\Windows\Prefetch)
{
    New-Item $Destination\$Triage\OS\Prefetch -ItemType Directory | Out-Null
    robocopy "C:\Windows\Prefetch" "$Destination\$Triage\OS\Prefetch\PF" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\OS\Prefetch\Prefetch.txt | Out-Null
}
# Recent File Cache
if (Test-Path C:\Windows\appcompat\Programs\RecentFileCache.bcf)
{
    New-Item $Destination\$Triage\OS\RecentFileCache -ItemType Directory | Out-Null
    esentutl /y /vss "C:\Windows\appcompat\Programs\RecentFileCache.bcf" /d "$Destination\$Triage\OS\RecentFileCache\RecentFileCache.bcf" | Out-Null
}
# Amcache
if (Test-Path C:\Windows\appcompat\Programs\Amcache.hve)
{
    New-Item $Destination\$Triage\OS\AppCompat -ItemType Directory | Out-Null
    esentutl /y /vss "C:\Windows\appcompat\Programs\Amcache.hve" /d "$Destination\$Triage\OS\AppCompat\Amcache.hve" | Out-Null
}
# Program Compatibility Assistant (PCA)
if (Test-Path C:\Windows\appcompat\pca)
{
    New-Item $Destination\$Triage\OS\PCA -ItemType Directory | Out-Null
    robocopy "C:\Windows\appcompat\pca" "$Destination\$Triage\OS\PCA\" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\Logs\PCA\PCA.txt | Out-Null
}
# LNK
$UserFolders = Get-Content $Destination\$Triage\Configuration\User_Folders.txt
foreach ($UserFolder in $UserFolders)
{
    robocopy "C:\Users\$UserFolder\AppData\Roaming\Microsoft\Windows\Recent" "$Destination\$Triage\OS\LNK\LNK-$UserFolder" *.lnk /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\OS\LNK\LNK-$UserFolder.txt | Out-Null
    }
# Jumplists
$UserFolders = Get-Content $Destination\$Triage\Configuration\User_Folders.txt
foreach ($UserFolder in $UserFolders)
{
    robocopy "C:\Users\$UserFolder\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" "$Destination\$Triage\OS\Jumplists\Jumplists-$UserFolder" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\OS\Jumplists\Jumplists-$UserFolder.txt | Out-Null
    robocopy "C:\Users\$UserFolder\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" "$Destination\$Triage\OS\Jumplists\Jumplists-$UserFolder" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\OS\Jumplists\Jumplists-$UserFolder.txt | Out-Null
    }
# Windows Timeline
$UserFolders = Get-Content $Destination\$Triage\Configuration\User_Folders.txt
foreach ($UserFolder in $UserFolders)
{
    robocopy "C:\Users\$UserFolder\AppData\Local\ConnectedDevicesPlatform" "$Destination\$Triage\OS\WinTimeline\WinTimeline-$UserFolder" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\OS\WinTimeline\WinTimline-$UserFolder.txt | Out-Null
    }

# Cryptnet URL Cache Metadata
$UserFolders = Get-Content $Destination\$Triage\Configuration\User_Folders.txt
foreach ($UserFolder in $UserFolders)
{
    robocopy "C:\Users\$UserFolder\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\" "$Destination\$Triage\OS\CryptnetURLCache\CryptnetMetaData-$UserFolder" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\OS\CryptnetURLCache\CryptnetMetaData_Folders_$UserFolder.txt | Out-Null
}
if (Test-Path C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData)
{
	robocopy "C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData" "$Destination\$Triage\OS\CryptnetURLCache\CryptnetMetaData-System32" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\OS\CryptnetURLCache\CryptnetMetaData_Folders_System32.txt | Out-Null
}
if (Test-Path C:\Windows\SysWOW64\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData)
{
	robocopy "C:\Windows\SysWOW64\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData" "$Destination\$Triage\OS\CryptnetURLCache\CryptnetMetaData-SysWOW64" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\OS\CryptnetURLCache\CryptnetMetaData_Folders_SysWOW64.txt | Out-Null
}

########## Internet ##########

# Script Progress
$Activity9 = "Task / Aufgabe (9 / 10)"
$Id9 = 9
$Task9 = "Gather internet information / Sammeln von Internet-Informationen."
Write-Progress -Id $Id9 -Activity $Activity9 -Status $Task9

# Directory Structure
New-Item $Destination\$Triage\Internet\Chrome -ItemType Directory | Out-Null
New-Item $Destination\$Triage\Internet\Firefox -ItemType Directory | Out-Null
New-Item $Destination\$Triage\Internet\IE -ItemType Directory | Out-Null
# Chrome
$UserFolders = Get-Content $Destination\$Triage\Configuration\User_Folders.txt
foreach ($UserFolder in $UserFolders)
{
    robocopy "C:\Users\$UserFolder\AppData\Local\Google\Chrome\User Data\Default" "$Destination\$Triage\Internet\Chrome\History-$UserFolder" History /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\Internet\Chrome\Chrome-$UserFolder.txt | Out-Null
    }
# Firefox
$UserFolders = Get-Content $Destination\$Triage\Configuration\User_Folders.txt
foreach ($UserFolder in $UserFolders)
{
    robocopy "C:\Users\$UserFolder\AppData\Roaming\Mozilla\Firefox\Profiles" "$Destination\$Triage\Internet\Firefox\places-$UserFolder" places.sqlite /s /ZB /TS /r:4 /w:3 /FP /NP /log+:$Destination\$Triage\Internet\Firefox\Firefox-$UserFolder.txt | Out-Null
    }
# IE
$UserFolders = Get-Content $Destination\$Triage\Configuration\User_Folders.txt
foreach ($UserFolder in $UserFolders)
{
    esentutl /y /vss "C:\Users\$UserFolder\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat" /d "$Destination\$Triage\Internet\IE\WebCacheV01.dat-$UserFolder" | Out-Null
    }

########## Organise Collection ##########

# Script Progress
$Activity10 = "Task / Aufgabe (10 / 10)"
$Id10 = 10
$Task10 = "Organise Collection / Sammlung organisieren."
Write-Progress -Id $Id10 -Activity $Activity10 -Status $Task10

# Hashing
Get-ChildItem $Destination\$Triage -Recurse | Where-Object {!$_.psiscontainer } | Get-FileHash -ErrorAction 0 -Algorithm MD5 | Format-List | Out-File $Destination\$Triage\Hashes.txt

Stop-Transcript | Out-Null

# Compress Archive
Get-ChildItem -Path $Destination\$Triage | Compress-Archive -DestinationPath $Destination\$Triage.zip -CompressionLevel Fastest

# Delete Folder
Get-ChildItem -Path "$Destination\$Triage\\*" -Recurse | Remove-Item -Force -Recurse
Remove-Item "$Destination\$Triage"

Write-Host "`nScript completed! / Skript abgeschlossen!" -ForegroundColor green -BackgroundColor black