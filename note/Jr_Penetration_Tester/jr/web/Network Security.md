## Passive Reconnaissance
###  WHOIS 記錄 : whois 
		--> TCP port 43
		--> whois tryhackme.com(DOMAIN_NAME)
		
### DNS資料庫記錄 : nslookup 
		--> format :
			--> nslookup -type=A tryhackme.com 1.1.1.1 
			--> nslookup -type=a tryhackme.com 1.1.1.1 
			
		--> Query type : 
			--> A (ipv4) AAAA (ipv6)
			--> CNAME (Canonical Name)
			--> MX (Mail Servers)
			--> SOA (Start of Authority)
			--> TXT (TXT Records)
		--> Server : 
			--> https://duckduckgo.com/?q=public+dns&ia=answer
			--> Cloudflare 	: 1.1.1.1 | 1.0.0.1
			--> Google 	: 8.8.8.8 | 8.8.4.4
			--> Quad9	: 9.9.9.9 | 49.112.112.112

###  更進階的DNS查詢和附加功能 : Domain Information Groper (dig)
		--> format :
			--> dig @1.1.1.1 tryhackme.com MX
			--> dig thmlabs.com TXT
			
###  線上服務 : 
		--> DNSDumpster : check 子網域
			--> https://dnsdumpster.com/
		--> Shodan.io 	: 物聯網搜尋引擎 : check 客戶端網路的各種信息
			--> https://www.shodan.io/
			--> https://tryhackme.com/r/room/shodan
## Active Reconnaissance
	--> need to connect server : HTTP、FTP、SMTP
	--> social engineering
	
	--> Web 瀏覽器 : 
		--> port : HTTP (80) | HTTPS (443)
	--> 插件 : 
		--> FoxyProxy : 速變更用於存取目標網站的代理伺服器
			--> https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/
		--> User-Agent Switcher and Manager : 假裝從不同的作業系統或不同的 Web 瀏覽器存取網頁
			--> https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher/
		--> Wappalyzer : 提供有關所造訪網站所使用技術的見解
			--> https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/
	--> Ping : 斷定遠端系統已上線並且兩個系統之間的網路正在運作
		-->  ping -c 5 MACHINE_IP
	--> traceroute : 找出封包從您的系統到達目標主機時所經過的路由器或躍點的 IP 位址
		-->
	--> telnet
		--> port 23
		--> telnet MACHINE_IP 80
			--> GET / HTTP/1.1GET /page.html HTTP/1.1page.htmlhost: example
			--> GET / HTTP/1.1 host: telnet
	--> Netcat :  支援 TCP 和UDP協定 | 作為客戶端連接到監聽連接埠
		--> nc 10.10.191.164 80
			--> GET / HTTP/1.1 host: netcat
		--> nc ip -vnlp 1234
		--> option : -l 聆聽模式 | -n 無法透過DNS解析主機名 | -v 詳細輸出
			--> -vv 非常詳細 | -k 客戶端斷開連線後繼續監聽
			--> 小於 1024 的連接埠號碼需要 root 權限才能偵聽。
## Nmap 
	--> Live Host Discovery
		--> /16(255.255.0.0)  | /24 (255.255.255.0)
		--> -sL : 提供 Nmap 將掃描的主機的詳細列表 -- list ip
		--> sudo nmap -PR -sn ip/24 : 掃描本地網路（乙太網路）上的目標
			--> sn : 不想隨後進行連接埠掃描
			
		--> ARP (MAC位址)
			--> sudo arp-scan ip/24
			--> arp-scan -l。此命令將向本地網路上的所有有效 IP 位址發送ARP查詢
			--> sudo arp-scan -I eth0 -l將發送介面上所有有效 IP 位址的ARPeth0查詢
			
		--> ICMP 
			-->  sudo nmap -PE -sn 10.10.68.220/24
			--> -PE : ping (ICMP 類型 0) --> （ICMP 類型 8/Echo）
			--> -PP : 時間戳記（ICMP 類型 13） --> （ICMP 類型 14）
			--> -PM : 位址遮罩查詢（ICMP 類型 17） --> （ICMP 類型 18）
			
		--> TCP/UDP 
			--> -PS : TCP SYN Ping | -PS21 (port 21)
			--> -PA : TCP ACK ping | root
			--> -PU : UDP ping 
			
			--> Masscan masscan MACHINE_IP/24 -p443
		--> DNS 
			--> -R : 來查詢DNS伺服器
			--> --dns-servers DNS_SERVER  | 使用特定的DNS伺服器
			--> -n  : 不想將 Nmap 連接到DNS伺服器
###  Basic Port Scans
		--> TCP header: URG(緊急)| ACK(確認)| PSH(推送)| RST(重設)| SYN(同步)| FIN(發送)
		--> -sT : 執行TCP連線掃描 
		--> -F  : 啟用快速模式並將掃描連接埠的數量從 1000 個最常見連接埠減少到 100 個
		--> -r  : 以連續順序而不是隨機順序掃描連接埠
		--> -sS : 不需要完成TCP 3次握手
		--> -sU : ICMP packet of type 3, destination unreachable, and code 3, port unreachable
		--> -p- : 掃描所有 65535 個端口
		--> --top-ports 10 : 將檢查十個最常見的連接埠
		--> -T<0-5> : -T0是最慢的 |  -T5而是最快的
		--> --min-rate <number> :  來控制資料包速率
			--> --max-rate 10或--max-rate=10 
		--> --min-parallelism <numprobes> : 控制探測並行化
			--> --min-parallelism=512 : 推動Nmap保持至少512個探針並行
###  Advanced Port Scans
		--> 掃描無狀態（非狀態）防火牆後面的目標
			--> -sN : Null Scan 	-- 0 flags
			--> -sF : FIN Scan  	-- 1 flags (FIN)
			--> -sX : Xmas Scan 	-- 3 flags (DIN PSH URG)
			--> -sM : Uriel Maimon 	-- 2 flags (FIN/ACK <-- RST)
			--> -sA : ACK Scan 	-- 1 flags (ACK) | 更適合發現防火牆規則集和配置
			--> -sW : Window Scan   -- same to -sA
			--> Custom Scan : --scanflags RSTSYNFIN
			
		--> Spoofing and Decoys
			--> 欺騙性的 IP 位址  : 
				--> nmap -S SPOOFED_IP ip 
				--> nmap -S 10.10.10.11 : 使掃描看起來像是來自來源 IP 位址 10.10.10.11 
				--> nmap -e NET_INTERFACE -Pn -S SPOOFED_IP 10.10.157.59
				
			--> 欺騙性的 MAC 位址 : --spoof-mac SPOOFED_MAC
				--> nmap -D 10.10.0.1,10.10.0.2,ME 10.10.157.59
				--> -D 啟動誘餌掃描 | ME 指示您的 IP 位址應出現在第三個順序中
				--> -D 使掃描看起來像是來自來源 IP 位址
				
		--> Fragmented Packets
			--> Firewall 防火牆
			--> IDS 入侵偵測系統 -sN
			--> Fragmented Packets 
				--> -f : 對資料包進行分段 | double -ff
				
		--> Idle/Zombie Scan
			--> nmap -sI ZOMBIE_IP 10.10.157.59
			
		-->  other : 
			--> --reason : 系統已啟動或特定連接埠已開啟的明確原因
			--> -v /-vv  : 更詳細的輸出
			--> -d/-dd   : 調試詳細資訊
			
###  Post Port Scans
		--> -sV : 收集並確定開放連接埠的服務和版本資訊
			--> --version-intensity LEVEL (0) | --version-light (2)| -version-all(9)
		--> -O  : 偵測作業系統 ( OS )
			-->  nmap -sS -O 10.10.236.174
		--> --traceroute
			--> nmap -sS --traceroute 10.10.236.174
			
		--> Nmap Scripting Engine (NSE) :  Lua 解釋器
			--> /usr/share/nmap/scripts
				--> less file | grep description 
			--> 預設腳本 : --script=default / -sC
				--> sudo nmap -sS -sC 10.10.184.233
				--> type :	
					--> auth 	認證相關腳本
					--> broadcast	透過發送廣播訊息發現主機
					--> brute	對登入執行暴力密碼審核
					--> default	預設腳本，同-sC
					--> discovery	資料庫表和DNS名稱
					--> dos		偵測易受拒絕服務 ( DoS )攻擊的伺服器
					--> exploit	嘗試利用各種易受攻擊的服務
					--> external	使用第三方服務進行檢查，例如 Geoplugin 和 Virustotal
					--> fuzzer	發動模糊攻擊
					--> intrusive	暴力攻擊和利用等侵入性腳本
					--> malware	掃描後門
					--> safe	不會使目標崩潰的安全腳本
					--> version	檢索服務版本
					--> vuln	檢查漏洞或利用易受攻擊的服務
			--> --script "SCRIPT-NAME" :
				--> --script "ftp*"
				--> --script "http-date"
				--> sudo namp --script "ssh2-enum-algos" 10.10.184.233
			--> save file 
				--> -oN FILENAME (N:normal)  .nmap
				--> -oG FILENAME (G:grepabl) .gnmap
				--> -oX FILENAME (X:XML)
				--> -oA FILENAME (A:ALL) (N/G/X)
				--> -oS FILENAME (S:script)  .kiddie 
				
			--> get file :
				--> sudo scp pentester@10.10.184.32:/home/pentester/* .

## Protocols and Servers 
###  遠端登入 (telnet) :  port 23
		--> telnet 10.10.67.180 / need username password 
			<-- Wireshark cut 流量 <-- find username password 
		--> host: telnet // enter 2 
###  超文本傳輸協定 (HTTP) : port 80
		--> telnet ip 80
		--> http : GET /index.html HTTP/1.1 host: telnet
###  文件傳輸協定 (FTP) : port 21
		--> telnet ip 21
		--> command :
			--> STAT	可以提供一些附加資訊
			--> SYST	指令顯示目標的系統類型
			--> PASV  	將模式切換為被動
			--> TYPE A 	將檔案傳輸模式切換為ASCII
			--> TYPE I	檔案傳輸模式切換為二進位
			
			--> username => password => SYST => TYPE A => STAT => QUIT
		--> ftp 10.10.67.180
			--> using normal command like ls
				--> ascii --> ASCII 
				--> get file --> exit 
				
###  簡單郵件傳輸協定 (SMTP) : port 25
		--> telnet 10.10.67.180 25
		--> helo telnet => mail from: 寄件人 => rcpt to 收件人 => data 輸入訊息
		
### 郵局協議 3 (POP3) : port 110
		--> telnet 10.10.67.180 110
		--> USER => PASS => STAT => LIST  => RETR 1
		
###  網際網路訊息存取協定 (IMAP) : port 143
		--> telnet 10.10.67.180 143
		--> c1 LOGIN frank D2xc9CgD
		--> c2 LIST "" "*" 列出郵件資料夾
		--> c3 EXAMINE INBOX 來檢查收件匣中是否有新郵件
		--> c4 LOGOUT
### Other
	--> 傳輸層安全性 (TLS) = SSL 
		--> 使用 SSL/TLS 加密 => 升級HTTP、FTP、SMTP、 POP3 和IMAP
		--> HTTPS 443 | FTPS 990 | SMTPS 465 | POP3S 995 | IMAPS 993
		--> 提供來自受信任證書頒發機構的簽章證書
		
	--> 安全殼 (SSH) : 提供一種安全的遠端系統管理方式
		--> 私鑰和公鑰 
		--> ssh username@10.10.126.186
		--> scp mark@10.10.126.186:/home/mark/archive.tar.gz ~ (down)
			--> scp mark@10.10.126.186:/home/mark/book.txt ~
		--> scp backup.tar.bz2 mark@10.10.126.186:/home/mark/ (up)
	
	--> Sniffing Attack (Network Packet Capture) 利用網路抓包工具來收集目標的資訊
		--> Tcpdump / Wireshark / Tshark
			--> sudo tcpdump port 110 -A | 使用 Tcpdump 嘗試捕獲使用者名稱和密碼 pop3 | ASCII 
		
	--> Man-in-the-Middle (MITM) Attack
		--> ETTERCAP : https://www.ettercap-project.org/
		--> bettercap : https://www.bettercap.org/
		
### Password Attack (Authentication Attack)
		--> 單字表 : /usr/share/wordlists/rockyou.txt
		-->  hydra -l username -P wordlist.txt server (IP 位址) service (發動字典攻擊)
			--> hydra -l mark -P /usr/share/wordlists/rockyou.txt 10.10.126.186 ftp
			--> hydra -l mark -P /usr/share/wordlists/rockyou.txt ftp://10.10.126.186
			--> hydra -l frank -P /usr/share/wordlists/rockyou.txt 10.10.126.186 ssh
			--> -s PORT 非預設連接埠 | -V或者-vV 詳細信息 | -t n 平行連接數。| -d 調試
			--> hydra -l lazie -P /usr/share/wordlists/rockyou.txt 10.10.126.186 imap
		--> hydra -l eddie -P /usr/share/wordlists/rockyou.txt ftp://10.10.123.96:10021 
## Network Security Challenge
	--> sudo nmap -sS -T5 10.10.123.96 
	--> highest port under 10000 : -p1-10000 
	--> common above 10,000 : -p- 
	--> How many TCP ports are open : -sT
	--> HTTP server header: 
		--> sudo nmap -sC -sV 10.10.123.96 -p80
		--> sudo namp -sV --script=http-headers -p80
	--> SSH server header : sudo nmap -sC -sV  10.10.123.96 -p22
	--> version of the FTP server : -sV
	
	--> ftp 10.10.123.96:10021 
	--> hydra -l eddie -P /usr/share/wordlists/rockyou.txt ftp://10.10.123.96:10021
		--> login:eddie   password: jordan
	--> hydra -l quinn -P /usr/share/wordlists/rockyou.txt ftp://10.10.123.96:10021
		--> login: quinn   password: andrea
	
	--> avoid being detected by the IDS
		--> 減速 : 
			--> --max-parallelism--min-rtt-timeout--scan-delay
			--> -T paranoid 選項使 Nmap 一次只發送一個探測 
			--> -T sneaky 探測之間僅等待 15 秒
			--> --scan-delay 1075ms
		--> 分片資料包 : 
			--> -f | -ff
		--> 跨網路分散探測，而不是連續掃描主機
			--> 10.0.0.2、.3、.4 和 .5 類似的資料包 
			--> -D 10.10.0.1,10.10.0.2,ME 10.10.157.59
		--> -sN NULL 
			

	
	
	
	

