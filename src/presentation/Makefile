all: vuln1 vuln2 vuln3

vuln1: vuln1.c
	gcc -m32 -o vuln1-nocanary-execstack -fno-stack-protector -zexecstack vuln1.c
	gcc -m32 -o vuln1-nocanary -fno-stack-protector vuln1.c
	gcc -m32 -o vuln1-execstack -zexecstack vuln1.c
	gcc -m32 -o vuln1-allprots vuln1.c

vuln2: vuln2.c
	gcc -m32 -o vuln2 -fno-stack-protector vuln2.c

vuln3: vuln3.c
	gcc -m32 -o vuln3 -fno-stack-protector vuln3.c

clean:
	rm vuln1-nocanary-execstack vuln1-nocanary vuln1-execstack vuln1-allprots vuln2 vuln3
