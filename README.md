# Incident-handling-with-Splunk
- Learn to use Splunk for incident handling through interactive scenarios.
- Investigate the cyber attack and map the attacker's activities into all 7 of the Cyber Kill Chain Phases.

Link to exercise: https://tryhackme.com/r/room/splunk201

Search Query: index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype=suricata

Search Query Explanation: This query will show the logs from the suricata log source that are detected/generated from the source IP 40.80.248.42

## Reconnaissance Phase:

	Questions:
	1. One suricata alert highlighted the CVE value associated with the attack attempt. What is the CVE value?
	
	Query: index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype="suricata" src_ip="40.80.148.42"
![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/ba426df9-8c0f-4d47-acc1-39bffd6712a4)

Answer: CVE-2014-6271
	
	2. What is the CMS our web server is using?

![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/87a2c0c8-f496-4b91-a5d7-2df95ec23141)

Answer: joomla
	
	3. What is the web scanner, the attacker used to perform the scanning attempts?
	
![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/87e3c7b3-bbe1-4e0a-a39a-deb3cdf9b577)

Answer: ACUNETIX
	
	4. What is the IP address of the server imreallynotbatman.com?

![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/7c1a3278-0edb-4801-b823-92e14e42da92)
	
Answer: 192.168.250.70
	
## Exploitation Phase:
	
	1. What was the URI which got multiple brute force attempts?
	
	Query: index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method = POST
![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/80749116-5520-4b20-be1b-439d140a8e01)

Answer: /joomla/administrator/index.php
	
	2. Against which username was the brute force attempt made?

	Query: index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method = POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data

![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/c88308c8-6585-4fc2-957e-a6332f358b6b)

Answer: Admin
	

	3. What was the correct password for admin access to the content management system running imreallynotbatman.com?
	
	Query: index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" |table _time src_ip uri http_user_agent creds src_headers

![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/b0e6ab8a-a2a8-42d2-981c-ab7f996cf7e0)

Answer: batman
	
	4. How many unique passwords were attempted in the brute force attempt?
	
	Query: index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" |stats count(creds) as unique_password by src_ip
	
![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/43ad8b79-a561-4185-8b50-5af8d319f05e)

Answer: 412
	
	5. What IP address is likely attempting a brute force password attack against imreallynotbatman.com?
Answer:  23.22.63.113 (see screenshot in #4)
	
	6. After finding the correct password, which IP did the attacker use to log in to the admin panel?
Answer: 40.80.148.42 (see screenshot in #3)
	
## Installation Phase:
	1. Sysmon also collects the Hash value of the processes being created. What is the MD5 HASH of the program 3791.exe?

	Query: index=botsv1 "3791.exe" sourcetype=xmlwineventlog EventCode=1 CommandLine="3791.exe"
![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/40303a99-8a03-459f-9a44-f854a4148db6)
	
Answer: AAE3F5A29935E6ABCC2C2754D12A9AF0
	
	2. Looking at the logs, which user executed the program 3791.exe on the server?
	
![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/0ef5ed4e-6c4b-489b-ae1c-a7ccec0beecf)
	
Answer: NT AUTHORITY\IUSR
	
	3. Search hash on the virustotal. What other name is associated with this file 3791.exe?
![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/5f5d7140-af87-4f57-8bc6-fcfd6588b165)

Answer: ab.exe
	
## Action on Objective:
	
	1. What is the name of the file that defaced the imreallynotbatman.com website ?
	
	Query1: index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114
	Query2: index=botsv1 url="/poisonivy-is-coming-for-you-batman.jpeg" dest_ip="192.168.250.70" | table _time src dest_ip http.hostname url
![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/77b5e7e4-5e54-486b-8e6d-fde047551a14)

![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/7a7f40b6-c863-45e3-98cc-253a5868a1fe)

Answer: poisonivy-is-coming-for-you-batman.jpeg
	
	2. Fortigate Firewall 'fortigate_utm' detected SQL attempt from the attacker's IP 40.80.148.42. What is the name of the rule that was triggered during the SQL Injection attempt?
	
![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/a9ada885-478f-4018-a052-a855c9f47061)

Answer: HTTP.URI.SQL.Injection
	
## Command and Control:
	
	1. This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?
	Query:
	index=botsv1 sourcetype=fortigate_utm"poisonivy-is-coming-for-you-batman.jpeg"
![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/8f098e3f-32c6-4eea-aa50-6788428d4fa7)

Answer: prankglassinebracket.jumpingcrab.com

## Weaponization:

	1. What IP address has P01s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?
	
![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/051272e4-a066-4059-ad68-1abf26bc2e7c)

Answer:23.22.63.114

	2. Based on the data gathered from this attack and common open-source intelligence sources for domain names, what is the email address that is most likely associated with the P01s0n1vy APT group?
	Search for the suspicious domains at https://otx.alienvault.com
	
	
Answer: lillian.rose@po1s0nvy.com
	
	
## Delivery:
	
	1. What is the HASH of the Malware associated with the APT group?
Go to threat miner and search the IP address 23.22.63.114

https://www.threatminer.org/host.php?q=23.22.63.114#gsc.tab=0&gsc.q=23.22.63.114&gsc.page=1
	
![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/5b26dcfd-f716-461e-a379-71f96c7cd805)

Answer:c99131e0169171935c5ac32615ed6261
	
	2. What is the name of the Malware associated with the Poison Ivy Infrastructure?
Go to Virus Total and search using file hash. 

![image](https://github.com/jli149/Incident-handling-with-Splunk/assets/52467584/e2c8e468-71d9-413b-b2ec-f53731cf4c07)

Answer: MirandaTateScreensaver.scr.exe
