# Dependency_guard
CLI tool to create, install and update dependencies from npm (and others) in a safely way.

Automatically creates docker containers each project.

**Requirements:**
- Use a Debian based distro
- Install Docker: https://docs.docker.com/engine/install/debian/


**Important:** This tool is supposed to create a secure development environment, not a production environment. 


Production environments should have stricter restrictions such as "read-only filesystem", (is possible), very detailed AppArmor restricted profiles, permissions, different users/groups, etc.


With this project, the goal is to create a usable and secure balance. It's important to note that the main problem we aim to solve is supply chain attacks, that is, preventing **malware files** from package repositories from entering the developer's machine.

And since this tool use Docker, this creates other problems such as:

> Where will the project's code files be located? (in the container? on the host machine?)

> Where will the Git files be located? (in the container? on the host machine?)

> "Can I open the code files in my text editor if they are in the container?"
Yes in vscode with: `code --folder-uri vscode-remote://attached-container+<container_id>/workspace`

### The solution:

...Working on it

## Recommended steps:

**Donload project and Run:**

- Docker must be installed

```
sudo usermod -aG docker $USER
```
- avoid the need for `sudo` to run the program

<br>

```
cd Dependency_guard
```

Install app armor profiles:
```
chmod +x setup_apparmor.sh
```

```
sudo ./setup_apparmor.sh
```

<br>

Compile:
```
go build
```

<br>

Add a link for the binary it works like a system command (just for you user):
```
ln -s ~/Dependency_guard/Dependency_guard ~/.local/bin/safe-env
```

or for all users:
```
sudo ln -s ~/Dependency_guard/Dependency_guard /usr/local/bin/safe-env
```
- **Note:** This option is better in some cases like for the lockdown network command.


<br>


Add to .bashrc file:
```
export PATH="$HOME/.local/bin:$PATH"
```

<br>

# Progress


| Feature                         | State |
| ------------------------------- | :---: |
| stable apparmor profile         |   ❌   |
| user and perms in the container |   ✅   |
| eBPF                            |   ❌   |
| Network lockdown                |  ✅  |
| analyze libs                    |  90%  |
| install libs                    |   ✅   |


