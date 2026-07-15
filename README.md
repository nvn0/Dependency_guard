# Dependency_guard
CLI tool to create isolated environments for projects and install/update dependencies from npm (and others) in a safely way.




<!-- 
Yes the Icon is AI generated 
-->

![icon](https://raw.githubusercontent.com/nvn0/tech-icons/refs/heads/main/Dependency_Guard/dependency_guard_icon_transparenteV3.png)


- Automatically creates docker containers for each project.

- Before every package/lib install/update an analysis is performed to provide useful information to the user, who then decides whether or not to proceed.

- The install/update command also applies a minimum age requirement of 24 hours for a package after it was published.

<br>

**Requirements:**
- Use a Debian based distro (Because of AppArmor, Red Hat based distros use SELinux, in Arch it can be installed)
- Install Docker: https://docs.docker.com/engine/install/debian/


**Important:** This tool is supposed to create a secure development environment, not a production environment. 


Production environments should have stricter restrictions such as "read-only filesystem", (if possible), very detailed AppArmor restricted profiles, permissions, different users/groups, etc.


With this project, the goal is to create a usable and secure balance. It's important to note that the main problem we aim to solve is supply chain attacks, that is, preventing **malware files** from package repositories from entering the developer's machine.

And since this tool use Docker, this creates other problems such as:

> Where will the project's code files be located? (in the container? on the host machine?)

A: In the Container.

> Where will the Git files be located? (in the container? on the host machine?)

A: In the Container.

> "Can I open the code files in my text editor if they are in the container?"

A: Yes in vscode with: `code --folder-uri vscode-remote://attached-container+<container_id>/workspace`





## Recommended steps:

**Download project and Run:**

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

<br>


Add to .bashrc file:
```
export PATH="$HOME/.local/bin:$PATH"
```

<br>

or for all users:
```
sudo ln -s ~/Dependency_guard/Dependency_guard /usr/local/bin/safe-env
```
- **Note:** This option is better in some cases like for the lockdown network command.


<br>



# How to use:

Help command: (lists all the commands)
```
safe-env help
```

Output:
```
usage:
 safe-env init <env-type> <project name>
 safe-env install <project name> <library name>
 safe-env update <project name> <library name>
 safe-env update <project name> all
 safe-env analyze <project name> <library name>
 safe-env show <project name> packages
 safe-env start <project name>
 safe-env stop <project name>
 sudo safe-env lockdown network <on/off>
 safe-env connect <project name>
 sudo safe-env monitor <project name>
 sudo safe-env enforce <project name>
 safe-env list
 safe-env help
```
- Each command syntax attempts to be as simple and straightforward as possible.

<br>

Create new project:
```
safe-env init node project1
```
- Creates a new hardened Docker container for a Node Js project.

- Now o can use the start command: `safe-env start <project name>`

- Install packages/libs with: `safe-env install <project name> <library name>` ex: `safe-env install project1 express` 

- Or connect to the container with: `safe-env connect <project name>`


**Note**: After creating a container, you cannot install other programs via APT. You can modify the project's Docker files, which are used to generate the container images, and for example, add new tools like text editors.

<br>

# Progress


| Feature                         | State |
| ------------------------------- | :---: |
| stable apparmor profile         |   ✅   |
| user and perms in the container |   ✅   |
| eBPF                            |   ✅   |
| Network lockdown                |  ✅  |
| analyze libs                    |  ✅  |
| install libs                    |   ✅   |


