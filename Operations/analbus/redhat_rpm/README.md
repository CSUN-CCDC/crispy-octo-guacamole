Role Name
=========
This role will install << Software name >> on << Supported operating systems >> machines.

Requirements
------------

Within the directory that you run ansible from create 2 directories: group_vars\ and roles\

  group_vars:
  -----------
  Holds global variables for the operating systems of the servers.

  Example:
 
  group_vars/redhatservers/vars.yml
  ---
    # Ansible Variables
    ansible_port: 12422
    ansible_connection: ssh
    ansible_user: admin
    host_key_checking: false
    # Host Variables
    # url_username and url_password are defined in vault.yml
 
  group_vars/windowsservers/vars.yml
  ---
    ansible_port: 5985
    ansible_connection: winrm
    ansible_user: Administrator
    win_become_user: Administrator
 
    # Host Variables
    # url_username and url_password are defined in vault.yml

  roles:
  ------
  Holds the entire directory tree of desired roles

  Vault
  ---
  If using vault to store passwords, use "--ask-vault-pass" so that Ansible can decrypt the vault and access the passwords

Role Variables
--------------

Variables in defaults/main.yml should remain untouched. Variable changes should occur in the global variables for the Operating System as follows.

Linux:
- url_username
- url_password (DO NOT STORE IN PLAINTEXT)
- ansible_become_password (DO NOT STORE IN PLAINTEXT)
** Role assumes logged in user has sudo privilege. If not, define become_user as a user with Sudo permission **

Windows:
- url_username
- url_password (DO NOT STORE IN PLAINTEXT)
- win_become_user

Dependencies
------------
<< List all dependencies >>

Example Playbook
----------------

    ---
    - name: Example Playbook
      hosts: all
      tasks:

        - name: Show OS
          debug:
            msg: "OS Distribution is: {{ ansible_facts['distribution'] }}"

        - name: Show OS Family
          debug:
            msg: "OS family is: {{ ansible_os_family }}"

      roles:
        - yum-installs
        - << Dependencies >>
        - << software >>


License
-------

 
Author Information
------------------
 
Maintained by lsassy.exe
