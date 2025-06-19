#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# quick script for installing tap
#
##
import base64
import getpass
import os
import pexpect
import re
import shutil
import stat
import subprocess
import sys

from Cryptodome.Cipher import AES
from pathlib import Path

from src.core.tapcore import motd
from src.core.tapcore import set_background
from src.core.tapcore import ssh_keygen

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
END = "\033[0m"


def kill_tap():
    proc = subprocess.Popen("ps -au | grep tap", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    for line in proc.stdout:
        try:
            match = re.search("tap.py", line)
            if match:
                print("[*] Killing running version of TAP..")
                line = line.split(" ")
                pid = line[6]
                subprocess.Popen(f"kill {pid}", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
                print(f"[*] Killed the TAP process: {pid}")

        except: pass

        try:
            # kill the heartbeat health check
            match = re.search("heartbeat.py", line)
            if match:
                print("[*] Killing running version of TAP HEARTBEAT..")
                line = line.split(" ")
                pid = line[6]
                subprocess.Popen(f"kill {pid}", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
                print(f"[*] Killed the Heartbeat TAP process: {pid}")
        except: pass

# here we encrypt via aes, will return encrypted string based on secret key which is random
def encryptAES(data):
    # the character used for padding--with a block cipher such as AES, the value
    # you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
    # used to ensure that your value is always a multiple of BLOCK_SIZE
    PADDING = '{'
    BLOCK_SIZE = 32
    # one-liner to sufficiently pad the text to be encrypted
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    # random value here to randomize builds
    a = 50 * 5
    # one-liners to encrypt/encode and decrypt/decode a string
    # encrypt with AES, encode with base64
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
    secret = os.urandom(BLOCK_SIZE)
    cipher = AES.new(secret)
    secret = base64.b64encode(secret)
    aes = EncodeAES(cipher, data)
    return aes.decode("utf-8") + "::::" + secret.decode("utf-8")

print (r"""
                                                                      
TTTTTTTTTTTTTTTTTTTTTTT         AAA               PPPPPPPPPPPPPPPPP   
T:::::::::::::::::::::T        A:::A              P::::::::::::::::P  
T:::::::::::::::::::::T       A:::::A             P::::::PPPPPP:::::P 
T:::::TT:::::::TT:::::T      A:::::::A            PP:::::P     P:::::P
TTTTTT  T:::::T  TTTTTT     A:::::::::A             P::::P     P:::::P
        T:::::T            A:::::A:::::A            P::::P     P:::::P
        T:::::T           A:::::A A:::::A           P::::PPPPPP:::::P 
        T:::::T          A:::::A   A:::::A          P:::::::::::::PP  
        T:::::T         A:::::A     A:::::A         P::::PPPPPPPPP    
        T:::::T        A:::::AAAAAAAAA:::::A        P::::P            
        T:::::T       A:::::::::::::::::::::A       P::::P            
        T:::::T      A:::::AAAAAAAAAAAAA:::::A      P::::P            
      TT:::::::TT   A:::::A             A:::::A   PP::::::PP          
      T:::::::::T  A:::::A               A:::::A  P::::::::P          
      T:::::::::T A:::::A                 A:::::A P::::::::P          
      TTTTTTTTTTTAAAAAAA                   AAAAAAAPPPPPPPPPP          
                                                                    
        The TrustedSec Attack Platform
        Written by: Dave Kennedy (@HackingDave)

        https://github.com/trustedsec/tap

       The self contained-deployable penetration testing kit
""")

print(""" 
Welcome to the TAP installer. TAP is a remote connection setup tool that will install a remote
pentest platform for you and automatically reverse SSH out back to home.
 """)

def install_ptf():
    """Install PTF and its modules."""
    try:
        print("[*] Installing PenTesters Framework...")
        
        if not os.path.isdir("/pentest"):
            os.makedirs("/pentest")
        
        if not os.path.isdir("/pentest/ptf"):
            subprocess.run([
                "git", "clone", 
                "https://github.com/trustedsec/ptf.git", 
                "/pentest/ptf"
            ], check=True)
        
        print("[*] Installing PTF modules...")
        os.chdir("/pentest/ptf")
        
        child = pexpect.spawn("python ptf")
        child.expect("ptf")
        child.sendline("use modules/install_update_all")
        child.interact()
        
    except Exception as e:
        print(f"{YELLOW}[!] PTF installation failed: {e}{END}")
        print("[*] You can install PTF manually later.")


def offer_ptf_installation():
    """Offer to install PTF (PenTesters Framework)."""
    print("[*] PTF Installation Option:")
    ptf = input("Do you want to install PTF and all modules now? [y/n]: ")
    
    if ptf.lower() in ["yes", "y"]:
        install_ptf()
    else:
        print("[*] You can install PTF later from: https://github.com/trustedsec/ptf")


def configure_ssh_server():
    """Configure SSH server settings."""
    print(f"{YELLOW}[*] Configuring SSH server...{END}")
    
    try:
        # Backup original config
        shutil.copy("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.backup")
        
        # Read and modify SSH config
        with open("/etc/ssh/sshd_config", "r") as f:
            data = f.read()
        
        # Enable root login
        data = data.replace("PermitRootLogin without-password", "PermitRootLogin yes")
        
        with open("/etc/ssh/sshd_config", "w") as f:
            f.write(data)
        
        # Restart SSH service
        subprocess.run(["service", "ssh", "restart"], check=True)
        print(f"{GREEN}[*] SSH server configured successfully.{END}")
        
    except (IOError, subprocess.CalledProcessError) as e:
        print(f"{YELLOW}[!] Warning: Failed to configure SSH server: {e}{END}")


def install_proxychains():
    """Install proxychains-ng for SOCKS5 proxy support."""
    print(f"{YELLOW}[*] Installing proxychains-ng for SOCKS5 proxy support...{END}")
    
    try:
        subprocess.run([
            "git", "clone", 
            "https://github.com/rofl0r/proxychains-ng", "proxy"
        ], check=True)
        
        os.chdir("proxy")
        subprocess.run(["./configure"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["make", "--silent"], check=True)
        subprocess.run(["make", "install", "--silent"], check=True)
        
        os.chdir("..")
        shutil.rmtree("proxy")
        
        print(f"{GREEN}[*] Proxychains-ng installed successfully.{END}")
        
    except (subprocess.CalledProcessError, OSError) as e:
        print(f"{YELLOW}[!] Warning: Failed to install proxychains-ng: {e}{END}")


def configure_ssh_connection():
    """Configure SSH connection settings for TAP."""
    
    print(f"\n{YELLOW}=== SSH Connection Configuration ==={END}")
    print("[*] Next we need to configure the remote SSH server you will want to tunnel over.")
    print("[*] This is the main remote SSH server you have running on the Internet that TAP will call back to.")
    
    print(f"\n{YELLOW}Authentication Method Selection:{END}")
    print("We need to figure out which method you want to use:")
    print("  1. SSH Keys (RECOMMENDED) - Generate or use existing SSH key pair")
    print("     This will generate a pub/priv key pair and upload to the remote server")
    print("  2. Password - Use username/password authentication")
    print("     Password is encrypted with AES but keys are stored locally")
    
    # Get authentication method choice with validation
    while True:
        choice1 = input("\nChoice 1: Use SSH keys, Choice 2: Use password (1,2) [1]: ").strip()
        if choice1 in ["1", "2", ""]:
            break
        print(f"{RED}[!] Invalid choice. Please enter 1 or 2.{END}")
    
    # Set authentication method
    auth_method = "ssh_keys" if choice1 in ["1", ""] else "password"
    password = ""
    
    print(f"\n{GREEN}[*] Selected authentication method: {auth_method.replace('_', ' ').title()}{END}")

    # Handle SSH key authentication
    if auth_method == "ssh_keys":
        print(f"\n{YELLOW}SSH Key Configuration:{END}")
        print("  1. Use existing SSH keys")
        print("  2. Create new SSH keys")
        
        # Get SSH key choice with validation
        while True:
            keys_choice = input("\nChoice (1,2) [2]: ").strip()
            if keys_choice in ["1", "2", ""]:
                break
            print(f"{RED}[!] Invalid choice. Please enter 1 or 2.{END}")
        
        if keys_choice == "1":
            _handle_existing_ssh_keys()
        else:
            print(f"\n{GREEN}[*] SSH Key generation selected. Beginning the process now...{END}")
            password = ""  # No passphrase for now
            try:
                ssh_keygen(password)
                print(f"{GREEN}[*] SSH keys generated successfully.{END}")
            except Exception as e:
                print(f"{RED}[!] Failed to generate SSH keys: {e}{END}")
                raise

    # Handle password authentication  
    elif auth_method == "password":
        print(f"\n{YELLOW}Password Authentication Configuration:{END}")
        print(f"{YELLOW}[!] WARNING: SSH keys are strongly recommended over password authentication.{END}")
        print("[*] This will ask for a username on the REMOTE system (root not recommended)")
        print("The username and password are for the REMOTE system exposed on the Internet.")
        print("ROOT access is NOT needed - this is a simple SSH tunnel.")
        print("Recommend using a restricted account in case this box gets compromised.")
        
        # Get username with validation
        while True:
            username = input("\nEnter username for SSH [root]: ").strip()
            if username == "":
                username = "root"
            if username:
                break
            print(f"{RED}[!] Username cannot be empty.{END}")
        
        # Get password
        while True:
            password = getpass.getpass(f"Enter password for {username}: ")
            if password:
                break
            print(f"{RED}[!] Password cannot be empty.{END}")
        
        print(f"{GREEN}[*] Password authentication configured for user: {username}{END}")

    # Handle password encryption if needed
    if password:
        print("[*] Encrypting the password...")
        try:
            encrypted_password = encryptAES(password)
            password_parts = encrypted_password.split("::::")
            password = password_parts[0]
            key = password_parts[1]

            # Ensure TAP directory exists
            tap_dir = Path("/root/.tap")
            tap_dir.mkdir(mode=0o700, exist_ok=True)
            
            # Store the encryption key securely
            key_file = tap_dir / "store"
            key_file.write_text(key)
            key_file.chmod(0o600)
            
            print(f"{GREEN}[*] Password encrypted and stored securely.{END}")
            
        except Exception as e:
            print(f"{RED}[!] Failed to encrypt password: {e}{END}")
            raise

    print(f"\n{YELLOW}=== Remote Server Configuration ==={END}")
    print(f"{YELLOW}[!] WARNING:{END} When specifying hostname, ensure the remote TAP device has DNS resolution.")
    print("    Otherwise, use an IP address to avoid connection failures.")
    
    print(f"\n{YELLOW}Remote SSH Server Details:{END}")
    host = input("Enter the remote IP or hostname for SSH connection: ")
    port = input("Enter the SSH port for reverse connection [22]: ")
    if port == "": port = "22"
    
    print(f"\n{YELLOW}Port Configuration:{END}")
    print("The following ports will be created on the REMOTE server for accessing TAP:")
    print("• Local Port: Used to SSH into the TAP device via the remote server")
    print("  Example: ssh user@remote-server, then ssh username@localhost -p <local_port>")
    print("• SOCKS Port: Used for HTTP proxy tunneling through the SSH connection")
    
    localport = input("\nEnter the LOCAL port for SSH access on remote server [10003]: ")
    socks = input("Enter the SOCKS proxy port on remote server [10004]: ")
    if localport == "": localport = "10003"
    if socks == "": socks = "10004"
    
    print(f"\n{YELLOW}Remote Command Execution (Optional):{END}")
    print("You can specify a URL containing commands to execute remotely.")
    print("This provides a backup method if reverse SSH access fails.")
    print("Place commands in a text file at the specified URL.")
    
    commands = input("\nEnter URL for remote commands (optional): ")
    if commands == "": 
        print(f"{YELLOW}[!] No command server specified - remote command execution disabled.{END}")
    
    print(f"\n{GREEN}[*] Configuration collection complete. Proceeding with setup...{END}")

    # determine if SSH keys are in use 
    if auth_method == "ssh_keys":
        ssh_keys = "ON"
        installed = input("[*] Has the SSH Public Key already been installed on the remote server (y/N) [N]?")
        if installed.lower() == 'y':
            username = input("Enter the username for the REMOTE account to log into the EXTERNAL server: ")
            if username == "": username = "root"
            child = pexpect.spawn("ssh %s@%s -p %s" % (username,host,port))
            i = child.expect(['The authenticity of host', 'password', 'Connection refused', 'Permission denied, please try again.', 'Last login:'])
            if i < 4:
                print("[*] Error: Could not connect to remote server. Either the SSH Key is incorrectly configured or no SSH Key has been configured")
                sys.exit()
            if i == 4:
                print("[*] Successfully logged into the system, good to go from here!")
        else:
            print(f"\n{YELLOW}[*] SSH Key Upload Required{END}")
            print("We need to upload the public key to the remote server.")
            print("You'll be prompted for the remote server password (one time only).")
            
            # clearing known hosts
            if os.path.isfile("/root/.ssh/known_hosts"):
                print("[*] Removing old known_hosts files...")                    
                os.remove("/root/.ssh/known_hosts")

            # pull public key into memory
            fileopen = open("/root/.ssh/id_rsa.pub", "r")
            pub = fileopen.read()
            
            # spawn pexpect to add key
            print(f"\n{YELLOW}[*] Initiating SSH Key Upload Process{END}")
            print("The following prompts are for the REMOTE server credentials:")
            print("• This is your external server exposed on the Internet")
            print("• This is a one-time setup to enable SSH key authentication")
            print("• After this, TAP will use SSH keys for all connections")
            username = input("Enter the username for the REMOTE account to log into the EXTERNAL server: ")
            if username == "": username = "root"
            child = pexpect.spawn("ssh %s@%s -p %s" % (username,host,port))
            password_onetime = getpass.getpass("Enter your password for the remote SSH server: ")
            i = child.expect(['The authenticity of host', 'password', 'Connection refused'])
            if i == 0:
                child.sendline("yes")
                child.expect("password")
                child.sendline(password_onetime)

            if i == 1:
                child.sendline(password_onetime)

            if i == 2:
                print(f"{RED}[!] Connection refused - cannot connect to remote server.{END}")
                print("Please verify the hostname/IP and port, then try again.")
                sys.exit()

            # here we need to verify that we actually log in with the right password
            i = child.expect(['Permission denied, please try again.', 'Last login:'])
            if i == 0:
                print(f"{RED}[!] Authentication failed - incorrect password.{END}")
                password_onetime = getpass.getpass("Please try again. Enter your SSH password: ")
                child.sendline(password_onetime)
                # second attempt
                i = child.expect(['Permission denied, please try again.'])
                if i == 0:
                    print(f"{RED}[!] Authentication failed again.{END}")
                    print("Please verify your credentials and run setup again.")
                    print("[!] Exiting TAP setup...")
                    sys.exit()
                # successfully logged in
                else:
                    print(f"{GREEN}[*] Successfully authenticated and logged in!{END}")

            if i == 1:
                print(f"{GREEN}[*] Successfully authenticated and logged in!{END}")

            # Add SSH key to remote server's authorized_keys
            print(f"\n{YELLOW}[*] Adding SSH key to remote server...{END}")
            fileopen = open("/etc/hostname", "r")
            hostname = fileopen.read().strip()
            
            # Add SSH key with proper formatting and comments
            child.sendline("echo '' >> ~/.ssh/authorized_keys")
            child.sendline("echo '# TAP box for hostname: %s' >> ~/.ssh/authorized_keys" % (hostname))
            child.sendline("echo '%s' >> ~/.ssh/authorized_keys" % (pub.strip()))
            
            print(f"{GREEN}[*] SSH key successfully added to remote server{END}")
            print(f"    Local hostname: {hostname}")
            print(f"    Remote server: {host}:{port}")
            
    else:
        ssh_keys = "OFF"
        # For password authentication, we need to get the username
        if 'username' not in locals():
            username = input("Enter the username for the REMOTE account to log into the EXTERNAL server: ")
            if username == "": username = "root"

    # Now write the config file with all collected parameters
    print("[*] Writing configuration to /usr/share/tap/config...")
    
    try:
        # Create the config file content
        config_content = f"""# TAP Configuration File
# Generated by setup.py
#
# SSH Connection Settings
USERNAME={username}
IPADDR={host}
PORT={port}
LOCAL_PORT={localport}
SOCKS_PROXY_PORT={socks}
SSH_KEYS={ssh_keys}

# Update Settings
COMMAND_UPDATES={commands}
AUTO_UPDATE=OFF
UPDATE_SERVER=git pull

# SSH Settings
SSH_CHECK_INTERVAL=60

# Logging
LOG_EVERYTHING=ON

# Password (encrypted if using password auth)
"""
        
        # Add password if using password authentication
        if auth_method == "password" and password:
            config_content += f"PASSWORD={password}\n"
        else:
            config_content += "PASSWORD=\n"
            
        # Write the config file
        with open("/usr/share/tap/config", "w") as config_file:
            config_file.write(config_content)
        
        # Set proper permissions
        os.chmod("/usr/share/tap/config", 0o600)
        
        print(f"{GREEN}[*] Configuration file created successfully at /usr/share/tap/config{END}")
        
    except Exception as e:
        print(f"{RED}[!] Failed to create config file: {e}{END}")
        raise


def _handle_existing_ssh_keys():
    """Handle the case where user wants to use existing SSH keys."""
    print(f"\n{YELLOW}[*] Using existing SSH keys...{END}")
    
    ssh_dir = Path("/root/.ssh")
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    
    # Remove old keys if they exist
    private_key = ssh_dir / "id_rsa"
    public_key = ssh_dir / "id_rsa.pub"
    
    if private_key.exists() or public_key.exists():
        print("[*] Removing old SSH keys...")
        private_key.unlink(missing_ok=True)
        public_key.unlink(missing_ok=True)
    
    # Get private key from user
    print("[*] Please paste your SSH Private Key below.")
    print("Paste the entire key including the header and footer lines:")
    print("-----BEGIN ... PRIVATE KEY-----")
    print("(paste your key here)")
    print("-----END ... PRIVATE KEY-----")
    print("\nPrivate Key > ", end="")
    
    try:
        with open(private_key, "w") as fd:
            while True:
                line = input()
                fd.write(line + '\n')
                if re.match(r'-----END .* PRIVATE KEY-----', line.strip()):
                    break
        
        private_key.chmod(0o600)
        print(f"{GREEN}[*] Private key saved successfully.{END}")
        
    except Exception as e:
        print(f"{RED}[!] Failed to save private key: {e}{END}")
        raise
    
    # Get public key from user
    print("\n[*] Please paste your SSH Public Key below.")
    print("This should be a single line starting with ssh-rsa, ssh-ed25519, etc.")
    print("Public Key > ", end="")
    
    try:
        with open(public_key, "w") as fd:
            while True:
                line = input()
                if line.strip() == '':
                    break
                fd.write(line + '\n')
        
        public_key.chmod(0o644)
        print(f"{GREEN}[*] Public key saved successfully.{END}")
        
    except Exception as e:
        print(f"{RED}[!] Failed to save public key: {e}{END}")
        raise


def finalize_installation():
    """Complete the installation process."""
    print(f"{YELLOW}[*] Finalizing installation...{END}")
    
    # Set permissions
    subprocess.run([
        "chmod", "+x", 
        "/usr/share/tap/tap.py",
        "/usr/share/tap/src/core/heartbeat.py"
    ], check=True)
    
    # Install proxychains
    install_proxychains()
    
    # Configure SSH server
    configure_ssh_server()
    
    print(f"{GREEN}[*] Installation complete!{END}")
    
    # Offer to start TAP
    choice = input("Would you like to start TAP now? [y/n]: ")
    if choice.lower() in ["yes", "y"]:
        subprocess.run(["systemctl", "start", "tap.service"], check=True)
        print(f"{GREEN}[*] TAP service started.{END}")
    
    # Offer PTF installation
    offer_ptf_installation()


def update_system():
    """Update the system and install required packages."""
    print("[*] Updating system packages...")
    
    try:
        # Update package lists
        print("[*] Updating package lists...")
        subprocess.run(["apt-get", "update"], check=True)
        
        # Upgrade packages
        print("[*] Upgrading packages...")
        subprocess.run([
            "apt-get", "--force-yes", "-y", "upgrade"
        ], check=True)
        
        # Distribution upgrade
        print("[*] Performing distribution upgrade...")
        subprocess.run([
            "apt-get", "--force-yes", "-y", "dist-upgrade"
        ], check=True)
        
        # Install required packages
        print("[*] Installing required packages...")
        subprocess.run([
            "apt-get", "--force-yes", "-y", "install",
            "git", "python3-pycryptodome", "python3-pexpect", 
            "openssh-server", "net-tools"
        ], check=True)
        
        print(f"{GREEN}[*] System update completed successfully.{END}")
        
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] System update failed: {e}{END}")
        print("[*] Continuing with installation despite update failure...")
        # Don't raise the exception to allow installation to continue


def setup_startup_scripts():
    """Configure TAP to start automatically using systemd."""
    print(f"{YELLOW}[*] Setting up TAP systemd service...{END}")
    
    # Create systemd service file
    service_content = """[Unit]
Description=TrustedSec Attack Platform (TAP)
After=network.target

[Service]
Type=forking
WorkingDirectory=/usr/share/tap/src/core
ExecStart=/usr/share/tap/src/core/heartbeat.py
ExecStop=/bin/bash -c 'pkill -f "heartbeat.py|tap.py"; rm -f /var/run/tap.pid'
PIDFile=/var/run/tap.pid
User=root
Group=root
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    
    try:
        # Remove old init.d script if it exists
        if os.path.isfile("/etc/init.d/tap"):
            print(f"{YELLOW}[*] Removing old init.d script...{END}")
            os.remove("/etc/init.d/tap")
            subprocess.run(["update-rc.d", "tap", "remove"], check=True)
        
        # Create systemd service file
        with open("/etc/systemd/system/tap.service", "w") as service_file:
            service_file.write(service_content)
        
        print(f"{GREEN}[*] Created systemd service file...{END}")
        
        # Reload systemd and enable the service
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "tap.service"], check=True)
        
        print(f"{GREEN}[*] TAP systemd service enabled successfully.{END}")
        
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        print(f"{RED}[!] Failed to setup systemd service: {e}{END}")
        raise


def setup_directories():
    """
    Create necessary directories and copy files for TAP installation.
    
    This function ensures all required directories exist and copies
    the necessary files to their installation locations with proper
    error handling and logging.
    
    Raises:
        OSError: If directory creation or file copying fails
        FileNotFoundError: If source files don't exist
    """
    print(f"{YELLOW}[*] Setting up TAP directory structure and files...{END}")
    
    # Define directory structure
    tap_base_dir = "/usr/share/tap"
    tap_src_dir = "/usr/share/tap/src"
    tap_core_dir = "/usr/share/tap/src/core"
    
    # Define file mappings: (source, destination, description)
    file_mappings = [
        ("./tap.py", "/usr/share/tap/tap.py", "main TAP script"),
        ("./update.py", "/usr/share/tap/update.py", "update script"),
        ("./src/motd.txt", "/usr/share/tap/src/motd.txt", "MOTD file"),
        ("./src/core/startup_tap", "/usr/share/tap/src/core/startup_tap", "startup script"),
        ("./src/core/tapcore.py", "/usr/share/tap/src/core/tapcore.py", "core TAP module"),
        ("./src/core/heartbeat.py", "/usr/share/tap/src/core/heartbeat.py", "heartbeat monitor"),
    ]
    
    try:
        # Create directory structure
        directories = [tap_base_dir, tap_src_dir, tap_core_dir]
        for directory in directories:
            if not os.path.isdir(directory):
                os.makedirs(directory, mode=0o755)
                print(f"[+] Created directory: {directory}")
            else:
                print(f"[*] Directory exists: {directory}")
        
        # Copy files with validation
        copied_files = 0
        for source_path, dest_path, description in file_mappings:
            try:
                # Check if source file exists
                if not os.path.isfile(source_path):
                    print(f"{RED}[!] Warning: Source file not found: {source_path}{END}")
                    continue
                
                # Skip if destination already exists and is identical
                if os.path.isfile(dest_path):
                    if os.path.getmtime(source_path) <= os.path.getmtime(dest_path):
                        print(f"[*] File up to date: {description}")
                        continue
                    else:
                        print(f"[*] Updating existing file: {description}")
                
                # Copy the file
                shutil.copy2(source_path, dest_path)  # copy2 preserves metadata
                
                # Set appropriate permissions
                if dest_path.endswith(('.py', 'startup_tap')):
                    os.chmod(dest_path, 0o755)  # Executable for scripts
                else:
                    os.chmod(dest_path, 0o644)  # Read-only for data files
                
                print(f"[+] Copied {description}: {source_path} -> {dest_path}")
                copied_files += 1
                
            except (OSError, IOError) as e:
                print(f"{RED}[!] Failed to copy {description} ({source_path}): {e}{END}")
                raise
        
        print(f"{GREEN}[*] Directory setup complete. Copied {copied_files} files.{END}")
        
    except OSError as e:
        print(f"{RED}[!] Failed to create directory structure: {e}{END}")
        raise
    except Exception as e:
        print(f"{RED}[!] Unexpected error during directory setup: {e}{END}")
        raise


def uninstall_tap():
    """Handle the TAP uninstallation process."""
    try:
        print("[*] Uninstalling TAP...")
        
        # Stop and disable systemd service
        try:
            subprocess.run(["systemctl", "stop", "tap.service"], check=False)
            subprocess.run(["systemctl", "disable", "tap.service"], check=False)
            if os.path.isfile("/etc/systemd/system/tap.service"):
                os.remove("/etc/systemd/system/tap.service")
            subprocess.run(["systemctl", "daemon-reload"], check=True)
        except subprocess.CalledProcessError:
            pass
        
        # Remove old init.d script if it exists
        if os.path.isfile("/etc/init.d/tap"):
            os.remove("/etc/init.d/tap")
        
        # Remove TAP directory
        if os.path.isdir("/usr/share/tap"):
            shutil.rmtree("/usr/share/tap")
        
        # Kill running processes
        print("[*] Checking to see if TAP is currently running...")
        kill_tap()
        
        print(f"{GREEN}[*] TAP has been uninstalled successfully.{END}")
        
    except Exception as e:
        print(f"{RED}[!] Uninstallation failed: {e}{END}")
        sys.exit(1)


def install_tap():
    """Handle the TAP installation process."""
    try:
        print(f"{YELLOW}[*] Checking to see if TAP is currently running...{END}")
        kill_tap()
        
        print(f"{YELLOW}[*] Beginning installation. This should only take a moment.{END}")
        setup_directories()
        setup_startup_scripts()
        set_background()
        try:
            update_system()
        except Exception as e:
            print(f"{RED}[!] Failed to update system: {e}{END}")
            print("[*] Continuing with installation despite update failure...")
            # Don't raise the exception to allow installation to continue
        
        try:
            configure_ssh_connection()
        except Exception as e:
            print(f"{RED}[!] Failed to configure SSH connection: {e}{END}")
            print("[*] Continuing with installation despite SSH configuration failure...")
            # Don't raise the exception to allow installation to continue
        
        finalize_installation()
        
    except Exception as e:
        print(f"{RED}[!] Installation failed: {e}{END}")
        sys.exit(1)


def check_and_install_dependencies():
    """
    Check for required dependencies and install if missing.
    
    This function ensures all necessary Python packages and system
    dependencies are installed before proceeding with the main installation.
    """
    print(f"{YELLOW}[*] Checking and installing dependencies...{END}")
    
    try:
        # Update package lists first
        print(f"{YELLOW}[*] Updating package lists...{END}")
        subprocess.run(["apt-get", "update"], check=True)
        
        # Install base system packages
        print(f"{YELLOW}[*] Installing base system packages...{END}")
        base_packages = [
            "htop", "dbus-x11"
        ]
        
        subprocess.run([
            "apt-get", "-y", "install"
        ] + base_packages, check=True)
        
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Failed to install dependencies: {e}{END}")
        print("Please install manually and re-run setup.")
        sys.exit(1)
    
    # Verify installations
    print("[*] Verifying installations...")
    required_modules = ['pexpect', 'Cryptodome']
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
            print(f"[+] {module} - OK")
        except ImportError:
            missing_modules.append(module)
            print(f"[-] {module} - MISSING")
    
    if missing_modules:
        print(f"{RED}[!] Still missing modules: {', '.join(missing_modules)}{END}")
        print("Please install manually and re-run setup.")
        sys.exit(1)
    
    print(f"{GREEN}[*] All dependencies are satisfied.{END}")


def main():
    """
    Main entry point for the TAP installation script.
    
    Handles dependency checking, user interaction, and orchestrates
    the installation or uninstallation process.
    """
    try:
        # Check if running as root first
        if os.geteuid() != 0:
            print(f"{RED}[!] This script must be run as root.{END}")
            sys.exit(1)
        
        # Check and install dependencies first
        check_and_install_dependencies()
        
        # Now try to import required modules
        try:
            
            print(f"{GREEN}[*] All required modules imported successfully.{END}")
        except ImportError as e:
            print(f"{RED}[!] Failed to import required modules after installation: {e}{END}")
            print("Please try running the script again or install manually:")
            print("  sudo apt-get install python3-pexpect python3-pycryptodome")
            print("  or")
            print("  pip3 install pexpect pycryptodome")
            sys.exit(1)
        
        # Determine operation mode
        if os.path.isfile("/etc/init.d/tap") or os.path.isfile("/etc/systemd/system/tap.service"):
            answer = input("TAP detected. Do you want to uninstall [y/n]: ")
            if answer.lower() in ["yes", "y"]:
                uninstall_tap()
                return
        
        # Proceed with installation
        answer = input("Do you want to start the installation of TAP: [y/n]: ")
        if answer.lower() in ["y", "yes"]:
            install_tap()
        else:
            print("[*] Installation cancelled.")
            
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Installation interrupted by user.{END}")
        sys.exit(0)
    except Exception as e:
        print(f"{RED}[!] An unexpected error occurred: {e}{END}")
        print("Please check the error and try again.")
        sys.exit(1)


# Remove the old problematic code at the bottom and replace with clean main call
if __name__ == "__main__":
    main()
