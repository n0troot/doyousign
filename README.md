# DoYouSign?

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash: 4.0+](https://img.shields.io/badge/Bash-4.0%2B-blue.svg)](https://www.gnu.org/software/bash/)

A powerful and comprehensive tool to evaluate LDAP security configurations on Windows Domain Controllers. Designed specifically for penetration testers and security professionals to quickly identify and exploit LDAP security weaknesses.

## Features

- **LDAP Signing Enforcement Detection**: Determines if the target requires signed LDAP connections
- **Channel Binding Assessment**: Checks if LDAP channel binding is enforced to prevent relay attacks
- **Anonymous Bind Testing**: Verifies if anonymous binds are allowed for information disclosure
- **Comprehensive Reporting**: Clear and actionable findings with exploitation guidance
- **Color-Coded Results**: Because if it ain't red ain't no way I know it's bad

## Installation

### Prerequisites

- Python 3
- Python LDAP module
- LDAP utilities

### Installing Dependencies

#### Debian/Ubuntu
```bash
sudo apt update
sudo apt install -y python3 python3-pip ldap-utils
pip3 install ldap3
```
#### Fedora/RHEL/CentOS

```bash
sudo dnf install -y python3 python3-pip openldap-clients
pip3 install ldap3
```

#### Arch Linux

```bash
sudo pacman -S python python-pip openldap
pip install ldap3
```

### Download and Install

```
git clone https://github.com/n0troot/doyousign.git
cd doyousign
chmod +x doyousign.sh
```

## Usage

Basic Usage:

```bash
./doyousign.sh <DC-IP> <Username> <Password> <Domain>
```

Example:

```bash
./doyousign.sh 192.168.1.10 administrator Password123 example.local
```

## Example Output
![image](https://github.com/user-attachments/assets/133f0171-eb74-49eb-9996-9c78f2f755b1)


## Exploitation Guidance

For each identified vulnerability, the tool provides specific exploitation techniques:

1. **Unsigned LDAP**:
   - Use network MITM tools to intercept and modify LDAP traffic
   - Potential for credential theft and modified LDAP queries

2. **No Channel Binding**:
   - Set up NTLM relay attacks (using tools like ntlmrelayx)
   - Leverage for credential theft and domain privilege escalation

3. **Anonymous Binds**:
   - Enumerate Active Directory users and groups without authentication
   - Gather valuable information for further attacks


## Disclaimer

This tool is provided for educational and professional security assessment purposes only. Use responsibly and only against systems you have permission to test.
