[![Binary Ninja](https://img.shields.io/badge/Binary%20Ninja-Plugin-00ccff?style=for-the-badge&logo=binaryninja)](https://binary.ninja/)
[![angr](https://img.shields.io/badge/angr-Powered-orange?style=for-the-badge)](https://angr.io/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/nyxFault/AngryNinja?style=for-the-badge&color=yellow)](https://github.com/nyxFault/AngryNinja/stargazers)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)]()

# AngryNinja - Binary Ninja Plugin
A lightweight angr-based automation script for solving simple crackmes that take input via `argv[1]` or `stdin` with no complex transformations.

## Installation

### Prerequisites
- Python 3.8+
- angr framework

### Install angr in Binary Ninja

- Open Binary Ninja
- Press Ctrl + P 
- Type: Install Python3 module
- Enter: angr

### Setup
```bash
# Clone the repository 
git clone https://github.com/nyxFault/AngryNinja.git
```

Copy `nyxfault_AngryNinja.py` to your Binary Ninja plugins directory:
- Windows: `%APPDATA%\Binary Ninja\plugins\`
- Linux: `~/.binaryninja/plugins/`

### Usage

1. Load Binary → Open your crackme in Binary Ninja
2. Run **Plugins** → **nyxFault-AngryNinja** or Ctrl + P → Search for **nyxFault-AngryNinja**
3. Configure → 
  - Set **Target String** and **Avoid String**
  - Set **Input Size** 
  - Select input type (**argv** or **stdin**)
  - Set **Character Constraints**
6. Execute → Watch angr find the password!

## Demonstration

### 1. Solving `argv[1]` Crackme (`crackme_argv`)

**Challenge:** Download from [crackme-challs repository](https://github.com/nyxFault/crackme-challs)  
**Binary Type:** Command-line argument input  
**Success Message:** `Congratulations! Cracked! Flag ...`  
**Failure Message:** `Try Again! Invalid password.`

**Steps in AngryNinja:**
1. Load `crackme_argv` in Binary Ninja
2. Navigate to: `Plugins → AngryNinja → Solve argv[1] Crackme`
3. Configure:
   - **Target String:** `Congratulations` (success indicator)
   - **Avoid String:** `Invalid` (failure indicator)
4. Click **Solve** and wait for results

**Result:** AngryNinja automatically finds the correct password that triggers the success message!

![crackme_argv Demonstration](https://github.com/nyxFault/Images/blob/main/crackme_argv.png?raw=true)


### 2. Solving `stdin` Crackme (`crackme_stdin`)

**Challenge:** From the same [crackme-challs repository](https://github.com/nyxFault/crackme-challs)  
**Binary Type:** Standard input (keyboard/piped input)  
**Success Message:** `Access granted! You entered the ...`  
**Failure Message:** `Access denied! Incorrect ...`

**Steps in AngryNinja:**
1. Load `crackme_stdin` in Binary Ninja
2. Navigate to: `Plugins → AngryNinja → Solve stdin Crackme`
3. Configure:
   - **Target String:** `granted` (success indicator)
   - **Avoid String:** `denied` (failure indicator)
4. Click **Solve** and let angr work its magic

**Result:** The plugin discovers the exact input needed to bypass the password check!

![crackme_stdin Demonstration](https://github.com/nyxFault/Images/blob/main/crackme_stdin.png?raw=true)
