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
