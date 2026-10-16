# InterpraticDecompiler v1.1

> A lightweight, fast, and multi-architecture CLI binary analysis and pseudo-C decompiler tool designed for MZ, PE, ELF, and Mach-O files, equipped with threat hunting and IoC extraction capabilities.

---

## 🚀 Features (v1.1 Updates)

- **Multi-Format Support:** Analyzes Windows (PE/MZ), Linux (ELF), and macOS/iOS (Mach-O) binaries.
- **Entropy & Packer Detection:** Calculates Shannon entropy for the whole file and sections to detect packed, compressed, or encrypted binaries.
- **Automatic IoC Extraction:** Automatically extracts IP addresses, URLs, Registry keys, and Emails into a dedicated report (`ioc.txt`).
- **YARA Threat Scanning:** Optional YARA rule scanning support (`-yara`) for threat hunting and malware signature detection.
- **Disassembly Engine:** Powered by **Capstone** to extract clean assembly output (`disassembled.asm`).
- **Pseudo-C Decompilation:** Generates clean, heuristic-based C code representation (`decompiled.c`) with header comments.
- **String Extraction:** Extracts both ASCII and Unicode (UTF-16LE) strings from the binary.
- **PE Deep Analysis:** Built-in checks for .NET assemblies (`-pecs`) and Debug/Release build detection (`-debugcheck`).
- **Rich CLI Interface:** Interactive and colorful command-line interface using **Rich** and **LIEF**.

---

## 📦 Requirements & Installation

Make sure you have Python installed, then clone the repository and install the required dependencies:

```bash
# Clone the repository
git clone [https://github.com/aetherdll/InterpraticDecompiler.git](https://github.com/aetherdll/InterpraticDecompiler.git)
cd InterpraticDecompiler/InterpraticDecompiler_v1.1
```

# Install dependencies

```bash
pip install -r requirements.txt
```

# 💻 Usage

Run the tool from your terminal by passing the target binary file:

```bash
python InterpraticDecompiler.py <path_to_binary> [options]
```

---

## Examples:

Basic Analysis (with Entropy & Hashes):

```bash
python InterpraticDecompiler.py sample.dll
```

Specify Custom Output Directory:

```bash
python InterpraticDecompiler.py sample.dll -outdir my_analysis
```

Check for .NET Managed Assembly (PE):

```bash
python InterpraticDecompiler.py sample.dll -pecs
```

Check for Debug vs Release Build Info (PE):

```bash
python InterpraticDecompiler.py sample.dll -debugcheck
```

Run with YARA Threat Rules:

```bash
python InterpraticDecompiler.py sample.dll -yara rules.yar
```

Force Linux ELF Mode:

```bash
python InterpraticDecompiler.py target_elf_binary -elf
```

# 📂 Generated Output Files

All analysis reports are automatically saved to your specified output directory (default is output_analysis/):

disassembled.asm - Full instruction disassembly.  
decompiled.c - Heuristic C-style pseudo code representation.  
functions.txt - Exported functions and symbols list.  
addresses.txt - Section virtual addresses, memory permissions, and section entropy.  
strings.txt - Extracted ASCII and Unicode strings.  
imports.txt - Imported libraries and API functions.
exports.txt - Exported symbols.
ioc.txt - Automatically extracted IoCs (IPs, URLs, Registry keys, Emails).
entropy.txt - Overall file entropy and packer status report.

# 🛠️ Tech Stack

LIEF: To parse and inspect executable file formats.
Capstone: Multi-architecture disassembly framework.
Rich: Rich text and beautiful formatting in the terminal.
YARA: Malware identification and classification framework.

# 📄 License

This project is open-source under the MIT License.
