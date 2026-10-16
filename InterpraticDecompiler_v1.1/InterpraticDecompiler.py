import sys
import os
import hashlib
import re
import math
from collections import Counter
import lief
from capstone import *
from rich.console import Console
from rich.table import Table
import argparse

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

console = Console()

def print_banner():
    banner = """
    [bold cyan]╔═════════════════════════════════════════════╗[/bold cyan]
    [bold cyan]║          InterpraticDecompiler v1.1         ║[/bold cyan]
    [bold cyan]║     MZ, PE, ELF & Mach-O CLI Analyzer       ║[/bold cyan]
    [bold cyan]╚═════════════════════════════════════════════╝[/bold cyan]
    """
    console.print(banner)

def calculate_entropy(data):
    """Calculate Shannon entropy of byte data to detect packing/encryption."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counter = Counter(data)
    for count in counter.values():
        p_x = count / length
        entropy += -p_x * math.log2(p_x)
    return entropy

def extract_iocs(text_content):
    """Extract IPs, URLs, Registry keys, and Emails using Regex."""
    iocs = {
        "ips": set(),
        "urls": set(),
        "registry": set(),
        "emails": set()
    }
    
    # Regex patterns
    ip_pattern_safe = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    reg_pattern = r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[^\s"]+'
    email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    
    for line in text_content:
        for ip in re.findall(ip_pattern_safe, line):
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                iocs["ips"].add(ip)
        for url in re.findall(url_pattern, line):
            iocs["urls"].add(url)
        for reg in re.findall(reg_pattern, line, re.IGNORECASE):
            iocs["registry"].add(reg)
        for email in re.findall(email_pattern, line):
            iocs["emails"].add(email)
            
    return iocs

def extract_strings(file_path, min_length=4):
    """Extract ASCII and Unicode strings from the binary file bytes."""
    ascii_strings = []
    unicode_strings = []
    try:
        with open(file_path, "rb") as f:
            content = f.read()
            
            ascii_pattern = b"[\x20-\x7e]{" + str(min_length).encode() + b",}"
            matches = re.findall(ascii_pattern, content)
            for m in matches:
                ascii_strings.append(m.decode("ascii", errors="ignore"))
                
            unicode_pattern = b"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + b",}"
            unicode_matches = re.findall(unicode_pattern, content)
            for m in unicode_matches:
                try:
                    unicode_strings.append(m.decode("utf-16le", errors="ignore"))
                except Exception:
                    pass
    except Exception as e:
        ascii_strings.append(f"Error extracting strings: {e}")
        
    return ascii_strings, unicode_strings

def get_section_permissions(section):
    """Determine section read/write/execute permissions."""
    perms = []
    try:
        if hasattr(section, "characteristics"):
            chars = section.characteristics
            if chars & lief.PE.Section.CHARACTERISTICS.MEM_READ:
                perms.append("R")
            if chars & lief.PE.Section.CHARACTERISTICS.MEM_WRITE:
                perms.append("W")
            if chars & lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE:
                perms.append("X")
        elif hasattr(section, "flags"):
            flags = section.flags
            perms.append(str(flags))
    except Exception:
        pass
    
    return "".join(perms) if perms else "Unknown"

def generate_pseudo_c(instructions):
    """Convert raw assembly instructions into Pseudo-C code with header comments."""
    c_lines = [
        "/* ========================================================== */",
        "/* InterpraticDecompiler - Auto-Generated Pseudo-C Code       */",
        "/* Note: This is a heuristic translation from Assembly.       */",
        "/* ========================================================== */\n",
        "#include <stdio.h>",
        "#include <stdint.h>\n",
        "void decompiled_main() {"
    ]
    
    for i in instructions:
        mnemonic = i.mnemonic.lower()
        op_str = i.op_str
        
        if mnemonic in ["mov", "movsxd", "movzx"]:
            parts = [p.strip() for p in op_str.split(",")]
            if len(parts) == 2:
                c_lines.append(f"    {parts[0]} = {parts[1]};")
        elif mnemonic in ["add", "sub", "imul", "xor"]:
            parts = [p.strip() for p in op_str.split(",")]
            if len(parts) == 2:
                op_symbol = {"add": "+=", "sub": "-=", "imul": "*=", "xor": "^="}.get(mnemonic, "=")
                c_lines.append(f"    {parts[0]} {op_symbol} {parts[1]};")
        elif mnemonic == "call":
            c_lines.append(f"    function_call_{op_str.replace('.', '_')}();")
        elif mnemonic in ["je", "jz"]:
            c_lines.append(f"    if (condition_met) {{}}")
        elif mnemonic in ["jne", "jnz"]:
            c_lines.append(f"    if (!condition_met) {{}}")
        elif mnemonic == "ret":
            c_lines.append(f"    return;")
            
    c_lines.append("}\n")
    return c_lines

def analyze_binary(file_path, outdir, f_mz, f_pe, f_elf, f_mo, f_pecs, f_debugcheck, yara_rule_path):
    print_banner()
    
    if not os.path.exists(file_path):
        console.print(f"[bold red][!] Error: File '{file_path}' not found![/bold red]")
        return

    if not outdir:
        outdir = "output_analysis"
    
    os.makedirs(outdir, exist_ok=True)
    console.print(f"[bold blue][+] Output directory active: {outdir}[/bold blue]")
    console.print(f"[bold yellow][*] Analyzing file: {file_path}[/bold yellow]\n")
    
    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()
            md5_hash = hashlib.md5(file_bytes).hexdigest()
            sha256_hash = hashlib.sha256(file_bytes).hexdigest()
            console.print(f"[bold green][+] MD5   :[/bold green] {md5_hash}")
            console.print(f"[bold green][+] SHA256:[/bold green] {sha256_hash}")
            
            # Entropy Analysis
            file_entropy = calculate_entropy(file_bytes)
            console.print(f"[bold green][+] Entropy Score:[/bold green] {file_entropy:.4f} / 8.0")
            if file_entropy > 7.0:
                console.print("[bold red][!] High Entropy detected! File might be packed, compressed, or encrypted.[/bold red]")
            else:
                console.print("[bold green][+] Normal entropy level (Likely unpacked).[/bold green]")
            console.print("")
    except Exception as e:
        console.print(f"[yellow][!] Could not calculate hashes/entropy: {e}[/yellow]")

    binary = lief.parse(file_path)
    if not binary:
        console.print("[bold red][!] Error: File format could not be recognized or not supported![/bold red]")
        return

    fmt = binary.format.name
    console.print(f"[bold green][+] Detected Format:[/bold green] {fmt}")

    arch = CS_ARCH_X86
    mode = CS_MODE_64

    if f_pecs or f_debugcheck:
        f_pe = True

    if f_mz:
        console.print("[bold cyan][*] MZ (DOS) mode active.[/bold cyan]")
        mode = CS_MODE_16
    elif f_pe or isinstance(binary, lief.PE.Binary):
        console.print("[bold cyan][*] PE (Windows) mode active.[/bold cyan]")
        try:
            mode = CS_MODE_64 if binary.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64 else CS_MODE_32
        except Exception:
            mode = CS_MODE_64
    elif f_elf or isinstance(binary, lief.ELF.Binary):
        console.print("[bold cyan][*] ELF (Linux) mode active.[/bold cyan]")
        mode = CS_MODE_64
    elif f_mo or isinstance(binary, lief.MachO.Binary):
        console.print("[bold cyan][*] Mach-O (macOS/iOS) mode active.[/bold cyan]")
        mode = CS_MODE_64

    if f_pecs and isinstance(binary, lief.PE.Binary):
        try:
            if binary.has_dotnet:
                console.print("[bold magenta][!] .NET Detection: Managed Assembly[/bold magenta]")
            else:
                console.print("[bold green][+] .NET Detection: Native Binary[/bold green]")
        except Exception:
            pass

    if f_debugcheck and isinstance(binary, lief.PE.Binary):
        try:
            if binary.has_debug:
                console.print("[bold cyan][*] Debug Info Found: Likely DEBUG build[/bold cyan]")
            else:
                console.print("[bold green][+] Debug Info: No debug directory. Likely RELEASE build[/bold green]")
        except Exception:
            pass

    md = Cs(arch, mode)
    
    asm_path = os.path.join(outdir, "disassembled.asm")
    decomp_path = os.path.join(outdir, "decompiled.c")
    func_path = os.path.join(outdir, "functions.txt")
    addr_path = os.path.join(outdir, "addresses.txt")
    strings_path = os.path.join(outdir, "strings.txt")
    imports_path = os.path.join(outdir, "imports.txt")
    exports_path = os.path.join(outdir, "exports.txt")
    ioc_path = os.path.join(outdir, "ioc.txt")
    entropy_path = os.path.join(outdir, "entropy.txt")

    asm_lines = []
    func_lines = []
    addr_lines = []
    import_lines = []
    export_lines = []
    all_instructions = []

    try:
        if hasattr(binary, "imports"):
            for imp in binary.imports:
                import_lines.append(f"Library: {imp.name}\n")
                for func in imp.entries:
                    import_lines.append(f"  - {func.name}\n")
    except Exception:
        import_lines.append("Imports could not be extracted.\n")

    try:
        if hasattr(binary, "exported_functions"):
            for f in binary.exported_functions:
                export_lines.append(f"{f.name} -> 0x{f.address:x}\n")
        elif hasattr(binary, "symbols"):
            for s in binary.symbols:
                if s.is_function:
                    export_lines.append(f"{s.name} -> 0x{s.value:x}\n")
    except Exception:
        export_lines.append("Exports could not be extracted.\n")

    func_lines.extend(export_lines)

    table = Table(title="Binary Sections & Permissions")
    table.add_column("Name", style="magenta")
    table.add_column("Size", style="green")
    table.add_column("Virtual Address (VA)", style="blue")
    table.add_column("Permissions", style="yellow")

    for section in binary.sections:
        sec_name = section.name
        sec_size = hex(section.size)
        sec_va = hex(section.virtual_address)
        sec_perms = get_section_permissions(section)
        
        table.add_row(sec_name, sec_size, sec_va, sec_perms)
        addr_lines.append(f"Section: {sec_name} | VA: {sec_va} | Size: {sec_size} | Permissions: {sec_perms}\n")

        if section.size > 0 and len(section.content) > 0:
            sec_entropy = calculate_entropy(section.content)
            addr_lines.append(f"    -> Section Entropy: {sec_entropy:.4f}\n")
            
            asm_lines.append(f"; --- SECTION: {sec_name} (VA: {sec_va}, Perms: {sec_perms}, Entropy: {sec_entropy:.2f}) ---\n")
            try:
                for i in md.disasm(bytes(section.content), section.virtual_address):
                    line = f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}"
                    asm_lines.append(line + "\n")
                    addr_lines.append(f"  [Code Address] 0x{i.address:x} -> {i.mnemonic} {i.op_str}\n")
                    all_instructions.append(i)
            except Exception as e:
                asm_lines.append(f"; [Error] Disassembly error: {e}\n")

    console.print(table)

    console.print("[bold yellow][*] Extracting strings (ASCII & Unicode) & Analyzing IoCs...[/bold yellow]")
    ascii_strs, unicode_strs = extract_strings(file_path)
    string_lines = ["[=== ASCII STRINGS ===]\n"] + [s + "\n" for s in ascii_strs] + ["\n[=== UNICODE STRINGS ===]\n"] + [s + "\n" for s in unicode_strs]

    # Extract IoCs
    all_strs_combined = ascii_strs + unicode_strs
    iocs = extract_iocs(all_strs_combined)
    ioc_lines = [
        "[=== AUTOMATICALLY EXTRACTED IoCs ===]\n",
        f"[-] IP Addresses Found: {len(iocs['ips'])}\n"
    ] + [f"    {ip}\n" for ip in iocs['ips']] + [
        f"\n[-] URLs Found: {len(iocs['urls'])}\n"
    ] + [f"    {url}\n" for url in iocs['urls']] + [
        f"\n[-] Registry Keys Found: {len(iocs['registry'])}\n"
    ] + [f"    {reg}\n" for reg in iocs['registry']] + [
        f"\n[-] Emails Found: {len(iocs['emails'])}\n"
    ] + [f"    {email}\n" for email in iocs['emails']]

    # YARA Scan if provided
    if yara_rule_path and YARA_AVAILABLE:
        console.print(f"[bold yellow][*] Running YARA scan with rules: {yara_rule_path}[/bold yellow]")
        try:
            rules = yara.compile(filepath=yara_rule_path)
            matches = rules.match(file_path)
            if matches:
                console.print(f"[bold red][!] YARA Matches Found: {matches}[/bold red]")
            else:
                console.print("[bold green][+] No YARA matches found.[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] YARA compilation/scan error: {e}[/bold red]")
    elif yara_rule_path and not YARA_AVAILABLE:
        console.print("[bold yellow][!] YARA requested, but 'yara-python' is not installed or available.[/bold yellow]")

    console.print("[bold yellow][*] Generating Pseudo-C decompiler output...[/bold yellow]")
    decomp_lines = [line + "\n" for line in generate_pseudo_c(all_instructions)]

    entropy_report = [
        f"File: {file_path}\n",
        f"Overall Shannon Entropy: {file_entropy:.4f} / 8.0\n",
        "Status: " + ("Packed/Encrypted" if file_entropy > 7.0 else "Normal/Unpacked") + "\n"
    ]

    with open(asm_path, "w", encoding="utf-8") as f:
        f.writelines(asm_lines)
        
    with open(decomp_path, "w", encoding="utf-8") as f:
        f.writelines(decomp_lines)
    
    with open(func_path, "w", encoding="utf-8") as f:
        f.writelines(func_lines if func_lines else ["No functions found.\n"])

    with open(addr_path, "w", encoding="utf-8") as f:
        f.writelines(addr_lines)

    with open(strings_path, "w", encoding="utf-8") as f:
        f.writelines(string_lines)

    with open(imports_path, "w", encoding="utf-8") as f:
        f.writelines(import_lines if import_lines else ["No imports found.\n"])

    with open(exports_path, "w", encoding="utf-8") as f:
        f.writelines(export_lines if export_lines else ["No exports found.\n"])

    with open(ioc_path, "w", encoding="utf-8") as f:
        f.writelines(ioc_lines)

    with open(entropy_path, "w", encoding="utf-8") as f:
        f.writelines(entropy_report)

    console.print(f"\n[bold green][+] Success! All comprehensive reports saved to '{outdir}' directory:[/bold green]")
    console.print(f"    - {asm_path}")
    console.print(f"    - {decomp_path}")
    console.print(f"    - {func_path}")
    console.print(f"    - {addr_path}")
    console.print(f"    - {strings_path}")
    console.print(f"    - {imports_path}")
    console.print(f"    - {exports_path}")
    console.print(f"    - {ioc_path} (Extracted IoCs)")
    console.print(f"    - {entropy_path} (Entropy Report)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="InterpraticDecompiler - CLI Binary Analysis Tool v1.1")
    parser.add_argument("file", help="Path to the binary file to analyze")
    parser.add_argument("-outdir", help="Directory to save output files", default="output_analysis")
    parser.add_argument("-mz", action="store_true", help="MZ (DOS) mode")
    parser.add_argument("-pe", action="store_true", help="PE (Windows) mode")
    parser.add_argument("-elf", action="store_true", help="ELF (Linux) mode")
    parser.add_argument("-mo", action="store_true", help="Mach-O (macOS/iOS) mode")
    parser.add_argument("-pecs", action="store_true", help="Check if the PE file is a .NET assembly")
    parser.add_argument("-debugcheck", action="store_true", help="Analyze if the PE binary contains debug info")
    parser.add_argument("-yara", help="Path to a YARA rule file for threat scanning", default=None)
    
    args = parser.parse_args()
    analyze_binary(args.file, args.outdir, args.mz, args.pe, args.elf, args.mo, args.pecs, args.debugcheck, args.yara)
