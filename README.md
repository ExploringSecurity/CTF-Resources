# CTF Resources
A list of Capture The Flag(CTF) frameworks, libraries, resources, softwares and tutorials. This list aims to help starters as well as seasoned CTF players to find everything related to CTFs at one place.
Focused on Crypto and Stego for now...

### Contents

- [Awesome CTF](#awesome-ctf)
  - [Create](#create)
    - [Forensics](#forensics)
    - [Platforms](#platforms)
    - [Steganography](#steganography)
    - [Web](#web)
  - [Solve](#solve)
    - [Attacks](#attacks)
    - [Bruteforcers](#bruteforcers)
    - [Cryptography](#crypto)
    - [Exploits](#exploits)
    - [Forensics](#forensics-1)
    - [Networking](#networking)
    - [Reversing](#reversing)
    - [Services](#services)
    - [Steganography](#steganography-1)
    - [Web](#web-1)

- [Resources](#resources)
  - [Operating Systems](#operating-systems)
  - [Starter Packs](#starter-packs)
  - [Tutorials](#tutorials)
  - [Wargames](#wargames)
  - [Websites](#websites)
  - [Wikis](#wikis)
  - [Writeups Collections](#writeups-collections)



## Crypto
| Resource  | Comment |
| ------------- | ------------- |
| [CyberChef](https://gchq.github.io/CyberChef)  | Web app for analysing and decoding data.  |
| [FeatherDuster](https://github.com/nccgroup/featherduster) | An automated, modular cryptanalysis tool.  |
| [dcode](https://dcode.fr/en) | Solvers for Crypto, Maths and Encodings online.|
| [Hash Extender](https://github.com/iagox86/hash_extender) | A utility tool for performing hash length extension attacks. |
| [padding-oracle-attacker](https://github.com/KishanBagaria/padding-oracle-attacker)| A CLI tool to execute padding oracle attacks. |
| [PkCrack](https://www.unix-ag.uni-kl.de/~conrad/krypto/pkcrack.html) | A tool for Breaking PkZip-encryption. |
| [QuipQuip](https://quipqiup.com)  | Automated cryptogram solver.|
| [RSACTFTool](https://github.com/Ganapati/RsaCtfTool)| A tool for recovering RSA private key with various attack. |
| [RSATool](https://github.com/ius/rsatool)  |  Generate private key with knowledge of p and q.|
| [XORTool](https://github.com/hellman/xortool)  | A tool to analyze multi-byte xor cipher.|
| [Base65536](https://github.com/qntm/base65536) | Unicode's answer to Base64.|
| [Braille Translator](https://www.branah.com/braille-translator) | Translate from braille to text.|
| [Ciphey](https://github.com/Ciphey/Ciphey) | Tool to automatically decrypt encryptions without knowing the key or cipher, decode encodings, and crack hashes.|
| [Cryptii](https://cryptii.com/) | Modular conversion, encoding and encryption online.|
| [Decodify](https://github.com/s0md3v/Decodify) | Detect and decode encoded strings, recursively.|
| [Enigma Machine](https://summersidemakerspace.ca/projects/enigma-machine/) | Universal Enigma Machine Simulator.|
| [Galois](http://web.eecs.utk.edu/~jplank/plank/papers/CS-07-593/) | A fast galois field arithmetic library/toolkit.|
| [Hash-identifier](https://code.google.com/p/hash-identifier/source/checkout) | Simple hash algorithm identifier.|
| [PadBuster](https://github.com/AonCyberLabs/PadBuster) | Automated script for performing Padding Oracle attacks.|
| [PEMCrack](https://github.com/robertdavidgraham/pemcrack) | Cracks SSL PEM files that hold encrypted private keys. Brute forces or dictionary cracks.|
| [Polybius Square Cipher](https://www.braingle.com/brainteasers/codes/polybius.php) | Table that allows someone to translate letters into numbers.|
| [Rumkin Cipher Tools](http://rumkin.com/tools/cipher/) | Collection of ciphhers/encoders tools.|
| [Vigenere Solver](https://www.guballa.de/vigenere-solver) | Online tool that breaks Vigenère ciphers without knowing the key.|
| [XOR Cracker](https://wiremask.eu/tools/xor-cracker/) | Online XOR decryption tool able to guess the key length and the cipher key to decrypt any file.|
| [XORTool](https://github.com/hellman/xortool) | A tool to analyze multi-byte xor cipher.|
| [yagu](https://sourceforge.net/projects/yafu/) | Automated integer factorization.|
| [Arfes](https://github.com/bee-san/Ares)| Discord based auto crypto solver|








## Misc
| Resource  | Comment |
| ------------- | ------------- |
| [Crackstation](https://crackstation.net/) | Hash cracker (database).|
| [Online Encyclopedia of Integer Sequences](https://oeis.org/) | OEIS: The On-Line Encyclopedia of Integer Sequences|


[https://github.com/uppusaikiran/awesome-ctf-cheatsheet\](https://github.com/uppusaikiran/awesome-ctf-cheatsheet)



## OSINT
Sherlock: A tool for finding usernames across multiple platforms, useful for OSINT challenges to track down someone’s social media footprint.
theHarvester: A tool to gather emails, subdomains, and IPs for a domain, valuable for footprinting and reconnaissance.
Maltego: A visual link analysis tool that can map relationships between data, great for investigating people, domains, or IP addresses. Community edition is free.

## Attacks

*Tools used for performing various kinds of attacks*

- [Bettercap](https://github.com/bettercap/bettercap) - Framework to perform MITM (Man in the Middle) attacks.
- [Yersinia](https://github.com/tomac/yersinia) - Attack various protocols on layer 2.

## Bruteforcers

*Tools used for various kind of bruteforcing (passwords etc.)*

- [Hashcat](https://hashcat.net/hashcat/) - Password Cracker
- [Hydra](https://tools.kali.org/password-attacks/hydra) - A parallelized login cracker which supports numerous protocols to attack
- [John The Jumbo](https://github.com/magnumripper/JohnTheRipper) - Community enhanced version of John the Ripper.
- [John The Ripper](http://www.openwall.com/john/) - Password Cracker.
- [Nozzlr](https://github.com/intrd/nozzlr) - Nozzlr is a bruteforce framework, trully modular and script-friendly.
- [Ophcrack](http://ophcrack.sourceforge.net/) - Windows password cracker based on rainbow tables.
- [Patator](https://github.com/lanjelot/patator) - Patator is a multi-purpose brute-forcer, with a modular design.
- [Turbo Intruder](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack) - Burp Suite extension for sending large numbers of HTTP requests 

## Exploits

*Tools used for solving Exploits challenges*

- [DLLInjector](https://github.com/OpenSecurityResearch/dllinjector) - Inject dlls in processes.
- [libformatstr](https://github.com/hellman/libformatstr) - Simplify format string exploitation.
- [Metasploit](http://www.metasploit.com/) - Penetration testing software.
  - [Cheatsheet](https://www.comparitech.com/net-admin/metasploit-cheat-sheet/)
- [one_gadget](https://github.com/david942j/one_gadget) -  A tool to find the one gadget `execve('/bin/sh', NULL, NULL)` call.
  - `gem install one_gadget`
- [Pwntools](https://github.com/Gallopsled/pwntools) - CTF Framework for writing exploits.
- [Qira](https://github.com/BinaryAnalysisPlatform/qira) - QEMU Interactive Runtime Analyser.
- [ROP Gadget](https://github.com/JonathanSalwan/ROPgadget) - Framework for ROP exploitation.
- [V0lt](https://github.com/P1kachu/v0lt) - Security CTF Toolkit.

  ## Exploiting / Pwn

*Tools used for solving Pwn challenges*

 - [afl](https://lcamtuf.coredump.cx/afl/) - Security-oriented fuzzer.
 - [honggfuzz](https://github.com/google/honggfuzz) - Security oriented software fuzzer. Supports evolutionary, feedback-driven fuzzing based on code coverage.
 - [libformatstr](https://github.com/hellman/libformatstr) - Simplify format string exploitation.
 - [One_gadget](https://github.com/david942j/one_gadget) - Tool for finding one gadget RCE.
 - [Pwntools](https://github.com/Gallopsled/pwntools) - CTF framework for writing exploits.
 - [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) - Framework for ROP exploitation.
 - [Ropper](https://github.com/sashs/Ropper) - Display information about files in different file formats and find gadgets to build rop chains for different architectures.
 - [Shellcodes Database](http://shell-storm.org/shellcode/) - A massive shellcodes database.


## Forensics

*Tools used for solving Forensics challenges*

- [Aircrack-Ng](http://www.aircrack-ng.org/) - Crack 802.11 WEP and WPA-PSK keys.
  - `apt-get install aircrack-ng`
- [Audacity](http://sourceforge.net/projects/audacity/) - Analyze sound files (mp3, m4a, whatever).
  - `apt-get install audacity`
- [Bkhive and Samdump2](http://sourceforge.net/projects/ophcrack/files/samdump2/) - Dump SYSTEM and SAM files.
  - `apt-get install samdump2 bkhive`
- [CFF Explorer](http://www.ntcore.com/exsuite.php) - PE Editor.
- [Creddump](https://github.com/moyix/creddump) - Dump windows credentials.
- [DVCS Ripper](https://github.com/kost/dvcs-ripper) - Rips web accessible (distributed) version control systems.
- [Exif Tool](http://www.sno.phy.queensu.ca/~phil/exiftool/) - Read, write and edit file metadata.
- [Extundelete](http://extundelete.sourceforge.net/) - Used for recovering lost data from mountable images.
- [Fibratus](https://github.com/rabbitstack/fibratus) - Tool for exploration and tracing of the Windows kernel.
- [Foremost](http://foremost.sourceforge.net/) - Extract particular kind of files using headers.
  - `apt-get install foremost`
- [Fsck.ext4](http://linux.die.net/man/8/fsck.ext3) - Used to fix corrupt filesystems.
- [Malzilla](http://malzilla.sourceforge.net/) - Malware hunting tool.
- [NetworkMiner](http://www.netresec.com/?page=NetworkMiner) - Network Forensic Analysis Tool.
- [PDF Streams Inflater](http://malzilla.sourceforge.net/downloads.html) - Find and extract zlib files compressed in PDF files.
- [Pngcheck](http://www.libpng.org/pub/png/apps/pngcheck.html) - Verifies the integrity of PNG and dump all of the chunk-level information in human-readable form.
  - `apt-get install pngcheck`
- [ResourcesExtract](http://www.nirsoft.net/utils/resources_extract.html) - Extract various filetypes from exes.
- [Shellbags](https://github.com/williballenthin/shellbags) - Investigate NT\_USER.dat files.
- [Snow](https://sbmlabs.com/notes/snow_whitespace_steganography_tool) - A Whitespace Steganography Tool.
- [USBRip](https://github.com/snovvcrash/usbrip) - Simple CLI forensics tool for tracking USB device artifacts (history of USB events) on GNU/Linux.
- [Volatility](https://github.com/volatilityfoundation/volatility) - To investigate memory dumps.
- [Wireshark](https://www.wireshark.org) - Used to analyze pcap or pcapng files
 - [A-Packets](https://apackets.com/) - Effortless PCAP File Analysis in Your Browser.
 - [Autopsy](https://www.autopsy.com/) - End-to-end open source digital forensics platform.
 - [Binwalk](https://github.com/devttys0/binwalk) - Firmware Analysis Tool.
 - [Bulk-extractor](https://github.com/simsong/bulk_extractor) - High-performance digital forensics exploitation tool.
 - [Bkhive & samdump2](https://www.kali.org/tools/samdump2/) - Dump SYSTEM and SAM files.
 - [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) - Small utility that reads the cache folder of Google Chrome Web browser, and displays the list of all files currently stored in the cache.
 - [Creddump](https://github.com/moyix/creddump) - Dump Windows credentials.
 - [Exiftool](https://exiftool.org/) - Read, write and edit file metadata.
 - [Extundelete](http://extundelete.sourceforge.net/) - Utility that can recover deleted files from an ext3 or ext4 partition.
 - [firmware-mod-kit](https://code.google.com/archive/p/firmware-mod-kit/) - Modify firmware images without recompiling.
 - [Foremost](http://foremost.sourceforge.net/) - Console program to recover files based on their headers, footers, and internal data structures.
 - [Forensic Toolkit](https://www.exterro.com/forensic-toolkit) - It scans a hard drive looking for various information. It can, potentially locate deleted emails and scan a disk for text strings to use them as a password dictionary to crack encryption.
 - [Forensically](https://29a.ch/photo-forensics/#forensic-magnifier) - Free online tool to analysis image this tool has many features.
 - [MZCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) - Small utility that reads the cache folder of Firefox/Mozilla/Netscape Web browsers, and displays the list of all files currently stored in the cache.
 - [NetworkMiner](https://www.netresec.com/index.ashx?page=NetworkMiner)  Network Forensic Analysis Tool (NFAT).
 - [OfflineRegistryView](https://www.nirsoft.net/utils/offline_registry_view.html) - Simple tool for Windows that allows you to read offline Registry files from external drive.
 - [photorec](https://www.cgsecurity.org/wiki/PhotoRec) - File data recovery software designed to recover lost files including video, documents and archives from hard disks, CD-ROMs, and lost pictures (thus the Photo Recovery name) from digital camera memory.
 - [Registry Viewer](https://accessdata.com/product-download/registry-viewer-2-0-0) - Tool to view Windows registers.
 - [Scalpel](https://github.com/sleuthkit/scalpel) - Open source data carving tool.
 - [The Sleuth Kit](https://www.sleuthkit.org/) - Collection of command line tools and a C library that allows you to analyze disk images and recover files from them.
 - [USBRip](https://github.com/snovvcrash/usbrip) - Simple CLI forensics tool for tracking USB device artifacts (history of USB events) on GNU/Linux.
 - [Volatility](https://github.com/volatilityfoundation/volatility) - An advanced memory forensics framework.
 - [Wireshark](https://www.wireshark.org/) - Tool to analyze pcap or pcapng files.
 - [X-Ways](https://www.x-ways.net/forensics/index-m.html) - Advanced work environment for computer forensic examiners.
 - 
*Registry Viewers*
- [OfflineRegistryView](https://www.nirsoft.net/utils/offline_registry_view.html) - Simple tool for Windows that allows you to read offline Registry files from external drive and view the desired Registry key in .reg file format.
- [Registry Viewer®](https://accessdata.com/product-download/registry-viewer-2-0-0) - Used to view Windows registries.
## Misc

*Tools used for solving Misc challenges*

 - [boofuzz](https://github.com/jtpereyda/boofuzz) - Network Protocol Fuzzing for Humans.
 - [Veles](https://codisec.com/veles/) - Binary data analysis and visualization tool.

**Bruteforcers:**

 - [changeme](https://github.com/ztgrace/changeme) - A default credential scanner.
 - [Hashcat](https://hashcat.net/hashcat/) - Advanced Password Recovery.
 - [Hydra](https://www.kali.org/tools/hydra/) - Parallelized login cracker which supports numerous protocols to attack.
 - [John the Ripper](https://www.openwall.com/john/) - Open Source password security auditing and password recovery.
 - [jwt_tool](https://github.com/ticarpi/jwt_tool) - A toolkit for testing, tweaking and cracking JSON Web Tokens.
 - [Ophcrack](https://ophcrack.sourceforge.io/) - Free Windows password cracker based on rainbow tables.
 - [Patator](https://github.com/lanjelot/patator) - Multi-purpose brute-forcer, with a modular design and a flexible usage.
 - [Turbo Intruder](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988) - Burp Suite extension for sending large numbers of HTTP requests and analyzing the results.

**Esoteric Languages:**

 - [Brainfuck](https://copy.sh/brainfuck/) - Brainfuck esoteric programming language IDE.
 - [COW](https://frank-buss.de/cow.html) - It is a Brainfuck variant designed humorously with Bovinae in mind.
 - [Malbolge](http://www.malbolge.doleczek.pl/) - Malbolge esoteric programming language solver.
 - [Ook!](https://www.dcode.fr/ook-language) - Tool for decoding / encoding in Ook!
 - [Piet](https://www.bertnase.de/npiet/npiet-execute.php) - Piet programming language compiler.
 - [Rockstar](https://codewithrockstar.com/online) - A language intended to look like song lyrics.
 - [Try It Online](https://tio.run/) - An online tool that has a ton of Esoteric language interpreters.


**Sandboxes:**

 - [Any.run](https://any.run/) - Interactive malware hunting service.
 - [Intezer Analyze](https://analyze.intezer.com/) - Malware analysis platform.
 - [Triage](https://tria.ge/) - State-of-the-art malware analysis sandbox designed for cross-platform support.
 - 
## Networking

*Tools used for solving Networking challenges*

- [Masscan](https://github.com/robertdavidgraham/masscan) - Mass IP port scanner, TCP port scanner.
- [Monit](https://linoxide.com/monitoring-2/monit-linux/) - A linux tool to check a host on the network (and other non-network activities).
- [Nipe](https://github.com/GouveaHeitor/nipe) - Nipe is a script to make Tor Network your default gateway.
- [Nmap](https://nmap.org/) - An open source utility for network discovery and security auditing.
- [Wireshark](https://www.wireshark.org/) - Analyze the network dumps.
  - `apt-get install wireshark`
- [Zeek](https://www.zeek.org) - An open-source network security monitor.
- [Zmap](https://zmap.io/) - An open-source network scanner.

## Reversing

*Tools used for solving Reversing challenges*

- [Androguard](https://github.com/androguard/androguard) - Reverse engineer Android applications.
- [Angr](https://github.com/angr/angr) - platform-agnostic binary analysis framework.
- [Apk2Gold](https://github.com/lxdvs/apk2gold) - Yet another Android decompiler.
- [ApkTool](http://ibotpeaches.github.io/Apktool/) - Android Decompiler.
- [Barf](https://github.com/programa-stic/barf-project) - Binary Analysis and Reverse engineering Framework.
- [Binary Ninja](https://binary.ninja/) - Binary analysis framework.
- [BinUtils](http://www.gnu.org/software/binutils/binutils.html) - Collection of binary tools.
- [BinWalk](https://github.com/devttys0/binwalk) - Analyze, reverse engineer, and extract firmware images.
- [Boomerang](https://github.com/BoomerangDecompiler/boomerang) - Decompile x86/SPARC/PowerPC/ST-20 binaries to C.
- [ctf_import](https://github.com/docileninja/ctf_import) – run basic functions from stripped binaries cross platform.
- [cwe_checker](https://github.com/fkie-cad/cwe_checker) - cwe_checker finds vulnerable patterns in binary executables.
- [demovfuscator](https://github.com/kirschju/demovfuscator) - A work-in-progress deobfuscator for movfuscated binaries.
- [Frida](https://github.com/frida/) - Dynamic Code Injection.
- [GDB](https://www.gnu.org/software/gdb/) - The GNU project debugger.
- [GEF](https://github.com/hugsy/gef) - GDB plugin.
- [Ghidra](https://ghidra-sre.org/) - Open Source suite of reverse engineering tools.  Similar to IDA Pro.
- [Hopper](http://www.hopperapp.com/) - Reverse engineering tool (disassembler) for OSX and Linux.
- [IDA Pro](https://www.hex-rays.com/products/ida/) - Most used Reversing software.
- [Jadx](https://github.com/skylot/jadx) - Decompile Android files.
- [Java Decompilers](http://www.javadecompilers.com) - An online decompiler for Java and Android APKs.
- [Krakatau](https://github.com/Storyyeller/Krakatau) - Java decompiler and disassembler.
- [Objection](https://github.com/sensepost/objection) - Runtime Mobile Exploration.
- [PEDA](https://github.com/longld/peda) - GDB plugin (only python2.7).
- [Pin](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool) - A dynamic binary instrumentaion tool by Intel.
- [PINCE](https://github.com/korcankaraokcu/PINCE) - GDB front-end/reverse engineering tool, focused on game-hacking and automation.
- [PinCTF](https://github.com/ChrisTheCoolHut/PinCTF) - A tool which uses intel pin for Side Channel Analysis.
- [Plasma](https://github.com/joelpx/plasma) - An interactive disassembler for x86/ARM/MIPS which can generate indented pseudo-code with colored syntax.
- [Pwndbg](https://github.com/pwndbg/pwndbg) - A GDB plugin that provides a suite of utilities to hack around GDB easily.
- [radare2](https://github.com/radare/radare2) - A portable reversing framework.
- [Triton](https://github.com/JonathanSalwan/Triton/) - Dynamic Binary Analysis (DBA) framework.
- [Uncompyle](https://github.com/gstarnberger/uncompyle) - Decompile Python 2.7 binaries (.pyc).
- [WinDbg](http://www.windbg.org/) - Windows debugger distributed by Microsoft.
- [Xocopy](http://reverse.lostrealm.com/tools/xocopy.html) - Program that can copy executables with execute, but no read permission.
- [Z3](https://github.com/Z3Prover/z3) - A theorem prover from Microsoft Research.

 - [Androguard](https://github.com/androguard/androguard) - Androguard is a full python tool to play with Android files.
 - [Angr](https://github.com/angr/angr) - A powerful and user-friendly binary analysis platform.
 - [Apk2gold](https://github.com/lxdvs/apk2gold) - CLI tool for decompiling Android apps to Java.
 - [ApkTool](https://ibotpeaches.github.io/Apktool/) - A tool for reverse engineering 3rd party, closed, binary Android apps.
 - [Binary Ninja](https://binary.ninja/) - Binary Analysis Framework.
 - [BinUtils](https://www.gnu.org/software/binutils/binutils.html) - Collection of binary tools.
 - [CTF_import](https://github.com/sciencemanx/ctf_import) - Run basic functions from stripped binaries cross platform.
 - [Compiler Explorer](https://godbolt.org/) - Online compiler tool.
 - [CWE_checker](https://github.com/fkie-cad/cwe_checker) - Finds vulnerable patterns in binary executables.
 - [Demovfuscator](https://github.com/kirschju/demovfuscator) - A work-in-progress deobfuscator for movfuscated binaries.
 - [Disassembler.io](https://onlinedisassembler.com/static/home/index.html) - Disassemble On Demand. 
A lightweight, online service for when you don’t have the time, resources, or requirements to use a heavier-weight alternative.
 - [dnSpy](https://github.com/dnSpy/dnSpy) - .NET debugger and assembly editor.
 - [EasyPythonDecompiler](https://sourceforge.net/projects/easypythondecompiler/) - A small .exe GUI application that will "decompile" Python bytecode, often seen in .pyc extension.
 - [Frida](https://github.com/frida/) - Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers.
 - [GDB](https://www.gnu.org/software/gdb/) - The GNU Project debugger.
 - [GEF](https://github.com/hugsy/gef) - A modern experience for GDB with advanced debugging features for exploit developers & reverse engineers.
 - [Ghidra](https://ghidra-sre.org/) - A software reverse engineering (SRE) suite of tools developed by NSA.
 - [Hopper](https://www.hopperapp.com/) - Reverse engineering tool (disassembler) for OSX and Linux.
 - [IDA Pro](https://hex-rays.com/ida-pro/) - Most used Reversing software.
 - [Jadx](https://github.com/skylot/jadx) - Command line and GUI tools for producing Java source code from Android Dex and Apk files.
 - [Java Decompilers](http://www.javadecompilers.com/) - An online decompiler for Java and Android APKs.
 - [JSDetox](https://github.com/svent/jsdetox) - A JavaScript malware analysis tool.
 - [miasm](https://github.com/cea-sec/miasm) - Reverse engineering framework in Python.
 - [Objection](https://github.com/sensepost/objection) - Runtime mobile exploration.
 - [Online Assembler/Disassembler](http://shell-storm.org/online/Online-Assembler-and-Disassembler/) - Online wrappers around the Keystone and Capstone projects.
 - [PEDA](https://github.com/longld/peda) - Python Exploit Development Assistance for GDB.
 - [PEfile](https://github.com/erocarrera/pefile) - Python module to read and work with PE (Portable Executable) files.
 - [Pwndbg](https://github.com/pwndbg/pwndbg) - Exploit Development and Reverse Engineering with GDB Made Easy.
 - [radare2](https://github.com/radareorg/radare2) - UNIX-like reverse engineering framework and command-line toolset.
 - [Rizin](https://github.com/rizinorg/rizin) - Rizin is a fork of the radare2 reverse engineering framework with a focus on usability, working features and code cleanliness.
 - [Uncompyle](https://github.com/gstarnberger/uncompyle) -  A Python 2.7 byte-code decompiler (.pyc)
 - [WinDBG](http://www.windbg.org/) - Windows debugger distributed by Microsoft.
 - [Z3](https://github.com/Z3Prover/z3) - A theorem prover from Microsoft Research.
 - [DogBolt](https://dogbolt.org/) - This gives output of many decompilers 
*JavaScript Deobfuscators*

- [Detox](http://relentless-coding.org/projects/jsdetox/install) - A Javascript malware analysis tool.
- [Revelo](http://www.kahusecurity.com/posts/revelo_javascript_deobfuscator.html) - Analyze obfuscated Javascript code.

*SWF Analyzers*
- [RABCDAsm](https://github.com/CyberShadow/RABCDAsm) - Collection of utilities including an ActionScript 3 assembler/disassembler.
- [Swftools](http://www.swftools.org/) - Collection of utilities to work with SWF files.
- [Xxxswf](https://bitbucket.org/Alexander_Hanel/xxxswf) -  A Python script for analyzing Flash files.

## Services

*Various kind of useful services available around the internet*

- [CSWSH](http://cow.cat/cswsh.html) - Cross-Site WebSocket Hijacking Tester.
- [Request Bin](https://requestbin.com/) - Lets you inspect http requests to a particular url.

## Steganography

*Tools used for solving Steganography challenges*

- [AperiSolve](https://aperisolve.fr/) - Aperi'Solve is a platform which performs layer analysis on image (open-source).
- [Convert](http://www.imagemagick.org/script/convert.php) - Convert images b/w formats and apply filters.
- [Exif](http://manpages.ubuntu.com/manpages/trusty/man1/exif.1.html) - Shows EXIF information in JPEG files.
- [Exiftool](https://linux.die.net/man/1/exiftool) - Read and write meta information in files.
- [Exiv2](http://www.exiv2.org/manpage.html) - Image metadata manipulation tool.
- [Image Steganography](https://sourceforge.net/projects/image-steg/) - Embeds text and files in images with optional encryption. Easy-to-use UI.
- [Image Steganography Online](https://incoherency.co.uk/image-steganography) - This is a client-side Javascript tool to steganographically hide images inside the lower "bits" of other images
- [ImageMagick](http://www.imagemagick.org/script/index.php) - Tool for manipulating images.
- [Outguess](https://www.freebsd.org/cgi/man.cgi?query=outguess+&apropos=0&sektion=0&manpath=FreeBSD+Ports+5.1-RELEASE&format=html) - Universal steganographic tool.
- [Pngtools](https://packages.debian.org/sid/pngtools) - For various analysis related to PNGs.
  - `apt-get install pngtools`
- [SmartDeblur](https://github.com/Y-Vladimir/SmartDeblur) - Used to deblur and fix defocused images.
- [Steganabara](https://www.openhub.net/p/steganabara) -  Tool for stegano analysis written in Java.
- [SteganographyOnline](https://stylesuxx.github.io/steganography/) - Online steganography encoder and decoder.
- [Stegbreak](https://linux.die.net/man/1/stegbreak) - Launches brute-force dictionary attacks on JPG image.
- [StegCracker](https://github.com/Paradoxis/StegCracker) - Steganography brute-force utility to uncover hidden data inside files.
- [stegextract](https://github.com/evyatarmeged/stegextract) - Detect hidden files and text in images.
- [Steghide](http://steghide.sourceforge.net/) - Hide data in various kind of images.
- [StegOnline](https://georgeom.net/StegOnline/upload) - Conduct a wide range of image steganography operations, such as concealing/revealing files hidden within bits (open-source).
- [Stegsolve](http://www.caesum.com/handbook/Stegsolve.jar) - Apply various steganography techniques to images.
- [Zsteg](https://github.com/zed-0xff/zsteg/) - PNG/BMP analysis.

 - [AperiSolve](https://aperisolve.fr/) - Platform which performs layer analysis on images.
 - [BPStegano](https://github.com/TapanSoni/BPStegano) - Python3 based LSB steganography.
 - [DeepSound](https://github.com/Jpinsoft/DeepSound) - Freeware steganography tool and audio converter that hides secret data into audio files.
 - [DTMF Detection](https://unframework.github.io/dtmf-detect/) - Audio frequencies common to a phone button.
 - [DTMF Tones](http://dialabc.com/sound/detect/index.html) - Audio frequencies common to a phone button.
 - [Exif](http://manpages.ubuntu.com/manpages/trusty/man1/exif.1.html) - Shows EXIF information in JPEG files.
 - [Exiv2](https://www.exiv2.org/manpage.html) - Image metadata manipulation tool.
 - [FotoForensics](https://fotoforensics.com/) - Provides budding researchers and professional investigators access to cutting-edge tools for digital photo forensics.
 - [hipshot](https://bitbucket.org/eliteraspberries/hipshot/src/master/) - Tool to converts a video file or series of photographs into a single image simulating a long-exposure photograph.
 - [Image Error Level Analyzer](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/) - Tool to analyze digital images. It's also free and web based. It features error level analysis, clone detection and more.
 - [Image Steganography](https://incoherency.co.uk/image-steganography/) - Client-side Javascript tool to steganographically hide/unhide images inside the lower "bits" of other images. 
 - [ImageMagick](http://www.imagemagick.org/script/index.php) - Tool for manipulating images.
 - [jsteg](https://github.com/lukechampine/jsteg) - Command-line tool to use against JPEG images.
 - [Magic Eye Solver](http://magiceye.ecksdee.co.uk/) - Get hidden information from images.
 - [Outguess](https://www.freebsd.org/cgi/man.cgi?query=outguess+&apropos=0&sektion=0&manpath=FreeBSD+Ports+5.1-RELEASE&format=html) - Universal steganographic tool.
 - [Pngcheck](http://www.libpng.org/pub/png/apps/pngcheck.html) - Verifies the integrity of PNG and dump all of the chunk-level information in human-readable form.
 - [Pngtools](https://packages.debian.org/sid/pngtools) - For various analysis related to PNGs.
 - [sigBits](https://github.com/Pulho/sigBits) - Steganography significant bits image decoder.
 - [SmartDeblur](https://github.com/Y-Vladimir/SmartDeblur) - Restoration of defocused and blurred photos/images.
 - [Snow](https://darkside.com.au/snow/) - Whitespace Steganography Tool
 - [Sonic Visualizer](https://www.sonicvisualiser.org/) - Audio file visualization.
 - [Steganography Online](https://stylesuxx.github.io/steganography/) - Online steganography encoder and decoder.
 - [Stegbreak](https://linux.die.net/man/1/stegbreak) - Launches brute-force dictionary attacks on JPG image.
 - [StegCracker](https://github.com/Paradoxis/StegCracker) - Brute-force utility to uncover hidden data inside files.
 - [stegextract](https://github.com/evyatarmeged/stegextract) - Detect hidden files and text in images.
 - [Steghide](http://steghide.sourceforge.net/) - Hide data in various kinds of image- and audio-files.
 - [StegOnline](https://stegonline.georgeom.net/) - Conduct a wide range of image steganography operations, such as concealing/revealing files hidden within bits.
 - [Stegosaurus](https://github.com/AngelKitty/stegosaurus) - A steganography tool for embedding payloads within Python bytecode.
 - [StegoVeritas](https://github.com/bannsec/stegoVeritas) - Yet another stego tool.
 - [Stegpy](https://github.com/dhsdshdhk/stegpy) - Simple steganography program based on the LSB method.
 - [stegseek](https://github.com/RickdeJager/stegseek) - Lightning fast steghide cracker that can be used to extract hidden data from files. 
 - [stegsnow](https://manpages.ubuntu.com/manpages/trusty/man1/stegsnow.1.html) - Whitespace steganography program.
 - [Stegsolve](https://github.com/zardus/ctf-tools/tree/master/stegsolve) - Apply various steganography techniques to images.
 - [Zsteg](https://github.com/zed-0xff/zsteg/) - PNG/BMP analysis.

WavSteg: A tool to hide data in WAV audio files or extract hidden data.
Sonic Visualiser / Friture: Tools to visualise sound waves and frequencies—useful for audio-based steganography challenges.
Exiftool: Extracts metadata from images, audio, and video files, potentially revealing hidden information.


https://book.hacktricks.wiki/en/index.html

https://dvd848.github.io/CTFs/CheatSheet.html

## Web

*Tools used for solving Web challenges*

- [BurpSuite](https://portswigger.net/burp) - A graphical tool to testing website security.
- [Commix](https://github.com/commixproject/commix) - Automated All-in-One OS Command Injection and Exploitation Tool.
- [Hackbar](https://addons.mozilla.org/en-US/firefox/addon/hackbartool/) - Firefox addon for easy web exploitation.
- [OWASP ZAP](https://www.owasp.org/index.php/Projects/OWASP_Zed_Attack_Proxy_Project) - Intercepting proxy to replay, debug, and fuzz HTTP requests and responses
- [Postman](https://chrome.google.com/webstore/detail/postman/fhbjgbiflinjbdggehcddcbncdddomop?hl=en) - Add on for chrome for debugging network requests.
- [Raccoon](https://github.com/evyatarmeged/Raccoon) - A high performance offensive security tool for reconnaissance and vulnerability scanning.
- [SQLMap](https://github.com/sqlmapproject/sqlmap) - Automatic SQL injection and database takeover tool.
  ```pip install sqlmap```
- [W3af](https://github.com/andresriancho/w3af) -  Web Application Attack and Audit Framework.
- [XSSer](http://xsser.sourceforge.net/) - Automated XSS testor.


 - [Arachni](https://www.arachni-scanner.com/) - Web Application Security Scanner Framework.
 - [Beautifier.io](https://beautifier.io/) - Online JavaScript Beautifier.
 - [BurpSuite](https://portswigger.net/burp) - A graphical tool to testing website security.
 - [Commix](https://github.com/commixproject/commix) - Automated All-in-One OS Command Injection Exploitation Tool.
 - [debugHunter](https://github.com/devploit/debugHunter) - Discover hidden debugging parameters and uncover web application secrets.
 - [Dirhunt](https://github.com/Nekmo/dirhunt) - Find web directories without bruteforce.
 - [dirsearch](https://github.com/maurosoria/dirsearch) - Web path scanner.
 - [nomore403](https://github.com/devploit/nomore403) - Tool to bypass 40x errors.
 - [ffuf](https://github.com/ffuf/ffuf) - Fast web fuzzer written in Go.
 - [git-dumper](https://github.com/arthaud/git-dumper) - A tool to dump a git repository from a website.
 - [Gopherus](https://github.com/tarunkant/Gopherus) - Tool that generates gopher link for exploiting SSRF and gaining RCE in various servers.
 - [Hookbin](https://hookbin.com/) - Free service that enables you to collect, parse, and view HTTP requests.
 - [JSFiddle](https://jsfiddle.net/) - Test your JavaScript, CSS, HTML or CoffeeScript online with JSFiddle code editor.
 - [ngrok](https://ngrok.com/) - Secure introspectable tunnels to localhost.
 - [OWASP Zap](https://owasp.org/www-project-zap/) - Intercepting proxy to replay, debug, and fuzz HTTP requests and responses.
 - [PHPGGC](https://github.com/ambionics/phpggc) - Library of PHP unserialize() payloads along with a tool to generate them, from command line or programmatically.
 - [Postman](https://chrome.google.com/webstore/detail/postman/fhbjgbiflinjbdggehcddcbncdddomop?hl=en) - Addon for chrome for debugging network requests.
 - [REQBIN](https://reqbin.com/) - Online REST & SOAP API Testing Tool.
 - [Request Bin](https://requestbin.com/) - A modern request bin to inspect any event by Pipedream.
 - [Revelo](http://www.kahusecurity.com/posts/revelo_javascript_deobfuscator.html) - Analyze obfuscated Javascript code.
 - [Smuggler](https://github.com/defparam/smuggler) -  An HTTP Request Smuggling / Desync testing tool written in Python3.
 - [SQLMap](https://github.com/sqlmapproject/sqlmap) - Automatic SQL injection and database takeover tool.
 - [W3af](https://github.com/andresriancho/w3af) - Web application attack and audit framework.
 - [XSSer](https://xsser.03c8.net/) - Automated XSS testor.
 - [ysoserial](https://github.com/frohoff/ysoserial) - Tool for generating payloads that exploit unsafe Java object deserialization.

 - https://securityheaders.com/

 - https://github.com/zardus/ctf-tools

 - UnderTheWire is another awesome website that offers PowerShell-based wargames designed explicitly for the cybersecurity community. Similar to OverTheWire, UnderTheWire employs wargames to sharpen PowerShell skills with rare instances and practical problem-solving techniques. The platform has five sets of levels for increasing difficulty, which can be adjusted to suit the level of users and the level they are playing at.

Root-Me PRO is a more advanced version of Root-me and is entirely dedicated to ethical hacking. The website has three main levels of CTF — Jeopardy CTF, Attack – Defense CTF, and Custom Cybersecurity Event. By signing up for challenges, users get SSH access to remote systems where they can participate in exploits and earn bounties. Additionally, the website has options to onboard cybersecurity training for companies, schools, colleges, and universities.


Developed for the Whitehat hacker community, Bugcrowd University doesn’t miss when it comes to CTF competitions and online training. The firm provides numerous programs and challenges through open-source instructional content that cybersecurity experts have carefully chosen. It regularly runs CTF events on its website and offers rewards to select winners. Additionally, the site has a wide range of educational content that can assist beginners to start their cybersecurity journey.


 - 
Burp Suite: An advanced web vulnerability scanner with a suite of tools to test and manipulate web traffic.
Postman: A tool to send API requests and inspect their responses, often helpful in testing or exploiting web applications.
OWASP ZAP: A web application security scanner that helps detect vulnerabilities in web applications, similar to Burp Suite but open-source.
Web Apps
Guyerre web app game: http://google-gruyere.appspot.com/

Hackademic from owasp: https://www.owasp.org/index.php/OWASP_Hackademic_Challenges_Project

Memory
http://www.honeynet.org/challenges/2011_7_compromised_server


# Resources

*Where to discover about CTF*

## Operating Systems

*Penetration testing and security lab Operating Systems*

- [Android Tamer](https://androidtamer.com/) - Based on Debian.
- [BackBox](https://backbox.org/) - Based on Ubuntu.
- [BlackArch Linux](https://blackarch.org/) - Based on Arch Linux.
- [Fedora Security Lab](https://labs.fedoraproject.org/security/) - Based on Fedora.
- [Kali Linux](https://www.kali.org/) - Based on Debian.
- [Parrot Security OS](https://www.parrotsec.org/) - Based on Debian.
- [Pentoo](http://www.pentoo.ch/) - Based on Gentoo.
- [URIX OS](http://urix.us/) - Based on openSUSE.
- [Wifislax](http://www.wifislax.com/) - Based on Slackware.

*Malware analysts and reverse-engineering*

- [Flare VM](https://github.com/fireeye/flare-vm/) - Based on Windows.
- [REMnux](https://remnux.org/) - Based on Debian.

## Starter Packs

*Collections of installer scripts, useful tools*

- [CTF Tools](https://github.com/zardus/ctf-tools) - Collection of setup scripts to install various security research tools.
- [LazyKali](https://github.com/jlevitsk/lazykali) - A 2016 refresh of LazyKali which simplifies install of tools and configuration.


# Create

*Tools used for creating CTF challenges*

- [Kali Linux CTF Blueprints](https://www.packtpub.com/eu/networking-and-servers/kali-linux-ctf-blueprints) - Online book on building, testing, and customizing your own Capture the Flag challenges.


## Forensics

*Tools used for creating Forensics challenges*

- [Dnscat2](https://github.com/iagox86/dnscat2) - Hosts communication through DNS.
- [Kroll Artifact Parser and Extractor (KAPE)](https://learn.duffandphelps.com/kape) - Triage program.
- [Magnet AXIOM](https://www.magnetforensics.com/downloadaxiom) - Artifact-centric DFIR tool.
- [Registry Dumper](http://www.kahusecurity.com/posts/registry_dumper_find_and_dump_hidden_registry_keys.html) - Dump your registry.
- [Belkasoft RAM Capturer](https://belkasoft.com/ram-capturer) - Volatile Memory Acquisition Tool.

## 
## Platforms

*Projects that can be used to host a CTF*

- [CTFd](https://github.com/isislab/CTFd) - Platform to host jeopardy style CTFs from ISISLab, NYU Tandon.
- [echoCTF.RED](https://github.com/echoCTF/echoCTF.RED) - Develop, deploy and maintain your own CTF infrastructure.
- [FBCTF](https://github.com/facebook/fbctf) - Platform to host Capture the Flag competitions from Facebook.
- [Haaukins](https://github.com/aau-network-security/haaukins)- A Highly Accessible and Automated Virtualization Platform for Security Education.
- [HackTheArch](https://github.com/mcpa-stlouis/hack-the-arch) - CTF scoring platform.
- [Mellivora](https://github.com/Nakiami/mellivora) - A CTF engine written in PHP.
- [MotherFucking-CTF](https://github.com/andreafioraldi/motherfucking-ctf) - Badass lightweight plaform to host CTFs. No JS involved.
- [NightShade](https://github.com/UnrealAkama/NightShade) - A simple security CTF framework.
- [OpenCTF](https://github.com/easyctf/openctf) - CTF in a box. Minimal setup required.
- [PicoCTF](https://github.com/picoCTF/picoCTF) - The platform used to run picoCTF. A great framework to host any CTF.
- [PyChallFactory](https://github.com/pdautry/py_chall_factory) - Small framework to create/manage/package jeopardy CTF challenges.
- [RootTheBox](https://github.com/moloch--/RootTheBox) - A Game of Hackers (CTF Scoreboard & Game Manager).
- [Scorebot](https://github.com/legitbs/scorebot) - Platform for CTFs by Legitbs (Defcon).
- [SecGen](https://github.com/cliffe/SecGen) - Security Scenario Generator. Creates randomly vulnerable virtual machines.
- [kCTF](https://github.com/google/kctf) - Kubernetes-based infrastructure for CTF competitions.
- [LibreCTF](https://github.com/easyctf/librectf) - CTF platform from EasyCTF.
- [rCTF](https://github.com/redpwn/rctf) - CTF platform maintained by the [redpwn](https://github.com/redpwn/rctf) CTF team.
- [ImaginaryCTF](https://github.com/Et3rnos/ImaginaryCTF) - Platform to host CTFs.

## Steganography

*Tools used to create stego challenges*

Check solve section for steganography.

## Web

*Tools used for creating Web challenges*

*JavaScript Obfustcators*

- [Metasploit JavaScript Obfuscator](https://github.com/rapid7/metasploit-framework/wiki/How-to-obfuscate-JavaScript-in-Metasploit)
- [Uglify](https://github.com/mishoo/UglifyJS)



## Tutorials

*Tutorials to learn how to play CTFs*

- [CTF Field Guide](https://trailofbits.github.io/ctf/) - Field Guide by Trails of Bits.
- [CTF Resources](http://ctfs.github.io/resources/) -  Start Guide maintained by community.
- [How to Get Started in CTF](https://www.endgame.com/blog/how-get-started-ctf) - Short guideline for CTF beginners by Endgame
- [Intro. to CTF Course](https://www.hoppersroppers.org/courseCTF.html) - A free course that teaches beginners the basics of forensics, crypto, and web-ex.
- [IppSec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) - Video tutorials and walkthroughs of popular CTF platforms.
- [LiveOverFlow](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w) - Video tutorials on Exploitation.
- [MIPT CTF](https://github.com/xairy/mipt-ctf) - A small course for beginners in CTFs (in Russian).


## Wargames

*Always online CTFs*

- [Backdoor](https://backdoor.sdslabs.co/) - Security Platform by SDSLabs.
- [Crackmes](https://crackmes.one/) - Reverse Engineering Challenges.
- [CryptoHack](https://cryptohack.org/) - Fun cryptography challenges.
- [echoCTF.RED](https://echoctf.red/) - Online CTF with a variety of targets to attack.
- [Exploit Exercises](https://exploit-exercises.lains.space/) - Variety of VMs to learn variety of computer security issues.
- [Exploit.Education](http://exploit.education) - Variety of VMs to learn variety of computer security issues.
- [Gracker](https://github.com/Samuirai/gracker) - Binary challenges having a slow learning curve, and write-ups for each level.
- [Hack The Box](https://www.hackthebox.eu) - Weekly CTFs for all types of security enthusiasts.
- [Hack This Site](https://www.hackthissite.org/) - Training ground for hackers.
- [Hacker101](https://www.hacker101.com/) - CTF from HackerOne
- [Hacking-Lab](https://hacking-lab.com/) - Ethical hacking, computer network and security challenge platform.
- [Hone Your Ninja Skills](https://honeyourskills.ninja/) - Web challenges starting from basic ones.
- [IO](http://io.netgarage.org/) - Wargame for binary challenges.
- [Microcorruption](https://microcorruption.com) - Embedded security CTF.
- [Over The Wire](http://overthewire.org/wargames/) - Wargame maintained by OvertheWire Community.
- [PentesterLab](https://pentesterlab.com/) - Variety of VM and online challenges (paid).
- [PicoCTF](https://2019game.picoctf.com) - All year round ctf game. Questions from the yearly picoCTF competition.
- [PWN Challenge](http://pwn.eonew.cn/) - Binary Exploitation Wargame.
- [Pwnable.kr](http://pwnable.kr/) - Pwn Game.
- [Pwnable.tw](https://pwnable.tw/) - Binary wargame.
- [Pwnable.xyz](https://pwnable.xyz/) - Binary Exploitation Wargame.
- [Reversin.kr](http://reversing.kr/) - Reversing challenge.
- [Ringzer0Team](https://ringzer0team.com/) - Ringzer0 Team Online CTF.
- [Root-Me](https://www.root-me.org/) - Hacking and Information Security learning platform.
- [ROP Wargames](https://github.com/xelenonz/game) - ROP Wargames.
- [SANS HHC](https://holidayhackchallenge.com/past-challenges/) - Challenges with a holiday theme
  released annually and maintained by SANS.
- [SmashTheStack](http://smashthestack.org/) - A variety of wargames maintained by the SmashTheStack Community.
- [Viblo CTF](https://ctf.viblo.asia) - Various amazing CTF challenges, in many different categories. Has both Practice mode and Contest mode.
- [VulnHub](https://www.vulnhub.com/) - VM-based for practical in digital security, computer application & network administration.
- [W3Challs](https://w3challs.com) - A penetration testing training platform, which offers various computer challenges, in various categories.
- [WebHacking](http://webhacking.kr) - Hacking challenges for web.
- [HackLIDO](https://hacklido.com/) - Game hacking, reverse engineering & ethical hacking. Learn how to reverse, hack & code
 - [0x0539](https://0x0539.net/) - Online CTF challenges.
 - [247CTF](https://247ctf.com/) - Free Capture The Flag Hacking Environment.
 - [Archive.ooo](https://archive.ooo/) - Live, playable archive of DEF CON CTF challenges.
 - [Atenea](https://atenea.ccn-cert.cni.es/) - Spanish CCN-CERT CTF platform.
 - [CTFlearn](https://ctflearn.com/) - Online platform built to help ethical hackers learn, practice, and compete.
 - [CTF365](https://ctf365.com/) - Security Training Platform.
 - [Crackmes.One](https://crackmes.one/) - Reverse Engineering Challenges.
 - [CryptoHack](https://cryptohack.org/) - Cryptography Challenges.
 - [Cryptopals](https://cryptopals.com/) - Cryptography Challenges.
 - [Defend the Web](https://defendtheweb.net/?hackthis) - An Interactive Cyber Security Platform.
 - [Dreamhack.io](https://dreamhack.io/wargame) - Online wargame.
 - [echoCTF.RED](https://echoctf.red/) - Online Hacking Laboratories.
 - [Flagyard](https://flagyard.com/) - An Online Playground of Hands-on Cybersecurity Challenges.
 - [HackBBS](https://hackbbs.org/index.php) - Online wargame.
 - [Hacker101](https://www.hacker101.com/) - CTF Platform by [HackerOne](https://www.hackerone.com/).
 - [Hackropole](https://hackropole.fr/en/) - This platform allows you to replay the challenges of the France Cybersecurity Challenge.
 - [HackTheBox](https://www.hackthebox.com/) - A Massive Hacking Playground.
 - [HackThisSite](https://www.hackthissite.org/) - Free, safe and legal training ground for hackers.
 - [HBH](https://hbh.sh/home) - Community designed to teach methods and tactics used by malicious hackers to access systems and sensitive information.
 - [Komodo](http://ctf.komodosec.com/) - This is a game designed to challenge your application hacking skills.
 - [MicroCorruption](https://microcorruption.com/) - Embedded Security CTF.
 - [MNCTF](https://mnctf.info/) - Online cybersecurity challenges.
 - [OverTheWire](https://overthewire.org/wargames/) - Wargame offered by the OverTheWire community.
 - [picoCTF](https://picoctf.org/) - Beginner-friendly CTF platform.
 - [Pwn.college](https://pwn.college/) - Education platform to learn about, and practice, core cybersecurity concepts.
 - [PWN.TN](https://pwn.tn/) - Educational and non commercial wargame.
 - [Pwnable.kr](http://pwnable.kr/) - Pwn/Exploiting platform.
 - [Pwnable.tw](https://pwnable.tw/) - Pwn/Exploiting platform.
 - [Pwnable.xyz](https://pwnable.xyz/) - Pwn/Exploiting platform.
 - [PWNChallenge](http://pwn.eonew.cn/) - Pwn/Exploiting platform.
 - [Reversing.kr](http://reversing.kr/) - Reverse Engineering platform.
 - [Root-me](https://www.root-me.org/) - CTF training platform.
 - [VibloCTF](https://ctf.viblo.asia/landing) - CTF training platform.
 - [VulnHub](https://www.vulnhub.com/) - VM-based pentesting platform.
 - [W3Challs](https://w3challs.com/) - Hacking/CTF platform.
 - [WebHacking](https://webhacking.kr/) - Web challenges platform.
 - [Websec.fr](http://websec.fr/) - Web challenges platform.
 - [WeChall](https://www.wechall.net/active_sites) - Challenge sites directory & forum.
 - [YEHD 2015](https://2015-yehd-ctf.meiji-ncc.tech/) - YEHD CTF 2015 online challenges
 -[CTF-LEARN](https://ctflearn.com/) - The most beginner-friendly way to get into hacking.
- [TryHackMe](https://tryhackme.com/) - huge number of training rooms
- [Web Security Academy](https://portswigger.net/web-security) - Free, online web security training from the creators of Burp Suite
- [VulnMachines](https://www.vulnmachines.com/)
- [hackxor](https://hackxor.net/)
- [hacktoria](https://hacktoria.com/) - story driven OSINT CTF
- 


*Self-hosted CTFs*
- [Damn Vulnerable Web Application](http://www.dvwa.co.uk/) - PHP/MySQL web application that is damn vulnerable.
- [Juice Shop CTF](https://github.com/bkimminich/juice-shop-ctf) - Scripts and tools for hosting a CTF on [OWASP Juice Shop](https://www.owasp.org/index.php/OWASP_Juice_Shop_Project) easily.
- [AWSGoat](https://github.com/ine-labs/AWSGoat) - A Damn Vulnerable AWS Infrastructure.
 - [CICD-goat](https://github.com/cider-security-research/cicd-goat) - A deliberately vulnerable CI/CD environment. Learn CI/CD security through multiple challenges.
 - [Damn Vulnerable Web Application](https://dvwa.co.uk/) - PHP/MySQL web application that is damn vulnerable.
 - [GCPGoat](https://github.com/ine-labs/GCPGoat) - A Damn Vulnerable GCP Infrastructure.
 - [Juice Shop](https://github.com/juice-shop/juice-shop-ctf) - Capture-the-Flag (CTF) environment setup tools for OWASP Juice Shop. 

## Collaborative Tools

 - [CTFNote](https://github.com/TFNS/CTFNote) - Collaborative tool aiming to help CTF teams to organise their work.

## Other
- [GSMEVIL 2](https://github.com/ninjhacks/gsmevil2) : a python web based tool which use for capturing imsi numbers and sms 
- [RouterSploit](https://github.com/threat9/routersploit) : an open-source exploitation framework dedicated to embedded devices.
- moroccan numbers : site:wa.me “+212”

## Websites

*Various general websites about and on CTF*

- [Awesome CTF Cheatsheet](https://github.com/uppusaikiran/awesome-ctf-cheatsheet#awesome-ctf-cheatsheet-) - CTF Cheatsheet.
- [CTF Time](https://ctftime.org/) - General information on CTF occuring around the worlds.
- [Reddit Security CTF](http://www.reddit.com/r/securityctf) - Reddit CTF category.

## Wikis

*Various Wikis available for learning about CTFs*

- [Bamboofox](https://bamboofox.github.io/) - Chinese resources to learn CTF.
- [bi0s Wiki](https://teambi0s.gitlab.io/bi0s-wiki/) - Wiki from team bi0s.
- [CTF Cheatsheet](https://uppusaikiran.github.io/hacking/Capture-the-Flag-CheatSheet/) - CTF tips and tricks.
- [ISIS Lab](https://github.com/isislab/Project-Ideas/wiki) - CTF Wiki by Isis lab.
- [OpenToAll](https://github.com/OpenToAllCTF/Tips) - CTF tips by OTA CTF team members.

## Writeups Collections

*Collections of CTF write-ups*

- [0e85dc6eaf](https://github.com/0e85dc6eaf/CTF-Writeups) - Write-ups for CTF challenges by 0e85dc6eaf
- [Captf](http://captf.com/) - Dumped CTF challenges and materials by psifertex.
- [CTF write-ups (community)](https://github.com/ctfs/) - CTF challenges + write-ups archive maintained by the community.
- [CTFTime Scrapper](https://github.com/abdilahrf/CTFWriteupScrapper) - Scraps all writeup from CTF Time and organize which to read first.
- [HackThisSite](https://github.com/HackThisSite/CTF-Writeups) - CTF write-ups repo maintained by HackThisSite team.
- [Mzfr](https://github.com/mzfr/ctf-writeups/) - CTF competition write-ups by mzfr
- [pwntools writeups](https://github.com/Gallopsled/pwntools-write-ups) - A collection of CTF write-ups all using pwntools.
- [SababaSec](https://github.com/SababaSec/ctf-writeups) - A collection of CTF write-ups by the SababaSec team
- [Shell Storm](http://shell-storm.org/repo/CTF/) - CTF challenge archive maintained by Jonathan Salwan.
- [Smoke Leet Everyday](https://github.com/smokeleeteveryday/CTF_WRITEUPS) - CTF write-ups repo maintained by SmokeLeetEveryday team.
## Writeups Repositories

*Repository of CTF Writeups*

 - [Courgettes.Club](https://ctf.courgettes.club/) - CTF Writeup Finder.
 - [CTFtime](https://ctftime.org/writeups) - CTFtime Writeups Collection.
 - [Github.com/CTFs](https://github.com/ctfs) - Collection of CTF Writeups.
 - [Braincoke](https://braincoke.fr/write-up) - Blog and Collection of CTF Writeups.

## Courses

 - [Roppers Bootcamp](https://www.roppers.org/courses/ctf) - CTF Bootcamp.

# 0x03. Bibliography

*The resources presented here have been gathered from numerous sources. However, the most important are:*

 - [apsdehal_awesome-ctf](https://github.com/apsdehal/awesome-ctf)
 - [vavkamil_awesome-bugbounty-tools](https://github.com/vavkamil/awesome-bugbounty-tools)
 - [zardus_ctf-tools](https://github.com/zardus/ctf-tools)

- [zlib Decompressor](https://github.com/gynvael/random-stuff/tree/master/brute_zlib) - It's somewhat useful to extract data from corrupted ZIP archives and other binary blobs which might contains DEFLATE streams.


Pwn / RE
Pwn.College
ROP Emporium
Exploit Education
How2Heap
Pwnables
Deusx64
Roppers Academy
Azeria Labs
Reversing Challenges
Begin RE
CrackMes

Blue Team
LetsDefend
Blue Team Labs Online
Cyber Defenders
Attack Defense
Immersive Labs

Videos
LiveOverflow
John Hammond
IppSec
XCT
Gynvael
ZetaTwo
PwnFunction
0xdf
247CTF
MalFind
DayZeroSec
Rana Khalil
PinkDraconian
Superhero1
S1lk
Alh4zr3d
Paweł Łukasik
Ephemeral
Hak5
Conda
HackerSploit
Condingo
InsiderPhd
HackSplained
TheCyberMentor
StackSmashing
Cybersecurity Meg
Tib3rius
SecAura
DarkSec
Hexorcist
PwnCollege
NahamSec
Optional
TheHackerish
Ryan Gordon
AlmondForce
VulnMachines
More
Even More..

Tools
Ghidra
Volatility
PwnTools
CyberChef
DCode
Decompile Code
Run Code
GTFOBins
ExploitDB
RevShells

More Resources
Bug Bounty Platforms
HackTricks
CTF Resources
Security Resources
Bug Bounty Resources
Seal9055 Resources
Forensics
Learn RE
Learn BinExp
HTB Writeups
