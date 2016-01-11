
bookmarks (awesome links / malware analysis / re)


- [Malware Analysis](malware-analysis)
    - [Malware Collection](#malware-collection)
        - [Anonymizers](#anonymizers)
        - [Honeypots](#honeypots)
        - [Malware Corpora](#malware-corpora)
    - [Open Source Threat Intelligence](#open-source-threat-intelligence)
        - [Tools](#tools)
        - [Other Resources](#other-resources)
    - [Detection and Classification](#detection-and-classification)
    - [Online Scanners and Sandboxes](#online-scanners-and-sandboxes)
    - [Domain Analysis](#domain-analysis)
    - [Browser Malware](#browser-malware)
    - [Documents and Shellcode](#documents-and-shellcode)
    - [File Carving](#file-carving)
    - [Deobfuscation](#deobfuscation)
    - [Debugging and Reverse Engineering](#debugging-and-reverse-engineering)
    - [Network](#network)
    - [Memory Forensics](#memory-forensics)
    - [Windows Artifacts](#windows-artifacts)
    - [Storage and Workflow](#storage-and-workflow)
    - [Miscellaneous](#miscellaneous)
- [Resources](#resources)
    - [Books](#books)
    - [Twitter](#twitter)
    - [Other](#other)


---

## Malware Collection

### Anonymizers

*Web traffic anonymizers for analysts.*

* [Anonymouse.org](http://anonymouse.org/) - A free, web based anonymizer.
* [OpenVPN](https://openvpn.net/) - VPN software and hosting solutions.
* [Privoxy](http://www.privoxy.org/) - An open source proxy server with some
  privacy features.
* [Tor](https://www.torproject.org/) - The Onion Router, for browsing the web
  without leaving traces of the client IP.

### Honeypots

*Trap and collect your own samples.*

* [Conpot](https://github.com/mushorg/conpot) - ICS/SCADA honeypot.
* [Dionaea](http://dionaea.carnivore.it/) - Honeypot designed to trap
  malware.
* [Glastopf](http://glastopf.org/) - Web application honeypot.
* [Honeyd](http://www.honeyd.org/) - Create a virtual honeynet.
* [HoneyDrive](http://bruteforce.gr/honeydrive) - Honeypot bundle Linux distro.
* [Kippo](https://github.com/desaster/kippo) - Medium interaction SSH honeypot.
* [Mnemosyne](https://github.com/johnnykv/mnemosyne) - A normalizer for
  honeypot data; supports Dionaea.
* [Thug](https://github.com/buffer/thug) - Low interaction honeyclient, for
  investigating malicious websites.

### Malware Corpora

*Malware samples collected for analysis.*

* [Clean MX](http://support.clean-mx.de/clean-mx/viruses.php) - Realtime
  database of malware and malicious domains.
* [Contagio](http://contagiodump.blogspot.com/) - A collection of recent
  malware samples and analyses.
* [Exploit Database](https://www.exploit-db.com/) - Exploit and shellcode
  samples.
* [Malshare](http://malshare.com) - Large repository of malware actively
  scrapped from malicious sites.
* [maltrieve](https://github.com/krmaxwell/maltrieve) - Retrieve malware
  samples directly from a number of online sources.
* [MalwareDB](http://malwaredb.malekal.com/) - Malware samples repository.
* [theZoo](https://github.com/ytisf/theZoo) - Live malware samples for
  analysts.
* [ViruSign](http://www.virusign.com/) - Malware database that detected by
  many anti malware programs except ClamAV.
* [VirusShare](http://virusshare.com/) - Malware repository, registration
* [Zeltser's Sources](https://zeltser.com/malware-sample-sources/) - A list
  of malware sample sources put together by Lenny Zeltser.
* [Zeus Source Code](https://github.com/Visgean/Zeus) - Source for the Zeus
  trojan leaked in 2011.
  required.

## Open Source Threat Intelligence

### Tools

*Harvest and analyze IOCs.*

* [Combine](https://github.com/mlsecproject/combine) - Tool to gather Threat
  Intelligence indicators from publicly available sources.
* [IntelMQ](https://www.enisa.europa.eu/activities/cert/support/incident-handling-automation) -
  A tool for CERTs for processing incident data using a message queue.
* [IOC Editor](https://www.fireeye.com/services/freeware/ioc-editor.html) -
  A free editor for XML IOC files.
* [ioc_writer](https://github.com/mandiant/ioc_writer) - Python library for
  working with OpenIOC objects, from Mandiant.
* [Massive Octo Spice](https://github.com/csirtgadgets/massive-octo-spice) -
  Previously known as CIF (Collective Intelligence Framework). Aggregates IOCs
  from various lists. Curated by the [CSIRT Gadgets Foundation](http://csirtgadgets.org/collective-intelligence-framework).
* [MISP](https://github.com/MISP/MISP) - Malware Information Sharing
  Platform curated by [The MISP Project](http://www.misp-project.org/).
* [PassiveTotal](https://www.passivetotal.org/) - Research, connect, tag and
  share IPs and domains.
* [PyIOCe](https://github.com/pidydx/PyIOCe) - A Python OpenIOC editor.
* [threataggregator](https://github.com/jpsenior/threataggregator) -
  Aggregates security threats from a number of sources, including some of
  those listed below in [other resources](#other-resources).
* [ThreatCrowd](https://www.threatcrowd.org/) - A search engine for threats,
  with graphical visualization.
* [ThreatTracker](https://github.com/jiachongzhi/ThreatTracker) - A Python
  script to monitor and generate alerts based on IOCs indexed by a set of
  Google Custom Search Engines.
* [TIQ-test](https://github.com/mlsecproject/tiq-test) - Data visualization
  and statistical analysis of Threat Intelligence feeds.

### Other Resources

*Threat intelligence and IOC resources.*

* [Autoshun](http://autoshun.org/) ([list](http://autoshun.org/files/shunlist.csv)) -
  Snort plugin and blocklist.
* [CI Army](http://cinsscore.com/) ([list](http://cinsscore.com/list/ci-badguys.txt)) -
  Network security blocklists.
* [Critical Stack- Free Intel Market](https://intel.CriticalStack.com) - Free
  intel aggregator with deduplication featuring 90+ feeds and over 1.2M indicators.
* [CRDF ThreatCenter](http://threatcenter.crdf.fr/) - List of new threats detected
  by CRDF anti-malware.
* [Emerging Threats](http://www.emergingthreats.net/) - Rulesets and more.
* [FireEye IOCs](https://github.com/fireeye/iocs) - Indicators of Compromise
  shared publicly by FireEye.
* [hpfeeds](https://github.com/rep/hpfeeds) - Honeypot feed protocol.
* [Internet Storm Center (DShield)](https://isc.sans.edu/) - Diary and
  searchable incident database, with a web [API](https://dshield.org/api/)
  ([unofficial Python library](https://github.com/rshipp/python-dshield)).
* [malc0de](http://malc0de.com/database/) - Searchable incident database.
* [Malware Domain List](http://www.malwaredomainlist.com/) - Search and share
  malicious URLs.
* [OpenIOC](http://openioc.org/) - Framework for sharing threat intelligence.
* [Palevo Blocklists](https://palevotracker.abuse.ch/blocklists.php) - Botnet
  C&C blocklists.
* [STIX - Structured Threat Information eXpression](http://stixproject.github.io) -
  Standardized language to represent and share cyber threat information.
  Related efforts from [MITRE](http://www.mitre.org/):
  - [CAPEC - Common Attack Pattern Enumeration and Classification](http://capec.mitre.org/)
  - [CybOX - Cyber Observables eXpression](http://cyboxproject.github.io)
  - [MAEC - Malware Attribute Enumeration and Characterization](http://maec.mitre.org/)
  - [TAXII - Trusted Automated eXchange of Indicator Information](http://taxiiproject.github.io)
* [threatRECON](https://threatrecon.co/) - Search for indicators, up to 1000
  free per month.
* [Yara rules](https://github.com/Yara-Rules/rules) - Yara rules repository.
* [ZeuS Tracker](https://zeustracker.abuse.ch/blocklist.php) - ZeuS
  blocklists.

## Detection and Classification

*Antivirus and other malware identification tools*

* [AnalyzePE](https://github.com/hiddenillusion/AnalyzePE) - Wrapper for a
  variety of tools for reporting on Windows PE files.
* [chkrootkit](http://www.chkrootkit.org/) - Local Linux rootkit detection.
* [ClamAV](http://www.clamav.net/) - Open source antivirus engine.
* [ExifTool](http://www.sno.phy.queensu.ca/~phil/exiftool/) - Read, write and
  edit file metadata.
* [hashdeep](https://github.com/jessek/hashdeep) - Compute digest hashes with
  a variety of algorithms.
* [Loki](https://github.com/Neo23x0/Loki) - Host based scanner for IOCs.
* [Malfunction](https://github.com/Dynetics/Malfunction) - Catalog and
  compare malware at a function level.
* [MASTIFF](https://github.com/KoreLogicSecurity/mastiff) - Static analysis
  framework.
* [MultiScanner](https://github.com/MITRECND/multiscanner) - Modular file
  scanning/analysis framework
* [nsrllookup](https://github.com/rjhansen/nsrllookup) - A tool for looking
  up hashes in NIST's National Software Reference Library database.
* [packerid](http://handlers.sans.org/jclausing/packerid.py) - A cross-platform
  Python alternative to PEiD.
* [PEiD](http://woodmann.com/BobSoft/Pages/Programs/PEiD) - Packer identifier
  for Windows binaries.
* [PEV](http://pev.sourceforge.net/) - A multiplatform toolkit to work with PE
  files, providing feature-rich tools for proper analysis of suspicious binaries.
* [Rootkit Hunter](http://rkhunter.sourceforge.net/) - Detect Linux rootkits.
* [ssdeep](http://ssdeep.sourceforge.net/) - Compute fuzzy hashes.
* [totalhash.py](https://gist.github.com/malc0de/10270150) - Python script
  for easy searching of the [TotalHash.com](https://totalhash.cymru.com/) database.
* [TrID](http://mark0.net/soft-trid-e.html) - File identifier.
* [YARA](https://plusvic.github.io/yara/) - Pattern matching tool for
  analysts.
* [Yara rules generator](https://github.com/Neo23x0/yarGen) - Generate
  yara rules based on a set of malware samples. Also contains a good
  strings DB to avoid false positives.

## Online Scanners and Sandboxes

*Web-based multi-AV scanners, and malware sandboxes for automated analysis.*

* [AndroTotal](https://andrototal.org/) - free online analysis of APKs
  against multiple mobile antivirus apps.
* [Anubis](https://anubis.iseclab.org/) - Malware Analysis for Unknown Binaries
  and Site Check.
* [AVCaesar](https://avcaesar.malware.lu/) - Malware.lu online scanner and
  malware repository.
* [Cryptam](http://www.cryptam.com/) - Analyze suspicious office documents.
* [Cuckoo Sandbox](http://cuckoosandbox.org/) - Open source, self hosted
  sandbox and automated analysis system.
* [cuckoo-modified](https://github.com/brad-accuvant/cuckoo-modified) - Modified
  version of Cuckoo Sandbox released under the GPL. Not merged upstream due to
  legal concerns by the author.
* [DeepViz](https://www.deepviz.com/) - Multi-format file analyzer with
  machine-learning classification.
* [DRAKVUF](https://github.com/tklengyel/drakvuf) - Dynamic malware analysis
  system.
* [Hybrid Analysis](https://www.hybrid-analysis.com/) - Online malware
  analysis tool, powered by VxSandbox.
* [IRMA](http://irma.quarkslab.com/) - An asynchronous and customizable
  analysis platform for suspicious files.
* [Jotti](https://virusscan.jotti.org/en) - Free online multi-AV scanner.
* [Malheur](https://github.com/rieck/malheur) - Automatic sandboxed analysis
  of malware behavior.
* [Malwr](https://malwr.com/) - Free analysis with an online Cuckoo Sandbox
  instance.
* [MASTIFF Online](https://mastiff-online.korelogic.com/) - Online static
  analysis of malware.
* [Metascan Online](https://live.metascan-online.com/) - Free file scanning
  with multiple antivirus engines.
* [Noriben](https://github.com/Rurik/Noriben) - Uses Sysinternals Procmon to
  collect information about malware in a sandboxed environment.
* [PDF Examiner](http://www.pdfexaminer.com/) - Analyse suspicious PDF files.
* [Recomposer](https://github.com/secretsquirrel/recomposer) - A helper
  script for safely uploading binaries to sandbox sites.
* [SEE](https://github.com/F-Secure/see) - Sandboxed Execution Environment (SEE) 
  is a framework for building test automation in secured Environments.
* [VirusTotal](https://www.virustotal.com/) - Free online analysis of malware
  samples and URLs
* [Zeltser's List](https://zeltser.com/automated-malware-analysis/) - Free
  automated sandboxes and services, compiled by Lenny Zeltser.

## Domain Analysis

*Inspect domains and IP addresses.*

* [Desenmascara.me](http://desenmascara.me) - One click tool to retrieve as
  much metadata as possible for a website and to assess its good standing.
* [Dig](http://networking.ringofsaturn.com/) - Free online dig and other
  network tools.
* [IPinfo](https://github.com/hiddenillusion/IPinfo) - Gather information
  about an IP or domain by searching online resources.
* [MaltegoVT](https://github.com/jiachongzhi/MaltegoVT) - Maltego
  transform for the VirusTotal API. Allows domain/IP research, and searching
  for file hashes and scan reports.
* [SenderBase](http://www.senderbase.org/) - Search for IP, domain or network
  owner.
* [SpamCop](https://www.spamcop.net/bl.shtml) - IP based spam block list.
* [SpamHaus](http://www.spamhaus.org/lookup/) - Block list based on
  domains and IPs.
* [Sucuri SiteCheck](https://sitecheck.sucuri.net/) - Free Website Malware
  and Security Scanner.
* [TekDefense Automator](http://www.tekdefense.com/automater/) - OSINT tool
  for gatherig information about URLs, IPs, or hashes.
* [URLQuery](https://urlquery.net/) - Free URL Scanner.
* [Whois](http://whois.domaintools.com/) - DomainTools free online whois
  search.
* [Zeltser's List](https://zeltser.com/lookup-malicious-websites/) - Free
  online tools for researching malicious websites, compiled by Lenny Zeltser.
* [ZScalar Zulu](http://zulu.zscaler.com/#) - Zulu URL Risk Analyzer.

## Browser Malware

*Analyze malicious URLs. See also the [domain analysis](#domain-analysis) and
[documents and shellcode](#documents-and-shellcode) sections.*

* [Firebug](http://getfirebug.com/) - Firefox extension for web development.
* [Java Decompiler](http://jd.benow.ca/) - Decompile and inspect Java apps.
* [Java IDX Parser](https://github.com/Rurik/Java_IDX_Parser/) - Parses Java
  IDX cache files.
* [JSDetox](http://www.relentless-coding.com/projects/jsdetox/) - JavaScript
  malware analysis tool.
* [jsunpack-n](https://github.com/urule99/jsunpack-n) - A javascript
  unpacker that emulates browser functionality.
* [Malzilla](http://malzilla.sourceforge.net/) - Analyze malicious web pages.
* [RABCDAsm](https://github.com/CyberShadow/RABCDAsm) - A "Robust
  ActionScript Bytecode Disassembler."
* [swftools](http://www.swftools.org/) - Tools for working with Adobe Flash
  files.
* [xxxswf](http://hooked-on-mnemonics.blogspot.com/2011/12/xxxswfpy.html) - A
  Python script for analyzing Flash files.

## Documents and Shellcode

*Analyze malicious JS and shellcode from PDFs and Office documents. See also
the [browser malware](#browser-malware) section.*

* [AnalyzePDF](https://github.com/hiddenillusion/AnalyzePDF) - A tool for
  analyzing PDFs and attempting to determine whether they are malicious.
* [diStorm](http://www.ragestorm.net/distorm/) - Disassembler for analyzing
  malicious shellcode.
* [JS Beautifier](http://jsbeautifier.org/) - JavaScript unpacking and deobfuscation.
* [JS Deobfuscator](http://www.kahusecurity.com/2015/new-javascript-deobfuscator-tool/) -
  Deobfuscate simple Javascript that use eval or document.write to conceal
  its code.
* [libemu](http://libemu.carnivore.it/) - Library and tools for x86 shellcode
  emulation.
* [malpdfobj](https://github.com/9b/malpdfobj) - Deconstruct malicious PDFs
  into a JSON representation.
* [OfficeMalScanner](http://www.reconstructer.org/code.html) - Scan for
  malicious traces in MS Office documents.
* [olevba](http://www.decalage.info/python/olevba) - A script for parsing OLE
  and OpenXML documents and extracting useful information.
* [Origami PDF](https://code.google.com/p/origami-pdf/) - A tool for
  analyzing malicious PDFs, and more.
* [PDF Tools](http://blog.didierstevens.com/programs/pdf-tools/) - pdfid,
  pdf-parser, and more from Didier Stevens.
* [PDF X-Ray Lite](https://github.com/9b/pdfxray_lite) - A PDF analysis tool,
  the backend-free version of PDF X-RAY.
* [peepdf](http://eternal-todo.com/tools/peepdf-pdf-analysis-tool) - Python
  tool for exploring possibly malicious PDFs.
* [Spidermonkey](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/SpiderMonkey) -
  Mozilla's JavaScript engine, for debugging malicious JS.

## File Carving

*For extracting files from inside disk and memory images.*

* [bulk_extractor](https://github.com/simsong/bulk_extractor) - Fast file
  carving tool.
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - Carve Windows
  Event Log files from raw binary data.
* [Foremost](http://foremost.sourceforge.net/) - File carving tool designed
  by the US Air Force.
* [Hachoir](https://bitbucket.org/haypo/hachoir) - A collection of Python
  libraries for dealing with binary files.
* [Scalpel](https://github.com/sleuthkit/scalpel) - Another data carving
  tool.

## Deobfuscation

*Reverse XOR and other code obfuscation methods.*

* [Balbuzard](https://bitbucket.org/decalage/balbuzard/wiki/Home) - A malware
  analysis tool for reversing obfuscation (XOR, ROL, etc) and more.
* [de4dot](https://github.com/0xd4d/de4dot) - .NET deobfuscator and
  unpacker.
* [ex_pe_xor](http://hooked-on-mnemonics.blogspot.com/2014/04/expexorpy.html)
  & [iheartxor](http://hooked-on-mnemonics.blogspot.com/p/iheartxor.html) -
  Two tools from Alexander Hanel for working with single-byte XOR encoded
  files.
* [NoMoreXOR](https://github.com/hiddenillusion/NoMoreXOR) - Guess a 256 byte
  XOR key using frequency analysis.
* [PackerAttacker](https://github.com/BromiumLabs/PackerAttacker) - A generic
  hidden code extractor for Windows malware.
* [unxor](https://github.com/tomchop/unxor/) - Guess XOR keys using
  known-plaintext attacks.
* [VirtualDeobfuscator](https://github.com/jnraber/VirtualDeobfuscator) -
  Reverse engineering tool for virtualization wrappers.
* [XORBruteForcer](http://eternal-todo.com/var/scripts/xorbruteforcer) -
  A Python script for brute forcing single-byte XOR keys.
* [XORSearch & XORStrings](http://blog.didierstevens.com/programs/xorsearch/) -
  A couple programs from Didier Stevens for finding XORed data.
* [xortool](https://github.com/hellman/xortool) - Guess XOR key length, as
  well as the key itself.

## Debugging and Reverse Engineering

*Disassemblers, debuggers, and other static and dynamic analysis tools.*

* [angr](https://github.com/angr/angr) - Platform-agnostic binary analysis
  framework developed at UCSB's Seclab.
* [BARF](https://github.com/programa-stic/barf-project) - Multiplatform, open
  source Binary Analysis and Reverse engineering Framework.
* [binnavi](https://github.com/google/binnavi) - Binary analysis IDE for
  reverse engineering based on graph visualization.
* [Bokken](https://inguma.eu/projects/bokken) - GUI for Pyew and Radare.
* [Capstone](https://github.com/aquynh/capstone) - Disassembly framework for
  binary analysis and reversing, with support for many architectures and
  bindings in several languages.
* [codebro](https://github.com/hugsy/codebro) - Web based code browser using
  clang to provide basic code analysis.
* [dnSpy](https://github.com/0xd4d/dnSpy) - .NET assembly editor, decompiler
  and debugger.
* [Evan's Debugger (EDB)](http://codef00.com/projects#debugger) - A
  modular debugger with a Qt GUI.
* [GDB](http://www.sourceware.org/gdb/) - The GNU debugger.
* [GEF](https://github.com/hugsy/gef) - GDB Enhanced Features, for exploiters
  and reverse engineers.
* [hackers-grep](https://github.com/codypierce/hackers-grep) - A utility to
  search for strings in PE executables including imports, exports, and debug
  symbols.
* [IDA Pro](https://www.hex-rays.com/products/ida/index.shtml) - Windows
  disassembler and debugger, with a free evaluation version.
* [Immunity Debugger](http://debugger.immunityinc.com/) - Debugger for
  malware analysis and more, with a Python API.
* [ltrace](http://ltrace.org/) - Dynamic analysis for Linux executables.
* [objdump](https://en.wikipedia.org/wiki/Objdump) - Part of GNU binutils,
  for static analysis of Linux binaries.
* [OllyDbg](http://www.ollydbg.de/) - An assembly-level debugger for Windows
  executables.
* [PANDA](https://github.com/moyix/panda) - Platform for Architecture-Neutral Dynamic Analysis
* [PEDA](https://github.com/longld/peda) - Python Exploit Development
  Assistance for GDB, an enhanced display with added commands.
* [pestudio](https://winitor.com/) - Perform static analysis of Windows
  executables.
* [Process Monitor](https://technet.microsoft.com/en-us/sysinternals/bb896645.aspx) -
  Advanced monitoring tool for Windows programs.
* [Pyew](https://github.com/joxeankoret/pyew) - Python tool for malware
  analysis.
* [Radare2](http://www.radare.org/r/) - Reverse engineering framework, with
  debugger support.
* [SMRT](https://github.com/pidydx/SMRT) - Sublime Malware Research Tool, a
  plugin for Sublime 3 to aid with malware analyis.
* [strace](http://sourceforge.net/projects/strace/) - Dynamic analysis for
  Linux executables.
* [Udis86](https://github.com/vmt/udis86) - Disassembler library and tool
  for x86 and x86_64.
* [Vivisect](https://github.com/vivisect/vivisect) - Python tool for
  malware analysis.
* [X64dbg](https://github.com/x64dbg/) - An open-source x64/x32 debugger for windows.

## Network

*Analyze network interactions.*

* [Bro](https://www.bro.org) - Protocol analyzer that operates at incredible
  scale; both file and network protocols.
* [BroYara](https://github.com/hempnall/broyara) - Use Yara rules from Bro.
* [CapTipper](https://github.com/omriher/CapTipper) -  Malicious HTTP traffic
  explorer.
* [chopshop](https://github.com/MITRECND/chopshop) - Protocol analysis and
  decoding framework.
* [Fiddler](http://www.telerik.com/fiddler) - Intercepting web proxy designed
  for "web debugging."
* [Hale](https://github.com/pjlantz/Hale) - Botnet C&C monitor.
* [INetSim](http://www.inetsim.org/) - Network service emulation, useful when
  building a malware lab.
* [Malcom](https://github.com/tomchop/malcom) - Malware Communications
  Analyzer.
* [Maltrail](https://github.com/stamparm/maltrail) - A malicious traffic 
  detection system, utilizing publicly available (black)lists containing 
  malicious and/or generally suspicious trails and featuring an reporting
  and analysis interface.
* [mitmproxy](https://mitmproxy.org/) - Intercept network traffic on the fly.
* [Moloch](https://github.com/aol/moloch) - IPv4 traffic capturing, indexing
  and database system.
* [NetworkMiner](http://www.netresec.com/?page=NetworkMiner) - Network
  forensic analysis tool, with a free version.
* [ngrep](http://ngrep.sourceforge.net/) - Search through network traffic
  like grep.
* [PcapViz](https://github.com/mateuszk87/PcapViz) - Network topology and traffic visualizer.
* [Tcpdump](http://www.tcpdump.org/) - Collect network traffic.
* [tcpick](http://tcpick.sourceforge.net/) - Trach and reassemble TCP streams
  from network traffic.
* [tcpxtract](http://tcpxtract.sourceforge.net/) - Extract files from network
  traffic.
* [Wireshark](https://www.wireshark.org/) - The network traffic analysis
  tool.

## Memory Forensics

*Tools for dissecting malware in memory images or running systems.*

* [DAMM](https://github.com/504ensicsLabs/DAMM) - Differential Analysis of
  Malware in Memory, built on Volatility
* [FindAES](http://jessekornblum.livejournal.com/269749.html) - Find AES
  encryption keys in memory.
* [Muninn](https://github.com/ytisf/muninn) - A script to automate portions
  of analysis using Volatility, and create a readable report.
* [Rekall](http://www.rekall-forensic.com/) - Memory analysis framework,
  forked from Volatility in 2013.
* [TotalRecall](https://github.com/sketchymoose/TotalRecall) - Script based
  on Volatility for automating various malware analysis tasks.
* [VolDiff](https://github.com/aim4r/VolDiff) - Run Volatility on memory
  images before and after malware execution, and report changes.
* [Volatility](https://github.com/volatilityfoundation/volatility) - Advanced
  memory forensics framework.
* [WinDbg](https://msdn.microsoft.com/en-us/windows/hardware/hh852365) - Live
  memory inspection and kernel debugging for Windows systems.

## Windows Artifacts

* [AChoir](https://github.com/OMENScan/AChoir) - A live incident response
  script for gathering Windows artifacts.
* [python-evt](https://github.com/williballenthin/python-evt) - Python
  library for parsing Windows Event Logs.
* [python-registry](http://www.williballenthin.com/registry/) - Python
  library for parsing registry files.
* [RegRipper](http://brettshavers.cc/index.php/brettsblog/tags/tag/regripper/)
  ([GitHub](https://github.com/keydet89/RegRipper2.8)) -
  Plugin-based registry analysis tool.

## Storage and Workflow

* [Aleph](https://github.com/trendmicro/aleph) - OpenSource Malware Analysis
  Pipeline System.
* [CRITs](https://crits.github.io/) - Collaborative Research Into Threats, a
  malware and threat repository.
* [Malwarehouse](https://github.com/sroberts/malwarehouse) - Store, tag, and
  search malware.
* [Viper](http://viper.li/) - A binary management and analysis framework for
  analysts and researchers.

## Miscellaneous

* [DC3-MWCP](https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP) -
  The Defense Cyber Crime Center's Malware Configuration Parser framework.
* [Pafish](https://github.com/a0rtega/pafish) - Paranoid Fish, a demonstration
  tool that employs several techniques to detect sandboxes and analysis
  environments in the same way as malware families do.
* [REMnux](https://remnux.org/) - Linux distribution and docker images for
  malware reverse engineering and analysis.
* [Santoku Linux](https://santoku-linux.com/) - Linux distribution for mobile
  forensics, malware analysis, and security.

# Resources

## Books

*Essential malware analysis reading material.*

* [Malware Analyst's Cookbook and DVD](https://amzn.com/dp/0470613033) -
  Tools and Techniques for Fighting Malicious Code.
* [Practical Malware Analysis](https://amzn.com/dp/1593272901) - The Hands-On Guide
  to Dissecting Malicious Software.
* [The Art of Memory Forensics](https://amzn.com/dp/1118825098) - Detecting
  Malware and Threats in Windows, Linux, and Mac Memory.
* [The IDA Pro Book](https://amzn.com/dp/1593272898) - The Unofficial Guide
  to the World's Most Popular Disassembler.

## Twitter

*Some relevant Twitter accounts.*

* Adamb [@Hexacorn](https://twitter.com/Hexacorn)
* Andrew Case [@attrc](https://twitter.com/attrc)
* Claudio [@botherder](https://twitter.com/botherder)
* Dustin Webber [@mephux](https://twitter.com/mephux)
* Glenn [@hiddenillusion](https://twitter.com/hiddenillusion)
* jekil [@jekil](https://twitter.com/jekil)
* Jurriaan Bremer [@skier_t](https://twitter.com/skier_t)
* Lenny Zeltser [@lennyzeltser](https://twitter.com/lennyzeltser)
* Liam Randall [@hectaman](https://twitter.com/hectaman)
* Mark Schloesser [@repmovsb](https://twitter.com/repmovsb)
* Michael Ligh (MHL) [@iMHLv2](https://twitter.com/iMHLv2)
* Open Malware [@OpenMalware](https://twitter.com/OpenMalware)
* Richard Bejtlich [@taosecurity](https://twitter.com/taosecurity)
* Volatility [@volatility](https://twitter.com/volatility)

## Other

* [APT Notes](https://github.com/kbandla/APTnotes) - A collection of papers
  and notes related to Advanced Persistent Threats.
* [Honeynet Project](http://honeynet.org/) - Honeypot tools, papers, and
  other resources.
* [Malicious Software](https://zeltser.com/malicious-software/) - Malware
  blog and resources by Lenny Zeltser.
* [Malware Analysis Search](https://cse.google.com/cse/home?cx=011750002002865445766%3Apc60zx1rliu) -
  Custom Google search engine from [Corey Harrell](journeyintoir.blogspot.com/).
* [WindowsIR: Malware](http://windowsir.blogspot.com/p/malware.html) - Harlan
  Carvey's page on Malware.
* [/r/csirt_tools](https://www.reddit.com/r/csirt_tools/) - Subreddit for CSIRT
  tools and resources, with a
  [malware analysis](https://www.reddit.com/r/csirt_tools/search?q=flair%3A%22Malware%20analysis%22&sort=new&restrict_sr=on) flair.
* [/r/Malware](https://www.reddit.com/r/Malware) - The malware subreddit.
* [/r/ReverseEngineering](https://www.reddit.com/r/ReverseEngineering) -
  Reverse engineering subreddit, not limited to just malware.
* [Malware Samples and Traffic](http://malware-traffic-analysis.net/) - This
  blog focuses on network traffic related to malware infections.

- [Online Resources](#online-resources)
  - [Penetration Testing Resources](#penetration-testing-resources)
  - [Shellcode development](#shellcode-development)
  - [Social Engineering Resources](#social-engineering-resources)
  - [Lock Picking Resources](#lock-picking-resources)
- [Tools](#tools)
  - [Penetration Testing Distributions](#penetration-testing-distributions)
  - [Basic Penetration Testing Tools](#basic-penetration-testing-tools)
  - [Vulnerability Scanners](#vulnerability-scanners)
  - [Network Tools](#network-tools)
  - [Wireless Network Tools](#wireless-network-tools)
  - [SSL Analysis Tools](#ssl-analysis-tools)
  - [Hex Editors](#hex-editors)
  - [Crackers](#crackers)
  - [Windows Utils](#windows-utils)
  - [DDoS Tools](#ddos-tools)
  - [Social Engineering Tools](#social-engineering-tools)
  - [OSInt Tools](#osint-tools)
  - [Anonimity Tools](#anonimity-tools)
  - [Reverse Engineering Tools](#reverse-engineering-tools)
- [Books](#books)
  - [Penetration Testing Books](#penetration-testing-books)
  - [Hackers Handbook Series](#hackers-handbook-series)
  - [Network Analysis Books](#network-analysis-books)
  - [Reverse Engineering Books](#reverse-engineering-books)
  - [Malware Analysis Books](#malware-analysis-books)
  - [Windows Books](#windows-books)
  - [Social Engineering Books](#social-engineering-books)
  - [Lock Picking Books](#lock-picking-books)
- [Vulnerability Databases](#vulnerability-databases)
- [Security Courses](#security-courses)
- [Information Security Conferences](#information-security-conferences)
- [Information Security Magazines](#information-security-magazines)



### Online Resources
#### Penetration Testing Resources
* [Metasploit Unleashed](http://www.offensive-security.com/metasploit-unleashed/) - Free Offensive Security metasploit course
* [PTES](http://www.pentest-standard.org/) - Penetration Testing Execution Standard
* [OWASP](https://www.owasp.org/index.php/Main_Page) - Open Web Application Security Project 

#### Shellcode development
* [Shellcode Tutorials](http://www.projectshellcode.com/?q=node/12) - Tutorials on how to write shellcode
* [Shellcode Examples](http://shell-storm.org/shellcode/) - Shellcodes database

#### Social Engineering Resources
* [Social Engineering Framework](http://www.social-engineer.org/framework/) - An information resource for social engineers

#### Lock Picking Resources
* [Schuyler Towne channel](http://www.youtube.com/user/SchuylerTowne/) - Lockpicking videos and security talks
* [/r/lockpicking](https://www.reddit.com/r/lockpicking) - Resources for learning lockpicking, equipment recommendations.

### Tools
#### Penetration Testing Distributions
* [Kali](http://www.kali.org/) - A Linux distribution designed for digital forensics and penetration testing
* [BlackArch](http://www.blackarch.org/) - Arch Linux-based distribution for penetration testers and security researchers
* [NST](http://networksecuritytoolkit.org/) - Network Security Toolkit distribution 
* [Pentoo](http://www.pentoo.ch/) -  security-focused livecd based on Gentoo
* [BackBox](http://www.backbox.org/) - Ubuntu-based distribution for penetration tests and security assessments

#### Basic Penetration Testing Tools
* [Metasploit Framework](http://www.metasploit.com/) - World's most used penetration testing software
* [Burp Suite](http://portswigger.net/burp/) - An integrated platform for performing security testing of web applications
* [ExploitPack](http://exploitpack.com/) - Graphical tool for penetration testing with a bunch of exploits

#### Vulnerability Scanners
* [Netsparker](https://www.netsparker.com/communityedition/) - Web Application Security Scanner
* [Nexpose](https://www.rapid7.com/products/nexpose/) - Vulnerability Management & Risk Management Software
* [Nessus](http://www.tenable.com/products/nessus) - Vulnerability, configuration, and compliance assessment
* [Nikto](https://cirt.net/nikto2) - Web application vulnerability scanner
* [OpenVAS](http://www.openvas.org/) - Open Source vulnerability scanner and manager
* [OWASP Zed Attack Proxy](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) - Penetration testing tool for web applications
* [Secapps](https://secapps.com/) - Integrated web application security testing environment
* [w3af](https://github.com/andresriancho/w3af) - Web application attack and audit framework
* [Wapiti](http://wapiti.sourceforge.net/) - Web application vulnerability scanner
* [WebReaver](http://www.webreaver.com/) - Web application vulnerability scanner for Mac OS X

#### Network Tools
* [nmap](http://nmap.org/) - Free Security Scanner For Network Exploration & Security Audits
* [tcpdump/libpcap](http://www.tcpdump.org/) - A common packet analyzer that runs under the command line
* [Wireshark](http://www.wireshark.org/) - A network protocol analyzer for Unix and Windows
* [Network Tools](http://network-tools.com/) - Different network tools: ping, lookup, whois, etc
* [netsniff-ng](https://github.com/netsniff-ng/netsniff-ng) - A Swiss army knife for for network sniffing
* [Intercepter-NG](http://intercepter.nerf.ru/) - a multifunctional network toolkit
* [SPARTA](http://sparta.secforce.com/) - Network Infrastructure Penetration Testing Tool

#### Wireless Network Tools
 * [Aircrack-ng](http://www.aircrack-ng.org/) - a set of tools for auditing wireless network
 * [Kismet](https://kismetwireless.net/) - Wireless network detector, sniffer, and IDS
 * [Reaver](https://code.google.com/p/reaver-wps/) - Brute force attack against Wifi Protected Setup

#### SSL Analysis Tools
* [SSLyze](https://github.com/nabla-c0d3/sslyze) - SSL configuration scanner
* [sslstrip](http://www.thoughtcrime.org/software/sslstrip/) - a demonstration of the HTTPS stripping attacks

#### Hex Editors
* [HexEdit.js](http://hexed.it/) - Browser-based hex editing

#### Crackers
* [John the Ripper](http://www.openwall.com/john/) - Fast password cracker
* [Online MD5 cracker](http://www.md5crack.com/) - Online MD5 hash Cracker

#### Windows Utils
* [Sysinternals Suite](http://technet.microsoft.com/en-us/sysinternals/bb842062) - The Sysinternals Troubleshooting Utilities
* [Windows Credentials Editor](http://www.ampliasecurity.com/research/windows-credentials-editor/) - security tool to list logon sessions and add, change, list and delete associated credentials
* [mimikatz](http://blog.gentilkiwi.com/mimikatz) - Credentials extraction tool for Windows OS

#### DDoS Tools
* [LOIC](https://github.com/NewEraCracker/LOIC/) - An open source network stress tool for Windows
* [JS LOIC](http://metacortexsecurity.com/tools/anon/LOIC/LOICv1.html) - JavaScript in-browser version of LOIC

#### Social Engineering Tools
* [SET](https://github.com/trustedsec/social-engineer-toolkit) - The Social-Engineer Toolkit from TrustedSec

#### OSInt Tools
* [Maltego](http://www.paterva.com/web6/products/maltego.php) - Proprietary software for open source intelligence and forensics, from Paterva.

#### Anonimity Tools
* [Tor](https://www.torproject.org/) - The free software for enabling onion routing online anonymity
* [I2P](https://geti2p.net) - The Invisible Internet Project

#### Reverse Engineering Tools
* [IDA Pro](https://www.hex-rays.com/products/ida/) - A Windows, Linux or Mac OS X hosted multi-processor disassembler and debugger
* [IDA Free](https://www.hex-rays.com/products/ida/support/download_freeware.shtml) - The freeware version of IDA v5.0
* [WDK/WinDbg](http://msdn.microsoft.com/en-us/windows/hardware/hh852365.aspx) - Windows Driver Kit and WinDbg
* [OllyDbg](http://www.ollydbg.de/) - An x86 debugger that emphasizes binary code analysis
* [Radare2](http://rada.re/r/index.html) - Opensource, crossplatform reverse engineering framework.
* [x64_dbg](http://x64dbg.com/) - An open-source x64/x32 debugger for windows.
* [Pyew](http://code.google.com/p/pyew/) - A Python tool for static malware analysis.
* [Bokken](https://inguma.eu/projects/bokken) - GUI for Pyew Radare2.
* [Immunity Debugger](http://debugger.immunityinc.com/) - A powerful new way to write exploits and analyze malware
* [Evan's Debugger](http://www.codef00.com/projects#debugger) - OllyDbg-like debugger for Linux


### Books
#### Penetration Testing Books
* [The Art of Exploitation by Jon Erickson, 2008](http://www.nostarch.com/hacking2.htm)
* [Metasploit: The Penetration Tester's Guide by David Kennedy and others, 2011](http://www.nostarch.com/metasploit)
* [Penetration Testing: A Hands-On Introduction to Hacking by Georgia Weidman, 2014](http://www.nostarch.com/pentesting)
* [Rtfm: Red Team Field Manual by Ben Clark, 2014](http://www.amazon.com/Rtfm-Red-Team-Field-Manual/dp/1494295504/)
* [The Hacker Playbook by Peter Kim, 2014](http://www.amazon.com/The-Hacker-Playbook-Practical-Penetration/dp/1494932636/)
* [The Basics of Hacking and Penetration Testing by Patrick Engebretson, 2013](https://www.elsevier.com/books/the-basics-of-hacking-and-penetration-testing/engebretson/978-1-59749-655-1)
* [Professional Penetration Testing by Thomas Wilhelm, 2013](https://www.elsevier.com/books/professional-penetration-testing/wilhelm/978-1-59749-993-4)
* [Advanced Penetration Testing for Highly-Secured Environments by Lee Allen,2012](http://www.packtpub.com/advanced-penetration-testing-for-highly-secured-environments/book)
* [Violent Python by TJ O'Connor, 2012](http://www.elsevier.com/books/violent-python/unknown/978-1-59749-957-6)
* [Fuzzing: Brute Force Vulnerability Discovery by Michael Sutton, Adam Greene, Pedram Amini, 2007](http://www.fuzzing.org/)
* [Black Hat Python: Python Programming for Hackers and Pentesters, 2014](http://www.amazon.com/Black-Hat-Python-Programming-Pentesters/dp/1593275900)
* [Penetration Testing: Procedures & Methodologies (EC-Council Press),2010](http://www.amazon.com/Penetration-Testing-Procedures-Methodologies-EC-Council/dp/1435483677)

#### Hackers Handbook Series
* [The Shellcoders Handbook by Chris Anley and others, 2007](http://wiley.com/WileyCDA/WileyTitle/productCd-047008023X.html)
* [The Web Application Hackers Handbook by D. Stuttard, M. Pinto, 2011](http://wiley.com/WileyCDA/WileyTitle/productCd-1118026470.html)
* [iOS Hackers Handbook by Charlie Miller and others, 2012](http://wiley.com/WileyCDA/WileyTitle/productCd-1118204123.html)
* [Android Hackers Handbook by Joshua J. Drake and others, 2014](http://wiley.com/WileyCDA/WileyTitle/productCd-111860864X.html)
* [The Browser Hackers Handbook by Wade Alcorn and others, 2014](http://wiley.com/WileyCDA/WileyTitle/productCd-1118662091.html)
* [The Mobile Application Hackers Handbook by Dominic Chell and others, 2015](http://wiley.com/WileyCDA/WileyTitle/productCd-1118958500.html)

#### Network Analysis Books
* [Nmap Network Scanning by Gordon Fyodor Lyon, 2009](http://nmap.org/book/)
* [Practical Packet Analysis by Chris Sanders, 2011](http://www.nostarch.com/packet2.htm)
* [Wireshark Network Analysis by by Laura Chappell, Gerald Combs, 2012](http://www.wiresharkbook.com/)

#### Reverse Engineering Books
* [Reverse Engineering for Beginners by Dennis Yurichev (free!)](http://beginners.re/)
* [The IDA Pro Book by Chris Eagle, 2011](http://www.nostarch.com/idapro2.htm)
* [Practical Reverse Engineering by Bruce Dang and others, 2014](http://wiley.com/WileyCDA/WileyTitle/productCd-1118787315.html)
* [Reverse Engineering for Beginners](http://beginners.re/)

#### Malware Analysis Books
* [Practical Malware Analysis by Michael Sikorski, Andrew Honig, 2012](http://www.nostarch.com/malware)
* [The Art of Memory Forensics by Michael Hale Ligh and others, 2014](http://wiley.com/WileyCDA/WileyTitle/productCd-1118825098.html)
* [Malware Analyst's Cookbook and DVD by Michael Hale Ligh and others, 2010](http://www.wiley.com/WileyCDA/WileyTitle/productCd-0470613033.html)

#### Windows Books
* [Windows Internals by Mark Russinovich, David Solomon, Alex Ionescu](http://technet.microsoft.com/en-us/sysinternals/bb963901.aspx)

#### Social Engineering Books
* [The Art of Deception by Kevin D. Mitnick, William L. Simon, 2002](http://wiley.com/WileyCDA/WileyTitle/productCd-0471237124.html)
* [The Art of Intrusion by Kevin D. Mitnick, William L. Simon, 2005](http://wiley.com/WileyCDA/WileyTitle/productCd-0764569597.html)
* [Ghost in the Wires by Kevin D. Mitnick, William L. Simon, 2011](http://www.hachettebookgroup.com/titles/kevin-mitnick/ghost-in-the-wires/9780316134477/)
* [No Tech Hacking by Johnny Long, Jack Wiles, 2008](http://www.elsevier.com/books/no-tech-hacking/mitnick/978-1-59749-215-7)
* [Social Engineering: The Art of Human Hacking by Christopher Hadnagy, 2010](http://wiley.com/WileyCDA/WileyTitle/productCd-0470639539.html)
* [Unmasking the Social Engineer: The Human Element of Security by Christopher Hadnagy, 2014](http://wiley.com/WileyCDA/WileyTitle/productCd-1118608577.html)
* [Social Engineering in IT Security: Tools, Tactics, and Techniques by Sharon Conheady, 2014](http://www.mhprofessional.com/product.php?isbn=0071818464)

#### Lock Picking Books
* [Practical Lock Picking by Deviant Ollam, 2012](https://www.elsevier.com/books/practical-lock-picking/ollam/978-1-59749-989-7)
* [Keys to the Kingdom by Deviant Ollam, 2012](https://www.elsevier.com/books/keys-to-the-kingdom/ollam/978-1-59749-983-5)
* [CIA Lock Picking Field Operative Training Manual](http://www.scribd.com/doc/7207/CIA-Lock-Picking-Field-Operative-Training-Manual)
* [Lock Picking: Detail Overkill by Solomon](https://www.dropbox.com/s/y39ix9u9qpqffct/Lockpicking%20Detail%20Overkill.pdf?dl=0)
* [Eddie the Wire books](https://www.dropbox.com/sh/k3z4dm4vyyojp3o/AAAIXQuwMmNuCch_StLPUYm-a?dl=0)


### Vulnerability Databases
* [NVD](http://nvd.nist.gov/) - US National Vulnerability Database
* [CERT](http://www.us-cert.gov/) - US Computer Emergency Readiness Team
* [OSVDB](http://osvdb.org/) - Open Sourced Vulnerability Database
* [Bugtraq](http://www.securityfocus.com/) - Symantec SecurityFocus
* [Exploit-DB](http://www.exploit-db.com/) - Offensive Security Exploit Database
* [Fulldisclosure](http://seclists.org/fulldisclosure/) - Full Disclosure Mailing List
* [MS Bulletin](https://technet.microsoft.com/security/bulletin/) - Microsoft Security Bulletin
* [MS Advisory](https://technet.microsoft.com/security/advisory/) - Microsoft Security Advisories
* [Inj3ct0r](http://1337day.com/) - Inj3ct0r Exploit Database
* [Packet Storm](http://packetstormsecurity.com/) - Packet Storm Global Security Resource
* [SecuriTeam](http://www.securiteam.com/) - Securiteam Vulnerability Information
* [CXSecurity](http://cxsecurity.com/) - CSSecurity Bugtraq List
* [Vulnerability Laboratory](http://www.vulnerability-lab.com/) - Vulnerability Research Laboratory
* [ZDI](http://www.zerodayinitiative.com/) - Zero Day Initiative


### Security Courses
* [Offensive Security Training](http://www.offensive-security.com/information-security-training/) - Training from BackTrack/Kali developers
* [SANS Security Training](http://www.sans.org/) - Computer Security Training & Certification
* [Open Security Training](http://opensecuritytraining.info/) - Training material for computer security classes
* [CTF Field Guide](https://trailofbits.github.io/ctf/) - everything you need to win your next CTF competition
* [Cybrary](https://www.cybrary.it/) - online IT and Cyber Security training platform


### Information Security Conferences
* [DEF CON](https://www.defcon.org/) - An annual hacker convention in Las Vegas
* [Black Hat](http://www.blackhat.com/) - An annual security conference in Las Vegas
* [BSides](http://www.securitybsides.com/) - A framework for organising and holding security conferences
* [CCC](http://events.ccc.de/congress/) - An annual meeting of the international hacker scene in Germany
* [DerbyCon](https://www.derbycon.com/) - An annual hacker conference based in Louisville
* [PhreakNIC](http://phreaknic.info/) - A technology conference held annually in middle Tennessee
* [ShmooCon](http://www.shmoocon.org/) - An annual US east coast hacker convention
* [CarolinaCon](http://www.carolinacon.org/) - An infosec conference, held annually in North Carolina
* [HOPE](http://hope.net/) - A conference series sponsored by the hacker magazine 2600
* [SummerCon](http://www.summercon.org/) - One of the oldest hacker conventions, held during Summer
* [Hack.lu](http://hack.lu/) - An annual conference held in Luxembourg
* [HITB](http://conference.hitb.org/) - Deep-knowledge security conference held in Malaysia and The Netherlands
* [Troopers](https://www.troopers.de) - Annual international IT Security event with workshops held in Heidelberg, Germany
* [Hack3rCon](http://hack3rcon.org/) - An annual US hacker conference
* [ThotCon](http://thotcon.org/) - An annual US hacker conference held in Chicago
* [LayerOne](http://www.layerone.org/) - An annual US security conerence held every spring in Los Angeles
* [DeepSec](https://deepsec.net/) - Security Conference in Vienna, Austria
* [SkyDogCon](http://www.skydogcon.com/) - A technology conference in Nashville
* [SECUINSIDE](http://secuinside.com) - Security Conference in [Seoul](http://en.wikipedia.org/wiki/Seoul)
* [DefCamp](http://defcamp.ro) - Largest Security Conference in Eastern Europe, held anually in Bucharest, Romania


### Information Security Magazines
* [2600: The Hacker Quarterly](http://www.2600.com/Magazine/DigitalEditions) - An American publication about technology and computer "underground"
* [Phrack Magazine](http://www.phrack.org/) - By far the longest running hacker zine


- [System](#system)
    - [Tutorials](#system-tutorials)
    - [Tools](#system-tools)
    - [General](#system-general)
- [Reverse Engineering](#reverse-engineering)
    - [Tutorials](#reverse-engineering-tutorials)
    - [Tools](#reverse-engineering-tools)
    - [General](#reverse-engineering-general)
- [Web](#web)
    - [Tutorials](#web-tutorials)
    - [Tools](#web-tools)
- [Network](#network)
    - [Tutorials](#network-tutorials)
    - [Tools](#network-tools)
- [Forensic](#forensic)
    - [Tutorials](#forensic-tutorials)
    - [Tools](#forensic-tools)
- [Cryptography](#cryptography)
    - [Tutorials](#cryptography-tutorials)
    - [Tools](#cryptography-tools)
- [Wargame](#wargame)
    - [System](#wargame-system)
    - [Reverse Engineering](#wargame-reverse-engineering)
    - [Web](#wargame-web)
    - [Network](#wargame-network)
    - [Forensic](#wargame-forensic)
    - [Cryptography](#wargame-cryptography)
- [CTF](#ctf)
    - [Competition](#ctf-competiton)
    - [General](#ctf-general)
- [General](#general)

<!-- /MarkdownTOC -->

<a name="system" />
# System

<a name="system-tutorial" />
## Tutorials
 * [Corelan Team's Exploit writing tutorial](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
 * [Exploit Writing Tutorials for Pentesters](http://www.punter-infosec.com/exploit-writing-tutorials-for-pentesters/)

<a name="system-tools" />
## Tools
 * [Metasploit](https://github.com/rapid7/metasploit-framework) A computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
 * [mimikatz](https://github.com/gentilkiwi/mimikatz) - A little tool to play with Windows security


<a name="system-general" />
## General
 * [Exploit database](https://www.exploit-db.com/) - An ultimate archive of exploits and vulnerable software


<a name="reverse-engineering" />
# Reverse Engineering

<a name="reverse-engineering-tutorial" />
## Tutorials
* [Lenas Reversing for Newbies](https://tuts4you.com/download.php?list.17)
* [Malware Analysis Tutorials: a Reverse Engineering Approach](http://fumalwareanalysis.blogspot.kr/p/malware-analysis-tutorials-reverse.html)

<a name="reverse-engineering-tools" />
## Tools
 * [IDA](https://www.hex-rays.com/products/ida/) - IDA is a Windows, Linux or Mac OS X hosted multi-processor disassembler and debugger
 * [OllyDbg](http://www.ollydbg.de/) - A 32-bit assembler level analysing debugger for Windows
 * [dex2jar](https://github.com/pxb1988/dex2jar) - Tools to work with android .dex and java .class files
 * [JD-GUI](http://jd.benow.ca/) - A standalone graphical utility that displays Java source codes of “.class” files
 * [androguard](https://code.google.com/p/androguard/) - Reverse engineering, Malware and goodware analysis of Android applications
 * [JAD](http://varaneckas.com/jad/) - JAD Java Decompiler
 * [dotPeek](https://www.jetbrains.com/decompiler/) - a free-of-charge .NET decompiler from JetBrains
 * [UPX](http://upx.sourceforge.net/) - the Ultimate Packer for eXecutables
 * [radare2](https://github.com/radare/radare2) - A portable reversing framework

<a name="reverse-engineering-general" />
## General
 * [Open Malware](http://www.offensivecomputing.net/)


<a name="web" />
# Web

<a name="web-tools" />
## Tools
 * [sqlmap](https://github.com/sqlmapproject/sqlmap) - Automatic SQL injection and database takeover tool
 * [tools.web-max.ca](http://tools.web-max.ca/encode_decode.php) - base64 base85 md4,5 hash, sha1 hash encoding/decoding


<a name="network" />
# Network

<a name="network-tools" />
## Tools
 * [Wireshark](https://www.wireshark.org/) - A free and open-source packet analyzer
 * [NetworkMiner](http://www.netresec.com/?page=NetworkMiner) - A Network Forensic Analysis Tool (NFAT)
 * [tcpdump](http://www.tcpdump.org/) - a powerful command-line packet analyzer; and libpcap, a portable C/C++ library for network traffic capture
 * [Paros](http://sourceforge.net/projects/paros/) - A Java based HTTP/HTTPS proxy for assessing web application vulnerability
 * [ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) - The Zed Attack Proxy (ZAP) is an easy to use integrated penetration testing tool for finding vulnerabilities in web applications
 * [mitmproxy](https://mitmproxy.org/) - An interactive, SSL-capable man-in-the-middle proxy for HTTP with a console interface
 * [mitmsocks4j](https://github.com/Akdeniz/mitmsocks4j) - Man in the Middle SOCKS Proxy for JAVA
 * [nmap](https://nmap.org/) - Nmap (Network Mapper) is a security scanner
 * [Aircrack-ng](http://www.aircrack-ng.org/) - An 802.11 WEP and WPA-PSK keys cracking program


<a name="forensic" />
# Forensic

<a name="forensic-tools" />
## Tools
 * [Autospy](http://www.sleuthkit.org/autopsy/) - A digital forensics platform and graphical interface to [The Sleuth Kit](http://www.sleuthkit.org/sleuthkit/index.php) and other digital forensics tools
 * [sleuthkit](https://github.com/sleuthkit/sleuthkit) - A library and collection of command line digital forensics tools
 * [EnCase](https://www.guidancesoftware.com/products/Pages/encase-forensic/overview.aspx) - the shared technology within a suite of digital investigations products by Guidance Software
 * [malzilla](http://malzilla.sourceforge.net/) - Malware hunting tool
 * [PEview](http://wjradburn.com/software/) - a quick and easy way to view the structure and content of 32-bit Portable Executable (PE) and Component Object File Format (COFF) files
 * [HxD](http://mh-nexus.de/en/hxd/) - A hex editor which, additionally to raw disk editing and modifying of main memory (RAM), handles files of any size
 * [WinHex](http://www.winhex.com/winhex/) - A hexadecimal editor, helpful in the realm of computer forensics, data recovery, low-level data processing, and IT security
 * [BinText](http://www.mcafee.com/kr/downloads/free-tools/bintext.aspx) - A small, very fast and powerful text extractor that will be of particular interest to programmers


# Cryptography

### Tools
 * [xortool](https://github.com/hellman/xortool) - A tool to analyze multi-byte xor cipher
 * [John the Ripper](http://www.openwall.com/john/) - A fast password cracker
 * [Aircrack](http://www.aircrack-ng.org/) - Aircrack is 802.11 WEP and WPA-PSK keys cracking program.


<a name="wargame" />
# Wargame

<a name="wargame-system" />
## System
 * [OverTheWire - Semtex](http://overthewire.org/wargames/semtex/)
 * [OverTheWire - Vortex](http://overthewire.org/wargames/vortex/)
 * [OverTheWire - Drifter](http://overthewire.org/wargames/drifter/)
 * [pwnable.kr](http://pwnable.kr/) - Provide various pwn challenges regarding system security
 * [Exploit Exercises - Nebula](https://exploit-exercises.com/nebula/)
 * [SmashTheStack](http://smashthestack.org/)

<a name="wargame-reverse-engineering" />
## Reverse Engineering
 * [Reversing.kr](http://www.reversing.kr/) - This site tests your ability to Cracking & Reverse Code Engineering
 * [CodeEngn](http://codeengn.com/challenges/) - (Korean)
 * [simples.kr](http://simples.kr/) - (Korean)

<a name="wargame-web" />
## Web
 * [Hack This Site!](https://www.hackthissite.org/) - a free, safe and legal training ground for hackers to test and expand their hacking skills
 * [Webhacking.kr](http://webhacking.kr/)
 * [0xf.at](https://0xf.at/) - a website without logins or ads where you can solve password-riddles (so called hackits).


<a name="wargame-cryptography" />
## Cryptography
 * [OverTheWire - Krypton](http://overthewire.org/wargames/krypton/)


<a name="ctf" />
# CTF

<a name="ctf-competition" />
## Competition
 * [DEF CON](https://legitbs.net/)
 * [CSAW CTF](https://ctf.isis.poly.edu/)
 * [hack.lu CTF](http://hack.lu/)
 * [Pliad CTF](http://www.plaidctf.com/)
 * [RuCTFe](http://ructf.org/e/)
 * [Ghost in the Shellcode](http://ghostintheshellcode.com/)
 * [PHD CTF](http://www.phdays.com/)
 * [SECUINSIDE CTF](http://secuinside.com/)
 * [Codegate CTF](http://ctf.codegate.org/html/Main.html?lang=eng)
 * [Boston Key Party CTF](http://bostonkeyparty.net/)

<a name="ctf-general" />
## General
 * [CTFtime.org](https://ctftime.org/) - All about CTF (Capture The Flag)
 * [WeChall](http://www.wechall.net/)
 * [CTF archives (shell-storm)](http://shell-storm.org/repo/CTF/)


<a name="etc" />
# ETC
 * [SecTools](http://sectools.org/) - Top 125 Network Security Tools
 * [BackTrack](http://www.backtrack-linux.org/)
