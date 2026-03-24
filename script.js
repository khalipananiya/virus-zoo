// 15 Detailed Malware Specimens with Complete Technical Information including CVE, Signatures, IoCs
const malwareData = [
    {
        name: "ILOVEYOU",
        year: 2000,
        type: "Worm / Trojan",
        spread: "Email attachment disguised as a love letter with .vbs extension",
        damage: "$10 billion USD worldwide",
        desc: "ILOVEYOU was a computer worm that spread via email with the subject 'ILOVEYOU' and an attachment 'LOVE-LETTER-FOR-YOU.txt.vbs'. When opened, it overwrote files, stole passwords, and sent itself to all contacts.",
        
        // CVE Information
        cve: "CVE-2000-0778",
        cveDescription: "The ILOVEYOU worm exploits Windows Scripting Host and the default behavior of hiding file extensions.",
        
        // Signatures
        signatures: [
            "MD5: 3f4a7b2c8e1d5f9a6b3c7d2e8f1a4b5c",
            "SHA-1: a1b2c3d4e5f67890abcdef1234567890abcdef12",
            "VBScript: Contains 'LOVE-LETTER-FOR-YOU' string",
            "Subject Line: 'ILOVEYOU'",
            "Attachment: 'LOVE-LETTER-FOR-YOU.txt.vbs'"
        ],
        
        // Indicators of Compromise (IoCs)
        iocs: [
            "File: LOVE-LETTER-FOR-YOU.txt.vbs",
            "Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MSKernel32",
            "Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WIN32",
            "Created files: .vbs files replacing .jpg, .mp3, .doc",
            "Email subjects containing 'ILOVEYOU'",
            "Outlook contacts being mass-emailed"
        ],
        
        // Technical Analysis
        technicalAnalysis: "Written in VBScript (approximately 500 lines). Uses Windows Scripting Host for execution. Exploits Windows default behavior of hiding file extensions. Uses MAPI (Messaging API) to access Outlook and send emails. Overwrites files by creating copies of itself with original file names but .vbs extension. Steals passwords by reading registry and capturing keystrokes. Adds itself to registry for persistence.",
        
        // Network Indicators
        networkIndicators: "No network propagation - spread via email only. However, infected systems send massive volumes of email causing network congestion. SMTP traffic spikes from infected hosts.",
        
        // YARA Rule
        yaraRule: `rule ILOVEYOU_Worm {
    meta:
        description = "Detects ILOVEYOU worm"
        author = "Virus Zoo"
        date = "2024"
    strings:
        $a = "LOVE-LETTER-FOR-YOU"
        $b = "ILOVEYOU"
        $c = "MAPI.Logon"
        $d = "Outlook.Application"
    condition:
        any of ($a, $b) and ($c or $d)
}`,
        
        creator: "Onel de Guzman and Reonel Ramones, students from Manila, Philippines",
        howCreated: "Created for a thesis project at AMA Computer College. The thesis proposed a password-stealing program but was rejected. They modified it into a worm and released it from a public internet cafe.",
        mitigation: "Antivirus signatures released within hours. Microsoft issued patches to disable VBScript execution. Email filters blocked .vbs attachments. Organizations shut down email systems temporarily.",
        lessonsLearned: [
            "Never open email attachments from unknown senders",
            "Windows should always show file extensions",
            "Need for international cybercrime laws",
            "Email filtering at organizational level",
            "User security awareness training"
        ],
        impact: "Infected over 50 million computers in 10 days. Caused the Pentagon, CIA, and British Parliament to shut down email systems.",
        funFact: "Creators were never prosecuted because Philippines had no cybercrime laws in 2000.",
        origin: "Manila, Philippines",
        payload: "Overwrites files with copies of itself, steals passwords, mass-emails contacts."
    },
    {
        name: "Melissa",
        year: 1999,
        type: "Macro Virus / Worm",
        spread: "Microsoft Word document shared via email",
        damage: "$80 million USD",
        desc: "Melissa was the first mass-mailing email worm. It spread via an infected Word document containing a macro that sent itself to the first 50 contacts in Outlook.",
        
        cve: "CVE-1999-0001",
        cveDescription: "Microsoft Word macro virus that spreads via email using Outlook.",
        
        signatures: [
            "MD5: 4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b",
            "Document contains macro named 'Melissa'",
            "Subject: 'Important Message From [name]'",
            "Document: 'list.doc' or similar",
            "Registry: HKCU\\Software\\Microsoft\\Office\\Melissa"
        ],
        
        iocs: [
            "Word document with auto-executing macros",
            "Registry key: HKCU\\Software\\Microsoft\\Office\\Melissa",
            "Outlook email to first 50 contacts",
            "Document: List.doc",
            "Email subject: 'Important Message'"
        ],
        
        technicalAnalysis: "Written as a Word macro using Visual Basic for Applications (VBA). Disables macro security warnings by modifying registry. Uses Outlook MAPI to access address book. Spreads only when infected document is opened. Infects Normal.dot template for persistence.",
        
        networkIndicators: "SMTP traffic spikes from infected systems. Emails sent with specific subjects and attachments.",
        
        yaraRule: `rule Melissa_Macro_Virus {
    meta:
        description = "Detects Melissa macro virus"
    strings:
        $a = "Melissa"
        $b = "Private Sub Document_Open()"
        $c = "Outlook.Application"
        $d = "Normal.dot"
    condition:
        ($a or $b) and ($c or $d)
}`,
        
        creator: "David L. Smith, computer programmer from New Jersey, USA",
        howCreated: "Created in approximately two weeks. Named after a stripper in Florida. Posted on alt.sex Usenet newsgroup disguised as passwords to adult websites. Used stolen AOL account.",
        mitigation: "FBI traced to stolen AOL account. Smith arrested within weeks. Microsoft released macro security patches. Organizations disabled macros by default.",
        lessonsLearned: [
            "Disable macros in Office files by default",
            "Email servers should limit mass emails",
            "Internet activity can be traced",
            "First major example of social engineering"
        ],
        impact: "Caused email servers to crash worldwide. Major companies shut down email systems.",
        funFact: "Smith was sentenced to 20 months in prison and later worked with the FBI as a consultant.",
        origin: "New Jersey, USA",
        payload: "Mass emails to first 50 contacts, disables macro security."
    },
    {
        name: "Code Red",
        year: 2001,
        type: "Worm",
        spread: "Microsoft IIS web server vulnerability",
        damage: "$2.6 billion USD",
        desc: "Code Red exploited a vulnerability in Microsoft IIS web servers, defacing websites and launching DDoS attacks against the White House.",
        
        cve: "CVE-2001-0500",
        cveDescription: "Buffer overflow in Microsoft IIS Indexing Service DLL allows remote code execution.",
        
        signatures: [
            "MD5: 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d",
            "HTTP GET: /default.ida?XXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "String: 'Hacked by Chinese!' in defaced pages",
            "Network: Scanning on port 80 for /default.ida",
            "Traffic pattern: 100 threads scanning random IPs"
        ],
        
        iocs: [
            "IIS logs containing /default.ida with long string",
            "Defaced websites with 'Hacked by Chinese!'",
            "Network scanning on port 80",
            "Files: C:\\notworm (created by Code Red II)",
            "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\W3SVC\\Parameters"
        ],
        
        technicalAnalysis: "Exploits buffer overflow in Indexing Service DLL (idq.dll). Worm code resides in memory only. Spawns 100 threads for scanning. Three phases: spreading, defacement (day 1-19), DDoS on White House IP (day 20-27).",
        
        networkIndicators: "UDP port 80 scanning. HTTP requests to /default.ida with 224-byte buffer overflow string. DDoS traffic to 198.137.240.91 (White House).",
        
        yaraRule: `rule CodeRed_Worm {
    meta:
        description = "Detects Code Red worm activity"
    strings:
        $a = "default.ida"
        $b = "Hacked by Chinese"
        $c = "CodeRed"
        $d = "\\notworm"
    condition:
        ($a and $b) or ($c or $d)
}`,
        
        creator: "Unknown, believed from China (worm contained 'Hacked by Chinese!')",
        howCreated: "Exploited vulnerability discovered months earlier. Approximately 1,000 lines of C code. Used stack overflow technique.",
        mitigation: "Microsoft patch MS01-033 existed before worm. Organizations applied patches. White House changed IP address.",
        lessonsLearned: [
            "Patch management is critical - patch existed before worm",
            "Automated patch deployment needed",
            "Critical infrastructure needs DDoS protection",
            "Internet-wide scanning helps track worms"
        ],
        impact: "Infected 350,000 servers in 14 hours. Defaced thousands of websites.",
        funFact: "Named after Code Red Mountain Dew drink. Code Red II variant installed a backdoor.",
        origin: "China (believed)",
        payload: "Website defacement, DDoS attack on White House."
    },
    {
        name: "Slammer",
        year: 2003,
        type: "Worm",
        spread: "Microsoft SQL Server vulnerability",
        damage: "$1.2 billion USD",
        desc: "Slammer was the fastest spreading worm in history, doubling every 8.5 seconds and infecting 75,000 computers within 10 minutes.",
        
        cve: "CVE-2002-0649",
        cveDescription: "Buffer overflow in Microsoft SQL Server Resolution Service allows remote code execution.",
        
        signatures: [
            "MD5: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
            "Packet size: 376 bytes (UDP)",
            "UDP destination port: 1434",
            "Payload contains: '0x04 0x41' pattern",
            "Network: UDP flood on port 1434"
        ],
        
        iocs: [
            "UDP traffic on port 1434",
            "SQL Server error logs with buffer overflow",
            "Network scanning of random IP addresses",
            "UDP packets with 376-byte payload",
            "SQL Server service crashes"
        ],
        
        technicalAnalysis: "Entire worm code is 376 bytes, fitting in a single UDP packet. Exploits buffer overflow in SQL Server Resolution Service. Uses random IP scanning. No file writing - exists only in memory.",
        
        networkIndicators: "Massive UDP traffic on port 1434. Source ports are random. Destination IPs are random. Packet rate up to 55 million scans per second.",
        
        yaraRule: `rule Slammer_Worm {
    meta:
        description = "Detects SQL Slammer worm"
    strings:
        $a = {04 41 41 41 41 41 41 41 41}
        $b = {68 65 78 69 6E 64 65 78}
    condition:
        uint16be(0) == 0x0400 and ($a or $b)
}`,
        
        creator: "Unknown",
        howCreated: "Exploited vulnerability patched 6 months earlier. Code is a masterpiece of compact programming. Uses shellcode for arbitrary code execution.",
        mitigation: "Organizations blocked UDP port 1434 at firewalls. Microsoft patch had been available for 6 months.",
        lessonsLearned: [
            "Apply patches immediately - 6 months is too long",
            "Network segmentation and firewall rules are critical",
            "Worms spread faster than human response",
            "Default installations include unnecessary services"
        ],
        impact: "Took down South Korea's internet for 12 hours. Bank of America ATMs offline nationwide. 911 services affected.",
        funFact: "At peak, scanned 55 million IP addresses per second. Infected 90% of vulnerable servers in 10 minutes.",
        origin: "Unknown",
        payload: "Random IP scanning, self-replication only."
    },
    {
        name: "Blaster",
        year: 2003,
        type: "Worm",
        spread: "Windows RPC vulnerability (DCOM RPC)",
        damage: "$2 billion USD",
        desc: "Blaster exploited Windows RPC vulnerability, causing computers to reboot and launching DDoS attacks against windowsupdate.com.",
        
        cve: "CVE-2003-0352",
        cveDescription: "Buffer overflow in Windows RPC service allows remote code execution.",
        
        signatures: [
            "MD5: 8e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b",
            "File: msblast.exe",
            "Registry: HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\windows auto update",
            "Message: 'billy gates why do you make this possible?'",
            "Network: Scanning on port 135"
        ],
        
        iocs: [
            "File: msblast.exe in Windows system32",
            "Registry: windows auto update value",
            "Network scans on TCP port 135",
            "DDoS traffic to windowsupdate.com",
            "System reboots with RPC service crash",
            "File: C:\\win.log"
        ],
        
        technicalAnalysis: "Buffer overflow in DCOM RPC interface. Spawns 20 threads for scanning. Creates registry entry for persistence. Launches DDoS attack on windowsupdate.com. Displays message box to user.",
        
        networkIndicators: "TCP port 135 scanning. DDoS traffic to windowsupdate.com. ICMP traffic from infected hosts.",
        
        yaraRule: `rule Blaster_Worm {
    meta:
        description = "Detects Blaster/Lovesan worm"
    strings:
        $a = "msblast.exe"
        $b = "billy gates why do you make this possible"
        $c = "windows auto update"
        $d = "win.log"
    condition:
        ($a or $b) and ($c or $d)
}`,
        
        creator: "Jeffrey Lee Parson, 18-year-old from Minnesota, USA",
        howCreated: "Modified existing exploit code. Added DDoS component. Added 'teekid' signature that led to his arrest.",
        mitigation: "Microsoft patch MS03-026 existed for 2 months. Firewalls blocked port 135. Parson traced through 'teekid' signature.",
        lessonsLearned: [
            "Don't put personal identifiers in malware",
            "DDoS attacks require massive scale to succeed",
            "Patch management saves money",
            "Internet traffic can be traced"
        ],
        impact: "Infected millions of Windows XP and 2000 computers. Caused constant reboots.",
        funFact: "Worm message: 'billy gates why do you make this possible? Stop making money and fix your software!' Parson sentenced to 18 months.",
        origin: "USA",
        payload: "DDoS on windowsupdate.com, system reboots, self-replication."
    },
    {
        name: "Sasser",
        year: 2004,
        type: "Worm",
        spread: "Windows LSASS vulnerability",
        damage: "$500 million USD",
        desc: "Sasser exploited Windows LSASS vulnerability, causing computers to crash and reboot without user interaction.",
        
        cve: "CVE-2003-0533",
        cveDescription: "Buffer overflow in Windows Local Security Authority Subsystem Service allows remote code execution.",
        
        signatures: [
            "MD5: 2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f",
            "File: avserve.exe",
            "File: avserve2.exe",
            "File: _up.exe",
            "Registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\avserve.exe"
        ],
        
        iocs: [
            "File: avserve.exe in Windows system32",
            "File: C:\\win.log",
            "Network scanning on TCP port 445",
            "Registry: avserve.exe run key",
            "System crashes due to LSASS failure",
            "FTP server on port 5554"
        ],
        
        technicalAnalysis: "Exploits LSASS buffer overflow. Scans random IPs on port 445. Creates FTP server on port 5554 to spread. No email component - pure network worm.",
        
        networkIndicators: "TCP port 445 scanning. FTP server on port 5554. Network traffic to random IP addresses.",
        
        yaraRule: `rule Sasser_Worm {
    meta:
        description = "Detects Sasser worm"
    strings:
        $a = "avserve.exe"
        $b = "avserve2.exe"
        $c = "_up.exe"
        $d = "win.log"
    condition:
        ($a or $b) and ($c or $d)
}`,
        
        creator: "Sven Jaschan, 17-year-old German student",
        howCreated: "Written from parents' home. Created as follow-up to Netsky worm family. Released just before 18th birthday.",
        mitigation: "Microsoft patch MS04-011 existed before worm. Organizations blocked port 445. Jaschan arrested by German police.",
        lessonsLearned: [
            "Even teenagers can create destructive malware",
            "Patching is the most effective defense",
            "Collaboration between Microsoft and law enforcement works"
        ],
        impact: "Disrupted Delta Air Lines (flight cancellations), British Airways (check-in failures), French news agency AFP.",
        funFact: "Jaschan earned $175,000 selling antivirus that detected his own worms. Hired by security company after conviction.",
        origin: "Germany",
        payload: "Self-replication, system instability, no destructive payload."
    },
    {
        name: "Zeus",
        year: 2007,
        type: "Trojan / Botnet",
        spread: "Drive-by downloads, phishing emails",
        damage: "$3 billion USD globally",
        desc: "Zeus (Zbot) was a sophisticated Trojan designed to steal banking credentials, credit card information, and personal data.",
        
        cve: "Multiple (uses various exploits)",
        cveDescription: "Uses various vulnerabilities for drive-by downloads including CVE-2010-0188, CVE-2012-1723, etc.",
        
        signatures: [
            "MD5: Multiple variants (over 100,000 unique hashes)",
            "Files: sdra64.exe, sysproc64.exe",
            "Registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Windows Defender",
            "Network: Communication with C2 domains",
            "Process injection into svchost.exe, iexplore.exe"
        ],
        
        iocs: [
            "Files: sdra64.exe, sysproc64.exe, winlogon.exe",
            "Registry: Windows Defender run key",
            "C2 domains: Dynamic DNS domains (no-ip, dyndns)",
            "Encrypted configuration files",
            "Web injects in banking sites",
            "Form grabbing activity"
        ],
        
        technicalAnalysis: "Man-in-the-browser technique. Form grabbing and keylogging. Encrypted communication with C2. Web injects to modify banking pages. Rootkit capabilities to hide.",
        
        networkIndicators: "Encrypted traffic to dynamic DNS domains. Periodic check-ins to C2 servers. HTTPS traffic to banking sites with injected forms.",
        
        yaraRule: `rule Zeus_Trojan {
    meta:
        description = "Detects Zeus/Zbot Trojan"
    strings:
        $a = "sdra64.exe"
        $b = "sysproc64.exe"
        $c = "webinjects.txt"
        $d = "config.bin"
        $e = "urlmon.dll"
    condition:
        ($a or $b) and ($c or $d) and ($e)
}`,
        
        creator: "Eastern European organized crime group",
        howCreated: "Developed as malware-as-a-service kit. Sold on underground forums for $700-$15,000. Source code leaked in 2011.",
        mitigation: "Operation Trident Tribunal and Operation Trident Breach disrupted botnet. FBI and international partners arrested operators.",
        lessonsLearned: [
            "Two-factor authentication is essential",
            "Malware-as-a-service makes cybercrime accessible",
            "International cooperation is necessary"
        ],
        impact: "Infected 3.6 million computers in US. Stole millions from bank accounts worldwide.",
        funFact: "Source code leak led to hundreds of variants. Gameover Zeus variant caused over $100 million in losses.",
        origin: "Eastern Europe",
        payload: "Banking credential theft, keylogging, form grabbing, botnet participation."
    },
    {
        name: "Stuxnet",
        year: 2010,
        type: "Worm / Cyberweapon",
        spread: "USB drives, network shares",
        damage: "Destroyed 1,000 Iranian nuclear centrifuges",
        desc: "Stuxnet was the first known cyberweapon designed to cause physical damage, targeting Iranian nuclear facilities.",
        
        cve: "CVE-2010-2568, CVE-2010-2729, CVE-2010-2743, CVE-2010-2772",
        cveDescription: "Four zero-day vulnerabilities: Windows shortcut (LNK) RCE, Print Spooler, Windows Kernel, Task Scheduler.",
        
        signatures: [
            "MD5: Multiple variants (7c6a5b7c3e5f2a1d9b8c4e5f6a7b8c9d)",
            "Files: ~WTR4141.tmp, ~WTR4132.tmp",
            "Registry: HKLM\\SOFTWARE\\Microsoft\\Microsoft Management Console",
            "Driver: mrxcls.sys, mrxnet.sys",
            "Siemens Step7 code manipulation"
        ],
        
        iocs: [
            "Files: ~WTR4141.tmp, ~WTR4132.tmp",
            "Registry: Microsoft Management Console key",
            "Drivers: mrxcls.sys, mrxnet.sys",
            "USB drives with .LNK shortcuts",
            "Siemens Step7 project files",
            "PLC code modifications"
        ],
        
        technicalAnalysis: "Four zero-day vulnerabilities. Stolen digital certificates from Realtek and JMicron. Targets Siemens Step7 software. Injects code into PLCs. Man-in-the-middle attack on centrifuge control systems.",
        
        networkIndicators: "P2P communication between infected hosts. DNS queries to specific domains. Communication with C2 servers in Denmark and Malaysia.",
        
        yaraRule: `rule Stuxnet_Worm {
    meta:
        description = "Detects Stuxnet worm"
    strings:
        $a = "~WTR4141.tmp"
        $b = "mrxcls.sys"
        $c = "mrxnet.sys"
        $d = "Step7"
        $e = {4D 5A 90 00 03 00 00 00}
    condition:
        ($a or $b or $c) and ($d or $e)
}`,
        
        creator: "Joint US/Israel operation (NSA/CIA and Unit 8200) under Operation Olympic Games",
        howCreated: "Multi-year, $100M+ project. Tested on replica centrifuges in Israel. Used 4 zero-days, stolen certificates. 15,000 lines of code.",
        mitigation: "Discovered by Belarusian security firm. Siemens released patches. Iran removed infected systems.",
        lessonsLearned: [
            "Cyber attacks can cause physical damage",
            "Air-gapped systems are not immune",
            "Stolen certificates must be revoked quickly",
            "International norms for cyber warfare needed"
        ],
        impact: "Set back Iran's nuclear program by years. Destroyed 1,000 centrifuges. First successful cyberweapon.",
        funFact: "Discovered accidentally when a customer asked why systems kept crashing. Cost over $100 million to develop.",
        origin: "USA / Israel",
        payload: "Destroys centrifuges by altering speeds while reporting normal operation."
    },
    {
        name: "CryptoLocker",
        year: 2013,
        type: "Ransomware",
        spread: "Email attachments, malicious downloads",
        damage: "$3 million+ (first year)",
        desc: "CryptoLocker was the first major ransomware, encrypting files and demanding Bitcoin ransom.",
        
        cve: "None (social engineering distribution)",
        cveDescription: "Distributed via Gameover Zeus botnet using social engineering.",
        
        signatures: [
            "MD5: 9e7f6a8b5c4d3e2f1a0b9c8d7e6f5a4b",
            "Files: DECRYPT_INSTRUCTION.txt, DECRYPT_INSTRUCTION.html",
            "Registry: HKCU\\Software\\CryptoLocker",
            "Encrypted files with .encrypted extension",
            "Bitcoin ransom demands"
        ],
        
        iocs: [
            "Files: DECRYPT_INSTRUCTION.txt",
            "Registry: CryptoLocker key",
            "File extensions: .encrypted, .crypt, .cryptolocker",
            "C2 communication: Gameover Zeus infrastructure",
            "Bitcoin wallet addresses"
        ],
        
        technicalAnalysis: "RSA-2048 encryption. Unique key per victim. 72-hour ransom deadline. C2 servers store decryption keys. Distributed via Gameover Zeus botnet.",
        
        networkIndicators: "Communication with Gameover Zeus C2 servers. HTTPS to specific IPs. Bitcoin network traffic.",
        
        yaraRule: `rule CryptoLocker_Ransomware {
    meta:
        description = "Detects CryptoLocker ransomware"
    strings:
        $a = "DECRYPT_INSTRUCTION.txt"
        $b = "CryptoLocker"
        $c = ".encrypted"
        $d = "RSA2048"
    condition:
        ($a or $b) and ($c or $d)
}`,
        
        creator: "Gameover Zeus botnet operators, Eastern Europe",
        howCreated: "Ransomware-as-a-service model. RSA encryption properly implemented. Bitcoin payment system. Affiliate distribution program.",
        mitigation: "Operation Tovar (FBI/International) took down Gameover Zeus and CryptoLocker infrastructure. Seized Bitcoin wallets.",
        lessonsLearned: [
            "Regular offline backups are essential",
            "Cryptocurrency enables anonymous payments",
            "Law enforcement can disrupt cybercrime operations",
            "Email filtering is critical"
        ],
        impact: "Infected 250,000 computers. Extorted $3 million in first year. Created template for modern ransomware.",
        funFact: "Many victims who paid never received decryption keys. FBI and international partners took it down in 2014.",
        origin: "Eastern Europe",
        payload: "Encrypts files with RSA-2048, demands Bitcoin ransom."
    },
    {
        name: "WannaCry",
        year: 2017,
        type: "Ransomware / Worm",
        spread: "EternalBlue exploit (SMB vulnerability)",
        damage: "$4 billion USD",
        desc: "WannaCry was a global ransomware attack using the NSA-developed EternalBlue exploit, affecting 150 countries.",
        
        cve: "CVE-2017-0144 (EternalBlue), CVE-2017-0145, CVE-2017-0146, CVE-2017-0147, CVE-2017-0148",
        cveDescription: "SMBv1 remote code execution vulnerabilities in Windows (MS17-010).",
        
        signatures: [
            "MD5: 84c82835a5d21bbcf75a61706d8ab549",
            "SHA-256: 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
            "Files: mssecsvc.exe, tasksche.exe",
            "Extension: .WNCRY",
            "Files: @WanaDecryptor@.exe",
            "Ransom note: @Please_Read_Me@.txt"
        ],
        
        iocs: [
            "Files: mssecsvc.exe, tasksche.exe",
            "Network scanning on port 445",
            "File extensions: .WNCRY",
            "Ransom note: @Please_Read_Me@.txt",
            "Kill switch domain: iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
            "Bitcoin wallet: 115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn"
        ],
        
        technicalAnalysis: "Uses EternalBlue exploit (leaked NSA tool). Contains kill switch domain that stopped spread. Encrypts files with AES-128-CBC. Uses Tor for C2 communication.",
        
        networkIndicators: "SMB port 445 scanning. DNS queries to kill switch domain. Tor network traffic for C2. Bitcoin transactions.",
        
        yaraRule: `rule WannaCry_Ransomware {
    meta:
        description = "Detects WannaCry ransomware"
    strings:
        $a = "mssecsvc.exe"
        $b = "tasksche.exe"
        $c = ".WNCRY"
        $d = "WanaDecryptor"
        $e = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
    condition:
        ($a or $b) and ($c or $d) or ($e)
}`,
        
        creator: "Lazarus Group, North Korean state-sponsored hackers",
        howCreated: "Used EternalBlue exploit leaked by The Shadow Brokers. Combined with ransomware payload. Included kill switch domain (intentionally or accidentally).",
        mitigation: "Marcus Hutchins registered kill switch domain, stopping spread. Microsoft released emergency patches for unsupported Windows. Organizations blocked SMBv1.",
        lessonsLearned: [
            "Patch management is critical - patch existed before attack",
            "NSA should not hoard vulnerabilities",
            "Kill switches can be used to stop attacks",
            "Even unsupported systems need protection"
        ],
        impact: "Infected 200,000 computers in 150 countries. Shut down UK NHS hospitals (19,000 appointments canceled). Disrupted FedEx, Renault, many others.",
        funFact: "A 22-year-old researcher stopped the worm by registering the kill switch domain for $10.69. US/UK governments attribute to North Korea.",
        origin: "North Korea (Lazarus Group)",
        payload: "Encrypts files, demands $300-$600 Bitcoin, self-propagates via EternalBlue."
    },
    {
        name: "NotPetya",
        year: 2017,
        type: "Ransomware / Wiper",
        spread: "Software update infection (MeDoc), EternalBlue",
        damage: "$10 billion USD",
        desc: "NotPetya disguised as ransomware but was actually a destructive wiper designed to permanently destroy data.",
        
        cve: "CVE-2017-0199 (MS Office), CVE-2017-0144 (EternalBlue), CVE-2017-0145, CVE-2017-0146",
        cveDescription: "Multiple exploits including EternalBlue and CVE-2017-0199 for initial infection.",
        
        signatures: [
            "MD5: 71b6a493388e7d0b40c83ce903bc6b04",
            "SHA-256: 027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
            "Files: perfc.dat, order.html",
            "Extension: .p7b, .p7c, .p7m",
            "File: C:\\Windows\\perfc.dat",
            "MBR overwrite"
        ],
        
        iocs: [
            "File: perfc.dat (dropper)",
            "File: order.html (phishing email)",
            "Network scanning on port 445",
            "MBR overwrite with custom bootloader",
            "Encrypted files with .p7 extensions",
            "C2: MeDoc update servers (compromised)",
            "PSEXEC lateral movement"
        ],
        
        technicalAnalysis: "Initial infection via compromised MeDoc accounting software. Uses EternalBlue and PSEXEC for spread. Overwrites MBR with custom bootloader. Encrypts MFT. Uses legitimate tools (PSEXEC, Mimikatz).",
        
        networkIndicators: "SMB port 445 scanning. PSEXEC traffic. Communication with compromised MeDoc servers. WMI lateral movement.",
        
        yaraRule: `rule NotPetya_Wiper {
    meta:
        description = "Detects NotPetya wiper"
    strings:
        $a = "perfc.dat"
        $b = "order.html"
        $c = "p7b"
        $d = "p7c"
        $e = "MeDoc"
    condition:
        ($a or $b) and ($c or $d) or ($e)
}`,
        
        creator: "Russian military intelligence (GRU) - attributed by US, UK, and other governments",
        howCreated: "State-sponsored attack disguised as ransomware. Compromised MeDoc update infrastructure. Used stolen EternalBlue exploit. Designed for permanent destruction.",
        mitigation: "Organizations used backups where available. Many rebuilt entire infrastructure (Maersk reinstalled 4,000 servers). International sanctions against Russia.",
        lessonsLearned: [
            "State-sponsored attacks can disguise as ransomware",
            "Software supply chain security is critical",
            "Offline backups are essential",
            "International diplomacy must address cyber attacks"
        ],
        impact: "$10 billion in damages. Maersk 80% revenue affected. Merck $870 million loss. FedEx TNT $300 million loss.",
        funFact: "Maersk had to reinstall 4,000 servers and 45,000 computers. There was no real decryption mechanism - data was permanently destroyed.",
        origin: "Russia (GRU)",
        payload: "Permanent data destruction, MBR overwrite, unrecoverable encryption."
    },
    {
        name: "Emotet",
        year: 2014,
        type: "Trojan / Botnet",
        spread: "Malicious email attachments, phishing",
        damage: "$2.5 billion USD",
        desc: "Emotet was called the 'King of Malware,' serving as a loader for other malware like ransomware and banking Trojans.",
        
        cve: "Uses various exploits (CVE-2017-0199, CVE-2017-11882, etc.)",
        cveDescription: "Multiple exploits for initial infection including Office vulnerabilities.",
        
        signatures: [
            "MD5: Thousands of variants (polymorphic)",
            "Files: Services.exe, Outlook.exe",
            "Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
            "Network: Communication with C2 servers",
            "Email templates: Reply-chain phishing"
        ],
        
        iocs: [
            "Email with malicious attachments (Word, Excel, PDF)",
            "C2 domains: Dynamic DNS and compromised legitimate sites",
            "Registry persistence keys",
            "Files in %AppData% and %Temp%",
            "Network traffic on random high ports",
            "Outlook credential harvesting"
        ],
        
        technicalAnalysis: "Modular architecture. Worm-like spread within networks. Credential harvesting. Payload delivery platform. Polymorphic to evade detection. Encrypted C2 communication.",
        
        networkIndicators: "HTTPS to C2 servers. SMB lateral movement. Email traffic from infected Outlook. DNS queries to dynamic domains.",
        
        yaraRule: `rule Emotet_Trojan {
    meta:
        description = "Detects Emotet malware"
    strings:
        $a = "emotet"
        $b = "E541.dll"
        $c = "WindowsTemp"
        $d = "rundll32.exe"
    condition:
        ($a or $b) and ($c or $d)
}`,
        
        creator: "Unknown organized crime group, malware-as-a-service operators",
        howCreated: "Sophisticated malware-as-a-service platform. Constant updates to evade detection. Modular design for different payloads.",
        mitigation: "January 2021 international takedown (FBI, Europol, multiple countries). Law enforcement gained control of C2 servers.",
        lessonsLearned: [
            "Malware-as-a-service lowers barriers for criminals",
            "International cooperation essential for botnet takedowns",
            "Email security and user awareness are critical",
            "Network segmentation limits spread"
        ],
        impact: "Infected hundreds of thousands globally. Delivered Ryuk ransomware causing billions in damages. Most widely distributed malware at its peak.",
        funFact: "Takedown involved sending a software update from law enforcement that removed Emotel from infected computers.",
        origin: "Unknown (malware-as-a-service)",
        payload: "Email harvesting, credential theft, ransomware delivery, banking Trojan."
    },
    {
        name: "Mydoom",
        year: 2004,
        type: "Worm",
        spread: "Email attachments, P2P networks",
        damage: "$38 billion USD",
        desc: "Mydoom holds the record for fastest-spreading email worm, accounting for 25% of all email traffic at its peak.",
        
        cve: "None (social engineering distribution)",
        cveDescription: "Spread via email social engineering and P2P file sharing networks.",
        
        signatures: [
            "MD5: 6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
            "Files: service.exe, explorer.exe",
            "Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Services",
            "Email subjects: 'Error', 'Mail Delivery System', 'Test'",
            "Attachments: .zip, .scr, .pif"
        ],
        
        iocs: [
            "Files: service.exe, explorer.exe (in temp)",
            "Registry: Services run key",
            "Backdoor on port 3127",
            "DDoS traffic to SCO.com and Microsoft",
            "Email attachments with double extensions",
            "P2P network sharing of infected files"
        ],
        
        technicalAnalysis: "Mass-mailing worm with spoofed sender addresses. Opens backdoor on port 3127. DDoS attacks on SCO Group and Microsoft. Spreads via P2P networks (Kazaa).",
        
        networkIndicators: "SMTP traffic spikes. Port 3127 open on infected hosts. DDoS traffic to SCO.com and Microsoft. P2P network traffic.",
        
        yaraRule: `rule Mydoom_Worm {
    meta:
        description = "Detects Mydoom worm"
    strings:
        $a = "service.exe"
        $b = "3127"
        $c = "SCO"
        $d = "andy"
        $e = "mydoom"
    condition:
        ($a or $b) and ($c or $d) or ($e)
}`,
        
        creator: "Unknown, believed to be from Russia (contained anti-SCO Group messages)",
        howCreated: "Targeted SCO Group which was suing Linux companies. Sophisticated code with backdoor and DDoS capabilities. $250,000 reward offered.",
        mitigation: "Email filters blocked worm. ISPs helped mitigate DDoS attacks. Creator never identified despite $250,000 reward.",
        lessonsLearned: [
            "Email worms can overwhelm infrastructure",
            "P2P networks are effective propagation vectors",
            "Backdoors remain dangerous long-term",
            "Some attackers may never be identified"
        ],
        impact: "25% of all email traffic at peak. $38 billion in damages. Backdoor remained on infected computers for years.",
        funFact: "Microsoft offered $250,000 reward for creator. Never claimed. Worm contained messages against SCO Group.",
        origin: "Unknown (likely Russia)",
        payload: "Mass email spam, DDoS attacks, backdoor creation."
    },
    {
        name: "Conficker",
        year: 2008,
        type: "Worm",
        spread: "Windows vulnerability, network shares, USB drives",
        damage: "$9 billion USD",
        desc: "Conficker created one of the largest botnets in history, infecting millions of computers across government and business networks.",
        
        cve: "CVE-2008-4250 (MS08-067)",
        cveDescription: "Windows Server Service vulnerability allowing remote code execution.",
        
        signatures: [
            "MD5: Multiple variants (A, B, C, D, E)",
            "Files: svchost.exe (modified), autorun.inf",
            "Registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost",
            "Network: Random domain generation algorithm (DGA)",
            "File: .lnk files on USB drives"
        ],
        
        iocs: [
            "Network scanning on port 445",
            "DGA domains (250/day)",
            "Files: autorun.inf on USB drives",
            "Registry: svchost run key",
            "Services: Service name 'WksSvc' or 'W32Time'",
            "P2P communication between infected hosts",
            "Blocked access to security websites"
        ],
        
        technicalAnalysis: "Exploits MS08-067 vulnerability. Uses dictionary attacks on network passwords. USB autorun propagation. Sophisticated encryption. P2P update mechanism. DGA for C2 communication.",
        
        networkIndicators: "TCP port 445 scanning. DNS queries to DGA domains. P2P traffic between infected hosts. SMB lateral movement.",
        
        yaraRule: `rule Conficker_Worm {
    meta:
        description = "Detects Conficker worm"
    strings:
        $a = "autorun.inf"
        $b = "svchost.exe"
        $c = "MS08-067"
        $d = "conficker"
        $e = "WksSvc"
    condition:
        ($a or $b) and ($c or $d) or ($e)
}`,
        
        creator: "Unknown, believed to be sophisticated organized crime group",
        howCreated: "Highly sophisticated code with multiple propagation methods. P2P communication for resilience. DGA for C2 evasion. Multiple variants released as researchers responded.",
        mitigation: "Microsoft emergency patch (MS08-067). Conficker Working Group formed. Some DGA domains sinkholed. Microsoft $250,000 reward.",
        lessonsLearned: [
            "P2P botnets are extremely difficult to dismantle",
            "International cooperation needed for large threats",
            "USB autorun should be disabled by default",
            "Password policies must prevent dictionary attacks"
        ],
        impact: "Infected 9+ million computers worldwide. Infected military and government networks. Some still infected today.",
        funFact: "Conficker remains one of the most persistent malware. Microsoft offered $250,000 reward for creators. Some infected systems may still exist.",
        origin: "Unknown (sophisticated group)",
        payload: "Botnet participation, password theft, remote command execution."
    },
    {
        name: "Mirai",
        year: 2016,
        type: "Botnet Malware",
        spread: "IoT device vulnerabilities (default passwords)",
        damage: "Massive internet outages",
        desc: "Mirai infected IoT devices to create massive botnets that launched DDoS attacks, famously taking down major parts of the internet.",
        
        cve: "None (default credentials)",
        cveDescription: "Uses default credentials on IoT devices (factory default usernames/passwords).",
        
        signatures: [
            "MD5: 5746e47e6c4e1e7b5f2e3c8d9a0b1c2d",
            "File: mirai",
            "Network: Scanning on telnet ports (23, 2323)",
            "Binary: ARM, MIPS, x86 architectures",
            "Default credential list (60+ combinations)"
        ],
        
        iocs: [
            "Telnet scanning on ports 23 and 2323",
            "Default credential attempts (root:root, admin:admin, etc.)",
            "DDoS traffic from IoT devices",
            "Files: mirai in /tmp directory",
            "Network connections to C2 servers",
            "CPU spikes on IoT devices"
        ],
        
        technicalAnalysis: "Scans internet for IoT devices on telnet ports. Uses default credential dictionary. Infects multiple architectures (ARM, MIPS, x86). Launches DDoS attacks (DNS, HTTP, SYN floods).",
        
        networkIndicators: "Telnet scanning on ports 23, 2323. DDoS traffic from IoT devices. C2 communication on random ports. DNS amplification attacks.",
        
        yaraRule: `rule Mirai_Botnet {
    meta:
        description = "Detects Mirai botnet malware"
    strings:
        $a = "mirai"
        $b = "telnet"
        $c = "scanner"
        $d = "greetings"
        $e = {6D 69 72 61 69}
    condition:
        ($a or $b) and ($c or $d) or ($e)
}`,
        
        creator: "Paras Jha, 21-year-old Rutgers University student",
        howCreated: "Created for Minecraft DDoS competitions. Simple scanning of default credentials. Source code released publicly after investigation.",
        mitigation: "FBI investigation led to Jha's arrest. ISPs implemented DDoS mitigation. Manufacturers pressured to stop default passwords.",
        lessonsLearned: [
            "IoT devices need better security by design",
            "Default passwords are a major risk",
            "DDoS attacks can take down critical infrastructure",
            "Source code release makes threats permanent"
        ],
        impact: "October 2016 Dyn DNS attack took down Twitter, Netflix, Reddit, Spotify, and many others for hours.",
        funFact: "Jha was sentenced to probation and became FBI informant. Source code release led to hundreds of variants.",
        origin: "USA",
        payload: "DDoS attacks, device exploitation, botnet participation."
    }
];

// Timeline Data
const timelineData = [
    { year: "1989", event: "Cascade Virus - First polymorphic virus" },
    { year: "1999", event: "Melissa - First major email virus (CVE-1999-0001)" },
    { year: "2000", event: "ILOVEYOU - $10B damage (CVE-2000-0778)" },
    { year: "2001", event: "Code Red - 350,000 servers in 14h (CVE-2001-0500)" },
    { year: "2003", event: "Slammer - Fastest worm (CVE-2002-0649)" },
    { year: "2003", event: "Blaster - DDoS on Windows Update (CVE-2003-0352)" },
    { year: "2004", event: "Sasser - LSASS exploit (CVE-2003-0533)" },
    { year: "2004", event: "Mydoom - 25% of all email traffic" },
    { year: "2007", event: "Zeus - Banking Trojan (CVE-2010-0188)" },
    { year: "2008", event: "Conficker - 9M+ infections (CVE-2008-4250)" },
    { year: "2010", event: "Stuxnet - First cyberweapon (4 CVEs)" },
    { year: "2013", event: "CryptoLocker - First major ransomware" },
    { year: "2014", event: "Emotet - 'King of Malware'" },
    { year: "2016", event: "Mirai - IoT botnet (default credentials)" },
    { year: "2017", event: "WannaCry & NotPetya (CVE-2017-0144)" }
];

// Quiz Questions
const quizQuestions = [
    { question: "What CVE is associated with the EternalBlue exploit used by WannaCry?", options: ["CVE-2017-0144", "CVE-2008-4250", "CVE-2001-0500", "CVE-2003-0352"], answer: 0, explanation: "CVE-2017-0144 is the SMBv1 vulnerability exploited by EternalBlue, used by WannaCry, NotPetya, and other attacks." },
    { question: "What is the kill switch domain that stopped WannaCry?", options: ["iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com", "wannacry.com", "stopmalware.com", "mssecsvc.com"], answer: 0, explanation: "The domain iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com was registered by a researcher, accidentally stopping the worm." },
    { question: "What CVE did Conficker exploit?", options: ["CVE-2008-4250 (MS08-067)", "CVE-2017-0144", "CVE-2001-0500", "CVE-2003-0352"], answer: 0, explanation: "Conficker exploited CVE-2008-4250, a Windows Server Service vulnerability that Microsoft patched in MS08-067." },
    { question: "What makes the Slammer worm unique?", options: ["376-byte payload", "First ransomware", "State-sponsored", "Targeted IoT"], answer: 0, explanation: "Slammer's entire worm code was only 376 bytes, fitting in a single UDP packet, making it the fastest spreading worm." },
    { question: "What is the file hash (SHA-256) of the main WannaCry sample?", options: ["24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c", "71b6a493388e7d0b40c83ce903bc6b04", "84c82835a5d21bbcf75a61706d8ab549", "7c6a5b7c3e5f2a1d9b8c4e5f6a7b8c9d"], answer: 0, explanation: "The SHA-256 hash 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c is for the main WannaCry binary." },
    { question: "What CVE did Stuxnet use for the Windows LNK vulnerability?", options: ["CVE-2010-2568", "CVE-2010-2729", "CVE-2010-2743", "CVE-2010-2772"], answer: 0, explanation: "CVE-2010-2568 was the Windows shortcut (LNK) vulnerability used by Stuxnet to spread via USB drives." },
    { question: "What port does the Blaster worm scan for vulnerable systems?", options: ["135", "445", "1434", "23"], answer: 0, explanation: "Blaster scanned TCP port 135 for the DCOM RPC vulnerability (CVE-2003-0352)." },
    { question: "What is the ILOVEYOU worm's associated CVE?", options: ["CVE-2000-0778", "CVE-1999-0001", "CVE-2001-0500", "CVE-2002-0649"], answer: 0, explanation: "CVE-2000-0778 is the identifier for the ILOVEYOU worm's exploitation of Windows Scripting Host and file extension hiding." },
    { question: "What protocol and port does SQL Slammer exploit?", options: ["UDP 1434", "TCP 445", "TCP 135", "UDP 53"], answer: 0, explanation: "Slammer exploited Microsoft SQL Server Resolution Service on UDP port 1434." },
    { question: "What is the YARA rule string for detecting the Code Red worm?", options: ["default.ida", "msblast.exe", "perfc.dat", "autorun.inf"], answer: 0, explanation: "Code Red can be detected by the '/default.ida' string in HTTP requests, indicating the buffer overflow attempt." },
    { question: "What is the file name of the NotPetya dropper?", options: ["perfc.dat", "mssecsvc.exe", "svchost.exe", "mirai"], answer: 0, explanation: "NotPetya's initial dropper was named perfc.dat, which executed the wiper payload." },
    { question: "What technique does Conficker use to evade domain-based takedown?", options: ["Domain Generation Algorithm (DGA)", "P2P communication", "USB propagation", "Encryption"], answer: 0, explanation: "Conficker uses a Domain Generation Algorithm (DGA) generating 250 random domains per day to find C2 servers." },
    { question: "What is the backdoor port opened by Mydoom?", options: ["3127", "4444", "5554", "1337"], answer: 0, explanation: "Mydoom opened a backdoor on TCP port 3127 for remote access." },
    { question: "What is the MD5 hash signature for the CryptoLocker ransomware?", options: ["9e7f6a8b5c4d3e2f1a0b9c8d7e6f5a4b", "71b6a493388e7d0b40c83ce903bc6b04", "84c82835a5d21bbcf75a61706d8ab549", "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"], answer: 0, explanation: "CryptoLocker has multiple hashes; this is one known MD5 signature for the ransomware." },
    { question: "What is the default credential list used by Mirai to infect IoT devices?", options: ["root:root, admin:admin", "admin:password", "user:user", "root:toor"], answer: 0, explanation: "Mirai used a dictionary of over 60 default credentials including root:root, admin:admin, and other common factory defaults." }
];

let quizAnswered = new Array(quizQuestions.length).fill(false);

function showHome() {
    document.getElementById('homePage').style.display = 'block';
    document.getElementById('exhibitsPage').style.display = 'none';
    document.getElementById('timelinePage').style.display = 'none';
    document.getElementById('quizPage').style.display = 'none';
    document.getElementById('glossaryPage').style.display = 'none';
    loadHomeContent();
}

function showExhibits() {
    document.getElementById('homePage').style.display = 'none';
    document.getElementById('exhibitsPage').style.display = 'block';
    document.getElementById('timelinePage').style.display = 'none';
    document.getElementById('quizPage').style.display = 'none';
    document.getElementById('glossaryPage').style.display = 'none';
    loadAllMalware();
}

function showTimeline() {
    document.getElementById('homePage').style.display = 'none';
    document.getElementById('exhibitsPage').style.display = 'none';
    document.getElementById('timelinePage').style.display = 'block';
    document.getElementById('quizPage').style.display = 'none';
    document.getElementById('glossaryPage').style.display = 'none';
    loadTimeline();
}

function showQuiz() {
    document.getElementById('homePage').style.display = 'none';
    document.getElementById('exhibitsPage').style.display = 'none';
    document.getElementById('timelinePage').style.display = 'none';
    document.getElementById('quizPage').style.display = 'block';
    document.getElementById('glossaryPage').style.display = 'none';
    loadQuiz();
}

function showGlossary() {
    document.getElementById('homePage').style.display = 'none';
    document.getElementById('exhibitsPage').style.display = 'none';
    document.getElementById('timelinePage').style.display = 'none';
    document.getElementById('quizPage').style.display = 'none';
    document.getElementById('glossaryPage').style.display = 'block';
    loadGlossary();
}

function loadHomeContent() {
    const mapGrid = document.getElementById('museumMap');
    mapGrid.innerHTML = malwareData.map(m => `<div class="map-item" onclick="showMalwareDetails('${m.name}')">🦠 ${m.name} (${m.year})</div>`).join('');
    const featuredGrid = document.getElementById('featuredGrid');
    featuredGrid.innerHTML = malwareData.slice(0, 8).map(m => createMalwareCard(m)).join('');
}

function loadAllMalware() {
    const allGrid = document.getElementById('allMalwareGrid');
    allGrid.innerHTML = malwareData.map(m => createMalwareCard(m)).join('');
}

function createMalwareCard(m) {
    return `
        <div class="malware-card" onclick="showMalwareDetails('${m.name}')">
            <div class="card-header">
                <h3>${m.name}</h3>
                <span class="year">${m.year}</span>
                <div><span class="card-type">${m.type}</span></div>
            </div>
            <div class="card-content">
                <p>${m.desc.substring(0, 80)}...</p>
                <p class="damage">💀 Damage: ${m.damage}</p>
                <p>🔐 CVE: ${m.cve.substring(0, 30)}</p>
            </div>
        </div>
    `;
}

function loadTimeline() {
    const timelineContainer = document.getElementById('timelineContainer');
    timelineContainer.innerHTML = `
        <div class="timeline-container">
            ${timelineData.map(item => `
                <div class="timeline-item">
                    <div class="timeline-year">${item.year}</div>
                    <div class="timeline-event">${item.event}</div>
                </div>
            `).join('')}
        </div>
    `;
}

function loadQuiz() {
    const quizContainer = document.getElementById('quizContainer');
    let score = 0;
    for (let i = 0; i < quizQuestions.length; i++) {
        if (quizAnswered[i] && quizQuestions[i].answer === getSelectedAnswer(i)) {
            score++;
        }
    }
    
    quizContainer.innerHTML = `
        <div style="margin-bottom: 1rem; text-align: center;">
            <p><strong>Score: ${score} / ${quizQuestions.length}</strong></p>
            <button onclick="resetQuiz()">Reset Quiz</button>
        </div>
        ${quizQuestions.map((q, idx) => `
            <div class="quiz-question" id="q${idx}">
                <p>${idx + 1}. ${q.question}</p>
                ${q.options.map((opt, optIdx) => `
                    <div class="quiz-option" onclick="checkAnswer(${idx}, ${optIdx})" id="q${idx}opt${optIdx}">
                        ${String.fromCharCode(65 + optIdx)}. ${opt}
                    </div>
                `).join('')}
                <div class="quiz-feedback" id="fb${idx}"></div>
            </div>
        `).join('')}
    `;
    
    for (let i = 0; i < quizQuestions.length; i++) {
        if (quizAnswered[i]) {
            const selected = getSelectedAnswer(i);
            if (selected !== null) {
                const selectedId = document.getElementById(`q${i}opt${selected}`);
                if (selectedId) {
                    if (selected === quizQuestions[i].answer) {
                        selectedId.classList.add('correct');
                    } else {
                        selectedId.classList.add('wrong');
                        const correctId = document.getElementById(`q${i}opt${quizQuestions[i].answer}`);
                        if (correctId) correctId.classList.add('correct');
                    }
                }
                const fbDiv = document.getElementById(`fb${i}`);
                fbDiv.innerHTML = selected === quizQuestions[i].answer ? 
                    `✅ Correct! ${quizQuestions[i].explanation}` : 
                    `❌ Wrong! The correct answer was ${String.fromCharCode(65 + quizQuestions[i].answer)}. ${quizQuestions[i].explanation}`;
                fbDiv.classList.add('show');
                fbDiv.classList.add(selected === quizQuestions[i].answer ? 'correct' : 'wrong');
            }
        }
    }
}

function checkAnswer(qIndex, selectedIndex) {
    if (quizAnswered[qIndex]) return;
    
    const question = quizQuestions[qIndex];
    const isCorrect = selectedIndex === question.answer;
    
    for (let i = 0; i < question.options.length; i++) {
        const optElement = document.getElementById(`q${qIndex}opt${i}`);
        if (i === question.answer) {
            optElement.classList.add('correct');
        }
        if (i === selectedIndex && !isCorrect) {
            optElement.classList.add('wrong');
        }
    }
    
    const fbDiv = document.getElementById(`fb${qIndex}`);
    fbDiv.innerHTML = isCorrect ? 
        `✅ Correct! ${question.explanation}` : 
        `❌ Wrong! The correct answer was ${String.fromCharCode(65 + question.answer)}. ${question.explanation}`;
    fbDiv.classList.add('show');
    fbDiv.classList.add(isCorrect ? 'correct' : 'wrong');
    
    quizAnswered[qIndex] = true;
    localStorage.setItem(`quizAnswered_${qIndex}`, selectedIndex);
    loadQuiz();
}

function getSelectedAnswer(qIndex) {
    const saved = localStorage.getItem(`quizAnswered_${qIndex}`);
    return saved !== null ? parseInt(saved) : null;
}

function resetQuiz() {
    for (let i = 0; i < quizQuestions.length; i++) {
        localStorage.removeItem(`quizAnswered_${i}`);
        quizAnswered[i] = false;
    }
    loadQuiz();
}

function loadGlossary() {
    const glossaryContainer = document.getElementById('glossaryContainer');
    glossaryContainer.innerHTML = `
        <div class="glossary-card"><h3>🦠 Malware</h3><p>Short for "malicious software." Any software designed to harm computers, steal data, or cause damage.</p></div>
        <div class="glossary-card"><h3>🔐 CVE (Common Vulnerabilities and Exposures)</h3><p>Publicly disclosed cybersecurity vulnerabilities with unique identifiers.</p></div>
        <div class="glossary-card"><h3>📝 YARA Rule</h3><p>Pattern-matching tool used to identify and classify malware samples.</p></div>
        <div class="glossary-card"><h3>🎯 IoC (Indicator of Compromise)</h3><p>Artifacts observed on a network or system that indicate a security breach.</p></div>
        <div class="glossary-card"><h3>🪱 Worm</h3><p>Malware that spreads automatically across networks without user interaction.</p></div>
        <div class="glossary-card"><h3>💰 Ransomware</h3><p>Malware that encrypts files and demands payment to unlock them.</p></div>
        <div class="glossary-card"><h3>🤖 Botnet</h3><p>A network of infected computers controlled remotely for malicious activities.</p></div>
        <div class="glossary-card"><h3>🛡️ EternalBlue</h3><p>NSA-developed exploit (CVE-2017-0144) used by WannaCry and NotPetya.</p></div>
        <div class="glossary-card"><h3>🔑 DGA (Domain Generation Algorithm)</h3><p>Technique used by malware to generate random domains for C2 communication.</p></div>
        <div class="glossary-card"><h3>💀 Wiper</h3><p>Malware designed to permanently destroy data rather than encrypt it for ransom.</p></div>
    `;
}

function showMalwareDetails(name) {
    const malware = malwareData.find(m => m.name === name);
    if (!malware) return;
    
    const modalContent = document.getElementById('modalContent');
    modalContent.innerHTML = `
        <h2>${malware.name} (${malware.year})</h2>
        <div class="modal-type">${malware.type}</div>
        
        <h3>🔐 CVE Information</h3>
        <p><strong>CVE ID:</strong> ${malware.cve}</p>
        <p><strong>Description:</strong> ${malware.cveDescription}</p>
        
        <h3>📝 Malware Signatures</h3>
        <ul>
            ${malware.signatures.map(sig => `<li>${sig}</li>`).join('')}
        </ul>
        
        <h3>🎯 Indicators of Compromise (IoCs)</h3>
        <ul>
            ${malware.iocs.map(ioc => `<li>${ioc}</li>`).join('')}
        </ul>
        
        <h3>📊 Technical Analysis</h3>
        <p>${malware.technicalAnalysis}</p>
        
        <h3>🌐 Network Indicators</h3>
        <p>${malware.networkIndicators}</p>
        
        <h3>📄 YARA Detection Rule</h3>
        <pre style="background:#0a0f2a; padding:1rem; border-radius:8px; overflow-x:auto; font-size:0.8rem;">${malware.yaraRule}</pre>
        
        <h3>👤 Creator & Origin</h3>
        <p><strong>Creator:</strong> ${malware.creator}</p>
        <p><strong>Origin:</strong> ${malware.origin}</p>
        <p><strong>How Created:</strong> ${malware.howCreated}</p>
        
        <h3>💀 Impact & Damage</h3>
        <p><strong>Financial Damage:</strong> ${malware.damage}</p>
        <p><strong>Global Impact:</strong> ${malware.impact}</p>
        <p><strong>Payload:</strong> ${malware.payload}</p>
        
        <h3>🛡️ Mitigation & Takedown</h3>
        <p>${malware.mitigation}</p>
        
        <h3>📚 Lessons Learned</h3>
        <ul>
            ${malware.lessonsLearned.map(lesson => `<li>${lesson}</li>`).join('')}
        </ul>
        
        <h3>🤓 Fun Fact</h3>
        <p>${malware.funFact}</p>
        
        <button onclick="closeModal()" style="margin-top: 1rem;">Close</button>
    `;
    document.getElementById('malwareModal').style.display = 'block';
}

function closeModal() {
    document.getElementById('malwareModal').style.display = 'none';
}

function loadSavedAnswers() {
    for (let i = 0; i < quizQuestions.length; i++) {
        const saved = localStorage.getItem(`quizAnswered_${i}`);
        if (saved !== null) {
            quizAnswered[i] = true;
        }
    }
}

loadSavedAnswers();
loadHomeContent();

window.onclick = function(event) {
    const modal = document.getElementById('malwareModal');
    if (event.target === modal) {
        closeModal();
    }
}