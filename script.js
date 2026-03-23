// 15 Detailed Malware Specimens with Complete Information
const malwareData = [
    {
        name: "ILOVEYOU",
        year: 2000,
        type: "Worm / Trojan",
        spread: "Email attachment disguised as a love letter with .vbs extension",
        damage: "$10 billion USD worldwide",
        desc: "ILOVEYOU was a computer worm that spread via email with the subject 'ILOVEYOU' and an attachment 'LOVE-LETTER-FOR-YOU.txt.vbs'. When opened, it overwrote files, stole passwords, and sent itself to all contacts in the victim's address book.",
        technical: "Written in VBScript, it used Windows scripting host to execute. It replaced .jpg, .mp3, and other files with copies of itself and added itself to the Windows registry for persistence.",
        prevention: "Never open suspicious email attachments, disable VBScript if not needed, use email filtering, keep antivirus updated.",
        impact: "Infected over 50 million computers in 10 days. Caused the Pentagon, CIA, and British Parliament to shut down their email systems.",
        funFact: "Created by two Filipino students who were not prosecuted because the Philippines had no cybercrime laws at the time.",
        detection: "Antivirus signatures were released within hours, but the worm spread faster than updates could be deployed.",
        origin: "Manila, Philippines",
        payload: "Overwrote files (.jpg, .jpeg, .mp3, .mp2, .vbs, .vbe, .js, .jse, .css, .wsh, .sct, .hta, .pl, .php, .php3, .php4) with copies of itself and stole passwords."
    },
    {
        name: "Melissa",
        year: 1999,
        type: "Macro Virus / Worm",
        spread: "Microsoft Word document shared via email",
        damage: "$80 million USD",
        desc: "Melissa was the first mass-mailing email worm. It spread via an infected Word document that contained a macro. When opened, it sent itself to the first 50 contacts in the user's Outlook address book.",
        technical: "Written as a Word macro using Visual Basic for Applications (VBA). It modified Word's registry to disable macro security warnings.",
        prevention: "Disable macros in Office files from unknown senders, keep Office security settings high, use email filtering.",
        impact: "Caused email servers to overload and crash worldwide. Major companies including Microsoft, Intel, and Lucent Technologies shut down their email systems.",
        funFact: "Named after a stripper in Florida. The creator, David L. Smith, was sentenced to 20 months in federal prison.",
        detection: "Antivirus companies updated signatures within hours, but the damage was already widespread.",
        origin: "New Jersey, USA",
        payload: "Auto-executing macro that replicated and sent emails automatically without user interaction."
    },
    {
        name: "Code Red",
        year: 2001,
        type: "Worm",
        spread: "Microsoft IIS web server vulnerability (buffer overflow)",
        damage: "$2.6 billion USD",
        desc: "Code Red exploited a vulnerability in Microsoft IIS web servers. It defaced websites with 'Hacked by Chinese!' and launched DDoS attacks against the White House website.",
        technical: "Used a buffer overflow vulnerability in Indexing Service DLL. After infection, it spawned 100 threads to find and infect new servers.",
        prevention: "Install security patches immediately, use firewalls, keep web servers updated.",
        impact: "Infected over 350,000 servers in 14 hours. Caused significant internet slowdowns and website defacements.",
        funFact: "Named after the drink Code Red Mountain Dew by the researchers who discovered it. The worm also had a variant called Code Red II.",
        detection: "Signature-based detection was effective, but the worm spread faster than manual patching could keep up.",
        origin: "China (believed)",
        payload: "Defaced websites, launched DDoS attack on White House IP address (198.137.240.91), spread rapidly across the internet."
    },
    {
        name: "Slammer",
        year: 2003,
        type: "Worm",
        spread: "Microsoft SQL Server vulnerability (buffer overflow)",
        damage: "$1.2 billion USD",
        desc: "Slammer (also called Sapphire) was the fastest spreading worm in history. It doubled in size every 8.5 seconds and infected 75,000 computers within 10 minutes.",
        technical: "Exploited a buffer overflow in Microsoft SQL Server Resolution Service. Entire worm code was only 376 bytes, fitting in a single UDP packet.",
        prevention: "Apply SQL Server patches, use firewalls to block SQL ports, disable unused services.",
        impact: "Caused widespread internet outages, ATM failures, and disrupted airline check-in systems. Took down South Korea's internet for 12 hours.",
        funFact: "At its peak, Slammer was scanning for new victims at 55 million IP addresses per second.",
        detection: "Network signatures could detect the worm, but it spread too fast for human response.",
        origin: "Unknown",
        payload: "Random IP scanning for vulnerable SQL servers, no malicious payload beyond replication."
    },
    {
        name: "Blaster",
        year: 2003,
        type: "Worm",
        spread: "Windows RPC vulnerability (DCOM RPC)",
        damage: "$2 billion USD",
        desc: "Blaster (also known as Lovsan) exploited a vulnerability in Windows RPC service. It caused computers to constantly reboot and launched a DDoS attack against windowsupdate.com.",
        technical: "Used a buffer overflow in the DCOM RPC interface. Created a registry key and launched a DDoS attack on Windows Update servers.",
        prevention: "Enable automatic Windows updates, use firewalls, install security patches.",
        impact: "Infected millions of Windows XP and Windows 2000 computers. Caused massive disruption to home users and businesses.",
        funFact: "The worm contained a message to Microsoft: 'billy gates why do you make this possible? Stop making money and fix your software!'",
        detection: "Network scans for port 135 traffic indicated infection. Antivirus signatures were released quickly.",
        origin: "USA (Jeffrey Lee Parson, an 18-year-old from Minnesota, was convicted)",
        payload: "DDoS attack on windowsupdate.com, system reboots, and self-replication."
    },
    {
        name: "Sasser",
        year: 2004,
        type: "Worm",
        spread: "Windows LSASS vulnerability",
        damage: "$500 million USD",
        desc: "Sasser spread by exploiting a vulnerability in Windows Local Security Authority Subsystem Service (LSASS). It caused computers to crash and reboot without user interaction.",
        technical: "Exploited a buffer overflow in the LSASS service. It scanned random IP addresses for vulnerable systems and connected to port 445.",
        prevention: "Apply security patches, enable firewall, use strong passwords.",
        impact: "Infected millions of computers worldwide, disrupted operations at Delta Air Lines, British Airways, and satellite news agencies.",
        funFact: "Written by Sven Jaschan, a 17-year-old German student. He was also responsible for the Netsky worm family.",
        detection: "Antivirus software detected the worm, but it spread through networks faster than manual removal.",
        origin: "Germany",
        payload: "File replication, system instability, no destructive payload but caused widespread disruption."
    },
    {
        name: "Zeus",
        year: 2007,
        type: "Trojan / Botnet",
        spread: "Drive-by downloads, phishing emails",
        damage: "$100 million+ USD",
        desc: "Zeus (Zbot) was a sophisticated Trojan designed to steal banking credentials, credit card information, and personal data from infected computers.",
        technical: "Used man-in-the-browser techniques, form grabbing, and keylogging. Created a massive botnet of infected machines controlled by command-and-control servers.",
        prevention: "Use two-factor authentication, keep antivirus updated, avoid suspicious downloads, use banking in incognito mode.",
        impact: "Infected over 3.6 million computers in the US alone. Stole millions of dollars from bank accounts worldwide.",
        funFact: "The Zeus source code was leaked in 2011, leading to hundreds of variants and spawning the Gameover Zeus botnet.",
        detection: "Difficult to detect due to rootkit capabilities and frequent updates from command servers.",
        origin: "Eastern Europe (believed)",
        payload: "Banking credential theft, keylogging, form grabbing, web injects, botnet participation."
    },
    {
        name: "Stuxnet",
        year: 2010,
        type: "Worm / Cyberweapon",
        spread: "USB drives, network shares",
        damage: "Destroyed approximately 1,000 Iranian nuclear centrifuges",
        desc: "Stuxnet was the first known cyberweapon designed to cause physical damage. It targeted Iranian nuclear facilities and destroyed uranium enrichment centrifuges by altering their rotational speeds.",
        technical: "Used four zero-day vulnerabilities. It infected Siemens Step7 software and sent malicious code to Programmable Logic Controllers (PLCs) controlling centrifuges.",
        prevention: "Air-gap critical systems, use application whitelisting, verify USB drives before use.",
        impact: "Set back Iran's nuclear program by several years. Caused physical destruction of centrifuges without detection for months.",
        funFact: "Stuxnet was discovered by a Belarusian security firm when a customer asked why their systems kept crashing. It was likely a joint US-Israeli operation.",
        detection: "Extremely sophisticated, used stolen digital certificates to appear legitimate. Remained undetected for over a year.",
        origin: "USA / Israel (joint operation believed)",
        payload: "Altered centrifuge speeds to destroy them while reporting normal operation to monitoring systems."
    },
    {
        name: "CryptoLocker",
        year: 2013,
        type: "Ransomware",
        spread: "Email attachments, malicious downloads",
        damage: "$3 million+ USD (first year)",
        desc: "CryptoLocker was the first major ransomware attack. It encrypted users' files and demanded Bitcoin payment to decrypt them, setting the template for modern ransomware.",
        technical: "Used RSA-2048 encryption to lock files. Victims had 72 hours to pay or the private key would be deleted.",
        prevention: "Regular offline backups, do not open suspicious attachments, use email filtering, enable file extensions view.",
        impact: "Infected over 250,000 computers. Estimated $3 million extorted in its first year before takedown.",
        funFact: "CryptoLocker was part of the Gameover Zeus botnet. The FBI and international partners took it down in 2014 through Operation Tovar.",
        detection: "Modern antivirus detects it, but new variants appear regularly.",
        origin: "Eastern Europe (Gameover Zeus gang)",
        payload: "Encrypted files with .encrypted extension, demanded Bitcoin ransom."
    },
    {
        name: "WannaCry",
        year: 2017,
        type: "Ransomware / Worm",
        spread: "EternalBlue exploit (SMB vulnerability)",
        damage: "$4 billion USD",
        desc: "WannaCry was a global ransomware attack that used the EternalBlue exploit, a tool developed by the NSA. It encrypted files and demanded Bitcoin ransom, spreading rapidly across networks.",
        technical: "Exploited SMBv1 vulnerability (MS17-010). Contained a 'kill switch' domain that halted its spread when activated.",
        prevention: "Install security updates immediately, block SMBv1, maintain offline backups.",
        impact: "Infected over 200,000 computers across 150 countries. Shut down UK National Health Service hospitals, causing appointment cancellations and ambulances to be diverted.",
        funFact: "A 22-year-old researcher accidentally stopped the worm by registering the kill switch domain for $10.69.",
        detection: "Network traffic on port 445 indicated infection. Antivirus signatures were released quickly.",
        origin: "North Korea (Lazarus Group, attributed by US and UK governments)",
        payload: "Encrypted files with .WNCRY extension, demanded $300-$600 in Bitcoin, self-propagated via EternalBlue."
    },
    {
        name: "NotPetya",
        year: 2017,
        type: "Ransomware / Wiper",
        spread: "Software update infection (MeDoc), EternalBlue",
        damage: "$10 billion USD",
        desc: "NotPetya disguised itself as ransomware but was actually a destructive wiper designed to destroy data. It spread via a compromised Ukrainian accounting software update.",
        technical: "Used EternalBlue and stolen credentials to spread. It overwrote the Master Boot Record (MBR) and encrypted files with a key that could never be recovered.",
        prevention: "Keep software updated, use application whitelisting, verify software update sources, maintain offline backups.",
        impact: "Caused over $10 billion in damages worldwide. Disrupted Maersk shipping, FedEx, Merck, and many Ukrainian government systems.",
        funFact: "Unlike ransomware, NotPetya had no recovery mechanism. It was a state-sponsored attack disguised as ransomware to hide its true purpose.",
        detection: "Behavioral detection was possible but it spread faster than traditional antivirus could respond.",
        origin: "Russia (attributed by US, UK, and other governments)",
        payload: "Permanent data destruction, Master Boot Record overwrite, file encryption with unrecoverable key."
    },
    {
        name: "Emotet",
        year: 2014,
        type: "Trojan / Botnet",
        spread: "Malicious email attachments, phishing",
        damage: "$2.5 billion USD",
        desc: "Emotet was one of the most dangerous and persistent malware families, often called the 'King of Malware.' It served as a loader for other malware like ransomware and banking Trojans.",
        technical: "Started as a banking Trojan and evolved into a malware delivery service. Used sophisticated email templates, modular design, and constant updates to evade detection.",
        prevention: "Email security, user awareness training, network segmentation, use of EDR solutions.",
        impact: "Infected hundreds of thousands of computers globally. Was responsible for delivering Ryuk ransomware that cost billions in damages.",
        funFact: "Emotet was taken down in January 2021 by a coordinated international law enforcement operation across multiple countries.",
        detection: "Difficult due to constant evolution. Used polymorphic techniques to avoid signature detection.",
        origin: "Unknown (operated as a malware-as-a-service)",
        payload: "Email harvesting, credential theft, payload delivery (ransomware, banking Trojans)."
    },
    {
        name: "Mydoom",
        year: 2004,
        type: "Worm",
        spread: "Email attachments, P2P networks",
        damage: "$38 billion USD",
        desc: "Mydoom holds the record for the fastest-spreading email worm in history. It sent massive volumes of spam and launched DDoS attacks against major companies.",
        technical: "Mass-mailing worm that spoofed sender addresses. Opened backdoors on infected systems and launched DDoS attacks on SCO Group and Microsoft.",
        prevention: "Email filtering, disable automatic email preview, never open suspicious attachments.",
        impact: "At its peak, Mydoom accounted for 25% of all email traffic globally. Caused estimated $38 billion in damages.",
        funFact: "The worm contained messages against SCO Group, which was suing Linux companies at the time. The identity of the creator remains unknown.",
        detection: "Network traffic patterns and email volume indicated infection.",
        origin: "Unknown (likely Russia)",
        payload: "Mass email spam, DDoS attacks, backdoor creation."
    },
    {
        name: "Conficker",
        year: 2008,
        type: "Worm",
        spread: "Windows vulnerability, network shares, USB drives",
        damage: "$9 billion USD",
        desc: "Conficker (Downup) created one of the largest botnets in history, infecting millions of computers across government, business, and home networks.",
        technical: "Exploited Windows Server Service vulnerability (MS08-067). Used dictionary attacks on network passwords and USB autorun to spread.",
        prevention: "Apply security patches, disable autorun, use strong passwords, patch management.",
        impact: "Infected over 9 million computers worldwide. Created a massive botnet used for cybercrime activities.",
        funFact: "Conficker remains one of the most persistent malware. Some infected systems may still be out there today, and its peer-to-peer command structure made it nearly impossible to fully dismantle.",
        detection: "Network scanning on port 445, DNS anomalies, specific registry keys.",
        origin: "Unknown (sophisticated, well-funded group)",
        payload: "Botnet participation, password theft, remote command execution."
    },
    {
        name: "Mirai",
        year: 2016,
        type: "Botnet Malware",
        spread: "IoT device vulnerabilities (default passwords)",
        damage: "Massive internet outages",
        desc: "Mirai infected Internet of Things (IoT) devices like cameras and routers to create massive botnets used for DDoS attacks. It famously took down major parts of the internet.",
        technical: "Scanned the internet for IoT devices using default credentials. Infected devices became part of a botnet controlled by command-and-control servers.",
        prevention: "Change default passwords on IoT devices, keep firmware updated, isolate IoT devices on separate networks.",
        impact: "October 2016, Mirai botnet DDoS attack on Dyn DNS took down Twitter, Netflix, Reddit, Spotify, and many other major websites.",
        funFact: "The creator, a Rutgers University student, was sentenced to probation and later became an FBI informant. The source code was released, leading to hundreds of variants.",
        detection: "Unusual network traffic from IoT devices indicated infection.",
        origin: "USA (Paras Jha, creator)",
        payload: "DDoS attacks, device exploitation, botnet participation."
    }
];

// Timeline Data (15 events)
const timelineData = [
    { year: "1989", event: "Cascade Virus - First polymorphic virus" },
    { year: "1999", event: "Melissa - First major email virus" },
    { year: "2000", event: "ILOVEYOU - Cost $10 billion in damages" },
    { year: "2001", event: "Code Red - Infected 350,000 servers in 14 hours" },
    { year: "2003", event: "Slammer - Fastest spreading worm (doubled every 8.5 seconds)" },
    { year: "2003", event: "Blaster - DDoS attack on Windows Update" },
    { year: "2004", event: "Sasser - Created by a 17-year-old" },
    { year: "2004", event: "Mydoom - Fastest email worm (25% of all email traffic)" },
    { year: "2007", event: "Zeus - Banking Trojan that stole millions" },
    { year: "2008", event: "Conficker - One of largest botnets (9 million+ infections)" },
    { year: "2010", event: "Stuxnet - First cyberweapon causing physical damage" },
    { year: "2013", event: "CryptoLocker - First major ransomware" },
    { year: "2014", event: "Emotet - The 'King of Malware'" },
    { year: "2016", event: "Mirai - IoT botnet took down major internet services" },
    { year: "2017", event: "WannaCry & NotPetya - Global ransomware attacks" }
];

// Quiz Questions (15 questions)
const quizQuestions = [
    { question: "Which malware was spread via a love letter email in 2000 and caused $10 billion in damages?", options: ["Melissa", "ILOVEYOU", "Stuxnet", "WannaCry"], answer: 1, explanation: "ILOVEYOU spread via email with subject 'ILOVEYOU' and caused $10 billion in damages, infecting 50 million computers!" },
    { question: "What type of malware was Stuxnet and what did it target?", options: ["Ransomware targeting banks", "Worm targeting nuclear centrifuges", "Trojan stealing passwords", "Spyware on government systems"], answer: 1, explanation: "Stuxnet was the first cyberweapon - a worm that destroyed Iranian nuclear centrifuges by altering their speeds." },
    { question: "Which ransomware used the EternalBlue exploit to shut down UK hospitals in 2017?", options: ["CryptoLocker", "Zeus", "WannaCry", "NotPetya"], answer: 2, explanation: "WannaCry infected over 200,000 computers across 150 countries, including UK's National Health Service hospitals." },
    { question: "What does malware stand for?", options: ["Malicious Hardware", "Malicious Software", "Malfunctioning Wear", "Manual Ware"], answer: 1, explanation: "Malware = Malicious Software. Any software designed to harm computers, steal data, or cause damage." },
    { question: "What made the Slammer worm unique?", options: ["It targeted Mac computers", "Fastest spreading worm (doubled every 8.5 seconds)", "First ransomware", "Created by a teenager"], answer: 1, explanation: "Slammer (Sapphire) was the fastest spreading worm in history, doubling every 8.5 seconds!" },
    { question: "Which malware was disguised as ransomware but was actually a destructive wiper?", options: ["WannaCry", "CryptoLocker", "NotPetya", "Zeus"], answer: 2, explanation: "NotPetya pretended to be ransomware but was actually designed to permanently destroy data with no recovery." },
    { question: "What was unique about the Mirai botnet?", options: ["Attacked Mac computers", "Infected IoT devices like cameras and routers", "First ransomware", "Spread via email"], answer: 1, explanation: "Mirai infected Internet of Things (IoT) devices using default passwords and launched massive DDoS attacks." },
    { question: "Which malware holds the record for fastest email worm (25% of all email traffic)?", options: ["Melissa", "ILOVEYOU", "Mydoom", "Blaster"], answer: 2, explanation: "Mydoom held the record, causing estimated $38 billion in damages and accounting for 25% of all email traffic at its peak." },
    { question: "What was the 'kill switch' that stopped WannaCry?", options: ["Antivirus update", "Domain registration", "Windows patch", "Computer restart"], answer: 1, explanation: "A researcher accidentally stopped WannaCry by registering a domain found in the code, which acted as a kill switch." },
    { question: "What did CryptoLocker do to files?", options: ["Deleted them", "Encrypted them for ransom", "Stole them", "Made them read-only"], answer: 1, explanation: "CryptoLocker was the first major ransomware - it encrypted files and demanded Bitcoin payment for decryption." },
    { question: "Which malware was called the 'King of Malware'?", options: ["Zeus", "Stuxnet", "Emotet", "Conficker"], answer: 2, explanation: "Emotet was called the 'King of Malware' because it served as a loader for other malware like ransomware." },
    { question: "How did the Code Red worm spread?", options: ["Email attachments", "USB drives", "Web server vulnerability", "Text messages"], answer: 2, explanation: "Code Red exploited a buffer overflow vulnerability in Microsoft IIS web servers." },
    { question: "What was unique about the Zeus Trojan?", options: ["Stole banking credentials", "Destroyed hardware", "Spread via Bluetooth", "Targeted Mac"], answer: 0, explanation: "Zeus was a sophisticated banking Trojan that stole millions of dollars from bank accounts worldwide." },
    { question: "What technology did the Conficker worm use to spread?", options: ["Email", "USB drives and network shares", "Bluetooth", "WiFi"], answer: 1, explanation: "Conficker spread through USB drives, network shares, and exploited Windows vulnerabilities." },
    { question: "What made the Melissa virus unique in 1999?", options: ["First mass-mailing email virus", "First ransomware", "First to target Mac", "First to use AI"], answer: 0, explanation: "Melissa was the first mass-mailing email virus, sending itself to the first 50 contacts in Outlook." }
];

let quizAnswered = new Array(quizQuestions.length).fill(false);

// Navigation Functions
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
                <p>🛡️ Spread: ${m.spread.substring(0, 50)}...</p>
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
        <div class="glossary-card"><h3>🐛 Virus</h3><p>Malware that spreads by attaching to other programs and replicates when those programs run.</p></div>
        <div class="glossary-card"><h3>🪱 Worm</h3><p>Malware that spreads automatically across networks without user interaction.</p></div>
        <div class="glossary-card"><h3>💰 Ransomware</h3><p>Malware that encrypts files and demands payment to unlock them.</p></div>
        <div class="glossary-card"><h3>🎭 Trojan</h3><p>Malware disguised as legitimate software to trick users into installing it.</p></div>
        <div class="glossary-card"><h3>🎣 Phishing</h3><p>Fake emails or websites that trick people into revealing passwords or personal information.</p></div>
        <div class="glossary-card"><h3>🤖 Botnet</h3><p>A network of infected computers controlled remotely for malicious activities like DDoS attacks.</p></div>
        <div class="glossary-card"><h3>🔐 Zero-day</h3><p>A software vulnerability that is unknown to the vendor and has no patch available.</p></div>
        <div class="glossary-card"><h3>🛡️ DDoS</h3><p>Distributed Denial of Service - overwhelming a server with traffic to make it unavailable.</p></div>
    `;
}

function showMalwareDetails(name) {
    const malware = malwareData.find(m => m.name === name);
    if (!malware) return;
    
    const modalContent = document.getElementById('modalContent');
    modalContent.innerHTML = `
        <h2>${malware.name} (${malware.year})</h2>
        <div class="modal-type">${malware.type}</div>
        <p><strong>📧 How it spread:</strong> ${malware.spread}</p>
        <p><strong>💀 Damage caused:</strong> ${malware.damage}</p>
        <p><strong>📝 What it did:</strong> ${malware.desc}</p>
        <p><strong>🔧 Technical Details:</strong> ${malware.technical}</p>
        <p><strong>🌍 Origin:</strong> ${malware.origin || "Unknown"}</p>
        <p><strong>⚙️ Payload:</strong> ${malware.payload}</p>
        <p><strong>🛡️ How to stay safe:</strong> ${malware.prevention}</p>
        <p><strong>🤓 Fun Fact:</strong> ${malware.funFact}</p>
        <p><strong>🕵️ Detection:</strong> ${malware.detection || "Antivirus signatures and behavioral analysis"}</p>
        <p><strong>📊 Global Impact:</strong> ${malware.impact}</p>
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