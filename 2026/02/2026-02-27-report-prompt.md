
## 2026-002: Multiple Vulnerabilities in Cisco Products
Cisco released security advisories on February 25, 2026, addressing multiple high and critical severity vulnerabilities in Cisco Catalyst SD-WAN controllers and Cisco SD-WAN Manager. The vulnerability CVE-2026-20127, with a CVSS score of 10, is an authentication bypass vulnerability exploited since 2023. Affected products include versions earlier than 20.9 and several versions between 20.9 and 20.18. 
analyse: Cisco released security advisories on February 25, 2026, addressing multiple high and critical severity vulnerabilities in Cisco Catalyst SD-WAN controllers and Cisco SD-WAN Manager. One vulnerability, CVE-2026-20127, has been exploited since 2023, allowing attackers to gain administrative access. Affected products include versions earlier than 20.9 and specific versions up to 20.18.
Strategic recommendations include:
*   Securing forensic evidence and reviewing SD-WAN configurations.
*   Updating affected devices to the latest fixed versions.
*   Restricting external access to SD-WAN management interfaces.
*   Auditing authentication logs for unauthorized access.
*   Validating peering events against a defined checklist. 
tags: ['Cisco', 'vulnerabilities', 'Catalyst', 'SD-WAN', 'Controller', 'Manager', 'authentication', 'bypass', 'CVE-2026-20127', 'root'] 
observables: {'directory': ['/var/log'], 'domain-name': ['cisco.com', 'cyber.gov.au', 'ncsc.gov.uk'], 'ipv4-addr': ['20.12.5.3', '20.12.6.1', '20.15.4.2', '20.18.2.1', '20.9.8.2'], 'url': ['http://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sd-wan-priv-E6e8tEdF.html[4', 'http://www.cyber.gov.au/sites/default/files/2026-02/ACSC-led%20Cisco%20SD-WAN%20Hunt%20Guide.pdf[5', 'http://www.ncsc.gov.uk/news/exploitation-cisco-catalyst-sd-wans', 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v[3', 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa-EHchtZk[2', 'https://sec.cloudapps.cisco.com/security/center/resources/Cisco-Catalyst-SD-WAN-HardeningGuide', 'https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sd-wan-priv-E6e8tEdF.html[4', 'https://www.cyber.gov.au/sites/default/files/2026-02/ACSC-led%20Cisco%20SD-WAN%20Hunt%20Guide.pdf[5', 'https://www.ncsc.gov.uk/news/exploitation-cisco-catalyst-sd-wans'], 'vulnerability': ['CVE-2026-20127', 'CVE-2026-20129', 'CVE-2026-20126', 'CVE-2026-20133', 'CVE-2026-20122', 'CVE-2026-20128', 'CVE-2022-20775']}
Publication date: Thu, 26 Feb 2026 19:38:52 CET
Source type: ['operational']
Sources: https://cert.europa.eu/publications/security-advisories/2026-002/        
Source level: 1

## ISC Stormcast For Friday, February 27th, 2026 https://isc.sans.edu/podcastdetail/9828, (Fri, Feb 27th)
The class is titled "Diary Archives." 
analyse: The provided text indicates a class titled "Diary Archives." No strategic analysis or cyber recommendations can be generated from this limited information. 
tags: ['Diary', 'Archives'] 
observables: {}
Publication date: Fri, 27 Feb 2026 02:00:02 GMT
Source type: ['operational', 'strategical']
Sources: https://isc.sans.edu/diary/rss/32752
Source level: 2

## Finding Signal in the Noise: Lessons Learned Running a Honeypot with AI Assistance &#x5b;Guest Diary&#x5d;, (Tue, Feb 24th)
The DShield honeypot is a sensor that pretends to be a vulnerable system exposed to the internet. Austin Bodolay, an ISC intern, used ChatGPT to assist in analyzing data collected from the honeypot, which included 8 million logs from 14,000 unique IP addresses. ChatGPT helped identify potential threats, validate conclusions, and avoid wasted time during investigations. The honeypot collects basic information such as source IP addresses, port, protocol, and URL. 
analyse: The DShield honeypot collects data from automated scans and attacks, generating 8 million logs from 14,000 unique IP addresses. Analysis using ChatGPT revealed a User-Agent "libredtail-http" associated with an automated multi-staged toolkit scanning for vulnerable Apache servers, Linux web interfaces, and IoT devices. The honeypot logs primarily record incoming traffic, and lack payload content, hindering comprehensive incident analysis. 
tags: ['DShield', 'SIEM', 'Analysis', 'libredtailhttp', 'ChatGPT', 'Investigation', 'DShield', 'BACS'] 
observables: {'domain-name': ['cisa.gov', 'cve.org', 'sans.edu'], 'ipv4-addr': ['100.173.183.197', '184.200.100.31', '20.86.82.62', '45.43.37.254', '45.48.37.254', '45.49.37.254', '46.43.37.204', '48.43.37.204', '94.247.150.119', '98.117.22.183'], 'url': ['http://www.cisa.gov/news-events/cybersecurity-advisories/aa24-016a', 'http://www.cve.org/CVERecord?id=CVE-2021-42013', 'http://www.sans.edu/cyber-security-programs/bachelors-degree', 'https://blog.cloudflare.com/measuring-network-connections-at-scale/', 'https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013', 'https://chatgpt.com/', 'https://github.com/bruneaug/DShield-Sensor', 'https://github.com/bruneaug/DShield-SIEM', 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773', 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-016a', 'https://www.cve.org/CVERecord?id=CVE-2021-42013', 'https://www.sans.edu/cyber-security-programs/bachelors-degree/'], 'vulnerability': ['CVE-2021-42013', 'CVE-2021-41773']}
Publication date: Thu, 26 Feb 2026 12:21:37 GMT
Source type: ['operational', 'strategical']
Sources: https://isc.sans.edu/diary/rss/32744
Source level: 2

## The CLAIR Model: A Synthesized Conceptual Framework for Mapping Critical Infrastructure Interdependencies &#x5b;Guest Diary&#x5d;, (Wed, Feb 25th)
The threat level is green. Xavier Mertens is the handler on duty. The next class is Application Security: Securing Web Apps, APIs, and Microservices in Orlando from March 29th to April 3rd, 2026. The CLAIR Model is a new conceptual framework that synthesizes the Purdue Enterprise Reference Architecture with the Zachman Framework for Enterprise Architecture. The CLAIR Model expands the traditional five-level Purdue hierarchy into a ten-level architectural stack. A cascading failure is a sequence where one component malfunction triggers successive failures. 
analyse: The threat level is green. The CLAIR Model is a conceptual framework synthesizing the Purdue Enterprise Reference Architecture and the Zachman Framework to map critical infrastructure interdependencies. The model expands the traditional five-level Purdue hierarchy into a ten-level architectural stack, incorporating dependencies on primary utility infrastructure and cloud systems. Power grid failures can trigger cascading effects on data centers, potentially leading to information blindness and business discontinuity. 
tags: ['CLAIR', 'Purdue', 'Zachman', 'Fortinet', 'IT', 'OT', 'cyber', 'data center', 'power grid', 'infrastructure'] 
observables: {'domain-name': ['cyber.gov.au', 'fortinet.com', 'opengroup.org'], 'url': ['https://doi.org/10.1111/j.1530-9290.2008.00004.x', 'https://doi.org/10.6028/NIST.SP.800-40r4']}
Publication date: Thu, 26 Feb 2026 12:21:26 GMT
Source type: ['operational', 'strategical']
Sources: https://isc.sans.edu/diary/rss/32748
Source level: 2

## ISC Stormcast For Thursday, February 26th, 2026 https://isc.sans.edu/podcastdetail/9826, (Thu, Feb 26th)
The class is titled Diary Archives. 
analyse: The provided text indicates the subject of the next class is "Diary Archives." No strategic analysis or cyber recommendations can be derived from this information. 
tags: ['Diary', 'Archives'] 
observables: {}
Publication date: Thu, 26 Feb 2026 02:00:03 GMT
Source type: ['operational', 'strategical']
Sources: https://isc.sans.edu/diary/rss/32750
Source level: 2
## Previously harmless Google API keys now expose Gemini AI data
Researchers discovered nearly 3,000 Google API keys exposed in publicly accessible code, potentially allowing access to private data through the Gemini AI assistant. These keys, previously considered harmless, now grant authentication to the Gemini API, potentially costing attackers thousands of dollars in API usage charges. Google has implemented measures to block leaked keys and is notifying developers to audit and rotate their API keys. 
analyse: Previously harmless Google API keys, now used for authentication with the Gemini AI assistant, have been exposed in publicly accessible code. Researchers discovered approximately 2,800 live Google API keys, some belonging to major financial institutions, which could allow attackers to access private data and incur significant charges. Google has implemented measures to block leaked keys and is notifying users of potential exposures, advising developers to audit and rotate their API keys. The TruffleHog tool can be used to detect exposed keys. 
tags: ['API', 'API Key', 'Gemini', 'Gemini AI', 'Google Gemini', 'Key', 'Secrets', 'Google', 'TruffleSecurity', 'Developers'] 
observables: {'domain-name': ['handle.in']}
Publication date: Thu, 26 Feb 2026 15:55:29 -0500
Source type: ['operational', 'vulnerabilities']
Sources: https://www.bleepingcomputer.com/news/security/previously-harmless-google-api-keys-now-expose-gemini-ai-data/
Source level: 2

## Trend Micro warns of critical Apex One code execution flaws
Trend Micro has patched two critical Apex One vulnerabilities, CVE-2025-71210 and CVE-2025-71211, which allow for remote code execution (RCE) on Windows systems. These vulnerabilities are path traversal weaknesses in the Apex One management console, requiring access to the console. Trend Micro has released Critical Patch Build 14136 to address these flaws, as well as two high-severity privilege escalation flaws in the Windows agent and four affecting the macOS agent. 
analyse: Trend Micro has patched two critical Apex One vulnerabilities, CVE-2025-71210 and CVE-2025-71211, which allow for remote code execution (RCE) on Windows systems. These vulnerabilities are path traversal weaknesses in the Apex One management console, potentially exploitable by attackers with access to the console. Trend Micro recommends immediate updates to the latest builds, especially for those with externally exposed console IP addresses. CISA tracks 10 Trend Micro Apex vulnerabilities that have been or are being exploited. 
tags: ['Trend Micro', 'Apex One', 'RCE', 'Remote Code Execution', 'Vulnerability', 'Windows', 'macOS', 'CVE-2025-71210', 'CVE-2025-71211', 'CVE-2025-54948'] 
observables: {'domain-name': ['handle.in'], 'vulnerability': ['CVE-2025-71210', 'CVE-2025-71211', 'CVE-2025-54948', 'CVE-2022-40139', 'CVE-2023-41179']}
Publication date: Thu, 26 Feb 2026 12:58:28 -0500
Source type: ['operational', 'vulnerabilities']
Sources: https://www.bleepingcomputer.com/news/security/trend-micro-warns-of-critical-apex-one-rce-vulnerabilities/
Source level: 2

## European DYI chain ManoMano data breach impacts 38 million customers
ManoMano, a French e-commerce firm, experienced a data breach impacting 38 million customers. The breach occurred in January 2026 due to a compromise of a third-party customer service provider. Exposed data includes full names, email addresses, phone numbers, and customer service communications, but not account passwords. 
analyse: The data breach at ManoMano impacted 38 million customers, resulting from a compromise of a third-party customer service provider in January 2026. Compromised data includes full names, email addresses, phone numbers, and customer service communications, but not account passwords or data modifications on ManoMano's systems. The company is notifying customers and has alerted the CNIL and ANSSI, while an investigation is ongoing. 
tags: ['Data Breach', 'ManoMano', 'Customer Data', 'Third-Party Data Breach', 'Notification', 'Customer Support', 'DIY', 'E-Commerce', 'Bill Toulas', 'Zendesk'] 
observables: {'domain-name': ['handle.in']}
Publication date: Thu, 26 Feb 2026 12:35:21 -0500
Source type: ['operational', 'vulnerabilities']
Sources: https://www.bleepingcomputer.com/news/security/european-dyi-chain-manomano-data-breach-impacts-38-million-customers/
Source level: 2

## Critical Juniper Networks PTX flaw allows full router takeover
A critical vulnerability (CVE-2026-21902) in Junos OS Evolved running on PTX Series routers allows an unauthenticated attacker to execute code remotely with root privileges. The vulnerability is caused by incorrect permission assignment in the ‘On-Box Anomaly Detection’ framework, affecting versions before 25.4R1-S1-EVO and 25.4R2-EVO. Juniper's SIRT was not aware of malicious exploitation of the vulnerability at the time of publishing the security bulletin. 
analyse: A critical vulnerability (CVE-2026-21902) in Juniper Networks PTX Series routers allows unauthenticated attackers to execute code remotely with root privileges. The vulnerability affects Junos OS Evolved versions before 25.4R1-S1-EVO and 25.4R2-EVO, and Juniper Networks SIRT has not observed malicious exploitation. Previous incidents include Chinese cyber-espionage deploying backdoors (March 2025), a malware campaign targeting VPN gateways (January 2025), and Mirai botnet campaigns (December 2024).
Cyber recommendations:
*   Upgrade to Junos OS Evolved versions 25.4R1-S1-EVO, 25.4R2-EVO, or 26.2R1-EVO.
*   Restrict access to vulnerable endpoints using firewall filters or ACLs if patching is not immediately possible.
*   Disable the vulnerable service using the command 'request pfe anomalies disable'. 
tags: ['CVE-2026-21902', 'Juniper', 'Junos', 'RCE', 'Remote Code Execution', 'Router', 'Vulnerability', 'PTX', 'Junos OS Evolved', 'J-magic'] 
observables: {'domain-name': ['handle.in'], 'vulnerability': ['CVE-2026-21902']}
Publication date: Thu, 26 Feb 2026 11:42:12 -0500
Source type: ['operational', 'vulnerabilities']
Sources: https://www.bleepingcomputer.com/news/security/critical-juniper-networks-ptx-flaw-allows-full-router-takeover/
Source level: 2

## Olympique Marseille confirms 'attempted' cyberattack after data leak
Olympique de Marseille confirmed an attempted cyberattack following claims by a threat actor who breached the club's systems earlier this month. The threat actor leaked a sample of allegedly stolen information on a hacking forum, claiming to have stolen a database containing information on 400,000 individuals. Olympique Marseille reported the incident to the French data protection authority (CNIL) and advised fans to remain vigilant against phishing attempts. 
analyse: Olympique de Marseille confirmed an attempted cyberattack following claims by a threat actor who breached the club's systems. The threat actor leaked a sample of data, alleging a database containing information on approximately 400,000 individuals was stolen, including names, addresses, and email addresses. The club reported the incident to the French data protection authority (CNIL) and advised supporters to remain vigilant against phishing attempts. 
tags: ['Cyberattack', 'Data Breach', 'Data Leak', 'Football', 'Olympique de Marseille', 'Threat Actor', 'CNIL', 'Phishing', 'Database', 'Ligue 1'] 
observables: {'domain-name': ['handle.in']}
Publication date: Thu, 26 Feb 2026 11:11:30 -0500
Source type: ['operational', 'vulnerabilities']
Sources: https://www.bleepingcomputer.com/news/security/olympique-marseille-football-club-confirms-cyberattack-after-data-leak/
Source level: 2

## Ransomware payment rate drops to record low as attacks surge
The number of ransomware victims paying threat actors dropped to 28% last year, marking an all-time low. Despite this decrease, the number of claimed ransomware attacks increased significantly. The total of on-chain ransomware payments in 2025 stood at $820 million, and is likely to exceed $900 million. The median ransom payment rose significantly, up 368% from $12,738 in 2024 to $59,556 in 2025. 
analyse: The ransomware payment rate decreased to 28% last year, marking an all-time low, despite a 50% increase in ransomware attacks year-over-year. Total on-chain ransomware payments in 2025 reached $820 million, potentially nearing $900 million. The median ransom payment significantly increased to $59,556 in 2025, suggesting victims are paying larger amounts to potentially ensure data deletion. The United States remains the most targeted country, followed by Canada, Germany, and the U.K. 
tags: ['Ransomware', 'Chainalysis', 'Payment', 'Victim', 'Attack', 'Ransom', 'Data', 'Threat Actors', 'RaaS', 'IABs'] 
observables: {'domain-name': ['handle.in']}
Publication date: Thu, 26 Feb 2026 09:00:59 -0500
Source type: ['operational', 'vulnerabilities']
Sources: https://www.bleepingcomputer.com/news/security/ransomware-payment-rate-drops-to-record-low-as-attacks-surge/
Source level: 2

## Microsoft expands Windows restore to more enterprise devices
Microsoft now allows enterprise users to restore personal settings and Microsoft Store apps from a previous Windows 11 device. The feature, called the first sign-in restore experience, extends support to hybrid-managed environments, multi-user device setups, and Windows 365 Cloud PCs. General availability begins with devices that have installed Windows updates released February 24, 2026, and later. 
analyse: Microsoft is expanding the Windows 11 first sign-in restore experience to more enterprise devices, previously limited to Microsoft Entra-joined devices. This feature, part of Windows Backup for Organizations, allows users to restore settings and Microsoft Store apps from a previous device during initial login. IT administrators can manage this feature through existing Windows Backup for Organizations policies using Microsoft Intune or Group Policy. 
tags: ['Microsoft', 'Windows', 'Windows 11', 'Windows Backup', 'Enterprise', 'Microsoft Entra', 'Microsoft Store', 'Hybrid', 'Intune', 'Group Policy'] 
observables: {'domain-name': ['handle.in']}
Publication date: Thu, 26 Feb 2026 08:04:02 -0500
Source type: ['operational', 'vulnerabilities']
Sources: https://www.bleepingcomputer.com/news/security/microsoft-expands-windows-restore-to-more-enterprise-devices/
Source level: 2

## Multiple Vulnerabilities in Cisco Catalyst SD-WAN Products Could Allow for Authentication Bypass
Multiple vulnerabilities have been discovered in Cisco Catalyst SD-WAN products, with the most severe allowing an unauthenticated, remote attacker to bypass authentication and obtain administrative privileges. CISA added CVE-2026-20127 and CVE-2022-20775 to its Known Exploited Vulnerabilities (KEV) Catalog on February 25, 2026. Affected systems include Cisco Catalyst SD-WAN Manager versions prior to 20.9.8.2, 20.11, 20.12.5 versions prior to 20.12.5.3, 20.12.6 versions prior to 20.12.6.1, 20.13, 20.14, 20.15 versions prior to 20.15.4.2, 20.16, and 20.18 versions prior to 20.18.2.1. Recommendations include applying updates from Cisco and implementing vulnerability management processes. 
analyse: Multiple vulnerabilities exist in Cisco Catalyst SD-WAN products, with the most severe allowing unauthenticated remote attackers to bypass authentication and obtain administrative privileges. CISA added CVE-2026-20127 and CVE-2022-20775 to its Known Exploited Vulnerabilities Catalog, and malicious actors have been observed exploiting these vulnerabilities to compromise systems globally. Affected products include Cisco Catalyst SD-WAN Manager versions prior to 20.9.8.2, 20.11, 20.12.5, 20.12.6, 20.13, 20.14, 20.15, 20.16, and 20.18. Recommendations include applying vendor updates, establishing a vulnerability management process, performing automated vulnerability scans, and implementing network segmentation. 
tags: ['CVE-2026-20127', 'CVE-2022-20775', 'Cisco', 'SD-WAN', 'authentication', 'bypass', 'Cisco Catalyst', 'CISA', 'vulnerability', 'administrative privileges'] 
observables: {'domain-name': ['cisa.gov', 'cve.mitre.org', 'sec.cloudapps.cisco.com'], 'ipv4-addr': ['20.9.8.2'], 'url': ['http://www.cisa.gov/news-events/news/immediate-action-required-cisa-issues-emergency-directive-secure-cisco-sd-wan-systemsCVEhttps://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-20127https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-20122https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-20126https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-20128https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-20129https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-20133Ciscohttps://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa-EHchtZkhttps://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v'], 'vulnerability': ['CVE-2026-20127', 'CVE-2022-20775', 'CVE-2026-20129', 'CVE-2026-20126', 'CVE-2026-20133', 'CVE-2026-20122', 'CVE-2026-20128'], 'mitre': {'tactic': ['TA0001']}}
Publication date: Thu, 26 Feb 2026 01:24:58 -0500
Source type: ['']
Sources: https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-cisco-catalyst-sd-wan-products-could-allow-for-authentication-bypass_2026-016
Source level: 2

## Why law firms need smarter cybersecurity solutions
Law firms are prime targets for cybercriminals due to the sensitive information they handle, including client records, case details, and financial data. Ransomware attacks on law firms have increased in recent years, and phishing schemes are becoming more sophisticated. Field Effect MDR offers two options, MDR Core and MDR Complete, combining technology and expert analysis to simplify cybersecurity for legal practices. 
analyse: Law firms are prime targets for cybercriminals due to the sensitive information they handle, and many firms rely on outdated security measures. Ransomware attacks and phishing schemes are increasingly targeting law firms, potentially leading to financial loss and reputational damage. Compliance with regulations like PIPEDA and GDPR requires robust safeguards and breach notifications, which can be challenging for smaller firms. Field Effect MDR offers tailored cybersecurity solutions, including MDR Core and MDR Complete, combining technology and expert analysis for threat detection and neutralization. 
tags: ['cybersecurity', 'law firms', 'data', 'security', 'breach', 'ransomware', 'phishing', 'compliance', 'Field Effect MDR', 'clients'] 
observables: {}
Publication date: Thu, 26 Feb 2026 05:45:00 GMT
Source type: ['operational']
Sources: https://fieldeffect.com/blog/law-firms-cybersecurity
Source level: 2

## OWASP Top 10:2025 – Wenn Framework-Komplexität zum Geschäftsrisiko wird
The OWASP Top 10 is a regularly published ranking of the ten most critical web application security risks. The 2021 version has been replaced by the OWASP Top 10:2025, reflecting a shift towards managing the integrity and security of the entire ecosystem on which web applications are built. Server-Side Request Forgery (SSRF) has been reclassified under Broken Access Control (A01), and Software Supply Chain (A03) has been newly prioritized due to the increasing reliance on third-party code. Mishandling of Exceptional Conditions (A10) is also a new addition to the list. 
analyse: The OWASP Top 10:2025 replaced the 2021 version, reflecting a shift towards recognizing the risks associated with modern web application development practices. The new list emphasizes the importance of software supply chain integrity, prioritizing it due to the increasing reliance on third-party code and frameworks. Server-Side Request Forgery (SSRF) has been reclassified under Broken Access Control, highlighting its systemic nature. Mishandling of Exceptional Conditions is a new category, addressing system stability and resilience under stress. 
tags: ['OWASP', 'Webanwendungen', 'Sicherheitsrisiken', 'Schwachstellen', 'Top 10', 'SSRF', 'Zugriffskontrolle', 'Software Supply Chain', 'Frameworks', 'Bibliotheken'] 
observables: {}
Publication date: Thu, 26 Feb 2026 10:59:42 +0000
Source type: ['operational']
Sources: https://research.hisolutions.com/2026/02/owasp-top-102025-wenn-framework-komplexitaet-zum-geschaeftsrisiko-wird/
Source level: 2

## Proofpoint Collaboration Security Integrates with New Extended Plan for AWS Security Hub 
Proofpoint Collaboration Protection is now integrated with the Extended plan in AWS Security Hub. This integration provides customers with Proofpoint's threat protection across email, messaging, and collaboration tools through a single vendor experience. The Extended Plan for AWS Security Hub is immediately available in all commercial AWS regions. 
analyse: Proofpoint Collaboration Security is now integrated with the Extended plan in AWS Security Hub, offering a unified vendor experience with consolidated support and flexible pricing. This integration provides advanced threat protection across email, messaging, and collaboration tools, leveraging Proofpoint’s Nexus AI threat detection stack. The Extended Plan for AWS Security Hub is immediately available in all commercial AWS regions. 
tags: ['Proofpoint', 'AWS', 'Security Hub', 'Extended Plan', 'Collaboration Security', 'threat protection', 'AI', 'email', 'messaging', 'collaboration'] 
observables: {'domain-name': ['proofpoint.com'], 'url': ['http://www.proofpoint.com']}
Publication date: 26 Feb 2026 14:38:07
Source type: ['']
Sources: https://www.proofpoint.com/us/newsroom/press-releases/proofpoint-collaboration-security-integrates-new-extended-plan-aws-security
Source level: 1

## Recorded Future Expands Coverage of Scams and Financial Fraud with Money Mule Intelligence from CYBERA
Recorded Future is partnering with CYBERA to expand payment fraud prevention capabilities through Money Mule Intelligence. Authorized Push Payment (APP) fraud losses are projected to reach nearly $15 billion in the U.S. by 2028. CYBERA's AI-powered Scam Engagement System verifies bank accounts and payment endpoints actively used by scam networks, supporting on-us mule detection and off-us screening. 
analyse: APP fraud losses are projected to reach nearly $15B in the U.S. by 2028, up from $8.3B in 2024. Mule accounts are critical infrastructure for APP fraud, converting stolen payments into untraceable cash or cryptocurrency. CYBERA's AI-powered Scam Engagement System verifies bank accounts and payment endpoints actively used by scam networks, providing evidence and contextual metadata. CYBERA supports On-Us Mule Detection and Off-Us Screening use cases. 
tags: ['Recorded Future', 'CYBERA', 'APP fraud', 'Deloitte', 'FedNow', 'Zelle', 'mule accounts', 'money mules', 'AI', 'CYBERA\'s Approach'] 
observables: {}
Publication date: Thu, 26 Feb 2026 00:00:00 GMT
Source type: ['']
Sources: https://www.recordedfuture.com/blog/recorded-future-money-mule-intelligence-cybera
Source level: 2

## How AI Aids Incident Response: Why Humans Alone Cannot Do IR Efficiently
AI accelerates incident response by correlating alerts and generating reports in minutes, helping teams scale beyond manual limits. A typical security investigation can take around 10-20 minutes, and complex incidents can take many days. AI can ingest and analyze data from multiple sources, such as endpoint telemetry, identity and access logs, and network flow data, within seconds. AI-based incident response also enhances all stages of the National Institute of Standards and Technology’s SP 800-61 incident handling model. 
analyse: AI accelerates incident response by correlating alerts and generating reports in minutes, helping teams scale beyond manual limits. Security investigations can take 10-20 minutes traditionally, but AI can deliver formatted summaries in minutes. AI can aggregate and correlate data across systems faster than human teams by analyzing data in parallel from sources like SIEM platforms, EDR, and threat intelligence feeds. AI-based incident response enhances all stages of the National Institute of Standards and Technology’s SP 800-61 incident handling model, including detection, containment, investigation, and reporting. AI incident response requires log data access, security tool integration, and threat intelligence feed access. 
tags: ['CVE-2026-1731', 'BeyondTrust', 'Cisco', 'SD-WAN', 'UNC2814', 'Claude', 'CarGurus', 'Soliton Systems', 'SolarWinds', 'VMware', 'Arkanix', 'Lazarus', 'APT28', 'Everest', 'Vikor Scientific', 'XMRig', 'Romanian hacker', 'AI', 'MITRE ATLAS', 'EU AI Act'] 
observables: {'email-addr': ['pierluigi.paganini@securityaffairs.co'], 'vulnerability': ['CVE-2026-1731']}
Publication date: Fri, 27 Feb 2026 08:50:53 +0000
Source type: ['']
Sources: https://securityaffairs.com/188599/ai/how-ai-aids-incident-response-why-humans-alone-cannot-do-ir-efficiently.html
Source level: 2

## 12 Million exposed .env files reveal widespread security failures
Mysterium VPN identified 12,088,677 IP addresses serving publicly accessible .env-style files, revealing credentials and tokens. The United States leads with nearly 2.8 million exposed IPs, followed by Japan, Germany, India, France, and the UK. Exposed files contained database credentials, API keys, and JWT signing secrets, potentially enabling attackers to bypass the break-in phase. Organizations must treat exposed .env files as a full security incident and implement layered defenses, including secret management systems and automated scanning. 
analyse: Mysterium VPN identified 12,088,677 IP addresses serving publicly accessible .env-style files, revealing credentials and tokens. The United States leads with nearly 2.8 million exposed IPs, followed by Japan, Germany, India, France, and the UK. Exposed secrets can enable data theft, privilege escalation, and financial abuse, often stemming from preventable errors like missing deny rules or forgotten backup files. Organizations should immediately remove public access, purge caches, rotate secrets, and implement automated secret scanning. 
tags: ['.env files', 'data breach', 'data leak', 'Hacking', 'APT', 'SECURITY', 'ARTIFICIAL INTELLIGENCE', 'Cyber Crime', 'Cyber warfare', 'Hacktivism'] 
observables: {'email-addr': ['pierluigi.paganini@securityaffairs.co'], 'vulnerability': ['CVE-2026-1731']}
Publication date: Fri, 27 Feb 2026 08:02:51 +0000
Source type: ['']
Sources: https://securityaffairs.com/188590/hacking/12-million-exposed-env-files-reveal-widespread-security-failures.html
Source level: 2

## ManoMano data breach impacted 38 Million customer accounts
ManoMano, a European DIY e-commerce platform, experienced a data breach in January 2026 impacting 38 million customers. The breach occurred through a compromised third-party service provider, exposing personal data such as first name, last name, email address, telephone number, and customer service interactions. A threat actor known as "Indra" claimed responsibility for the breach, alleging possession of data on 37.8 million users. 
analyse: The European DIY platform ManoMano experienced a data breach in January 2026, impacting 38 million customer accounts through a compromised third-party service provider. Exposed data includes first name, last name, email address, telephone number, and customer service interactions, although passwords were not compromised. A threat actor known as "Indra" claimed responsibility for the breach, and investigations are ongoing. 
tags: ['CYBER CRIME', 'DATA BREACH', 'HACKING', 'APT', 'INTELLIGENCE', 'ARTIFICIAL INTELLIGENCE', 'SECURITY', 'MALWARE', 'CYBER WARFARE', 'HACKTIVISM'] 
observables: {'email-addr': ['pierluigi.paganini@securityaffairs.co'], 'vulnerability': ['CVE-2026-1731']}
Publication date: Fri, 27 Feb 2026 07:41:50 +0000
Source type: ['']
Sources: https://securityaffairs.com/188582/data-breach/manomano-data-breach-impacted-38-million-customer-accounts.html
Source level: 2

## Trend Micro fixes two critical flaws in Apex One
Trend Micro fixed two critical Apex One flaws, CVE-2025-71210 and CVE-2025-71211, which enable remote code execution on vulnerable Windows systems. Researchers Jacky Hsieh and Charles Yang reported the flaws through TrendAI’s Zero Day Initiative, and the company released Critical Patch Build 14136 to address them. Trend Micro also fixed two high-severity privilege escalation flaws and four issues impacting the macOS agent. 
analyse: Multiple vulnerabilities, including CVE-2025-71210 and CVE-2025-71211, have been addressed in Trend Micro Apex One, enabling potential remote code execution. Trend Micro released Critical Patch Build 14136 to mitigate these issues, which affect the management console and Windows agent. Customers are urged to promptly apply the security updates to prevent exploitation and protect their environments. 
tags: ['CVE-2025-71210', 'CVE-2025-71211', 'CVE-2025-71212', 'CVE-2025-71213', 'Trend Micro', 'Apex One', 'Windows', 'Hacking', 'Vulnerability', 'Remote Code Execution'] 
observables: {'email-addr': ['pierluigi.paganini@securityaffairs.co'], 'vulnerability': ['CVE-2026-1731', 'CVE-2025-71210', 'CVE-2025-71211', 'CVE-2025-71212', 'CVE-2025-71213']}
Publication date: Thu, 26 Feb 2026 21:35:51 +0000
Source type: ['']
Sources: https://securityaffairs.com/188572/security/trend-micro-fixes-two-critical-flaws-in-apex-one.html
Source level: 2

## UAT-10027 campaign hits U.S. education and healthcare with stealthy Dohdoor backdoor
The UAT-10027 campaign has been targeting U.S. education and healthcare sectors since December 2025 to deploy a previously unseen backdoor named Dohdoor. Attackers use phishing to trigger a PowerShell script that downloads a malicious DLL named Dohdoor via sideloading, utilizing DNS-over-HTTPS and Cloudflare infrastructure to evade detection. Talos assesses with low confidence that UAT-10027 links to North Korea due to overlaps with the Lazarus Group. 
analyse: The UAT-10027 campaign has been targeting U.S. education and healthcare organizations since December 2025, deploying a previously unseen backdoor named Dohdoor. Attackers use phishing to initiate PowerShell scripts that download a malicious DLL, employing DNS-over-HTTPS and Cloudflare infrastructure to evade detection. The Dohdoor backdoor uses hash-based lookups, process hollowing, and NTDLL unhooking to bypass security measures. Cisco Talos assesses a low confidence link between UAT-10027 and the Lazarus Group due to technical similarities, although the campaign's focus deviates from Lazarus' typical targets. 
tags: ['APT', 'DATA BREACH', 'HACKING', 'CYBER CRIME', 'CYBER WARFARE', 'INTELLIGENCE', 'Dohdoor', 'Lazarus', 'UAT-10027', 'Cobalt Strike'] 
observables: {'email-addr': ['pierluigi.paganini@securityaffairs.co'], 'process': ['OpenWith.exe', 'wksprt.exe'], 'vulnerability': ['CVE-2026-1731']}
Publication date: Thu, 26 Feb 2026 19:10:34 +0000
Source type: ['']
Sources: https://securityaffairs.com/188558/apt/uat-10027-campaign-hits-u-s-education-and-healthcare-with-stealthy-dohdoor-backdoor.html
Source level: 2

## U.S. CISA adds Cisco SD-WAN flaws to its Known Exploited Vulnerabilities catalog
The U.S. Cybersecurity and Infrastructure Security Agency (CISA) added two Cisco SD-WAN flaws to its Known Exploited Vulnerabilities (KEV) catalog. These flaws are CVE-2022-20775 and CVE-2026-20127, with the latter having a CVSS score of 10.0 and being actively exploited since 2023. A highly sophisticated threat actor, tracked as UAT-8616, has been exploiting these vulnerabilities to gain full administrative access, potentially escalating to root user via a software version downgrade. Customers running versions prior to 20.9.1 are advised to migrate to a patched release. 
analyse: The U.S. Cybersecurity and Infrastructure Security Agency (CISA) has added two Cisco SD-WAN flaws to its Known Exploited Vulnerabilities (KEV) catalog. These vulnerabilities are CVE-2022-20775, a path traversal vulnerability, and CVE-2026-20127, an authentication bypass vulnerability, which has been actively exploited since 2023. A sophisticated threat actor, tracked as UAT-8616, has been observed exploiting these flaws to gain full administrative access and escalate privileges to root. CISA urges federal agencies and private organizations to address these vulnerabilities by upgrading to patched software versions. 
tags: ['CVE-2026-1731', 'APT28', 'Cisco SD-WAN', 'Cisco', 'Lazarus', 'Medusa Ransomware', 'Operation MacroMaze', 'Arkanix Stealer', 'Everest ransomware', 'Romanian hacker', 'UAT-8616', 'CVE-2022-20775', 'CVE-2026-20127', 'Soliton Systems K.K FileZen', 'VMware', 'ShinyHunters', 'ManoMano', 'Trend Micro'] 
observables: {'directory': ['/var/log'], 'email-addr': ['pierluigi.paganini@securityaffairs.co'], 'ipv4-addr': ['20.12.5.3', '20.12.6.1', '20.15.4.2', '20.18.2.1', '20.9.8.2'], 'vulnerability': ['CVE-2026-1731', 'CVE-2022-20775', 'CVE-2026-20127']}
Publication date: Thu, 26 Feb 2026 15:04:20 +0000
Source type: ['']
Sources: https://securityaffairs.com/188548/hacking/u-s-cisa-adds-cisco-sd-wan-flaws-to-its-known-exploited-vulnerabilities-catalog.html
Source level: 2

## Hackers abused Cisco SD-WAN zero-day since 2023 to gain full admin control
A critical Cisco SD-WAN vulnerability, tracked as CVE-2026-20127, has been exploited since 2023 to gain unauthenticated admin access. The flaw affects Catalyst SD-WAN Controller and Manager, allowing attackers to bypass authentication and manipulate network configuration. Cisco Talos tracks the exploitation as UAT-8616, a highly sophisticated threat actor active since at least 2023. 
analyse: A critical Cisco SD-WAN vulnerability, CVE-2026-20127, has been exploited since 2023, allowing unauthenticated attackers to gain full administrative access. The vulnerability affects Catalyst SD-WAN Controller and Manager, impacting On-Prem deployments, Cisco Hosted SD-WAN Cloud, and related configurations. Cisco attributes the discovery of the vulnerability to the Australian Cyber Security Centre (ASD-ACSC) and tracks related exploitation as UAT-8616, involving a highly sophisticated threat actor. 
tags: ['CVE-2026-20127', 'Cisco SD-WAN', 'UAT-8616', 'Cisco Catalyst SD-WAN', 'APT28', 'Lazarus', 'Medusa Ransomware', 'Everest ransomware', 'Arkanix Stealer', 'ShinyHunters'] 
observables: {'directory': ['/var/log'], 'email-addr': ['pierluigi.paganini@securityaffairs.co'], 'ipv4-addr': ['20.12.5.3', '20.12.6.1', '20.15.4.2', '20.18.2.1', '20.9.8.2'], 'url': ['https://sec.cloudapps.cisco.com/security/center/resources/Cisco-Catalyst-SD-WAN-HardeningGuide'], 'vulnerability': ['CVE-2026-1731', 'CVE-2026-20127', 'CVE-2022-20775']}
Publication date: Thu, 26 Feb 2026 11:40:33 +0000
Source type: ['']
Sources: https://securityaffairs.com/188540/security/hackers-abused-cisco-sd-wan-zero-day-since-2023-to-gain-full-admin-control.html
Source level: 2

## CVE-2026-20127: Cisco SD-WAN Zero-Day Exploited Since 2023
CVE-2026-20127 is a critical authentication bypass affecting Cisco Catalyst SD-WAN Controller and Cisco Catalyst SD-WAN Manager. Cisco Talos reports the flaw is being actively exploited by a sophisticated threat actor since at least 2023. Successful exploitation allows an unauthenticated attacker to gain administrative privileges and manipulate SD-WAN fabric configuration. CISA issued Emergency Directive 26-03 for U.S. federal civilian agencies to address the vulnerability. 
analyse: CVE-2026-20127 is a critical authentication bypass affecting Cisco Catalyst SD-WAN Controller and Cisco Catalyst SD-WAN Manager, actively exploited since at least 2023. Attackers prioritize edge-facing infrastructure to control traffic flows and identity paths. Mitigation strategies include patching, restricting network exposure, isolating management interfaces, forwarding logs to external systems, and auditing authentication logs. CISA issued Emergency Directive 26-03 for U.S. federal civilian agencies to address this vulnerability. 
tags: ['CVE-2025-20393', 'CVE-2026-20045', 'CVE-2026-22769', 'CVE-2026-20127', 'UAT-8616', 'CVE-2022-20775', 'Cisco Catalyst SD-WAN Controller', 'Cisco Catalyst SD-WAN Manager', 'FedRAMP', 'SOC Prime'] 
observables: {'directory': ['/var/log', '/var/log/tmplog/vdebug', '/var/volatile/log', '/var/volatile/log/vdebug'], 'vulnerability': ['CVE-2025-20393', 'CVE-2026-20045', 'CVE-2026-22769', 'CVE-2026-20127', 'CVE-2022-20775', 'CVE-2026-2441', 'CVE-2026-20700']}
Publication date: Thu, 26 Feb 2026 11:56:32 +0000
Source type: ['']
Sources: https://socprime.com/blog/cve-2026-20127-vulnerability/
Source level: 2

## Leveling up Kubernetes Posture: From baselines to risk-aware admission
The blog post discusses evolving Kubernetes posture management beyond basic baselines like Pod Security Standards (PSS). Modern Kubernetes environments require more contextual risk assessment, as clusters now include privileged infrastructure and workloads interacting with sensitive data. The article suggests treating posture as a decision point, incorporating risk-aware admission, and leveraging tools like Sysdig to enable granular enforcement and vulnerability-aware policies. 
analyse: The blog post discusses Kubernetes posture management, starting with common guardrails like Pod Security Standards (PSS) and progressing to risk-aware admission control. Initial approaches using PSS are easy to adopt but fall short in modern Kubernetes environments with complex workloads. Moving beyond baselines involves treating posture as a decision point, evaluating risk contextually, and leveraging tools like OPA Gatekeeper and Kyverno, although these can introduce complexity. Sysdig admission control offers a solution by enabling granular enforcement based on workload attributes and incorporating vulnerability findings into admission decisions. 
tags: ['Kubernetes', 'Posture', 'baselines', 'risk', 'admission', 'Falco', 'Sysdig', 'PSS', 'Pod Security Standards', 'Kubernetes ecosystem'] 
observables: {'domain-name': ['app.kubernetes.io', 'eks.in', 'generalize.in', 'pod-security.kubernetes.io', 'runtime.in', 'updated.in', 'vac.secure.sysdig.com'], 'url': ['https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/699f2c7ae4c74c2d1501eeaa_7c51fe75.png', 'https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/699f2c7ae4c74c2d1501eead_da776a6d.png', 'https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/699f2c7ae4c74c2d1501eeb6_fae9b610.png', 'https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/699f2c7ae4c74c2d1501eeb9_7b3d0f01.png', 'https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/69a022bf575efc1ff838a6fb_Frame.png', 'https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/69a022f8b651317de52ce4dd_Frame-1.png']}
Publication date: Thu, 26 Feb 2026 00:00:00 GMT
Source type: ['']
Sources: https://www.sysdig.com/blog/leveling-up-kubernetes-posture-from-baselines-to-risk-aware-admission
Source level: 2

## Henry IV, Hotspur, Hal, and hallucinations
Cisco Talos identified an ongoing campaign by UAT-10027, using a new backdoor called "Dohdoor," since December 2025. Dohdoor leverages DNS-over-HTTPS (DoH) for command-and-control communications and targets education and health care sectors in the US. The campaign uses phishing, PowerShell scripts, and DLL sideloading, with infrastructure hidden behind Cloudflare. 
analyse: The text draws a parallel between Shakespeare's Hotspur and cybersecurity, emphasizing the need for calculated risks. The ongoing campaign by UAT-10027, utilizing the "Dohdoor" backdoor, targets education and healthcare sectors in the US. Security teams should update detection tools, monitor DoH traffic, review endpoint logs, and share threat intelligence. 
tags: ['Hotspur', 'Shakespeare', 'AI', 'Dohdoor', 'DNS-over-HTTPS', 'C2', 'ClamAV', 'SNORT', 'UAT-10027', 'Cisco Talos'] 
observables: {'file': [{'hash_type': 'MD5', 'values': ['0c883b1d66afce606d9830f48d69d74b', '2915b3f8b703eb744fc54c81f4a9c67f', '85bbddc502f7b10871621fd460243fbc', 'aac3165ece2959f39ff98334618d10d9', 'c2efb2dcacba6d3ccc175b6ce1b7ed0a']}, {'hash_type': 'SHA-256', 'values': ['41f14d86bcaf8e949160ee2731802523e0c76fea87adf00ee7fe9567c3cec610', '90b1456cdbe6bc2779ea0b4736ed9a998a71ae37390331b6ba87e389a49d3d59', '96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974', '9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507', 'd921fc993574c8be76553bcf4296d2851e48ee39b958205e69bdfd7cf661d2b1']}], 'ipv6-addr': ['1201', '95'], 'process': ['85bbddc502f7b10871621fd460243fbc.exe', 'd4aa3e7010220ad1b458fac17039c274_63_Exe.exe', 'd921fc993574c8be76553bcf4296d2851e48ee39b958205e69bdfd7cf661d2b1.exe', 'https_2915b3f8b703eb744fc54c81f4a9c67f.exe'], 'url': ['https://talosintelligence.com/talos_file_reputation?s=41f14d86bcaf8e949160ee2731802523e0c76fea87adf00ee7fe9567c3cec610', 'https://talosintelligence.com/talos_file_reputation?s=90b1456cdbe6bc2779ea0b4736ed9a998a71ae37390331b6ba87e389a49d3d59', 'https://talosintelligence.com/talos_file_reputation?s=96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974', 'https://talosintelligence.com/talos_file_reputation?s=9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507', 'https://talosintelligence.com/talos_file_reputation?s=d921fc993574c8be76553bcf4296d2851e48ee39b958205e69bdfd7cf661d2b1'], 'vulnerability': ['CVE-2026-20127']}
Publication date: Thu, 26 Feb 2026 19:00:39 GMT
Source type: ['']
Sources: https://blog.talosintelligence.com/henry-iv-hotspur-hal-and-hallucinations/
Source level: 1

## New Dohdoor malware campaign targets education and health care
Cisco Talos discovered an ongoing malicious campaign since December 2025 by a threat actor tracked as “UAT-10027,” delivering a previously undisclosed backdoor dubbed “Dohdoor.” Dohdoor utilizes DNS-over-HTTPS (DoH) for command-and-control (C2) communications and can download and execute other payload binaries. The campaign targets victims in the education and health care sectors in the United States through a multi-stage attack chain. Talos assesses with low confidence that UAT-10027 is North Korea-nexus, based on similarities in tactics, techniques, and procedures (TTPs) with the Lazarus Group. 
analyse: The threat actor UAT-10027 has been conducting a malicious campaign since December 2025, utilizing a previously undisclosed backdoor called Dohdoor. Dohdoor employs DNS-over-HTTPS (DoH) for command-and-control communications and can download and execute additional payloads. The campaign targets education and healthcare sectors in the United States through a multi-stage attack chain involving PowerShell scripts, batch scripts, and DLL sideloading. The threat actor hides C2 servers behind Cloudflare infrastructure and uses deceptive domain names and irregular capitalization to evade detection. 
tags: ['UAT-10027', 'Dohdoor', 'DNS-over-HTTPS', 'DoH', 'Cloudflare', 'PowerShell', 'Windows', 'LOLBins', 'education', 'healthcare'] 
observables: {'directory': ['c:\\windows\\system32'], 'domain-name': ['cloudflare-dns.com'], 'file': [{'hash_type': 'MD5', 'values': ['466556e923186364e82cbdb4cad8df2c', '7FF31977972C224A76155D13B6D685E3']}], 'ipv4-addr': ['1.1.1.1'], 'process': ['curl.exe', 'eblctr.exe', 'Fondue.exe', 'ImagingDevices.exe', 'mblctr.exe', 'OpenWith.exe', 'sample.exe', 'ScreenClippingHost.exe', 'wab.exe', 'wksprt.exe'], 'windows-registry-key': ['HKCU\\Software\\Wicrosoft\\Windows\\CurrentVersion\\Explorer\\RunMRU" /f >nul']}
Publication date: Thu, 26 Feb 2026 11:00:25 GMT
Source type: ['']
Sources: https://blog.talosintelligence.com/new-dohdoor-malware-campaign/
Source level: 1

## CVE-2026-21654 - Johnson Controls -Frick Quantum HD- Unauthenticated Remote Code Execution
A high-severity vulnerability, CVE-2026-21654, affects Johnson Controls Frick Controls Quantum HD version 10.22 and prior. The vulnerability is an OS Command Injection, allowing for remote code execution. Affected products are identified as having a CVSS 4.0 score of 8.8, and updates to version 10.23 or later are recommended. 
analyse: The CVE-2026-21654 vulnerability is a high-severity (CVSS score 8.8) OS Command Injection affecting Johnson Controls Frick Controls Quantum HD version 10.22 and prior. The vulnerability allows unauthenticated remote code execution. Affected products are listed as having no recorded versions, and updates to version 10.23 or later, along with vendor-provided security patches, are recommended. The vulnerability is associated with CWE-78 and several CAPEC entries related to injection and command execution. 
tags: ['CVE-2026-21654', 'Johnson Controls', 'Frick Quantum HD', 'OS Command Injection', 'CVSS 4.0', 'vulnerability', 'productsecurity@jci.com', '10.22', '10.23', 'CWE-78', 'CAPEC', 'GitHub', 'EPSS'] 
observables: {'domain-name': ['cisa.gov', 'cvefeed.io', 'johnsoncontrols.com'], 'email-addr': ['productsecurity@jci.com'], 'url': ['http://www.cisa.gov/news-events/ics-advisories/icsa-26-057-01', 'http://www.johnsoncontrols.com/trust-center/cybersecurity/security-advisories', 'https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-01', 'https://www.johnsoncontrols.com/trust-center/cybersecurity/security-advisories'], 'vulnerability': ['CVE-2026-21654']}
Publication date: Fri, 27 Feb 2026 08:38:42 +0000
Source type: ['']
Sources: https://cvefeed.io/vuln/detail/CVE-2026-21654
Source level: 2

## CVE-2026-27776 - Intra-mart Accel Platform IM-LogicDesigner Deserialization RCE Vulnerability
The IM-LogicDesigner module of intra-mart Accel Platform contains an insecure deserialization issue, identified as CVE-2026-27776. This vulnerability can be exploited when IM-LogicDesigner is deployed, potentially allowing arbitrary code execution if a user with administrative privileges imports a crafted file. The vulnerability has a CVSS 4.0 score of 8.6, categorized as HIGH, and a CVSS 3.0 score of 7.2, also HIGH. Recommended mitigation steps include updating the IM-LogicDesigner module, restricting administrative privileges, and reviewing system deployment. 
analyse: The IM-LogicDesigner module of intra-mart Accel Platform contains an insecure deserialization vulnerability (CVE-2026-27776). This vulnerability can be exploited by importing a crafted file with administrative privileges, potentially leading to arbitrary code execution. The vulnerability has a CVSS score of 8.6 (CVSS 4.0), indicating a high severity level. Affected products are currently unspecified.
Strategic recommendations include updating the IM-LogicDesigner module, restricting administrative privileges, and reviewing system deployments. The vulnerability is associated with CWE-502 (Deserialization of Untrusted Data) and CAPEC-586 (Object Injection). 
tags: ['CVE-2026-27776', 'Intra-mart', 'Accel', 'Platform', 'IM-LogicDesigner', 'Deserialization', 'RCE', 'CVSS', 'vultures@jpcert.or.jp', 'GitHub'] 
observables: {'domain-name': ['cvefeed.io'], 'email-addr': ['vultures@jpcert.or.jp'], 'url': ['https://global.intra-mart.support/hc/en-us/articles/55266898383641', 'https://jvn.jp/en/jp/JVN80500630/'], 'vulnerability': ['CVE-2026-27776']}
Publication date: Fri, 27 Feb 2026 08:17:09 +0000
Source type: ['']
Sources: https://cvefeed.io/vuln/detail/CVE-2026-27776
Source level: 2

## CVE-2026-0980 - Rubyipmi: red hat satellite: remote code execution in rubyipmi via malicious bmc username
A remote code execution (RCE) vulnerability (CVE-2026-0980) exists in the rubyipmi gem used in Red Hat Satellite. An authenticated attacker can exploit this flaw by crafting a malicious username for the BMC interface, potentially leading to RCE. The vulnerability has a CVSS 3.1 score of 8.3, classified as high severity, and is associated with CWE-78, among other Common Attack Patterns. Mitigation strategies include updating the rubyipmi gem, restricting host creation/update permissions, sanitizing BMC username inputs, and reviewing BMC credentials. 
analyse: The vulnerability CVE-2026-0980 is rated HIGH with a CVSS 3.1 score of 8.3. It affects Red Hat Satellite through a flaw in the rubyipmi gem, allowing remote code execution if an authenticated attacker has host creation or update permissions. Mitigation strategies include updating the rubyipmi gem, restricting host creation/update permissions, sanitizing BMC username inputs, and reviewing BMC credentials. Associated CWEs include CWE-78, and CAPEC identifiers such as CAPEC-6 and CAPEC-88. 
tags: ['CVE-2026-0980', 'rubyipmi', 'Red Hat Satellite', 'BMC', 'RCE', 'CVSS 3.1', 'secalert@redhat.com', 'CWE-78', 'CAPEC', 'GitHub', 'EPSS'] 
observables: {'domain-name': ['cvefeed.io'], 'email-addr': ['secalert@redhat.com'], 'url': ['https://access.redhat.com/security/cve/CVE-2026-0980', 'https://bugzilla.redhat.com/show_bug.cgi?id=2429874'], 'vulnerability': ['CVE-2026-0980']}
Publication date: Fri, 27 Feb 2026 08:17:09 +0000
Source type: ['']
Sources: https://cvefeed.io/vuln/detail/CVE-2026-0980
Source level: 2

## CVE-2026-2251 - Path Traversal leading to Remote Code Execution (RCE)
A critical path traversal vulnerability (CVE-2026-2251) exists in Xerox FreeFlow Core versions up to and including 8.0.7, potentially leading to remote code execution. The vulnerability is rated 9.8 based on the CVSS 3.1 scoring system. Affected users are advised to upgrade to FreeFlow Core version 8.1.0, which can be downloaded from the Xerox support website. 
analyse: The vulnerability CVE-2026-2251 is a critical Path Traversal leading to Remote Code Execution (RCE) affecting Xerox FreeFlow Core versions up to and including 8.0.7. The CVSS score is 9.8, indicating a high likelihood of exploitation. Affected products are identified, but specific version details are not provided. Upgrade to FreeFlow Core version 8.1.0 is recommended, and software can be downloaded from the Xerox support website. 
tags: ['CVE-2026-2251', 'Path Traversal', 'RCE', 'Xerox FreeFlow Core', '8.0.7', '8.1.0', 'CVSS 3.1', 'CWE-22', 'CAPEC', 'GitHub'] 
observables: {'domain-name': ['cvefeed.io', 'support.xerox.com'], 'url': ['http://www.support.xerox.com/en-us/product/core/downloads', 'https://securitydocs.business.xerox.com/wp-content/uploads/2026/02/Xerox-Security-Bulletin-026-005-for-Xerox-Freeflow-Core.pdf', 'https://www.support.xerox.com/en-us/product/core/downloads'], 'vulnerability': ['CVE-2026-2251']}
Publication date: Fri, 27 Feb 2026 08:08:52 +0000
Source type: ['']
Sources: https://cvefeed.io/vuln/detail/CVE-2026-2251
Source level: 2

## CVE-2025-12981 - Listee <= 1.1.6 - Unauthenticated Privilege Escalation
The Listee WordPress theme is vulnerable to unauthenticated privilege escalation through CVE-2025-12981, affecting versions up to 1.1.6. This vulnerability arises from insufficient sanitization of the user_role parameter during user registration within the listee-core plugin, allowing attackers to register as administrators. The CVSS score is 9.8, indicating a critical severity, and the vulnerability is associated with CWE-269, Improper Privilege Management. Affected users are advised to update to version 1.1.7 or later. 
analyse: The Listee WordPress theme, specifically versions up to 1.1.6, is vulnerable to unauthenticated privilege escalation due to flawed user registration validation. An attacker can manipulate the user_role parameter to register as an administrator. Affected systems should update the theme to version 1.1.7 or later and review user roles and permissions. The vulnerability is categorized as critical with a CVSS score of 9.8 and is associated with CWE-269 (Improper Privilege Management). 
tags: ['CVE-2025-12981', 'Listee', 'WordPress', 'unauthenticated', 'Administrator', 'user_role', 'CVSS', 'CWE-269', 'CAPEC', 'security@wordfence.com'] 
observables: {'domain-name': ['cvefeed.io'], 'email-addr': ['security@wordfence.com'], 'url': ['http://www.wordfence.com/threat-intel/vulnerabilities/id/d534feae-d1b7-4544-b1c5-c23f37dd5bab?source=cve', 'https://listee-wp.dreamstechnologies.com/documentation/changelog.html', 'https://themeforest.net/item/listee-classified-ads-wordpress-theme/44526956', 'https://themes.trac.wordpress.org/browser/listee/1.1.5/listee-core/includes/listee-core-users.php#L928', 'https://www.wordfence.com/threat-intel/vulnerabilities/id/d534feae-d1b7-4544-b1c5-c23f37dd5bab?source=cve'], 'vulnerability': ['CVE-2025-12981']}
Publication date: Fri, 27 Feb 2026 07:17:09 +0000
Source type: ['']
Sources: https://cvefeed.io/vuln/detail/CVE-2025-12981
Source level: 2

## CVE-2026-3301 - Totolink N300RH Web Management cstecgi.cgi setWebWlanIdx os command injection
A security flaw exists in Totolink N300RH 6.1c.1353_B20190305, specifically within the setWebWlanIdx function of the /cgi-bin/cstecgi.cgi file in the Web Management Interface. This vulnerability allows for OS command injection through manipulation of the webWlanIdx argument and can be exploited remotely. A public proof-of-concept exploit is available on GitHub, and the vulnerability has a CVSS score of 10.0. 
analyse: A critical security flaw (CVE-2026-3301) exists in the Totolink N300RH web management interface, allowing for remote OS command injection via manipulation of the webWlanIdx argument. The vulnerability, affecting version 6.1c.1353_B20190305, has a CVSS score of 10.0 and a public exploit is available. Affected devices should be updated immediately, network traffic should be monitored, and vendor patches should be applied. The vulnerability is associated with CWE-77 and CWE-78, and several CAPEC entries related to command injection. 
tags: ['CVE-2026-3301', 'Totolink', 'N300RH', 'cstecgi.cgi', 'setWebWlanIdx', 'os command injection', 'CVSS 2.0', 'CVSS 3.1', 'CVSS 4.0', 'GitHub', 'vuldb.com'] 
observables: {'domain-name': ['cvefeed.io', 'totolink.net'], 'email-addr': ['cna@vuldb.com'], 'url': ['http://www.totolink.net', 'https://github.com/xyh4ck/iot_poc/blob/main/TOTOLINK/N300RHv4/01_setWebWlanIdx_RCE/README.md', 'https://vuldb.com/?ctiid.348052', 'https://vuldb.com/?id.348052', 'https://vuldb.com/?submit.761297', 'https://www.totolink.net/'], 'vulnerability': ['CVE-2026-3301']}
Publication date: Fri, 27 Feb 2026 06:18:00 +0000
Source type: ['']
Sources: https://cvefeed.io/vuln/detail/CVE-2026-3301
Source level: 2

## CVE-2026-28370 - OpenStack Vitrage Code Execution Vulnerability
CVE-2026-28370 describes a critical code execution vulnerability in OpenStack Vitrage versions before 12.0.1, 13.0.0, 14.0.0, and 15.0.0. A user with access to the Vitrage API can trigger code execution on the Vitrage service host, potentially leading to unauthorized access and service compromise. The vulnerability exists in the _create_query_function within vitrage/graph/query.py, and a public proof-of-concept exploit is available on GitHub. Affected users should update Vitrage to version 12.0.1 or later. 
analyse: A critical code execution vulnerability (CVE-2026-28370) exists in OpenStack Vitrage versions prior to 12.0.1, 13.0.0, 14.0.0, and 15.0.0. The vulnerability allows an attacker with access to the Vitrage API to execute code on the host system. Affected deployments exposing the Vitrage API are at risk, and a public proof-of-concept exploit is available on GitHub. Mitigation involves updating Vitrage to version 12.0.1 or later, 13.0.1 or later, 14.0.1 or later, or 15.0.1 or later. 
tags: ['CVE-2026-28370', 'OpenStack', 'Vitrage', 'code execution', 'API', 'query.py', 'CVSS', 'CWE-95', 'CAPEC', 'Github'] 
observables: {'domain-name': ['cvefeed.io'], 'email-addr': ['cve@mitre.org'], 'file': [{'hash_type': 'SHA-1', 'values': ['a1f86950e1314b0c740f9cd9b7e9dbab7d02af51']}], 'url': ['https://github.com/openstack/vitrage/blob/a1f86950e1314b0c740f9cd9b7e9dbab7d02af51/vitrage/graph/query.py#L70', 'https://storyboard.openstack.org/#%21/story/2011539'], 'vulnerability': ['CVE-2026-28370']}
Publication date: Fri, 27 Feb 2026 05:18:20 +0000
Source type: ['']
Sources: https://cvefeed.io/vuln/detail/CVE-2026-28370
Source level: 2

## Multiples vulnérabilités dans Wireshark (26 février 2026)
This document, dated February 26, 2026, from the French National Cybersecurity Agency (ANSSI) concerns multiple vulnerabilities in Wireshark. Affected systems include Wireshark versions 4.4.x prior to 4.4.14 and 4.6.x prior to 4.6.4, which can lead to remote denial-of-service. Refer to the Wireshark security advisories and CVE records for remediation. 
analyse: Multiple vulnerabilities in Wireshark versions 4.4.x prior to 4.4.14 and 4.6.x prior to 4.6.4 allow a remote attacker to cause a denial-of-service. Affected systems should refer to the vendor's security advisories for patches. The referenced CVEs are CVE-2026-3201, CVE-2026-3202, and CVE-2026-3203.
Cyber recommendations:
*   Apply patches from the vendor.
*   Monitor systems for exploitation attempts.
*   Review network traffic for suspicious activity. 
tags: ['CERTFR-2026-AVI-0211', 'Wireshark', 'wnpa-sec-2026-05', 'wnpa-sec-2026-06', 'wnpa-sec-2026-07', 'CVE-2026-3201', 'CVE-2026-3202', 'CVE-2026-3203', '4.4.x', '4.6.x'] 
observables: {'domain-name': ['cve.org', 'wireshark.org'], 'url': ['http://www.cve.org/CVERecord?id=CVE-2026-3201', 'http://www.cve.org/CVERecord?id=CVE-2026-3202', 'http://www.cve.org/CVERecord?id=CVE-2026-3203', 'http://www.wireshark.org/security/wnpa-sec-2026-05.html', 'http://www.wireshark.org/security/wnpa-sec-2026-06.html', 'http://www.wireshark.org/security/wnpa-sec-2026-07.html', 'https://www.cve.org/CVERecord?id=CVE-2026-3201', 'https://www.cve.org/CVERecord?id=CVE-2026-3202', 'https://www.cve.org/CVERecord?id=CVE-2026-3203', 'https://www.wireshark.org/security/wnpa-sec-2026-05.html', 'https://www.wireshark.org/security/wnpa-sec-2026-06.html', 'https://www.wireshark.org/security/wnpa-sec-2026-07.html'], 'vulnerability': ['CVE-2026-3201', 'CVE-2026-3202', 'CVE-2026-3203']}
Publication date: Thu, 26 Feb 2026 00:00:00 +0000
Source type: ['operational', 'vulnerabilities']
Sources: https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0211/
Source level: 1

## Multiples vulnérabilités dans les produits Centreon (26 février 2026)
Multiple vulnerabilities have been discovered in Centreon products, potentially leading to data integrity and confidentiality breaches, as well as remote code execution. Affected systems include Centreon Open Tickets versions 24.10.x prior to Tickets 24.10.8, versions 25.x prior to Tickets 25.10.3, versions prior to 24.04.7, and Centreon Web versions 24.10.x prior to 24.10.21, versions 25.x prior to 25.10.9, and versions prior to 24.04.25. Refer to the vendor's security bulletin for remediation details. 
analyse: Multiple vulnerabilities have been identified in Centreon products, potentially leading to data integrity and confidentiality breaches, and remote code execution. Affected systems include Centreon Open Tickets versions 24.10.x, 25.x, and versions prior to 24.04.7, as well as Centreon Web versions 24.10.x, 25.x, and versions prior to 24.04.25. Remediation involves applying security patches available from the Centreon vendor's security bulletins. Referenced CVEs include CVE-2025-12523, CVE-2025-13050, CVE-2026-2749, CVE-2026-2750, and CVE-2026-2751. 
tags: ['Centreon', 'CVE-2025-12523', 'CVE-2025-13050', 'CVE-2026-2750', 'CVE-2026-2751', 'Open Tickets', 'Web', 'SQLi', 'Code arbitraire', 'Confidentialité'] 
observables: {'domain-name': ['cve.org'], 'url': ['http://www.cve.org/CVERecord?id=CVE-2025-12523', 'http://www.cve.org/CVERecord?id=CVE-2025-13050', 'http://www.cve.org/CVERecord?id=CVE-2026-2749', 'http://www.cve.org/CVERecord?id=CVE-2026-2750', 'http://www.cve.org/CVERecord?id=CVE-2026-2751', 'https://thewatch.centreon.com/latest-security-bulletins-64/cve-2025-12523-centreon-web-medium-severity-5505', 'https://thewatch.centreon.com/latest-security-bulletins-64/cve-2025-13050-centreon-web-medium-severity-5506', 'https://thewatch.centreon.com/latest-security-bulletins-64/cve-2026-2750-centreon-web-critical-severity-5503', 'https://thewatch.centreon.com/latest-security-bulletins-64/cve-2026-2751-centreon-web-high-severity-5504', 'https://thewatch.centreon.com/latest-security-bulletins-64/february-release-monthly-security-bulletin-for-centreon-infra-monitoring-critical-5502', 'https://www.cve.org/CVERecord?id=CVE-2025-12523', 'https://www.cve.org/CVERecord?id=CVE-2025-13050', 'https://www.cve.org/CVERecord?id=CVE-2026-2749', 'https://www.cve.org/CVERecord?id=CVE-2026-2750', 'https://www.cve.org/CVERecord?id=CVE-2026-2751'], 'vulnerability': ['CVE-2025-12523', 'CVE-2025-13050', 'CVE-2026-2750', 'CVE-2026-2751', 'CVE-2026-2749']}
Publication date: Thu, 26 Feb 2026 00:00:00 +0000
Source type: ['operational', 'vulnerabilities']
Sources: https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0212/
Source level: 1

## Multiples vulnérabilités dans les produits Cisco (26 février 2026)
The CERT-FR has issued an advisory regarding multiple vulnerabilities discovered in Cisco products. These vulnerabilities allow an attacker to trigger a denial-of-service attack remotely, affecting Nexus 3000, 3600, and 9000 series switches, as well as UCS 9108 100G Fabric Interconnects versions prior to 4.3(6e) and 4.3(6.260003). Refer to Cisco's security advisories and the CVE records CVE-2026-20010, CVE-2026-20033, CVE-2026-20048, and CVE-2026-20051 for details and corrective actions. 
analyse: Multiple vulnerabilities in Cisco products allow a remote denial-of-service attack. Affected systems include Nexus 3000, 3600, and 9000 series switches, as well as UCS 9108 100G Fabric Interconnects versions prior to 4.3(6e) and 4.3(6.260003). Refer to Cisco security advisories for details on affected versions, configurations, and corrective actions. The referenced CVEs are CVE-2026-20010, CVE-2026-20033, CVE-2026-20048, and CVE-2026-20051. 
tags: ['Cisco', 'vulnérabilités', 'Nexus', 'UCS', '9000', '4.3.x', '4.3(6e)', '4.3(6.260003)', 'déni de service', 'CVE-2026-20010'] 
observables: {'domain-name': ['cve.org'], 'url': ['http://www.cve.org/CVERecord?id=CVE-2026-20010', 'http://www.cve.org/CVERecord?id=CVE-2026-20033', 'http://www.cve.org/CVERecord?id=CVE-2026-20048', 'http://www.cve.org/CVERecord?id=CVE-2026-20051', 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n3kn9k_aci_lldp_dos-NdgRrrA3', 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-cpdos-qLsv6pFD', 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-dsnmp-cNN39Uh', 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-ether-dos-Kv8YNWZ4', 'https://www.cve.org/CVERecord?id=CVE-2026-20010', 'https://www.cve.org/CVERecord?id=CVE-2026-20033', 'https://www.cve.org/CVERecord?id=CVE-2026-20048', 'https://www.cve.org/CVERecord?id=CVE-2026-20051'], 'vulnerability': ['CVE-2026-20010', 'CVE-2026-20033', 'CVE-2026-20048', 'CVE-2026-20051']}
Publication date: Thu, 26 Feb 2026 00:00:00 +0000
Source type: ['operational', 'vulnerabilities']
Sources: https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0213/
Source level: 1

## Vulnérabilité dans Juniper Networks Junos OS Evolved (26 février 2026)
A vulnerability exists in Juniper Networks Junos OS Evolved versions prior to 25.4R1-S1-EVO on PTX Series. This vulnerability allows a remote attacker to execute arbitrary code. The CERT-FR reference is CERTFR-2026-AVI-0214, and the associated CVE identifier is CVE-2026-21902. Refer to Juniper Networks security bulletin JSA107128 for remediation. 
analyse: A vulnerability exists in Juniper Networks Junos OS Evolved, allowing for remote arbitrary code execution. Affected systems include versions prior to 25.4R1-S1-EVO on PTX Series. Refer to Juniper Networks security bulletin JSA107128 for remediation.
Cyber recommendations:
*   Apply the security patch from Juniper Networks.
*   Consult the provided CVE record for further details.
*   Review Juniper Networks security bulletin JSA107128. 
tags: ['Premier Ministre', 'CERTFR-2026-AVI-0214', 'Juniper', 'Junos OS Evolved', 'PTX Series', 'CVE-2026-21902', 'JSA107128', 'code arbitraire', '26 février 2026', '25.4R1-S1-EVO'] 
observables: {'domain-name': ['cve.org'], 'url': ['http://www.cve.org/CVERecord?id=CVE-2026-21902', 'https://supportportal.juniper.net/s/article/2026-02-Out-of-Cycle-Security-Bulletin-Junos-OS-Evolved-PTX-Series-A-vulnerability-allows-a-unauthenticated-network-based-attacker-to-execute-code-as-root-CVE-2026-21902', 'https://www.cve.org/CVERecord?id=CVE-2026-21902'], 'vulnerability': ['CVE-2026-21902']}
Publication date: Thu, 26 Feb 2026 00:00:00 +0000
Source type: ['operational', 'vulnerabilities']
Sources: https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0214/
Source level: 1

## Multiples vulnérabilités dans les produits Microsoft (26 février 2026)
The CERT-FR has issued an advisory (CERTFR-2026-AVI-0215) concerning multiple vulnerabilities discovered in Microsoft products, impacting azl3 kernel 6.6.121.1-1 versions prior to 6.6.121.1-2. These vulnerabilities could allow an attacker to cause an unspecified security problem, and mitigation involves referring to Microsoft's security bulletins for patches. The referenced Microsoft security bulletins are CVE-2025-71230, CVE-2026-23223, CVE-2026-23224, CVE-2026-23225, and CVE-2026-23229. 
analyse: Multiple vulnerabilities exist within Microsoft products, impacting systems running azl3 kernel 6.6.121.1-1 versions prior to 6.6.121.1-2. The vulnerabilities allow an attacker to cause an unspecified security problem, and the risk level is not specified by the editor. Remediation involves applying patches available through Microsoft's security bulletins, specifically CVE-2025-71230, CVE-2026-23223, CVE-2026-23224, CVE-2026-23225, and CVE-2026-23229. Further details and mitigation steps can be found in the provided Microsoft security bulletins and CVE records. 
tags: ['CERTFR-2026-AVI-0215', 'Microsoft', 'CVE-2025-71230', 'CVE-2026-23223', 'CVE-2026-23224', 'CVE-2026-23225', 'CVE-2026-23229', 'azl3', 'kernel', 'éditeur'] 
observables: {'domain-name': ['cve.org'], 'ipv4-addr': ['6.6.121.1'], 'url': ['http://www.cve.org/CVERecord?id=CVE-2025-71230', 'http://www.cve.org/CVERecord?id=CVE-2026-23223', 'http://www.cve.org/CVERecord?id=CVE-2026-23224', 'http://www.cve.org/CVERecord?id=CVE-2026-23225', 'http://www.cve.org/CVERecord?id=CVE-2026-23229', 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-71230', 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-23223', 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-23224', 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-23225', 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-23229', 'https://www.cve.org/CVERecord?id=CVE-2025-71230', 'https://www.cve.org/CVERecord?id=CVE-2026-23223', 'https://www.cve.org/CVERecord?id=CVE-2026-23224', 'https://www.cve.org/CVERecord?id=CVE-2026-23225', 'https://www.cve.org/CVERecord?id=CVE-2026-23229'], 'vulnerability': ['CVE-2025-71230', 'CVE-2026-23223', 'CVE-2026-23224', 'CVE-2026-23225', 'CVE-2026-23229']}
Publication date: Thu, 26 Feb 2026 00:00:00 +0000
Source type: ['operational', 'vulnerabilities']
Sources: https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0215/
Source level: 1

## Vulnérabilité dans PostgreSQL (26 février 2026)
This document from CERT-FR, dated February 26, 2026, concerns a vulnerability in PostgreSQL. Versions of pgvector prior to 0.8.2 are affected, potentially leading to denial of service and data confidentiality breaches. The vulnerability is detailed in the PostgreSQL security bulletin pgvector-082-released-3245 and referenced by CVE-2026-3172. 
analyse: A vulnerability exists in PostgreSQL versions prior to 0.8.2, potentially leading to remote denial of service and data confidentiality breaches. The CERT-FR advisory, reference CERTFR-2026-AVI-0216, details the issue and refers to CVE-2026-3172. Mitigation involves applying patches available in the PostgreSQL security bulletin pgvector-082-released-3245. 
tags: ['PostgreSQL', 'CVE-2026-3172', 'pgvector', 'vulnérabilité', 'sécurité', 'attaquant', 'données', 'service', 'correctifs', 'éditeur'] 
observables: {'domain-name': ['cve.org', 'postgresql.org'], 'url': ['http://www.cve.org/CVERecord?id=CVE-2026-3172', 'http://www.postgresql.org/about/news/pgvector-082-released-3245', 'https://www.cve.org/CVERecord?id=CVE-2026-3172', 'https://www.postgresql.org/about/news/pgvector-082-released-3245/'], 'vulnerability': ['CVE-2026-3172']}
Publication date: Thu, 26 Feb 2026 00:00:00 +0000
Source type: ['operational', 'vulnerabilities']
Sources: https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0216/
Source level: 1

## Multiples vulnérabilités dans SPIP (26 février 2026)
The CERT-FR has issued an advisory, CERTFR-2026-AVI-0217, regarding multiple vulnerabilities discovered in SPIP. Affected systems are SPIP versions prior to 4.4.10, and the vulnerabilities include remote code execution, SQL injection, and security policy bypass. Refer to the SPIP security bulletin at https://blog.spip.net/Mise-a-jour-de-securite-sortie-de-SPIP-4-4-10.html for remediation. 
analyse: Multiple vulnerabilities impacting SPIP versions prior to 4.4.10 have been identified, potentially enabling remote code execution, SQL injection, and security policy bypass. Affected systems should refer to the SPIP security bulletin for available patches. The CERT-FR issued this advisory on February 26, 2026, and the case is tracked under reference CERTFR-2026-AVI-0217.
Cyber recommendations:
*   Update SPIP to version 4.4.10 or later.
*   Monitor systems for exploitation attempts.
*   Review security policies to ensure SPIP usage aligns with security requirements. 
tags: ['SPIP', 'vulnérabilités', 'sécurité', 'code', 'distance', 'SQLi', 'injection', 'attaquant', 'correctifs', 'éditeur'] 
observables: {'url': ['https://blog.spip.net/Mise-a-jour-de-securite-sortie-de-SPIP-4-4-10.html']}
Publication date: Thu, 26 Feb 2026 00:00:00 +0000
Source type: ['operational', 'vulnerabilities']
Sources: https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0217/
Source level: 1

## Cisco says hackers have been exploiting a critical bug to break into big customer networks since 2023
Cisco reports hackers have exploited a bug in its Catalyst SD-WAN products for at least three years. The vulnerability, with a severity score of 10.0, enables remote network breaches and allows hackers to gain high-level permissions. Cisco researchers found evidence of exploitation dating back to 2023. 
analyse: Hackers have exploited a critical vulnerability (severity score of 10.0) in Cisco Catalyst SD-WAN products for at least three years, enabling remote network breaches. Exploitation was traced back to 2023, allowing attackers to gain high-level permissions and persistent access for data theft or espionage. The U.S. government and allies are advising organizations to address this vulnerability immediately.
Cyber recommendations:
* Patch Cisco Catalyst SD-WAN products promptly.
* Implement network segmentation to limit potential damage.
* Enhance intrusion detection systems to identify malicious activity.
* Review access controls and monitor for suspicious behavior. 
tags: ['Cisco', 'hackers', 'bug', 'networks', 'Catalyst SD-WAN', 'vulnerability', 'data', 'permissions', 'exploitation', 'government'] 
observables: {}
Publication date: Thu, 26 Feb 2026 23:51:07 +0000
Source type: ['']
Sources: https://databreaches.net/2026/02/26/cisco-says-hackers-have-been-exploiting-a-critical-bug-to-break-into-big-customer-networks-since-2023/?pk_campaign=feed&pk_kwd=cisco-says-hackers-have-been-exploiting-a-critical-bug-to-break-into-big-customer-networks-since-2023
Source level: 2

## Extorting the Extorters? Moscow man accused of posing as FSB officer to extort Conti ransomware gang
Ruslan Satuchin, a Moscow resident, is accused of attempting to extort money from the Conti ransomware group. He allegedly posed as an FSB officer and demanded payment to avoid criminal prosecution, starting in September 2022. Satuchin denies the allegations, according to RBC. 
analyse: A Moscow resident, Ruslan Satuchin, is accused of attempting to extort money from the Conti ransomware group by impersonating an FSB officer. The alleged scheme started in September 2022, with Satuchin claiming influence over law enforcement to avoid prosecution for Conti members. Satuchin denies the accusations.
Cyber recommendations:
* Verify the identity of individuals claiming official affiliation.
* Implement robust access controls and authentication measures.
* Enhance monitoring of communications for suspicious activity. 
tags: ['Moscow', 'Russia', 'FSB', 'Conti', 'Ransomware', 'Ruslan Satuchin', 'Criminal Prosecution', 'September 2022', 'RBC', 'The Record'] 
observables: {}
Publication date: Thu, 26 Feb 2026 14:32:47 +0000
Source type: ['']
Sources: https://databreaches.net/2026/02/26/extorting-the-extorters-moscow-man-accused-of-posing-as-fsb-officer-to-extort-conti-ransomware-gang/?pk_campaign=feed&pk_kwd=extorting-the-extorters-moscow-man-accused-of-posing-as-fsb-officer-to-extort-conti-ransomware-gang
Source level: 2

## European #DIY chain #ManoMano #DataBreach impacts 38 million customershttps://www.bleepingcomputer.com/news/security/european-dyi-chain-manomano-data-breach-impacts-38-million-customers/#cybersecurity #privacy
Mastodon.thenewoil.org is an independent Mastodon server. It is hosted by The New Oil Media. This server allows participation in the fediverse. 
analyse: Mastodon.thenewoil.org is a Mastodon server operated by The New Oil Media. It functions as one of numerous independent servers within the decentralized fediverse. No strategic analysis or cyber recommendations can be derived from this limited information. 
tags: ['Mastodon', 'fediverse', 'servers', 'instance', 'The New Oil Media'] 
observables: {'domain-name': ['mastodon.thenewoil.org']}
Publication date: Fri, 27 Feb 2026 10:06:12 +0000
Source type: ['']
Sources: https://mastodon.thenewoil.org/@thenewoil/116142008056065374
Source level: 2

## AI agents need orchestration - not just intelligence
Most organizations struggle to coordinate AI agents and digital workers, not with their intelligence. SS&C Blue Prism plans to launch WorkHQ on April 28, 2026, a platform designed to orchestrate and govern work across various systems and agents. The live broadcast, from 9:30am to 11:00am EST, will demonstrate WorkHQ's capabilities and emphasize governance and security guardrails. Attendees will also hear from AWS and IDC regarding strategic perspectives and customer stories. 
analyse: Organizations struggle to coordinate AI agents and digital workers, hindering enterprise automation efforts. SS&C Blue Prism will launch WorkHQ on April 28, 2026, a platform designed to unify agentic automation through orchestration, governance, and a single environment. The launch event will feature live demonstrations, strategic insights from AWS and IDC, and a focus on governance and control within defined security and compliance guardrails. 
tags: ['AI', 'agents', 'automation', 'governance', 'WorkHQ', 'digital workers', 'APIs', 'systems', 'orchestration', 'SS&C Blue Prism'] 
observables: {'url': ['https://pubads.g.doubleclick.net/gampad/ad?co=1&amp;iu=/6978/reg_software/aiml&amp;sz=300x50%7C300x100%7C300x250%7C300x251%7C300x252%7C300x600%7C300x601&amp;tile=2&amp;c=2aaF49hk8N3exCOs62g8s6QAAANM&amp;t=ct%3Dns%26unitnum%3D2%26raptor%3Dcondor%26pos%3Dtop%26test%3D0', 'https://pubads.g.doubleclick.net/gampad/ad?co=1&amp;iu=/6978/reg_software/aiml&amp;sz=300x50%7C300x100%7C300x250%7C300x251%7C300x252%7C300x600%7C300x601&amp;tile=4&amp;c=44aaF49hk8N3exCOs62g8s6QAAANM&amp;t=ct%3Dns%26unitnum%3D426raptor%3Dfalcon%26pos%3Dmid%26test%3D0', 'https://pubads.g.doubleclick.net/gampad/jump?co=1&amp;iu=/6978/reg_software/aiml&amp;sz=300x50%7C300x100%7C300x250%7C300x251%7C300x252%7C300x600%7C300x601&amp;tile=2&amp;c=2aaF49hk8N3exCOs62g8s6QAAANM&amp;t=ct%3Dns%26unitnum%3D2%26raptor%3Dcondor%26pos%3Dtop%26test%3D0', 'https://pubads.g.doubleclick.net/gampad/jump?co=1&amp;iu=/6978/reg_software/aiml&amp;sz=300x50%7C300x100%7C300x250%7C300x251%7C300x252%7C300x600%7C300x601&amp;tile=4&amp;c=44aaF49hk8N3exCOs62g8s6QAAANM&amp;t=ct%3Dns%26unitnum%3D4%26raptor%3Dfalcon%26pos%3Dmid%26test%3D0']}
Publication date: Fri, 27 Feb 2026 09:49:57 +0000
Source type: ['']
Sources: https://go.theregister.com/i/cfa/https://www.theregister.com/2026/02/27/ai_agents_need_orchestration/
Source level: 2

## Engineer held hostage by client who asked for the wrong fix
A field engineer, identified as "Kent," was dispatched to replace a failed system board in an HP server within a private datacenter. After successfully completing the board swap and verifying the server's functionality, Kent was unexpectedly detained by security. The client's admin blamed Kent for ongoing server issues, despite his successful board replacement. Ultimately, Kent was released after his supervisor threatened to trigger a fire alarm or call the police, and he was subsequently banned from the site. 
analyse: A field engineer, "Kent," replaced a failed system board in an HP server at a private datacenter, completing the task as outlined in his brief. Subsequently, he was detained by the client due to a software malfunction unrelated to the hardware replacement. Kent was eventually released after his supervisor threatened to trigger a fire alarm or contact the police, and he was subsequently banned from the site. 
tags: ['Kent', 'datacenter', 'server', 'board', 'RAM', 'CPU', 'admin', 'software', 'security', 'fire alarm'] 
observables: {'url': ['https://pubads.g.doubleclick.net/gampad/ad?co=1&amp;iu=/6978/reg_onprem/front&amp;sz=300x50%7C300x100%7C300x250%7C300x251%7C300x252%7C300x600%7C300x601&amp;tile=2&amp;c=2aaF5dFhzYlAHtEM-pbR5kQAAAFY&amp;t=ct%3Dns%26unitnum%3D2%26raptor%3Dcondor%26pos%3Dtop%26test%3D0', 'https://pubads.g.doubleclick.net/gampad/ad?co=1&amp;iu=/6978/reg_onprem/front&amp;sz=300x50%7C300x100%7C300x250%7C300x251%7C300x252%7C300x600%7C300x601&amp;tile=3&amp;c=33aaF5dFhzYlAHtEM-pbR5kQAAAFY&amp;t=ct%3Dns%26unitnum%3D3%26raptor%3Deagle%26pos%3Dmid%26test%3D0', 'https://pubads.g.doubleclick.net/gampad/ad?co=1&amp;iu=/6978/reg_onprem/front&amp;sz=300x50%7C300x100%7C300x250%7C300x251%7C300x252%7C300x600%7C300x601&amp;tile=4&amp;c=44aaF5dFhzYlAHtEM-pbR5kQAAAFY&amp;t=ct%3Dns%26unitnum%3D426raptor%3Dfalcon%26pos%3Dmid%26test%3D0', 'https://pubads.g.doubleclick.net/gampad/jump?co=1&amp;iu=/6978/reg_onprem/front&amp;sz=300x50%7C300x100%7C300x250%7C300x251%7C300x252%7C300x600%7C300x601&amp;tile=2&amp;c=2aaF5dFhzYlAHtEM-pbR5kQAAAFY&amp;t=ct%3Dns%26unitnum%3D2%26raptor%3Dcondor%26pos%3Dtop%26test%3D0', 'https://pubads.g.doubleclick.net/gampad/jump?co=1&amp;iu=/6978/reg_onprem/front&amp;sz=300x50%7C300x100%7C300x250%7C300x251%7C300x252%7C300x600%7C300x601&amp;tile=3&amp;c=33aaF5dFhzYlAHtEM-pbR5kQAAAFY&amp;t=ct%3Dns%26unitnum%3D3%26raptor%3Deagle%26pos%3Dmid%26test%3D0', 'https://pubads.g.doubleclick.net/gampad/jump?co=1&amp;iu=/6978/reg_onprem/front&amp;sz=300x50%7C300x100%7C300x250%7C300x251%7C300x252%7C300x600%7C300x601&amp;tile=4&amp;c=44aaF5dFhzYlAHtEM-pbR5kQAAAFY&amp;t=ct%3Dns%26unitnum%3D4%26raptor%3Dfalcon%26pos%3Dmid%26test%3D0']}
Publication date: Fri, 27 Feb 2026 08:49:07 +0000
Source type: ['']
Sources: https://go.theregister.com/i/cfa/https://www.theregister.com/2026/02/27/on_call/
Source level: 2

## This Conduent breach, impacting 2.5M individuals, highlights critical supply chain risks. Ensure robust vendor security assessments. For individuals, immediately change passwords, enable MFA, and monitor credit. Organizations should leverage tools like Lunar, https://lunarcyber.com/, for real-time exposure monitoring. #DataBreach #SupplyChainSecurity #Cybersecurity
The user lacks the necessary authorization to access the requested page. 
analyse: Access to the requested page is denied. No strategic analysis or cyber recommendations can be provided due to the lack of accessible content. 
tags: ['permission', 'page'] 
observables: {}
Publication date: Fri, 27 Feb 2026 08:04:58 +0000
Source type: ['']
Sources: https://mastodon.social/@rangeva/116141537162163979
Source level: 2

## Ugh, another one. This is a critical reminder to change your password immediately, especially if you reuse it anywhere. Enable MFA on all accounts. Organizations need real-time breach monitoring. Check out Lunar at https://lunarcyber.com/ for free exposure monitoring. It flags new exposures fast, crucial for infostealer and data breach defense. #DataBreach #Cybersecurity #PasswordSecurity
The user lacks the necessary authorization to access the requested webpage. This indicates a permission restriction is in place. The specific reason for the denial is not provided. 
analyse: Access to the requested page is denied. No strategic analysis or cyber recommendations can be provided due to the lack of accessible content. 
tags: ['permission', 'page'] 
observables: {}
Publication date: Fri, 27 Feb 2026 08:04:58 +0000
Source type: ['']
Sources: https://mastodon.social/@rangeva/116141536706594966
Source level: 2

## Even with an apology, a data breach is serious. Companies must prioritize robust security over all else, following frameworks like NIST. For victims, immediate password changes, MFA enablement, and monitoring for suspicious activity are crucial. Use tools like Lunar https://lunarcyber.com/ to detect your company's exposure quickly. #DataBreach #Cybersecurity #IncidentResponse
The user lacks the necessary authorization to access the requested page. 
analyse: Access to the requested page is denied. No strategic analysis or cyber recommendations can be provided due to the lack of accessible content. 
tags: ['permission', 'page'] 
observables: {}
Publication date: Fri, 27 Feb 2026 07:04:20 +0000
Source type: ['']
Sources: https://mastodon.social/@rangeva/116141301585787767
Source level: 2

## A large breach can be devastating. Immediately change passwords, especially for critical accounts, and enable MFA everywhere. Monitor your financial accounts for suspicious activity. For real-time monitoring of your company's exposure to such breaches, check out Lunar, powered by Webz.io, at https://lunarcyber.com/. It helps catch leaked credentials fast.#DataBreach #Cybersecurity #MFA
The user lacks the necessary authorization to access the requested webpage. This indicates a permission restriction is in place. The error message confirms the user's inability to view the content. 
analyse: Access to the requested page is denied. No strategic analysis or cyber recommendations can be provided due to the lack of accessible content. 
tags: ['permission', 'page'] 
observables: {}
Publication date: Fri, 27 Feb 2026 07:04:20 +0000
Source type: ['']
Sources: https://mastodon.social/@rangeva/116141301415816294
Source level: 2

## Odido - 688,102 breached accounts
In February 2026, Dutch telco Odido experienced a data breach and extortion attempt. The breach involved 2 million records containing 688,100 affected accounts, including email addresses, names, physical addresses, phone numbers, bank account numbers, and customer service comments. Exposed data may also include dates of birth, passport numbers, and driver's license numbers, and the incident was added to Have I Been Pwned on February 26, 2026. Recommendations include changing passwords and enabling two-factor authentication. 
analyse: The Dutch telco Odido experienced a data breach in February 2026, resulting in the publication of 2 million records containing email addresses and other sensitive data. Compromised data includes bank account numbers, dates of birth, driver's licenses, passport numbers, names, physical addresses, and phone numbers. Recommended actions involve changing passwords, enabling two-factor authentication, and utilizing a password manager. 
tags: ['Odido', 'data breach', 'extortion', 'email addresses', 'records', 'bank account numbers', 'passwords', 'passwords manager', 'two-factor authentication', 'February 2026'] 
observables: {}
Publication date: Thu, 26 Feb 2026 23:25:29 Z
Source type: ['']
Sources: https://haveibeenpwned.com/Breach/Odido
Source level: 2

## Faille IDMerit : quand la vérification d’identité menace notre souveraineté numérique
A security breach exposed 1 billion personal data records from a leader in identity verification. Over 52 million French citizens are affected, and the compromised data includes personal identifiable information (PII) such as ID cards, phone numbers, and addresses. The vulnerable database belonged to IDMerit's subsidiary, IDMkyc, which provides KYC solutions for the FinTech and banking sectors, and was accessible without authentication until November 2025. The exposed data could be exploited for spear phishing, credit fraud, or identity theft. 
analyse: A data breach at a digital identity verification leader exposed approximately 1 billion personal records, with over 52 million French citizens affected. The exposed data includes personally identifiable information (PII) such as ID cards, phone numbers, and addresses, potentially enabling spear phishing, credit fraud, and identity theft. The vulnerable database belonged to IDMkyc, a subsidiary of IDMerit, and provided Know Your Customer (KYC) solutions for FinTech and banking sectors. 
Cyber recommendations:
*   Strengthen data security measures for identity verification organizations.
*   Implement robust access controls and authentication protocols for sensitive databases.
*   Enhance monitoring and detection capabilities to identify and respond to data breaches promptly.
*   Prioritize data minimization and anonymization techniques to reduce the risk of PII exposure.
*   Reinforce security awareness training for employees handling critical identity data. 
tags: ['IDMerit', 'IDMkyc', 'KYC', 'Know Your Customer', 'FinTech', 'spear phishing', 'données personnelles', 'souveraineté des données d’identité', 'droit à l’anonymat', 'sécurité numérique'] 
observables: {}
Publication date: Fri, 27 Feb 2026 08:26:28 +0000
Source type: ['']
Sources: https://www.portail-ie.fr/univers/2026/faille-idmerit-verification-identite-souverainete-numerique/
Source level: 2

## Russia’s quest for disinformation gold
Pro-Kremlin outlets smeared Ukrainian athletes at the Olympics, falsely alleged France was moving towards authoritarianism, and attempted to deflect attention from a report on Navalny’s poisoning by referencing the Epstein files. Russia banned from Olympic events due to doping scandals and the war in Ukraine, some athletes compete under a neutral flag, and pro-Kremlin outlets launched an AI-enhanced FIMI campaign portraying Ukrainian athletes negatively. The Russian Foreign Ministry spokesperson, Maria Zakharova, falsely linked the release of a joint statement regarding Navalny’s poisoning to the release of the Epstein files. 
analyse: Pro-Kremlin outlets have smeared Ukrainian athletes at the Olympics, falsely alleged France is moving towards authoritarianism, and attempted to deflect attention from Navalny’s poisoning by referencing the Epstein files. Russia has banned VPN services that do not accept Kremlin censorship since November 2017, while blocking services like WhatsApp and YouTube. Maria Zakharova, the Russian Foreign Ministry spokesperson, falsely linked the release of a joint statement regarding Navalny’s poisoning to the release of the Epstein files. 
tags: ['Russia', 'disinformation', 'Kremlin', 'Ukraine', 'France', 'Navalny', 'VPNs', 'Epstein files', 'athletes', 'FIMI'] 
observables: {}
Publication date: Fri, 27 Feb 2026 06:21:10 +0000
Source type: ['']
Sources: https://euvsdisinfo.eu/russias-quest-for-disinformation-gold/
Source level: 2

## Russie-Ukraine : quel état des lieux après quatre ans de guerre ?
Four years after the war in Ukraine began, the balance of power has shifted, with Russia occupying a significant portion of the claimed territory. The Kremlin's strategy, differing from that of Europeans, appears to have partially succeeded, but the Ukrainian issue extends beyond territorial concerns to encompass political identity, cultural affiliations, and spheres of influence. Russia aims to prevent NATO expansion and limit foreign military presence in Ukraine, but will not alter the nature of the Ukrainian power structure. The Russian economy shows signs of stagnation, with indicators turning orange towards the end of 2025. 
analyse: The evolving power dynamics indicate that Russia currently occupies a significant portion of the territory claimed by Ukraine, with the erosion of American support weakening the West's ability to defend Ukraine's territorial integrity. The Kremlin's strategy, differing from that of Europeans, appears to prioritize the status of Ukraine over territorial gains, focusing on neutrality, restrictions on the Ukrainian army's capabilities, and cultural and religious considerations. Russia anticipates exhausting Ukraine's resources and leveraging a diplomatic framework established with Washington to impose a ceasefire on Europeans. Economically, Russia faces constraints with indicators turning orange, inflation impacting purchasing power, and a budget deficit, limiting further industrial investment. 
tags: ['Russie', 'Ukraine', 'Kremlin', 'OTAN', 'Europe', 'guerre', 'Vladimir Poutine', 'Kiev', 'Washington', 'Russie-Ukraine'] 
observables: {}
Publication date: Thu, 26 Feb 2026 16:07:36 +0000
Source type: ['']
Sources: https://www.iris-france.org/russie-ukraine-quel-etat-des-lieux-apres-4-ans-de-guerre/
Source level: 2

## Un dialogue est-il possible avec l’ambassadeur d’Israël ?
Joshua Zarka, the ambassador of Israel to France, was invited to participate in an episode of "Comprendre le monde" after Pascal Boniface received an email from the embassy. Boniface accepted the invitation but has not received a follow-up, which is consistent with previous attempts to invite individuals with differing viewpoints. Dialogue between divergent perspectives is increasingly difficult, particularly regarding the Middle East. 
analyse: A dialogue with the Israeli ambassador is possible, but has proven difficult due to a lack of response to invitations. This reflects and exacerbates political polarization, hindering constructive debate. The author maintains an open stance for respectful discussions despite disagreements. 
tags: ['Israël', 'ambassadeur', 'dialogue', 'Proche-Orient', 'politique', 'polarisation', 'débat', 'France', 'IRIS', 'Joshua Zarka'] 
observables: {}
Publication date: Thu, 26 Feb 2026 14:35:48 +0000
Source type: ['']
Sources: https://www.iris-france.org/un-dialogue-est-il-possible-avec-lambassadeur-disrael/
Source level: 2

## L’impact de la crise malienne sur l’Algérie et la Mauritanie : enjeux, dynamiques et répercussions régionales
The Mali crisis, ongoing for over a decade, involves state decline, jihadist expansion, intercommunal tensions, and institutional weaknesses. This instability impacts the Sahel and Maghreb regions, prompting neighboring countries to increase security efforts. Algeria and Mauritania, sharing borders and maintaining significant ties with Mali, are particularly exposed to the crisis's repercussions. 
analyse: The Malian crisis has led to a deterioration of regional security, characterized by the proliferation of weapons, the expansion of jihadist movements, and the strengthening of transnational criminal networks. Algeria and Mauritania, sharing long borders and significant ties with Mali, are particularly exposed to the crisis's repercussions. These countries are intensifying their security efforts in response to the instability impacting the Sahel and the Maghreb. 
tags: ['Mali', 'Sahel', 'Algérie', 'Mauritanie', 'sécurité', 'crise', 'régionale', 'djihadistes', 'frontières', 'terrorisme'] 
observables: {}
Publication date: Thu, 26 Feb 2026 14:35:48 +0000
Source type: ['']
Sources: https://www.iris-france.org/limpact-de-la-crise-malienne-sur-lalgerie-et-la-mauritanie-enjeux-dynamiques-et-repercussions-regionales/
Source level: 2

## Total Recall: Russian attempts to erase the Ukrainian language
Russia has historically treated the Ukrainian language as a political variable, implementing measures to constrain its use across four centuries. The "Strategy for Policy on Russian State Nationalities up to 2036" justifies Russian intervention based on the narrative of protecting Russian speakers and the claim that most Ukrainians are Russian-speaking. By the end of 2025, no Ukrainian schools remained in occupied Crimea, with Russia attempting to Russify and militarize Ukrainian children. Despite Kremlin messaging, surveys indicate over 90% of Ukrainian teachers, parents, and students identify Ukrainian as their native language, a percentage that has been rising due to Russian aggression. 
analyse: Russia's strategy aims to control Ukraine by dismantling its language, viewing it as a political variable rather than a cultural inheritance. The "Strategy for Policy on Russian State Nationalities up to 2036" justifies occupation as historic reunification of Russian-speaking populations, combined with narratives portraying Ukrainians as Russian-speaking. Policies include limiting Ukrainian's use in education, administration, and public life, exemplified by the elimination of Ukrainian schools in occupied Crimea. Despite surveys indicating a rising percentage of Ukrainians identifying Ukrainian as their native language, Kremlin messaging continues to falsely claim oppression of Russian speakers. 
tags: ['Russian', 'Ukraine', 'language', 'Kremlin', 'Ukrainian', 'history', 'culture', 'Russian speakers', 'Soviet', 'Putin'] 
observables: {}
Publication date: Thu, 26 Feb 2026 10:07:59 +0000
Source type: ['']
Sources: https://euvsdisinfo.eu/total-recall-language/
Source level: 2

## The Emerging US Influence Threat to British Democracy
The UK must urgently reassess its foreign interference defenses as US political norms shift and the influence of tech platforms expands. The US National Security Strategy warns of "civilizational erasure" in Europe and intends to cultivate resistance to Europe’s current trajectory. The US State Department intends to fund "MAGA-aligned think tanks" across Europe and the UK. The UK should strengthen its defenses by ensuring only tax-paying voters are eligible to donate to UK political parties, properly maintaining the Foreign Influence Registration Scheme, and applying mandatory funding disclosure standards to think tanks. 
analyse: The UK must urgently reassess its foreign interference defenses due to shifting US political norms and the expanding influence of tech platforms. The US National Security Strategy signals a departure from traditional diplomacy, warning of "civilizational erasure" in Europe and intending to promote "American values" abroad through funding policy discourse. The US government is supporting think tanks, potentially eclipsing the Russian threat in scale and effectiveness. Political finance rules should ensure only eligible voters can donate to UK political parties, and a ceiling should be imposed on individual and corporate donations. 
tags: ['US', 'UK', 'Trump', 'Europe', 'US technology', 'think tanks', 'MAGA', 'Elon Musk', 'Digital Services Act', 'Online Safety Act'] 
observables: {'email-addr': ['069JimMc@rusi.org', 'commentaries@rusi.org'], 'url': ['https://ik.imagekit.io/po8th4g4eqj/production/tr:fo-face,ar-88-112,w-168/eliza-lockhart-jan25-160x224.jpg', 'https://ik.imagekit.io/po8th4g4eqj/production/tr:fo-face,ar-88-112,w-168/Neil-Barnett-AuthorImage-116x224px.jpg', 'https://ik.imagekit.io/po8th4g4eqj/production/tr:w-1168/US-Influence-BannerImage-1168x440px.jpg']}
Publication date: Thu, 26 Feb 2026 00:00:00 GMT
Source type: ['']
Sources: https://www.rusi.org/explore-our-research/publications/commentary/emerging-us-influence-threat-british-democracy
Source level: 2