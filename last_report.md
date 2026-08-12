# Brief quotidien de veille cyber - 2026-08-12

**Domaine :** cyber SOC/CERT
**Date :** 2026-08-12
**Entrée :** 136 articles scrapés (12 source_level 1, 119 level 2, 5 level 3)
**Sortie :** 38 clusters produits (Patch Tuesday Microsoft, Zoomsday, 6 avis CERT-FR, 14 éditeurs CVE, 14 menaces/breaches)

## Table des matières

- [Géopolitique](#geopolitique)
- [Réglementaire et légal](#reglementaire-et-legal)
- [Vulnérabilités](#vulnerabilites)
- [Menaces SOC/CERT](#menaces-soc-cert)

<a id="analyse-strategique"></a>
## Analyse stratégique

Le jour est dominé par le Patch Tuesday d'août 2026 : Microsoft corrige 415 vulnérabilités dont une zero-day exploitée activement (CVE-2026-68820, AFD.sys / WinSock, élévation de privilège locale, attribuée à Lazarus dans Operation Dream Job par Check Point Research) et 62 CVE Critical, dont 4 CVSS 9.8 sans authentification (Windows DNS Server, Windows Deployment Services, QUIC, HPC Pack). À côté, la zero-day Cisco firewall (CVE-2026-20349, DoS sur Remote Access SSL VPN, exploitée en août 2026) et les 7 flaws ClamAV (dont 2 avec PoC public) rappellent que les infrastructures de sécurité sont elles-mêmes la cible. Le second signal fort est la divulgation de « Zoomsday » (CVE-2026-53413/14/15), faille zero-click dans l'annotation Zoom permettant le hijack du client d'un participant, corrigée depuis juin/juillet mais publiée le 11 août.

Côté menaces actives, trois clusters à fort impact opérationnel : Gunra ransomware (alerte FBI/CISA, 51 victimes, exploitation Fortinet CVE-2025-24472 + Schneider CVE-2024-5559, double extorsion) ; Lazarus Operation Dream Job (déploiement du rootkit kernel FudModule via la zero-day AFD.sys sur des cibles défense en Europe et Inde) ; et la compromission d'une centrale polonaise CHP via un APN cellulaire privé, premier cas documenté de pivot IT/OT par ce vecteur (turbine arrêtée, 50 000 habitants concernés, incident de décembre 2025 divulgué le 8 août par CERT Polska). Côté breaches, DentaQuest confirme 15 millions d'individus impactés (plus grosse breach santé 2026, ShinyHunters, base de 234 Go publiée), et la supply chain logistique CEVA Logistics contamine banques, retailers et clients Steam. À surveiller aussi : OpenAI lance GPT-5.6-Cyber avec safeguards réduits pour la recherche d'exploits (Daybreak Red), et l'OpenSSF publie un guide de préparation au Cyber Resilience Act (CRA) pour les communautés open source.

<a id="geopolitique"></a>
## Géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Iran / US** | Eau potable / infrastructure critique | Cyberattaque APT contre infrastructures US | Groupe lié à l'Iran ciblant de nouvelles infrastructures water aux US (New Jersey et Alabama). S'inscrit dans la série d'attaques contre stations de traitement eau et municipalités observée depuis 2023, attribution typique CyberAv3ngers / IRGC-aligned. Pas de détail technique sur le vecteur dans la source. | [securityaffairs](https://securityaffairs.com/197012/hacking/iran-linked-hackers-target-more-us-water-infrastructure-in-new-jersey-and-alabama.html) |
| **Pologne / Russie (présumé)** | Énergie / CHP | Premier pivot IT/OT via APN cellulaire privé documenté | Incident de décembre 2025 divulgué le 8 août 2026 par CERT Polska. Attaquants ont atteint le réseau de contrôle d'une centrale CHP (50 000 habitants chauffés) via un APN cellulaire privé de l'opérateur de distribution, en pivotant depuis un réseau éolien compromis. Turbine à vapeur et traitement d'eau process arrêtées. Aucune coupure client. Premier cas réel de ce vecteur APN selon CERT Polska. CVE-2023-32349 et CVE-2023-32350 citées. Voir [Menaces SOC/CERT](#polish-power-apn). | [thehackernews](https://thehackernews.com/2026/08/hackers-breach-polish-power-plant.html) |
| **DPRK / Europe + Inde** | Défense | Operation Dream Job - Lazarus exploite zero-day Microsoft | Campagne Lazarus (DPRK) ciblant le secteur défense en Europe et Inde via de fausses offres d'emploi et un faux lecteur PDF « SecurityPDF » livrant le backdoor Troy. Exploitation de CVE-2026-68820 (AFD.sys, zero-day Microsoft Patch Tuesday août) pour déployer le rootkit kernel FudModule. Divulgation Check Point Research, patch Microsoft publié le 11 août. Voir [Menaces SOC/CERT](#lazarus-dream-job). | [Check Point Research](https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/) |

<a id="reglementaire-et-legal"></a>
## Réglementaire et légal

**Meta sanctionnée pour destruction de preuves (France, Le Monde, 11 août 2026).** Meta a été condamné pour destruction de preuves dans une affaire de publicités frauduleuses. La sanction illustre l'obligation de préservation des preuves numériques au titre du droit de la consommation et du RGPD, et l'escalade des sanctions contre les plateformes pour manquement à la coopération avec les autorités. Source : [Le Monde](https://www.lemonde.fr/pixels/article/2026/08/11/meta-sanctionnee-pour-destruction-de-preuves-dans-une-affaire-de-publicites-frauduleuses).

**Change Healthcare - encadrement judiciaire des données volées (Minnesota, 7 août 2026).** Un juge fédéral du Minnesota a approuvé un protocole strict de manipulation des données volées lors du litige consolidé contre UnitedHealth Group, Change Healthcare, Optum et United HealthCare Services (suite à la breach 2024). Le protocole couvre les données patients (PHI/PII), validé par un expert cyber indépendant. Précédent sur la gestion judiciaire des données exfiltrées en class action. Source : [databreaches.net](https://databreaches.net/2026/08/11/stolen-change-healthcare-data-gets-new-handling-rules-in-court-order/).

**Cyber Resilience Act (CRA) - guide de préparation pour les communautés open source (OpenSSF, 11 août 2026).** L'OpenSSF publie « CRA Readiness: A Practitioner's Guide to Compliance » et un podcast associé, pour accompagner les communautés open source dans la mise en conformité au Cyber Resilience Act (UE). Enjeu : obligations des fabricants de produits numériques, responsabilité de la supply chain open source, exigences de divulgation de vulnérabilités. À suivre pour les éditeurs intégrant des composants OSS. Sources : [openssf.org/blog](https://openssf.org/blog/2026/08/11/cra-readiness-a-practitioners-guide-to-compliance/), [openssf.org/podcast](https://openssf.org/podcast/2026/08/11/whats-in-the-soss-podcast-68-s3e20-cra-readiness-practical-strategies-for-open-source-communities-with-megan-knight).

<a id="vulnerabilites"></a>
## Vulnérabilités

### Microsoft (Patch Tuesday août 2026 - 415 CVE, 1 zero-day exploitée)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-68820](https://www.cve.org/CVERecord?id=CVE-2026-68820) | 7.0 (IMPORTANT, v3.1) | N/A | Oui (exploitée, KEV) | **Microsoft** Windows AFD.sys (Ancillary Function Driver for WinSock) | Toutes versions antérieures au patch du 11/08 | Use-after-free (CWE-416), race condition | Élévation de privilège locale vers SYSTEM | Correctif publié 11/08 ; exploitée par Lazarus (Operation Dream Job) → voir [Lazarus Dream Job](#lazarus-dream-job) | [CrowdStrike](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-august-2026)<br>[thehackernews](https://thehackernews.com/2026/08/microsoft-patches-398-flaws-including-a-windows-driver-zero-day-under-active-attack.html)<br>[Check Point](https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/)<br>[CIS](https://www.cisecurity.org/advisory/critical-patches-issued-for-microsoft-products-august-11-2026)<br>[KrebsOnSecurity](https://krebsonsecurity.com/2026/08/microsoft-plugs-nearly-400-security-holes/) |
| [CVE-2026-62832](https://www.cve.org/CVERecord?id=CVE-2026-62832) | 9.8 (CRITICAL, v3.1) | N/A | Non | **Microsoft** Windows DNS Server | Versions antérieures au patch | RCE non authentifiée | RCE distante sans interaction | Correctif publié 11/08 | [CrowdStrike](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-august-2026)<br>[KrebsOnSecurity](https://krebsonsecurity.com/2026/08/microsoft-plugs-nearly-400-security-holes/) |
| [CVE-2026-62893](https://www.cve.org/CVERecord?id=CVE-2026-62893) | 9.8 (CRITICAL, v3.1) | N/A | Non | **Microsoft** Windows Deployment Services (WDSServer) | Windows Server avec WDS activé | Use-after-free, RCE adjacente réseau | RCE SYSTEM sans authentification (si WDS activé) | Correctif publié 11/08 ; désactiver WDS si inutile | [ZDI-26-544](http://www.zerodayinitiative.com/advisories/ZDI-26-544/)<br>[thehackernews](https://thehackernews.com/2026/08/microsoft-patches-398-flaws-including-a-windows-driver-zero-day-under-active-attack.html) |
| [CVE-2026-72971](https://www.cve.org/CVERecord?id=CVE-2026-72971) | 9.8 (CRITICAL, v3.1) | N/A | Non | **Microsoft** implémentation QUIC | Versions antérieures au patch | RCE non authentifiée | RCE distante | Correctif publié 11/08 | [CrowdStrike](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-august-2026)<br>[KrebsOnSecurity](https://krebsonsecurity.com/2026/08/microsoft-plugs-nearly-400-security-holes/) |
| CVE-2026-xxxx (HPC Pack) | 9.8 (CRITICAL, v3.1) | N/A | Non | **Microsoft** HPC Pack | Versions antérieures au patch | RCE non authentifiée | RCE distante | Correctif publié 11/08 | [thehackernews](https://thehackernews.com/2026/08/microsoft-patches-398-flaws-including-a-windows-driver-zero-day-under-active-attack.html) |
| [CVE-2026-63520](https://www.cve.org/CVERecord?id=CVE-2026-63520) | N/A | N/A | Non | **Microsoft** SharePoint | Toutes versions non patchées (patch 11/08) | RCE via custom .NET gadget chain | RCE authentifiée ; combinée à CVE-2026-55040 = RCE non authentifiée | Correctif publié 11/08 ; → voir [SharePoint RCE chain](#sharepoint-rce) | [thehackernews](https://thehackernews.com/2026/08/researchers-disclose-ai-assisted-sharepoint-exploit-chain-reaching-unauthenticated-rce.html)<br>[security.nl](https://www.security.nl/posting/948844/Microsoft+komt+vanavond+met+update+voor+RCE-lek+in+SharePoint) |
| [CVE-2026-55040](https://www.cve.org/CVERecord?id=CVE-2026-55040) | N/A | N/A | Non | **Microsoft** SharePoint | Versions patchées le 14/07 seulement | Contournement authentification | RCE non authentifiée combinée à CVE-2026-63520 | Correctif publié 14/07 ; surveiller exploitation chain | [thehackernews](https://thehackernews.com/2026/08/researchers-disclose-ai-assisted-sharepoint-exploit-chain-reaching-unauthenticated-rce.html)<br>[security.nl](https://www.security.nl/posting/948844/Microsoft+komt+vanavond+met+update+voor+RCE-lek+in+SharePoint) |
| [CVE-2026-45659](https://www.cve.org/CVERecord?id=CVE-2026-45659) | 9.8 (CRITICAL, v3.1) | N/A | Oui (KEV, ransomware) | **Microsoft** SharePoint | Versions antérieures au patch 12/05 | RCE non authentifiée | RCE distante exploitée pour ransomware (CISA KEV depuis 01/07) | Correctif publié 12/05 (bulletin publié 21/05) ; → voir [Gunra](#gunra-ransomware) | [security.nl](https://www.security.nl/posting/948804/Kritiek+Microsoft+SharePoint-lek+ook+gebruikt+bij+ransomware-aanvallen) |
| [CVE-2026-62911](https://www.cve.org/CVERecord?id=CVE-2026-62911) | 8.8 (HIGH, v3.1) | N/A | Non | **Microsoft** Exchange | Versions antérieures au patch | Improper authorization, contournement auth | Élévation de privilège vers SYSTEM (auth requise mais bypassable) | Correctif publié 11/08 (Pwn2Own, orange_8361 DEVCORE) | [ZDI-26-538](http://www.zerodayinitiative.com/advisories/ZDI-26-538/) |
| [CVE-2026-65814](https://www.cve.org/CVERecord?id=CVE-2026-65814) | 8.8 (HIGH, v3.1) | N/A | Non | **Microsoft** Windows storport | Versions antérieures au patch | Integer overflow | Élévation de privilège locale vers SYSTEM | Correctif publié 11/08 (Pwn2Own, Viettel) | [ZDI-26-537](http://www.zerodayinitiative.com/advisories/ZDI-26-537/) |
| [CVE-2026-54984](https://www.cve.org/CVERecord?id=CVE-2026-54984) | 7.8 (HIGH, v3.1) | N/A | Non | **Microsoft** Windows (Mscms.dll ICC) | Versions antérieures au patch | OOB write parsing ICC color profiles | RCE dans le contexte du processus | Correctif publié 11/08 | [ZDI-26-543](http://www.zerodayinitiative.com/advisories/ZDI-26-543/) |
| [CVE-2026-62712](https://www.cve.org/CVERecord?id=CVE-2026-62712) | 7.8 (HIGH, v3.1) | N/A | Non | **Microsoft** Windows UMPDDrvBitBlt (win32kfull) | Versions antérieures au patch | Improper object management | Élévation de privilège locale vers SYSTEM | Correctif publié 11/08 | [ZDI-26-542](http://www.zerodayinitiative.com/advisories/ZDI-26-542/) |
| [CVE-2026-65775](https://www.cve.org/CVERecord?id=CVE-2026-65775) | 8.8 (HIGH, v3.1) | N/A | Non | **Microsoft** Windows win32kfull (Pwn2Own) | Versions antérieures au patch | Use-after-free | Élévation de privilège locale vers SYSTEM | Correctif publié 11/08 | [ZDI-26-541](http://www.zerodayinitiative.com/advisories/ZDI-26-541/) |
| [CVE-2026-65776](https://www.cve.org/CVERecord?id=CVE-2026-65776) | 6.5 (MEDIUM, v3.1) | N/A | Non | **Microsoft** Windows win32kfull (Pwn2Own) | Versions antérieures au patch | Use-after-free information disclosure | Fuite d'informations, exploitable en chain vers SYSTEM | Correctif publié 11/08 | [ZDI-26-540](http://www.zerodayinitiative.com/advisories/ZDI-26-540/) |
| [CVE-2026-65773](https://www.cve.org/CVERecord?id=CVE-2026-65773) | 7.8 (HIGH, v3.1) | N/A | Non | **Microsoft** Windows ipt.sys (Pwn2Own) | Versions antérieures au patch | Incorrect permission on registry key | Élévation de privilège locale vers SYSTEM | Correctif publié 11/08 | [ZDI-26-539](http://www.zerodayinitiative.com/advisories/ZDI-26-539/) |

> Patch Tuesday août 2026 : 415 CVE au total (CrowdStrike) / 398 (ZDI, en comptant différemment), 62 Critical, 4 zero-day divulguées (3 non exploitées + 1 exploitée CVE-2026-68820). Répartition par technique : élévation de privilège 174 (42 %), RCE 109 (26 %), fuite d'informations 85 (20 %). Windows reçoit 233 patches, ESU 192, Office 125. Aucune des 4 CVE 9.8 non authentifiées n'était exploitée au moment du patch. Source additionnelle : [Talos (Snort rules)](https://blog.talosintelligence.com/microsoft-patch-tuesday-for-august-2026), [ISC SANS](https://isc.sans.edu/diary/rss/33236).

### Zoom (Zoomsday - faille zero-click annotation)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-53413](https://www.cve.org/CVERecord?id=CVE-2026-53413) | N/A (critique, zero-click) | N/A | Non | **Zoom** Workplace / Rooms / Meeting SDK | Workplace < 7.1.5 / 7.0.6 ; VDI Client < 7.0.11 / 6.6.16 ; Rooms & SDK < 7.1.0 | Faille annotation zero-click | Hijack du client d'un participant (RCE potentielle) par un participant partageant l'écran | Correctifs client publiés en juin/juillet ; aucune exploitation signalée | [thehackernews](https://thehackernews.com/2026/08/zoom-annotation-flaws-could-let-a-meeting-participant-hijack-another-attendees-client.html)<br>[securityaffairs](https://securityaffairs.com/197042/hacking/zoom-patches-zoomsday-zero-click-flaw-enabling-remote-code-execution.html)<br>[security.nl](https://www.security.nl/posting/948857/Zoom-beveiligingslek) |
| [CVE-2026-53414](https://www.cve.org/CVERecord?id=CVE-2026-53414) | N/A | N/A | Non | **Zoom** Workplace / Rooms / Meeting SDK | Idem | Faille annotation zero-click | Hijack du client du présentateur par un participant | Correctifs juin/juillet | [thehackernews](https://thehackernews.com/2026/08/zoom-annotation-flaws-could-let-a-meeting-participant-hijack-another-attendees-client.html) |
| [CVE-2026-53415](https://www.cve.org/CVERecord?id=CVE-2026-53415) | N/A | N/A | Non | **Zoom** Workplace / Rooms / Meeting SDK | Rooms & SDK < 7.1.5 | Faille annotation zero-click | Hijack du client | Correctifs juin/juillet | [thehackernews](https://thehackernews.com/2026/08/zoom-annotation-flaws-could-let-a-meeting-participant-hijack-another-attendees-client.html) |

> Surnommée « Zoomsday ». La faille est dans l'outil d'annotation (partage d'écran). Aucun clic, aucun prompt, aucun téléchargement requis côté victime : la simple présence dans la réunion suffit. Recherche par « A Security » (startup israélienne, levée 37 M$ en juin). Correctifs clients publiés en juin (Zoom Workplace) et juillet (VDI, Rooms, SDK), soit ~2 mois avant divulgation publique. Pas d'exploitation connue. Source additionnelle : [infosec.exchange/@Markcarter](https://infosec.exchange/@Markcarter/117080210846617612).

### CERT-FR (avis du 11 août 2026)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| N/A | N/A | N/A | N/A | **Postfix** | Versions antérieures au dernier correctif | Multiples vulnérabilités | Non spécifié par l'éditeur | Suivre bulletin éditeur | [CERTFR-2026-AVI-0993](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0993/) |
| [CVE-2026-18503](https://www.cve.org/CVERecord?id=CVE-2026-18503) | N/A | N/A | N/A | **CPython** | Versions antérieures au dernier correctif | Vulnérabilité | Non spécifié | Suivre bulletin éditeur | [CERTFR-2026-AVI-0994](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0994/) |
| N/A | N/A | N/A | N/A | **SPIP** | Versions antérieures au dernier correctif | Multiples vulnérabilités | Non spécifié | Suivre bulletin éditeur | [CERTFR-2026-AVI-0995](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0995/) |
| [CVE-2026-17106](https://www.cve.org/CVERecord?id=CVE-2026-17106) | N/A | N/A | N/A | **Docker** Desktop | < 4.86.0 | Atteinte à l'intégrité des données | Compromission de l'intégrité | MAJ Docker Desktop >= 4.86.0 | [CERTFR-2026-AVI-0996](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0996/) |
| N/A | N/A | N/A | N/A | **OpenSSH** | < 10.5 | Multiples vulnérabilités | Non spécifié | MAJ OpenSSH 10.5 | [CERTFR-2026-AVI-0997](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0997/) |
| N/A | N/A | N/A | N/A | **SAP** (ABAP Tools, APO, AP FICA ODN, et autres) | Multiples versions SAP_BASIS, S4CORE, KERNEL, FI-CA | RCE, XSS, SQLi, élév. privilèges, contournement politique sécurité, atteinte confidentialité | Multiples | Appliquer correctifs SAP august-2026 | [CERTFR-2026-AVI-0998](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0998/) |

### Adobe (CIS advisory, 12 CVE)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| CVE-2026-48362, CVE-2026-48273, CVE-2026-71384, CVE-2026-71387, CVE-2026-71385, CVE-2026-25652, CVE-2026-71383, CVE-2026-48375, CVE-2026-71386, CVE-2026-34635, CVE-2026-48440, CVE-2026-21279 | N/A | N/A | N/A | **Adobe** (multiples produits) | Multiples | Arbitrary code execution | Exécution de code arbitraire | Appliquer correctifs Adobe | [CIS](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-adobe-products-could-allow-for-arbitrary-code-execution) |

### Cisco (ClamAV 7 flaws + firewall zero-day)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| CVE-2026-20337, CVE-2026-20339, CVE-2026-20345, CVE-2026-20348, CVE-2026-20338 (+ 2 autres) | N/A | N/A | N/A | **Cisco** ClamAV | Versions antérieures au dernier correctif | Multiples (2 avec PoC public) | RCE / DoS (antivirus lui-même) | MAJ ClamAV ; surveiller PoC publics | [securityaffairs](https://securityaffairs.com/196973/security/cisco-warns-of-seven-clamav-flaws-two-with-public-pocs.html) |
| [CVE-2026-20349](https://www.cve.org/CVERecord?id=CVE-2026-20349) | N/A | N/A | Oui (exploitée août 2026) | **Cisco** Secure Firewall ASA / FTD (Remote Access SSL VPN) | Versions antérieures au patch | DoS via requête HTTP craftée sur SSL VPN | Reload appliance = DoS du pare-feu (impact sécurité : désactivation détection/blocage) | Correctif publié ; exploité depuis août 2026 | [securityweek](https://www.securityweek.com/cisco-patches-firewall-zero-day-exploited-for-dos-attacks/) |

### SonicWall GMS

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-66147](https://www.cve.org/CVERecord?id=CVE-2026-66147) | 9.4 (CRITICAL, v3.1) | N/A | Non | **SonicWall** GMS Dispatcher Service | GMS <= 9.5.1 (Build 9510.1044) | Command injection non authentifiée | RCE distante non authentifiée | MAJ GMS ; restreindre exposition | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-66147) |
| [CVE-2026-66154](https://www.cve.org/CVERecord?id=CVE-2026-66154) | 8.3 (HIGH, v3.1) | N/A | Non | **SonicWall** GMS | GMS <= 9.5.1 | Insufficient certificate validation | Changements non autorisés sous MitM | MAJ GMS ; durcir TLS | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-66154) |

### ZDI - Flowise (RCE non authentifiée)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-69264](https://www.cve.org/CVERecord?id=CVE-2026-69264) | 9.8 (CRITICAL, v3.1) | N/A | Non | **Flowise** (Airtable_Agent) | Versions antérieures au patch | Code injection non authentifiée | RCE contexte service account | MAJ Flowise (PR #6499) | [ZDI-26-546](http://www.zerodayinitiative.com/advisories/ZDI-26-546/) |
| [CVE-2026-69256](https://www.cve.org/CVERecord?id=CVE-2026-69256) | 8.8 (HIGH, v3.1) | N/A | Non | **Flowise** (CSV_Agent customReadCSV) | Versions antérieures au patch | Code injection authentifiée | RCE contexte service account | MAJ Flowise (PR #6257) | [ZDI-26-545](http://www.zerodayinitiative.com/advisories/ZDI-26-545/) |

### ZDI - OriginLab OriginPro (6 CVE parsing fichiers)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-18289](https://www.cve.org/CVERecord?id=CVE-2026-18289) | 7.8 (HIGH, v3.1) | N/A | Non | **OriginLab** OriginPro (OPJ) | Versions antérieures au patch | OOB write parsing OPJ | RCE contexte processus (interaction utilisateur requise) | MAJ OriginPro ; ne pas ouvrir fichiers suspects | [ZDI-26-548](http://www.zerodayinitiative.com/advisories/ZDI-26-548/) |
| [CVE-2026-18288](https://www.cve.org/CVERecord?id=CVE-2026-18288) | 7.8 (HIGH, v3.1) | N/A | Non | **OriginLab** OriginPro (OPJU) | Versions antérieures au patch | OOB write parsing OPJU | RCE | MAJ OriginPro | [ZDI-26-547](http://www.zerodayinitiative.com/advisories/ZDI-26-547/) |
| [CVE-2026-18290](https://www.cve.org/CVERecord?id=CVE-2026-18290) | 7.8 (HIGH, v3.1) | N/A | Non | **OriginLab** OriginPro (OGG) | Versions antérieures au patch | OOB write parsing OGG | RCE | MAJ OriginPro | [ZDI-26-549](http://www.zerodayinitiative.com/advisories/ZDI-26-549/) |
| [CVE-2026-18291](https://www.cve.org/CVERecord?id=CVE-2026-18291) | 7.8 (HIGH, v3.1) | N/A | Non | **OriginLab** OriginPro (OGW) | Versions antérieures au patch | Memory corruption parsing OGW | RCE | MAJ OriginPro | [ZDI-26-550](http://www.zerodayinitiative.com/advisories/ZDI-26-550/) |
| [CVE-2026-18292](https://www.cve.org/CVERecord?id=CVE-2026-18292) | 7.8 (HIGH, v3.1) | N/A | Non | **OriginLab** OriginPro (OGG) | Versions antérieures au patch | Memory corruption parsing OGG | RCE | MAJ OriginPro | [ZDI-26-551](http://www.zerodayinitiative.com/advisories/ZDI-26-551/) |
| [CVE-2026-18293](https://www.cve.org/CVERecord?id=CVE-2026-18293) / [CVE-2026-18294](https://www.cve.org/CVERecord?id=CVE-2026-18294) | 7.8 (HIGH, v3.1) | N/A | Non | **OriginLab** OriginPro / Origin Viewer (OPJ, OGW) | Versions antérieures au patch | OOB write / memory corruption | RCE | MAJ OriginLab | [ZDI-26-552](http://www.zerodayinitiative.com/advisories/ZDI-26-552/)<br>[ZDI-26-553](http://www.zerodayinitiative.com/advisories/ZDI-26-553/) |

### ZDI - Parallels RAS Client (3 CVE LPE)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-18263](https://www.cve.org/CVERecord?id=CVE-2026-18263) | N/A | N/A | N/A | **Parallels** RAS Client RDP Backend Service | Versions antérieures au patch | Exposed dangerous function | Élévation de privilège locale | MAJ Parallels RAS | [ZDI-26-556](http://www.zerodayinitiative.com/advisories/ZDI-26-556/) |
| [CVE-2026-18262](https://www.cve.org/CVERecord?id=CVE-2026-18262) | N/A | N/A | N/A | **Parallels** RAS Client RDP Backend Service | Versions antérieures au patch | Exposed dangerous function | Élévation de privilège locale | MAJ Parallels RAS | [ZDI-26-555](http://www.zerodayinitiative.com/advisories/ZDI-26-555/) |
| [CVE-2026-13121](https://www.cve.org/CVERecord?id=CVE-2026-13121) | N/A | N/A | N/A | **Parallels** RAS Client RDP Backend Service | Versions antérieures au patch | Exposed dangerous function | Élévation de privilège locale | MAJ Parallels RAS | [ZDI-26-554](http://www.zerodayinitiative.com/advisories/ZDI-26-554/) |

### libgit2 (shell command injection via ssh_libssh2)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-5917](https://www.cve.org/CVERecord?id=CVE-2026-5917) | 9.6 (CRITICAL, v3.1) | N/A | Non | **libgit2** (build avec backend ssh_libssh2) | v0.27.0 à v1.9.0 | Shell command injection (gen_proto() non échappé) | RCE sur serveur SSH via métacaractères dans le chemin du repo (submodule URL malveillante dans .gitmodules, recursive clone) | MAJ libgit2 ; éviter backend libssh2 si possible | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-5917) |

### Snowflake (path traversal, confused-deputy priv esc)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-19594](https://www.cve.org/CVERecord?id=CVE-2026-19594) | N/A | N/A | Non | **Snowflake** Python API (snowflake.core) | Versions antérieures au patch | Path traversal + HTTP parameter pollution | Confused-deputy privilege escalation | MAJ snowflake.core | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-19594) |

### Autres éditeurs (cvefeed, tableau compact)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-73248](https://www.cve.org/CVERecord?id=CVE-2026-73248) | N/A | N/A | Non | **calibre** | Versions antérieures au patch | Bypass des restrictions Python template via nested `template()` | RCE | MAJ calibre | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-73248) |
| [CVE-2026-73247](https://www.cve.org/CVERecord?id=CVE-2026-73247) | N/A | N/A | Non | **Kestra** (Pebble http()) | Versions antérieures au patch | SSRF non authentifiée | Accès services internes + cloud metadata | MAJ Kestra ; restreindre Pebble http() | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-73247) |
| [CVE-2026-73242](https://www.cve.org/CVERecord?id=CVE-2026-73242) | 8.3 (HIGH, v4.0) | N/A | Non | **FreeRDP** (Kerberos) | < 3.30.0 | OOB decrypt (GSS Wrap-token EC non borné) | OOB read/write via RDP peer malveillant (CredSSP/NLA) | MAJ FreeRDP 3.30.0 | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-73242) |
| [CVE-2026-55676](https://www.cve.org/CVERecord?id=CVE-2026-55676) | 8.8 (HIGH, v3.1) | N/A | Non | **Malcolm** (network traffic analysis, FilePond PHP) | < 26.06.1 | Upload .php non restreint | RCE via GET sur fichier uploadé (exécution php-fpm) | MAJ Malcolm 26.06.1 ; durcir allow-list | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-55676) |
| [CVE-2026-48765](https://www.cve.org/CVERecord?id=CVE-2026-48765) | 9.9 (CRITICAL, v3.1) | N/A | Non | **TypeBot** (OAuth credentials) | < 3.17.0 | Cross-workspace OAuth credential takeover | Takeover credentials OAuth cross-workspace | MAJ TypeBot 3.17.0 | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-48765) |
| [CVE-2026-48763](https://www.cve.org/CVERecord?id=CVE-2026-48763) | 8.2 (HIGH, v3.1) | N/A | Non | **TypeBot** (S3 upload) | < 3.17.0 | S3 object write arbitraire via endpoint public déprécié | Écriture S3 cross-tenant | MAJ TypeBot 3.17.0 | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-48763) |
| [CVE-2026-14863](https://www.cve.org/CVERecord?id=CVE-2026-14863) | 8.8 (HIGH, v3.1) | N/A | Non | **FileRun** (thumbnail generation) | <= 2026.2.0 | Command injection (filename non échappé via exec()) | RCE authentifiée via nom de fichier malveillant | MAJ FileRun ; sanitize filenames | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-14863) |
| [CVE-2026-15606](https://www.cve.org/CVERecord?id=CVE-2026-15606) | 8.8 (HIGH, v3.1) | N/A | Non | **Frontend Admin by DynamiApps** (plugin WordPress) | <= 3.29.9 | Auth bypass (CBC bit-flipping sur token chiffré) | Reset password arbitraire (y compris admin) = takeover complet | MAJ plugin > 3.29.9 | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-15606) |
| [CVE-2026-18961](https://www.cve.org/CVERecord?id=CVE-2026-18961) | N/A | N/A | Non | **VentraConnect** (plugin WordPress passwordless login) | <= 1.4.3 | Unauthenticated authentication bypass | Auth bypass = accès admin | MAJ plugin > 1.4.3 | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-18961) |
| CVE-2026-72526 / CVE-2026-70398 | N/A | N/A | Non | **multicloud-integrations** | Versions antérieures au patch | Hub tenant → spoke cluster arbitraire / exposition bearer tokens spoke | Compromission multi-cloud | MAJ multicloud-integrations | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-72526)<br>[cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-70398) |
| CVE-2026-68067 / CVE-2026-67568 / CVE-2026-66875 | N/A | N/A | Non | **Mira** Hormone Monitor / Mira Android App | Versions antérieures au patch | Weak auth, hard-coded credentials, missing auth sur fonction critique | Compromission device médical IoT | MAJ app ; contacter éditeur | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-68067)<br>[cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-67568)<br>[cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-66875) |
| [CVE-2026-6484](https://www.cve.org/CVERecord?id=CVE-2026-6484) | N/A | N/A | Non | **Microsoft** GMS FV (verified boot) | Certaines FV | Lack of verified boot | Arbitrary code execution | MAJ firmware | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-6484) |
| [CVE-2026-64954](https://www.cve.org/CVERecord?id=CVE-2026-64954) | N/A | N/A | Non | **Velociraptor** (collect_client) | Versions antérieures au patch | Permissions bypass | Contournement des permissions | MAJ Velociraptor | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-64954) |

### StormEncryptor (ransomware, thecyberthrone)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| CVE-2026-18577 / CVE-2026-18556 | N/A | N/A | N/A | **StormEncryptor** (ransomware) | N/A | Vulnérabilités internes au ransomware | Exploitation possible de la chaîne StormEncryptor | Analyse défensive ; pas de correctif (malware) | [thecyberthrone](https://thecyberthrone.in/2026/08/11/stormencryptor-ransomware-dissection/) |

<a id="menaces-soc-cert"></a>
## Menaces SOC/CERT

<a id="lazarus-dream-job"></a>
### Lazarus / Operation Dream Job - Zero-day Microsoft AFD.sys + FudModule rootkit

### Résumé technique

Check Point Research publie « Shattering the Dream », l'analyse d'une vague récente de l'Operation Dream Job, campagne longue durée attribuée au groupe Lazarus (DPRK). La vague actuelle cible le secteur défense en Europe et en Inde. Le vecteur initial est un faux offre d'emploi livrant « SecurityPDF », un lecteur PDF modifié qui ouvre des documents PDF artisanalement conçus et exécute un nouveau backdoor baptisé Troy.

Pendant l'intrusion, l'attaquant exploite CVE-2026-68820, zero-day du driver Microsoft AFD.sys (Windows Ancillary Function Driver for WinSock), pour déployer une nouvelle version du rootkit kernel-mode FudModule. La divulgation responsable de Check Point a conduit au patch Microsoft du 11 août 2026 (Patch Tuesday).

### Analyse de l'impact

Lazarus combine ingénierie sociale ciblée (faux emploi défense) + zero-day kernel + rootkit persistant : c'est un scénario d'espionnage à haut rendement contre le secteur défense. Le déploiement d'un rootkit kernel via zero-day Microsoft est rare et indique un acteur étatique bien doté. Le patch de CVE-2026-68820 est obligatoire en priorité maximale : la zero-day est activement exploitée et désormais publique.

### Recommandations

* Appliquer immédiatement le patch Microsoft d'août 2026 (CVE-2026-68820) sur tous les postes Windows, en particulier les postes R&D / défense.
* Surveiller les activités de recrutement par email ciblant les ingénieurs défense (faux offres, PDF joints, plateformes job suspicieuses).
* Déployer la détection du rootkit FudModule (signatures YARA, EDR avec inspection kernel).
* Sensibiliser les employés du secteur défense à l'ingénierie sociale par fake job offer (campaigne Operation Dream Job documentée).

### Playbook de réponse à incident

#### Phase 1 - Préparation
* Vérifier le déploiement du patch CVE-2026-68820 sur tout le parc Windows (priorité R&D/défense).
* Activer la journalisation kernel (Sysmon Event ID 1, 7, 8 pour chargement drivers ; ETW pour AFD.sys).
* Préparer des signatures FudModule (YARA, EDR) et le backdoor Troy.
* Sauvegardes hors-ligne des postes R&D sensibles.

#### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle Sysmon : chargement de driver non signé ou suspect dans le contexte d'un process PDF reader / SecurityPDF.
  * Règle YARA : signatures FudModule (kernel rootkit) et Troy (backdoor userland).
  * Détection EDR : manipulation de tokens kernel, hooks SSRB, désactivation de solutions de sécurité (T1562).
* Analyser la chronologie : email de phishing → ouverture PDF → Troy → exploitation CVE-2026-68820 → FudModule.
* Identifier les comptes ciblés (ingénieurs défense, accès à la propriété intellectuelle).

#### Phase 3 - Confinement, éradication et récupération

**Confinement :**
* Isoler les postes compromis du réseau.
* Révoquer les credentials des comptes ciblés.

**Éradication :**
* Supprimer FudModule (kernel) et Troy (userland). Reconstruire le poste depuis une image propre si doute sur l'intégrité kernel.
* Fermer les canaux de persistance FudModule (SSDT hooks, callback kernel).

**Récupération :**
* Restaurer depuis image propre post-patch CVE-2026-68820.
* Surveillance EDR 72h post-restauration.

#### Phase 4 - Activités post-incident
* Rapport d'incident avec chronologie Dream Job → Troy → FudModule.
* Notifications (NIS2 si entité essentielle, RGPD si données personnelles, export control si données défense).
* Partage IOCs au CERT national et partenaires sectoriels défense.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres postes ont reçu SecurityPDF. | T1566.001 - Spearphishing Attachment | Logs email / EDR | Pièces jointes PDF + process `SecurityPDF.exe` ou variantes sur 90 jours. |
| FudModule a désactivé des solutions de sécurité. | T1562.001 - Disable Tools | EDR / Sysmon Event ID 1 | Arrêt ou modification de configuration d'AV/EDR sur postes R&D. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC technique publié dans la source OTX, se référer au rapport Check Point complet) | N/A | IOCs à extraire du PDF Check Point Research. | Moyenne |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566.001 | Initial Access | Spearphishing Attachment | Faux offre d'emploi + SecurityPDF malveillant. |
| T1068 | Privilege Escalation | Exploitation for Privilege Escalation | Zero-day CVE-2026-68820 AFD.sys. |
| T1014 | Defense Evasion | Rootkit | FudModule rootkit kernel-mode. |

### Sources
* [Check Point Research - Shattering the Dream](https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/)
* [thehackernews - Lazarus / AFD.sys](https://thehackernews.com/2026/08/microsoft-patches-398-flaws-including-a-windows-driver-zero-day-under-active-attack.html)
* [OTX Pulse - Lazarus AFD.sys FudModule](https://social.raytec.co/@techbot/117080559364185575)
* [reddit r/blueteamsec](https://www.reddit.com/r/blueteamsec/comments/1vm2uwf/shattering_the_dream_when_a_job_offer_becomes_a/)

---

<a id="gunra-ransomware"></a>
### Gunra ransomware - Alerte FBI/CISA, 51 victimes, Fortinet + Schneider

### Résumé technique

Les services cyber de Corée du Sud et la CISA/FBI publient une alerte conjointe sur le rançongiciel Gunra, qui cible les infrastructures critiques mondiales : santé, services financiers, gouvernement, services professionnels et à but non lucratif. Gunra a listé 51 victimes depuis son émergence (Ransomware.Live).

Le vecteur d'accès initial combine : (1) failles internet-facing Schneider Electric PowerLogic P5 (CVE-2024-5559) et Fortinet FortiOS / FortiProxy (CVE-2025-24472), (2) credentials volés ou leakés, (3) failles SSH access control sur passerelles VPN. Post-compromission : mouvement latéral via sessions volées et RDP, ciblage des webservers d'auth VDI, contrôleurs Active Directory, bureaux virtuels IT, exfiltration OneDrive/SharePoint (parfois dizaines de To), puis déploiement ransomware. Modèle double extorsion : exfiltration + chiffrement. Délai de paiement 5 à 7 jours, publication sur data leak site sinon.

### Analyse de l'impact

Gunra est l'évolution courante du « ransomware as a service » ciblant l'infrastructure critique. Le schéma Fortinet + credentials + SharePoint est opérationnellement critique : les pare-feu Fortinet sont très répandus, et la combinaison avec CVE-2026-45659 SharePoint (CISA KEV pour ransomware) crée une chaîne complète d'accès initial jusqu'au déploiement. Les SOC/CERT doivent traiter l'alerte FBI/CISA comme priorité maximale.

### Recommandations

* Vérifier le patch Fortinet CVE-2025-24472 sur tous les FortiOS / FortiProxy exposés (patch disponible depuis février 2025).
* Vérifier le patch Schneider Electric PowerLogic P5 CVE-2024-5559.
* Surveiller et restreindre les accès VPN (MFA phishing-resistant, rotation des credentials, détection SSH access control anomalies).
* Segmenter Active Directory, VDI et SharePoint ; durcir l'authentification admin.
* Détection d'exfiltration OneDrive/SharePoint (DLP, anomaly detection, alertes sur gros volumes).

### Playbook de réponse à incident

#### Phase 1 - Préparation
* Inventorier les pare-feu Fortinet et Schneider PowerLogic P5 exposés, vérifier patchs.
* MFA FIDO2 sur VPN, comptes admin AD, comptes VDI.
* Sauvegardes hors-ligne immuables ; test de restauration SharePoint.
* Journalisation VDI, AD, OneDrive/SharePoint (audit logs activés).

#### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle SIEM : authentifications VPN成功 depuis IP suspectes + rotation rapide de sessions RDP/VDI.
  * Règle EDR : exécution PsExec / WMI / Cobalt Strike post-authentification VPN.
  * Détection cloud : bulk download OneDrive / SharePoint (>10 Go anormaux), créations de comptes admin AD.
* Chronologie : identifier l'entrée (Fortinet / Schneider / credentials), le dwell time, le volume exfiltré.

#### Phase 3 - Confinement, éradication et récupération

**Confinement :**
* Isoler les segments impactés ; couper l'accès VPN externe si déploiement ransomware.
* Désactiver les comptes admin compromis ; réinitialiser deux fois `krbtgt`.

**Éradication :**
* Supprimer les implants ransomware et les comptes malveillants.
* Pivoter toutes les credentials admin AD, VPN, VDI.
* Fermer les canaux de persistance (tâches planifiées, services malveillants).

**Récupération :**
* Restaurer SharePoint / OneDrive depuis sauvegardes hors-ligne immuables.
* Reconstruire les contrôleurs de domaine si compromis.
* Surveillance 72h post-restauration.

#### Phase 4 - Activités post-incident
* Notifications NIS2/RGPD/DORA selon entité ; CISA si US.
* Partage IOCs au CERT national et FS-ISAC.
* REX et métriques MTTD/MTTR.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Sessions VPN suspectes avec rotation RDP/VDI anormale. | T1078 - Valid Accounts | Logs VPN / VDI | Authentifications VPN réussies hors heures ouvrées + sessions RDP vers AD/VDI dans la foulée. |
| Bulk download OneDrive/SharePoint pré-chiffrement. | T1530 - Data from Cloud Storage | Microsoft 365 audit logs | Téléchargements >10 Go par comptes non-admin sur 7 jours. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC publié dans les sources journalistiques, se référer à l'alerte FBI/CISA originale) | N/A | IOCs à extraire de l'alerte conjointe. | Moyenne |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1190 | Initial Access | Exploit Public-Facing Application | Fortinet CVE-2025-24472 + Schneider CVE-2024-5559. |
| T1078 | Initial Access | Valid Accounts | Credentials volés / leakés. |
| T1021.001 | Lateral Movement | Remote Desktop Protocol | RDP pour mouvement latéral post-VPN. |
| T1486 | Impact | Data Encrypted for Impact | Déploiement ransomware Gunra. |
| T1567 | Exfiltration | Exfiltration Over Web Service | Exfiltration OneDrive/SharePoint. |

### Sources
* [thehackernews - Gunra](https://thehackernews.com/2026/08/gunra-ransomware-exploits-fortinet-and-schneider-electric-flaws-to-breach-networks.html)
* [security.nl - Gunra Fortinet](https://www.security.nl/posting/948776/VS+waarschuwt+voor+ransomware-aanvallen+via+kwetsbare+Fortinet-firewalls)
* [thecyberexpress - Gunra RaaS](https://thecyberexpress.com/gunra-ransomware-expands-raas-operations/)
* [security.nl - SharePoint ransomware](https://www.security.nl/posting/948804/Kritiek+Microsoft+SharePoint-lek+ook+gebruikt+bij+ransomware-aanvallen)

---

<a id="polish-power-apn"></a>
### Centrale polonaise CHP - Premier pivot IT/OT via APN cellulaire privé

### Résumé technique

CERT Polska a divulgué le 8 août 2026 un incident survenu en décembre 2025 dans une centrale combinée chaleur-énergie (CHP) polonaise approvisionnant en chaleur ~50 000 habitants. Les attaquants ont atteint le réseau de contrôle industriel via un APN cellulaire privé (Access Point Name), dédié à l'opérateur de distribution pour joindre des équipements distants. Une configuration permettant à n'importe quel device sur l'APN de communiquer avec les autres a permis à l'attaquant de pivoter depuis un réseau éolien compromis vers un contrôleur de la centrale CHP.

L'attaquant a arrêté la turbine à vapeur et le système de traitement d'eau process. La récupération a commencé vers 7h30 alors que les intrus étaient encore actifs. Aucune coupure client (ni chaleur ni électricité). CERT Polska indique qu'il s'agit, à sa connaissance, du premier cas réel documenté d'attaque IT/OT via APN cellulaire privé. CVE-2023-32349 et CVE-2023-32350 sont citées dans la chaîne (côté wind farm).

### Analyse de l'impact

Le vecteur APN cellulaire privé outrepasse la plupart des contrôles IT/OT classiques (segmentation Ethernet, pare-feu). Les infrastructures utilisant des APN dédiés (énergie, transport, télécoms) doivent reconsidérer leur modèle de isolation : un équipement compromis sur l'APN peut atteindre n'importe quel autre. L'arrêt d'une turbine en exploitation est un événement de sécurité physique potentiel.

### Recommandations

* Segmenter les APN cellulaires privés : interdire la communication device-à-device sur l'APN sauf whitelist explicite.
* Appliquer l'authentification mutuelle et le chiffrement sur les APN industriels.
* Surveiller les flux intra-APN (IDS dédié, NetFlow).
* Vérifier le patch CVE-2023-32349 / CVE-2023-32350 sur les équipements éoliens.

### Playbook de réponse à incident

#### Phase 1 - Préparation
* Inventorier les APN cellulaires privés et leur configuration (isolation device-à-device).
* Plan de coupure / isolation APN en cas d'incident.
* Journalisation des flux intra-APN (IDS, NetFlow).

#### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle IDS/APN : connexion d'un équipement vers un contrôleur hors de son whitelist.
  * Détection OT : arrêt de turbine / système de traitement sans commande légitime.
* Chronologie : identifier le pivot depuis le réseau éolien, l'arrêt de la turbine, la fenêtre d'activité.

#### Phase 3 - Confinement, éradication et récupération

**Confinement :**
* Isoler l'APN cellulaire ; couper la connectivité device-à-device.
* Couper l'accès du réseau éolien compromis à l'APN.

**Éradication :**
* Restaurer la configuration APN (whitelist, authentification mutuelle).
* Patch CVE-2023-32349/32350 sur les équipements éoliens.
* Reconstruire les contrôleurs compromise.

**Récupération :**
* Redémarrer la turbine et le traitement d'eau process selon procédure OT.
* Surveillance OT 72h post-restauration.

#### Phase 4 - Activités post-incident
* Notifications NIS2 (entité essentielle énergie), IEC 62443, autorité sectorielle.
* Partage au CERT national et ENISA.
* REX avec l'opérateur de distribution et le régulateur énergie.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres équipements sur l'APN ont été ciblés. | T808 - Contamination of Public Cloud (n/a) - préférer T1021 - Remote Services | Logs APN / NetFlow | Communications intra-APN hors whitelist sur 90 jours. |
| Le réseau éolien a d'autres vecteurs d'accès non patchés. | T1190 - Exploit Public-Facing Application | Logs éoliens / EDR OT | Équipements éoliens non patchés CVE-2023-32349/32350. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC publié par CERT Polska dans la source journalistique) | N/A | Se référer au rapport CERT Polska original. | Moyenne |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T808 | (ICS) | (n/a) | Pivot IT/OT via APN cellulaire privé. |
| T1021 | Lateral Movement | Remote Services | Accès au contrôleur via APN. |
| T1485 | Impact | Data Destruction | Arrêt de la turbine et du traitement d'eau. |

### Sources
* [thehackernews - Polish power plant APN](https://thehackernews.com/2026/08/hackers-breach-polish-power-plant-controls-via-private-cellular-network-and-shut-turbine.html)

---

<a id="head-mare-trueconf"></a>
### Head Mare APT - Exploitation TrueConf server + PhantomCore / PhantomGraph

### Résumé technique

Kaspersky publie l'analyse d'une attaque du groupe Head Mare (précédemment classé hacktiviste, requalifié APT) détectée en juillet 2026. L'attaquant exploite une chaîne de deux nouvelles vulnérabilités (KLCERT-26-057 et KLCERT-26-058) sur le serveur de visioconférence TrueConf pour exécuter du code arbitraire avec privilèges maximaux. Le port 4307/TCP, ouvert par défaut, est utilisé pour se connecter sans autorisation préalable. Les versions TrueConf 5.3.x à 5.3.9, 5.4.x à 5.4.9, et 5.5.x à 5.5.5 sont affectées.

Les attaquants remplacent les installers TrueConf client par des versions infectées qui déploient le malware PhantomCore sur les participants à la visioconférence. Un second composant, PhantomGraph, est aussi déployé. Absence d'activité destructive (chiffrement / wiping) sur les infrastructures cibles : orientation espionnage.

### Analyse de l'impact

TrueConf est un système de visioconférence déployé en entreprise et dans des contextes sensibles (gouvernement, défense). La compromission du serveur permet la redistribution de clients infectés à tous les participants, ce qui en fait un vecteur de supply chain interne à large échelle. Head Mare est désormais qualifié APT, ce qui élève le niveau de menace au-dessus des hacktivistes classiques.

### Recommandations

* Mettre à jour TrueConf server au-delà des versions affectées (5.3.9, 5.4.9, 5.5.5).
* Restreindre l'accès au port 4307/TCP (segmentation, ACL) ; ne pas l'exposer publiquement.
* Vérifier l'intégrité des installers TrueConf client distribués (hashs, signature).
* Déployer la détection PhantomCore et PhantomGraph (YARA, EDR).

### Playbook de réponse à incident

#### Phase 1 - Préparation
* Inventorier les serveurs TrueConf et leur exposition (port 4307/TCP).
* Vérifier les versions (5.3.x-5.3.9, 5.4.x-5.4.9, 5.5.x-5.5.5).
* Préparer signatures YARA PhantomCore / PhantomGraph.

#### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle firewall / IDS : connexions sur port 4307/TCP depuis IP non whitelistées.
  * Détection EDR : exécution de binaires TrueConf client non signés ou avec hash inconnu.
  * YARA : PhantomCore, PhantomGraph.
* Analyser les installers distribués sur la période d'exposition.

#### Phase 3 - Confinement, éradication et récupération

**Confinement :**
* Isoler le serveur TrueConf compromise.
* Couper la distribution d'installers client suspects.

**Éradication :**
* Mettre à jour le serveur TrueConf.
* Supprimer PhantomCore / PhantomGraph des postes participants.
* Redistribuer des installers TrueConf authentiques.

**Récupération :**
* Surveillance EDR 72h post-éradication.

#### Phase 4 - Activités post-incident
* Notifications (NIS2/RGPD selon entité).
* Partage IOCs au CERT national.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres installers TrueConf ont été remplacés. | T1195.002 - Compromise Software Supply Chain | Logs déploiement / EDR | Hashs des binaires TrueConf client distribués sur 90 jours vs hashs officiels. |
| PhantomCore a exfiltré des données. | T1041 - Exfiltration Over C2 Channel | EDR / réseau | Connexions sortantes depuis process TrueConf / PhantomCore. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (IOCs disponibles dans le rapport Securelist complet : file hashes MD5, IP, domaines, noms de services Windows, chemins, clés de registre, règles YARA) | N/A | Se référer à la section IOCs du rapport Securelist. | Haute (Kaspersky) |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1190 | Initial Access | Exploit Public-Facing Application | Exploitation TrueConf server (KLCERT-26-057/058). |
| T1195.002 | Initial Access | Compromise Software Supply Chain: Compromise Software Update | Remplacement des installers TrueConf client. |
| T1219 | Execution | Remote Access Software | TrueConf utilisé comme vecteur d'exécution. |

### Sources
* [Securelist - Head Mare TrueConf](https://securelist.com/tr/head-mare-targets-trueconf-server-with-phantomcore-phantomgraph/120981/)

---

<a id="cav3rn"></a>
### Project CAV3RN - C2 Google Apps Script relay, DNS-based channel selection (cibles Israël)

### Résumé technique

Kaspersky publie la suite de l'analyse du framework d'espionnage modulaire CAV3RN (rapports précédents juin et juillet 2026). Cible : Israël. Le nouveau module de communication C2 (`GoogleService.dll`, .NET 8 NativeAOT) utilise les réponses DNS A-record pour choisir entre canal HTTPS direct et relay Google Apps Script pour chaque transaction. L'infrastructure DNS peut valider et remplacer l'ID de déploiement du relay, permettant la rotation du canal Google.

Le framework inclut aussi un broker local qui découvre et charge les composants DLL, route les messages entre eux, et supporte les mises à jour runtime. PDB path : `C:\Users\user\Desktop\Modules\broker-cavern\communication\GoogleCommunication\bin\Release\net8.0\win-x64\native\GoogleService.pdb`.

### Analyse de l'impact

L'usage de Google Apps Script comme relay C2 est significatif : le trafic sortant ressemble à un appel légitime à Google, contournant la plupart des listes de blocage. La sélection DNS entre canaux ajoute une résilience opérationnelle élevée. Framework modulaire typique d'un acteur étatique (cible Israël suggère Iran-aligned probable). Détection difficile, à baser sur le comportement (DLL inattendue, DNS exfiltration patterns).

### Recommandations

* Surveiller les appels à `script.google.com` depuis des processus non navigateurs (GoogleService.dll, .NET NativeAOT).
* Détection DNS : requêtes A-record anormales avec rotation d'ID de déploiement.
* Détection EDR : chargement de DLL non signée `GoogleService.dll`, broker DLL local.
* Restreindre l'exécution de .NET NativeAOT hors des chemins approuvés.

### Playbook de réponse à incident

#### Phase 1 - Préparation
* Journaliser les requêtes DNS et les appels à `script.google.com`.
* Activer la détection EDR sur chargement de DLL .NET NativeAOT.

#### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle DNS : requêtes A avec patterns de rotation d'ID suspects.
  * Règle EDR : process non navigateur contactant `script.google.com`.
  * YARA : GoogleService.dll, broker CAV3RN.
* Analyser le PDB path et les hashes.

#### Phase 3 - Confinement, éradication et récupération

**Confinement :**
* Isoler les postes compromis.
* Bloquer `script.google.com` pour les comptes non approuvés (proxy).

**Éradication :**
* Supprimer GoogleService.dll et les composants CAV3RN.
* Pivoter les credentials compromises.

**Récupération :**
* Surveillance 72h post-éradication.

#### Phase 4 - Activités post-incident
* Notifications (NIS2/RGPD).
* Partage IOCs au CERT national.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres postes contactent `script.google.com` hors navigateur. | T1071.001 - Web Protocols | Proxy / EDR | Appels `script.google.com` par process hors Chrome/Edge/Firefox. |
| Rotation d'ID de déploiement Google Apps Script suspecte. | T1568.002 - Dynamic Resolution | Logs DNS | Requêtes A avec changements fréquents d'ID dans le path. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (IOCs disponibles dans le rapport Securelist : file hashes, domaines, IPs) | N/A | Se référer au rapport complet. | Haute (Kaspersky) |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1071.001 | Command and Control | Web Protocols | HTTPS via Google Apps Script relay. |
| T1568.002 | Command and Control | Dynamic Resolution: Domain Generation Algorithms | Sélection de canal via DNS A-record. |
| T1219 | Command and Control | Remote Access Software | (n/a - préférer T1105 Ingress Tool Transfer) |

### Sources
* [Securelist - Project CAV3RN continues](https://securelist.com/project-cav3rn-continues/120991/)
* [OTX Pulse - CAV3RN Google Apps Script](https://social.raytec.co/@techbot/117080803713457795)

---

<a id="iran-water"></a>
### Hackers liés à l'Iran ciblent de nouvelles infrastructures water US (NJ + Alabama)

### Résumé technique

SecurityAffairs rapporte que des hackers liés à l'Iran ciblent de nouvelles infrastructures water aux US (New Jersey et Alabama). S'inscrit dans la série d'attaques contre stations de traitement eau et municipalités US observée depuis 2023, attribution typique CyberAv3ngers / IRGC-aligned. La source journalistique ne fournit pas de détail technique sur le vecteur (à corréler avec les alertes FBI/CISA sur appareils Unitronics PLC).

### Analyse de l'impact

Le secteur water est une infrastructure critique sous-protégée (OT peu segmenté, appareils PLC exposés). Les attaques successives contre le secteur water US indiquent une intention étatique de démonstration de capacité et de collecte de renseignement. Risque de contamination potable ou de coupure.

### Recommandations

* Segmenter les réseaux OT water des réseaux IT.
* Vérifier l'exposition publique des PLC (Unitronics, Schneider) via Shodan.
* Déployer la détection OT (Nozomi, Claroty).
* Appliquer les recommandations CISA pour le secteur water (alertes CyberAv3ngers précédentes).

### Playbook de réponse à incident

#### Phase 1 - Préparation
* Inventorier les PLC et équipements OT water exposés.
* Journalisation OT (logs PLC, network flows).

#### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle OT/IDS : connexions non autorisées sur PLC.
  * Détection : changements de configuration PLC hors fenêtres de maintenance.

#### Phase 3 - Confinement, éradication et récupération
* Isoler les PLC compromise du réseau.
* Restaurer la configuration PLC depuis backup offline.
* Surveillance 72h.

#### Phase 4 - Activités post-incident
* Notifications NIS2 / CISA / EPA (secteur water US).
* Partage au CERT national et WaterISAC.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres PLC sont exposés publiquement. | T805 - (ICS) | Shodan / scans externes | Exposition PLC Unitronics / Schneider sur IP publiques. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC publié dans la source) | N/A | À corréler avec les alertes CISA CyberAv3ngers. | Faible |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T808 | (ICS) | (n/a) | Attaque sur infrastructure water. |

### Sources
* [securityaffairs - Iran water NJ Alabama](https://securityaffairs.com/197012/hacking/iran-linked-hackers-target-more-us-water-infrastructure-in-new-jersey-and-alabama.html)

---

<a id="kimwolf-v7"></a>
### Kimwolf v7 - Évolution du botnet Android / IoT

### Résumé technique

Unit 42 (Palo Alto Networks) publie l'analyse de la v7 du botnet Kimwolf, qui cible les Android TV boxes et set-top boxes. La v7 améliore les capacités d'attaque DDoS et la résilience du C2 via un tunnel HTTP. Le nom « Kimwolf » contient un slur racial utilisé par l'opérateur (partiellement redacted par Unit 42 pour permettre l'identification).

### Analyse de l'impact

Les Android TV boxes et set-top boxes sont massivement déployées, sous-protégées (firmware non mis à jour, credentials par défaut), et constituent une surface de botnet idéal. Kimwolf v7 ajoute la résilience C2 (HTTP tunnel) qui complique le démantèlement. Les DDoS qui en sortent peuvent saturer des cibles critiques.

### Recommandations

* Mettre à jour les Android TV boxes et set-top boxes.
* Changer les credentials par défaut.
* Déployer la détection DDoS en sortie (NDR, NetFlow).
* Surveiller les tunnels HTTP anormaux depuis devices IoT.

### Playbook de réponse à incident

#### Phase 1 - Préparation
* Inventorier les Android TV / set-top boxes.
* Journalisation des flux sortants IoT.

#### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle NDR : tunnels HTTP anormaux depuis devices IoT.
  * Détection : pics de trafic DDoS en sortie.

#### Phase 3 - Confinement, éradication et récupération
* Isoler les devices compromise.
* Rebuilder firmware depuis image propre.
* Surveillance 72h.

#### Phase 4 - Activités post-incident
* Notifications si DDoS sortant impacte des tiers.
* Partage au CERT national.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres Android TV boxes sont infectées. | T1498 - Network Denial of Service | NDR / NetFlow | Pics de trafic UDP/TCP synchronisés depuis devices IoT. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (IOCs dans le rapport Unit 42 complet) | N/A | Se référer au rapport Unit 42. | Haute (Unit 42) |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1498 | Impact | Network Denial of Service | DDoS via botnet Kimwolf v7. |
| T1071.001 | Command and Control | Web Protocols | Tunnel HTTP C2. |

### Sources
* [Unit 42 - Kimwolf v7](https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/)

---

<a id="bdthemes-supply-chain"></a>
### BdThemes - Supply chain attack via JSON poisoning, rogue WordPress admins

### Résumé technique

thehackernews rapporte une attaque par supply chain contre BdThemes (vendeur de thèmes WordPress). Des fichiers JSON malveillants ont été injectés pour créer des administrateurs WordPress fantaisistes sur les sites utilisant les thèmes compromise. Le vecteur exact (compromission du dépôt, mise à jour malveillante) n'est pas détaillé dans la source journalistique.

### Analyse de l'impact

Les thèmes WordPress sont massivement déployés. Une compromission de la supply chain permet une prise de contrôle à large échelle de sites WordPress (e-commerce, médias, institutionnels). Les administrateurs fantaisistes constituent une persistance difficile à détecter sans audit des comptes admin.

### Recommandations

* Vérifier les comptes administrateurs WordPress sur les sites utilisant BdThemes.
* Mettre à jour les thèmes BdThemes depuis une source propre.
* Activer la détection d'administration fantaisiste (WAF, audit des comptes admin).
* Durcir l'authentification admin WordPress (MFA, limitation des créations de comptes).

### Playbook de réponse à incident

#### Phase 1 - Préparation
* Inventorier les sites WordPress utilisant BdThemes.
* Activer l'audit des comptes admin.

#### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle WAF / SIEM : créations de comptes admin WordPress sans légitimité.
  * Détection : connexions admin WordPress depuis IP suspectes.

#### Phase 3 - Confinement, éradication et récupération
* Supprimer les comptes admin fantaisistes.
* Mettre à jour BdThemes depuis source propre.
* Pivoter les credentials admin légitimes.

#### Phase 4 - Activités post-incident
* Notifications si données personnelles / e-commerce compromises.
* Partage au CERT national.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres sites WordPress ont des comptes admin fantaisistes. | T1136.001 - Create Account: Local Account | Logs WordPress | Créations de comptes admin hors fenêtres de maintenance sur 90 jours. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC publié dans la source journalistique) | N/A | À corréler avec l'analyse technique complète. | Faible |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1195.002 | Initial Access | Compromise Software Supply Chain | Supply chain BdThemes. |
| T1136.001 | Persistence | Create Account: Local Account | Admins WordPress rogue. |

### Sources
* [thehackernews - BdThemes supply chain](https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons-json-to-create-rogue-wordpress-admins.html)

---

<a id="chaindrop-npm"></a>
### ChainDrop - Ver auto-propageant npm, 400+ packages compromise

### Résumé technique

Un pulse OTX signale « ChainDrop Worm », un ver auto-propageant sur l'écosystème npm qui aurait infecté plus de 400 packages. Données préliminaires (non vérifiées). Pas de détail technique dans la source OTX. À rapprocher des vers npm précédents (2024, packages self-propagating).

### Analyse de l'impact

Un ver npm à 400+ packages indique une propagation transverse dans la supply chain JavaScript. Tout projet Node.js avec dépendances non verrouillées (pas de `npm ci` depuis lockfile immuable) est à risque d'exécution de code malveillant en build ou runtime. Les SOC/CERT avec un parc de développement Node.js doivent traiter comme incident supply chain majeur.

### Recommandations

* Verrouiller les dépendances npm (`npm ci`, lockfile integrity, SBOM).
* Restreindre l'installation de packages non vérifiés.
* Activer npm 2FA pour les mainteneurs internes.
* Surveiller les `npm install` depuis registry non officiel.

### Playbook de réponse à incident

#### Phase 1 - Préparation
* Inventorier les dépendances npm critiques.
* Vérifier l'intégrité des lockfiles (SBOM, sigstore).

#### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle SIEM : `npm install` exécuté par compte service + connexion vers registry non officiel.
  * Détection : dépendances avec hashes inattendus vs lockfile.

#### Phase 3 - Confinement, éradication et récupération
* Isoler les machines de dev / build compromise.
* Forcer `npm ci` depuis lockfile propre (post-nettoyage).
* Bloquer les registrys non officiels.

#### Phase 4 - Activités post-incident
* Notifications si breach en production.
* Partage au CERT national et écosystème npm (GitHub Advisory).

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres packages malveillants installés. | T1195.002 - Compromise Software Supply Chain | Logs npm / EDR | `npm install` hors lockfile sur 30 jours. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC publié, pulse OTX préliminaire) | N/A | À enrichir dès publication technique. | Faible |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1195.002 | Initial Access | Compromise Software Supply Chain: Package Manager | Ver npm auto-propageant. |

### Sources
* [OTX Pulse - ChainDrop npm worm](https://social.raytec.co/@techbot/117080803630207771)

---

<a id="abyssos-rat"></a>
### Abyssos - Nouveau RAT modulaire (OTX préliminaire)

### Résumé technique

Deux pulses OTX (auteur Tr1sa111, préliminaires non vérifiés) décrivent « Abyssos », un nouveau RAT modulaire. Pas de détail technique dans les sources OTX (à enrichir dès publication publique). Architecture modulaire suggère capacité d'extension par plugins.

### Analyse de l'impact

Faible densité informationnelle mais signal à surveiller. Les RAT modulaires sont difficiles à détecter par signatures fixes (plugins variables). Détection à baser sur le comportement (process injection, C2 anormal).

### Recommandations

* Surveiller les comportements de RAT (process injection, C2 beacons).
* Déployer EDR avec détection comportementale.

### Playbook de réponse à incident

#### Phase 1 - Préparation
* EDR détection comportementale active.

#### Phase 2 - Détection et analyse
* Détection : process injection, connexions C2 anormales.

#### Phase 3 - Confinement, éradication et récupération
* Isoler le poste.
* Supprimer les modules Abyssos.

#### Phase 4 - Activités post-incident
* Partage au CERT national.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres postes infectés par Abyssos. | T1055 - Process Injection | EDR | Process injection anormale sur 30 jours. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC publié, pulse OTX préliminaire) | N/A | À enrichir. | Faible |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1055 | Defense Evasion | Process Injection | (typique RAT modulaire). |

### Sources
* [OTX Pulse - Abyssos RAT](https://social.raytec.co/@techbot/117080812382778866)
* [OTX Pulse - Abyssos RAT (duplicate)](https://social.raytec.co/@techbot/117080792373367137)

---

<a id="falcon-extortion"></a>
### Falcon extortion - AitM phishing + vishing contre services financiers

### Résumé technique

GuidePoint Security publie « Bird Watching », une analyse de l'infrastructure et du comportement des opérations d'extortion « Falcon-branded ». Activité soutenue depuis avril 2026, caractérisée par phishing adversary-in-the-middle (AitM) et vishing ciblant les services financiers, services professionnels, énergie et technologie. Le cluster est publiquement désigné sous le nom « Falcon ».

### Analyse de l'impact

L'attaque combine AitM (pour capturer credentials + MFA en temps réel) et vishing (pour manipuler les employés et bypass les procédures). Cible le secteur financier et l'énergie : impact financier direct et potentiel OT. Cluster à suivre pour les SOC/CERT de ces secteurs.

### Recommandations

* Déployer MFA phishing-resistant (FIDO2/WebAuthn) qui résiste à AitM.
* Renforcer les procédures de vérification téléphone (callback).
* Surveiller les sessions AitM (proxy TLS, anomalies de géolocalisation et user-agent).

### Playbook de réponse à incident

#### Phase 1 - Préparation
* MFA FIDO2 sur comptes à privilèges.
* Formation anti-vishing fonctions support.

#### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle IDP : sessions avec user-agent / IP / géoloc anormales (AitM proxy).
  * Détection : callback vishing + élévation de privilège dans la foulée.

#### Phase 3 - Confinement, éradication et récupération
* Révoquer les sessions AitM.
* Pivoter les credentials compromis.

#### Phase 4 - Activités post-incident
* Notifications FS-ISAC / CERT national.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Sessions AitM actives. | T1557.001 - Adversary-in-the-Middle | IDP / WAF | Sessions avec user-agent inattendu et IP proxy connues. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (IOCs disponibles dans le rapport GuidePoint complet : AS, domaines, URLs) | N/A | Se référer au rapport GuidePoint complet. | Moyenne |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1557.001 | Credential Access | Adversary-in-the-Middle | Phishing AitM. |
| T1566.004 | Initial Access | Spearphishing Voice | Vishing sur fonctions support. |

### Sources
* [GuidePoint Security - Bird Watching Falcon extortion](https://www.guidepointsecurity.com/blog/characterizing-infrastructure-and-behavior-of-falcon-branded-extortion-operations/)

---

<a id="exfilsquad-ceva-wesco"></a>
### ExfilSquad - Extorsion CEVA Logistics + Wesco (2,6 M records)

### Résumé technique

ExfilSquad, groupe d'extorsion par données, partage ses données via torrents selon SecurityAffairs. Deux victimes confirmées le 11 août :

* **CEVA Logistics** (géant logistique, 8 entrepôts européens) : cyberattaque confirmée, retards de livraison, expositions de données clients personnels. Effet domino sur les clients de CEVA : banques, retailers, et clients Steam (Valve a prévenu les clients européens de Steam hardware). Noms, adresses, téléphones, emails, détails de commande exposés.
* **Wesco** (distributeur B2B, cloud CRM) : ExfilSquad revendique le vol et la fuite de 2,6 millions de records.

### Analyse de l'impact

CEVA Logistics illustre l'effet domino d'une breach supply chain logistique : l'attaquant compromet un tiers et atteint les données de centaines de clients finaux (banques, retailers, gamers Steam). Wesco confirme la même stratégie (cloud CRM, 2,6 M records). Le modèle « extortion via torrents » de ExfilSquad (sans chiffrement, pure publication) rend les données rapidement disponibles publiquement.

### Recommandations

* Cartographier les tiers logistiques et leur accès aux données clients.
* Vérifier les clauses de notification de breach dans les contrats supply chain.
* Surveiller la réutilisation des données ExfilSquad (credential stuffing, phishing ciblé).

### Playbook de réponse à incident

#### Phase 1 - Préparation
* Inventaire des tiers logistiques / supply chain et de leur exposition.
* Plan de communication breach multi-clients.

#### Phase 2 - Détection et analyse
* Détection : corrélation entre incident tiers et données clients internes.
* Identifier les enregistrements exposés via les listes ExfilSquad.

#### Phase 3 - Confinement, éradication et récupération
* Révoquer les accès du tiers compromise temporairement.
* Notifier les clients dont les données sont exposées.

#### Phase 4 - Activités post-incident
* Notifications RGPD (72h CNIL) pour chaque entité dont les données clients sont impactées.
* Notifications NIS2 si entité essentielle.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Les données ExfilSquad sont réutilisées en credential stuffing. | T1110.004 - Credential Stuffing | WAF / IDP | Pics d'échecs d'authentification avec credentials de la breach. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC technique publié) | N/A | Données exfiltrées (PII), pas d'IOC réseau/fichier. | N/A |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1530 | Collection | Data from Cloud Storage | Exfiltration cloud CRM / supply chain. |
| T1567 | Exfiltration | Exfiltration Over Web Service | Publication via torrents. |

### Sources
* [securityaffairs - ExfilSquad torrents](https://securityaffairs.com/197025/security/exfilsquad-targets-new-victims-shares-data-via-torrents.html)
* [DevaOnBreaches - CEVA Logistics](https://infosec.exchange/@DevaOnBreaches/117080368393294744)
* [DevaOnBreaches - Wesco](https://infosec.exchange/@DevaOnBreaches/117080365225417924)
* [DevaOnBreaches - Valve Steam](https://infosec.exchange/@DevaOnBreaches/117080362008865002)
* [killbait - CEVA](https://mastodon.social/@killbait/117078950350935953)
* [thenewoil - CEVA](https://mastodon.thenewoil.org/@thenewoil/117078176696857846)

---

<a id="dentaquest-15m"></a>
### DentaQuest - 15 millions d'individus, plus grosse breach santé 2026 (ShinyHunters)

### Résumé technique

DentaQuest disclosed une breach massive impactant 15 millions de personnes, qualifiée de plus grosse breach santé de 2026. Le groupe d'extorsion ShinyHunters a publié une base de données de 234 Go contenant PII, PHI et SSN des patients.

### Analyse de l'impact

Le secteur santé reste la cible numéro 1 des extorsions par données. 15 millions d'individus impactent un nombre significatif de patients US, avec risque d'usurpation d'identité, de fraude médicale, et de phishing ciblé. Impact réglementaire HIPAA majeur.

### Recommandations

* Surveiller la réutilisation des données patients (credential stuffing, fraude).
* Notifier les patients impactés selon HIPAA.
* Renforcer l'accès aux bases de données patients (MFA, moindre privilège).

### Playbook de réponse à incident

#### Phase 1 - Préparation
* Inventaire des bases de données PHI.
* Sauvegardes immuables + journalisation d'accès.

#### Phase 2 - Détection et analyse
* Détection : accès bulk aux données patients, exports massifs.

#### Phase 3 - Confinement, éradication et récupération
* Révoquer credentials / tokens compromise.
* Couper l'accès externe aux entrepôts.

#### Phase 4 - Activités post-incident
* Notifications HIPAA (HHS), RGPD si patients EU.
* Communication aux 15 M patients.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Accès bulk aux données patients. | T1530 - Data from Cloud Storage | Logs base de données | Requêtes `SELECT *` massives hors heures ouvrées. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC publié) | N/A | Breach notification, pas de rapport technique. | N/A |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1530 | Collection | Data from Cloud Storage | Exfiltration base patients 234 Go. |

### Sources
* [netsecio - DentaQuest 15M](https://mastodon.social/@netsecio/117079487308517819)

---

<a id="vague-breaches-jp-us"></a>
### Vague de breaches - Japon, US, Canada (Lennar, Oculus, Gig Works, tl;dv, JST, Digital Agency, Yonex, Beaver County, Manitoba HSC)

### Résumé technique

Plusieurs breaches disclosed le 11 août 2026, sans lien d'acteur établi :

* **Lennar Corp** (US homebuilder) : breach par « ingénierie sociale sophistiquée », accès en mars 2026, vol SSN et données financières.
* **Oculus Pathology** (US) : breach via compromission de comptes email employés en avril 2026, PHI, PII, SSN, diagnostics médicaux exposés.
* **Gig Works** (Japon) : 3e notification d'accès serveur non autorisé, base de données de déclaration de dépendance potentiellement leakée.
* **Nice Corp** (Japon) : accès non autorisé à l'adresse email de gestion, ~2 400 PII potentiellement leakées.
* **tl;dv** (outil AI de transcription de réunions) : mauvaise configuration Firestore, 180 000+ réunions exposées, participation non autorisée aux appels en cours, contradiction entre chercheurs et entreprise.
* **Digital Agency Japon** : fichier d'historique de login créé par erreur, 150 personnels leakés.
* **JST** (Japan Science and Technology Agency) : accès non autorisé, 12 emails de staff, 16 000 records potentiellement leakés.
* **Yonex Taiwan** : accès non autorisé à la filiale taïwanaise, serveurs isolés, fuite potentielle.
* **Beaver County, Pennsylvania** : ransomware, 175 000 $ de rançon payée, accès aux dossiers patients coupé.
* **Health Sciences Centre Manitoba** : ransomware, l'union des infirmières questionne la sécurité.
* **Spacebears** (nouveau groupe ransomware) : publie Basso Fedele & Figli (Olio Basso) et Villa Raiano.

### Analyse de l'impact

La pression opérationnelle est continue, en particulier sur le secteur santé (Oculus, Beaver County, Manitoba) et les organisations japonaises (4 entités JP distinctes). Le pattern « erreur de configuration SaaS » (tl;dv Firestore) confirme que la surface d'attaque tierce reste sous-contrôlée. Spacebears est un nouveau groupe à suivre.

### Recommandations

* Durcir l'authentification email employé (MFA phishing-resistant) pour réduire le vecteur « email hack » (Oculus).
* Auditer les configurations Firestore / SaaS (tl;dv) sur les bases contenant des PII.
* Renforcer les procédures anti-ingénierie sociale (Lennar).
* Préparer un plan de réponse ransomware pour le secteur santé (Beaver, Manitoba).

### Playbook de réponse à incident

#### Phase 1 - Préparation
* MFA sur tous les comptes email.
* Audit des configurations SaaS (Firestore, AWS S3, GitHub).
* Plan de continuité d'activité pour établissements de santé.

#### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle IDP : connexions email depuis IP suspectes.
  * Règle cloud : bucket Firestore / S3 exposé publiquement.
  * Détection : accès bulk aux données patients.

#### Phase 3 - Confinement, éradication et récupération
* Révoquer les comptes email compromise.
* Restreindre l'accès public aux buckets SaaS.
* Pour ransomware : restaurer depuis backups hors-ligne.

#### Phase 4 - Activités post-incident
* Notifications HIPAA (US), loi JP, RGPD si EU.
* Communication aux patients / individus impactés.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres buckets SaaS sont exposés publiquement. | T1530 - Data from Cloud Storage | CSPM / audit cloud | Buckets Firestore / S3 avec `public` ACL. |
| Comptes email compromise non détectés. | T1078 - Valid Accounts | IDP | Connexions email depuis pays / IP anormaux. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC publié, notifications de breach) | N/A | Pas de rapport technique. | N/A |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566.004 | Initial Access | Spearphishing Voice | Lennar social engineering. |
| T1078 | Initial Access | Valid Accounts | Oculus email hack. |
| T1530 | Collection | Data from Cloud Storage | tl;dv Firestore misconfiguration. |
| T1486 | Impact | Data Encrypted for Impact | Beaver County, Manitoba ransomware. |

### Sources
* [netsecio - Lennar](https://mastodon.social/@netsecio/117079487674283367)
* [netsecio - Oculus Pathology](https://mastodon.social/@netsecio/117079487943286626)
* [securityLab_jp - Gig Works](https://mastodon.social/@securityLab_jp/117080139120543623)
* [securityLab_jp - Nice Corp](https://mastodon.social/@securityLab_jp/117079848476499119)
* [securityLab_jp - tl;dv](https://mastodon.social/@securityLab_jp/117079506701951419)
* [securityLab_jp - Digital Agency](https://mastodon.social/@securityLab_jp/117079378997478979)
* [securityLab_jp - JST](https://mastodon.social/@securityLab_jp/117079345587093784)
* [securityLab_jp - Yonex Taiwan](https://mastodon.social/@securityLab_jp/117079341043077294)
* [DysruptionHub - Beaver County](https://infosec.exchange/@DysruptionHub/117078053805140272)
* [glwinnipeg - Manitoba HSC](https://mastodon.hongkongers.net/@glwinnipeg_mirror/11707851)
* [CTI_FYI - Spacebears](https://infosec.exchange/@CTI_FYI/117080373475266425)

---

<a id="lexisnexis-tierce"></a>
### LexisNexis - Activité suspicieuse sur serveurs tierce partie, services offline

### Résumé technique

LexisNexis a disclosed le 10 août 2026 une activité inhabituelle sur des serveurs hébergés et gérés par un tiers. Leçons : isolation des systèmes affectés, services clients offline (Nexis Diligence, Newsdesk, Metabase API), investigation en cours avec experts externes, infrastructure reconstruite avant restauration.

### Analyse de l'impact

LexisNexis est un agrégateur de données massif (due diligence, intelligence, enquêtes). Une breach affecte potentiellement des données sensibles B2B et de due diligence. Le pattern « tierce partie qui héberge » rappelle que la supply chain d'infrastructure reste un vecteur majeur (cf. Snowflake 2024).

### Recommandations

* Auditer les contrats d'hébergement tierce (clause de sécurité, notification, audit).
* Vérifier l'isolation des systèmes chez les hébergeurs.
* Surveiller l'accès aux API sensibles (Metabase API ici, à corréler avec les vulnérabilités Metabase signalées par Bobe_bot).

### Playbook de réponse à incident

#### Phase 1 - Préparation
* Inventaire des hébergeurs tierces et périmètres de données.
* Contrats avec clause de notification < 24h.

#### Phase 2 - Détection et analyse
* Détection : activité inhabituelle sur serveurs hébergés.
* Chronologie : identifier le vecteur d'entrée chez le tiers.

#### Phase 3 - Confinement, éradication et récupération
* Isoler les systèmes affectés.
* Reconstruire l'infrastructure avant restauration.

#### Phase 4 - Activités post-incident
* Notifications RGPD/NIS2 selon données impactées.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres serveurs hébergés par le même tiers sont compromise. | T1190 - Exploit Public-Facing Application | Logs hébergeur | Activité inhabituelle sur serveurs du même tiers. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC publié) | N/A | Notification initiale. | N/A |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1190 | Initial Access | Exploit Public-Facing Application | (probable, à confirmer). |

### Sources
* [Field Effect - LexisNexis](https://fieldeffect.com/blog/lexisnexis-suspicious-activity-services-offline)
