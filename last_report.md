# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités](#synthese-des-vulnerabilites)
  * [Articles sélectionnés](#articles-selectionnes)
  * [Articles non sélectionnés](#articles-non-selectionnes)
* [Articles](#articles)
  * [lumma stealer et sectop rat analyse dune infection par logiciel cracke](#lumma-stealer-et-sectop-rat-analyse-dune-infection-par-logiciel-cracke)
  * [zionsiphon le nouveau malware de sabotage ciblant les infrastructures hydrauliques](#zionsiphon-le-nouveau-malware-de-sabotage-ciblant-les-infrastructures-hydrauliques)
  * [redsun une nouvelle zero-day dans microsoft defender permet une elevation de privileges](#redsun-une-nouvelle-zero-day-dans-microsoft-defender-permet-une-elevation-de-privileges)
  * [exploitation de la faille marimo pour deployer le malware nkabuse via hugging face](#exploitation-de-la-faille-marimo-pour-deployer-le-malware-nkabuse-via-hugging-face)
  * [cyber-vol de fret les hackers ciblent lindustrie de la logistique avec des outils de signature as a service](#cyber-vol-de-fret-les-hackers-ciblent-lindustrie-de-la-logistique-avec-des-outils-de-signature-as-a-service)
  * [uac-0247 une campagne despoinnage persistante contre les infrastructures critiques ukrainiennes](#uac-0247-une-campagne-despoinnage-persistante-contre-les-infrastructures-critiques-ukrainiennes)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage cyber actuel est marqué par une transition brutale vers des offensives à "vitesse machine", portées par l'intégration massive de l'intelligence artificielle générative dans les arsenaux criminels. L'émergence de plateformes comme ATHR pour le vishing automatisé et l'utilisation de LLM pour la découverte de vulnérabilités (RedSun, projet Mythos) saturent les capacités de défense humaines traditionnelles. Parallèlement, le conflit hybride sino-israélo-iranien s'intensifie avec des capacités de sabotage ciblant les infrastructures vitales, notamment l'eau et l'énergie, comme l'illustre la menace ZionSiphon. Les acteurs étatiques, particulièrement nord-coréens et russes, affinent leurs techniques d'intrusion sur macOS et Linux tout en exploitant des vecteurs de confiance tels que Hugging Face ou n8n. La chaîne d'approvisionnement logicielle demeure une vulnérabilité critique, les attaquants utilisant désormais des services de "signature-as-a-service" pour légitimer leurs malwares. Les décideurs doivent impérativement pivoter vers des centres d'opérations de sécurité (SOC) "agentiques" et automatisés pour contrer cette montée en puissance technologique. La résilience passera par une collaboration radicale et le durcissement des systèmes industriels (OT) face à des cyber-attaques de plus en plus cinétiques.

<br>
<br>
<div id="syntheses"></div>
<br/>

# Synthèses
<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants
Voici un tableau récapitulatif des acteurs malveillants identifiés :
| Nom de l'acteur | Secteur d'activité ciblé | Mode opératoire privilégié | Source(s)/Url(s) |
|:---|:---|:---|:---|
| APT37 (ScarCruft) | Recherche militaire | Pretexting sur réseaux sociaux et logiciels trojanisés | [Sploited.blog](https://sploited.blog/2026/04/16/weekly-threat-landscape-thursday-roundup-4/) |
| APT41 | Cloud (AWS, Azure, GCP) | Backdoor ELF indétectable via protocole SMTP | [The Hacker News](https://thehackernews.com/2026/04/threatsday-bulletin-17-year-old-excel.html) |
| Handala Hack | Gouvernement (EAU), Santé (US), Industrie (ISR) | Wiper, exfiltration de données, abus de Microsoft Intune | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Rhysida | Santé (Hôpitaux) | Ransomware et exfiltration massive de données | [Security Affairs](https://securityaffairs.com/190898/cyber-crime/cookeville-regional-medical-center-hospital-data-breach-impacts-337917-people.html) |
| Sapphire Sleet | Tech, Crypto, macOS | Ingénierie sociale, empoisonnement de packages npm (Axios) | [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/) |
| UAC-0247 | Gouvernement et Santé (Ukraine) | Phishing humanitaire, malwares AgingFly et SilentLoop | [Security Affairs](https://securityaffairs.com/190875/apt/from-clinics-to-government-uac-0247-expands-cyber-campaign-across-ukraine.html) |
| Water Hydra | Finance, Trading | Phishing ciblé et exploitation de vulnérabilités | [The Hacker News](https://thehackernews.com/2026/04/threatsday-bulletin-17-year-old-excel.html) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Énergie | Sabotage | La Suède attribue une tentative d'attaque contre une centrale thermique à un groupe pro-russe lié au renseignement. | [Security Affairs](https://securityaffairs.com/190869/intelligence/sweden-reports-cyberattack-attempt-on-heating-plant-amid-rising-energy-threats.html) |
| Gouvernement | Espionnage | Campagne UAC-0247 contre les institutions municipales et de santé ukrainiennes via des thèmes humanitaires. | [SOC Prime](https://socprime.com/blog/uac-0247-attack-detection-agingfly-malware-targets-hospitals-local-governments-and-fpv-operators-in-ukraine/) |
| Infrastructures critiques | Conflit militaire | Cyber-attaques croisées entre les USA, Israël et l'Iran incluant le sabotage de systèmes d'eau et l'usage de satellites. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Militaire | Guerre de l'eau | Analyse des tensions hydriques comme multiplicateur de risques entre l'Égypte, l'Éthiopie et Israël. | [Portail de l'IE](https://www.portail-ie.fr/univers/2026/le-nil-et-le-levant-deux-modeles-face-a-la-contrainte-hydrique/) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date | Juridiction | Référence | Description | Source |
|:---|:---|:---|:---|:---|:---|:---|
| E.U. Plans Bloc-Wide Age Verification App | Ravie Lakshmanan | 16/04/2026 | Union Européenne | Protection des mineurs | Application open-source d'authentification de l'âge respectant la vie privée pour les plateformes. | [The Hacker News](https://thehackernews.com/2026/04/threatsday-bulletin-17-year-old-excel.html) |
| Raspberry Pi Disables Passwordless sudo | Raspberry Pi | 16/04/2026 | Monde (OS) | Raspberry Pi OS 6.2 | Désactivation du sudo sans mot de passe par défaut pour renforcer la sécurité post-installation. | [The Hacker News](https://thehackernews.com/2026/04/threatsday-bulletin-17-year-old-excel.html) |
| Defendant Sentenced To Prison For Hacking Betting Website | Jay Clayton | 16/04/2026 | USA | Southern District of NY | Condamnation de Kamerin Stokes à 30 mois de prison pour credential stuffing sur un site de paris. | [DataBreaches.net](https://databreaches.net/2026/04/16/defendant-sentenced-to-prison-for-hacking-betting-website/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Éducation | McGraw Hill | 13,5 millions de comptes exposés suite à une mauvaise configuration de Salesforce. | [HIBP](https://haveibeenpwned.com/Breach/McGrawHill) |
| Gouvernement | Agences Mexicaines | Neuf agences compromises via l'usage combiné de Claude Code et ChatGPT pour l'exfiltration de registres de citoyens. | [DataBreaches.net](https://databreaches.net/2026/04/16/double-trouble-hackers-used-both-claude-code-and-chatgpt-in-a-cybersecurity-hack-that-lasted-two-and-a-half-months/) |
| Santé | Cookeville Regional Medical Center | 337 917 personnes affectées par un ransomware Rhysida ; 500 Go de données volées. | [Security Affairs](https://securityaffairs.com/190898/cyber-crime/cookeville-regional-medical-center-hospital-data-breach-impacts-337917-people.html) |
| Tourisme | Booking.com | Accès non autorisé à des détails de réservations et informations personnelles des clients. | [NetSecIO](https://mastodon.social/@netsecio/116416313793802783) |
| Transport | Amtrak | Revendication par ShinyHunters du vol de 9,4 millions d'enregistrements via Salesforce. | [NetSecIO](https://mastodon.social/@netsecio/116416313473735499) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).
| CVE-ID | CVSS | EPSS | CISA Kev | Produit affecté | Type | MITRE ATT&CK | Description | Source |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2026-20147 | 9.9 | N/A | FALSE | Cisco ISE | Injection | T1190 | Validation d'entrée défaillante permettant une exécution de code à distance (RCE). | [Security Affairs](https://securityaffairs.com/190909/security/cisco-fixed-four-critical-flaws-in-identity-services-and-webex.html) |
| CVE-2026-39808 | 9.8 | N/A | FALSE | Fortinet FortiSandbox | RCE | T1203 | Injection de commandes OS via l'API permettant un compromis total du bac à sable. | [HelpNetSecurity](https://www.helpnetsecurity.com/2026/04/16/fortinet-fortisandbox-vulnerabilities-cve-2026-39813-cve-2026-39808/) |
| CVE-2026-20184 | 9.8 | N/A | FALSE | Cisco Webex SSO | Auth Bypass | T1550 | Mauvaise validation de certificat permettant l'usurpation de n'importe quel utilisateur. | [Security Affairs](https://securityaffairs.com/190909/security/cisco-fixed-four-critical-flaws-in-identity-services-and-webex.html) |
| CVE-2026-39987 | 9.8 | N/A | TRUE | Marimo Python Notebook | RCE | T1190 | Faille exploitée activement pour déployer des malwares via Hugging Face. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-marimo-flaw-to-deploy-nkabuse-malware-from-hugging-face/) |
| CVE-2026-5189 | 9.2 | N/A | FALSE | Nexus Repository 3 | Hardcoded Creds | T1552 | Identifiants codés en dur dans le composant OrientDB permettant le contrôle du système. | [SecurityOnline](https://securityonline.info/nexus-repository-hardcoded-credential-vulnerability-cve-2026-5189/) |
| CVE-2026-34457 | 9.1 | N/A | FALSE | OAuth2 Proxy | Auth Bypass | T1550 | Loophole dans les health checks permettant de contourner l'authentification via User-Agent. | [SecurityOnline](https://securityonline.info/oauth2-proxy-authentication-bypass-cve-2026-34457/) |
| CVE-2026-40322 | 9.0 | N/A | FALSE | SiYuan | XSS to RCE | T1189 | Injection de lien Mermaid JS menant à une exécution de code arbitraire sur Electron. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-40322) |
| CVE-2009-0238 | 8.8 | High | TRUE | Microsoft Excel | RCE | T1203 | Faille de 17 ans réactivée pour exécution de code via fichiers Excel malformés. | [The Hacker News](https://thehackernews.com/2026/04/threatsday-bulletin-17-year-old-excel.html) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Lumma Stealer infection with Sectop RAT | Analyse technique détaillée d'une chaîne d'infection multi-malwares courante. | [ISC SANS](https://isc.sans.edu/diary/rss/32904) |
| ZionSiphon malware designed to sabotage water systems | Menace critique ciblant l'OT et les infrastructures vitales. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/zionsiphon-malware-designed-to-sabotage-water-treatment-systems/) |
| New Microsoft Defender “RedSun” zero-day | Découverte d'une zero-day majeure affectant la défense native Windows. | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/new-microsoft-defender-redsun-zero-day-poc-grants-system-privileges/) |
| Hackers exploit Marimo flaw via Hugging Face | Nouvelle tendance d'abus de plateformes d'IA et de frameworks Python. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-marimo-flaw-to-deploy-nkabuse-malware-from-hugging-face/) |
| Cargo thieving hackers running sophisticated campaigns | Focus sur une menace sectorielle (logistique) utilisant des techniques avancées. | [Proofpoint](https://www.proofpoint.com/us/newsroom/news/cargo-thieving-hackers-running-sophisticated-remote-access-campaigns-researchers-find) |
| From clinics to government: UAC-0247 expands campaign | Documentation d'une menace étatique persistante en zone de conflit. | [Security Affairs](https://securityaffairs.com/190875/apt/from-clinics-to-government-uac-0247-expands-cyber-campaign-across-ukraine.html) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| Brian Cute on the Techsequences Podcast | Contenu audio, résumé stratégique peu opérationnel. | [GCA](https://globalcyberalliance.org/brian-cute-on-the-techsequences-podcast/) |
| Most "AI SOCs" Are Just Faster Triage | Contenu sponsorisé/promotionnel (Tines). | [BleepingComputer](https://www.bleepingcomputer.com/news/security/most-ai-socs-are-just-faster-triage-thats-not-enough/) |
| McGraw Hill data breach | Violation de données pure sans nouvelle analyse technique de menace. | [HIBP](https://haveibeenpwned.com/Breach/McGrawHill) |
| More than pretty pictures: Wendy Bishop | Article de type "Portrait" sans lien direct avec la menace. | [Cisco Talos](https://blog.talosintelligence.com/more-than-pretty-pictures-wendy-bishop-on-visual-storytelling-in-tech/) |

<br>
<br/>
<div id="articles"></div>

# ARTICLES

<div id="lumma-stealer-et-sectop-rat-analyse-dune-infection-par-logiciel-cracke"></div>

## Lumma Stealer et Sectop RAT : analyse d'une infection par logiciel cracké
Cette analyse documente une infection par Lumma Stealer suivie du déploiement de Sectop RAT (ArechClient2). Le vecteur initial est le téléchargement de versions crackées de logiciels (Adobe Premiere Pro), une technique de distribution très courante. Le malware est livré dans une archive 7-zip protégée par mot de passe contenant un exécutable Windows "gonflé" à 806 Mo pour échapper aux analyses antivirus automatiques. Une fois extrait, Lumma Stealer établit une communication avec plusieurs domaines de commande et contrôle (C2) en .cyou, .vu, .club, etc. Par la suite, une DLL de 64 bits est récupérée pour installer Sectop RAT, assurant une persistance sur l'hôte. Le trafic C2 de Sectop RAT est encodé mais n'utilise pas le protocole HTTPS/TLS standard, facilitant sa détection réseau.

**Analyse de l'impact** : Risque élevé de vol d'identifiants, d'exfiltration de données sensibles et de prise de contrôle à distance totale de la machine infectée. L'usage de fichiers "gonflés" (null-byte padding) neutralise de nombreux outils d'analyse statique.

**Recommandations** :
* Bloquer les domaines C2 identifiés (genugsq.best, cankgmr.cyou, etc.).
* Surveiller les processus exécutant rundll32 avec des arguments inhabituels (ex: LoadForm).
* Implémenter une politique stricte d'interdiction de logiciels non officiels et crackés.
* Configurer l'EDR pour détecter les fichiers de taille inhabituelle (exécutables > 500 Mo).

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié (Cybercriminalité opportuniste) |
| Tactiques, Techniques et Procédures (TTP) | * T1204.002: User Execution (Malicious File)<br/>* T1027.001: Binary Padding<br/>* T1547.001: Registry Run Keys / Startup Folder |
| Observables & IoCs | ```* 4849f76dafbef516df91fecfc23a72afffaf77ade51f805eae5ad552bed88923 (Lumma EXE)<br/>* d9b576eb6827f38e33eda037d2cda4261307511303254a8509eeb28048433b2f (Sectop DLL)<br/>* cankgmr[.]cyou<br/>* 91.92.241[.]102:9000``` |

### Source (url) du ou des articles
* https://isc.sans.edu/diary/rss/32904

<br>
<br>

<div id="zionsiphon-le-nouveau-malware-de-sabotage-ciblant-les-infrastructures-hydrauliques"></div>

## ZionSiphon : le nouveau malware de sabotage ciblant les infrastructures hydrauliques
ZionSiphon est un malware spécialisé dans les technologies opérationnelles (OT), conçu pour saboter les usines de traitement d'eau et de dessalement. Il a la capacité d'ajuster les pressions hydrauliques et d'augmenter les niveaux de chlore à des seuils dangereux via une fonction spécifique "IncreaseChlorineLevel()". Le malware cible prioritairement des infrastructures basées en Israël, vérifiant les plages d'adresses IP locales et la présence de logiciels SCADA/ICS. Bien qu'une erreur de logique de chiffrement XOR empêche actuellement l'activation de sa charge utile, sa conception montre une intention claire de destruction physique. Le malware tente d'interagir avec les automates via les protocoles Modbus, DNP3 et S7comm. Il dispose également d'un mécanisme de propagation par USB via un processus caché 'svchost.exe'.

**Analyse de l'impact** : Risque de dommages physiques majeurs aux infrastructures, empoisonnement potentiel de l'approvisionnement en eau et destruction de matériel industriel. C'est une menace "cinétique" de premier plan.

**Recommandations** :
* Segmenter strictement les réseaux IT et OT.
* Désactiver l'exécution automatique et l'usage des ports USB sur les systèmes critiques.
* Surveiller les modifications anormales des fichiers de configuration ICS/SCADA mentionnés (Chlorine_Dose, RO_Pressure).
* Auditer les communications Modbus/S7comm vers des hôtes non autorisés.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable (Origine probable : Iran) |
| Tactiques, Techniques et Procédures (TTP) | * T0801: Monitor Process State<br/>* T0831: Data Destruction<br/>* T0847: Replication Through Removable Media |
| Observables & IoCs | ```* svchost.exe (USB version)<br/>* Protocoles: Modbus, DNP3, S7comm<br/>* Chaines: Chlorine_Flow=MAX, RO_Pressure=80``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/zionsiphon-malware-designed-to-sabotage-water-treatment-systems/

<br>
<br>

<div id="redsun-une-nouvelle-zero-day-dans-microsoft-defender-permet-une-elevation-de-privileges"></div>

## RedSun : une nouvelle zero-day dans Microsoft Defender permet une élévation de privilèges
Un chercheur nommé "Chaotic Eclipse" a publié un exploit PoC pour une seconde faille zero-day dans Microsoft Defender, nommée "RedSun". Cette vulnérabilité d'élévation de privilèges locaux (LPE) permet d'obtenir les privilèges SYSTEM sur Windows 10, 11 et Windows Server. L'exploit abuse de l'API "Cloud Files" et de la manière dont Defender gère les fichiers avec des tags cloud : il force l'antivirus à réécrire un fichier malveillant (EICAR) à son emplacement d'origine, détourné via un point de jonction/reparse. Ce processus permet d'écraser des binaires système comme TieringEngineService.exe par l'exécutable de l'attaquant. Cette publication est un acte de protestation contre les méthodes de communication de Microsoft avec les chercheurs en sécurité.

**Analyse de l'impact** : Impact critique car elle permet à un attaquant ayant un accès utilisateur simple de prendre le contrôle total du système de manière indétectable par la défense native Windows.

**Recommandations** :
* Surveiller la création inhabituelle de points de jonction de répertoires vers C:\Windows\system32.
* Détecter l'exécution suspecte de TieringEngineService.exe s'il n'est pas signé par Microsoft.
* Limiter les privilèges d'accès aux APIs de fichiers Cloud pour les utilisateurs non administrateurs.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Chercheur "Chaotic Eclipse" (Hacktivisme technique) |
| Tactiques, Techniques et Procédures (TTP) | * T1068: Exploitation for Privilege Escalation<br/>* T1543.003: Windows Service<br/>* T1497: Virtualization/Sandbox Evasion |
| Observables & IoCs | ```* RedSun.exe<br/>* TieringEngineService.exe (modifié)<br/>* Usage abusif de l'API Cloud Files``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/microsoft/new-microsoft-defender-redsun-zero-day-poc-grants-system-privileges/

<br>
<br>

<div id="exploitation-de-la-faille-marimo-pour-deployer-le-malware-nkabuse-via-hugging-face"></div>

## Exploitation de la faille Marimo pour déployer le malware NKAbuse via Hugging Face
Des attaquants exploitent la vulnérabilité critique CVE-2026-39987 (RCE) dans les notebooks Python Marimo pour diffuser une variante de NKAbuse. L'attaque utilise la plateforme Hugging Face Spaces comme hôte de confiance pour stocker un script dropper (install-linux.sh) et un binaire nommé 'kagent'. Le dropper installe le malware et établit une persistance via systemd ou cron. NKAbuse est un cheval de Troie d'accès à distance (RAT) et un botnet DDoS qui utilise le protocole décentralisé NKN (New Kind of Network) pour ses communications C2, ce qui le rend difficile à bloquer. Des pivots vers PostgreSQL et Redis ont été observés après le compromis initial pour l'exfiltration de jetons de session.

**Analyse de l'impact** : Compromis de serveurs de développement IA et machine learning, vol de données de bases de données et intégration dans un botnet DDoS mondial.

**Recommandations** :
* Mettre à jour Marimo vers la version 0.23.0 ou supérieure immédiatement.
* Bloquer ou restreindre l'accès externe à l'endpoint '/terminal/ws'.
* Surveiller l'usage inhabituel du protocole NKN sur le réseau.
* Auditer les variables d'environnement pour prévenir le vol de jetons d'accès.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié (Hacking opportuniste ciblant l'IA) |
| Tactiques, Techniques et Procédures (TTP) | * T1190: Exploit Public-Facing Application<br/>* T1105: Ingress Tool Transfer<br/>* T1584.005: Botnet |
| Observables & IoCs | ```* install-linux.sh<br/>* kagent (binaire)<br/>* Hugging Face Space: vsccode-modetx<br/>* Protocole C2: NKN (New Kind of Network)``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/hackers-exploit-marimo-flaw-to-deploy-nkabuse-malware-from-hugging-face/

<br>
<br>

<div id="cyber-vol-de-fret-les-hackers-ciblent-lindustrie-de-la-logistique-avec-des-outils-de-signature-as-a-service"></div>

## Cyber-vol de fret : les hackers ciblent l'industrie de la logistique avec des outils de signature "as-a-service"
L'industrie du transport routier subit une vague d'attaques sophistiquées visant le vol de fret, ayant causé 6,6 milliards de dollars de pertes en 2025. Les cybercriminels compromettent les plateformes de gestion de chargement pour injecter des payloads malveillants. Une innovation majeure a été détectée : l'usage d'un script de "signing-as-a-service" qui interroge un service externe pour signer numériquement les composants du malware (notamment ScreenConnect). Cela permet aux outils de passer outre les alertes de sécurité Windows. Une fois en place, les attaquants utilisent des scripts PowerShell pour scanner les comptes bancaires, les portefeuilles crypto et les informations d'identification PayPal.

**Analyse de l'impact** : Pertes financières massives directes (vols de marchandises) et indirectes (compromis de comptes bancaires). La capacité de signer des malwares à la volée réduit l'efficacité des solutions de protection traditionnelles.

**Recommandations** :
* Auditer l'installation et l'usage de ScreenConnect et autres outils RMM.
* Bloquer les scripts PowerShell non signés ou émanant de sources inconnues.
* Sensibiliser les employés de la logistique au phishing ciblant les plateformes de chargement.
* Surveiller les connexions vers les services de signature de certificats non approuvés.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Groupes cybercriminels organisés (Logistique) |
| Tactiques, Techniques et Procédures (TTP) | * T1553.002: Code Signing<br/>* T1219: Remote Access Software<br/>* T1059.001: PowerShell |
| Observables & IoCs | ```* Instances ScreenConnect non autorisées<br/>* Scripts de recherche de portefeuilles crypto<br/>* MSI installateurs auto-signés``` |

### Source (url) du ou des articles
* https://www.proofpoint.com/us/newsroom/news/cargo-thieving-hackers-running-sophisticated-remote-access-campaigns-researchers-find

<br>
<br>

<div id="uac-0247-une-campagne-despoinnage-persistante-contre-les-infrastructures-critiques-ukrainiennes"></div>

## UAC-0247 : une campagne d'espionnage persistante contre les infrastructures critiques ukrainiennes
Le CERT-UA a identifié l'acteur UAC-0247 ciblant les agences gouvernementales et les hôpitaux ukrainiens. L'attaque débute par un phishing via des offres d'aide humanitaire menant au téléchargement d'une archive contenant un fichier LNK malveillant. Celui-ci utilise mshta.exe pour exécuter une charge utile qui injecte du shellcode dans 'RuntimeBroker.exe'. Le malware principal, AgingFly (développé en C#), permet de contrôler à distance la machine, d'exfiltrer les mots de passe des navigateurs Chromium (via ChromeElevator) et les données WhatsApp (via ZapixDesk). Le groupe utilise également des tunnels Ligolo-ng et Chisel pour le mouvement latéral, ainsi que Signal pour cibler les opérateurs de drones FPV.

**Analyse de l'impact** : Risque d'espionnage d'État, perturbation des services de santé d'urgence et collecte de données tactiques militaires (drones).

**Recommandations** :
* Restreindre le lancement des fichiers LNK, HTA et JS.
* Surveiller ou bloquer les utilitaires mshta.exe, powershell.exe et wscript.exe s'ils ne sont pas nécessaires.
* Rechercher les tunnels réseau non autorisés (Ligolo, Chisel).
* Mettre en place des alertes sur l'injection de code dans RuntimeBroker.exe.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UAC-0247 |
| Tactiques, Techniques et Procédures (TTP) | * T1566.002: Spearphishing Link<br/>* T1055: Process Injection<br/>* T1572: Protocol Tunneling |
| Observables & IoCs | ```* AgingFly (RAT)<br/>* ChromeElevator<br/>* ZapixDesk<br/>* Key XOR: 01 01 02 03 74 15 04 FF EE``` |

### Source (url) du ou des articles
* https://socprime.com/blog/uac-0247-attack-detection-agingfly-malware-targets-hospitals-local-governments-and-fpv-operators-in-ukraine/
* https://securityaffairs.com/190875/apt/from-clinics-to-government-uac-0247-expands-cyber-campaign-across-ukraine.html