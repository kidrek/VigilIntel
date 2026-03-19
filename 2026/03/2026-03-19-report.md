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
  * [darksword : un kit d'exploitation ios sophistiqué utilisé par plusieurs acteurs](#darksword-un-kit-dexploitation-ios-sophistiqué-utilisé-par-plusieurs-acteurs)
  * [interlock ransomware : exploitation de vulnérabilités zero-day cisco secure fmc](#interlock-ransomware-exploitation-de-vulnérabilités-zero-day-cisco-secure-fmc)
  * [silentconnect et windsurf : le ciblage des outils de développement s'intensifie](#silentconnect-et-windsurf-le-ciblage-des-outils-de-développement-sintensifie)
  * [cyber-conflit iran-israël-usa : une escalade numérique majeure](#cyber-conflit-iran-israël-usa-une-escalade-numérique-majeure)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage actuel de la menace cyber est marqué par une intensification sans précédent des opérations d'espionnage d'État et de sabotage industriel, portées par les tensions géopolitiques au Moyen-Orient et en Europe de l'Est. L'émergence du kit d'exploitation "DarkSword" illustre la démocratisation de capacités offensives de niveau étatique, désormais partagées entre plusieurs groupes malveillants pour cibler massivement les écosystèmes mobiles iOS. Parallèlement, l'exploitation par le groupe Interlock d'une vulnérabilité zero-day sur les pare-feux Cisco souligne une tendance critique : les acteurs de ransomware n'attendent plus les correctifs pour frapper les infrastructures critiques, notamment le secteur de la santé. On observe également un déplacement de la menace vers les environnements de développement, avec l'utilisation ingénieuse de la blockchain Solana pour distribuer des charges utiles et des extensions IDE compromises. L'intelligence artificielle devient un vecteur double, facilitant à la fois le codage de malwares complexes et constituant une nouvelle surface d'attaque via les agents IA autonomes. Enfin, la professionnalisation de la fraude au remboursement démontre que la cybercriminalité de bas niveau s'industrialise en adoptant des modèles de service (SaaS) robustes. Pour les décideurs, la priorité absolue doit être la résilience des chaînes d'approvisionnement logicielles et le durcissement des accès à distance. La veille stratégique confirme que la défense périmétrique traditionnelle est insuffisante face à des acteurs capables de pré-positionner des accès des mois avant toute escalade cinétique.
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
| APT33 (IRGC) | Énergie, Défense (USA) | Password spraying, ciblage des systèmes de sécurité | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| APT55 (IRGC) | Énergie, Défense (USA) | Cyber-espionnage, collecte de cibles | [Euronews/Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| CyberAv3ngers | Infrastructures critiques (Eau, Énergie) | Exploitation de mots de passe par défaut sur les ICS | [Euronews/Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Handala Hack | Médical (Stryker), ICS, Énergie | Abus de Microsoft Intune (MDM wipe), défaçage | [The Register/Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Interlock | Santé, Éducation, Gouvernement | Exploitation de zero-day Cisco, double extorsion | [BleepingComputer](https://www.bleepingcomputer.com/news/security/interlock-ransomware-exploited-secure-fmc-flaw-in-zero-day-attacks-since-january/) |
| Kimsuky | Divers | Malwares utilisant l'API Dropbox | [Reddit/IIJ](https://www.reddit.com/r/blueteamsec/comments/1rxe9cf/dropbox_api%E3%82%92%E4%BD%BF%E7%94%A8%E3%81%99%E3%82%8Bkimsuky%E3%81%AE%E3%83%9E%E3%83%AB%E3%82%A6%E3%82%A7%E3%82%A2_kimsuky_malware/) |
| MuddyWater (MOIS) | Finance, Aéroports, Défense (META region) | Opération Olalampo, courtier d'accès initiaux | [ESET/Halcyon/Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| ShinyHunters | Protection de l'identité (Aura) | Extorsion de données après vol par phishing | [BleepingComputer](https://www.bleepingcomputer.com/news/security/aura-confirms-data-breach-exposing-900-000-marketing-contacts/) |
| UNC6353 (Russe) | Gouvernemental (Ukraine) | Watering hole, kit DarkSword/Coruna | [Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain/) |
| UNC6748 | Snapchat users (Arabie Saoudite) | Phishing Snapchat, kit DarkSword | [Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain/) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Civil / Télécoms | Conflit Iran-Israël-USA | Blackout internet quasi-total en Iran (1% de connectivité) depuis 19 jours. | [NetBlocks](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Énergie | Stratégie Nucléaire | Le retour stratégique à l'énergie nucléaire comme réponse à l'instabilité géopolitique des hydrocarbures. | [RUSI](https://www.rusi.org/explore-our-research/publications/commentary/energy-security-lessons-oil-crises-and-nuclear-powers-strategic-return) |
| Étatique | Guerre hybride Baltique | Campagne informationnelle russe autour d'une fictive "République populaire de Narva" en Estonie. | [IRIS](https://www.iris-france.org/la-republique-populaire-de-narva-lestonie-dans-le-viseur-de-la-russie/) |
| Gouvernemental | Sanctions EU | L'UE sanctionne des acteurs chinois et iraniens pour des cyberattaques contre les infrastructures critiques. | [SecurityAffairs](https://securityaffairs.com/189628/security/u-s-cisa-adds-microsoft-sharepoint-and-zimbra-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| Nucléaire | Conflit Iran-Pologne | Enquête polonaise sur une tentative de hack du Centre national de recherche nucléaire liée à l'Iran. | [Axios/Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Sport | Droits de l'Homme | Publication d'une feuille de route européenne pour la protection des droits des athlètes. | [IRIS](https://www.iris-france.org/roadmap-for-the-protection-respect-and-promotion-of-the-human-rights-of-athletes-in-sport-in-europe-2/) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| UK Watchdog Tightens Cyber Incident Reporting | Yaminin Kahlia | 18/03/2026 | Royaume-Uni | FCA Reporting Rules | Nouvelles règles de signalement des incidents tiers et cyber sous 12 mois. | [DataBreaches.net](https://databreaches.net/2026/03/18/uk-watchdog-tightens-cyber-incident-reporting-rules-as-attacks-surge/) |
| Five lessons from three years of DSA risk assessments | ECNL / EDRi | 18/03/2026 | Union Européenne | Digital Services Act (DSA) | Analyse des lacunes de transparence dans les rapports d'audit des VLOPs (Facebook, X, etc.). | [EDRi](https://edri.org/our-work/five-lessons-from-three-years-of-risk-assessments-under-the-digital-services-act/) |
| Court rules in favour of Bits of Freedom | Bits of Freedom | 18/03/2026 | Pays-Bas | DSA / GDPR | Meta condamné à offrir un flux non profilé (chronologique) à ses utilisateurs. | [EDRi](https://edri.org/our-work/court-again-rules-in-favour-of-bits-of-freedom-freedom-of-choice-for-instagram-and-facebook-users-remains-intact/) |
| Proofpoint Pursues FedRAMP High Authorization | Proofpoint | 18/03/2026 | USA | FedRAMP High | Processus d'autorisation pour les charges de travail fédérales à haut impact. | [Proofpoint](https://www.proofpoint.com/us/newsroom/press-releases/proofpoint-pursues-fedramp-high-authorization-process-collaboration-security) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Finance | Marquis | Ransomware en août 2025 via SonicWall. 672 000 personnes impactées, perturbations chez 74 banques. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/marquis-ransomware-gang-stole-data-of-672-000-people-in-2025-cyberattack/) |
| Médical | Intuitive | Attaque par phishing ciblé sur un employé. Fuite de données clients et employés. | [SecurityAffairs](https://securityaffairs.com/189598/data-breach/robotic-surgery-firm-intuitive-reports-data-breach-after-targeted-phishing-attack.html) |
| Santé | Royal Bahrain Hospital | Revendication de piratage par le groupe Payload Ransomware. | [SecurityAffairs](https://securityaffairs.com/189628/security/u-s-cisa-adds-microsoft-sharepoint-and-zimbra-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| Sécurité / Marketing | Aura | Phishing vocal (Vishing) exposant 900 000 contacts marketing. Données héritées d'une acquisition de 2021. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/aura-confirms-data-breach-exposing-900-000-marketing-contacts/) |
| Social | Starbucks | Violation de données impactant 889 employés. | [SecurityAffairs](https://securityaffairs.com/189628/security/u-s-cisa-adds-microsoft-sharepoint-and-zimbra-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|
| CVE-2026-20131 | 10.0 | Cisco Secure Firewall (FMC) | Exécution de code à distance (RCE) via désérialisation | [The Hacker News](https://thehackernews.com/2026/03/interlock-ransomware-exploits-cisco-fmc.html) |
| CVE-2026-32731 | 9.9 | ApostropheCMS | Zip Slip / Écriture de fichier arbitraire | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-32731) |
| CVE-2026-32746 | 9.8 | GNU InetUtils telnetd | Buffer Overflow / RCE en tant que root | [SecurityAffairs](https://securityaffairs.com/189620/hacking/researchers-warn-of-unpatched-critical-telnetd-flaw-affecting-all-versions.html) |
| CVE-2026-3564 | Critiques | ScreenConnect | Défaut de vérification de signature cryptographique | [BleepingComputer](https://www.bleepingcomputer.com/news/security/connectwise-patches-new-flaw-allowing-screenconnect-hijacking/) |
| CVE-2026-20963 | 8.8 | MS SharePoint | Désérialisation de données non fiables / RCE | [CISA/SecurityAffairs](https://securityaffairs.com/189628/security/u-s-cisa-adds-microsoft-sharepoint-and-zimbra-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| CVE-2026-31998 | 8.3 | OpenClaw | Contournement d'autorisation dans Synology Chat | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-31998) |
| CVE-2026-3888 | 7.8 | Ubuntu Desktop 24.04+ | Escalade de privilèges locaux (LPE) vers root | [Qualys/SecurityAffairs](https://securityaffairs.com/189614/security/cve-2026-3888-ubuntu-desktop-24-04-vulnerable-to-root-exploit.html) |
| CVE-2026-20643 | - | WebKit (Safari) | Contournement de la Same Origin Policy (SOP) | [SOC Prime](https://socprime.com/blog/cve-2026-20643-vulnerability/) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| DarkSword: iOS Exploit Chain Adopted by Multiple Threat Actors | Menace critique ciblant la mobilité, exploitant des vulnérabilités zero-day. | [Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain/) |
| Interlock Ransomware Exploits Cisco FMC Zero-Day | Utilisation de zero-day par un groupe de ransomware, ciblage critique. | [The Hacker News](https://thehackernews.com/2026/03/interlock-ransomware-exploits-cisco-fmc.html) |
| Monitoring Cyberattacks Directly Linked to US-Israel-Iran Conflict | Synthèse complète d'un conflit cyber-étatique majeur actuel. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| SilentConnect Delivers ScreenConnect | Analyse d'un nouveau loader ciblant les outils RMM légitimes. | [Elastic](https://www.elastic.co/security-labs/silentconnect-delivers-screenconnect) |
| Windsurf IDE Extension Drops Malware via Solana | Innovation technique utilisant une blockchain pour les infrastructures de commande. | [Bitdefender](https://www.bitdefender.com/en-us/blog/labs/windsurf-extension-malware-solana) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| Brian Cute Appointed President and CEO of GCA | Actualité purement institutionnelle sans analyse de menace. | [Global Cyber Alliance](https://globalcyberalliance.org/brian-cute-president-ceo/) |
| Linux & Cloud Detection Engineering - Getting Started with D4C | Contenu éducatif/tutoriel produit, pas une menace active. | [Elastic](https://www.elastic.co/security-labs/getting-started-with-defend-for-containers) |
| Observability Pipeline: Managing Telemetry at Scale | Article promotionnel sur l'architecture de données, pas de menace. | [SOC Prime](https://socprime.com/blog/what-is-an-observability-pipeline/) |
| Transparent COM instrumentation for malware analysis | Présentation d'un outil d'analyse open-source (DispatchLogger). | [Cisco Talos](https://blog.talosintelligence.com/transparent-com-instrumentation-for-malware-analysis/) |

<br>
<br/>
<div id="articles"></div>

# ARTICLES
<div id="darksword-un-kit-dexploitation-ios-sophistiqué-utilisé-par-plusieurs-acteurs"></div>

## [DarkSword: iOS Exploit Chain Adopted by Multiple Threat Actors]
Découvert par Google, Lookout et iVerify, DarkSword est un kit d'exploitation iOS utilisant six vulnérabilités, dont quatre zero-days au moment de leur exploitation. Il cible les versions iOS 18.4 à 18.7 et a été utilisé contre des victimes en Ukraine, Turquie, Malaisie et Arabie Saoudite. Trois familles de malwares (GHOSTBLADE, GHOSTKNIFE, GHOSTSABER) ont été identifiées, chacune étant capable d'extraire une quantité massive de données sensibles (photos, messages, localisation, portefeuilles crypto). Le groupe russe UNC6353 l'utilise activement via des attaques de type "watering hole" sur des sites gouvernementaux ukrainiens. Le kit se distingue par une utilisation exclusive de JavaScript, évitant ainsi les protections natives d'Apple. Une fois les données exfiltrées, le malware s'autodétruit pour compliquer l'analyse forensique.

**Analyse de l'impact** : Impact critique sur la confidentialité des communications et des actifs financiers (cryptomonnaies) pour les utilisateurs à haut risque. La sophistication et la prolifération du kit entre divers acteurs suggèrent l'existence d'un marché de cyber-espionnage commercial très actif.

**Recommandations** : 
* Mettre à jour immédiatement les appareils iOS vers la version 26.3 ou supérieure.
* Activer le "Lockdown Mode" (Mode Isolement) pour les profils à risque (journalistes, officiels, diplomates).
* Surveiller les requêtes réseau vers les domaines identifiés comme `cdncounter[.]net` ou `snapshare[.]chat`.
* Utiliser des solutions de Mobile Threat Defense (MTD) pour détecter les anomalies système (évasion de bac à sable).

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UNC6353, UNC6748, PARS Defense |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1204.001: User Execution (Phishing/Link) <br/> * T1068: Exploitation for Privilege Escalation <br/> * T1539: Steal Web Session Cookie |
| Observables & Indicateurs de compromission | ```* static.cdncounter[.]net * snapshare[.]chat * sahibndn[.]io * e5.malaymoil[.]com * 2e5a56beb63f21d9347310412ae6efb29fd3db2d3a3fc0798865a29a3c578d35 (GHOSTBLADE)``` |

### Source (url) du ou des articles
* https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain/
* https://www.lookout.com/blog/darksword
* https://go.theregister.com/feed/www.theregister.com/2026/03/18/darksword_exploit_kit_steals_iphone/

<br>
<br/>
<div id="interlock-ransomware-exploitation-de-vulnérabilités-zero-day-cisco-secure-fmc"></div>

## [Interlock Ransomware Exploits Cisco FMC Zero-Day CVE-2026-20131]
L'acteur de ransomware Interlock a exploité une vulnérabilité critique (CVE-2026-20131) dans les pare-feux Cisco plus de 30 jours avant sa divulgation publique. Cette faille de désérialisation permet une exécution de code arbitraire avec des privilèges root, sans authentification. Une erreur de configuration d'un serveur des attaquants a permis à Amazon de découvrir l'intégralité de leur boîte à outils post-exploitation. Cette trousse comprend des scripts de reconnaissance PowerShell massifs, des chevaux de Troie personnalisés en JavaScript et Java, ainsi que l'abus de logiciels légitimes comme ScreenConnect ou Volatility. Le groupe cible prioritairement le secteur médical, exerçant une pression maximale par la menace de sanctions réglementaires en plus de l'extorsion de données.

**Analyse de l'impact** : Menace directe sur la continuité des soins et la sécurité des données médicales. L'exploitation réussie d'un zero-day sur un équipement périmétrique critique comme un firewall FMC rend les systèmes internes vulnérables sans préavis.

**Recommandations** : 
* Appliquer les patchs Cisco publiés le 4 mars 2026 immédiatement sur les instances FMC.
* Auditer les logs système pour détecter des requêtes HTTP PUT inhabituelles ou des déploiements d'exécutables ELF.
* Vérifier la légitimité de toute installation de ScreenConnect dans l'environnement.
* Restreindre l'accès à l'interface de gestion FMC aux réseaux internes de confiance uniquement.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Interlock |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br/> * T1059.001: PowerShell <br/> * T1021.001: Remote Desktop Protocol |
| Observables & Indicateurs de compromission | ```* Utilisation d'un webshell Java résident en mémoire * Purge des logs *.log toutes les 5 minutes via cron * Scripts d'énumération compressant les données en ZIP par hôte``` |

### Source (url) du ou des articles
* https://thehackernews.com/2026/03/interlock-ransomware-exploits-cisco-fmc.html
* https://www.bleepingcomputer.com/news/security/interlock-ransomware-exploited-secure-fmc-flaw-in-zero-day-attacks-since-january/
* https://cybersecuritynews.com/cisco-firewall-0-day-ransomware/

<br>
<br/>
<div id="silentconnect-et-windsurf-le-ciblage-des-outils-de-développement-sintensifie"></div>

## [Windsurf IDE Extension Drops Malware via Solana Blockchain]
Une nouvelle campagne cible les développeurs via des extensions malveillantes pour l'IDE Windsurf (comparable à VS Code). L'extension, nommée `reditorsupporter.r-vscode`, récupère son code malveillant directement depuis les transactions de la blockchain Solana pour contourner les outils de détection classiques. Le malware évite délibérément les systèmes russes et se concentre sur l'exfiltration de données de navigation (mots de passe, cookies de session) depuis Chrome. Parallèlement, le chargeur "SilentConnect" utilise des techniques avancées comme le "PEB masquerading" (se déguiser en processus légitime `winhlp32.exe`) pour déployer discrètement l'outil RMM ScreenConnect via des liens Google Drive.

**Analyse de l'impact** : Risque élevé de compromission de la chaîne d'approvisionnement logicielle. Le ciblage des développeurs permet d'accéder à des secrets d'API, des clés de production et des environnements privilégiés.

**Recommandations** : 
* Interdire l'installation d'extensions IDE non vérifiées ou provenant de sources inconnues.
* Surveiller l'activité réseau liée aux API Solana (api.mainnet-beta.solana[.]com) sur les postes de développement.
* Implémenter le "Multi-Admin Approval" pour les commandes critiques sur les outils MDM/RMM.
* Chasser les anomalies dans le Process Environment Block (PEB) via des outils EDR avancés.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non mentionné (exclusion des cibles russes suggérée) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1584.007: Compromise Infrastructure: Serverless/Blockchain <br/> * T1564: Hide Artifacts <br/> * T1534: Internal Spearphishing |
| Observables & Indicator of Compromise | ```* windsurf.exe * UpdateApp (Tâche planifiée) * bumptobabeco[.]top * hxxps://drive.google[.]com/uc?id=1ohZxxT-h7xWVgclB1kvpvwkF0AGWoUtq``` |

### Source (url) du ou des articles
* https://www.bitdefender.com/en-us/blog/labs/windsurf-extension-malware-solana
* https://www.elastic.co/security-labs/silentconnect-delivers-screenconnect

<br>
<br/>
<div id="cyber-conflit-iran-israël-usa-une-escalade-numérique-majeure"></div>

## [Monitoring Cyberattacks Directly Linked to the US-Israel-Iran Military Conflict]
Le conflit au Moyen-Orient a généré une période de cyberguerre d'une intensité record. Les groupes liés au CGRI (CyberAv3ngers, APT33) ciblent les systèmes industriels américains (eau, électricité) en exploitant des mots de passe par défaut. L'entreprise médicale Stryker subit une interruption majeure de ses systèmes de commande suite à une attaque par déni de service de type "wipe" via MDM. MuddyWater agit comme un courtier d'accès pour des opérations destructrices en Europe et aux États-Unis. Un nouveau ransomware, Sicarii, a été identifié : il détruit les données de manière irréversible à cause d'une faille volontaire de gestion de clés, rendant tout paiement inutile.

**Analyse de l'impact** : Risque systémique pour les infrastructures critiques mondiales. La collaboration entre hacktivistes étatiques et cybercriminels russes augmente la portée et la toxicité des attaques.

**Recommandations** : 
* Changer immédiatement tous les mots de passe par défaut sur les systèmes OT/ICS.
* Isoler physiquement ou via VLAN les systèmes de sécurité des processus industriels.
* Réaliser des sauvegardes "Air-gapped" hors ligne face au risque de malwares de type wiper/Sicarii.
* Effectuer une chasse aux menaces (Threat Hunting) sur les backdoors Dindoor et Fakeset.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | CyberAv3ngers, APT33, MuddyWater, Sicarii Group |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T0806: External Network Boundaries <br/> * T1485: Data Destruction <br/> * T1489: Service Stop |
| Observables & Indicateurs de compromission | ```* Malware Sicarii * Backdoors Dindoor/Fakeset * Activité runtime Deno inhabituelle``` |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict
* https://securityaffairs.com/189604/cyber-warfare-2/tracking-the-iran-war-a-month-of-escalation-and-regional-impact.html