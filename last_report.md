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
  * [Attaque dévastatrice contre Stryker : 80 000 appareils effacés via Microsoft Intune](#attaque-devastatrice-contre-stryker-80-000-appareils-effaces-via-microsoft-intune)
  * [Glassworm : une campagne de supply chain massive ciblant GitHub et npm](#glassworm-une-campagne-de-supply-chain-massive-ciblant-github-et-npm)
  * [Leaknet et la technique ClickFix : l'usage furtif du runtime Deno](#leaknet-et-la-technique-clickfix-lusage-furtif-du-runtime-deno)
  * [Cursorjack : exploitation des deeplinks dans l'IDE Cursor](#cursorjack-exploitation-des-deeplinks-dans-lide-cursor)
  * [Manipulation des assistants IA par substitution de polices de caractères](#manipulation-des-assistants-ia-par-substitution-de-polices-de-caracteres)
  * [CL-STA-1087 : cyber-espionnage de longue durée contre les forces armées d'Asie du Sud-Est](#cl-sta-1087-cyber-espionnage-de-longue-duree-contre-les-forces-armees-dasie-du-sud-est)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage de la menace cyber en mars 2026 est marqué par une accélération sans précédent des cycles d'attaque, portée par l'intégration massive de l'IA et l'exploitation des infrastructures de gestion centralisées. L'incident majeur frappant Stryker démontre que la compromission d'un seul compte administrateur sur une plateforme MDM (Microsoft Intune) peut paralyser une multinationale en effaçant instantanément 80 000 terminaux, transformant les outils de résilience en vecteurs de destruction. Parallèlement, l'émergence des agents IA autonomes (OpenClaw, Cursor) crée une nouvelle surface d'attaque où des vulnérabilités de type "prompt injection" et "deeplink hijacking" permettent des exécutions de code furtives. Sur le plan géopolitique, le conflit US-Israël-Iran s'étend au cyberespace avec des attaques de représailles systématiques et des sanctions européennes fermes contre les entités chinoises et iraniennes. La menace "GlassWorm" illustre la fragilité persistante de la supply chain logicielle, tandis que l'utilisation du runtime Deno par LeakNet montre une volonté d'évasion sophistiquée en environnement mémoire. Les décideurs doivent impérativement renforcer la gouvernance des identités machines et sécuriser le déploiement des outils d'IA pour contrer ces menaces à "vitesse machine".

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
| CL-STA-1087 | Militaire (Asie du Sud-Est) | Backdoors AppleChris et MemFun, persistance longue durée, DLL hijacking. | [Security Affairs](https://securityaffairs.com/189553/apt/cl-sta-1087-targets-military-capabilities-since-2020.html) |
| Emennet Pasargad | Médias, Événementiel (Paris 2024) | Influence, vol de données, piratage de panneaux publicitaires. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/europe-sanctions-chinese-and-iranian-firms-for-cyberattacks/) |
| Flax Typhoon (Integrity Tech) | Infrastructures critiques | Botnet 'Raptor Train', compromission de dispositifs IoT/Edge. | [Security Affairs](https://securityaffairs.com/189585/security/eu-sanctions-chinese-and-iranian-actors-over-cyberattacks-on-critical-infrastructure.html) |
| GlassWorm | Développeurs, Supply Chain | Maliciels sur GitHub/npm, C2 via blockchain Solana, caractères Unicode invisibles. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/glassworm-malware-hits-400-plus-code-repos-on-github-npm-vscode-openvsx/) |
| Handala (Void Manticore) | Santé, Médical, Gouvernement | Wiper, abus de Microsoft Intune pour effacement à distance. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| i-Soon (Anxun) | Gouvernements, Infrastructures | Hacker-for-hire, services d'espionnage pour le compte de l'État chinois. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/europe-sanctions-chinese-and-iranian-firms-for-cyberattacks/) |
| LeakNet | Entreprises diverses | Technique "ClickFix", usage du runtime Deno pour exécution en mémoire. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/leaknet-ransomware-uses-clickfix-and-deno-runtime-for-stealthy-attacks/) |
| MuddyWater (MOIS) | Banque, Aviation, Défense | Backdoors Python (Fakeset), exfiltration via Rclone, accès persistants. | [Cybersecurity News](https://cybersecuritynews.com/iranian-cyber-ops-maintain-us-network-footholds/) |
| RondoDox | IoT, Serveurs web | Botnet exploitant 174 vulnérabilités (dont React2Shell). | [Security Affairs](https://securityaffairs.com/189569/malware/rondodox-botnet-expands-arsenal-targeting-174-flaws-and-hits-15000-daily-exploit-attempts.html) |
| SiegedSec | Politique, Think Tanks | Hacktivisme pro-LGBTQ+, SQL injection, XSS. | [Flare](https://flare.io/learn/resources/blog/rise-and-fall-siegedsec) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Défense / International | Conflit US-Israël-Iran | Escalade cyber suite aux frappes cinétiques. Blackout total de l'internet en Iran (18ème jour). | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Gouvernemental | Sanctions Européennes | L'UE sanctionne 3 entreprises et 2 individus (Chine et Iran) pour des cyberattaques contre les infrastructures critiques. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/europe-sanctions-chinese-and-iranian-firms-for-cyberattacks/) |
| Militaire | Modernisation de l'armée | Transformation de l'Armée de Terre française vers une "Armée de Combat" (SCORPION) face aux menaces russes. | [RUSI](https://www.rusi.org/explore-our-research/publications/commentary/lessons-french-armys-transformation-towards-modern-fighting-army) |
| Souveraineté | IA Open Source | Partenariat stratégique entre Mistral AI (France) et NVIDIA (USA) pour la coalition Nemotron. | [Portail de l'IE](https://www.portail-ie.fr/univers/blockchain-data-et-ia/2026/mistral-ai-sassocie-a-nvidia-pour-developper-les-modeles-dia-en-source-ouverte/) |
| International | Désinformation (FIMI) | Publication du 4ème rapport du SEAE sur les manipulations de l'information étrangère par la Russie et la Chine. | [EUvsDisinfo](https://euvsdisinfo.eu/4th-eeas-report-on-fimi-threats-dismantling-the-fimi-house-of-cards/) |

<br>
<br>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Backbone connectivity for Digital Global Gateways | Commission Européenne | 17/03/2026 | Union Européenne | CEF-DIG-2026 | Financement pour la sécurisation et la redondance des câbles sous-marins et réseaux terrestres. | [Digital Strategy](https://digital-strategy.ec.europa.eu/en/funding/backbone-connectivity-digital-global-gateways-studies-0) |
| Equipment for smart European cable systems | Commission Européenne | 17/03/2026 | Union Européenne | CEF-DIG-2026 | Appel à projets pour équiper les câbles de capacités de surveillance "smart" contre le sabotage. | [Digital Strategy](https://digital-strategy.ec.europa.eu/en/funding/equipment-smart-european-cable-systems-works) |
| GCA Endorses Global Framework against Fraud | Global Cyber Alliance | 17/03/2026 | Internationale (ONU/INTERPOL) | Call to Action on Combating Fraud | Soutien au cadre de partenariat public-privé pour lutter contre la fraude industrialisée par l'IA. | [Global Cyber Alliance](https://globalcyberalliance.org/gca-endorses-the-global-public-private-partnership-framework-against-fraud/) |
| The Digital Omnibus: A step back from the brink | EDRi | 17/03/2026 | Union Européenne | RGPD / ePrivacy | Analyse des compromis au Conseil de l'UE sur la simplification réglementaire du paquet "Omnibus". | [EDRi](https://edri.org/our-work/the-digital-omnibus-a-step-back-from-the-brink-but-the-risks-remain/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Santé / Médical | Stryker Corporation | Effacement de 80 000 terminaux via Intune. Handala revendique 50 To de données volées (non confirmé). | [BleepingComputer](https://www.bleepingcomputer.com/news/security/attack-on-stryker-s-microsoft-environment-wiped-employee-devices-without-malware.html) |
| Services / Réparation | Sears | Samantha, l'agent IA de Sears, exposait les appels vocaux et SMS des clients sur le web. | [DataBreaches.net](https://databreaches.net/2026/03/17/sears-exposed-ai-chatbot-phone-calls-and-text-chats-to-anyone-on-the-web/) |
| Médias | Charlie Hebdo | Vente des données de 230 000 abonnés par le groupe Emennet Pasargad. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/europe-sanctions-chinese-and-iranian-firms-for-cyberattacks/) |
| Santé | Royal Bahrain Hospital | Revendication de piratage par le groupe Payload Ransomware. | [Security Affairs](https://securityaffairs.com/189585/security/eu-sanctions-chinese-and-iranian-actors-over-cyberattacks-on-critical-infrastructure.html) |
| Éducation | Saint Elizabeth University | Accès non autorisé au système de caméras de sécurité par SiegedSec. | [Flare](https://flare.io/learn/resources/blog/rise-and-fall-siegedsec) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).
| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|
| CVE-2026-21994 | 9.8 | Oracle Edge Cloud Infrastructure | Compromission totale via HTTP (Unauthenticated) | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-21994) |
| CVE-2026-21643 | 9.1 | Fortinet FortiClient EMS | Injection SQL pré-authentification (Zero-click) | [Security Online](https://securityonline.info/publicly-disclosed-critical-zero-click-sql-injection-forticlient-ems-cve-2026-21643/) |
| CVE-2026-3288 | 8.8 | Ingress-nginx (Kubernetes) | Injection de configuration NGINX permettant une RCE | [Sysdig](https://www.sysdig.com/blog/detecting-cve-2026-3288-cve-2026-24512-ingress-nginx-configuration-injection-vulnerabilities-for-kubernetes) |
| CVE-2026-27811 | 8.8 | Roxy-WI | Injection de commande via paramètre 'diff' (RCE) | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-27811) |
| CVE-2026-22730 | 8.8 | Spring AI (MariaDB) | Injection SQL via metadata-based access control | [Security Online](https://securityonline.info/critical-spring-ai-vulnerabilities-sql-jsonpath-injection-cve-2026-22730/) |
| CVE-2026-22171 | 8.8 | OpenClaw | Traversée de fichiers (Path Traversal) via Feishu media keys | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-22171) |
| CVE-2026-3909 | - (Exploitée) | Microsoft Edge | Vulnérabilité critique activement exploitée ("In the wild") | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0303/) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Attack on Stryker’s Microsoft environment wiped employee devices without malware | Incident majeur illustrant l'abus d'outils d'administration (MDM) pour une destruction massive. | [Security Affairs](https://securityaffairs.com/189535/hacking/attack-on-stryker-s-microsoft-environment-wiped-employee-devices-without-malware.html) |
| GlassWorm malware hits 400+ code repos on GitHub, npm, VSCode, OpenVSX | Campagne de supply chain sophistiquée ciblant l'écosystème de développement moderne. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/glassworm-malware-hits-400-plus-code-repos-on-github-npm-vscode-openvsx/) |
| LeakNet ransomware uses ClickFix, Deno runtime in stealthy attacks | Utilisation innovante du runtime Deno pour l'évasion des défenses traditionnelles. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/leaknet-ransomware-uses-clickfix-and-deno-runtime-for-stealthy-attacks/) |
| CursorJack: weaponizing Deeplinks to exploit Cursor IDE | Nouvelle méthode d'attaque exploitant les protocoles deeplink dans les IDE basés sur l'IA. | [Proofpoint](https://www.proofpoint.com/us/blog/threat-insight/cursorjack-weaponizing-deeplinks-exploit-cursor-ide) |
| New font-rendering trick hides malicious commands from AI tools | Technique ingénieuse de contournement des guardrails de sécurité des assistants IA (substitution de glyphes). | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-font-rendering-trick-hides-malicious-commands-from-ai-tools/) |
| CL-STA-1087 targets military capabilities since 2020 | Espionnage étatique de long terme utilisant des backdoors modulaires et furtives. | [Security Affairs](https://securityaffairs.com/189553/apt/cl-sta-1087-targets-military-capabilities-since-2020.html) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| Free Applied Skills assessment for Defender XDR | Contenu éducatif/promotionnel, pas une menace cyber. | [Reddit](https://www.reddit.com/r/blueteamsec/comments/1rwpoqw/free_applied_skills_assessment_for_defender_xdr/) |
| Security Stack Recommendations for a Mid-Size Dev Company | Discussion communautaire et conseils, pas une actualité de veille. | [Reddit](https://www.reddit.com/r/blueteamsec/comments/1rw3ex7/security_stack_recommendations_for_a_midsize_dev/) |
| ISC Stormcast For Tuesday, March 17th, 2026 | Podcast généraliste sans détails textuels exploitables. | [SANS ISC](https://isc.sans.edu/diary/rss/32802) |
| Identity and Access Management in Google Cloud | Guide opérationnel sur les bonnes pratiques GCP, pas un incident. | [CyberEngage](https://www.cyberengage.org/post/identity-and-access-management-in-google-cloud) |
| Mistral AI s’associe à NVIDIA | Actualité business/partenariat technologique. | [Portail de l'IE](https://www.portail-ie.fr/univers/blockchain-data-et-ia/2026/mistral-ai-sassocie-a-nvidia-pour-developper-les-modeles-dia-en-source-ouverte/) |

<br>
<br>
<div id="articles"></div>

# ARTICLES

<div id="attaque-devastatrice-contre-stryker-80-000-appareils-effaces-via-microsoft-intune"></div>

## Attaque dévastatrice contre Stryker : 80 000 appareils effacés via Microsoft Intune
Le géant des technologies médicales Stryker a subi une attaque destructrice sans précédent. L'acteur de menace, identifié comme Handala (front du groupe iranien Void Manticore), a compromis un compte administrateur pour accéder à la console Microsoft Intune. Entre 05h00 et 08h00 UTC le 11 mars, l'attaquant a exécuté la commande native "Wipe" sur près de 80 000 appareils (PC et smartphones), y compris des terminaux personnels (BYOD). L'attaque n'a utilisé aucun malware traditionnel, exploitant uniquement les fonctionnalités légitimes de la plateforme de gestion. Bien que Handala revendique le vol de 50 To de données, les premières investigations de Microsoft DART et Palo Alto Unit 42 n'ont pas confirmé d'exfiltration. Les systèmes de commande électronique de Stryker sont restés hors ligne pendant plus d'une semaine, obligeant à des processus manuels.

**Analyse de l'impact** : L'impact est critique en termes de disponibilité et de continuité d'activité. L'utilisation de "Living-off-the-Land" (LotL) sur des outils d'administration centralisés rend la détection par EDR inopérante puisque les actions sont perçues comme légitimes. La destruction des données sur les appareils BYOD pose également des défis juridiques et de protection de la vie privée.

**Recommandations** :
* Activer l'approbation multi-administrateur (Multi-Admin Approval) pour les actions destructrices dans Intune/Azure.
* Imposer l'accès conditionnel strict pour les comptes d'administration (MFA résistant au phishing, localisation nommée).
* Auditer en temps réel la création de nouveaux comptes "Global Administrator".
* Segmenter les réseaux de gestion des appareils pour isoler les environnements critiques.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Handala / Void Manticore |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1078.004: Cloud Accounts<br>* T1531: Account Access Removal (via Wipe)<br>* T1566: Phishing |
| Observables & Indicateurs de compromission | ```Aucun IoC malveillant (malware) - auditer les logs Intune pour l'ID d'opération 'Wipe' et les adresses IP d'administration inhabituelles.``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/attack-on-stryker-s-microsoft-environment-wiped-employee-devices-without-malware/
* https://securityaffairs.com/189535/hacking/attack-on-stryker-s-microsoft-environment-wiped-employee-devices-without-malware.html
* https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict

<br>
<br>

<div id="glassworm-une-campagne-de-supply-chain-massive- ciblant-github-et-npm"></div>

## Glassworm : une campagne de supply chain massive ciblant GitHub et npm
La campagne GlassWorm a frappé plus de 433 composants open-source, incluant 200 dépôts Python et 151 dépôts JavaScript sur GitHub, ainsi que des extensions VSCode. Les attaquants utilisent des caractères Unicode invisibles pour dissimuler du code malveillant au sein des sources. Une fois exécuté, le script interroge la blockchain Solana toutes les cinq secondes pour recevoir des instructions C2 via des "memos" de transaction. Le payload final est un info-stealer basé sur Node.js qui cible les clés SSH, les portefeuilles de crypto-monnaies et les identifiants de développeurs. Les indices suggèrent une origine russophone, le malware vérifiant la langue du système pour s'auto-terminer s'il détecte une configuration russe. La persistance est assurée par un fichier `~/init.json`.

**Analyse de l'impact** : Menace sérieuse pour l'intégrité de la supply chain logicielle. La compromission des environnements de développement peut mener à des accès persistants dans les infrastructures de production des entreprises clientes via les accès et secrets volés.

**Recommandations** :
* Rechercher la variable marqueur `lzcdrtfxyqiplpd` dans les bases de code.
* Vérifier la présence du fichier de persistance `~/init.json`.
* Surveiller l'installation de binaires Node.js inattendus dans les répertoires personnels.
* Auditer les dates des commits Git pour détecter des anomalies entre la date de l'auteur et celle du committer.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | GlassWorm |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Dependencies and Development Tools<br>* T1027: Obfuscated Files or Information (Unicode)<br>* T1102: Web Service (Solana C2) |
| Observables & Indicateurs de compromission | ```* lzcdrtfxyqiplpd (Variable)<br>* ~/init.json (Persistance)<br>* Solana Address (C2)``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/glassworm-malware-hits-400-plus-code-repos-on-github-npm-vscode-openvsx/

<br>
<br>

<div id="leaknet-et-la-technique-clickfix-lusage-furtif-du-runtime-deno"></div>

## Leaknet et la technique ClickFix : l'usage furtif du runtime Deno
Le groupe LeakNet adopte la technique "ClickFix" (leurres de fausses corrections de navigateurs) pour infecter des environnements corporate. L'innovation majeure réside dans l'utilisation du runtime légitime Deno (JavaScript/TypeScript) comme loader de malware. En téléchargeant l'exécutable Deno officiel, signé et donc souvent autorisé par les solutions de sécurité, les attaquants peuvent exécuter du code malveillant directement en mémoire sans laisser d'artefacts sur le disque. Une fois l'ID victime généré, le loader se connecte à un C2 pour exfiltrer des données vers des compartiments Amazon S3. Le mouvement latéral est assuré via PsExec et le DLL sideloading (`jli.dll`).

**Analyse de l'impact** : Risque d'évasion élevé face aux antivirus traditionnels grâce à la stratégie "Bring Your Own Runtime" (BYOR). L'automatisation du fingerprinting et de la persistance via PowerShell/VBS augmente la vélocité des attaques.

**Recommandations** :
* Bloquer ou surveiller étroitement l'exécution du binaire `deno.exe` en dehors des environnements de développement approuvés.
* Rechercher des exécutions suspectes de `msiexec` initiées par des navigateurs.
* Surveiller le trafic outbound inhabituel vers des buckets Amazon S3.
* Vérifier les tentatives de DLL sideloading dans `C:\ProgramData\USOShared`.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | LeakNet |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1204.002: User Execution (ClickFix)<br>* T1574.002: DLL Side-Loading<br>* T1059.001: PowerShell |
| Observables & Indicator de compromission | ```* Romeo.ps1 / Juliet.vbs (Scripts)<br>* deno.exe (Runtime utilisé à des fins malveillantes)<br>* jli.dll (DLL malveillante)``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/leaknet-ransomware-uses-clickfix-and-deno-runtime-for-stealthy-attacks/

<br>
<br>

<div id="cursorjack-exploitation-des-deeplinks-dans-lide-cursor"></div>

## Cursorjack : exploitation des deeplinks dans l'IDE Cursor
L'IDE basé sur l'IA "Cursor" présente une faiblesse dans la gestion du gestionnaire de protocole `cursor://`. La méthode CursorJack abuse des deeplinks utilisés pour installer des serveurs Model Context Protocol (MCP). Un attaquant peut créer un lien malveillant qui, après acceptation par l'utilisateur, configure un serveur MCP exécutant des commandes arbitraires avec les privilèges de l'utilisateur. En test, une session Meterpreter a été établie simplement en convainquant un utilisateur d'installer un "plugin" via une page de phishing. Aucune distinction visuelle n'existe entre un lien légitime et un lien malveillant dans l'interface d'installation actuelle.

**Analyse de l'impact** : Ciblage direct des développeurs, souvent détenteurs de secrets critiques (clés SSH, tokens cloud, code source). La persistance est possible car le serveur MCP est relancé à chaque démarrage de l'IDE.

**Recommandations** :
* Sensibiliser les développeurs à ne jamais installer de serveurs MCP depuis des sources non officielles (MCP Directory).
* Auditer le fichier `~/.cursor/mcp.json` pour détecter des commandes ou URLs suspectes.
* Utiliser des solutions de protection de la navigation pour bloquer les redirections vers le protocole `cursor://`.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1204.001: Malicious Link<br>* T1548: Abuse Elevation Control Mechanism<br>* T1133: External Remote Services (Malicious MCP Server) |
| Observables & Indicateurs de compromission | ```* mcp.json (Configuration modifiée)<br>* cursor://anysphere.cursor-deeplink/mcp/install (Schéma URL)``` |

### Source (url) du ou des articles
* https://www.proofpoint.com/us/blog/threat-insight/cursorjack-weaponizing-deeplinks-exploit-cursor-ide

<br>
<br>

<div id="manipulation-des-assistants-ia-par-substitution-de-polices-de-caracteres"></div>

## Manipulation des assistants IA par substitution de polices de caractères
Une nouvelle technique d'attaque utilise le rendu de polices personnalisées pour masquer des commandes malveillantes aux yeux des assistants IA (ChatGPT, Gemini, etc.). L'attaquant remplace les glyphes d'une police : le texte lisible par l'IA semble inoffensif dans le code HTML (ex: "Instructions de nettoyage"), mais le rendu visuel pour l'utilisateur affiche une commande dangereuse (ex: un reverse shell). Lors d'un test, si l'utilisateur demande à l'IA si la page est sûre, l'assistant répond positivement car il n'analyse que le DOM textuel, ignorant la transformation visuelle opérée par la police personnalisée. Microsoft a adressé le problème, mais Google l'a classé comme dépendant du social engineering.

**Analyse de l'impact** : Érosion de la confiance envers les assistants de sécurité IA. Cette technique permet de tromper les outils d'analyse automatisés qui ne simulent pas le rendu visuel complet de la page.

**Recommandations** :
* Ne pas se fier uniquement aux assistants IA pour valider la sécurité d'une commande à exécuter dans un terminal.
* Étendre les scanners de sécurité pour détecter les substitutions de glyphes massives dans les fichiers de polices web.
* Analyser les CSS pour détecter les textes cachés (opacité zéro, taille de police minuscule).

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1204: User Execution<br>* T1027: Obfuscated Files or Information |
| Observables & Indicateurs de compromission | ```Usage de polices web (WOFF/TTF) avec remappage de glyphes asymétrique.``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/new-font-rendering-trick-hides-malicious-commands-from-ai-tools/

<br>
<br>

<div id="cl-sta-1087-cyber-espionnage-de-longue-duree-contre-les-forces-armees-dasie-du-sud-est"></div>

## CL-STA-1087 : cyber-espionnage de longue durée contre les forces armées d'Asie du Sud-Est
Une campagne d'espionnage attribuée à un acteur lié à la Chine cible les organisations militaires en Asie du Sud-Est depuis 2020. L'attaquant utilise des outils sur mesure : les backdoors AppleChris (évoluant vers une version 'Tunneler') et MemFun, ainsi qu'un extracteur de d'identifiants nommé Getpass. Le groupe fait preuve d'une grande patience, restant dormant pendant plusieurs mois avant de s'activer pour exfiltrer des fichiers spécifiques sur les capacités militaires et la collaboration avec les forces occidentales. Ils exploitent Pastebin et Dropbox comme "dead drop resolvers" pour localiser leurs serveurs C2 de manière dynamique. MemFun est particulièrement furtif, s'exécutant entièrement en mémoire via le process hollowing.

**Analyse de l'impact** : Risque géopolitique majeur avec le vol de secrets militaires sensibles et la compréhension des structures de commandement C4I. La persistance de 6 ans démontre l'inefficacité des détections périmétriques classiques face à cet acteur.

**Recommandations** :
* Surveiller les activités PowerShell suspectes créant des reverse shells.
* Auditer l'accès au processus `lsass.exe` par des DLL non signées ou déguisées en outils légitimes.
* Bloquer les accès aux domaines Pastebin et Dropbox dans les environnements de serveurs critiques.
* Rechercher l'indicateur de persistance WMI utilisé par l'acteur.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | CL-STA-1087 (Chine-nexus) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1003.001: LSASS Memory (Getpass)<br>* T1055.012: Process Hollowing<br>* T1102.001: Dead Drop Resolver (Pastebin) |
| Observables & Indicateurs de compromission | ```* AppleChris / MemFun (Malwares)<br>* GoogleUpdate.exe (Loader utilisé par MemFun)<br>* WinSAT.db (Log de Getpass)``` |

### Source (url) du ou des articles
* https://securityaffairs.com/189553/apt/cl-sta-1087-targets-military-capabilities-since-2020.html