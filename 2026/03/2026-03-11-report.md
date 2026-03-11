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
  * [iranian mois actors the cyber crime connection](#iranian-mois-actors-the-cyber-crime-connection)
  * [microsoft march 2026 patch tuesday fixes 2 zero days 79 flaws](#microsoft-march-2026-patch-tuesday-fixes-2-zero-days-79-flaws)
  * [monitoring cyberattacks directly linked to the us israel iran military conflict](#monitoring-cyberattacks-directly-linked-to-the-us-israel-iran-military-conflict)
  * [new blacksanta edr killer spotted targeting hr departments](#new-blacksanta-edr-killer-spotted-targeting-hr-departments)
  * [ivanti endpoint manager under active exploitation](#ivanti-endpoint-manager-under-active-exploitation)
  * [attackers exploit fortigate devices to access sensitive network information](#attackers-exploit-fortigate-devices-to-access-sensitive-network-information)
  * [apt28 conducts long term espionage on ukrainian forces using custom malware](#apt28-conducts-long-term-espionage-on-ukrainian-forces-using-custom-malware)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage de la menace de mars 2026 est marqué par une intensification critique du conflit cyber entre l'axe États-Unis/Israël et l'Iran, où les infrastructures industrielles (SCADA) deviennent des cibles prioritaires. On observe une hybridation croissante entre les services de renseignement étatiques (notamment l'Iran avec le MOIS) et l'écosystème du cybercrime, les acteurs étatiques utilisant désormais des outils criminels "sur étagère" pour complexifier l'attribution. Le "Patch Tuesday" de Microsoft souligne une nouvelle ère de vulnérabilités, avec l'émergence de failles découvertes par des agents d'IA, augmentant la vitesse de l'exploitation automatisée. Parallèlement, l'identité numérique devient la surface d'attaque dominante, avec 80 % des incidents liés à la compromission de comptes cloud et à l'abus d'outils de collaboration (Teams, Zoom). Les techniques d'évasion se sophistiquent, comme le démontrent le malware BlackSanta capable de neutraliser les EDR et la technique "Zombie ZIP" contournant la quasi-totalité des antivirus. Enfin, la menace pesant sur les passerelles d'accès (Ivanti, FortiGate) reste une constante, servant de vecteur privilégié pour le vol d'identifiants à privilèges et le mouvement latéral massif.

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
| **APT28 (Fancy Bear)** | Défense, Gouvernement (Ukraine) | Espionnage à long terme, malwares personnalisés (BEARDSHELL, COVENANT) | [Security Affairs](https://securityaffairs.com/189230/apt/apt28-conducts-long-term-espionage-on-ukrainian-forces-using-custom-malware.html) |
| **BlackSanta** | Ressources Humaines (RH) | Spear-phishing (ISO), DLL side-loading, désactivation massive d'EDR/Antivirus | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-blacksanta-edr-killer-spotted-targeting-hr-departments/) |
| **MuddyWater (MOIS)** | Télécoms, Défense, Énergie | Utilisation de malwares criminels (Castle Loader), backdoors Dindoor, exploitation d'identités cloud | [Check Point](https://research.checkpoint.com/2026/iranian-mois-actors-the-cyber-crime-connection/) / [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| **ShinyHunters** | Cloud (Salesforce) | Scan massif d'Experience Cloud, exploitation de mauvaises configurations de droits "invité" | [Security Affairs](https://securityaffairs.com/189214/security/threat-actors-use-custom-aurainspector-to-harvest-data-from-salesforce-systems.html) |
| **Void Manticore (Handala)** | Énergie, Infrastructures critiques (Israël) | Hack-and-leak, utilisation de l'infostealer Rhadamanthys, wipers destructifs | [Check Point](https://research.checkpoint.com/2026/iranian-mois-actors-the-cyber-crime-connection/) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Défense / Multi-sectoriel | Conflit Israël-Iran-USA | Blackout internet en Iran, frappes cinétiques sur les QG cyber de l'IRGC, et cyberattaques sur les systèmes SCADA israéliens. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Énergie | Ukraine | Résilience agricole et logistique de l'Ukraine face à l'arme alimentaire utilisée par la Russie. | [IRIS](https://www.iris-france.org/ukraine-front-agricole-dispute/) |
| Gouvernemental | Hongrie | Pratiques de passation de marchés de défense centrées sur la modernisation industrielle nationale. | [IRIS](https://www.iris-france.org/what-are-the-main-drivers-of-member-states-defence-procurement-practices-the-hungarian-case/) |
| Maritime | Golfe Persique | Perturbation massive des systèmes GPS/AIS affectant plus de 1100 navires suite à des opérations de guerre électronique. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Sécurité Européenne | UE | Europol avertit d'une hausse des menaces terroristes et cyber sur le sol européen liées à l'escalade au Moyen-Orient. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| EDRi files DSA complaint against YouTube | EDRi | 10/03/2026 | Belgique / UE | Digital Services Act (DSA) | Plainte concernant l'absence d'alternative réelle au profilage dans les systèmes de recommandation. | [EDRi](https://edri.org/our-work/edri-files-dsa-complaint-against-youtube-for-undermining-user-autonomy/) |
| The eID Wallet still doesn’t deserve your full trust | EDRi | 10/03/2026 | UE | Regulation (EU) 2024/1183 (eIDAS 2.0) | Critiques sur les actes d'exécution techniques affaiblissant la protection de la vie privée (traçabilité). | [EDRi](https://edri.org/our-work/the-eid-wallet-still-doesnt-deserve-your-full-trust/) |
| White House Unveils National Cyber Strategy | Sean Cairncross | 10/03/2026 | USA | Cyber Strategy for America 2026 | Nouvelle stratégie offensive visant à imposer des coûts aux adversaires étatiques. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Énergie | Sharjah National Oil Corporation (UAE) | Exfiltration de 1,3 To de données (contrats, finances) par le groupe Handala. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Santé | Shamir Medical Center (Israël) | Attaque par ransomware Qilin (affilié iranien), fuite de correspondances et données médicales. | [Check Point](https://research.checkpoint.com/2026/iranian-mois-actors-the-cyber-crime-connection/) |
| Santé | TriZetto Provider Solutions | Violation de données impactant plus de 3,4 millions de patients. | [Security Affairs](https://securityaffairs.com/189266/security/microsoft-patch-tuesday-security-updates-for-march-2026-fixed-84-bugs.html) |
| Télécommunications | Ericsson US | Compromission d'un fournisseur tiers exposant des données employés et clients. | [Security Affairs](https://securityaffairs.com/189197/data-breach/ericsson-us-confirms-breach-after-third-party-provider-attack.html) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par score CVSS.
| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|
| CVE-2026-21536 | 9.8 | Microsoft Devices Pricing Program | Remote Code Execution (RCE) - IA discovered | [SANS](https://isc.sans.edu/diary/rss/32782) / [Krebs](https://krebsonsecurity.com/2026/03/microsoft-patch-tuesday-march-2026-edition/) |
| CVE-2025-41709 | 9.8 | Janitza / Weidmueller Energy Meters | Command Injection (RCE) | [Security Online](https://securityonline.info/critical-rce-vulnerabilities-uncovered-in-janitza-and-weidmueller-energy-meters/) |
| CVE-2025-26399 | 9.8 | SolarWinds Web Help Desk | Deserialization of Untrusted Data | [Security Affairs](https://securityaffairs.com/189172/security/u-s-cisa-adds-ivanti-epm-solarwinds-and-omnissa-workspace-one-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| CVE-2026-23813 | 9.8 | HPE Aruba Networking AOS-CX | Authentication Bypass (Admin password reset) | [BleepingComputer](https://www.bleepingcomputer.com/news/security/hpe-warns-of-critical-aos-cx-flaw-allowing-admin-password-resets/) |
| CVE-2026-1603 | 8.6 | Ivanti Endpoint Manager (EPM) | Authentication Bypass (KEV CISA) | [Field Effect](https://fieldeffect.com/blog/ivanti-endpoint-manager-active-exploitation) |
| CVE-2026-21262 | 8.8 | Microsoft SQL Server | Elevation of Privilege (Zero-day / Public) | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-march-2026-patch-tuesday-fixes-2-zero-days-79-flaws/) |
| CVE-2026-0866 | N/A | Format ZIP (Moteurs AV) | Technique "Zombie ZIP" (Evasion de détection) | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-zombie-zip-technique-lets-malware-slip-past-security-tools/) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Iranian MOIS Actors & the Cyber Crime Connection | Analyse majeure de la convergence entre espionnage étatique et cybercriminalité. | [Check Point](https://research.checkpoint.com/2026/iranian-mois-actors-the-cyber-crime-connection/) |
| Microsoft March 2026 Patch Tuesday | Synthèse indispensable des mises à jour de sécurité critiques du mois. | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-march-2026-patch-tuesday-fixes-2-zero-days-79-flaws/) |
| Monitoring Cyberattacks Directly Linked to the US-Israel-Iran Military Conflict | Chronologie détaillée d'un conflit cyber-cinétique majeur. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| New ‘BlackSanta’ EDR killer spotted targeting HR departments | Découverte d'une nouvelle technique sophistiquée de neutralisation des outils de sécurité. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-blacksanta-edr-killer-spotted-targeting-hr-departments/) |
| Ivanti Endpoint Manager under active exploitation | Alerte critique sur une exploitation active (KEV CISA). | [Field Effect](https://fieldeffect.com/blog/ivanti-endpoint-manager-active-exploitation) |
| Attackers exploit FortiGate devices to access sensitive network information | Incident concret d'exploitation de passerelles pour le vol d'identifiants AD. | [Security Affairs](https://securityaffairs.com/189241/security/attackers-exploit-fortigate-devices-to-access-sensitive-network-information.html) |
| APT28 conducts long-term espionage on Ukrainian forces | Analyse technique du retour d'un acteur étatique russe majeur. | [Security Affairs](https://securityaffairs.com/189230/apt/apt28-conducts-long-term-espionage-on-ukrainian-forces-using-custom-malware.html) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| The RSAC 2026 Conference talks worth catching | Contenu promotionnel / événementiel peu opérationnel. | [Red Canary](https://redcanary.com/blog/news-events/rsac-2026/) |
| Security News Digest - 2026-03-11 | Redondance avec les articles détaillés déjà sélectionnés. | [Social Media](https://infosec.exchange/@securityfeed/116208187850182165) |
| ASN: AS137425 Location: Dhaka | Information de routine sans contexte de menace spécifique. | [Social Media](https://infosec.exchange/@shodansafari/116207833026896761) |
| ISC Stormcast for Wednesday, March 11th | Format podcast avec peu de détails écrits exploitables. | [SANS ISC](https://isc.sans.edu/diary/rss/32784) |

<br>
<br>
<div id="articles"></div>

# ARTICLES
<div id="iranian-mois-actors-the-cyber-crime-connection"></div>

## Iranian MOIS Actors & the Cyber Crime Connection
L'analyse de Check Point Research révèle une évolution majeure des tactiques de renseignement iranien (MOIS). Des groupes comme MuddyWater et Void Manticore ne se contentent plus d'imiter des cybercriminels, mais intègrent activement l'écosystème criminel pour leurs opérations. Ils utilisent désormais des infostealers commerciaux (Rhadamanthys), des botnets tiers (Tsundere) et des services de Malware-as-a-Service (Castle Loader). Cette approche offre deux avantages : l'augmentation des capacités techniques via des outils matures et une complexification extrême de l'attribution. Les attaques contre les hôpitaux israéliens (Shamir Medical Center) via l'infrastructure de ransomware Qilin illustrent cette transition où le crime devient une ressource opérationnelle d'État.

**Analyse de l'impact** : Impact critique sur la capacité de détection et d'attribution des équipes de réponse aux incidents, car les marqueurs techniques sont partagés avec des groupes criminels financiers communs.

**Recommandations** : 
* Renforcer la surveillance des infostealers même dans des contextes non financiers.
* Surveiller l'utilisation d'outils de transfert comme `rclone` vers des services cloud (Wasabi).
* Vérifier les certificats de signature de code suspects ("Amy Cherne", "Donald Gay").

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | MuddyWater, Void Manticore, Qilin (affilié) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.001: Spear-phishing with link * T1588.002: Acquire Infrastructure (Criminal Tools) * T1486: Data Encrypted for Impact |
| Observables & Indicateurs de compromission | * IP: 18.223.24.218 * Hash: aae017e7a36e016655c91bd01b4f3c46309bbe540733f82cce29392e72e9bd1f (Rhadamanthys) * Certificats: Amy Cherne, Donald Gay |

### Source (url) du ou des articles
* https://research.checkpoint.com/2026/iranian-mois-actors-the-cyber-crime-connection/

<br>
<div id="microsoft-march-2026-patch-tuesday-fixes-2-zero-days-79-flaws"></div>

## Microsoft March 2026 Patch Tuesday fixes 2 zero-days, 79 flaws
Le Patch Tuesday de mars 2026 corrige 79 vulnérabilités, dont deux "zero-day" divulgués publiquement (CVE-2026-21262 et CVE-2026-26127). Huit vulnérabilités sont classées comme critiques. Un fait notable est la découverte par une IA (agent XBOW) de la faille RCE critique CVE-2026-21536 dans les services cloud de Microsoft. Les correctifs couvrent Windows, Office, SQL Server et Azure. Les failles de Microsoft Office exploitables via le volet de visualisation (Preview Pane) restent une priorité haute, tout comme une faille d'Excel (CVE-2026-26144) pouvant être détournée par Copilot pour exfiltrer des données.

**Analyse de l'impact** : Risque élevé d'escalade de privilèges et d'exécution de code à distance sur les parcs Windows. L'automatisation de la découverte de failles par l'IA accélère le cycle d'exploitation.

**Recommandations** : 
* Déployer prioritairement les correctifs pour SQL Server (CVE-2026-21262).
* Désactiver le volet de visualisation dans Outlook si le patch ne peut être appliqué immédiatement.
* Restreindre les privilèges des utilisateurs Copilot sur les données sensibles dans Excel.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1203: Exploitation for Client Execution * T1068: Exploitation for Privilege Escalation |
| Observables & Indicateurs de compromission | CVE-2026-21262, CVE-2026-26127, CVE-2026-21536, CVE-2026-26144 |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/microsoft/microsoft-march-2026-patch-tuesday-fixes-2-zero-days-79-flaws/
* https://isc.sans.edu/diary/rss/32782
* https://krebsonsecurity.com/2026/03/microsoft-patch-tuesday-march-2026-edition/

<br>
<div id="monitoring-cyberattacks-directly-linked-to-the-us-israel-iran-military-conflict"></div>

## Monitoring Cyberattacks Directly Linked to the US-Israel-Iran Military Conflict
Le conflit cyber-cinétique entre les États-Unis, Israël et l'Iran a atteint un paroxysme en mars 2026. L'Iran subit un blackout internet quasi-total (1 % de connectivité) suite à des frappes israéliennes sur les infrastructures de télécommunications et de commandement de l'IRGC. En représailles, des collectifs hacktivistes pro-iraniens et russes (NoName057) multiplient les attaques contre les systèmes de contrôle industriel (ICS) israéliens, affirmant avoir pris le contrôle de pompes à eau et de systèmes énergétiques. Des opérations d'influence massives via des applications mobiles compromises (BadeSaba) ont été observées pour diffuser des messages de propagande.

**Analyse de l'impact** : Menace directe sur la sécurité physique et les services essentiels (eau, électricité) au Moyen-Orient. Risque de débordement vers les alliés occidentaux (frappes DDoS sur des ports US).

**Recommandations** : 
* Isoler impérativement les interfaces de gestion ICS/SCADA d'Internet.
* Activer une surveillance accrue sur les logs d'accès VPN provenant de zones géopolitiques instables.
* Sensibiliser les utilisateurs aux risques de malwares mobiles thématiques (alertes de guerre).

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | IRGC, CyberAv3ngers, NoName057(16), Handala |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T0801: Monitor Process State * T0814: Denial of Service (ICS) * T1491: Defacement |
| Observables & Indicateurs de compromission | CVE-2017-7921 (Hikvision), CVE-2021-22681 (Rockwell) |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict

<br>
<div id="new-blacksanta-edr-killer-spotted-targeting-hr-departments"></div>

## New ‘BlackSanta’ EDR killer spotted targeting HR departments
Le malware BlackSanta cible spécifiquement les services RH via des ISO malveillants déguisés en CV. Une fois exécuté, il déploie un module de neutralisation ("EDR killer") extrêmement efficace. BlackSanta utilise des pilotes légitimes détournés (BYOD - Bring Your Own Driver) comme IObitUnlocker.sys pour terminer les processus de sécurité au niveau du noyau. Il ajoute également des exclusions dans Microsoft Defender et réduit la télémétrie envoyée vers le cloud de sécurité. Le malware effectue des tests de lecture/écriture disque et des vérifications d'environnement (anti-VM/sandbox) avant de charger son payload final par "process hollowing".

**Analyse de l'impact** : Menace sérieuse pour l'intégrité des postes de travail RH qui gèrent des données sensibles. La neutralisation de l'EDR rend l'infection invisible aux outils classiques.

**Recommandations** : 
* Bloquer le montage des fichiers ISO au niveau de la politique de groupe (GPO) pour les utilisateurs non techniques.
* Surveiller le chargement de pilotes non signés ou connus pour être abusés (IObitUnlocker.sys).
* Implémenter des alertes sur les modifications des clés de registre Microsoft Defender.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Acteur russophone (non nommé) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1562.001: Disable or Modify Tools * T1055.012: Process Hollowing * T1574.002: DLL Side-Loading |
| Observables & Indicateurs de compromission | * Pilotes: truesight.sys, IObitUnlocker.sys * Archive: SumatraPDF avec DWrite.dll malveillant |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/new-blacksanta-edr-killer-spotted-targeting-hr-departments/

<br>
<div id="ivanti-endpoint-manager-under-active-exploitation"></div>

## Ivanti Endpoint Manager under active exploitation
La vulnérabilité CVE-2026-1603 (CVSS 8.6) affectant Ivanti Endpoint Manager (EPM) est activement exploitée selon la CISA. Cette faille de contournement d'authentification permet à un attaquant non authentifié, ayant un accès réseau au serveur central, de récupérer des identifiants stockés. Ivanti EPM étant une solution de gestion centralisée avec des privilèges élevés sur tout le parc (Windows, macOS, IoT), sa compromission offre un contrôle quasi-total sur l'infrastructure ciblée. Le patch correctif est disponible depuis février 2026 (version 2024 SU5).

**Analyse de l'impact** : Risque critique de mouvement latéral massif et de vol d'identifiants à hauts privilèges.

**Recommandations** : 
* Mettre à jour immédiatement vers EPM 2024 SU5.
* Isoler le serveur EPM dans un segment réseau administratif restreint (Jump host).
* Effectuer une rotation immédiate de tous les secrets et identifiants gérés par Ivanti.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1556: Modify Authentication Process * T1555: Credentials from Password Stores |
| Observables & Indicateurs de compromission | CVE-2026-1603 |

### Source (url) du ou des articles
* https://fieldeffect.com/blog/ivanti-endpoint-manager-active-exploitation
* https://securityaffairs.com/189172/security/u-s-cisa-adds-ivanti-epm-solarwinds-and-omnissa-workspace-one-flaws-to-its-known-exploited-vulnerabilities-catalog.html

<br>
<div id="attackers-exploit-fortigate-devices-to-access-sensitive-network-information"></div>

## Attackers exploit FortiGate devices to access sensitive network information
SentinelOne rapporte plusieurs incidents où des pare-feu FortiGate ont été compromis pour servir de tête de pont. Les attaquants exploitent des vulnérabilités de validation de signature SSO (CVE-2025-59718/19) pour obtenir un accès administrateur sans authentification. Une fois l'accès obtenu, ils exfiltrent les fichiers de configuration contenant les identifiants chiffrés des comptes de service LDAP. Ces identifiants sont ensuite déchiffrés hors-ligne pour s'authentifier sur l'Active Directory (AD), permettant l'enrôlement de stations de travail pirates et le déploiement d'outils RMM (Pulseway, MeshAgent).

**Analyse de l'impact** : Compromission totale de l'AD à partir d'un accès périphérique mal sécurisé. Les secteurs de la santé et des MSP sont particulièrement visés.

**Recommandations** : 
* Appliquer les correctifs FortiOS pour le SSO immédiatement.
* Limiter l'accès aux interfaces d'administration FortiGate à des adresses IP sources de confiance.
* Surveiller la création de nouveaux comptes administrateurs locaux sur les appliances réseau.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable (espionnage/financier) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1556.002: Password Policy Discovery * T1555.004: Windows Credential Manager * T1219: Remote Access Software |
| Observables & Indicateurs de compromission | * CVE-2025-59718, CVE-2025-59719, CVE-2026-24858 * Fichiers: NTDS.dit exfiltré |

### Source (url) du ou des articles
* https://securityaffairs.com/189241/security/attackers-exploit-fortigate-devices-to-access-sensitive-network-information.html

<br>
<div id="apt28-conducts-long-term-espionage-on-ukrainian-forces-using-custom-malware"></div>

## APT28 conducts long-term espionage on Ukrainian forces using custom malware
Le groupe APT28 (lié au GRU russe) mène une campagne d'espionnage active contre le personnel militaire ukrainien depuis avril 2024. Le toolkit repose sur deux implants modernes : BEARDSHELL (backdoor C++) et COVENANT (framework de post-exploitation modifié). Ces outils utilisent des services cloud légitimes (Icedrive, Filen) pour leur communication C2 afin de rester furtifs. BEARDSHELL présente des similitudes de code avec XTunnel, utilisé lors du piratage du DNC en 2016, confirmant la pérennité de l'expertise de développement du groupe. SLIMAGENT, un autre module, est utilisé pour la capture de captures d'écran et l'exfiltration de documents.

**Analyse de l'impact** : Risque d'espionnage stratégique et tactique persistant sur les opérations militaires.

**Recommandations** : 
* Analyser les flux sortants vers les services de stockage cloud peu communs (Filen, Icedrive).
* Rechercher les mécanismes de persistance basés sur le framework Covenant.
* Surveiller l'utilisation suspecte de scripts PowerShell déchiffrés en mémoire.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | APT28 (Fancy Bear / GRU) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1102.002: Bidirectional Communication * T1113: Screen Capture * T1027.001: Binary Obfuscation (Opaque Predicate) |
| Observables & Indicateurs de compromission | * Malwares: BEARDSHELL, SLIMAGENT * C2: Icedrive API, Filen.io |

### Source (url) du ou des articles
* https://securityaffairs.com/189230/apt/apt28-conducts-long-term-espionage-on-ukrainian-forces-using-custom-malware.html