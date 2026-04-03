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
  * [Compromission de la chaîne d'approvisionnement axios par l'acteur unc1069](#compromission-de-la-chaine-dapprovisionnement-axios-par-lacteur-unc1069)
  * [Guide de défense contre le malware brickstorm ciblant vsphere](#guide-de-developpement-contre-le-malware-brickstorm-ciblant-vsphere)
  * [Analyse technique du malware qilin edr killer](#analyse-technique-du-malware-qilin-edr-killer)
  * [Opération de récolte de d'identifiants à grande échelle via react2shell](#operation-de-recolte-de-didentifiants-a-grande-echelle-via-react2shell)
  * [Le réseau de recrutement international des travailleurs it nord-coréens nkitw](#le-reseau-de-recrutement-international-des-travailleurs-it-nord-coreens-nkitw)
  * [Impersonnalisation du cert-ua par l'acteur uac-0255](#impersonnalisation-du-cert-ua-par-lacteur-uac-0255)
  * [Ciblage des appareils ios par le groupe ta446 coldriver](#ciblage-des-appareils-ios-par-le-groupe-ta446-coldriver)
  * [Restauration de stryker après l'attaque wiper de handala hack](#restauration-de-stryker-apres-lattaque-wiper-de-handala-hack)
  * [Augmentation des cyberattaques mirai contre les infrastructures françaises](#augmentation-des-cyberattaques-mirai-contre-les-infrastructures-françaises)
  * [Vulnerabilites critiques cisco imc et ssm on-prem](#vulnerabilites-critiques-cisco-imc-et-ssm-on-prem)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage actuel de la menace est marqué par une industrialisation accrue des compromissions de la chaîne d'approvisionnement logicielle, comme l'illustre l'attaque massive sur le package npm Axios par des acteurs nord-coréens. L'exploitation de vulnérabilités récentes telles que React2Shell démontre une vélocité alarmante dans la transition de la découverte à l'exploitation automatisée à grande échelle, souvent facilitée par l'IA. Parallèlement, le conflit entre l'Iran, Israël et les États-Unis s'intensifie dans le cyberespace, avec des menaces directes des Gardiens de la Révolution contre 18 entreprises technologiques américaines. Les groupes cybercriminels comme Qilin perfectionnent leurs capacités d'aveuglement des solutions de défense (EDR), rendant les attaques par ransomware plus furtives. L'écosystème de la virtualisation, notamment vSphere, devient une cible privilégiée pour l'établissement de persistances durables sous le système d'exploitation invité. On observe également une professionnalisation des fraudes hybrides, utilisant des identités volées et le recrutement international pour infiltrer les entreprises occidentales. La menace mobile franchit un nouveau palier avec le déploiement d'exploits iOS complexes par des acteurs étatiques russes. Enfin, la France subit une pression croissante avec un triplement des événements d'attaques liés à des botnets de la famille Mirai.

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
| Chronus Team | Mexique (Secteur public) | Défiguraction web et fuites de données | [Recorded Future](https://www.recordedfuture.com/research/latin-america-and-the-caribbean-cybercrime-landscape) |
| Cyber Av3ngers | ICS/OT, infrastructures critiques | Ciblage de PLC, opérations psychologiques | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Handala Hack | Santé, Technologie, Infrastructures | Wiper malware, compromission de comptes admin Windows/Intune | [BleepingComputer](https://www.bleepingcomputer.com/news/security/medtech-giant-stryker-fully-operational-after-data-wiping-attack/) |
| IRGC (Gardiens de la Révolution) | Technologie et Défense US | Désignation de cibles, menaces hybrides | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Payload | Finance, Services, Santé | Ransomware et exfiltration de données | [Ransomlook](https://www.ransomlook.io//group/payload) |
| Qilin (Agenda) | Industrie, Santé, Construction | Utilisation de malwares "EDR killer", vol d'identifiants | [Cisco Talos](https://blog.talosintelligence.com/qilin-edr-killer/) |
| TA416 (Mustang Panda) | Gouvernements européens | RAT PlugX, web beacons pour reconnaissance | [Weekly Threat Landscape](https://sploited.blog/2026/04/02/weekly-threat-landscape-thursday-roundup-2/) |
| TA446 (COLDRIVER) | Diplomatie, Gouvernement | Exploitation iOS (DarkSword), phishing ciblé | [Weekly Threat Landscape](https://sploited.blog/2026/04/02/weekly-threat-landscape-thursday-roundup-2/) |
| TeamPCP | Chaîne d'approvisionnement logicielle | Empoisonnement de pipelines CI/CD (Trivy, LiteLLM) | [Elastic Security Labs](https://www.elastic.co/security-labs/how-we-caught-the-axios-supply-chain-attack) |
| UAC-0255 (CyberSerp) | Gouvernement Ukraine | Impersonnalisation du CERT-UA, RAT AGEWHEEZE | [Security Affairs](https://securityaffairs.com/190287/hacking/threat-actor-uac-0255-impersonate-cert-ua-to-spread-agewheeze-malware-via-phishing.html) |
| UAT-10608 | Applications Web (Next.js) | Exploitation React2Shell, récolte massive de secrets | [Cisco Talos](https://blog.talosintelligence.com/uat-10608-inside-a-large-scale-automated-credential-harvesting-operation-targeting-web-applications/) |
| UNC1069 | Crypto, DeFi, Logiciels | Ingénierie sociale, compromission npm Axios | [Elastic Security Labs](https://www.elastic.co/security-labs/how-we-caught-the-axios-supply-chain-attack) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Défense / Energie | Conflit Ukraine-Russie | Frappes de drones ukrainiens sur les ports pétroliers de Ust-Luga et Primorsk. | [EUvsDisinfo](https://euvsdisinfo.eu/ukraine-hits-russian-oil-ports-kremlin-blames-nato-and-warns-of-a-coup-in-hungary/) |
| Gouvernement | Influence Hongrie | Narratifs pro-Kremlin accusant l'UE et l'Ukraine de préparer un coup d'État en Hongrie. | [EUvsDisinfo](https://euvsdisinfo.eu/ukraine-hits-russian-oil-ports-kremlin-blames-nato-and-warns-of-a-coup-in-hungary/) |
| Population civile | Blackout Internet Iran | Le blackout internet en Iran entre dans son 34ème jour avec une connectivité à 1%. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Technologie / Défense | Conflit Moyen-Orient | L'IRGC désigne 18 entreprises technologiques américaines comme cibles légitimes au Moyen-Orient. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Transport maritime | Conflit Mer Rouge | Les Houthis lancent des attaques conjointes avec l'Iran et le Hezbollah, menaçant le détroit de Bab al-Mandeb. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Europe’s digital laws are not bargaining chips | EDRi | 02/04/2026 | Union Européenne | DSA, DMA, AI Act, GDPR | Critique du plan de dialogue formel entre l'UE et les USA sur l'application des lois technologiques, craignant un affaiblissement de la réglementation. | [EDRi](https://edri.org/our-work/europes-digital-laws-are-not-bargaining-chips/) |
| Le réseau des Campus Cyber dévoile sa feuille de route | Campus Cyber | 02/04/2026 | France | Feuille de route territoriale | Structuration d'une action collective cyber au service des entreprises et collectivités territoriales. | [Campus Cyber](https://campuscyber.fr/le-reseau-des-campus-cyber-devoile-sa-feuille-de-route-strategique-commune/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Finance | United Finance Egypt | Compromission de l'infrastructure complète et fuite des données clients par le groupe Payload. | [Ransomlook](https://www.ransomlook.io//group/payload) |
| Finance | Drift Protocol | Vol de 280 millions de dollars suite à la prise de contrôle du Conseil de Sécurité via des comptes durable nonce. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/drift-loses-280-million-as-hackers-seize-security-council-powers/) |
| Gouvernement | National Assembly (Ecuador) | Deux cyberattaques visant à accéder à des données confidentielles et perturber les services. | [Recorded Future](https://www.recordedfuture.com/research/latin-america-and-the-caribbean-cybercrime-landscape) |
| Gouvernement | Citoyens du Paraguay | Fuite de données massives (ID, dates de naissance, adresses) sur le dark web. | [Recorded Future](https://www.recordedfuture.com/research/latin-america-and-the-caribbean-cybercrime-landscape) |
| Santé | The Center for Hearing & Speech | Publication de la victime sur le blog du groupe de ransomware Interlock. | [cti.fyi](https://cti.fyi/groups/interlock.html) |
| Services | Tscherne Consulting | Violation de données par le groupe Payload affectant ce cabinet de conseil autrichien. | [Ransomlook](https://www.ransomlook.io//group/payload) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité.
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2025-55182 | 10.0 | N/A | FALSE | React Server Components / Next.js | RCE (React2Shell) | T1190: Exploit Public-Facing Application | Désérialisation non sécurisée permettant une exécution de code à distance pré-authentification. | [Cisco Talos](https://blog.talosintelligence.com/uat-10608-inside-a-large-scale-automated-credential-harvesting-operation-targeting-web-applications/) |
| CVE-2026-33105 | 10.0 | N/A | FALSE | Microsoft Azure Kubernetes Service | Elevation of Privilege | Non mentionnées | Autorisation inappropriée permettant une élévation de privilèges à distance via le réseau. | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-33105) |
| CVE-2026-33107 | 10.0 | N/A | FALSE | Azure Databricks | Elevation of Privilege | Non mentionnées | SSRF permettant une élévation de privilèges à distance. | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-33107) |
| CVE-2026-32213 | 10.0 | N/A | FALSE | Azure AI Foundry | Elevation of Privilege | Non mentionnées | Autorisation inappropriée dans Azure AI Foundry. | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-32213) |
| CVE-2026-20093 | 9.8 | N/A | FALSE | Cisco Integrated Management Controller | Auth Bypass | T1556: Modify Authentication Process | Mauvaise gestion des requêtes de changement de mot de passe permettant un accès Admin. | [Cisco](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cimc-auth-bypass-AgG2BxTn) |
| CVE-2026-20160 | 9.8 | N/A | FALSE | Cisco SSM On-Prem | RCE | Non mentionnées | Exposition involontaire d'un service interne permettant l'exécution de commandes root. | [Cisco](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ssm-cli-execution-cHUcWuNr) |
| CVE-2026-2699 | 9.8 | N/A | FALSE | Progress ShareFile | Auth Bypass | Non mentionnées | Mauvaise gestion des redirections HTTP permettant l'accès à l'interface d'administration. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-progress-sharefile-flaws-can-be-chained-in-pre-auth-rce-attacks/) |
| CVE-2026-2701 | 9.1 | N/A | FALSE | Progress ShareFile | RCE | T1505.003: Web Shell | Exploitation des fonctions d'upload pour placer un shell ASPX dans le webroot. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-progress-sharefile-flaws-can-be-chained-in-pre-auth-rce-attacks/) |
| CVE-2026-32211 | 9.1 | N/A | FALSE | Azure MCP Server | Information Disclosure | Non mentionnées | Absence d'authentification pour une fonction critique. | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-32211) |
| CVE-2026-5281 | N/A | N/A | TRUE | Google Chrome | Use-After-Free | T1203: Exploitation for Client Execution | Vulnérabilité dans l'implémentation WebGPU Dawn permettant une RCE via une page HTML forgée. | [CISA](https://cybersecuritynews.com/chrome-0-day-flaw-exploited/) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| How we caught the Axios supply chain attack | Analyse majeure d'une compromission de supply chain critique touchant des millions d'utilisateurs. | [Elastic Security Labs](https://www.elastic.co/security-labs/how-we-caught-the-axios-supply-chain-attack) |
| vSphere and BRICKSTORM Malware: A Defender's Guide | Guide complet sur une menace sophistiquée ciblant les infrastructures de virtualisation. | [Google/Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/vsphere-brickstorm-defender-guide/) |
| Qilin EDR killer infection chain | Analyse technique profonde d'une méthode de désactivation des protections de sécurité (EDR). | [Cisco Talos](https://blog.talosintelligence.com/qilin-edr-killer/) |
| UAT-10608: Credential harvesting operation | Détails sur l'exploitation à grande échelle de la vulnérabilité React2Shell. | [Cisco Talos](https://blog.talosintelligence.com/uat-10608-inside-a-large-scale-automated-credential-harvesting-operation-targeting-web-applications/) |
| Code Names, Fake Personas, and Iranian Recruits | Révélations sur les réseaux de recrutement et d'infiltration des travailleurs IT nord-coréens. | [Flare](https://flare.io/learn/resources/blog/iranian-recruits-inside-the-nkitw-operation) |
| Threat actor UAC-0255 impersonate CERT-UA | Cas d'école d'impersonnalisation d'une autorité de sécurité nationale pour diffuser un malware. | [Security Affairs](https://securityaffairs.com/190287/hacking/threat-actor-uac-0255-impersonate-cert-ua-to-spread-agewheeze-malware-via-phishing.html) |
| Russian FSB-Linked Group Targets iOS Devices | Utilisation d'exploits iOS complexes ("DarkSword") par des acteurs étatiques russes. | [Weekly Threat Landscape](https://sploited.blog/2026/04/02/weekly-threat-landscape-thursday-roundup-2/) |
| Medtech giant Stryker fully operational after attack | Retour d'expérience sur la restauration après une attaque destructrice (wiper) de grande envergure. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/medtech-giant-stryker-fully-operational-after-data-wiping-attack/) |
| Cyberattacks on France Are Rising | Données télémétriques sur l'augmentation des attaques contre les infrastructures françaises. | [Global Cyber Alliance](https://globalcyberalliance.org/cyberattacks-on-france-are-rising-heres-what-the-aide-data-shows/) |
| Critical Cisco IMC auth bypass | Détails sur des vulnérabilités critiques affectant les contrôleurs de gestion matérielle Cisco. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-cisco-imc-auth-bypass-gives-attackers-admin-access/) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| ISC Stormcast For Friday, April 3rd | Format podcast trop généraliste sans focus spécifique immédiat. | [SANS](https://isc.sans.edu/diary/rss/32862) |
| The Sysdig MCP server is available | Annonce purement commerciale/produit. | [Sysdig](https://webflow.sysdig.com/blog/the-sysdig-mcp-server-is-now-available-in-aws-marketplace) |
| Risk isn’t reduced until you take action | Article d'opinion et de leadership sans renseignement technique sur une menace précise. | [Sysdig](https://webflow.sysdig.com/blog/risk-isnt-reduced-until-you-take-action-how-teams-resolve-issues-in-the-cloud) |
| Drifts loses $280 million | Classé en violation de données dans la synthèse correspondante. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/drift-loses-280-million-as-hackers-seize-security-council-powers/) |
| United Finance Egypt By payload | Classé en violation de données. | [Ransomlook](https://www.ransomlook.io//group/payload) |

<br>
<br>
<div id="articles"></div>

# ARTICLES
<div id="compromission-de-la-chaine-dapprovisionnement-axios-par-lacteur-unc1069"></div>

## How we caught the Axios supply chain attack
Le package npm extrêmement populaire Axios a été compromis par un acteur lié à la Corée du Nord (UNC1069), via le détournement d'un compte de mainteneur. Les attaquants ont publié les versions malveillantes 1.14.1 et 0.30.4, intégrant une dépendance fantôme nommée "plain-crypto-js". Cette dernière exécute un hook postinstall pour déployer un malware multiplateforme (RAT). L'attaque a été détectée rapidement grâce à un outil de monitoring basé sur l'IA analysant les différentiels de code. Ce malware permettait l'extraction d'identifiants et la prise de contrôle à distance des systèmes infectés. L'incident s'inscrit dans une vague de compromissions incluant Trivy, LiteLLM et Telnyx. L'infrastructure C2 de l'attaquant a été submergée par le nombre de requêtes avant d'être neutralisée.

**Analyse de l'impact** : Impact global massif étant donné qu'Axios est téléchargé plus de 100 millions de fois par semaine. La compromission permet un accès persistant et non authentifié à des milliers d'environnements de développement et de serveurs de production.

**Recommandations** : Appliquer un "soak time" (délai de latence) d'au moins 7 jours avant de mettre à jour les dépendances npm. Auditer les hooks de post-installation dans les pipelines CI/CD. Déployer des contrôles d'exécution d'applications (AppControl) pour bloquer les binaires non signés issus des dossiers de paquets.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UNC1069 (lié à la Corée du Nord / Lazarus) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Supply Chain Compromise (Software Dependencies) <br/> * T1547.001: Persistence (Registry Run Keys) <br/> * T1059: Command and Scripting Interpreter |
| Observables & Indicateurs de compromission | * hxxp://www.npmjs.com/package/axios/v/0.30.4 <br/> * plain-crypto-js (dépendance malveillante) <br/> * msbuild.exe (implant déguisé sur Windows) |

### Source (url) du ou des articles
* https://www.elastic.co/security-labs/how-we-caught-the-axios-supply-chain-attack
* https://www.helpnetsecurity.com/2026/04/02/supply-chain-hacks-data-theft/
<br>
<br>

<div id="guide-de-developpement-contre-le-malware-brickstorm-ciblant-vsphere"></div>

## vSphere and BRICKSTORM Malware: A Defender's Guide
Le malware BRICKSTORM cible spécifiquement les infrastructures VMware vSphere, en particulier vCenter (VCSA) et les hyperviseurs ESXi. Les attaquants exploitent des architectures de sécurité faibles et l'absence de MFA sur les comptes d'administration pour établir une persistance au niveau de la couche de virtualisation. Une fois vCenter compromis, l'attaquant obtient un contrôle total sur toutes les machines virtuelles, contournant les permissions au niveau OS via l'accès direct aux fichiers VMDK. Le malware utilise des techniques d'aveuglement des journaux et des binaires natifs pour rester discret. Mandiant souligne que les agents EDR classiques ne supportent pas ces plans de contrôle, créant un déficit de visibilité critique. La stratégie de défense recommandée repose sur le durcissement de la couche Photon Linux et l'utilisation de scripts d'automatisation de la sécurité.

**Analyse de l'impact** : Risque critique de compromission de la "Tier-0" de l'infrastructure, permettant l'exfiltration silencieuse de bases de données NTDS.dit et la destruction complète des capacités de restauration.

**Recommandations** : Utiliser le script de durcissement vCenter de Mandiant. Imposer le MFA pour toutes les sessions SSO vsphere.local. Isoler les interfaces de gestion (VAMI port 5480, SSH port 22) derrière des stations de travail privilégiées (PAW). Activer le forwarding systématique des logs auditd vers un SIEM externe.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié (campagne d'espionnage BRICKSTORM) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1068: Exploitation for Privilege Escalation <br/> * T1098.004: Account Manipulation (SSH Authorized Keys) <br/> * T1484.002: Domain Policy Modification (Group Policy Plugin) |
| Observables & Indicateurs de compromission | * VCSA_FW_DROP (logs iptables custom) <br/> * /etc/audisp/plugins.d/syslog.conf (désactivation du pont de log) <br/> * SLAYSTYLE (malware lié) |

### Source (url) du ou des articles
* https://cloud.google.com/blog/topics/threat-intelligence/vsphere-brickstorm-defender-guide/
<br>
<br>

<div id="analyse-technique-du-malware-qilin-edr-killer"></div>

## Qilin EDR killer infection chain
Le groupe de ransomware Qilin utilise une DLL malveillante "msimg32.dll" sophistiquée pour désactiver les solutions EDR avant l'exécution du payload final. L'infection se déroule en plusieurs étapes, utilisant le side-loading via des applications légitimes. Le chargeur (loader) utilise des exceptions VEH/SEH pour obscurcir son flux d'exécution et contourner les hooks en mode utilisateur via la technique "Halo's Gate". Il charge ensuite deux drivers ("rwdrv.sys" et "hlpdrv.sys") pour accéder directement à la mémoire physique du noyau. Ces drivers permettent d'écraser les objets du noyau et de supprimer les rappels (callbacks) de notification de création de processus des logiciels de sécurité. Le malware est capable de neutraliser plus de 300 drivers EDR différents de quasiment tous les éditeurs du marché.

**Analyse de l'impact** : Neutralisation totale des capacités de détection et de réponse sur l'hôte, laissant le champ libre au déploiement du ransomware sans aucune alerte SOC.

**Recommandations** : Surveiller l'utilisation anormale des drivers matériels comme TechPowerUp ThrottleStop (rwdrv.sys). Détecter les écritures via le syscall `bpf_probe_write_user`. Implémenter des règles de détection sur la modification de la section `.mrdata` de ntdll.dll.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Qilin (Agenda) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1562.001: Impair Defenses (Disable or Modify Tools) <br/> * T1574.002: DLL Side-Loading <br/> * T1014: Rootkit |
| Observables & Indicateurs de compromission | * 7787da25451f5538766240f4a8a2846d0a589c59391e15f188aa077e8b888497 (msimg32.dll) <br/> * 16f83f056177c4ec24c7e99d01ca9d9d6713bd0497eeedb777a3ffefa99c97f0 (rwdrv.sys) |

### Source (url) du ou des articles
* https://blog.talosintelligence.com/qilin-edr-killer/
<br>
<br>

<div id="operation-de-recolte-de-didentifiants-a-grande-echelle-via-react2shell"></div>

## UAT-10608: Inside a large-scale automated credential harvesting operation
Une campagne massive automatisée, orchestrée par le groupe UAT-10608, cible les applications Next.js vulnérables à React2Shell (CVE-2025-55182). Plus de 760 hôtes ont été compromis en 24 heures à travers divers fournisseurs cloud. L'attaquant utilise une désérialisation non sécurisée dans les React Server Components pour obtenir une exécution de code à distance (RCE) pré-authentification. Un script de récolte automatisé extrait ensuite les variables d'environnement, les clés SSH, les tokens Kubernetes, et les secrets cloud (AWS/Azure/GCP). Les données sont centralisées sur un serveur C2 via une interface nommée "NEXUS Listener". Cette interface permet aux attaquants de naviguer dans les secrets de chaque victime avec des statistiques détaillées.

**Analyse de l'impact** : Risque extrême de compromission en cascade (supply chain) et de mouvement latéral dans le cloud grâce aux clés d'accès volées (Stripe, AWS, GitHub).

**Recommandations** : Mettre à jour Next.js vers une version corrigée. Imposer l'utilisation de IMDSv2 sur toutes les instances AWS pour bloquer l'extraction de métadonnées. Auditer les composants web pour détecter toute utilisation de `__NEXT_DATA__` contenant des secrets.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UAT-10608 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br/> * T1555.004: Credentials from Private Sources <br/> * T1552.004: Private Keys |
| Observables & Indicateurs de compromission | * 144[.]172[.]102[.]88 <br/> * 172[.]86[.]127[.]128 <br/> * .eba9ee1e4.sh (script dans /tmp) |

### Source (url) du ou des articles
* https://blog.talosintelligence.com/uat-10608-inside-a-large-scale-automated-credential-harvesting-operation-targeting-web-applications/
<br>
<br>

<div id="le-reseau-de-recrutement-international-des-travailleurs-it-nord-coreens-nkitw"></div>

## Code Names, Fake Personas, and Iranian Recruits: NKITW Operation
Le régime nord-coréen a étendu son programme d'infiltration de travailleurs IT (NKITW) en recrutant activement des ingénieurs en Iran, Syrie et Arabie Saoudite. Ces recrues servent de prête-noms et effectuent les entretiens techniques en anglais pour le compte des agents de la RPDC. L'objectif est de contourner les sanctions internationales et d'infiltrer les entreprises de défense, les banques et les plateformes de cryptomonnaies occidentales. Des documents internes révèlent des plans d'embauche structurés avec des quotas d'applications quotidiennes (plus de 100 par profil). Les travailleurs IT utilisent de faux profils LinkedIn et des facilitateurs aux États-Unis pour recevoir les ordinateurs portables de travail. Michael et Lander sont des noms de code identifiés comme gérant ces cellules de recrutement. Le programme offre des salaires attractifs en cryptomonnaies pour inciter les développeurs de pays sous sanctions à participer à la fraude.

**Analyse de l'impact** : Infiltration massive d'agents hostiles au sein de secteurs critiques, permettant l'exfiltration continue de propriété intellectuelle et de fonds financiers vers la Corée du Nord.

**Recommandations** : Renforcer les processus de vérification d'identité lors des entretiens (biométrie, vérification de l'arrière-plan vidéo). Surveiller les adresses IP d'accès VPN des employés pour détecter des incohérences géographiques extrêmes. Vérifier l'authenticité des historiques GitHub et LinkedIn des candidats.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | NKITW (Corée du Nord) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566: Phishing <br/> * T1078.004: Cloud Accounts <br/> * T1098: Account Manipulation |
| Observables & Indicator de compromission | * 192.168.109.2 (IP de plateforme back-office interne) <br/> * Michael / Lander (alias d'opérateurs) |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/iranian-recruits-inside-the-nkitw-operation
<br>
<br>

<div id="impersonnalisation-du-cert-ua-par-lacteur-uac-0255"></div>

## Threat actor UAC-0255 impersonate CERT-UA
L'acteur pro-russe UAC-0255 (CyberSerp) a mené une campagne de phishing massive impersonnalisant le CERT-UA. Environ 1 million d'utilisateurs ont reçu des emails les alertant d'une cyberattaque russe imminente et les incitant à installer un faux "outil de sécurité". Le lien menait vers un site contrefait (cert-ua[.]tech) hébergeant une archive contenant le malware AGEWHEEZE. Ce RAT écrit en Go utilise des WebSockets pour son C2 et permet une prise de contrôle totale de l'hôte (exécution de commandes, capture d'écran, vol de presse-papier). Bien que l'acteur revendique 200 000 infections, l'impact réel semble limité à quelques institutions éducatives. Le site malveillant a probablement été généré par IA pour augmenter sa crédibilité.

**Analyse de l'impact** : Atteinte à la crédibilité des autorités de cyberdéfense ukrainiennes et risque d'infection systémique des infrastructures critiques par un RAT persistant.

**Recommandations** : Bloquer le domaine `cert-ua[.]tech`. Déployer des politiques AppLocker pour interdire l'exécution de binaires non autorisés depuis le répertoire AppData. Sensibiliser les utilisateurs aux méthodes d'impersonnalisation des autorités officielles.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UAC-0255 (CyberSerp) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.002: Spearphishing Link <br/> * T1071.001: Web Protocols (WebSockets) <br/> * T1547.001: Registry Run Keys |
| Observables & Indicateurs de compromission | * cert-ua[.]tech <br/> * protection_tool.zip <br/> * AGEWHEEZE (famille de malware) |

### Source (url) du ou des articles
* https://securityaffairs.com/190287/hacking/threat-actor-uac-0255-impersonate-cert-ua-to-spread-agewheeze-malware-via-phishing.html
* https://sploited.blog/2026/04/02/weekly-threat-landscape-thursday-roundup-2/
<br>
<br>

<div id="ciblage-des-appareils-ios-par-le-groupe-ta446-coldriver"></div>

## Russian FSB-Linked Group Targets iOS Devices with DarkSword Exploit
Le groupe TA446 (Coldriver), affilié au FSB russe, utilise désormais un exploit iOS fuité nommé "DarkSword". Cette campagne cible des diplomates, des personnels gouvernementaux et des experts en politique internationale via des emails de spear-phishing imitant l'Atlantic Council. L'exploit permet une compromission avec peu ou pas d'interaction utilisateur, autorisant la surveillance des communications et l'exfiltration de données sensibles depuis les iPhones. Cette transition vers l'exploitation mobile sophistiquée marque un changement stratégique pour Coldriver, historiquement focalisé sur le vol d'identifiants web. L'absence de persistance binaire classique rend l'analyse forensique difficile sur les appareils infectés.

**Analyse de l'impact** : Menace directe contre la confidentialité des communications diplomatiques et gouvernementales de haut niveau. Invalidation du dogme de l'invulnérabilité relative d'iOS contre les acteurs étatiques.

**Recommandations** : Appliquer immédiatement les mises à jour de sécurité iOS. Activer le "Lockdown Mode" pour les profils à haut risque. Surveiller les connexions réseau sortantes inhabituelles depuis les terminaux mobiles via une solution de Mobile Threat Defense (MTD).

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TA446 (Coldriver / Callisto) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1203: Exploitation for Client Execution <br/> * T1566.002: Spearphishing Link <br/> * T1005: Data from Local System |
| Observables & Indicateurs de compromission | * DarkSword (chaîne d'exploit iOS) <br/> * Emails imitant l'Atlantic Council |

### Source (url) du ou des articles
* https://sploited.blog/2026/04/02/weekly-threat-landscape-thursday-roundup-2/
<br>
<br>

<div id="restauration-de-stryker-apres-lattaque-wiper-de-handala-hack"></div>

## Medtech giant Stryker fully operational after data-wiping attack
Le géant de la technologie médicale Stryker a annoncé avoir retrouvé sa pleine capacité opérationnelle trois semaines après une attaque dévastatrice par un malware wiper. L'attaque, revendiquée par le groupe pro-iranien Handala Hack, avait entraîné l'effacement de près de 80 000 appareils. Les attaquants ont utilisé un compte Global Administrator créé après avoir compromis un compte admin de domaine Windows, pour ensuite abuser de Microsoft Intune afin de diffuser l'ordre de destruction. Les experts ont découvert un fichier malveillant utilisé pour masquer les activités des attaquants durant l'intrusion. Stryker a priorisé la restauration des systèmes de commande et d'expédition pour minimiser l'impact sur les soins aux patients. Des actions de groupe (class-action) réclamant 20 millions de dollars sont en cours suite à l'incident.

**Analyse de l'impact** : Perturbation majeure d'une entreprise Fortune 500, illustrant la dangerosité des wipers utilisés comme arme de coercition géopolitique. Impact financier et juridique significatif.

**Recommandations** : Durcir les configurations Microsoft Intune (MFA sur les actions critiques, approbation multi-administrateurs). Surveiller la création de nouveaux comptes Global Admin. Maintenir des sauvegardes déconnectées (air-gapped) pour permettre une reconstruction totale.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Handala Hack (lié à l'Iran / Void Manticore) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1485: Data Destruction <br/> * T1078.003: Cloud Accounts <br/> * T1496: Resource Hijacking |
| Observables & Indicateurs de compromission | * Abus de Microsoft Intune pour le déploiement du wiper <br/> * stryker.com identifiants compromis |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/medtech-giant-stryker-fully-operational-after-data-wiping-attack/
* https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict
<br>
<br>

<div id="augmentation-des-cyberattaques-mirai-contre-les-infrastructures-françaises"></div>

## Cyberattacks on France Are Rising—Here’s What the AIDE Data Shows
La Global Cyber Alliance (GCA) a observé un triplement des cyberattaques ciblant les réseaux français entre mai 2025 et février 2026. Cette augmentation est principalement portée par des botnets de la famille Mirai (variantes LZRD, SORA). Un pic distinct d'attaques originaires d'infrastructures françaises a été noté en décembre 2025, indiquant une vague d'infections d'appareils locaux. Les cibles incluent des ministères, le service postal français (La Poste) et des infrastructures bancaires. Les données révèlent une persistance des infrastructures d'attaque, avec des adresses IP ciblant de manière répétée les mêmes capteurs sur plusieurs mois. Les Pays-Bas, le Vietnam et l'Allemagne sont les principales sources géographiques des flux d'attaque entrants vers la France.

**Analyse de l'impact** : Risque de déni de service distribué (DDoS) massif contre les services publics essentiels et saturation des capacités de réponse aux incidents des opérateurs d'infrastructures vitales.

**Recommandations** : Appliquer strictement les bonnes pratiques de sécurité IoT (changement des mots de passe par défaut, fermeture des ports non nécessaires). Surveiller les flux sortants vers les infrastructures de C2 connues de Mirai. Mettre en place des solutions de protection DDoS en amont des services critiques.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Botnets famille Mirai (LZRD, SORA, Cult) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1595: Active Scanning <br/> * T1498: DDoS <br/> * T1046: Network Service Scanning |
| Observables & Indicateurs de compromission | * hxxp://cert.ssi.gouv.fr/uploads/CERTFR-2025-CTI-007.pdf <br/> * Signatures malwares Mirai.A, Mirai.D |

### Source (url) du ou des articles
* https://globalcyberalliance.org/cyberattacks-on-france-are-rising-heres-what-the-aide-data-shows/
<br>
<br>

<div id="vulnerabilites-critiques-cisco-imc-et-ssm-on-prem"></div>

## Critical Cisco IMC auth bypass gives attackers Admin access
Cisco a publié des correctifs pour plusieurs vulnérabilités critiques, dont un bypass d'authentification dans le contrôleur de gestion intégré (IMC). La faille CVE-2026-20093 permet à un attaquant distant non authentifié de réinitialiser les mots de passe de tous les utilisateurs, y compris Admin, via une requête HTTP forgée. Parallèlement, une faille RCE critique (CVE-2026-20160) dans Cisco Smart Software Manager On-Prem permet l'exécution de commandes avec les privilèges root. Ces composants sont essentiels pour la gestion "hors bande" des serveurs UCS. Aucune exploitation active n'est signalée à ce jour pour ces failles spécifiques, mais Cisco conseille une mise à jour immédiate. L'entreprise a également rappelé la compromission récente de son environnement de développement suite à un vol d'identifiants.

**Analyse de l'impact** : Prise de contrôle totale du matériel serveur physique, indépendamment de l'OS installé, permettant l'installation de rootkits matériels et l'espionnage persistant.

**Recommandations** : Mettre à jour Cisco IMC vers les versions 4.15.5+, 4.18.3+ ou 6.0(1.250174)+ selon le modèle. Isoler les réseaux de gestion matérielle (OOB) dans des VLANs strictement contrôlés. Auditer les accès administratifs aux serveurs UCS.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non mentionné (exploité potentiellement par des acteurs d'espionnage) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1556: Modify Authentication Process <br/> * T1210: Exploitation of Remote Services |
| Observables & Indicateurs de compromission | * Requêtes HTTP ciblant les endpoints de changement de mot de passe CIMC |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/critical-cisco-imc-auth-bypass-gives-attackers-admin-access/
* https://securityaffairs.com/190295/security/cisco-fixed-critical-and-high-severity-flaws.html
<br>
<br>