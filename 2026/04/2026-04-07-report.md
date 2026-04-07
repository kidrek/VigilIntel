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
  * [Fortinet : Exploitation active de la vulnérabilité critique CVE-2026-35616](#fortinet-exploitation-active-de-la-vulnerabilite-critique-cve-2026-35393)
  * [BlueHammer : Fuite d'un exploit Zero-Day pour Windows](#bluehammer-fuite-dun-exploit-zero-day-pour-windows)
  * [Drift Protocol : Vol de 280M$ par ingénierie sociale physique (Lazarus)](#drift-protocol-vol-de-280m-par-ingenierie-sociale-physique-lazarus)
  * [Storm-1175 : L'élite du Ransomware Medusa et l'exploitation ultra-rapide](#storm-1175-lelite-du-ransomware-medusa-et-lexploitation-ultra-rapide)
  * [GPUBreach : Prise de contrôle système via Rowhammer sur GPU](#gpubreach-prise-de-controle-systeme-via-rowhammer-sur-gpu)
  * [Doxxing des leaders de REvil et GandCrab par la police allemande](#doxxing-des-leaders-de-revil-et-gandcrab-par-la-police-allemande)
  * [Menaces sur Kubernetes : Augmentation massive des vols de jetons](#menaces-sur-kubernetes-augmentation-massive-des-vols-de-jetons)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage actuel de la menace est marqué par une accélération sans précédent du cycle d'exploitation, où des groupes comme Storm-1175 (Medusa) militarisent des vulnérabilités moins de 24 heures après leur divulgation. L'émergence de techniques d'ingénierie sociale "physique", orchestrées par des acteurs nord-coréens lors de conférences internationales pour compromettre des protocoles DeFi comme Drift, démontre un investissement opérationnel sur le long terme (6 mois). Parallèlement, le conflit US-Israël-Iran atteint un point de rupture cyber-cinétique, avec des menaces directes contre 18 géants technologiques américains et des infrastructures énergétiques. L'IA générative transforme également la découverte de vulnérabilités en un défi de capacité de traitement pour les mainteneurs de logiciels libres. On observe une résurgence des attaques matérielles sophistiquées, à l'instar de GPUBreach, contournant les protections IOMMU via la mémoire vidéo. Enfin, le doxxing des cadres de REvil prouve une efficacité accrue de la coopération policière internationale, malgré l'impunité relative offerte par certains territoires. Cette période exige une réactivité immédiate sur le patching des actifs périmétriques et une vigilance accrue lors des interactions humaines de haut niveau.
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
| **Handala** | Israël (Défense, Infrastructures) | Brute-force VPN, Wiper-as-a-Service, exfiltration de données. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| **IRGC** (Gardiens de la Révolution) | Technologie, Énergie, Finance (USA/EAU) | Désignation de cibles stratégiques, menaces hybrides cyber-cinétiques. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| **Lazarus** (Slow Pisces / UNC4736) | Crypto-monnaie, Finance, Cloud | Ingénierie sociale physique (conférences), vol de jetons Kubernetes/AWS. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/drift-280m-crypto-theft-linked-to-6-month-in-person-operation/), [Unit 42](https://unit42.paloaltonetworks.com/modern-kubernetes-threats/) |
| **REvil / GandCrab** | Multi-sectoriel (Global) | Ransomware-as-a-Service (RaaS), double extorsion. | [Krebs on Security](https://krebsonsecurity.com/2026/04/germany-doxes-unkn-head-of-ru-ransomware-gangs-revil-gandcrab/) |
| **Storm-1175** (Affilié Medusa) | Santé, Éducation, Finance | Exploitation ultra-rapide de 0-days et N-days sur actifs web. | [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/04/06/storm-1175-focuses-gaze-on-vulnerable-web-facing-assets-in-high-tempo-medusa-ransomware-operations/) |
| **UNC1069** | Supply Chain (npm) | Compromission du package Axios pour livrer des chevaux de Troie. | [Security Affairs](https://securityaffairs.com/190413/uncategorized/phishing-lnk-files-and-github-c2-power-new-dprk-cyber-attacks.html) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| États-Unis / Iran | Conflit Cyber-Cinétique | Expiration de l'ultimatum américain sur le détroit d'Ormuz ; risque maximal de cyber-représailles contre l'énergie. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Technologie / Défense | Liste de cibles IRGC | L'Iran désigne 18 entreprises technologiques US (Microsoft, Google, Apple, etc.) comme cibles légitimes. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Iran | Blackout Internet | L'Iran entre dans son 38ème jour de coupure quasi-totale d'internet au niveau national. | [Check Point](https://research.checkpoint.com/2026/6th-march-threat-intelligence-report-2/) |
| Turquie / Europe | Industrie de Défense | Dilemme européen sur les partenariats militaires avec la Turquie face à sa montée en puissance technologique. | [Portail de l'IE](https://www.portail-ie.fr/univers/defense-industrie-de-larmement-et-renseignement/2026/industrie-defense-turque-partenariat-europe/) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif des articles juridiques relatifs à la réglementation cyber :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Maine House advances hospital cybersecurity bill | Maine House Democrats | 06/04/2026 | Maine, USA | LD 2103 | Obligation pour les hôpitaux d'adopter des plans de continuité et des standards de sécurité cyber. | [DataBreaches](https://databreaches.net/2026/04/06/maine-house-advances-mccabe-bill-to-strengthen-cybersecurity-at-maine-hospitals/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Éducation | Écoles de New York | Augmentation de 72 % des incidents de données scolaires en 2025. | [DataBreaches](https://databreaches.net/2026/04/06/nys-school-data-incidents-rose-72-in-2025-with-44-reported-on-long-island/) |
| Gouvernement | Commission Européenne | Compromission via une plateforme tierce liée à l'attaque de la chaîne logistique Trivy. | [Check Point](https://research.checkpoint.com/2026/6th-march-threat-intelligence-report-2/) |
| Industrie | Hasbro | Détection d'un accès non autorisé au réseau ; systèmes mis hors ligne. | [Check Point](https://research.checkpoint.com/2026/6th-march-threat-intelligence-report-2/) |
| Juridique | DocketWise | Violation de données affectant les informations personnelles de clients de cabinets d'immigration. | [DataBreaches](https://databreaches.net/2026/04/06/two-data-security-incidents-affected-immigration-law-firms-and-their-clients/) |
| Loisirs | Roan & Eurocamp | Fuite de données clients utilisées pour des arnaques au paiement via WhatsApp. | [Check Point](https://research.checkpoint.com/2026/6th-march-threat-intelligence-report-2/) |
| Santé | Valley Family Health Care | Affecté par la violation de TriZetto Provider Solutions (TPS) touchant 4 300 patients. | [DataBreaches](https://databreaches.net/2026/04/06/two-breaches-one-quarter-valley-family-health-cares-challenging-start-to-2026/) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité.
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| **CVE-2026-34838** | 10.0 | N/A | FALSE | GroupOffice CRM | Désérialisation non sécurisée | Non mentionnées | Permet une exécution de code à distance (RCE) via une chaîne POP utilisant Guzzle. | [SecurityOnline](https://securityonline.info/groupoffice-cve-2026-34838-insecure-deserialization-rce/) |
| **CVE-2026-0740** | 9.8 | N/A | FALSE | Ninja Forms (WordPress) | Téléchargement de fichier non sécurisé | Non mentionnées | Un attaquant peut uploader des fichiers PHP et obtenir une RCE. | [SecurityOnline](https://securityonline.info/ninja-forms-file-upload-rce-vulnerability-cve-2026-0740/) |
| **CVE-2025-53521** | 9.8 | N/A | TRUE | F5 BIG-IP APM | Exécution de code à distance (RCE) | Non mentionnées | Trafic malveillant spécifique déclenchant une RCE sur les serveurs virtuels. | [Security Affairs](https://securityaffairs.com/190384/security/attackers-exploit-rce-flaw-as-14000-f5-big-ip-apm-instances-remain-exposed.html) |
| **CVE-2026-35616** | 9.1 | N/A | TRUE | Fortinet FortiClient EMS | Contrôle d'accès incorrect | Non mentionnées | Bypass d'authentification API permettant l'exécution de code ou de commandes. | [Fortinet](https://fieldeffect.com/blog/fortinet-releases-forticlient-ems-hotfix) |
| **CVE-2026-35393** | N/A | N/A | FALSE | goshs | Path Traversal | Non mentionnées | Permet l'écriture de fichiers n'importe où sur le système via des uploads POST. | [OffSeq](https://infosec.exchange/@offseq/116360834428673806) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| German authorities identify REvil and GangCrab ransomware bosses | Identification majeure de leaders de cybercriminalité historique. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/german-authorities-identify-revil-and-gangcrab-ransomware-bosses/) |
| Drift $280M crypto theft linked to 6-month in-person operation | Mode opératoire d'ingénierie sociale physique exceptionnel par le groupe Lazarus. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/drift-280m-crypto-theft-linked-to-6-month-in-person-operation/) |
| New GPUBreach attack enables system takeover via GPU rowhammer | Menace technologique avancée sur le matériel GPU. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-gpubreach-attack-enables-system-takeover-via-gpu-rowhammer/) |
| Disgruntled researcher leaks “BlueHammer” Windows zero-day exploit | Menace immédiate suite à la fuite publique d'un exploit zero-day OS. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/disgruntled-researcher-leaks-bluehammer-windows-zero-day-exploit/) |
| Storm-1175 focuses gaze on vulnerable web-facing assets | Analyse détaillée d'un acteur ransomware à haute vélocité. | [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/04/06/storm-1175-focuses-gaze-on-vulnerable-web-facing-assets-in-high-tempo-medusa-ransomware-operations/) |
| Understanding Current Threats to Kubernetes Environments | Étude critique sur l'augmentation des attaques d'identité Cloud/Kubernetes. | [Unit 42](https://unit42.paloaltonetworks.com/modern-kubernetes-threats/) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| ISC Stormcast For Tuesday, April 7th, 2026 | Format podcast trop générique, informations couvertes par d'autres articles détaillés. | [ISC SANS](https://isc.sans.edu/podcastdetail/9882) |
| SpaceCoastSec Meetup | Événement communautaire local sans valeur analytique de menace. | [Mastodon](https://mastodon.social/@spacecoastsec/116360176792335021) |
| Even experienced devs often hardcode API keys | Conseil de sécurité généraliste sans actualité spécifique. | [Mastodon](https://mastodon.social/@threatchain/116360538159089020) |
| Microsoft fixes Classic Outlook bug | Bug fonctionnel de livraison d'emails sans impact cyber majeur direct. | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-fixes-classic-outlook-bug-causing-email-delivery-issues/) |

<br>
<br>
<div id="articles"></div>

# ARTICLES

<div id="fortinet-exploitation-active-de-la-vulnerabilite-critique-cve-2026-35393"></div>

## Fortinet : Exploitation active de la vulnérabilité critique CVE-2026-35616
Une vulnérabilité critique d'improper access control (CVE-2026-35616) affecte les versions 7.4.5 et 7.4.6 de FortiClient Enterprise Management Server (EMS). Cette faille permet à un attaquant non authentifié de bypasser les vérifications de l'API EMS via des requêtes HTTP forgées. Des tentatives d'exploitation en mode "zero-day" ont été observées dès le 31 mars 2026. Une fois l'authentification contournée, l'attaquant obtient des privilèges administratifs complets sur le serveur. Ce contrôle permet de modifier les politiques de sécurité des endpoints et de distribuer des charges utiles malveillantes aux appareils enrôlés. CISA a ajouté cette vulnérabilité à son catalogue KEV le 6 avril avec un délai de remédiation très court. Le score CVSS est évalué à 9.1 ou 9.8 selon les sources, soulignant sa dangerosité extrême. Fortinet a publié un hotfix d'urgence en attendant la version permanente 7.4.7. Les instances exposées sur internet sont les plus à risque.

**Analyse de l'impact** : L'impact est majeur car le serveur EMS centralise la gestion de la sécurité de tout le parc informatique ; sa compromission équivaut à un contrôle total sur les postes de travail et serveurs de l'entreprise.

**Recommandations** :
* Appliquer immédiatement le hotfix Fortinet pour les versions EMS 7.4.5 et 7.4.6.
* Restreindre l'accès à l'interface API EMS aux réseaux de confiance uniquement (VPN, proxy d'identité).
* Analyser les logs API pour détecter des appels inhabituels ou des exécutions de commandes suspectes remontant jusqu'au 31 mars 2026.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié (exploitation opportuniste détectée par watchTowr) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application |
| Observables & Indicateurs de compromission | ```Requêtes HTTP malveillantes vers les endpoints de l'API EMS.``` |

### Source (url) du ou des articles
* https://fieldeffect.com/blog/fortinet-releases-forticlient-ems-hotfix
* https://cybersecuritynews.com/cisa-warns-fortinet-vulnerability/
* https://go.theregister.com/feed/www.theregister.com/2026/04/06/forticlient_ems_bug_exploited/

<br>
<br>

<div id="bluehammer-fuite-dun-exploit-zero-day-pour-windows"></div>

## BlueHammer : Fuite d'un exploit Zero-Day pour Windows
Un chercheur en sécurité mécontent du traitement de son rapport par Microsoft a publié un exploit fonctionnel pour une vulnérabilité de Windows baptisée "BlueHammer". Cette faille de type Local Privilege Escalation (LPE) combine un TOCTOU (time-of-check to time-of-use) et une confusion de chemin. L'exploit permet à un utilisateur local d'accéder à la base de données SAM (Security Account Manager) qui contient les condensats de mots de passe. En obtenant ces accès, un attaquant peut élever ses privilèges jusqu'au niveau SYSTEM, prenant ainsi le contrôle total de la machine. L'exploit a été confirmé comme fonctionnel sur les versions clientes de Windows, bien que des instabilités subsistent sur Windows Server. Microsoft considère cette faille comme un Zero-day puisqu'aucun correctif n'est disponible à ce jour. Le code a été diffusé via un dépôt GitHub par l'alias "Chaotic Eclipse".

**Analyse de l'impact** : Risque élevé de compromission complète des postes de travail par des utilisateurs malveillants ou via des logiciels malveillants déjà présents sur le système.

**Recommandations** :
* Surveiller les accès inhabituels aux fichiers de la base SAM.
* Limiter l'accès physique et logique aux machines sensibles jusqu'à la sortie d'un patch officiel.
* Renforcer la surveillance des processus suspects tentant de spawner un shell avec les privilèges SYSTEM.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Chaotic Eclipse / Nightmare-Eclipse (chercheur) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1068: Exploitation for Privilege Escalation <br/> * T1003.002: Security Account Manager |
| Observables & Indicateurs de compromission | ```Dépôt GitHub Nightmare-Eclipse/BlueHammer (PoC).``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/disgruntled-researcher-leaks-bluehammer-windows-zero-day-exploit/

<br>
<br>

<div id="drift-protocol-vol-de-280m-par-ingenierie-sociale-physique-lazarus"></div>

## Drift Protocol : Vol de 280M$ par ingénierie sociale physique (Lazarus)
Le protocole Drift (Solana) a été victime d'un vol de 280 millions de dollars suite à une opération de longue haleine attribuée au groupe nord-coréen Lazarus (UNC4736). L'attaque se distingue par l'utilisation d'une infiltration physique : les attaquants ont rencontré des contributeurs de Drift en personne lors de conférences crypto mondiales. Se faisant passer pour une société de trading quantitatif, ils ont tissé des liens pendant six mois via Telegram. L'accès initial a probablement été obtenu via un dépôt de code malveillant partagé ou une application de test compromise (TestFlight). Les attaquants ont ensuite pris le contrôle du Conseil de Sécurité pour drainer les fonds en seulement 12 minutes. Cette opération montre un niveau de sophistication extrême, mélangeant espionnage humain et cybercriminalité financière.

**Analyse de l'impact** : Impact dévastateur sur l'écosystème DeFi Solana et démonstration d'une nouvelle frontière dans les méthodes d'accès initial.

**Recommandations** :
* Instaurer des procédures de vérification strictes pour tout nouveau partenaire ou collaborateur rencontré lors d'événements.
* Auditer les outils de développement (VSCode/Cursor) et interdire l'utilisation d'applications non vérifiées via TestFlight.
* Mettre en place des délais de retrait (timelocks) sur les pouvoirs administratifs multisig.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UNC4736 (Lazarus / AppleJeus) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566: Phishing <br/> * T1591: Gather Victim Org Information |
| Observables & Indicateurs de compromission | ```Comptes Telegram supprimés post-attaque.``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/drift-280m-crypto-theft-linked-to-6-month-in-person-operation/

<br>
<br>

<div id="storm-1175-lelite-du-ransomware-medusa-et-lexploitation-ultra-rapide"></div>

## Storm-1175 : L'élite du Ransomware Medusa et l'exploitation ultra-rapide
Storm-1175, un groupe cybercriminel basé en Chine, mène des campagnes de ransomware Medusa à une vélocité exceptionnelle. Le groupe cible les vulnérabilités sur les systèmes web-facing dès leur divulgation, parfois moins de 24 heures après l'annonce (ex: CVE-2025-31324 sur SAP NetWeaver). Ils utilisent également des vulnérabilités zero-day, notamment sur SmarterMail (CVE-2026-23760) et GoAnywhere MFT. Leur chaîne d'attaque est optimisée pour passer de l'accès initial à l'exfiltration de données en quelques jours, voire 24 heures. Ils privilégient les outils RMM (Atera, AnyDesk) pour la persistance et Rclone pour l'exfiltration massive. La phase finale utilise souvent PDQ Deployer pour distribuer la charge utile Medusa sur l'ensemble du réseau compromis.

**Analyse de l'impact** : Risque critique pour les organisations de santé, d'éducation et de finance en raison de la rapidité de l'impact (moins de 24h).

**Recommandations** :
* Patching ultra-rapide (moins de 24h) pour tout actif exposé sur internet.
* Activer la protection anti-tamper sur les solutions EDR/AV pour empêcher la désactivation des protections.
* Surveiller et bloquer l'utilisation non autorisée d'outils de synchronisation comme Rclone.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Storm-1175 (affilié Medusa) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br/> * T1021.001: Remote Desktop Protocol <br/> * T1567.002: Exfiltration to Cloud Storage |
| Observables & Indicateurs de compromission | ```IPs: 185.135.86.149, 134.195.91.224 / SHA-256: 0cefeb6210b7103fd32b996beff518c9b6e1691a97bb1cda7f5fb57905c4be96``` |

### Source (url) du ou des articles
* https://www.microsoft.com/en-us/security/blog/2026/04/06/storm-1175-focuses-gaze-on-vulnerable-web-facing-assets-in-high-tempo-medusa-ransomware-operations/
* https://securityonline.info/storm-1175-medusa-ransomware-high-velocity-attacks/

<br>
<br>

<div id="gpubreach-prise-de-controle-systeme-via-rowhammer-sur-gpu"></div>

## GPUBreach : Prise de contrôle système via Rowhammer sur GPU
Des chercheurs de l'Université de Toronto ont présenté "GPUBreach", une attaque exploitant le phénomène Rowhammer sur les mémoires GDDR6 des GPU. Contrairement aux attaques précédentes, GPUBreach permet une élévation de privilèges jusqu'au niveau root sans avoir à désactiver l'IOMMU (Input-Output Memory Management Unit). En induisant des inversions de bits (bit-flips) dans les tables de pages du GPU, un noyau CUDA non privilégié peut obtenir un accès complet en lecture/écriture à la mémoire système. Cette capacité est ensuite couplée à l'exploitation de bugs de sécurité mémoire dans les pilotes NVIDIA pour compromettre l'hôte CPU. L'attaque a été démontrée sur des GPU NVIDIA RTX A6000, couramment utilisés pour l'entraînement d'IA.

**Analyse de l'impact** : Menace sérieuse pour les environnements de Cloud et d'IA où des utilisateurs tiers peuvent exécuter du code sur des ressources GPU partagées.

**Recommandations** :
* Activer le mode ECC (Error-Correcting Code) au niveau système sur les GPU compatibles.
* Isoler physiquement les workloads GPU critiques.
* Mettre à jour les pilotes NVIDIA dès la sortie des patches de sécurité mentionnant les protections contre Rowhammer.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable (recherche académique) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1068: Exploitation for Privilege Escalation <br/> * T1535: Unused/Unsupported Cloud Regions (via GPU manipulation) |
| Observables & Indicateurs de compromission | ```Comportements anormaux d'accès mémoire via CUDA.``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/new-gpubreach-attack-enables-system-takeover-via-gpu-rowhammer/

<br>
<br>

<div id="doxxing-des-leaders-de-revil-et-gandcrab-par-la-police-allemande"></div>

## Doxxing des leaders de REvil et GandCrab par la police allemande
La police fédérale allemande (BKA) a identifié officiellement deux ressortissants russes comme étant les leaders des opérations ransomware GandCrab et REvil entre 2019 et 2021. Daniil Maksimovich Shchukin (31 ans), connu sous l'alias "UNKN" ou "UNKNOWN", et Anatoly Sergeevitsch Kravchuk (43 ans) sont accusés d'avoir orchestré au moins 130 extorsions en Allemagne. Shchukin agissait comme le visage du groupe sur les forums cybercriminels (XSS). REvil, successeur de GandCrab, a été pionnier dans la "double extorsion". Le BKA a diffusé des photos et des détails personnels, incluant des tatouages, pour aider à leur localisation. Les autorités estiment qu'ils se trouvent actuellement en Russie, ce qui limite les possibilités d'arrestation immédiate.

**Analyse de l'impact** : Victoire symbolique et opérationnelle pour les forces de l'ordre, limitant la liberté de mouvement des acteurs ciblés et décourageant potentiellement d'autres cybercriminels.

**Recommandations** :
* Ne pas payer de rançon, car cela finance directement ces structures identifiées.
* Maintenir des sauvegardes hors ligne robustes, REvil étant spécialisé dans l'exfiltration et le chiffrement massif.
* Signaler toute activité suspecte liée aux alias identifiés aux autorités compétentes.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | REvil / GandCrab |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1486: Data Encrypted for Impact <br/> * T1021.001: RDP Lateral Movement |
| Observables & Indicateurs de compromission | ```Portefeuille crypto de Shchukin contenant plus de 317 000 $.``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/german-authorities-identify-revil-and-gangcrab-ransomware-bosses/
* https://krebsonsecurity.com/2026/04/germany-doxes-unkn-head-of-ru-ransomware-gangs-revil-gandcrab/

<br>
<br>

<div id="menaces-sur-kubernetes-augmentation-massive-des-vols-de-jetons"></div>

## Menaces sur Kubernetes : Augmentation massive des vols de jetons
Unit 42 (Palo Alto Networks) signale une augmentation de 282 % des opérations de vol de jetons Kubernetes en un an. Le secteur informatique est le plus touché (78 % de l'activité). L'attaque type consiste à obtenir une exécution de code initiale (via des vulnérabilités comme React2Shell - CVE-2025-55182), puis à extraire les jetons de compte de service (Service Account Tokens) montés dans les pods. Ces jetons sont ensuite utilisés pour interagir avec l'API Kubernetes, énumérer les secrets et pivoter vers l'infrastructure Cloud sous-jacente. Le groupe Lazarus a notamment utilisé ces techniques pour compromettre les systèmes financiers d'échanges de crypto-monnaies. Les mauvaises configurations de RBAC (Role-Based Access Control) restent le principal facilitateur de ces escalades de privilèges.

**Analyse de l'impact** : Risque systémique pour les infrastructures Cloud-native où une seule compromission de conteneur peut mener à un contrôle total du cluster et du compte Cloud.

**Recommandations** :
* Imposer le principe du moindre privilège via des rôles RBAC strictement limités.
* Utiliser des jetons de compte de service à durée de vie courte et projetés (projected tokens).
* Activer et surveiller les logs d'audit Kubernetes pour détecter des appels API anormaux.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Slow Pisces (Lazarus / TraderTraitor) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1613: Container and Resource Discovery <br/> * T1528: Steal Application Access Token |
| Observables & Indicateurs de compromission | ```Accès au fichier /var/run/secrets/kubernetes.io/serviceaccount/token par des processus inhabituels (curl, wget).``` |

### Source (url) du ou des articles
* https://unit42.paloaltonetworks.com/modern-kubernetes-threats/