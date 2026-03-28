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
  * [TeamPCP : Campagne massive de Supply Chain et extension vers PyPI](#teampcp-campagne-massive-de-supply-chain-et-extension-vers-pypi)
  * [Red Menshen : Espionnage étatique via BPFDoor dans les télécoms](#red-menshen-espionnage-etatique-via-bpfdoor-dans-les-telecoms)
  * [BRUSHWORM et BRUSHLOGGER : Menaces persistantes contre le secteur financier](#brushworm-et-brushlogger-menaces-persistantes-contre-le-secteur-financier)
  * [Campagne de phishing AITM ciblant TikTok Business](#campagne-de-phishing-aitm-ciblant-tiktok-business)
  * [Fausses alertes de sécurité VS Code sur GitHub](#fausses-alertes-de-securite-vs-code-sur-github)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage cyber actuel est marqué par une industrialisation sans précédent des attaques sur la chaîne d'approvisionnement (Supply Chain), illustrée par l'agressivité du groupe TeamPCP ciblant PyPI et GitHub. L'émergence de partenariats hybrides entre acteurs du cyberespionnage et opérateurs de ransomwares (Vect) signale une convergence dangereuse visant une exfiltration massive suivie d'une extorsion systématique. Parallèlement, les infrastructures critiques, notamment les télécoms au Moyen-Orient et en Asie, subissent des intrusions furtives de longue durée (Red Menshen) via des implants de niveau noyau (BPFDoor), rendant la détection traditionnelle inopérante. La compromis de comptes de hauts dirigeants (FBI, LiteLLM) confirme que le ciblage individuel reste le vecteur privilégié pour contourner les protections d'entreprise. On observe également une exploitation accrue des outils d'IA et de développement (Trivy, Spring AI, VS Code), transformant les instruments de sécurité en vecteurs d'infection. Les tensions géopolitiques autour de l'Iran et de la Chine catalysent des cyber-opérations de type "wiper" et d'espionnage académique, menaçant la souveraineté technologique occidentale. Face à ces menaces, la posture régalienne française privilégie une défense active structurée, tout en proscrivant fermement le "hack-back" privé pour éviter toute escalade incontrôlée. Une vigilance accrue sur la rotation atomique des secrets et le verrouillage des dépendances CI/CD est désormais une nécessité vitale pour les organisations.

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
| Handala | Gouvernemental (FBI), Médical (Stryker) | Piratage de boîtes mails personnelles, Wiper, influence propalestinienne | [Le Monde](https://www.lemonde.fr/pixels/article/2026/03/27/des-hackeurs-iraniens-revendiquent-le-piratage-de-la-boite-mail-personnelle-du-directeur-du-fbi_6674660_4408996.html) |
| LAPSUS$ | Pharmacie (AstraZeneca), Technologie | Extorsion de données, vol de dépôts de code source | [SANS ISC](https://isc.sans.edu/diary/32838) |
| Red Menshen | Télécommunications, Gouvernemental | Implants BPFDoor furtifs au niveau noyau (Linux/BSD), magic packets | [Security Affairs](https://securityaffairs.com/190029/malware/china-linked-red-menshen-apt-deploys-stealthy-bpfdoor-implants-in-telecom-networks.html) |
| ShinyHunters | Cybercriminalité (BreachForums) | Fuite de bases de données utilisateurs, gestion de forums underground | [HackRead](https://hackread.com/shinyhunters-breachforums-leak-300000-user-database/) |
| TeamPCP | Supply Chain (PyPI, GitHub), IA/ML | Compromission de packages (WAV steganography), vol de credentials, déploiement de wipers | [SANS ISC](https://isc.sans.edu/diary/32838) |
| Vect | Transversal (Affiliés) | Ransomware-as-a-Service (RaaS), partenariat avec TeamPCP | [SANS ISC](https://isc.sans.edu/diary/32838) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Gouvernemental | Commission Européenne | Enquête sur une intrusion majeure dans un environnement cloud AWS (350 Go de données volées). | [BleepingComputer](https://www.bleepingcomputer.com/news/security/european-commission-investigating-breach-after-amazon-cloud-account-hack/) |
| Éducation / Recherche | UK Universities | Mise en garde contre l'espionnage et les activités d'influence chinoises dans les universités britanniques. | [RUSI](https://www.rusi.org/explore-our-research/publications/commentary/who-pays-price-managing-china-related-risks-uk-universities) |
| Défense / Souveraineté | Iran / Moyen-Orient | Déploiement de capacités aéroterrestres US/Israël et multiplication des cyber-attaques wipers contre les infrastructures iraniennes. | [IRIS](https://www.iris-france.org/operations-aeroterrestres-sur-liran-de-quoi-parle-t-on/) |
| Sécurité Internationale | Diego Garcia (Océan Indien) | Attribution à l'Iran d'une attaque de missile contre une base anglo-américaine, sur fond de désinformation russe. | [EUvsDisinfo](https://euvsdisinfo.eu/disrupting-the-foundations-of-fimi/) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Active Cyber Defense Certainty Act | Nino Caraty | 27/03/2026 | États-Unis | Proposition de loi 2019 | Projet autorisant les mesures de défense active (hack-back) sous conditions de notification au FBI. | [Portail-IE](https://www.portail-ie.fr/univers/risques-et-gouvernance-cyber/2026/la-legitime-defense-numerique-les-entreprises-francaises-doivent-elles-sarmer-pour-maintenir-leur-perennite-et-leur-competitivite/) |
| Amende contre xAI (Grok) | HackerWorkspace | 27/03/2026 | Pays-Bas | Décision judiciaire | Menace d'amendes suite à la génération d'images nues non consensuelles par l'IA Grok. | [HackerWorkspace](https://hackerworkspace.com/article/dutch-court-threatens-xai-with-fines-over-grok-s-nonconsensual-nude-images) |
| Doctrine de lutte informatique offensive (LIO) | SGDSN / COMCYBER | 27/03/2026 | France | Cadre stratégique national | Rappel de la séparation stricte entre acteurs privés (défense) et État (seules armées habilitées à l'offensive). | [Portail-IE](https://www.portail-ie.fr/univers/risques-et-gouvernance-cyber/2026/la-legitime-defense-numerique-les-entreprises-francaises-doivent-elles-sarmer-pour-maintenir-leur-perennite-et-leur-competitivite/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Cybercriminalité | BreachForums V5 | Fuite de 339 778 comptes (emails, noms d'utilisateurs, hashs de mots de passe Argon2). | [HIBP](https://haveibeenpwned.com/Breach/BreachForumsV5) |
| Gouvernemental | Commission Européenne | Vol de 350 Go de données incluant des bases de données d'employés et des serveurs de messagerie. | [SecurityAffairs](https://securityaffairs.com/190067/data-breach/the-european-commission-confirmed-a-cyberattack-affecting-part-of-its-cloud-systems.html) |
| Gouvernemental | Police Néerlandaise | Compromission via phishing ; impact limité selon l'agence, pas d'accès aux données des citoyens. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/dutch-police-discloses-security-breach-after-phishing-attack/) |
| Gouvernemental | Shérif du comté de Jackson (USA) | Attaque par ransomware ayant paralysé l'ensemble du réseau et des systèmes de rapport. | [DataBreaches](https://databreaches.net/2026/03/27/ransomware-attack-totally-cripples-jackson-county-sheriffs-office-in-indiana/) |
| Pharmaceutique | AstraZeneca | Revendication de vol de 3 Go de données (code interne, configurations cloud, données employés) par LAPSUS$. | [SANS ISC](https://isc.sans.edu/diary/32838) |
| Sport | AFC Ajax | Accès non autorisé aux données des supporters et manipulation des systèmes de billetterie. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/ajax-football-club-hack-exposed-fan-data-enabled-ticket-hijack/) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2026-4681 | 10.0 | Non spécifié | FALSE | PTC Windchill & FlexPLM | Exécution de code à distance (RCE) via désérialisation | Non mentionnées | Vulnérabilité critique de désérialisation permettant une exécution de code à distance sans authentification. | [Security Affairs](https://securityaffairs.com/190049/security/cisa-and-bsi-warn-orgs-of-critical-ptc-windchill-and-flexplm-flaw.html) |
| CVE-2026-3055 | 9.3 | Non spécifié | FALSE | Citrix NetScaler ADC/Gateway | Fuite de mémoire (Session Hijacking) | Non mentionnées | Permet à un attaquant non authentifié de lire la mémoire sensible pour voler des jetons de session. | [Field Effect](https://fieldeffect.com/blog/netscaler-adc-gateway-vulnerabilities) |
| CVE-2026-33992 | 9.3 | Non spécifié | FALSE | pyLoad | Server-Side Request Forgery (SSRF) | Non mentionnées | L'absence de validation des URLs permet d'accéder aux métadonnées des fournisseurs cloud (ex: DigitalOcean). | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-33992) |
| CVE-2026-33634 | 9.3 | Non spécifié | TRUE | Aquasecurity Trivy | Supply Chain / Injection | Non mentionnées | Utilisation de credentials compromis pour diffuser des versions malveillantes via GitHub Actions. | [Security Affairs](https://securityaffairs.com/190044/security/u-s-cisa-adds-an-aquasecurity-trivy-flaw-to-its-known-exploited-vulnerabilities-catalog.html) |
| CVE-2026-22738 | 9.3 | Non spécifié | FALSE | Spring AI | RCE / SSRF | Non mentionnées | Vulnérabilités multiples permettant l'exécution de code et le contournement de politiques de sécurité. | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0365/) |
| CVE-2026-33991 | 8.8 | Non spécifié | FALSE | WeGIA | SQL Injection | Non mentionnées | Injection SQL dans `deletar_tag.php` via la fonction `extract($_REQUEST)` sans préparation de requête. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-33991) |
| CVE-2026-33981 | 8.3 | Non spécifié | FALSE | changedetection.io | Information Exposure | Non mentionnées | Fuite de variables d'environnement sensibles via l'utilisation de la commande `jq env` dans les filtres. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-33981) |
| CVE-2026-33980 | 8.3 | Non spécifié | FALSE | Azure Data Explorer | KQL Injection | Non mentionnées | Permet l'exécution de requêtes Kusto arbitraires via des f-strings non assainies. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-33980) |
| CVE-2026-4248 | 8.0 | Non spécifié | FALSE | WordPress Ultimate Member | Account Takeover | Non mentionnées | Fuite de jeton de réinitialisation de mot de passe via un shortcode, permettant la prise de contrôle d'un admin. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-4248) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| TeamPCP Supply Chain Campaign: Update 002 | Analyse exhaustive d'une menace supply chain majeure en cours. | [SANS ISC](https://isc.sans.edu/diary/rss/32838) |
| China-linked Red Menshen APT deploys stealthy BPFDoor implants | Analyse technique d'une campagne d'espionnage critique dans les télécoms. | [SecurityAffairs](https://securityaffairs.com/190029/malware/china-linked-red-menshen-apt-deploys-stealthy-bpfdoor-implants-in-telecom-networks.html) |
| Elastic Security Labs uncovers BRUSHWORM and BRUSHLOGGER | Détails sur de nouveaux malwares ciblant le secteur financier. | [Elastic](https://www.elastic.co/security-labs/brushworm-targets-financial-services) |
| Fake VS Code alerts on GitHub spread malware to developers | Alerte sur une nouvelle technique de phishing ciblant les développeurs. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/fake-vs-code-alerts-on-github-spread-malware-to-developers/) |
| New AITM phishing wave hijacks TikTok Business accounts | Évolution des techniques de phishing AITM vers de nouvelles plateformes sociales. | [SecurityAffairs](https://securityaffairs.com/190058/security/new-aitm-phishing-wave-hijacks-tiktok-business-accounts.html) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| ISC Stormcast For Friday, March 27th, 2026 | Contenu audio/podcast redondant avec les rapports écrits. | [SANS ISC](https://isc.sans.edu/diary/rss/32836) |
| Agentic GRC: Teams Get the Tech. | Article d'opinion sponsorisé sans indicateurs techniques concrets. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/agentic-grc-teams-get-the-tech-the-mindset-shift-is-whats-missing/) |
| Windows 11 KB5079391 update rolls out | Mise à jour de fonctionnalités mineures sans impact critique sur la sécurité immédiate. | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/windows-11-kb5079391-update-rolls-out-smart-app-control-improvements/) |
| Anti-piracy coalition takes down AnimePlay app | Information purement opérationnelle sur la lutte contre le piratage, hors menace cyber directe. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/anti-piracy-coalition-takes-down-animeplay-app-with-5-million-users/) |
| Mastodon / Social Media posts (divers) | Sources non structurées, doublons ou informations trop parcellaires. | [Divers (Mastodon/Hachyderm)](https://mastodon.social/...) |

<br>
<br/>
<div id="articles"></div>

# ARTICLES
<div id="teampcp-campagne-supply-chain"></div>

## TeamPCP : Campagne massive de Supply Chain et extension vers PyPI
Le groupe TeamPCP a intensifié sa campagne de supply chain en compromettant le SDK Python de Telnyx sur PyPI (plus de 670 000 téléchargements mensuels). Des versions malveillantes (4.87.1 et 4.87.2) utilisent une nouvelle technique de stéganographie via des fichiers WAV pour dissimuler leurs charges utiles. Sur Windows, un binaire persistant est déposé sous le nom `msbuild.exe` dans le dossier de démarrage, tandis que sur Linux/macOS, le malware récolte des identifiants. Parallèlement, TeamPCP s'est associé au ransomware Vect pour lancer un programme d'affiliation massif via BreachForums, marquant un pivot de la simple intrusion vers l'extorsion à grande échelle. Le groupe LAPSUS$ a également revendiqué le piratage d'AstraZeneca en utilisant des credentials volés lors des phases précédentes de cette campagne (Trivy/Checkmarx). L'analyse révèle que le vecteur initial pour LiteLLM était le compte GitHub personnel de son PDG, soulignant le ciblage de dirigeants. CISA a ajusté la date limite de remédiation pour la vulnérabilité Trivy (CVE-2026-33634) au 8 avril 2026.

**Analyse de l'impact** : Impact critique sur l'écosystème de développement Python et les pipelines CI/CD. La convergence entre supply chain, RaaS et exploitation de forums cybercriminels crée une menace systémique capable de déploiements industriels de ransomwares.

**Recommandations** :
- Vérifier immédiatement la présence des versions 4.87.1/2 de Telnyx et 1.82.8 de LiteLLM.
- Rechercher des fichiers `.wav` suspects et l'exécutable `msbuild.exe` dans les dossiers Startup Windows.
- Surveiller les connexions sortantes vers `models.litellm.cloud`.
- Réinitialiser impérativement tous les secrets (clés SSH, tokens cloud) ayant transité par des environnements exposés.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TeamPCP, Vect, LAPSUS$ |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Supply Chain Compromise<br/>* T1027.003: Steganography (WAV files)<br/>* T1547.001: Boot or Logon Autostart Execution<br/>* T1078.004: Cloud Accounts |
| Observables & Indicateurs de compromission | * Domaine : `models.litellm.cloud`<br/>* Fichier : `msbuild.exe`<br/>* Chemin : `~/.config/sysmon/sysmon.py`<br/>* Processus : `node-setup-*` (Kubernetes) |

### Source (url) du ou des articles
* https://isc.sans.edu/diary/rss/32838
* https://www.bleepingcomputer.com/news/security/backdoored-telnyx-pypi-package-pushes-malware-hidden-in-wav-audio/

<br>
<br>
<div id="red-menshen-bpfdoor-telecom"></div>

## Red Menshen : Espionnage étatique via BPFDoor dans les télécoms
Le groupe APT Red Menshen, lié à la Chine, mène une campagne d'espionnage de longue durée ciblant les réseaux de télécommunications au Moyen-Orient et en Asie. L'acteur utilise l'implant BPFDoor, un backdoor Linux furtif qui réside dans le noyau et n'écoute sur aucun port visible. L'activation se fait via des "paquets magiques" spécialement conçus, permettant une surveillance quasi invisible du trafic. Les nouvelles variantes dissimulent leurs déclencheurs dans le trafic HTTPS légitime et utilisent le protocole SCTP pour accéder aux données de signalisation et aux localisations des abonnés. Red Menshen imite des services légitimes (Docker, serveurs HPE) pour se fondre dans les environnements 5G. Cette stratégie de "cellules dormantes" assure une persistance pluriannuelle.

**Analyse de l'impact** : Menace stratégique majeure pour la confidentialité des communications gouvernementales et citoyennes. La capacité de l'implant à intercepter les flux de signalisation télécom remet en cause la sécurité des identités numériques.

**Recommandations** :
- Implémenter une surveillance rigoureuse des filtres BPF (Berkeley Packet Filter) au niveau système.
- Rechercher des anomalies dans le trafic ICMP et SCTP.
- Auditer les processus Linux pour détecter des anomalies de type "Raw Sockets" sans ports ouverts.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Red Menshen (Chine) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1014: Rootkit<br/>* T1573.001: Symmetric Cryptography<br/>* T1021.004: SSH (TinyShell)<br/>* T1205.002: Socket Filters (BPFDoor) |
| Observables & Indicateurs de compromission | * Type d'implant : ELF 64-bit BPFdoor<br/>* Marqueur : `0xFFFFFFFF`<br/>* Protocole : SCTP, ICMP |

### Source (url) du ou des articles
* https://securityaffairs.com/190029/malware/china-linked-red-menshen-apt-deploys-stealthy-bpfdoor-implants-in-telecom-networks.html

<br>
<br>
<div id="brushworm-brushlogger-elastic"></div>

## BRUSHWORM et BRUSHLOGGER : Menaces persistantes contre le secteur financier
Une institution financière d'Asie du Sud a été la cible de deux nouveaux composants malveillants : BRUSHWORM et BRUSHLOGGER. BRUSHWORM est un backdoor modulaire capable de se propager via USB en utilisant des noms de fichiers attractifs comme `Salary Slips.exe`. Il effectue des vérifications anti-sandbox sophistiquées (résolution d'écran, hyperviseurs) et exfiltre une vaste gamme de documents (Office, PDF, SQL, archives). BRUSHLOGGER est un enregistreur de frappe qui utilise le side-loading de DLL en se faisant passer pour `libcurl.dll`. Il capture les frappes système et le contexte des fenêtres actives, stockant les données dans des fichiers XOR-encryptés. Les erreurs de codage suggèrent une utilisation possible de l'IA pour la génération de code par les attaquants.

**Analyse de l'impact** : Risque élevé de vol de données financières et de propriété intellectuelle. La capacité de propagation USB rend ce malware efficace même dans des environnements isolés (air-gapped).

**Recommandations** :
- Désactiver l'exécution automatique des périphériques USB.
- Surveiller la création de tâches planifiées nommées `MSGraphics` ou `MSRecorder`.
- Rechercher les répertoires cachés dans `C:\ProgramData\Photoes\`.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Activité non attribuée spécifiquement (Ciblage Asie du Sud) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1053.005: Scheduled Task<br/>* T1574.002: DLL Side-Loading<br/>* T1056.001: Keylogging<br/>* T1091: Replication Through Removable Media |
| Observables & Indicateurs de compromission | * Mutex : `Windows-Updates-KB852654856`<br/>* Hash : `89891aa3867c1a57512d77e8e248d4a35dd32e99dcda0344a633be402df4a9a7`<br/>* Chemin : `C:\Users\Public\Systeminfo\` |

### Source (url) du ou des articles
* https://www.elastic.co/security-labs/brushworm-targets-financial-services

<br>
<br>
<div id="campagne-de-phishing-aitm-ciblant-tiktok-business"></div>

## Campagne de phishing AITM ciblant TikTok Business
Une nouvelle vague de phishing de type Adversary-in-the-Middle (AiTM) cible les comptes TikTok for Business. L'objectif est de prendre le contrôle de ces comptes pour mener des campagnes de malvertising et de fraude publicitaire. Les attaquants utilisent des domaines fraîchement enregistrés protégés par Cloudflare Turnstile pour évader les outils de détection automatisés. Les victimes sont redirigées depuis des sites légitimes (Google Storage) vers des pages imitant TikTok ou Google "Schedule a call". Les kits AiTM permettent de capturer les identifiants et les jetons de session en temps réel, contournant ainsi l'authentification multi-facteurs (MFA). La compromission d'un compte TikTok lié à un compte Google peut entraîner une cascade de vols de données.

**Analyse de l'impact** : Détournement de budgets publicitaires et utilisation de comptes de confiance pour diffuser des malwares (ex: Vidar, StealC). Risque de réputation important pour les entreprises.

**Recommandations** :
- Former les équipes marketing à la vérification des URLs de connexion.
- Utiliser des clés de sécurité matérielles (FIDO2) pour contrer le phishing AiTM.
- Surveiller les activités inhabituelles sur les plateformes de gestion publicitaire.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1557: Adversary-in-the-Middle<br/>* T1566.002: Spearphishing Link |
| Observables & Indicateurs de compromission | * Utilisation de Cloudflare Turnstile sur des domaines de phishing. |

### Source (url) du ou des articles
* https://securityaffairs.com/190058/security/new-aitm-phishing-wave-hijacks-tiktok-business-accounts.html

<br>
<br>
<div id="fausses-alertes-de-securite-vs-code-sur-github"></div>

## Fausses alertes de sécurité VS Code sur GitHub
Une campagne massive cible les développeurs sur GitHub via de fausses alertes de sécurité VS Code postées dans les sections "Discussions". Les messages, utilisant des titres alarmants comme "Severe Vulnerability - Immediate Update Required", incitent à télécharger des versions "patchées" d'extensions hébergées sur Google Drive. Les victimes sont redirigées vers un site de reconnaissance (`drnatashachinn[.]com`) qui profile les systèmes (OS, locale, timezone) via JavaScript. Ce système de distribution de trafic (TDS) permet de ne délivrer le malware final qu'aux cibles réelles, excluant les bots et les chercheurs. Les comptes utilisés pour poster ces alertes sont souvent nouveaux ou usurpés.

**Analyse de l'impact** : Risque d'infection des stations de travail des développeurs par des infostealers ou des outils d'accès à distance (RAT), compromettant l'intégrité du code source de l'organisation.

**Recommandations** :
- Sensibiliser les développeurs à ne jamais télécharger d'extensions en dehors des marketplaces officielles.
- Vérifier systématiquement la légitimité des CVE cités sur des sources officielles (NVD, MITRE).
- Bloquer le domaine de reconnaissance identifié au niveau du proxy/DNS.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1204.001: Malicious Link<br/>* T1584.001: DNS Server (TDS)<br/>* T1592: Gather Victim Host Information |
| Observables & Indicateurs de compromission | * Domaine : `drnatashachinn[.]com` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/fake-vs-code-alerts-on-github-spread-malware-to-developers/