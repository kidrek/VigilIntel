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
  * [Compromission de Trivy : une attaque supply chain majeure par TeamPCP](#compromission-de-trivy-une-attaque-supply-chain-majeure-par-teampcp)
  * [Abus des alertes Microsoft Azure Monitor pour du phishing par rappel](#abus-des-alertes-microsoft-azure-monitor-pour-du-phishing-par-rappel)
  * [PolyShell : une faille critique expose Magento et Adobe Commerce](#polyshell-une-faille-critique-expose-magento-et-adobe-commerce)
  * [CISA : Ajout de vulnérabilités critiques liées à DarkSword et Craft CMS](#cisa-ajout-de-vulnerabilites-critiques-liees-a-darksword-et-craft-cms)
  * [Google introduit l'Advanced Flow pour sécuriser le sideloading sur Android](#google-introduit-ladvanced-flow-pour-securiser-le-sideloading-sur-android)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
L'actualité cyber de cette période est marquée par une recrudescence des attaques sophistiquées sur la chaîne d'approvisionnement logicielle, comme l'illustre la compromission de l'outil de sécurité Trivy par le groupe TeamPCP. Cette attaque démontre que même les outils destinés à la sécurisation des infrastructures deviennent des vecteurs de propagation privilégiés pour des infostealers. Parallèlement, l'abus de services cloud légitimes (Microsoft Azure Monitor) pour des campagnes de phishing souligne une tendance durable à l'évasion des filtres de sécurité par l'usurpation de plateformes de confiance. Sur le plan des vulnérabilités, l'exploitation active de failles critiques dans Oracle Identity Manager (9.8) et Craft CMS (10.0) nécessite une réaction immédiate des organisations. Enfin, les initiatives de Google avec l'"Advanced Flow" pour Android montrent une volonté de l'industrie d'ajouter de la friction de sécurité pour contrer les tactiques d'ingénierie sociale basées sur l'urgence. Les décideurs doivent prioriser la rotation des secrets dans les pipelines CI/CD et le durcissement des accès administratifs aux plateformes SaaS/PaaS.

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
| Boggy Serpens (MuddyWater) | Diplomatie, infrastructures critiques, énergie (Moyen-Orient) | Phishing, utilisation de comptes piratés, outils en Rust et IA | [The Hacker News](https://thehackernews.com/2026/03/cisa-flags-apple-craft-cms-laravel-bugs.html) |
| Mimo (Hezb) | Serveurs web | Exploitation de vulnérabilités CMS pour mineurs de crypto et proxyware | [The Hacker News](https://thehackernews.com/2026/03/cisa-flags-apple-craft-cms-laravel-bugs.html) |
| TeamPCP (DeadCatx3) | DevOps, CI/CD, Cloud | Supply-chain attack via GitHub Actions et infostealer personnalisé | [BleepingComputer](https://www.bleepingcomputer.com/news/security/trivy-vulnerability-scanner-breach-pushed-infostealer-via-github-actions/) |
| WorldLeaks | Municipalités, organismes de transport | Exfiltration de données et double extorsion (ex-Hunters International) | [Security Affairs](https://securityaffairs.com/189753/data-breach/worldleaks-group-breached-the-city-of-los-angels.html) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Défense (France) | OPSEC | Le porte-avions Charles de Gaulle localisé via l'application de sport Strava. | [Security Affairs](https://securityaffairs.com/189765/breaking-news/security-affairs-newsletter-round-568-by-pierluigi-paganini-international-edition.html) |
| Gouvernement (Autriche) | Espionnage | Vienne identifiée comme un hub d'espionnage russe ciblant les communications de l'OTAN. | [Security Affairs](https://securityaffairs.com/189765/breaking-news/security-affairs-newsletter-round-568-by-pierluigi-paganini-international-edition.html) |
| Multi-sectoriel (UE) | Sanctions | Sanctions de l'UE contre des entités chinoises et iraniennes pour des cyberattaques sur des infrastructures critiques. | [Security Affairs](https://securityaffairs.com/189765/breaking-news/security-affairs-newsletter-round-568-by-pierluigi-paganini-international-edition.html) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Google adds ‘Advanced Flow’ for safe APK sideloading on Android | Bill Toulas | 21/03/2026 | Monde (Google Android) | Developer Verification Requirements | Système imposant une identité vérifiée pour tous les éditeurs d'applications Android et processus de sécurité renforcé pour l'installation hors-store. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-adds-advanced-flow-for-safe-apk-sideloading-on-android/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Collectivités locales | Town of Blacksburg (Virginia) | Revendication d'une intrusion par Worldleaks avec menace de publication de données. | [Mastodon (@darkwebsonar)](https://infosec.exchange/@darkwebsonar/116268230963005713) |
| Marketing / Sécurité | Aura | Exposition de 922 000 adresses e-mail liée à un outil marketing d'une société acquise. | [Mastodon (@XposedOrNot)](https://infosec.exchange/@XposedOrNot/116267608142754147) |
| Santé | Navia | Violation de données impactant près de 2,7 millions de personnes via un administrateur tiers. | [Security Affairs](https://securityaffairs.com/189765/breaking-news/security-affairs-newsletter-round-568-by-pierluigi-paganini-international-edition.html) |
| Télécommunications | AT&T | Fuite de données clients signalée par Credit Karma sans notification préalable de l'opérateur. | [Mastodon (@OldSquida2)](https://kolektiva.social/@OldSquida2/116267633852147639) |
| Transport | City of Los Angeles (Metro) | Attaque par ransomware (WorldLeaks) entraînant l'exfiltration de 159 Go de données et une interruption partielle des services. | [Security Affairs](https://securityaffairs.com/189753/data-breach/worldleaks-group-breached-the-city-of-los-angels.html) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).
| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|
| CVE-2025-32432 | 10.0 | Craft CMS | Injection de code / RCE | [Security Online](https://securityonline.info/active-exploits-cisa-adds-craft-cms-apple-darksword-flaws-kev/) |
| CVE-2026-21992 | 9.8 | Oracle Identity Manager | Remote Code Execution (RCE) | [The Hacker News](https://thehackernews.com/2026/03/oracle-patches-critical-cve-2026-21992.html) |
| CVE-2025-54068 | 9.8 | Laravel Livewire | Injection de code / RCE | [The Hacker News](https://thehackernews.com/2026/03/cisa-flags-apple-craft-cms-laravel-bugs.html) |
| CVE-2026-22898 | 9.3 | QNAP QVR Pro | Contournement d'authentification | [Security Online](https://securityonline.info/critical-9-3-cvss-flaw-qnap-qvr-pro-surveillance-systems-cve-2026-22898/) |
| CVE-2026-4529 | 9.0 | D-Link DHP-1320 | Stack-based buffer overflow | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-4529) |
| CVE-2025-43520 | 8.8 | Apple iOS/macOS | Corruption de mémoire (Kernel) | [The Hacker News](https://thehackernews.com/2026/03/cisa-flags-apple-craft-cms-laravel-bugs.html) |
| CVE-2025-31277 | 8.8 | Apple WebKit | Corruption de mémoire | [The Hacker News](https://thehackernews.com/2026/03/cisa-flags-apple-craft-cms-laravel-bugs.html) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Abus des alertes Microsoft Azure Monitor pour du phishing par rappel | Nouvelle tactique utilisant des vecteurs de confiance cloud. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/microsoft-azure-monitor-alerts-abused-in-callback-phishing-campaigns/) |
| CISA : Ajout de vulnérabilités critiques liées à DarkSword et Craft CMS | Impact direct sur les infrastructures gouvernementales et mobiles. | [Security Online](https://securityonline.info/active-exploits-cisa-adds-craft-cms-apple-darksword-flaws-kev/) |
| Compromission de Trivy : une attaque supply chain majeure par TeamPCP | Incident critique touchant les outils de sécurité DevOps. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/trivy-vulnerability-scanner-breach-pushed-infostealer-via-github-actions/) |
| Google introduit l'Advanced Flow pour sécuriser le sideloading sur Android | Changement stratégique dans l'écosystème mobile Android. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-adds-advanced-flow-for-safe-apk-sideloading-on-android/) |
| PolyShell : une faille critique expose Magento et Adobe Commerce | Menace imminente pour les plateformes e-commerce. | [Security Affairs](https://securityaffairs.com/189744/security/polyshell-flaw-exposes-magento-and-adobe-commerce-to-file-upload-attacks.html) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| @XposedOrNot += Aura Data Breach | Violation de données (exclu selon critères). | [Mastodon](https://infosec.exchange/@XposedOrNot/116267608142754147) |
| again AT&T exposes customer data... | Violation de données / Réseau social. | [Mastodon](https://kolektiva.social/@OldSquida2/116267633852147639) |
| CVE-2019-25581 - i-doit CMDB... | Vulnérabilité ancienne (2019). | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2019-25581) |
| Oracle Patches Critical CVE-2026-21992... | Doublon (plusieurs sources traitant de la même CVE Oracle). | [The Hacker News](https://thehackernews.com/2026/03/oracle-patches-critical-cve-2026-21992.html) |
| Security Affairs newsletter Round 568... | Lettre d'information trop généraliste. | [Security Affairs](https://securityaffairs.com/189765/breaking-news/security-affairs-newsletter-round-568-by-pierluigi-paganini-international-edition.html) |
| WorldLeaks ransomware group breached the City of Los Angels | Violation de données (exclu selon critères). | [Security Affairs](https://securityaffairs.com/189753/data-breach/worldleaks-group-breached-the-city-of-los-angels.html) |

<br>
<br>
<div id="articles"></div>

# ARTICLES

<div id="compromission-de-trivy-une-attaque-supply-chain-majeure-par-teampcp"></div>

## Compromission de Trivy : une attaque supply chain majeure par TeamPCP
Le scanner de vulnérabilités Trivy a été la cible d'une attaque sophistiquée sur sa chaîne d'approvisionnement par le groupe TeamPCP. Les attaquants ont compromis le processus de construction GitHub du projet, publiant des versions malveillantes (v0.69.4) intégrant des infostealers. Cette attaque a touché presque tous les tags du dépôt "trivy-action". Le malware exfiltre une vaste gamme de secrets : clés SSH, identifiants Cloud (AWS, Azure, GCP), configurations Kubernetes et jetons Slack/Discord. Les données volées étaient soit envoyées à un serveur de commande et contrôle (C2), soit téléchargées dans un dépôt public créé sur le compte GitHub de la victime. Une persistance a été établie via un service systemd exécutant un script Python. Aqua Security a confirmé que l'incident découle de jetons non révoqués d'une brèche antérieure. Une seconde vague d'attaque, utilisant le ver "CanisterWorm", cible désormais les paquets npm.

**Analyse de l'impact** : Impact critique sur les environnements DevOps et CI/CD. La compromission d'un outil de sécurité de confiance permet une exfiltration massive de secrets de production, ouvrant la voie à des compromissions totales d'infrastructures Cloud.

**Recommandations** : 
* Révoquer et renouveler immédiatement tous les secrets (clés API, identifiants Cloud, clés SSH) manipulés dans les environnements où Trivy v0.69.4 a été utilisé.
* Auditer les workflows GitHub Actions pour détecter des modifications suspectes de l'entrypoint.sh.
* Rechercher la présence du fichier `~/.config/systemd/user/sysmon.py` et du service systemd associé.
* Analyser les logs réseau pour des connexions vers `scan.aquasecurtiy[.]org` (typosquattage).

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TeamPCP (alias DeadCatx3, PCPcat, ShellForce) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Supply Chain Compromise (Software Dependencies) <br> * T1552: Unsecured Credentials <br> * T1567: Exfiltration Over Web Service |
| Observables & Indicateurs de compromission | ```* scan.aquasecurtiy[.]org <br> * tpcp.tar.gz <br> * ~/.config/systemd/user/sysmon.py <br> * Dépôt GitHub "tpcp-docs" sur les comptes victimes``` |

### Source (url) du ou des articles
* [BleepingComputer](https://www.bleepingcomputer.com/news/security/trivy-vulnerability-scanner-breach-pushed-infostealer-via-github-actions/)

<br/>
<div id="abus-des-alertes-microsoft-azure-monitor-pour-du-phishing-par-rappel"></div>

## Abus des alertes Microsoft Azure Monitor pour du phishing par rappel
Des attaquants exploitent les alertes légitimes de Microsoft Azure Monitor pour mener des campagnes de phishing par rappel (callback phishing). Les cybercriminels créent des règles d'alerte sur des événements de facturation factices dans Azure, en insérant des messages d'urgence dans le champ de description. Les victimes reçoivent alors un e-mail officiel provenant de `azure-noreply@microsoft.com`, ce qui permet au message de passer les contrôles SPF, DKIM et DMARC. L'e-mail prétend qu'une transaction frauduleuse (souvent pour Windows Defender) a été détectée et invite à appeler un numéro de support technique factice. Une fois au téléphone, les attaquants tentent de voler des identifiants ou d'installer des logiciels de prise en main à distance. Cette méthode cible particulièrement les entreprises pour obtenir un accès initial aux réseaux corporatifs.

**Analyse de l'impact** : Risque élevé de contournement des protections e-mail standards. L'utilisation d'une infrastructure Microsoft légitime augmente considérablement le taux de réussite de l'ingénierie sociale auprès des employés.

**Recommandations** : 
* Sensibiliser les employés au fait que les alertes Azure officielles ne contiennent jamais de numéros de téléphone pour résoudre des litiges de facturation.
* Configurer des règles de transport e-mail pour marquer les notifications Azure Monitor contenant des numéros de téléphone externes.
* En cas de doute, vérifier l'état réel de la facturation uniquement via le portail Azure officiel.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.003: Phishing (Spearphishing Service) <br> * T1204.001: User Execution (Malicious Link) |
| Observables & Indicateurs de compromission | ```* azure-noreply@microsoft.com <br> * +1 (864) 347-2494 <br> * +1 (864) 347-4846``` |

### Source (url) du ou des articles
* [BleepingComputer](https://www.bleepingcomputer.com/news/security/microsoft-azure-monitor-alerts-abused-in-callback-phishing-campaigns/)

<br/>
<div id="polyshell-une-faille-critique-expose-magento-and-adobe-commerce"></div>

## PolyShell : une faille critique expose Magento et Adobe Commerce
Sansec a révélé une vulnérabilité critique nommée "PolyShell" dans l'API REST de Magento et Adobe Commerce. Cette faille permet à un attaquant non authentifié d'uploader des fichiers exécutables déguisés en images (polyglottes) sur le serveur. Le problème réside dans le traitement des options de fichiers des articles du panier via l'API REST, où les données encodées en base64 sont enregistrées sans vérification suffisante dans le répertoire `pub/media/`. Bien qu'Adobe ait corrigé le problème dans une version préliminaire (2.4.9-alpha2), aucun correctif isolé n'est disponible pour les versions de production actuelles. Les configurations de serveurs web par défaut peuvent permettre l'exécution à distance de code (RCE) ou le vol de comptes via XSS stocké.

**Analyse de l'impact** : Menace directe sur l'intégrité des boutiques en ligne. L'absence de correctif officiel pour les versions stables rend cette vulnérabilité particulièrement dangereuse, d'autant plus que des exploits commencent à circuler.

**Recommandations** : 
* Utiliser un Web Application Firewall (WAF) pour bloquer les requêtes REST malveillantes ciblant les options de fichiers.
* Restreindre les privilèges d'exécution dans le répertoire `pub/media/custom_options/quote/` au niveau de la configuration du serveur web (Nginx/Apache).
* Scanner régulièrement le système pour détecter des fichiers suspects dans les répertoires d'upload de Magento.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br> * T1505.003: Web Shell |
| Observables & Indicateurs de compromission | ```Fichiers inattendus dans /pub/media/custom_options/quote/``` |

### Source (url) du ou des articles
* [Security Affairs](https://securityaffairs.com/189744/security/polyshell-flaw-exposes-magento-and-adobe-commerce-to-file-upload-attacks.html)

<br/>
<div id="cisa-ajout-de-vulnerabilites-critiques-liees-a-darksword-et-craft-cms"></div>

## CISA : Ajout de vulnérabilités critiques liées à DarkSword et Craft CMS
La CISA a ajouté cinq vulnérabilités à son catalogue KEV (Known Exploited Vulnerabilities), exigeant des correctifs avant le 3 avril 2026. Parmi elles, la faille CVE-2025-32432 dans Craft CMS affiche un score CVSS de 10.0 et permet une exécution de code à distance. De plus, trois failles Apple (iOS, macOS, Safari) sont activement exploitées par le kit DarkSword pour déployer des spywares tels que GHOSTBLADE et GHOSTSABER. Ces logiciels malveillants ciblent les communications (iMessage, WhatsApp, Telegram) et les portefeuilles de crypto-monnaies. Enfin, une vulnérabilité dans Laravel Livewire (CVE-2025-54068, CVSS 9.8) est utilisée par le groupe iranien MuddyWater pour attaquer des infrastructures stratégiques au Moyen-Orient.

**Analyse de l'impact** : Risque majeur d'espionnage d'État et de prise de contrôle de serveurs web. L'exploitation combinée de failles mobiles et de frameworks web montre une volonté de cibler les données personnelles et organisationnelles de manière holistique.

**Recommandations** : 
* Mettre à jour Craft CMS vers les versions 3.9.15, 4.14.15 ou 5.6.17 minimum.
* Appliquer les dernières mises à jour de sécurité sur l'ensemble de la flotte Apple (iOS 18.7.2 et équivalents).
* Mettre à jour Laravel Livewire vers la version 3.6.4 ou supérieure.
* Rechercher des IoC liés aux familles de malwares "Ghost" sur les terminaux mobiles.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | MuddyWater (Boggy Serpens), Mimo (Hezb) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1210: Exploitation of Remote Services <br> * T1518.001: Security Software Discovery |
| Observables & Indicateurs de compromission | ```Charge utile GHOSTBLADE (JavaScript) <br> Backdoor GHOSTSABER``` |

### Source (url) du ou des articles
* [The Hacker News](https://thehackernews.com/2026/03/cisa-flags-apple-craft-cms-laravel-bugs.html)
* [Security Online](https://securityonline.info/active-exploits-cisa-adds-craft-cms-apple-darksword-flaws-kev/)

<br/>
<div id="google-introduit-ladvanced-flow-pour-securiser-le-sideloading-sur-android"></div>

## Google introduit l'Advanced Flow pour sécuriser le sideloading sur Android
Google a annoncé "Advanced Flow", un nouveau mécanisme pour Android prévu pour août 2026, visant à sécuriser l'installation d'applications (APKs) provenant de développeurs non vérifiés. Ce système introduit un processus en plusieurs étapes pour les utilisateurs avancés : activation du mode développeur, confirmation de l'absence de coercition par un tiers, redémarrage du téléphone et un délai d'attente de 24 heures avant la validation finale. L'objectif est de briser l'urgence souvent exploitée par les cybercriminels dans les arnaques au support technique ou bancaires. Cette initiative accompagne une nouvelle politique exigeant que tous les éditeurs d'applications, quelle que soit la méthode de distribution, fassent vérifier leur identité par Google.

**Analyse de l'impact** : Impact stratégique positif sur la réduction des infections par malwares bancaires et fraudes sur mobile. Cependant, cela augmente considérablement la complexité pour les utilisateurs légitimes de sideloading.

**Recommandations** : 
* Pour les entreprises gérant des flottes mobiles, anticiper les changements de déploiement d'applications internes hors Play Store.
* Préparer les équipes de support à expliquer ces nouveaux mécanismes de friction aux utilisateurs finaux.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1456: Drive-By Compromise <br> * T1204.002: User Execution (Malicious File) |
| Observables & Indicateurs de compromission | ```Aucun IoC spécifique n'est fourni``` |

### Source (url) du ou des articles
* [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-adds-advanced-flow-for-safe-apk-sideloading-on-android/)