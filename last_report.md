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
  * [L'attaque de la chaîne d'approvisionnement Axios par UNC1069](#lattaque-de-la-chaine-dapprovisionnement-axios-par-unc1069)
  * [Explosion des attaques de phishing par "Device Code" OAuth 2.0](#explosion-des-attaques-de-phishing-par-device-code-oauth-20)
  * [Compromission massive de l'infrastructure Cloud de la Commission Européenne](#compromission-massive-de-linfrastructure-cloud-de-la-commission-europeenne)
  * [Le conflit hybride Moyen-Orient : escalade cyber et blocus numérique](#le-conflit-hybride-moyen-orient-escalade-cyber-et-blocus-numerique)
  * [Vulnérabilités critiques et chaînes d'attaque sur Progress ShareFile](#vulnerabilites-critiques-et-chaines-dattaque-sur-progress-sharefile)
  * [Opération TrueChaos : Ciblage gouvernemental via TrueConf](#operation-truechaos-ciblage-gouvernemental-via-trueconf)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage de la menace d'avril 2026 est marqué par une hybridation croissante entre conflits cinétiques et opérations cyber, particulièrement au Moyen-Orient où les cyber-attaques s'alignent désormais sur les agendas militaires de l'Iran et d'Israël. On observe une professionnalisation extrême de l'ingénierie sociale, illustrée par l'attaque contre Axios utilisant de fausses réunions Microsoft Teams pour compromettre des mainteneurs de bibliothèques critiques. Parallèlement, l'industrialisation du phishing via l'abus du flux "Device Code" d'OAuth 2.0 montre une adaptation rapide des cybercriminels aux protections MFA classiques. La chaîne d'approvisionnement logicielle demeure un vecteur privilégié, touchant tant le secteur open-source que les institutions européennes via des outils comme Trivy. Les vulnérabilités "zéro-day" sur les solutions de périmètre (Fortinet, Progress ShareFile) sont immédiatement exploitées par des acteurs étatiques pour l'accès initial. Le blocus numérique imposé à la population iranienne souligne l'utilisation d'Internet comme une arme de contrôle souverain total. Enfin, l'émergence d'outils d'IA pour automatiser la création de malwares (wipers) et l'analyse de données de masse confirme un changement de paradigme technologique chez les attaquants. Les décideurs doivent impérativement renforcer la sécurité des accès à privilèges et la surveillance des infrastructures cloud tierces.

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
| 313 Team | E-commerce, Gouvernements | Attaques DDoS coordonnées avec les agendas militaires de l'IRGC. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Cyber Av3ngers | ICS/OT, Infrastructures critiques | Exploitation de PLC et systèmes de contrôle industriel. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Handala (Void Manticore) | Gouvernements, Santé, Défense | Wipers, exfiltration de données, ingénierie sociale, tunneling via NetBird. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Qilin | Santé, Industrie, Finance, Politique | Ransomware-as-a-Service (RaaS), double extorsion, alliances stratégiques. | [SecurityAffairs](https://securityaffairs.com/190348/cyber-crime/qilin-ransomware-group-claims-the-hack-of-german-political-party-die-linke.html) |
| TA416 | Gouvernements européens, Diplomatie | Malware PlugX, phishing basé sur OAuth. | [Mastodon](https://mastodon.social/@cyberthreatsweekly/116348719845469854) |
| TeamPCP | Cloud, Chaîne d'approvisionnement | Compromission de clés API (Trivy), exfiltration massive de données cloud. | [SecurityAffairs](https://securityaffairs.com/190333/security/european-commission-breach-exposed-data-of-30-eu-entities-cert-eu-says.html) |
| UNC1069 (North Korea) | Développeurs, Open-source | Ingénierie sociale via Slack/Teams, malware WAVESHAPER.V2, vol de credentials NPM. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/axios-npm-hack-used-fake-teams-error-fix-to-hijack-maintainer-account/) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Défense / Énergie | Conflit Iran-Israël-USA | Intensification de la cyberguerre liée aux frappes militaires ; menace sur les détroits d'Ormuz et Bab el-Mandeb. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) / [IRIS](https://www.iris-france.org/ormuz-bab-el-mandeb-la-guerre-dans-la-guerre/) |
| Gouvernemental | Blocus numérique | L'Iran maintient un black-out internet quasi total (1% de connectivité) depuis 36 jours. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Politique | Ingérence / Cybercrime | Ciblage du parti politique allemand Die Linke par le groupe Qilin (lié à la sphère russe). | [SecurityAffairs](https://securityaffairs.com/190348/cyber-crime/qilin-ransomware-group-claims-the-hack-of-german-political-party-die-linke.html) |
| Technologie | Souveraineté IA | Utilisation croissante de l'IA par des entreprises chinoises pour traquer les mouvements militaires américains. | [Mastodon/WaPo](https://infosec.exchange/@iamnickw/116349261041367769) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif des articles juridiques et réglementaires relatifs à la cybersécurité :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| BOD 22-01: KEV Catalog Update | CISA | 04/04/2026 | USA | BOD 22-01 | Obligation pour les agences fédérales de corriger les vulnérabilités exploitées (CVE-2026-3502). | [SecurityAffairs](https://securityaffairs.com/190341/security/u-s-cisa-adds-a-flaw-in-trueconf-client-to-its-known-exploited-vulnerabilities-catalog.html) |
| Emergency Hotfix Advisory | Fortinet | 04/04/2026 | Global | FG-IR-26-099 | Directive d'application immédiate de correctifs pour FortiClient EMS suite à une exploitation active. | [CybersecurityNews](https://cybersecuritynews.com/fortinet-forticlient-ems-0-day/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Divertissement | Crunchyroll | Fuite de données via Zendesk impactant 1,2 million d'utilisateurs (emails). | [HIBP](https://haveibeenpwned.com/Breach/Crunchyroll) |
| Divertissement | SongTrivia2 | Violation impactant 291 000 comptes (emails, hashs de mots de passe, pseudos). | [HIBP](https://haveibeenpwned.com/Breach/SongTrivia2) |
| Gouvernemental | Commission Européenne | Vol de 350 Go de données (emails, contrats, bases de données) via une clé API AWS. | [SecurityAffairs](https://securityaffairs.com/190333/security/european-commission-breach-exposed-data-of-30-eu-entities-cert-eu-says.html) |
| Gouvernemental | St. Joseph County (USA) | Allégation (non confirmée) de suppression de 12 To de données par Handala. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Juridique | Auger & Auger | Accès non autorisé de 25 minutes aux données du cabinet. | [DataBreaches](https://databreaches.net/2026/04/04/the-breach-lasted-25-minutes-how-long-will-the-litigation-last/) |
| Santé | Hospital Authority (HK) | Fuite de données concernant 56 000 patients à Kowloon East. | [DataBreaches](https://databreaches.net/2026/04/04/hong-kong-hospital-authority-apologises-for-data-breach-involving-56000-patients/) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par criticité.
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2026-2699 | 9.8 | N/A | FALSE | Progress ShareFile | Authentification Bypass | T1190: Exploit Public-Facing Application | Contournement d'auth via "Execution After Redirect" sur Admin.aspx. | [CybersecurityNews](https://cybersecuritynews.com/progress-sharefile-vulnerability/) |
| CVE-2026-35616 | 9.1 | N/A | TRUE | Fortinet FortiClientEMS | RCE / Access Control | T1190, TA0001 : Initial Access | Bypass d'auth API permettant l'exécution de code à distance. | [MS-ISAC](https://www.cisecurity.org/advisory/a-vulnerability-in-fortinet-forticlientemscould-allow-for-arbitrary-code-execution_2026-031) |
| CVE-2026-2701 | 9.1 | N/A | FALSE | Progress ShareFile | Remote Code Execution | T1190, T1505.003: Web Shell | Téléchargement d'archive malveillante permettant l'upload de webshell. | [CybersecurityNews](https://cybersecuritynews.com/progress-sharefile-vulnerability/) |
| CVE-2026-3502 | 7.8 | N/A | TRUE | TrueConf Client | Unverified Update | T1543 : Create or Modify System Process | Absence de vérification des mises à jour, permettant l'injection de malware. | [SecurityAffairs](https://securityaffairs.com/190341/security/u-s-cisa-adds-a-flaw-in-trueconf-client-to-its-known-exploited-vulnerabilities-catalog.html) |
| CVE-2026-3666 | N/A (HIGH) | N/A | FALSE | wpForo (WordPress) | Path Traversal | T1083: File and Directory Discovery | Permet aux utilisateurs authentifiés de supprimer des fichiers serveurs. | [Mastodon/OffSeq](https://infosec.exchange/@offseq/116349156511822989) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Axios npm hack used fake Teams error fix... | Analyse détaillée d'une attaque de chaîne d'approvisionnement hautement sophistiquée. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/axios-npm-hack-used-fake-teams-error-fix-to-hijack-maintainer-account/) |
| Device code phishing attacks surge 37x... | Émergence massive d'une technique de contournement d'authentification OAuth. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/device-code-phishing-attacks-surge-37x-as-new-kits-spread-online/) |
| European Commission breach exposed data... | Impact critique sur les institutions européennes et vecteur d'attaque via Trivy. | [SecurityAffairs](https://securityaffairs.com/190333/security/european-commission-breach-exposed-data-of-30-eu-entities-cert-eu-says.html) |
| Monitoring Cyberattacks US-Israel-Iran | Synthèse opérationnelle majeure sur un conflit cyber-cinétique actuel. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| New Progress ShareFile Bugs... | Vulnérabilités critiques sur une solution largement utilisée en entreprise. | [CybersecurityNews](https://cybersecuritynews.com/progress-sharefile-vulnerability/) |
| U.S. CISA adds a flaw in TrueConf Client... | Détails sur une opération d'espionnage ciblée (TrueChaos) via des mises à jour. | [SecurityAffairs](https://securityaffairs.com/190341/security/u-s-cisa-adds-a-flaw-in-trueconf-client-to-its-known-exploited-vulnerabilities-catalog.html) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| Claude Code leak used to push infostealer... | Violation de données / Distribution de malware via dépôts factices. | [DataBreaches](https://databreaches.net/2026/04/04/claude-code-leak-used-to-push-infostealer-malware-on-github/) |
| Elastic Security Integrations Roundup: Q1 2026 | Article de type "Mise à jour produit" sans analyse de menace spécifique. | [Elastic](https://www.elastic.co/security-labs/elastic-security-integrations-roundup-q1-2026) |
| Hong Kong Hospital Authority apologises... | Violation de données sans détails sur le mode opératoire technique. | [DataBreaches](https://databreaches.net/2026/04/04/hong-kong-hospital-authority-apologises-for-data-breach-involving-56000-patients/) |
| I really felt internally motivated... | Contenu de type opinion/éditorial issu de réseaux sociaux. | [Mastodon](https://infosec.exchange/@iamnickw/116349261041367769) |
| Ormuz, Bab el-Mandeb : la guerre dans la guerre | Analyse purement géopolitique, traitée en synthèse mais pas en article cyber. | [IRIS](https://www.iris-france.org/ormuz-bab-el-mandeb-la-guerre-dans-la-guerre/) |
| RE: Nikolai Hampton LLM rant | Discussion philosophique sur l'IA, hors périmètre veille technique. | [Mastodon](https://infosec.exchange/@nikolaihampton/116349300185603897) |

<br>
<br>
<div id="articles"></div>

# ARTICLES

<div id="lattaque-de-la-chaine-dapprovisionnement-axios-par-unc1069"></div>

## L'attaque de la chaîne d'approvisionnement Axios par UNC1069
Un mainteneur principal de la bibliothèque npm populaire Axios a été victime d'une campagne d'ingénierie sociale sophistiquée attribuée à l'acteur nord-coréen UNC1069. Les attaquants ont créé un environnement Slack d'entreprise fictif, complet avec de faux profils d'employés et de contributeurs open-source, pour gagner sa confiance. Lors d'un appel Microsoft Teams planifié, un faux message d'erreur technique a incité le développeur à installer une soi-disant mise à jour SDK. Cette mise à jour était en réalité un cheval de Troie d'accès à distance (RAT) nommé WAVESHAPER.V2. Grâce à cet accès, les attaquants ont dérobé les identifiants npm pour publier deux versions malveillantes d'Axios (1.14.1 et 0.30.4). Ces versions injectaient une dépendance malveillante, `plain-crypto-js`, installant des RAT sur Windows, Linux et macOS. L'attaque a duré trois heures avant le retrait des packages.

**Analyse de l'impact** : L'impact est sévère en raison de l'omniprésence d'Axios dans l'écosystème JavaScript. Une compromission réussie permet un accès persistant aux systèmes des développeurs et des serveurs de production, facilitant l'exfiltration de données et d'autres attaques de chaîne d'approvisionnement.

**Recommandations** :
* Auditer immédiatement les dépendances npm pour détecter les versions 1.14.1 et 0.30.4 d'Axios.
* Révoquer et renouveler tous les jetons d'accès et clés d'authentification sur les systèmes ayant installé ces versions.
* Sensibiliser les équipes de développement aux attaques "ClickFix" via de faux messages d'erreur Teams ou Slack.
* Imposer l'authentification à deux facteurs (MFA) matérielle pour la publication de packages.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UNC1069 (lié à la Corée du Nord) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.003: Phishing: Spearphishing via Service<br>* T1195.002: Supply Chain Compromise: Compromise Software Dependencies<br>* T1204.002: User Execution: Malicious File |
| Observables & Indicateurs de compromission | ```* Versions npm: axios@1.14.1, axios@0.30.4\n* Package: plain-crypto-js\n* Malware: WAVESHAPER.V2``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/axios-npm-hack-used-fake-teams-error-fix-to-hijack-maintainer-account/

<br>
<br>

<div id="explosion-des-attaques-de-phishing-par-device-code-oauth-20"></div>

## Explosion des attaques de phishing par "Device Code" OAuth 2.0
Les attaques de phishing utilisant le flux "Device Authorization Grant" d'OAuth 2.0 ont été multipliées par 37,5 en 2026. Cette technique abuse d'une fonctionnalité conçue pour les appareils sans clavier (Smart TV, IoT) en envoyant un code d'autorisation à la victime. L'attaquant incite l'utilisateur à saisir ce code sur une page de connexion légitime de Microsoft ou Google. Une fois validé, l'attaquant obtient des jetons d'accès et de rafraîchissement valides, contournant ainsi les protections MFA traditionnelles. Plusieurs kits de phishing "as-a-Service" (PhaaS) comme EvilTokens, Venom ou Docupoll démocratisent cette attaque. Ces kits utilisent des leurres réalistes (DocuSign, SharePoint, Teams) et des protections anti-bot avancées.

**Analyse de l'impact** : Cette méthode est particulièrement redoutable car elle s'appuie sur des infrastructures de connexion légitimes, rendant la détection par l'utilisateur final très difficile. Elle permet une prise de contrôle totale des comptes SaaS (Office 365, etc.) avec une persistance longue durée via les jetons de rafraîchissement.

**Recommandations** :
* Désactiver le flux "Device Code" via des politiques d'accès conditionnel si l'usage n'est pas justifié.
* Surveiller les logs d'authentification pour des événements "DeviceCode" inattendus ou provenant d'IP inhabituelles.
* Utiliser des clés de sécurité matérielles (FIDO2) qui lient l'authentification à l'origine du site.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Opérateurs EvilTokens, VENOM, CLURE, LINKID |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.002: Phishing: Spearphishing Link<br>* T1528: Steal Application Access Token<br>* T1550.001: Use Alternate Authentication Material: Application Access Token |
| Observables & Indicateurs de compromission | ```* Domaines: workers.dev, github.io\n* Phishing kits: EvilTokens, Docupoll, Flow_Token``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/device-code-phishing-attacks-surge-37x-as-new-kits-spread-online/

<br>
<br>

<div id="compromission-massive-de-linfrastructure-cloud-de-linfrastructure-cloud-de-la-commission-europeenne"></div>

## Compromission massive de l'infrastructure Cloud de la Commission Européenne
Le groupe TeamPCP a compromis un compte Amazon Web Services (AWS) de la Commission Européenne, exposant les données de plus de 30 entités de l'UE. L'accès initial a été obtenu le 19 mars 2026 via une compromission de la chaîne d'approvisionnement de l'outil de sécurité Trivy. Les attaquants ont récupéré un secret API AWS, leur permettant de créer de nouvelles clés d'accès pour maintenir leur persistance. Environ 350 Go de données ont été exfiltrés, incluant des bases de données de sites web, des contrats confidentiels et plus de 51 000 fichiers d'emails. Le groupe a utilisé des outils comme TruffleHog pour scanner d'autres secrets au sein de l'environnement cloud. L'incident n'a pas causé d'interruption de service mais a entraîné une fuite massive d'informations sensibles.

**Analyse de l'impact** : L'impact est politique et stratégique majeur pour l'Union Européenne. La fuite de documents confidentiels et de données personnelles de personnels de l'UE peut alimenter des opérations d'espionnage ultérieures ou des campagnes de désinformation.

**Recommandations** :
* Auditer l'utilisation des scanners de vulnérabilités (comme Trivy) et vérifier l'intégrité des binaires utilisés.
* Mettre en œuvre une rotation stricte des clés API et interdire les clés à durée de vie illimitée.
* Surveiller les appels API AWS inhabituels, notamment ceux liés à l'outil STS (Security Token Service).

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TeamPCP (lié à des attaques sur GitHub/npm) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Supply Chain Compromise<br>* T1552.001: Unsecured Credentials: Private Keys<br>* T1537: Transfer Data to Cloud Account |
| Observables & Indicateurs de compromission | ```* Outils: TruffleHog, STS API abuse\n* Vecteur: Compromission Trivy (Aqua Security advisory)``` |

### Source (url) du ou des articles
* https://securityaffairs.com/190333/security/european-commission-breach-exposed-data-of-30-eu-entities-cert-eu-says.html

<br>
<br>

<div id="le-conflit-hybride-moyen-orient-escalade-cyber-et-blocus-numerique"></div>

## Le conflit hybride Moyen-Orient : escalade cyber et blocus numérique
Le conflit militaire US-Israël-Iran s'accompagne d'une cyberguerre intensive. Le groupe Handala (Void Manticore) a déployé de nouveaux TTP, incluant le tunneling via NetBird et l'utilisation d'IA pour générer des scripts de suppression de données (wipers). Des attaques DDoS massives menées par le "313 Team" ont visé Amazon Arabie Saoudite, s'alignant précisément sur les deadlines fixées par les Gardiens de la Révolution (IRGC). En Iran, un black-out internet quasi total persiste depuis plus de 36 jours, avec une connectivité réduite à 1%. Ce blocus vise à isoler la population civile tout en maintenant des accès "whitelistés" pour les élites du régime. Les infrastructures industrielles (OT) sont également ciblées par "Cyber Av3ngers", exploitant des automates programmables (PLC).

**Analyse de l'impact** : Les cyber-opérations servent de multiplicateurs de force cinétique, visant à déstabiliser l'économie régionale et à saper la confiance dans les systèmes de défense aérienne et civile. Le risque de débordement vers les entreprises occidentales liées à la chaîne d'approvisionnement militaire est critique.

**Recommandations** :
* Bloquer les connexions entrantes en provenance d'Iran sur les services d'accès distant (VPN).
* Renforcer la surveillance des systèmes ICS/SCADA et isoler les réseaux OT des réseaux IT.
* Valider l'intégrité et la disponibilité des sauvegardes hors-ligne face aux menaces de wipers.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Handala (Void Manticore), 313 Team, Cyber Av3ngers |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1567: Exfiltration Over Web Service (NetBird)<br>* T1485: Data Destruction (AI-assisted wipers)<br>* T1498: Network Denial of Service |
| Observables & Indicateurs de compromission | ```* Logiciel: NetBird\n* Cibles: amazon.sa, systèmes de police St. Joseph County\n* Référence: Rapport Check Point du 02/04/2026``` |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict

<br>
<br>

<div id="vulnerabilites-critiques-et-chaines-dattaque-sur-progress-sharefile"></div>

## Vulnérabilités critiques et chaînes d'attaque sur Progress ShareFile
Deux vulnérabilités critiques ont été découvertes dans Progress ShareFile Storage Zones Controller, permettant une prise de contrôle totale des serveurs sans authentification. La première (CVE-2026-2699) est un contournement d'authentification via une condition "Execution After Redirect" sur la page Admin.aspx. La seconde (CVE-2026-2701) permet l'exécution de code à distance via l'upload d'archives malveillantes. Combinées, ces failles permettent à un attaquant distant de modifier les paramètres de stockage et de déployer un webshell ASPX dans le dossier racine de l'application. Environ 30 000 instances sont potentiellement exposées sur Internet.

**Analyse de l'impact** : ShareFile étant utilisé pour le partage de documents sensibles et la conformité, une compromission permet aux attaquants de voler des données souveraines ou d'utiliser le serveur comme point d'entrée pour des ransomwares au sein du réseau d'entreprise.

**Recommandations** :
* Mettre à jour immédiatement vers la version 5.12.4 ou migrer vers la branche 6.x.
* Restreindre l'accès à l'interface de gestion ShareFile via un VPN ou une liste blanche IP.
* Rechercher la présence de fichiers ASPX suspects ou de modifications de configuration dans les répertoires web.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non mentionnés (menace imminente de ransomwares) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application<br>* T1505.003: Web Shell |
| Observables & Indicateurs de compromission | ```* CVE-2026-2699 (CVSS 9.8)\n* CVE-2026-2701 (CVSS 9.1)\n* Fichier cible: Admin.aspx``` |

### Source (url) du ou des articles
* https://cybersecuritynews.com/progress-sharefile-vulnerability/

<br>
<br>

<div id="operation-truechaos-ciblage-gouvernemental-via-trueconf"></div>

## Opération TrueChaos : Ciblage gouvernemental via TrueConf
La CISA a ajouté la CVE-2026-3502 à son catalogue KEV après l'observation d'attaques ciblées contre des gouvernements utilisant la plateforme de visioconférence TrueConf. Baptisée "Opération TrueChaos", cette campagne est attribuée à un acteur chinois. Les attaquants compromettent le serveur TrueConf local pour remplacer les fichiers de mise à jour par des versions malveillantes. Lorsque le client TrueConf est lancé, il propose une mise à jour que l'utilisateur installe sans méfiance, car elle provient d'une source interne "approuvée". Cela permet le déploiement du framework Havoc et du malware ShadowPad, offrant un contrôle total sur les postes de travail gouvernementaux.

**Analyse de l'impact** : Cette attaque est particulièrement efficace dans les environnements sécurisés ou isolés où TrueConf est privilégié pour sa capacité à fonctionner hors-ligne. Elle permet une surveillance audio/vidéo et un vol de données persistant au cœur des ministères.

**Recommandations** :
* Appliquer les correctifs TrueConf avant le 16 avril 2026 selon la directive CISA.
* Mettre en œuvre une vérification d'intégrité (hash) pour tous les packages de mise à jour distribués en interne.
* Surveiller les communications réseau vers des infrastructures Alibaba ou Tencent inhabituelles.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Acteur lié à la Chine (Operation TrueChaos) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1543.003: Create or Modify System Process: Windows Service<br>* T1574.002: DLL Side-Loading |
| Observables & Indicateurs de compromission | ```* Malware: ShadowPad, Havoc Framework\n* CVE-2026-3502``` |

### Source (url) du ou des articles
* https://securityaffairs.com/190341/security/u-s-cisa-adds-a-flaw-in-trueconf-client-to-its-known-exploited-vulnerabilities-catalog.html