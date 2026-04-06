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
  * [Exploitation critique de FortiClient EMS](#exploitation-critique-de-forticlient-ems)
  * [Campagne massive d'extraction de secrets via React2Shell](#campagne-massive-dextraction-de-secrets-via-react2shell)
  * [Convergence cyber-cinétique dans le conflit US-Israël-Iran](#convergence-cyber-cinetique-dans-le-conflit-us-israel-iran)
  * [Analyse technique d'une infection par script CMD malveillant](#analyse-technique-dune-infection-par-script-cmd-malveillant)
  * [Attaque par canal d'approvisionnement visant le paquet npm Axios](#attaque-par-canal-dapprovisionnement-visant-le-paquet-npm-axios)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage cyber actuel est marqué par une intensification de la convergence entre opérations cinétiques et numériques, particulièrement illustrée par l'usage de spywares lors de frappes de missiles en Israël. On observe une industrialisation des capacités destructrices via l'émergence du modèle "Wiper-as-a-Service" par les proxies iraniens, abaissant le seuil technique requis pour des attaques paralysantes. Parallèlement, la menace sur la chaîne d'approvisionnement logicielle se confirme avec le compromis du paquet npm "Axios" par la Corée du Nord, visant l'exfiltration massive de secrets cloud et d'identifiants. L'exploitation active de vulnérabilités critiques "zero-day" sur des solutions d'accès périmétriques comme Fortinet souligne l'urgence de cycles de correctifs ultra-rapides. L'automatisation des attaques sur les frameworks modernes (Next.js) permet désormais aux attaquants de compromettre des centaines d'hôtes en moins de 24 heures pour récolter des clés API et SSH. Ces tendances démontrent une volonté des acteurs étatiques de maximiser l'impact psychologique et économique tout en automatisant le vol de données à haute valeur stratégique.

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
| **BlueNoroff** | Cryptomonnaie, macOS | Utilisation de malwares RustBucket pour l'exfiltration | [Security Affairs](https://securityaffairs.com/190368/breaking-news/security-affairs-newsletter-round-571-by-pierluigi-paganini-international-edition.html) |
| **Handala Hack** | Défense, Infrastructure israélienne | Wiper, abus de MDM Intune, vol de données | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| **Kimsuky** | Gouvernement (UK), R&D | Fichiers LNK malveillants, backdoor Python | [OTX Alientvault](https://social.raytec.co/@techbot/116353998219070686) |
| **Qilin** | Partis politiques, Industrie | Ransomware, exfiltration de données | [Security Affairs](https://securityaffairs.com/190379/malware/security-affairs-malware-newsletter-round-91.html) |
| **TA446** (lié à la Russie) | Utilisateurs iPhone | Kit d'exploitation iOS DarkSword via spear-phishing | [Security Affairs](https://securityaffairs.com/190368/breaking-news/security-affairs-newsletter-round-571-by-pierluigi-paganini-international-edition.html) |
| **UAC-0255** | Ukraine (Gouvernement) | Impersonnalisation du CERT-UA, malware AGEWHEEZE | [Security Affairs](https://securityaffairs.com/190379/malware/security-affairs-malware-newsletter-round-91.html) |
| **UAT-10608** | Cloud, Applications Next.js | Exploitation React2Shell, framework NEXUS Listener | [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-react2shell-in-automated-credential-theft-campaign/) |
| **UNC1069** (Corée du Nord) | Développeurs, Chaîne d'approvisionnement | Hijacking de comptes npm (Axios), malware RAT | [Security Affairs](https://securityaffairs.com/190368/breaking-news/security-affairs-newsletter-round-571-by-pierluigi-paganini-international-edition.html) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Cyber-Guerre | Conflit Israël-Iran | Campagne de spyware via de fausses applications d'alerte à la bombe lors de frappes de missiles. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Cyber-Guerre | Conflit US-Iran | Sauvetage d'un pilote de F-15E suivi d'une intensification des opérations d'information pro-iraniennes. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Infrastructure | Iran | Coupure prolongée d'Internet en Iran (37 jours) avec un trafic réduit à 1%. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Politique | Allemagne | Revendication par le groupe Qilin d'une attaque contre le parti politique "Die Linke". | [Security Affairs](https://securityaffairs.com/190368/breaking-news/security-affairs-newsletter-round-571-by-pierluigi-paganini-international-edition.html) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Verification des développeurs Android | Google | 05/04/2026 | Mondiale | Google Play Policy | Déploiement obligatoire de la vérification d'identité pour tous les développeurs sur Play Console. | [Security Affairs](https://securityaffairs.com/190368/breaking-news/security-affairs-newsletter-round-571-by-pierluigi-paganini-international-edition.html) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Automobile | Dow Inc | Fuite de données présumée suite à une attaque du groupe Qilin. | [Security Affairs](https://securityaffairs.com/190368/breaking-news/security-affairs-newsletter-round-571-by-pierluigi-paganini-international-edition.html) |
| Banque | Lloyds Banking Group | Incident de sécurité affectant les données personnelles de près de 500 000 clients mobiles. | [Security Affairs](https://securityaffairs.com/190368/breaking-news/security-affairs-newsletter-round-571-by-pierluigi-paganini-international-edition.html) |
| Défense | PSK Wind Technologies | Brèche confirmée par le groupe pro-iranien Handala chez ce sous-traitant israélien. | [Security Affairs](https://securityaffairs.com/190379/malware/security-affairs-malware-newsletter-round-91.html) |
| Finance | Drift (Solana) | Vol de 285 millions de dollars en cryptomonnaie par des acteurs liés à la Corée du Nord. | [Mastodon](https://mastodon.social/@SubProxy/116355155429365798) |
| Gouvernement | Commission Européenne | Brèche de données exposant 30 entités de l'UE via une compromission de la chaîne d'approvisionnement cloud. | [Security Affairs](https://securityaffairs.com/190368/breaking-news/security-affairs-newsletter-round-571-by-pierluigi-paganini-international-edition.html) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées :
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2026-35616 | 9.8 | Non spécifié | TRUE | FortiClient EMS | Contrôle d'accès incorrect | T1190: Exploit Public-Facing Application | Permet l'exécution de code à distance sans authentification via des requêtes forgées. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-fortinet-forticlient-ems-flaw-cve-2026-35616-exploited-in-attacks/) |
| CVE-2025-55182 | 9.8 | Non spécifié | TRUE | Next.js (React2Shell) | RCE / Injection | T1505: Server Software Component | Exploitation de composants Next.js pour l'exécution de commandes et le vol de secrets. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-react2shell-in-automated-credential-theft-campaign/) |
| CVE-2026-3055 | 9.3 | Non spécifié | TRUE | Citrix NetScaler | Memory Overread | T1005: Data from Local System | Fuite de données sensibles via une lecture mémoire hors limites. | [Security Affairs](https://securityaffairs.com/190368/breaking-news/security-affairs-newsletter-round-571-by-pierluigi-paganini-international-edition.html) |
| CVE-2026-5605 | 9.0 | Non spécifié | FALSE | Tenda CH22 | Stack-based Overflow | T1210: Exploitation of Remote Services | Dépassement de tampon dans la fonction formWrlExtraSet permettant une exploitation distante. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-5605) |
| CVE-2026-4272 | 8.1 | Non spécifié | FALSE | Honeywell Handheld Scanners | Auth Bypass / RCE | T1210: Exploitation of Remote Services | Permet l'exécution de commandes système via Bluetooth sans authentification. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-4272) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Analyse d'un script CMD malveillant | Détails tactiques précis sur l'évasion d'antivirus et la persistance. | [Security Affairs](https://securityaffairs.com/190358/hacking/image-or-malware-read-until-the-end-and-answer-in-comments.html) |
| Campagne d'extraction via React2Shell | Alerte sur une automatisation massive ciblant les environnements cloud. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-react2shell-in-automated-credential-theft-campaign/) |
| Conflit US-Israël-Iran : Contexte Cyber | Analyse de la convergence cyber-cinétique et du modèle "Wiper-as-a-Service". | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| FortiClient EMS : Vulnérabilité critique | Criticité extrême et exploitation active sur un produit périmétrique. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-fortinet-forticlient-ems-flaw-cve-2026-35616-exploited-in-attacks/) |
| Hijacking npm Axios par la Corée du Nord | Menace majeure sur la chaîne d'approvisionnement (Supply Chain). | [Security Affairs](https://securityaffairs.com/190368/breaking-news/security-affairs-newsletter-round-571-by-pierluigi-paganini-international-edition.html) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| Attaque DCSync Active Directory | Article purement éducatif/générique sur une technique connue. | [Deniz Halil](https://denizhalil.com/2026/03/27/dcsync-attack-active-directory-guide/) |
| ISC Stormcast 06/04/2026 | Sommaire de podcast trop généraliste. | [SANS ISC](https://isc.sans.edu/podcastdetail/9880) |
| Killer Robots Podcast | Discussion éthique et philosophique, peu de données techniques exploitables. | [Malwarebytes](https://www.malwarebytes.com/blog/podcast/2026/04/killer-robots-are-here-now-what-lock-and-code-s07e07) |
| Vulnérabilités Kados R10 (2019) | Failles datant de 2019, manque de pertinence pour une veille actuelle. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2019-25704) |

<br>
<br>
<div id="articles"></div>

# ARTICLES
<div id="exploitation-critique-de-forticlient-ems"></div>

## [New FortiClient EMS flaw exploited in attacks, emergency patch released]
Fortinet a publié en urgence une mise à jour pour corriger la vulnérabilité CVE-2026-35616, affectant FortiClient EMS versions 7.4.5 et 7.4.6. Cette faille de contrôle d'accès permet à un attaquant non authentifié d'exécuter du code à distance via des requêtes HTTP forgées. La vulnérabilité est activement exploitée dans la nature, confirmée comme un "zero-day" avant son correctif. Plus de 2 000 instances exposées ont été identifiées, principalement aux États-Unis et en Allemagne. Cette faille suit une autre vulnérabilité critique corrigée la semaine précédente. Les correctifs sont disponibles sous forme de "hotfixes" spécifiques pour les versions impactées. Une montée de version vers la 7.4.7 est recommandée dès sa disponibilité. L'absence de mesures d'atténuation alternatives rend l'application des correctifs impérative.

**Analyse de l'impact** : Impact critique sur la sécurité périmétrique des entreprises utilisant Fortinet pour la gestion de leurs terminaux, pouvant mener à un compromis total du réseau interne.

**Recommandations** :
*   Appliquer immédiatement les hotfixes pour les versions 7.4.5 et 7.4.6 de FortiClient EMS.
*   Isoler les serveurs EMS d'Internet si le correctif ne peut être appliqué immédiatement.
*   Surveiller les logs HTTP pour des requêtes inhabituelles vers les API de gestion EMS.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié (exploité en "wild") |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br> * T1068: Exploitation for Privilege Escalation |
| Observables & Indicateurs de compromission | ```Aucun IoC spécifique n'est fourni dans l'article au-delà de la CVE-ID.``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/new-fortinet-forticlient-ems-flaw-cve-2026-35616-exploited-in-attacks/

<br>
<br>

<div id="campagne-massive-dextraction-de-secrets-via-react2shell"></div>

## [Hackers exploit React2Shell in automated credential theft campaign]
Le groupe UAT-10608 mène une campagne automatisée d'envergure ciblant la vulnérabilité React2Shell (CVE-2025-55182) dans les applications Next.js. Au moins 766 hôtes ont été compromis en seulement 24 heures pour dérober des secrets critiques. Les attaquants utilisent un framework nommé "NEXUS Listener" pour gérer l'exfiltration massive de données. Les informations ciblées incluent les identifiants AWS/GCP/Azure, les clés SSH privées, les tokens GitHub et les variables d'environnement. Le vol s'effectue via des scripts placés dans les répertoires temporaires des serveurs compromis. Cette campagne facilite les attaques ultérieures sur la chaîne d'approvisionnement et les mouvements latéraux via SSH. Cisco Talos a pu analyser un panneau de contrôle exposé, révélant l'ampleur du butin. Les victimes sont réparties mondialement chez divers fournisseurs cloud.

**Analyse de l'impact** : Risque majeur de compromission de l'infrastructure cloud et de fuite de données massives via le vol de tokens d'accès à privilèges élevés.

**Recommandations** :
*   Mettre à jour les frameworks Next.js et auditer l'exposition des données côté serveur.
*   Rotation immédiate de tous les secrets (clés API, SSH, tokens cloud) en cas de suspicion.
*   Activer le scan de secrets et appliquer le principe du moindre privilège pour les containers.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UAT-10608 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1505: Server Software Component <br> * T1555: Credentials from Password Stores <br> * T1048: Exfiltration Over Alternative Protocol |
| Observables & Indicateurs de compromission | ```* NEXUS Listener framework <br> * Exfiltration via port 8080 <br> * Scripts malveillants dans /tmp``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/hackers-exploit-react2shell-in-automated-credential-theft-campaign/

<br>
<br>

<div id="convergence-cyber-cinetique-dans-le-conflit-us-israel-iran"></div>

## [Monitoring Cyberattacks Directly Linked to the US-Israel-Iran Military Conflict]
Le conflit entre les États-Unis, Israël et l'Iran a généré une période de cyber-guerre intensive sans précédent. Une campagne de spyware iranienne cible actuellement les civils israéliens via de fausses applications de localisation d'abris anti-bombes. Ces SMS malveillants sont envoyés précisément pendant les frappes de missiles pour maximiser les téléchargements sous l'effet de la panique. Le groupe Code Blue signale un virage stratégique iranien du "Ransomware-as-a-Service" vers le "Wiper-as-a-Service". Ce modèle permet de distribuer des outils destructeurs identiques à divers groupes proxies pour compliquer l'attribution. En Iran, la coupure quasi-totale d'Internet (1% de connectivité) entre dans son 37ème jour pour museler la population. Près de 5 800 cyberattaques ont été enregistrées contre les intérêts américains et israéliens depuis le début des hostilités.

**Analyse de l'impact** : Escalade de la menace destructive (wipers) et utilisation tactique du cyber pour soutenir des opérations psychologiques et cinétiques en temps réel.

**Recommandations** :
*   Renforcer la vigilance sur les menaces mobiles (SMishing) ciblant les employés en zones de conflit.
*   Bloquer les flux réseau entrants provenant de plages IP iraniennes non nécessaires.
*   Maintenir des sauvegardes "hors ligne" robustes face à la recrudescence des malwares de type wiper.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Handala Hack, IRGC, 313 Team, Fox Kitten |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.002: Spearphishing Service <br> * T1485: Data Destruction <br> * T1471: Data Encrypted for Impact (Pseudo-ransomware) |
| Observables & Indicateurs de compromission | ```* Malware: Shamoon 4.0 <br> * App: Fake Bomb Shelter (Android) <br> * Tunnels: NetBird``` |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict

<br>
<br>

<div id="analyse-technique-dune-infection-par-script-cmd-malveillant"></div>

## [Image or Malware? Read until the end and answer in comments]
Une analyse détaillée d'un script `.cmd` malveillant révèle une chaîne d'infection sophistiquée visant les systèmes Windows. Le script débute par une escalade de privilèges via PowerShell pour s'exécuter en tant qu'administrateur. Il configure immédiatement des exclusions dans Windows Defender pour son répertoire d'installation caché. Le malware utilise `curl.exe` pour télécharger un payload déguisé en image `.jpg`, qui est ensuite renommé en `.zip` et extrait. La persistance est établie via une tâche planifiée nommée "IntelGraphicsTask" pour paraître légitime. Le script finalise l'infection par un redémarrage forcé du système sous 60 secondes avant de s'auto-supprimer. L'analyse des fichiers extraits (DLL et exécutable) montre des techniques d'obfuscation et l'utilisation de fonctions dupliquées pour tromper les analystes.

**Analyse de l'impact** : Risque de prise de contrôle totale de la machine victime avec des mécanismes d'évasion d'antivirus efficaces au moment de l'infection.

**Recommandations** :
*   Interdire l'exécution de scripts `.cmd` ou `.bat` provenant de sources non fiables (e-mail).
*   Monitorer l'utilisation de `Add-MpPreference` dans PowerShell via les outils EDR/SIEM.
*   Rechercher la présence de tâches planifiées suspectes comme "IntelGraphicsTask".

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1548.002: Bypass User Account Control <br> * T1053.005: Scheduled Task <br> * T1562.001: Disable or Modify Tools (AV Exclusion) |
| Observables & Indicateurs de compromission | ```* URL: hxxps://search[.]app/a3qBe <br> * URL: hxxps://is[.]gd/cjIjvU <br> * Tâche: \Microsoft\Windows\IntelGraphicsTask``` |

### Source (url) du ou des articles
* https://securityaffairs.com/190358/hacking/image-or-malware-read-until-the-end-and-answer-in-comments.html

<br>
<br>

<div id="attaque-par-canal-dapprovisionnement-visant-le-paquet-npm-axios"></div>

## [North Korea-Nexus Threat Actor Compromises Widely Used Axios NPM Package]
L'acteur nord-coréen UNC1069 a réussi à détourner le compte d'un mainteneur du paquet npm très populaire "Axios". Cette attaque par la chaîne d'approvisionnement a permis d'injecter des versions malveillantes du paquet pour diffuser un cheval de Troie (RAT). L'objectif principal semble être le vol d'identifiants de développeurs et l'exfiltration de secrets de configuration. L'attaque utilise des techniques d'injection de dépendances pour se propager silencieusement dans les projets utilisant Axios. Google et SentinelOne ont lié cette activité à l'APT BlueNoroff, connu pour ses motivations financières. L'incident souligne la fragilité des écosystèmes de gestion de paquets et l'impact démesuré du compromis d'un seul compte clé.

**Analyse de l'impact** : Risque systémique pour des millions d'applications web dépendant d'Axios, pouvant mener à des compromissions en cascade de serveurs de production.

**Recommandations** :
*   Vérifier les versions des paquets Axios utilisées et s'assurer de ne pas utiliser de versions compromises (vérifier les signatures).
*   Implémenter le "lock-filing" (package-lock.json) et auditer les changements de dépendances.
*   Utiliser des outils de SCA (Software Composition Analysis) pour détecter les paquets malveillants connus.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UNC1069 (BlueNoroff / Corée du Nord) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.001: Compromise Software Dependencies <br> * T1552: Unsecured Credentials |
| Observables & Indicateurs de compromission | ```* Paquet: axios (npm) <br> * Malware: RustBucket variant / Axios RAT``` |

### Source (url) du ou des articles
* https://securityaffairs.com/190368/breaking-news/security-affairs-newsletter-round-571-by-pierluigi-paganini-international-edition.html
* https://securityaffairs.com/190379/malware/security-affairs-malware-newsletter-round-91.html