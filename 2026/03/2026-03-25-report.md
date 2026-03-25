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
  * [Conflit cyber US-Israël-Iran : l'attaque de Stryker par Handala](#conflit-cyber-us-israel-iran-lattaque-de-stryker-par-handala)
  * [Campagne SmartApeSG : Remcos RAT et technique ClickFix](#campagne-smartapesg-remcos-rat-et-technique-clickfix)
  * [Compromission de la chaîne d'approvisionnement LiteLLM](#compromission-de-la-chaine-dapprovisionnement-litellm)
  * [Exploitation critique de l'outil d'IA Langflow](#exploitation-critique-de-loutil-dia-langflow)
  * [Fuite du kit d'exploitation DarkSword pour iOS](#fuite-du-kit-dexploitation-darksword-pour-ios)
  * [Menace imminente sur PTC Windchill et FlexPLM](#menace-imminente-sur-ptc-windchill-et-flexplm)
  * [StoatWaffle : Malware nord-coréen via VS Code](#stoatwaffle-malware-nord-coreen-via-vs-code)
  * [Vulnérabilité RCE critique dans Microsoft Azure MCP](#vulnerabilite-rce-critique-dans-microsoft-azure-mcp)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage cyber de mars 2026 est marqué par une intensification sans précédent des conflits étatiques, particulièrement dans le triangle États-Unis-Israël-Iran, où le cyber est désormais une extension directe des opérations cinétiques avec des attaques destructrices sur les infrastructures critiques. Parallèlement, la menace sur la chaîne d'approvisionnement logicielle franchit un nouveau palier avec la compromission de paquets populaires comme LiteLLM et Trivy, ciblant spécifiquement les environnements de développement et d'IA. L'émergence d'attaques exploitant les frameworks d'IA (Langflow) et les outils de développement (VS Code) souligne une volonté de compromettre les actifs immatériels les plus sensibles des entreprises. La fuite du kit DarkSword pour iOS démocratise des capacités d'espionnage autrefois réservées aux États, augmentant radicalement le risque pour les décideurs mobiles. Enfin, la réponse des autorités allemandes face à la faille PTC témoigne d'une urgence accrue pour sécuriser la base industrielle face à l'espionnage. Les organisations doivent impérativement renforcer leur résilience en couplant une approche Zero Trust stricte à une surveillance accrue de leurs dépendances logicielles.
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
| APT Iran | Défense (Lockheed Martin) | Vol de données massif (375To revendiqués) | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Handala Hack (MOIS) | Santé, Gouvernement | Wipe de dispositifs via Microsoft Intune | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Nasir Security | Énergie | Ciblage des compagnies du Golfe | [Security Affairs](https://securityaffairs.com) |
| Team 8 (Contagious Interview) | Blockchain, Développement | Malicious VS Code projects (StoatWaffle) | [Security Affairs](https://securityaffairs.com) |
| TeamPCP | Logistique, Logiciel | Supply chain attack (PyPI, Trivy) | [BleepingComputer](https://www.bleepingcomputer.com/news/security/popular-litellm-pypi-package-compromised-in-teampcp-supply-chain-attack/) |
| UNC6353 | Gouvernement (Ukraine) | Espionnage via iOS (DarkSword) | [CybersecurityNews](https://cybersecuritynews.com/darksword-exploit-chain-leaked/) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Commerce | Blocage OMC | Obstruction américaine systématique du système de règlement des différends. | [Portail IE](https://www.portail-ie.fr/univers/droit-et-intelligence-juridique/2026/blocage-de-lorgane-dappel-de-lomc/) |
| Défense | Guerre US-Israël-Iran | Cyberattaques intensives liées au conflit cinétique, blackout internet en Iran. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Diplomatie | Influence Maroc | Stratégie de "Sport Power" via la CAN 2025 et le Mondial 2030 pour le rayonnement économique. | [Portail IE](https://www.portail-ie.fr/univers/2026/maroc-economie-sport/) |
| États-Unis | Divisions internes | Fractures au sein de l'administration Trump concernant l'engagement en Iran. | [IRIS](https://www.iris-france.org/divisions-au-sein-de-ladministration-trump-la-guerre-comme-reflet-dune-fragilisation-du-soutien-a-la-politique-etrangere-etats-unienne/) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Ban on foreign-made routers | FCC | 24/03/2026 | États-Unis | Secure and Trusted Communications Networks Act | Interdiction de vente de routeurs grand public fabriqués à l'étranger pour des raisons de sécurité nationale. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/fcc-bans-new-routers-made-outside-the-usa-over-security-risks/) |
| Data Disclosure Bill (AB 2013) | État de Californie | 24/03/2026 | Californie, USA | AB 2013 | Obligation de divulguer les données utilisées pour l'entraînement des IA génératives. | [GuidePoint Security](https://www.guidepointsecurity.com/blog/ai-transparency-paradox-build-trust-without-risk/) |
| RAISE Act | État de New York | 24/03/2026 | New York, USA | RAISE Act | Exigences de transparence et de reporting pour les développeurs de grands modèles d'IA. | [GuidePoint Security](https://www.guidepointsecurity.com/blog/ai-transparency-paradox-build-trust-without-risk/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Éducation | Ministère de l'Éducation Nationale (France) | Compromission de 243 000 agents via le logiciel Compas (stagiaires). | [Le Monde](https://www.lemonde.fr/education/article/2026/03/24/le-piratage-d-un-logiciel-compromet-les-donnees-de-243-000-agents-de-l-education-nationale_6673988_1473685.html) |
| Finance | Ministère des Finances (Pays-Bas) | Accès non autorisé à des systèmes internes impactant une partie du personnel. | [Security Affairs](https://securityaffairs.com/189929/data-breach/data-breach-at-dutch-ministry-of-finance-impacts-staff-following-cyberattack.html) |
| Gouvernement | Foster City | Ville mise hors ligne suite à une cyberattaque impactant les services municipaux. | [DataBreaches](https://databreaches.net) |
| Santé | Mirra Health (Floride) | Données de milliers de membres Medicare exposées via une sous-traitance illégale en Asie. | [DataBreaches](https://databreaches.net) |
| Santé | QualDerm Partners | Vol de données médicales et personnelles impactant 3,1 millions de patients. | [Security Affairs](https://securityaffairs.com/189917/data-breach/qualderm-partners-december-2025-data-breach-impacts-over-3-million-people.html) |
| Technologie | HackerOne | Fuite de données d'employés suite à la compromission du prestataire Navia. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackerone-discloses-employee-data-breach-after-navia-hack/) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|
| CVE-2026-4606 | 10.0 | GeoVision Edge Recording Manager | Élévation de privilèges SYSTEM | [SecurityOnline](https://securityonline.info/geovision-erm-critical-vulnerability-cve-2026-4606-system-privilege-escalation/) |
| ZDI-26-226 | 9.8 | Microsoft Azure MCP (azure-cli-mcp) | Exécution de code à distance (RCE) | [ZDI](http://www.zerodayinitiative.com/advisories/ZDI-26-226/) |
| CVE-2026-3055 | 9.3 | Citrix NetScaler ADC & Gateway | Fuite de mémoire (SAML IDP) | [HelpNetSecurity](https://www.helpnetsecurity.com/2026/03/24/netscaler-adc-gateway-cve-2026-3055/) |
| CVE-2026-33017 | 9.3 | Langflow | Exécution de code à distance (RCE) | [Field Effect](https://fieldeffect.com/blog/langflow-deployments-targeted-patch) |
| CVE-2026-33419 | 9.1 | MinIO | Brute-force et énumération d'utilisateurs | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-33419) |
| CVE-2025-33244 | 9.0 | NVIDIA APEX (Linux) | Désérialisation de données non fiables | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2025-33244) |
| CVE-2026-3912 | 8.7 | TIBCO ActiveMatrix BusinessWorks | Injection et divulgation d'informations | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-3912) |
| CVE-2026-32710 | 8.6 | MariaDB | Buffer Overflow (JSON Schema) | [SecurityOnline](https://securityonline.info/mariadb-json-schema-validation-buffer-overflow-vulnerability-cve-2026-32710/) |
| CVE-2026-4681 | Critique | PTC Windchill & FlexPLM | Exécution de code à distance (RCE) | [BleepingComputer](https://www.bleepingcomputer.com/news/security/ptc-warns-of-imminent-threat-from-critical-windchill-flexplm-rce-bug/) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| (0Day) Microsoft Azure MCP AzureCliService RCE | Vulnérabilité majeure (9.8) sur un service cloud critique sans authentification. | [ZDI](http://www.zerodayinitiative.com/advisories/ZDI-26-226/) |
| DarkSword Exploit Chain Leaked Online | Fuite d'un kit d'espionnage iOS étatique impactant potentiellement des millions d'appareils. | [CybersecurityNews](https://cybersecuritynews.com/darksword-exploit-chain-leaked/) |
| Langflow deployments targeted hours after patch | Ciblage actif d'outils d'IA, domaine en pleine expansion et critique. | [Field Effect](https://fieldeffect.com/blog/langflow-deployments-targeted-patch) |
| LiteLLM PyPI package backdoored | Attaque supply chain majeure sur un outil d'IA très populaire (3.4M downloads/jour). | [BleepingComputer](https://www.bleepingcomputer.com/news/security/popular-litellm-pypi-package-compromised-in-teampcp-supply-chain-attack/) |
| Monitoring Cyberattacks Linked to US-Israel-Iran | Détails cruciaux sur un conflit cyber d'envergure mondiale impactant des entreprises US. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| North Korea-linked threat actors abuse VS Code | Technique innovante ciblant les développeurs via des fonctionnalités légitimes. | [Security Affairs](https://securityaffairs.com/189880/security/north-korea-linked-threat-actors-abuse-vs-code-auto-run-to-spread-stoatwaffle-malware.html) |
| PTC warns of imminent threat from critical bug | Urgence exceptionnelle (intervention police allemande) et risque d'espionnage industriel. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/ptc-warns-of-imminent-threat-from-critical-windchill-flexplm-rce-bug/) |
| SmartApeSG campaign pushes Remcos RAT | Analyse détaillée d'une campagne active utilisant la technique ClickFix. | [SANS ISC](https://isc.sans.edu/diary/32826) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| 50 Israeli companies ‘digitally erased’ | Notification de violation de données (Critères). | [DataBreaches](https://databreaches.net) |
| 81-month sentence for Russian hacker | Actualité juridique/judiciaire sans menace technique immédiate. | [Security Affairs](https://securityaffairs.com) |
| Data breach at Dutch Ministry of Finance | Notification de violation de données (Critères). | [Security Affairs](https://securityaffairs.com) |
| FCC bans new routers | Article réglementaire traité en synthèse. | [BleepingComputer](https://www.bleepingcomputer.com) |
| Firefox now has a free built-in VPN | Actualité produit/fonctionnalité, faible menace cyber directe. | [BleepingComputer](https://www.bleepingcomputer.com) |
| Maroc : la conquête économique par le sport | Actualité géopolitique pure sans volet cyber. | [Portail IE](https://www.portail-ie.fr) |
| QualDerm Partners breach | Notification de violation de données (Critères). | [Security Affairs](https://securityaffairs.com) |
| Zero Trust: Bridging the Gap | Article sponsorisé/marketing à faible valeur analytique. | [BleepingComputer](https://www.bleepingcomputer.com) |

<br>
<br>
<div id="articles"></div>

# ARTICLES

<div id="conflit-cyber-us-israel-iran-lattaque-de-stryker-par-handala"></div>

## Monitoring Cyberattacks Directly Linked to the US-Israel-Iran Military Conflict
Le conflit cyber entre les États-Unis, Israël et l’Iran atteint des sommets d’intensité avec des opérations destructrices ciblant les infrastructures critiques. L’entreprise médicale Stryker Corporation subit les conséquences d’une attaque par « wiper » attribuée au groupe Handala (lié à l’Iran). L’attaque a exploité Microsoft Intune pour effacer plus de 200 000 dispositifs dans 79 pays. En parallèle, le groupe « APT Iran » revendique le vol de 375 To de données chez Lockheed Martin, incluant des plans du F-35. L’Iran fait face à un blackout internet national de plus de 550 heures. Le FBI a publié une alerte sur des campagnes de malware via Telegram (MOIS) ciblant les dissidents. Le Département d'État américain a lancé un bureau spécialisé pour contrer ces menaces cyber adverses.

**Analyse de l'impact** : L'impact est systémique, touchant à la fois la sécurité nationale (espionnage aéronautique), la santé publique (paralysie de Stryker) et l'économie globale. L'utilisation de plateformes de gestion cloud (Intune) comme vecteur de destruction massive redéfinit les risques pour les entreprises globales.

**Recommandations** : Activer impérativement l'approbation multi-administrateurs (Multi-Admin Approval) pour les commandes critiques de type "wipe" ou "reset" dans les consoles MDM/EDM. Effectuer des recherches de compromission (Threat Hunting) sur les comptes à privilèges Azure/Intune.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Handala Hack, APT Iran, MOIS |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1071.001: Application Layer Protocol (Telegram C2) <br/> * T1561.002: Endpoint Denial of Service (Disk Wipe) <br/> * T1078.004: Cloud Accounts |
| Observables & Indicateurs de compromission | ```api.telegram.org``` |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict

<br>
<br>

<div id="campagne-smartapesg-remcos-rat-et-technique-clickfix"></div>

## SmartApeSG campaign pushes Remcos RAT, NetSupport RAT, StealC, and Sectop RAT
La campagne SmartApeSG (aussi connue sous les noms ZPHP ou HANEYMANEY) utilise la technique « ClickFix » pour infecter ses victimes. L’attaque repose sur une fausse page de CAPTCHA injectée dans des sites web légitimes compromis. L'utilisateur est incité à copier et exécuter un script malveillant dans son presse-papiers, qui déploie initialement Remcos RAT. Quelques minutes ou heures plus tard, d'autres malwares sont téléchargés : NetSupport RAT, StealC (infostealer) et Sectop RAT. L'analyse montre l'utilisation de fichiers HTA et de packages ZIP utilisant le DLL side-loading pour s'exécuter. Les indicateurs de compromission changent quasi quotidiennement, rendant la détection par signature difficile.

**Analyse de l'impact** : La menace est élevée car elle combine ingénierie sociale efficace et déploiement de multiples outils d'accès distant et de vol de données, permettant une persistance et une exfiltration complète.

**Recommandations** : Sensibiliser les utilisateurs contre les instructions de type "Copier-Coller" dans PowerShell ou les invites de commande provenant de sites web (CAPTCHA, erreurs de navigateur). Surveiller l'exécution de processus suspects issus de fichiers .HTA.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | SmartApeSG (ZPHP / HANEYMANEY) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1204.002: User Execution (Malicious File) <br/> * T1574.002: DLL Side-Loading <br/> * T1059.007: JavaScript/VBScript (HTA) |
| Observables & Indicateurs de compromission | ```95.142.45.231```, ```185.163.47.220```, ```89.46.38.100```, ```195.85.115.11```, ```urotypos.com```, ```212d8007a7ce374d38949cf54d80133bd69338131670282008940f1995d7a720``` |

### Source (url) du ou des articles
* https://isc.sans.edu/diary/rss/32826

<br>
<br>

<div id="compromission-de-la-chaine-dapprovisionnement-litellm"></div>

## Popular LiteLLM PyPI package backdoored to steal credentials
Le groupe de pirates TeamPCP a compromis le paquet Python « LiteLLM », téléchargé plus de 3,4 millions de fois par jour. Les versions malveillantes 1.82.7 et 1.82.8 contiennent un infostealer nommé « TeamPCP Cloud Stealer ». Le code malveillant est injecté sous forme de charge utile base64 dans le fichier `proxy_server.py`. Une fois exécuté, il récolte des clés SSH, des jetons cloud (AWS, GCP, Azure), des secrets Kubernetes et des portefeuilles crypto. Il installe également un service système persistant déguisé en télémétrie. TeamPCP revendique la compromission de centaines de milliers de dispositifs. Cette attaque fait suite à la brèche d'Aqua Security Trivy, suggérant un effet de cascade.

**Analyse de l'impact** : L'impact est critique pour les entreprises développant des solutions d'IA, car LiteLLM est un composant central de nombreux pipelines. Le vol de secrets cloud peut mener à des compromissions totales d'infrastructure.

**Recommandations** : Vérifier immédiatement les installations de LiteLLM et rétrograder vers la version 1.82.6. Faire pivoter impérativement tous les secrets, jetons et identifiants présents sur les machines affectées. Rechercher le fichier `~/.config/sysmon/sysmon.py`.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TeamPCP |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Supply Chain Compromise (Software Dependencies) <br/> * T1539: Steal Web Session Cookie <br/> * T1543.002: Systemd Service |
| Observables & Indicateurs de compromission | ```models.litellm.cloud```, ```checkmarx.zone```, ```/tmp/pglog``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/popular-litellm-pypi-package-compromised-in-teampcp-supply-chain-attack/

<br>
<br>

<div id="exploitation-critique-de-loutil-dia-langflow"></div>

## Internet‑exposed Langflow deployments targeted hours after patch release
Une vulnérabilité critique de type RCE (CVE-2026-33017) dans le framework IA Langflow est activement exploitée. La faille affecte les versions jusqu'à 1.8.1 et permet à un attaquant non authentifié d'exécuter du code Python arbitraire. L'exploitation a commencé moins de 20 heures après la publication de l'avis de sécurité, sans preuve de concept publique initiale. Le point de terminaison vulnérable est `POST /api/v1/build_public_tmp/{flow_id}/flow`. Les attaquants peuvent accéder aux variables d'environnement et établir un accès persistant. Langflow est souvent utilisé pour connecter des agents IA à des sources de données sensibles.

**Analyse de l'impact** : Menace sérieuse pour les environnements de recherche en IA et les bacs à sable de développement souvent exposés sans contrôles stricts.

**Recommandations** : Mettre à jour vers Langflow 1.9.0 immédiatement. En cas d'impossibilité, bloquer l'accès externe à l'endpoint spécifique et placer l'instance derrière un VPN ou une passerelle Zero Trust. Faire pivoter les clés d'API exposées dans les variables d'environnement.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br/> * T1059.006: Python execution |
| Observables & Indicateurs de compromission | Aucun IoC spécifique n'est fourni |

### Source (url) du ou des articles
* https://fieldeffect.com/blog/langflow-deployments-targeted-patch

<br>
<br>

<div id="fuite-du-kit-dexploitation-darksword-pour-ios"></div>

## DarkSword Exploit Chain That Can Hack Millions of iPhones Leaked Online
Le kit d'exploitation iOS « DarkSword », utilisé par des acteurs étatiques, a été divulgué sur GitHub. Ce kit combine six vulnérabilités zero-day pour obtenir un accès complet au noyau (kernel) d'un iPhone via une simple page web. Il a été initialement observé dans des campagnes d'espionnage contre des citoyens ukrainiens par le groupe UNC6353 (lié à la Russie). DarkSword permet l'exfiltration rapide de messages WhatsApp, Telegram, iMessage, de photos et de données de portefeuilles crypto. Environ 25% des appareils iOS actifs seraient encore vulnérables car fonctionnant sous iOS 18 ou antérieur. Le kit a été testé avec succès par des chercheurs sur des appareils iOS 18.6.2.

**Analyse de l'impact** : Très élevé. La fuite transforme un outil sophistiqué en une arme accessible à des attaquants moins compétents, menaçant des centaines de millions d'utilisateurs.

**Recommandations** : Mettre à jour les appareils vers iOS 26 (ou le dernier patch d'urgence pour les anciens modèles). Activer le « Lockdown Mode » (Mode de protection maximale) pour les profils à risque, ce qui bloque efficacement cette chaîne d'exploitation.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UNC6353 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1203: Exploitation for Client Execution <br/> * T1068: Exploitation for Privilege Escalation <br/> * T1437.001: Browser-based injection |
| Observables & Indicateurs de compromission | Aucun IoC spécifique n'est fourni |

### Source (url) du ou des articles
* https://cybersecuritynews.com/darksword-exploit-chain-leaked/

<br/>
<br/>

<div id="menace-imminente-sur-ptc-windchill-et-flexplm"></div>

## PTC warns of imminent threat from critical Windchill, FlexPLM RCE bug
L'éditeur PTC a émis une alerte urgente concernant une vulnérabilité RCE critique (CVE-2026-4681) dans ses solutions PLM Windchill et FlexPLM. La faille provient d'une désérialisation de données non fiables. La menace est jugée si imminente que la police fédérale allemande (BKA) a dépêché des agents pour alerter physiquement les entreprises durant le week-end. Bien qu'aucun exploit public ne soit recensé, des preuves crédibles indiquent qu'un groupe tiers se prépare à l'exploiter. Ces systèmes gèrent des données sensibles de conception industrielle et de chaînes d'approvisionnement critiques.

**Analyse de l'impact** : Risque majeur d'espionnage industriel à grande échelle ciblant les secteurs de l'armement et de la fabrication lourde.

**Recommandations** : Appliquer immédiatement la règle Apache/IIS fournie par PTC pour bloquer l'accès au chemin du servlet affecté. Prioriser la protection des instances exposées à internet ou déconnecter temporairement les services si aucune mesure de blocage n'est possible.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1203: Exploitation for Client Execution |
| Observables & Indicateurs de compromission | ```GW.class```, ```payload.bin```, ```dpr_*.jsp``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/ptc-warns-of-imminent-threat-from-critical-windchill-flexplm-rce-bug/

<br/>
<br/>

<div id="stoatwaffle-malware-nord-coreen-via-vs-code"></div>

## North Korea-linked threat actors abuse VS Code auto-run to spread StoatWaffle
Le groupe nord-coréen Team 8 (lié à la campagne Contagious Interview) utilise une nouvelle technique de malware nommée « StoatWaffle ». L'attaque cible les développeurs via des projets malicieux Microsoft Visual Studio Code. En abusant de la fonctionnalité légitime `tasks.json`, les attaquants déclenchent l'exécution de code dès l'ouverture d'un dossier dans l'éditeur. StoatWaffle est un malware modulaire basé sur Node.js comprenant des modules de vol de données (credentials, Keychain macOS, extensions de navigateur) et un cheval de Troie d'accès à distance (RAT). L'acteur utilise des projets blockchain comme leurres.

**Analyse de l'impact** : Ciblage précis des développeurs pour voler des secrets de code source et des clés d'infrastructure, avec une exécution quasi-transparente.

**Recommandations** : Désactiver l'exécution automatique des tâches dans Visual Studio Code ou restreindre l'ouverture de dossiers provenant de sources non vérifiées. Surveiller les exécutions inhabituelles de `cmd.exe` ou `node.exe` initiées par VS Code.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Team 8 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1204.001: User Execution (Malicious Link/File) <br/> * T1555.003: Credentials from Web Browsers <br/> * T1059.003: Windows Command Shell |
| Observables & Indicateurs de compromission | ```StoatWaffle```, ```cmd.exe```, ```tasks.json``` |

### Source (url) du ou des articles
* https://securityaffairs.com/189880/security/north-korea-linked-threat-actors-abuse-vs-code-auto-run-to-spread-stoatwaffle-malware.html

<br/>
<br/>

<div id="vulnerabilite-rce-critique-dans-microsoft-azure-mcp"></div>

## (0Day) Microsoft Azure MCP AzureCliService Command Injection RCE
Une vulnérabilité de type injection de commande (ZDI-26-226) a été découverte dans le composant `azure-cli-mcp` de Microsoft Azure. La faille permet à un attaquant distant d'exécuter du code arbitraire sur les installations affectées sans aucune authentification préalable. Le problème réside dans un manque de validation d'une chaîne fournie par l'utilisateur avant son utilisation dans un appel système. L'attaquant peut ainsi prendre le contrôle du serveur MCP. Cette vulnérabilité a reçu le score CVSS maximal de 9.8.

**Analyse de l'impact** : Critique. Cette faille permet une prise de contrôle totale de segments d'infrastructure Azure, avec un risque élevé de mouvement latéral ou de compromission de données clients.

**Recommandations** : Appliquer les correctifs de sécurité fournis par Microsoft pour Azure CLI. Limiter les accès réseau aux services de gestion Azure uniquement aux adresses IP de confiance. Surveiller les logs système pour toute exécution de commande inhabituelle par le processus MCP.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br/> * T1059: Command and Scripting Interpreter |
| Observables & Indicateurs de compromission | Aucun IoC spécifique n'est fourni |

### Source (url) du ou des articles
* http://www.zerodayinitiative.com/advisories/ZDI-26-226/