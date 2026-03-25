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
  * [Campagne SmartApeSG : une cascade de malwares via ClickFix](#campagne-smartapesg-une-cascade-de-malwares-via-clickfix)
  * [Menace imminente sur PTC Windchill et FlexPLM](#menace-imminente-sur-ptc-windchill-et-flexplm)
  * [Attaque de la chaîne d'approvisionnement sur LiteLLM](#attaque-de-la-chaine-dapprovisionnement-sur-litellm)
  * [Exploitation critique de Langflow après correction](#exploitation-critique-de-langflow-apres-correction)
  * [Compromission de Trivy et vol de secrets CI/CD](#compromission-de-trivy-et-vol-de-secrets-cicd)
  * [StoatWaffle : la Corée du Nord abuse des tâches VS Code](#stoatwaffle-la-coree-du-nord-abuse-des-taches-vs-code)
  * [GeoVision ERM : une faille critique CVSS 10.0](#geovision-erm-une-faille-critique-cvss-100)
  * [Citrix NetScaler : fuite de mémoire critique (CVE-2026-3055)](#citrix-netscaler-fuite-de-memoire-critique-cve-2026-3055)
  * [Conflit US-Israël-Iran : escalade des opérations cyber destructrices](#conflit-us-israel-iran-escalade-des-operations-cyber-destructrices)
  * [Guerre d'usure et souveraineté du détroit d'Ormuz](#guerre-dusure-et-souverainete-du-detroit-dormuz)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage actuel de la menace est dominé par l'escalade sans précédent du conflit cyber entre l'axe US-Israël et l'Iran, marqué par des attaques destructrices d'envergure contre les infrastructures critiques (Stryker, Lockheed Martin). Cette période de "guerre totale" met en lumière la fragilité des chaînes d'approvisionnement logicielles, comme en témoignent les compromissions successives de Trivy et LiteLLM par le groupe TeamPCP pour le vol de secrets CI/CD. Parallèlement, l'épuisement rapide des stocks de munitions de précision par les forces de la coalition souligne un nouveau paradigme : la "Command of the Reload", où la capacité industrielle de réapprovisionnement devient le pivot de la survie stratégique. On observe également une professionnalisation des attaques sur les environnements de développement, avec l'usage par la Corée du Nord de fonctionnalités légitimes de VS Code pour diffuser des malwares modulaires. La découverte de vulnérabilités critiques avec un score CVSS de 10.0 (GeoVision) ou provoquant des alertes gouvernementales nocturnes (PTC) confirme une pression constante sur les actifs industriels et de surveillance. Enfin, les mesures protectionnistes américaines, telles que le bannissement des routeurs étrangers, marquent une fragmentation croissante de l'infrastructure numérique mondiale.
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
| **APT Iran** | Défense (Lockheed Martin) | Exfiltration massive de données (375 To revendiqués), extorsion de fonds. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| **Handala Hack** | Santé, Défense, Dissidents | Abus de Microsoft Intune pour des attaques d'effacement (wiper), Telegram C2. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| **MOIS (Iran)** | Dissidents, Journalistes | Malwares camouflés (Pictory, KeePass), C2 via bots Telegram, enregistrement Zoom. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| **SmartApeSG (ZPHP)** | Multi-secteurs | Technique ClickFix (faux CAPTCHA), diffusion en cascade de RAT (Remcos, NetSupport). | [SANS ISC](https://isc.sans.edu/diary/rss/32826) |
| **Team 8 (Corée du Nord)** | Blockchain, Développeurs | Abus du fichier `tasks.json` dans VS Code pour exécuter StoatWaffle. | [Security Affairs](https://securityaffairs.com/189880/security/north-korea-linked-threat-actors-abuse-vs-code-auto-run-to-spread-stoatwaffle-malware.html) |
| **TeamPCP** | Supply Chain Cyber | Compromission de packages PyPI (LiteLLM) et outils de sécurité (Trivy), vol de secrets cloud/SSH. | [Bleeping Computer](https://www.bleepingcomputer.com/news/security/popular-litellm-pypi-package-compromised-in-teampcp-supply-chain-attack/) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| **Commerce Mondial** | OMC / Obstruction US | Blocage systématique de l'Organe d'appel de l'OMC par les États-Unis, paralysant le règlement des différends. | [Portail de l'IE](https://www.portail-ie.fr/univers/droit-et-intelligence-juridique/2026/blocage-de-lorgane-dappel-de-lomc/) |
| **Défense / Énergie** | Conflit US-Israël-Iran | Guerre cyber intensive liée aux frappes cinétiques ; blackout internet total en Iran (25ème jour). | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| **Diplomatie / Sport** | Soft Power Marocain | Utilisation de la CAN 2025 et du Mondial 2030 comme outils d'influence économique et politique en Afrique. | [Portail de l'IE](https://www.portail-ie.fr/univers/2026/maroc-economie-sport/) |
| **Guerre Informationnelle** | Propagande Russe | Amplification par le Kremlin des mouvements séparatistes occidentaux (Texas, Alberta) tout en réprimant l'autonomie interne. | [EUvsDisinfo](https://euvsdisinfo.eu/secession-for-you-prison-in-russia-moscows-selective-love-for-self-determination/) |
| **Logistique Maritime** | Détroit d'Ormuz | Contrôle pratique du détroit par l'Iran via des taxes et des inspections, malgré la présence militaire américaine. | [RUSI](https://www.rusi.org/explore-our-research/publications/commentary/strait-hormuz-problem-what-securing-waterway-actually-requires) |
| **Politique US** | Divisions Trump | Fractures internes suite à l'implication dans la guerre en Iran et démissions au sein de l'administration. | [IRIS](https://www.iris-france.org/divisions-au-sein-de-ladministration-trump-la-guerre-comme-reflet-dune-fragilisation-du-soutien-a-la-politique-etrangere-etats-unienne/) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| **California Generative AI Training Data Disclosure Bill** | GuidePoint Security | 24/03/2026 | États-Unis (Californie) | AB 2013 | Obligation de divulguer les données utilisées pour l'entraînement des systèmes d'IA générative. | [GuidePoint](https://www.guidepointsecurity.com/blog/ai-transparency-paradox-build-trust-without-risk/) |
| **FCC bans new routers made outside the USA** | Bill Toulas | 24/03/2026 | États-Unis | Secure and Trusted Communications Networks Act | Interdiction de vente de nouveaux routeurs grand public fabriqués à l'étranger pour des raisons de sécurité nationale. | [Bleeping Computer](https://www.bleepingcomputer.com/news/security/fcc-bans-new-routers-made-outside-the-usa-over-security-risks/) |
| **RAISE Act** | GuidePoint Security | 24/03/2026 | États-Unis (New York) | RAISE Act | Exigences de transparence et de reporting pour les développeurs de grands modèles d'IA "frontière". | [GuidePoint](https://www.guidepointsecurity.com/blog/ai-transparency-paradox-build-trust-without-risk/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| **Administration Publique** | Ministère de l'Éducation (FR) | Vol de données de 243 000 agents via le logiciel Compas ; revendiqué par "Hexdex". | [Le Monde](https://www.lemonde.fr/education/article/2026/03/24/le-piratage-d-un-logiciel-compromet-les-donnees-de-243-000-agents-de-l-education-nationale_6673988_1473685.html) |
| **Administration Publique** | Ministère des Finances (NL) | Accès non autorisé à des systèmes internes ; impact sur une partie des employés. | [Security Affairs](https://securityaffairs.com/189929/data-breach/data-breach-at-dutch-ministry-of-finance-impacts-staff-following-cyberattack.html) |
| **Cyber-services** | HackerOne | Fuite de données via le prestataire Navia (vulnérabilité BOLA) ; 287 employés touchés. | [Bleeping Computer](https://www.bleepingcomputer.com/news/security/hackerone-discloses-employee-data-breach-after-navia-hack/) |
| **Santé** | Mirra Health (US/FL) | Exposition de données Medicare suite à l'externalisation illégale vers l'Inde et les Philippines. | [DataBreaches.net](https://databreaches.net/2026/03/24/florida-medicare-members-data-exposed-as-mirra-health-improperly-outsourced-records-overseas/) |
| **Santé** | QualDerm Partners (US) | Vol de données personnelles et médicales de 3,1 millions de personnes en décembre 2025. | [Security Affairs](https://securityaffairs.com/189917/data-breach/qualderm-partners-december-2025-data-breach-impacts-over-3-million-people.html) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par score CVSS décroissant.
| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|
| **CVE-2026-4606** | 10.0 | GeoVision Edge Recording Manager | Escalade de privilèges vers SYSTEM | [SecurityOnline](https://securityonline.info/geovision-erm-critical-vulnerability-cve-2026-4606-system-privilege-escalation/) |
| **ZDI-26-226** | 9.8 | Microsoft Azure MCP | Exécution de code à distance (RCE) | [ZDI](http://www.zerodayinitiative.com/advisories/ZDI-26-226/) |
| **CVE-2026-3055** | 9.3 | Citrix NetScaler ADC/Gateway | Fuite de mémoire (Memory Leak) | [Rapid7 / Citrix](https://www.helpnetsecurity.com/2026/03/24/netscaler-adc-gateway-cve-2026-3055/) |
| **CVE-2026-33017** | 9.3 | Langflow (AI framework) | RCE non authentifiée | [Field Effect](https://fieldeffect.com/blog/langflow-deployments-targeted-patch) |
| **CVE-2026-33419** | 9.1 | MinIO | Brute-force LDAP / Énumération d'utilisateurs | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-33419) |
| **CVE-2025-33244** | 9.0 | NVIDIA APEX | Désérialisation de données non fiables | [NVIDIA](https://cvefeed.io/vuln/detail/CVE-2025-33244) |
| **CVE-2026-4681** | Critique | PTC Windchill / FlexPLM | RCE via désérialisation | [Bleeping Computer](https://www.bleepingcomputer.com/news/security/ptc-warns-of-imminent-threat-from-critical-windchill-flexplm-rce-bug/) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| **LiteLLM backdoored to steal credentials** | Attaque supply chain majeure sur un package IA ultra-populaire. | [Bleeping Computer](https://www.bleepingcomputer.com/news/security/popular-litellm-pypi-package-compromised-in-teampcp-supply-chain-attack/) |
| **PTC warns of imminent RCE bug** | Faille critique sur PLM industriel avec réponse urgente des autorités (BKA). | [Bleeping Computer](https://www.bleepingcomputer.com/news/security/ptc-warns-of-imminent-threat-from-critical-windchill-flexplm-rce-bug/) |
| **Cyberattacks US-Israel-Iran** | Suivi détaillé du premier conflit cyber de haute intensité en 2026. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| **Langflow deployments targeted** | Exploitation active massive d'une plateforme d'IA open-source. | [Field Effect](https://fieldeffect.com/blog/langflow-deployments-targeted-patch) |
| **Strait of Hormuz Problem** | Analyse stratégique des contraintes maritimes et souveraineté cyber/physique. | [RUSI](https://www.rusi.org/explore-our-research/publications/commentary/strait-hormuz-problem-what-securing-waterway-actually-requires) |
| **North Korea-linked VS Code auto-run** | Technique innovante d'infection des environnements de développement. | [Security Affairs](https://securityaffairs.com/189880/security/north-korea-linked-threat-actors-abuse-vs-code-auto-run-to-spread-stoatwaffle-malware.html) |
| **GeoVision ERM Full Host Takeover** | Score CVSS 10.0 sur un logiciel de sécurité physique. | [SecurityOnline](https://securityonline.info/geovision-erm-critical-vulnerability-cve-2026-4606-system-privilege-escalation/) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| **ISC Stormcast (March 24/25)** | Contenu audio générique sans analyse détaillée propre. | [SANS ISC](https://isc.sans.edu/podcastdetail/9864) |
| **Microsoft fixes Outlook sync bug** | Problème de synchronisation mineur résolu, faible impact sécurité. | [Bleeping Computer](https://www.bleepingcomputer.com/news/microsoft/microsoft-fixes-bug-causing-outlook-sync-issues-for-gmail-users/) |
| **81-month sentence for Russian hacker** | Actualité judiciaire (Aleksei Volkov) non liée à une menace active immédiate. | [Security Affairs](https://securityaffairs.com/189900/cyber-crime/81-month-sentence-for-russian-hacker-behind-major-ransomware-campaigns.html) |
| **Elastic Security XDR / Workflows** | Articles promotionnels/marketing focalisés sur des produits spécifiques. | [Elastic Security](https://www.elastic.co/security-labs/investigating-from-the-endpoint-across-your-environment) |
| **Zero Trust: Bridging the Gap** | Contenu sponsorisé par Specops Software, généralités théoriques. | [Bleeping Computer](https://www.bleepingcomputer.com/news/security/zero-trust-bridging-the-gap-between-authentication-and-trust/) |

<br>
<br/>
<div id="articles"></div>

# ARTICLES

<div id="campagne-smartapesg-une-cascade-de-malwares-via-clickfix"></div>

## Campagne SmartApeSG : une cascade de malwares via ClickFix
La campagne SmartApeSG (alias ZPHP ou HANEYMANEY) utilise la technique ClickFix via de faux CAPTCHA sur des sites compromis. L'attaque incite l'utilisateur à copier-coller un script malveillant dans son terminal, déclenchant l'infection. Une fois le premier accès établi via Remcos RAT, les attaquants déploient successivement d'autres malwares : NetSupport RAT, StealC et Sectop RAT (ArechClient2). L'infection se déroule en plusieurs étapes sur quelques heures, utilisant le DLL side-loading pour échapper à la détection. Les fichiers malveillants sont camouflés sous des noms légitimes comme `UpdateInstaller.zip` ou `drag2pdf.zip`. Cette campagne montre une grande agilité, les indicateurs de compromission changeant presque quotidiennement.

**Analyse de l'impact** : Impact critique sur les postes de travail, permettant l'exfiltration de données, le contrôle à distance total et la persistance via plusieurs familles de malwares.

**Recommandations** : 
* Bloquer les domaines `fresicrto[.]top` et `urotypos[.]com`.
* Surveiller les exécutions PowerShell/CMD suspectes initiées par le navigateur.
* Sensibiliser les utilisateurs aux dangers des instructions de "copier-coller" provenant de pages web (technique ClickFix).
* Rechercher la présence de fichiers `.hta` dans `%AppData%\Local\`.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | SmartApeSG (ZPHP, HANEYMANEY) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.002: Spearphishing Link (Fake CAPTCHA) <br/> * T1204.002: User Execution: Malicious File <br/> * T1574.002: DLL Side-Loading |
| Observables & Indicateurs de compromission | ```* 95.142.45[.]231 (Remcos C2) * 185.163.47[.]220 (NetSupport C2) * 89.46.38[.]100 (StealC C2) * 195.85.115[.]11 (Sectop C2) * Hash HTA: 212d8007a7ce374d38949cf54d80133bd69338131670282008940f1995d7a720``` |

### Source (url) du ou des articles
* https://isc.sans.edu/diary/rss/32826

<br/>

<div id="menace-imminente-sur-ptc-windchill-et-flexplm"></div>

## Menace imminente sur PTC Windchill et FlexPLM
PTC Inc. a émis une alerte urgente concernant la vulnérabilité CVE-2026-4681 affectant ses solutions PLM (Product Lifecycle Management). Cette faille critique permet l'exécution de code à distance (RCE) via la désérialisation de données de confiance. La situation est jugée si sérieuse que la police fédérale allemande (BKA) a dépêché des agents pour alerter physiquement les entreprises concernées durant le week-end. Bien qu'aucun patch officiel ne soit encore disponible, une règle de mitigation Apache/IIS a été fournie. La menace est jugée imminente par un tiers non identifié, ciblant potentiellement des secrets industriels et des chaînes de conception critiques (défense, ingénierie). Des indicateurs de compromission, notamment des chaînes User-Agent et des noms de fichiers de webshells, ont été diffusés.

**Analyse de l'impact** : Risque d'espionnage industriel massif et de compromission de la propriété intellectuelle sur des secteurs stratégiques.

**Recommandations** : 
* Appliquer immédiatement la règle de déni d'accès au servlet affecté sur Apache/IIS.
* Isoler les instances Windchill/FlexPLM de l'internet si possible.
* Rechercher les fichiers webshell suivants : `GW.class`, `payload.bin`, ou `dpr_*.jsp`.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Groupe tiers non identifié (menace imminente) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1505.003: Web Shell <br/> * T1203: Exploitation for Client Execution |
| Observables & Indicateurs de compromission | ```* Fichiers: GW.class, payload.bin * Patterns: run?p= / .jsp?c= dans les logs serveurs``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/ptc-warns-of-imminent-threat-from-critical-windchill-flexplm-rce-bug/

<br/>

<div id="attaque-de-la-chaine-dapprovisionnement-sur-lite-llm"></div>

## Attaque de la chaîne d'approvisionnement sur LiteLLM
Le groupe de pirates TeamPCP a compromis le package Python populaire "LiteLLM" sur PyPI, utilisé pour interfacer avec plusieurs modèles d'IA. Les versions 1.82.7 et 1.82.8 contenaient une charge utile malveillante de type "infostealer". Ce malware récolte une vaste gamme de données sensibles : clés SSH, tokens cloud (AWS, Azure, GCP), secrets Kubernetes et portefeuilles crypto. L'attaque utilise une technique de persistance via un fichier `.pth` qui s'exécute à chaque démarrage de l'interpréteur Python. Les données volées sont exfiltrées vers des domaines contrôlés par les attaquants sous forme d'archives cryptées. TeamPCP prétend avoir infecté près de 500 000 dispositifs lors de cette opération.

**Analyse de l'impact** : Compromission systémique des environnements de développement IA et des infrastructures cloud associées.

**Recommandations** : 
* Vérifier les versions de LiteLLM installées (utiliser la 1.82.6 ou ultérieure).
* Rotation immédiate de TOUS les secrets (SSH, Cloud, K8s) présents sur les machines affectées.
* Nettoyer les artefacts de persistance : `~/.config/sysmon/sysmon.py`.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TeamPCP |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Supply Chain Compromise: Compromise Software Dependencies <br/> * T1539: Steal Web Session Cookie <br/> * T1552.001: Unsecured Credentials: Private Keys |
| Observables & Indicateurs de compromission | ```* domaines: checkmarx[.]zone, models.litellm[.]cloud * fichiers: litellm_init.pth, /tmp/pglog * archive: tpcp.tar.gz``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/popular-litellm-pypi-package-compromised-in-teampcp-supply-chain-attack/

<br/>

<div id="exploitation-critique-de-langflow-apres-correction"></div>

## Exploitation critique de Langflow après correction
Une vulnérabilité RCE critique (CVE-2026-33017) dans le framework IA Langflow est activement exploitée quelques heures seulement après la publication de son avis de sécurité. La faille réside dans un endpoint non authentifié (`POST /api/v1/build_public_tmp/`) permettant l'exécution de code Python arbitraire. Langflow étant souvent utilisé pour connecter des agents IA à des sources de données sensibles, l'impact est majeur. Les attaquants peuvent exfiltrer des variables d'environnement et établir des accès persistants. L'exploitation a commencé avant même la publication de codes de preuve de concept publics, suggérant un développement rapide basé sur l'avis technique. Les versions antérieures à 1.9.0 sont vulnérables.

**Analyse de l'impact** : Risque élevé de fuite de données d'entraînement d'IA et de compromission des clés d'API LLM.

**Recommandations** : 
* Mettre à jour vers Langflow 1.9.0 ou supérieur immédiatement.
* Bloquer l'accès externe à l'endpoint `POST /api/v1/build_public_tmp/`.
* Faire tourner toutes les clés d'API et tokens configurés dans l'interface Langflow.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br/> * T1059.006: Command and Scripting Interpreter: Python |
| Observables & Indicateurs de compromission | ```Aucun IoC spécifique de C2 n'est fourni, mais surveiller les appels HTTP vers /api/v1/build_public_tmp/``` |

### Source (url) du ou des articles
* https://fieldeffect.com/blog/langflow-deployments-targeted-patch

<br/>

<div id="compromission-de-trivy-et-vol-de-secrets-cicd"></div>

## Compromission de Trivy et vol de secrets CI/CD
L'outil de scan de vulnérabilités open-source Trivy a subi une attaque sophistiquée de sa chaîne d'approvisionnement. Les attaquants ont détourné des comptes de contributeurs pour modifier les tags de version de `trivy-action` et injecter du code malveillant. Contrairement à une nouvelle version suspecte, la modification des tags existants permet d'infecter silencieusement les pipelines CI/CD qui font confiance à ces versions. Le code injecté s'exécute avant le scan légitime et vole les tokens API, clés cloud (AWS, Azure, GCP) et secrets Kubernetes. L'attaque a duré plusieurs semaines avant d'être détectée le 19 mars 2026. Seul l'écosystème open-source est touché, les produits commerciaux d'Aqua Security restent sains.

**Analyse de l'impact** : Rupture de la confiance dans les outils de sécurité ; vol massif de secrets permettant des mouvements latéraux dans le cloud.

**Recommandations** : 
* Réinstaller Trivy uniquement depuis des sources vérifiées et valider les signatures.
* Utiliser des hashs de commits (SHA) plutôt que des tags de version dans les pipelines GitHub Actions.
* Révoquer et renouveler tous les secrets ayant transité par un pipeline utilisant Trivy en mars 2026.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TeamPCP |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195: Supply Chain Compromise <br/> * T1552: Unsecured Credentials <br/> * T1071.001: Application Layer Protocol: Web Protocols |
| Observables & Indicateurs de compromission | ```* Versions malveillantes: 0.69.4 * Actions GitHub altérées: trivy-action, setup-trivy``` |

### Source (url) du ou des articles
* https://fieldeffect.com/blog/trivy-breach

<br/>

<div id="stoatwaffle-la-coree-du-nord-abuse-des-taches-vs-code"></div>

## StoatWaffle : la Corée du Nord abuse des tâches VS Code
L'acteur nord-coréen Team 8 (campagne "Contagious Interview") utilise une nouvelle méthode pour infecter les développeurs via Visual Studio Code. En abusant de la fonctionnalité d'auto-exécution du fichier `tasks.json` situé dans le répertoire `.vscode`, les attaquants lancent le malware StoatWaffle dès qu'un dossier malveillant est ouvert. Le processus télécharge une chaîne d'infection multi-étape incluant un loader Node.js et des modules de vol de données (Stealer) et d'accès distant (RAT). StoatWaffle cible spécifiquement les identifiants de navigateurs, les extensions et les données du Keychain sur macOS. Il est également capable de s'infiltrer dans les environnements WSL sur Windows.

**Analyse de l'impact** : Compromission ciblée des environnements de développement et vol de propriété intellectuelle.

**Recommandations** : 
* Désactiver ou surveiller l'exécution automatique des tâches dans VS Code via les paramètres de sécurité de l'espace de travail.
* Inspecter les dossiers `.vscode` dans les projets partagés ou téléchargés, en particulier le fichier `tasks.json`.
* Rechercher les connexions réseau sortantes inhabituelles initiées par `node.exe` ou `cmd.exe` depuis les répertoires de développement.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Team 8 (Corée du Nord) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1554: Compromise Client Software Binary <br/> * T1059.003: Command and Scripting Interpreter: Windows Command Shell <br/> * T1555.001: Steal Web Browsers Credentials |
| Observables & Indicator de compromission | ```* Payload: StoatWaffle * Domaines C2: Vercel (utilisé pour le téléchargement) * Fichiers: tasks.json malveillant``` |

### Source (url) du ou des articles
* https://securityaffairs.com/189880/security/north-korea-linked-threat-actors-abuse-vs-code-auto-run-to-spread-stoatwaffle-malware.html

<br/>

<div id="geovision-erm-une-faille-critique-cvss-100"></div>

## GeoVision ERM : une faille critique CVSS 10.0
Une vulnérabilité d'escalade de privilèges critique (CVE-2026-4606) a été découverte dans le logiciel GeoVision GV-Edge Recording Manager (ERM). La faille, notée 10.0 sur l'échelle CVSS, provient du fait que l'application exécute certains composants avec les privilèges SYSTEM au lieu du contexte utilisateur. Un utilisateur local peu privilégié peut déclencher l'ouverture de boîtes de dialogue de fichiers Windows (Open/Save) via les fonctions de l'ERM. Comme le processus parent tourne en SYSTEM, la boîte de dialogue hérite de ces droits, permettant de naviguer, modifier ou supprimer n'importe quel fichier système protégé. Cette vulnérabilité permet une prise de contrôle totale de l'hôte.

**Analyse de l'impact** : Compromission totale des serveurs de surveillance vidéo et des stations de travail associées.

**Recommandations** : 
* Mettre à jour immédiatement vers GV-Edge Recording Manager V2.3.2 ou plus récent.
* Restreindre strictement les accès interactifs locaux sur les machines exécutant le logiciel.
* Auditer les services Windows liés à GeoVision pour vérifier les comptes d'exécution.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1068: Exploitation for Privilege Escalation <br/> * T1543.003: Create or Modify System Process: Windows Service |
| Observables & Indicateurs de compromission | ```CVE-2026-4606``` |

### Source (url) du ou des articles
* https://securityonline.info/geovision-erm-critical-vulnerability-cve-2026-4606-system-privilege-escalation/

<br/>

<div id="citrix-netscaler-fuite-de-memoire-critique-cve-2026-3055"></div>

## Citrix NetScaler : fuite de mémoire critique (CVE-2026-3055)
Citrix a corrigé deux vulnérabilités dans NetScaler ADC et Gateway, dont la plus grave, CVE-2026-3055 (CVSS 9.3), permet une lecture hors limites (memory overread). Cette faille peut être exploitée par un attaquant non authentifié pour extraire des jetons de session active de la mémoire de l'appareil. Seules les configurations où l'appareil agit comme un fournisseur d'identité SAML (SAML IdP) sont vulnérables. Cette vulnérabilité rappelle la célèbre "CitrixBleed" et pourrait être exploitée massivement très prochainement par rétro-ingénierie du correctif. Une seconde faille (CVE-2026-4368) permet également des mixages de sessions utilisateurs via une "race condition".

**Analyse de l'impact** : Risque de détournement de sessions à grande échelle et d'accès non autorisé aux ressources internes protégées par VPN/SSO.

**Recommandations** : 
* Installer immédiatement les correctifs (versions 14.1-66.59 ou 13.1-62.23).
* Vérifier si la configuration inclut `add authentication samlIdPProfile`.
* Mettre en place des restrictions d'accès au niveau réseau (IP allowlisting) pour les interfaces Gateway/AAA.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1558: Steal or Forge Authentication Tickets <br/> * T1212: Exploitation for Credential Access |
| Observables & Indicateurs de compromission | ```CVE-2026-3055, CVE-2026-4368``` |

### Source (url) du ou des articles
* https://www.helpnetsecurity.com/2026/03/24/netscaler-adc-gateway-cve-2026-3055/
* https://thecyberthrone.in/2026/03/24/cve-2026-3055-citrix-netscaler-critical-saml-idp-memory-leak/

<br/>

<div id="conflit-us-israel-iran-escalade-des-operations-cyber-destructrices"></div>

## Conflit US-Israël-Iran : escalade des opérations cyber destructrices
Depuis juin 2025, le conflit militaire entre les États-Unis, Israël et l'Iran s'est doublé d'une guerre cyber d'une intensité rare. Des groupes comme Handala Hack (lié à l'Iran) ont mené des attaques dévastatrices contre Stryker Corporation, essuyant plus de 200 000 dispositifs via l'abus de Microsoft Intune. L'Iran subit un blackout internet quasi-total depuis 25 jours, tandis que des acteurs comme APT Iran revendiquent le vol de 375 To de données chez Lockheed Martin, incluant des plans du F-35. Parallèlement, le FBI a alerté sur une campagne de malware du MOIS (renseignement iranien) utilisant Telegram comme infrastructure C2 contre des dissidents. Ce conflit redéfinit les normes de la cyberguerre étatique.

**Analyse de l'impact** : Perturbations majeures des chaînes d'approvisionnement médicales et militaires ; destruction de données à grande échelle.

**Recommandations** : 
* Imposer l'approbation multi-administrateur (Multi-Admin Approval) pour toute commande d'effacement (wipe) dans les plateformes MDM (Intune).
* Isoler les systèmes critiques des connexions directes vers l'internet.
* Surveiller les communications vers `api.telegram.org` provenant de comptes systèmes ou de serveurs critiques.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Handala Hack, MOIS, APT Iran |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1485: Data Destruction <br/> * T1071.001: Web Protocols (Telegram C2) <br/> * T1078.004: Valid Accounts: Cloud Accounts |
| Observables & Indicateurs de compromission | ```*api.telegram.org (utilisé comme C2) *Scripts de wipe via Intune``` |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict

<br/>

<div id="guerre-dusure-et-souverainete-du-detroit-dormuz"></div>

## Guerre d'usure et souveraineté du détroit d'Ormuz
L'Iran a instauré un contrôle de facto du détroit d'Ormuz sans fermeture formelle, réduisant le transit commercial de 90%. Cette "souveraineté pratique" s'appuie sur des frappes ciblées de drones et de missiles, ainsi que sur l'imposition d'un corridor d'inspection. Parallèlement, la coalition US-Israël fait face à un défi industriel majeur : la "Command of the Reload". En 16 jours, plus de 11 000 munitions avancées ont été dépensées pour un coût de 26 milliards de dollars. La disproportion entre le coût des drones iraniens et les missiles d'interception occidentaux (ratio de 1 à 100) menace d'épuiser les stocks critiques (Arrow, Patriot, THAAD) d'ici la fin mars 2026.

**Analyse de l'impact** : Menace sur la stabilité économique mondiale via le blocage énergétique et épuisement des capacités de défense stratégiques.

**Recommandations** : 
* Prioriser l'usage de systèmes de défense à bas coût (C-RAM, lasers) contre les essaims de drones pour préserver les intercepteurs haut de gamme.
* Sécuriser les chaînes d'approvisionnement en matériaux critiques (tungstène, gallium) pour la production de munitions.
* Revoir les modèles d'assurance risque de guerre pour le transport maritime.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Forces armées iraniennes / IRGC |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * Non applicable (domaine militaire/cinétique avec forte composante électronique) |
| Observables & Indicateurs de compromission | ```Aucun IoC cyber spécifique n'est fourni dans cette analyse géopolitique.``` |

### Source (url) du ou des articles
* https://www.rusi.org/explore-our-research/publications/commentary/strait-hormuz-problem-what-securing-waterway-actually-requires
* https://www.rusi.org/explore-our-research/publications/commentary/over-11000-munitions-16-days-iran-war-command-reload-governs-endurance