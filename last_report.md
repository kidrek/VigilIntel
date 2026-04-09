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
  * [TeamPCP / UNC6780 : Escalade dans la supply chain](#teampcp-unc6780-escalade-dans-la-supply-chain)
  * [Conflit US-Israël-Iran : Sabotage des infrastructures critiques](#conflit-us-israel-iran-sabotage-des-infrastructures-critiques)
  * [APT28 : Déploiement de la suite PRISMEX](#apt28-deploiement-de-la-suite-prismex)
  * [Sécurisation de l'IA Agentique et Projet Glasswing](#securisation-de-lia-agentique-et-projet-glasswing)
  * [UNC6783 : Ciblage des BPO et des tickets Zendesk](#unc6783-ciblage-des-bpo-et-des-tickets-zendesk)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage cyber de ce début avril 2026 est marqué par une hybridation croissante entre tensions géopolitiques cinétiques et opérations de sabotage numérique, particulièrement via le ciblage iranien des automates industriels (PLC) américains. L'industrialisation des attaques sur la chaîne d'approvisionnement atteint un sommet avec l'acteur UNC6780 (TeamPCP), capable de compromettre des milliers d'environnements SaaS et de dérober le code source de leaders technologiques comme Cisco. On observe un changement de paradigme dans la menace macOS, qui délaisse les payloads classiques pour des techniques d'ingénierie sociale "fileless" exploitant les outils natifs du système. La généralisation de l'IA introduit de nouveaux risques liés aux "agents autonomes" dont le comportement non-déterministe échappe aux contrôles traditionnels, nécessitant une refonte des modèles de privilèges. Les acteurs étatiques, notamment russes (APT28), pivotent vers une domination de la couche réseau (Edge devices) pour l'interception de flux à grande échelle. La compromission des prestataires de services (BPO) s'affirme comme le vecteur privilégié pour atteindre les données sensibles des grandes entreprises via leurs outils de support. Enfin, la persistance de vulnérabilités critiques non corrigées sur des équipements exposés (Ivanti, ActiveMQ) souligne une fatigue systémique du patch management face à une exploitation quasi instantanée.

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
| **APT28 (Fancy Bear)** | Défense, Gouvernement, Logistique (Ukraine/OTAN) | Spear-phishing, exploitation de vulnérabilités Office, malware PRISMEX, détournement DNS | [Security Affairs](https://securityaffairs.com/190510/apt/russia-linked-apt28-uses-prismex-to-infiltrate-ukraine-and-allied-infrastructure-with-advanced-tactics.html) |
| **Handala Hack** | Infrastructure israélienne, USA | Wiper, intrusion via VPN brute-force, exfiltration et fuite de données | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| **MuddyWater (IRGC)** | Énergie, Eau, Gouvernement (USA) | Ciblage de PLC (Rockwell Automation), utilisation de C2 via Telegram | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| **ShinyHunters** | Cloud, SaaS, Technologie | Exploitation de tokens d'authentification (Snowflake/Anodot), extorsion | [SANS ISC](https://isc.sans.edu/diary/rss/32880) |
| **UNC6780 (TeamPCP)** | Développement logiciel, SaaS | Compromission de pipelines CI/CD (Trivy), vol de secrets/code source, malware SANDCLOCK | [SANS ISC](https://isc.sans.edu/diary/rss/32880) |
| **UNC6783 (Raccoon)** | BPO (Business Process Outsourcing) | Ingénierie sociale via chat, usurpation de pages Okta/Zendesk, vol de sessions MFA | [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-new-unc6783-hackers-steal-corporate-zendesk-support-tickets/) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| État Iranien | Conflit cinétique/Cyber | Annonce d'un cessez-le-feu de deux semaines médié par le Pakistan suite aux frappes américano-israéliennes. | [IRIS](https://www.iris-france.org/trump-triomphe-apparent-echec-en-realite/) |
| Infrastructure Critique (USA) | Sabotage industriel | Les agences américaines confirment le sabotage de PLC Rockwell Automation par des acteurs affiliés à l'Iran. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Ukraine / OTAN | Espionnage russe | Campagne massive d'APT28 visant à cartographier et saboter les flux logistiques et d'aide militaire. | [The Hacker News](https://thehackernews.com/2026/04/apt28-deploys-prismex-malware-in.html) |
| Venezuela | Transition Politique | Delcy Rodríguez assure l'intérim présidentiel après l'extraction de Maduro par les forces spéciales américaines. | [Recorded Future](https://www.recordedfuture.com/research/understanding-and-anticipating-venezuelan-government-actions) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif des articles juridiques relatifs à la réglementation cyber :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Cyber Threat Intelligence Framework | CERT-EU | 08-04-2026 | Union Européenne | Règlement 2023/2841 | Standardisation du partage de renseignement sur les menaces pour les entités de l'UE. | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cyber-threat-intelligence-framework/) |
| CISA orders feds to patch exploited Ivanti | Sergiu Gatlan | 08-04-2026 | USA (Fédéral) | BOD 22-01 | Obligation de corriger CVE-2026-1340 avant le 11 avril 2026 pour les agences gouvernementales. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-exploited-ivanti-epmm-flaw-by-sunday/) |
| 1 000ème certification ISO 27001 | Portail IE | 08-04-2026 | France | ISO/IEC 27001 | Célébration de la millième certification en France, illustrant la maturité de la gestion de la sécurité de l'information. | [Portail IE](https://www.portail-ie.fr/univers/blockchain-data-et-ia/2026/retour-sur-le-forum-incyber-2026-a-lille/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Gouvernement | LAPD (Los Angeles Police) | Vol et fuite de dossiers personnels d'officiers et d'enquêtes internes par World Leaks. | [DataBreaches.net](https://databreaches.net/2026/04/08/hackers-steal-and-leak-sensitive-lapd-police-documents/) |
| Santé | Signature Healthcare | Cyberattaque (possible ransomware) entraînant le détournement d'ambulances et la paralysie des pharmacies. | [Security Affairs](https://securityaffairs.com/190504/security/signature-healthcare-hit-by-cyberattack-services-and-pharmacies-impacted.html) |
| Technologie | Cisco | Vol de plus de 300 répertoires de code source (IA, produits non publiés) via la supply chain Trivy. | [SANS ISC](https://isc.sans.edu/diary/rss/32880) |
| Web / IA | My Lovely AI | Fuite des données de 106 271 comptes, incluant des prompts utilisateur et des contenus privés. | [HIBP](https://haveibeenpwned.com/Breach/MyLovelyAI) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées :
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2026-1340 | 9.8 | Non spécifié | TRUE | Ivanti EPMM | Injection de code | T1190 : Exploit Public-Facing Application | RCE non authentifiée exploitée activement depuis janvier. | [Security Affairs](https://securityaffairs.com/190519/security/u-s-cisa-adds-a-flaw-in-ivanti-epmm-to-its-known-exploited-vulnerabilities-catalog-2.html) |
| CVE-2026-39890 | 9.8 | Non spécifié | FALSE | PraisonAI | Désérialisation YAML | T1203 : Exploitation for Client Execution | Exécution de code JavaScript arbitraire via le chargement de définitions d'agents. | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-39890) |
| CVE-2026-1188 | 9.8 | Non spécifié | FALSE | IBM Verify Access | Buffer Overflow | T1210 : Exploitation of Remote Services | Dépassement de tampon dans la bibliothèque Eclipse OMR menant à une compromission système. | [Cybersecurity News](https://cybersecuritynews.com/ibm-identity-and-verify-access-vulnerabilities/) |
| CVE-2026-3199 | 9.4 | Non spécifié | FALSE | Sonatype Nexus | Injection de propriétés | T1210 : Exploitation of Remote Services | RCE authentifiée via le composant de gestion des tâches. | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-3199) |
| CVE-2026-34197 | 8.8 | Non spécifié | FALSE | Apache ActiveMQ | RCE via Jolokia | T1210 : Exploitation of Remote Services | Chaîne d'exploitation via l'API de gestion Jolokia pour charger des fichiers Spring XML distants. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/13-year-old-bug-in-activemq-lets-hackers-remotely-execute-commands/) |
| CVE-2026-5747 | 8.7 | Non spécifié | FALSE | AWS Firecracker | Out-of-bounds Write | T1611 : Escape to Host | Un invité privilégié root peut s'évader vers l'hôte via la couche de transport virtio-pci. | [Security Online](https://securityonline.info/aws-firecracker-cve-2026-5747-virtio-pci-vulnerability/) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| TeamPCP Supply Chain Campaign Update 007 | Menace systémique majeure sur les pipelines de développement et impact critique (Cisco). | [SANS ISC](https://isc.sans.edu/diary/rss/32880) |
| Monitoring Cyberattacks directly linked to US-Israel-Iran | Escalade géopolitique majeure avec sabotage avéré d'infrastructures critiques (OT/ICS). | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Russia-linked APT28 uses PRISMEX with advanced tactics | Nouvelle suite de malwares sophistiquée utilisant la stéganographie contre l'Ukraine. | [Security Affairs](https://securityaffairs.com/190510/apt/russia-linked-apt28-uses-prismex-to-infiltrate-ukraine-and-allied-infrastructure-with-advanced-tactics.html) |
| Securing Agentic AI / Project Glasswing | Analyse prospective sur les nouveaux vecteurs d'attaque liés à l'autonomie de l'IA. | [OpenSSF](https://openssf.org/blog/2026/04/08/openssf-tech-talk-recap-securing-agentic-ai/) |
| Google: New UNC6783 hackers steal support tickets | Nouvelle technique de ciblage indirect via les prestataires BPO et l'abus de Zendesk. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-new-unc6783-hackers-steal-corporate-zendesk-support-tickets/) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| Don’t Pack a Scam | Article de sensibilisation généraliste sans nouvelle menace technique. | [GCA](https://globalcyberalliance.org/dont-pack-a-scam-how-to-travel-smart-in-a-digital-world/) |
| Microsoft rolls out fix for Start Menu search | Problème de performance/bug IT, non lié à une menace cyber. | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-rolls-out-fix-for-broken-windows-start-menu-search/) |
| ISC Stormcast Podcast | Simple lien vers un flux audio sans résumé textuel exploitable. | [SANS ISC](https://isc.sans.edu/diary/rss/32882) |
| Is a $30,000 GPU Good at Password Cracking? | Étude comparative de matériel, utile mais pas une actualité de menace immédiate. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/is-a-30-000-gpu-good-at-password-cracking/) |
| Number Usage in Passwords | Analyse statistique de recherche académique sans incident lié. | [SANS ISC](https://isc.sans.edu/diary/rss/32866) |

<br>
<br>
<div id="articles"></div>

# ARTICLES
<div id="teampcp-unc6780-escalade-dans-la-supply-chain"></div>

## TeamPCP / UNC6780 : Escalade dans la supply chain
L'acteur UNC6780 (TeamPCP) continue son exploitation massive de la vulnérabilité CVE-2026-33634 affectant l'outil de scan de sécurité Trivy. Cisco est confirmé comme la victime la plus notable, avec le vol de plus de 300 dépôts GitHub privés contenant du code source sensible, y compris des technologies d'IA. L'attaque a été réalisée via un plugin GitHub Action malveillant permettant l'accès aux systèmes de build. Parallèlement, Google a formellement désigné ce groupe comme UNC6780 et identifié leur payload principal sous le nom de SANDCLOCK. L'impact s'étend à plus de 1 000 environnements SaaS compromis, illustrant une capacité de mouvement latéral via des clés AWS dérobées. Bien que les sites de fuite de CipherForce soient actuellement hors ligne, les deadlines d'extorsion approchent pour des victimes comme Sportradar. Cette campagne marque une transition de l'intrusion pure vers la monétisation agressive des secrets dérobés.

**Analyse de l'impact** : Impact critique sur l'intégrité de la supply chain logicielle globale. Le vol du code source de Cisco pourrait faciliter la découverte de vulnérabilités zero-day futures dans leurs produits.

**Recommandations** :
* **SOC** : Rechercher l'utilisation anormale de clés d'accès AWS et de tokens GitHub dans les logs CloudTrail.
* **DFIR** : Procéder à une rotation immédiate de tous les secrets (API keys, certificats) ayant transité par des pipelines utilisant Trivy (v0.69.2+ requise).
* **Threat Hunting** : Détecter le malware SANDCLOCK via ses indicateurs comportementaux dans les environnements CI/CD.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UNC6780 (TeamPCP), ShinyHunters |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002 : Supply Chain Compromise (Software Dependencies) <br/> * T1078.004 : Valid Accounts (Cloud Accounts) <br/> * T1537 : Transfer Data to Cloud Account |
| Observables & Indicateurs de compromission | * Malware : SANDCLOCK <br/> * CVE associée : CVE-2026-33634 |

### Source (url) du ou des articles
* https://isc.sans.edu/diary/rss/32880

<br>
<br>

<div id="conflit-us-israel-iran-sabotage-des-infrastructures-critiques"></div>

## Conflit US-Israël-Iran : Sabotage des infrastructures critiques
Les agences américaines (CISA, FBI, NSA) ont émis une alerte conjointe (AA26-097A) confirmant que des acteurs cyber iraniens ciblent activement les automates programmables industriels (PLC) Rockwell Automation/Allen-Bradley. Ces intrusions ont entraîné des pertes financières et des perturbations opérationnelles dans les secteurs de l'eau, de l'énergie et des services gouvernementaux. Les attaquants exploitent des équipements exposés sur Internet en utilisant le logiciel de configuration Studio 5000 Logix Designer via des infrastructures louées à l'étranger. Bien qu'un cessez-le-feu de deux semaines ait été annoncé le 7 avril, la menace reste critique, les agences de renseignement craignant la présence de "backdoors" dormantes. Les ports 44818, 2222, 102, 22 et 502 sont particulièrement visés pour l'accès et le contrôle. Les tactiques rappellent celles de CyberAv3ngers (IRGC) observées fin 2023.

**Analyse de l'impact** : Menace directe sur la sécurité publique et la continuité des services essentiels aux USA et dans les pays alliés.

**Recommandations** :
* **Equipes OT** : Déconnecter immédiatement tous les PLC de l'Internet public et les placer derrière des pare-feu industriels/VPN.
* **SOC** : Surveiller les flux entrants sur les ports OT mentionnés (ex: 44818) en provenance d'adresses IP étrangères.
* **Architecture** : Passer les contrôleurs Rockwell en mode physique "RUN" pour empêcher les modifications de projet à distance.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | CyberAv3ngers (affilié IRGC / MOIS) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T0815 : External Remote Services <br/> * T0843 : Modification of Parameter <br/> * T0831 : Data Destruction |
| Observables & Indicateurs de compromission | * Ports cibles : 44818, 2222, 102, 22, 502 <br/> * Outil : Dropbear SSH, Studio 5000 Logix Designer |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict
* https://www.lemonde.fr/pixels/article/2026/04/08/des-hackeurs-lies-a-l-iran-ont-perturbe-des-sites-industriels-americains_6678228_4408996.html

<br>
<br>

<div id="apt28-deploiement-de-la-suite-prismex"></div>

## APT28 : Déploiement de la suite PRISMEX
Le groupe de renseignement militaire russe APT28 mène une vaste campagne d'espionnage contre l'Ukraine et ses alliés logistiques (Pologne, Roumanie, Slovaquie). La suite de malwares identifiée, PRISMEX, se distingue par l'utilisation intensive de la stéganographie pour dissimuler ses payloads dans des images PNG. L'infection débute par du spear-phishing avec des documents RTF exploitant CVE-2026-21509 pour forcer une connexion WebDAV. Les composants incluent des droppers (PrismexDrop), des chargeurs (PrismexLoader) et des implants basés sur le framework Covenant. Le groupe utilise des services cloud légitimes comme Filen.io pour l'exfiltration et le C2, rendant le trafic difficile à distinguer des flux normaux. Les leurres portent sur des inventaires de drones et des données météorologiques, essentiels aux opérations militaires de terrain.

**Analyse de l'impact** : Risque élevé de sabotage logistique et de vol de renseignement stratégique sur l'aide militaire à l'Ukraine.

**Recommandations** :
* **SOC** : Bloquer les domaines associés à Filen.io et surveiller les requêtes DNS vers des domaines WebDAV suspects.
* **Endpoint** : Surveiller le détournement d'objets COM (COM hijacking) et la création de tâches planifiées redémarrant explorer.exe.
* **Threat Hunting** : Analyser les fichiers images "SplashScreen.png" pour détecter des anomalies de structure liées à la stéganographie.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | APT28 (Fancy Bear / UAC-0001) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1027.003 : Steganography <br/> * T1546.015 : Component Object Model Hijacking <br/> * T1567.002 : Exfiltration to Cloud Storage |
| Observables & Indicateurs de compromission | * Domaine : wellnesscaremed[.]com <br/> * Service C2 : Filen.io <br/> * CVE : CVE-2026-21509, CVE-2026-21513 |

### Source (url) du ou des articles
* https://securityaffairs.com/190510/apt/russia-linked-apt28-uses-prismex-to-infiltrate-ukraine-and-allied-infrastructure-with-advanced-tactics.html
* https://thehackernews.com/2026/04/apt28-deploys-prismex-malware-in.html

<br>
<br>

<div id="securisation-de-lia-agentique-et-projet-glasswing"></div>

## Sécurisation de l'IA Agentique et Projet Glasswing
L'évolution vers une IA dite "agentique" (agents autonomes capables d'exécuter du code et d'appeler des outils) crée une nouvelle surface d'attaque non-déterministe. Contrairement aux logiciels classiques, les agents IA suivent le chemin de moindre résistance, pouvant extraire des données sensibles par excès de zèle sans intention malveillante. L'OpenSSF a introduit le catalogue de menaces SAFE-MCP, inspiré de MITRE ATT&CK, pour classifier ces attaques (ex: SAFE-T1201). En parallèle, Anthropic a dévoilé "Project Glasswing", une initiative visant à utiliser le modèle Claude Mythos pour détecter des vulnérabilités critiques avant les attaquants. Ce modèle aurait déjà identifié des milliers de failles dans des OS et navigateurs majeurs. L'enjeu est de limiter l'accès à ces capacités offensives de l'IA tout en renforçant les défenses via des agents de sécurité guidés par l'humain dans les SOC.

**Analyse de l'impact** : Transformation radicale du cycle de vulnérabilité. L'IA peut réduire le temps d'investigation des SOC mais aussi accélérer drastiquement le développement d'exploits sophistiqués.

**Recommandations** :
* **Architecture** : Appliquer le principe du moindre privilège strict aux agents IA (least privilege as an architectural requirement).
* **Développement** : Imposer un Software Bill of Materials (SBOM) pour toutes les dépendances open source des piles IA (souvent > 3000).
* **SOC** : Intégrer des agents IA non-autonomes pour l'aide au diagnostic, tout en gardant une validation humaine (Human-in-the-loop).

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable (Menace structurelle / Recherche) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1201 : MCP Rugpull Attack (SAFE-MCP) <br/> * T1190 : Exploit Public-Facing Application (AI-driven) |
| Observables & Indicateurs de compromission | * Modèles IA : Claude Mythos, SAFE-MCP framework |

### Source (url) du ou des articles
* https://openssf.org/blog/2026/04/08/openssf-tech-talk-recap-securing-agentic-ai/
* https://securityaffairs.com/190496/ai/project-glasswing-powered-by-claude-mythos-defending-software-before-hackers-do.html

<br>
<br>

<div id="unc6783-ciblage-des-bpo-et-tickets-zendesk"></div>

## UNC6783 : Ciblage des BPO et des tickets Zendesk
L'acteur malveillant UNC6783 (possiblement lié au persona "Mr. Raccoon") cible stratégiquement les fournisseurs de Business Process Outsourcing (BPO) pour atteindre les données de grandes entreprises clientes. En utilisant l'ingénierie sociale via chat en direct, l'attaquant redirige les employés du support vers des pages de phishing Okta usurpant l'identité de l'organisation visée. Ces pages utilisent des kits capables de voler le contenu du presse-papier pour contourner les protections MFA. Le but est d'accéder aux consoles d'administration Zendesk pour exfiltrer des millions de tickets de support contenant des données personnelles, des informations sur les employés et des rapports de sécurité internes. Une violation majeure a été revendiquée chez Adobe via un prestataire basé en Inde, avec 13 millions de tickets prétendument dérobés pour extorsion.

**Analyse de l'impact** : Risque majeur de fuite de données massives et d'extorsion. La confiance dans la chaîne de support externe est gravement compromise.

**Recommandations** :
* **IAM** : Déployer des clés de sécurité FIDO2 pour le MFA, insensibles au phishing de tokens.
* **SOC** : Surveiller et bloquer les domaines suivant le motif `<org>[.]zendesk-support<##>[.]com`.
* **Audit** : Auditer régulièrement les enregistrements de nouveaux périphériques MFA, en particulier pour les comptes ayant des accès aux outils de support.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UNC6783 (Raccoon) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.003 : Spearphishing via Service <br/> * T1556.006 : Modify Authentication Process: Multi-Factor Authentication <br/> * T1078 : Valid Accounts |
| Observables & Indicateurs de compromission | * Domaines de phishing : motifs zendesk-support[.]com <br/> * Cibles : Plateformes Zendesk, Okta |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/google-new-unc6783-hackers-steal-corporate-zendesk-support-tickets/