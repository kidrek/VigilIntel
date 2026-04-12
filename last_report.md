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
  * [Plus de 20 000 victimes de fraude crypto identifiées lors d'un coup de filet international](#plus-de-20000-victimes-de-fraude-crypto-identifiees-lors-dun-coup-de-filet-international)
  * [Censys identifie 5 219 appareils exposés aux attaques des APT iraniens](#censys-identifie-5-219-appareils-exposes-aux-attaques-des-apt-iraniens)
  * [GlassWorm évolue avec un dropper en Zig pour infecter les outils de développement](#glassworm-evolue-avec-un-dropper-en-zig-pour-infecter-les-outils-de-developpement)
  * [CVE-2026-39987 : RCE sur Marimo exploitée quelques heures après sa divulgation](#cve-2026-39987-rce-sur-marimo-exploitee-quelques-heures-apres-sa-divulgation)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage actuel des cybermenaces est marqué par une réduction drastique du délai entre la divulgation d'une vulnérabilité et son exploitation active, illustrée par le cas Marimo où des acteurs malveillants ont réagi en moins de dix heures. L'infrastructure critique, particulièrement aux États-Unis, subit une pression constante de la part d'acteurs étatiques comme l'Iran, qui tirent parti de l'exposition directe d'automates programmables (PLCs) sur Internet. Les attaques sur la chaîne d'approvisionnement évoluent également, ciblant désormais les développeurs via des extensions d'IDE compromises, une méthode furtive pour infiltrer des environnements de production. En parallèle, la cybercriminalité financière, bien que massive avec plus de 20 000 victimes de fraudes crypto, fait face à une réponse internationale de plus en plus coordonnée et efficace. Le secteur de la santé reste une cible de choix pour les opérations de rançongiciel (Anubis), provoquant des interruptions de soins critiques. Les organisations doivent prioriser la réduction de l'exposition de leurs actifs industriels et le durcissement de la surveillance des outils tiers. La coopération public-privé s'affirme comme le rempart le plus solide contre ces menaces transfrontalières.
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
| Anubis | Santé / Hôpitaux | Ransomware-as-a-Service (RaaS), chiffrement de données | [DataBreaches](https://databreaches.net/2026/04/11/brockton-hospital-still-dealing-with-aftermath-of-ransomware-attack/) |
| CyberAv3ngers (lié à l'Iran/IRGC) | Infrastructures critiques (Eau, Énergie, Gouv) | Exploitation de PLCs Rockwell Automation exposés, manipulation de données SCADA | [Security Affairs](https://securityaffairs.com/190646/ics-scada/censys-finds-5219-devices-exposed-to-attacks-by-iranian-apts-majority-in-u-s.html) |
| GlassWorm | Développeurs de logiciels | Attaque supply chain via fausses extensions IDE (npm, VS Code), dropper Zig, C2 Solana | [Security Affairs](https://securityaffairs.com/190638/malware/glassworm-evolves-with-zig-dropper-to-infect-multiple-developer-tools.html) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Étatique / Infrastructures | Cyber-espionnage / Sabotage | Des groupes liés à l'Iran ciblent activement des dispositifs de contrôle industriel (OT) aux États-Unis. | [Security Affairs](https://securityaffairs.com/190646/ics-scada/censys-finds-5219-devices-exposed-to-attacks-by-iranian-apts-majority-in-u-s.html) |
| Finance / Justice internationale | Coopération policière | "Operation Atlantic" : action conjointe du Royaume-Uni, des États-Unis et du Canada contre la fraude crypto mondiale. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/police-identifies-20-000-victims-in-international-crypto-fraud-crackdown/) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Fraud Strategy (U.K. Government) | Gouvernement britannique | 11/04/2026 | Royaume-Uni | Stratégie Nationale contre la Fraude | Modèle de partenariat public-privé visant à connecter les données industrielles et l'expertise policière pour prévenir la fraude. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/police-identifies-20-000-victims-in-international-crypto-fraud-crackdown/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Finance | 20 000+ particuliers | Victimes identifiées de fraudes à l'investissement et "approval phishing" à l'échelle internationale. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/police-identifies-20-000-victims-in-international-crypto-fraud-crackdown/) |
| Santé | Brockton Hospital (Signature Healthcare) | Attaque par rançongiciel Anubis entraînant une interruption des services électroniques et des soins. | [DataBreaches](https://databreaches.net/2026/04/11/brockton-hospital-still-dealing-with-aftermath-of-ransomware-attack/) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2026-4149 | 10.0 | Non spécifié | FALSE | Sonos Era 300 | Out-of-bounds Access (SMB) | Non mentionnées | Permet l'exécution de code à distance dans le contexte du noyau via le champ DataOffset des réponses SMB. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-4149) |
| CVE-2026-5059 | 9.8 | Non spécifié | FALSE | aws-mcp-server | Command Injection | Non mentionnées | Injection de commande via la liste des commandes autorisées, permettant une RCE sans authentification. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-5059) |
| CVE-2026-5058 | 9.8 | Non spécifié | FALSE | aws-mcp-server | Command Injection | Non mentionnées | Similaire à la CVE-2026-5059, défaut de validation des chaînes fournies par l'utilisateur. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-5058) |
| CVE-2026-34621 | 9.6 | Non spécifié | FALSE | Adobe Acrobat Reader | Prototype Pollution | Non mentionnées | Modification non contrôlée des attributs du prototype d'objet permettant une RCE via l'ouverture d'un fichier malveillant. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-34621) |
| CVE-2026-39987 | 9.3 | Non spécifié | FALSE | Marimo (Python notebook) | Pre-Auth RCE | Non mentionnées | Absence de validation d'authentification sur le terminal WebSocket (/terminal/ws) permettant un shell complet. | [Security Affairs](https://securityaffairs.com/190623/hacking/cve-2026-39987-marimo-rce-exploited-in-hours-after-disclosure.html) |
| CVE-2026-31845 | 9.3 | Non spécifié | FALSE | Rukovoditel CRM | Reflected XSS | Non mentionnées | Injection de script via le paramètre 'zd_echo' de l'API Zadarma, permettant le vol de session. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-31845) |
| CVE-2026-5144 | 8.8 | Non spécifié | FALSE | BuddyPress Groupblog | Privilege Escalation | Non mentionnées | Défaut de contrôle IDOR permettant à un simple abonné de devenir administrateur sur un réseau Multisite. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-5144) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Over 20,000 crypto fraud victims identified in international crackdown | Action majeure de lutte contre la cybercriminalité financière mondiale. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/police-identifies-20-000-victims-in-international-crypto-fraud-crackdown/) |
| Brockton Hospital still dealing with aftermath of ransomware attack | Impact opérationnel réel d'un ransomware sur des services de santé critiques. | [DataBreaches](https://databreaches.net/2026/04/11/brockton-hospital-still-dealing-with-aftermath-of-ransomware-attack/) |
| Censys finds 5,219 devices exposed to attacks by Iranian APTs | Menace étatique directe sur les infrastructures critiques (ICS/SCADA). | [Security Affairs](https://securityaffairs.com/190646/ics-scada/censys-finds-5219-devices-exposed-to-attacks-by-iranian-apts-majority-in-u-s.html) |
| CVE-2026-39987: Marimo RCE exploited in hours after disclosure | Démonstration de la vélocité extrême d'exploitation des vulnérabilités actuelles. | [Security Affairs](https://securityaffairs.com/190623/hacking/cve-2026-39987-marimo-rce-exploited-in-hours-after-disclosure.html) |
| GlassWorm evolves with Zig dropper to infect multiple developer tools | Attaque supply chain sophistiquée ciblant les environnements de développement. | [Security Affairs](https://securityaffairs.com/190638/malware/glassworm-evolves-with-zig-dropper-to-infect-multiple-developer-tools.html) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| 🚨 HIGH risk: Optimole WordPress plugin... | Publication provenant d'un réseau social (Mastodon). | [OffSeq](https://infosec.exchange/@offseq/116388792901284434) |
| Comparison of Android-based Operating Systems | Publication provenant d'un réseau social (Mastodon). | [Mastodon](https://nerdculture.de/@anon_4601/116388577211771302) |
| New security advisory: CVE-2026-39911 | Publication provenant d'un réseau social (Mastodon). | [Matchbook3469](https://mastodon.social/@Matchbook3469/116388561092693522) |
| Поганые вещи в инфобезе (Opinion piece) | Publication provenant d'un réseau social (Mastodon). | [meowmashine](https://ioc.exchange/@meowmashine/116388931137974056) |
| Red teamers don’t just rely on software... | Publication provenant d'un réseau social (Mastodon) / Contenu promotionnel. | [dan_nanni](https://mastodon.social/@dan_nanni/116388663072153035) |
| Seen this mistake kill companies: hardcoded API keys | Publication provenant d'un réseau social (Mastodon). | [threatchain](https://mastodon.social/@threatchain/116388853720157844) |
| What is NetBIOS and SMB Exploitation Techniques | Publication provenant d'un réseau social (Mastodon) / Guide technique général. | [halildeniz](https://mastodon.social/@halildeniz/116388885860868664) |

<br>
<br>
<div id="articles"></div>

# ARTICLES

<div id="plus-de-20000-victimes-de-fraude-crypto-identifiees-lors-dun-coup-de-filet-international"></div>

## Plus de 20 000 victimes de fraude crypto identifiées lors d'un coup de filet international
L'opération internationale "Atlantic", menée par la National Crime Agency (NCA) britannique avec le soutien des États-Unis et du Canada, a permis d'identifier plus de 20 000 victimes de fraudes aux crypto-monnaies. L'action s'est concentrée sur le démantèlement de réseaux pratiquant l'"approval phishing", où les escrocs trompent les victimes pour obtenir l'accès à leurs portefeuilles numériques. Plus de 12 millions de dollars de revenus criminels présumés ont été gelés et 45 millions de dollars de crypto-monnaies volées ont été identifiés. Ce coup de filet s'inscrit dans la nouvelle stratégie de lutte contre la fraude du gouvernement britannique, privilégiant le partenariat public-privé. En parallèle, le FBI rapporte une augmentation massive des plaintes liées aux investissements crypto en 2025, avec des pertes s'élevant à 7,2 milliards de dollars. L'opération a mobilisé des acteurs tels que le Secret Service américain et la Police provinciale de l'Ontario. Les autorités prévoient de poursuivre l'analyse des données recueillies pour engager d'autres poursuites.

**Analyse de l'impact** : Impact financier massif avec des milliards de dollars de pertes annuelles. La confiance des utilisateurs dans les actifs numériques est érodée par des techniques de "pig butchering" et de phishing de plus en plus sophistiquées.

**Recommandations** :
* Éduquer les utilisateurs sur les risques de l'"approval phishing" et l'importance de ne jamais accorder de droits d'accès complets aux portefeuilles à des tiers inconnus.
* Collaborer activement avec les plateformes d'échange pour geler rapidement les fonds signalés comme frauduleux.
* Intégrer des outils de surveillance des transactions pour détecter les schémas de transfert suspects liés aux arnaques à l'investissement.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Réseaux de fraude internationaux (non nommés spécifiquement) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.002 : Spearphishing Link <br> * T1566.003 : Spearphishing Service |
| Observables & Indicateurs de compromission | ```Aucun IoC spécifique n'est fourni``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/police-identifies-20-000-victims-in-international-crypto-fraud-crackdown/

<br/>
<br/>

<div id="censys-identifie-5-219-appareils-exposes-aux-attaques-des-apt-iraniens"></div>

## Censys identifie 5 219 appareils exposés aux attaques des APT iraniens
Des chercheurs de Censys ont découvert 5 219 automates programmables (PLC) Rockwell Automation exposés sur Internet, dont près de 75 % se situent aux États-Unis. Cette alerte fait suite à une mise en garde des agences américaines (FBI, CISA, NSA) concernant des groupes liés à l'Iran, comme CyberAv3ngers, ciblant ces dispositifs. Les attaquants manipulent les fichiers de projet et les données des systèmes HMI/SCADA, provoquant des interruptions opérationnelles dans les secteurs de l'eau, de l'énergie et des services gouvernementaux. De nombreux dispositifs sont connectés via des réseaux cellulaires (Verizon, AT&T), ce qui rend leur surveillance et leur correction difficiles. Les familles MicroLogix et CompactLogix sont les plus touchées, utilisant souvent des micrologiciels obsolètes. L'exposition permet une identification granulaire des modèles sans authentification. Les experts recommandent de déconnecter ces systèmes d'Internet ou d'utiliser des VPN sécurisés.

**Analyse de l'impact** : Risque critique de sabotage physique et d'interruption de services essentiels (eau, électricité). L'exposition directe de l'OT facilite grandement la reconnaissance pour les acteurs étatiques.

**Recommandations** :
* Déconnecter immédiatement les automates programmables (PLC) de l'Internet public.
* Mettre en œuvre des passerelles sécurisées (VPN, accès ZTNA) si un accès distant est indispensable.
* Mettre à jour les micrologiciels (firmware) des appareils Rockwell MicroLogix et CompactLogix.
* Surveiller le port EtherNet/IP (44818) pour toute activité inhabituelle.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | CyberAv3ngers (lié à l'IRGC iranien) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T0883 : Screen Capture (HMI) <br> * T0833 : Modify Parameter <br> * T0866 : Softwate Discovery |
| Observables & Indicateurs de compromission | ```Port 44818 (EtherNet/IP), protocoles Modbus, VNC exposés sur des IPs cellulaires.``` |

### Source (url) du ou des articles
* https://securityaffairs.com/190646/ics-scada/censys-finds-5219-devices-exposed-to-attacks-by-iranian-apts-majority-in-u-s.html

<br/>
<br/>

<div id="glassworm-evolue-avec-un-dropper-en-zig-pour-infecter-les-outils-de-developpement"></div>

## GlassWorm évolue avec un dropper en Zig pour infecter les outils de développement
La campagne malveillante GlassWorm a franchi une nouvelle étape en utilisant un dropper compilé en langage Zig, dissimulé dans une fausse extension VS Code nommée "WakaTime Activity Tracker". Ce binaire s'exécute en dehors du bac à sable JavaScript et infecte silencieusement tous les IDE présents sur le système (VS Code, Cursor, VSCodium). Le logiciel malveillant télécharge ensuite une seconde extension depuis GitHub pour assurer sa persistance. GlassWorm évite les systèmes russes et communique avec un serveur de commande (C2) basé sur la blockchain Solana. Le payload final installe un cheval de troie d'accès à distance (RAT) et une extension Chrome malveillante pour voler des données. Cette attaque cible directement la chaîne d'approvisionnement logicielle en compromettant l'environnement de travail des développeurs. Aikido Security, à l'origine de la découverte, souligne la furtivité accrue de cette méthode.

**Analyse de l'impact** : Menace sérieuse sur l'intégrité du code source et des secrets (clés API, identifiants) détenus par les développeurs. La capacité d'infection multi-IDE augmente radicalement la portée de la compromission.

**Recommandations** :
* Auditer la liste des extensions installées dans les IDE (chercher "specstudio/code-wakatime-activity-tracker" ou "floktokbok.autoimport").
* Réinitialiser tous les secrets et clés API si une extension suspecte est découverte.
* Restreindre l'installation d'extensions provenant de sources non vérifiées ou tierces sur les postes de développement.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | GlassWorm |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002 : Supply Chain Compromise (Software Dependencies) <br> * T1547.001 : Boot or Logon Autostart Execution |
| Observables & Indicateurs de compromission | ```Extensions : specstudio/code-wakatime-activity-tracker, floktokbok.autoimport. C2 lié à Solana.``` |

### Source (url) du ou des articles
* https://securityaffairs.com/190638/malware/glassworm-evolves-with-zig-dropper-to-infect-multiple-developer-tools.html

<br/>
<br/>

<div id="cve-2026-39987-rce-sur-marimo-exploitee-quelques-heures-apres-sa-divulgation"></div>

## CVE-2026-39987 : RCE sur Marimo exploitée quelques heures après sa divulgation
Une vulnérabilité critique (CVE-2026-39987, score CVSS 9.3) dans l'outil de notebook Python open-source Marimo a été exploitée moins de dix heures après sa publication le 8 avril 2026. La faille réside dans l'absence d'authentification sur le terminal WebSocket (/terminal/ws), permettant à un attaquant distant d'obtenir un shell complet et d'exécuter des commandes système. L'équipe Sysdig a observé des tentatives d'exploitation réelles en seulement 9 heures et 41 minutes, suivies d'un vol de credentials en moins de trois minutes. Fait remarquable, aucun code d'exploitation public (PoC) n'existait au moment de l'attaque ; l'attaquant a construit son exploit directement à partir de l'avis de sécurité. L'activité enregistrée suggère un opérateur humain méthodique ciblant les fichiers .env et les clés SSH. Ce cas illustre la capacité des attaquants à surveiller et armer les vulnérabilités sur des logiciels de niche, probablement aidés par l'IA.

**Analyse de l'impact** : Compromission totale des environnements de science des données et vol de secrets sensibles. Cette vélocité réduit à néant le temps de réaction traditionnel des équipes de sécurité.

**Recommandations** :
* Mettre à jour Marimo vers la version 0.23.0 ou supérieure immédiatement.
* Isoler les instances de notebook derrière un VPN ou un proxy d'authentification robuste.
* Surveiller les connexions WebSockets inhabituelles sur le endpoint /terminal/ws.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Inconnu (opérateur humain qualifié) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1210 : Exploitation of Remote Services <br> * T1552.001 : Unsecured Credentials (Files) |
| Observables & Indicateurs de compromission | ```Endpoint : /terminal/ws (WebSocket). Cibles : fichiers .env, clés SSH.``` |

### Source (url) du ou des articles
* https://securityaffairs.com/190623/hacking/cve-2026-39987-marimo-rce-exploited-in-hours-after-disclosure.html