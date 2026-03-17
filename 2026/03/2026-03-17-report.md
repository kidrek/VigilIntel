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
  * [Évolution de la menace iranienne : du wiper à l'armement de l'identité](#evolution-de-la-menace-iranienne--du-wiper-a-larmement-de-lidentite)
  * [Boggy serpens : analyse d'une campagne d'espionnage sophistiquée](#boggy-serpens--analyse-dune-campagne-despionnage-sophistiquee)
  * [Ransomware 2025 : pression accrue et mutation des tactiques](#ransomware-2025--pression-accrue-et-mutation-des-tactiques)
  * [Drillapp : un nouveau backdoor ciblant l'ukraine via edge](#drillapp--un-nouveau-backdoor-ciblant-lukraine-via-edge)
  * [L'économie des infostealers en 2025 : une accélération alarmante](#leconomie-des-infostealers-en-2025--une-acceleration-alarmante)
  * [Rondodox : expansion massive d'un botnet exploitant 174 vulnérabilités](#rondodox--expansion-massive-dun-botnet-exploitant-174-vulnerabilites)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage cyber de mars 2026 est marqué par une escalade majeure du conflit tripartite US-Israël-Iran, où le domaine cyber sert de multiplicateur de force asymétrique. L'attaque massive contre Stryker illustre un changement de paradigme : le passage de l'usage de malwares personnalisés (wipers) à "l'armement de l'identité", où des outils d'administration légitimes (Microsoft Intune) sont détournés pour une destruction à grande échelle. Parallèlement, l'écosystème du ransomware mute face à la baisse de rentabilité, délaissant les grandes entreprises pour multiplier les attaques contre des structures plus petites et ciblant systématiquement les infrastructures de virtualisation (ESXi). L'économie des *infostealers* s'industrialise, avec une exploitation croissante des cookies de session pour contourner l'authentification multi-facteurs (MFA), désormais jugée insuffisante. En Europe, l'accent est mis sur la résilience industrielle via le *European Chips Act* et le renforcement de la "digital fairness" face aux modèles manipulateurs. La Russie maintient une pression constante sur l'Ukraine par des attaques hybrides ciblant le réseau énergétique et l'utilisation de backdoors innovants comme DRILLAPP. Enfin, la nouvelle stratégie cyber américaine sous l'administration Trump prône une posture offensive décomplexée, incitant le secteur privé à participer activement à la disruption des réseaux adverses.
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
| APT28 (Pawn Storm) | Gouvernement, Ukraine | Utilisation du toolkit "Roundish", exploitation de Roundcube | [The Hacker News](https://thehackernews.com/2026/03/weekly-recap-chrome-0-days-router.html) |
| Boggy Serpens (MuddyWater) | Diplomatie, Énergie, Maritime, Finance | Phishing via comptes compromis, malware en Rust (BlackBeard), RMM | [Unit 42](https://unit42.paloaltonetworks.com/boggy-serpens-threat-assessment/) |
| Camaro Dragon | Gouvernement, Énergie (Qatar) | Déploiement de PlugX et Cobalt Strike | [Check Point](https://research.checkpoint.com/2026/16th-march-threat-intelligence-report/) |
| CyberAv3ngers | Infrastructures critiques (Eau, Énergie) | Exploitation de PLC/OT, malware IOCONTROL | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Forbidden Hyena (4B1D) | Organisations en Russie | BlackReaperRAT, Blackout Locker ransomware | [The Hacker News](https://thehackernews.com/2026/03/weekly-recap-chrome-0-days-router.html) |
| Handala Hack (Void Manticore) | Santé, Technologies médicales, Infrastructures israéliennes | Wiper via abus MDM (Intune), exfiltration de données | [BleepingComputer](https://www.bleepingcomputer.com/news/security/stryker-attack-wiped-tens-of-thousands-of-devices-no-malware-needed/) / [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Hydro Kitten | Secteur financier | Ciblage des services financiers US/alliés | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Laundry Bear (Void Blizzard) | Défense, Ukraine | Backdoor DRILLAPP via Microsoft Edge | [Security Affairs](https://securityaffairs.com/189519/malware/russia-linked-apt-uses-drillapp-backdoor-to-spy-on-ukrainian-targets.html) |
| LummaC2 | Global | Infostealer-as-a-Service, évasion de sandbox trigonométrique | [Recorded Future](https://www.recordedfuture.com/blog/identity-trend-report-march-blog) |
| Russian Legion | Défense (Israël) | Allégations de compromission de l'Iron Dome | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| ShinyHunters | Télécommunications (Telus Digital) | Vol de données massif, demande de rançon | [Check Point](https://research.checkpoint.com/2026/16th-march-threat-intelligence-report/) |
| TA402 (Frankenstein) | Gouvernement Moyen-Orient | Phishing thématique via emails diplomatiques compromis | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Défense | Conflit Iran-Israël-USA | Intensification des cyber-opérations liées au conflit cinétique entamé le 28 février 2026. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Énergie | Guerre en Ukraine | Frappes russes méthodiques sur le réseau électrique ukrainien durant l'hiver. | [EUvsDisinfo](https://euvsdisinfo.eu/targeting-the-grid-shaping-the-story-russias-dual-assault-on-ukraine/) |
| Énergie | Sommet Nucléaire | Deuxième sommet mondial à Paris sur la relance du nucléaire dans un contexte d'instabilité. | [IRIS](https://www.iris-france.org/sommet-sur-lenergie-nucleaire-comment-envisager-la-relance-du-nucleaire-dans-un-contexte-dinstabilite-geopolitique/) |
| Gouvernement | Stratégie Cyber US | Publication de la stratégie cyber sous Trump privilégiant l'offensive et la domination technologique. | [RUSI](https://www.rusi.org/explore-our-research/publications/commentary/brief-bold-and-beautiful-reactions-us-national-cyber-strategy) |
| Maritime | Résilience Portuaire | Analyse de la résilience du port Nantes-Saint-Nazaire face aux enjeux de souveraineté. | [Portail IE](https://www.portail-ie.fr/univers/enjeux-de-puissances-et-geoeconomie/2026/competitivite-et-resilience-de-la-zone-industrialo-portuaire-de-nantes-saint-nazaire/) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Civil society calls for an ambitious Digital Fairness Act | EDRi | 16/03/2026 | Union Européenne | Digital Fairness Act (DFA) | Appel à moderniser la protection des consommateurs contre les designs manipulateurs et l'extraction de données. | [EDRi](https://edri.org/our-work/civil-society-calls-for-an-ambitious-digital-fairness-act-on-world-consumer-rights-day/) |
| Open EU Foundry status granted to Silicon Box | Commission Européenne | 16/03/2026 | Union Européenne | European Chips Act | Octroi d'un statut facilitant le soutien administratif et financier pour la production de semi-conducteurs. | [European Commission](https://digital-strategy.ec.europa.eu/en/news/open-eu-foundry-status-granted-innovative-chiplet-facility) |
| Stratégie Cyber pour l'Amérique | Administration Trump | Mars 2026 | États-Unis | National Cyber Strategy 2026 | Stratégie courte (7 pages) axée sur la défense active, la domination technologique (IA) et l'offensive préemptive. | [RUSI](https://www.rusi.org/explore-our-research/publications/commentary/brief-bold-and-beautiful-reactions-us-national-cyber-strategy) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Administration | Companies House (UK) | Faille WebFiling exposant les données de 5 millions d'entreprises (dates de naissance, adresses) depuis oct. 2025. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/uks-companies-house-confirms-security-flaw-exposed-business-data/) |
| Collectivité | DeKalb County (Tennessee) | Attaque par ransomware touchant le bureau du shérif et la prison, perturbant les emails et les dossiers. | [DataBreaches.net](https://databreaches.net/2026/03/16/dekalb-county-tennessee-sheriff-and-jail-hit-by-ransomware-attack/) |
| Distribution | Loblaw Companies | Accès non autorisé au réseau informatique exposant noms, numéros et adresses email de clients. | [Check Point](https://research.checkpoint.com/2026/16th-march-threat-intelligence-report/) |
| Santé | Stryker Corporation | Wiper massif de 80 000 appareils via abus Microsoft Intune par le groupe Handala (Iran). | [BleepingComputer](https://www.bleepingcomputer.com/news/security/stryker-attack-wiped-tens-of-thousands-of-devices-no-malware-needed/) |
| Télécoms | Telus Digital | Revendication de vol d'un pétaoctet de données par ShinyHunters (rançon de 65M$). | [Check Point](https://research.checkpoint.com/2026/16th-march-threat-intelligence-report/) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).
| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|
| CVE-2026-3059 | 9.8 | SGLang (AI Framework) | Désérialisation Python Pickle non sécurisée (RCE) | [SecurityOnline](https://securityonline.info/poisoned-pickle-critical-unpatched-rce-flaws-sglang-ai-infrastructure/) |
| CVE-2026-3060 | 9.8 | SGLang (AI Framework) | Désérialisation Python Pickle non sécurisée (RCE) | [SecurityOnline](https://securityonline.info/poisoned-pickle-critical-unpatched-rce-flaws-sglang-ai-infrastructure/) |
| CVE-2025-68613 | 10.0 | n8n workflow platform | Exécution de code à distance (RCE) - Exploitée | [Check Point](https://research.checkpoint.com/2026/16th-march-threat-intelligence-report/) |
| CVE-2026-28792 | 9.7 | TinaCMS | Path Traversal + CORS misconfiguration (RCE) | [SecurityOnline](https://securityonline.info/drive-by-hijack-critical-9-7-cvss-tinacms-flaw-cve-2026-28792/) |
| CVE-2026-32267 | 9.2 | Craft CMS | Escalade de privilèges via ImpersonateWithToken | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-32267) |
| CVE-2026-30881 | 8.8 | Chamilo LMS | Injection SQL dans l'endpoint AJAX | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-30881) |
| CVE-2026-30875 | 8.8 | Chamilo LMS | RCE via Import H5P (File Upload) | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-30875) |
| CVE-2025-13957 | 8.8 | Schneider EcoStruxure | Mot de passe codé en dur (RCE) | [ZDI](http://www.zerodayinitiative.com/advisories/ZDI-26-212/) |
| CVE-2026-29522 | 8.7 | ZwickRoell Test Data | Path Traversal LFI | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-29522) |
| CVE-2026-31386 | 8.6 | LiteSpeed Web Server | Injection de commande OS via WebAdmin | [SecurityOnline](https://securityonline.info/server-siege-critical-8-6-cvss-flaw-litespeed-web-server-os-command-injection/) |
| CVE-2026-3909 | Haut | Google Chrome | Out-of-bounds write dans Skia - Exploitée | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0297/) |
| CVE-2026-3910 | Haut | Microsoft Edge | Vulnérabilité V8 - Exploitée | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0298/) |
| CVE-2025-47813 | 4.3 | Wing FTP Server | Information Disclosure (Path leak) - Exploitée | [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-flags-wing-ftp-server-flaw-as-actively-exploited-in-attacks/) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Boggy Serpens Threat Assessment | Rapport détaillé sur un groupe étatique iranien majeur et ses nouveaux outils IA. | [Unit 42](https://unit42.paloaltonetworks.com/boggy-serpens-threat-assessment/) |
| DRILLAPP backdoor targets Ukraine | Analyse d'une nouvelle technique de backdoor utilisant Microsoft Edge pour la furtivité. | [Security Affairs](https://securityaffairs.com/189519/malware/russia-linked-apt-uses-drillapp-backdoor-to-spy-on-ukrainian-targets.html) |
| Inside the Infostealer Economy 2025 | Étude statistique exhaustive sur l'évolution du vol d'identifiants et le contournement MFA. | [Recorded Future](https://www.recordedfuture.com/blog/identity-trend-report-march-blog) |
| Iranian Cyber Threat Evolution | Vision stratégique sur le passage des wipers vers l'abus des outils d'administration (MDM). | [Unit 42](https://unit42.paloaltonetworks.com/evolution-of-iran-cyber-threats/) |
| Ransomware Under Pressure: TTPs | Analyse de Mandiant sur les changements de modèles économiques et techniques des ransomwares. | [Google/Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/ransomware-ttps-shifting-threat-landscape/) |
| RondoDox Botnet Expands | Cas d'école d'un botnet industrialisé utilisant plus de 174 exploits et des IPs résidentielles. | [Cybersecurity News](https://cybersecuritynews.com/rondodox-botnet-expands/) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| Mastodon posts (multiples) | Réseaux sociaux non autorisés par les critères. | [Mastodon](https://mastodon.social/) |
| Stryker attack wiped devices | Classé en synthèse des violations de données. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/stryker-attack-wiped-tens-of-thousands-of-devices-no-malware-needed/) |
| UK Companies House flaw | Classé en synthèse des violations de données. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/uks-companies-house-confirms-security-flaw-exposed-business-data/) |
| CISA flags Wing FTP Server | Traité dans la synthèse des vulnérabilités. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-flags-wing-ftp-server-flaw-as-actively-exploited-in-attacks/) |
| SGLang AI infrastructure vulns | Traité dans la synthèse des vulnérabilités. | [SecurityOnline](https://securityonline.info/poisoned-pickle-critical-unpatched-rce-flaws-sglang-ai-infrastructure/) |
| DeKalb County Ransomware | Classé en synthèse des violations de données. | [DataBreaches.net](https://databreaches.net/2026/03/16/dekalb-county-tennessee-sheriff-and-jail-hit-by-ransomware-attack/) |

<br>
<br/>
<div id="articles"></div>

# ARTICLES

<div id="evolution-de-la-menace-iranienne--du-wiper-a-larmement-de-lidentite"></div>

## Évolution de la menace iranienne : du wiper à l'armement de l'identité
L'analyse retrace une décennie d'opérations cyber offensives iraniennes, soulignant une mutation radicale depuis 2023. Historiquement, des groupes comme APT33 (Curious Serpens) utilisaient des malwares de type "wiper" (Shamoon) pour détruire physiquement les disques. Aujourd'hui, les acteurs iraniens, notamment Void Manticore (Handala), privilégient les techniques de *Living-off-the-Land* (LotL) en ciblant les plans de gestion d'identité. L'attaque contre Stryker illustre cette tendance : aucun malware destructeur n'a été utilisé, mais des comptes d'administrateurs globaux ont été compromis pour envoyer des commandes légitimes de "remote wipe" via Microsoft Intune. Cette approche permet de contourner les solutions EDR/AV qui ne détectent pas de code malveillant, mais des actions administratives autorisées. L'objectif est d'atteindre une échelle de destruction massive (200 000 appareils) avec un coût de développement minimal. Cette stratégie offre également un déni plausible en imitant des cybercriminels ou des hacktivistes.

**Analyse de l'impact** : La menace ne réside plus dans le binaire malveillant mais dans la compromission du "Tier-0" (administration cloud). L'impact est systémique, capable de paralyser une multinationale en quelques heures via ses propres outils de gestion.

**Recommandations** :
*   Implémenter l'approbation multi-administrateurs (Multi-Admin Approval) pour les commandes sensibles comme l'effacement d'appareils (Wipe).
*   Gérer les plateformes MDM/RMM comme des infrastructures critiques de niveau Tier-0 avec un contrôle de changement rigoureux.
*   Éliminer les privilèges permanents et utiliser le *Privileged Identity Management* (PIM) pour des accès "Just-In-Time".
*   Maintenir des sauvegardes hors-ligne, immuables et isolées du tenant cloud principal.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Handala Hack (Void Manticore / Iran MOIS) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1078.004: Cloud Accounts<br/>• T1531: Account Access Removal<br/>• T1020: Automated Exfiltration<br/>• T1562.001: Disable or Modify Tools |
| Observables & Indicateurs de compromission | ```Abus de commandes Microsoft Intune (Wipe/Factory Reset) via comptes compromis.``` |

### Source (url) du ou des articles
* https://unit42.paloaltonetworks.com/evolution-of-iran-cyber-threats/
<br>
<br>

<div id="boggy-serpens--analyse-dune-campagne-despionnage-sophistiquee"></div>

## Boggy Serpens : analyse d'une campagne d'espionnage sophistiquee
Le groupe iranien Boggy Serpens (MuddyWater), lié au MOIS, a considérablement affiné son mode opératoire au cours de l'année écoulée. Il utilise désormais des leurres de phishing extrêmement personnalisés, basés sur des renseignements préalablement exfiltrés, pour cibler les secteurs de l'énergie et du maritime aux Émirats Arabes Unis. L'acteur utilise une plateforme d'orchestration web personnalisée en Python pour automatiser l'envoi massif d'emails via des comptes officiels compromis, contournant ainsi les filtres anti-spam. Techniquement, le groupe a adopté le langage Rust (backdoors BlackBeard et LampoRAT) et intègre du code généré par IA, identifiable par l'usage inhabituel d'emojis dans les journaux de debug. Une nouvelle famille de backdoor HTTP, nommée Nuso, utilise des codes de statut HTTP (ex: 201/204) comme déclencheurs de commandes plutôt que des chaînes de caractères traditionnelles. Le groupe maintient également une lignée de macros VBA sophistiquées utilisant des boucles de temporisation mathématiques pour épuiser les délais d'analyse des bacs à sable (sandboxes).

**Analyse de l'impact** : Forte capacité d'espionnage économique et politique, avec une résilience accrue grâce à la diversification des langages de programmation (C++, Rust, Python) et l'abus de services légitimes comme Telegram pour le C2.

**Recommandations** :
*   Surveiller les connexions UDP inhabituelles (ports 1259/1269) vers des IPs suspectes.
*   Bloquer l'exécution de macros VBA non signées et surveiller l'usage de WMI par les processus Office.
*   Auditer les comptes d'utilisateurs pour des signes de détournement (envoi massif d'emails, connexions depuis des localisations inhabituelles).

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Boggy Serpens (MuddyWater) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1566.002: Spearphishing Link<br/>• T1071.001: Web Protocols<br/>• T1102.002: Bidirectional Communication (Telegram API)<br/>• T1059.005: Visual Basic |
| Observables & Indicateurs de compromission | ```• Domains: stratioai[.]org, screenai[.]online, bootcamptg[.]org<br/>• IP: 157.20.182[.]75, 64.7.198[.]12<br/>• SHA-256 (Nuso): 1b9e6fe4b03285b2e768c57e320d84323ac9167598395918d56a12e568b0009a<br/>• Token Telegram: 8398566164:AAEJbk6EOirZ_ybm4PJ-q8mOpr1RkZx1H7Q``` |

### Source (url) du ou des articles
* https://unit42.paloaltonetworks.com/boggy-serpens-threat-assessment/
<br>
<br>

<div id="ransomware-2025--pression-accrue-et-mutation-des-tactiques"></div>

## Ransomware 2025 : pression accrue et mutation des tactiques
Le rapport Mandiant/Google souligne une baisse de la rentabilité globale des opérations de ransomware en 2025, poussant les acteurs à devenir plus agressifs. Une tendance majeure est le ciblage systématique des infrastructures de virtualisation, avec 43 % des intrusions ciblant ESXi (contre 29 % en 2024). Les attaquants automatisent désormais le déploiement sur les hyperviseurs via des scripts PowerShell et des outils comme NetExec. Le vol de données est devenu quasi systématique (77 % des cas), servant de levier de pression principal au-delà du chiffrement. On note un délaissement des outils classiques comme Cobalt Strike BEACON au profit de frameworks de test d'intrusion plus récents comme AdaptixC2. Le vecteur d'accès initial privilégié reste l'exploitation de vulnérabilités sur les VPN et pare-feux (Fortinet, SonicWall). Enfin, l'usage de l'IA pour l'analyse des points de pression des victimes et des technologies Web3 (smart contracts) pour la résilience des C2 commence à émerger.

**Analyse de l'impact** : Transition vers un modèle d'extorsion de données pure et vulnérabilité critique des serveurs de virtualisation qui permettent un arrêt complet de la production.

**Recommandations** :
*   Durcir les hyperviseurs ESXi : désactiver SSH, activer le mode Lockdown et désactiver l'option ExecInstalledOnly.
*   Surveiller l'usage d'outils de synchronisation cloud comme Rclone et MEGASync utilisés pour l'exfiltration.
*   Prioriser le correctif des CVE sur les équipements périmétriques (VPN/Firewall).

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | REDBIKE (Akira), Qilin, RansomHub, LockBit.WarLock |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1190: Exploit Public-Facing Application<br/>• T1484.001: Group Policy Modification<br/>• T1048.003: Exfiltration Over Unencrypted Non-HTTP Protocol (Rclone)<br/>• T1562.001: Disable or Modify Tools |
| Observables & Indicateurs de compromission | ```• Scripts: Veeam-Get-Creds.ps1<br/>• Ransomware families: REDBIKE, AGENDA, INC, NITROGEN<br/>• Processus: vmsvc, esxcli``` |

### Source (url) du ou des articles
* https://cloud.google.com/blog/topics/threat-intelligence/ransomware-ttps-shifting-threat-landscape/
<br>
<br>

<div id="drillapp--un-nouveau-backdoor-ciblant-lukraine-via-edge"></div>

## Drillapp : un nouveau backdoor ciblant l'ukraine via edge
Une nouvelle campagne d'espionnage attribuée avec une confiance modérée au groupe russe Laundry Bear (Void Blizzard) utilise un malware innovant nommé DRILLAPP. Ce backdoor se distingue par l'utilisation abusive du mode "headless" et des paramètres de débogage de Microsoft Edge pour s'exécuter furtivement. En activant le paramètre `--remote-debugging-port`, les attaquants utilisent le protocole Chrome DevTools (CDP) pour contourner les restrictions JavaScript et exfiltrer des fichiers, enregistrer l'audio du microphone ou capturer l'écran. L'infection débute par des fichiers LNK ou CPL déguisés en documents caritatifs ("Come Back Alive") ou techniques (installation Starlink). Le script malveillant est souvent hébergé sur des services de partage de texte publics comme pastefy.app. Cette méthode permet de dissimuler l'activité malveillante derrière un processus système courant et légitime, rendant la détection par les outils de surveillance traditionnels très difficile.

**Analyse de l'impact** : Menace sérieuse pour la confidentialité des données sur les postes de travail, permettant une surveillance audiovisuelle en temps réel sans éveiller les soupçons.

**Recommandations** :
*   Surveiller les lignes de commande de navigateur incluant `--remote-debugging-port` ou `--disable-web-security`.
*   Restreindre l'exécution des fichiers .CPL et surveiller la création de fichiers .LNK dans les dossiers temporaires.
*   Bloquer l'accès aux sites de partage de code/texte non nécessaires (pastefy.app, etc.).

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Laundry Bear (UAC-0190 / Void Blizzard) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1204.002: Malicious File<br/>• T1189: Drive-by Compromise<br/>• T1123: Audio Capture<br/>• T1113: Screen Capture |
| Observables & Indicateurs de compromission | ```• URLs: pastefy[.]app, gnome[.]com<br/>• Paramètres: --no-sandbox, --remote-debugging-port, --allow-file-access-from-files<br/>• Extensions: .lnk, .cpl``` |

### Source (url) du ou des articles
* https://securityaffairs.com/189519/malware/russia-linked-apt-uses-drillapp-backdoor-to-spy-on-ukrainian-targets.html
<br>
<br>

<div id="leconomie-des-infostealers-en-2025--une-acceleration-alarmante"></div>

## L'économie des infostealers en 2025 : une accélération alarmante
Le vol d'identifiants est devenu le vecteur d'accès initial dominant en 2025, avec une accélération marquée en fin d'année (+90 % de volume au dernier trimestre). Les infostealers comme LummaStealer ciblent spécifiquement les systèmes d'authentification (VPN, plateformes cloud, RMM). Une découverte majeure est que 31 % des identifiants volés incluent désormais des cookies de session actifs, permettant un contournement total du MFA (Multi-Factor Authentication). Chaque appareil infecté (souvent un appareil personnel utilisé pour le télétravail) livre en moyenne 87 jeux d'identifiants. Malgré les actions policières (opération contre LummaC2 en mai 2025), les malwares se réinventent rapidement via des rebrandings (StealC v2, MacSync). Les attaquants utilisent des techniques sophistiquées comme l'analyse trigonométrique des mouvements de souris pour détecter les environnements d'analyse automatisés.

**Analyse de l'impact** : Le MFA n'est plus un rempart absolu. La compromission d'un seul appareil personnel peut exposer l'intégralité de l'infrastructure d'entreprise via le vol de sessions.

**Recommandations** :
*   Réduire la durée de vie des jetons de session (session tokens) pour les applications critiques.
*   Mettre en place des politiques d'accès conditionnel basées sur la conformité de l'appareil (device health).
*   Surveiller les journaux d'accès pour des réutilisations de cookies depuis des adresses IP ou des navigateurs inhabituels.
*   Sensibiliser au risque lié à l'usage d'appareils personnels non gérés pour accéder aux ressources d'entreprise.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | LummaC2, Rhadamanthys, StealC v2, MacSync |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1539: Steal Web Session Cookie<br/>• T1555.003: Credentials from Web Browsers<br/>• T1027: Obfuscated Files or Information<br/>• T1497: Virtualization/Sandbox Evasion |
| Observables & Indicateurs de compromission | ```Usage de techniques "ClickFix" et faux téléchargements CAPTCHA pour l'infection initiale.``` |

### Source (url) du ou des articles
* https://www.recordedfuture.com/blog/identity-trend-report-march-blog
<br>
<br>

<div id="rondodox--expansion-massive-dun-botnet-exploitant-174-vulnerabilites"></div>

## Rondodox : expansion massive d'un botnet exploitant 174 vulnérabilités
RondoDox est un nouveau botnet spécialisé dans les attaques par déni de service (DoS), construit sur une base Mirai mais avec une ambition technique inédite. Il intègre un arsenal de 174 exploits ciblant 18 architectures système différentes, des serveurs x86 aux objets connectés (ARM, MIPS). Sa particularité réside dans sa réactivité : il intègre de nouvelles vulnérabilités quelques jours seulement après leur divulgation publique (ex: CVE-2025-55182 ajoutée en 3 jours). Le botnet utilise une couche d'hébergement trompeuse basée sur des adresses IP résidentielles compromises (UniFi, Android TV, domotique) pour masquer son infrastructure de contrôle. Les serveurs de commande renvoient des pages de leurre (vidéos de fond avec boutons inactifs) pour bloquer les tentatives d'analyse par les chercheurs en sécurité. 

**Analyse de l'impact** : Capacité de frappe DoS massive et difficile à filtrer en raison de la nature résidentielle des sources d'attaque.

**Recommandations** :
*   Désactiver les services d'administration à distance inutilisés sur les objets connectés.
*   Mettre à jour immédiatement les équipements réseau exposés à Internet.
*   Utiliser des solutions de protection anti-DDoS capables d'identifier les comportements de trafic botnet sur des plages IP résidentielles.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Opérateurs du botnet RondoDox |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1498: Network Denial of Service<br/>• T1190: Exploit Public-Facing Application<br/>• T1584.005: Compromise Infrastructure (Botnet)<br/>• T1205: Traffic Signaling |
| Observables & Indicateurs de compromission | ```• CVEs ciblées: CVE-2025-55182, CVE-2025-62593<br/>• Flux de 15 000 tentatives d'exploitation par jour.``` |

### Source (url) du ou des articles
* https://cybersecuritynews.com/rondodox-botnet-expands/