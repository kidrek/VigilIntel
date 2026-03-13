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
  * [“handala hack” – unveiling group’s modus operandi](#handala-hack--unveiling-groups-modus-operandi)
  * [ai-generated slopoly malware used in interlock ransomware attack](#ai-generated-slopoly-malware-used-in-interlock-ransomware-attack)
  * [us disrupts socksescort proxy network powered by linux malware](#us-disrupts-socksescort-proxy-network-powered-by-linux-malware)
  * [tengu ransomware: what security teams need to know](#tengu-ransomware-what-security-teams-need-to-know)
  * [storm-2561 uses seo poisoning to distribute fake vpn clients for credential theft](#storm-2561-uses-seo-poisoning-to-distribute-fake-vpn-clients-for-credential-theft)
  * [suspected china-based espionage operation against military targets in southeast asia](#suspected-china-based-espionage-operation-against-military-targets-in-southeast-asia)
<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage actuel de la menace est marqué par une escalade sans précédent des cyber-opérations étatiques liées au conflit US-Israël-Iran, où les attaques destructrices de type "wiper" prennent le pas sur l'extorsion financière classique. L'acteur Handala Hack (Void Manticore) illustre cette tendance en exploitant des outils de gestion légitimes comme Microsoft Intune pour paralyser des infrastructures critiques à l'échelle mondiale. Parallèlement, l'usage de l'IA générative pour le développement de malwares, comme Slopoly, abaisse la barrière technique pour les attaquants, permettant la création rapide de codes évasifs. Les vulnérabilités logicielles dans les outils d'automatisation (n8n) et les extensions de navigateur deviennent des vecteurs de compromission de la chaîne d'approvisionnement extrêmement critiques. Le démantèlement du réseau SocksEscort démontre l'efficacité des actions policières internationales, bien que la résilience des botnets comme AVRecon reste préoccupante. Les décideurs doivent s'attendre à une volatilité accrue due à la nouvelle stratégie cyber offensive des États-Unis, susceptible de provoquer des représailles. La gestion des identités et des accès privilégiés (PAM/PIM) devient le rempart indispensable contre des acteurs qui privilégient désormais l'usage de comptes légitimes détournés. Enfin, la pression pour l'innovation en IA en Europe pourrait fragiliser les cadres réglementaires de protection des données au profit de la compétitivité.
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
| AiLock | Entreprises mondiales | Ransomware double-extorsion, chiffrement ChaCha20/NTRU | England Hockey |
| APT28 | Gouvernements, Militaires | Phishing via fichiers .LNK, exploitation MSHTML (CVE-2026-21513) | Recorded Future |
| CL-STA-1087 (Chine) | Militaire (Asie du Sud-Est) | Backdoors sur mesure (AppleChris, MemFun), DLL Hijacking | Unit 42 |
| Handala Hack (Void Manticore) | Infrastructures critiques, Médical | Wiper destructeur, abus de Microsoft Intune, vol de données | Checkpoint, Unit 42 |
| Hive0163 | Finance, Santé | Malware généré par IA (Slopoly), intrusion via ClickFix | BleepingComputer |
| Lotus Blossom | Utilisateurs de Notepad++ | Attaque supply-chain via faux installeurs, Cobalt Strike | Recorded Future |
| Medusa | Santé, Services d'urgence | Ransomware, vol de données (219 GB) | Bell Ambulance |
| ShinyHunters | BPO, Télécoms, Cloud | Vishing (voix), vol de jetons Microsoft Entra, accès via fuites GCP | Telus Digital |
| Storm-1811 | Finance, Santé | Phishing via Teams, malware A0Backdoor via Quick Assist | The Hacker News |
| Storm-2561 | Utilisateurs de VPN | SEO Poisoning, faux installeurs VPN signés, infostealer Hyrax | Microsoft Security |
| Tengu | Tech, Manufacturier, Public | Ransomware-as-a-Service, abus de RDP/VPN sans MFA | Flare |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Afghanistan / Pakistan | Conflit frontalier | Escalade des tensions et bombardements le long de la ligne Durand. | IRIS |
| Europe | Terrorisme & Cyber | Alertes d'Europol sur des représailles iraniennes (bombes, cyberattaques) sur le sol européen. | Flare |
| Iran | Blackout Internet | Coupure quasi-totale de l'internet en Iran suite aux frappes américano-israéliennes. | Flare |
| Moyen-Orient | Guerre Cyber | Conflit US-Israël-Iran : vagues d'attaques wipers et sabotages d'infrastructures ICS/SCADA. | Flare, Unit 42 |
| Turquie | Diplomatie | Ankara tente de maintenir une neutralité délicate face au conflit en Iran. | IRIS |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » (cybersécurité, protection des données, cybersécurité publique, etc.) :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Digital Omnibus | Commission Européenne | 12/03/2026 | Union Européenne | Digital Omnibus / IA Act | Projet de simplification administrative visant à alléger les contraintes réglementaires pour favoriser l'IA. | EDRi |
| ENISA Technical Advisory | ENISA | 12/03/2026 | Union Européenne | DevSecOps Guidance | Recommandations sur la sécurisation des gestionnaires de paquets tiers (npm, pip, Maven). | Security Affairs |
| US National Cyber Strategy | Sean Cairncross | 10/03/2026 | États-Unis | Cyber Strategy for America | Nouvelle stratégie mettant l'accent sur les opérations offensives pour imposer des coûts aux adversaires. | Flare |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Distribution / Retail | Loblaw (Canada) | Accès non autorisé à des informations de base (noms, emails, téléphones). | BleepingComputer |
| Médical | Stryker (USA) | Attaque massive par wiper (Handala Hack), 50 To de données exfiltrées. | Flare |
| Santé | Bell Ambulance | Violation de données affectant 238 000 personnes (SSN, données médicales). | Security Affairs |
| Santé / Assurance | TriZetto | Hack d'un an exposé, données de 3,4 millions de patients compromises. | Joe Talos |
| Sport | England Hockey | Revendication de 129 Go de données volées par le gang AiLock. | BleepingComputer |
| Télécoms / BPO | Telus Digital | Vol présumé de 1 pétaoctet de données par ShinyHunters (données clients et appels). | BleepingComputer |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).
| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|
| CVE-2025-68613 | 10.0 | n8n | Exécution de code à distance (RCE) | CISA, The Register |
| CVE-2026-3611 | 10.0 | Honeywell IQ4x BMS | Absence d'authentification critique | CVE Feed |
| CVE-2026-32306 | 9.9 | OneUptime (ClickHouse) | Injection SQL critique | CVE Feed |
| CVE-2026-23813 | 9.8 | Aruba AOS-CX | Contournement d'authentification critique | Field Effect |
| CVE-2026-32304 | 9.8 | Locutus | Exécution de code à distance (RCE) | CVE Feed |
| CVE-2026-21666 | 9.8 | Veeam Backup & Replication | Exécution de code à distance (RCE) | BleepingComputer |
| CVE-2026-32301 | 9.3 | Centrifugo | Server-Side Request Forgery (SSRF) | CVE Feed |
| CVE-2026-21262 | 8.8 | Microsoft SQL Server | Élévation de privilèges (EoP) | SOC Prime |
| CVE-2026-3909 | Crit. | Google Chrome (Skia) | Out-of-bounds write (Zero-day) | SecurityOnline |
| CVE-2026-3910 | Crit. | Google Chrome (V8) | Erreur d'implémentation (Zero-day) | SecurityOnline |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| “Handala Hack” – Unveiling Group’s Modus Operandi | Détails tactiques cruciaux sur un acteur étatique majeur actuel. | https://research.checkpoint.com/2026/handala-hack-unveiling-groups-modus-operandi/ |
| AI-generated Slopoly malware | Première observation documentée de malware complexe généré par IA. | https://www.bleepingcomputer.com/news/security/ai-generated-slopoly-malware-used-in-interlock-ransomware-attack/ |
| US disrupts SocksEscort proxy network | Analyse d'une opération de démantèlement internationale réussie. | https://www.bleepingcomputer.com/news/security/us-disrupts-socksescort-proxy-network-powered-by-linux-malware/ |
| Tengu Ransomware: What Security Teams Need to Know | Analyse complète d'un nouveau RaaS très actif. | https://flare.io/learn/resources/blog/tengu-ransomware |
| Storm-2561 fake VPN clients | Alerte sur une technique sophistiquée de SEO poisoning ciblant les accès distants. | https://www.microsoft.com/en-us/security/blog/2026/03/12/storm-2561-uses-seo-poisoning-to-distribute-fake-vpn-clients-for-credential-theft/ |
| China-Based Espionage Against Military Targets | Rapport détaillé sur des backdoors persistantes en Asie. | https://unit42.paloaltonetworks.com/espionage-campaign-against-military-targets/ |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| ISC Stormcast | Format podcast sans détails textuels exploitables pour ce rapport. | https://isc.sans.edu/diary/rss/32792 |
| Licensing Review of Microsoft 365 E7 | Article à visée commerciale et promotionnelle sur les licences. | https://www.guidepointsecurity.com/blog/microsoft-licensing-review-365-e7/ |
| This one’s for you, Mom | Newsletter Talos contenant trop d'avis personnels et peu de données techniques neuves. | https://blog.talosintelligence.com/this-ones-for-you-mom/ |

<br>
<br>
<div id="articles"></div>

# ARTICLES
<div id="handala-hack--unveiling-groups-modus-operandi"></div>

## “Handala Hack” – Unveiling Group’s Modus Operandi
Handala Hack est un acteur affilié au ministère iranien du Renseignement (MOIS), opérant sous plusieurs identités comme Void Manticore ou Homeland Justice. Le groupe privilégie les attaques destructrices de type "wiping" combinées à des fuites de données (hack-and-leak). Récemment, ils ont visé des infrastructures critiques en Israël et de grandes entreprises américaines comme Stryker. Leur mode opératoire repose sur un accès manuel (hands-on) après avoir obtenu des identifiants compromis, souvent via des VPN ou du phishing. Une fois à l'intérieur, ils se déplacent latéralement par RDP et utilisent des outils de tunnellisation comme NetBird. Pour la destruction, ils déploient plusieurs wipers simultanément, dont un script PowerShell probablement assisté par IA. Ils utilisent également des outils de chiffrement légitimes comme VeraCrypt pour rendre les données irrécupérables. Le groupe abuse des scripts de connexion GPO pour propager leurs malwares sur tout le réseau. Les analyses montrent une baisse de leur discipline opérationnelle, avec des connexions directes depuis des IP iraniennes. Des preuves suggèrent qu'ils ont ciblé plus de 200 000 appareils chez Stryker via Microsoft Intune.

**Analyse de l'impact** : Impact critique sur la continuité d'activité. La combinaison de wipers et de chiffrement par des outils légitimes rend la récupération extrêmement complexe sans sauvegardes hors-ligne robustes. L'utilisation d'outils d'administration (Intune, GPO) pour la destruction massive multiplie la vitesse de l'attaque.

**Recommandations** :
* Appliquer impérativement le MFA sur tous les accès VPN et comptes privilégiés.
* Restreindre les capacités de "wipe" à distance dans Microsoft Intune via des politiques d'approbation multi-administrateur (MAA).
* Surveiller les connexions RDP provenant de machines utilisant des noms par défaut (ex: DESKTOP-XXXXXX).
* Bloquer les outils de tunnellisation non autorisés comme NetBird et surveiller l'usage de VeraCrypt.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Handala Hack (Void Manticore / Storm-1084) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1133: External Remote Services<br/>* T1078.002: Domain Accounts<br/>* T1561.002: Disk Structure Wipe<br/>* T1484.001: Group Policy Modification |
| Observables & Indicateurs de compromission | * IP: 107.189.19.52 (VPS)<br/>* IP: 146.185.219.235 (VPN exit)<br/>* Hash (PowerShell Wiper): 3cb9dea916432ffb8784ac36d1f2d3cd |

### Source (url) du ou des articles
* https://research.checkpoint.com/2026/handala-hack-unveiling-groups-modus-operandi/
* https://unit42.paloaltonetworks.com/handala-hack-wiper-attacks/

<br/>
<div id="ai-generated-slopoly-malware-used-in-interlock-ransomware-attack"></div>

## AI-generated Slopoly malware used in Interlock ransomware attack
Une nouvelle souche de malware nommée Slopoly a été identifiée lors d'attaques du ransomware Interlock. Ce malware, un script PowerShell agissant comme client C2, présente des signes clairs de création par intelligence artificielle générative (LLM). Les chercheurs d'IBM X-Force ont noté des commentaires extensifs, une gestion d'erreurs structurée et des noms de variables très explicites, rares dans les développements humains. Slopoly permet de maintenir une persistance sur un serveur compromis et de collecter des informations système. Bien que décrit comme "polymorphe" dans ses commentaires, il ne modifie pas réellement son code en exécution. L'attaque débute par une technique d'ingénierie sociale de type "ClickFix". Outre Slopoly, les attaquants déploient les backdoors NodeSnake et InterlockRAT. Le groupe derrière ces attaques, Hive0163, est motivé par l'extorsion financière massive. Cette utilisation de l'IA montre une accélération dans le développement de malwares personnalisés pour échapper à la détection.

**Analyse de l'impact** : L'impact est significatif par la capacité de l'IA à générer des variantes uniques de malwares simples, compliquant la détection par signature. Cela permet à des acteurs peu sophistiqués de maintenir des accès persistants plus longtemps.

**Recommandations** :
* Sensibiliser les utilisateurs aux ruses "ClickFix" (fausses alertes de navigateur demandant de copier/coller une commande).
* Surveiller l'exécution de scripts PowerShell suspects dans le répertoire C:\ProgramData\Microsoft\Windows\Runtime\.
* Implémenter une surveillance des tâches planifiées nommées "Runtime Broker" pointant vers des scripts.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Hive0163 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1059.001: PowerShell<br/>* T1566: Phishing (ClickFix)<br/>* T1053.005: Scheduled Task |
| Observables & Indicateurs de compromission | * Chemin: C:\ProgramData\Microsoft\Windows\Runtime\<br/>* Processus: cmd.exe via PowerShell |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/ai-generated-slopoly-malware-used-in-interlock-ransomware-attack/

<br/>
<div id="us-disrupts-socksescort-proxy-network-powered-by-linux-malware"></div>

## US disrupts SocksEscort proxy network powered by Linux malware
Les autorités américaines et européennes ont démantelé le réseau de proxy cybercriminel SocksEscort. Ce réseau reposait sur plus de 20 000 appareils infectés chaque semaine, principalement des routeurs SOHO via le malware AVRecon. SocksEscort vendait l'accès à des adresses IP "propres" pour permettre aux cybercriminels de contourner les listes de blocage. Le service a été impliqué dans des vols de cryptomonnaies s'élevant à des millions de dollars et des fraudes bancaires. L'opération a permis de saisir 34 domaines et 23 serveurs dans sept pays, ainsi que de geler 3,5 millions de dollars en cryptomonnaies. AVRecon, actif depuis 2021, avait infecté plus de 70 000 routeurs Linux. Malgré une première tentative de neutralisation en 2023, les opérateurs avaient réussi à rétablir leur infrastructure. Plus de la moitié des victimes se situaient aux États-Unis et au Royaume-Uni. Cette action coordonnée marque un coup d'arrêt important pour les services de routage anonyme utilisés par les botnets.

**Analyse de l'impact** : La neutralisation réduit immédiatement la capacité des attaquants à masquer leur origine géographique lors d'attaques de phishing ou de brute force. Cependant, l'existence de botnets similaires comme KadNap montre la persistance de cette menace sur les équipements réseaux.

**Recommandations** :
* Remplacer les routeurs en fin de vie (EoL) qui ne reçoivent plus de mises à jour de sécurité.
* Changer impérativement les mots de passe administrateur par défaut des équipements réseaux.
* Désactiver les panneaux d'accès à distance (WAN administration) si non strictement nécessaires.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Opérateurs de SocksEscort / AVRecon |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1090: Proxy<br/>* T1201: Password Policy Discovery<br/>* T1584: Compromise Infrastructure |
| Observables & Indicateurs de compromission | * Botnet: AVRecon<br/>* Protocoles: Kademlia DHT (pour botnets similaires) |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/us-disrupts-socksescort-proxy-network-powered-by-linux-malware/

<br/>
<div id="tengu-ransomware-what-security-teams-need-to-know"></div>

## Tengu Ransomware: What Security Teams Need to Know
Tengu est une opération de Ransomware-as-a-Service (RaaS) apparue en octobre 2025 avec déjà 50 victimes revendiquées. Le groupe utilise un modèle classique de double extorsion : vol de données suivi d'un chiffrement. Leurs cibles sont variées, incluant la technologie, l'industrie manufacturière et le secteur public. L'accès initial se fait quasi exclusivement par l'abus de comptes valides sur des services RDP ou VPN sans MFA. Une fois dans le réseau, les affiliés utilisent massivement des outils légitimes (LOLBins) comme PowerShell et cmd. Ils désactivent Microsoft Defender (via Set-MpPreference) et effacent les journaux d'événements. La persistance est établie via des clés de registre aux noms trompeurs (ex: WindowsSecurityUpdate). L'exfiltration des données s'appuie sur des outils comme Rclone et WinSCP. Les fichiers chiffrés reçoivent l'extension .tengu.

**Analyse de l'impact** : Risque élevé de fuite de données et d'arrêt de production. Le groupe cible spécifiquement les organisations ayant une hygiène de sécurité des identifiants faible.

**Recommandations** :
* Imposer un MFA résistant au phishing (FIDO2) pour tous les accès distants.
* Surveiller l'utilisation de `wevtutil cl` (effacement de logs), signe d'une action malveillante imminente.
* Restreindre ou bloquer les outils d'exfiltration comme Rclone s'ils ne sont pas nécessaires.
* Maintenir des sauvegardes hors-ligne et segmentées.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Tengu Ransomware Group |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1078: Valid Accounts<br/>* T1562.001: Disable or Modify Tools<br/>* T1070.001: Clear Windows Event Logs<br/>* T1567: Exfiltration Over Web Service |
| Observables & Indicateurs de compromission | * Registre: HKLM\...\Run\SystemSecurityMonitor<br/>* Extension: .tengu<br/>* Hash (MD5): dfbc9412be99b25137ab6ab575489a93 |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/tengu-ransomware

<br/>
<div id="storm-2561-uses-seo-poisoning-to-distribute-fake-vpn-clients-for-credential-theft"></div>

## Storm-2561 uses SEO poisoning to distribute fake VPN clients for credential theft
L'acteur cybercriminel Storm-2561 utilise le "SEO poisoning" pour distribuer de faux clients VPN. En manipulant les résultats de recherche pour des termes comme "Pulse VPN download", il attire les utilisateurs vers des sites frauduleux. Ces sites redirigent vers des dépôts GitHub contenant des fichiers ZIP malveillants. L'installeur MSI déploie un exécutable légitime détourné pour charger latéralement (DLL side-loading) des DLL malveillantes. Ces DLL installent une variante de l'infostealer Hyrax conçue pour voler les identifiants VPN saisis. Pour plus de crédibilité, les fichiers sont signés numériquement par un certificat d'une entreprise technologique chinoise (désormais révoqué). Après le vol des identifiants, l'application affiche une fausse erreur et redirige l'utilisateur vers le site officiel du VPN. Cette ruse permet de minimiser les soupçons de l'utilisateur qui finit par installer le logiciel légitime.

**Analyse de l'impact** : Risque majeur de compromission des accès initiaux à l'entreprise. Le vol des identifiants VPN permet aux attaquants de pénétrer directement dans le réseau interne sans passer par des vulnérabilités complexes.

**Recommandations** :
* Sensibiliser les utilisateurs à ne télécharger des logiciels d'entreprise que via les portails officiels internes.
* Utiliser Microsoft Edge avec SmartScreen pour bloquer les sites de phishing connus.
* Activer l'EDR en mode blocage pour détecter le side-loading de DLL inhabituelles dans les répertoires programmes.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Storm-2561 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.002: Spearphishing Link (SEO poisoning)<br/>* T1574.002: DLL Side-Loading<br/>* T1555: Credentials from Password Stores |
| Observables & Indicateurs de compromission | * Domaine: vpn-fortinet[.]com<br/>* IP C2: 194.76.226.93:8080<br/>* Signataire: Taiyuan Lihua Near Information Technology Co., Ltd. |

### Source (url) du ou des articles
* https://www.microsoft.com/en-us/security/blog/2026/03/12/storm-2561-uses-seo-poisoning-to-distribute-fake-vpn-clients-for-credential-theft/

<br/>
<div id="suspected-china-based-espionage-operation-against-military-targets-in-southeast-asia"></div>

## Suspected China-Based Espionage Operation Against Military Targets in Southeast Asia
Une opération d'espionnage sophistiquée, baptisée CL-STA-1087, cible les organisations militaires en Asie du Sud-Est depuis 2020. L'acteur, suspecté d'être lié à la Chine, fait preuve d'une grande patience opérationnelle, restant parfois dormant plusieurs mois. Ils utilisent des backdoors sur mesure nommées AppleChris et MemFun pour maintenir l'accès. Le vecteur initial d'infection reste indéterminé, mais le groupe se déplace via WMI et détourne des services comme le Volume Shadow Copy. Ils recherchent activement des documents sensibles sur les structures organisationnelles militaires et la collaboration avec les forces occidentales. AppleChris utilise des techniques de "Dead Drop Resolver" (DDR) via Pastebin ou Dropbox pour localiser ses serveurs C2. MemFun est un malware multi-étapes opérant presque entièrement en mémoire pour éviter la détection. Un variant personnalisé de Mimikatz, appelé Getpass, est utilisé pour récolter les identifiants système.

**Analyse de l'impact** : Risque critique d'espionnage d'État et de vol de secrets militaires. La persistance et l'utilisation d'outils en mémoire rendent ces attaques extrêmement difficiles à détecter par des solutions antivirus classiques.

**Recommandations** :
* Auditer les logs WMI pour détecter des exécutions de scripts PowerShell distants suspects.
* Surveiller les connexions vers Pastebin et Dropbox depuis des serveurs sensibles.
* Utiliser des solutions de type EDR/XDR capables de détecter les injections en mémoire et le "process hollowing".

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | CL-STA-1087 (Nexus Chinois) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1047: Windows Management Instrumentation<br/>* T1574.001: DLL Hijacking<br/>* T1102: Web Service (DDR)<br/>* T1003: OS Credential Dumping |
| Observables & Indicateurs de compromission | * Mutex: 0XFEXYCDAPPLE05CHRIS<br/>* IP C2: 154.39.142.177<br/>* Hash (AppleChris): 9e44a460196cc92fa6c6c8a12d74fb73a55955045733719e3966a7b8ced6c500 |

### Source (url) du ou des articles
* https://unit42.paloaltonetworks.com/espionage-campaign-against-military-targets/