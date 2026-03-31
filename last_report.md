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
  * [TeamPCP : Extension de la campagne et monétisation](#teampcp-extension-de-la-campagne-et-monetisation)
  * [RoadK1ll : Nouvel implant de pivot via WebSocket](#roadk1ll-nouvel-implant-de-pivot-via-websocket)
  * [Exploitation active de Citrix NetScaler (CVE-2026-3055)](#exploitation-active-de-citrix-netscaler-cve-2026-3055)
  * [Fuite de données ChatGPT via DNS Tunneling](#fuite-de-donnees-chatgpt-via-dns-tunneling)
  * [F5 BIG-IP : Vulnérabilité critique reclassée en RCE](#f5-big-ip-vulnerabilite-critique-reclassee-en-rce)
  * [TA446 : Utilisation du kit d'exploitation DarkSword contre iOS](#ta446-utilisation-du-kit-dexploitation-darksword-contre-ios)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage actuel de la menace est dominé par une transition critique des attaques de la chaîne d'approvisionnement vers une phase de monétisation agressive, illustrée par le groupe TeamPCP. Ce dernier exploite un gisement de 300 Go de comptes dérobés pour cibler des plateformes de données cloud comme Databricks et extorquer des entreprises majeures. Parallèlement, nous observons une réduction drastique du délai entre la divulgation d'une vulnérabilité et son exploitation active, notamment sur les équipements de bord de réseau (F5, Citrix, Fortinet), qui restent des cibles privilégiées pour l'accès initial. Sur le plan tactique, l'utilisation de tunnels WebSocket (RoadK1ll) et de canaux DNS dissimulés (ChatGPT) souligne une sophistication croissante dans l'exfiltration et le pivotement interne. La dimension géopolitique s'intensifie avec le conflit en Iran, où le cyberespace devient un prolongement direct des hostilités, comme en témoigne le piratage du compte personnel du directeur du FBI par le groupe Handala. Enfin, l'adaptation de kits d'exploitation iOS (DarkSword) par des acteurs étatiques russes montre que la mobilité reste un maillon faible stratégique. Les décideurs doivent prioriser la rotation des secrets et la sécurisation des accès distants SAML/OIDC face à ces menaces persistantes.
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
| Handala Hack | Gouvernement US, FBI | Phishing, vol de données personnelles et fuite (Doxxing) | [The Hacker News](https://thehackernews.com/2026/03/weekly-recap-telecom-sleeper-cells-llm.html) |
| LAPSUS$ | Santé, Industrie | Vol de code source et exfiltration de données massives | [SANS ISC](https://isc.sans.edu/diary/rss/32846) |
| Mustang Panda (Stately Taurus) | Gouvernements Asie du Sud-Est | Propagation par USB (USBFect), malwares PUBLOAD et CoolClient | [Security Affairs](https://securityaffairs.com/190174/apt/china-linked-groups-target-southeast-asian-government-with-advanced-malware-in-2025.html) |
| Red Menshen | Télécommunications | Implants kernel BPFDoor pour une persistance à long terme | [The Hacker News](https://thehackernews.com/2026/03/weekly-recap-telecom-sleeper-cells-llm.html) |
| TA446 (ColdRiver/Callisto) | Défense, ONG, iCloud | Spear-phishing ciblant iOS via le kit DarkSword | [Security Affairs](https://securityaffairs.com/190139/apt/russia-linked-apt-ta446-uses-darksword-exploit-to-target-iphone-users-in-phishing-wave.html) |
| TeamPCP | Cloud, Développeurs, DevOps | Empoisonnement de la chaîne d'approvisionnement, vol de tokens CI/CD | [SANS ISC](https://isc.sans.edu/diary/rss/32846) |
| XP95 | Gouvernement, Santé | Ransomware et exfiltration de données statistiques | [DataBreaches.net](https://databreaches.net/2026/03/30/south-african-government-agency-and-spanish-psychological-software-provider-victims-of-cyberattacks-by-xp95/) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Gouvernement | Conflit Iran-USA | Piratage du compte Gmail personnel du directeur du FBI par le groupe Handala (Iran) | [Le Monde](https://www.lemonde.fr/pixels/article/2026/03/30/depuis-le-debut-de-la-guerre-en-iran-les-hackeurs-proches-de-teheran-menent-des-attaques-opportunistes-a-la-portee-limitee_6675442_4408996.html) |
| Gouvernement | Tension Chine-Asie du Sud-Est | Campagnes d'espionnage massives de Mustang Panda contre un gouvernement d'Asie du Sud-Est | [Security Affairs](https://securityaffairs.com/190174/apt/china-linked-groups-target-southeast-asian-government-with-advanced-malware-in-2025.html) |
| Institutions | Europe-Chine/Iran | Cyberattaque contre la Commission européenne (350 Go volés) suite aux sanctions de l'UE contre des entités chinoises et iraniennes | [Infosec.exchange](https://infosec.exchange/@brian_greenberg/116321046727605004) |
| Défense | Russie-OTAN | Recrudescence des attaques de spear-phishing de TA446 visant les pays de l'OTAN via iOS | [Security Affairs](https://securityaffairs.com/190139/apt/russia-linked-apt-ta446-uses-darksword-exploit-to-target-iphone-users-in-phishing-wave.html) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Apple adds macOS Terminal warning | Bill Toulas | 30/03/2026 | Monde (Apple) | macOS Tahoe 26.4 | Nouveau mécanisme de blocage et d'alerte lors du copier-coller de commandes Terminal potentiellement malveillantes | [BleepingComputer](https://www.bleepingcomputer.com/news/security/apple-adds-macos-terminal-warning-to-block-clickfix-attacks/) |
| CISA KEV Catalog Additions | CISA | 27/03/2026 | USA | BOD 22-01 | Ajout des vulnérabilités F5 (CVE-2025-53521) et Trivy (CVE-2026-33634) au catalogue des vulnérabilités exploitées | [Field Effect](https://fieldeffect.com/blog/updated-f5-big-ip-apm-vulnerability-kev) |
| FCC Router Ban | FCC | 30/03/2026 | USA | Covered List | Interdiction d'importation de routeurs grand public de fabrication étrangère jugés risqués pour la sécurité nationale | [The Hacker News](https://thehackernews.com/2026/03/weekly-recap-telecom-sleeper-cells-llm.html) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Gouvernement | Commission Européenne | Vol allégué de 350 Go de données comprenant des emails, bases de données et contrats confidentiels | [Infosec.exchange](https://infosec.exchange/@brian_greenberg/116321046727605004) |
| Gouvernement | Statistics South Africa | Attaque par le ransomware XP95 ciblant l'agence nationale des statistiques | [DataBreaches.net](https://databreaches.net/2026/03/30/south-african-government-agency-and-spanish-psychological-software-provider-victims-of-cyberattacks-by-xp95/) |
| Pharmacie | AstraZeneca | Publication gratuite par LAPSUS$ de 3 Go de données (infos développeurs GitHub, code source interne) après échec de vente | [SANS ISC](https://isc.sans.edu/diary/rss/32846) |
| Santé | CareCloud | Violation de données impactant l'un des six environnements de dossiers médicaux électroniques (EHR) | [BleepingComputer](https://www.bleepingcomputer.com/news/security/healthcare-tech-firm-carecloud-says-hackers-stole-patient-data/) |
| Santé | West Tallinn Central Hospital | Un patient a reçu une clé USB contenant ses radios ainsi que les données de santé d'autres patients par erreur | [DataBreaches.net](https://databreaches.net/2026/03/30/estonian-hospital-sends-patient-home-with-other-peoples-health-data/) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2025-53521 | 9.8 | Non mentionné | TRUE | F5 BIG-IP APM | Remote Code Execution (RCE) | T1190: Exploit Public-Facing Application | Reclassée de DoS à RCE critique. Exploitation active pour déployer des webshells via des politiques d'accès mal configurées. | [F5 Advisory](https://my.f5.com/manage/s/article/K000156741) |
| CVE-2026-4257 | 9.8 | Non mentionné | FALSE | Contact Form by Supsystic (WP) | Server-Side Template Injection (SSTI) | T1190: Exploit Public-Facing Application | Injection Twig non sandboxée permettant l'exécution de code PHP arbitraire par des utilisateurs non authentifiés. | [Wordfence](https://www.wordfence.com/threat-intel/vulnerabilities/id/415c9658-bfb2-453b-a697-c63c08b0ca61?source=cve) |
| CVE-2026-33757 | 9.6 | Non mentionné | FALSE | OpenBao | OIDC Session Hijacking | T1550: Use Alternate Authentication Material | Fail politique d'authentification OIDC en mode direct permettant le détournement de session sans confirmation utilisateur. | [SecurityOnline](https://securityonline.info/openbao-critical-oidc-vulnerability-session-hijacking-xss/) |
| CVE-2026-33864 | 9.4 | Non mentionné | FALSE | node-convict (npm) | Prototype Pollution | T1211: Exploitation for Privilege Escalation | Bypass de filtres via manipulation de String.prototype permettant d'injecter des propriétés malveillantes globales. | [SecurityOnline](https://securityonline.info/node-convict-prototype-pollution-vulnerability-cve-2026-33864/) |
| CVE-2026-3055 | 9.3 | Non mentionné | FALSE | Citrix NetScaler ADC/Gateway | Memory Overread | T1190: Exploit Public-Facing Application | Lecture mémoire hors limites permettant de voler des jetons de session administrative sur les équipements configurés en SAML IDP. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-citrix-netscaler-memory-flaw-actively-exploited-in-attacks/) |
| CVE-2026-21643 | 9.1 | Non mentionné | FALSE | Fortinet FortiClient EMS | SQL Injection | T1190: Exploit Public-Facing Application | Injection SQL via le header "Site" permettant l'exécution de commandes à distance par un attaquant non authentifié. | [Security Affairs](https://securityaffairs.com/190158/security/critical-fortinet-forticlient-ems-flaw-exploited-for-remote-code-execution.html) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| TeamPCP Supply Chain Campaign: Update 004 | Analyse détaillée d'une campagne de chaîne d'approvisionnement majeure en cours de monétisation. | [SANS ISC](https://isc.sans.edu/diary/rss/32846) |
| New RoadK1ll WebSocket implant | Identification d'un nouvel implant furtif pour le mouvement latéral via des protocoles légitimes. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-roadk1ll-websocket-implant-used-to-pivot-on-breached-networks/) |
| Critical Citrix NetScaler memory flaw exploited | Alerte immédiate sur une vulnérabilité critique activement exploitée sur des équipements d'accès. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-citrix-netscaler-memory-flaw-actively-exploited-in-attacks/) |
| ChatGPT Data Leakage via Hidden Outbound Channel | Découverte d'une méthode innovante d'exfiltration via DNS tunneling dans les environnements IA. | [Check Point Research](https://research.checkpoint.com/2026/chatgpt-data-leakage-via-a-hidden-outbound-channel-in-the-code-execution-runtime/) |
| Hackers now exploit critical F5 BIG-IP flaw | Reclassification majeure d'une vulnérabilité et signalement d'exploitation active. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-now-exploit-critical-f5-big-ip-flaw-in-attacks-patch-now/) |
| Russia-linked APT TA446 uses DarkSword exploit | Menace étatique sophistiquée ciblant les appareils mobiles (iOS) via des exploits récents. | [Security Affairs](https://securityaffairs.com/190139/apt/russia-linked-apt-ta446-uses-darksword-exploit-to-target-iphone-users-in-phishing-wave.html) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| ISC Stormcast For Tuesday, March 31st | Format podcast trop succinct pour une analyse technique détaillée. | [SANS ISC](https://isc.sans.edu/podcastdetail/9872) |
| DShield (Cowrie) Honeypot Stats | Statistiques générales et méthodologiques sans menace immédiate spécifique. | [SANS ISC](https://isc.sans.edu/diary/rss/32840) |
| How to Evaluate AI SOC Agents | Contenu promotionnel/sponsorisé de type "livre blanc" sans information sur une menace réelle. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/how-to-evaluate-ai-soc-agents-7-questions-gartner-says-you-should-be-asking/) |
| Wave Browser: Gaming Platforms | Présentation marketing d'un navigateur orienté utilisateur, pas de veille cyber. | [Hackread](https://hackread.com/strongswan-flaw-attackers-crash-vpn-integer-underflow/) |
| Discord age verification fiasco | Sujet lié à la confidentialité et aux politiques de plateforme plutôt qu'à une intrusion. | [Infosec.exchange](https://infosec.exchange/@brian_greenberg/116321127124914201) |

<br>
<br/>
<div id="articles"></div>

# ARTICLES

<div id="teampcp-extension-de-la-campagne-et-monetisation"></div>

## TeamPCP : Extension de la campagne et monétisation
La campagne de la chaîne d'approvisionnement TeamPCP est entrée dans une phase critique de monétisation de ses actifs volés. Databricks enquête actuellement sur une compromission potentielle liée à une récolte de comptes effectuée par le groupe, marquant la première victime d'entreprise d'envergure. TeamPCP gère désormais deux filières de ransomware en parallèle : leur propre opération, CipherForce, et un programme d'affiliation via Vect. Le groupe détient un trésor de 300 Go de comptes volés, incluant des tokens AWS et des configurations CloudFormation. Par ailleurs, LAPSUS$ a publié gratuitement 3 Go de données d'AstraZeneca après avoir échoué à les vendre. La pause dans les nouvelles compromissions de paquets open-source (npm, PyPI) dépasse désormais 96 heures. Les défenseurs sont invités à utiliser cette fenêtre pour réinitialiser les secrets et auditer les pipelines CI/CD. La signature RSA-4096 partagée reste l'indicateur d'attribution le plus fiable entre les différentes opérations du groupe.

**Analyse de l'impact** : L'impact est systémique pour les organisations utilisant des outils de sécurité compromis (Trivy, KICS) ou des bibliothèques cloud (LiteLLM, Telnyx). La fuite de tokens cloud permet une persistance et un pivotement profond dans les infrastructures AWS/GCP/Azure, au-delà de la simple compromission logicielle.

**Recommandations** :
* Rotation immédiate de toutes les clés d'API, tokens CI/CD et identifiants cloud ayant transité par des versions compromises.
* Surveillance des connexions sortantes vers des adresses IP brutes à partir des serveurs de build.
* Blocage des déploiements utilisant des versions non épinglées (unpinned) des paquets LiteLLM (<v1.82.6) et Telnyx.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TeamPCP (aliases: PCPcat, ShellForce, CipherForce) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Supply Chain Compromise: Software Dependencies <br/> * T1552: Unsecured Credentials <br/> * T1486: Data Encrypted for Impact |
| Observables & Indicateurs de compromission | ```* Clef publique RSA-4096 partagée <br/> * Payload caché dans fichiers .WAV <br/> * Distribution via GHOSTYNETWORKS (ASNs)``` |

### Source (url) du ou des articles
* [SANS ISC - TeamPCP Update 004](https://isc.sans.edu/diary/rss/32846)
* [Field Effect - TeamPCP Multi-ecosystem expansion](https://fieldeffect.com/blog/teampcp-supply-chain-intrusions-developers)
<br>
<br>

<div id="roadk1ll-nouvel-implant-de-pivot-via-websocket"></div>

## RoadK1ll : Nouvel implant de pivot via WebSocket
Découvert lors d'un incident de réponse par Blackpoint, RoadK1ll est un implant malveillant basé sur Node.js conçu pour le mouvement latéral discret. Contrairement aux outils classiques, il n'écoute pas de port entrant mais établit une connexion WebSocket sortante vers l'infrastructure de l'attaquant. Ce tunnel permet de relayer le trafic TCP vers des services internes (RDP, bases de données, interfaces d'administration) non exposés sur Internet. L'implant peut gérer plusieurs connexions simultanées sur le même tunnel, maximisant l'efficacité de l'attaquant. Il intègre un mécanisme de reconnexion automatique en cas d'interruption du canal. RoadK1ll ne possède pas de mécanisme de persistance propre (registre ou tâche planifiée), opérant uniquement tant que son processus est actif. Son architecture légère lui permet de se fondre dans le trafic réseau normal, contournant souvent les contrôles de périmètre classiques.

**Analyse de l'impact** : Cet implant transforme une machine compromise en un point de relais (proxy) contrôlable, annulant les bénéfices de la segmentation réseau. Il permet à un attaquant externe de naviguer dans le réseau interne avec le niveau de confiance de la machine infectée.

**Recommandations** :
* Rechercher des processus Node.js inhabituels sans persistance apparente sur les serveurs et postes de travail.
* Monitorer les connexions sortantes persistantes sur le protocole WebSocket vers des adresses IP inconnues.
* Mettre en œuvre une micro-segmentation stricte pour limiter les capacités de rebond TCP même depuis des hôtes de confiance.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1090.003: Proxy: Multi-hop Proxy <br/> * T1572: Protocol Tunneling <br/> * T1021: Remote Services |
| Observables & Indicateurs de compromission | ```* Commandes: CONNECT, DATA, CLOSE <br/> * Protocole: WebSocket custom <br/> * Agent: Node.js runtime``` |

### Source (url) du ou des articles
* [BleepingComputer - New RoadK1ll WebSocket implant](https://www.bleepingcomputer.com/news/security/new-roadk1ll-websocket-implant-used-to-pivot-on-breached-networks/)
<br>
<br>

<div id="exploitation-active-de-citrix-netscaler-cve-2026-3055"></div>

## Exploitation active de Citrix NetScaler (CVE-2026-3055)
Une vulnérabilité critique de lecture mémoire hors limites (CVE-2026-3055) dans Citrix NetScaler ADC et Gateway est activement exploitée. La faille affecte les équipements configurés en tant que fournisseur d'identité SAML (IDP). Des chercheurs ont observé des tentatives de reconnaissance dès le 27 mars, suivies d'exploitations réelles. L'attaque permet d'extraire des identifiants de session administrative directement depuis la mémoire du système. Il s'avère que CVE-2026-3055 regroupe au moins deux bugs distincts impactant les points de terminaison '/saml/login' et '/wsfed/passive'. Environ 29 000 instances NetScaler sont actuellement exposées sur Internet. La simplicité de l'exploitation — l'envoi d'un paramètre vide suffit à déclencher la fuite mémoire — rend cette menace particulièrement urgente. Les technicités de cette faille rappellent les incidents "CitrixBleed" de 2023.

**Analyse de l'impact** : La compromission d'un NetScaler Gateway peut entraîner la prise de contrôle totale de l'infrastructure d'accès distant. Le vol de jetons de session active permet de contourner l'authentification multi-facteurs (MFA) pour les accès administratifs.

**Recommandations** :
* Mettre à jour immédiatement vers les versions corrigées (ex: 14.1-60.58 ou 13.1-62.23).
* Invalider toutes les sessions actives et forcer une reconnexion après l'application du correctif.
* Surveiller les logs HTTP pour des requêtes anormales vers '/saml/login' avec des paramètres malformés ou vides.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié (plusieurs acteurs identifiés via honeypots) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br/> * T1005: Data from Local System |
| Observables & Indicateurs de compromission | ```* Endpoints: /saml/login, /wsfed/passive <br/> * Scripts de détection: Python (via watchTowr) <br/> * IPs sources connues liées à l'exploitation``` |

### Source (url) du ou des articles
* [BleepingComputer - Critical Citrix NetScaler memory flaw](https://www.bleepingcomputer.com/news/security/critical-citrix-netscaler-memory-flaw-actively-exploited-in-attacks/)
* [The Hacker News - Citrix Flaw Under Active Exploitation](https://thehackernews.com/2026/03/weekly-recap-telecom-sleeper-cells-llm.html)
<br>
<br>

<div id="fuite-de-donnees-chatgpt-via-dns-tunneling"></div>

## Fuite de données ChatGPT via DNS Tunneling
Check Point Research a identifié un canal de communication sortant caché dans l'environnement d'exécution de code de ChatGPT. Bien que cet environnement soit isolé et n'ait pas d'accès direct à Internet, les requêtes DNS restent autorisées. Un attaquant peut utiliser le DNS tunneling pour exfiltrer des données sensibles (historique médical, secrets financiers, fichiers téléchargés) encodées dans des sous-domaines. L'attaque commence par un simple prompt malveillant qui instruit le modèle de résumer les messages et de les envoyer vers un serveur contrôlé. Cette méthode permet également d'établir un "reverse shell" bidirectionnel dans le runtime Linux de l'IA. OpenAI a déployé un correctif le 20 février 2026 après avoir identifié le problème. Cette vulnérabilité met en lumière les risques liés aux capacités d'analyse de données et d'exécution de scripts des assistants IA.

**Analyse de l'impact** : L'impact est majeur pour la confidentialité des données d'entreprise partagées avec des assistants IA. Un "GPT" personnalisé malveillant pourrait silencieusement voler des secrets industriels sans qu'aucune alerte de partage de données externe ne soit déclenchée.

**Recommandations** :
* Auditer l'utilisation des GPTs personnalisés au sein de l'organisation et restreindre ceux provenant de sources non vérifiées.
* Surveiller les requêtes DNS volumineuses ou structurées de manière anormale provenant des infrastructures cloud.
* Sensibiliser les utilisateurs au risque de copier-coller des "prompts de productivité" trouvés sur des forums publics.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Preuve de concept (Check Point Research) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1071.004: Application Layer Protocol: DNS <br/> * T1041: Exfiltration Over C2 Channel |
| Observables & Indicateurs de compromission | ```* Requêtes DNS avec données encodées en sous-domaines <br/> * Communication bidirectionnelle via réponses DNS``` |

### Source (url) du ou des articles
* [Check Point Research - ChatGPT Data Leakage](https://research.checkpoint.com/2026/chatgpt-data-leakage-via-a-hidden-outbound-channel-in-the-code-execution-runtime/)
<br>
<br>

<div id="f5-big-ip-vulnerabilite-critique-reclassee-en-rce"></div>

## F5 BIG-IP : Vulnérabilité critique reclassée en RCE
F5 Networks a officiellement reclassé la vulnérabilité CVE-2025-53521 affectant BIG-IP APM (Access Policy Manager). Initialement considérée comme un déni de service (DoS), de nouvelles informations ont confirmé qu'elle permet une exécution de code à distance (RCE) non authentifiée. La faille réside dans le traitement du trafic malveillant par la logique APM lorsqu'elle est liée à un serveur virtuel. CISA a ajouté cette vulnérabilité à son catalogue KEV, signalant une exploitation active dans la nature. Des attaquants utilisent cette faille pour déployer des webshells et obtenir une persistance sur les équipements. Plus de 240 000 instances BIG-IP sont exposées en ligne, bien que toutes ne soient pas vulnérables. F5 recommande une vérification urgente des disques, des journaux et de l'historique des terminaux pour détecter tout signe de compromission.

**Analyse de l'impact** : Une exploitation réussie donne un contrôle total sur l'équipement de gestion des accès. Cela permet aux attaquants de voler des informations d'identification, de modifier les politiques de sécurité et de pivoter vers le réseau interne.

**Recommandations** :
* Appliquer immédiatement les correctifs fournis (ex: v17.5.1.3, v15.1.10.8).
* Isoler les serveurs virtuels activés par l'APM des réseaux non approuvés si la mise à jour n'est pas possible immédiatement.
* Chasser les IoC : modification inattendue de fichiers, hashes de fichiers inhabituels, trafic HTTPS sortant avec type de contenu CSS et réponses HTTP 201.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié (acteurs étatiques et cybercriminels suspectés) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br/> * T1505.003: Server Software Component: Web Shell |
| Observables & Indicateurs de compromission | ```* Trafic HTTPS sortant anormal <br/> * Fichiers webshells sur le disque BIG-IP``` |

### Source (url) du ou des articles
* [BleepingComputer - Hackers exploit F5 BIG-IP flaw](https://www.bleepingcomputer.com/news/security/hackers-now-exploit-critical-f5-big-ip-flaw-in-attacks-patch-now/)
* [Field Effect - CISA adds F5 vulnerability to KEV](https://fieldeffect.com/blog/updated-f5-big-ip-apm-vulnerability-kev)
<br>
<br>

<div id="ta446-utilisation-du-kit-dexploitation-darksword-contre-ios"></div>

## TA446 : Utilisation du kit d'exploitation DarkSword contre iOS
Le groupe APT TA446 (lié à la Russie, également connu sous le nom de ColdRiver ou Star Blizzard) a été observé utilisant le kit d'exploitation DarkSword dans des campagnes de spear-phishing. Cette vague d'attaques cible spécifiquement les utilisateurs d'iPhone, marquant une évolution dans les cibles habituelles du groupe. Les courriels malveillants usurpent l'identité de l'Atlantic Council pour inciter les victimes à cliquer sur des liens. Un filtrage côté serveur redirige uniquement les utilisateurs d'iOS vers le kit d'exploitation, tandis que les autres voient un PDF bénin. Le kit comprend des composants de redirection, un chargeur (loader) et des capacités d'exécution de code à distance (RCE) nommées GHOSTBLADE. Bien qu'aucune évasion de sandbox n'ait été confirmée, l'adoption de ce kit montre une volonté d'expansion de la collecte de renseignements vers les terminaux mobiles.

**Analyse de l'impact** : Le ciblage réussi des appareils mobiles permet d'accéder aux comptes iCloud, aux communications chiffrées et aux données de localisation des individus ciblés (gouvernements, think tanks, entités financières).

**Recommandations** :
* Maintenir les appareils iOS à jour avec les dernières versions de sécurité (iOS 17+).
* Sensibiliser les utilisateurs VIP aux risques de phishing sophistiqué via des invitations à des conférences ou des documents de réflexion.
* Utiliser des solutions de Mobile Threat Defense (MTD) pour détecter les redirections vers des infrastructures malveillantes connues.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TA446 (ColdRiver / Star Blizzard) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.002: Phishing: Spearphishing Link <br/> * T1203: Exploitation for Client Execution |
| Observables & Indicateurs de compromission | ```* Domaines: escofiringbijou[.]com, motorbeylimited[.]com <br/> * Hash Loader (MD5): 5fa967dbef026679212f1a6ffa68d575``` |

### Source (url) du ou des articles
* [Security Affairs - TA446 uses DarkSword exploit](https://securityaffairs.com/190139/apt/russia-linked-apt-ta446-uses-darksword-exploit-to-target-iphone-users-in-phishing-wave.html)
<br>
<br>