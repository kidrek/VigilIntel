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
  * [Note d’alerte – Ciblage des messageries instantanées et attribution russe](#note-alerte-ciblage-des-messageries-instantanees-et-attribution-russe)
  * [Exploitation immédiate de la faille RCE critique dans Langflow](#exploitation-immediate-de-la-faille-rce-critique-dans-langflow)
  * [Campagne de wipers iraniens et compromission de Microsoft Intune chez Stryker](#campagne-de-wipers-iraniens-et-compromission-de-microsoft-intune-chez-stryker)
  * [Démantèlement international des botnets IoT Aisuru et Kimwolf](#demantelement-international-des-botnets-iot-aisuru-et-kimwolf)
  * [Analyse de l'attaque par conteneur de TeamPCP](#analyse-de-lattaque-par-conteneur-de-teampcp)
  * [L'émergence des kits d'exploitation iOS Coruna et DarkSword](#lemergence-des-kits-dexploitation-ios-coruna-et-darksword)
  * [Risques de fraude e-commerce via les agents IA autonomes](#risques-de-fraude-e-commerce-via-les-agents-ia-autonomes)
  * [L'exploitation Zero-Day par le gang Interlock sur Cisco FMC](#lexploitation-zero-day-par-le-gang-interlock-sur-cisco-fmc)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage cyber de mars 2026 est marqué par une intensification sans précédent des opérations liées au conflit israélo-iranien, où le groupe Handala (Void Manticore) redéfinit la menace en détournant des outils de gestion légitimes comme Microsoft Intune pour mener des campagnes de destruction massives. Parallèlement, l'attribution formelle par le FBI de campagnes de phishing contre Signal et WhatsApp aux services de renseignement russes souligne une volonté étatique de contourner le chiffrement de bout en bout par le piratage de comptes. On observe une réduction critique du temps d'exploitation (TTE), illustrée par la vulnérabilité Langflow armée en moins de 20 heures, mettant au défi les capacités de réaction des SOC. Le domaine de l'intelligence artificielle devient un nouveau front, tant par l'exploitation de ses failles de développement (RCE) que par son utilisation pour industrialiser la fraude e-commerce via des agents autonomes. La réussite des opérations policières internationales contre les botnets DDoS record (Aisuru) apporte un répit, bien que la volatilité des infrastructures cloud et la persistence des accès initiaux via infostealers maintiennent un niveau de risque élevé. Les décideurs doivent impérativement renforcer le contrôle des accès privilégiés et la segmentation des outils d'administration centralisée pour limiter le "rayon d'explosion" des attaques destructrices.

<br>
<br>
<div id="syntheses"></div>

# Synthèses
<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants
Voici un tableau récapitulatif des acteurs malveillants identifiés :
| Nom de l'acteur | Secteur d'activité ciblé | Mode opératoire privilégié | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Beast Gang | Multi-sectoriel | Ransomware-as-a-Service, serveurs C2 ouverts | [DataBreaches.net](https://databreaches.net/2026/03/20/cyber-opsec-fail-beast-gang-exposes-ransomware-server/) |
| GreenGolf (MuddyWater) | Diplomatie, Énergie, Finance | Malware en Rust (LampoRAT), backdoors UDP | [Recorded Future](https://www.recordedfuture.com/blog/the-iran-war-what-you-need-to-know) |
| Handala Hack (Void Manticore) | Santé, Infrastructure critique, Secteur public | Abus de Microsoft Intune (Remote Wipe), Wipers, Phishing | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Interlock Ransomware | Santé, Éducation, Gouvernement | Exploitation Zero-day (Cisco FMC), NodeSnake RAT, Slopoly | [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-max-severity-cisco-flaw-by-sunday/) |
| Renseignement Russe (SVR/FSB) | Politique, Militaire, Journalisme | Phishing de messageries sécurisées, Device Linking | [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-links-signal-phishing-attacks-to-russian-intelligence-services/) |
| TeamPCP | Cloud-native, Kubernetes | Cryptojacking, Ransomware cloud, pipe-to-shell | [Elastic Security Labs](https://www.elastic.co/security-labs/teampcp-container-attack-scenario) |
| UNC6353 | Gouvernement ukrainien, Finance | Exploit kits iOS (DarkSword), point d'eau (watering hole) | [Security Affairs](https://securityaffairs.com/189716/security/apple-urges-iphone-users-to-update-as-coruna-and-darksword-exploit-kits-emerge.html) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Énergie | Libye / Espionage | Campagne d'espionnage AsyncRAT ciblant les raffineries libyennes sur fond d'instabilité régionale. | [Security.com](https://www.security.com/threat-intelligence/asyncrat-libya-oil-cyberattack) |
| Global | Désinformation (FIMI) | Publication du rapport EEAS sur la "FIMI Galaxy" exposant les infrastructures de manipulation russe et chinoise. | [EUvsDisinfo](https://euvsdisinfo.eu/whats-new-in-the-fimi-galaxy/) |
| Militaire | Conflit Iran-Israël-USA | Intensification des frappes cinétiques et cyber suite à l'assassinat de dirigeants iraniens. | [Recorded Future](https://www.recordedfuture.com/blog/the-iran-war-what-you-need-to-know) |
| Militaire | France / OPSEC | Localisation du porte-avions Charles de Gaulle exposée par l'activité Strava d'un marin. | [Le Monde](https://www.lemonde.fr/pixels/article/2026/03/20/cyberattaques-une-operation-policiere-internationale-porte-un-coup-a-d-importants-reseaux-de-botnets_6672727_4408996.html) |
| Sécurité Européenne | Soutien Ukraine | Analyse stratégique du RUSI appelant à une mission militaire humanitaire européenne en Ukraine. | [RUSI](https://www.rusi.org/explore-our-research/publications/commentary/europes-power-defined-ability-take-action-ukraine) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| All aboard: the NIST Cybersecurity for IoT Program | Michael Fagan | 20 mars 2026 | USA | NISTIR 8259 / SP 800-213 | Mise à jour des directives de cybersécurité pour les fabricants et utilisateurs d'objets connectés. | [NIST](https://www.nist.gov/blogs/cybersecurity-insights/all-aboard-nist-cybersecurity-iot-program-headed-our-next-stop-share) |
| EU sanctions Chinese and Iranian actors | Conseil de l'UE | 20 mars 2026 | Union Européenne | Régime de sanctions cyber | Sanctions contre Integrity Technology Group et Emennet Pasargad pour cyberattaques majeures. | [Security Affairs](https://securityaffairs.com/189734/hacking/7500-magento-sites-defaced-in-global-hacking-campaign.html) |
| Joint advisory on Endpoint Management | CISA / FBI | 19 mars 2026 | USA | BOD 22-01 | Recommandations de durcissement impératif pour Microsoft Intune et systèmes MDM. | [CISA](https://www.cisa.gov/news-events/ics-advisories/icsa-26-078-08) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Industrie Médicale | Stryker Corporation | 80 000 appareils effacés, 50 To de données exfiltrées via compromis Intune. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Santé | Navia Benefit Solutions | Fuite de données personnelles (SSN, noms) affectant 2,7 millions d'individus. | [Security Affairs](https://securityaffairs.com/189726/data-breach/navia-data-breach-impacts-nearly-2-7-million-people.html) |
| Santé | Weill Cornell Medicine | Accès non autorisé interne aux dossiers médicaux électroniques de 516 patients. | [DataBreaches.net](https://databreaches.net/2026/03/20/weill-cornell-medicine-discloses-an-insider-data-breach/) |
| Technologie / Pharma | AstraZeneca (non vérifié) | Revendication par LAPSUS$ du vol de 3 Go de code source et configurations cloud. | [Mastodon (@Hackread)](https://mstdn.social/@Hackread/116263714781132663) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).
| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|
| CVE-2026-20131 | 10.0 | Cisco Secure FMC | Désérialisation non sécurisée / RCE Root | [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-max-severity-cisco-flaw-by-sunday/) |
| CVE-2026-21992 | 9.8 | Oracle Identity Manager | RCE unauthenticated | [Oracle](https://www.oracle.com/security-alerts/cpumar2026.html) |
| CVE-2026-33017 | 9.3 | Langflow | Code Injection / RCE | [The Hacker News](https://thehackernews.com/2026/03/critical-langflow-flaw-cve-2026-33017.html) |
| CVE-2026-24060 | 9.1 | Automated Logic WebCTRL | Transmission en clair d'infos sensibles | [VulnCheck](https://cvefeed.io/vuln/detail/CVE-2026-24060) |
| CVE-2026-32051 | 8.8 | OpenClaw | Bypass d'autorisation (Privilege Escalation) | [VulnCheck](https://cvefeed.io/vuln/detail/CVE-2026-32051) |
| CVE-2026-32746 | N/A | GNU Inetutils (telnetd) | Buffer Overflow (32 ans d'existence) | [Security.nl](https://www.security.nl/posting/929334/32+jaar+oud+Telnet-lek+kan+aanvaller+volledige+controle+over+servers+geven) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| FBI links Signal phishing attacks to Russian intelligence | Attribution étatique critique et nouvelle technique de contournement de chiffrement. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-links-signal-phishing-attacks-to-russian-intelligence-services/) |
| Critical Langflow Flaw CVE-2026-33017 Triggers Attacks | Illustration de la réduction drastique du délai d'exploitation (20h) et risque IA. | [The Hacker News](https://thehackernews.com/2026/03/critical-langflow-flaw-cve-2026-33017.html) |
| Monitoring Cyberattacks Directly Linked to US-Israel-Iran | Synthèse exhaustive d'un conflit cyber majeur et de l'abus de Microsoft Intune. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| International joint action disrupts world’s largest botnets | Succès opérationnel majeur contre les infrastructures DDoS mondiales. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/aisuru-kimwolf-jackskid-and-mossad-botnets-disrupted-in-joint-action/) |
| TeamPCP Container Attack Scenario | Analyse technique profonde d'une chaîne d'attaque cloud-native moderne. | [Elastic Security Labs](https://www.elastic.co/security-labs/teampcp-container-attack-scenario) |
| Apple urges iPhone users to update (Coruna/DarkSword) | Prolifération des kits zero-day iOS sur le marché secondaire. | [Security Affairs](https://securityaffairs.com/189716/security/apple-urges-iphone-users-to-update-as-coruna-and-darksword-exploit-kits-emerge.html) |
| Retail Fraud in the Age of Agentic AI | Menace émergente et stratégique liée à l'autonomie des agents IA. | [Unit 42](https://unit42.paloaltonetworks.com/retail-fraud-agentic-ai/) |
| Interlock Ransomware Exploits Cisco FMC Zero-Day | Danger des vulnérabilités zero-day sur les équipements de sécurité périmétrique. | [SentinelOne](https://www.sentinelone.com/blog/the-good-the-bad-and-the-ugly-in-cybersecurity-week-12-7/) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| 7,500+ Magento sites defaced | Attaque opportuniste de faible technicité (défaçage txt). | [Security Affairs](https://securityaffairs.com/189734/hacking/7500-magento-sites-defaced-in-global-hacking-campaign.html) |
| Musician admits to $10M streaming royalty fraud | Fraude financière via bots, peu de pertinence pour la menace cyber infra/data. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/musician-pleads-guilty-to-10m-streaming-fraud-powered-by-ai-bots/) |
| 10 Can’t-Miss RSAC 2026 Sessions | Contenu promotionnel / événementiel. | [Flare](https://flare.io/learn/resources/blog/rsac-2026-sessions) |
| Charles de Gaulle tracked via Strava | Erreur humaine OPSEC déjà documentée par le passé, pas de nouvelle menace technique. | [Le Monde](https://www.lemonde.fr/pixels/article/2026/03/20/cyberattaques-une-operation-policiere-internationale-porte-un-coup-a-d-importants-reseaux-de-botnets_6672727_4408996.html) |

<br>
<br/>
<div id="articles"></div>

# ARTICLES
<div id="note-alerte-ciblage-des-messageries-instantanees-et-attribution-russe"></div>

## Note d’alerte – Ciblage des messageries instantanées et attribution russe
Le FBI et le CERT-FR ont émis des alertes conjointes concernant une campagne massive de piratage de comptes Signal et WhatsApp. L'attribution est désormais formellement liée aux services de renseignement russes, ciblant des personnalités politiques, militaires et journalistes de haut vol. L'attaque ne brise pas le chiffrement mais détourne le processus d'association de nouveaux appareils (device linking) via des messages de phishing sophistiqués imitant le support technique. Les victimes sont incitées à scanner des QR codes malveillants ou à partager des codes de vérification, permettant aux attaquants de surveiller les échanges en temps réel et de diffuser des messages d'usurpation d'identité. Cette technique permet d'accéder aux listes de contacts et aux historiques de conversation de manière silencieuse.

**Analyse de l'impact** : Impact critique sur la confidentialité des communications étatiques et diplomatiques. Le détournement de comptes de confiance permet des campagnes de phishing "latéral" extrêmement efficaces au sein des écosystèmes gouvernementaux.

**Recommandations** :
* Interdire l'utilisation de comptes personnels pour des échanges professionnels sensibles.
* Sensibiliser les utilisateurs VIP à ne jamais scanner de QR code envoyé par messagerie instantanée, même sous prétexte de "support".
* Désactiver la prévisualisation des liens dans les paramètres de Signal/WhatsApp.
* Vérifier régulièrement la liste des "Appareils liés" dans les paramètres de l'application et supprimer tout appareil suspect.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Renseignement Russe (SVR/FSB) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.002: Spearphishing Link <br/> * T1098.003: Account Manipulation: Add Device <br/> * T1553.007: QR Codes |
| Observables & Indicateurs de compromission | * Messages provenant de faux comptes "Support Signal" ou "Support WhatsApp" <br/> * Demandes inhabituelles de scan de QR code pour "mise à jour de sécurité" |

### Source (url) du ou des articles
* https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-003/
* https://www.bleepingcomputer.com/news/security/fbi-links-signal-phishing-attacks-to-russian-intelligence-services/

<br>
<br>
<div id="exploitation-immediate-de-la-faille-rce-critique-dans-langflow"></div>

## Exploitation immédiate de la faille RCE critique dans Langflow
Une vulnérabilité critique, CVE-2026-33017 (score CVSS 9.3), a été découverte dans la plateforme d'orchestration d'IA open-source Langflow. Elle permet une exécution de code à distance (RCE) non authentifiée via l'endpoint `/api/v1/build_public_tmp/`. Un attaquant peut envoyer une requête POST HTTP contenant du code Python malveillant qui est exécuté par le serveur sans aucun sandboxing. Des tentatives d'exploitation ont été observées seulement 20 heures après la publication de l'avis de sécurité. Les attaquants utilisent cette faille pour exfiltrer des variables d'environnement, des fichiers sensibles comme `/etc/passwd` et des clés d'accès aux bases de données connectées.

**Analyse de l'impact** : Risque majeur pour la chaîne d'approvisionnement logicielle basée sur l'IA. L'accès au serveur Langflow permet souvent de compromettre l'ensemble des données et modèles d'IA de l'entreprise.

**Recommandations** :
* Mettre à jour immédiatement vers la version 1.9.0 ou ultérieure.
* Isoler les instances Langflow derrière un VPN ou un proxy inverse avec authentification forte.
* Auditer et révoquer toutes les clés API et mots de passe de base de données stockés dans les instances Langflow exposées.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Inconnu (activités de scan automatisé) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br/> * T1059.006: Command and Scripting Interpreter: Python |
| Observables & Indicateurs de compromission | * Appels POST vers `/api/v1/build_public_tmp/{flow_id}/flow` <br/> * IP source suspecte: `173.212.205.251` |

### Source (url) du ou des articles
* https://thehackernews.com/2026/03/critical-langflow-flaw-cve-2026-33017.html

<br>
<br>
<div id="campagne-de-wipers-iraniens-et-compromission-de-microsoft-intune-chez-stryker"></div>

## Campagne de wipers iraniens et compromission de Microsoft Intune chez Stryker
Le conflit cyber entre l'Iran, Israël et les USA a atteint un nouveau palier avec l'attaque contre Stryker, un géant des technologies médicales. Le groupe Handala a réussi à compromettre un compte administrateur Microsoft Intune, utilisant les fonctionnalités de gestion centralisée pour déclencher un "Remote Wipe" (effacement à distance) sur 80 000 appareils. Contrairement aux attaques classiques, aucun malware wiper complexe n'a été utilisé : les attaquants ont simplement détourné les fonctions de gestion légitimes du MDM. L'impact a entraîné des reports de chirurgies et une exfiltration massive de 50 To de données. Le DOJ américain a riposté en saisissant quatre domaines utilisés par l'acteur pour ses opérations psychologiques.

**Analyse de l'impact** : Rupture catastrophique de la chaîne de soins et démonstration d'une efficacité redoutable de l'abus de MDM pour la destruction systémique d'une infrastructure mondiale.

**Recommandations** :
* Implémenter le "Multi-Admin Approval" pour toutes les actions critiques dans Intune (wipe, déploiement de scripts).
* Utiliser exclusivement des accès MFA résistants au phishing (FIDO2) pour les comptes Global Admin.
* Séparer strictement les comptes d'administration MDM des comptes de messagerie standard.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Handala Hack (Void Manticore) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566: Phishing <br/> * T1531: Account Access Removal (via MDM Wipe) <br/> * T1078: Valid Accounts |
| Observables & Indicateurs de compromission | * Domaines saisis: `handala-hack.to`, `justicehomeland.org` <br/> * E-mail: `Handala_Team@outlook.com` |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict
* https://www.bleepingcomputer.com/news/security/how-cisos-can-survive-the-era-of-geopolitical-cyberattacks/

<br>
<br>
<div id="demantelement-international-des-botnets-iot-aisuru-kimwolf-jackskid-botnet-operators"></div>

## Démantèlement international des botnets IoT Aisuru et Kimwolf
Une opération policière conjointe (USA, Allemagne, Canada) a démantelé les infrastructures de commande et contrôle (C2) de quatre botnets majeurs : Aisuru, KimWolf, JackSkid et Mossad. Ces réseaux comptaient plus de 3 millions d'appareils infectés (caméras IP, routeurs, boîtiers TV Android). Ils étaient loués via un modèle de "DDoS-as-a-Service", ayant généré des attaques record de plus de 30 Tbps fin 2025. Kimwolf se distinguait par sa capacité à infecter des appareils derrière des pare-feu via un mécanisme de propagation latérale innovant. Deux administrateurs ont été identifiés et des cryptoactifs saisis.

**Analyse de l'impact** : Réduction temporaire mais significative de la capacité mondiale à lancer des attaques DDoS de grande envergure.

**Recommandations** :
* Changer les mots de passe par défaut sur tous les équipements IoT.
* Désactiver les services de gestion à distance (Telnet, HTTP) non nécessaires sur l'Internet public.
* Mettre en œuvre une solution de protection anti-DDoS robuste pour les services Web critiques.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Opérateurs d'Aisuru et Kimwolf (Individus au Canada et Allemagne) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1498: Network Denial of Service <br/> * T1584: Compromise Infrastructure |
| Observables & Indicateurs de compromission | Aucun IoC spécifique n'est fourni |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/aisuru-kimwolf-jackskid-and-mossad-botnets-disrupted-in-joint-action/
* https://krebsonsecurity.com/2026/03/feds-disrupt-iot-botnets-behind-huge-ddos-attacks/

<br>
<br>
<div id="analyse-de-lattaque-par-conteneur-de-teampcp"></div>

## Analyse de l'attaque par conteneur de TeamPCP
Une analyse détaillée du mode opératoire de TeamPCP révèle une chaîne d'attaque sophistiquée ciblant les environnements Kubernetes. L'accès initial se fait souvent via l'exploitation de serveurs Web (React2Shell). L'acteur utilise ensuite des pipelines pipe-to-shell (`curl | bash`) pour éviter l'écriture de fichiers sur disque. Une fois dans le conteneur, TeamPCP cherche à s'échapper vers le nœud hôte en abusant de rôles ClusterRole surprivilégiés et en créant des DaemonSets malveillants avec des montages `hostPath`. L'objectif final est le cryptojacking et potentiellement le déploiement de ransomware cloud-native.

**Analyse de l'impact** : Risque élevé d'escalade de privilèges du conteneur vers l'infrastructure de contrôle Kubernetes complète.

**Recommandations** :
* Appliquer le principe du moindre privilège aux ServiceAccounts Kubernetes.
* Utiliser des Admission Controllers pour interdire les conteneurs privilégiés et les montages `hostPath`.
* Surveiller les exécutions interactives (`exec`) et les processus `curl`/`wget` inhabituels au sein des pods.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TeamPCP |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1611: Escape to Host <br/> * T1613: Container and Resource Discovery <br/> * T1496: Resource Hijacking |
| Observables & Indicateurs de compromission | * IPs: `67.217.57.240`, `44.252.85.168` <br/> * Fichiers: `/tmp/k8s.py`, `/tmp/miner` |

### Source (url) du ou des articles
* https://www.elastic.co/security-labs/teampcp-container-attack-scenario

<br>
<br>
<div id="lemergence-des-kits-dexploitation-ios-coruna-and-darksword"></div>

## L'émergence des kits d'exploitation iOS Coruna et DarkSword
Apple a urgé ses utilisateurs à mettre à jour leurs appareils suite à la découverte de deux kits d'exploitation iOS massifs : Coruna et DarkSword. Coruna contient 23 exploits ciblant les versions 13.0 à 17.2.1, tandis que DarkSword s'attaque aux versions 18.4 à 18.7 via des vulnérabilités zero-day dans WebKit et le noyau iOS. Ces outils sont utilisés pour livrer des malwares comme GHOSTBLADE, spécialisé dans le vol de mots de passe, messages et portefeuilles crypto. Les attaquants utilisent des "watering holes" (ex: faux sites Snapchat) pour infecter les téléphones en quelques secondes sans interaction humaine majeure.

**Analyse de l'impact** : Menace critique pour la confidentialité des données personnelles et professionnelles stockées sur iPhone. Le "hit-and-run" rapide rend la détection après exfiltration difficile.

**Recommandations** :
* Mettre à jour vers iOS 26.3.1 immédiatement.
* Activer le "Lockdown Mode" pour les utilisateurs à haut risque (VIP, journalistes, admins).
* Redémarrer régulièrement les appareils pour perturber les implants non-persistants.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UNC6353 (suspecté lié à la Russie), NC6748 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1203: Exploitation for Client Execution <br/> * T1406: Obfuscated Files or Information |
| Observables & Indicateurs de compromission | * Domaine: `snapshare.chat` <br/> * Scripts: `rce_loader.js`, `pe_main.js` |

### Source (url) du ou des articles
* https://securityaffairs.com/189716/security/apple-urges-iphone-users-to-update-as-coruna-and-darksword-exploit-kits-emerge.html
* https://www.sentinelone.com/blog/the-good-the-bad-and-the-ugly-in-cybersecurity-week-12-7/

<br>
<br>
<div id="risques-de-fraude-e-commerce-via-les-agents-ia-autonomes"></div>

## Risques de fraude e-commerce via les agents IA autonomes
L'essor des agents IA autonomes utilisant des protocoles comme l'UCP (Universal Commerce Protocol) introduit de nouveaux vecteurs de fraude. Les attaquants peuvent utiliser l'injection de prompt indirecte pour détourner le comportement d'un agent de shopping. Par exemple, un agent parcourant un site malveillant pour chercher des coupons pourrait être "reprogrammé" via des métadonnées cachées pour ajouter des cartes-cadeaux au panier de la victime ou valider des remboursements indus sans retour de marchandise réelle. Cette "mort invisible de la fidélité client" permettrait à des fermes de bots de liquider les réserves de trésorerie d'un commerçant en automatisant des milliers de retours frauduleux en une heure.

**Analyse de l'impact** : Risque stratégique pour le secteur du retail, pouvant mener à des pertes financières massives et une érosion totale de la confiance dans les transactions automatisées par IA.

**Recommandations** :
* Implémenter des frameworks de type "Know Your Agent" (KYA) pour valider l'identité et la réputation des bots.
* Renforcer la validation côté serveur de chaque étape de la transaction, indépendamment des commandes de l'agent.
* Utiliser des techniques de détection d'injection de prompt pour scanner le contenu tiers avant traitement par l'IA.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable (menace émergente) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566: Phishing (Indirect Prompt Injection) <br/> * T1059: Command and Scripting Interpreter |
| Observables & Indicateurs de compromission | Aucun IoC spécifique n'est fourni |

### Source (url) du ou des articles
* https://unit42.paloaltonetworks.com/retail-fraud-agentic-ai/

<br>
<br>
<div id="lexploitation-zero-day-par-le-gang-interlock-sur-cisco-fmc"></div>

## L'exploitation Zero-Day par le gang Interlock sur Cisco FMC
Le gang de ransomware Interlock a exploité une vulnérabilité critique (CVE-2026-20131) dans Cisco Secure Firewall Management Center (FMC) 36 jours avant sa divulgation publique. Cette faille de désérialisation Java permet d'obtenir des privilèges root à distance sans authentification. Les attaquants ont utilisé cet accès pour déployer des outils d'énumération réseau, des implants Java persistants et des serveurs de relais anonymisant leurs activités. CISA a ordonné le patchage d'urgence de tous les systèmes fédéraux avant le 22 mars, soulignant la criticité de cet équipement de sécurité centralisé qui, une fois compromis, permet un accès total au réseau interne.

**Analyse de l'impact** : Compromission totale de la sécurité périmétrique. La position centrale de Cisco FMC permet aux attaquants de désactiver les pare-feu ou de modifier les politiques de sécurité à leur guise.

**Recommandations** :
* Appliquer immédiatement les correctifs Cisco ou restreindre l'accès à l'interface de gestion au seul réseau local de confiance.
* Rechercher des traces de requêtes HTTP PUT suspectes dans les logs de l'interface d'administration FMC.
* Auditer la création de nouveaux comptes administrateurs sur les dispositifs de sécurité.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Interlock Ransomware |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br/> * T1068: Exploitation for Privilege Escalation |
| Observables & Indicateurs de compromission | * Requêtes HTTP vers `/control/br/login` avec payloads Java sérialisés <br/> * Utilisation illégitime de ConnectWise ScreenConnect |

### Source (url) du ou des articles
* https://www.helpnetsecurity.com/2026/03/20/cisco-fmc-interlock-ransomware-cve-2026-20131/
* https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-max-severity-cisco-flaw-by-sunday/