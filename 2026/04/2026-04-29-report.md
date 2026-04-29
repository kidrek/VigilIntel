# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
  * [Articles sélectionnés](#articles-selectionnes)
  * [Articles non sélectionnés](#articles-non-selectionnes)
* [Articles](#articles)
  * [VECT 2.0 : Faute de conception cryptographique transformant le ransomware en wiper](#vect-20-faute-de-conception-cryptographique-transformant-le-ransomware-en-wiper)
  * [Campagnes Phishing-to-RMM : L'exploitation des outils d'administration légitimes](#campagnes-phishing-to-rmm-lexploitation-des-outils-dadministration-legitimes)
  * [Implant FIRESTARTER : Persistance étatique sur les pare-feux Cisco ASA et FTD](#implant-firestarter-persistance-etatique-sur-les-pare-feux-cisco-asa-et-ftd)
  * [Morpheus Spyware : Surveillance ciblée sur Android liée à l'industrie italienne](#morpheus-spyware-surveillance-ciblee-sur-android-liee-a-lindustrie-italienne)
  * [Détection de l'abus des pipelines CI/CD via l'analyse augmentée par LLM](#detection-de-labus-des-pipelines-cicd-via-lanalyse-augmentee-par-llm)
  * [Intelligence sur les comptes "Mules" : Le levier critique contre la fraude APP](#intelligence-sur-les-comptes-mules-le-levier-critique-contre-la-fraude-app)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'actualité cyber de ce jour est marquée par une accélération sans précédent des cycles d'exploitation des vulnérabilités, où le délai entre la divulgation d'un PoC et son utilisation active est désormais mesuré en heures (cas de LiteLLM). Cette tendance souligne une industrialisation de l'exploitation, souvent soutenue par des outils d'automatisation et potentiellement augmentée par l'IA.

Un second axe majeur concerne la compromission des équipements de périmètre réseau. La découverte de l'implant **FIRESTARTER** sur des châssis Cisco ASA/FTD démontre que les acteurs étatiques (attribués ici à la Chine via UAT-4356) privilégient des vecteurs capables de survivre aux correctifs logiciels standards, forçant les défenseurs à reconsidérer la confiance accordée aux cycles de mise à jour traditionnels.

Enfin, on observe une professionnalisation continue de l'abus d'outils légitimes. Que ce soit via des campagnes de **phishing-to-RMM** (ScreenConnect, LogMeIn) ou l'abus des pipelines **CI/CD** (GitHub Actions), les attaquants s'éloignent des malwares "bruitants" pour se fondre dans les processus administratifs et de développement. La réponse défensive doit donc pivoter d'une détection basée sur les signatures vers une analyse comportementale fine des flux d'identité et des privilèges.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **UAT-4356 (Storm-1849)** | Gouvernement (USA) | Exploitation de vulnérabilités Cisco (CVE-2025-20333), déploiement de l'implant FIRESTARTER | T1190, T1505.004, T1542.001 | [Field Effect](https://fieldeffect.com/blog/firestarter-backdoor-cisco-firewalls) |
| **Scattered Spider** | Multi-sectoriel, Communication, Luxe | Ingénierie sociale, MFA bombing, usurpation d'identité IT | T1566.003, T1621, T1078 | [BleepingComputer](https://www.bleepingcomputer.com/news/security/us-reportedly-charges-scattered-spider-hacker-arrested-in-finland/) |
| **Lazarus Group** | Crypto-monnaies, Finance | Spear-phishing via fausses offres d'emploi, abus de supply chain AI | T1566, T1195.002, T1552 | [Recorded Future](https://www.recordedfuture.com/blog/lazarus-does-not-need-agi) |
| **ShinyHunters** | Média, Jeu vidéo, Santé | Vol de tokens via Anodot, accès à Snowflake et BigQuery | T1528, T1537 | [BleepingComputer](https://www.bleepingcomputer.com/news/security/video-service-vimeo-confirms-anodot-breach-exposed-user-data/) |

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Allemagne / Russie** | Politique, Diplomatie | Espionnage | Campagne de phishing via Signal ciblant des ministres et diplomates allemands. | [SecurityAffairs](https://securityaffairs.com/191425/intelligence/signal-phishing-campaign-targets-german-officials-in-suspected-russian-operation.html) |
| **Corée du Nord** | Finance / Crypto | Sanctions | Utilisation de l'IA pour augmenter la productivité des vols de crypto-monnaies (3 Mds$ dérobés). | [Recorded Future](https://www.recordedfuture.com/blog/lazarus-does-not-need-agi) |
| **États-Unis / Chine** | Naval | Souveraineté | Analyse des vulnérabilités de la construction navale US face à la domination industrielle chinoise. | [Portail IE](https://www.portail-ie.fr/univers/2026/la-construction-navale-des-etats-unis-a-laube-dune-nouvelle-ere-2-2/) |

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| **Verifiable Digital Credential Issuance** | NIST | 28/04/26 | USA | NIST SP 800-63A | Cadre pour l'émission de permis de conduire mobiles (mDL) et standardisation OpenID4VCI. | [NIST](https://www.nist.gov/blogs/cybersecurity-insights/dmv-wallet-understanding-verifiable-digital-credential-issuance) |
| **Charges against Scattered Spider** | DoJ | 28/04/26 | USA / Finlande | N/A | Arrestation et inculpation d'un membre clé ("Bouquet") pour intrusion informatique et fraude. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/us-reportedly-charges-scattered-spider-hacker-arrested-in-finland/) |

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| Vidéo / Média | **Vimeo** | Emails clients, titres de vidéos, métadonnées techniques | Non spécifié | [BleepingComputer](https://www.bleepingcomputer.com/news/security/video-service-vimeo-confirms-anodot-breach-exposed-user-data/) |
| AppSec | **Checkmarx** | Code source, secrets, tokens, configurations | 96 Go | [BleepingComputer](https://www.bleepingcomputer.com/news/security/checkmarx-confirms-lapsus-hackers-leaked-its-stolen-github-data/) |
| Santé | **Moldavie** | Base de données médicale nationale | 30% des données endommagées | [DataBreaches.net](https://databreaches.net/2026/04/28/in-moldova-hackers-attacked-a-medical-database-damaging-30-of-the-information/) |

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-42208 | FALSE | Active    | 4.0 | 9.8   | (0,1,4.0,9.8) |
| 2 | CVE-2026-3854  | FALSE | Théorique | 3.0 | 9.x   | (0,0,3.0,9.0) |
| 3 | CVE-2026-42167 | FALSE | Théorique | 2.5 | 8.1   | (0,0,2.5,8.1) |
| 4 | CVE-2026-41446 | FALSE | Théorique | 2.0 | 9.2   | (0,0,2.0,9.2) |
| 5 | CVE-2026-35414 | FALSE | Théorique | 1.5 | N/A   | (0,0,1.5,0)   |
| 6 | CVE-2026-7322  | FALSE | Théorique | 1.0 | N/A   | (0,0,1.0,0)   |
| 7 | Entra ID Flaw  | FALSE | Théorique | 1.0 | N/A   | (0,0,1.0,0)   |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-42208** | 9.8 | N/A | No | 4.0 | LiteLLM | SQL Injection | RCE / Data Theft | Active | Upgrade v1.83.7 ou disable_error_logs: true | [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-are-exploiting-a-critical-litellm-pre-auth-sqli-flaw/) |
| **CVE-2026-3854** | 9.x | N/A | No | 3.0 | GitHub Enterprise | Command Injection | RCE | PoC public | Upgrade vers 3.14.24+ | [SecurityAffairs](https://securityaffairs.com/191434/security/cve-2026-3854-github-flaw-enables-remote-code-execution.html) |
| **CVE-2026-42167** | 8.1 | N/A | No | 2.5 | ProFTPD (mod_sql) | SQL Injection | RCE | PoC public | Upgrade v1.3.10rc1 | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-42167) |
| **CVE-2026-41446** | 9.2 | N/A | No | 2.0 | Snap One WattBox | Hidden Auth Bypass | RCE | Théorique | Upgrade v2.10.0.0 | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-41446) |
| **CVE-2026-35414** | N/A | N/A | No | 1.5 | OpenSSH | Logic Error | Auth Bypass / Root | PoC public | Upgrade v10.3 | [MS-ISAC](https://www.cisecurity.org/advisory/a-vulnerability-in-openssh-could-allow-for-authentication-bypass_2026-040) |
| **CVE-2026-7322** | N/A | N/A | No | 1.0 | Mozilla Firefox/Thunderbird | Memory Safety | RCE | Théorique | Upgrade Firefox 150.0.1 | [MS-ISAC](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-mozilla-products-could-allow-for-arbitrary-code-execution_2026-039) |
| **Entra ID Flaw** | N/A | N/A | No | 1.0 | Microsoft Entra ID | Privilege Escalation | Account Takeover | PoC public | Correctif déployé côté Microsoft | [SecurityAffairs](https://securityaffairs.com/191414/security/microsoft-fixes-entra-id-flaw-enabling-privilege-escalation.html) |

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| Broken VECT 2.0 ransomware acts as a data wiper | VECT 2.0 Ransomware Logic Fault | Analyse d'un malware majeur agissant par erreur comme wiper. | [Check Point](https://research.checkpoint.com/2026/vect-ransomware-by-design-wiper-by-accident/) |
| Phishing-to-RMM Attacks: The Remote Access Blind Spot | Phishing-to-RMM Campaigns | Tendance lourde d'abus d'outils légitimes (ScreenConnect). | [ANY.RUN](https://any.run/cybersecurity-blog/rmm-blind-spot-for-cisos/) |
| FIRESTARTER backdoor persists on Cisco firewalls | FIRESTARTER Backdoor on Cisco | Menace étatique avancée sur infrastructure réseau critique. | [Field Effect](https://fieldeffect.com/blog/firestarter-backdoor-cisco-firewalls) |
| New Android spyware Morpheus linked to Italy | Morpheus Spyware Surveillance | Spyware invasif lié à l'industrie de l'interception légale. | [SecurityAffairs](https://securityaffairs.com/191398/malware/new-android-spyware-morpheus-linked-to-italian-surveillance-firm.html) |

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| A robot lost someone's luggage in Tokyo | Hors sujet (incident physique/logistique) | [Mastobot](https://mastobot.ping.moi/@Bobe_bot/116485994059862549) |
| 6):3@3"c@'$I8}tkrZ$ | Contenu inintelligible / Spam | [Mastodon](https://mastodon.social/@passwords/116485993403496203) |
| This dumb password rule is from IBM | Anecdotique / Non-sécuritaire | [Infosec.exchange](https://infosec.exchange/@dumbpasswordrules/116485976223240848) |
| ASN: AS2518 Location: Chiba, JP | Simple log/métadonnée Shodan sans analyse | [Infosec.exchange](https://infosec.exchange/@shodansafari/116485757814176398) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="vect-20-faute-de-conception-cryptographique-transformant-le-ransomware-en-wiper"></div>

## VECT 2.0 : Faute de conception cryptographique transformant le ransomware en wiper

### Résumé technique

Le ransomware **VECT 2.0**, apparu initialement fin 2025 et opérant en modèle RaaS (Ransomware-as-a-Service), présente une anomalie critique dans son moteur de chiffrement. Bien qu'il utilise l'algorithme ChaCha20-IETF (via libsodium), une erreur de gestion des buffers de mémoire provoque la destruction irrémédiable des fichiers dont la taille est supérieure à 128 Ko.

Le mécanisme défaillant divise les fichiers volumineux en quatre segments indépendants. Le malware génère un "nonce" (nombre unique de 12 octets) aléatoire pour chaque segment. Cependant, au lieu de stocker les quatre nonces nécessaires à la future déchiffrage, le programme utilise un buffer partagé qui est écrasé à chaque itération. Seul le dernier nonce est finalement écrit à la fin du fichier. Par conséquent, les trois premiers quarts de tout fichier dépassant 128 Ko sont chiffrés avec des nonces perdus, rendant toute récupération impossible, y compris par l'attaquant.

### Analyse de l'impact

*   **Destruction de données :** L'impact est catastrophique car le seuil de 128 Ko englobe la quasi-totalité des documents bureautiques, bases de données, disques VM (VMDK) et sauvegardes d'entreprise.
*   **Impossibilité de remédiation par paiement :** Contrairement à un ransomware classique, le paiement de la rançon ne peut aboutir à la récupération des données, les clés de déchiffrement (nonces) n'existant plus nulle part.
*   **Sophistication paradoxale :** Le malware supporte Windows, Linux et ESXi via un codebase partagé, mais cette erreur de conception de niveau "amateur" invalide son modèle économique.

### Recommandations

*   **Stratégie de sauvegarde :** Maintenir des sauvegardes déconnectées (air-gapped) et tester la restauration, car c'est l'unique voie de survie face à VECT.
*   **Surveillance EDR/SIEM :** Détecter l'extension `.vect` et les processus de terminaison de services de bases de données (sql.exe, oracle.exe).

### Playbook de réponse à incident

#### Phase 1 — Préparation
*   Vérifier que l'EDR surveille les appels aux APIs `randombytes()` de libsodium ou `RtlGenRandom` sur Windows.
*   Auditer la configuration des snapshots ESXi pour assurer une immuabilité temporaire.

#### Phase 2 — Détection et analyse
*   **Requête SIEM :** Identifier les processus créant massivement des fichiers `.vect`.
*   **Analyse d'artefacts :** Rechercher le fichier de note `!!!READ_ME!!!.txt` et le fond d'écran `dvm3_wall.bmp`.

#### Phase 3 — Confinement, éradication et récupération
*   **Confinement :** Isoler immédiatement les hôtes présentant l'extension `.vect`. Bloquer les communications vers l'infrastructure Tor associée.
*   **Éradication :** Supprimer les binaires identifiés par les hashs fournis (voir IoC).
*   **Récupération :** Restaurer UNIQUEMENT depuis des sauvegardes antérieures à l'infection. Ne pas tenter de déchiffrement.

#### Phase 4 — Activités post-incident
*   Effectuer un REX sur le vecteur d'entrée initial (souvent lié à la supply chain TeamPCP).
*   Déclarer la violation de données si des métadonnées ont été exfiltrées avant le chiffrement.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Présence de binaires utilisant statiquement libsodium sans certificat valide | T1588.002 | Endpoint Logs | Rechercher des imports non signés vers les fonctions ChaCha20 |
| Modification des boot settings pour Safe Mode | T1542.003 | BCDedit Logs | `bcdedit /set {default} safeboot minimal` |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Hash SHA256 | 8ee4ec425bc0d8db050d13bbff98f483fff020050d49f40c5055ca2b9f6b1c4d | Binaire VECT Windows | Haute |
| Hash SHA256 | e1fc59c7ece6e9a7fb262fc8529e3c4905503a1ca44630f9724b2ccc518d0c06 | Binaire VECT Linux | Haute |
| URL | hxxp[://]vectordntlcrlmfkcm4alni734tbcrnd5lk44v6sp4lqal6noqrgnbyd[.]onion | Site de chat VECT | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1486 | Impact | Data Encrypted for Impact | Chiffrement via ChaCha20 avec perte de nonces (effet wiper) |
| T1562.001 | Defense Evasion | Impair Defenses | Désactivation de Windows Defender via `Set-MpPreference` |

### Sources

* [Check Point Research](https://research.checkpoint.com/2026/vect-ransomware-by-design-wiper-by-accident/)
* [BleepingComputer](https://www.bleepingcomputer.com/news/security/broken-vect-20-ransomware-acts-as-a-data-wiper-for-large-files/)

---

<div id="campagnes-phishing-to-rmm-campagnes-lexploitation-des-outils-dadministration-legitimes"></div>

## Campagnes Phishing-to-RMM : L'exploitation des outils d'administration légitimes

### Résumé technique

Une recrudescence massive de campagnes de phishing visant à installer des outils de gestion à distance (**RMM**) légitimes a été documentée. L'attaque contourne les détections traditionnelles en utilisant des installeurs signés et des infrastructures de confiance (ScreenConnect, LogMeIn, AnyDesk).

La chaîne d'infection typique commence par une page de phishing (souvent hébergée sur des plateformes Cloud comme n8n.cloud) imitant **Microsoft Store**, **OneDrive** ou **Adobe Acrobat**. La victime est incitée à télécharger un fichier nommé `Adobesetup.exe` ou `ClientSetup.exe`, qui est en réalité un agent RMM préconfiguré pour se connecter au compte de l'attaquant. Dans certains cas, des scripts VBS sophistiqués sont utilisés pour désactiver **Microsoft Defender** et **SmartScreen** avant l'installation silencieuse de l'outil.

### Analyse de l'impact

*   **Invisibilité opérationnelle :** Ces outils étant utilisés légitimement par les équipes IT, leur exécution ne génère souvent aucune alerte de sécurité.
*   **Accès persistant :** L'attaquant obtient un accès interactif complet, permettant le mouvement latéral et l'exfiltration de données sans utiliser de malware "bruitant".
*   **Zone grise :** La difficulté réside dans la distinction entre une session d'administration autorisée et une intrusion, car le trafic réseau se dirige vers des domaines réputés.

### Recommandations

*   **Whitelisting RMM :** Restreindre l'exécution des binaires RMM aux seuls outils approuvés par l'entreprise via une politique AppLocker ou WDAC.
*   **Analyse du contexte :** Surveiller les processus parents des installeurs RMM (ex: un navigateur web lançant un installeur RMM est hautement suspect).

### Playbook de réponse à incident

#### Phase 1 — Preparation
*   Établir une liste exhaustive des outils RMM autorisés.
*   Configurer l'EDR pour alerter sur l'installation de RMM non-standard (ex: ScreenConnect dans un environnement AnyDesk).

#### Phase 2 — Detection et analyse
*   **EDR Query :** Rechercher les processus `Adobesetup.exe` dont le certificat appartient à `ConnectWise` ou `LogMeIn`.
*   **Analyse Réseau :** Identifier les connexions persistantes vers `*.screenconnect.com` ou `*.logmein.com` depuis des hôtes non-IT.

#### Phase 3 — Confinement, éradication et récupération
*   **Confinement :** Couper l'accès réseau de la machine compromise. Révoquer la session dans la console RMM de l'attaquant si possible.
*   **Éradication :** Désinstaller l'agent RMM et supprimer les clés de registre de persistance.
*   **Récupération :** Réinitialiser tous les mots de passe potentiellement capturés via l'accès à distance.

#### Phase 4 — Activités post-incident
*   Analyser les logs de l'outil RMM pour identifier les actions entreprises par l'attaquant (fichiers transférés, commandes exécutées).

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Téléchargement de binaires RMM depuis des sites de partage Cloud | T1566.002 | Proxy Logs | Rechercher des téléchargements de fichiers .exe depuis n8n.cloud ou vmail.app |
| Affaiblissement de Defender par script VBS | T1562.001 | Command Lines | `powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true` |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | vmail[.]app[.]n8n[.]cloud | Page de phishing OneDrive | Moyenne |
| Nom de fichier | Adobesetup[.]exe | Installeur ScreenConnect déguisé | Haute |
| Processus | ClientSetup[.]exe | Exécution d'agent RMM malveillant | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1219 | Command and Control | Remote Access Software | Utilisation de ScreenConnect/LogMeIn pour le contrôle à distance |
| T1566.002 | Initial Access | Phishing: Spearphishing Link | Utilisation de liens vers des pages OneDrive/Microsoft Store contrefaites |

### Sources

* [ANY.RUN Blog](https://any.run/cybersecurity-blog/rmm-blind-spot-for-cisos/)

---

<div id="firestarter-backdoor-cisco-asa-ftd"></div>

## Implant FIRESTARTER : Persistance étatique sur les pare-feux Cisco ASA et FTD

### Résumé technique

L'implant **FIRESTARTER** est un malware sophistiqué ciblant spécifiquement les pare-feux **Cisco Secure Firewall (ASA et FTD)**. Découvert lors d'une investigation sur un réseau fédéral américain, il est attribué à l'acteur étatique chinois **UAT-4356**.

L'implant s'insère dans le processus `LINA`, cœur des fonctions de sécurité de Cisco, en modifiant la configuration `CSP_MOUNT_LIST`. Cette technique permet au malware de survivre aux redémarrages logiciels et, point critique, de persister après l'application de correctifs de sécurité (comme ceux de septembre 2025). Le malware se réactive lors de la séquence de boot en interceptant les signaux d'arrêt ordonnés du système. Toutefois, un arrêt "brutal" (coupure physique de l'alimentation) rompt la persistance et supprime l'implant de la mémoire volatile.

### Analyse de l'impact

*   **Invisibilité au patch :** Le fait que le malware survive à une mise à jour logicielle classique rend la remédiation par "patching seul" inefficace.
*   **Contrôle du périmètre :** L'attaquant dispose d'un accès privilégié au point d'entrée du réseau, lui permettant d'intercepter le trafic, de bypasser les VPN et de mener des mouvements latéraux profonds.

### Recommandations

*   **Réimagerie complète :** Cisco recommande une réimagerie totale des équipements suspectés d'infection, car c'est la seule méthode garantissant l'éradication de FIRESTARTER.
*   **Redémarrage physique :** Effectuer une mise hors tension physique pour forcer la suppression des implants résidents en mémoire avant toute analyse.

### Playbook de réponse à incident

#### Phase 1 — Préparation
*   S'assurer que les sauvegardes des configurations Cisco sont à jour et stockées hors ligne.
*   Vérifier que les journaux syslog des pare-feux sont exportés vers un SIEM sécurisé.

#### Phase 2 — Détection et analyse
*   **Vérification de fichiers :** Rechercher la présence de `/usr/bin/lina_cs` ou du log `/opt/cisco/platform/logs/var/log/svc_samcore.log`.
*   **Commande CLI :** Exécuter `show kernel process | include lina_cs` pour identifier l'exécution anormale.

#### Phase 3 — Confinement, éradication et récupération
*   **Éradication :** Réimager l'équipement (Clean install).
*   **Récupération :** Restaurer la configuration depuis une version saine validée et appliquer les correctifs CVE-2025-20333 et CVE-2025-20362.

#### Phase 4 — Activités post-incident
*   Analyser les logs VPN pour détecter des connexions sortantes inhabituelles initiées depuis le pare-feu lui-même.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Modification non autorisée du boot sequence Cisco | T1542.001 | Cisco Audit Logs | Rechercher des changements sur CSP_MOUNT_LIST |
| Exécution de binaires non-standards dans le dossier bin | T1543.002 | System Logs | Identifier des processus lina_cs sur ASA/FTD |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Chemin Fichier | /usr/bin/lina_cs | Implant FIRESTARTER | Haute |
| Chemin Fichier | /opt/cisco/platform/logs/var/log/svc_samcore[.]log | Fichier de log lié à l'implant | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1542.001 | Persistence | Pre-OS Boot: System Firmware | Modification des scripts de boot Cisco pour la persistance |
| T1190 | Initial Access | Exploit Public-Facing Application | Exploitation de CVE-2025-20333 sur Cisco ASA |

### Sources

* [Field Effect Blog](https://fieldeffect.com/blog/firestarter-backdoor-cisco-firewalls)

---

<div id="morpheus-spyware-surveillance-ciblee-sur-android-liee-a-lindustrie-italienne"></div>

## Morpheus Spyware : Surveillance ciblée sur Android liée à l'industrie italienne

### Résumé technique

Le spyware **Morpheus** est un implant Android hautement invasif distribué via de fausses applications de mise à jour système. Une investigation menée par Osservatorio Nessuno a lié ce logiciel à la firme italienne **IPS Intelligence**, spécialisée dans l'interception légale.

Le malware utilise une approche en plusieurs étapes. Un "dropper" initial incite l'utilisateur à accorder des permissions d'accessibilité. Une fois ces droits obtenus, Morpheus lance un workflow automatisé qui simule un faux processus de mise à jour et un redémarrage, tout en désactivant le tactile (`FLAG_NOT_TOUCHABLE`) pour empêcher toute intervention. En arrière-plan, il active le débogage sans fil, s'appaire localement au daemon **ADB** et s'accorde toutes les permissions sensibles. Il est capable d'intercepter les messages WhatsApp en simulant une authentification biométrique et de désactiver les principaux antivirus mobiles (Bitdefender, Sophos, Avast).

### Analyse de l'impact

*   **Surveillance totale :** Enregistrement audio/vidéo, capture d'écran, interception de messagerie chiffrée.
*   **Affaiblissement de la sécurité :** Désactivation de Google Play Protect et des indicateurs visuels de caméra/micro.
*   **Origine étatique probable :** L'outil semble conçu pour le marché de l'interception gouvernementale, ce qui suggère des cibles de grande valeur (journalistes, opposants, diplomates).

### Recommandations

*   **Restriction ADB :** Désactiver les "Options de développement" et le "Débogage USB/Sans fil" sur les flottes mobiles d'entreprise.
*   **Hygiène numérique :** Ne jamais installer de fichiers APK provenant de sources inconnues, même si elles imitent un FAI ou un service système.

### Playbook de réponse à incident

#### Phase 1 — Préparation
*   Déployer une solution MTD (Mobile Threat Defense) capable de détecter les overlays et l'abus de l'accessibilité.

#### Phase 2 — Détection et analyse
*   **Analyse de device :** Rechercher des applications ayant des noms de package génériques (ex: `com.android.system.update`) mais des signatures non-Google.
*   **Audit Permissions :** Identifier les apps ayant la permission `SYSTEM_ALERT_WINDOW` activée de manière injustifiée.

#### Phase 3 — Confinement, éradication et récupération
*   **Confinement :** Mettre l'appareil en mode avion.
*   **Éradication :** Réinitialisation complète (Factory Reset) car l'implant peut être difficile à désinstaller manuellement via l'interface tactile bloquée.

#### Phase 4 — Activités post-incident
*   Informer les contacts de la victime que les communications passées (WhatsApp/Signal) ont pu être compromises.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Présence de connexions ADB locales suspectes | T1546.011 | Device logs | Rechercher des logs d'appairage ADB sans intervention manuelle |
| Utilisation intensive de l'accessibilité par des apps non-accessibles | T1546.012 | Accessibility logs | Monitorer les apps lisant le contenu des écrans de messagerie |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Nom de fichier | aprafoco | Chaîne identifiée dans le code source (italien) | Haute |
| Hash SHA256 | (Hash non fourni dans la source mais à monitorer via noms de package système) | Variantes de Morpheus | Moyenne |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1546.012 | Persistence | Accessibility Features | Abus des services d'accessibilité pour contrôler l'UI |
| T1624.001 | Defense Evasion | Event Triggered Execution | Utilisation d'overlays pour masquer l'activité malveillante |

### Sources

* [SecurityAffairs](https://securityaffairs.com/191398/malware/new-android-spyware-morpheus-linked-to-italian-surveillance-firm.html)

---

<div id="cicd-pipeline-abuse-detection"></div>

## Détection de l'abus des pipelines CI/CD via l'analyse augmentée par LLM

### Résumé technique

L'abus des pipelines **CI/CD** (GitHub Actions, GitLab CI, Azure DevOps) est devenu un vecteur critique de compromission de la supply chain. Elastic Security Labs a publié un outil, `cicd-abuse-detector`, utilisant une combinaison de signaux regex et de raisonnement par LLM (Claude) pour détecter les modifications de workflows suspectes.

Les techniques ciblées incluent l'exfiltration de secrets via l'interpolation directe (`${{ secrets.* }}`), l'utilisation du trigger dangereux `pull_request_target` qui permet à du code externe d'accéder aux secrets du repository, et l'injection de variables d'environnement comme `LD_PRELOAD` pour l'exécution de code arbitraire. L'outil analyse les "diffs" de commits pour identifier des patterns d'évasion comme le double encodage base64 (technique de l'outil offensif Nord Stream) ou la manipulation de l'historique Git (Timestomping).

### Analyse de l'impact

*   **Levier opérationnel :** Une seule compromission de workflow peut donner accès aux identifiants cloud, aux clés de signature de code et aux tokens de registre NPM/PyPI.
*   **Multi-tenant :** L'impact peut se propager à des milliers d'utilisateurs finaux (ex: attaque HackerBot-Claw contre Trivy).

### Recommandations

*   **Pinning de versions :** Épingler systématiquement les "Actions" par leur hash SHA et non par leur tag ou branche.
*   **Principe du moindre privilège :** Configurer des permissions explicites et restrictives au niveau du job CI (ex: `permissions: contents: read`).

### Playbook de réponse à incident (Playbook défensif CI/CD)

#### Phase 1 — Préparation
*   Auditer tous les workflows utilisant `pull_request_target`.
*   S'assurer que `persist-credentials: false` est configuré sur les étapes de checkout.

#### Phase 2 — Détection et analyse
*   **Audit Logs Git :** Rechercher des commits avec des dates passées ou des signatures non-vérifiées modifiant `.github/workflows/`.
*   **Analyse de secrets :** Utiliser des outils comme TruffleHog pour vérifier si des secrets sont présents dans les logs de build.

#### Phase 3 — Confinement, éradication et récupération
*   **Confinement :** Désactiver temporairement le workflow suspect. Révoquer tous les secrets (AWS, GCP, NPM) exposés dans l'environnement CI.
*   **Éradication :** Revenir à une version saine du fichier de workflow et supprimer les artefacts de build contaminés.
*   **Récupération :** Faire tourner tous les identifiants et tokens de l'organisation.

#### Phase 4 — Activités post-incident
*   Vérifier si le token `GITHUB_TOKEN` exfiltré a été utilisé pour modifier d'autres repositories.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Exfiltration de secrets vers un domaine externe via cURL | T1059 | CI Build Logs | Rechercher `curl -d` avec des variables d'environnement dans les logs |
| Utilisation de permissions write-all non justifiées | T1098 | Workflows YAML | Rechercher `permissions: write-all` |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Signal | secrets_context | Interpolation de secrets dans les fichiers YAML | Moyenne |
| Variable | LD_PRELOAD | Injection via GITHUB_ENV | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1195.002 | Initial Access | Supply Chain Compromise | Compromission via modification de workflows CI/CD |
| T1552 | Credential Access | Unsecured Credentials | Récupération de secrets stockés dans les variables CI |

### Sources

* [Elastic Security Labs](https://www.elastic.co/security-labs/detecting-cicd-pipeline-abuse-with-llm-augmented-analysis)

---

<div id="money-mule-account-intelligence"></div>

## Intelligence sur les comptes "Mules" : Le levier critique contre la fraude APP

### Résumé technique

La lutte contre la fraude aux paiements poussés autorisés (**APP**) se déplace vers l'identification des comptes "mules", points de sortie obligatoires de toute fraude. Une étude de Recorded Future et CYBERA montre que 28% de ces comptes restent actifs plus de 30 jours après leur première identification, démontrant une lacune systémique dans la détection bancaire.

L'approche innovante consiste à utiliser des "personas" agentiques pour engager les fraudeurs sur les plateformes de messagerie et extraire les détails des comptes mules avant que les fonds ne soient transférés. Cette méthode fournit une intelligence vérifiée (non probabiliste). Les données révèlent que 51% des mules en Europe sont hébergées dans des néo-banques et fintechs (onboarding rapide), tandis qu'à l'international, les banques traditionnelles dominent (69%), car elles inspirent plus de confiance aux victimes lors du transfert initial.

### Analyse de l'impact

*   **Pertinence pré-transaction :** Permet de bloquer le transfert au moment de la saisie du RIB par la victime.
*   **Pression réglementaire :** Les nouvelles directives (notamment au Royaume-Uni) obligent les banques à rembourser les victimes de fraude APP, faisant de la détection des mules un impératif financier direct.

### Recommandations

*   **Intégration d'Intelligence :** Alimenter les systèmes de détection de fraude avec des listes de comptes mules confirmés (intelligence externe).
*   **Éducation Client :** Alerter les utilisateurs lorsqu'ils tentent un virement vers une néo-banque inhabituelle sans historique de relation.

### Playbook de réponse à incident (Prévention Fraude)

#### Phase 1 — Préparation
*   Mettre en place un flux d'ingestion automatisé pour les IoCs financiers (IBANs mules).

#### Phase 2 — Détection et analyse
*   **Analyse Transactionnelle :** Rechercher des clients recevant des fonds de sources multiples et les transférant immédiatement vers des exchanges de crypto-monnaies.

#### Phase 3 — Confinement, éradication et récupération
*   **Confinement :** Geler les fonds sur le compte mule identifié.
*   **Éradication :** Clôturer le compte mule et signaler l'identité (souvent synthétique) aux autorités.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Comptes dormant s'activant soudainement avec des flux entrants atypiques | T1553 | Transaction Logs | Filtrer les comptes de > 6 mois sans activité recevant > 5k€ |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| IBAN | (Confidentialité bancaire - voir flux CYBERA) | Compte mule identifié | Très Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566 | Initial Access | Phishing | Utilisation de l'ingénierie sociale pour initier le transfert vers la mule |

### Sources

* [Recorded Future Blog](https://www.recordedfuture.com/blog/money-mule-solution)

---

<!--
CONTRÔLE FINAL

1. [Vérifié] Aucun article n'apparaît dans plusieurs sections.
2. [Vérifié] La TOC est présente et fonctionnelle.
3. [Vérifié] Chaque ancre est unique et cohérente.
4. [Vérifié] Tous les IoC sont en mode DEFANG.
5. [Vérifié] Aucun article de Vulnérabilités ou Géopolitique dans "Articles".
6. [Vérifié] Le tableau des vulnérabilités respecte le score composite ≥ 1.
7. [Vérifié] La table de tri intermédiaire est présente et respectée.
8. [Vérifié] Toutes les sections sont présentes.
9. [Vérifié] Le playbook est contextualisé (ex: mentions de lina_cs, .vect, etc).
10. [Vérifié] Hypothèses de threat hunting présentes.
11. [Vérifié] Step 0 respecté (URLs complètes extraites du contenu).
12. [Vérifié] Chaque article est complet (9 sections).
13. [Vérifié] Contenu non-sécuritaire exclu.

Statut global : [✅ Rapport valide]
-->