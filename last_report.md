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
  * [Mini Shai-Hulud + PyTorch supply chain compromise](#mini-shai-hulud-plus-pytorch-supply-chain-compromise)
  * [AiTM phishing campaign via code of conduct lures](#aitm-phishing-campaign-via-code-of-conduct-lures)
  * [Bluekit automated phishing kit with AI capabilities](#bluekit-automated-phishing-kit-with-ai-capabilities)
  * [VK.com phishing via compromised Italian infrastructure](#vk-com-phishing-via-compromised-italian-infrastructure)
  * [Trellix source code repository compromise](#trellix-source-code-repository-compromise)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

Le paysage des menaces de mai 2026 est marqué par une convergence critique entre l'Intelligence Artificielle générative et l'automatisation des attaques. L'IA n'est plus un concept théorique mais un levier opérationnel : elle accélère la découverte de vulnérabilités, comme le souligne le NCSC britannique, et sophistique les campagnes de phishing via des outils comme Bluekit capable de cloner des voix pour le vishing. Parallèlement, une pression extrême s'exerce sur les infrastructures critiques (énergie, eau, gestion de crise). Les opérations de sabotage et de reconnaissance attribuées à l'Iran et à la Russie illustrent une volonté d'impacter les systèmes de dissuasion ou de contrôle environnemental (pompes de Venise, automates Rockwell).

Le secteur technologique et du développement logiciel subit une offensive majeure sur la chaîne d'approvisionnement. Le groupe Lazarus et des acteurs comme TeamPCP saturent les dépôts (npm, PyPI) de packages empoisonnés (ex: Mini Shai-Hulud), ciblant directement les environnements de build. Enfin, l'exploitation active de failles critiques sur des briques d'infrastructure (cPanel, Linux Kernel, MOVEit) force les organisations à une réactivité sans précédent, alors que les attaquants déploient des ransomwares (Sorry, Everest) quelques heures seulement après la publication des PoC. Les recommandations stratégiques s'orientent vers le "hot patching" automatisé et l'adoption de l'authentification résistante au phishing (FIDO2) pour contrer l'AiTM.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **APT28** (Fancy Bear) | Gouvernement, Énergie | Compromission de routeurs SOHO, détournement DNS et attaques AiTM sur Outlook. | T1584.006, T1557 | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-05/) |
| **Silk Typhoon** (Hafnium) | Gouvernement, Secteur Privé | Exploitation de Zero-day (Exchange) pour exfiltration de données massive. | T1190 | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-05/) |
| **Lazarus Group** | Technologie, Développement | Campagne "Contagious Interview" utilisant des packages malveillants npm/PyPI. | T1195.002 | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-05/) |
| **TeamPCP** | Technologie, Éducation | Propagation du ver Mini Shai-Hulud via des identifiants GitHub volés. | T1195 | [SANS ISC](https://isc.sans.edu/diary/rss/32950) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| Europe / Russie | Administration Publique | Sanctions Hybrides | L'UE sanctionne Euromore et Pravfond pour des opérations de déstabilisation et désinformation liées à l'Ukraine. | [Council of the EU](https://cert.europa.eu/publications/threat-intelligence/cb26-05/) |
| France | Défense | Force stratégique | Cartographie russe des systèmes de communication basse fréquence de la dissuasion nucléaire française. | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-05/) |
| USA / Iran | Énergie / Eau | Sabotage ICS | L'IRGC cible des automates Rockwell Automation, manipulant les écrans HMI et extrayant des fichiers sensibles. | [CISA](https://cert.europa.eu/publications/threat-intelligence/cb26-05/) |
| Moyen-Orient / EAU | Énergie | Stratégie OPEP | Rupture géopolitique suite au retrait des EAU de l'OPEP, impactant la stabilité énergétique mondiale. | [IRIS](https://www.iris-france.org/retrait-de-lopep-le-pari-risque-des-emirats-arabes-unis/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Opération PowerOFF | Europol | 2026-04-13 | Global | DDoS Services | Saisie de domaines et identification de 75 000 utilisateurs de services DDoS-for-hire. | [Europol](https://cert.europa.eu/publications/threat-intelligence/cb26-05/) |
| ESMA AI Warning | ESMA | 2026-04-24 | Europe | Finance | Avertissement sur les risques IA pour le secteur financier et les plateformes crypto. | [ESMA](https://cert.europa.eu/publications/threat-intelligence/cb26-05/) |
| CSWP 50 | NIST | 2026-05-04 | USA | NIST 2.0 | Nouvelles ressources pour la gestion des risques cyber pour les micro-entreprises. | [NIST](https://www.nist.gov/blogs/cybersecurity-insights/stronger-cybersecurity-stronger-business-nist-celebrates-2026-national) |
| AI Patch Wave Warning | UK NCSC | 2026-05-04 | UK | Strategic Guidance | Le NCSC alerte sur l'accélération de la découverte de failles via l'IA, imposant un cycle de patch urgent. | [UK NCSC](https://securityaffairs.com/191657/security/ai-speeds-flaw-discovery-forcing-rapid-updates-uk-ncsc-warns.html) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| Environnement | Venice Flood Defence | Accès administratif (Root) aux pompes | N/A (Accès critique) | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-05/) |
| Public | ANTS (France) | Noms, e-mails, dates de naissance | 19 000 000 | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-05/) |
| Law Enforcement | FBI Surveillance System | Retours de surveillance, données d'enquêtes | Massif | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-05/) |
| Fintech | TSYS | Données financières potentielles | Inconnu (Everest Ransomware) | [Mastobot](https://mastobot.ping.moi/@Bobe_bot/116519495924597375) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-41940 | TRUE  | Active    | 7.0 | 9.8   | (1,1,7.0,9.8) |
| 2 | CVE-2026-31431 | TRUE  | Active    | 5.5 | 7.8   | (1,1,5.5,7.8) |
| 3 | CVE-2026-35616 | FALSE | Active    | 4.0 | 9.8   | (0,1,4.0,9.8) |
| 4 | CVE-2026-4670  | FALSE | Active    | 3.5 | 9.8   | (0,1,3.5,9.8) |
| 5 | CVE-2026-22679 | FALSE | Active    | 3.0 | N/A→0 | (0,1,3.0,0)   |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| CVE-2026-41940 | 9.8 | N/A | TRUE | 7.0 | cPanel, WHM | Auth Bypass / RCE | RCE | Active | Correctif d'urgence du 28/04/2026 | [Security Affairs](https://securityaffairs.com/191666/breaking-news/hackers-target-governments-and-msps-via-critical-cpanel-flaw-cve-2026-41940.html) |
| CVE-2026-31431 | 7.8 | N/A | TRUE | 5.5 | Linux Kernel | Copy Fail logic | LPE | Active | Mise à jour vers Kernel 6.12+ | [Security Affairs](https://securityaffairs.com/191629/hacking-u-s-cisa-adds-a-flaw-in-linux-kernel-to-its-known-exploited-vulnerabilities-catalog.html) |
| CVE-2026-35616 | 9.8 | N/A | FALSE | 4.0 | FortiClient EMS | Improper Access Control | RCE | Active | Mise à jour vers EMS 7.4.7 | [Fortinet](https://cert.europa.eu/publications/threat-intelligence/cb26-05/) |
| CVE-2026-4670 | 9.8 | N/A | FALSE | 3.5 | MOVEit Automation | Authentication Bypass | Admin Access | Active | Version 2025.1.5 | [The Hacker News](https://thehackernews.com/2026/05/progress-patches-critical-moveit.html) |
| CVE-2026-22679 | N/A | N/A | FALSE | 3.0 | Weaver E-cology | API Debug RCE | RCE | Active | Désactiver l'API de debug | [BleepingComputer](https://www.bleepingcomputer.com/news/security/weaver-e-cology-critical-bug-exploited-in-attacks-since-march/) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| TeamPCP Weekly / PyTorch Backdoor | Mini Shai-Hulud + PyTorch supply chain compromise | Menace majeure sur la supply chain logicielle affectant des packages populaires. | [SANS ISC](https://isc.sans.edu/diary/rss/32950)<br>[BleepingComputer](https://www.bleepingcomputer.com/news/security/backdoored-pytorch-lightning-package-drops-credential-stealer/) |
| Breaking the code: Code of conduct phishing | AiTM phishing campaign via code of conduct lures | Campagne AiTM sophistiquée ciblant les tokens MFA via des leurres RH. | [Microsoft Security](https://www.microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/) |
| Bluekit phishing kit automated | Bluekit automated phishing kit with AI capabilities | Utilisation d'IA pour le clonage de voix et l'automatisation de phishing massif. | [Security Affairs](https://securityaffairs.com/191646/cyber-crime/bluekit-phishing-kit-enables-automated-phishing-with-40-templates-and-ai-tools.html) |
| Phishing Detection on VK.com | VK.com phishing via compromised Italian infrastructure | Exploitation de réseaux sociaux et d'infrastructure compromise pour le phishing. | [URLDNA](https://infosec.exchange/@urldna/116519377921115682) |
| Trellix source code breach | Trellix source code repository compromise | Intrusion dans le dépôt de code source d'un éditeur de sécurité majeur. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/trellix-discloses-data-breach-after-source-code-repository-hack/) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| Cyber Brief 26-05 - April 2026 | Rapport de synthèse mensuel sans détails techniques exploitables pour un article complet. | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-05/) |
| Elastic Security 9.4 Release | Annonce de sortie de produit (commercial/fonctionnel). | [Elastic Security](https://www.elastic.co/security-labs/skills-elastic-security-9-4) |
| ISC Stormcast (May 4/5) | Format podcast/journalier sans analyse granulaire propre à un sujet unique. | [SANS ISC](https://isc.sans.edu/diary/rss/32952) |
| Amazon SES Phishing Abuse | Analyse de tendance de vecteur sans détails d'incident spécifique. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/amazon-ses-increasingly-abused-in-phishing-to-evade-detection/) |
| Red Canary CFP Tracker | Article utilitaire/communautaire (calendrier de conférences). | [Red Canary](https://redcanary.com/blog/news-events/red-canary-cfp-tracker-may-2026/) |
| Fiber-optic hidden microphone | Recherche scientifique/physique hors périmètre cyber-opérationnel immédiat. | [Mastodon](https://mastodon.social/@const_data/116519423729704102) |
| Amazon WorkSpaces Skylight Agent | Classé en Vulnérabilités (P1), score < 1. | [AWS Security](https://aws.amazon.com/security/security-bulletins/rss/2026-025-aws/) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="mini-shai-hulud-plus-pytorch-supply-chain-compromise"></div>

## Mini Shai-Hulud + PyTorch supply chain compromise

---

### Résumé technique

Une campagne d'infection de la chaîne d'approvisionnement logicielle menée par l'acteur **TeamPCP** cible les écosystèmes Python et SAP. Le ver malveillant, baptisé **Mini Shai-Hulud**, a été injecté dans des packages populaires tels que `pytorch-lightning` (version 2.6.3) et des composants SAP sur npm. La chaîne d'infection débute par l'utilisation d'identifiants GitHub volés pour modifier des dépôts légitimes. Le package compromis contient un payload obfusqué de 11.4 MB qui utilise le runtime **Bun** pour s'exécuter lors de l'importation du module. Une fois actif, le malware tente de voler des secrets d'environnement, des clés SSH/RSA et des tokens CI/CD pour faciliter sa propagation inter-écosystèmes.

### Analyse de l'impact

L'impact est critique pour les entreprises utilisant des pipelines de Machine Learning et des infrastructures SAP. La compromission permet aux attaquants d'accéder aux modèles d'IA en cours d'entraînement et d'exfiltrer des données sensibles. La sophistication réside dans l'utilisation du runtime Bun pour l'exécution discrète de payloads JavaScript au sein d'environnements Python.

### Recommandations

*   Vérifier immédiatement l'intégrité de la version de `lightning` installée (éviter la 2.6.3).
*   Réinitialiser tous les tokens d'accès GitHub et variables d'environnement CI/CD.
*   Auditer les dépendances via des outils comme `Safety` ou `npm audit`.

### Playbook de réponse à incident

#### Phase 1 — Préparation
*   Activer le monitoring des changements de packages sur les registres privés npm/PyPI.
*   Former les développeurs au "secret management" pour éviter le stockage de clés en clair dans les dépôts.
*   Mettre en œuvre une solution d'audit de composition logicielle (SCA) en temps réel.

#### Phase 2 — Détection et analyse
*   **Règles de détection :**
    *   Requête EDR : Rechercher l'exécution du processus `bun` dont le parent est un interpréteur `python`.
    *   Règle YARA : Cibler les chaînes de caractères spécifiques au ver Mini Shai-Hulud dans les répertoires `site-packages`.
*   Scanner les journaux GitHub pour détecter des clones de dépôts massifs ou des commits inhabituels depuis des IPs inconnues.

#### Phase 3 — Confinement, éradication et récupération
*   **Confinement :** Isoler les stations de build ayant téléchargé les packages incriminés.
*   **Éradication :** Supprimer de force les versions compromises (`pip uninstall lightning==2.6.3`). Révoquer l'ensemble des clés SSH et tokens API potentiellement lus par le malware.
*   **Récupération :** Restaurer les environnements de développement à partir de caches de packages certifiés sains (miroirs internes).

#### Phase 4 — Activités post-incident
*   Analyser les logs d'exfiltration pour déterminer quels secrets ont été compromis.
*   Conduire un REX sur la sécurité des comptes développeurs (passage obligatoire au MFA matériel).
*   Notifier les partenaires si des dépôts privés ont été clonés.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Exécution furtive via Bun | T1195.002 | Endpoint Logs | `ProcessCreation | where ParentImage contains 'python' and ProcessName == 'bun'` |
| Accès non autorisé aux secrets | T1555 | File Access Logs | `FileAccess | where FileName in ('.ssh/id_rsa', '.env', 'config.json')` |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | hxxps[://]wiz[.]io/blog/mini-shai-hulud-supply-chain-sap-npm | Analyse technique du ver | Haute |
| Nom de fichier | lightning-2.6.3.tar.gz | Package empoisonné | Haute |
| Technique | Bun runtime execution | Vecteur d'obfuscation | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1195.002 | Initial Access | Malicious Code in Supply Chain | Empoisonnement des registres npm et PyPI. |
| T1555 | Credential Access | Credentials from Password Stores | Vol de tokens et secrets d'environnement. |

---

### Sources

* [SANS ISC](https://isc.sans.edu/diary/rss/32950)
* [BleepingComputer](https://www.bleepingcomputer.com/news/security/backdoored-pytorch-lightning-package-drops-credential-stealer/)

---

<div id="aitm-phishing-campaign-via-code-of-conduct-lures"></div>

## AiTM phishing campaign via code of conduct lures

---

### Résumé technique

Une campagne de phishing de type **Adversary-in-the-Middle (AiTM)** particulièrement sophistiquée cible les organisations via des leurres basés sur le "Code de conduite" interne. Les attaquants envoient des e-mails contenant des liens vers des fichiers PDF ou des pages hébergées sur des domaines usurpant Microsoft Outlook. Pour échapper aux scanners de sécurité automatisés, la campagne utilise des **CAPTCHA Cloudflare** avant d'afficher la page de connexion factice. Le mécanisme permet d'intercepter en temps réel les identifiants et, surtout, les **tokens de session MFA**, contournant ainsi les protections par SMS ou application d'authentification classique.

### Analyse de l'impact

L'impact est élevé car l'attaque neutralise le MFA standard. Une fois le token intercepté, l'attaquant accède directement à la boîte mail de la victime, permettant le vol de données eDiscovery et des attaques par rebond (BEC).

### Recommandations

*   Adopter des méthodes MFA résistantes au phishing basées sur la norme **FIDO2** (Yubikey).
*   Configurer des politiques d'accès conditionnel limitant les connexions aux appareils gérés.
*   Activer la protection réseau **SmartScreen** sur tous les postes.

### Playbook de réponse à incident

#### Phase 1 — Preparation
*   Déployer des clés de sécurité matérielles pour les comptes VIP/Privilégiés.
*   Configurer Azure AD pour détecter les anomalies de type "impossible travel".

#### Phase 2 — Detection et analyse
*   **Règles de détection :**
    *   Query SIEM : Rechercher les logs `SigninLogs` Azure AD contenant l'étiquette `AiTM` ou des connexions via des adresses IP de proxies connus.
    *   Identifier les e-mails contenant des pièces jointes PDF pointant vers les domaines `acceptable-use-policy-calendly[.]de`.

#### Phase 3 — Confinement, éradication et récupération
*   **Confinement :** Révoquer immédiatement tous les tokens de session actifs pour l'utilisateur (`Revoke-MgUserSignInSession`).
*   **Éradication :** Bloquer les domaines de phishing au niveau du proxy et du DNS.
*   **Récupération :** Forcer le changement de mot de passe et réinitialiser les méthodes MFA si nécessaire.

#### Phase 4 — Activités post-incident
*   Analyser la boîte mail pour détecter la création de règles de transfert de courrier (forwarding rules).
*   Notifier les contacts externes si des e-mails de phishing ont été envoyés depuis le compte compromis.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détournement de session AiTM | T1557.001 | Azure AD Logs | `SigninLogs | where AuthenticationProcessingDetails has 'AiTM'` |
| Persistance via règles Outlook | T1137 | Office 365 Logs | `OfficeActivity | where Operation == 'New-InboxRule'` |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | acceptable-use-policy-calendly[.]de | Serveur de phishing AiTM | Haute |
| Domaine | compliance-protectionoutlook[.]de | Serveur de phishing AiTM | Haute |
| Hash SHA256 | 11420D6D693BF8B19195E6B98FEDD03B9BCBC770B6988BC64CB788BFABE1A49D | Payload PDF malveillant | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1557.001 | Credential Access | Adversary-in-the-Middle | Interception de tokens de session MFA. |
| T1566.001 | Initial Access | Spearphishing Attachment | Utilisation de leurres PDF sur le code de conduite. |

---

### Sources

* [Microsoft Security](https://www.microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/)

---

<div id="bluekit-automated-phishing-kit-with-ai-capabilities"></div>

## Bluekit automated phishing kit with AI capabilities

---

### Résumé technique

La découverte du kit de phishing **Bluekit** marque un tournant dans la démocratisation de l'IA pour la cybercriminalité. Ce kit "clés en main" propose plus de 40 templates (iCloud, Gmail, Outlook, services bancaires) et intègre des outils d'IA pour le **clonage de voix (vishing)** et la génération de contenu textuel persuasif. Bluekit dispose également de mécanismes avancés de contournement 2FA et d'un système antibot robuste pour empêcher l'analyse par les chercheurs en sécurité. L'infrastructure permet aux attaquants de générer automatiquement des domaines crédibles et de gérer des campagnes à grande échelle avec un minimum d'effort technique.

### Analyse de l'impact

Bluekit réduit drastiquement la barrière à l'entrée pour les cybercriminels, augmentant le volume d'attaques sophistiquées. L'intégration de l'IA vocale rend les attaques par ingénierie sociale beaucoup plus difficiles à détecter pour les employés, même formés.

### Recommandations

*   Mettre à jour les programmes de sensibilisation pour inclure la détection du "Deepfake" vocal.
*   Implémenter des politiques de filtrage d'e-mails basées sur l'ancienneté des domaines (bloquer les domaines de < 24h).
*   Utiliser des solutions de protection de la navigation bloquant les redirections complexes.

### Playbook de réponse à incident

#### Phase 1 — Preparation
*   Organiser des exercices de crise incluant des simulations de vishing par IA.
*   Déployer des certificats racines pour l'inspection SSL afin de détecter les kits de phishing.

#### Phase 2 — Detection et analyse
*   **Règles de détection :**
    *   DNS Logs : Rechercher des pics de requêtes vers des domaines générés aléatoirement avec des entropies élevées.
    *   Vérifier les flux réseau pour détecter des signatures de serveurs antibot connus.

#### Phase 3 — Confinement, éradication et récupération
*   **Confinement :** Blacklister globalement les domaines identifiés dans les configurations Bluekit.
*   **Éradication :** Identifier les utilisateurs ayant interagi avec les pages et forcer une réinitialisation d'identité complète.

#### Phase 4 — Activités post-incident
*   Analyser les enregistrements téléphoniques (si vishing suspecté) pour identifier les patterns vocaux.
*   Ajuster les filtres heuristiques du SIEM pour intégrer les nouveaux templates.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Domaines Bluekit DGA | T1566 | DNS logs | `DNSQueries | where DomainAge < 24h and QueryName matches regex '[a-z0-9-]{10,}'` |
| Vishing via VoIP | T1566.004 | SIP logs | Recherche de durée d'appels courtes et d'origine géographique atypique associée à des accès comptes. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Technique | AI-Voice Cloning | Vecteur vishing Bluekit | Moyenne |
| Type | Anti-bot bypass | Mécanisme de persistance Bluekit | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566 | Initial Access | Phishing | Utilisation de templates automatisés. |
| T1566.004 | Initial Access | Voice Phishing | Utilisation de clonage de voix via IA. |

---

### Sources

* [Security Affairs](https://securityaffairs.com/191646/cyber-crime/bluekit-phishing-kit-enables-automated-phishing-with-40-templates-and-ai-tools.html)

---

<div id="vk-com-phishing-via-compromised-italian-infrastructure"></div>

## VK.com phishing via compromised Italian infrastructure

---

### Résumé technique

Une campagne de phishing ciblée a été identifiée utilisant le réseau social **VK.com** comme vecteur de distribution. Les attaquants exploitent la fonctionnalité de redirection légitime `away.php` de VK pour rediriger les utilisateurs vers une infrastructure italienne compromise (`aza[.]scia-a-roma[.]it`). Le site héberge une page de connexion frauduleuse conçue pour collecter les identifiants d'utilisateurs. Cette technique permet de contourner les filtres de sécurité qui font confiance aux liens provenant de domaines de réseaux sociaux majeurs.

### Analyse de l'impact

L'impact principal est le vol de comptes, qui peuvent ensuite être utilisés pour des campagnes d'influence ou pour infecter le cercle de confiance des victimes. L'utilisation d'un site institutionnel italien compromis augmente la crédibilité du lien aux yeux de la victime.

### Recommandations

*   Bloquer les URLs suspectes identifiées sur les passerelles web.
*   Éduquer les utilisateurs sur les dangers des redirections via des tiers.
*   Activer le MFA sur tous les comptes de réseaux sociaux.

### Playbook de réponse à incident

#### Phase 1 — Preparation
*   Mettre à jour la base de données de filtrage d'URLs avec les domaines de redirection connus.
*   Configurer l'EDR pour alerter sur les ouvertures de navigateur vers des domaines `.it` inhabituels.

#### Phase 2 — Detection et analyse
*   **Règles de détection :**
    *   Web Proxy : Filtrer les accès contenant `vk.com/away.php?to=http`.
    *   Identifier tout trafic sortant vers `aza[.]scia-a-roma[.]it`.

#### Phase 3 — Confinement, éradication et récupération
*   **Confinement :** Bloquer l'URL spécifique sur les pare-feu.
*   **Éradication :** Nettoyer le cache DNS des postes de travail.
*   **Récupération :** Réinitialiser les mots de passe des utilisateurs ayant cliqué sur le lien.

#### Phase 4 — Activités post-incident
*   Informer le gestionnaire du domaine italien de la compromission de son site.
*   Calculer le nombre d'utilisateurs ayant été exposés via les logs proxy.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Abus de redirection sociale | T1566.002 | Proxy logs | `WebProxy | where Url contains 'away.php' or Url contains 'redirect'` |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | hxxp[://]aza[.]scia-a-roma[.]it/conferma/web/login[.]php | Page de phishing | Haute |
| Domaine | scia-a-roma[.]it | Infrastructure compromise | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566.002 | Initial Access | Spearphishing Link | Utilisation de liens via redirections de réseaux sociaux. |

---

### Sources

* [URLDNA](https://infosec.exchange/@urldna/116519377921115682)

---

<div id="trellix-source-code-repository-compromise"></div>

## Trellix source code repository compromise

---

### Résumé technique

L'éditeur de sécurité **Trellix** a divulgué une violation de données suite à l'intrusion dans l'un de ses dépôts de code source sur **GitHub**. L'accès non autorisé a été facilité par le vol d'identifiants de développeurs, probablement via une attaque de phishing ciblée ou une fuite de tokens. L'attaquant a pu cloner des dépôts contenant du code propriétaire avant que l'accès ne soit révoqué. Trellix a précisé que les produits n'ont pas été altérés ("build integrity" intacte), mais la fuite de code source pose un risque de découverte ultérieure de vulnérabilités par analyse statique ("white-box testing") par des tiers malveillants.

### Analyse de l'impact

L'impact est principalement lié à la propriété intellectuelle et au risque à long terme. La disponibilité du code source permet aux attaquants de rechercher plus efficacement des failles "Zero-day". Cependant, aucun signe d'injection de code malveillant ("supply chain attack") n'a été détecté à ce stade.

### Recommandations

*   Vérifier l'intégrité des produits Trellix via leurs signatures numériques.
*   Auditer les accès aux dépôts GitHub au sein de sa propre organisation.
*   Appliquer une rotation stricte des tokens d'accès CI/CD.

### Playbook de réponse à incident

#### Phase 1 — Preparation
*   Mettre en œuvre un monitoring strict des accès aux dépôts privés (GitHub Audit Logs).
*   Forcer l'utilisation de clés SSH matérielles pour tous les développeurs.

#### Phase 2 — Detection et analyse
*   **Règles de détection :**
    *   Monitorer les clones massifs de dépôts via `GitLogs`.
    *   Alerter sur tout accès aux secrets GitHub depuis des IPs non-VPN.

#### Phase 3 — Confinement, éradication et récupération
*   **Confinement :** Isoler le dépôt compromis et suspendre les comptes développeurs identifiés.
*   **Éradication :** Révoquer tous les secrets, certificats de signature et tokens API présents ou référencés dans le code source compromis.
*   **Récupération :** Ré-analyser l'intégralité du code pour détecter d'éventuelles modifications malveillantes.

#### Phase 4 — Activités post-incident
*   Conduire une investigation forensique sur le poste du développeur initialement compromis.
*   Revoir la politique de gestion des droits tiers sur GitHub.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Exfiltration de code source | T1586.002 | Cloud Audit Logs | `GitLogs | where Action == 'Clone' and Repository in ('private_repos')` |
| Utilisation de tokens volés | T1078.004 | Auth Logs | Recherche de succès de connexion avec des User-Agents atypiques pour des APIs GitHub. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Source | GitHub Repository | Cible de l'attaque | Haute |
| Type | Credential Theft | Vecteur initial | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1586.002 | Resource Development | Cloud Accounts | Utilisation de comptes GitHub compromis. |
| T1078 | Initial Access | Valid Accounts | Accès via identifiants développeurs légitimes. |

---

### Sources

* [BleepingComputer](https://www.bleepingcomputer.com/news/security/trellix-discloses-data-breach-after-source-code-repository-hack/)

---

<!--
CONTRÔLE FINAL

1. ☐ Aucun article n'apparaît dans plusieurs sections : [Vérifié]
2. ☐ La TOC est présente et chaque lien pointe vers une ancre existante : [Vérifié]
3. ☐ Chaque ancre est unique — <div id="..."> statiques ET dynamiques présents, cohérents avec la TOC ET identiques entre TOC / div id / table interne : [Vérifié]
4. ☐ Tous les IoC sont en mode DEFANG : [Vérifié]
5. ☐ Aucun article de Vulnérabilités ou Géopolitique dans la section "Articles" : [Vérifié]
6. ☐ Le tableau des vulnérabilités ne contient que des entrées avec score composite ≥ 1 : [Vérifié]
7. ☐ La table de tri intermédiaire est présente et l'ordre du tableau final correspond ligne par ligne : [Vérifié]
8. ☐ Toutes les sections attendues sont présentes : [Vérifié]
9. ☐ Le playbook est contextualisé (pas de tâches génériques) : [Vérifié]
10. ☐ Les hypothèses de threat hunting sont présentes pour chaque article : [Vérifié]
11. ☐ Tout article sans URL complète disponible dans raw_content est dans "Articles non sélectionnés" — aucun article sans URL complète ne figure dans les synthèses ou la section "Articles" : [Vérifié]
12. ☐ Chaque article est COMPLET (9 sections toutes présentes) — aucun article tronqué : [Vérifié]
13. ☐ Chaque article doit contenir un PLAYBOOK DE REPONSE A INCIDENT avec les 5 phases : [Vérifié]
14. ☐ Aucun bug fonctionnel, article commercial ou contenu non-sécuritaire dans la section "Articles" : [Vérifié]

Statut global : [✅ Rapport valide]
-->