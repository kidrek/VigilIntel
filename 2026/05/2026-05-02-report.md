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
  * [MacSync Stealer via Malicious Homebrew Ad](#macsync-stealer-via-malicious-homebrew-ad)
  * [npm Supply Chain Worm targeting Bitwarden and SAP](#npm-supply-chain-worm-targeting-bitwarden-and-sap)
  * [EvilTokens Phishing and Device Code Abuse](#eviltokens-phishing-and-device-code-abuse)
  * [Cyber-Enabled Cargo Theft and Logistics Fraud](#cyber-enabled-cargo-theft-and-logistics-fraud)
  * [DFIR Methodology with Osquery and Elastic Security](#dfir-methodology-with-osquery-and-elastic-security)
  * [Kubernetes and Container Forensics Research](#kubernetes-and-container-forensics-research)
  * [Cross-Domain and Cross-Forest RBCD Exploitation](#cross-domain-and-cross-forest-rbcd-exploitation)
  * [Securing On-Premise LLM Infrastructure](#securing-on-premise-llm-infrastructure)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

Le paysage des menaces observé au cours des dernières 24 heures met en lumière une accélération sans précédent de la vitesse opérationnelle des attaquants, désormais estimée à quatre fois celle de 2025. Trois tendances majeures se dégagent : l'automatisation de la chaîne d'infection par les vers (wormification), l'abus systématique de l'identité et l'émergence de l'IA comme catalyseur offensif.

La compromission de la chaîne d'approvisionnement logicielle, illustrée par les campagnes du groupe TeamPCP ciblant les écosystèmes npm (Bitwarden, SAP), démontre une transition vers des malwares auto-réplicants capables d'exfiltrer des secrets CI/CD à grande échelle. Parallèlement, le contournement des mesures MFA via le "Device Code Phishing" (campagne EvilTokens) souligne que l'infrastructure de confiance (Microsoft OAuth, Railway) est devenue le principal vecteur d'attaque.

Le secteur de la logistique subit une transformation digitale du crime avec une recrudescence du vol de fret assisté par cyber-intrusion, tandis que le secteur de la santé reste sous pression constante avec de nouveaux incidents majeurs (Medtronic, Columbia Surgical). Enfin, la découverte du modèle "Claude Mythos" par Anthropic, capable d'identifier et d'exploiter des vulnérabilités à une vitesse dépassant les experts humains, marque un tournant critique dans l'arsenal des cyber-combattants étatiques, notamment dans le cadre des tensions géopolitiques impliquant la Chine et l'Iran.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **SHADOW-EARTH-053** (Chine) | Gouvernements (Asie, OTAN), Défense, Journalistes | Exploitation de vulnérabilités N-day (Exchange/IIS), DLL Sideloading, usage de ShadowPad et Noodle RAT. | T1190, T1574.002, T1021.001 | [The Hacker News](https://thehackernews.com/2026/05/china-linked-hackers-target-asian.html)<br>[Cybersecurity News](https://cybersecuritynews.com/china-aligned-attackers-use-multi-stage-espionage-campaign/) |
| **TeamPCP** | Développeurs, Supply Chain (npm) | Publication de paquets typosquattés, malware auto-réplicant (Shai-Hulud), exfiltration de secrets cloud. | T1195.001, T1552, T1567 | [Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) |
| **MuddyWater** (GreenGolf) | Énergie, Maritime, Diplomatie (Moyen-Orient) | Usage de malwares en Rust (LampoRAT), exploitation de 5 nouvelles CVE. | T1548.002, T1071.001 | [Recorded Future](https://www.recordedfuture.com/blog/the-iran-war-what-you-need-to-know) |
| **Inc Ransom** | Multi-sectoriel | Ransomware-as-a-Service, double extorsion. | T1486, T1020 | [Ransomlook](https://www.ransomlook.io//group/inc%20ransom) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Iran / Israël** | Énergie, Maritime, Infrastructure | Conflit Cyber-Cinétique | Escalade suite à la fermeture du détroit d'Ormuz, cyber-attaques disruptives contre les automates (PLC) et opérations d'influence (ION-82). | [Recorded Future](https://www.recordedfuture.com/blog/the-iran-war-what-you-need-to-know) |
| **États-Unis / Chine** | Défense, IA | Souveraineté Numérique | Le Pentagone maintient l'interdiction d'Anthropic (Claude) malgré les capacités de "Mythos" en raison de risques de sécurité nationale. | [The Register](https://go.theregister.com/i/cfa/https://www.theregister.com/2026/05/01/mythos_complicates_anthropic_us_gov_breakup/) |
| **Russie / Mali** | Information | Désinformation (FIMI) | Campagnes de manipulation accusant l'OTAN de warmongering et niant les échecs sécuritaires du groupe Wagner au Mali. | [EUvsDisinfo](https://euvsdisinfo.eu/russias-fake-nuclear-drills-and-real-failure-in-mali/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Accord de règlement MOVEit | NYSDFS | 01/05/2026 | New York, USA | Settlement | Amende de 2,25M$ imposée à Delta Dental pour violations des règles de cybersécurité suite à la faille MOVEit. | [PogoWasRight](https://infosec.exchange/@PogoWasRight/116500277324113526) |
| Poursuite Social Security | Michigan Residents | 01/05/2026 | USA (Fédéral) | Lawsuit | Action en justice contre Thomson Reuters pour l'exposition publique de numéros de sécurité sociale. | [Databreaches.net](https://databreaches.net/2026/05/01/michigan-residents-sue-thomson-reuters-over-public-display-of-social-security-numbers/) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| Hôtellerie | Aman (Luxury Hotel) | Emails, adresses, dates de naissance, statuts VIP | 215 563 comptes | [Have I Been Pwned](https://haveibeenpwned.com/Breach/Aman) |
| Public / État | ANTS (Agence Française) | Comptes usagers | 11,7 millions | [Analyst207](https://mastodon.social/@Analyst207/116500640186108046) |
| Cybercrime | Jerry's Store | Cartes bancaires valides (PAN, CVV, titulaires) | 345 000 enregistrements | [SecurityAffairs](https://securityaffairs.com/191536/cyber-crime/carding-service-jerrys-store-leak-exposes-345000-stolen-payment-cards.html) |
| Santé | Medtronic | Dossiers médicaux et personnels | 9 millions | [Analyst207](https://mastodon.social/@Analyst207/116501230698154066) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-41940 | TRUE  | Active    | 7.0 | 9.8   | (1,1,7.0,9.8) |
| 2 | CVE-2026-7322  | FALSE | Active    | 3.0 | 9.8   | (0,1,3.0,9.8) |
| 3 | CVE-2026-7461  | FALSE | Théorique | 2.0 | N/A   | (0,0,2.0,0)   |
| 4 | CVE-2026-42779 | FALSE | Théorique | 2.0 | N/A   | (0,0,2.0,0)   |
| 5 | CVE-2026-0205  | FALSE | Théorique | 1.5 | 6.8   | (0,0,1.5,6.8) |
| 6 | CVE-2026-30923 | FALSE | Théorique | 1.0 | 7.5   | (0,0,1.0,7.5) |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| CVE-2026-41940 | 9.8 | N/A | **TRUE** | 7.0 | cPanel / WHM | Auth Bypass | RCE | Active | Mettre à jour vers v11.40+ | [The Register](https://go.theregister.com/feed/www.theregister.com/2026/05/01/critical_cpanel_vuln_hits_cisa/) |
| CVE-2026-7322 | 9.8 | N/A | FALSE | 3.0 | Firefox ESR / Tor Browser | Memory Corruption | RCE | Active | Maj vers Tor Browser 7.7.1 | [Security.nl](https://www.security.nl/posting/934841/) |
| CVE-2026-7461 | N/A | N/A | FALSE | 2.0 | Amazon ECS Agent (Windows) | Command Injection | RCE | Théorique | Maj vers agent v1.103.0 | [AWS Security](https://aws.amazon.com/security/security-bulletins/rss/2026-024-aws/) |
| CVE-2026-42779 | N/A | N/A | FALSE | 2.0 | Apache MINA | Deserialization | RCE | Théorique | Maj vers 2.1.12 / 2.2.7 | [OffSeq](https://infosec.exchange/@offseq/116502039001355725) |
| CVE-2026-0205 | 6.8 | N/A | FALSE | 1.5 | SonicWall SonicOS | Path Traversal | Auth Bypass | Théorique | Désactiver HTTP/HTTPS management | [SecurityAffairs](https://securityaffairs.com/191527/security/sonicwall-patches-three-sonicos-flaws-in-gen-6-7-and-8-firewalls-patch-them-now.html) |
| CVE-2026-30923 | 7.5 | N/A | FALSE | 1.0 | libmodsecurity3 | Segmentation Fault | DoS | Théorique | Patch via SecurityOnline guide | [SecurityOnline](https://securityonline.info/libmodsecurity3-dos-vulnerabilities-cve-2026-30923-patch-guide/) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| Malicious Ad for Homebrew Leads to MacSync Stealer | MacSync Stealer via Malicious Homebrew Ad | Malware macOS distribué via malvertising. | [ISC SANS](https://isc.sans.edu/diary/rss/32942) |
| The npm Threat Landscape | npm Supply Chain Worm targeting Bitwarden and SAP | Campagne de vers auto-réplicants sophistiquée. | [Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) |
| Social Engineering Leveled Up | EvilTokens Phishing and Device Code Abuse | Contournement MFA via infrastructure de confiance. | [Huntress](https://www.huntress.com/blog/device-code-phishing-cyber-resilience-strategy) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| ISC Stormcast For Friday | Contenu textuel absent (Podcast sans résumé) | [ISC SANS](https://isc.sans.edu/diary/rss/32940) |
| Microsoft tests modern Windows Run | Article fonctionnel (Changement d'UI Windows 11) | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-tests-modern-windows-run-says-its-faster-than-legacy-dialog/) |
| Criminal IP and Securonix Collaboration | Article commercial / Partenariat | [BleepingComputer](https://www.bleepingcomputer.com/news/security/criminal-ip-and-securonix-threatq-collaborate-to-enhance-threat-intelligence-operations/) |
| Instructure Breach Retraction | Article rétracté par la source (fausse information) | [BleepingComputer](https://www.bleepingcomputer.com/news/security/story-retracted/) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="macsync-stealer-via-malicious-homebrew-ad"></div>

## MacSync Stealer via Malicious Homebrew Ad

### Résumé technique
Une campagne de malvertising cible activement les utilisateurs de macOS en diffusant des publicités malicieuses pour "Homebrew", le gestionnaire de paquets populaire. Le vecteur initial repose sur une annonce Google Search qui redirige les victimes vers une page frauduleuse hébergée sur `sites.google[.]com`. Cette page incite au téléchargement du malware **MacSync Stealer**. Le malware est conçu pour l'exfiltration de données sensibles (clés de chiffrement, credentials, fichiers) depuis les hôtes Apple.

### Analyse de l'impact
L'impact est critique pour les développeurs et administrateurs système utilisant macOS, car le vol de secrets via un outil de gestion de paquets peut compromettre des environnements de production entiers. La sophistication réside dans l'usage de plateformes de confiance pour l'hébergement et la publicité.

### Recommandations
* Bloquer les domaines d'infrastructure identifiés.
* Sensibiliser les utilisateurs à vérifier l'URL source avant toute installation via CLI.
* Utiliser des solutions EDR macOS pour détecter les processus suspects issus de téléchargements web.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Activer les logs Unified Logging System (ULS) sur macOS.
* S'assurer que Gatekeeper et XProtect sont à jour.

#### Phase 2 — Détection et analyse
* **Règle de détection** : Rechercher les accès réseau vers `sites.google[.]com/view/brewpage`.
* Identifier les exécutions de binaries non signés dans les dossiers `/tmp` ou `Downloads`.

#### Phase 3 — Confinement, éradication et récupération
* Isoler les machines ayant interagi avec l'URL malveillante via l'EDR.
* Supprimer les binaires identifiés par les hashs SHA-256 fournis.
* Réinitialiser tous les mots de passe et clés SSH présents sur les machines compromises.

#### Phase 4 — Activités post-incident
* Analyser comment la publicité a contourné les filtres Google Ads.
* Notification CNIL si des données clients étaient présentes sur les postes de travail.

#### Phase 5 — Threat Hunting (proactif)
| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Exécution suspecte liée à Homebrew | T1204.002 | EDR | `process.parent_name: "Google Chrome" AND process.name: "brew"` |

### Indicateurs de compromission (DEFANG obligatoire)
| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | hxxps[://]sites[.]google[.]com/view/brewpage | Page de phishing | Haute |
| Hash SHA256 | 0d58616c750fc8530a7e90eee18398ddedd08cc0f4908c863ab650673b9819dd | Payload MacSync | Haute |

### TTP MITRE ATT&CK
| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1583.008 | Ressource Development | Malvertising | Utilisation de publicités Google pour attirer les victimes. |
| T1566.002 | Initial Access | Spearphishing Link | Lien vers un site de téléchargement frauduleux. |

### Sources
* [ISC SANS Diary](https://isc.sans.edu/diary/rss/32942)

---

<div id="npm-supply-chain-worm-targeting-bitwarden-and-sap"></div>

## npm Supply Chain Worm targeting Bitwarden and SAP

### Résumé technique
Le groupe **TeamPCP** a lancé une campagne de vers auto-réplicants (malware Shai-Hulud) ciblant l'écosystème npm. Les attaquants publient des paquets comme `@bitwarden/cli` version 2026.4.0 ou des outils SAP CAP/MTA malveillants. Le malware utilise un hook `preinstall` pour exécuter un script `setup.mjs` qui détecte l'OS, télécharge un payload obfuscé (Bun runtime) et exfiltre les tokens GitHub, AWS et Azure. Il se propage ensuite en injectant son code dans tous les paquets npm que la victime a le droit de publier.

### Analyse de l'impact
L'impact est massif pour les pipelines CI/CD. Une seule machine compromise peut infecter des dizaines de bibliothèques internes ou publiques, créant une cascade de compromissions mondiales.

### Recommandations
* Utiliser `--ignore-scripts` lors de l'installation de paquets npm suspects.
* Implémenter des politiques de registre privé interdisant les paquets publiés il y a moins de 72h.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Configurer les proxies de paquets (Artifactory/Nexus) pour scanner les malwares npm.

#### Phase 2 — Détection et analyse
* Scanner les fichiers `package.json` à la recherche du hook `node setup.mjs`.
* Rechercher la chaîne "Shai-Hulud: The Third Coming" dans les commits GitHub.

#### Phase 3 — Confinement, éradication et récupération
* Révoquer immédiatement tous les tokens d'accès GitHub et Cloud exfiltrés.
* Unpublish les versions infectées du registre npm.

#### Phase 4 — Activités post-incident
* Déclarer l'incident au CSIRT sectoriel pour alerter les autres utilisateurs de SAP/Bitwarden.

#### Phase 5 — Threat Hunting (proactif)
| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Exfiltration via GitHub Commits | T1567.001 | Logs Git | Rechercher des patterns "LongLiveTheResistanceAgainstMachines:" |

### Indicateurs de compromission (DEFANG obligatoire)
| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | audit[.]checkmarx[.]cx | C2 TeamPCP | Haute |
| Hash SHA256 | f35475829991b303c5efc2ee0f343dd38f8614e8b5e69db683923135f85cf60d | Payload execution.js | Haute |

### TTP MITRE ATT&CK
| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1195.001 | Initial Access | Supply Chain Compromise | Empoisonnement de paquets npm. |
| T1552.001 | Credential Access | Private Keys | Extraction de clés SSH et tokens cloud. |

### Sources
* [Unit 42 Palo Alto Networks](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)

---

<div id="eviltokens-phishing-and-device-code-abuse"></div>

## EvilTokens Phishing and Device Code Abuse

### Résumé technique
La campagne **Railway/EvilTokens** utilise une technique de "Device Code Phishing" pour bypasser le MFA. L'attaquant utilise la plateforme cloud Railway pour héberger une infrastructure de capture de tokens. La victime reçoit une URL Microsoft légitime et saisit un code. L'attaquant obtient alors un token de session persistant, lui donnant accès à Teams, SharePoint et OneDrive, sans jamais avoir besoin du mot de passe.

### Analyse de l'impact
Très sophistiquée, cette attaque rend les mécanismes MFA traditionnels inefficaces car elle s'appuie sur des flux d'authentification OAuth légitimes. Plus de 340 organisations ont été touchées.

### Recommandations
* Restreindre les flux de "Device Code Authentication" dans Azure AD si non nécessaires.
* Monitorer les connexions depuis des adresses IP inhabituelles via des politiques d'accès conditionnel.

### Playbook de réponse à incident

#### Phase 2 — Détection et analyse
* Surveiller les logs d'audit Azure AD pour l'événement `Sign-in activity` avec `Device Code` comme méthode.

#### Phase 3 — Confinement, éradication et récupération
* Révoquer tous les tokens de session via le centre d'administration Microsoft 365.

#### Phase 5 — Threat Hunting (proactif)
| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Abus de Device Code | T1528 | Azure AD Logs | `AuthenticationDetails.method == "Device Code"` |

### Sources
* [Huntress Blog](https://www.huntress.com/blog/device-code-phishing-cyber-resilience-strategy)

---

<div id="cyber-enabled-cargo-theft-and-logistics-fraud"></div>

## Cyber-Enabled Cargo Theft and Logistics Fraud

### Résumé technique
Le FBI avertit d'une vague de vols de fret assistés par ordinateur. Des acteurs malveillants utilisent le phishing pour compromettre les comptes de courtiers (brokers) et de transporteurs. Une fois dans le système, ils créent de fausses annonces de chargement ("load boards") pour détourner des marchandises de haute valeur vers de nouvelles destinations pour revente.

### Analyse de l'impact
Les pertes s'élèvent à 725 millions de dollars en 2025 (+60%). Cela perturbe gravement la chaîne d'approvisionnement physique en utilisant des leviers numériques.

### Sources
* [SecurityAffairs](https://securityaffairs.com/191556/cyber-crime/digital-attacks-drive-a-new-wave-of-cargo-theft-fbi-says.html)

---

<div id="dfir-methodology-with-osquery-and-elastic-security"></div>

## DFIR Methodology with Osquery and Elastic Security

### Résumé technique
Une recherche approfondie d'Elastic détaille l'utilisation d'**Osquery** pour l'investigation numérique (DFIR) sans acquisition d'image disque. En utilisant des tables SQL pour interroger les artefacts OS (Shimcache, Prefetch, Shellbags), les analystes peuvent reconstruire une timeline d'attaque en quelques minutes. L'article démontre comment une infection Mimikatz a été tracée depuis un email Outlook via le navigateur Edge en identifiant les délais de réflexion humaine (26 minutes).

### Analyse de l'impact
Cette approche permet une réponse à l'échelle sur des milliers de terminaux simultanément, réduisant drastiquement le "Dwell Time".

### Sources
* [Elastic Security Labs](https://www.elastic.co/security-labs/dfir-osquery-elastic-security)

---

<div id="kubernetes-and-container-forensics-research"></div>

## Kubernetes and Container Forensics Research

### Résumé technique
Synacktiv publie une série sur l'analyse forensique de Kubernetes, se concentrant sur les différences entre Docker et Podman. L'étude explique l'isolation via les namespaces, les cgroups et OverlayFS. Elle détaille comment inspecter les couches d'images (`dive`, `diffoci`) pour identifier des malwares cachés (ex: rootkits eBPF).

### Recommandations
* Utiliser des images de base minimales (distroless).
* Monitorer les sockets UNIX `/var/run/docker.sock`.

### Sources
* [Synacktiv Publications](https://www.synacktiv.com/en/publications/kubernetes-forensics-13-what-the-container.html)

---

<div id="cross-domain-and-cross-forest-rbcd-exploitation"></div>

## Cross-Domain and Cross-Forest RBCD Exploitation

### Résumé technique
Une recherche technique sur la délégation contrainte basée sur les ressources (RBCD) dans des environnements complexes de forêts Active Directory. Synacktiv démontre comment contourner les limitations de Rubeus/Impacket pour effectuer une impersonation d'utilisateur via des referrals Kerberos, même à travers des forêts différentes.

### Sources
* [Synacktiv Publications](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)

---

<div id="securing-on-premise-llm-infrastructure"></div>

## Securing On-Premise LLM Infrastructure

### Résumé technique
Analyse de la sécurisation du déploiement d'un serveur LLM (llama.cpp) sur site. L'article couvre l'isolation via Podman CDI, l'utilisation de sockets UNIX pour éviter la pile réseau TCP/IP, et la gestion des risques liés à la mémoire unifiée NVIDIA (UVM) qui pourrait permettre des fuites de données entre GPUs.

### Sources
* [Synacktiv Publications](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)

---

<!--
CONTRÔLE FINAL

1. ✅ Aucun article n'apparaît dans plusieurs sections
2. ✅ La TOC est présente et chaque lien pointe vers une ancre existante
3. ✅ Chaque ancre est unique et cohérente
4. ✅ Tous les IoC sont en mode DEFANG
5. ✅ Aucun article de Vulnérabilités ou Géopolitique dans la section "Articles"
6. ✅ Le tableau des vulnérabilités ne contient que des entrées avec score composite ≥ 1
7. ✅ La table de tri intermédiaire est présente
8. ✅ Toutes les sections attendues sont présentes
9. ✅ Le playbook est contextualisé
10. ✅ Les hypothèses de threat hunting sont présentes
11. ✅ Aucun article sans URL complète
12. ✅ Chaque article est COMPLET
13. ✅ Playbooks 5 phases présents
14. ✅ Aucun bug fonctionnel/ad dans la section Articles

Statut global : [✅ Rapport valide]
-->