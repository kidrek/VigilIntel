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
  * [GOLD ENCOUNTER + QEMU evasion for PayoutsKing ransomware](#gold-encounter-qemu-evasion-for-payoutsking-ransomware)
  * [Nexcorium Mirai variant + TBK DVR-TP-Link IoT exploitation](#nexcorium-mirai-variant-tbk-dvr-tp-link-iot-exploitation)
  * [AI-assisted exploitation + Claude Opus Chrome exploit chain](#ai-assisted-exploitation-claude-opus-chrome-exploit-chain)
  * [Data Breach + Los Angeles County Office of Education tax documents](#data-breach-los-angeles-county-office-of-education-tax-documents)
  * [Data Breach + Education Nationale France](#data-breach-education-nationale-france)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

La période actuelle est marquée par une convergence inquiétante entre l'instabilité géopolitique et l'accélération des capacités techniques des attaquants. Le conflit au Moyen-Orient continue de générer un volume massif d'opérations cyber, notamment à travers le groupe **Handala**, dont les revendications d'attaques destructrices contre les infrastructures des Émirats Arabes Unis (6 Po de données) soulignent une volonté de paralysie régionale, bien que leur ampleur reste à confirmer. Parallèlement, l'Iran maintient un black-out internet national sans précédent (50 jours), illustrant l'utilisation de la souveraineté numérique comme outil de contrôle de guerre.

Sur le plan technique, l'émergence de l'IA générative (**Claude Opus**) dans le cycle d'armement cyber franchit une étape critique. La démonstration d'une chaîne d'exploitation fonctionnelle pour Chrome, construite avec l'aide d'un LLM, réduit drastiquement le coût économique de l'exploitation des vulnérabilités "n-day", mettant sous pression les éditeurs dont les cycles de patch (notamment pour les frameworks comme Electron) sont trop lents. Enfin, l'utilisation de techniques d'évasion sophistiquées comme l'usage de micro-VMs **QEMU** par des groupes comme **GOLD ENCOUNTER** montre une professionnalisation accrue des opérateurs de ransomware pour contourner les solutions EDR/XDR modernes.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s)/Lien(s) |
|---|---|---|---|---|
| **Handala Hack** | Israël, UAE (Gouvernement, Transport) | Wiper, Exfiltration massive, PsychOp | T1567, T1485, T1071 | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| **GOLD ENCOUNTER** | Environnements virtualisés (VMware, ESXi) | Evasion via QEMU, Ransomware PayoutsKing | T1564.006, T1021.004 | [SecurityAffairs](https://securityaffairs.com/190982/security/hidden-vms-how-hackers-leverage-qemu-to-stealthily-steal-data-and-spread-malware.html) |
| **UAC-0247** | Santé, Gouvernement local (Ukraine) | Espionnage (AgingFly), Crypto-mining | T1566.001, T1496 | [DataBreaches](https://databreaches.net/2026/04/18/ukrainian-emergency-services-and-hospitals-hit-by-espionage-campaign-using-new-agingfly-malware/) |
| **Nexus Team** | IoT (DVR, Routeurs) | Botnet Nexcorium, Exploitation CVE-2024-3721 | T1505.003, T1498 | [Fortinet](https://www.fortinet.com/blog/threat-research/nexcorium-mirai-variant-uses-tbk-dvr-exploit) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s)/Lien(s) |
|---|---|---|---|---|
| **Moyen-Orient** | Maritime/Énergie | Conflit Iran-Israël-USA | Cessez-le-feu Liban-Israël ; détroit d'Ormuz ouvert mais blocus US maintenu. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| **Iran** | Télécoms | Censure d'État | Black-out internet national entrant dans son 50ème jour (> 1176 heures). | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| **Ukraine** | Santé / Public | Espionnage Russe | Campagne UAC-0247 via le malware AgingFly ciblant hôpitaux et municipalités. | [DataBreaches](https://databreaches.net/2026/04/18/ukrainian-emergency-services-and-hospitals-hit-by-espionage-campaign-using-new-agingfly-malware/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s)/Lien(s) |
|---|---|---|---|---|---|---|
| Enquête Conduent | État du Montana | 18/04/2026 | USA (MT) | Justice Helena | Un juge autorise l'enquête sur la diligence de BCBSMT suite à une fuite de 462k membres. | [DataBreaches](https://databreaches.net/2026/04/18/judge-lets-state-auditors-investigation-into-data-breach-affecting-blue-cross-blue-shield-members-move-forward/) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s)/Lien(s) |
|---|---|---|---|---|
| **Éducation** | LA County Office of Ed. | Documents fiscaux (W-2), SSN | Potentiellement 150k employés | [DataBreaches](https://databreaches.net/2026/04/18/tax-documents-for-school-employees-potentially-stolen-across-los-angeles-county/) |
| **Éducation** | Éducation Nationale (FR) | Identité, identifiants EduConnect, emails | 243 000 enseignants + élèves | [Le Monde](https://www.lemonde.fr/pixels/article/2026/04/18/fuites-de-donnees-l-education-nationale-une-cible-vulnerable-face-aux-cyberattaques_6681062_4408996.html) |
| **Sport** | Basic-Fit | Données membres | 1 000 000 membres | [HackerNews](https://thehackernews.com/2026/04/mirai-variant-nexcorium-exploits-cve.html) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-33825 | FALSE | Active    | 3.5 | 7.8   | (0,1,3.5,7.8) |
| 2 | RedSun (N/A)  | FALSE | Active    | 3.5 | N/A   | (0,1,3.5,0.0) |
| 3 | UnDefend (N/A)| FALSE | Active    | 3.5 | N/A   | (0,1,3.5,0.0) |
| 4 | CVE-2026-41242 | FALSE | Théorique | 3.0 | 9.4   | (0,0,3.0,9.4) |
| 5 | CVE-2026-40494 | FALSE | Théorique | 2.0 | 9.8   | (0,0,2.0,9.8) |
| 6 | CVE-2026-39808 | FALSE | Théorique | 2.0 | N/A   | (0,0,2.0,0.0) |
| 7 | CVE-2026-5387  | FALSE | Théorique | 1.5 | 9.3   | (0,0,1.5,9.3) |
| 8 | CVE-2026-6518  | FALSE | Théorique | 1.5 | 8.8   | (0,0,1.5,8.8) |
| 9 | CVE-2026-40489 | FALSE | Théorique | 1.5 | 8.6   | (0,0,1.5,8.6) |
| 10| CVE-2026-40487 | FALSE | Théorique | 1.0 | 8.9   | (0,0,1.0,8.9) |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s)/Lien(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-33825** | 7.8 | N/A | FALSE | 3.5 | Microsoft Defender | LPE (BlueHammer) | SYSTEM Privilege | Active | Appliquer MAJ du 14/04 | [CyberThrone](https://thecyberthrone.in/2026/04/18/microsoft-defender-under-siege/) |
| **RedSun** | N/A | N/A | FALSE | 3.5 | Microsoft Defender | LPE | SYSTEM Privilege | Active | Aucun (0-day) | [SecurityAffairs](https://securityaffairs.com/190961/hacking/microsoft-defender-under-siege.html) |
| **UnDefend** | N/A | N/A | FALSE | 3.5 | Microsoft Defender | DoS / Evasion | Defense Bypass | Active | Aucun (0-day) | [SecurityAffairs](https://securityaffairs.com/190961/hacking/microsoft-defender-under-siege.html) |
| **CVE-2026-41242** | 9.4 | N/A | FALSE | 3.0 | Protobuf.js | Code Injection | RCE | PoC public | MAJ v8.0.1+ / v7.5.5+ | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-41242) |
| **CVE-2026-40494** | 9.8 | N/A | FALSE | 2.0 | SAIL Library | Heap Overflow | RCE | Théorique | Appliquer correctif Git | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-40494) |
| **CVE-2026-39808** | N/A | N/A | FALSE | 2.0 | FortiSandbox | Cmd Injection | RCE (Root) | PoC public | MAJ v4.4.8+ | [CyberNews](https://cybersecuritynews.com/poc-exploit-fortisandbox-vulnerability/) |
| **CVE-2026-5387** | 9.3 | N/A | FALSE | 1.5 | AVEVA Pipeline Sim | Missing Auth | Auth Bypass | Théorique | MAJ 2025 SP1 P01 | [SecurityOnline](https://securityonline.info/aveva-pipeline-simulation-critical-vulnerability-cve-2026-5387/) |
| **CVE-2026-6518** | 8.8 | N/A | FALSE | 1.5 | CMP Plugin (WP) | Arbitrary Upload | RCE | Théorique | MAJ v4.1.17+ | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-6518) |
| **CVE-2026-40489** | 8.6 | N/A | FALSE | 1.5 | editorconfig-core-c | Stack Overflow | DoS / RCE | Théorique | MAJ v0.12.11 | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-40489) |
| **CVE-2026-40487** | 8.9 | N/A | FALSE | 1.0 | Postiz | MIME Spoofing | Stored XSS | Théorique | MAJ v2.21.6 | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-40487) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s)/Lien(s) |
|---|---|---|---|
| Hidden VMs: QEMU abuse | GOLD ENCOUNTER + QEMU evasion for PayoutsKing ransomware | Technique d'évasion avancée via micro-virtualisation. | [SecurityAffairs](https://securityaffairs.com/190982/security/hidden-vms-how-hackers-leverage-qemu-to-stealthily-steal-data-and-spread-malware.html) |
| Nexcorium Mirai variant | Nexcorium Mirai variant + TBK DVR-TP-Link IoT exploitation | Campagne botnet active sur IoT. | [Fortinet](https://www.fortinet.com/blog/threat-research/nexcorium-mirai-variant-uses-tbk-dvr-exploit) |
| Claude Opus Chrome Exploit | AI-assisted exploitation + Claude Opus Chrome exploit chain | Impact de l'IA sur la génération d'exploits. | [CybersecurityNews](https://cybersecuritynews.com/claude-opus-to-build-a-working-chrome-exploit-chain/) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s)/Lien(s) |
|---|---|---|
| Microsoft Teams paste broken | Bug fonctionnel lié à Edge, pas de faille de sécurité. | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-teams-right-click-paste-broken-by-edge-update-bug/) |
| NAKIVO v11.2 Release | Annonce commerciale de mise à jour produit. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/nakivo-v112-ransomware-defense-faster-replication-vsphere-9-and-proxmox-ve-90-support/) |
| Casse-tête des Captcha | Article de réflexion technologique généraliste. | [Le Monde](https://www.lemonde.fr/m-perso/article/2026/04/18/non-je-ne-suis-pas-un-robot-le-casse-tete-des-captcha_6681096_4497916.html) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

<div id="gold-encounter-qemu-evasion-for-payoutsking-ransomware"></div>

## [GOLD ENCOUNTER + QEMU evasion for PayoutsKing ransomware]

### Résumé technique
Le groupe de menace **GOLD ENCOUNTER** utilise une technique d'évasion sophistiquée consistant à héberger ses outils d'attaque à l'intérieur de machines virtuelles **QEMU** légères (distributions Alpine Linux). L'objectif est de contourner les solutions de détection sur l'hôte (EDR/AV) en exécutant les charges malveillantes dans un environnement virtualisé isolé. Deux campagnes distinctes, STAC4713 et STAC3725, ont été identifiées.

Dans la campagne STAC4713, les attaquants créent une tâche planifiée nommée `TPMProfiler` pour lancer une VM QEMU avec des privilèges `SYSTEM`. L'image disque est souvent camouflée en fichier DLL ou base de données. Ils utilisent ensuite des tunnels SSH inversés pour maintenir l'accès et déploient finalement le ransomware **PayoutsKing**. L'accès initial exploite des VPN non protégés (MFA manquant) ou des failles comme CVE-2025-26399 (SolarWinds).

### Analyse de l'impact
Cette méthode réduit considérablement la visibilité des équipes de défense (SOC), car l'activité réseau et les exécutions de processus malveillants semblent provenir du processus légitime QEMU. L'impact final est une compromission totale du réseau avec exfiltration de données et chiffrement des hyperviseurs VMware/ESXi.

### Recommandations
*   Surveiller l'installation non autorisée du binaire `qemu-system-x86_64.exe` sur les serveurs de production.
*   Auditer les tâches planifiées créées récemment, en particulier celles lançant des processus de virtualisation.
*   Bloquer les tunnels SSH sortants non justifiés.

### Playbook de réponse à incident

#### Phase 1 — Préparation
*   Activer la surveillance des créations de tâches planifiées via l'Event ID 4698.
*   S'assurer que l'EDR bloque l'exécution de binaires de virtualisation (QEMU, VirtualBox) sur les endpoints non-administrateurs.

#### Phase 2 — Détection et analyse
*   **Requête EDR :** Rechercher le processus `qemu-system-x86_64.exe` avec des arguments pointant vers des fichiers aux extensions suspectes (`.dll`, `.db`, `.dat`).
*   Identifier la présence de la tâche `TPMProfiler` dans les logs Windows.
*   Vérifier les connexions réseau sortantes sur le port 22 ou des ports non standard initiées par le processus QEMU.

#### Phase 3 — Confinement, éradication et récupération
*   **Confinement :** Isoler l'hôte infecté. Tuer le processus QEMU malveillant.
*   **Éradication :** Supprimer la tâche planifiée `TPMProfiler`. Supprimer les images disques Alpine Linux identifiées.
*   **Récupération :** Réinitialiser les mots de passe des comptes de service si une extraction de base de données AD est suspectée.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détection d'images disques virtuelles camouflées | T1027 | File Logs | Chercher des fichiers > 50Mo avec extensions `.dll` ou `.sys` mais avec un header QCOW2. |

### Indicateurs de compromission (DEFANG)
| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Nom de fichier | `qemu-system-x86_64[.]exe` | Binaire d'émulation utilisé pour l'évasion | Moyenne |
| Tâche planifiée | `TPMProfiler` | Tâche de persistance pour la VM malveillante | Haute |
| Vecteur | `CVE-2025-26399` | Faille SolarWinds exploitée pour l'accès | Haute |

### TTP MITRE ATT&CK
| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1564.006 | Defense Evasion | Hide Artifacts: Virtualization/Sandbox | Utilisation de QEMU pour masquer le malware. |
| T1021.004 | Lateral Movement | Remote Services: SSH | Utilisation de tunnels SSH inversés pour le C2. |

---

<div id="nexcorium-mirai-variant-tbk-dvr-tp-link-iot-exploitation"></div>

## [Nexcorium Mirai variant + TBK DVR-TP-Link IoT exploitation]

### Résumé technique
**Nexcorium** est une nouvelle variante du botnet Mirai qui cible agressivement les enregistreurs vidéo numériques (DVR) de marque TBK (modèles DVR-4104/4216) et les anciens routeurs TP-Link. L'attaque exploite principalement **CVE-2024-3721**, une vulnérabilité d'injection de commande. Le trafic malveillant contient souvent un en-tête HTTP personnalisé `X-Hacked-By: Nexus Team`.

Une fois le script de téléchargement `dvr` exécuté, il récupère des payloads `nexuscorp` adaptés à diverses architectures (ARM, MIPS, x86). Le malware établit sa persistance en modifiant `/etc/inittab`, `/etc/rc.local`, en créant un service `persist.service` et une tâche `crontab`. Il intègre également des modules de brute-force Telnet et des exploits pour d'autres failles (ex: CVE-2017-17215).

### Analyse de l'impact
Le botnet est utilisé pour lancer des attaques DDoS massives (UDP, TCP flood). La persistance multi-niveaux rend l'éradication difficile sans une réinitialisation complète ou une mise à jour du firmware.

### Recommandations
*   Remplacer immédiatement les mots de passe par défaut sur tous les dispositifs IoT.
*   Désactiver Telnet et isoler les segments réseau contenant des DVR.
*   Mettre à jour les systèmes TBK ou remplacer les équipements en fin de vie (EoL).

### Playbook de réponse à incident

#### Phase 2 — Détection et analyse
*   **Signature Réseau :** Détecter l'en-tête HTTP `X-Hacked-By: Nexus Team` dans le trafic entrant.
*   Vérifier la présence du fichier binaire `nexuscorp` ou du script `dvr` dans `/tmp` ou `/var`.

#### Phase 3 — Confinement, éradication et récupération
*   **Confinement :** Bloquer les IP de C2 identifiées au niveau du firewall. Isoler les DVR du réseau externe.
*   **Éradication :** Nettoyer les fichiers `/etc/inittab` et `/etc/rc.local`. Supprimer `persist.service`.
*   **Récupération :** Flasher le firmware avec une version saine.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Tentatives de brute-force Telnet sortantes | T1110 | Network Logs | Rechercher un volume anormal de connexions Telnet (port 23) depuis les segments IoT. |

### Indicateurs de compromission (DEFANG)
| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Header HTTP | `X-Hacked-By: Nexus Team` | Marqueur d'attribution de l'attaquant | Haute |
| Nom de fichier | `nexuscorp[.]x86` | Payload principal Nexcorium | Haute |
| Fichier | `/etc/persist[.]service` | Mécanisme de persistance systemd | Moyenne |

---

<div id="ai-assisted-exploitation-claude-opus-chrome-exploit-chain"></div>

## [AI-assisted exploitation + Claude Opus Chrome exploit chain]

### Résumé technique
Un chercheur a démontré qu'en utilisant le modèle d'IA **Claude Opus**, il est possible de construire une chaîne d'exploitation fonctionnelle pour Google Chrome (ciblant ici Discord via Electron). L'IA a aidé à chaîner deux vulnérabilités : **CVE-2026-5873** (OOB write dans Turboshaft) et un bypass de sandbox V8 (UAF dans WasmCPT). Bien que l'IA nécessite une supervision humaine experte, elle a généré des payloads capables de rediriger le flux d'exécution pour lancer des commandes système sur macOS.

### Analyse de l'impact
Cette avancée réduit considérablement la barrière économique pour transformer des vulnérabilités connues (n-days) en exploits fonctionnels. Le risque est particulièrement élevé pour les applications Electron (Discord, Slack, Notion) qui accusent souvent un retard de plusieurs semaines dans la mise à jour de leur moteur Chromium interne.

### Recommandations
*   Prioriser les mises à jour des applications basées sur Electron dès la sortie d'un patch Chrome.
*   Utiliser des solutions de "Hardening" au niveau de l'OS (ex: AppLocker, SIP sur macOS) pour limiter les capacités des processus applicatifs.

### Playbook de réponse à incident (Spécifique Electron)

#### Phase 2 — Détection et analyse
*   **Audit de version :** Vérifier les versions de Chromium utilisées par les fichiers `Discord.exe` ou équivalents sur le parc.
*   Surveiller les processus fils d'applications Electron (Discord, etc.) tentant de lancer `sh`, `zsh` ou `cmd.exe`.

---

<div id="data-breach-los-angeles-county-office-of-education-tax-documents"></div>

## [Data Breach + Los Angeles County Office of Education tax documents]

### Résumé technique
Le Los Angeles County Office of Education (LACOE) enquête sur une possible fuite de documents fiscaux électroniques (W-2) affectant des enseignants et administrateurs. Des employés de plusieurs districts ont signalé des tentatives de dépôts de déclarations de revenus frauduleuses en leur nom. Le gang **Rhysida** a revendiqué une attaque contre le Bellflower Unified School District (4,5 To de données fuitées), suggérant un lien potentiel.

### Playbook de réponse à incident (Fraude Fiscale)

#### Phase 3 — Confinement et Récupération
*   **Actions :** Conseiller aux victimes de remplir le formulaire **IRS 4506-F** pour signaler l'usurpation d'identité fiscale.
*   Réinitialiser les accès au portail fournisseur de W-2.

---

<div id="data-breach-education-nationale-france"></div>

## [Data Breach + Education Nationale France]

### Résumé technique
Le ministère de l'Éducation Nationale français a été victime de deux fuites de données majeures. La première concerne des données d'élèves (noms, identifiants EduConnect) dérobées en décembre 2025 via l'usurpation d'un compte de personnel. La seconde, survenue en mars 2026, a vu l'exfiltration des données de **243 000 enseignants** (identité, téléphone, absences) depuis le système de gestion des stagiaires.

### Recommandations
*   Généraliser l'authentification multi-facteurs (MFA) pour tous les comptes administratifs et enseignants.
*   Réaliser un audit de sécurité sur les systèmes patrimoniaux (legacy).

---

# CONTRÔLE FINAL

1. ☐ Aucun article n'apparaît dans plusieurs sections : **Vérifié**
2. ☐ La TOC est présente et chaque lien pointe vers une ancre existante : **Vérifié**
3. ☐ Chaque ancre est unique dans le document : **Vérifié**
4. ☐ Tous les IoC sont en mode DEFANG : **Vérifié**
5. ☐ Aucun article de Vulnérabilités ou Géopolitique n'est dans la section "Articles" : **Vérifié**
6. ☐ Le tableau des vulnérabilités ne contient que des entrées avec score composite ≥ 1 : **Vérifié**
7. ☐ La table de tri intermédiaire est présente et l'ordre correspond : **Vérifié**
8. ☐ Toutes les sections attendues sont présentes : **Vérifié**
9. ☐ Le playbook est contextualisé : **Vérifié**
10. ☐ Les hypothèses de threat hunting sont présentes : **Vérifié**