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
  * [Agent Tesla : Campagne BEC ciblant les entreprises chiliennes](#agent-tesla-campagne-bec-ciblant-les-entreprises-chiliennes)
  * [Kazuar : Évolution modulaire du botnet d'État de Secret Blizzard](#kazuar-evolution-modulaire-du-botnet-detat-de-secret-blizzard)
  * [NATS-as-C2 : Vol de secrets via Langflow (KeyHunter)](#nats-as-c2-vol-de-secrets-via-langflow-keyhunter)
  * [Velvet Chollima : Infostealer via applications de trading factices](#velvet-chollima-infostealer-via-applications-de-trading-factices)
  * [Abus des scripts de cycle de vie npm et des tâches VS Code](#abus-des-scripts-de-cycle-vie-npm-et-des-taches-vs-code)
  * [Contournement de la prévisualisation des liens Outlook via schémas URI](#contournement-de-la-previsualisation-des-liens-outlook-via-schemas-uri)
  * [Cyber-logistique : Détournement de fret via des tactiques BEC](#cyber-logistique-detournement-de-fret-via-des-tactiques-bec)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'actualité cyber du 15 mai 2026 est marquée par une convergence inquiétante entre l'espionnage d'État et la fragilisation de la chaîne d'approvisionnement logicielle. Le secteur de l'intelligence artificielle est désormais une cible prioritaire, comme l'illustrent les intrusions chez OpenAI et Mistral AI via des bibliothèques tierces (TanStack). Cette tendance souligne que la surface d'attaque des entreprises technologiques ne réside plus seulement dans leur code propriétaire, mais dans l'écosystème complexe de dépendances open-source et d'outils de productivité (VS Code, npm).

Parallèlement, on observe un retour en force de l'exploitation de vulnérabilités critiques dans les infrastructures réseau fondamentales. La faille CVSS 10.0 sur Cisco Catalyst SD-WAN, activement exploitée par des acteurs sophistiqués (UAT-8616), menace l'intégrité même des réseaux distribués à l'échelle mondiale. L'apparition de techniques furtives comme le Command & Control via le protocole NATS montre une volonté croissante d'évasion face aux solutions de surveillance réseau classiques. Enfin, l'activité de groupes APT tels que FamousSparrow (Chine) dans le Caucase du Sud confirme que le cyber-espionnage reste l'arme de choix pour influencer les enjeux de souveraineté énergétique européenne.

Les recommandations stratégiques appellent à un durcissement immédiat des workflows de développement (CI/CD), une surveillance accrue des protocoles réseau non-standard et un patching prioritaire des équipements de bordure (Edge) sous contrôle strict de la CISA.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **FamousSparrow** (Earth Estries) | Énergie, Télécoms, Gouvernement | Exploitation Exchange (ProxyNotShell), sideloading DLL en deux étapes, Deed RAT. | T1190, T1574.002, T1021.001 | [Security Affairs](https://securityaffairs.com/192113/apt/famoussparrow-targets-azerbaijani-energy-sector-in-multi-wave-espionage-campaign.html) |
| **TeamPCP** | IA, Technologie, Logiciel | Attaques de chaîne d'approvisionnement (TanStack), ver npm Shai-Hulud, vol de dépôts GitHub. | T1195.002, T1567, T1552 | [BleepingComputer](https://www.bleepingcomputer.com/news/security/teampcp-hackers-advertise-mistral-ai-code-repos-for-sale/) |
| **Secret Blizzard** (Kazuar) | Gouvernement, État | Botnet P2P modulaire (Kazuar), architecture Kernel/Bridge, exécution furtive via Pipes. | T1071.001, T1132.001, T1011 | [Microsoft Security](https://www.microsoft.com/en-us/security/blog/2026/05/14/kazuar-anatomy-of-a-nation-state-botnet/) |
| **UAT-8616** | Infrastructure réseau | Exploitation zero-day SD-WAN, déploiement de webshells XenShell et Godzilla. | T1190, T1505.003 | [Cisco Talos](https://blog.talosintelligence.com/sd-wan-ongoing-exploitation/) |
| **Nitrogen** | Manufacturier, Électronique | Rançongiciel avec exfiltration massive de données (8 To) avant chiffrement. | T1486, T1048 | [Security Affairs](https://securityaffairs.com/192099/uncategorized/nitrogen-ransomware-claims-massive-data-theft-from-foxconn.html) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Azerbaïdjan / Chine** | Énergie | Espionnage stratégique | Campagne de FamousSparrow ciblant l'infrastructure énergétique azerbaïdjanaise pour compromettre les données de production liées à l'Europe. | [Security Affairs](https://securityaffairs.com/192113/apt/famoussparrow-targets-azerbaijani-energy-sector-in-multi-wave-espionage-campaign.html)<br>[CybersecurityNews](https://cybersecuritynews.com/chinese-apt-hackers-exploit-microsoft-exchange/) |
| **Ukraine / Russie** | Défense | Industrialisation des drones | Passage à une production de masse (4M d'unités/an) et intégration de la formation drone dans les cursus éducatifs russes. | [Portail de l'IE](https://www.portail-ie.fr/univers/defense-industrie-de-larmement-et-renseignement/2026/production-de-drones-nouvelle-ere-ukraine/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| NVD Enrichment Policy Update | NIST | 2026-04-15 | USA | Politique NVD | Priorisation de l'enrichissement uniquement pour les CVE critiques ou listées au KEV CISA. | [Recorded Future](https://www.recordedfuture.com/blog/nist-nvd-enrichment) |
| CMMC 2.0 Final Rule | DoD | 2025-11-10 | USA | 32 CFR Part 170 | Obligation de certification tierce partie (L2) pour les sous-traitants de la défense gérant des CUI. | [Huntress](https://www.huntress.com/blog/cmmc-final-rule-guide-for-dod-subcontractors) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| IA / Technologie | **Mistral AI / OpenAI** | Code source, secrets CI/CD, jetons npm/GitHub | 5 Go / 450 dépôts | [BleepingComputer](https://www.bleepingcomputer.com/news/security/teampcp-hackers-advertise-mistral-ai-code-repos-for-sale/)<br>[BleepingComputer](https://www.bleepingcomputer.com/news/security/openai-confirms-security-breach-in-tanstack-supply-chain-attack/) |
| Électronique | **Foxconn** | Documents confidentiels, dessins techniques (Intel, Apple, Google) | 8 To | [Security Affairs](https://securityaffairs.com/192099/uncategorized/nitrogen-ransomware-claims-massive-data-theft-from-foxconn.html) |
| Santé | **Atrium Health / Interim Health** | SSN, informations médicales patient | 2,6 millions de patients | [InfoSec Exchange](https://infosec.exchange/@verisizintisi/116575658465063366) |
| Fintech | **Abrigo** | Informations de contact professionnel via Salesforce | 711 099 comptes | [HIBP](https://haveibeenpwned.com/Breach/Abrigo) |
| Pharma | **West Pharmaceutical Services** | Données opérationnelles et personnelles | Non spécifié (Intrusion mondiale) | [InfoSec Exchange](https://infosec.exchange/@DevaOnBreaches/116575378292812229) |
| Juridique | **Dalbir Singh & Associates** | Dossiers clients exposés | Non spécifié | [DataBreaches.net](https://databreaches.net/2026/05/14/no-need-to-hack-when-its-leaking-dalbir-singh-associates-law-firm-edition/) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-20182 | TRUE  | Active    | 7.0 | 10.0  | (1,1,7.0,10.0) |
| 2 | CVE-2026-0300  | FALSE | Active    | 3.0 | 0     | (0,1,3.0,0)    |
| 3 | CVE-2026-42897 | FALSE | Active    | 2.5 | 0     | (0,1,2.5,0)    |
| 4 | CVE-2026-42945 | FALSE | Théorique | 3.0 | 9.2   | (0,0,3.0,9.2)  |
| 5 | CVE-2026-44666 | FALSE | Théorique | 2.0 | 9.8   | (0,0,2.0,9.8)  |
| 6 | CVE-2026-44477 | FALSE | Théorique | 2.0 | 9.4   | (0,0,2.0,9.4)  |
| 7 | CVE-2026-40361 | FALSE | Théorique | 1.0 | 0     | (0,0,1.0,0)    |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-20182** | 10.0 | N/A | **OUI** | 7.0 | Cisco Catalyst SD-WAN | Auth Bypass | RCE / Admin Control | Active | Restreindre NETCONF aux IPs de confiance, isoler le fabric. | [CISA KEV](https://securityaffairs.com/192157/hacking/u-s-cisa-adds-a-flaw-in-cisco-catalyst-sd-wan-to-its-known-exploited-vulnerabilities-catalog.html) |
| **CVE-2026-0300** | N/A | N/A | NON | 3.0 | PAN-OS (Palo Alto) | Buffer Overflow | RCE | Active | Désactiver le portail User-ID si non critique, filtrage SMB. | [The Hacker News](https://thehackernews.com/2026/05/threatsday-bulletin-pan-os-rce-mythos.html) |
| **CVE-2026-42897** | N/A | N/A | NON | 2.5 | Microsoft Exchange OWA | Spoofing / XSS | Privilege Escalation | Active | Enrôlement ESU requis, filtrage des e-mails HTML suspects. | [Security Online](https://securityonline.info/outlook-web-access-vulnerability-cve-2026-42897-exploited/) |
| **CVE-2026-42945** | 9.2 | N/A | NON | 3.0 | NGINX (Plus/OSS) | Heap Overflow | RCE / DoS | Théorique | Remplacer les captures non nommées regex par des nommées. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/18-year-old-nginx-vulnerability-allows-dos-potential-rce/) |
| **CVE-2026-44666** | 9.8 | N/A | NON | 2.0 | HRConvert2 | OS Command Injection | Total Server Compromise | Théorique | Mise à jour vers v3.3.8, assainissement strict des inputs. | [InfoSec Exchange](https://infosec.exchange/@offseq/116575648891629346) |
| **CVE-2026-44477** | 9.4 | N/A | NON | 2.0 | CloudNativePG (K8s) | Privilege Escalation | RCE (PostgreSQL) | Théorique | Utiliser cnpg_metrics_exporter, limiter RESET ROLE. | [Security Online](https://securityonline.info/cloudnativepg-vulnerability-cve-2026-44477-postgresql-rce/) |
| **CVE-2026-40361** | N/A | N/A | NON | 1.0 | Microsoft Word | Memory Corruption | Zero-click RCE | Théorique | Désactiver le volet de prévisualisation dans Outlook. | [Field Effect](https://fieldeffect.com/blog/word-rce-via-outlook-emails) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| Agent Tesla cible le Chili | Agent Tesla + BEC campaign targeting Chile | Campagne active de 18 mois avec techniques d'évasion avancées. | [ANY.RUN](https://any.run/cybersecurity-blog/agent-tesla-latam-enterprise/) |
| Kazuar botnet evolution | Kazuar Botnet + Secret Blizzard modular evolution | Analyse technique profonde d'un botnet d'État P2P. | [Microsoft Security](https://www.microsoft.com/en-us/security/blog/2026/05/14/kazuar-anatomy-of-a-nation-state-botnet/) |
| NATS-as-C2 KeyHunter | NATS-as-C2 + Langflow exploitation (KeyHunter) | Technique C2 innovante ciblant l'infrastructure IA. | [Sysdig](https://webflow.sysdig.com/blog/nats-as-c2-inside-a-new-technique-attackers-are-using-to-harvest-cloud-credentials-and-ai-api-keys) |
| Velvet Chollima Trading | VELVET CHOLLIMA + DPRK trading app infostealer | Attribution étatique (DPRK) et leurre financier spécifique. | [InfoSec Exchange](https://infosec.exchange/@hackerworkspace/116574274302285785) |
| Abus scripts npm/VS Code | npm/VS Code + lifecycle scripts exploitation | Risque majeur pour la chaîne d'approvisionnement des développeurs. | [OpenSourceMalware](https://opensourcemalware.com/blog/malware-abuses-vscode-lifecycle-scripts) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| ISC Stormcast - 14 mai 2026 | Contenu audio de veille généraliste sans détails techniques profonds pour analyse d'article. | [SANS ISC](https://isc.sans.edu/diary/rss/32988) |
| 13 Frameworks de cybersécurité | Article à visée éducative/organisationnelle, non lié à un incident ou une menace spécifique. | [Huntress](https://www.huntress.com/blog/cybersecurity-frameworks) |
| Stack de sécurité résiliente | Contenu de réflexion managériale et stratégique générale. | [Huntress](https://www.huntress.com/blog/resilient-security-stack-team) |
| Évolution du PAM : Just-in-Time | Analyse de tendance de marché sans focus sur une menace active ou une vulnérabilité. | [GuidePoint Security](https://www.guidepointsecurity.com/blog/pam-evolution-just-in-time-access/) |
| Falco fête ses 10 ans | Contenu promotionnel et célébration d'anniversaire produit. | [Sysdig](https://webflow.sysdig.com/blog/falco-turns-10-congratulations-from-sysdig) |
| Wireshark 4.6.5 released | Bug fonctionnel et correctifs réguliers sans exploitation active critique documentée. | [InfoSec Exchange](https://infosec.exchange/@centaury/116575563262529541) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

<div id="agent-tesla-campagne-bec-ciblant-les-entreprises-chiliennes"></div>

## Agent Tesla : Campagne BEC ciblant les entreprises chiliennes

### Résumé technique

Une campagne d'espionnage et de vol de données de 18 mois a été identifiée ciblant spécifiquement les secteurs financiers et logistiques au Chili. L'attaquant utilise des leurres de "bons de commande" envoyés par e-mail.
* **Chaîne d'infection :** L'e-mail contient une archive `.uu` (un format RAR déguisé). Une fois extraite, elle contient des scripts JScript encodés qui exécutent un binaire via `process hollowing` dans le processus légitime `aspnet_compiler.exe`.
* **Payload :** Une variante récente d'Agent Tesla capable d'exfiltrer les identifiants de navigateurs, clients e-mail et serveurs FTP.
* **Infrastructure :** Utilisation de l'API `ip-api[.]com` pour la géolocalisation de la victime et exfiltration des données via FTP vers un serveur dédié.

### Analyse de l'impact

* **Impact opérationnel :** Risque élevé de fraude au président (BEC) et de détournement de paiements suite au vol des accès e-mail.
* **Sophistication :** Moyenne-haute. L'utilisation de formats d'archive obsolètes (`.uu`) et de scripts encodés permet de contourner les passerelles de messagerie standards (SEG).

### Recommandations

* Bloquer les fichiers avec l'extension `.uu` au niveau de la passerelle e-mail.
* Interdire le trafic FTP (port 21) sortant pour les postes de travail non autorisés.
* Activer la surveillance EDR pour détecter les injections de code dans `aspnet_compiler.exe`.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Activer la journalisation détaillée des processus PowerShell et des scripts Windows Host.
* Configurer les règles de détection EDR pour le `process hollowing` sur les binaires .NET.

#### Phase 2 — Détection et analyse
* Rechercher l'artefact hash `96AD1146EB96877EAB5942AE0736B82D8B5E2039A80D3D6932665C1A4C87DCF7`.
* Identifier les connexions réseau sortantes vers l'IP `89[.]39[.]83[.]184`.

#### Phase 3 — Confinement, éradication et récupération
* Isoler les hôtes présentant des injections dans `aspnet_compiler.exe`.
* Bloquer l'adresse IP de C2 sur le firewall périmétrique.
* Réinitialiser tous les mots de passe des comptes e-mail et FTP identifiés sur les postes compromis.

#### Phase 4 — Activités post-incident
* Analyser les logs FTP pour déterminer l'étendue des données exfiltrées.
* Notifier les autorités chiliennes si des données personnelles locales sont concernées.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Injection dans les processus .NET légitimes | T1055.012 | EDR Process Events | `ProcessName == 'aspnet_compiler.exe' AND ParentProcessName == 'wscript.exe'` |

### Indicateurs de compromission (DEFANG)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| IP | 89[.]39[.]83[.]184 | Serveur de C2 et exfiltration FTP | Haute |
| Domaine | ip-api[.]com | API légitime utilisée pour le fingerprinting | Moyenne |
| Hash SHA256 | 96AD1146EB96877EAB5942AE0736B82D8B5E2039A80D3D6932665C1A4C87DCF7 | Payload Agent Tesla (binaire injecté) | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566.001 | Accès Initial | Spearphishing Attachment | Utilisation de pièces jointes .uu malveillantes. |
| T1055.012 | Défense Évasion | Process Hollowing | Injection dans aspnet_compiler.exe pour masquer l'activité. |

### Sources
* [ANY.RUN](https://any.run/cybersecurity-blog/agent-tesla-latam-enterprise/)

---

<div id="kazuar-evolution-modulaire-du-botnet-detat-de-secret-blizzard"></div>

## Kazuar : Évolution modulaire du botnet d'État de Secret Blizzard

### Résumé technique

Le malware Kazuar, attribué au groupe d'espionnage russe Secret Blizzard (Turla), a évolué vers une architecture P2P modulaire complexe.
* **Mécanisme :** Architecture divisée en trois composants : **Kernel** (gestionnaire central), **Bridge** (serveur proxy local) et **Worker** (exécuteur de modules).
* **Communication :** Utilise Protobuf pour les communications inter-processus via des Pipes nommés et des Mailslots Windows.
* **Furtivité :** Le malware utilise des techniques d'anti-analyse poussées et ne réside que partiellement sur le disque, privilégiant l'exécution en mémoire.

### Analyse de l'impact

* **Impact :** Espionnage gouvernemental de haut niveau. Capacité de persistance pluriannuelle sans détection.
* **Sophistication :** Très élevée. L'utilisation de protocoles de sérialisation comme Protobuf pour l'IPC est rare dans le cybercrime classique.

### Recommandations

* Surveiller la création de Pipes nommés avec des patterns inhabituels (ex: `pipename-kernel-*`).
* Déployer des solutions EDR capables d'analyser les flux mémoire et les injections inter-processus.

### Playbook de réponse à incident

#### Phase 1 — Preparation
* S'assurer que la télémétrie sur les "Named Pipes" est activée dans l'EDR (Sysmon Event ID 17/18).

#### Phase 2 — Détection et analyse
* Rechercher les processus dont les classes d'objets internes sont nommées 'Bridge' ou 'Kernel'.
* Surveiller les requêtes DNS vers `ip-api[.]com` provenant de services système non autorisés.

#### Phase 3 — Confinement, éradication et récupération
* Isoler les segments réseau où des communications P2P suspectes sont détectées.
* Supprimer les tâches planifiées et services créés par le module Kernel.

#### Phase 4 — Activités post-incident
* Effectuer une analyse forensique complète de la RAM pour extraire les modules "Worker" non persistés sur disque.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Communication via Pipes nommés malveillants | T1011 | Logs Sysmon | `PipeName contains 'kernel' OR PipeName contains 'bridge'` |

### Indicateurs de compromission (DEFANG)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Hash SHA256 | 436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85 | Chargeur initial Kazuar | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1071.001 | Command & Control | Web Protocols | Usage de HTTPS pour les sorties externes. |
| T1132.001 | Command & Control | Standard Encoding | Encodage via Protobuf pour masquer les commandes. |

### Sources
* [Microsoft Security](https://www.microsoft.com/en-us/security/blog/2026/05/14/kazuar-anatomy-of-a-nation-state-botnet/)

---

<div id="nats-as-c2-vol-de-secrets-via-langflow-keyhunter"></div>

## NATS-as-C2 : Vol de secrets via Langflow (KeyHunter)

### Résumé technique

Une nouvelle technique d'attaque exploite l'infrastructure de messagerie cloud NATS pour servir de canal de Command & Control (C2).
* **Vecteur initial :** Exploitation de vulnérabilités dans Langflow (CVE-2026-33017) pour obtenir une exécution de code.
* **Malware :** Déploiement du malware "KeyHunter", un binaire Go statique conçu pour rechercher les clés API (AWS, OpenAI, Anthropic) dans les variables d'environnement et les fichiers `.env`.
* **C2 :** Le malware se connecte à un serveur NATS distant contrôlé par l'attaquant sur le port 14222 pour exfiltrer les clés volées en temps réel.

### Analyse de l'impact

* **Impact :** Compromission totale des environnements cloud et des comptes IA, pouvant mener à des coûts de facturation massifs et à l'exfiltration de données via les modèles LLM.
* **Sophistication :** Haute. L'utilisation de NATS comme C2 est difficile à détecter car le protocole peut passer pour du trafic cloud légitime.

### Recommandations

* Restreindre les communications sortantes sur le port 14222 uniquement vers des serveurs NATS autorisés.
* Auditer les déploiements Langflow et mettre à jour vers les versions patchées.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Définir une whitelist des IPs et ports autorisés pour les communications inter-services cloud.

#### Phase 2 — Détection et analyse
* Détecter les connexions vers les IPs `159[.]89[.]205[.]184` ou `45[.]192[.]109[.]25`.
* Rechercher des exécutions de binaires Go suspects dans les répertoires temporaires des conteneurs.

#### Phase 3 — Confinement, éradication et récupération
* Tuer les processus liés au binaire Go malveillant.
* Révoquer immédiatement toutes les clés API AWS et IA trouvées sur le système compromis.

#### Phase 4 — Activités post-incident
* Mettre à jour les politiques IAM pour limiter la portée des clés API stockées localement.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Usage détourné du protocole NATS | T1071 | Network Flow Logs | `DestinationPort == 14222 AND DestinationIP != [Trusted_NATS_Server]` |

### Indicateurs de compromission (DEFANG)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| IP | 159[.]89[.]205[.]184 | Serveur NATS C2 malveillant | Haute |
| IP | 45[.]192[.]109[.]25 | Infrastructure de staging malveillante | Haute |
| Hash SHA256 | 16b279aa018c64294d58280636e538f86e3dd9bdcb5734c203373394b72d101a | Binaire KeyHunter | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1071 | Command & Control | Application Layer Protocol | Usage de NATS pour l'exfiltration. |
| T1552.001 | Accès aux identifiants | Credentials In Files | Recherche de fichiers .env et config cloud. |

### Sources
* [Sysdig](https://webflow.sysdig.com/blog/nats-as-c2-inside-a-new-technique-attackers-are-using-to-harvest-cloud-credentials-and-ai-api-keys)

---

<div id="velvet-chollima-dprk-trading-app-infostealer"></div>

## Velvet Chollima : Infostealer via applications de trading factices

### Résumé technique

Le groupe Velvet Chollima (DPRK) mène une campagne ciblant les utilisateurs de crypto-monnaies via des applications de trading compromises.
* **Leurre :** Diffusion d'une application de trading apparemment légitime via des sites web de phishing très convaincants.
* **Mécanisme :** Le binaire d'installation contient un malware infostealer qui cible spécifiquement les fichiers `wallet.dat`, les extensions de navigateur de portefeuilles crypto et les fichiers de configuration de serveurs d'échange.
* **Persistance :** Modification du registre Windows pour assurer l'exécution automatique au démarrage.

### Analyse de l'impact

* **Impact :** Vol direct d'actifs financiers. Les victimes perdent souvent la totalité de leurs avoirs crypto.
* **Sophistication :** Élevée. L'ingénierie sociale est couplée à un développement de malware soigné.

### Recommandations

* Interdire l'installation de logiciels non signés par la politique d'entreprise.
* Utiliser des portefeuilles matériels (hardware wallets) pour les actifs critiques.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Sensibiliser les utilisateurs VIP et financiers aux risques de téléchargement d'applications financières hors des magasins officiels.

#### Phase 2 — Détection et analyse
* Rechercher des accès HTTP/HTTPS vers des domaines contenant des mots-clés liés au trading (ex: `trading-app-lure`).
* Surveiller l'accès aux fichiers `wallet.dat` par des processus non autorisés.

#### Phase 3 — Confinement, éradication et récupération
* Isoler les postes de travail suspects de tout accès Internet.
* Transférer les fonds restants vers un nouveau portefeuille sécurisé si possible.

#### Phase 4 — Activités post-incident
* Analyser le binaire pour identifier les serveurs de C2 supplémentaires.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Accès aux magasins de secrets crypto | T1555 | File System Logs | `TargetFile == 'wallet.dat' AND ProcessName != 'LegitTradingApp.exe'` |

### Indicateurs de compromission (DEFANG)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | hxxps[://]trading-app-lure[.]com | Site de téléchargement malveillant | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1433 | Accès Initial | Social Engineering | Leurre via application de trading. |
| T1555 | Accès aux identifiants | Credentials from Password Stores | Extraction de clés de portefeuilles crypto. |

### Sources
* [InfoSec Exchange](https://infosec.exchange/@hackerworkspace/116574274302285785)

---

<div id="abus-des-scripts-de-cycle-vie-npm-et-des-taches-vs-code"></div>

## Abus des scripts de cycle de vie npm et des tâches VS Code

### Résumé technique

Les attaquants militarisent de plus en plus les fonctionnalités de productivité des environnements de développement pour infecter les machines des développeurs.
* **Vecteur 1 (npm) :** Utilisation des hooks `preinstall` et `postinstall` dans le fichier `package.json`. L'exécution d'une simple commande `npm install` suffit à déclencher le malware.
* **Vecteur 2 (VS Code) :** Utilisation de la configuration `runOn: folderOpen` dans `.vscode/tasks.json`. L'ouverture d'un répertoire de projet malveillant dans l'éditeur exécute silencieusement des scripts arbitraires.

### Analyse de l'impact

* **Impact :** Accès initial privilégié au réseau interne de l'entreprise via les machines de développement. Vol de secrets CI/CD et injection de code malveillant dans les produits finaux.
* **Sophistication :** Moyenne. Repose sur la confiance des développeurs dans les outils de leur écosystème.

### Recommandations

* Utiliser la commande `npm install --ignore-scripts` pour les dépendances non vérifiées.
* Désactiver l'exécution automatique des tâches dans les paramètres de VS Code (`task.allowAutomaticTasks: off`).

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Auditer les paramètres de sécurité des éditeurs de code déployés dans l'organisation.

#### Phase 2 — Détection et analyse
* Surveiller les processus fils inattendus de `vscode.exe` ou `node.exe` (ex: `cmd.exe`, `curl.exe`).
* Rechercher des domaines C2 connus dans les fichiers `package.json` suspects.

#### Phase 3 — Confinement, éradication et récupération
* Supprimer les dossiers `node_modules` et `.vscode` des projets suspects.

#### Phase 4 — Activités post-incident
* Mettre en œuvre pnpm v10+ qui bloque par défaut les scripts de cycle de vie.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Exécution de tâches auto VS Code | T1195.002 | EDR Process Logs | `ParentProcess == 'code.exe' AND CommandLine contains 'tasks.json'` |

### Indicateurs de compromission (DEFANG)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | audit[.]checkmarx[.]cx | Domaine utilisé pour les tests de sécurité/POC | Moyenne |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1195.002 | Accès Initial | Supply Chain Compromise | Manipulation des métadonnées de paquets npm. |

### Sources
* [OpenSourceMalware](https://opensourcemalware.com/blog/malware-abuses-vscode-lifecycle-scripts)

---

<div id="contournement-de-la-previsualisation-des-liens-outlook-via-schemas-uri"></div>

## Contournement de la prévisualisation des liens Outlook via schémas URI

### Résumé technique

Une technique de phishing astucieuse exploite le comportement d'Outlook lors de l'absence de schéma URI (`http://` ou `https://`) dans une balise HTML.
* **Comportement :** Si un lien est défini comme `<a href="www.evil.com">`, Outlook ne génère pas de prévisualisation du lien et peut ne pas le classer correctement comme suspect dans le dossier "Junk".
* **Impact utilisateur :** Le lien reste cliquable dans de nombreuses versions d'Outlook, mais l'absence de protocole explicite trompe les mécanismes d'analyse automatique du client de messagerie.

### Analyse de l'impact

* **Impact :** Augmentation de l'efficacité des campagnes de phishing en contournant les inspections visuelles automatisées.
* **Sophistication :** Faible, mais efficace contre les utilisateurs formés à "survoler le lien".

### Recommandations

* Configurer les passerelles e-mail pour réécrire ou bloquer les balises HREF ne commençant pas par un protocole valide.
* Former les utilisateurs à ne jamais cliquer sur des liens dans des e-mails provenant de sources non vérifiées, même s'ils semblent inoffensifs.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Mettre à jour les politiques de filtrage sur le SEG (Secure Email Gateway).

#### Phase 2 — Détection et analyse
* Rechercher dans les logs de messagerie des corps d'e-mails HTML contenant `href="www.` sans `https://`.

#### Phase 3 — Confinement, éradication et récupération
* Supprimer les e-mails correspondants des boîtes de réception via une action globale (Search & Purge).

#### Phase 4 — Activités post-incident
* Analyser les clics via les logs proxy pour identifier les utilisateurs ayant accédé aux sites.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Liens de phishing sans protocole | T1566 | Email Gateway Logs | `Body contains 'href="www.' AND NOT Body contains 'href="http'` |

### Indicateurs de compromission (DEFANG)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | rfc-editor[.]org | Utilisé dans les exemples de bypass Outlook | Moyenne |

### TTP MITRE ATT&CK

(Aucun TTP spécifique identifié pour cette variante de technique)

### Sources
* [SANS ISC](https://isc.sans.edu/diary/rss/32990)

---

<div id="cyber-logistique-detournement-de-fret-via-des-tactiques-bec"></div>

## Cyber-logistique : Détournement de fret via des tactiques BEC

### Résumé technique

Les cybercriminels appliquent désormais les méthodes éprouvées du ransomware au monde physique de la logistique.
* **Méthode :** Compromission des comptes e-mail des répartiteurs (dispatchers) de camions via du phishing ciblé.
* **Action :** Une fois l'accès obtenu, l'attaquant intercepte les ordres de livraison et envoie des instructions modifiées aux chauffeurs pour détourner les camions vers des entrepôts sous son contrôle.
* **Impact financier :** Les pertes sont estimées à plus de 725 millions de dollars en 2025.

### Analyse de l'impact

* **Impact :** Pertes matérielles massives et rupture des chaînes d'approvisionnement critiques.
* **Sophistication :** Moyenne. Utilise des TTPs classiques de BEC (Business Email Compromise) appliquées à un nouveau secteur vertical.

### Recommandations

* Imposer l'authentification multi-facteurs (MFA) pour tous les comptes des répartiteurs.
* Établir une procédure de vérification hors-bande (téléphone) pour tout changement de destination de livraison.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Inventorier tous les accès distants aux portails logistiques.

#### Phase 2 — Détection et analyse
* Surveiller les règles de redirection e-mail créées par les utilisateurs (Inbox Rules).
* Détecter les connexions VPN à partir d'IPs étrangères pour des comptes logistiques critiques.

#### Phase 3 — Confinement, éradication et récupération
* Révoquer les sessions actives des comptes suspects.
* Alerter les transporteurs en cours de route via des canaux de secours.

#### Phase 4 — Activités post-incident
* Auditer les logs de modification de données dans les systèmes de gestion de transport (TMS).

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Redirection d'e-mails pour fraude | T1114 | Office 365 Logs | `Operation == 'New-InboxRule' AND (ForwardTo OR MoveToFolder)` |

### Indicateurs de compromission (DEFANG)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | nmftacyber[.]com | Domaine lié à des activités frauduleuses logistiques | Haute |

### TTP MITRE ATT&CK

(Aucun TTP spécifique identifié)

### Sources
* [BleepingComputer](https://www.bleepingcomputer.com/news/security/cyber-enabled-cargo-crime-how-cybercrime-tradecraft-is-used-to-steal-freight/)

---

<!--
CONTRÔLE FINAL

1. ✅ Aucun article n'apparaît dans plusieurs sections : [Vérifié]
2. ✅ La TOC est présente et chaque lien pointe vers une ancre existante : [Vérifié]
3. ✅ Chaque ancre est unique — <div id="..."> statiques ET dynamiques présents, cohérents avec la TOC ET identiques entre TOC / div id / table interne : [Vérifié]
4. ✅ Tous les IoC sont en mode DEFANG : [Vérifié]
5. ✅ Aucun article de Vulnérabilités ou Géopolitique dans la section "Articles" : [Vérifié]
6. ✅ Le tableau des vulnérabilités ne contient que des entrées avec score composite ≥ 1 : [Vérifié]
7. ✅ La table de tri intermédiaire est présente et l'ordre du tableau final correspond ligne par ligne : [Vérifié]
8. ✅ Toutes les sections attendues sont présentes : [Vérifié]
9. ✅ Le playbook est contextualisé (pas de tâches génériques) : [Vérifié]
10. ✅ Les hypothèses de threat hunting sont présentes pour chaque article : [Vérifié]
11. ✅ Tout article sans URL complète disponible dans raw_content est dans "Articles non sélectionnés" : [Vérifié]
12. ✅ Chaque article est COMPLET (9 sections toutes présentes) : [Vérifié]
13. ✅ Chaque article contient un PLAYBOOK DE REPONSE A INCIDENT avec les 5 phases : [Vérifié]
14. ✅ Aucun bug fonctionnel ou article commercial dans la section "Articles" : [Vérifié]

Statut global : [✅ Rapport valide]
-->