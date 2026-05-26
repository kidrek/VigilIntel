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
  * [TeamPCP supply chain campaign via poisoned VS Code extensions](#teampcp-supply-chain-campaign-via-poisoned-vs-code-extensions)
  * [ACR Stealer infection chain via fake Claude AI pages](#acr-stealer-infection-chain-via-fake-claude-ai-pages)
  * [Kali365 PhaaS targeting Microsoft 365 OAuth flow](#kali365-phaas-targeting-microsoft-365-oauth-flow)
  * [YY Lai Yu Chinese-language PhaaS targeting Japanese market](#yy-lai-yu-chinese-language-phaas-targeting-japanese-market)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

La fin du mois de mai 2026 marque une intensification sans précédent des attaques ciblant la chaîne d'approvisionnement logicielle (*software supply chain*). Menées de façon agressive par l'acteur cybercriminel ou étatique TeamPCP, ces campagnes ont abouti à la compromission d'acteurs technologiques majeurs, à l'instar de GitHub, OpenAI et Mistral AI. Le mode opératoire identifié repose sur l'empoisonnement d'extensions légitimes au sein de l'écosystème VS Code (notamment Nx Console) et l'utilisation de faux badges de provenance Sigstore pour contourner les contrôles de sécurité. L'objectif technique sous-jacent est le vol systématique de secrets industriels, de clés cloud (AWS, GCP, Azure) et de jetons d'accès d'environnements CI/CD pour exfiltrer des bases de code propriétaires et déployer des *wipers* Linux.

Parallèlement, nous observons une professionnalisation et une industrialisation poussées de la cybercriminalité financière avec l'émergence d'écosystèmes sophistiqués de *Phishing-as-a-Service* (PhaaS) basés en Chine. Les plateformes comme "YY Lai Yu" et "Kali365" se distinguent par l'interception dynamique en temps réel des codes d'authentification à usage unique (OTP) et l'abus du protocole d'autorisation par code d'appareil (*Device Authorization Grant Flow*) d'OAuth 2.0. Ces techniques permettent de neutraliser efficacement les mesures d'authentification multifactorielle (MFA) traditionnelles pour dérober des jetons de session Microsoft 365.

Face à ces menaces systémiques, l'Union européenne adopte une posture proactive en neutralisant les infrastructures de transit et de serveurs proxy (saisie coordonnée de MIRhosting et de sa filiale WorkTitans par la FIOD néerlandaise) utilisées pour masquer des attaques d'influence russes et des opérations DDoS. Sur le plan économique, le débat autour de l'Instrument Anti-Coercition (IAC) illustre la recherche constante d'une souveraineté numérique et commerciale face aux pressions bilatérales.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **TeamPCP** | Technologie, Développement logiciel, Intelligence Artificielle, Finance | Compromission de comptes de développeurs pour pousser des mises à jour malveillantes via des extensions VS Code, exfiltration de secrets d'environnements CI/CD, et déploiement de *wipers*. | T1195.002 (Supply Chain)<br>T1553.006 (Code Signing)<br>T1539 (Steal Session Cookie) | [SANS ISC Diary 33016](https://isc.sans.edu/diary/rss/33016)<br>[SANS ISC Diary 33014](https://isc.sans.edu/diary/rss/33014) |
| **UAC-0057** (Ghostwriter) | Gouvernement, Défense, Éducation, Secteur Public | Campagnes d'hameçonnage ciblé exploitant des leurres liés à l'administration ukrainienne pour déployer le loader JavaScript OYSTER et Cobalt Strike. | T1566.002 (Spearphishing Link)<br>T1059.007 (JavaScript Execution)<br>T1071.001 (Web Protocols C2) | [SOC Prime Blog](https://socprime.com/blog/uac-0057-attack-detection/) |
| **Inc Ransom** | Industrie, Santé, Éducation, Services | Opération de Ransomware-as-a-Service (RaaS) utilisant la double extorsion (chiffrement de fichiers locaux et exfiltration de données critiques). | T1486 (Data Encrypted for Impact) | [Ransomlook Group Info](https://www.ransomlook.io//group/inc%20ransom) |
| **YY Lai Yu** | E-Commerce, Finance, Services Publics, Transports | Fourniture de modèles de phishing automatisés avec interception d'OTP en temps réel et provisioning de cartes volées vers des portefeuilles numériques. | T1566.002 (Spearphishing Link)<br>T1556 (Modify Auth Process) | [Google Threat Intelligence Group](https://cloud.google.com/blog/topics/threat-intelligence/chinese-language-phishing-services/) |
| **Kali365 PhaaS** | Multi-sectoriel, Clients Microsoft 365 | Abus du flux d'authentification par code d'appareil OAuth (Device Code) pour capturer les jetons d'accès de comptes M365 sans interaction complexe. | T1528 (Steal Access Token)<br>T1566.002 (Spearphishing Link) | [FBI Cyber Division PSA](https://www.bleepingcomputer.com/news/security/fbi-warns-of-kali365-phishing-service-targeting-microsoft-365-accounts/) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Europe, Pays-Bas, Russie, Danemark** | FSI | Saisie policière d'infrastructures de cyberattaques | Saisie massive de plus de 800 serveurs de MIRhosting / WorkTitans par la FIOD néerlandaise, démantelant un réseau russe d'évasion de sanctions ayant appuyé des attaques DDoS contre le gouvernement danois. | [KrebsOnSecurity](https://krebsonsecurity.com/2026/05/netherlands-seizes-800-servers-arrests-2-for-aiding-cyberattacks/) |
| **Ukraine, Biélorussie** | Gouvernemental / Public | Espionnage de l'acteur étatique UAC-0057 (Oyster) | Utilisation d'emails d'hameçonnage envoyés par l'acteur étatique Ghostwriter (UAC-0057) pour exfiltrer des configurations système et implanter des charges mémoire persistantes en Ukraine. | [SOC Prime Blog](https://socprime.com/blog/uac-0057-attack-detection/) |
| **Union européenne, États-Unis, Chine** | Multi-sectoriel | Limites de l'Instrument Anti-Coercition (IAC) | Analyse stratégique des difficultés réglementaires et politiques de mise en œuvre de l'IAC par l'UE face aux pressions douanières imposées par des pays tiers. | [Portail de l'IE](https://www.portail-ie.fr/univers/droit-et-intelligence-juridique/2026/instrument-anti-coercition-union-europeenne-trump/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Avis sur le Digital Omnibus | Banque Centrale Européenne | 2026-05-26 | Union européenne | CON/2026/9 | Simplification réglementaire visant à réduire le chevauchement administratif des rapports de conformité pour le RGPD, NIS2, CER et DORA. | [EUR-Lex Official Journal](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=OJ:C_202602621) |
| PowerSchool Settlement | U.S. Civil Courts | 2026-05-25 | États-Unis | Accord de règlement amiable | PowerSchool accepte de payer 17,25 millions de dollars pour clore les litiges relatifs à la collecte abusive et non consentie de données d'élèves mineurs. | [DataBreaches.net](https://databreaches.net/2026/05/25/powerschools-17-25-million-settlement-exposes-years-of-student-data-tracking/) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Multi-sectoriel** (Éducation, SaaS, Fintech, Blockchain) | Plus de 700 sites Web (via Ghost CMS) | Clés d'API d'administration, code source des sites de gestion de contenu. | 700 sites Web piratés | [The Hacker News - Ghost CMS Exploited](https://thehackernews.com/2026/05/ghost-cms-cve-2026-26980-exploited-to.html) |
| **Industrie / Manufacturier** | PILLER AIMMCO | Données d'entreprise et fichiers d'ingénierie opérationnels. | Inconnu (revendiqué par Inc Ransom) | [Ransomlook](https://www.ransomlook.io//group/inc%20ransom) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-5426 | TRUE  | Active    | 7.0 | 9.8   | (1,1,7.0,9.8) |
| 2 | CVE-2026-48172| TRUE  | Active    | 6.0 | 8.8   | (1,1,6.0,8.8) |
| 3 | CVE-2026-25185| TRUE  | Active    | 5.5 | 7.8   | (1,1,5.5,7.8) |
| 4 | CVE-2026-26980| FALSE | Active    | 3.5 | 8.5   | (0,1,3.5,8.5) |
| 5 | CVE-2025-1041 | FALSE | Théorique | 2.0 | 9.9   | (0,0,2.0,9.9) |
| 6 | CVE-2026-45216| FALSE | Théorique | 1.0 | 8.5   | (0,0,1.0,8.5) |
| 7 | CVE-2026-42773| FALSE | Théorique | 1.0 | 8.0   | (0,0,1.0,8.0) |
| 8 | CVE-2026-42774| FALSE | Théorique | 1.0 | 8.0   | (0,0,1.0,8.0) |
| 9 | CVE-2026-48837| FALSE | Théorique | 1.0 | 8.0   | (0,0,1.0,8.0) |
| 10| CVE-2026-48842| FALSE | Théorique | 1.0 | 8.0   | (0,0,1.0,8.0) |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-5426** | 9.8 | N/A | TRUE | 7.0 | KnowledgeDeliver LMS | Désérialisation ASP.NET (ViewState) | RCE | Active | Modifier la configuration web.config pour utiliser une clé *machineKey* unique et aléatoire. | [Mandiant Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/knowledgedeliver-viewstate-deserialization-vulnerability/)<br>[Cyber Security News](https://cybersecuritynews.com/knowledgedeliver-lms-zero-day-exploited/) |
| **CVE-2026-48172** | 8.8 | N/A | TRUE | 6.0 | LiteSpeed cPanel Plugin | Validation JSON de l'API Redis insuffisante | LPE | Active | Installer immédiatement le plugin d'administration LiteSpeed WHM v5.3.1.0 ou supérieure. | [Field Effect Blog](https://fieldeffect.com/blog/actively-exploited-litespeed-cpanel-flaw-enables-full-server-takeover) |
| **CVE-2026-25185** | 7.8 | N/A | TRUE | 5.5 | Windows Explorer | Analyse défectueuse des fichiers Shell (.LNK) | Spoofing / Relais NTLM | Active | Bloquer le port SMB sortant (TCP 445) vers l'Internet ; appliquer les correctifs cumulatifs de Microsoft de mars 2026 ou les micropatchs 0patch. | [0patch Blog](https://blog.0patch.com/2026/05/micropatches-released-for-windows-shell.html) |
| **CVE-2026-26980** | 8.5 | N/A | FALSE | 3.5 | Ghost CMS | Injection SQL (SQLi) | Auth Bypass | Active | Migrer les instances Ghost vers la version corrective 6.19.1+ et révoquer l'ensemble des clés d'API d'administration. | [The Hacker News](https://thehackernews.com/2026/05/ghost-cms-cve-2026-26980-exploited-to.html) |
| **CVE-2025-1041** | 9.9 | N/A | FALSE | 2.0 | Avaya Call Management System | Mauvaise validation d'entrée | RCE | Théorique | Vulnérabilité actuellement non patchée. Isoler et restreindre tout accès public à l'interface d'administration. | [Mastodon / Hugo Valters](https://mastodon.social/@hugovalters/116637710815186444) |
| **CVE-2026-45216** | 8.5 | N/A | FALSE | 1.0 | WordPress Smart Manager | Traitement inadapté de l'authentification | LPE | Théorique | Mettre à jour d'urgence le plugin Smart Manager vers une version supérieure à 8.85.0. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-45216) |
| **CVE-2026-42773** | 8.0 | N/A | FALSE | 1.0 | WordPress eMagicOne Store Manager | Blind SQL Injection | SQLi | Théorique | Mettre à jour le plugin eMagicOne Store Manager vers la version corrigée supérieure à la version 1.3.2. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-42773) |
| **CVE-2026-42774** | 8.0 | N/A | FALSE | 1.0 | WordPress JetEngine | Mauvaise gestion des paramètres SQL | SQLi | Théorique | Installer la mise à jour corrective résolvant la faille pour les versions supérieures à 3.8.8.1. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-42774) |
| **CVE-2026-48837** | 8.0 | N/A | FALSE | 1.0 | WordPress Unlimited Elements for Elementor | Neutralisation incorrecte de variables | SQLi | Théorique | Installer la version corrigée du plugin Unlimited Elements (supérieure à la version 2.0.8). | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-48837) |
| **CVE-2026-48842** | 8.0 | N/A | FALSE | 1.0 | Roundcube Webmail | Faiblesse d'assainissement de variables SQL | SQLi | Théorique | Mettre à jour Roundcube vers les versions de sécurité 1.6.16 ou 1.7.1. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-48842) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| TeamPCP supply chain campaign via poisoned VS Code extensions | `teampcp-supply-chain-campaign-via-poisoned-vs-code-extensions` | Analyse technique poussée de la campagne d'empoisonnement d'extensions VS Code et de SDK ayant mené au vol massif de secrets cloud chez plusieurs éditeurs. | [SANS ISC Diary 33016](https://isc.sans.edu/diary/rss/33016)<br>[SANS ISC Diary 33014](https://isc.sans.edu/diary/rss/33014) |
| ACR Stealer infection chain via fake Claude AI pages | `acr-stealer-infection-chain-via-fake-claude-ai-pages` | Description détaillée d'une campagne de distribution d'infostealers s'appuyant sur l'usurpation d'outils d'IA sur Google Sites pour compromettre Windows et macOS. | [SANS ISC Diary](https://isc.sans.edu/diary/rss/33018) |
| Kali365 PhaaS targeting Microsoft 365 OAuth flow | `kali365-phaas-targeting-microsoft-365-oauth-flow` | Rappel des risques inhérents à l'abus du flux d'authentification Device Code par des kits de phishing industrialisés. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-warns-of-kali365-phishing-service-targeting-microsoft-365-accounts/) |
| YY Lai Yu Chinese-language PhaaS targeting Japanese market | `yy-lai-yu-chinese-language-phaas-targeting-japanese-market` | Évolution technologique du PhaaS ciblant l'interception automatique de codes OTP en temps réel via des panels interactifs. | [Google Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/chinese-language-phishing-services/) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| ISC Stormcast For Tuesday, May 26th, 2026 | Flux audio récapitulatif général sans focus technique spécifique. | [SANS ISC Diary](https://isc.sans.edu/diary/rss/33020) |
| Microsoft Access VBA | Note fonctionnelle d'outil d'analyse statique sans incident ni menace de sécurité associée. | [SANS ISC Diary](https://isc.sans.edu/diary/rss/33012) |
| Anthropic’s restricted Claude Mythos model may be coming to Claude Code | Simple annonce de fonctionnalité d'IA sans incident de sécurité ou menace active documentée. | [BleepingComputer](https://www.bleepingcomputer.com/news/artificial-intelligence/anthropics-restricted-claude-mythos-model-may-be-coming-to-claude-code/) |
| 25th May – Threat Intelligence Report | Rapport d'actualité cyber généraliste sans focus technique unique. | [Check Point Research](https://research.checkpoint.com/2026/25th-may-threat-intelligence-report/) |
| Why the new AI attack surface demands a new cybersecurity approach | Livre blanc conceptuel sur la surface d'attaque IA dénué de données techniques d'un incident précis. | [Field Effect Blog](https://fieldeffect.com/blog/ai-tools-new-attack-surface) |
| GitHub - mrexodia/ida-pro-mcp | Annonce d'outil de reverse engineering open-source sans incident de sécurité. | [Reddit BlueTeamSec](https://www.reddit.com/r/blueteamsec/comments/1tnqzaz/github_mrexodiaidapromcp_aipowered_reverse/) |
| Automate containment while aligning with legal, PR, and executive workflows. | Opinion ou discussion d'ordre général sur les réseaux sociaux. | [Mastodon / lbhuston](https://mastodon.social/@lbhuston/116638264260640297) |
| Integration Issues: Disconnected tools produce siloed alerts and fractured context. | Opinion ou discussion d'ordre général sur les réseaux sociaux. | [Mastodon / lbhuston](https://mastodon.social/@lbhuston/116638048331289113) |
| Possible Phishing on Yahoo/AT&T Google Sites | Campagne de phishing à faible impact technique. | [Mastodon / URLDNA](https://infosec.exchange/@urldna/116637696685201454) |
| Who's got a good talk about POSIX ACLs ? | Simple requête d'opinion technique communautaire sans fait de sécurité associé. | [Mastodon / rye](https://ioc.exchange/@rye/116637666545318624) |
| CVE-2018-25379 - Collectric CMU 1.0 SQL Injection | Vulnérabilité historique datant de 2018 exclue du périmètre de la veille quotidienne active. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2018-25379) |
| CVE-2018-25377 - Flash Slideshow Maker Professional 5.20 Buffer Overflow | Vulnérabilité historique datant de 2018 exclue du périmètre de la veille quotidienne active. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2018-25377) |
| Vulnerability in Kenik cameras software | Vulnérabilité mineure (score composite = 0). Exclue définitivement de l'analyse détaillée. | [CERT Polska](https://cert.pl/en/posts/2026/05/CVE-2026-7766/) |
| Vulnerability in Szafir SDK software | Vulnérabilité mineure (score composite = 0.5). Exclue sous le seuil d'inclusion. | [CERT Polska](https://cert.pl/en/posts/2026/05/CVE-2026-9058/) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="teampcp-supply-chain-campaign-via-poisoned-vs-code-extensions"></div>

## TeamPCP supply chain campaign via poisoned VS Code extensions

### Résumé technique

Une campagne d'une agressivité et d'une portée sans précédent est menée par l'acteur de menace TeamPCP (également identifié sous l'alias "Mini Shai-Hulud Operator"). L'acteur cible directement les développeurs travaillant dans des entités stratégiques de l'intelligence artificielle et de la tech (dont OpenAI, Mistral AI et GitHub). L'infection initiale repose sur l'empoisonnement d'extensions populaires de console de développement VS Code (notamment l'extension Nx Console en version compromise 18.95.0), ainsi que la diffusion de paquets SDK falsifiés sur npm et PyPI (tels que des composants Microsoft `durabletask` altérés). 

Une fois l'extension malveillante installée sur la machine du développeur, elle exécute un script furtif en tâche de fond pour exfiltrer de façon systématique les jetons de session locale d'accès au cloud, les fichiers de configuration contenant les clés d'API (comme `~/.claude/settings.json`) et les configurations d'environnements CI/CD. Plus sophistiqué encore, l'attaquant a intégré des faux badges de provenance cryptographique Sigstore pour faire passer ces packages empoisonnés pour authentiques. En cas de détection d'environnements sandbox ou pour effacer ses traces, l'acteur déploie un chargeur de *wiper* Linux qui détruit sélectivement les dépôts de code locaux.

---

### Analyse de l'impact

L'impact opérationnel est critique. TeamPCP a réussi à exfiltrer le code source complet de plus de 3 800 dépôts GitHub internes appartenant aux organisations compromises, exposant des secrets industriels de modèles d'IA propriétaires. L'attaque contourne directement le 2FA en subtilisant les cookies de session OAuth actifs directement sur les terminaux des développeurs. La sophistication technique de cette campagne est évaluée comme très élevée, caractérisée par une parfaite maîtrise des mécanismes de packaging et d'intégration continue.

---

### Recommandations

* Interdire immédiatement toute mise à jour automatique des modules de développement et extensions VS Code sur l'ensemble du parc de machines.
* Appliquer une règle de validation stricte des hachages (*lockfiles*) pour tout package de dépendance importé.
* Migrer l'authentification des environnements de déploiement et d'administration cloud vers des flux OIDC à usage unique avec expiration stricte des jetons.
* Forcer la désinstallation immédiate de la version compromise 18.95.0 de l'extension Nx Console.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Activer la surveillance d'intégrité des fichiers locaux (FIM) sur les répertoires d'extensions VS Code des postes de travail.
* Déployer l'agent EDR en mode bloquant sur les processus de développement de type `node.exe` et `python.exe`.
* S'assurer que les journaux d'accès aux jetons d'API AWS, Azure et GCP sont centralisés et historisés dans le SIEM.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * **Règle Sigma (recherche SIEM)** :
    ```yaml
    title: Detection of VS Code Malicious Extension Task
    status: active
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            ParentImage|endswith: '\code.exe'
            CommandLine|contains:
                - 'filev2.getsession.org'
                - 'seed1.getsession.org'
        condition: selection
    ```
  * **Requête de recherche réseau** :
    Surveiller les connexions DNS/HTTP sortantes vers les domaines `filev2[.]getsession[.]org` ou `seed1[.]getsession[.]org`.
* Analyser les logs système pour identifier des écritures ou des lectures suspectes sur `~/.claude/settings.json` ou `.vscode/tasks.json`.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Isoler immédiatement du réseau de l'entreprise l'ensemble des postes de développeurs ayant téléchargé ou mis à jour des paquets npm/PyPI ou extensions VS Code suspectes entre le 18 et le 21 mai 2026.
* Bloquer au niveau de la passerelle de filtrage réseau et du proxy d'entreprise les adresses IP et domaines associés aux serveurs de commande de TeamPCP.

**Éradication :**
* Supprimer de force tous les artefacts locaux stockés sous les chemins d'extensions de VS Code liés à Nx Console altérée.
* Révoquer l'intégralité des identifiants et clés d'accès cloud (AWS, GCP, Azure, GitHub, npm, PyPI) configurés sur les hôtes identifiés comme compromis.

**Récupération :**
* Reconstruire totalement à partir d'un master de système d'exploitation validé et sain les machines des collaborateurs touchés.
* Restaurer les projets de développement uniquement à partir de commits de dépôts de référence dont l'intégrité a été préalablement validée de manière indépendante.

#### Phase 4 — Activités post-incident

* Documenter de manière exhaustive le volume exact des dépôts de code source potentiellement exfiltrés.
* Réaliser une déclaration de violation de données personnelles auprès de la CNIL (sous 72h selon l'Art. 33 du RGPD) si des fichiers contenant des PII ou des données RH clients figuraient dans les dépôts exfiltrés.
* Ajuster et renforcer les filtres d'intégration continue (*CI/CD gatekeeping*) en y intégrant une validation de signature cryptographique Sigstore pour tous les tiers internes.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Découverte de fichiers de configuration VS Code modifiés contenant des commandes PowerShell ou Bash d'exfiltration. | T1195.002 | Journaux d'activité FIM / EDR | `index=endpoints EventID=11 (FileCreate) AND file_path="*.vscode/tasks.json" AND file_data="*getsession*"` |
| Recherche de connexions sortantes non autorisées via des modules Python suspects. | T1539 | logs Proxy / NetFlow | `index=proxy dest_ip IN (IPS_getsession_org)` |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | filev2[.]getsession[.]org | Serveur d'exfiltration de cookies et de secrets d'API de TeamPCP | Haute |
| Domaine | seed1[.]getsession[.]org | Serveur d'exfiltration de cookies de session et C2 secondaire | Haute |
| URL | hxxps[://]filev2[.]getsession[.]org/api/v1/exfil | Point de dépôt d'API utilisé pour téléverser les fichiers de configuration secrets | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1195.002 | Access Initial | Supply Chain Compromise | Empoisonnement des modules de packages de l'écosystème open-source npm/PyPI et des extensions de VS Code. |
| T1553.006 | Defense Evasion | Code Signing | Falsification de badges de provenance cryptographiques Sigstore pour contourner les contrôles d'intégrité logicielles. |
| T1539 | Credential Access | Steal Web Session Cookie | Extraction et vol de cookies de session OAuth persistants de développeurs pour neutraliser le MFA. |

---

### Sources

* [SANS ISC Diary 33016](https://isc.sans.edu/diary/rss/33016)
* [SANS ISC Diary 33014](https://isc.sans.edu/diary/rss/33014)

---

<div id="acr-stealer-infection-chain-via-fake-claude-ai-pages"></div>

## ACR Stealer infection chain via fake Claude AI pages

### Résumé technique

Une campagne intensive de malvertising exploite l'intérêt croissant autour des technologies d'intelligence artificielle pour attirer des utilisateurs vers de fausses pages d'atterrissage hébergées indûment sur le service Google Sites. Les attaquants imitent à la perfection l'identité visuelle de la suite Claude AI d'Anthropic pour inciter au téléchargement d'un prétendu client lourd de bureau pour Windows ou macOS. 

En réalité, le lien de téléchargement pointe vers un fichier archive contenant un exécutable malveillant compilé sur mesure. Ce programme déploie le malware d'exfiltration d'informations "ACR Stealer". Une fois en mémoire, ACR Stealer procède au profilage complet de la machine victime. Il inspecte et extrait les clés privées de portefeuilles de crypto-monnaies, copie les bases de données locales SQLite d'historiques et de mots de passe stockés sur l'ensemble des navigateurs Internet installés (Chrome, Firefox, Edge, Safari), et exfiltre ces données chiffrées vers des domaines d'infrastructure C2 configurés derrière Cloudflare pour éviter le blocage IP simple.

---

### Analyse de l'impact

L'impact porte sur la perte d'intégrité et de confidentialité des données d'authentification des employés. Le vol de cookies de session par ACR Stealer permet aux attaquants de réaliser des connexions directes vers des outils SaaS de l'entreprise (CRMs, ERPs, messageries). La sophistication de l'attaque est jugée modérée mais particulièrement efficace en raison de l'abus de services légitimes (Google Sites, Cloudflare) rendant la détection réseau initiale complexe.

---

### Recommandations

* Bloquer systématiquement les accès utilisateurs aux chemins d'hébergement personnels ou non administratifs sur le domaine `sites.google.com`.
* Utiliser un EDR configuré pour interdire à tout processus non signé d'accéder aux répertoires de profils de navigateurs (répertoires `User Data\Default` sous AppData).
* Implémenter des alertes d'authentification en cas d'apparition de sessions d'utilisateurs provenant de systèmes d'exploitation différents ou de localisations IP géographiquement anormales.

---

### Playbook de réponse à incident

#### Phase 1 — Preparation

* Configurer le serveur proxy ou la passerelle web sécurisée pour analyser le contenu dynamique des pages de création récente.
* Mettre en œuvre une politique de restriction de téléchargement de binaires non certifiés pour l'ensemble des terminaux d'utilisateurs non techniques.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * **Règle YARA de détection de fichier** :
    ```yara
    rule ACR_Stealer_In_Memory {
        meta:
            description = "Detects ACR Stealer memory patterns"
            author = "Senior Cyber Analyst"
        strings:
            $s1 = "fairpoint29.com" ascii wide
            $s2 = "primemetricsa.com" ascii wide
            $s3 = "sqlite3_column_text" ascii
        condition:
            all of them
    }
    ```
  * **Indicateur de comportement** :
    Processus non standard effectuant de multiples requêtes de lecture de fichiers SQLite dans AppData.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Isoler le terminal Windows ou macOS infecté du reste du réseau d'entreprise dès confirmation de l'exécution de l'archive ou du processus non approuvé.
* Procéder à la coupure réseau immédiate de toute communication vers les domaines d'exfiltration identifiés.

**Éradication :**
* Terminer le processus malveillant d'ACR Stealer via la console d'administration de l'EDR.
* Supprimer l'archive d'installation et nettoyer les fichiers temporaires du profil utilisateur.
* Forcer l'expiration de l'intégralité des sessions actives associées à tous les comptes d'utilisateurs authentifiés sur la machine lors de la compromission.

**Récupération :**
* Réinstaller le système d'exploitation concerné si le niveau de compromission système ou d'injection mémoire n'a pas pu être formellement circonscrit.
* Demander au collaborateur d'effectuer une réinitialisation générale de tous ses mots de passe personnels et professionnels.

#### Phase 4 — Activités post-incident

* Réaliser une chronologie des accès d'API externes pour confirmer si des jetons ou cookies de session volés ont été exploités par l'attaquant avant le confinement de la machine.
* Sensibiliser les collaborateurs aux dangers des campagnes d'annonces publicitaires frauduleuses ciblant les outils d'IA.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identification de connexions DNS initiées par des navigateurs vers des domaines d'exfiltration d'infostealers. | T1566.002 | Journaux DNS | `index=dns query IN ("*fairpoint29.com*", "*primemetricsa.com*")` |
| Détection d'accès anormaux aux répertoires de stockage des cookies de navigateurs par des processus non autorisés. | T1539 | logs Processus EDR | `index=endpoints action=file_read file_path="*AppData*Login Data*"` |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | fairpoint29[.]com | Serveur de Commande et de Contrôle (C2) d'ACR Stealer | Haute |
| Domaine | primemetricsa[.]com | Infrastructure de repli et d'exfiltration d'ACR Stealer | Haute |
| URL | hxxps[://]i[.]ibb[.]co/Xx16sbMz/init-block.jpg | Image d'initialisation de payload détournée | Moyenne |
| Hash SHA256 | 47fa746422f1bf6b7712dc6803378e6a995488007193a7441d790f70d204728f | Payload exécutable malveillant ACR Stealer pour environnement Windows | Haute |
| Hash SHA256 | 70b5ecc110e074dbca92932c0e840ea3492ea0a43c3f215b71392c12b02213b2 | Fichier d'installation d'ACR Stealer ciblant macOS | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566.002 | Access Initial | Spearphishing Link | Utilisation d'annonces publicitaires et de liens redirigeant vers de fausses pages de téléchargement Claude AI. |
| T1539 | Credential Access | Steal Web Session Cookie | Extraction de bases de données et de cookies de sessions locales des principaux navigateurs. |

---

### Sources

* [SANS ISC Diary](https://isc.sans.edu/diary/rss/33018)

---

<div id="kali365-phaas-targeting-microsoft-365-oauth-flow"></div>

## Kali365 PhaaS targeting Microsoft 365 OAuth flow

### Résumé technique

L'agence fédérale du FBI a émis une alerte critique concernant l'expansion du service de Phishing-as-a-Service nommé "Kali365". Cette plateforme industrielle est conçue pour cibler spécifiquement les comptes d'entreprises hébergés sur Microsoft 365. Contrairement aux portails de phishing traditionnels qui collectent de simples identifiants et mots de passe, Kali365 abuse du flux d'authentification par code d'appareil d'OAuth 2.0 (*Device Authorization Grant Flow*). 

Les attaquants envoient des messages incitant les utilisateurs à visiter le portail légitime de Microsoft (`hxxps[://]microsoft[.]com/devicelogin`) et à y saisir un code de vérification généré par la plateforme de l'attaquant. Dès que l'utilisateur saisit ce code et valide l'accès, le protocole OAuth délivre de manière transparente un jeton d'authentification de session complet à l'infrastructure de Kali365. L'attaquant obtient ainsi un accès de haut niveau à la boîte aux lettres et aux applications Teams/OneDrive de la victime, sans avoir eu besoin de connaître son mot de passe et en contournant l'ensemble des règles de validation MFA (Multi-Factor Authentication).

---

### Analyse de l'impact

L'impact est extrêmement important au niveau organisationnel, car il expose instantanément les documents d'entreprise, les boîtes de messagerie et l'ensemble de l'annuaire d'organisation. Ce type de vol de jetons OAuth persistants permet également d'établir des connexions ultérieures sans interaction, et de contourner les contrôles géographiques. La sophistication technique réside dans l'utilisation malveillante d'un protocole d'authentification légitime d'entreprise.

---

### Recommandations

* Désactiver complètement le protocole d'autorisation par code d'appareil (*Device Authorization Grant Flow*) au sein d'Entra ID pour l'ensemble des utilisateurs qui n'exploitent pas de terminaux sans navigateur (smart TV, IoT).
* Configurer des politiques d'accès conditionnel strictes imposant l'usage d'équipements gérés (*compliant devices*) pour toute validation de session OAuth.
* Sensibiliser les employés à ne jamais valider de codes de connexion reçus de manière inopinée par messagerie ou provenant d'expéditeurs externes.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Configurer les alertes d'administration Entra ID pour notifier toute demande d'authentification via le protocole par code d'appareil.
* S'assurer que les connexions administratives Microsoft 365 sont limitées aux plages d'adresses IP publiques de l'entreprise.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * **Requête KQL Entra ID** :
    ```kusto
    SigninLogs
    | where AuthenticationProtocol == "deviceCode"
    | project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName
    ```
  * **Indicateur de compromission** :
    Connexion d'appareil réussie via Device Code depuis une adresse IP géographique suspecte ne correspondant pas à l'emplacement physique réel de l'utilisateur.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Forcer immédiatement la révocation globale de l'ensemble des jetons de rafraîchissement d'OAuth et des sessions actives de l'utilisateur compromis via le portail d'administration d'Entra ID.
* Suspendre temporairement le compte d'utilisateur le temps de finaliser les vérifications de sécurité.

**Éradication :**
* Auditer et supprimer l'ensemble des applications tierces suspectes qui auraient pu obtenir un consentement d'autorisation OAuth durant l'incident.
* Bloquer le domaine de phishing relais de Kali365 identifié au niveau du système de filtrage de messagerie.

**Récupération :**
* Lever la suspension du compte utilisateur une fois la validité de l'authentification rétablie.
* Imposer l'enrôlement du terminal de l'utilisateur dans la console MDM de l'entreprise avant toute nouvelle session d'accès.

#### Phase 4 — Activités post-incident

* Mener une analyse forensique des journaux d'audit de Microsoft 365 pour s'assurer qu'aucune exfiltration massive d'emails ou de fichiers Sharepoint n'a eu lieu pendant l'accès frauduleux.
* Mettre à jour les règles d'accès conditionnel de l'entreprise pour interdire définitivement le Device Code flow.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'utilisateurs s'étant authentifiés via le protocole d'appareil sans motif de service valide. | T1528 | Journaux Azure Sign-In | `index=azure_signin protocol="DeviceCode"` |
| Identification de modifications de consentements d'applications tierces au sein d'Entra ID. | T1528 | Audit Logs d'Entra ID | `index=azure_audit activity_name="Consent to application"` |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | hxxps[://]microsoft[.]com/devicelogin | Portail d'authentification légitime utilisé comme vecteur d'abus | Haute |
| Domaine | login[.]microsoft-secure[.]com | Faux portail d'enregistrement et de phishing exploité par Kali365 | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1528 | Credential Access | Steal Application Access Token | Interception et vol de jetons d'accès d'application Microsoft 365 OAuth via l'abus du flux Device Code. |
| T1566.002 | Access Initial | Spearphishing Link | Envoi de messages de leurres incitant à visiter le lien officiel et à entrer un code malveillant. |

---

### Sources

* [FBI Cyber Division PSA](https://www.bleepingcomputer.com/news/security/fbi-warns-of-kali365-phishing-service-targeting-microsoft-365-accounts/)

---

<div id="yy-lai-yu-chinese-language-phaas-targeting-japanese-market"></div>

## YY Lai Yu Chinese-language PhaaS targeting Japanese market

### Résumé technique

Les chercheurs en cybersécurité ont mis en évidence la montée en puissance de l'écosystème de phishing "YY Lai Yu". Il s'agit d'une plateforme de *Phishing-as-a-Service* (PhaaS) de langue chinoise hautement structurée qui cible de manière privilégiée le marché de consommation japonais. Le vecteur d'attaque exploite massivement les protocoles SMS, iMessage et RCS pour acheminer des leurres réalistes évoquant des gains de points de fidélité ou des remboursements d'aides à l'énergie du gouvernement. 

Le lien de ces messages redirige la victime vers une interface dynamique d'interception d'OTP (One-Time Password) gérée en temps réel par les opérateurs de la plateforme. Lorsqu'un utilisateur saisit son mot de passe et son OTP de confirmation bancaire, les informations sont instantanément transmises via des canaux synchronisés au panneau de contrôle de l'attaquant. Celui-ci peut alors bypasser l'authentification forte en temps réel pour valider des transactions frauduleuses ou directement enregistrer (*provisioner*) la carte de paiement compromise au sein de portefeuilles numériques Google Pay ou Apple Pay configurés sur ses propres terminaux physiques.

---

### Analyse de l'impact

L'impact financier direct est très élevé en raison du détournement immédiat de fonds bancaires. La structure automatisée de la plateforme permet de générer des centaines d'instances de phishing différentes de manière simultanée. Le niveau de sophistication est considéré comme élevé en raison de l'infrastructure d'anti-botting humaine mise en place pour interdire l'analyse automatique par les scanners de sécurité des éditeurs de solutions défensives.

---

### Recommandations

* Déployer l'authentification forte de type FIDO2/WebAuthn pour l'ensemble des systèmes d'accès internes afin de résister aux interceptions d'OTP par phishing d'intercepteur.
* Mettre en œuvre une politique d'interdiction d'enregistrement de cartes professionnelles au sein de portefeuilles de paiement mobiles non préalablement certifiés.
* Collaborer activement avec les institutions bancaires partenaires pour mettre en place des blocages instantanés dès l'apparition d'alertes de transactions de tokenisation suspectes.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Assurer des campagnes régulières de sensibilisation auprès des utilisateurs concernant l'hameçonnage ciblant les messages de type SMS/iMessage professionnels.
* Valider les configurations MDM pour s'assurer que les applications de messagerie d'entreprise filtrent les URLs suspectes.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * **Analyse de logs MDM** :
    Rechercher les ouvertures d'URLs éphémères de sous-domaines contenant des mots clés de fidélité ou d'institutions bancaires japonaises.
  * **Comportement suspect** :
    Réception de messages groupés iMessage/RCS contenant des liens courts redirigeant vers des adresses IP d'hébergeurs asiatiques alternatifs.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Bloquer le domaine principal de YY Lai Yu sur les serveurs de filtrage Web et DNS de l'entreprise.
* Isoler le terminal mobile de l'utilisateur s'il s'agit d'une flotte professionnelle et révoquer les sessions de messagerie synchronisées.

**Éradication :**
* Déclarer l'URL malveillante auprès des principaux moteurs de réputation web (Google Safe Browsing, Microsoft SmartScreen) pour bloquer l'accès public au site de phishing.
* Contacter les établissements bancaires pour invalider toute carte de paiement d'entreprise compromise et bloquer les jetons de paiement mobiles nouvellement associés.

**Récupération :**
* Rétablir l'accès de l'utilisateur après renouvellement complet des identifiants et remplacement de la carte bancaire affectée.

#### Phase 4 — Activités post-incident

* Mener un débriefing de l'incident avec l'équipe de sécurité financière de l'entreprise afin de raffiner les seuils d'alertes d'utilisation des cartes professionnelles de paiement.
* Documenter la timeline de l'attaque pour l'intégrer au flux d'amélioration continue des règles d'accès conditionnel.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identification de connexions réseau mobiles d'entreprise vers des panels administratifs de YY Lai Yu. | T1566.002 | logs DNS Mobile / proxy MDM | `index=mdm_dns query IN ("*yylaiyu.com*", "*yylaiyu*")` |
| Détection d'anomalies de double connexion (deux terminaux pour un même compte de paiement). | T1556 | logs de transactions financières | `index=transactions device_count > 1` |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | yylaiyu[.]com | Domaine d'administration de la plateforme de PhaaS chinoise | Haute |
| URL | hxxps[://]yylaiyu[.]com/panel/login | URL d'accès au panneau de configuration des kits de phishing | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566.002 | Access Initial | Spearphishing Link | Diffusion de liens frauduleux de fidélité via des vecteurs SMS, iMessage et RCS. |
| T1556 | Credential Access | Modify Authentication Process | Capture dynamique et interception des codes de validation à usage unique (OTP) des utilisateurs. |

---

### Sources

* [Google Threat Intelligence Group](https://cloud.google.com/blog/topics/threat-intelligence/chinese-language-phishing-services/)

---

<!--
CONTRÔLE FINAL

1. Aucun article n'apparaît dans plusieurs sections : [Vérifié]
2. La TOC est présente et chaque lien pointe vers une ancre existante : [Vérifié]
3. Chaque ancre est unique — <div id="..."> statiques ET dynamiques présents, cohérents avec la TOC ET identiques entre TOC / div id / table interne : [Vérifié]
4. Tous les IoC sont en mode DEFANG : [Vérifié]
5. Aucun article de Vulnérabilités ou Géopolitique dans la section "Articles" : [Vérifié]
6. Le tableau des vulnérabilités ne contient que des entrées avec score composite ≥ 1 : [Vérifié]
7. La table de tri intermédiaire est présente et l'ordre du tableau final correspond ligne par ligne : [Vérifié]
8. Toutes les sections attendues sont présentes : [Vérifié]
9. Le playbook est contextualisé (pas de tâches génériques) : [Vérifié]
10. Les hypothèses de threat hunting sont présentes pour chaque article : [Vérifié]
11. Tout article sans URL complète disponible dans raw_content est dans "Articles non sélectionnés" — aucun article sans URL complète ne figure dans les synthèses ou la section "Articles" : [Vérifié]
12. Chaque article est COMPLET (9 sections toutes présentes) — aucun article tronqué : [Vérifié]
13. Chaque article doit contenir un PLAYBOOK DE REPONSE A INCIDENT avec les 5 phases : Phase 1 — Préparation, Phase 2 — Détection et analyse, Phase 3 — Confinement, éradication et récupération, Phase 4 — Activités post-incident, Phase 5 — Threat Hunting (proactif) : [Vérifié]
14. Aucun bug fonctionnel, article commercial ou contenu non-sécuritaire dans la section "Articles" : [Vérifié]

Statut global : [✅ Rapport valide]
-->