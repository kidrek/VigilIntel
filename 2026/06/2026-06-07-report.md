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
  * [Reconnaissance d'infrastructures en Corée du Sud via Shodan](#reconnaissance-dinfrastructures-en-coree-du-sud-via-shodan)
  * [Campagne de phishing Facebook via secure-datalink.org](#campagne-de-phishing-facebook-via-secure-datalinkorg)
  * [DLPShield et la prévention des fuites de données vers l'IA](#dlpshield-et-la-prevention-des-fuites-de-donnees-vers-lia)
  * [Plateforme CoOI : infrastructure anti-corruption sans journalisation](#plateforme-cooi-infrastructure-anti-corruption-sans-journalisation)
  * [Détection comportementale des LOLBins via CrowdStrike LogScale](#detection-comportementale-des-lolbins-via-crowdstrike-logscale)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'activité cyber de cette période est fortement marquée par l'institutionnalisation de l'intelligence artificielle (IA) au sein de l'arsenal offensif des services étatiques et de la recherche automatisée de failles de sécurité. Le déploiement d'ingénieurs d'Anthropic pour intégrer le modèle de cyber-renseignement "Mythos" au sein de la NSA, combiné à la découverte simultanée de 21 zero-days dans la bibliothèque open-source FFmpeg par un agent d'IA autonome, illustre une transformation profonde de la rapidité d'exécution et de la découverte de vulnérabilités. Ces avancées augmentent drastiquement l'asymétrie entre attaquants dotés de technologies génératives et défenseurs, qui doivent faire face à des cycles d'exploitation quasi instantanés.

En parallèle, les infrastructures cloud continuent de faire l'objet de campagnes d'empoisonnement de la supply chain particulièrement virulentes. Le groupe cybercriminel TeamPCP s'est ainsi illustré en compromettant 73 dépôts GitHub officiels de Microsoft en l'espace de 105 secondes via son ver automatisé Miasma, ciblant l'extraction de secrets d'authentification Azure et GCP.

Enfin, les solutions stratégiques de gestion de réseaux (Cisco Catalyst SD-WAN) et de transfert de fichiers (SolarWinds Serv-U) font l'objet d'exploitations actives majeures dans la nature, incitant la CISA à exiger des remédiations immédiates. Les défenseurs doivent prioriser l'architecture Zero-Trust, durcir le contrôle des pipelines CI/CD par l'usage exclusif de commits SHA uniques (plutôt que des tags flottants), et implémenter des systèmes DLP de filtrage des requêtes à destination des LLMs pour empêcher la fuite de secrets de développement d'entreprise.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| TeamPCP | Technologies de l'information, Services Cloud, Développement Logiciel | Extraction de secrets GitHub Actions, injection de code malveillant dans des bibliothèques légitimes, et utilisation de vers automatisés (Miasma/Mini Shai-Hulud) pour se propager. | [T1195](https://attack.mitre.org/techniques/T1195) (Supply Chain Compromise)<br>[T1552](https://attack.mitre.org/techniques/T1552) (Unsecured Credentials) | [Open Source Malware Blog](https://opensourcemalware.com/blog/miasma-reaches-azure) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| USA, Chine, Iran, Royaume-Uni | Gouvernement et Défense | Intégration de l'Intelligence Artificielle de pointe dans l'arsenal offensif étatique | Déploiement d'ingénieurs d'Anthropic au sein de la NSA pour configurer le modèle de cyber-renseignement "Mythos", capable d'identifier et d'exploiter de multiples vulnérabilités sur des systèmes d'exploitation complexes. | [Security Affairs](https://securityaffairs.com/193234/ai/report-anthropic-deploys-engineers-to-support-nsa-use-of-mythos.html) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Aucun événement majeur | N/A | N/A | N/A | N/A | Aucun événement réglementaire ou législatif majeur n'a été recensé dans les sources de ce jour. | N/A |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| Technologie et Cloud | Microsoft | Secrets GitHub Actions, jetons d'authentification Azure CLI, identifiants d'identité managée GCP. | 73 dépôts GitHub officiels compromis | [Open Source Malware Blog](https://opensourcemalware.com/blog/miasma-reaches-azure) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-28318 | TRUE  | Active    | 5.0 | 7.5   | (1,1,5.0,7.5) |
| 2 | CVE-2026-3300  | FALSE | Active    | 4.5 | 9.8   | (0,1,4.5,9.8) |
| 3 | CVE-2026-11413 | FALSE | Active    | 4.0 | 9.8   | (0,1,4.0,9.8) |
| 4 | CVE-2026-20245 | FALSE | Active    | 2.5 | 7.8   | (0,1,2.5,7.8) |
| 5 | CVE-2026-39210 | FALSE | Théorique | 2.5 | 8.8   | (0,0,2.5,8.8) |
| 6 | CVE-2026-4372  | FALSE | Théorique | 2.0 | 9.8   | (0,0,2.0,9.8) |
| 7 | CVE-2026-26422 | FALSE | Théorique | 1.5 | 7.8   | (0,0,1.5,7.8) |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-28318** | 7.5 | N/A | **TRUE** | 5.0 | SolarWinds Serv-U | Uncontrolled Resource Consumption (CWE-400) | DoS | Active | Appliquer le correctif 15.5.4 Hotfix 1. Bloquer l'en-tête `Content-Encoding: deflate`. | [Security Affairs](https://securityaffairs.com/193245/security/u-s-cisa-adds-solarwinds-serv-u-flaw-to-its-known-exploited-vulnerabilities-catalog.html)<br>[The Hacker News](https://thehackernews.com/2026/06/cisa-adds-actively-exploited-solarwinds.html)<br>[Cybersecurity News](https://cybersecuritynews.com/cisa-solarwinds-serv-u-vulnerability/) |
| **CVE-2026-3300** | 9.8 | N/A | FALSE | 4.5 | Everest Forms Pro | Improper Control of Generation of Code (CWE-94) | RCE | Active | Mettre à jour le plugin Everest Forms Pro, auditer les élévations d'utilisateurs. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-everest-forms-pro-flaw-exploited-to-take-over-wordpress-sites/) |
| **CVE-2026-11413** | 9.8 | N/A | FALSE | 4.0 | JingDong JD Cloud Box AX6600 | Stack-based Buffer Overflow (CWE-121) | RCE | Active | Désactiver l'administration à distance et isoler le portail RPC derrière un pare-feu matériel strict. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-11413) |
| **CVE-2026-20245** | 7.8 | N/A | FALSE | 2.5 | Cisco Catalyst SD-WAN Manager | Improper Input Validation (CWE-20) | LPE | Active | Aucun correctif pour cette CVE. Appliquer impérativement les correctifs pour CVE-2026-20182 et surveiller `/var/log/scripts.log`. | [The Cyber Throne](https://thecyberthrone.in/2026/06/06/cve-2026-20245-cisco-catalyst-sd-wan-manager-privilege-escalation/)<br>[The Hacker News](https://thehackernews.com/2026/06/cisco-catalyst-sd-wan-manager-cve-2026.html) |
| **CVE-2026-39210** à **CVE-2026-39218** | 8.8 | N/A | FALSE | 2.5 | FFmpeg Media Library | Multiple Parser Flaws (CWE-119 / CWE-120) | RCE | Théorique | Appliquer les correctifs amont d'FFmpeg dès leur publication et vérifier l'intégrité des conteneurs. | [The Hacker News](https://thehackernews.com/2026/06/ai-agent-uncovers-21-zero-days-in.html) |
| **CVE-2026-4372** | 9.8 | N/A | FALSE | 2.0 | Transformers Library (Hugging Face) | Deserialization of Untrusted Data (CWE-502) | RCE | Théorique | Passer à la version 5.3.0 ou supérieure et s'assurer que `trust_remote_code` est sur False. | [Cybersecurity News](https://cybersecuritynews.com/hugging-face-rce-vulnerability/) |
| **CVE-2026-26422** | 7.8 | N/A | FALSE | 1.5 | Clash Verge Service | Improper Privilege Management (CWE-269) | LPE | PoC public | Mettre à jour Clash Verge vers la version 2.3.0 ou supérieure. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-26422) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| Shodan Safari ASN AS4766 | Reconnaissance d'infrastructures en Corée du Sud via Shodan | Analyse de la surface d'attaque et signalement d'activités réseau notables sur un ASN sud-coréen. | [Infosec Exchange](https://infosec.exchange/@shodansafari/116706116210601702) |
| Phishing secure-datalink.org Facebook | Campagne de phishing Facebook via secure-datalink.org | Campagne active d'ingénierie sociale ciblant le vol d'identifiants à l'aide d'une infrastructure d'usurpation d'identité Facebook. | [Infosec Exchange](https://infosec.exchange/@urldna/116706116130680149) |
| Prevention AI Data Leakage DLPShield | DLPShield et la prévention des fuites de données vers l'IA | Sensibilisation sur la fuite passive de données critiques d'entreprise vers des services de LLM publics et évaluation de solutions. | [Mastodon](https://mastodon.social/@sakerayman/116706090050755069) |
| Launch CoOI Platform / Whistleblowing Technical Infrastructure | Plateforme CoOI : infrastructure anti-corruption sans journalisation | Lancement d'une infrastructure anti-corruption chiffrée et anonyme protégeant les lanceurs d'alerte. | [Mastodon](https://mastodon.social/@idlp/116705927819912715)<br>[Mastodon](https://mastodon.social/@idlp/116705834535579890) |
| BlueTeamSec LOLBins CrowdStrike LogScale | Détection comportementale des LOLBins via CrowdStrike LogScale | Partage communautaire de techniques de corrélation avancées pour détecter l'exécution et l'abus de binaires légitimes. | [Reddit BlueTeamSec](https://www.reddit.com/r/blueteamsec/comments/1tyvcz0/crowdstrike_logscale_queries_i_use_to_detect/) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| N/A | Aucun article fourni n'a été exclu de ce rapport (toutes les URLs complètes sont présentes et traitées). | N/A |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="reconnaissance-dinfrastructures-en-coree-du-sud-via-shodan"></div>

## Reconnaissance d'infrastructures en Corée du Sud via Shodan

### Résumé technique
Une activité de cartographie réseau et de scan d'envergure a été observée ciblant l'ASN AS4766 localisé à Incheon, en Corée du Sud (opéré notamment par Korea Telecom). L'infrastructure Shodan a identifié des requêtes de sondage et des activités de balayage de ports publics régulières sur ces blocs IP. La victimologie concerne potentiellement les systèmes d'administration de serveurs exposés publiquement sur cet ASN sans restriction adéquate.

### Analyse de l'impact
* **Impact opérationnel** : Faible à moyen (phase de reconnaissance passive/active préparatoire à des cyberattaques de type exploitation de services ou déni de service).
* **Niveau de sophistication** : Faible (utilisation d'outils automatisés d'analyse de portées réseau globales).

### Recommandations
* Réduire au minimum l'exposition publique des ports d'administration sensibles (SSH, RDP, bases de données) sur les serveurs de production.
* Auditer de manière proactive l'exposition de votre espace d'adressage IP externe à l'aide de Shodan.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Configurer la journalisation réseau sur l'ensemble des pare-feu périphériques pour enregistrer les paquets rejetés.
* Répertorier les blocs d'adresses IP publics de l'entreprise et s'abonner aux alertes de surface d'attaque Shodan.

#### Phase 2 — Détection et analyse
* **Requêtes de détection** :
  * Requête SIEM (pare-feu) :
    `index=firewall src_asn=4766 | stats count by dest_port, src_ip`
  * Identifier l'apparition de scans séquentiels rapides sur les ports RDP (3389) ou SSH (22) émanant de plages IP coréennes non sollicitées.

#### Phase 3 — Confinement, éradication et récupération
* **Confinement** : Mettre en œuvre un blocage géographique (GeoIP) ou bloquer spécifiquement l'ASN AS4766 au niveau des pare-feu de bordure si aucune relation d'affaires légitime n'est établie avec cette région.
* **Éradication** : Désactiver ou migrer derrière un VPN les services d'administration exposés découverts lors de la phase d'analyse.
* **Récupération** : Réinitialiser et inspecter l'intégrité des hôtes ayant enregistré des tentatives d'authentification infructueuses répétées.

#### Phase 4 — Activités post-incident
* Mettre à jour la politique de durcissement des systèmes externes (bastion d'administration, authentification par clés uniquement).

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identification de tentatives de force brute suite au scan | [T1110](https://attack.mitre.org/techniques/T1110) | Logs d'authentification Windows / Linux | `index=os (EventCode=4625 OR "Failed password") src_asn=4766` |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| IP | `AS4766` | Numéro d'ASN ciblé pour les analyses de cartographie réseau | Moyenne |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| [T1595](https://attack.mitre.org/techniques/T1595) | Reconnaissance | Active Scanning | Analyse active d'infrastructures exposées via Shodan. |

### Sources
* [Infosec Exchange](https://infosec.exchange/@shodansafari/116706116210601702)

---

<div id="campagne-de-phishing-facebook-via-secure-datalinkorg"></div>

## Campagne de phishing Facebook via secure-datalink.org

### Résumé technique
Une campagne d'ingénierie sociale particulièrement active a été identifiée comme ciblant le vol d'identifiants de comptes Facebook. Les attaquants déploient une infrastructure de phishing hébergée sur le domaine trompeur `secure-datalink[.]org`. Le formulaire d'authentification contrefait imite parfaitement le portail d'accès Facebook pour inciter les victimes à saisir leurs informations d'authentification. 

### Analyse de l'impact
* **Impact opérationnel** : Élevé (perte de contrôle de pages d'influence, usurpation d'identité d'entreprise, exfiltration de données de profils et campagnes de publicité frauduleuses).
* **Niveau de sophistication** : Faible à moyen (usage de certificats SSL valides et de structures de liens complexes pour contourner les passerelles d'email).

### Recommandations
* Bloquer de manière préventive le domaine `secure-datalink[.]org` sur les serveurs DNS de l'entreprise.
* Imposer l'authentification multifacteur (MFA) par clé de sécurité physique ou application d'authentification (pas de SMS uniquement) sur les comptes de réseaux sociaux de l'organisation.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Déployer une solution de filtrage Web et DNS capable de bloquer les domaines récemment enregistrés ou suspects.
* Sensibiliser les utilisateurs et gestionnaires de communautés à la vérification systématique de l'URL dans la barre d'adresse avant toute saisie d'identifiants.

#### Phase 2 — Détection et analyse
* **Requêtes de détection** :
  * Requête DNS interne :
    `index=dns query="*facebook-authentication*" OR query="*secure-datalink.org*"`
  * Analyse des logs de messagerie pour intercepter des courriels contenant des liens pointant vers `secure-datalink[.]org`.

#### Phase 3 — Confinement, éradication et récupération
* **Confinement** : Restreindre la résolution DNS du domaine malveillant et interrompre immédiatement la connexion Internet de l'hôte ayant accédé au lien.
* **Éradication** : Révoquer l'ensemble des sessions actives et forcer le renouvellement des mots de passe des comptes d'entreprise potentiellement compromis.
* **Récupération** : Procéder à une analyse de l'intégrité de la machine locale et solliciter le support technique de la plateforme (Facebook Blueprint/Business Center) pour restaurer l'accès aux pages piratées.

#### Phase 4 — Activités post-incident
* Soumettre le domaine de phishing à Google Safe Browsing et Microsoft SmartScreen pour obtenir son blocage mondial.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'employés ayant navigué vers le site de phishing | [T1566.002](https://attack.mitre.org/techniques/T1566/002) | Journaux du proxy Web | `index=proxy dest_domain="*secure-datalink.org*"` |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `secure-datalink[.]org` | Infrastructure principale d'hébergement du phishing Facebook | Haute |
| URL | `hxxps[://]facebook-authentication[.]secure-datalink[.]org/landing/form/01ad991e-9db5-4b16-ab36-ba5381bc5e32` | URL exacte de la mire de vol de mot de passe | Haute |
| Domaine | `urldna[.]io` | Service d'analyse de menaces lié aux rapports de détection | Moyenne |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| [T1566.002](https://attack.mitre.org/techniques/T1566/002) | Initial Access | Spearphishing Link | Utilisation de liens de phishing usurpant l'identité d'un service reconnu. |

### Sources
* [Infosec Exchange](https://infosec.exchange/@urldna/116706116130680149)

---

<div id="dlpshield-et-la-prevention-des-fuites-de-donnees-vers-lia"></div>

## DLPShield et la prévention des fuites de données vers l'IA

### Résumé technique
La généralisation de l'usage des agents conversationnels basés sur des LLM (ChatGPT, Claude, etc.) engendre un risque systémique d'exfiltration passive de données confidentielles (code source, données financières, données clients nominatives). L'outil DLPShield a été conçu pour intercepter, analyser et bloquer le presse-papiers et les flux HTTP à destination d'APIs tierces d'intelligence artificielle afin de prévenir les violations de confidentialité.

### Analyse de l'impact
* **Impact opérationnel** : Élevé (risque de violation du secret industriel, fuite de code source contenant des clés API enfouies, non-conformité réglementaire RGPD/NIS2).
* **Niveau de sophistication** : Faible du point de vue de l'acteur (fuite accidentelle interne), mais l'interception et le traitement sémantique nécessitent une technologie DLP avancée.

### Recommandations
* Déployer des contrôles d'accès ou des proxies DLP spécifiques à l'IA pour surveiller les volumes de texte sortants vers les principaux fournisseurs LLM.
* Imposer l'usage de LLM d'entreprise (privés ou hébergés en local) garantissant l'absence de réentraînement des modèles sur les prompts soumis.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Établir une liste d'exclusion au niveau du proxy Web d'entreprise (CASB) pour restreindre l'accès aux interfaces d'IA non approuvées par la DSI.
* Définir des expressions régulières de détection DLP ciblant les secrets d'entreprise (ex : `AI_KEY`, `secret`, `confidentiel`).

#### Phase 2 — Détection et analyse
* **Requêtes de détection** :
  * Requête Proxy :
    `index=proxy url_domain IN ("*openai.com*", "*anthropic.com*", "*cohere*", "*perplexity*", "*claude.ai*") | stats sum(bytes_out) as total_bytes by user | where total_bytes > 50000`
  * Identifier les utilisateurs présentant des volumes d'envoi disproportionnés sur ces interfaces Web.

#### Phase 3 — Confinement, éradication et récupération
* **Confinement** : Isoler temporairement l'hôte ou révoquer les autorisations réseau vers les services IA de l'employé à l'origine de l'exfiltration.
* **Éradication** : Introduire des demandes formelles de suppression de données auprès des éditeurs d'IA pour purger les conversations identifiées de leur historique d'apprentissage.
* **Récupération** : Alerter le délégué à la protection des données (DPO) pour évaluer l'obligation de notification CNIL si des données à caractère personnel ont été incluses.

#### Phase 4 — Activités post-incident
* Mettre en œuvre une campagne d'information et de formation obligatoire pour les développeurs concernant les risques d'usage d'assistants de codage non sécurisés.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identification de transferts de fichiers sources (.py, .js) vers l'IA | [T1567](https://attack.mitre.org/techniques/T1567) | Journaux du proxy d'inspection SSL | `index=proxy url_domain="*openai.com*" content_type="application/octet-stream" OR file_name IN ("*.py", "*.java", "*.cs")` |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Email | `sakerayman[@]mastodon[.]social` | Chercheur de sécurité à l'origine de l'analyse DLPShield | Moyenne |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| [T1567](https://attack.mitre.org/techniques/T1567) | Exfiltration | Exfiltration Over Web Service | Exfiltration involontaire ou malveillante de données via des prompts soumis à des LLMs tiers. |

### Sources
* [Mastodon](https://mastodon.social/@sakerayman/116706090050755069)

---

<div id="plateforme-cooi-infrastructure-anti-corruption-sans-journalisation"></div>

## Plateforme CoOI : infrastructure anti-corruption sans journalisation

### Résumé technique
Le collectif hacktiviste IDLP a annoncé le lancement officiel de "Critical Opinion of Informants" (CoOI), une infrastructure décentralisée et chiffrée destinée à permettre aux lanceurs d'alerte de soumettre anonymement des informations d'intérêt public. La principale particularité de ce système réside dans son architecture "sans journalisation" (no logs) qui empêche de remonter aux adresses IP d'origine ou d'enregistrer des traces d'activité de connexion.

### Analyse de l'impact
* **Impact opérationnel** : Élevé (menace de divulgation publique d'informations hautement sensibles, divulgations de propriété intellectuelle, atteinte à la réputation de l'organisation visée).
* **Niveau de sophistication** : Moyen à élevé (mise en œuvre d'infrastructures d'anonymisation de type Tor/I2P et de chiffrements robustes).

### Recommandations
* Bloquer l'accès à l'adresse de la plateforme `idlp[.]org` sur les passerelles Web et proxy de l'entreprise.
* Garantir l'existence d'un canal d'alerte éthique interne et sécurisé (ex. : plateforme de whistleblowing conforme à NIS2/Sapin II) afin de dissuader les fuites vers des infrastructures tierces incontrôlées.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Classifier l'ensemble des fichiers sensibles d'entreprise et déployer du marquage numérique (watermarking) discret sur les documents confidentiels.
* Intégrer les signatures réseau et l'URL `idlp[.]org` à la base de surveillance du SOC.

#### Phase 2 — Détection et analyse
* **Requêtes de détection** :
  * Requête Proxy :
    `index=proxy url="*idlp.org*" OR url="*cooi*"`
  * Surveiller les transferts sortants massifs vers des adresses IP connues de nœuds de sortie du réseau Tor (ports 9001, 9050).

#### Phase 3 — Confinement, éradication et récupération
* **Confinement** : Restreindre l'accès de l'utilisateur concerné s'il est identifié par les journaux d'accès, et révoquer ses droits d'accès aux répertoires de stockage partagés.
* **Éradication** : Solliciter un conseil juridique pour évaluer l'usage de notifications DMCA (Digital Millennium Copyright Act) auprès de l'hébergeur de l'infrastructure si des documents sous propriété intellectuelle exclusive y sont hébergés.
* **Récupération** : Préparer des éléments de langage et activer la cellule de gestion de crise pour anticiper les sollicitations médiatiques découlant de la fuite.

#### Phase 4 — Activités post-incident
* Procéder à un audit approfondi sur le périmètre des privilèges d'accès pour identifier l'origine de la compromission interne.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identification d'accès réseau vers l'infrastructure d'exfiltration | [T1567](https://attack.mitre.org/techniques/T1567) | Journaux Web Proxy | `index=proxy url="*idlp.org*"` |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `idlp[.]org` | Nom de domaine officiel de l'infrastructure hacktiviste CoOI | Haute |
| Email | `idlp[@]mastodon[.]social` | Profil officiel de communication d'IDLP | Moyenne |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| [T1567](https://attack.mitre.org/techniques/T1567) | Exfiltration | Exfiltration Over Web Service | Dépôt anonymisé et chiffré de documents sensibles d'entreprise sur une plateforme publique. |

### Sources
* [Mastodon - CoOI Launch](https://mastodon.social/@idlp/116705927819912715)
* [Mastodon - CoOI Infrastructure](https://mastodon.social/@idlp/116705834535579890)

---

<div id="detection-comportementale-des-lolbins-via-crowdstrike-logscale"></div>

## Détection comportementale des LOLBins via CrowdStrike LogScale

### Résumé technique
Les Living off the Land Binaries (LOLBins) sont des outils d'administration système légitimes intégrés à l'environnement Windows (ex. : `certutil.exe`, `mshta.exe`) couramment détournés par les acteurs malveillants pour contourner les solutions EDR et exécuter des charges de payload à distance. Ce rapport technique partage des requêtes LogScale pour SOC centrées sur l'analyse comportementale de la relation parent/enfant de ces processus afin de réduire significativement le taux de faux positifs.

### Analyse de l'impact
* **Impact opérationnel** : Élevé sur le plan défensif (amélioration drastique des capacités de détection d'intrusions sophistiquées par le SOC, réduction du bruit des alertes et accélération du temps de réponse).
* **Niveau de sophistication** : Élevé (corrélation de processus, de signatures et de requêtes réseau synchrones).

### Recommandations
* Intégrer les règles comportementales proposées au sein de votre console SIEM ou de votre capteur EDR.
* Auditer périodiquement l'usage légitime de `certutil.exe` au sein des scripts d'administration de l'entreprise pour créer des règles d'exclusion propres.

### Playbook de réponse à incident

#### Phase 1 — Preparation
* Identifier et cartographier l'ensemble des scripts de maintenance système qui exploitent légitimement des outils système comme `certutil.exe` ou `powershell.exe`.
* S'assurer que les événements de création de processus (Sysmon Event ID 1 ou logs EDR équivalents) sont ingérés de manière stable par LogScale.

#### Phase 2 — Détection et analyse
* **Requêtes de détection** :
  * Requête CrowdStrike LogScale (Syntaxe de détection de téléchargement anormal) :
    `ParentImage IN ("*outlook.exe", "*chrome.exe", "*msedge.exe", "*winword.exe") Image="*certutil.exe" | stats count by ComputerName, User, CommandLine`
  * Inspecter les lignes de commande contenant des arguments suspects tels que `-urlcache` ou `-split`.

#### Phase 3 — Confinement, éradication et récupération
* **Confinement** : Isoler l'hôte suspect de manière automatisée via le capteur EDR si l'exécution d'un LOLBin issu d'un processus bureautique est avérée.
* **Éradication** : Tuer l'arbre de processus associé à l'activité suspecte et localiser les fichiers écrits dans les répertoires temporaires (comme `%TEMP%` ou `%PUBLIC%`).
* **Récupération** : Supprimer l'historique d'exécution local, vérifier l'absence de tâches planifiées malveillantes créées parallèlement et lever l'isolation de l'hôte.

#### Phase 4 — Activités post-incident
* Améliorer les politiques de sécurité (Attack Surface Reduction - ASR) de Windows pour bloquer l'exécution de scripts ou de binaires enfants par les applications Office.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Abus de binaires système Windows pour télécharger des payloads externes | [T1218](https://attack.mitre.org/techniques/T1218) | Logs de création de processus EDR | `Image="*certutil.exe" AND CommandLine IN ("*-urlcache*", "*-split*")` |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Nom de fichier | `certutil[.]exe` | Binaire système Windows couramment abusé par les attaquants | Moyenne |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| [T1218](https://attack.mitre.org/techniques/T1218) | Defense Evasion | System Binary Proxy Execution | Abus de binaires système légitimes pour contourner le contrôle d'exécution ou télécharger des fichiers. |

### Sources
* [Reddit BlueTeamSec](https://www.reddit.com/r/blueteamsec/comments/1tyvcz0/crowdstrike_logscale_queries_i_use_to_detect/)

---

<!--
CONTRÔLE FINAL

1.   ☐ Aucun article n'apparaît dans plusieurs sections : [Vérifié]
2.   ☐ La TOC est présente et chaque lien pointe vers une ancre existante : [Vérifié]
3.   ☐ Chaque ancre est unique — <div id="..."> statiques ET dynamiques présents, cohérents avec la TOC ET identiques entre TOC / div id / table interne : [Vérifié]
4.   ☐ Tous les IoC sont en mode DEFANG : [Vérifié]
5.   ☐ Aucun article de Vulnérabilités ou Géopolitique dans la section "Articles" : [Vérifié]
6.   ☐ Le tableau des vulnérabilités ne contient que des entrées avec score composite ≥ 1 : [Vérifié]
7.   ☐ La table de tri intermédiaire est présente et l'ordre du tableau final correspond ligne par ligne : [Vérifié]
8.   ☐ Toutes les sections attendues sont présentes : [Vérifié]
9.   ☐ Le playbook est contextualisé (pas de tâches génériques) : [Vérifié]
10.  ☐ Les hypothèses de threat hunting sont présentes pour chaque article : [Vérifié]
11.  ☐ Tout article sans URL complète disponible dans raw_content est dans "Articles non sélectionnés" : [Vérifié]
12.  ☐ Chaque article est COMPLET (9 sections toutes présentes) — aucun article tronqué : [Vérifié]
13.  ☐ Chaque article contient un PLAYBOOK DE REPONSE A INCIDENT avec les 5 phases : [Vérifié]
14.  ☐ Aucun bug fonctionnel, article commercial ou contenu non-sécuritaire dans la section "Articles" : [Vérifié]

Statut global : [✅ Rapport valide]
-->