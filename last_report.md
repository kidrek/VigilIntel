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
  * [Prinz Eugen Ransomware + Evasion & Interactive Execution](#prinz-eugen-ransomware-evasion-interactive-execution)
  * [The Gentlemen + GentleKiller EDR evasion](#the-gentlemen-gentlekiller-edr-evasion)
  * [Google Forms credential harvesting campaign](#google-forms-credential-harvesting-campaign)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

Le paysage des cybermenaces actuel est caractérisé par une augmentation drastique des opérations cybercriminelles automatisées à grande échelle et par le raffinement technique des techniques d'évasion défensive. La campagne majeure baptisée "FortiBleed" (ciblée par la CVE-2026-20262) illustre parfaitement cette tendance : des centaines de milliers de pare-feu Fortinet et d'appliances Sophos ont fait l'objet de balayages et de campagnes coordonnées de "credential spraying", aboutissant à la compromission d'identifiants de connexion administratifs et VPN. L'exploitation de hachages SHA-256 faibles non migrés vers PBKDF2 met en lumière l'importance vitale d'une gestion proactive de la configuration des équipements de sécurité réseau, souvent considérés à tort comme d'office hermétiques.

Parallèlement, la menace des rançongiciels continue de se restructurer à travers des écosystèmes hautement spécialisés (Ransomware-as-a-Service). L'émergence du groupe "The Gentlemen" et de son composant d'évasion agressive "GentleKiller" confirme la popularisation de la technique du BYOVD (Bring Your Own Vulnerable Driver), qui neutralise les agents EDR d'entreprise avant de déployer la charge utile. Les infrastructures critiques et les réseaux industriels (OT/SCADA) demeurent également sous haute pression, en témoignent les dizaines de failles non corrigées affectant le constructeur Advantech. 

Sur le plan de la gouvernance et de la géopolitique de l'information, l'essor rapide de l'intelligence artificielle générative et de ses capacités offensives suscite de profondes inquiétudes étatiques. La décision historique de la Maison Blanche d'imposer des restrictions géographiques strictes sur les nouveaux modèles d'analyse d'Anthropic souligne la militarisation de ces technologies. Face à des attaquants agiles qui industrialisent aussi bien le phishing (via des formulaires Google Forms détournés) que le piratage d'infrastructures de développement (à l'instar de l'attaque de la chaîne d'approvisionnement Mastra AI attribuée au groupe étatique nord-coréen Sapphire Sleet), les organisations doivent impérativement durcir leurs privilèges locaux, isoler leurs réseaux industriels et généraliser l'authentification multifacteur résistante au hameçonnage.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **Sapphire Sleet** *(APT38, BlueNoroff)* | Finance, Cryptomonnaie, Technologies / IA | Compromission de dépôts open source, typosquattage de bibliothèques JavaScript (comme `dayjs`) et injection de codes malveillants pour dérober des actifs. | T1195.002 (Software Supply Chain Compromise) | [Microsoft Threat Intelligence via BleepingComputer](https://www.bleepingcomputer.com/news/security/microsoft-links-mastra-ai-supply-chain-attack-to-north-korean-hackers/) |
| **The Gentlemen** *(zeta88, hastalamuerte)* | Technologie, Télécommunications, Multi-secteur | Fournit un framework d'EDR Killer hautement optimisé nommé *GentleKiller*. Utilise la technique BYOVD via de nombreux pilotes signés légitimes. | T1068 (Exploitation of Vulnerability)<br>T1562.001 (Disable or Evade Security Tools) | [ESET via SecurityAffairs](https://securityaffairs.com/193941/uncategorized/inside-gentlekiller-the-edr-killer-powering-the-gentlemen.html) |
| **Prinz Eugen Operators** | Multi-secteur | Cible de manière chirurgicale les fichiers récemment modifiés sur les serveurs afin de maximiser la pression lors de l'extorsion. Exécution interactive hands-on-keyboard. | T1486 (Data Encrypted for Impact) | [Threatdown via BleepingComputer](https://www.bleepingcomputer.com/news/security/new-prinz-eugen-ransomware-prioritizes-recent-files-for-encryption/) |
| **Nova Ransomware Group** | Multi-secteur | Double extorsion avec exfiltration préalable des données sensibles et publication sur un portail public dédié ("leak site"). | T1486 (Data Encrypted for Impact) | [Ransomlook](https://www.ransomlook.io//group/nova) |
| **ShinyHunters** | Retail, Technologies, Services financiers | Exploitation de vulnérabilités critiques sur des systèmes ERP (ex: Oracle PeopleSoft) pour extraire de gros volumes d'informations personnelles. | T1190 (Exploit Public-Facing Application) | [HaveIBeenPwned](https://haveibeenpwned.com/Breach/JCPenney) |
| **FortiBleed Crew** | Télécoms, Gouvernement, Finance, Services IT | Balayage massif d'équipements FortiGate et Sophos, spraying de mots de passe à l'échelle industrielle via l'outil `forticheck`, puis cassage de hashs sur cluster GPU. | T1110.003 (Password Spraying) | [SecurityAffairs](https://securityaffairs.com/193931/hacking/fortibleed-exposes-global-credential-spraying-operation.html) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **USA / Global** | Technologie / Intelligence Artificielle | Régulation géopolitique et sécurité nationale de l'IA | L'administration américaine a exigé d'Anthropic de restreindre l'accès à ses nouveaux modèles d'IA (Fable 5 et Mythos 5) aux seuls citoyens américains, en raison de risques accrus de détournement de leurs capacités de détection de vulnérabilités. | [Le Monde](https://www.lemonde.fr/pixels/article/2026/06/20/comment-l-essor-inedit-des-competences-de-l-ia-inquiete-autant-qu-il-enthousiasme-le-monde-de-la-cybersecurite_6705262_4408996.html) |
| **Corée du Nord / Global** | Technologies / IA | Campagne étatique d'attaque de supply chain | Le groupe Sapphire Sleet a compromis la chaîne d'approvisionnement de Mastra AI en modifiant plus de 140 paquets officiels pour exfiltrer des clés API et portefeuilles crypto. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/microsoft-links-mastra-ai-supply-chain-attack-to-north-korean-hackers/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Injonctions judiciaires - Global Schools Group | Cour de Justice | 2026-06-20 | Global / UK | Injonctions de Cour | Global Schools Group a obtenu deux injonctions judiciaires pour tenter de bloquer la diffusion de données piratées, une stratégie légale au succès limité qui pourrait générer un effet Streisand. | [DataBreaches.net](https://databreaches.net/2026/06/20/global-schools-group-obtained-two-court-injunctions-that-didnt-seem-to-change-much-and-might-backfire/?pk_campaign=feed&pk_kwd=global-schools-group-obtained-two-court-injunctions-that-didnt-seem-to-change-much-and-might-backfire) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| Commerce de détail / Retail | **JCPenney** | Noms, adresses e-mail d'entreprise et personnelles, dates de naissance, numéros de sécurité sociale, numéros de téléphone, adresses postales d'anciens et d'actuels employés. | 368 418 enregistrements | [HaveIBeenPwned](https://haveibeenpwned.com/Breach/JCPenney) |
| Multi-secteur | **Multiples entreprises** *(511producciones, acerosbeta, bassetti-group, comune.pisa, etc.)* | Données d'entreprises diverses (financières, RH, techniques, commerciales). | Plusieurs dizaines d'entreprises compromises | [Ransomlook](https://www.ransomlook.io//group/nova) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-20262 | TRUE  | Active    | 6.5 | 9.8   | (1,1,6.5,9.8) |
| 2 | CVE-2026-23111 | FALSE | Active    | 3.5 | 7.8   | (0,1,3.5,7.8) |
| 3 | CVE-2026-4020  | FALSE | Active    | 2.5 | 5.3   | (0,1,2.5,5.3) |
| 4 | CVE-2026-5366  | FALSE | Théorique | 2.0 | 9.9   | (0,0,2.0,9.9) |
| 5 | CVE-2024-58351 | FALSE | Théorique | 2.0 | 9.8   | (0,0,2.0,9.8) |
| 6 | CVE-2022-50972 | FALSE | Théorique | 2.0 | 9.8   | (0,0,2.0,9.8) |
| 7 | CVE-2020-37255 | FALSE | Théorique | 1.5 | 9.8   | (0,0,1.5,9.8) |
| 8 | Advantech-Multiple-CVEs | FALSE | Théorique | 1.5 | 7.38  | (0,0,1.5,7.38) |
| 9 | CVE-2026-56345 | FALSE | Théorique | 1.0 | 8.8   | (0,0,1.0,8.8) |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-20262** | 9.8 | N/A | **TRUE** | **6.5** | FortiGate SSL VPN & Sophos User Portal | Weak Password Storage | Auth Bypass / RCE | Active | Terminer les sessions actives, réinitialiser tous les mots de passe admin/VPN, activer le MFA, forcer le hachage PBKDF2 sur FortiOS, désactiver l'administration publique. | [SecurityAffairs](https://securityaffairs.com/193931/hacking/fortibleed-exposes-global-credential-spraying-operation.html)<br>[SecurityAffairs CISA Warning](https://securityaffairs.com/193902/hacking/cisa-warns-of-active-exploitation-following-fortibleed-leak.html)<br>[Unit 42 Threat Brief](https://unit42.paloaltonetworks.com/large-scale-credential-attacks/) |
| **CVE-2026-23111** | 7.8 | N/A | FALSE | **3.5** | Ubuntu Kernel | One-character bug dans `nf_tables` | LPE / Container Escape | Active | Appliquer d'urgence les correctifs de noyau fournis par Canonical, durcir la configuration d'isolation des conteneurs. | [Mastodon SIGINT](https://fosstodon.org/@sigint/116785093665678309) |
| **CVE-2026-4020** | 5.3 | N/A | FALSE | **2.5** | Gravity SMTP (plugin WordPress) | REST API Endpoint Exposure | Info Disclosure / API Leak | Active | Mettre à jour immédiatement vers la version 2.1.5 ou supérieure du plugin Gravity SMTP. Réinitialiser les clés API exposées (SendGrid, Mailgun, etc.). | [The Hacker News](https://thehackernews.com/2026/06/hackers-exploit-gravity-smtp-wordpress.html) |
| **CVE-2026-5366** | 9.9 | N/A | FALSE | **2.0** | prefecthq/prefect (v3.6.23) | Git Argument Injection via `commit_sha` ou `directories` | RCE | Théorique | Mettre à jour Prefect, restreindre les autorisations de création de déploiement, auditer l'exécution de commandes Git. | [Mastodon OffSeq](https://infosec.exchange/@offseq/116785154318795848)<br>[CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-5366) |
| **CVE-2024-58351** | 9.8 | N/A | FALSE | **2.0** | Flowise (< 2.1.4) | Sandbox Escape via la dépendance `vm2` | RCE | Théorique | Mettre à jour Flowise vers la version 2.1.4 ou supérieure, appliquer un filtrage strict des variables d'environnement. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2024-58351) |
| **CVE-2022-50972** | 9.8 | N/A | FALSE | **2.0** | WooCommerce (v7.1.0) | Argument Injection dans `class-wc-meta-box-product-images.php` | RCE | Théorique | Mettre à jour l'extension WooCommerce au-delà de la version 7.1.0. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2022-50972) |
| **CVE-2020-37255** | 9.8 | N/A | FALSE | **1.5** | WordPress Time Capsule Plugin (v1.21.16) | Authentication Bypass via l'en-tête `IWP_JSON_PREFIX` | Auth Bypass | Théorique | Mettre à jour ou désactiver définitivement le plugin Time Capsule. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2020-37255) |
| **Advantech-Multiple-CVEs** | 7.38 *(max 9.8)* | N/A | FALSE | **1.5** | Équipements industriels SCADA / OT d'Advantech | Accumulation de failles d'architecture et de sécurité | SCADA takeover / RCE | Théorique | Isoler strictement les réseaux OT, interdire l'exposition Internet directe de ces équipements, appliquer les mesures de durcissement. | [Mastodon Hugo Valters](https://mastodon.social/@hugovalters/116785176841593345) |
| **CVE-2026-56345** | 8.8 | N/A | FALSE | **1.0** | AVideo (Meet Plugin) | Session Hijacking via `uploadRecordedVideo.json.php` | Auth Bypass / Account Takeover | Théorique | Mettre à jour AVideo au-delà de la version 29.0, restreindre l'accès à l'endpoint vulnérable, régénérer les secrets du plugin Meet. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-56345) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| Nouveau rançongiciel Prinz Eugen ciblant en priorité les fichiers récents | **Prinz Eugen Ransomware + Evasion & Interactive Execution** | Menace cybercriminelle active sans attribution étatique. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-prinz-eugen-ransomware-prioritizes-recent-files-for-encryption/) |
| Dans les coulisses de GentleKiller, l'EDR-killer qui propulse l'opération The Gentlemen | **The Gentlemen + GentleKiller EDR evasion** | Framework actif de neutralisation d'outils de sécurité. | [SecurityAffairs](https://securityaffairs.com/193941/uncategorized/inside-gentlekiller-the-edr-killer-powering-the-gentlemen.html) |
| Campagne de phishing active via un formulaire Google Forms malveillant | **Google Forms credential harvesting campaign** | Campagne de vol d'identifiants ciblant les organisations. | [Mastodon URLDNA](https://infosec.exchange/@urldna/116785389370513023) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| Microsoft links Mastra AI supply chain attack to North Korean hackers (art_02) | Redirigé vers la section Géopolitique (priorité supérieure - acteur étatique Sapphire Sleet). | [BleepingComputer](https://www.bleepingcomputer.com/news/security/microsoft-links-mastra-ai-supply-chain-attack-to-north-korean-hackers/) |
| FortiBleed exposes global credential spraying operation (art_04, art_05, art_06) | Redirigé vers la section des vulnérabilités critiques (CVE-2026-20262). | [SecurityAffairs](https://securityaffairs.com/193931/hacking/fortibleed-exposes-global-credential-spraying-operation.html)<br>[SecurityAffairs](https://securityaffairs.com/193902/hacking/cisa-warns-of-active-exploitation-following-fortibleed-leak.html)<br>[Unit 42 Threat Brief](https://unit42.paloaltonetworks.com/large-scale-credential-attacks/) |
| Nova Ransomware Leaks Update (art_07) | Redirigé vers la section des violations de données (Nova Leaks). | [Ransomlook](https://www.ransomlook.io//group/nova) |
| Discussion communautaire sur les outils TUI Linux pour la Blue Team (art_09) | Exclu. Contenu généraliste issu de réseaux sociaux, non assimilable à un incident ou à une cyberattaque. | [Mastodon Bob Dobberson](https://kolektiva.social/@bobdobberson/116785195844622002) |
| Alerte sur 76 vulnérabilités d'équipements industriels Advantech (art_10) | Redirigé vers la section des vulnérabilités critiques (Advantech-Multiple-CVEs). | [Mastodon Hugo Valters](https://mastodon.social/@hugovalters/116785176841593345) |
| CVE-2026-5366 Prefect (art_11, art_17) | Redirigé vers la section des vulnérabilités critiques. | [Mastodon OffSeq](https://infosec.exchange/@offseq/116785154318795848)<br>[CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-5366) |
| CVE-2026-23111 Ubuntu (art_12) | Redirigé vers la section des vulnérabilités critiques. | [Mastodon SIGINT](https://fosstodon.org/@sigint/116785093665678309) |
| CVE-2026-9375 urllib3 (art_13) | Exclu de la synthèse des vulnérabilités (score composite = 0, vulnérabilité DoS de sévérité modérée sans exploitation). | [Mastodon Hugo Valters](https://mastodon.social/@hugovalters/116784960875993335) |
| CVE-2026-56345 AVideo (art_14) | Redirigé vers la section des vulnérabilités critiques. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-56345) |
| CVE-2026-56341 AVideo (art_15) | Exclu de la synthèse des vulnérabilités (score composite = 0, fuite de données financière de sévérité modérée). | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-56341) |
| CVE-2026-56340 vLLM (art_16) | Exclu de la synthèse des vulnérabilités (score composite = 0, DoS d'inférence d'IA). | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-56340) |
| CVE-2024-58351 Flowise (art_18) | Redirigé vers la section des vulnérabilités critiques. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2024-58351) |
| CVE-2022-50972 WooCommerce (art_19) | Redirigé vers la section des vulnérabilités critiques. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2022-50972) |
| CVE-2020-37255 WordPress Time Capsule (art_20) | Redirigé vers la section des vulnérabilités critiques. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2020-37255) |
| CVE-2026-4020 Gravity SMTP (art_21) | Redirigé vers la section des vulnérabilités critiques. | [The Hacker News](https://thehackernews.com/2026/06/hackers-exploit-gravity-smtp-wordpress.html) |
| Injonctions judiciaires - Global Schools Group (art_22) | Redirigé vers la section Réglementaire et juridique. | [DataBreaches.net](https://databreaches.net/2026/06/20/global-schools-group-obtained-two-court-injunctions-that-didnt-seem-to-change-much-and-might-backfire/?pk_campaign=feed&pk_kwd=global-schools-group-obtained-two-court-injunctions-that-didnt-seem-to-change-much-and-might-backfire) |
| JCPenney Data Breach (art_23) | Redirigé vers la section Violations de données. | [HaveIBeenPwned](https://haveibeenpwned.com/Breach/JCPenney) |
| Arrêt et régulation des modèles Anthropic (art_24) | Redirigé vers la section Géopolitique. | [Le Monde](https://www.lemonde.fr/pixels/article/2026/06/20/comment-l-essor-inedit-des-competences-de-l-ia-inquiete-autant-qu-il-enthousiasme-le-monde-de-la-cybersecurite_6705262_4408996.html) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="prinz-eugen-ransomware-evasion-interactive-execution"></div>

## Prinz Eugen Ransomware + Evasion & Interactive Execution

### Résumé technique

Prinz Eugen est un nouveau groupe de rançongiciel dont la particularité réside dans l'utilisation d'une charge utile codée en langage Go. Le mécanisme d'infection repose sur une exécution de type interactive de type "hands-on-keyboard". Les attaquants pénètrent le réseau cible, puis déploient manuellement leurs utilitaires de chiffrement. Plutôt que de lancer une routine de chiffrement de masse indifférenciée, le ransomware cible en priorité les fichiers les plus récemment créés ou modifiés sur les postes de travail et serveurs d'entreprise. 

Ce comportement "chirurgical" vise à verrouiller immédiatement les fichiers en cours d'utilisation par les employés, maximisant la perturbation opérationnelle et forçant les victimes à négocier sous l'effet de l'urgence. L'infrastructure de l'attaque s'appuie sur le détournement d'outils d'administration et de gestion à distance légitimes (RMM) ainsi que d'utilitaires LOLBins (Living-off-the-Land Binaries). De plus, pour entraver l'analyse forensique, les opérateurs de Prinz Eugen n'utilisent pas de note de rançon textuelle standardisée sur le bureau, privilégiant des canaux d'extorsion directs ou hors bande.

---

### Analyse de l'impact

Le ciblage chirurgical des documents de travail récents engendre un impact opérationnel immédiat pour les organisations victimes en bloquant les projets actifs, les devis ou les factures en cours d'édition. L'impact financier de l'extorsion est doublé par l'exfiltration préalable de données confidentielles. Le niveau de sophistication de cette menace est évalué comme moyen à élevé, de par son mode d'exécution humain direct qui lui permet de s'adapter dynamiquement aux réactions des équipes de défense internes.

---

### Recommandations

* Restreindre et surveiller l'usage des outils d'administration à distance (RMM) au sein du système d'information.
* Mettre en œuvre une politique de sauvegarde déconnectée (hors ligne ou immuable) axée en priorité sur la protection continue des répertoires de travail des utilisateurs.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Configurer une règle de blocage applicative stricte (AppLocker ou WDAC) pour empêcher l'exécution d'applications d'administration à distance (RMM) non autorisées par la DSI.
* S'assurer que les journaux d'événements liés à l'exécution de processus (EventID 4688 sous Windows ou logs d'audit EDR) sont centralisés vers un SIEM avec une rétention minimale de 30 jours.
* Valider l'étanchéité et l'immuabilité des serveurs de sauvegarde réseau.

#### Phase 2 — Détection et analyse

* **Détection comportementale** : Détection comportementale de l'écriture en volume de fichiers dotés de l'extension `.prinzeugen`.
* **Requête EDR** (syntaxe générique) :
  `process_name == "servertool.exe" OR (process_name == "cmd.exe" AND command_line CONTAINS "prinzeugen")`
* Corréler l'apparition de l'utilitaire `servertool.exe` avec les comptes d'administration ayant ouvert des sessions interactives suspectes dans les 24 heures précédentes.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Isoler immédiatement du réseau local (via l'EDR) toutes les machines sur lesquelles le fichier `servertool.exe` ou l'extension `.prinzeugen` ont été détectés.
* Révoquer tous les comptes AD et les clés de session associés aux administrateurs réseau suspectés de compromission.

**Éradication :**
* Supprimer le fichier binaire malveillant `servertool.exe` de l'ensemble des répertoires systèmes cibles.
* Nettoyer les clés de registre de persistance et les tâches planifiées créées par le binaire Go.
* Injecter les signatures de hachage associées aux binaires identifiés dans la liste noire du système de prévention des menaces (AV/EDR).

**Récupération :**
* Restaurer les données chiffrées à partir du dernier instantané de sauvegarde validé comme sain.
* Surveiller l'activité réseau des hôtes réintégrés pendant un intervalle post-remédiation de 72 heures.

#### Phase 4 — Activités post-incident

* Identifier le vecteur d'accès initial (ex: faiblesse VPN, e-mail de phishing) et corriger la faille.
* Évaluer s'il y a eu exfiltration de données à caractère personnel impliquant des notifications NIS2 / RGPD.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détection d'utilisation illicite d'outils d'administration à distance (RMM) | T1021 (Remote Services) | Logs de connexions réseau, logs EDR | Rechercher l'installation et l'exécution d'agents comme AnyDesk, ScreenConnect ou RustDesk hors du profil des administrateurs officiels. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Nom de fichier | `servertool[.]exe` | Charge utile interactive Go du ransomware | Élevée |
| Extension | `.prinzeugen` | Extension ajoutée aux fichiers chiffrés par le ransomware | Élevée |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1486 | Impact | Data Encrypted for Impact | Chiffrement ciblé des fichiers les plus récents sur les serveurs d'entreprise. |
| T1021 | Lateral Movement | Remote Services | Navigation interactive sur le réseau cible à l'aide d'outils d'administration tiers (RMM). |

---

### Sources

* [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-prinz-eugen-ransomware-prioritizes-recent-files-for-encryption/)

---

<div id="the-gentlemen-gentlekiller-edr-evasion"></div>

## The Gentlemen + GentleKiller EDR evasion

### Résumé technique

The Gentlemen est un groupe criminel opérant selon le modèle du Ransomware-as-a-Service (RaaS). Ses affiliés s'appuient sur un cadre d'évasion d'EDR et d'antivirus extrêmement destructeur nommé GentleKiller. Ce composant utilise la méthode BYOVD (Bring Your Own Vulnerable Driver), qui consiste à installer sur la machine de la victime un pilote légitime, mais doté d'une vulnérabilité connue et signé numériquement par une autorité reconnue. 

L'utilitaire GentleKiller exploite ensuite ce pilote vulnérable avec des privilèges de niveau noyau (Kernel Space) pour contourner la protection du système d'exploitation et forcer l'arrêt ou la neutralisation de plus de 400 processus et services associés à 48 solutions de cybersécurité du marché. L'arsenal du groupe The Gentlemen, développé notamment par un individu connu sous le pseudonyme *zeta88* (Alexander Andreevich Yapaev), contient huit variantes différentes de GentleKiller ainsi que d'autres utilitaires d'évasion (comme *HexKiller*, *HavocKiller*) et un collecteur de données d'identification en langage Rust nommé *OxideHarvest*.

---

### Analyse de l'impact

L'utilisation de GentleKiller permet aux attaquants d'aveugler totalement les systèmes de détection d'une entreprise avant d'initier la phase de chiffrement et d'exfiltration de données. L'absence de visibilité EDR réduit à néant les capacités de détection en temps réel du SOC. Le niveau de sophistication est jugé critique en raison de l'implémentation robuste de la technique BYOVD.

---

### Recommandations

* Activer la liste de blocage des pilotes vulnérables recommandée par Microsoft (Driver Blocklist / WHQL).
* Configurer les règles de durcissement EDR pour interdire le chargement de pilotes tiers non homologués dans l'infrastructure de production.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* S'assurer que le service Microsoft Defender Credential Guard et la fonction d'intégrité de la mémoire (HVCI) sont activés sur l'ensemble du parc.
* Déployer une règle de surveillance de l'API de chargement de pilotes Windows (Event ID 6 sous Sysmon) pour tracker l'installation de pilotes non standards.

#### Phase 2 — Détection et analyse

* **Détection** : Alerte de type "EDR Heartbeat Failure" ou déconnexion simultanée de plusieurs agents de la console centrale.
* **Règles YARA de détection de GentleKiller** (recherche d'artefacts) :
  ```yara
  rule Detect_GentleKiller {
      strings:
          $s1 = "GentleKiller" ascii wide
          $s2 = "OxideHarvest" ascii wide
      condition:
          any of them
  }
  ```
* Analyser les logs Windows à la recherche de l'installation de pilotes associés à des signatures d'éditeurs détournés (ex: pilotes de jeu anti-triche).

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Isoler physiquement du réseau les machines suspectées d'avoir subi une désactivation de leur EDR.
* Bloquer les communications DNS et IP vers les serveurs C2 suspectés de piloter le framework GentleKiller.

**Éradication :**
* Identifier et purger les pilotes vulnérables usurpés du répertoire `C:\Windows\System32\drivers\`.
* Supprimer les fichiers et binaires liés aux outils d'attaque `OxideHarvest`, `HexKiller` et `GentleKiller`.
* Forcer la réinstallation de l'agent EDR corrompu sur l'hôte ciblé.

**Récupération :**
* Vérifier l'intégrité de l'hôte à l'aide d'un scanner de sécurité hors-ligne.
* Rétablir les communications de l'EDR et s'assurer du retour d'un état "conforme" sur la console d'administration.

#### Phase 4 — Activités post-incident

* Documenter le cheminement d'accès de l'attaquant et soumettre les IoC de GentleKiller à la base de renseignements de l'organisation.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Tentative d'utilisation de pilotes vulnérables (BYOVD) | T1068 (Exploitation for Privilege Escalation) | Logs Sysmon (Event ID 6 - Driver Loaded) | Rechercher le chargement de pilotes légitimes connus pour être vulnérables (ex: pilotes anciens d'anti-virus, outils de diagnostic matériel). |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Outil | `GentleKiller` | Framework d'EDR-Killer du groupe The Gentlemen | Élevée |
| Outil | `OxideHarvest` | Malware de collecte d'identifiants en Rust | Élevée |
| Outil | `HexKiller` | Variante de l'utilitaire d'évasion | Élevée |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1562.001 | Defense Evasion | Disable or Evade Security Tools | Arrêt brutal des processus d'agents de sécurité sur les terminaux. |
| T1068 | Privilege Escalation | Exploitation for Privilege Escalation | Usage de la méthode BYOVD pour contourner les protections d'intégrité du noyau Windows. |

---

### Sources

* [SecurityAffairs](https://securityaffairs.com/193941/uncategorized/inside-gentlekiller-the-edr-killer-powering-the-gentlemen.html)

---

<div id="google-forms-credential-harvesting-campaign"></div>

## Google Forms credential harvesting campaign

### Résumé technique

Une campagne d'hameçonnage (phishing) active utilise l'infrastructure légitime de Google Forms pour héberger des formulaires malveillants de collecte d'informations d'identification. Les attaquants envoient des courriels usurpant l'identité d'équipes de support technique ou de départements de ressources humaines d'entreprises. Ces e-mails incitent les destinataires à cliquer sur un lien redirigeant vers un formulaire hébergé sur Google Forms. 

Le formulaire imite visuellement une interface d'authentification ou un portail de validation interne d'entreprise. Étant donné que le domaine parent (`docs.google.com`) est de confiance et n'est généralement pas bloqué par les passerelles de sécurité de messagerie (Secure Email Gateways - SEG) ou les filtres web d'entreprise, les courriels d'hameçonnage parviennent à contourner la détection automatisée traditionnelle. Les saisies des utilisateurs naïfs sont ensuite centralisées directement sur le serveur d'infrastructure de l'attaquant.

---

### Analyse de l'impact

L'impact principal réside dans la compromission d'accès initiaux à des comptes d'entreprise. Ces identifiants volés permettent ensuite aux attaquants de pénétrer les systèmes d'information, de mener des mouvements latéraux, de voler des données sensibles ou de propager des logiciels malveillants en interne. Le niveau de technicité est faible, mais son taux de réussite est élevé en raison du contournement des solutions de filtrage d'URL basé sur la réputation du domaine de confiance de Google.

---

### Recommandations

* Mettre en œuvre une authentification multifacteur (MFA) résistante aux techniques de relecture (ex. clés physiques FIDO2).
* Mettre en place des outils d'analyse de messagerie capables d'inspecter dynamiquement le contenu textuel et les structures des pages cibles liées dans les e-mails.

---

### Playbook de réponse à incident

#### Phase 1 — Preparation

* Configurer une règle de messagerie pour interdire ou tagguer explicitement les e-mails externes contenant des liens vers des formulaires publics de type `forms.gle` ou `docs.google.com/forms`.
* Sensibiliser les utilisateurs aux risques de saisie de mots de passe professionnels sur des plateformes d'hébergement externes.

#### Phase 2 — Détection et analyse

* **Détection réseau** : Surveiller les logs de proxy pour détecter tout trafic sortant vers l'URL spécifique de la campagne.
* **Requête SIEM** :
  `url_domain == "docs.google.com" AND url_path CONTAINS "/forms/d/e/1FAIpQLSfKMqOtY6KF6gqmVxtHk1OqX6cm_TlL14zN3VpwarnJkZtDjA"`
* Identifier les boîtes de réception ayant reçu l'e-mail de phishing pour évaluer le nombre d'employés potentiellement exposés.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Bloquer immédiatement l'URL de destination sur le proxy web ou le pare-feu de l'entreprise.
* Supprimer l'e-mail d'hameçonnage identifié de l'ensemble des boîtes de réception (via des commandes PowerShell Exchange ou l'outil d'orchestration de messagerie).

**Éradication :**
* Réinitialiser de manière obligatoire et immédiate les mots de passe de tous les utilisateurs ayant cliqué sur le lien ou soumis des données dans le formulaire.
* Révoquer l'ensemble des sessions actives et des jetons d'authentification (tokens MFA/OAuth) des utilisateurs concernés.

**Récupération :**
* Signaler le formulaire frauduleux aux équipes de sécurité de Google via leur plateforme de signalement d'abus pour forcer sa désactivation.
* Inspecter l'historique récent de connexion des utilisateurs compromis à la recherche d'adresses IP suspectes.

#### Phase 4 — Activités post-incident

* Rédiger un mémo récapitulant la campagne d'hameçonnage et le partager en interne pour renforcer la vigilance des collaborateurs.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Tentative de connexion suite à une compromission d'identifiants | T1078 (Valid Accounts) | Journaux d'authentification (IdP / Active Directory / Azure AD) | Rechercher des connexions d'utilisateurs issues de plages d'adresses IP ou de pays inhabituels (impossibilité physique de voyage) peu de temps après l'accès à l'URL Google Forms. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | `hxxps[:]//docs[.]google[.]com/forms/d/e/1FAIpQLSfKMqOtY6KF6gqmVxtHk1OqX6cm_TlL14zN3VpwarnJkZtDjA/viewform` | URL du formulaire d'hameçonnage actif | Élevée |
| Domaine | `urldna[.]io` | Domaine d'infrastructure d'analyse | Faible |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566.002 | Initial Access | Spearphishing Link | Utilisation d'un lien malveillant pointant vers un formulaire légitime de Google Forms pour leurrer les utilisateurs. |

---

### Sources

* [Mastodon URLDNA](https://infosec.exchange/@urldna/116785389370513023)

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
13. Chaque article contient un PLAYBOOK DE REPONSE A INCIDENT avec les 5 phases : [Vérifié]
14. Aucun bug fonctionnel, article commercial ou contenu non-sécuritaire dans la section "Articles" : [Vérifié]

Statut global : [✅ Rapport valide]
-->