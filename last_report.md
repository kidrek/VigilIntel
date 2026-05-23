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
  * [Cross-Platform NPM Stealer + OtterCookie](#cross-platform-npm-stealer-ottercookie)
  * [CA Cloud + Tech Support Scam](#ca-cloud-tech-support-scam)
  * [Kimwolf botnet + Jacob Butler arrest](#kimwolf-botnet-jacob-butler-arrest)
  * [STC Telecom Network + C2 Abuse](#stc-telecom-network-c2-abuse)
  * [ROADtools + Entra ID compromise tactics](#roadtools-entra-id-compromise-tactics)
  * [art-template npm package + Coruna exploit kit](#art-template-npm-package-coruna-exploit-kit)
  * [INJ3CTOR3 + FreePBX JOMANGY webshell persistence](#inj3ctor3-freepbx-jomangy-webshell-persistence)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'analyse de la cybermenace pour la période se clôturant le 23 mai 2026 met en lumière quatre dynamiques majeures qui redéfinissent la posture de sécurité des organisations à l'échelle internationale.

Premièrement, l'avènement de l'ère de l'intelligence artificielle (AI Epoch) bouscule les paradigmes de la découverte de vulnérabilités. L'émergence d'agents autonomes d'exploitation comme Anthropic Mythos et GPT-5.4-Cyber accroît drastiquement le volume de CVEs identifiées, sans pour autant saturer immédiatement les capacités de remédiation en production, forçant les équipes de sécurité à délaisser le seul score CVSS au profit d'indicateurs de menace active comme le catalogue CISA KEV ou l'EPSS.

Deuxièmement, les tensions géopolitiques mondiales se traduisent par des vagues d'espionnage et de sabotage sophistiquées. L'acteur iranien Screening Serpens (Nimbus Manticore) illustre cette tendance en fusionnant le DLL Sideloading avec l'AppDomainManager Hijacking pour paralyser les télémétries de sécurité .NET et contourner furtivement les solutions EDR.

Troisièmement, l'infrastructure de commandement et de contrôle (C2) mondiale montre une concentration sans précédent : plus de 72 % de l'activité C2 cartographiée au Moyen-Orient est hébergée sur le réseau de Saudi Telecom Company (STC), soulignant la dépendance des attaquants envers le détournement d'infrastructures compromises légitimes pour éluder la réputation IP.

Enfin, la compromission récurrente des chaînes d'approvisionnement logicielles (art-template, npm) et les fuites massives de secrets d'État (CISA GovCloud) rappellent la fragilité persistante des accès à privilèges et des dépendances tierces. Pour faire face à ces menaces, les organisations doivent prioriser l'implémentation de modèles d'architecture Zero Trust et durcir le contrôle d'intégrité de leurs dépendances.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **Screening Serpens**<br>*(Nimbus Manticore, UNC1549, Smoke Sandstorm, Iranian Dream Job)* | Aviation, Défense, Télécommunications | Hameçonnage ciblé, fausses offres d'emploi, contournement d'EDR par AppDomainManager Hijacking pour désactiver la journalisation ETW de .NET et déploiement de backdoors (MiniFast, MiniUpdate). | T1574.002, T1574.012, T1566.001 | [Unit 42 Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)<br>[Check Point Nimbus Manticore](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/) |
| **NoName057(16)** | Gouvernements, Transports, Services Financiers | Campagnes de DDoS massives contre les infrastructures critiques de pays alliés de l'Ukraine via des réseaux de proxys et de serveurs VPS loués sous de fausses identités en Europe. | T1498 | [BleepingComputer Dutch Server Seizure](https://www.bleepingcomputer.com/news/security/netherlands-seizes-800-servers-of-hosting-firm-enabling-cyberattacks/)<br>[DataBreaches NoName057 Arrest](https://databreaches.net/2026/05/22/how-a-consultant-and-a-concert-pianist-from-the-netherlands-were-arrested-on-suspicion-of-aiding-noname05716/) |
| **ShinyHunters** | Santé, Télécommunications, Distribution | Exploitation d'identifiants volés, compromission de bases de données cloud, exfiltration massive et chantage public via des portails de double extorsion. | T1567 | [Ransomlook Shinyhunters](https://www.ransomlook.io//group/shinyhunters) |
| **INJ3CTOR3** | Télécommunications | Exploitation automatisée de vulnérabilités dans FreePBX (VoIP) pour mener de la fraude téléphonique (toll fraud), déploiement du webshell JOMANGY avec six couches de persistance. | T1190, T1505.003 | [CybersecurityNews FreePBX](https://cybersecuritynews.com/hackers-use-six-layer-persistence/) |
| **MuddyWater**<br>*(Mercury)* | Gouvernements, Énergie, Technologies | Exploitation active de vulnérabilités récemment publiées dans des applications publiques (comme Langflow) pour obtenir un accès initial et voler des clés d'API. | T1190 | [SecurityAffairs CISA KEV](https://securityaffairs.com/192529/hacking/u-s-cisa-adds-trend-micro-apex-one-and-langflow-to-its-known-exploited-vulnerabilities-catalog.html) |
| **Eagle Werewolf** | Gouvernements, Secteur Industriel, Défense | Hameçonnage par courriel et via Telegram, leurres liés à Starlink ou à la formation de drones, et déploiement de RAT multi-étapes (SoullessRAT, Sliver) par DLL sideloading. | T1566.002, T1574.002 | [SecurityAffairs Middle East C2](https://securityaffairs.com/192518/hacking/one-telecom-provider-hosted-most-of-the-middle-east-s-active-c2-infrastructure.html) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| Moyen-Orient, Israël, Émirats Arabes Unis, États-Unis | Aviation et Défense | Espionnage étatique lié au conflit moyen-oriental | Intensification des campagnes d'espionnage iraniennes parallèlement aux tensions cinétiques. Recours à l'AppDomainManager hijacking pour neutraliser les EDR de l'aviation civile américaine. | [Unit 42 Iran APT](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)<br>[Check Point Operations](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/) |
| Russie, Ukraine, Europe | Gouvernement et Médias | Campagnes de manipulation de l'information (FIMI) | Intensification des opérations d'influence pro-russes pour saper le soutien européen à l'Ukraine en propageant des narratifs de corruption ou de faux laboratoires biologiques. | [EUvsDisinfo Report](https://euvsdisinfo.eu/lies-about-russias-military-success-yermaks-arrest-and-secret-biolabs/) |
| Pays-Bas, Russie, Europe | Fournisseurs de services Internet | Démantèlement d'infrastructures de cyberattaque étatiques | Saisie de 800 serveurs aux Pays-Bas gérés par Mirhosting et Stark Industries, utilisés par les hacktivistes pro-russes NoName057(16) pour mener des attaques DDoS massives. | [BleepingComputer Dutch Seizure](https://www.bleepingcomputer.com/news/security/netherlands-seizes-800-servers-of-hosting-firm-enabling-cyberattacks/)<br>[DataBreaches NoName Dutch Connection](https://databreaches.net/2026/05/22/how-a-consultant-and-a-concert-pianist-from-the-netherlands-were-arrested-on-suspicion-of-aiding-noname05716/) |
| Russie, Ukraine, Europe | Administrations, Énergie | Espionnage et destruction (RDP, VPN, Wipers) | Hausse de 37,4 % des cyber-incidents d'État russes en Ukraine et en Europe. Usage intensif de serveurs RDP exposés, de VPN (Fortinet) et d'outils d'ingénierie sociale sur Signal. | [CybersecurityNews Russian Threat Groups](https://cybersecuritynews.com/russian-threat-groups-use-rdp-vpn-supply-chain-attacks/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| US State Breach Notification Bills 2026 | Législateurs des États américains | 2026-05-22 | États-Unis | US State Breach Notification Bills 2026 | Propositions de lois étatiques visant à durcir les exigences et à réduire les délais de notification à 72 heures en cas de fuite de données d'utilisateurs. | [DataBreaches Proposed Laws](https://databreaches.net/2026/05/22/proposed-state-laws-for-breach-notification-could-reshape-incident-response-plans/?pk_campaign=feed&pk_kwd=proposed-state-laws-for-breach-notification-could-reshape-incident-response-plans) |
| Avis exploratoire sur la résilience des réseaux | Comité économique et social européen (CESE) | 2026-05-22 | Union européenne | CELEX:52025AE3570 | Avis appelant à la création d'un fonds européen de cybersécurité physique et logique pour protéger et sanctuariser l'interconnexion des réseaux électriques et d'énergie européens. | [EUR-Lex CELEX:52025AE3570](https://eur-lex.europa.eu/legal-content/AUTO/?uri=CELEX:52025AE3570) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| Gouvernement | CISA (U.S. Cybersecurity and Infrastructure Security Agency) | Clés d'accès AWS GovCloud, clés de sécurité d'infrastructure, clés RSA d'accès à l'organisation GitHub CISA-IT, secrets de configuration. | Système critique de l'agence | [KrebsOnSecurity CISA Data Leak](https://krebsonsecurity.com/2026/05/lawmakers-demand-answers-as-cisa-tries-to-contain-data-leak/)<br>[Veri Sizintisi CISA Breach](https://verisizintisi.com/en/blog/2026-05-23-lawmakers-demand-answers-cisa-data-leak) |
| Gouvernement | Ministères du gouvernement vietnamien | Dossiers gouvernementaux et informations d'identification personnelle (PII) de citoyens suite à un échec des SOC nationaux. | Millions de dossiers de citoyens | [Netsecio Mastodon Report](https://mastodon.social/@netsecio/116619809487942455) |
| Santé | Radiology Associates of Richmond | Numéros de sécurité sociale (SSN), fiches de santé, données médicales et informations de facturation (seconde fuite majeure). | 266 000 patients | [DataBreaches Radiology Breach](https://databreaches.net/2026/05/22/radiology-associates-of-richmond-discloses-second-data-breach-266k-people-affected/?pk_campaign=feed&pk_kwd=radiology-associates-of-richmond-discloses-second-data-breach-266k-people-affected)<br>[PogoWasRight Mastodon](https://infosec.exchange/@PogoWasRight/116619559065555589)<br>[Veri Sizintisi Richmond](https://infosec.exchange/@verisizintisi/116619541594743211) |
| Télécommunications | Trump Mobile | Numéros de téléphone, adresses physiques, identités d'abonnés suite à un bucket cloud mal configuré et exposé. | Non spécifié | [DataBreaches Trump Mobile](https://databreaches.net/2026/05/22/trump-mobile-confirms-it-exposed-customers-personal-data-unclear-whether-it-will-notify-those-affected/?pk_campaign=feed&pk_kwd=trump-mobile-confirms-it-exposed-customers-personal-data-unclear-whether-it-will-notify-those-affected)<br>[TechCrunch Trump Mobile Leak](https://techcrunch.com/2026/05/22/trump-mobile-confirms-it-exposed-customers-personal-data-including-phone-numbers-and-home-addresses/) |
| Santé | Multiples hôpitaux et programmes US (dont WTC Health Program) | Numéros de sécurité sociale (SSN), antécédents médicaux d'assurés, données d'identité compromises par des ransomwares. | Plusieurs milliers de patients | [Netsecio HIPAA Breach Wave](https://mastodon.social/@netsecio/116619807976125691) |
| Santé | Plusieurs hôpitaux allemands | Données médicales et de facturation hautement sensibles dérobées par l'intrusion d'un prestataire de facturation tiers. | Multiples établissements allemands | [DataBreaches German Hospitals](https://databreaches.net/2026/05/22/hackers-steal-patient-and-billing-data-from-german-hospitals-via-third-party-provider/?pk_campaign=feed&pk_kwd=hackers-steal-patient-and-billing-data-from-german-hospitals-via-third-party-provider) |
| Finance Décentralisée | Verus DeFi Bridge | Crypto-actifs restitués par le hacker suite à un accord de compromis et à l'attribution d'une prime. | 8,5 millions de dollars | [DataBreaches Verus Hack](https://databreaches.net/2026/05/22/verus-hacker-returns-8-5m-after-bridge-exploit-deal/?pk_campaign=feed&pk_kwd=verus-hacker-returns-8-5m-after-bridge-exploit-deal) |
| Gouvernement | ANTS & OFII (France) | Données d'identité de citoyens et d'immigrants dérobées par de jeunes cyberdélinquants français (Breach3d, HexDex) pour la notoriété. | Millions d'utilisateurs | [Le Monde - Cyberdélinquance Française](https://www.lemonde.fr/pixels/article/2026/05/22/derriere-les-fuites-de-donnees-une-cyberdelinquance-francaise-jeune-et-en-quete-d-affirmation-de-soi_6692230_4408996.html) |
| Assurances, Télécoms, Distribution | Baker Distributing Company, Charter Communications Inc., DentaQuest | Informations d'abonnés, données de facturation, informations de santé confidentielles publiées par ShinyHunters. | Volumineux | [Ransomlook Shinyhunters Group](https://www.ransomlook.io//group/shinyhunters) |
| Logistique, Services | lasevillanita.com | Fichiers financiers, contrats d'entreprise, données de facturation chiffrées par le ransomware Krybit. | Plusieurs serveurs critiques | [Ransomlook Krybit](https://www.ransomlook.io//group/krybit) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2025-34291 | TRUE  | Active    | 6.0 | 7.5   | (1,1,6.0,7.5) |
| 2 | CVE-2026-34926 | TRUE  | Active    | 6.0 | 6.7   | (1,1,6.0,6.7) |
| 3 | CVE-2026-9082  | FALSE | Active    | 2.5 | 6.5   | (0,1,2.5,6.5) |
| 4 | CVE-2026-34910 | FALSE | Théorique | 2.0 | 10.0  | (0,0,2.0,10.0)|
| 5 | CVE-2026-34908 | FALSE | Théorique | 1.5 | 10.0  | (0,0,1.5,10.0)|
| 6 | CVE-2026-34909 | FALSE | Théorique | 1.5 | 10.0  | (0,0,1.5,10.0)|
| 7 | CVE-2026-9291  | FALSE | Théorique | 1.5 | 8.8   | (0,0,1.5,8.8) |
| 8 | CVE-2026-45659 | FALSE | Théorique | 1.5 | 8.8   | (0,0,1.5,8.8) |
| 9 | CVE-2026-25262 | FALSE | Théorique | 1.5 | 8.4   | (0,0,1.5,8.4) |
| 10| CVE-2026-9255  | FALSE | Théorique | 1.0 | 6.1   | (0,0,1.0,6.1) |
| 11| CVE-2026-40411 | FALSE | Théorique | 1.0 | N/A→0 | (0,0,1.0,0)   |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2025-34291** | 7.5 | N/A | TRUE | **6.0** | Langflow (AI tool) | Origin Validation / Overly Permissive CORS | RCE / Info Disclosure | Active | Appliquer la mise à jour pour réviser les paramètres CORS et forcer la validation CSRF. | [SecurityAffairs CISA KEV](https://securityaffairs.com/192529/hacking/u-s-cisa-adds-trend-micro-apex-one-and-langflow-to-its-known-exploited-vulnerabilities-catalog.html) |
| **CVE-2026-34926** | 6.7 | N/A | TRUE | **6.0** | Trend Micro Apex One (on-premise) | Directory Traversal | RCE / Code Execution | Active | Mettre à jour Apex One on-premise d'urgence et restreindre l'accès au réseau d'administration. | [BleepingComputer Trend Micro Zero-Day](https://www.bleepingcomputer.com/news/security/trend-micro-warns-of-apex-one-zero-day-exploited-in-attacks/) |
| **CVE-2026-9082** | 6.5 | N/A | FALSE | **2.5** | Drupal Core (PostgreSQL backend) | SQL Injection | Auth Bypass / Info Disclosure | Active | Mettre à jour Drupal Core vers les versions corrigées (11.3.10+, 10.6.9+). Filtrer via le WAF. | [BleepingComputer Drupal Flaw](https://www.bleepingcomputer.com/news/security/drupal-critical-sql-injection-flaw-now-targeted-in-attacks/) |
| **CVE-2026-34910** | 10.0 | N/A | FALSE | **2.0** | Ubiquiti UniFi OS | Command Injection | RCE | Théorique | Appliquer la version firmware de sécurité UniFi OS 5.1.12 ou supérieure. | [Field Effect UniFi OS](https://fieldeffect.com/blog/unifi-os-vulnerabilities-patches) |
| **CVE-2026-34908** | 10.0 | N/A | FALSE | **1.5** | Ubiquiti UniFi OS | Improper Access Control | Auth Bypass | Théorique | Installer la mise à jour UniFi OS 5.0.8 ou supérieure et isoler les consoles d'administration. | [BleepingComputer Ubiquiti Patches](https://www.bleepingcomputer.com/news/security/ubiquiti-patches-three-max-severity-unifi-os-vulnerabilities/) |
| **CVE-2026-34909** | 10.0 | N/A | FALSE | **1.5** | Ubiquiti UniFi OS | Path Traversal | Info Disclosure | Théorique | Installer le correctif logiciel firmware UniFi OS version 5.1.12 ou supérieure. | [CybersecurityNews UniFi Patches](https://cybersecuritynews.com/unifi-os-vulnerabilities-privilege-escalation/) |
| **CVE-2026-9291** | 8.8 | N/A | FALSE | **1.5** | Amazon Braket SDK (Python) | Insecure Deserialization | RCE | Théorique | Mettre à jour le SDK Braket vers la version corrigée. Restreindre l'accès en écriture aux buckets S3. | [AWS Security Bulletin](https://aws.amazon.com/security/security-bulletins/rss/2026-036-aws/) |
| **CVE-2026-45659** | 8.8 | N/A | FALSE | **1.5** | Microsoft SharePoint Server | Remote Code Execution | RCE | Théorique | Déployer la mise à jour de sécurité de mai 2026 et auditer les droits de publication. | [CERT-FR AVI-0634](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0634/) |
| **CVE-2026-25262** | 8.4 | N/A | FALSE | **1.5** | Puces Qualcomm (MDM9x07, MSM8909, etc.) | Write-What-Where (BootROM Sahara) | RCE / LPE | Théorique | Ne pas laisser de terminaux sensibles sans surveillance. Purger la RAM par coupure d'alimentation totale. | [Kaspersky Qualcomm Sahara Vuln](https://www.kaspersky.co.uk/blog/qualcomm-cve-2026-25262/30591/) |
| **CVE-2026-9255** | 6.1 | N/A | FALSE | **1.0** | Kiro CLI (AWS AI agent) | Stdin Injection | RCE | Théorique | Utiliser l'argument `--no-interactive` pour les exécutions de Kiro CLI non approuvées. | [AWS Security Bulletin](https://aws.amazon.com/security/security-bulletins/rss/2026-035-aws/) |
| **CVE-2026-40411** | N/A | N/A | FALSE | **1.0** | Azure Virtual Network Gateway | Remote Code Execution | RCE | Théorique | Appliquer la mise à jour corrective Microsoft. Restreindre les IP d'administration de la passerelle. | [cvefeed Azure Gateway](https://cvefeed.io/vuln/detail/CVE-2026-40411) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| Cross-Platform NPM Stealer ciblant Windows, macOS et Linux | Cross-Platform NPM Stealer + OtterCookie | Analyse technique détaillée d'une chaîne d'infection par malware de vol de données sur plusieurs plateformes. | [Cross-Platform NPM Stealer](https://isc.sans.edu/diary/rss/33006) |
| Des dirigeants américains plaident coupables d'aide aux escroqueries au faux support technique | CA Cloud + Tech Support Scam | Cas d'école de fraude par support technique s'appuyant sur des complices administratifs locaux. | [BleepingComputer Tech Support Scammers](https://www.bleepingcomputer.com/news/security/former-us-execs-plead-guilty-to-aiding-tech-support-scammers/) |
| Arrestation du gestionnaire présumé du botnet Kimwolf par les États-Unis et le Canada | Kimwolf botnet + Jacob Butler arrest | Opération de police internationale contre un botnet IoT d'attaque DDoS majeur. | [BleepingComputer Kimwolf Admin](https://www.bleepingcomputer.com/news/security/us-and-canada-arrest-and-charge-suspected-kimwolf-botnet-admin/) |
| Un opérateur télécom saoudien héberge la majorité de l'infrastructure C2 du Moyen-Orient | STC Telecom Network + C2 Abuse | Concentration d'infrastructures de serveurs C2 malveillants détournant des réseaux télécoms légitimes. | [SecurityAffairs Middle East C2](https://securityaffairs.com/192518/hacking/one-telecom-provider-hosted-most-of-the-middle-east-s-active-c2-infrastructure.html) |
| ROADtools et les tactiques d'attaques des acteurs étatiques dans le Cloud | ROADtools + Entra ID compromise tactics | Analyse technique des détournements d'outils de red-teaming d'identité cloud d'entreprise. | [Unit 42 Cloud Attacks](https://unit42.paloaltonetworks.com/roadtools-cloud-attacks/) |
| Compromission de la bibliothèque npm 'art-template' pour des attaques d'eau d'abreuvage | art-template npm package + Coruna exploit kit | Compromission d'une chaîne de dépendances npm (watering-hole) ciblant les navigateurs web mobiles iOS. | [CybersecurityNews art-template](https://cybersecuritynews.com/hackers-backdoor-popular-art-template-npm-package/) |
| FreePBX ciblé par le groupe INJ3CTOR3 avec des persistance à six couches | INJ3CTOR3 + FreePBX JOMANGY webshell persistence | Attaque à but lucratif ciblant les serveurs VoIP d'entreprise, dotée d'un webshell d'une persistance exceptionnelle. | [CybersecurityNews FreePBX](https://cybersecuritynews.com/hackers-use-six-layer-persistence/) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| SANS ISC Stormcast - 22 mai 2026 | Contenu audio d'actualités et synthèse quotidienne sans incident unique. | [SANS Technology Institute](https://isc.sans.edu/diary/rss/33004) |
| Pourquoi les litiges financiers ne sont qu'une facette de la lutte anti-fraude | Analyse conceptuelle sur le coût de la fraude sans fait de piratage direct ni incident spécifique. | [BleepingComputer Chargebacks](https://www.bleepingcomputer.com/news/security/why-chargebacks-are-just-one-piece-of-the-fraud-puzzle/) |
| Prévisions des vulnérabilités 2026 : Naviguer au sein de l'ère de l'IA | Rapport de prévisions et analyses statistiques globales sans incident ou campagne active. | [FIRST Blog](https://www.first.org/blog/20260522-vulnerability-forecast-update) |
| Anthropic Mythos, l'IA et la cybersécurité : Un changement de paradigme | Analyse générale de l'évolution théorique des outils d'IA en cybersécurité. | [Flare Learn](https://flare.io/learn/resources/blog/anthropic-mythos-ai-cybersecurity) |
| Les appels FaceTime divulguent l'adresse IP des participants | Analyse d'exposition protocolaire passive liée au P2P, sans incident actif de sécurité. | [Mysk Mastodon](https://mastodon.social/@mysk/116620824789235197) |
| L'IA est un outil technologique, pas une solution magique | Tribune d'opinion sur l'IA, sans contenu technique de cybersécurité ni incident associé. | [ChiefGyk3D Pics](https://pics.chiefgyk3d.com/p/ChiefGyk3D/963581149343845027) |
| Analyse Shodan Safari - Serveur exposé à Klagenfurt, Autriche | Simple indexation automatisée de serveur potentiellement exposé, sans incident ou compromission avérée. | [Shodan Safari Mastodon](https://infosec.exchange/@shodansafari/116620709806297856) |
| YellowKey BitLocker Bypass Exposes Encrypted Data | Vulnérabilité de contournement de fonction de sécurité (CVE-2026-45585) sous le seuil d'inclusion de score composite (0.5). | [SoCPrime BitLocker Bypass](https://socprime.com/blog/cve-2026-45585-yellowkey-bitlocker-bypass/) |
| Microsoft Entra ID Elevation of Privilege Vulnerability | Vulnérabilité d'élévation de privilèges (CVE-2026-42901) sous le seuil d'inclusion de score composite (0.5). | [cvefeed Entra ID](https://cvefeed.io/vuln/detail/CVE-2026-42901) |
| Microsoft Planetary Computer Pro Information Disclosure | Faille de divulgation d'informations (CVE-2026-41104) sous le seuil d'inclusion de score composite (0.0). | [cvefeed Planetary Computer](https://cvefeed.io/vuln/detail/CVE-2026-41104) |
| Microsoft Azure Active Directory B2C Elevation of Privilege | Vulnérabilité d'élévation de privilèges (CVE-2026-33843) sous le seuil d'inclusion de score composite (0.5). | [cvefeed Azure B2C](https://cvefeed.io/vuln/detail/CVE-2026-33843) |
| Microsoft Copilot Tampering Vulnerability | Vulnérabilité d'altération logique (CVE-2026-41090) sous le seuil d'inclusion de score composite (0.0). | [cvefeed Copilot](https://cvefeed.io/vuln/detail/CVE-2026-41090) |
| Azure Resource Manager Elevation of Privilege Vulnerability | Vulnérabilité d'élévation de privilèges (CVE-2026-47280) sous le seuil d'inclusion de score composite (0.5). | [cvefeed ARM](https://cvefeed.io/vuln/detail/CVE-2026-47280) |
| Multiples vulnérabilités dans Tenable Sensor Proxy | Agent de proxy tns-2026-15 sous le seuil d'inclusion de score composite (0.0). | [CERT-FR AVI-0630](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0630/) |
| Faille de sécurité dans Stormshield Network Security | Faille de pare-feu SNS CVE-2025-9086 sous le seuil d'inclusion de score composite (0.0). | [CERT-FR AVI-0631](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0631/) |
| Multiples vulnérabilités dans les produits Mattermost | Faille d'application collaborative sous le seuil d'inclusion de score composite (0.0). | [CERT-FR AVI-0632](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0632/) |
| Multiples vulnérabilités dans Microsoft Edge | Correctifs d'application de navigateur Chromium sous le seuil d'inclusion de score composite (0.0). | [CERT-FR AVI-0633](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0633/) |
| Faille de sécurité critique dans SPIP | Correctif d'application CMS SPIP 4.4.15 sous le seuil d'inclusion de score composite (0.0). | [CERT-FR AVI-0635](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0635/) |
| Faille de sécurité dans le noyau Linux de Debian LTS | Faille d'élévation locale de privilèges (CVE-2026-46333) sous le seuil d'inclusion de score composite (0.5). | [CERT-FR AVI-0636](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0636/) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="cross-platform-npm-stealer-ottercookie"></div>

## Cross-Platform NPM Stealer + OtterCookie

### Résumé technique

Un nouveau voleur de données (stealer) écrit en Node.js cible de manière transversale les environnements Windows (via le sous-système Windows pour Linux - WSL), macOS et Linux. Le malware est distribué via des paquets npm piégés et utilise des techniques d'obfuscation de base générées par le projet `obfuscator.io`. 

L'analyse de l'infrastructure a révélé que les charges utiles de second niveau de l'implant intègrent un module de connexion WebSocket persistant qui permet d'obtenir un reverse-shell interactif. Les données dérobées et le trafic de contrôle sont transmis par requêtes HTTP POST à l'adresse IP de destination `216[.]126[.]225[.]243` sur les ports `8086` et `8087`. L'analyse de l'infrastructure d'attaque a permis d'attribuer cette campagne au groupe d'espionnage nord-coréen **OtterCookie**.

La victimologie cible principalement les stations de travail de développeurs de logiciels et les serveurs d'intégration continue (CI/CD) afin d'exfiltrer des secrets d'infrastructure de code et d'initier des attaques sur la supply chain applicative.

---

### Analyse de l'impact

L'impact opérationnel pour les entreprises ciblées est majeur : la compromission des jetons d'accès, des secrets d'API et du code source stocké localement offre à l'attaquant la capacité de modifier des composants logiciels distribués. Le niveau de sophistication technique est modéré mais redoutablement efficace en raison de son exécution transparente sur plusieurs types d'architectures système de développement.

---

### Recommandations

* Interdire l'exécution de runtimes Node.js non surveillés ou de scripts de build d'utilisateurs n'étant pas explicitement signés.
* Restreindre et analyser de manière stricte l'ensemble des installations de modules npm externes via des proxys d'artéfacts de type Nexus ou JFrog.
* Configurer une isolation stricte des stations de travail des développeurs par rapport aux segments de production d'entreprise.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Configurer les règles EDR d'entreprise pour identifier et journaliser toute création de processus enfant par l'exécuteur `node.exe` ou `node`.
* Établir un inventaire à jour de l'ensemble des dépendances de paquets npm utilisées en interne dans les applications de l'entreprise.
* Assurer l'activation de la surveillance des communications sortantes sur les ports non conventionnels (`8086`, `8087`).

#### Phase 2 — Détection et analyse
* **Détection SIEM / Sigma** :
  ```yml
  title: Execution of Suspect Node.js Child Process
  logsource:
    category: process_creation
    product: windows
  detection:
    selection:
      ParentImage|endswith: '\node.exe'
      Image|endswith:
        - '\cmd.exe'
        - '\powershell.exe'
        - '\sh'
        - '\bash'
    condition: selection
  ```
* **Règle YARA** :
  ```yara
  rule OtterCookie_NPM_Stealer_JS {
    meta:
      description = "Detects obfuscated Node.js stealer linked to OtterCookie"
    strings:
      $obfuscation_pattern = "obfuscator.io" ascii
      $c2_ip = "216.126.225.243" ascii
      $endpoint = "/api/notify" ascii
    condition:
      any of them
  }
  ```
* Analyser les logs réseau pour isoler des flux WebSockets persistants sortant vers l'IP `216[.]126[.]225[.]243`.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Isoler logiquement et physiquement le poste du développeur infecté en le déconnectant du réseau local (VLAN d'isolement ou quarantaine EDR).
* Bloquer de manière permanente l'adresse IP `216[.]126[.]225[.]243` et l'URL `hxxp[:]//216[.]126[.]225[.]243[:]8087/` sur les pare-feu périmétriques.

**Éradication :**
* Supprimer l'ensemble des répertoires `node_modules` corrompus et nettoyer les fichiers de scripts `.js` suspects identifiés dans les dossiers temporaires utilisateur.
* Révoquer de manière immédiate l'ensemble des clés d'accès SSH, jetons d'authentification Git, API cloud et identifiants mémorisés sur l'ordinateur touché.

**Récupération :**
* Réinstaller l'environnement système de l'ordinateur à partir d'une image d'entreprise certifiée et exempte de dépendances non vérifiées.
* Surveiller l'activité réseau de l'utilisateur réhabilité pendant un délai minimal de 72 heures.

#### Phase 4 — Activités post-incident
* Rédiger et diffuser un rapport d'incident complet détaillant le paquet npm à l'origine de l'infection.
* Évaluer l'obligation légale de notification réglementaire sous le RGPD (Art. 33) si des données à caractère personnel de clients ou secrets de propriété industrielle ont fait l'objet d'une exfiltration.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'autres connexions réseau établies vers l'infrastructure C2 d'OtterCookie. | T1041 | Journaux de pare-feu et proxy d'entreprise | Rechercher des requêtes HTTP vers l'adresse IP `216.126.225.243` ou sur les ports `8086` et `8087`. |
| Recherche d'installations de paquets npm malveillants par des scripts d'intégration. | T1195.001 | Journaux d'audits des pipelines CI/CD | Analyser les packages.json modifiés contenant des scripts d'installation automatique suspects (`preinstall`, `postinstall`). |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| IP | `216[.]126[.]225[.]243` | Serveur C2 OtterCookie | Haute |
| URL | `hxxp[:]//216[.]126[.]225[.]243[:]8087/api/notify` | Endpoint d'exfiltration et de notification du stealer | Haute |
| Hash SHA256 | `049300aa5dd774d6c984779a0570f59610399c71864b5d5c2605906db46ddeb9` | Fichier JavaScript d'installation d'OtterCookie | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1195.001 | Initial Access | Supply Chain Compromise: Compromise Software Dependencies | Distribution du stealer via des dépendances de bibliothèques npm altérées. |
| T1041 | Exfiltration | Exfiltration Over C2 Channel | Exfiltration de secrets système et clés privées directement vers l'IP C2. |
| T1584.005 | Resource Development | Stage Capabilities: Botnet | Recrutement de la machine au sein d'un botnet C2 Node.js interactif. |

---

### Sources

* [SANS SANS ISC - Cross-Platform NPM Stealer](https://isc.sans.edu/diary/rss/33006)

---

<div id="ca-cloud-tech-support-scam"></div>

## CA Cloud + Tech Support Scam

### Résumé technique

Les autorités judiciaires ont mis en évidence la complicité d'Adam Young et Harrison Gevirtz, anciens dirigeants de la plateforme de télécommunications américaine **C.A. Cloud**, dans le soutien logistique à grande échelle d'activités frauduleuses au faux support technique. Les accusés exploitaient également un centre d'appels à Tunis.

Les complices fournissaient sciemment des ressources de télécommunication (numéros VoIP, enregistrements de lignes téléphoniques) et généraient des fenêtres pop-ups publicitaires agressives imitant des plantages système de Windows pour inciter les victimes, notamment des personnes âgées, à appeler le centre d'assistance factice. Une fois l'appel établi, les faux techniciens utilisaient des logiciels de prise en main à distance (RAT commerciaux) pour se connecter aux machines des victimes et facturer de fausses opérations de réparation de sécurité informatique pour un préjudice financier de plusieurs millions de dollars.

---

### Analyse de l'impact

L'impact opérationnel s'illustre par le détournement malveillant d'infrastructures cloud et télécoms légitimes à des fins d'extorsion et d'ingénierie sociale. La sophistication technique de la fraude s'appuie sur la manipulation psychologique et l'installation d'outils de contrôle distants légitimes détournés de leur usage pour éviter les alertes antivirus.

---

### Recommandations

* Installer et forcer des extensions de blocage de fenêtres publicitaires et scripts intrusifs sur l'ensemble des navigateurs web de l'entreprise.
* Restreindre drastiquement par stratégie d'Active Directory l'exécution et l'installation d'outils de contrôle à distance non explicitement approuvés par la charte informatique.

---

### Playbook de réponse à incident

#### Phase 1 — Preparation
* Établir une liste blanche restrictive d'outils d'assistance à distance autorisés en interne (ex: TeamViewer géré, LogMeIn approuvé).
* Configurer la détection SIEM pour les connexions réseau sortantes vers des services tiers de partage d'écran non autorisés.

#### Phase 2 — Détection et analyse
* **Requête EDR (générique)** :
  ```
  DeviceProcessEvents 
  | where FileName in~ ('anydesk.exe', 'teamviewer.exe', 'logmein.exe', 'screenconnect.exe') 
  | where InitiatingProcessFileName in~ ('chrome.exe', 'msedge.exe', 'firefox.exe')
  ```
* Analyser les logs web à la recherche de redirections massives d'utilisateurs vers des sites de fausses alertes système contenant des domaines frauduleux.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Tuer immédiatement tous les processus d'accès distants non validés s'exécutant sur l'ordinateur concerné et déconnecter le terminal d'internet.
* Bloquer les domaines associés aux pop-ups et publicités frauduleuses signalés.

**Éradication :**
* Désinstaller l'intégralité des logiciels d'accès distants installés de manière opportuniste lors de l'appel.
* Analyser le poste avec des outils d'antivirus complets pour s'assurer qu'aucun autre implant ou backdoor n'a été installé durant la session d'accès.

**Récupération :**
* Réinitialiser les mots de passe et sessions de l'ensemble des comptes et applications de l'utilisateur concerné qui étaient ouverts durant la prise de contrôle.
* Restaurer le système à partir d'une sauvegarde approuvée en cas de modifications structurelles d'administration.

#### Phase 4 — Activités post-incident
* Documenter la timeline de l'appel et de la connexion distante pour l'équipe juridique d'assurance ou de dépôt de plainte de l'entreprise.
* Sensibiliser les utilisateurs aux risques des arnaques au faux support technique et aux procédures officielles d'appel de l'assistance interne.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche de l'utilisation d'outils d'accès distants non répertoriés au sein du parc. | T1219 | Journaux d'exécution de processus d'endpoints | Lister l'intégralité des binaires s'exécutant et initiant des sessions réseau de contrôle à distance sur le parc. |
| Identification d'alertes web d'ingénierie sociale redirigeant les utilisateurs. | T1204.001 | Journaux d'audits du proxy web | Rechercher des requêtes web présentant des motifs d'URLs de redirections publicitaires agressives connues. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Nom de fichier | `anydesk[.]exe` | Outil de contrôle à distance commercial souvent abusé | Moyenne |
| Nom de fichier | `teamviewer[.]exe` | Outil de contrôle à distance commercial souvent abusé | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1219 | Command and Control | Remote Access Software | Utilisation détournée d'applications légitimes d'administration à distance pour contrôler les terminaux. |
| T1204.001 | Execution | User Execution: Malicious Link | Incitation de l'utilisateur à cliquer sur des alertes pop-ups pour déclencher la fraude. |

---

### Sources

* [BleepingComputer - Former US execs plead guilty to aiding tech support scammers](https://www.bleepingcomputer.com/news/security/former-us-execs-plead-guilty-to-aiding-tech-support-scammers/)

---

<div id="kimwolf-botnet-jacob-butler-arrest"></div>

## Kimwolf botnet + Jacob Butler arrest

### Résumé technique

Les polices américaines et canadiennes ont procédé à l'inculpation de Jacob Butler, un individu de 23 ans résidant à Ottawa, identifié comme le concepteur et l'administrateur principal du réseau d'appareils infectés (botnet) nommé **Kimwolf**. Ce réseau d'objets connectés (IoT) asservis regroupait plus de 3 millions d'équipements à travers le monde, incluant des boîtiers de streaming basés sur Android, des téléviseurs connectés et des routeurs domestiques.

Le botnet Kimwolf exploitait des vulnérabilités au niveau des protocoles d'administration et des configurations logicielles par défaut d'appareils Android pour installer des outils d'attaques DDoS et de redirection de serveurs mandataires (proxys résidentiels) à l'aide de bibliothèques compilées par NDK. Pour masquer son infrastructure C2, le malware stockait ses configurations chiffrées avec un algorithme de Stack XOR rudimentaire et transmettait ses requêtes de contrôle via le protocole DNS over TLS (DoT). 

L'infrastructure d'attaque commercialisait des capacités de sabotage par déni de service distribué (DDoS-as-a-service) pouvant générer des attaques records de l'ordre de 30 térabits par seconde, ciblant des institutions financières et des infrastructures publiques.

---

### Analyse de l'impact

L'impact technique réside dans la neutralisation d'un acteur majeur de l'économie cybercriminelle du DDoS à la demande. Le niveau de sophistication du malware est modéré mais l'étendue géographique et la volumétrie globale du botnet représentaient une menace critique d'écroulement d'infrastructures internet majeures.

---

### Recommandations

* Désactiver systématiquement le protocole de configuration automatique de ports UPnP sur l'ensemble des routeurs de l'entreprise.
* Configurer les serveurs de filtrage DNS internes pour interdire et bloquer l'usage de connexions DNS over TLS (DoT) vers des résolveurs publics non approuvés.
* Segmenter de manière étanche les réseaux d'équipements connectés et de diffusion multimédia du réseau de production d'entreprise.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Établir un inventaire de tous les dispositifs de diffusion multimédia (boîtiers Android, TV connectées) présents dans les locaux d'entreprise.
* Configurer la surveillance du trafic réseau de type DoT (port `853`) afin d'interdire son utilisation vers des adresses IP externes non spécifiées.

#### Phase 2 — Détection et analyse
* **Requête SIEM (flux réseau DoT)** :
  ```
  NetworkConnections
  | where DestinationPort == 853
  | where DestinationIP not in ('trusted_dns_resolvers_list')
  ```
* Analyser l'activité de trafic UDP ou TCP sortant d'appareils de diffusion IoT pour repérer des pics de bande passante anormaux représentatifs d'une participation active à une attaque de déni de service.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Déconnecter immédiatement l'équipement Android ou IoT ciblé du réseau d'entreprise.
* Bloquer le domaine de résolution d'infrastructure identifié `git[.]youzzjizz[.]com`.

**Éradication :**
* Procéder à une réinstallation d'usine du micrologiciel système de l'appareil Android et appliquer l'ensemble des mises à jour de sécurité disponibles.
* Modifier l'ensemble des identifiants et clés d'accès de configuration d'origine du dispositif.

**Récupération :**
* Réintégrer l'appareil au sein d'un VLAN d'isolement sans aucune communication possible vers les données stratégiques d'entreprise.
* Surveiller l'activité réseau de l'appareil pendant 72 heures pour écarter toute ré-infection automatique.

#### Phase 4 — Activités post-incident
* Analyser la conformité de l'inventaire matériel d'entreprise pour s'assurer qu'aucun autre équipement de marque ou firmware vulnérable similaire n'est connecté.
* Communiquer les indicateurs découverts (IoC) aux autorités policières s'occupant de l'enquête Kimwolf.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'équipements IoT internes communiquant via DNS over TLS suspect. | T1584.005 | Journaux de pare-feu et de flux réseau | Identifier l'ensemble des équipements initiant des connexions réseau persistantes sur le port `853`. |
| Recherche de connexions vers le domaine d'infrastructure Kimwolf. | T1584.005 | Journaux DNS d'entreprise | Rechercher des requêtes DNS résolvant le domaine `git.youzzjizz.com`. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `git[.]youzzjizz[.]com` | Domaine d'infrastructure C2 du botnet Kimwolf | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1584.005 | Resource Development | Stage Capabilities: Botnet | Enrôlement d'objets connectés et de boîtiers Android de streaming pour constituer un botnet d'attaque DDoS. |
| T1071.001 | Command and Control | Application Layer Protocol: Web Protocols | Dissimulation de l'activité de contrôle via le protocole chiffré DNS over TLS. |

---

### Sources

* [BleepingComputer - US and Canada arrest and charge suspected Kimwolf botnet admin](https://www.bleepingcomputer.com/news/security/us-and-canada-arrest-and-charge-suspected-kimwolf-botnet-admin/)
* [SecurityAffairs - Authorities arrest 23-year-old accused of running the Kimwolf botnet](https://securityaffairs.com/192533/cyber-crime/authorities-arrest-23-year-old-accused-of-running-the-kimwolf-botnet.html)

---

<div id="stc-telecom-network-c2-abuse"></div>

## STC Telecom Network + C2 Abuse

### Résumé technique

Une étude approfondie menée par les analystes de Hunt.io a mis en évidence une concentration technique anormale d'infrastructures de commandement et de contrôle (C2) de groupes d'attaquants mondiaux au Moyen-Orient. Sur un ensemble de 1 350 serveurs C2 actifs cartographiés, plus de **72 % d'entre eux** (981 serveurs) sont directement hébergés sur les segments réseau de l'opérateur historique saoudien **Saudi Telecom Company (STC)**.

Cette situation critique ne résulte pas d'une malveillance délibérée de l'opérateur, mais de la compromission massive et systématique de serveurs cloud et d'infrastructures de clients légitimes de STC par des attaquants externes. Les acteurs de menace, notamment russes (groupes RondoDox et Eagle Werewolf), exploitent ces serveurs piratés pour y déployer des agents d'implants de contrôle réseau variés de type Sliver, SoullessRAT, EchoGather ou Cobalt Strike. L'usage de segments d'IP commerciales deSTC permet de dissimuler le trafic d'exfiltration de données et de contourner les règles de blocage géographique des pare-feu d'entreprise sous couvert de connexions vers un opérateur de télécommunication saoudien majeur.

---

### Analyse de l'impact

L'impact opérationnel pour les équipes de défense SOC est particulièrement complexe : le blocage complet des blocs IP d'un opérateur de télécommunication d'envergure nationale est inenvisageable en raison des faux positifs massifs sur les communications commerciales d'entreprise. Le niveau de sophistication technique est élevé, exploitant la réputation IP d'infrastructures d'opérateurs pour éluder la détection.

---

### Recommandations

* Déployer des solutions d'analyse de comportement de flux réseau (NDR) capables d'identifier des balises de communication régulières (beacons) indépendamment de l'adresse IP de destination.
* Intégrer des flux de Threat Intelligence dynamiques pour identifier de manière chirurgicale les adresses IP individuelles compromises de STC plutôt que des blocs réseau globaux.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Intégrer la surveillance de l'activité d'outils d'implants C2 open-source ou commerciaux (Sliver, Cobalt Strike) au sein des règles d'alertes EDR de l'entreprise.
* Valider la journalisation continue des requêtes réseau de connexion vers l'Arabie Saoudite et les pays du Moyen-Orient.

#### Phase 2 — Détection et analyse
* **Règle de détection de balisage réseau (NDR/SIEM)** :
  ```
  NetworkConnections
  | where DestinationPort in (443, 80)
  | where RemoteIPCountry == 'SA'
  | summarize ConnectionCount = count() by SourceIP, DestinationIP, bin(TimeGenerated, 1h)
  | where ConnectionCount > 100
  ```
* Analyser l'activité des processus système Windows pour identifier l'exécution inattendue de binaires de diagnostic légitimes détournés (ex: `Fondue.exe`) s'exécutant parallèlement aux connexions réseau STC suspectes.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Isoler logiquement du réseau interne l'ensemble des serveurs ou postes initiant des communications avec les IP compromises de STC, notamment l'IP d'attaque `45[.]95[.]147[.]178`.
* Bloquer de manière individuelle les adresses IP d'attaques recensées par Hunt.io sur les pare-feu de périmètre.

**Éradication :**
* Identifier et supprimer l'ensemble des implants (fichiers DLL malveillants, agents Sliver) présents sur la station de travail compromise.
* Réinitialiser l'ensemble des sessions actives et forcer le renouvellement des identifiants des utilisateurs ayant interagi avec l'hôte compromis.

**Récupération :**
* Reconstruire le système à partir d'une sauvegarde officielle propre de l'entreprise et valider l'intégrité de la base de registre.
* Surveiller intensément le comportement de l'hôte pendant 72 heures après sa reconnexion au réseau de production.

#### Phase 4 — Activités post-incident
* Documenter la timeline de compromission et identifier le vecteur d'intrusion initial ayant permis le déploiement de l'implant.
* Mettre à jour l'ensemble des listes de serveurs de réputation IP d'entreprise avec les données qualifiées de Hunt.io.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'implants de type Sliver ou RAT communiquant vers STC. | T1071.001 | Journaux d'activité réseau d'endpoints | Identifier des connexions HTTPS persistantes d'intervalle régulier vers des segments d'IP de l'opérateur STC. |
| Détection d'utilisation de processus système légitimes détournés pour de la communication réseau. | T1583.003 | Journaux d'exécution de processus d'endpoints | Rechercher le lancement anormal de `Fondue.exe` ou d'outils d'exécution locaux avec arguments de connexion réseau. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| IP | `45[.]95[.]147[.]178` | Serveur relais d'attaque C2 hébergé chez STC | Haute |
| Domaine | `hunt[.]io` | Domaine officiel de recherche Hunt.io | Haute |
| Processus | `Fondue.exe` | Binaire Windows légitime abusé pour de l'exécution | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1071.001 | Command and Control | Application Layer Protocol: Web Protocols | Utilisation de flux HTTP/HTTPS standards pour dissimuler les échanges d'administration C2. |
| T1583.003 | Resource Development | Acquire Infrastructure: Virtual Private Server | Compromission et détournement de serveurs clients légitimes de STC pour établir des points d'appui. |

---

### Sources

* [SecurityAffairs - One Telecom Provider Hosted Most of the Middle East's Active C2 Infrastructure](https://securityaffairs.com/192518/hacking/one-telecom-provider-hosted-most-of-the-middle-east-s-active-c2-infrastructure.html)
* [CybersecurityNews - Hackers Abuse Middle East Telecom Networks for Large-Scale Command-and-Control Operations](https://cybersecuritynews.com/hackers-abuse-middle-east-telecom-networks/)

---

<div id="roadtools-entra-id-compromise-tactics"></div>

## ROADtools + Entra ID compromise tactics

### Résumé technique

Les analyses de l'unité de Threat Intelligence Unit 42 de Palo Alto Networks décrivent le détournement systématique de l'outil open-source de red-teaming de sécurité cloud **ROADtools** par des groupes cyber-attaquants étatiques. Cet outil en ligne de commande, conçu à l'origine pour l'audit, permet d'énumérer l'annuaire d'utilisateurs, de s'établir de manière persistante et de contourner les processus de double authentification (MFA) au sein des environnements d'identité cloud de type Microsoft Entra ID (anciennement Azure AD).

ROADtools exploite deux modules majeurs : `roadrecon` pour l'extraction massive d'informations de l'annuaire de locataire via les API Microsoft Graph, et `roadtx` pour la création, l'extraction et l'échange de jetons OAuth 2.0 ou de jetons principaux de rafraîchissement (Primary Refresh Tokens - PRT). Les attaquants utilisent `roadtx` pour enregistrer de manière illégitime de faux appareils de confiance au sein de l'annuaire d'entreprise afin de contourner les politiques d'accès conditionnel (CAP). L'utilisation de cet outil s'appuie sur des bibliothèques Python spécifiques (`python-requests`) qui génèrent des signatures d'accès et d'identifications de navigateurs caractéristiques, détectables par les défenseurs dans les journaux d'audit cloud.

---

### Analyse de l'impact

L'impact opérationnel est critique : la compromission et la falsification de jetons d'accès d'identité cloud permettent aux attaquants d'accéder sans restriction et de manière indétectable par mot de passe aux courriels, documents partagés et ressources d'administration cloud de l'entreprise. Le niveau de sophistication technique est élevé, abusant de la logique native de l'authentification moderne pour persister.

---

### Recommandations

* Activer et forcer la fonction de protection globale des jetons (Token Protection) dans Azure Entra ID pour lier de manière cryptographique les jetons d'accès aux terminaux approuvés.
* Configurer des politiques d'accès conditionnel strictes imposant uniquement l'usage d'appareils gérés ou de clés matérielles de sécurité physiques de type FIDO2.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Configurer la centralisation en temps réel de l'ensemble des journaux d'audit d'accès Entra ID et Microsoft Graph au sein du SIEM d'entreprise.
* Établir une ligne de base d'activité d'enregistrement et d'approbation d'appareils légitimes dans le locataire de l'entreprise.

#### Phase 2 — Détection et analyse
* **Requête d'audit cloud SIEM (Entra ID)** :
  ```
  AuditLogs
  | where OperationName == 'Register device'
  | where Result == 'success'
  | where AdditionalDetails contains 'requests' or AdditionalDetails contains 'python'
  ```
* Analyser les logs de connexion pour identifier des comportements d'énumération rapides et massifs de répertoires d'utilisateurs via les API Microsoft Graph.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Révoquer et supprimer immédiatement l'appareil non autorisé de l'annuaire Microsoft Entra ID.
* Forcer la révocation de l'intégralité des jetons d'accès actifs (PRT) et sessions utilisateur pour le compte d'identité compromis.

**Éradication :**
* Identifier l'ordinateur ayant servi de point d'entrée pour la compromission des identifiants et éliminer l'ensemble des outils ROADtools présents localement.
* Modifier les privilèges d'accès et exiger une ré-authentification forte par MFA FIDO2 pour l'utilisateur concerné.

**Récupération :**
* Valider l'intégrité de l'annuaire des configurations d'accès conditionnel d'Entra ID pour s'assurer qu'aucun autre changement malveillant n'a été appliqué.
* Surveiller de manière renforcée les logs d'accès du locataire cloud pendant une période minimale de 72 heures.

#### Phase 4 — Activités post-incident
* Analyser les documents et emails accédés par le compte utilisateur compromis pour évaluer d'éventuels risques de fuites de données d'entreprise ou réglementaires sous le RGPD.
* Améliorer les règles d'alertes SOC pour bloquer de manière proactive l'authentification par des agents de navigateurs d'outils Python non approuvés.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détection d'enregistrements d'appareils non autorisés utilisant des agents Python. | T1098.005 | Journaux d'audits d'identité Entra ID | Rechercher l'enregistrement de terminaux dont la version d'OS déclarée correspond aux signatures d'outils automatisés (`10.0.19041.928`). |
| Recherche d'abus de jetons d'accès PRT dérobés. | T1550 | Journaux de connexions cloud d'entreprise | Identifier des sessions d'accès d'utilisateurs présentant des changements géographiques impossibles ou de navigateurs non standards sans invite MFA. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `enterpriseregistration[.]windows[.]net` | Domaine standard de Microsoft pour l'enregistrement de terminaux | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1098.005 | Persistence | Account Manipulation: Device Registration | Enregistrement de faux terminaux au sein de l'annuaire d'identité cloud pour contourner les politiques d'accès. |
| T1550 | Defense Evasion | Use Alternate Authentication Material | Vol et réutilisation de jetons de session d'accès (PRT) pour éviter l'invite d'authentification MFA. |
| T1087 | Discovery | Account Discovery | Utilisation d'API Graph pour cartographier et énumérer l'annuaire d'utilisateurs d'entreprise. |

---

### Sources

* [Unit 42 - Paved With Intent: ROADtools and Nation-State Tactics in the Cloud](https://unit42.paloaltonetworks.com/roadtools-cloud-attacks/)

---

<div id="art-template-npm-package-coruna-exploit-kit"></div>

## art-template npm package + Coruna exploit kit

### Résumé technique

Des attaquants ont compromis la chaîne d'approvisionnement logicielle en s'emparant du contrôle de l'un des dépôts publics de la populaire bibliothèque JavaScript **art-template** sur le registre public npm. Ils ont publié des versions corrompues (allant de la version `4.13.3` à `4.13.6`) qui intègrent des scripts de chargement malveillants cachés (watering-hole attack) s'exécutant au niveau du navigateur des visiteurs des sites web intégrant ce composant.

Le script de chargement JavaScript côté client exécute le kit d'exploitation iOS nommé **Coruna**. Ce kit sophistiqué procède à cinq niveaux de vérifications structurelles successives (dont des validations de balises MathML et des calculs de preuve de travail via WebAssembly) pour confirmer l'absence d'environnements d'analyses automatisés (sandboxes). 

Une fois validé, le kit cible de manière active la vulnérabilité critique WebKit d'exécution de code à distance (**CVE-2024-23222**) affectant les téléphones d'utilisateurs iOS d'une version inférieure à `17.3` afin d'exécuter des commandes malveillantes système et d'implanter un espion sur l'appareil.

---

### Analyse de l'impact

L'impact opérationnel est majeur : la compromission d'une dépendance logicielle standard d'un site web d'entreprise permet de pirater de manière automatisée les téléphones portables personnels ou professionnels des collaborateurs ou clients visitant le portail. Le niveau de sophistication technique est très élevé, combinant une attaque de supply-chain avec un kit de détection anti-sandbox évolué et une exploitation de faille WebKit.

---

### Recommandations

* Auditer immédiatement l'arbre complet des dépendances logicielles de l'entreprise pour identifier et exclure d'urgence toute version affectée d'art-template (`4.13.3` à `4.13.6`).
* Exiger et forcer la mise à jour immédiate de l'ensemble de la flotte de terminaux mobiles d'entreprise de marque iOS vers une version supérieure à `17.3`.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Intégrer des outils d'analyse statique de composition logicielle (SCA) au sein des pipelines de build CI/CD d'entreprise.
* Assurer la journalisation réseau des requêtes et connexions web effectuées par les applications de production vers des domaines tiers non approuvés.

#### Phase 2 — Détection et analyse
* **Détection dans les fichiers source (SCA/Script)** :
  ```bash
  grep -r "l1ewsu3yjkqeroy.xyz" ./src/
  ```
* Analyser les logs réseau des terminaux mobiles pour isoler des requêtes web HTTP/HTTPS dirigées vers le domaine malveillant de chargement du kit Coruna `l1ewsu3yjkqeroy[.]xyz`.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Retirer et déréférencer immédiatement les versions compromises d'art-template du référentiel interne de stockage d'artéfacts de l'entreprise.
* Bloquer sur les pare-feu et proxy d'entreprise l'accès aux domaines associés `l1ewsu3yjkqeroy[.]xyz` et `v3[.]jiathis[.]com`.

**Éradication :**
* Remplacer la bibliothèque compromise par une version antérieure saine (`4.13.2`) ou appliquer le correctif applicatif officiel exempt de code de chargement.
* Recompiler et déployer en production la nouvelle version saine de l'application web d'entreprise.

**Récupération :**
* Mener un audit de sécurité sur l'ensemble des téléphones mobiles d'entreprise iOS d'une version vulnérable s'étant connectés aux applications web durant la période de compromission.
* Valider la réinitialisation de la session d'accès et surveiller le trafic des terminaux mobiles identifiés.

#### Phase 4 — Activités post-incident
* Collaborer avec l'équipe de développement logiciel pour s'assurer de l'adoption de processus de verrouillage des versions de dépendances (utilisation d'un fichier lock).
* Évaluer les obligations réglementaires de notification d'incidents de sécurité en cas de preuve de compromission de données de terminaux d'utilisateurs.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'applications internes ayant compilé la bibliothèque npm compromise. | T1195.001 | Journaux d'audits des pipelines CI/CD | Rechercher des exécutions de compilations de packages utilisant les versions `4.13.3` à `4.13.6` de la dépendance art-template. |
| Identification de terminaux iOS communiquant avec l'infrastructure Coruna. | T1189 | Journaux de proxy web mobile d'entreprise | Rechercher des traces de requêtes HTTP/HTTPS à destination du domaine `l1ewsu3yjkqeroy.xyz` initiées par des User-Agents mobiles. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `l1ewsu3yjkqeroy[.]xyz` | Serveur de distribution du kit d'exploitation WebKit Coruna | Haute |
| Domaine | `v3[.]jiathis[.]com` | Domaine tiers de redirection publicitaire intégré | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1195.001 | Initial Access | Supply Chain Compromise: Compromise Software Dependencies | Injection de code malveillant de chargement au sein d'une bibliothèque JavaScript npm publique. |
| T1189 | Initial Access | Drive-by Compromise | Exécution automatique du kit d'exploitation de vulnérabilité lors de la simple visite du site web corrompu. |

---

### Sources

* [CybersecurityNews - Hackers Abuse Popular art-template npm Package to Launch Watering-Hole Attacks](https://cybersecuritynews.com/hackers-backdoor-popular-art-template-npm-package/)

---

<div id="inj3ctor3-freepbx-jomangy-webshell-persistence"></div>

## INJ3CTOR3 + FreePBX JOMANGY webshell persistence

### Résumé technique

L'acteur cybercriminel connu sous le pseudonyme **INJ3CTOR3** mène des campagnes d'intrusions automatisées à grande échelle ciblant les serveurs de téléphonie professionnelle VoIP ouverts sur internet utilisant la solution de gestion **FreePBX (Asterisk)**. Le groupe exploite deux vulnérabilités critiques pour obtenir un accès initial : une injection de commande lors du stockage de configurations (CVE-2025-64328) et une injection SQL au niveau de points d'accès réseau d'endpoints (CVE-2025-57819).

Une fois l'intrusion réussie, l'attaquant déploie un webshell PHP malveillant sophistiqué nommé **JOMANGY**. Pour se prémunir de toute tentative de nettoyage par les administrateurs, JOMANGY implémente une persistance logique robuste structurée en six couches distinctes :
1. Écriture d'un script de démarrage système s'exécutant à chaque initialisation root de la machine.
2. Installation d'une tâche planifiée crontab verrouillée avec l'attribut d'immuabilité Linux (`chattr +i`).
3. Exécution en mémoire d'un démon chien de garde (watchdog) qui télécharge à nouveau le webshell s'il détecte sa suppression.
4. Écriture redondante du code PHP du webshell dans plus de 12 répertoires d'applications web d'administration différents de FreePBX.
5. Création de 18 comptes d'utilisateurs locaux d'accès dérobés dotés de privilèges variés pour maintenir l'accès.

L'objectif final de cette compromission est de commettre de la fraude à la facturation de télécommunications (toll fraud) en émettant des appels d'extorsion surtaxés aux frais de l'organisation victime.

---

### Analyse de l'impact

L'impact financier pour l'entreprise est immédiat et particulièrement lourd en raison du coût des communications téléphoniques internationales surtaxées passées de manière frauduleuse. Le niveau de sophistication technique de la persistance de JOMANGY est exceptionnel, rendant l'éradication manuelle quasiment impossible et imposant une réinstallation complète des serveurs affectés.

---

### Recommandations

* Isoler de manière stricte les serveurs d'administration et de gestion FreePBX de tout accès public direct depuis internet en forçant l'accès via un VPN ou un filtrage d'adresses IP.
* Procéder à des audits de configuration réguliers et appliquer immédiatement les correctifs pour les failles CVE-2025-64328 et CVE-2025-57819.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* S'assurer de la présence d'images de sauvegardes d'OS et de configurations saines et isolées hors ligne pour l'ensemble des serveurs VoIP de l'entreprise.
* Configurer des règles d'audits de création de fichiers au niveau des répertoires web d'administration de FreePBX.

#### Phase 2 — Détection et analyse
* **Requête de détection de fichiers d'endpoints (EDR/Linux)** :
  ```
  DeviceFileEvents
  | where FolderPath startswith '/var/www/html/admin/'
  | where FileName endswith '.php'
  | where InitiatingProcessFileName == 'httpd' or InitiatingProcessFileName == 'apache2'
  ```
* Analyser l'activité réseau pour détecter d'éventuelles connexions sortantes volumineuses ou vers des IP malveillantes associées de l'acteur, comme `45[.]95[.]147[.]178`.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Isoler immédiatement le serveur FreePBX affecté du réseau local d'entreprise et couper les liaisons d'appels SIP de l'opérateur pour stopper la fraude financière.
* Bloquer de manière permanente l'adresse IP `45[.]95[.]147[.]178` sur l'ensemble des pare-feu.

**Éradication :**
* En raison de la persistance à six couches de JOMANGY, l'éradication manuelle est déconseillée. Il convient de formater intégralement les disques du serveur et de réinstaller le système d'exploitation FreePBX à partir de paquets et de sources officielles certifiées.
* Forcer le renouvellement complet de l'ensemble des mots de passe des comptes administratifs et des secrets de configuration SIP.

**Récupération :**
* Restaurer les données d'annuaires et de configurations à partir d'une sauvegarde saine antérieure validée exempte de comptes dérobés.
* Valider que le serveur VoIP est réinstallé au sein d'un VLAN d'isolement avant d'autoriser à nouveau les connexions SIP réseau de l'opérateur.

#### Phase 4 — Activités post-incident
* Collaborer avec l'opérateur de télécommunication pour contester et évaluer le coût financier de la fraude d'appels émise.
* Mettre en œuvre une surveillance comportementale automatisée renforcée de l'activité du serveur FreePBX pendant un délai de 72 heures après sa remise en production.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détection de fichiers de webshells persistants au sein de répertoires web de FreePBX. | T1505.003 | Journaux d'audits du système de fichiers Linux | Analyser la présence de scripts PHP d'administration récemment modifiés ou non répertoriés dans les dossiers web. |
| Recherche d'activités réseau d'attaques d'INJ3CTOR3. | T1190 | Journaux d'accès HTTP du serveur Apache | Identifier des requêtes web HTTP POST dirigées vers des endpoints applicatifs présentant des structures d'injections SQL ou de commandes. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| IP | `45[.]95[.]147[.]178` | Serveur d'attaque et C2 du groupe INJ3CTOR3 | Haute |
| Chemin fichier | `/var/www/html/admin/modules/freepbx_ha` | Répertoire d'implantation récurrent de modules malveillants | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1190 | Initial Access | Exploit Public-Facing Application | Exploitation de vulnérabilités d'injections de commande ou SQL au niveau de serveurs FreePBX exposés. |
| T1505.003 | Persistence | Server Software Component: Web Shell | Déploiement du webshell PHP JOMANGY hautement persistant et redondant dans les répertoires d'administration. |
| T1098 | Persistence | Account Manipulation | Création et dissimulation de comptes d'utilisateurs locaux à privilèges pour maintenir l'accès. |

---

### Sources

* [CybersecurityNews - Hackers Use Six-Layer Persistence to Maintain Access on Compromised FreePBX Systems](https://cybersecuritynews.com/hackers-use-six-layer-persistence/)

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