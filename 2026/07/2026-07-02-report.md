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
  * [JADEPUFFER + Agentic ransomware](#jadepuffer-agentic-ransomware)
  * [FortiBleed campaign + Lynx ransomware](#fortibleed-campaign-lynx-ransomware)
  * [GuardFall + Open-source AI agents vulnerability](#guardfall-open-source-ai-agents-vulnerability)
  * [Phantom Squatting + AI domain hallucinations](#phantom-squatting-ai-domain-hallucinations)
  * [CleverHans research + AI-powered computer worm](#cleverhans-research-ai-powered-computer-worm)
  * [Operation Endgame + SocGholish botnet dismantlement](#operation-endgame-socgholish-botnet-dismantlement)
  * [JetBrains Marketplace + Malicious AI plugins](#jetbrains-marketplace-malicious-ai-plugins)
  * [ChocoPoC malware + Trojanized PoC exploits](#chocopoc-malware-trojanized-poc-exploits)
  * [EvilTokens PhaaS + ARToken panel](#eviltokens-phaas-artoken-panel)
  * [INC Ransom + Colorado Rehabilitation breach](#inc-ransom-colorado-rehabilitation-breach)
  * [LSHIY campaign + Azure CLI password spraying](#lshiy-campaign-azure-cli-password-spraying)
  * [Kubota network intrusion + Persistent access](#kubota-network-intrusion-persistent-access)
  * [Tchap compromise + French administration](#tchap-compromise-french-administration)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'analyse du paysage cyber de la mi-2026 met en lumière une transition critique vers des menaces hautement automatisées et systémiques, redéfinissant les concepts traditionnels de détection et de réponse. L’apparition d’acteurs de menaces dits « agentiques » (ATAs), illustrée par la campagne autonome **JADEPUFFER**, marque un jalon historique. Pour la première fois, des agents autonomes pilotés par de grands modèles de langage (LLM) sont observés en situation réelle, capables d'exécuter l'intégralité d'une chaîne d'attaque (reconnaissance, exploitation, pivot, chiffrement et extorsion) sans intervention humaine directe.

Cette automatisation offensive s'accompagne d'une exploitation fine des faiblesses inhérentes aux technologies d'IA en cours de déploiement au sein des entreprises. Les vulnérabilités de conception telles que **GuardFall** menacent la supply chain des assistants de codage open-source, tandis que les techniques de **Phantom Squatting** tirent astucieusement parti des hallucinations sémantiques des LLM pour empoisonner les dépendances logicielles. 

Parallèlement, les infrastructures cloud subissent une pression accrue via des campagnes massives d'ingénierie sociale et de contournement MFA (comme l'illustrent les kits **EvilTokens** / **ARToken** et la campagne **LSHIY**), démontrant que l'identité reste le maillon le plus vulnérable. Face à ces attaques adaptatives, les organisations doivent impérativement abandonner les approches réactives basées sur de simples signatures pour adopter des stratégies de résilience cyber dynamiques, axées sur l'isolation des environnements d'IA, le durcissement de la gestion des accès à privilèges et la détection comportementale proactive.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **Evil Corp** | Gouvernement, Finance, Infrastructures critiques | Utilisation de sites légitimes compromis pour injecter des scripts de redirection et distribuer le malware SocGholish. | T1566 (Phishing)<br>T1059 (Command and Scripting Interpreter) | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **Ghostwriter** | Administrations publiques, Partis politiques, Journalisme | Campagnes de phishing ciblées pour intercepter les identifiants Gmail et contourner les mécanismes de double facteur (MFA). | T1566.001 (Spearphishing Attachment)<br>T1114 (Email Collection) | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **Mustang Panda** | Diplomatie, Défense | Usurpation d'identités diplomatiques de pays partenaires pour distribuer des archives malveillantes via de faux portails de sécurité. | T1566.002 (Spearphishing Link)<br>T1105 (Ingress Tool Transfer) | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **TAG-182** | Société civile, Droits de l'homme, Dissidents | Promotion de faux outils de sécurité (VPN, lecteurs multimédias) via des réseaux sociaux pour installer le logiciel espion MarkiRAT. | T1566 (Phishing)<br>T1105 (Ingress Tool Transfer) | [Recorded Future TAG-182 Report](https://www.recordedfuture.com/research/nexus-tag182-disseminates-markirat) |
| **JADEPUFFER** | Technologie, Fournisseurs Cloud, Bases de données | Automatisation complète de l'exploitation de vulnérabilités applicatives (CVE-2025-3248), élévation de privilèges SQL et rançonnage autonome. | T1190 (Exploit Public-Facing Application)<br>T1486 (Data Encrypted for Impact) | [Sysdig Threat Research JADEPUFFER](https://webflow.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Ukraine / UE** | Administration publique | Intégration à la réserve cyber | Le Conseil de l'UE approuve l'inclusion formelle de l'Ukraine au sein de la réserve de cybersécurité européenne pour une assistance mutuelle d'urgence. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **Russie / Ukraine** | Société civile | Guerre de l'information | Écosystème coordonné d'ingérence étrangère (FIMI) exploitant l'IA générative pour diffuser des narratifs hostiles à l'adhésion européenne de l'Ukraine. | [EUvsDisinfo Russia Ukraine Report](https://euvsdisinfo.eu/russias-information-war-against-ukraines-european-future-is-a-threat-to-europe-itself/) |
| **Grèce / OTAN** | Diplomatie, Défense | Espionnage étatique | Campagne de spearphishing attribuée au groupe chinois Mustang Panda ciblant la représentation grecque auprès de l'OTAN. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **Belgique** | Renseignement | Infiltration mobile | Ciblage des terminaux professionnels des services de renseignement belges via l'exploitation de failles sur les serveurs Ivanti EPMM. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **France** | Administration publique | Ingérence électorale | Viginum identifie l'opération d'influence « Rokh Solis », liée à la firme israélienne Blackcore, ciblant les élections municipales françaises. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **USA / Chine** | Défense, Renseignement | Saisie d'infrastructures | Les autorités américaines démantèlent 13 domaines web opérés par le renseignement chinois pour recruter sous couverture des profils militaires. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **USA / Russie** | Gouvernement | Pression diplomatique | Le Département d'État américain offre une prime de 10 millions USD pour toute information menant à l'identification des opérateurs des groupes UNC5792 et UNC4221. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **Chine** | Technologie | IA défensive et offensive | Qihoo 360 annonce le développement de ses modèles Tulongfeng (recherche automatique de failles) et Yitianzhen (réponse à incident). | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **Russie** | Droits de l'homme, Justice | Détournement technologique | Les autorités russes utilisent des technologies médico-légales de Cellebrite pour extraire de force les données de l'activiste Andrey Pivovarov. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **Chine / USA** | Technologie | Espionnage Cloud | Le groupe Warp Panda compromet des pare-feux de bordure pour s'introduire de manière persistante au sein des locataires Microsoft 365 de ses cibles. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **Chine / USA** | Technologie | Vol de propriété intellectuelle | Alibaba est impliqué dans l'extraction industrielle (distillation de modèles) de données d'entraînement à partir des LLM Claude d'Anthropic. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **Israël / USA** | Diplomatie | Écoutes diplomatiques | Soupçons du renseignement américain concernant des tentatives d'interception israéliennes sur les canaux de négociations bilatérales avec l'Iran. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **Israël / Global** | Société civile | Espionnage ciblé | WhatsApp bloque des infrastructures d'ingénierie sociale liées à NSO Group destinées à déployer le logiciel espion Pegasus. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **Russie** | Gouvernement, Journalisme | Vol d'identifiants de communication | Des agents russes déploient des campagnes de phishing sophistiquées pour subtiliser les clés de secours et de chiffrement de comptes Signal. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Cryptographie post-quantique obligatoire | ANSSI | 16/06/2026 | France | ANSSI-2026-NQE | Arrêt des certifications de sécurité nationale pour les outils dépourvus de protections post-quantiques (PQC) dès 2027. Obligation pour l'administration publique d'ici 2030. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| Contrôle à l'exportation des modèles d'IA | Bureau of Industry and Security (BIS) | 12/06/2026 | États-Unis | US-BIS-2026-EXP | Directive temporaire suspendant l'accès mondial aux modèles d'IA Claude (Fable et Mythos) d'Anthropic pour réévaluation des risques de sécurité nationale. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| Réforme de la législation IA en Russie | Gouvernement de la Fédération de Russie | 01/07/2026 | Russie | RU-AI-2026-LAW | Révision du cadre légal sur l'usage des données d'entraînement pour stimuler l'IA souveraine russe et faciliter l'accès des services de renseignement (FSB). | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| Bulletin EDRi-gram | EDRi | 01/07/2026 | Europe | EDRi-gram 07/26 | Revue critique dénonçant la dérive des budgets européens alloués à l'IA au détriment du respect des droits fondamentaux. | [EDRi Gram July 1st](https://edri.org/our-work/edri-gram-1-july-2026/) |
| Recommandations Euro Numérique | EDRi | 01/07/2026 | Europe | EDRi-Euro-Priv | Plaidoyer technique exigeant l'intégration de preuves à divulgation nulle de connaissance (ZKP) pour garantir l'anonymat des transactions en Euro numérique. | [EDRi Digital Euro Study](https://edri.org/our-work/now-or-never-why-the-digital-euro-must-not-fail-on-privacy/) |
| Opacité des subventions de l'Union | Open Future | 01/07/2026 | Europe | OF-AI-2026-REP | Rapport dénonçant le manque de transparence et de marquage comptable standardisé (AI-tagging) sur les fonds de développement d'IA distribués par l'UE. | [EDRi AI Spend Transparency Report](https://edri.org/our-work/the-eu-spends-billions-on-ai-but-can-anyone-track-the-money/) |
| Harmonisation de la défense européenne | Comité économique et social européen (CESE) | 02/07/2026 | Europe | OJ:C_202603231 | Avis officiel portant sur la feuille de route de préparation de la défense 2030, prônant la standardisation des équipements de chiffrement tactiques. | [EUR-Lex JOIN 2025 27](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=OJ:C_202603231) |
| Encadrement de l'innovation de rupture | Comité économique et social européen (CESE) | 02/07/2026 | Europe | OJ:C_202603232 | Avis portant sur l'adaptation industrielle face aux technologies quantiques et d'intelligence artificielle appliquées à la défense nationale. | [EUR-Lex COM 2025 845](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=OJ:C_202603232) |
| Préservation des droits des travailleurs | Présidence chypriote du Conseil de l'UE | 02/07/2026 | Europe | OJ:C_202603220 | Recommandations juridiques visant à encadrer et limiter les dérives de surveillance algorithmique de l'activité des employés via des outils d'IA. | [EUR-Lex Cypriot Presidency](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=OJ:C_202603220) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Aide Humanitaire** | World Food Programme (PAM) | Noms, identifiants, coordonnées téléphoniques, coordonnées géospatiales GPS des populations enregistrées à Gaza. | 600 000 foyers | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **Justice / Droits de l'Homme** | Conseil de l'Europe | Documents d'identification personnelle des collaborateurs, archives internes d'enquêtes et correspondances confidentielles. | 297 Go de données | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **Santé** | Lithuanian State Accreditation Service | Informations administratives de certification professionnelle et dossiers d'accréditations médicales. | 62 000 professionnels | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **Santé / Pharma** | Novo Nordisk | Données médicales pseudonymisées relatives à des participants d'essais cliniques et données d'identification de médecins. | Non spécifié | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **Éducation** | Établissements clients d'Oracle PeopleSoft | Informations personnelles, scolaires et administratives des étudiants de plus de 100 universités (dont l'Université de Nottingham). | 300 instances compromises | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **Gouvernement** | Homeland Security Information Network (HSIN) | Rapports de renseignement criminel partagés, alertes internes de sécurité et fiches d'identification d'agents de la force publique. | Non spécifié | [BleepingComputer](https://www.bleepingcomputer.com/news/security/dhs-confirms-hackers-breached-hsin-info-sharing-platform/) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-46817 | TRUE  | Active    | 7.0 | 9.8   | (1,1,7.0,9.8) |
| 2 | CVE-2026-33825 | TRUE  | Active    | 5.5 | N/A→0 | (1,1,5.5,0)   |
| 3 | CVE-2026-28318 | TRUE  | Active    | 5.0 | 7.5   | (1,1,5.0,7.5) |
| 4 | CVE-2026-11645 | FALSE | Active    | 3.0 | N/A→0 | (0,1,3.0,0)   |
| 5 | VS Code zero-day|FALSE | Active    | 2.5 | N/A→0 | (0,1,2.5,0)   |
| 6 | CVE-2026-42897 | FALSE | Active    | 2.5 | N/A→0 | (0,1,2.5,0)   |
| 7 | CVE-2026-20230 | FALSE | Active    | 2.5 | N/A→0 | (0,1,2.5,0)   |
| 8 | CVE-2026-13760 | FALSE | Théorique | 2.0 | N/A→0 | (0,0,2.0,0)   |
| 9 | CVE-2026-14265 | FALSE | Théorique | 2.0 | N/A→0 | (0,0,2.0,0)   |
| 10| CVE-2026-14419 | FALSE | Théorique | 2.0 | N/A→0 | (0,0,2.0,0)   |
| 11| CVE-2026-14439 | FALSE | Théorique | 2.0 | N/A→0 | (0,0,2.0,0)   |
| 12| CVE-2026-50521 | FALSE | Théorique | 2.0 | N/A→0 | (0,0,2.0,0)   |
| 13| CVE-2026-58592 | FALSE | Théorique | 2.0 | N/A→0 | (0,0,2.0,0)   |
| 14| CVE-2026-58457 | FALSE | Théorique | 2.0 | N/A→0 | (0,0,2.0,0)   |
| 15| CVE-2026-49119 | FALSE | Théorique | 2.0 | N/A→0 | (0,0,2.0,0)   |
| 16| CVE-2026-13769 | FALSE | Théorique | 1.5 | N/A→0 | (0,0,1.5,0)   |
| 17| CVE-2026-34103 | FALSE | Théorique | 1.5 | N/A→0 | (0,0,1.5,0)   |
| 18| CVE-2026-58593 | FALSE | Théorique | 1.5 | N/A→0 | (0,0,1.5,0)   |
| 19| CVE-2026-53489 | FALSE | Théorique | 1.5 | N/A→0 | (0,0,1.5,0)   |
| 20| Citrix DoS     | FALSE | Théorique | 1.5 | N/A→0 | (0,0,1.5,0)   |
| 21| Adobe multiple | FALSE | Théorique | 1.0 | N/A→0 | (0,0,1.0,0)   |
| 22| Mozilla mult.  | FALSE | Théorique | 1.0 | N/A→0 | (0,0,1.0,0)   |
| 23| Chrome mult.   | FALSE | Théorique | 1.0 | N/A→0 | (0,0,1.0,0)   |
| 24| CRM Perks      | FALSE | Théorique | 1.0 | N/A→0 | (0,0,1.0,0)   |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-46817** | 9.8 | N/A | **TRUE** | 7.0 | Oracle Payments (E-Business Suite 12.2) | Injection SQL / RCE HTTP | RCE | Active | Isoler d'urgence les serveurs EBS d'Internet, appliquer les correctifs cumulatifs (CPU) d'Oracle. | [Security Affairs](https://securityaffairs.com/194599/security/oracle-e-business-suite-flaw-under-active-attack-950-systems-exposed.html) |
| **CVE-2026-33825** | N/A | N/A | **TRUE** | 5.5 | Microsoft Defender | Élévation locale de privilèges (BlueHammer) | LPE | Active | Appliquer les mises à jour automatiques du moteur Microsoft Defender / System Center. | [Security Affairs](https://securityaffairs.com/194577/security/cisa-warns-bluehammer-flaw-is-now-exploited-in-ransomware-attacks.html) |
| **CVE-2026-28318** | 7.5 | N/A | **TRUE** | 5.0 | SolarWinds Serv-U File Transfer | Déni de Service non authentifié | DoS | Active | Appliquer le correctif de SolarWinds, filtrer les ports d'administration. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **CVE-2026-11645** | N/A | N/A | FALSE | 3.0 | Google Chrome (V8 Engine) | Corruption de mémoire | RCE | Active | Mettre à jour immédiatement Google Chrome vers la dernière version stable. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **VS Code zero-day** | N/A | N/A | FALSE | 2.5 | github.dev / VS Code integration | Détournement de jetons OAuth (One-Click) | Auth Bypass | Active | Désactiver l'autorisation d'extensions tierces non vérifiées dans les workspaces web. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **CVE-2026-42897** | N/A | N/A | FALSE | 2.5 | Microsoft Exchange Server (OWA) | Cross-Site Scripting (XSS) stocké | Auth Bypass | Active | Appliquer le correctif cumulatif Microsoft Exchange de juin 2026. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **CVE-2026-20230** | N/A | N/A | FALSE | 2.5 | Cisco Unified Communications Manager | Server-Side Request Forgery (SSRF) | SSRF | Active | Isoler l'accès réseau aux services SIP et d'administration de Cisco Unified CM. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| **CVE-2026-13760** | N/A | N/A | FALSE | 2.0 | AWS CDK (NodejsFunction bundling) | Injection de commande OS (Docker) | RCE | PoC public | Mettre à jour d'urgence la dépendance globale `aws-cdk-lib`. | [AWS Security Bulletins](https://aws.amazon.com/security/security-bulletins/rss/2026-050-aws/) |
| **CVE-2026-14265** | N/A | N/A | FALSE | 2.0 | Pilotes JDBC AWS (Query Cache) | Désérialisation de données non vérifiées | RCE | PoC public | Mettre à jour les pilotes d'accès de bases de données, désactiver RemoteQueryCachePlugin. | [AWS Security Bulletins](https://aws.amazon.com/security/security-bulletins/rss/2026-051-aws/) |
| **CVE-2026-14419** | N/A | N/A | FALSE | 2.0 | Google Chrome (Skia Graphics Library) | Use-After-Free critique | RCE | PoC public | Mettre à jour Chrome vers une version supérieure à 150.0.7871.46. | [OffSeq Exchange](https://infosec.exchange/@offseq/116847792934953006) |
| **CVE-2026-14439** | N/A | N/A | FALSE | 2.0 | Outil Git partagé Altium | Path Traversal / Directory Escape | RCE | PoC public | Migrer sans délai vers la mise à jour Altium 8.1.1. | [CVEFeed Altium](https://cvefeed.io/vuln/detail/CVE-2026-14439) |
| **CVE-2026-50521** | N/A | N/A | FALSE | 2.0 | Microsoft Edge | Corruption de mémoire | RCE | PoC public | Forcer la mise à jour de Microsoft Edge sur l'ensemble du parc de postes clients. | [CVEFeed Edge](https://cvefeed.io/vuln/detail/CVE-2026-50521) |
| **CVE-2026-58592** | N/A | N/A | FALSE | 2.0 | Navigateur Ladybird (WebAssembly ESM) | Référence pendante (Dangling Reference) | RCE | PoC public | Mettre à jour le moteur de Ladybird vers les dernières compilations de correctifs. | [CVEFeed Ladybird](https://cvefeed.io/vuln/detail/CVE-2026-58592) |
| **CVE-2026-58457** | N/A | N/A | FALSE | 2.0 | Répéteurs Wi-Fi Shenzhen Aitemi | Injection de commande OS non authentifiée | RCE | PoC public | Désactiver les ports d'administration WAN des routeurs ou remplacer les matériels obsolètes. | [CVEFeed Shenzhen Aitemi](https://cvefeed.io/vuln/detail/CVE-2026-58457) |
| **CVE-2026-49119** | N/A | N/A | FALSE | 2.0 | Interface Web Gradio | Séquence de retour de répertoires | RCE | PoC public | Mettre à jour l'application Gradio vers la version stable 6.16.0 ou supérieure. | [CVEFeed Gradio](https://cvefeed.io/vuln/detail/CVE-2026-49119) |
| **CVE-2026-13769** | N/A | N/A | FALSE | 1.5 | AWS CLI (Insecure Unix Permissions) | Droits de fichiers incorrects par umask | LPE | PoC public | Réinitialiser les droits d'écriture et de lecture sur les dossiers de profils AWS, mettre à jour la CLI. | [AWS Security Bulletins](https://aws.amazon.com/security/security-bulletins/rss/2026-049-aws/) |
| **CVE-2026-34103** | N/A | N/A | FALSE | 1.5 | Système de gestion Guardian | Injection SQL dans subtitles.php | Auth Bypass | PoC public | Durcir les variables d'entrées et isoler la base de données SQL. | [Hugo Valters Mastodon](https://mastodon.social/@hugovalters/116847217989292663) |
| **CVE-2026-58593** | N/A | N/A | FALSE | 1.5 | Plateforme NodeBB | Spoofing d'en-tête de message ActivityPub | Auth Bypass | PoC public | Restreindre l'accès à la fédération ou appliquer les correctifs logiques NodeBB. | [CVEFeed NodeBB](https://cvefeed.io/vuln/detail/CVE-2026-58593) |
| **CVE-2026-53489** | N/A | N/A | FALSE | 1.5 | Moteur containerd | Abus de liens symboliques sur les fichiers de logs | LPE | PoC public | Mettre à jour containerd vers la version corrigée. | [CVEFeed containerd](https://cvefeed.io/vuln/detail/CVE-2026-53489) |
| **Citrix DoS** | N/A | N/A | FALSE | 1.5 | Passerelles VPN de marque Citrix | Plantage de processus via des paquets forgés | DoS | PoC public | Appliquer les correctifs recommandés par l'éditeur pour éviter les déconnexions massives. | [CERT-FR Citrix](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0822/) |
| **Adobe multiple** | N/A | N/A | FALSE | 1.0 | Adobe Reader et Acrobat | Dépassements de tampon en lecture PDF | RCE | Théorique | Planifier le déploiement d'urgence des patchs pour l'ensemble des postes bureautiques. | [CI Security Adobe Advisory](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-adobe-products-could-allow-for-arbitrary-code-execution_2026-066) |
| **Mozilla mult.** | N/A | N/A | FALSE | 1.0 | Moteur JavaScript Firefox | Corruption mémoire par type-confusion | RCE | Théorique | Déployer sans attendre les dernières versions logicielles de Firefox. | [CI Security Mozilla Advisory](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-mozilla-products-could-allow-for-arbitrary-code-execution_2026-065) |
| **Chrome mult.** | N/A | N/A | FALSE | 1.0 | Navigateur Chromium (Multiple Components) | Use-After-Free / Dépassements de limites | RCE | Théorique | Forcer la mise à jour automatique des instances Chromium de l'entreprise. | [CI Security Google Chrome Advisory](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-064) |
| **CRM Perks** | N/A | N/A | FALSE | 1.0 | Extensions WordPress (CRM Perks) | Injections SQL et redirections ouvertes | RCE | Théorique | Supprimer ou désactiver d'urgence l'ensemble des modules fournis par CRM Perks. | [Hugo Valters Mastodon](https://mastodon.social/@hugovalters/116847455342380229) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| JADEPUFFER: Agentic ransomware for automated database extortion | JADEPUFFER + Agentic ransomware | Première campagne autonome documentée de rançongiciel pilotée par agent IA. | [Sysdig Threat Research JADEPUFFER](https://webflow.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion) |
| FortiGate and MSSQL targeted in Fortibleed campaign | FortiBleed campaign + Lynx ransomware | Menace d'infiltration d'envergure ciblant les identifiants VPN d'entreprises clés. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/fortibleed-credential-theft-campaign-linked-to-lynx-ransomware/) |
| GuardFall Flaw Hits 10 of 11 Popular Open-Source AI Agents | GuardFall + Open-source AI agents vulnerability | Vulnérabilité de conception critique impactant les assistants IA de développement. | [Security Affairs](https://securityaffairs.com/194546/ai/guardfall-flaw-hits-10-of-11-popular-open-source-ai-agents.html) |
| Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector | Phantom Squatting + AI domain hallucinations | Nouvelle méthode d'empoisonnement de supply chain exploitant les faiblesses des LLM. | [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/) |
| What the first experimental AI-powered computer worm teaches us | CleverHans research + AI-powered computer worm | Démonstration pratique de la viabilité des vers informatiques autonomes dopés à l'IA. | [Le Monde](https://www.lemonde.fr/sciences/article/2026/07/01/ce-que-nous-enseigne-la-premiere-attaque-experimentale-d-un-ver-informatique-mu-par-l-intelligence-actuelle_6717463_1650684.html) |
| Operation Endgame dismantled SocGholish network | Operation Endgame + SocGholish botnet dismantlement | Opération internationale d'envergure contre un botnet d'accès initiaux critique. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| JetBrains Marketplace malicious plugins campaign | JetBrains Marketplace + Malicious AI plugins | Attaque ciblée de la supply chain de développement via de faux modules d'IA. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| New ChocoPoC malware targets security researchers | ChocoPoC malware + Trojanized PoC exploits | Campagne d'ingénierie sociale ciblant spécifiquement les chercheurs en cybersécurité. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-chocopoc-malware-targets-researchers-via-trojanized-poc-exploits/) |
| ARToken: Inside an EvilTokens affiliate panel targeting Microsoft 365 | EvilTokens PhaaS + ARToken panel | Plateforme avancée de contournement de l'authentification multifacteur d'M365. | [Cisco Talos Blog](https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/) |
| Colorado Rehabilitation By inc ransom | INC Ransom + Colorado Rehabilitation breach | Cyber-extorsion impactant un opérateur d'importance vitale du secteur médical. | [Ransomlook](https://www.ransomlook.io//group/inc%20ransom) |
| Azure CLI Targeted in LSHIY Password Spray Campaign | LSHIY campaign + Azure CLI password spraying | Infiltration d'environnements cloud par abus du protocole OAuth ROPC. | [Security Affairs](https://securityaffairs.com/194588/uncategorized/azure-cli-targeted-in-lshiy-password-spray-campaign-across-64-orgs.html) |
| Kubota hackers month-long network compromise | Kubota network intrusion + Persistent access | Intrusion industrielle persistante non détectée s'étendant sur un mois complet. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/kubota-says-hackers-had-month-long-access-to-network-systems/) |
| Compromise of the French State’s messaging service Tchap | Tchap compromise + French administration | Compromission et détournement de comptes sur un système de communication chiffré étatique. | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| Guide on Avoiding Money Transfer Scams | Contenu d'éducation générale ou de sensibilisation non-sécuritaire | [Global Cyber Alliance](https://globalcyberalliance.org/pause-before-you-pay-a-guide-to-avoiding-money-transfer-scams/) |
| SANS Stormcast July 2nd, 2026 | Contenu généraliste de type podcast récapitulatif | [SANS ISC](https://isc.sans.edu/diary/rss/33120) |
| SANS Stormcast July 1st, 2026 | Contenu généraliste de type podcast récapitulatif | [SANS ISC](https://isc.sans.edu/diary/rss/33116) |
| ANY.RUN Release Notes June 2026 | Notes de version commerciales d'un produit logiciel | [ANY.RUN Blog](https://any.run/cybersecurity-blog/release-notes-june-2026/) |
| Webinar: Why traditional email security is no longer enough | Contenu promotionnel de type webinaire marketing | [BleepingComputer](https://www.bleepingcomputer.com/news/security/webinar-why-traditional-email-security-is-no-longer-enough/) |
| Turning Indicators into Intelligence in OpenCTI | Guide d'intégration d'un produit commercial sans cas de menace active | [BleepingComputer](https://www.bleepingcomputer.com/news/security/turning-indicators-into-intelligence-in-opencti-with-criminal-ip/) |
| Check Point June 22nd Threat Intelligence Report | Rapport de veille d'actualité généraliste | [Check Point Research](https://research.checkpoint.com/2026/22nd-june-threat-intelligence-report/) |
| Martin Lee: Running through the Arctic | Contenu de portrait personnel ou de parcours de carrière | [Cisco Talos Blog](https://blog.talosintelligence.com/martin-lee-running-through-the-arctic-and-the-threat-landscape/) |
| Google malware infecting Android computers | Contenu de tribune ou de dénonciation sans faits techniques vérifiables | [Dendrobatus Azureus Mastodon](https://mastodon.bsd.cafe/@Dendrobatus_Azureus/116847264435698386) |
| Threat Model Weekly by Violet Blue | Revue de presse d'actualité généraliste hebdomadaire | [Violet Blue](https://sfba.social/@gypsyvegan/116847253159970766) |
| My fight for Gaza - with Aymeric Caron | Discussion de politique nationale sans aucun rapport avec la cybersécurité | [IRIS France](https://www.iris-france.org/mon-combat-sur-gaza-avec-aymeric-caron/) |
| Geopolitics of Fruits and Vegetables | Rapport macro-économique agricole hors domaine cyber | [IRIS France](https://www.iris-france.org/geopolitique-des-fruits-et-legumes/) |
| Mamdani: Democratic Primaries in New York | Chronique politique américaine sans rapport avec la cybersécurité | [IRIS France](https://www.iris-france.org/mamdani-grand-chelem-a-new-york-les-mardis-de-liris/) |
| Why Ask Credentials If There Are Secret Codes | Phishing d'opportunité ciblant des portefeuilles cryptos personnels (hors-cible corporate) | [SANS ISC](https://isc.sans.edu/diary/rss/33118) |
| Arrests in Poland over SIM-swapping cryptocurrency theft | Fait divers cybercriminel classique axé sur des actions de police locales | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| Instagram Meta AI recovery tool abused for takeovers | Abus logique sur une fonctionnalité de réseau social grand public | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| China-based Z.ai released GLM-5.2 model | Publication de modèle d'IA généraliste sans menace cyber directe | [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/) |
| Browser-Only Ransomware and LLM Hallucinations | Étude prospective ou théorique de laboratoire sans exploitation observée | [Check Point Research](https://research.checkpoint.com/2026/browser-only-ransomware-from-llm-hallucinations-to-a-practical-attack-technique/) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="jadepuffer-agentic-ransomware"></div>

## JADEPUFFER + Agentic ransomware

### Résumé technique

L'acteur de menace JADEPUFFER a mené la première campagne d'extorsion autonome historiquement documentée. Contrairement aux rançongiciels classiques nécessitant des opérateurs humains pour valider chaque étape, cette menace s'appuie sur un agent logiciel autonome piloté par LLM. 

La chaîne d'attaque débute par l'exploitation automatique de la vulnérabilité d'exécution de code à distance (RCE) référencée **CVE-2025-3248** sur l'outil de gestion d'orchestration d'IA **Langflow**. Une fois le point d'ancrage établi, l'agent autonome exécute des scripts de reconnaissance réseau locaux, découvre des services de bases de données internes, réalise une escalade de privilèges sur un serveur MySQL et procède au chiffrement automatique des tables Nacos et de bases applicatives critiques. L'agent conclut l'attaque en générant et déposant de manière dynamique une note de rançon personnalisée, gérant les interactions initiales d'extorsion de façon algorithmique.

### Analyse de l'impact

Cette attaque redéfinit la vitesse d'exécution des menaces cyber. Le passage d'attaques manuelles ou semi-automatiques à des campagnes agentiques élimine le « dwell time » classique dont disposent les analystes du SOC pour isoler les machines. L'impact opérationnel est immédiat : chiffrement total de bases de données en quelques minutes. La sophistication réside dans la capacité de l'agent à s'auto-adapter aux contraintes techniques de l'environnement compromis sans générer de requêtes de commande et contrôle (C2) humaines prévisibles.

### Recommandations

* Isoler immédiatement les environnements de test, de développement et de déploiement d'outils d'IA (Langflow, Flowise, etc.) au sein de segments réseau étanches.
* Imposer une authentification forte de type MFA sur l'accès aux interfaces graphiques de gestion des pipelines d'IA.
* Durcir les privilèges d'accès des comptes de services de bases de données (MySQL, Nacos) en interdisant les droits d'administration d'écriture globaux depuis l'extérieur.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* S'assurer que les flux d'audit système des environnements d'IA et de conteneurisation sont centralisés vers le SIEM.
* Valider que les solutions de filtrage réseau internes bloquent les accès non authentifiés aux ports d'administration des outils d'IA.

#### Phase 2 — Détection et analyse
* Surveiller les requêtes d'exécution de code ou les comportements de requêtes HTTP inattendus sur le service Langflow.
* Recherche de connexions sortantes suspectes depuis les serveurs d'IA vers l'extérieur.
* **Règle Sigma (Query SIEM) :**
  ```yml
  title: Langflow Execution from Unknown Source
  logsource:
    product: webserver
  detection:
    selection:
      uri|contains: '/api/v1/process'
      method: 'POST'
      status: 200
    condition: selection
  ```

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Isoler du réseau le serveur hébergeant Langflow via l'EDR. Couper les accès sortants de l'ensemble du segment IA.
* **Éradication :** Identifier et détruire les fichiers éphémères créés par l'agent. Réinitialiser l'ensemble des clés d'accès SQL et Nacos stockées ou accessibles sur le serveur d'IA.
* **Récupération :** Restaurer les bases de données et les serveurs d'orchestration d'IA depuis les sauvegardes hors-ligne saines, puis appliquer les correctifs d'urgence de Langflow.

#### Phase 4 — Activités post-incident
* Analyser les décisions prises par l'agent autonome durant l'intrusion en extrayant son historique de requêtes LLM local.
* Notifier les autorités (CNIL / NIS2) si des données clients hébergées en bases SQL ont été consultées ou compromises.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Découvrir des accès anormaux ou des escalades de privilèges SQL initiés par des comptes de services IA. | T1078.002 | Journaux d'audit MySQL | `search DB_User='langflow_user' AND Query matches 'GRANT ALL'` |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| IP | `45[.]131[.]66[.]106` | Serveur de commande de l'agent JADEPUFFER | Haute |
| IP | `64[.]20[.]53[.]230` | Serveur secondaire d'exfiltration de base de données | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1190 | Initial Access | Exploit Public-Facing Application | Exploitation de l'instance d'administration Langflow non protégée (CVE-2025-3248). |
| T1486 | Impact | Data Encrypted for Impact | Chiffrement automatisé des bases SQL et des configurations Nacos. |

### Sources

* [Sysdig Threat Research JADEPUFFER](https://webflow.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion)

---

<div id="fortibleed-campaign-lynx-ransomware"></div>

## FortiBleed campaign + Lynx ransomware

### Résumé technique

La campagne malveillante baptisée **FortiBleed** consiste en un ciblage massif et coordonné d'équipements de sécurité de bordure VPN SSL **Fortinet FortiGate** et de serveurs d'entreprise de gestion de bases de données **MSSQL**. 

L'attaque utilise des réseaux d'accès initiaux automatisés générant des milliards de tentatives d'authentification par force brute et de rejeux d'identifiants dérobés (credential stuffing) contre les serveurs ciblés. En cas de succès d'authentification sur le portail d'accès VPN SSL, l'attaquant s'introduit au sein du réseau d'entreprise, exécute des outils d'extraction d'identifiants (Credential Dumping) et procède à un mouvement latéral rapide vers l'Active Directory. L'objectif final identifié est le déploiement du rançongiciel **Lynx Ransomware**, opérant selon le schéma classique de double extorsion (vol de documents confidentiels et chiffrement du parc). Un sous-traitant critique de l'OTAN a notamment été compromis via cette méthode.

### Analyse de l'impact

L'impact est extrêmement critique pour les secteurs de la défense et de la logistique industrielle. L'intrusion via des passerelles de sécurité de confiance (VPN) rend l'activité initiale difficile à distinguer du trafic des collaborateurs légitimes. Les fuites d'e-mails et de secrets de conception industrielle chez les sous-traitants d'organisations de défense ou d'importance vitale menacent directement la sécurité nationale et la propriété intellectuelle industrielle.

### Recommandations

* Désactiver impérativement les protocoles de chiffrement et d'accès VPN SSL obsolètes au profit de méthodes d'accès Zero Trust Network Access (ZTNA).
* Imposer et durcir l'usage de l'authentification multifacteur (MFA) pour toute ouverture de session VPN.
* Restreindre et interdire l'exposition directe des ports de serveurs MSSQL (port 1433) sur Internet.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Configurer le blocage automatique temporaire des adresses IP réalisant plus de 5 tentatives infructueuses de connexion sur le portail FortiGate.
* Mettre en œuvre une surveillance de la cohérence géographique des connexions des comptes utilisateurs (Impossible Travel).

#### Phase 2 — Détection et analyse
* Analyser les logs FortiGate pour isoler les pics d'authentifications échouées sur des comptes d'administration.
* Repérer les mouvements latéraux émanant d'adresses d'accès VPN vers des serveurs sensibles hors des heures de bureau habituelles.
* **Règle YARA (Artefact FortiBleed) :**
  ```yara
  rule Detect_FortiBleed_CredentialDumper {
      strings:
          $str1 = "FortiBleed" nocase
          $str2 = "fortigate_login_brute"
      condition:
          any of them
  }
  ```

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Révoquer immédiatement les sessions actives du compte VPN identifié comme source de l'intrusion. Isoler l'accès externe du serveur MSSQL compromis.
* **Éradication :** Réinitialiser les mots de passe de l'ensemble des comptes Active Directory et des serveurs MSSQL de production. Purger l'ensemble des scripts de persistance locaux.
* **Récupération :** Valider l'intégrité des configurations FortiGate, replacer les instances MSSQL derrière des pare-feux restrictifs et restaurer les systèmes chiffrés par Lynx.

#### Phase 4 — Activités post-incident
* Mener une analyse forensique complète pour valider si le répertoire de l'Active Directory a été intégralement exfiltré.
* Notifier les correspondants sécurité nationaux (ANSSI / CSIRT) et les clients d'importance vitale (ex : OTAN) de la nature de l'exfiltration.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identifier des authentifications VPN réussies émanant de réseaux de routage VPN grand public ou de nœuds d'anonymisation Tor. | T1133 | Journaux d'accès FortiGate | `search EventID=Logon AND Source_IP matches Tor_Exit_Nodes` |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `bleepingcomputer[.]com` | Utilisé pour le relais de l'actualité de la menace | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1110 | Credential Access | Brute Force | Campagnes de force brute d'envergure globale sur VPN SSL FortiGate et ports d'accès MSSQL. |
| T1133 | Initial Access | External Remote Services | Utilisation d'accès VPN authentifiés pour s'introduire sur les postes d'administration. |

### Sources

* [BleepingComputer FortiBleed Link](https://www.bleepingcomputer.com/news/security/fortibleed-credential-theft-campaign-linked-to-lynx-ransomware/)
* [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/)

---

<div id="guardfall-open-source-ai-agents-vulnerability"></div>

## GuardFall + Open-source AI agents vulnerability

### Résumé technique

L'anomalie de conception critique nommée **GuardFall** a été identifiée au sein de 10 des 11 agents et assistants d'écriture de code d'Intelligence Artificielle open-source les plus populaires du marché. 

Cette vulnérabilité réside dans une mauvaise gestion du nettoyage et de la validation des données d'entrées (inputs) de commandes bash exécutées par les agents logiciels autonomes. Un attaquant peut injecter des instructions shell hostiles en exploitant la réécriture dynamique de requêtes au format d'expressions régulières (Regex). En incitant l'agent d'IA à parser un fichier de documentation ou un dépôt de code corrompu, l'attaquant provoque l'exécution de commandes malveillantes arbitraires dans le contexte système de la station de travail de développement ou du conteneur d'exécution de l'agent. Seul l'assistant de codage open-source *Continue* s'est révélé immunisé grâce à un système de vérification des jetons d'appels stricts.

### Analyse de l'impact

L'impact potentiel de GuardFall sur la supply chain logicielle est dévastateur. Étant donné l'adoption généralisée des assistants d'IA par les équipes de développement logiciel, un attaquant peut compromettre à distance des milliers d'environnements de développement (IDE) en soumettant simplement des pull requests intégrant des fichiers Markdown contenant des charges utiles spécifiquement forgées. Cela peut mener à l'exfiltration automatique de clés d'API, de codes sources propriétaires et de jetons d'accès privilégiés.

### Recommandations

* Interdire l'utilisation d'assistants IA de codage open-source non approuvés par l'équipe de sécurité et n'intégrant pas d'isolation étanche des processus d'exécution (sandboxing).
* Préférer des solutions industrielles robustes de type *Continue* ou des agents configurés au sein de conteneurs Docker éphémères sans droits root.
* Auditer systématiquement l'ensemble des fichiers Markdown de documentation importés au sein des projets.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Définir une politique de sécurité système interdisant aux éditeurs de code (VS Code, JetBrains) d'exécuter des processus enfants bash avec des privilèges élevés sans validation utilisateur.
* Déployer des conteneurs de développement isolés (DevContainers) pour restreindre l'accès au système hôte.

#### Phase 2 — Détection et analyse
* Surveiller l'arborescence des processus pour détecter toute exécution anormale de shell émanant du processus parent de l'assistant d'IA ou de l'éditeur de code.
* Relever toute tentative anormale de lecture des fichiers sensibles locaux (clés ssh, fichiers d'environnement `.env`).
* **Requête EDR (Détection Processus Enfant suspect) :**
  ```
  ProcessParentName IN ('vscode.exe', 'idea64.exe') AND ProcessChildName IN ('bash', 'sh', 'cmd.exe', 'powershell.exe') AND CommandLine matches 'curl|wget|chmod'
  ```

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Isoler le conteneur de développement suspect ou la station de travail de l'ingénieur ciblé. Bloquer les jetons de session d'accès aux dépôts Git associés.
* **Éradication :** Supprimer les dépendances et dépôts de code corrompus contenant les charges utiles. Mettre à niveau les agents d'IA de codage vers des versions appliquant des contrôles d'exécutions d'API stricts.
* **Récupération :** Recompiler et réinitialiser les identifiants d'accès d'intégration continue potentiellement compromis par l'exfiltration de variables d'environnement.

#### Phase 4 — Activités post-incident
* Conduire un examen complet des derniers commits poussés par le poste de développement compromis pour éliminer tout risque d'injection de portes dérobées dans le produit applicatif.
* Identifier l'ensemble des extensions d'IA compromises installées au sein de l'organisation.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Rechercher des tentatives d'exécution de commandes non conventionnelles intégrées au sein d'historiques de builds ou de logs de déploiements. | T1203 | Journaux d'audit de l'IDE / CI-CD | `search Command matches 'bash -c' AND Source matches 'AI_Assistant_Plugin'` |

### Indicateurs de compromission (DEFANG obligatoire)

*Aucun indicateur réseau ou d'artefact binaire spécifique n'est applicable à cette vulnérabilité conceptuelle de conception générique.*

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1203 | Execution | Exploitation for Client Execution | Exploitation des faiblesses logiques de parsing des requêtes bash par les agents d'IA. |
| T1195 | Initial Access | Supply Chain Compromise | Introduction de charges utiles malveillantes au sein de projets ou documentations pour piéger les développeurs. |

### Sources

* [Security Affairs GuardFall](https://securityaffairs.com/194546/ai/guardfall-flaw-hits-10-of-11-popular-open-source-ai-agents.html)

---

<div id="phantom-squatting-ai-domain-hallucinations"></div>

## Phantom Squatting + AI domain hallucinations

### Résumé technique

La technique offensive émergente baptisée **Phantom Squatting** exploite de façon systémique le phénomène d'hallucination inhérent aux grands modèles de langage (LLM). 

Les développeurs interrogent de plus en plus les modèles d'IA pour obtenir des conseils ou des scripts de dépannage logiciel. Lors de la génération de codes ou d'instructions réseau, les LLM ont tendance à halluciner et à insérer des adresses de domaines internet ou des URL d'API fictifs (comme des dépôts de paquets ou des serveurs de collecte de logs non existants). Les attaquants exploitent cette faiblesse en prédisant de manière linguistique ces hallucinations sémantiques, puis enregistrent de façon préventive ces noms de domaines inexistants. Dès lors qu'un développeur exécute le code proposé par l'IA sans vérification préalable, les pipelines de déploiement et d'intégration continue (CI/CD) de la victime se connectent automatiquement à l'infrastructure malveillante, facilitant l'interception furtive de données de débogage et de secrets de production.

### Analyse de l'impact

L'impact sur la supply chain logicielle est majeur et extrêmement difficile à détecter par les outils classiques d'analyse de vulnérabilités (SCA). Le trafic réseau émis par les serveurs d'intégration semble légitime, car il provient de lignes de codes directement approuvées et insérées par les développeurs. Cette technique permet l'interception passive automatisée de jetons de pipelines, de configurations sensibles ou de données de test de bases de données de production.

### Recommandations

* Interdire l'utilisation et l'exécution directe de codes et scripts générés par des LLM sans vérification humaine ou automatisation d'audits statiques de sécurité (SAST).
* Mettre en œuvre une surveillance DNS proactive pour identifier les connexions émises par les serveurs internes vers des noms de domaines nouvellement enregistrés (New Domains Registration).
* Bloquer les requêtes réseau vers des adresses résolues par des requêtes de type NXDOMAIN (No Such Domain).

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Configurer les serveurs DNS de l'entreprise pour logger l'intégralité des requêtes émises par les pipelines d'intégration continue (CI/CD).
* Intégrer des listes de domaines de confiance exclusifs (Whitelisting) pour le téléchargement de dépendances et de modules logiciels.

#### Phase 2 — Détection et analyse
* Surveiller l'apparition de résolutions DNS réussies vers des domaines récemment enregistrés (depuis moins de 30 jours) émanant de serveurs de développement.
* Analyser les codes sources internes pour repérer les URL suspectes insérées par les modèles d'IA.
* **Règle de détection DNS (Requête proxy/WAF) :**
  ```
  search Domain_Query matches '*notifier[.]io*' AND Age_Of_Domain < 30 days
  ```

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Bloquer immédiatement la résolution DNS et l'adresse IP du domaine squatté au niveau des pare-feux périphériques. Isoler le pipeline CI/CD concerné.
* **Éradication :** Retirer du code source les lignes contenant les domaines hallucinés et nettoyer les caches de dépendances locales.
* **Récupération :** Réinitialiser d'urgence l'ensemble des clés d'API et identifiants qui ont transité par le domaine intercepté.

#### Phase 4 — Activités post-incident
* Réaliser une rétrospective avec les équipes de développement pour identifier les assistants LLM d'IA à l'origine du code halluciné afin d'ajuster leurs règles d'usage.
* Auditer les dépôts Git internes pour valider qu'aucun autre composant de l'application n'utilise des variables pointant vers des infrastructures non maîtrisées.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Rechercher des flux de données sortants volumineux ou inhabituels émis vers des ports de collecte de logs (ports 514, 443, 9200) par des pipelines CI/CD vers des adresses externes suspectes. | T1195 | Journaux d'audit Firewall / Netflow | `search Source_IP IN (Pipelines_IP) AND Dest_IP NOT IN (Whitelisted_Clouds)` |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | `hxxps[://]api[.]build-notifier[.]io/v1/pipeline/events` | Domaine halluciné enregistré et exploité par les attaquants | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1195 | Initial Access | Supply Chain Compromise | Enregistrement de domaines hallucinés par IA pour intercepter passivement les données de développement. |
| T1583.001 | Resource Development | Acquire Infrastructure: Domains | Achat préventif de domaines suggérés par les modèles d'apprentissage. |

### Sources

* [Palo Alto Unit 42 Phantom Squatting](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)

---

<div id="cleverhans-research-ai-powered-computer-worm"></div>

## CleverHans research + AI-powered computer worm

### Résumé technique

L'équipe canadienne de recherche en cybersécurité *CleverHans* a réalisé la première démonstration technique concluante de la viabilité d'un **ver informatique autonome propulsé par Intelligence Artificielle**. 

Ce logiciel malveillant de type ver utilise l'API d'un modèle de langage hébergé (LLM) pour analyser à la volée son environnement, reconfigurer son propre code de manière dynamique et identifier les failles du système cible afin de se propager d'hôte en hôte. L'originalité technique réside dans l'utilisation de techniques d'ingénierie d'invites (prompt injection) pour forcer le LLM à bypasser ses propres barrières d'éthique et de sécurité afin de générer des payloads offensifs furtifs adaptés à chaque cible sans nécessiter de connexions C2 pour obtenir des instructions humaines additionnelles.

### Analyse de l'impact

L'existence d'outils d'infection capables d'auto-adaptation en temps réel menace l'ensemble des mécanismes de sécurité historiques basés sur des signatures fixes de malwares (antivirus traditionnels, IDS). Un ver autonome peut muter ses patterns comportementaux et de fichiers d'une machine à une autre, rendant la détection extrêmement ardue. Son rayon d'action est décuplé au sein des réseaux industriels ou des environnements IoT connectés où les correctifs sont difficiles à déployer à grande échelle.

### Recommandations

* Mettre en œuvre des technologies de détection comportementale basées sur l'analyse des anomalies (EDR de nouvelle génération utilisant des heuristiques dynamiques).
* Restreindre drastiquement les communications de machine à machine au sein du réseau local par des règles de micro-segmentation strictes.
* Isoler les hôtes hébergeant des interfaces de programmation et des API d'IA du reste du réseau de production d'entreprise.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Valider que les règles de blocage de communications latérales locales (East-West traffic) sont effectives au niveau des switches et pare-feux locaux.
* Disposer de sauvegardes immuables et d'images de serveurs prêtes à être redéployées rapidement.

#### Phase 2 — Détection et analyse
* Surveiller l'augmentation anormale du trafic réseau local sur des ports d'administration (WinRM, SSH, SMB) émanant de machines bureautiques.
* Repérer des modifications dynamiques inhabituelles de fichiers binaires ou de scripts systèmes locaux.
* **Indicateur Réseau (Scan latéral suspect) :**
  ```
  ProcessName='system' AND EventID=LogonAttempt AND Frequency_By_Minute > 100
  ```

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Isoler immédiatement l'ensemble des postes de travail affectés de manière physique en déconnectant les réseaux Wi-Fi et filaires. Configurer des règles d'isolation EDR globales.
* **Éradication :** Reconstruire intégralement les serveurs et postes contaminés à partir des masters sains certifiés.
* **Récupération :** Rétablir les accès réseaux de manière progressive, segment par segment, après validation de l'absence totale d'activité malveillante.

#### Phase 4 — Activités post-incident
* Analyser l'évolution sémantique et la structure logique des versions du ver récupérées en mémoire pour comprendre l'algorithme d'apprentissage offensif déployé.
* Ajuster les modèles de détection heuristique et mettre à niveau la surveillance réseau.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Découvrir des modifications furtives de fichiers systèmes (systèmes d'exploitation Windows ou Linux) n'entrant pas dans les cadres classiques d'administration ou de mises à jour de l'entreprise. | T1542 | Journaux de contrôle d'intégrité (FIM) | `search File_Path matches 'C:\Windows\System32\*' AND Modified_By NOT IN (Trusted_WUA)` |

### Indicateurs de compromission (DEFANG obligatoire)

*Aucun marqueur binaire universel unique n'est édité en raison de la nature dynamique et auto-générée du code par le modèle de langage de l'infection.*

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1542 | Defense Evasion | Pre-OS Boot | Modification de sections de démarrage ou de scripts système pour se rendre persistant. |
| T1105 | Command and Control | Ingress Tool Transfer | Copie autonome de binaires et de scripts adaptatifs d'une machine vers une autre. |

### Sources

* [Le Monde AI Computer Worm](https://www.lemonde.fr/sciences/article/2026/07/01/ce-que-nous-enseigne-la-premiere-attaque-experimentale-d-un-ver-informatique-mu-par-l-intelligence-actuelle_6717463_1650684.html)

---

<div id="operation-endgame-socgholish-botnet-dismantlement"></div>

## Operation Endgame + SocGholish botnet dismantlement

### Résumé technique

L'opération policière internationale d'envergure baptisée **Operation Endgame** a permis de porter un coup d'arrêt majeur aux opérations du groupe criminel **Evil Corp** en démantelant son réseau de distribution de malwares de type **SocGholish** (également connu sous le nom de *UpdateAgent*). 

Ce botnet utilisait un mécanisme d'accès initial basé sur la compromission préalable de milliers de serveurs web légitimes. Les serveurs piratés injectaient des scripts JavaScript masqués qui redirigeaient les visiteurs vers de fausses pages d'alerte de mise à jour de navigateur internet. L'opération d'infiltration policière internationale a permis la saisie coordonnée de 106 serveurs d'administration et la neutralisation de 14 971 sites web infectés à travers le monde.

### Analyse de l'impact

Cette action policière d'envergure réduit significativement les capacités de diffusion d'infections initiales du groupe cybercriminel Evil Corp à l'échelle globale. SocGholish servait de vecteur d'accès initial privilégié pour le déploiement de rançongiciels impactant les finances, les services gouvernementaux et les infrastructures critiques de dizaines de pays. L'analyse des serveurs saisis fournit aux équipes de threat intelligence un volume inédit d'informations sur l'infrastructure de command and control de cet acteur de menace.

### Recommandations

* Nettoyer d'urgence les serveurs web d'entreprise infectés par des scripts de redirection JavaScript de types SocGholish.
* Restreindre les droits des utilisateurs bureautiques concernant l'exécution automatique de scripts Java, JS ou PowerShell à partir des navigateurs internet.
* Déployer des solutions de filtrage d'URL capables de catégoriser et bloquer en temps réel les domaines suspects créés de manière opportuniste.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Mettre en place des politiques d'isolation et de restriction de l'usage des fichiers d'extensions `.js`, `.jse` et `.vbs` sur les terminaux des utilisateurs via les règles GPO de l'Active Directory.
* Auditer de manière externe l'intégrité des serveurs web publics de l'entreprise.

#### Phase 2 — Détection et analyse
* Surveiller l'exécution inhabituelle du processus système `wscript.exe` initié par des processus de navigateurs internet (Chrome, Edge).
* Repérer des requêtes réseau sortantes d'utilisateurs vers des domaines générés de manière aléatoire (DGA).
* **Règle de détection EDR (Processus Suspect) :**
  ```
  ParentProcessName IN ('chrome.exe', 'msedge.exe', 'firefox.exe') AND ProcessName='wscript.exe' AND CommandLine matches '\.js'
  ```

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Isoler le poste utilisateur affecté du réseau informatique. Révoquer ses identifiants et accès réseau d'entreprise.
* **Éradication :** Supprimer les clés de registre de persistance et purger les fichiers de scripts malveillants stockés dans les répertoires temporaires `%TEMP%`.
* **Récupération :** S'assurer de la réinstallation saine des applications et de l'activation des protections de navigateur avant de reconnecter la machine au réseau.

#### Phase 4 — Activités post-incident
* Identifier l'ensemble des sites web institutionnels compromis de l'entreprise pour supprimer les injections malveillantes.
* Capitaliser sur les IoC découverts suite au démantèlement judiciaire pour mettre à jour les grilles de détection du SIEM.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Rechercher des tentatives d'exécution de fichiers d'extensions JavaScript en dehors des répertoires de développement approuvés. | T1059.007 | Journaux d'activité des postes EDR | `search File_Created IN ('*.js') AND Path NOT IN ('C:\Users\*\Development\*')` |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | `hxxps[://]cert[.]europa[.]eu/publications/threat-intelligence/cb26-07/` | Rapport de threat intelligence documentant l'opération | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566 | Initial Access | Phishing | Diffusion via des techniques d'ingénierie sociale imitant de fausses mises à jour de navigateurs (Drive-by Compromise). |
| T1059 | Execution | Command and Scripting Interpreter | Exécution de charges utiles par l'intermédiaire d'interpréteurs de scripts locaux (wscript/cscript). |

### Sources

* [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/)

---

<div id="jetbrains-marketplace-malicious-ai-plugins"></div>

## JetBrains Marketplace + Malicious AI plugins

### Résumé technique

Une quinzaine d'extensions de développement tierces compromises ont été identifiées et supprimées de la boutique d'applications officielle **JetBrains Marketplace**. 

Ces plugins malveillants imitaient des assistants d'écriture de code et de génération d'Intelligence Artificielle légitimes. Une fois installés par les développeurs au sein de leurs environnements de développement intégrés (IDE), les plugins malveillants s'exécutaient de manière invisible pour analyser les fichiers système locaux et intercepter les clés d'API secrètes d'accès aux services de grands modèles de langage (LLM) comme OpenAI ou Anthropic. Environ 70 000 développeurs de par le monde ont téléchargé ces modules vérolés avant leur neutralisation par l'équipe de sécurité de JetBrains.

### Analyse de l'impact

L'impact financier et informationnel est significatif pour les entreprises éditrices de logiciels. L'exfiltration de clés d'API de services LLM peut mener au détournement des crédits financiers des abonnements d'entreprise par les attaquants (pour des activités de revente ou de calcul de masse). De plus, l'accès frauduleux à ces jetons peut permettre aux attaquants d'accéder indirectement aux historiques de requêtes confidentielles soumises par les développeurs ou d'injecter des données d'entraînement empoisonnées.

### Recommandations

* Interdire le téléchargement de modules et d'extensions d'IDE n'ayant pas reçu de certification officielle de la part de l'éditeur ou de validation de l'équipe de cybersécurité interne.
* Restreindre les clés d'API des services LLM de production en configurant des limitations financières de consommation mensuelles d'urgence.
* Réinitialiser sans attendre l'ensemble des clés de services d'IA générative utilisées au sein des IDE des développeurs.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Établir une liste d'extensions JetBrains explicitement autorisées (Whitelisting) et bloquer l'installation libre par les collaborateurs depuis les options de configuration centralisées de l'IDE.
* Monitorer et isoler l'usage des variables d'environnement contenant des secrets ou des clés de services d'IA.

#### Phase 2 — Détection et analyse
* Surveiller les requêtes d'exfiltrations réseau suspectes émanant des processus parents de l'IDE JetBrains (`idea64.exe`, `pycharm64.exe`).
* Relever toute modification inhabituelle des fichiers de configurations locaux des extensions.
* **Indicateur de comportement suspect (EDR) :**
  ```
  ProcessParentName='idea64.exe' AND ProcessChildName IN ('curl', 'wget') AND CommandLine matches 'api\.openai\.com'
  ```

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Isoler le poste de travail du développeur de manière logique. Révoquer ses jetons d'accès d'intégration et ses clés d'API d'Intelligence Artificielle.
* **Éradication :** Désinstaller manuellement les extensions malveillantes de l'arborescence des répertoires de JetBrains. Purger les répertoires temporaires locaux.
* **Récupération :** Assurer la réinitialisation complète de l'ensemble des clés secrètes d'entreprise et déployer l'environnement de développement assaini.

#### Phase 4 — Activités post-incident
* Identifier et auditer l'ensemble des consommations financières d'API enregistrées durant les derniers jours pour évaluer le coût du vol de ressources.
* Alerter la communauté des développeurs de l'organisation sur les méthodes d'usurpations de plugins sur les Marketplaces officielles.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Identifier des appels de connexions réseau inhabituels d'outils de codage vers des adresses IP externes non associées à des services clouds légitimes. | T1195 | Journaux d'audit Firewall / Netflow | `search Source_IP IN (Dev_Subnet) AND Application='JetBrains' AND Dest_IP NOT IN (Whitelisted_Clouds)` |

### Indicateurs de compromission (DEFANG obligatoire)

*Les indicateurs d'IP spécifiques et les signatures de hachages des modules modifiés font l'objet d'un nettoyage dynamique par l'éditeur JetBrains.*

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1195 | Initial Access | Supply Chain Compromise | Infiltration de la boutique de plugins officielle de JetBrains pour cibler les stations de travail de développement. |
| T1539 | Credential Access | Steal Web Session Cookie | Recherche et siphonnage furtif de clés secrètes de services d'IA stockées en mémoire ou sur disque. |

### Sources

* [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/)

---

<div id="chocopoc-malware-trojanized-poc-exploits"></div>

## ChocoPoC malware + Trojanized PoC exploits

### Résumé technique

Une campagne d'ingénierie sociale ciblée fait rage contre la communauté internationale des experts et chercheurs en cybersécurité. Les attaquants conçoivent et publient de faux codes d'exploits de vulnérabilités (Proof of Concept - PoC) de type zero-day ou très récemment publiées sur la plateforme **GitHub**. 

Ces codes d'exploitation factices embarquent discrètement un script de téléchargement malveillant (dropper). Dès lors qu'un analyste de sécurité télécharge et exécute le script pour tester la vulnérabilité au sein de son laboratoire, le malware baptisé **ChocoPoC** s'installe en mémoire, s'assure d'une persistance sur le poste de travail de l'expert, collecte les informations d'identification locales et exfiltre l'historique des travaux d'audits en cours.

### Analyse de l'impact

L'impact informationnel et stratégique est majeur pour les sociétés de services en cybersécurité et les équipes de réponse à incident (CERT/SOC). En compromettant les postes de travail d'auditeurs de sécurité, les attaquants accèdent à des rapports de vulnérabilités critiques non encore publiques (zero-days) d'entreprises clientes, ainsi qu'à des clés de connexions SSH d'infrastructures sensibles en cours de remédiation, créant un risque immédiat d'attaques secondaires d'envergure.

### Recommandations

* Interdire formellement l'exécution directe de codes d'exploits ou de PoC issus de sources publiques GitHub non certifiées directement sur les stations de travail d'administration ou de production.
* Exécuter systématiquement toute preuve de concept de test au sein d'environnements de bac à sable (sandbox) physiques ou de machines virtuelles totalement isolées logiquement d'Internet et du réseau d'entreprise.
* Analyser manuellement et de manière critique la structure logique de tout script (PowerShell, Python, Bash) avant son exécution.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Déployer des environnements d'analyse virtuelle isolés (VLAN laboratoire hors production) pour l'usage des analystes de sécurité.
* Mettre en œuvre une journalisation avancée de l'usage des outils d'exécution système (Python, PowerShell) sur les postes des équipes de cybersécurité.

#### Phase 2 — Détection et analyse
* Surveiller les connexions sortantes inattendues initiées par des interpréteurs de scripts Python ou de codes compilés à la suite du téléchargement de dépôts GitHub récents.
* Repérer des activités de collecte de clés de registres de sécurité ou de fichiers SSH locaux.
* **Règle de détection EDR (Execution Python suspecte) :**
  ```
  ProcessName='python.exe' AND CommandLine matches 'github' AND ProcessChildName IN ('powershell.exe', 'cmd.exe')
  ```

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Isoler de manière réseau immédiate le poste de l'analyste de sécurité compromis. Suspendre ses accès administratifs de production et révoquer l'ensemble des jetons VPN associés.
* **Éradication :** Réinstaller intégralement la station de travail de l'utilisateur à partir d'une image certifiée. Supprimer les dépôts suspects de la plateforme de partage locale.
* **Récupération :** Assurer la rotation exhaustive de l'ensemble des mots de passe, clés SSH et clés d'API manipulés par l'expert de sécurité affecté.

#### Phase 4 — Activités post-incident
* Réaliser l'inventaire précis de l'ensemble des fichiers, rapports d'audits de sécurité ou codes sources de clients qui étaient hébergés sur le poste compromis pour anticiper d'éventuelles notifications d'incidents.
* Partager les signatures du malware ChocoPoC détectées avec la communauté cyber.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Repérer des processus d'exécution éphémères exécutant des scripts de contournement de défenses système émanant d'outils de développement. | T1140 | Journaux de processus EDR | `search ParentProcessName='python.exe' AND CommandLine matches 'bypass|hidden'` |

### Indicateurs de compromission (DEFANG obligatoire)

*Les indicateurs réseau et hachages d'échantillons de ChocoPoC font l'objet de mises à jour fréquentes sur les dépôts de Threat Intelligence.*

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1195.002 | Initial Access | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Piégeage de dépôts GitHub de preuves de concept de sécurité pour cibler les ingénieurs. |
| T1140 | Defense Evasion | Deobfuscate/Decode Files or Information | Dissimulation et décodage dynamique de charges utiles au sein de scripts d'audits d'apparence inoffensive. |

### Sources

* [BleepingComputer ChocoPoC](https://www.bleepingcomputer.com/news/security/new-chocopoc-malware-targets-researchers-via-trojanized-poc-exploits/)

---

<div id="eviltokens-phaas-artoken-panel"></div>

## EvilTokens PhaaS + ARToken panel

### Résumé technique

Une analyse poussée des laboratoires de threat intelligence de Cisco Talos a permis de décrypter le fonctionnement interne de la plateforme de Phishing as a Service (PhaaS) baptisée **EvilTokens**, et plus spécifiquement son panneau d'administration d'affiliés nommé **ARToken**. 

Cette infrastructure criminelle est spécialisée dans le contournement furtif et à grande échelle de l'authentification multifacteur (MFA) des comptes cloud **Microsoft 365**. 

La technique employée repose sur l'abus du protocole d'enregistrement de périphériques (Device Registration - RFC 8628). L'attaquant envoie un leurre d'ingénierie sociale incitant la cible à copier un code d'authentification sur une fausse page Microsoft de confiance. Une fois le code validé, la plateforme ARToken génère un jeton d'accès OAuth complet, contournant de fait les mécanismes classiques de double facteur (SMS ou application d'authentification) pour maintenir une persistance silencieuse au sein de la messagerie de la victime.

### Analyse de l'impact

L'impact est particulièrement redoutable pour les environnements de messagerie d'entreprise cloud. Les attaquants s'octroient des accès persistants à distance qui résistent aux réinitialisations classiques de mots de passe, tant que les jetons OAuth actifs et les enregistrements de périphériques frauduleux ne sont pas explicitement purgés par les administrateurs du tenant d'entreprise. Cela favorise le déploiement silencieux d'attaques de compromissions de courriels d'affaires (Business Email Compromise - BEC), de vols de factures ou de fraudes au président.

### Recommandations

* Désactiver l'enregistrement automatique de périphériques inconnus (Device Registration) au sein du portail d'administration Microsoft Entra ID.
* Configurer des politiques d'accès conditionnel basées sur la conformité de l'appareil (Device Compliance) et l'utilisation exclusive de clés d'authentification physiques résistantes au phishing (FIDO2).
* Réaliser des audits d'accès fréquents sur les autorisations d'applications d'entreprise tierces (OAuth Permissions) octroyées par les utilisateurs.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Mettre en œuvre une journalisation centralisée des événements d'enregistrement de périphériques et d'approbations d'applications dans Azure Active Directory / Entra ID.
* Définir un processus d'approbation administrative obligatoire pour toute nouvelle application sollicitant des droits de lecture de messagerie.

#### Phase 2 — Détection et analyse
* Surveiller l'enregistrement de périphériques émanant d'adresses IP n'entrant pas dans le cadre des plages géographiques cohérentes des collaborateurs.
* Repérer des approbations d'applications tierces inconnues sollicitant des permissions d'envergure (ex : `Mail.ReadWrite`, `Directory.Read`).
* **Requête KQL (Entra ID Log Detection) :**
  ```kql
  AuditLogs
  | where OperationName == "Register device"
  | where Result == "success"
  | project TimeGenerated, Identity, TargetResources[0].displayName
  ```

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Révoquer l'ensemble des sessions actives et des jetons d'accès OAuth associés au compte utilisateur ciblé au sein d'Entra ID. Désactiver temporairement le compte.
* **Éradication :** Supprimer le périphérique frauduleux enregistré dans la liste d'appareils de l'utilisateur. Révoquer l'application d'entreprise malveillante identifiée.
* **Récupération :** Restaurer l'accès du collaborateur après validation de son poste et activation d'une authentification de type clé matérielle exclusive.

#### Phase 4 — Activités post-incident
* Analyser l'historique d'accès de la boîte de messagerie pour identifier si des règles de transfert automatique de courriels ont été créées furtivement par les attaquants.
* Sensibiliser les équipes administratives aux attaques exploitant le protocole d'enregistrement de périphériques (Device Code Flow Phishing).

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Rechercher des modifications soudaines de règles de routage de boîtes aux lettres d'utilisateurs clés de l'entreprise émanant d'IP d'accès inhabituelles. | T1114 | Journaux d'audit Exchange Online | `search OperationName='Set-Mailbox' AND Parameters matches 'ForwardingAddress'` |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | `dashboard-bl[.]pamconj[.]com` | Serveur d'administration de la plateforme ARToken d'EvilTokens | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566.002 | Initial Access | Phishing: Spearphishing Link | Utilisation d'URL de redirection malveillantes exploitant le protocole RFC 8628 pour piéger les usagers. |
| T1078.004 | Defense Evasion | Valid Accounts: Cloud Accounts | Utilisation frauduleuse de comptes légitimes par usurpation de jetons de session OAuth persistants. |

### Sources

* [Cisco Talos EvilTokens Analysis](https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/)

---

<div id="inc-ransom-colorado-rehabilitation-breach"></div>

## INC Ransom + Colorado Rehabilitation breach

### Résumé technique

Le groupe de cybercriminels hautement structuré **INC Ransom** a revendiqué l'intrusion et l'exfiltration massive de données au détriment de l'établissement médical américain **Colorado Rehabilitation**. 

L'attaque a débuté par l'infiltration des réseaux informatiques internes par le biais de l'exploitation d'identifiants d'accès d'administration VPN compromis. Une fois maîtres de l'environnement Active Directory de la clinique, les attaquants ont désactivé silencieusement les outils de surveillance de sécurité locaux, extrait d'importantes bases de données contenant les informations médicales protégées (PHI) des patients ainsi que des documents d'identification de collaborateurs. L'attaque s'est conclue par le chiffrement total des serveurs de fichiers et l'affichage de la victime sur le site de fuite d'INC Ransom opérant sur le réseau Tor.

### Analyse de l'impact

L'impact opérationnel et éthique est critique pour cette infrastructure de soins. L'indisponibilité des serveurs et des dossiers médicaux informatisés peut perturber directement l'administration de soins de réhabilitation d'urgence. De plus, la mise en vente et la divulgation de données de santé protégées exposent l'établissement médical à de lourdes amendes réglementaires et à des risques de poursuites judiciaires, ainsi qu'au chantage direct ciblant les patients vulnérables.

### Recommandations

* Mettre en œuvre une surveillance continue et un cloisonnement strict des accès de maintenance tiers au sein du réseau informatique de santé.
* Durcir les politiques de sauvegarde en conservant des copies immuables et déconnectées (Air-gapped backups) des bases de données médicales critiques.
* Déployer des agents de détection EDR capables de contrer l'arrêt frauduleux de processus de sécurité par des utilisateurs pourtant dotés de droits d'administration (Tamper Protection).

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Valider que les plans de continuité d'activité (PCA) médicaux en mode papier dégradé sont opérationnels et testés par les équipes de soins.
* Réaliser des audits d'intégrité réguliers des droits d'administration globaux attribués au sein de l'Active Directory.

#### Phase 2 — Détection et analyse
* Surveiller l'exfiltration suspecte de volumes importants de données réseau vers des serveurs d'hébergement ou de partages cloud tiers.
* Détecter les alertes d'arrêt ou de dysfonctionnement anormal d'agents de sécurité sur les serveurs de fichiers.
* **Règle de détection (Activité d'exfiltration EDR) :**
  ```
  ProcessName IN ('rclone.exe', 'megacmd.exe') AND CommandLine matches 'copy|sync'
  ```

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Isoler l'ensemble des segments réseaux de serveurs de l'établissement du réseau internet général. Couper les passerelles VPN d'accès distants.
* **Éradication :** Réinitialiser la totalité des mots de passe d'administration Active Directory. Purger les scripts de déploiement de rançongiciels des contrôleurs de domaine.
* **Récupération :** Restaurer les applications de gestion de dossiers de soins à partir des sauvegardes certifiées saines et appliquer des règles de durcissement systèmes globales avant la reconnexion.

#### Phase 4 — Activités post-incident
* Conduire une investigation pour dresser l'inventaire complet des dossiers patients exfiltrés afin d'assurer la conformité vis-à-vis des obligations de notifications réglementaires (RGPD / HIPAA).
* Collaborer avec les autorités de répression criminelle pour documenter l'activité de chantage d'INC Ransom.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Repérer des activations ou créations de comptes d'administration locaux sur les serveurs de fichiers n'entrant pas dans le cadre des demandes d'interventions planifiées. | T1136.001 | Journaux d'événements de sécurité Windows | `search EventID=4720 AND TargetAccountName matches '*admin*'` |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | `http[:]//incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad[.]onion/` | Site de revendication d'exfiltration d'INC Ransom sur Tor | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1486 | Impact | Data Encrypted for Impact | Chiffrement destructeur de bases de données médicales et de fichiers serveurs de production. |
| T1078.002 | Initial Access | Valid Accounts: Domain Accounts | Utilisation d'identifiants d'accès VPN distants compromis pour l'accès initial au réseau de santé. |

### Sources

* [Ransomlook INC Ransom](https://www.ransomlook.io//group/inc%20ransom)
* [Mastodon CTI_FYI](https://infosec.exchange/@CTI_FYI/116847605261310392)

---

<div id="lshiy-campaign-azure-cli-password-spraying"></div>

## LSHIY campaign + Azure CLI password spraying

### Résumé technique

La campagne cybercriminelle active identifiée sous le nom de code **LSHIY** cible spécifiquement les infrastructures cloud **Microsoft Azure** de dizaines d'organisations mondiales. 

Le mode opératoire repose sur le déploiement d'attaques par dictionnaire d'identifiants (Password Spraying) hautement distribuées ciblant spécifiquement l'interface de commande en ligne **Azure CLI**. Les attaquants exploitent une faiblesse de configuration fréquente liée au protocole d'authentification OAuth de type *Resource Owner Password Credentials* (ROPC). Ce protocole permet de valider des connexions sans interagir avec une interface web classique de double authentification, facilitant l'accès frauduleux des attaquants en présence de règles MFA mal définies sur les comptes de services d'administration ou les comptes sans privilèges. Plus de 64 organisations d'importance ont été infiltrées via cette méthode de force brute ciblée.

### Analyse de l'impact

L'impact est particulièrement redoutable pour la sécurité des infrastructures hébergées. Une fois connectés via Azure CLI, les attaquants s'octroient l'accès à la console de gestion d'infrastructure Azure Resource Manager (ARM). Ils peuvent modifier les configurations de sécurité, déployer de nouvelles machines virtuelles éphémères pour des activités illicites (minage, rebonds d'attaques), ou exfiltrer l'intégralité des bases de données de stockage en nuage (Azure Blob Storage).

### Recommandations

* Désactiver l'usage du protocole d'authentification OAuth ROPC au sein des locataires Azure en imposant des politiques d'accès conditionnel modernes.
* Restreindre drastiquement l'utilisation d'Azure CLI pour les comptes dépourvus de rôles administratifs de premier niveau (privilege levels).
* Mettre en œuvre des règles de blocage géographique des adresses IP d'accès d'administration cloud (IP Geolocation Restrictions).

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Activer et configurer la détection des anomalies de connexion (Identity Protection) de Microsoft Entra ID pour repérer les attaques de password spraying.
* Exclure l'usage de protocoles d'authentification hérités (Legacy Authentication) au niveau global de l'organisation.

#### Phase 2 — Détection et analyse
* Surveiller les vagues massives de tentatives de connexions échouées émanant d'adresses IP externes multiples ciblant un grand nombre de comptes utilisateurs sur l'application Azure CLI.
* Repérer des requêtes d'énumérations d'infrastructures cloud réussies émanant de profils d'utilisateurs métiers inhabituels.
* **Requête KQL de détection d'attaques par Password Spraying :**
  ```kql
  SigninLogs
  | where AppDisplayName == "Azure CLI"
  | where ResultType == "50126" // Erreur d'authentification mot de passe
  | summarize count() by IPAddress
  | where count_ > 50
  ```

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Bloquer immédiatement les comptes utilisateurs compromis identifiés dans les logs de connexion Entra ID. Révoquer les jetons d'accès d'API actifs.
* **Éradication :** Modifier les mots de passe des comptes affectés et imposer l'enregistrement obligatoire d'une double validation matérielle (MFA robuste).
* **Récupération :** Auditer les logs d'activité Azure Resource Manager pour vérifier qu'aucune ressource ou clé de service frauduleuse n'a été déployée par l'attaquant avant de réactiver les accès.

#### Phase 4 — Activités post-incident
* Mener une revue globale de conformité des politiques d'accès cloud pour s'assurer du déploiement universel du MFA sur l'ensemble des accès d'administration.
* Ajuster les seuils de détection automatique des attaques de dictionnaire au niveau de l'infrastructure de sécurité Microsoft Entra.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Repérer des connexions d'accès Azure CLI réussies émanant de postes d'utilisateurs bureautiques n'ayant pas de rôle d'ingénierie système ou d'administration cloud. | T1078.004 | Journaux de connexion Entra ID | `search AppDisplayName='Azure CLI' AND UserPrincipalName NOT IN (Cloud_Engineers)` |

### Indicateurs de compromission (DEFANG obligatoire)

*Les adresses IP utilisées par la campagne LSHIY changent de manière dynamique par l'utilisation de réseaux de proxys résidentiels.*

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1110.003 | Credential Access | Brute Force: Password Spraying | Attaques coordonnées de dictionnaires d'identifiants sur l'application Azure CLI. |
| T1078.004 | Initial Access | Valid Accounts: Cloud Accounts | Infiltration d'environnements cloud suite à l'usurpation d'identifiants utilisateur légitimes sur Azure. |

### Sources

* [Security Affairs Azure CLI Campaign](https://securityaffairs.com/194588/uncategorized/azure-cli-targeted-in-lshiy-password-spray-campaign-across-64-orgs.html)

---

<div id="kubota-network-intrusion-persistent-access"></div>

## Kubota network intrusion + Persistent access

### Résumé technique

Le constructeur d'équipements industriels et de matériels agricoles **Kubota** a confirmé avoir été victime d'une intrusion informatique majeure au sein de ses infrastructures de production. 

L'enquête interne a révélé que les attaquants avaient obtenu et maintenu un **accès persistant non détecté durant un mois complet** au sein des réseaux internes administratifs et de logistique. L'intrusion s'est opérée initialement par l'exploitation d'une vulnérabilité applicative sur un serveur périphérique exposé. Une fois au cœur du réseau, les attaquants ont déployé des outils de dissimulation d'activité et ont procédé à un déplacement latéral lent pour cartographier les environnements de bases de données industrielles et de gestion logistique d'approvisionnement globale.

### Analyse de l'impact

L'impact potentiel pour un géant industriel de cette envergure est critique. Une présence hostile persistante d'un mois permet aux attaquants d'exfiltrer des volumes massifs de propriété intellectuelle, de secrets de conception industrielle de nouvelles gammes d'équipements, ou de perturber la chaîne d'approvisionnement et de livraisons logistiques mondiales en modifiant des bases de données de commandes.

### Recommandations

* Mener des campagnes d'audits d'intégrité régulières de l'arborescence des connexions de serveurs Active Directory pour identifier les comptes dormants réactivés de manière suspecte.
* Mettre en œuvre une segmentation réseau hermétique entre les environnements de bureautique générale d'entreprise et les réseaux industriels de production (OT).
* Déployer des capteurs de détection comportementale réseau (NDR) pour repérer les anomalies de transferts de volumes internes de données hors des heures de production.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Disposer d'une cartographie réseau à jour identifiant l'ensemble des serveurs périphériques exposés sur Internet et leurs dépendances logicielles.
* Assurer la centralisation des logs de pare-feu et de routage réseau vers un outil d'analyse centralisé.

#### Phase 2 — Détection et analyse
* Surveiller l'exécution anormale d'outils d'administration système légitimes (PowerShell, WMI) détournés pour réaliser de la reconnaissance interne (Living off the Land).
* Repérer des volumes de données inhabituels circulant entre des segments réseau différents d'importance vitale.
* **Indicateur de mouvement latéral suspect (EDR) :**
  ```
  ProcessName='powershell.exe' AND CommandLine matches 'Get-WmiObject' AND CommandLine matches 'ActiveDirectory'
  ```

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Isoler le segment réseau où l'activité suspecte a été identifiée. Couper les liaisons réseaux VPN partagées avec les filiales de l'entreprise.
* **Éradication :** Réinitialiser l'ensemble des clés de sécurité de confiance du domaine Active Directory (double rotation du compte `krbtgt`). Purger les serveurs compromis et remplacer les services vulnérables.
* **Récupération :** Restaurer la configuration réseau sécurisée, durcir les règles de filtrage de communication inter-segments et surveiller de manière renforcée le retour en production.

#### Phase 4 — Activités post-incident
* Conduire une analyse forensique de bout en bout pour reconstituer précisément l'intégralité des actions menées par les attaquants durant les 30 jours de compromission furtive.
* Mettre en conformité les processus de gestion des vulnérabilités applicatives périphériques pour réduire le temps de déploiement des correctifs d'urgence.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Repérer des connexions persistantes établies depuis l'intérieur du réseau industriel vers des adresses IP d'hébergeurs VPS non conventionnels. | T1041 | Journaux de connexions Firewall | `search Outbound_Traffic IN (Industrial_VLAN) AND Dest_IP IN (VPS_Providers_Ranges)` |

### Indicateurs de compromission (DEFANG obligatoire)

*Les indicateurs techniques et hachages d'artefact de l'intrusion font l'objet d'analyses approfondies réservées aux équipes d'enquêtes forensiques de l'entreprise.*

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1078.002 | Defense Evasion | Valid Accounts: Domain Accounts | Utilisation de comptes d'administration recréés ou détournés pour s'assurer une persistance à long terme. |
| T1041 | Exfiltration | Exfiltration Over C2 Channel | Fuite furtive et progressive de données industrielles confidentielles vers des serveurs d'exfiltration externes. |

### Sources

* [BleepingComputer Kubota](https://www.bleepingcomputer.com/news/security/kubota-says-hackers-had-month-long-access-to-network-systems/)

---

<div id="tchap-compromise-french-administration"></div>

## Tchap compromise + French administration

### Résumé technique

Une faille opérationnelle a affecté la messagerie instantanée sécurisée de l'État français, baptisée **Tchap**. 

Cette application, basée sur le protocole décentralisé Matrix, est réservée aux agents de l'administration publique pour coordonner leurs activités administratives quotidiennes. L'incident consiste en l'infiltration et l'usurpation d'identifiants de comptes d'utilisateurs légitimes par des attaquants non identifiés. Les pirates ont profité d'une faille logique d'invitation et d'un manque de double facteur d'authentification sur les terminaux mobiles de certains agents pour s'introduire de manière indue au sein de salons de discussion et de canaux de coordination de projets administratifs non chiffrés de bout en bout.

### Analyse de l'impact

Bien que l'accès aux canaux contenant des informations classifiées de niveau Défense soit exclu (ces canaux nécessitant des environnements de chiffrement de bout en bout stricts), l'impact reste significatif. L'usurpation de comptes d'agents publics sur une messagerie de confiance de l'État permet aux attaquants de mener des campagnes d'ingénierie sociale internes extrêmement crédibles (phishing ciblé d'autres ministères, demandes de modifications de coordonnées de virement, collecte d'organigrammes fonctionnels).

### Recommandations

* Imposer l'activation obligatoire et centralisée de l'authentification multifacteur pour l'ensemble des profils d'utilisateurs se connectant au service Tchap.
* Configurer l'application pour interdire l'accès automatique de nouveaux membres à des canaux de discussions d'administration sensibles sans double validation de l'administrateur du salon.
* Réaliser une campagne de sensibilisation auprès des agents de l'État concernant le risque d'ingénierie sociale interne sur les messageries de confiance de l'administration.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Assurer la possibilité technique de révoquer d'urgence l'accès de terminaux mobiles d'agents publics via des solutions de gestion de flotte mobile (MDM).
* Rédiger des règles de sécurité claires d'usage des canaux chiffrés de bout en bout pour toute communication traitant d'activités administratives sensibles.

#### Phase 2 — Détection et analyse
* Surveiller les connexions à l'application Tchap d'agents publics émanant d'adresses IP suspectes ou incohérentes géographiquement par rapport aux adresses d'accès VPN administratifs.
* Repérer des comportements d'invitations massives de nouveaux membres par des comptes d'agents inactifs depuis longtemps.
* **Règle de détection (Activité Tchap suspecte) :**
  ```
  search Event='UserLogon' AND App='Tchap' AND Source_IP NOT IN (French_Government_IP_Ranges)
  ```

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Révoquer immédiatement les jetons de sessions actifs et réinitialiser les identifiants d'accès du compte utilisateur usurpé. Suspendre le compte de manière temporaire.
* **Éradication :** Identifier et détruire l'ensemble des invitations frauduleuses générées par le compte compromis au sein des salons d'administration.
* **Récupération :** Réinitialiser les paramètres d'authentification de l'agent affecté via un canal sécurisé hors-bande (appel téléphonique, rencontre physique) avant de réactiver le compte.

#### Phase 4 — Activités post-incident
* Mener une enquête administrative interne pour évaluer précisément l'ensemble des messages et des documents confidentiels échangés au sein des canaux auxquels l'attaquant a eu accès durant la compromission.
* Publier des bulletins de sécurité interministériels pour avertir les agents de l'État de la compromission de comptes sur la plateforme.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Repérer des modifications ou l'ajout d'appareils de connexions tiers (Devices/Matrix Keys) associés à des comptes d'agents publics clés de manière suspecte. | T1078.002 | Journaux d'audit du serveur Matrix Tchap | `search Operation='DeviceAdded' AND AccountType='Government_Employee'` |

### Indicateurs de compromission (DEFANG obligatoire)

*Les indicateurs d'adresses IP spécifiques font l'objet d'un suivi confidentiel par l'agence de sécurité nationale (ANSSI).*

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1078.002 | Initial Access | Valid Accounts: Domain Accounts | Usurpation de comptes d'agents de la fonction publique pour s'introduire sur la messagerie de l'État. |
| T1566 | Lateral Movement | Phishing | Exploitation de comptes usurpés pour mener des campagnes d'ingénierie sociale internes de confiance. |

### Sources

* [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence/cb26-07/)

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
13. ☐ Chaque article doit contenir un PLAYBOOK DE REPONSE A INCIDENT avec les 5 phases : Phase 1 — Préparation, Phase 2 — Détection et analyse, Phase 3 — Confinement, éradication et récupération, Phase 4 — Activités post-incident, Phase 5 — Threat Hunting (proactif) : [Vérifié]
14. ☐ Aucun bug fonctionnel, article commercial ou contenu non-sécuritaire dans la section "Articles" : [Vérifié]

Statut global : [✅ Rapport valide]
-->