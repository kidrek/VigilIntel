# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités](#synthese-des-vulnerabilites)
  * [Articles sélectionnés](#articles-selectionnes)
  * [Articles non sélectionnés](#articles-non-selectionnes)
* [Articles](#articles)
  * [IA et Malware : La maturité opérationnelle de l'agentique avec VoidLink](#ia-et-malware-la-maturite-operationnelle-de-lagentique-avec-voidlink)
  * [Ciblage stratégique : Le groupe Handala compromet le Directeur du FBI](#ciblage-strategique-le-groupe-handala-compromet-le-directeur-du-fbi)
  * [Vulnérabilités critiques en périphérie : F5 BIG-IP et Citrix NetScaler](#vulnerabilites-critiques-en-peripherie-f5-big-ip-et-citrix-netscaler)
  * [Exploitation iOS : Évolution des kits Coruna et DarkSword](#exploitation-ios-evolution-des-kits-coruna-et-darksword)
  * [Menaces sur la Supply Chain : Les campagnes agressives de TeamPCP](#menaces-sur-la-supply-chain-les-campagnes-agressives-de-teampcp)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage de la menace cyber en ce début d'année 2026 est marqué par une rupture technologique majeure : l'IA générative est passée du stade expérimental à une maturité opérationnelle fulgurante, comme l'illustre le framework VoidLink. Parallèlement, l'activisme d'État, notamment iranien avec le groupe Handala, démontre une capacité de nuisance symbolique forte en ciblant directement les communications personnelles des hauts responsables du renseignement américain. La périphérie des réseaux (Edge) reste une zone de faille critique, avec des vulnérabilités RCE massives sur F5 BIG-IP et Citrix NetScaler faisant l'objet de mandats de correction d'urgence par la CISA. Le risque sur la "Supply Chain" logicielle s'intensifie avec les attaques répétées de TeamPCP sur les dépôts PyPI, exploitant la confiance des développeurs dans les outils d'IA. Sur le front mobile, l'évolution de kits d'exploitation sophistiqués comme Coruna souligne la persistance des menaces ciblant iOS via le Web. Enfin, la confiance envers les infrastructures Cloud gouvernementales (Microsoft GCC High) est ébranlée par des révélations sur des processus de certification défaillants. Ces tendances exigent une réévaluation urgente de la posture de défense, intégrant l'automatisation de la réponse et une surveillance accrue des actifs exposés.
<br>
<br>
<div id="syntheses"></div>
<br/>

# Synthèses
<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants
Voici un tableau récapitulatif des acteurs malveillants identifiés :
| Nom de l'acteur | Secteur d'activité ciblé | Mode opératoire privilégié | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Handala (Hatef / Hamsa) | Gouvernement (USA), Médical (Stryker) | Hacktivisme, exfiltration de données, sabotage | [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-confirms-hack-of-director-patels-personal-email-inbox/) |
| Lapsus$ | Santé / Pharmacie | Vol de données à but d'extorsion | [Security Affairs](https://securityaffairs.com/190104/uncategorized/security-affairs-newsletter-round-569-by-pierluigi-paganini-international-edition.html) |
| Red Menshen | Télécommunications | Implants furtifs BPFdoor | [Security Affairs](https://securityaffairs.com/190104/uncategorized/security-affairs-newsletter-round-569-by-pierluigi-paganini-international-edition.html) |
| ShinyHunters | Institutions Publiques | Compromission de Cloud / Exfiltration | [Security Affairs](https://securityaffairs.com/190104/uncategorized/security-affairs-newsletter-round-569-by-pierluigi-paganini-international-edition.html) |
| TeamPCP | Supply Chain (Développeurs) | Empoisonnement de paquets PyPI / GitHub | [Help Net Security](https://www.helpnetsecurity.com/2026/03/29/week-in-review-nist-updates-dns-security-guidance-compromised-litellm-pypi-packages/) |
<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Gouvernement | Espionnage Chine-Belgique | Utilisation de faux profils LinkedIn pour espionner l'OTAN et l'UE. | [Security Affairs](https://securityaffairs.com/190104/uncategorized/security-affairs-newsletter-round-569-by-pierluigi-paganini-international-edition.html) |
| Gouvernement | Relations Iran-USA | Piratage du compte Gmail personnel du directeur du FBI par un groupe lié au MOIS iranien. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-confirms-hack-of-director-patels-personal-email-inbox/) |
| Renseignement | Russie vs USA | Ciblage des comptes Signal et WhatsApp par le renseignement russe. | [Help Net Security](https://www.helpnetsecurity.com/2026/03/29/week-in-review-nist-updates-dns-security-guidance-compromised-litellm-pypi-packages/) |
| Sécurité Nationale | Commerce International | Bannissement par la FCC des routeurs étrangers pour des raisons de sécurité nationale. | [Security Affairs](https://securityaffairs.com/190104/uncategorized/security-affairs-newsletter-round-569-by-pierluigi-paganini-international-edition.html) |
| Surveillance | Vie Privée | Débat aux USA sur l'achat de données de masse par les agences fédérales (ICE) auprès de courtiers. | [NPR via Mastodon](https://www.npr.org/2026/03/25/nx-s1-5752369/ice-surveillance-data-brokers-congress-anthropic) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| CareCloud notifies the SEC | CareCloud | 29/03/2026 | USA | SEC Filing | Notification obligatoire suite à une intrusion dans un environnement de dossiers médicaux électroniques. | [DataBreaches](https://databreaches.net/2026/03/29/carecloud-notifies-the-sec-after-attack-on-one-of-its-ehr-environments/) |
| FCC Updates Covered List | FCC | 29/03/2026 | USA | FCC Covered List | Interdiction d'importation et de vente de nouveaux routeurs fabriqués à l'étranger pour risque de sécurité. | [Security Affairs](https://securityaffairs.com/190104/uncategorized/security-affairs-newsletter-round-569-by-pierluigi-paganini-international-edition.html) |
| NIST updates DNS security guidance | NIST | 29/03/2026 | USA | SP 800-81r3 | Mise à jour des directives sur le déploiement sécurisé du DNS pour la première fois en 12 ans. | [Help Net Security](https://www.helpnetsecurity.com/2026/03/29/week-in-review-nist-updates-dns-security-guidance-compromised-litellm-pypi-packages/) |
<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Gouvernement | Commission Européenne | Revendication de piratage par le groupe ShinyHunters. | [Security Affairs](https://securityaffairs.com/190104/uncategorized/security-affairs-newsletter-round-569-by-pierluigi-paganini-international-edition.html) |
| Gouvernement | Kash Patel (Directeur FBI) | Compromission d'un compte Gmail personnel ; fuite de photos et documents historiques. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-confirms-hack-of-director-patels-personal-email-inbox/) |
| Gouvernement | Ministère des Finances (Pays-Bas) | Violation de données affectant le personnel suite à une cyberattaque. | [Security Affairs](https://securityaffairs.com/190104/uncategorized/security-affairs-newsletter-round-569-by-pierluigi-paganini-international-edition.html) |
| Santé | CareCloud | Accès non autorisé à l'un des six environnements de dossiers médicaux électroniques (EHR). | [DataBreaches](https://databreaches.net/2026/03/29/carecloud-notifies-the-sec-after-attack-on-one-of-its-ehr-environments/) |
| Sport | AFC Ajax | Accès non autorisé aux adresses email de supporters via des vulnérabilités d'API. | [Help Net Security](https://www.helpnetsecurity.com/2026/03/29/week-in-review-nist-updates-dns-security-guidance-compromised-litellm-pypi-packages/) |
<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité.
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2025-53521 | 9.8 | N/A | TRUE | F5 BIG-IP APM | Exécution de code à distance (RCE) | T1190: Exploit Public-Facing Application | Faille critique permettant de contourner les limites de sécurité et d'exécuter du code via du trafic malveillant. | [SecurityOnline](https://securityonline.info/f5-big-ip-rce-vulnerability-cve-2025-53521-cisa-kev/) |
| CVE-2026-3055 | 9.3 | N/A | FALSE | Citrix NetScaler ADC/Gateway | Memory Overread (Out-of-bounds Read) | T1005: Data from Local System | Fuite potentielle de données sensibles en mémoire, notamment des jetons de session SAML. | [Security Affairs](https://securityaffairs.com/190131/hacking/urgent-alert-netscaler-bug-cve-2026-3055-probed-by-attackers-could-leak-sensitive-data.html) |
| CVE-2026-27876 | 9.1 | N/A | FALSE | Grafana (sqlExpressions) | Exécution de code à distance (RCE) | T1210: Exploitation of Remote Services | Chaînage d'écriture de fichiers via des expressions SQL pour obtenir un accès SSH. | [SecurityOnline](https://securityonline.info/grafana-critical-rce-vulnerability-cve-2026-27876-sql-expressions/) |
| CVE-2026-5046 | 9.0 | N/A | FALSE | Tenda FH1201 | Buffer Overflow | T1210: Exploitation of Remote Services | Débordement de tampon dans la fonction formWrlExtraSet permettant une attaque à distance. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-5046) |
| CVE-2026-4946 | 8.8 | N/A | FALSE | NSA Ghidra | Exécution de code à distance (RCE) | T1203: Exploitation for Client Execution | Traitement incorrect des directives d'annotation (@execute) lors de l'auto-analyse de binaires. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-4946) |
| CVE-2026-2370 | 8.1 | N/A | FALSE | GitLab CE/EE | Broken Access Control | T1078: Valid Accounts | Obtention d'identifiants d'installation Jira Connect par des utilisateurs avec des privilèges minimaux. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-2370) |
<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| AI Threat Landscape Digest January-February 2026 | Analyse approfondie du framework VoidLink et de l'usage opérationnel de l'IA par les attaquants. | [Check Point Research](https://research.checkpoint.com/2026/ai-threat-landscape-digest-january-february-2026/) |
| Apple issues urgent lock screen warnings for unpatched iPhones | Détails sur les kits d'exploitation Coruna et DarkSword ciblant activement iOS. | [Security Affairs](https://securityaffairs.com/190109/security/apple-issues-urgent-lock-screen-warnings-for-unpatched-iphones-and-ipads.html) |
| CISA Issues Three-Days Patch Mandate for Critical 9.8 F5 BIG-IP RCE | Alerte sur une vulnérabilité critique activement exploitée sur des équipements de bord. | [SecurityOnline](https://securityonline.info/f5-big-ip-rce-vulnerability-cve-2025-53521-cisa-kev/) |
| FBI confirms hack of Director Patel's personal email inbox | Cas concret de ciblage de VIP et de hacktivisme d'État iranien. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-confirms-hack-of-director-patels-personal-email-inbox/) |
| Week in review: NIST updates DNS guidance, compromised LiteLLM packages | Synthèse des attaques de Supply Chain par TeamPCP et évolutions normatives. | [Help Net Security](https://www.helpnetsecurity.com/2026/03/29/week-in-review-nist-updates-dns-security-guidance-compromised-litellm-pypi-packages/) |
<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| At a #CyberSecurity forum recently... | Message social sans contenu technique suffisant. | [Mastodon](https://mstdn.ca/@mamba/116315174309783513) |
| DEF CON 34 Call for Music | Information organisationnelle non liée à une menace. | [Mastodon](https://defcon.social/@Defcon_Music/116315073618945324) |
| That should get you PQC resistance... | Discussion technique sur une configuration spécifique (PQC) sans actualité de menace directe. | [Mastodon](https://mastodon.social/@JulianOliver/116315154967077163) |
| This is quite the read... White House app | Lien social vers un blog sans résumé intégré. | [Mastodon](https://fosstodon.org/@shawnhooper/116315310093780888) |
<br>
<br/>
<div id="articles"></div>

# ARTICLES

<div id="ia-et-malware-la-maturite-operationnelle-de-lagentique-avec-voidlink"></div>

## IA et Malware : La maturité opérationnelle de l'agentique avec VoidLink
L'année 2026 marque l'avènement des malwares développés par des agents IA autonomes. Le framework VoidLink, comprenant des rootkits Linux sophistiqués (eBPF/LKM), a été produit en seulement une semaine par un développeur unique utilisant l'IDE TRAE SOLO de ByteDance. Cette performance, qui aurait nécessité 30 semaines à une équipe humaine, repose sur le "Spec Driven Development" (SDD) où l'IA implémente des sprints complets à partir de spécifications Markdown. L'étude montre que les attaquants privilégient désormais les modèles commerciaux (Claude, GPT-4) via des techniques de contournement architectural (abus des fichiers CLAUDE.md) plutôt que de simples "prompts" de jailbreak. Les modèles auto-hébergés restent coûteux et moins performants pour la génération de code compilable. Par ailleurs, 90 % des entreprises utilisant l'IA générative subissent des fuites de données sensibles via les requêtes des employés. Le framework RAPTOR illustre également comment transformer un agent de code en opérateur offensif autonome. L'IA n'est plus un outil expérimental mais un composant temps réel des pipelines d'attaque.

**Analyse de l'impact** : L'impact est systémique : la barrière à l'entrée pour créer des cyber-menaces de niveau étatique s'effondre. La rapidité de développement et la qualité professionnelle du code généré par l'IA rendent la détection traditionnelle obsolète, car l'origine "IA" du code est invisible sans preuve opérationnelle (OPSEC).

**Recommandations** :
*   Intégrer l'hypothèse d'un développement assisté par IA dans toutes les analyses de nouveaux malwares.
*   Surveiller l'utilisation des IDE IA (Cursor, TRAE, Copilot) au sein de l'entreprise pour prévenir les fuites de code source.
*   Mettre en œuvre des contrôles de Data Loss Prevention (DLP) spécifiques aux flux vers les LLM commerciaux.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non mentionné (Développeur individuel identifié via faille OPSEC) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1588.006: Obtain Capabilities: AI Services<br/>• T1014: Rootkit<br/>• T1548.001: Abuse Elevation Control Mechanism |
| Observables & Indicateurs de compromission | • Framework: VoidLink (Linux)<br/>• Composants: eBPF rootkit, LKM modules<br/>• IDE utilisé: TRAE SOLO |

### Source (url) du ou des articles
* [Check Point Research](https://research.checkpoint.com/2026/ai-threat-landscape-digest-january-february-2026/)
<br>
<br>

<div id="ciblage-strategique-le-groupe-handala-compromet-le-directeur-du-fbi"></div>

## Ciblage stratégique : Le groupe Handala compromet le Directeur du FBI
Le groupe de piratage Handala, affilié au ministère du Renseignement iranien (MOIS), a revendiqué la compromission du compte Gmail personnel de Kash Patel, directeur du FBI. Les attaquants ont publié des photos personnelles, des documents et des correspondances historiques pour prouver leur intrusion. Le FBI a confirmé l'incident, précisant qu'aucune donnée gouvernementale ou classifiée récente n'a été compromise. Handala affirme avoir agi en représailles aux saisies de domaines par le FBI et à la prime de 10 millions de dollars offerte par le gouvernement américain pour leur identification. Bien que les systèmes internes du FBI n'aient pas été touchés, l'action sert d'outil de propagande puissant. Le groupe a précédemment mené des attaques destructrices contre l'entreprise médicale Stryker, détruisant près de 80 000 appareils. Cette attaque souligne la vulnérabilité des communications privées des hauts responsables face à des acteurs étatiques persistants.

**Analyse de l'impact** : L'impact est principalement psychologique et réputationnel. Il démontre que même les responsables de la cybersécurité nationale sont vulnérables via leur vie privée, créant un risque de chantage ou d'influence géopolitique.

**Recommandations** :
*   Appliquer des politiques d'hygiène numérique strictes pour les VIP/Exécutifs (isolation totale des comptes personnels et professionnels).
*   Généraliser l'usage de clés de sécurité matérielles (type FIDO2) pour tous les comptes personnels des employés sensibles.
*   Réaliser des audits de l'empreinte numérique (OSINT) pour les décideurs afin de réduire la surface d'attaque.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Handala (Hatef / Hamsa) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1589: Gather Victim Identity Information<br/>• T1566: Phishing (suspecté pour accès Gmail)<br/>• T1567: Exfiltration Over Web Service |
| Observables & Indicateurs de compromission | Aucun IoC technique fourni dans l'article (compromission de service tiers). |

### Source (url) du ou des articles
* [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-confirms-hack-of-director-patels-personal-email-inbox/)
<br>
<br>

<div id="vulnerabilites-critiques-en-peripherie-f5-big-ip-et-citrix-netscaler"></div>

## Vulnérabilités critiques en périphérie : F5 BIG-IP et Citrix NetScaler
Deux équipements critiques d'infrastructure réseau font l'objet d'alertes majeures. La CISA a ajouté CVE-2025-53521 (score 9.8) à son catalogue des vulnérabilités exploitées, imposant un correctif sous 3 jours pour les agences fédérales. Cette faille RCE dans F5 BIG-IP APM permet à un attaquant non authentifié d'intercepter du trafic chiffré et de se déplacer latéralement dans le réseau. Parallèlement, Citrix NetScaler fait face à CVE-2026-3055 (score 9.3), une erreur de lecture mémoire hors limites. Cette vulnérabilité est activement ciblée par des campagnes de reconnaissance via des requêtes POST sur l'endpoint `/cgi/GetAuthMethods`. Elle affecte spécifiquement les instances configurées comme fournisseurs d'identité SAML (IdP). Les chercheurs comparent cette faille à "CitrixBleed" pour sa capacité à exfiltrer des jetons de session en mémoire. L'exploitation massive semble imminente selon les réseaux de pots de miel (honeypots).

**Analyse de l'impact** : L'impact est critique car ces dispositifs se situent à la frontière du réseau. Une compromission réussie permet de contourner les pare-feux traditionnels et d'accéder directement au cœur des systèmes d'information d'entreprise et gouvernementaux.

**Recommandations** :
*   Patch immédiat des systèmes F5 BIG-IP vers les versions supportées.
*   Vérifier si NetScaler est configuré en tant que SAML IdP via la commande `add authentication samlIdPProfile`.
*   Surveiller les logs HTTP pour des requêtes anormales vers `/cgi/GetAuthMethods`.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Acteurs non identifiés (ciblage de masse observé) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1190: Exploit Public-Facing Application<br/>• T1005: Data from Local System |
| Observables & Indicateurs de compromission | • CVE-2025-53521 (F5)<br/>• CVE-2026-3055 (Citrix)<br/>• Endpoint cible: /cgi/GetAuthMethods |

### Source (url) du ou des articles
* [SecurityOnline - F5](https://securityonline.info/f5-big-ip-rce-vulnerability-cve-2025-53521-cisa-kev/)
* [Security Affairs - NetScaler](https://securityaffairs.com/190131/hacking/urgent-alert-netscaler-bug-cve-2026-3055-probed-by-attackers-could-leak-sensitive-data.html)
<br>
<br>

<div id="exploitation-ios-evolution-des-kits-coruna-et-darksword"></div>

## Exploitation iOS : Évolution des kits Coruna et DarkSword
Apple a émis des avertissements urgents via l'écran de verrouillage pour les utilisateurs d'iPhones et iPads non patchés. Des kits d'exploitation web sophistiqués, nommés "Coruna" et "DarkSword", ciblent activement les versions d'iOS allant de la 13 à la 17.2.1. Coruna semble être une évolution directe du framework utilisé lors de la campagne "Operation Triangulation" de 2023, partageant des similarités de code frappantes dans ses exploits de noyau (kernel). DarkSword, plus récent, vise les versions iOS 18.4 à 18.7. Ces attaques sont déclenchées par simple consultation d'un site web compromis ou clic sur un lien malveillant, permettant le vol de données sensibles. Bien que le mode "Isolement" (Lockdown Mode) bloque ces attaques, Apple insiste sur la mise à jour immédiate vers iOS 15/16 minimum pour les anciens appareils. La persistance de ces frameworks suggère un investissement continu d'acteurs de cyber-espionnage dans l'exploitation mobile.

**Analyse de l'impact** : Impact élevé pour la confidentialité des données mobiles. La capacité de ces kits à infecter des appareils sans interaction complexe (zero-click ou simple clic) facilite l'espionnage à grande échelle de cibles d'intérêt.

**Recommandations** :
*   Forcer la mise à jour immédiate de tous les terminaux iOS vers la version la plus récente disponible.
*   Activer le "Lockdown Mode" pour les utilisateurs à haut risque (journalistes, officiels, exécutifs).
*   Éduquer les utilisateurs sur les risques liés aux liens suspects, même sur des messageries chiffrées.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Lié potentiellement aux auteurs d'Operation Triangulation |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1203: Exploitation for Client Execution<br/>• T1068: Exploitation for Privilege Escalation |
| Observables & Indicateurs de compromission | • Frameworks: Coruna, DarkSword<br/>• Vecteur: Web content malveillant |

### Source (url) du ou des articles
* [Security Affairs](https://securityaffairs.com/190109/security/apple-issues-urgent-lock-screen-warnings-for-unpatched-iphones-and-ipads.html)
<br>
<br>

<div id="menaces-sur-la-supply-chain-les-campagnes-agressives-de-teampcp"></div>

## Menaces sur la Supply Chain : Les campagnes agressives de TeamPCP
Le groupe cybercriminel TeamPCP intensifie ses attaques contre les dépôts de logiciels open source. Après avoir compromis des dépôts de GitHub et Aqua Security (Trivy), le groupe a ciblé la bibliothèque populaire LiteLLM sur PyPI. Les versions compromises (1.82.7 et 1.82.8), téléchargées des millions de fois, incluaient un voleur d'identifiants et un dropper de malware. TeamPCP a également empoisonné le paquet Telnyx pour diffuser des logiciels malveillants. Les attaquants exploitent la rapidité d'adoption des outils d'IA pour glisser du code malveillant dans des dépendances couramment utilisées par les développeurs. La CISA a intégré la vulnérabilité liée à Trivy (CVE-2026-33634) à son catalogue de menaces actives. Ces incidents montrent une transition des attaques directes vers une compromission de l'infrastructure de développement elle-même.

**Analyse de l'impact** : L'impact est majeur pour l'intégrité des pipelines CI/CD. Une seule bibliothèque compromise peut infecter des milliers d'applications finales, offrant aux attaquants un accès privilégié aux environnements de production des entreprises.

**Recommandations** :
*   Utiliser des outils de scan de dépendances (SCA) en temps réel dans les pipelines de build.
*   Épingler les versions des bibliothèques (pinning) et utiliser des sommes de contrôle (hashes) pour vérifier l'intégrité des paquets.
*   Mettre en place des registres privés de paquets (mirroring) pour contrôler les mises à jour avant leur déploiement.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TeamPCP |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | • T1195.002: Supply Chain Compromise: Compromise Software Dependencies<br/>• T1552.001: Unsecured Credentials: Credentials in Files |
| Observables & Indicateurs de compromission | • Paquets PyPI: litellm (1.82.7, 1.82.8), telnyx<br/>• Vulnérabilité: CVE-2026-33634 |

### Source (url) du ou des articles
* [Help Net Security](https://www.helpnetsecurity.com/2026/03/29/week-in-review-nist-updates-dns-security-guidance-compromised-litellm-pypi-packages/)