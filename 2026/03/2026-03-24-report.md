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
  * [attaque de la chaîne d'approvisionnement d'aqua security par teampcp](#attaque-de-la-chaine-dapprovisionnement-daqua-security-par-teampcp)
  * [compromission de crunchyroll via un prestataire bpo](#compromission-de-crunchyroll-via-un-prestataire-bpo)
  * [m-trends 2026 : le panorama des menaces de mandiant](#m-trends-2026-le-panorama-des-menaces-de-mandiant)
  * [suivi des cyberattaques liées au conflit us-israel-iran](#suivi-des-cyberattaques-liées-au-conflit-us-israel-iran)
  * [le retour de la plateforme tycoon2fa après son démantèlement](#le-retour-de-la-plateforme-tycoon2fa-après-son-démantèlement)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage cyber de ce premier trimestre 2026 est marqué par une hybridation croissante entre conflits cinétiques et opérations numériques de haute intensité, particulièrement dans le triangle US-Israël-Iran. Les acteurs étatiques comme Handala Hack et TeamPCP industrialisent le sabotage via des outils de gestion cloud (Microsoft Intune) et des malwares destructeurs de type wiper. Parallèlement, la menace sur la chaîne d'approvisionnement atteint un point critique, illustrée par la compromission répétée d'Aqua Security et l'exploitation de prestataires de services (BPO) pour atteindre des millions d'utilisateurs. Mandiant souligne une accélération spectaculaire des phases d'attaque : le délai moyen de passage entre l'accès initial et l'action malveillante est tombé à seulement 22 secondes. L'identité numérique devient le pivot central des défenses, tandis que les attaquants ciblent désormais les infrastructures de sauvegarde pour empêcher toute restauration. L'émergence de plateformes de "Phishing-as-a-Service" résilientes comme Tycoon2FA démontre l'inefficacité relative des démantèlements d'infrastructure sans arrestations physiques. Enfin, l'intégration de l'IA générative dans les processus de détection et de réponse devient une nécessité opérationnelle pour faire face à l'automatisation des offensives.

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
| Handala Hack (Void Manticore) | Multinationales US, Infrastructures israéliennes | Sabotage via Microsoft Intune, exfiltration de données, wipers | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Nasir Security | Secteur de l'énergie (Golfe) | BEC, Spear phishing, exploitation d'applications publiques | [Security Affairs](https://securityaffairs.com/189865/cyber-warfare-2/pro-iranian-nasir-security-is-targeting-energy-companies-in-the-gulf.html) |
| TeamPCP (CanisterWorm) | Cloud, Kubernetes, Chaîne d'approvisionnement | Wipers ciblés géographiquement, empoisonnement de tags GitHub/Docker | [KrebsOnSecurity](https://krebsonsecurity.com/2026/03/canisterworm-springs-wiper-attack-targeting-iran/) |
| Tycoon2FA (Opérateurs) | Comptes Microsoft 365 & Gmail | Phishing-as-a-Service (PhaaS), contournement MFA via AiTM | [BleepingComputer](https://www.bleepingcomputer.com/news/security/tycoon2fa-phishing-platform-returns-after-recent-police-disruption/) |
| UNC3944 | Services IT, SaaS, Hyperviseurs | Vishing (social engineering vocal), vol de cookies de session et jetons OAuth | [Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Civil / Infrastructure | Conflit Moyen-Orient | Frappes de missiles iraniens sur Dimona et Arad en réponse à l'attaque de Natanz. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Civil / Population | Black-out Internet | L'Iran subit un blocage d'Internet d'État depuis plus de 528 heures consécutives. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| États / Multilatéral | Guerre des systèmes | Analyse de la résilience énergétique suite au black-out ibérique de 2025 et ses leçons pour l'Europe. | [Portail IE](https://www.portail-ie.fr/univers/enjeux-de-puissances-et-geoeconomie/2026/impact-du-black-out-iberique-sur-la-resilience-energetique/) |
| Gouvernemental | Loi de Sécurité Nationale | Hong Kong autorise la police à exiger les mots de passe des téléphones et ordinateurs. | [The Guardian](https://www.theguardian.com/world/2026/mar/24/hong-kong-phone-passwords-national-security-law) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Amendments to the National Security Law | Gouvernement de Hong Kong | 24/03/2026 | Hong Kong | National Security Law | Pouvoir de réquisition des mots de passe et méthodes de déchiffrement par la police. | [The Guardian](https://www.theguardian.com/world/2026/mar/24/hong-kong-phone-passwords-national-security-law) |
| NIST Cyber AI Profile (Reflections) | Katerina Megas et al. | 23/03/2026 | États-Unis | NIST CSF 2.0 / AI RMF | Directives pour la gestion des risques liés à l'IA et taxonomie commune de l'IA. | [NIST](https://www.nist.gov/blogs/cybersecurity-insights/reflections-second-nist-cyber-ai-profile-workshop) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Divertissement | Crunchyroll | Vol présumé des données de 6,8 millions d'utilisateurs (tickets de support Zendesk). | [BleepingComputer](https://www.bleepingcomputer.com/news/security/crunchyroll-probes-breach-after-hacker-claims-to-steal-68m-users-data/) |
| Éducation | Éducation Nationale (France) | Compromission des données de 243 000 agents via le logiciel RH "Compas". | [Le Monde](https://www.lemonde.fr/education/article/2026/03/24/le-piratage-d-un-logiciel-compromet-les-donnees-de-243-000-agents-de-l-education-nationale_6673988_1473685.html) |
| Santé / RH | Navia Benefit Solutions | Violation affectant 2,6 millions d'individus (données de santé et prestations). | [Check Point](https://research.checkpoint.com/2026/23rd-march-threat-intelligence-report/) |
| Services Médicaux | Telehealth (OpenLoop & Woundtech) | 3,7 millions de patients affectés par des vols de données et tentatives d'extorsion. | [DataBreaches.net](https://databreaches.net/2026/03/23/3-7-million-telehealth-patients-allegedly-affected-by-two-recent-breaches/) |
| Transport / Auto | Mazda Motor Corp | Exposition de 692 enregistrements concernant des employés et partenaires. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/mazda-discloses-security-breach-exposing-employee-and-partner-data/) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).
| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|
| CVE-2026-21992 | 9.8 | Oracle Identity Manager | Exécution de code à distance (RCE) | [Oracle](https://www.cisecurity.org/advisory/a-vulnerability-in-oracle-products-could-allow-for-remote-code-execution_2026-024) |
| CVE-2026-4001 | 9.8 | WooCommerce Custom Product Addons Pro | Remote Code Execution (RCE) | [Wordfence](https://cvefeed.io/vuln/detail/CVE-2026-4001) |
| CVE-2026-32746 | 9.8 | GNU InetUtils telnetd | Buffer Overflow / RCE | [Check Point](https://research.checkpoint.com/2026/23rd-march-threat-intelligence-report/) |
| CVE-2026-33211 | 9.6 | Tekton Pipelines | Path Traversal / Vol de jetons | [GitHub Security](https://cvefeed.io/vuln/detail/CVE-2026-33211) |
| CVE-2026-3055 | 9.3 | Citrix NetScaler ADC / Gateway | Out-of-bounds Read (Memory Overread) | [Citrix](https://cert.europa.eu/publications/security-advisories/2026-003/) |
| CVE-2026-33286 | 9.1 | Graphiti | Arbitrary Method Execution | [GitHub Security](https://cvefeed.io/vuln/detail/CVE-2026-33286) |
| CVE-2025-14233 | 8.8 | Canon imageCLASS (Imprimantes) | Memory Corruption / RCE | [ZDI](http://www.zerodayinitiative.com/advisories/ZDI-26-222/) |
| CVE-2026-3533 | 8.8 | JupiterX Core (WordPress) | Unrestricted File Upload | [Wordfence](https://cvefeed.io/vuln/detail/CVE-2026-3533) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| 44 Aqua Security repositories defaced after Trivy supply chain breach | Escalade majeure d'une attaque supply chain contre un éditeur de sécurité. | [Security Affairs](https://securityaffairs.com/189856/uncategorized/44-aqua-security-repositories-defaced-after-trivy-supply-chain-breach.html) |
| Crunchyroll probes breach after hacker claims to steal 6.8M users' data | Illustration parfaite de la menace via les prestataires BPO et le vol de session Okta. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/crunchyroll-probes-breach-after-hacker-claims-to-steal-68m-users-data/) |
| M-Trends 2026: Data, Insights, and Strategies From the Frontlines | Rapport de référence sur les tendances TTP et la réduction critique des fenêtres d'attaque. | [Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/) |
| Monitoring Cyberattacks Directly Linked to the US-Israel-Iran Military Conflict | Synthèse exhaustive du cyber-sabotage étatique en temps de guerre cinétique. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Tycoon2FA phishing platform returns after recent police disruption | Analyse de la résilience des plateformes PhaaS face aux démantèlements policiers. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/tycoon2fa-phishing-platform-returns-after-recent-police-disruption/) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| OpenAI rolls out ChatGPT Library | Simple annonce de fonctionnalité produit sans impact sécurité direct. | [BleepingComputer](https://www.bleepingcomputer.com/news/artificial-intelligence/openai-rolls-out-chatgpt-library-to-store-your-personal-files/) |
| Snowflake's ongoing pitch: bring AI to data | Article promotionnel / marketing sur la stratégie d'IA de Snowflake. | [The Register](https://www.theregister.com/2026/03/23/snowflake_ai_data_project_snowwork/) |
| ISC Stormcast For Tuesday, March 24th | Podcast quotidien sans contenu détaillé dans le texte analysé. | [SANS ISC](https://isc.sans.edu/diary/rss/32822) |
| RuneScape Boards breach | Information sur une fuite de données datant de 2011, peu pertinente pour la veille actuelle. | [HIBP](https://haveibeenpwned.com/Breach/RSBoards) |

<br>
<br/>
<div id="articles"></div>

# ARTICLES
<div id="attaque-de-la-chaine-dapprovisionnement-daqua-security-par-teampcp"></div>

## 44 Aqua Security repositories defaced after Trivy supply chain breach
L'organisation GitHub interne d'Aqua Security (aquasec-com) a été victime d'un sabotage massif orchestré par l'acteur TeamPCP. En seulement deux minutes, 44 dépôts ont été renommés avec le préfixe "tpcp-docs-" et leurs descriptions ont été modifiées par un script automatisé. L'attaque semble découler d'une compromission précédente du pipeline CI/CD de l'outil Trivy. L'attaquant a utilisé un jeton de compte de service (PAT) volé pour obtenir des privilèges d'administrateur. Cette intrusion a exposé du code propriétaire, des configurations d'infrastructure et des bases de connaissances internes. TeamPCP a testé la validité du jeton sept heures avant l'attaque finale en créant brièvement une branche fantôme. Cet incident souligne la persistance des menaces après un nettoyage incomplet de secrets compromis. Il met en lumière la vulnérabilité des jetons d'accès personnels (PAT) par rapport aux applications GitHub plus sécurisées.

**Analyse de l'impact** : Impact critique sur la réputation et la propriété intellectuelle d'un leader de la sécurité cloud. Risque de compromission en cascade pour les clients utilisant des outils d'Aqua si des secrets ont été exfiltrés du code source.

**Recommandations** :
* Révoquer immédiatement tous les jetons PAT des comptes de service et passer à des GitHub Apps avec des jetons à courte durée de vie.
* Imposer l'authentification multi-facteurs (MFA) pour tous les comptes ayant accès aux dépôts, y compris les bots.
* Mener une rotation complète des secrets (clés AWS, jetons API) présents ou référencés dans les dépôts compromis.
* Mettre en œuvre une surveillance stricte des API GitHub pour détecter les changements massifs de métadonnées en un court laps de temps.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TeamPCP (alias CanisterWorm, DeadCatx3) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Supply Chain Compromise (Software Dependencies) <br/> * T1078.004: Valid Accounts (Cloud Accounts) <br/> * T1565.001: Data Manipulation (Stored Data Manipulation) |
| Observables & Indicateurs de compromission | ```* aquasecurtiy[.]org <br/> * tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io <br/> * /tmp/pglog <br/> * Jeton de compte Argon-DevOps-Mgt (ID 139343333)``` |

### Source (url) du ou des articles
* https://securityaffairs.com/189856/uncategorized/44-aqua-security-repositories-defaced-after-trivy-supply-chain-breach.html
* https://opensourcemalware.com/blog/teampcp-aquasec-com-github-org-compromise
* https://www.bleepingcomputer.com/news/security/trivy-supply-chain-attack-spreads-to-docker-github-repos/

<br>
<br>
<div id="compromission-de-crunchyroll-via-un-prestataire-bpo"></div>

## Crunchyroll probes breach after hacker claims to steal 6.8M users' data
Le service de streaming Crunchyroll fait l'objet d'une enquête suite à une violation de données affectant potentiellement 6,8 millions d'utilisateurs. L'attaquant aurait accédé au système via le compte Okta SSO d'un agent de support employé par Telus International, un prestataire BPO. La compromission a été facilitée par un malware infectant l'ordinateur de l'agent. Grâce à cet accès, l'attaquant a pu télécharger 8 millions de tickets de support depuis l'instance Zendesk de Crunchyroll. Les données exposées comprennent des noms d'utilisateurs, adresses e-mail, adresses IP et contenus de tickets. Dans de rares cas, des numéros de carte de crédit partagés par les clients dans les messages ont été vus par l'attaquant. Une demande de rançon de 5 millions de dollars a été envoyée à Crunchyroll sans réponse. L'accès a été révoqué après 24 heures, mais l'extraction des données était déjà terminée.

**Analyse de l'impact** : Risque élevé de phishing ciblé pour les utilisateurs dont les informations de contact et l'historique de support ont été volés. Exposition de la fragilité de la chaîne d'approvisionnement via les prestataires de services externes (BPO).

**Recommandations** :
* Renforcer la sécurisation des accès tiers par des politiques de "Zero Trust" et des accès conditionnels stricts.
* Sensibiliser les utilisateurs à ne jamais partager de données sensibles (comme des numéros de carte) dans les tickets de support.
* Auditer les terminaux des prestataires externes pour s'assurer du respect des normes de sécurité (EDR, correctifs).
* Surveiller les signes de vol de jetons de session (session hijacking) au sein des plateformes Okta et Zendesk.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable (Individu anonyme) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1078.003: Valid Accounts (Cloud Accounts) <br/> * T1566: Phishing <br/> * T1212: Exploitation for Credential Access |
| Observables & Indicateurs de compromission | ```Aucun IoC spécifique n'est fourni pour le malware initial``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/crunchyroll-probes-breach-after-hacker-claims-to-steal-6.8m-users-data/

<br>
<br>
<div id="m-trends-2026-le-panorama-des-menaces-de-mandiant"></div>

## M-Trends 2026: Data, Insights, and Strategies From the Frontlines
Le rapport M-Trends 2026 de Mandiant révèle une transformation profonde de la rapidité des cyberattaques en 2025. Le temps moyen entre l'accès initial et le passage à un groupe d'exécution (hand-off) est passé de 8 heures à 22 secondes. Les exploits restent le vecteur d'infection dominant (32 %), suivis d'une forte hausse du phishing vocal (11 %). Les attaquants ciblent désormais activement les hyperviseurs et les infrastructures de sauvegarde pour empêcher toute récupération. Le secteur technologique est devenu la cible prioritaire, dépassant le secteur financier. Les groupes d'espionnage privilégient la persistance sur les périphériques réseau (VPN, routeurs) dépourvus de télémétrie EDR. Les attaquants utilisent également l'IA pour automatiser l'évasion des malwares et extraire des données sensibles. Le temps de rétention moyen des logs (90 jours) est jugé insuffisant face à des intrusions dont la durée de présence dépasse souvent un an.

**Analyse de l'impact** : Les organisations doivent réagir instantanément aux alertes de faible intensité, car le délai de réaction humaine est devenu incompatible avec la vitesse automatisée des attaquants. La résilience opérationnelle est menacée par le ciblage direct des capacités de restauration.

**Recommandations** :
* Automatiser la réponse aux alertes de malware initial pour bloquer les intrusions avant le passage à l'action interactive.
* Isoler les consoles de gestion de virtualisation et de sauvegarde en tant qu'actifs de "Tier-0" avec un accès restreint.
* Étendre la rétention des logs critiques bien au-delà de 90 jours pour permettre les investigations a posteriori sur les APT.
* Implémenter une vérification continue de l'identité et passer de la détection basée sur les IoC statiques à l'analyse comportementale.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UNC3944, UNC6201, UNC5807 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br/> * T1566.004: Voice Phishing <br/> * T1485: Data Destruction (Backup Deletion) <br/> * T1021.002: SMB/Windows Admin Shares |
| Observables & Indicateurs de compromission | ```Malwares BRICKSTORM, QUIETVAULT, PROMPTFLUX``` |

### Source (url) du ou des articles
* https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/

<br>
<br>
<div id="suivi-des-cyberattaques-liées-au-conflit-us-israel-iran"></div>

## Monitoring Cyberattacks Directly Linked to the US-Israel-Iran Military Conflict
Le conflit entre les États-Unis, Israël et l'Iran génère une guerre cybernétique d'une intensité sans précédent. Le groupe Handala Hack, lié au renseignement iranien, a causé le sabotage de plus de 200 000 appareils dans 79 pays via Microsoft Intune. Cette attaque contre la multinationale Stryker a duré 13 jours avant un début de restauration partielle. Les attaquants utilisent des techniques "living-off-the-land", détournant des outils de gestion légitimes pour lancer des commandes d'effacement à distance. En représailles aux missiles iraniens, les États-Unis et Israël intensifient leurs pressions sur les infrastructures critiques. L'Iran subit un black-out Internet quasi-total depuis quatre semaines, sans que cela n'affecte l'activité de ses groupes proxys basés à l'étranger. La menace s'étend désormais aux entreprises technologiques et financières occidentales présentes au Moyen-Orient.

**Analyse de l'impact** : Risque systémique pour les entreprises dépendantes de plateformes de gestion centralisée (MDM). Les tensions cinétiques au Moyen-Orient se traduisent directement par des tentatives de sabotage d'infrastructures critiques et commerciales mondiales.

**Recommandations** :
* Activer l'approbation multi-administrateur pour toutes les commandes critiques (comme le wipe) dans Microsoft Intune ou équivalent.
* Revoir les dépendances aux systèmes de recalibrage connectés pour les infrastructures de sécurité et de santé.
* Surveiller étroitement les signes de scan de vulnérabilités provenant de sources inhabituelles sur les actifs exposés à Internet.
* Effectuer des exercices de crise simulant une perte massive de terminaux (laptops/serveurs) suite à un détournement de l'outil d'administration.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Handala Hack (MOIS / Void Manticore) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1078: Valid Accounts <br/> * T1485: Data Destruction (Intune MDM wipe) <br/> * T1059: Command and Scripting Interpreter |
| Observables & Indicateurs de compromission | ```Utilisation frauduleuse de Microsoft Intune ; pas de malware traditionnel identifié``` |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict

<br>
<br>
<div id="le-retour-de-la-plateforme-tycoon2fa-après-son-démantèlement"></div>

## Tycoon2FA phishing platform returns after recent police disruption
Malgré une opération internationale menée par Europol et Microsoft le 4 mars, la plateforme Tycoon2FA a retrouvé son plein niveau d'activité. L'infrastructure, composée de plus de 330 domaines saisis, a été rapidement remplacée par de nouvelles inscriptions de domaines et d'adresses IP. Tycoon2FA est une plateforme de Phishing-as-a-Service (PhaaS) spécialisée dans le vol de comptes Microsoft 365 et Gmail. Elle utilise des techniques "Adversary-in-the-Middle" (AiTM) pour intercepter les jetons de session et contourner la double authentification (2FA). La plateforme génère environ 30 millions d'e-mails de phishing par mois. Ses opérateurs ont intégré des pages de leurre générées par IA pour accroître la crédibilité des attaques. Sans arrestations physiques des administrateurs, les cybercriminels parviennent à reconstruire leur capacité opérationnelle en quelques jours.

**Analyse de l'impact** : Persistance d'une menace de haut niveau contre les entreprises utilisant Office 365. Le 2FA traditionnel n'est plus suffisant contre ce type de plateforme automatisée.

**Recommandations** :
* Déployer des méthodes d'authentification résistantes au phishing (FIDO2, Passkeys).
* Surveiller les règles de boîte de réception suspectes créées immédiatement après une connexion utilisateur (signe de post-compromission).
* Filtrer les URL raccourcies et les domaines nouvellement enregistrés dans les passerelles de messagerie.
* Analyser les connexions provenant d'adresses IP associées à des services cloud ou des proxies malveillants.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Opérateurs de Tycoon2FA |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1557.001: Adversary-in-the-Middle <br/> * T1566.002: Spearphishing Link <br/> * T1114: Email Collection |
| Observables & Indicateurs de compromission | ```Utilisation massive de domaines éphémères et de redirection via des outils de présentation légitimes``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/tycoon2fa-phishing-platform-returns-after-recent-police-disruption/