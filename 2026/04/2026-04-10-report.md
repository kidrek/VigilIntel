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
  * [analyse des cyberattaques ciblant leconomie allemande](#analyse-des-cyberattaques-ciblant-leconomie-allemande)
  * [decouverte du malware lucidrook ciblant taiwan](#decouverte-du-malware-lucidrook-ciblant-taiwan)
  * [campagne venom ciblant les cadres dirigeants](#campagne-venom-ciblant-les-cadres-dirigeants)
  * [etat du dark web en 2026 et ecosysteme russe](#etat-du-dark-web-en-2026-et-ecosysteme-russe)
  * [operation storm2755 de detournement de salaires au canada](#operation-storm2755-de-detournement-de-salaires-au-canada)
  * [industrialisation de labus des pipelines de notification saas](#industrialisation-de-labus-des-pipelines-de-notification-saas)
  * [tendances des techniques dattaque au t1 2026](#tendances-des-techniques-dattaque-au-t1-2026)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage de la menace cyber au second trimestre 2026 est marqué par un basculement critique vers l'exploitation de l'identité et la compromission des infrastructures de gestion comme vecteurs privilégiés. L'utilisation massive de plateformes de "Phishing-as-a-Service" telles que VENOM ou EvilProxy démontre que l'authentification multifacteur (MFA) traditionnelle est désormais systématiquement contournée par des techniques d'Adversary-in-the-Middle (AiTM). Parallèlement, l'armement des outils d'administration, illustré par le détournement des solutions MDM (Microsoft Intune) contre Stryker, transforme les leviers de défense en armes de destruction massive d'actifs. La menace se déplace également vers la supply chain logicielle et les services SaaS, où la confiance implicite accordée aux notifications automatisées est exploitée pour diffuser des malwares sophistiqués comme LucidRook. Sur le plan géopolitique, l'instabilité au Moyen-Orient et les cyber-opérations russes ciblant les routeurs domestiques confirment l'instrumentalisation croissante de l'infrastructure civile pour l'espionnage stratégique. Enfin, l'accélération de l'exploitation des vulnérabilités critiques, souvent moins de 10 heures après leur divulgation grâce à l'assistance de l'IA, impose aux décideurs une réduction drastique des temps de réaction. La résilience repose désormais sur une approche Zero Trust stricte, le déploiement de MFA résistant au phishing (FIDO2) et une surveillance accrue des identités à hauts privilèges.

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
| APT28 (Fancy Bear) | Gouvernement, Militaire, Infrastructures critiques | DNS hijacking, compromission de routeurs SOHO (Opération Masquerade) | [Sploited Blog](https://sploited.blog/2026/04/09/weekly-threat-landscape-thursday-roundup-3/) |
| FlamingChina | Défense, Aérospatial (Chine) | Exfiltration massive via VPN compromis et botnets | [Security Affairs](https://securityaffairs.com/190536/hacking/the-alleged-breach-of-chinas-national-supercomputing-center-can-have-serious-geopolitical-consequences.html) |
| Handala Hack | Médical, Infrastructures critiques, Gouvernement | Abus de Microsoft Intune (Wipe), PowerShell wipers, influence ops | [HiSolutions](https://research.hisolutions.com/2026/04/stryker-breach-wenn-das-eigene-mdm-zur-waffe-wird/), [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| MuddyWater | Défense, Énergie, Aérospatial | Déploiement de CastleRAT et malware ChainShell via blockchain | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Storm-2755 | Multi-sectoriel (Canada) | Malvertising, SEO poisoning, AiTM via client HTTP Axios | [Microsoft Security](https://www.microsoft.com/en-us/security/blog/2026/04/09/investigating-storm-2755-payroll-pirate-attacks-targeting-canadian-employees/) |
| UAT-10362 | ONG, Universités (Taiwan) | Spear-phishing, DLL sideloading, malware LucidRook (Lua) | [Cisco Talos](https://blog.talosintelligence.com/the-threat-hunters-gambit/) |
| UNC6783 | BPO, Support technique | Social engineering via live chat, spoofing Okta | [The Hacker News](https://thehackernews.com/2026/04/threatsday-bulletin-hybrid-p2p-botnet.html) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Aérospatial & Défense | Chine - NSCC | Allégation de vol de 10 Po de données militaires et de recherche auprès du Centre National de Supercalcul de Tianjin. | [Security Affairs](https://securityaffairs.com/190536/hacking/the-alleged-breach-of-chinas-national-supercomputing-center-can-have-serious-geopolitical-consequences.html) |
| Gouvernement | États-Unis - Iran | Piratage des emails personnels du directeur du FBI Kash Patel par un groupe lié à l'Iran. | [HiSolutions](https://research.hisolutions.com/2026/04/weitere-news-im-april-2/) |
| Infrastructures Critiques | Israël - Iran | Poursuite des cyber-opérations offensives (wipers) malgré l'annonce fragile d'un cessez-le-feu. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Services Publics | Russie - Ukraine | Instrumentalisation croissante du cybercrime par l'État russe pour contourner les sanctions et espionner l'Occident. | [Flare](https://flare.io/learn/resources/blog/state-of-the-dark-web-2026) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| AI Continent Action Plan delivers major milestones | Commission Européenne | 09/04/2026 | Union Européenne | AI Omnibus / Data Union Strategy | Mise à jour sur les piliers de l'infrastructure, des données et de l'IA de confiance en Europe. | [European Commission](https://digital-strategy.ec.europa.eu/en/news/ai-continent-action-plan-delivers-major-milestones) |
| Anthropic Faces Legal Setback | Cour d'appel Washington | 09/04/2026 | États-Unis | National Security Designation | Maintien de la désignation d'Anthropic comme risque pour la chaîne d'approvisionnement par le DoD. | [The Hacker News](https://thehackernews.com/2026/04/threatsday-bulletin-hybrid-p2p-botnet.html) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Finance | Figure | Exposition de 967 200 enregistrements d'emails, facilitant le credential stuffing. | [Bleeping Computer](https://www.bleepingcomputer.com/news/security/when-attackers-already-have-the-keys-mfa-is-just-another-door-to-open/) |
| Médical | ChipSoft (Pays-Bas) | Attaque par ransomware impactant les services numériques de plusieurs hôpitaux néerlandais. | [Bleeping Computer](https://www.bleepingcomputer.com/news/security/healthcare-it-solutions-provider-chipsoft-hit-by-ransomware-attack/) |
| Médical | Hims & Hers | Vol de noms et d'adresses email via une attaque d'ingénierie sociale sur le support client. | [Cisco Talos](https://blog.talosintelligence.com/the-threat-hunters-gambit/) |
| Supercalcul | NSCC Tianjin | Exfiltration présumée de 10 pétaoctets de données militaires et technologiques sensibles. | [Sploited Blog](https://sploited.blog/2026/04/09/weekly-threat-landscape-thursday-roundup-3/) |
| Transport | Eurail | Violation de données impactant 308 777 voyageurs (noms, numéros de passeport). | [Security Affairs](https://securityaffairs.com/190570/data-breach/eurail-data-breach-impacted-308777-people.html) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2026-34424 | 9.8 | Élevé | TRUE | Smart Slider 3 Pro | Supply Chain / Backdoor | T1195.002: Supply Chain Compromise | Injection de code malveillant via le système de mise à jour compromis. | [PatchStack](https://patchstack.com/articles/critical-supply-chain-compromise-in-smart-slider-3-pro-full-malware-analysis/) |
| CVE-2026-35393 | 9.8 | Moyen | FALSE | goshs | Path Traversal | T1083: File and Directory Discovery | Permet l'écriture arbitraire de fichiers sans authentification. | [Security Online](https://securityonline.info/goshs-vulnerability-path-traversal-rce-exploit/) |
| CVE-2026-33784 | 9.8 | Moyen | FALSE | Juniper vLWC | Default Credentials | T1078: Valid Accounts | Absence d'obligation de changer le mot de passe par défaut du compte privilégié. | [Security Online](https://securityonline.info/juniper-vlwc-default-password-vulnerability-cve-2026-33784/) |
| CVE-2026-33017 | 9.8 | Élevé | TRUE | Langflow | RCE unauthenticated | T1190: Exploit Public-Facing Application | Exécution de code à distance via l'exposition d'un endpoint de build sans isolation. | [HiSolutions](https://research.hisolutions.com/2026/04/weitere-news-im-april-2/) |
| GHSA-2679-6mx9-h9xc | 9.3 | N/A | FALSE | Marimo | RCE pre-auth | T1210: Exploitation of Remote Services | Accès shell interactif via WebSocket sans aucune validation d'authentification. | [Sysdig](https://webflow.sysdig.com/blog/marimo-oss-python-notebook-rce-from-disclosure-to-exploitation-in-under-10-hours) |
| CVE-2026-34197 | 8.8 | Moyen | FALSE | Apache ActiveMQ Classic | RCE / Input Validation | T1210: Exploitation of Remote Services | Chaînage avec Jolokia pour une exécution de commandes à distance (vieux de 13 ans). | [Help Net Security](https://www.helpnetsecurity.com/2026/04/09/apache-activemq-rce-vulnerability-cve-2026-34197-claude/) |
| CVE-2026-5707 | 8.8 | Moyen | FALSE | AWS RES | Privilege Escalation / RCE | T1068: Exploitation for Privilege Escalation | Entrée non assainie dans le nom de session permettant l'exécution de commandes root. | [Security Online](https://securityonline.info/aws-res-vulnerabilities-privilege-escalation-root-access-patch/) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| How Phishing Is Targeting Germany’s Economy | Analyse détaillée des attaques par secteur et outils (EvilProxy, FlowerStorm). | [ANY.RUN](https://any.run/cybersecurity-blog/german-industries-attack-cases/) |
| Investigating Storm-2755: Payroll pirate attacks | Étude d'une menace financière ciblée utilisant des techniques AiTM sophistiquées. | [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/04/09/investigating-storm-2755-payroll-pirate-attacks-targeting-canadian-employees/) |
| New ‘LucidRook’ malware used in targeted attacks | Découverte d'un nouveau malware Lua furtif ciblant des entités stratégiques à Taiwan. | [Cisco Talos](https://blog.talosintelligence.com/the-threat-hunters-gambit/) |
| Phishing Campaigns Weaponize Trust (Talos) | Analyse de la technique "Platform-as-a-Proxy" via GitHub/Jira. | [Cisco Talos](https://blog.talosintelligence.com/the-threat-hunters-gambit/) |
| Q1 2026 Attack Technique Trends Report | Synthèse des évolutions tactiques incluant l'IA et l'abus de relations de confiance. | [AhnLab](https://asec.ahnlab.com/en/93278/) |
| State of the Dark Web in 2026 | Panorama complet de l'évolution des places de marché russes et de l'usage de Telegram. | [Flare](https://flare.io/learn/resources/blog/state-of-the-dark-web-2026) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| ISC Stormcast For Thursday, April 9th | Format podcast trop succinct, pas de nouvelle menace spécifique détaillée. | [SANS ISC](https://isc.sans.edu/diary/rss/32882) |
| Webinar: From noise to signal | Article promotionnel pour un événement futur. | [Bleeping Computer](https://www.bleepingcomputer.com/news/security/webinar-from-noise-to-signal-what-threat-actors-are-targeting-next/) |
| Elastic on Defence Cyber Marvel 2026 | Rétrospective technique d'un exercice militaire, pas une menace réelle. | [Elastic](https://www.elastic.co/security-labs/elastic-defence-cyber-marvel) |
| Third-Party Risk Is an Intelligence Operation | Article de positionnement produit / marketing. | [Recorded Future](https://www.recordedfuture.com/blog/recorded-future-sees-its-inclusion-in-the-2026-forrester-wave) |

<br>
<br/>
<div id="articles"></div>

# ARTICLES

<div id="analyse-des-cyberattaques-ciblant-leconomie-allemande"></div>

## How Phishing Is Targeting Germany’s Economy: Active Threats from Finance to Manufacturing
L'économie allemande subit une pression systématique via des campagnes de phishing ciblant cinq secteurs clés : finance, santé, tech, télécoms et industrie. L'analyse révèle que l'identité est devenue le nouveau périmètre, les attaquants contournant la MFA par le détournement de sessions en temps réel. Des plateformes de Phishing-as-a-Service comme FlowerStorm et EvilProxy sont massivement utilisées. Ces outils permettent de simuler parfaitement les flux OAuth de Microsoft 365 pour intercepter les cookies de session. Les leurres sont hautement contextualisés, tels que des avis d'augmentation de salaire pour la finance ou des messages vocaux Teams pour l'industrie. L'infrastructure d'attaque abuse de services légitimes comme Amazon SES, Cloudflare Workers et WordPress pour échapper aux filtres de réputation. L'automatisation du phishing AiTM démocratise l'accès aux attaques de haut niveau pour des acteurs moins qualifiés. La reconnaissance préalable est évidente, avec des domaines enregistrés aux noms des entreprises cibles.

**Analyse de l'impact** : Impact critique sur la continuité d'activité et le risque de fraude financière massive (BEC). La capacité de contourner la MFA rend les défenses périmétriques traditionnelles obsolètes pour la protection des accès cloud.

**Recommandations** :
*   Migrer vers une authentification MFA résistante au phishing (FIDO2/WebAuthn).
*   Mettre en œuvre une validation de session Zero Trust avec des politiques d'accès conditionnel strictes.
*   Surveiller les anomalies de navigation (User-Agent inattendu, adresses IP distantes géographiquement).
*   Réaliser des simulations de phishing spécifiques aux flux SaaS (OAuth, Teams).

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | FlowerStorm, opérateurs EvilProxy |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | - T1566.002: Spearphishing Link<br/>- T1557: Adversary-in-the-Middle<br/>- T1539: Steal Web Session Cookie |
| Observables & Indicateurs de compromission | - saicares.com.au<br/>- ogbarberschool.com<br/>- teams-ms365.cloud<br/>- voicbx.com<br/>- jewbreats.org |

### Source (url) du ou des articles
* https://any.run/cybersecurity-blog/german-industries-attack-cases/

<br>
<br>

<div id="decouverte-du-malware-lucidrook-ciblant-taiwan"></div>

## New ‘LucidRook’ malware used in targeted attacks on NGOs, universities
Cisco Talos a identifié un nouveau malware basé sur Lua, nommé LucidRook, ciblant des ONG et des universités à Taiwan. Attribué au groupe UAT-10362, ce malware se distingue par sa grande maturité opérationnelle et sa furtivité. L'infection débute par du spear-phishing avec des archives protégées par mot de passe contenant des fichiers LNK ou des exécutables usurpant Trend Micro. LucidRook utilise un environnement d'exécution Lua intégré, permettant de mettre à jour ses fonctionnalités via du bytecode sans modifier le binaire principal. Cette approche limite considérablement la visibilité forensique pour les défenseurs. Le malware effectue une reconnaissance système complète avant d'exfiltrer les données via FTP sous forme d'archives RSA chiffrées. Un outil compagnon, LucidKnight, a également été détecté, abusant de Gmail (SMTP) pour l'exfiltration. L'utilisation de documents leurres imitant le gouvernement taïwanais confirme le ciblage stratégique.

**Analyse de l'impact** : Risque élevé d'espionnage et de vol de propriété intellectuelle. La modularité du malware Lua permet une adaptation rapide à l'environnement de la victime, rendant la détection par signature inefficace.

**Recommandations** :
*   Bloquer les exécutions de fichiers LNK à partir de supports amovibles ou de dossiers temporaires.
*   Surveiller l'utilisation inhabituelle de l'interpréteur Lua dans les processus utilisateur.
*   Implémenter des alertes sur l'exfiltration de données via FTP ou des connexions SMTP inhabituelles vers Gmail.
*   Renforcer la détection du DLL sideloading (ex: DismCore.dll).

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UAT-10362 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | - T1574.002: DLL Side-Loading<br/>- T1059.006: Lua scripting<br/>- T1020: Automated Exfiltration |
| Observables & Indicateurs de compromission | - DismCore.dll<br/>- LucidPawn (dropper)<br/>- LucidKnight (reconnaissance) |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/new-lucidrook-malware-used-in-targeted-attacks-on-ngos-universities/
* https://blog.talosintelligence.com/the-threat-hunters-gambit/

<br>
<br>

<div id="campagne-venom-ciblant-les-cadres-dirigeants"></div>

## New VENOM phishing attacks steal senior executives' Microsoft logins
Une plateforme de Phishing-as-a-Service (PhaaS) non documentée, baptisée VENOM, cible spécifiquement les comptes Microsoft de cadres dirigeants (C-suite). Active depuis novembre 2025, cette opération se distingue par un accès fermé et une absence de promotion sur les forums publics. Les emails imitent des notifications SharePoint hautement personnalisées, incluant du "HTML noise" pour tromper les scanners. Un code QR Unicode est utilisé pour forcer le passage de l'attaque sur mobile, échappant ainsi aux protections de bureau. VENOM utilise deux méthodes : le relais AiTM classique pour capturer les jetons de session et l'attaque par "device-code". Cette dernière incite la victime à approuver l'accès à son compte pour un appareil tiers malveillant. Une fois authentifié, l'attaquant établit un accès persistant en enregistrant son propre appareil sur le compte de la victime.

**Analyse de l'impact** : Risque majeur de compromission de messagerie d'entreprise (BEC) au plus haut niveau. L'accès aux comptes des CEO/CFO permet l'exfiltration de données stratégiques et la manipulation de transactions financières.

**Recommandations** :
*   Désactiver le flux d'authentification par "Device Code" si non nécessaire.
*   Mettre en œuvre des clés de sécurité matérielles FIDO2 pour les comptes à hauts privilèges.
*   Appliquer des politiques d'accès conditionnel strictes basées sur la conformité de l'appareil.
*   Éduquer les dirigeants sur les risques liés aux QR codes dans les emails.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Opérateurs VENOM |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | - T1566.003: Phishing via QR Code<br/>- T1557: Adversary-in-the-Middle<br/>- T1528: Steal Application Access Token |
| Observables & Indicateurs de compromission | Aucun IoC spécifique de domaine n'est fourni dans l'article original. |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/new-venom-phishing-attacks-steal-senior-executives-microsoft-logins/

<br>
<br>

<div id="etat-du-dark-web-en-2026-et-ecosysteme-russe"></div>

## State of the Dark Web in 2026: Russian-Speaking Cybercrime Ecosystem & Telegram
En 2026, le dark web n'est plus statique mais fonctionne comme une économie de marché dynamique. L'écosystème russophone est profondément remodelé par la guerre en Ukraine, voyant une coopération accrue entre l'Occident et l'Ukraine, contrebalancée par l'instrumentalisation du cybercrime par l'État russe. Les démantèlements (takedowns) de forums comme XSS ou RAMP provoquent une fragmentation des communautés et une érosion de la confiance. Telegram est devenu la plateforme dominante, hébergeant plus de 90% des logs d'infostealers observés. La chute de Lumma Stealer illustre que les rivaux cybercriminels peuvent être plus menaçants que la police. Les infostealers évoluent d'une menace grand public vers le vol d'identités d'entreprise (SSO/IdP). Microsoft Entra ID apparaît dans 79% des logs d'entreprise compromis. Le blocage imminent de Telegram en Russie pousse les acteurs vers des méthodes de contournement sophistiquées (DPI bypass).

**Analyse de l'impact** : Transition du risque vers la compromission d'identité centralisée (Okta, Azure AD). La disparition des forums centraux rend le monitoring de la menace plus complexe car plus diffus sur Telegram.

**Recommandations** :
*   Surveiller activement les canaux Telegram pour la détection précoce de fuites de credentials.
*   Renforcer la sécurité des accès SSO avec du monitoring sur les sessions simultanées inhabituelles.
*   Mettre en place des mesures de "cleanside" pour détecter les infostealers sur les postes de travail.
*   Réduire la durée de vie des jetons de session (session lifetime).

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Vidar, StealC, ex-Lumma operators |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | - T1552.001: Credentials In Files<br/>- T1539: Steal Web Session Cookie<br/>- T1583.001: Domains |
| Observables & Indicateurs de compromission | - xss[.]pro<br/>- damagelib (forum)<br/>- Lumma Rats (underground site) |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/state-of-the-dark-web-2026

<br>
<br>

<div id="operation-storm2755-de-detournement-de-salaires-au-canada"></div>

## Investigating Storm-2755: “Payroll pirate” attacks targeting Canadian employees
Microsoft a identifié Storm-2755, un acteur motivé par l'appât du gain ciblant les employés canadiens pour détourner leurs salaires. L'attaque utilise le SEO poisoning pour diriger les victimes vers une fausse page de connexion Microsoft 365 (via le domaine bluegraintours[.]com). Une technique AiTM est employée via le client HTTP open-source Axios (v1.7.9) pour rejouer les jetons d'authentification et contourner la MFA. Une fois à l'intérieur, l'acteur recherche des termes liés aux RH et à la paie (Workday, ADP). Il crée des règles de boîte de réception pour cacher les emails de confirmation de changement de RIB. Storm-2755 opère souvent à 5h00 du matin pour minimiser les risques de détection par l'utilisateur. L'acteur interagit manuellement avec les portails SaaS pour modifier les informations de dépôt direct. Microsoft a noté l'exploitation de la vulnérabilité CVE-2025-27152 dans Axios pour faciliter le relais.

**Analyse de l'impact** : Perte financière directe pour les individus et risque réputationnel pour les organisations. La persistance moyenne des jetons volés est observée sur 30 jours.

**Recommandations** :
*   Surveiller les logs de connexion pour l'User-Agent "Axios/1.7.9".
*   Alerter sur la création de règles de messagerie suspectes incluant les mots "RIB", "banque" ou "salaire".
*   Mettre en œuvre l'évaluation continue de l'accès (CAE) pour révoquer les sessions en cas de changement de risque.
*   Sensibiliser le personnel RH à la vérification hors canal des demandes de changement de coordonnées bancaires.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Storm-2755 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | - T1557: Adversary-in-the-Middle<br/>- T1137.005: Outlook Rules<br/>- T1566.002: Spearphishing Link |
| Observables & Indicators of compromise | - bluegraintours[.]com<br/>- Axios/1.7.9 (User-Agent) |

### Source (url) du ou des articles
* https://www.microsoft.com/en-us/security/blog/2026/04/09/investigating-storm-2755-payroll-pirate-attacks-targeting-canadian-employees/

<br>
<br>

<div id="industrialisation-de-labus-des-pipelines-de-notification-saas"></div>

## Phishing Campaigns Weaponize Trust: Platform-as-a-Proxy (PaaP)
Cisco Talos alerte sur l'utilisation des pipelines de notification légitimes de plateformes comme GitHub et Jira pour diffuser des emails de phishing. En utilisant les infrastructures officielles (ex: fonction "Invite Customers" de Jira), les attaquants s'assurent que leurs emails passent les protocoles SPF, DKIM et DMARC. Cette technique de "Platform-as-a-Proxy" (PaaP) exploite la confiance implicite des utilisateurs envers les notifications de services d'entreprise connus. Les emails sont techniquement authentiques et proviennent de domaines de confiance, rendant les passerelles de sécurité traditionnelles aveugles. L'objectif est souvent le vol de credentials ou le déploiement d'outils de gestion à distance (RMM) comme LogMeIn Resolve. Cette approche mise sur la "fatigue de l'automatisation" où l'utilisateur accepte machinalement les invitations système. La campagne STAC6405 illustre cet abus depuis avril 2025.

**Analyse de l'impact** : Érosion de la confiance dans les outils de collaboration internes. Risque élevé de compromission initiale par le biais de services pourtant jugés "sûrs" par les politiques de sécurité.

**Recommandations** :
*   Ingérer les journaux d'API des plateformes SaaS (GitHub, Jira) dans le SIEM pour détecter les créations de projets ou invitations de masse.
*   Mettre en place une vérification au niveau de l'instance pour les notifications entrantes.
*   Exiger une vérification hors bande pour toute action critique initiée via une notification de plateforme.
*   Appliquer une analyse sémantique des intentions sur les notifications suspectes.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | STAC6405 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | - T1566.003: Phishing via trusted platforms<br/>- T1213: Data from Information Repositories |
| Observables & Indicators of compromise | - LogMeIn Resolve (abus)<br/>- ValleyRAT (payload) |

### Source (url) du ou des articles
* https://blog.talosintelligence.com/the-threat-hunters-gambit/

<br>
<br>

<div id="tendances-des-techniques-dattaque-au-t1-2026"></div>

## Q1 2026 Attack Technique Trends Report
Le paysage des attaques au premier trimestre 2026 montre un saut qualitatif par rapport aux menaces automatisées de masse. L'adoption de l'IA générative accélère les taux de pénétration en automatisant la reconnaissance et la mutation de code. Les attaques deviennent "centrées sur l'identité", préférant l'usage de comptes légitimes au cassage de firewalls. L'abus de relations de confiance (partenaires, SaaS, API) devient le moyen de contournement par excellence. On observe des techniques d'évasion sophistiquées comme l'utilisation de pilotes anti-triche de jeux (CVE-2025-61155) pour désactiver les EDR. Une autre technique consiste à utiliser des binaires de mise à jour légitimes (comme upd.exe de Carbon Black) pour tuer les processus de sécurité. L'industrialisation du phishing multilingue via l'IA permet à des acteurs de niveau moyen de mener des campagnes de grande envergure.

**Analyse de l'impact** : Augmentation du temps de présence (dwell time) des attaquants grâce à l'évasion de détection. La frontière entre cybercriminels et acteurs étatiques s'estompe avec la démocratisation des outils de pointe.

**Recommandations** :
*   Auditer régulièrement les droits accordés aux applications OAuth tierces.
*   Implémenter un monitoring comportemental pour détecter les tentatives de désactivation des agents EDR.
*   Renforcer la vérification de l'intégrité des pilotes système.
*   Déployer des pipelines de sécurité "AI-native" pour auditer le code interne en continu.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | - T1562.001: Disable or Modify Tools<br/>- T1078.004: Cloud Accounts<br/>- T1553.006: Code Signing Policy Bypass |
| Observables & Indicators of compromise | - upd.exe (Carbon Black)<br/>- hotta Killer (exploit) |

### Source (url) du ou des articles
* https://asec.ahnlab.com/en/93278/