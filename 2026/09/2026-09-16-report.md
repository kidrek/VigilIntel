# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [Cyberacteurs iraniens : ciblage de dissidents, activistes et journalistes et usage de Telegram comme C2 pour distribuer du malware](#cyberacteurs-iraniens-ciblage-de-dissidents-activistes-et-journalistes-et-usage-de-telegram-comme-c2-pour-distribuer-du-malware)
  * [macOS 27 « Golden Gate » : analyse du trafic réseau émis au premier démarrage, avant connexion utilisateur](#macos-27-golden-gate-analyse-du-trafic-reseau-emis-au-premier-demarrage-avant-connexion-utilisateur)
  * [Persistance macOS via man.conf : preuve de concept d'une exécution pilotée par configuration](#persistance-macos-via-manconf-preuve-de-concept-dune-execution-pilotee-par-configuration)
  * [L'évolution de l'identité : étendre l'IAM aux personnes, aux machines et aux agents IA](#levolution-de-lidentite-etendre-liam-aux-personnes-aux-machines-et-aux-agents-ia)
  * [Google Doc avec sidebar malveillante : AMOS sur macOS et loader PowerShell sur Windows via des DM X](#google-doc-avec-sidebar-malveillante-amos-sur-macos-et-loader-powershell-sur-windows-via-des-dm-x)
  * [ResetSpy : énumération des comptes et des méthodes MFA via le portail SSPR de Microsoft](#resetspy-enumeration-des-comptes-et-des-methodes-mfa-via-le-portail-sspr-de-microsoft)
  * [0xCr0ssCrush : deux drivers signés vulnérables (DCRCVDrv.sys, Alinubx.sys) abusés par le loader MaaS Cruciferra](#0xcr0sscrush-deux-drivers-signes-vulnerables-dcrcvdrvsys-alinubxsys-abuses-par-le-loader-maas-cruciferra)
  * [SindriKit v2.0.0 : framework C réorganisé autour des couches ABI Windows, syscalls et injection](#sindrikit-v200-framework-c-reorganise-autour-des-couches-abi-windows-syscalls-et-injection)
  * [Kage : console de triage DFIR Windows automatisant la première heure d'investigation](#kage-console-de-triage-dfir-windows-automatisant-la-premiere-heure-dinvestigation)
  * [CISA : ressource « Detecting and Mitigating Active Directory Compromises » (révision du 15 septembre 2026)](#cisa-ressource-detecting-and-mitigating-active-directory-compromises-revision-du-15-septembre-2026)
  * [Hey, You Hacked a Hacker! Are You Ready For My Revenge? — compromission d'un red teamer via un dépôt GitHub malveillant](#hey-you-hacked-a-hacker-are-you-ready-for-my-revenge-compromission-dun-red-teamer-via-un-depot-github-malveillant)
  * [Feuille de travail gratuite : lister ses actifs exposés sur Internet et les prioriser face au catalogue KEV](#feuille-de-travail-gratuite-lister-ses-actifs-exposes-sur-internet-et-les-prioriser-face-au-catalogue-kev)
  * [186.96.194.192 — IP à activité mixte signalée par un flux de renseignement (confiance 45 %)](#18696194192-ip-a-activite-mixte-signalee-par-un-flux-de-renseignement-confiance-45)
  * [Injection SQL UNION-based : méthodologie d'extraction de données décrite dans un guide Codelivly](#injection-sql-union-based-methodologie-dextraction-de-donnees-decrite-dans-un-guide-codelivly)
  * [Un groupe ransomware revendique l'attaque du Cedar County Memorial Hospital (Missouri) après une panne informatique](#un-groupe-ransomware-revendique-lattaque-du-cedar-county-memorial-hospital-missouri-apres-une-panne-informatique)
  * [Des membres du groupe cybercriminel « Black Axe » extradés d'Afrique du Sud](#des-membres-du-groupe-cybercriminel-black-axe-extrades-dafrique-du-sud)
  * [Photos d'élèves et coordonnées bancaires dérobées après une cyberattaque contre St James Anglican School à Perth](#photos-deleves-et-coordonnees-bancaires-derobees-apres-une-cyberattaque-contre-st-james-anglican-school-a-perth)
  * [Rohto Pharmaceutical : accès non autorisé au système de vente en ligne, un pirate revendique ~4 To de données dont ~3,95 millions de fiches clients Salesforce](#rohto-pharmaceutical-acces-non-autorise-au-systeme-de-vente-en-ligne-un-pirate-revendique-4-to-de-donnees-dont-395-millions-de-fiches-clients-salesforce)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

La veille du jour est dominée par les vulnérabilités (38 signalements), confirmant une pression d'exposition élevée qui exige une priorisation rigoureuse des correctifs. Les fuites de données (23) constituent le second foyer de risque, suggérant une exploitation active d'informations compromises à surveiller de près. L'absence totale d'activité attribuée à des acteurs de la menace (0) est atypique et pourrait refléter un déficit de collecte plutôt qu'une accalmie réelle, justifiant une vérification des sources. Le volet géopolitique (5) reste modéré mais mérite un suivi des tensions susceptibles d'alimenter des opérations cyber à dimension étatique. La faible activité réglementaire (2) n'indique aucun changement immédiat du cadre de conformité. Le volume éditorial (18 articles) offre une couverture suffisante pour contextualiser ces signaux. Recommandation : concentrer le triage sur les vulnérabilités exploitables et auditer la continuité de la collecte sur les acteurs de la menace.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

_Aucun acteur identifié._

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Algérie, Niger, Sahel, Maghreb, Afrique de l'Ouest** | Défense et sécurité | Rupture de la doctrine de non-ingérence algérienne : intervention militaire au Niger et recomposition géopolitique du Sahel | Le 30 août 2026, à la suite d'une tentative de coup d'État contre le régime du général Tiani à Niamey (nuit du 28 au 29 août), l'Algérie a déployé quatre chasseurs Sukhoï Su-30, un ravitailleur Il-78 et un appareil de transport Il-76 sur la base aérienne de Niamey, à la demande des autorités nigériennes, après une première livraison de quatre hélicoptères militaires le 9 août. Il s'agit de la première intervention militaire assumée hors des frontières algériennes depuis l'indépendance, rompant avec la doctrine historique de non-ingérence. Ce tournant s'inscrit dans un Sahel profondément déstabilisé : succession de coups d'État au Mali, au Burkina Faso et au Niger, effondrement des dispositifs régionaux (G5 Sahel paralysé, AES dépassée), retrait accéléré des forces françaises et expansion des groupes jihadistes JNIM et EIGS. Alger, qui partage environ 2 500 km de frontières avec le Sahel dont près de 1 000 km avec le Niger, axe majeur des routes migratoires subsahariennes, y voit un enjeu direct de sécurité nationale. Cette intervention intervient alors que l'influence régionale algérienne s'était érodée : détérioration avec Bamako (dénonciation par Goïta de l'accord de paix d'Alger de 2015), tensions avec Niamey depuis 2023 (refoulement de migrants), abattage d'un drone malien en avril 2025 ayant provoqué le rappel des ambassadeurs de l'AES. Le dégel amorcé par la visite de Tiani à Alger en février 2026 et le retour des ambassadeurs en juillet 2026 ont ouvert la voie à ce repositionnement stratégique. | [https://www.iris-france.org/algerie-vers-un-changement-de-paradigme-en-matiere-de-politique-etrangere/](https://www.iris-france.org/algerie-vers-un-changement-de-paradigme-en-matiere-de-politique-etrangere/) |
| **Europe, Amérique du Nord** | Industrie de défense et armement | Articulation des politiques industrielles de défense et d'acquisition de l'UE et de l'OTAN : complémentarité ou concurrence | Dans une note de l'IRIS, Federico Santopinto analyse le renforcement considérable, en une décennie, des compétences de l'UE en matière d'industrie de défense et l'adoption récente de nouveaux instruments d'acquisition militaire, faisant de l'Union un acteur à part entière dans deux secteurs stratégiques majeurs. La note interroge l'articulation — potentiellement concurrentielle — de ces compétences avec celles de l'OTAN, alors que l'Alliance traverse de profondes transformations impulsées par l'administration Trump. Trois axes structurent la réflexion : la nature réelle du positionnement américain vis-à-vis de l'OTAN et des Européens (désengagement total, délégation contrôlée ou nouvelle forme de tutelle stratégique) ; les effets de cette recomposition sur la relation UE-OTAN dans les domaines militaro-industriels et des acquisitions, notamment la capacité de l'UE à promouvoir l'autonomie stratégique de ses États membres ; et les enjeux de planification et de gouvernance à l'échelle européenne, en particulier le rôle que devrait jouer l'OTAN dans la définition des priorités orientant les politiques industrielles et d'armement de l'UE. | [https://www.iris-france.org/les-politiques-industrielles-de-defense-et-dacquisition-de-lue-et-de-lotan-complementarite-ou-concurrence/](https://www.iris-france.org/les-politiques-industrielles-de-defense-et-dacquisition-de-lue-et-de-lotan-complementarite-ou-concurrence/) |
| **Iran, Moyen-Orient** | Médias et société civile (dissidents, journalistes) | Cyberespionnage iranien visant les « ennemis du régime » : leurres médicaux et malware contrôlé via Telegram | Selon The Record (Recorded Future) et The Hacker News, relayés par le digest du 15 septembre 2026, des cyberespions iraniens ont utilisé de faux résultats d'IRM comme lure pour compromettre des personnes qualifiées d'« ennemis du régime ». Une campagne distincte s'appuie sur un malware contrôlé via Telegram pour espionner des dissidents et des journalistes. Ces opérations, à motivation politique et attribuées à des acteurs iraniens, illustrent la persistance de la surveillance transnationale menée contre l'opposition et la presse en exil, avec un recours à des leurres thématiques crédibles (documents médicaux) et à des canaux de communication grand public comme vecteur de contrôle. | [https://infosec.exchange/@securityfeed/117277466816426847](https://infosec.exchange/@securityfeed/117277466816426847)<br>[https://therecord.media/iran-cyber-spies-use-fake-mri-scans-as-lure](https://therecord.media/iran-cyber-spies-use-fake-mri-scans-as-lure)<br>[https://thehackernews.com/2026/09/iranian-hackers-use-telegram-controlled.html](https://thehackernews.com/2026/09/iranian-hackers-use-telegram-controlled.html) |
| **Norvège, Myanmar, Asie du Sud-Est** | Télécommunications | Ouverture d'enquêtes en Norvège sur les activités de l'opérateur Telenor avec la junte birmane | The Record (Recorded Future) rapporte, via le digest du 15 septembre 2026, que la Norvège a annoncé des enquêtes sur les travaux menés par l'opérateur de télécommunications Telenor avec la junte au pouvoir au Myanmar. Cette affaire illustre les tensions entre les impératifs commerciaux des opérateurs européens et le respect des régimes de sanctions et des droits humains dans les juridictions sous régime autoritaire. Elle pourrait déboucher sur des mesures réglementaires ou sanctionnaires et affecter la réputation et l'exposition des entreprises européennes opérant dans des environnements à risque. | [https://infosec.exchange/@securityfeed/117277466816426847](https://infosec.exchange/@securityfeed/117277466816426847)<br>[https://therecord.media/norway-investigations-telenor-telecom-myanmar-regime](https://therecord.media/norway-investigations-telenor-telecom-myanmar-regime) |
| **États-Unis** | Défense / aérospatial | Confirmation du déploiement d'armes américaines en orbite terrestre : nouvelle étape de la militarisation de l'espace | TechCrunch rapporte, via le digest du 15 septembre 2026, que l'armée américaine confirme avoir lancé des armes dans l'orbite terrestre. Cette annonce marque une étape notable dans la militarisation de l'espace et pourrait accentuer la dynamique de course aux capacités orbitales entre grandes puissances. Elle a des implications directes pour la sécurité des actifs spatiaux (communications, navigation, observation) dont dépendent les infrastructures civiles et militaires occidentales, et pour l'équilibre stratégique global. | [https://infosec.exchange/@securityfeed/117277466816426847](https://infosec.exchange/@securityfeed/117277466816426847)<br>[https://techcrunch.com/2026/09/15/us-military-confirms-it-launched-space-weapons-into-earths-orbit/](https://techcrunch.com/2026/09/15/us-military-confirms-it-launched-space-weapons-into-earths-orbit/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| OpenSSF – « Grow CRA Readiness: Find Your Path Through the European Union Cyber Resilience Act » | Union européenne (règlement Cyber Resilience Act) – analyse publiée par l'Open Source Security Foundation (OpenSSF) | 2026-09-15 | Union européenne | OpenSSF – « Grow CRA Readiness: Find Your Path Through the European Union Cyber Resilience Act » | L'OpenSSF publie un guide d'aide à la mise en conformité avec le Cyber Resilience Act (CRA, règlement (UE) 2024/2847), quelques jours après l'entrée en vigueur des obligations de notification des vulnérabilités activement exploitées (11 septembre 2026) et avant l'application intégrale prévue le 11 décembre 2027. L'article propose aux fabricants de produits avec éléments numériques et aux « open source software stewards » un cheminement progressif pour évaluer leur niveau de préparation : cartographie des produits, classification par niveaux de criticité, mise en place de processus de gestion des vulnérabilités et de PSIRT, documentation technique et attestations de cybersécurité. Pour l'écosystème open source, l'enjeu est de clarifier le périmètre des responsabilités (gratuité, usage commercial, rôle de steward) et de mobiliser les ressources d'appui de l'OpenSSF (guides CRA, outils de conformité). Aucun IOC malveillant n'est associé à cette publication : il s'agit d'une veille réglementaire à fort impact pour les éditeurs, fabricants et intégrateurs commercialisant des produits dans l'UE. | [https://openssf.org/blog/2026/09/15/grow-cra-readiness-find-your-path-through-the-european-union-cyber-resilience-act/](https://openssf.org/blog/2026/09/15/grow-cra-readiness-find-your-path-through-the-european-union-cyber-resilience-act/) |
| Position (UE) n° 10/2026 du Conseil du 3 septembre 2026 – CELEX:52026AG0010(01) – JO C/2026/4825 du 15.9.2026 | Conseil de l'Union européenne (procédure législative ordinaire avec le Parlement européen) | 2026-09-15 | Union européenne (texte avec pertinence EEE) | Position (UE) n° 10/2026 du Conseil du 3 septembre 2026 – CELEX:52026AG0010(01) – JO C/2026/4825 du 15.9.2026 | Le Conseil a adopté le 3 septembre 2026 sa position en première lecture (Position (UE) n° 10/2026) en vue de l'adoption d'un règlement du Parlement européen et du Conseil établissant le code des douanes de l'Union (Union Customs Code) et une Autorité douanière de l'Union européenne (European Union Customs Authority), abrogeant le règlement (UE) n° 952/2013. Le texte a été publié au Journal officiel série C (C/2026/4825) le 15 septembre 2026 (ELI : hxxp://data.europa.eu/eli/C/2026/4825/oj). Fondé sur les articles 33, 114 et 207 du TFUE, il vise à moderniser et numériser le cadre douanier de l'Union, à centraliser la gestion des données douanières au sein d'une nouvelle autorité européenne et à renforcer l'interopérabilité des systèmes douaniers nationaux. Pour la CTI, ce texte est notable : la mutualisation des données douanières et la création d'une autorité dédiée accroîtront les échanges de données sensibles (flux commerciaux, opérateurs économiques, chaînes logistiques), avec des implications en matière de cybersécurité des infrastructures douanières, de protection des données et de conformité pour les acteurs économiques. La prochaine étape est l'adoption définitive du règlement, suivie de la publication d'actes délégués et d'exécution précisant les obligations techniques. | [https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52026AG0010(02)](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52026AG0010(02))<br>[https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:32026D2060](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:32026D2060)<br>[https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52026AG0010(01)](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52026AG0010(01)) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Secteur public / administration religieuse et éducation (mosquées, madrasas) — via un fournisseur RH tiers** | Islamic Religious Council of Singapore (MUIS) — mosquées et madrasas, via le fournisseur RH Avelogic (SmartHRMS) | Données RH et de paie du personnel des mosquées et madrasas (identités, coordonnées, informations salariales) — potentiellement compromises ; périmètre exact non confirmé. | Inconnu | [https://databreaches.net/2026/09/15/payroll-system-of-mosques-madrasahs-hit-by-ransomware-staff-details-potentially-compromised/](https://databreaches.net/2026/09/15/payroll-system-of-mosques-madrasahs-hit-by-ransomware-staff-details-potentially-compromised/) |
| **Fintech / Services financiers** | Revolut | Données d'environ 680 clients : dates de naissance, adresses postales et e-mails, numéros de téléphone, copies de passeports et de permis de conduire, selfies de vérification, et dans certains cas relevés de compte et historiques de transactions. Infrastructure bancaire cœur et fonds clients non affectés. | 680 | [https://databreaches.net/2026/09/15/revoluts-paperwork-breach-shows-why-insurers-are-rethinking-what-counts-as-a-cyber-attack/](https://databreaches.net/2026/09/15/revoluts-paperwork-breach-shows-why-insurers-are-rethinking-what-counts-as-a-cyber-attack/)<br>[https://databreaches.net/2026/09/15/hackers-demand-10000-bitcoin-from-revolut-following-data-breach/](https://databreaches.net/2026/09/15/hackers-demand-10000-bitcoin-from-revolut-following-data-breach/)<br>[https://www.insurancebusinessmag.com/uk/news/cyber/revoluts-paperwork-breach-shows-why-insurers-are-rethinking-what-counts-as-a-cyber-attack-589775.aspx](https://www.insurancebusinessmag.com/uk/news/cyber/revoluts-paperwork-breach-shows-why-insurers-are-rethinking-what-counts-as-a-cyber-attack-589775.aspx)<br>[https://www.rte.ie/news/business/2026/0914/1591493-revolut-customer-data-breach-after-fake-govt-requests/](https://www.rte.ie/news/business/2026/0914/1591493-revolut-customer-data-breach-after-fake-govt-requests/)<br>[https://infosec.exchange/@edwardk/117276177984744494](https://infosec.exchange/@edwardk/117276177984744494)<br>[https://ukrmedia.news/en/science-tech/revolut-data-leak-extortion/](https://ukrmedia.news/en/science-tech/revolut-data-leak-extortion/)<br>[https://infosec.exchange/@edwardk/117276183429000480](https://infosec.exchange/@edwardk/117276183429000480) |
| **Technologie / IA — biométrie et reconnaissance faciale** | Entreprise non nommée (opérateur d'un système de reconnaissance faciale) | Images faciales (données biométriques) — plus de 9 millions ; métadonnées associées éventuelles non précisées. | 9000000 | [https://bsky.brid.gy/r/https://bsky.app/profile/did:plc:7hc3ntwii55gbipddmecsn47/post/3mvllw3qgec2y](https://bsky.brid.gy/r/https://bsky.app/profile/did:plc:7hc3ntwii55gbipddmecsn47/post/3mvllw3qgec2y) |
| **Énergie / services publics (utilities) — infrastructures critiques** | CenterPoint Energy | 7,49 millions d'enregistrements revendiqués : noms, numéros de téléphone, adresses de service et de facturation, numéros de compte, montants de facturation et numéros de Sécurité sociale partiels (SSN). Périmètre exact en cours de détermination par l'entreprise. | 7490000 | [https://cyberworldops.eu/en/centerpoint-energy-confirms-customer-data-theft-after-hacker-publishes](https://cyberworldops.eu/en/centerpoint-energy-confirms-customer-data-theft-after-hacker-publishes)<br>[https://infosec.exchange/@cyberworldops/117277025964686869](https://infosec.exchange/@cyberworldops/117277025964686869)<br>[https://osintsights.com/centerpoint-energy-breach-exposes-customer-data](https://osintsights.com/centerpoint-energy-breach-exposes-customer-data)<br>[https://infosec.exchange/@AAKL/117275807590535602](https://infosec.exchange/@AAKL/117275807590535602)<br>[https://www.securityweek.com/texas-utility-centerpoint-energy-confirms-breach-after-hacker-leaks-data/](https://www.securityweek.com/texas-utility-centerpoint-energy-confirms-breach-after-hacker-leaks-data/)<br>[https://www.sec.gov/Archives/edgar/data/1130310/000110465926107560/tm2625326d1_8k.htm](https://www.sec.gov/Archives/edgar/data/1130310/000110465926107560/tm2625326d1_8k.htm) |
| **Secteur public / soutien aux victimes (Royaume-Uni)** | Victimes, survivants et familles de l'attaque de Southport (Royaume-Uni) | Données personnelles de victimes, survivants et familles — nature et volume non disponibles dans la source. | Inconnu | [https://www.bbc.co.uk/news/articles/cr74kwn1eeyjo?at_medium=RSS&at_campaign=rss](https://www.bbc.co.uk/news/articles/cr74kwn1eeyjo?at_medium=RSS&at_campaign=rss)<br>[https://www.bbc.co.uk/news/articles/cr74kwn1eeyjo](https://www.bbc.co.uk/news/articles/cr74kwn1eeyjo) |
| **Cryptomonnaies / Sécurité des actifs numériques (hardware wallets)** | Ledger | 471 000 enregistrements clients revendiqués (nature exacte des champs non confirmée ; vraisemblablement des coordonnées clients : e-mails, noms, adresses). Aucune seed phrase ni actif crypto n'est concerné par ce type de fuite. | 471000 | [https://thecybersecguru.com/news/ledger-data-breach-2026-471000-customer-records/](https://thecybersecguru.com/news/ledger-data-breach-2026-471000-customer-records/) |
| **GovTech / Logiciels cloud pour administrations publiques** | Accela, Inc. | 1 To de données internes exfiltrées ; PII de résidents californiens : noms, numéros de Sécurité sociale (SSN), adresses, dates de naissance. Nombre exact de personnes affectées non confirmé. | Inconnu | [https://cyber.netsecops.io/articles/accela-discloses-data-breach-277-days-after-incident/](https://cyber.netsecops.io/articles/accela-discloses-data-breach-277-days-after-incident/) |
| **Télécommunications** | TELUS | Données de comptes clients consultées via des identifiants compromis sur une période de 16 mois (détail exact des champs limité dans la source) ; abus des comptes à des fins de fraude. | Inconnu | [https://thecybersecguru.com/news/telus-data-breach-2026-customer-accounts/](https://thecybersecguru.com/news/telus-data-breach-2026-customer-accounts/) |
| **Vérification d'identité / KYC (Identity Verification)** | IDScan (société de vérification d'identité - attribution circonstancielle, enquête en cours) | 153 millions de permis de conduire américains et canadiens et 3 millions de documents de voyage : photos, adresses domicile, numéros de permis, données d'identité complètes, y compris ceux de hauts fonctionnaires américains. Ingestion continue de nouveaux documents pendant plus d'un an. | 153000000 | [https://www.lawfaremedia.org/article/america%27s-drivers-licence-breach-is-a-national-security-disaster](https://www.lawfaremedia.org/article/america%27s-drivers-licence-breach-is-a-national-security-disaster) |
| **Secteur public / Administration (DMV - véhicules et sécurité routière)** | Florida Department of Highway Safety and Motor Vehicles (FLHSMV) | Plus de 200 000 enregistrements de conducteurs revendiqués par ShinyHunters ; détail exact des champs non précisé dans la source (les bases DMV contiennent typiquement identité, adresses, numéros de permis et données de véhicules). | 200000 | [https://www.bleepingcomputer.com/news/security/florida-confirms-dmv-database-breached-via-stolen-police-account/](https://www.bleepingcomputer.com/news/security/florida-confirms-dmv-database-breached-via-stolen-police-account/) |
| **Santé / Technologies de santé (e-health)** | Veradigm | Données personnelles de patients téléchargées via des identifiants volés, incluant des numéros de Sécurité sociale (SSN) ; aucune donnée clinique ou médicale impliquée. Nombre de patients affectés non précisé. | Inconnu | [https://www.netsec.news/veradigm-third-party-data-breach/](https://www.netsec.news/veradigm-third-party-data-breach/) |
| **Santé — groupe de soins médicaux multi-sites (Tennessee, États-Unis)** | Summit Medical Group, PLLC | Noms, coordonnées, données démographiques, noms de prestataires, numéros de dossier médical, dates et établissements de soins, données de traitement, informations d'assurance médicale ; les numéros de Sécurité sociale sont également cités comme potentiellement exposés. | 464000 | [https://www.defensorum.com/summit-medical-group-litigation-data-breach/](https://www.defensorum.com/summit-medical-group-litigation-data-breach/)<br>[https://mastodon.social/@defensorum/117274980485387588](https://mastodon.social/@defensorum/117274980485387588) |
| **Santé — soins dentaires (Hawaï, États-Unis)** | Hawaii Family Dental (Hawaii Dental Group, Inc.) | Informations de traitement médical et dentaire, informations d'assurance santé, dates de naissance, noms complets, numéros de téléphone, adresses postales, adresses e-mail (SSN et données de comptes financiers non impliqués selon l'organisation). | 45853 | [https://beyondmachines.net/event_details/hawaii-family-dental-reports-data-breach-impacting-45000-patients-v-1-4-q-4/gD2P6Ple2L](https://beyondmachines.net/event_details/hawaii-family-dental-reports-data-breach-impacting-45000-patients-v-1-4-q-4/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117274946648933089](https://infosec.exchange/@beyondmachines1/117274946648933089) |
| **Santé — centre de soins communautaire (États-Unis)** | Community Health Care Inc. | Numéros de Sécurité sociale, noms complets et adresses, dates de naissance et numéros de téléphone, informations d'assurance santé, dossiers de diagnostic et de traitement, identifiants patients et numéros de dossier médical, noms de prestataires et dates de service. | 808 | [https://beyondmachines.net/event_details/community-health-care-inc-reports-data-breach-after-phishing-attack-j-e-3-9-3/gD2P6Ple2L](https://beyondmachines.net/event_details/community-health-care-inc-reports-data-breach-after-phishing-attack-j-e-3-9-3/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117274474797025912](https://infosec.exchange/@beyondmachines1/117274474797025912) |
| **Fintech / paiements cryptomonnaies — processeur de paiement non custodial (Neuchâtel, Suisse)** | Swiss Bitcoin Pay | Adresses e-mail clients, adresses de portefeuilles Bitcoin, IBAN, historiques de transactions, mots de passe hachés. | Inconnu | [https://thecybersecguru.com/news/swiss-bitcoin-pay-breach/](https://thecybersecguru.com/news/swiss-bitcoin-pay-breach/)<br>[https://infosec.exchange/@thecybersecguru/117274254461912642](https://infosec.exchange/@thecybersecguru/117274254461912642)<br>[https://beyondmachines.net/event_details/swiss-bitcoin-pay-shuts-down-infrastructure-following-internal-system-breach-u-v-0-h-z/gD2P6Ple2L](https://beyondmachines.net/event_details/swiss-bitcoin-pay-shuts-down-infrastructure-following-internal-system-breach-u-v-0-h-z/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117274238915574259](https://infosec.exchange/@beyondmachines1/117274238915574259) |
| **Services de renseignement sur les personnes / reverse lookup (SaaS) — exposition cloud** | ClarityCheck | Plus de 9 millions d'images de reconnaissance faciale (~450 Go) concernant des adultes, adolescents et enfants ; via des API mal configurées : adresses e-mail, numéros de téléphone et adresses physiques potentiellement accessibles. | 9000000 | [https://info.cyberprotectllc.com/2026/09/15/9-million-facial-recognition-images-exposed-in-major-breach/](https://info.cyberprotectllc.com/2026/09/15/9-million-facial-recognition-images-exposed-in-major-breach/)<br>[https://mastodon.online/@clarinette/117277242652650405](https://mastodon.online/@clarinette/117277242652650405) |
| **Mobilité — autopartage (Montréal, Canada)** | Communauto | Noms complets, dates de naissance, adresses, numéros de téléphone, numéros de permis de conduire, contacts d'urgence, copies (images/PDF) de permis de conduire et autres documents d'identité, photos de vérification d'identité. | Inconnu | [https://beyondmachines.net/event_details/communauto-insider-incident-exposes-customer-records-through-unauthorized-script-0-7-s-q-y/gD2P6Ple2L](https://beyondmachines.net/event_details/communauto-insider-incident-exposes-customer-records-through-unauthorized-script-0-7-s-q-y/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117276126305642378](https://infosec.exchange/@beyondmachines1/117276126305642378) |
| **Secteur public — administration numérique gouvernementale (Japon)** | Agence numérique du Japon (Digital Agency) | ~236 000 noms, ~231 000 adresses e-mail, ~94 000 numéros de téléphone, ~1 000 adresses postales (numéros My Number, données bancaires et numéros de pension non affectés). | 246000 | [https://beyondmachines.net/event_details/japan-digital-agency-vpn-breach-potentially-exposes-246000-personnel-records-l-u-u-m-r/gD2P6Ple2L](https://beyondmachines.net/event_details/japan-digital-agency-vpn-breach-potentially-exposes-246000-personnel-records-l-u-u-m-r/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117275890328343838](https://infosec.exchange/@beyondmachines1/117275890328343838) |
| **Transport urbain ferroviaire (métro) - Kochi, Inde** | Kochi Metro Rail Ltd (KMRL) | Documents confidentiels internes, informations personnelles d'employés et détails de transactions financières. Non confirmé : informations relatives au poste central de contrôle, à la technologie de signalisation ferroviaire et au réseau de vidéosurveillance des stations. | Inconnu | [https://keralakaumudi.com/en/kerala/general/kochi-metro-documents-leak-whatsapp-1802961](https://keralakaumudi.com/en/kerala/general/kochi-metro-documents-leak-whatsapp-1802961)<br>[https://infosec.exchange/@edwardk/117276186316250721](https://infosec.exchange/@edwardk/117276186316250721) |
| **Gouvernemental / Documents d'identité (multi-juridictionnel, États-Unis et Canada)** | Non confirmé - bases de données de permis de conduire et documents d'identité gouvernementaux (États-Unis / Canada) | Scans de permis de conduire (environ 153 millions selon B. Krebs), cartes d'identité, documents de voyage, et centaines de milliers de dossiers médicaux, concernant des résidents des États-Unis et du Canada. | 153000000 | [https://globalnews.ca/news/12058464/drivers-license-hack-north-america-rcmp/](https://globalnews.ca/news/12058464/drivers-license-hack-north-america-rcmp/)<br>[https://mstdn.party/@GoWeaponsHot/117277432670873375](https://mstdn.party/@GoWeaponsHot/117277432670873375) |
| **Application de la loi / Organisation internationale (siège en France)** | Interpol | Documents présumés fuités d'Interpol ; nature, volume et authenticité non précisés, accès conditionné à une interaction sur le forum. | Inconnu | [https://go.darkwebsonar.io/civ-mastodon](https://go.darkwebsonar.io/civ-mastodon)<br>[https://infosec.exchange/@darkwebsonar/117275032719250834](https://infosec.exchange/@darkwebsonar/117275032719250834) |
| **Distribution alimentaire / Commerce de gros fruits et légumes - Saint-Laurent-Blangy, Hauts-de-France, France** | Rosello et Fils | Non confirmé. Exposition plausible si l'allégation est exacte : contrats clients, accords tarifaires, données fournisseurs, données logistiques et informations des employés. Aucune preuve publiée. | Inconnu | [https://www.yazoul.net/intel/claim/2026-09-15-rosello-et-fils-ransomware-claim-by-eclipse-sep-2026](https://www.yazoul.net/intel/claim/2026-09-15-rosello-et-fils-ransomware-claim-by-eclipse-sep-2026)<br>[https://infosec.exchange/@Matchbook3469/117276727372023019](https://infosec.exchange/@Matchbook3469/117276727372023019) |
| **Transport et logistique - Brésil** | Alicotrans | Non confirmé. Volume et nature des données non divulgués ; aucune preuve de compromission publiée. Exposition plausible : données clients, partenaires et employés. | Inconnu | [https://www.yazoul.net/intel/claim/2026-09-14-alicotrans-ransomware-claim-by-qilin-sept-2026](https://www.yazoul.net/intel/claim/2026-09-14-alicotrans-ransomware-claim-by-qilin-sept-2026)<br>[https://infosec.exchange/@Matchbook3469/117275063885325218](https://infosec.exchange/@Matchbook3469/117275063885325218) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-76461** | 9.8 | N/A | TRUE | Cisco Secure Email Gateway (physique et virtuel), toutes configurations confondues — AsyncOS 15.5 et antérieurs, 16.0 et 16.5 (corrigés en 15.5.5-0141, 16.0.4-3021 et 16.5.0-780). Non affectés : Secure Email and Web Manager et Secure Web Appliance. | Injection SQL (CWE-89) dans la logique d'analyse des e-mails d'AsyncOS, menant à l'exécution de commandes système avec privilèges root (CVSS 9.8, vecteur CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) | Exécution de commandes en tant que root sur l'appliance de messagerie : accès à la configuration, aux identifiants, aux données de messagerie et à la connectivité réseau ; possibilité de déployer des outils, d'établir une persistance et d'utiliser la passerelle comme point d'entrée vers le réseau interne. | Active | Mettre à jour vers 16.5.0-780 (ou 15.5.5-0141 / 16.0.4-3021 selon la branche) ; aucun contournement n'existe ; inspecter les mail_logs de chaque membre de cluster à la recherche d'instructions SQL ; surveiller les flux sortants de l'appliance et croiser avec les logs pare-feu externes ; respecter l'échéance de remédiation CISA KEV du 17/09/2026. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1175/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1175/)<br>[https://www.security.nl/posting/953050/Cisco+waarschuwt+voor+misbruik+van+kritiek+SQL+Injection-lek+in+Email+Gateway?channel=rss](https://www.security.nl/posting/953050/Cisco+waarschuwt+voor+misbruik+van+kritiek+SQL+Injection-lek+in+Email+Gateway?channel=rss)<br>[https://thehackernews.com/2026/09/cisco-secure-email-gateway-flaw.html](https://thehackernews.com/2026/09/cisco-secure-email-gateway-flaw.html)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-cisco-secure-email-products-could-allow-for-remote-code-execution_2026-096](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-cisco-secure-email-products-could-allow-for-remote-code-execution_2026-096)<br>[https://securityaffairs.com/199156/security/u-s-cisa-adds-cisco-secure-email-gateway-flaw-to-its-known-exploited-vulnerabilities-catalog.html](https://securityaffairs.com/199156/security/u-s-cisa-adds-cisco-secure-email-gateway-flaw-to-its-known-exploited-vulnerabilities-catalog.html)<br>[https://securityaffairs.com/199137/hacking/cisco-warns-of-ongoing-exploitation-of-critical-email-gateway-zero-day.html](https://securityaffairs.com/199137/hacking/cisco-warns-of-ongoing-exploitation-of-critical-email-gateway-zero-day.html)<br>[https://socprime.com/blog/cve-2026-76461-critical-cisco-secure-email-gateway-zero-day-enables-root-rce/](https://socprime.com/blog/cve-2026-76461-critical-cisco-secure-email-gateway-zero-day-enables-root-rce/)<br>[https://www.reddit.com/r/blueteamsec/comments/1whay8e/cisco_security_advisory_cisco_secure_email/](https://www.reddit.com/r/blueteamsec/comments/1whay8e/cisco_security_advisory_cisco_secure_email/) |
| **CVE-2026-20353** | N/A | N/A | FALSE | Cisco Secure Email Gateway et Cisco Secure Email and Web Manager (SEG : versions < 15.5.5-0141, < 16.0.4-302, < 16.5.0-780 ; SEWM : versions < 15.5.5-006, < 16.5.0-429, branche 16.0 sans correctif) | Gestion incorrecte de la durée de vie des ressources (consommation non contrôlée de ressources, désérialisation non sûre, initialisation incorrecte de ressources) | Déni de service à distance potentiel et affaiblissement de la posture de sécurité de la passerelle de messagerie ou de la plateforme de gestion centralisée. | None | Appliquer les correctifs Cisco des bulletins du 14 septembre 2026 (versions corrigées SEG : 15.5.5-0141, 16.0.4-302, 16.5.0-780 ; SEWM : 15.5.5-006, 16.5.0-429 ; migration obligatoire pour les branches 16.0 de SEWM). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1175/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1175/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-cisco-secure-email-products-could-allow-for-remote-code-execution_2026-096](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-cisco-secure-email-products-could-allow-for-remote-code-execution_2026-096) |
| **CVE-2026-76440** | N/A | N/A | FALSE | Cisco Secure Email Gateway et Cisco Secure Email and Web Manager (SEG : versions < 15.5.5-0141, < 16.0.4-302, < 16.5.0-780 ; SEWM : versions < 15.5.5-006, < 16.5.0-429, branche 16.0 sans correctif) | Traversée de répertoires (limitation incorrecte d'un chemin ou résolution de lien incorrecte avant accès fichier) | Lecture ou manipulation de fichiers sensibles hors du périmètre restreint, pouvant exposer des configurations, des journaux ou des identifiants. | None | Appliquer les correctifs Cisco des bulletins du 14 septembre 2026 (SEG : 15.5.5-0141, 16.0.4-302, 16.5.0-780 ; SEWM : 15.5.5-006, 16.5.0-429 ; migration obligatoire pour les branches 16.0 de SEWM). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1175/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1175/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-cisco-secure-email-products-could-allow-for-remote-code-execution_2026-096](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-cisco-secure-email-products-could-allow-for-remote-code-execution_2026-096) |
| **CVE-2026-76441** | N/A | N/A | FALSE | Cisco Secure Email Gateway et Cisco Secure Email and Web Manager (SEG : versions < 15.5.5-0141, < 16.0.4-302, < 16.5.0-780 ; SEWM : versions < 15.5.5-006, < 16.5.0-429, branche 16.0 sans correctif) | Contrôle d'accès incorrect (contournement des mécanismes d'autorisation ou d'authentification) | Contournement de l'authentification/autorisation sur l'appareil affecté, pouvant mener à un accès non autorisé aux fonctions d'administration. | None | Appliquer les correctifs Cisco des bulletins du 14 septembre 2026 (SEG : 15.5.5-0141, 16.0.4-302, 16.5.0-780 ; SEWM : 15.5.5-006, 16.5.0-429 ; migration obligatoire pour les branches 16.0 de SEWM). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1175/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1175/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-cisco-secure-email-products-could-allow-for-remote-code-execution_2026-096](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-cisco-secure-email-products-could-allow-for-remote-code-execution_2026-096) |
| **CVE-2026-76442** | N/A | N/A | FALSE | Cisco Secure Email Gateway et Cisco Secure Email and Web Manager (SEG : versions < 15.5.5-0141, < 16.0.4-302, < 16.5.0-780 ; SEWM : versions < 15.5.5-006, < 16.5.0-429, branche 16.0 sans correctif) | Validation d'entrée insuffisante (entrée numérique non bornée) entraînant une consommation excessive de ressources | Déni de service par épuisement des ressources de la passerelle ou du manager, pouvant perturber le filtrage des e-mails. | None | Appliquer les correctifs Cisco des bulletins du 14 septembre 2026 (SEG : 15.5.5-0141, 16.0.4-302, 16.5.0-780 ; SEWM : 15.5.5-006, 16.5.0-429 ; migration obligatoire pour les branches 16.0 de SEWM). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1175/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1175/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-cisco-secure-email-products-could-allow-for-remote-code-execution_2026-096](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-cisco-secure-email-products-could-allow-for-remote-code-execution_2026-096) |
| **CVE-2026-76443** | N/A | N/A | FALSE | Cisco Secure Email Gateway et Cisco Secure Email and Web Manager (SEG : versions < 15.5.5-0141, < 16.0.4-302, < 16.5.0-780 ; SEWM : versions < 15.5.5-006, < 16.5.0-429, branche 16.0 sans correctif) | Neutralisation incorrecte des entrées (injection de commandes, SQL, code/eval, ou cross-site scripting) | Exécution d'injections (commandes, SQL, code) ou de scripts cross-site à l'encontre des appliances, pouvant compromettre leur intégrité ou celle des données traitées. | None | Appliquer les correctifs Cisco des bulletins du 14 septembre 2026 (SEG : 15.5.5-0141, 16.0.4-302, 16.5.0-780 ; SEWM : 15.5.5-006, 16.5.0-429 ; migration obligatoire pour les branches 16.0 de SEWM). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1175/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1175/)<br>[https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-cisco-secure-email-products-could-allow-for-remote-code-execution_2026-096](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-cisco-secure-email-products-could-allow-for-remote-code-execution_2026-096) |
| **CVE-2026-85046** | N/A | N/A | FALSE | Google Chrome (moteur V8) et Microsoft Windows (noyau) — chaîne d'exploits navigateur puis système, exploitée avant la publication du correctif Chrome | Chaîne de trois zéro-days : confusion de type dans V8 (CVE-2026-85046) offrant lecture/écriture arbitraire dans le sandbox V8, défaut WebAssembly permettant l'évasion du sandbox V8 (CVE-2026-87491), vulnérabilité du noyau Windows permettant de sortir du processus renderer sandboxé de Chrome et d'injecter du code dans le processus navigateur (CVE-2026-85880) | Compromission complète du poste de travail (exécution de code côté client, évasion des sandbox navigateur et V8, injection dans le processus navigateur), déploiement de portes dérobées d'espionnage, vol de données et persistance au sein d'ONG ciblées ; la réutilisation de la même chaîne par deux clusters distincts suggère un risque étendu à d'autres acteurs et cibles. | Active | Appliquer dès publication les correctifs Chrome (V8) et les mises à jour de sécurité Windows ; activer les mises à jour automatiques des navigateurs et de l'OS ; sensibiliser au spearphishing avec liens via des sites légitimes compromis ; déployer un EDR avec détection des scripts JScript et des injections de processus ; restreindre et journaliser les sorties réseau. | [https://thehackernews.com/2026/09/china-linked-hackers-exploit-chrome.html](https://thehackernews.com/2026/09/china-linked-hackers-exploit-chrome.html)<br>[https://securityaffairs.com/199104/apt/one-exploit-chain-two-espionage-campaigns-chrome-and-windows-under-fire.html](https://securityaffairs.com/199104/apt/one-exploit-chain-two-espionage-campaigns-chrome-and-windows-under-fire.html) |
| **CVE-2026-87491** | N/A | N/A | FALSE | Google Chrome — deuxième étape de la chaîne d'exploits zero-day « BlueMoon » ciblant Chrome sur Windows | Évasion du bac à sable du navigateur (sandbox escape) | Sortie du confinement du navigateur, prérequis à l'injection de code dans le processus Chrome et à l'exécution de code arbitraire sur le poste de la victime. | Active | Maintenir Chrome et Windows à jour (correctifs publiés) ; bloquer le domaine de C2 ocr.opusaccel[.]top ; détecter msgbox.exe et wsc.dll ; sensibiliser au spearphishing avec liens. | [https://thehackernews.com/2026/09/china-linked-hackers-exploit-chrome.html](https://thehackernews.com/2026/09/china-linked-hackers-exploit-chrome.html) |
| **CVE-2026-85880** | N/A | N/A | FALSE | Microsoft Windows (Advanced Local Procedure Call / ALPC) — troisième étape de la chaîne d'exploits zero-day « BlueMoon » ciblant Chrome sur Windows | Abus d'ALPC Windows pour injecter du code dans le processus Chrome et obtenir l'exécution de code arbitraire | Exécution de code arbitraire sur le poste de la victime avec élévation de privilèges possible, permettant le déploiement de la porte dérobée GRIMWEDGE (reconnaissance, gestion de fichiers/processus, exécution de commandes, exfiltration de fichiers). | Active | Maintenir Windows et Chrome à jour (correctifs publiés) ; bloquer le domaine de C2 ocr.opusaccel[.]top ; détecter msgbox.exe et wsc.dll ; sensibiliser au spearphishing avec liens. | [https://thehackernews.com/2026/09/china-linked-hackers-exploit-chrome.html](https://thehackernews.com/2026/09/china-linked-hackers-exploit-chrome.html) |
| **CVE-2026-39364** | 8.2 | N/A | FALSE | Vite (serveur de développement) versions 7.1.0 à 7.3.1 et 8.0.0 à 8.0.4 lorsqu'ils sont exposés au réseau ; corrigé en 7.3.2 et 8.0.5 | Contournement de la protection server.fs.deny par manipulation de paramètres de requête (?raw, ?import&raw, ?import&url&inline) permettant la divulgation de fichiers sensibles (CVSS 8.2) | Vol de secrets en clair (clés API, mots de passe de bases de données, identifiants cloud administrateurs, états d'infrastructure) pouvant conduire à une prise de contrôle des environnements cloud (AWS/Azure), à l'espionnage et à des mouvements latéraux via les chaînes CI/CD ; la valeur de l'attaque réside dans les fichiers stockés à côté du dev server plutôt que dans le serveur lui-même. | Active | Mettre à jour Vite vers 7.3.2 ou 8.0.5 ; ne pas exposer les dev servers au-delà de localhost (éviter --host, sécuriser les mappings de ports Docker) ; restreindre l'accès par pare-feu ; retirer les secrets des répertoires servis ; auditer et faire pivoter les identifiants potentiellement exposés ; surveiller les requêtes /@fs/ avec paramètres de contournement et les User-Agent usurpés. | [https://thehackernews.com/2026/09/mass-scanning-campaign-exploits-vite.html](https://thehackernews.com/2026/09/mass-scanning-campaign-exploits-vite.html)<br>[https://fieldeffect.com/blog/mass-scanning-exposed-vite-development-servers](https://fieldeffect.com/blog/mass-scanning-exposed-vite-development-servers)<br>[https://www.f5.com/labs/articles/cloud-takeover-mass-scanning-for-exposed-vite-endpoints-cve-2026-39364](https://www.f5.com/labs/articles/cloud-takeover-mass-scanning-for-exposed-vite-endpoints-cve-2026-39364)<br>[https://www.reddit.com/r/blueteamsec/comments/1wh1s7r/cloud_takeover_mass_scanning_for_exposed_vite/](https://www.reddit.com/r/blueteamsec/comments/1wh1s7r/cloud_takeover_mass_scanning_for_exposed_vite/) |
| **CVE-2026-83408** | 8.1 | N/A | FALSE | Oracle GraalVM for JDK 17 (23.0.13.1), Oracle GraalVM for JDK 21 (23.1.12.1) et Oracle GraalVM 25.0.4.1 — composant Compiler d'Oracle Java SE | Compromission à distance via HTTP (prise de contrôle possible), difficile à exploiter | Prise de contrôle complète de l'instance Oracle GraalVM for JDK / Oracle GraalVM, avec des impacts sur la confidentialité, l'intégrité et la disponibilité (C:H/I:H/A:H). Score CVSS 3.1 : 8.1 (HIGH). | Theoretical | Appliquer les correctifs du bulletin de sécurité Oracle de septembre 2026 (Critical Patch Update) ; mettre à jour GraalVM for JDK vers les versions corrigées ; restreindre l'exposition réseau des services Java ; surveiller les tentatives d'exploitation via HTTP. | [https://cvefeed.io/vuln/detail/CVE-2026-83408](https://cvefeed.io/vuln/detail/CVE-2026-83408)<br>[https://www.oracle.com/security-alerts/cspusep2026.html](https://www.oracle.com/security-alerts/cspusep2026.html) |
| **CVE-2026-83357** | 8.1 | N/A | FALSE | Oracle GraalVM for JDK 17 (23.0.13.1), Oracle GraalVM for JDK 21 (23.1.12.1) et Oracle GraalVM 25.0.4.1 — composant Compiler d'Oracle Java SE | Compromission à distance via HTTP (prise de contrôle possible), difficile à exploiter | Prise de contrôle complète de l'instance Oracle GraalVM for JDK / Oracle GraalVM, avec des impacts sur la confidentialité, l'intégrité et la disponibilité (C:H/I:H/A:H). Score CVSS 3.1 : 8.1 (HIGH). | Theoretical | Appliquer les correctifs du bulletin de sécurité Oracle de septembre 2026 (Critical Patch Update) ; mettre à jour GraalVM for JDK vers les versions corrigées ; restreindre l'exposition réseau des services Java ; surveiller les tentatives d'exploitation via HTTP. | [https://cvefeed.io/vuln/detail/CVE-2026-83357](https://cvefeed.io/vuln/detail/CVE-2026-83357)<br>[https://www.oracle.com/security-alerts/cspusep2026.html](https://www.oracle.com/security-alerts/cspusep2026.html) |
| **CVE-2026-81855** | 9.3 | N/A | FALSE | Wärtsilä FOS-Onboard — composant « robot testing framework » (clé d'authentification client codée en dur) | Utilisation de clé cryptographique codée en dur (CWE-321) — authentification client | Un attaquant disposant de la clé codée en dur peut s'authentifier auprès du composant affecté et compromettre la confidentialité et l'intégrité des systèmes embarqués à bord (C:H/I:H/A:N en CVSS 3.1), avec un risque direct sur des systèmes de contrôle moteur critiques. | Theoretical | Supprimer les clés d'authentification client codées en dur ; mettre à jour le robot testing framework ; déployer les correctifs via le service de déploiement de correctifs ICS Wärtsilä ; appliquer une gestion sécurisée des clés (variables d'environnement, gestionnaire de secrets) ; segmenter le réseau OT. | [https://cvefeed.io/vuln/detail/CVE-2026-81855](https://cvefeed.io/vuln/detail/CVE-2026-81855)<br>[https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-02](https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-02)<br>[https://www.wartsila.com/services-catalogue/engine-services-4-stroke/wartsila-ics-patch-deployment#contact](https://www.wartsila.com/services-catalogue/engine-services-4-stroke/wartsila-ics-patch-deployment#contact) |
| **CVE-2026-78225** | 9.5 | N/A | FALSE | Wärtsilä FOS-Onboard — composant « deployer-ng Update Controller » (clé serveur codée en dur) | Utilisation de clé cryptographique codée en dur (CWE-321) — clé serveur | Compromission du mécanisme de mise à jour : un attaquant pourrait usurper le serveur de mise à jour, altérer les déploiements logiciels et obtenir des impacts étendus sur la confidentialité, l'intégrité et la disponibilité (propagation S:C), avec un risque sur des systèmes de contrôle moteur critiques. | Theoretical | Supprimer les clés cryptographiques codées en dur du code ; mettre en place une gestion sécurisée des clés avec rotation régulière ; éviter l'exposition des clés dans les journaux ; déployer les correctifs Wärtsilä (ICSA-26-258-02) ; restreindre l'accès réseau au Update Controller. | [https://cvefeed.io/vuln/detail/CVE-2026-78225](https://cvefeed.io/vuln/detail/CVE-2026-78225)<br>[https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-02](https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-02)<br>[https://www.wartsila.com/services-catalogue/engine-services-4-stroke/wartsila-ics-patch-deployment#contact](https://www.wartsila.com/services-catalogue/engine-services-4-stroke/wartsila-ics-patch-deployment#contact) |
| **CVE-2026-85921** | N/A | N/A | FALSE | Microsoft Windows 11 version 26H1 pour systèmes ARM64 et x64, versions antérieures à 10.0.28000.2956 | Élévation de privilèges | Élévation de privilèges sur les systèmes Windows 11 26H1 vulnérables, pouvant conduire à un accès avec privilèges accrus (potentiellement SYSTEM) et faciliter la persistance et le déplacement latéral d'un attaquant. | Theoretical | Appliquer la mise à jour Microsoft portant le build 10.0.28000.2956 ou supérieur (cf. bulletin MSRC CVE-2026-85921) ; prioriser les hôtes exposés et les postes à risque ; surveiller les tentatives d'élévation de privilèges. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1174/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1174/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-85921](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-85921) |
| **CVE-2026-15640** | 9.5 | N/A | FALSE | Delinea Secret Server | Contournement d'authentification par manipulation de réponse SAML | Usurpation d'identité d'utilisateurs légitimes de Secret Server via manipulation de réponse SAML, permettant un accès non autorisé aux secrets et credentials stockés, avec un potentiel de compromission en cascade de l'ensemble des systèmes dont les secrets sont gérés par le coffre-fort. | Theoretical | Appliquer les mises à jour de sécurité de Secret Server ; auditer et durcir la configuration SAML IdP ; garantir une validation stricte des réponses SAML ; tester la configuration corrigée ; surveiller les authentifications SAML anormales et les accès aux secrets. | [https://cvefeed.io/vuln/detail/CVE-2026-15640](https://cvefeed.io/vuln/detail/CVE-2026-15640) |
| **CVE-2026-76860** | 8.8 | N/A | FALSE | Netcore NR255-V firmware version 1.5.130703 | Débordement de tampon basé sur la pile (CWE-121) | Corruption de la mémoire du routeur, crash du service, et potentiellement exécution de code arbitraire avec les privilèges du processus, conduisant à la compromission complète de l'équipement réseau (interception de trafic, pivot vers le réseau interne). | Theoretical | Mettre à jour le firmware Netcore NR255-V vers la dernière version dès que le correctif est disponible ; appliquer les correctifs du fournisseur ; restreindre l'accès à l'interface d'administration ; ne pas exposer le routeur directement sur Internet. | [https://cvefeed.io/vuln/detail/CVE-2026-76860](https://cvefeed.io/vuln/detail/CVE-2026-76860)<br>[https://www.vulncheck.com/advisories/netcore-nr255-v-1.5.130703-stack-based-buffer-overflow-in-wake-up-set-cgi-via-mac-and-id-tokenization](https://www.vulncheck.com/advisories/netcore-nr255-v-1.5.130703-stack-based-buffer-overflow-in-wake-up-set-cgi-via-mac-and-id-tokenization)<br>[https://github.com/draw-ctf/netcore-router-public-refs/blob/main/2026.08.19-netcore-nr255v-wake-up-set-overflow.md](https://github.com/draw-ctf/netcore-router-public-refs/blob/main/2026.08.19-netcore-nr255v-wake-up-set-overflow.md) |
| **CVE-2026-76856** | 8.1 | N/A | FALSE | Netcore NR255-V firmware version 1.5.130703 | Cross-Site Request Forgery (CWE-352) | Modification non autorisée de la configuration WAN/LAN : redirection du trafic, modification de serveurs DNS, déni de service, ou mise en place de conditions propices à l'interception de communications. | Theoretical | Mettre à jour le firmware vers une version corrigée ; éviter de modifier les paramètres réseau depuis des sources non fiables ; sensibiliser les administrateurs ; contrôler les en-têtes Origin/Referer sur les endpoints sensibles. | [https://cvefeed.io/vuln/detail/CVE-2026-76856](https://cvefeed.io/vuln/detail/CVE-2026-76856)<br>[https://www.vulncheck.com/advisories/netcore-nr255-v-1.5.130703-cross-site-request-forgery-in-wan-lan-configuration-endpoints](https://www.vulncheck.com/advisories/netcore-nr255-v-1.5.130703-cross-site-request-forgery-in-wan-lan-configuration-endpoints)<br>[https://github.com/draw-ctf/netcore-router-public-refs/blob/main/2026.08.19-netcore-nr255v-csrf-wan-reconfig.md](https://github.com/draw-ctf/netcore-router-public-refs/blob/main/2026.08.19-netcore-nr255v-csrf-wan-reconfig.md) |
| **CVE-2026-76853** | 8.1 | N/A | FALSE | Netcore NR268 firmware version 1.7.121109 | Contournement de contrôle de sécurité - intégrité non vérifiée (CWE-353) | Contournement des restrictions sur les archives de restauration, permettant potentiellement l'injection de configurations ou de données malveillantes dans l'équipement et la compromission de son intégrité. | Theoretical | Mettre à jour le firmware vers la dernière version ; vérifier que la validation de préfixe des archives de restauration est corrigée ; restreindre l'accès aux fonctionnalités de mise à jour du firmware. | [https://cvefeed.io/vuln/detail/CVE-2026-76853](https://cvefeed.io/vuln/detail/CVE-2026-76853)<br>[https://www.vulncheck.com/advisories/netcore-nr268-1.7.121109-security-check-bypass-in-parame-put-file-cgi](https://www.vulncheck.com/advisories/netcore-nr268-1.7.121109-security-check-bypass-in-parame-put-file-cgi)<br>[https://github.com/draw-ctf/netcore-router-public-refs/blob/main/2026.08.19-netcore-nr268-restore-bypass.md](https://github.com/draw-ctf/netcore-router-public-refs/blob/main/2026.08.19-netcore-nr268-restore-bypass.md) |
| **CVE-2026-76852** | 8.8 | N/A | FALSE | Netcore NR268 firmware version 1.7.121109 | Validation d'intégrité défaillante - firmware falsifiable (CWE-354) | Chargement de firmware non autorisé ou contrefait, permettant une compromission persistante et totale du routeur (implant de backdoor au niveau du firmware, interception de tout le trafic transitant par l'équipement). | Theoretical | Mettre à jour le firmware vers la dernière version sécurisée ; vérifier l'intégrité du firmware après chaque mise à jour ; restreindre l'accès aux fonctions de mise à jour du firmware. | [https://cvefeed.io/vuln/detail/CVE-2026-76852](https://cvefeed.io/vuln/detail/CVE-2026-76852)<br>[https://www.vulncheck.com/advisories/netcore-nr268-1.7.121109-forgeable-firmware-authenticity-check-in-mtd-write](https://www.vulncheck.com/advisories/netcore-nr268-1.7.121109-forgeable-firmware-authenticity-check-in-mtd-write)<br>[https://github.com/draw-ctf/netcore-router-public-refs/blob/main/2026.08.19-netcore-nr268-firmware-forgery.md](https://github.com/draw-ctf/netcore-router-public-refs/blob/main/2026.08.19-netcore-nr268-firmware-forgery.md) |
| **CVE-2026-73807** | 9.8 | N/A | FALSE | mySCADA myPRO Manager | Absence d'autorisation (CWE-862) | Accès non autorisé aux fonctions de gestion privilégiées d'une plateforme SCADA/HMI industrielle : manipulation potentielle des processus industriels, modification de configurations, arrêt de production ou mise en danger physique des installations. | Theoretical | Sécuriser l'API en appliquant une authentification appropriée pour les fonctions privilégiées ; implémenter une authentification robuste sur tous les endpoints ; restreindre l'accès aux fonctions privilégiées selon les rôles ; valider les identifiants avant tout accès ; appliquer les correctifs publiés par mySCADA et restreindre l'exposition réseau. | [https://cvefeed.io/vuln/detail/CVE-2026-73807](https://cvefeed.io/vuln/detail/CVE-2026-73807)<br>[https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-03](https://www.cisa.gov/news-events/ics-advisories/icsa-26-258-03)<br>[https://www.myscada.org/downloads/mySCADAPROManager/](https://www.myscada.org/downloads/mySCADAPROManager/) |
| **CVE-2026-73437** | 9.6 | N/A | FALSE | Arista EOS avec relais DHCP (DHCP relay) configuré | Vérification insuffisante de l'authenticité des données (CWE-345) | Fourniture de paramètres réseau malveillants aux clients DHCP, pouvant entraîner une interception de trafic (homme du milieu via passerelle/DNS contrôlés par l'attaquant) ou un déni de service pour les clients affectés. | Theoretical | Restreindre le transfert du relais DHCP aux adresses helper de confiance uniquement ; s'assurer que les adresses helper DHCP sont configurées avec précision ; valider les adresses IP sources des réponses DHCP ; implémenter des contrôles d'accès sur les agents relais DHCP ; appliquer les correctifs EOS de l'advisory Arista. | [https://cvefeed.io/vuln/detail/CVE-2026-73437](https://cvefeed.io/vuln/detail/CVE-2026-73437)<br>[https://www.arista.com/en/support/advisories-notices/security-advisory/24712-security-advisory-0156](https://www.arista.com/en/support/advisories-notices/security-advisory/24712-security-advisory-0156) |
| **CVE-2026-61560** | 9.8 | N/A | FALSE | @zereight/mcp-gitlab versions antérieures à 2.1.27 (serveur MCP pour GitLab) | Lecture arbitraire de fichiers non authentifiée via path traversal (CWE-22) | Vol du jeton d'accès personnel GitLab (PAT), prise de contrôle complète du compte GitLab, exfiltration de code source, de secrets CI/CD et de variables de projet, et pivot possible vers les systèmes intégrés à GitLab. | Theoretical | Mettre à jour la bibliothèque @zereight/mcp-gitlab vers la version 2.1.27 ou ultérieure ; désactiver ou sécuriser le mode de transport SSE ; restreindre l'exposition réseau des serveurs MCP ; assainir les paramètres de chemin de fichiers ; faire tourner les jetons potentiellement exposés. | [https://cvefeed.io/vuln/detail/CVE-2026-61560](https://cvefeed.io/vuln/detail/CVE-2026-61560)<br>[https://github.com/zereight/gitlab-mcp/security/advisories/GHSA-cv3r-c5h8-f4g5](https://github.com/zereight/gitlab-mcp/security/advisories/GHSA-cv3r-c5h8-f4g5)<br>[https://github.com/zereight/gitlab-mcp/pull/482](https://github.com/zereight/gitlab-mcp/pull/482)<br>[https://github.com/zereight/gitlab-mcp/pull/554](https://github.com/zereight/gitlab-mcp/pull/554)<br>[https://github.com/zereight/gitlab-mcp/pull/622](https://github.com/zereight/gitlab-mcp/pull/622) |
| **CVE-2026-39987** | 9.3 | N/A | FALSE | Marimo (toutes versions, notebook Python) | Exécution de code à distance pré-authentification (RCE) via le endpoint WebSocket /terminal/ws | Compromission complète des instances Marimo exposées, vol de credentials AWS depuis l'instance et depuis Secrets Manager, accès au bastion SSH par clé privée volée, mouvement latéral dans l'infrastructure cloud, et potentiellement déploiement de listeners persistants vers des VPS contrôlés par l'attaquant. | Active | Appliquer immédiatement les correctifs Marimo pour CVE-2026-39987 ; restreindre l'exposition réseau du endpoint /terminal/ws (authentification, VPN, proxy) ; ne pas stocker de credentials AWS statiques sur les instances (privilèges minimaux, rôles IAM) ; surveiller CloudTrail et les authentifications SSH sur les bastions ; faire tourner les secrets en cas de suspicion de compromission ; pour la campagne Redis connexe, ne pas exposer Redis sur Internet et désactiver les commandes dangereuses (SLAVEOF, EVAL). | [https://thehackernews.com/2026/09/human-attacker-exploits-marimo-rce.html](https://thehackernews.com/2026/09/human-attacker-exploits-marimo-rce.html) |
| **CVE-2026-65414** | N/A | N/A | FALSE | iOS, iPadOS et macOS (iPhone, iPad, Mac) — composant Bluetooth | Exécution de code à distance (RCE) via le composant Bluetooth | Crash d'application ou exécution de code arbitraire à distance sur iPhone, iPad et Mac via le canal Bluetooth. | None | Mettre à jour vers iOS/iPadOS 27 ou 26.7, et macOS Sequoia 15.8, macOS Tahoe 26.7 ou macOS Golden Gate 27 ; désactiver le Bluetooth sur les terminaux non corrigés. | [https://www.security.nl/posting/953073/Bluetooth-lek+maakt+uitvoeren+van+code+op+iPhones+en+Macs+mogelijk?channel=rss](https://www.security.nl/posting/953073/Bluetooth-lek+maakt+uitvoeren+van+code+op+iPhones+en+Macs+mogelijk?channel=rss) |
| **CVE-2026-86890** | N/A | N/A | FALSE | iOS et iPadOS (iPhone, iPad) — Siri Suggestions | Divulgation d'informations / accès non autorisé à des données sensibles | Exposition d'informations utilisateur sensibles sans déverrouillage de l'appareil (accès physique requis). | None | Mettre à jour vers iOS/iPadOS 27 ou 26.7 ; en attendant, désactiver Siri Suggestions et l'accès à Siri depuis l'écran verrouillé. | [https://www.security.nl/posting/953073/Bluetooth-lek+maakt+uitvoeren+van+code+op+iPhones+en+Macs+mogelijk?channel=rss](https://www.security.nl/posting/953073/Bluetooth-lek+maakt+uitvoeren+van+code+op+iPhones+en+Macs+mogelijk?channel=rss) |
| **CVE-2026-27540** | N/A | N/A | FALSE | Plugin WordPress WooCommerce Wholesale Lead Capture (versions < 2.0.3.2) — environ 6 000 boutiques utilisatrices | Upload de fichiers arbitraire non authentifié menant à l'exécution de code (webshell PHP) | Compromission totale de la boutique en ligne : webshell PHP, création de comptes administrateur, vol de données, prise de contrôle complète du site. | Active | Mettre à jour le plugin en version 2.0.3.2 ; auditer le site (webshells, comptes admin frauduleux) ; bloquer l'exécution PHP dans les répertoires d'upload ; vérifier une éventuelle compromission passée. | [https://www.security.nl/posting/953068/Webwinkels+aangevallen+via+kritiek+uploadlek+in+WooCommerce-plug-in?channel=rss](https://www.security.nl/posting/953068/Webwinkels+aangevallen+via+kritiek+uploadlek+in+WooCommerce-plug-in?channel=rss) |
| **** | N/A | N/A | FALSE | LiteSpeed Web Server Enterprise, versions antérieures à 6.3.7, sur des serveurs d'hébergement mutualisé (contexte cPanel / CloudLinux avec CageFS) | Élévation de privilèges critique permettant à un utilisateur de site web à faibles privilèges d'obtenir un accès root sur l'ensemble du serveur, en contournant l'isolation des comptes (y compris CageFS) | Compromission complète du serveur d'hébergement : accès ou altération de tous les sites hébergés, vol de données multi-clients, persistance au niveau système et pivot vers d'autres infrastructures. | None | Mettre à jour LiteSpeed Enterprise vers la version 6.3.7 (mise à jour forcée disponible) ; en attendant la mise à jour, surveiller étroitement les comptes d'hébergement à faibles privilèges et les tentatives d'évasion de CageFS. | [https://securityaffairs.com/199127/security/shared-hosting-at-risk-litespeed-enterprise-bug-can-grant-root-from-a-single-tenant.html](https://securityaffairs.com/199127/security/shared-hosting-at-risk-litespeed-enterprise-bug-can-grant-root-from-a-single-tenant.html) |
| **** | N/A | N/A | FALSE | Telegram Desktop — fonctionnalité d'export HTML des discussions (les exports anciens déjà générés restent concernés) | Cross-site scripting (XSS) stocké dans la fonctionnalité d'export HTML de Telegram Desktop ; aucun identifiant CVE clairement associé dans la source | Vol de l'intégralité du contenu et des métadonnées des discussions exportées vers le serveur de l'attaquant, manipulation de la page affichée (possible hameçonnage secondaire), y compris à partir d'exports HTML anciens générés bien avant l'attaque. | Theoretical | Traiter les exports HTML comme des fichiers non fiables et les ouvrir dans un environnement isolé (sandbox, navigateur jetable) ; appliquer les mises à jour de Telegram Desktop dès la publication du correctif ; supprimer les messages suspects de bots inconnus ; éviter d'exporter des canaux contenant des messages de tiers non vérifiés ; surveiller les exfiltrations depuis les postes ayant ouvert des exports. | [https://securityaffairs.com/199076/security/telegram-desktop-flaw-could-turn-old-chat-exports-into-data-theft-traps.html](https://securityaffairs.com/199076/security/telegram-desktop-flaw-could-turn-old-chat-exports-into-data-theft-traps.html) |
| **** | N/A | N/A | FALSE | Équipement VPN desservant le Government Solution Service (GSS) de l'Agence numérique du Japon, plateforme IT mutualisée reliant 23 ministères et agences ; éditeur et identifiant CVE non divulgués | Exploitation d'une vulnérabilité d'un équipement VPN (explicitement non zero-day) suivie d'un accès authentifié avec un compte valide de maintenance/exploitation | Fuite potentielle de données personnelles d'environ 246 000 agents, fonctionnaires et prestataires répartis sur 23 ministères et agences ; risque d'exploitation ultérieure des données (hameçonnage ciblé, usurpation d'identité, accès à d'autres systèmes gouvernementaux). | Active | Corriger l'équipement VPN et appliquer sans délai les correctifs des vulnérabilités connues ; réinitialiser les identifiants de maintenance et imposer le MFA ; auditer les accès fichiers et les comptes à privilèges ; notifier les organisations utilisatrices du GSS et les personnes concernées ; renforcer la supervision des plateformes mutualisées et réduire les délais de divulgation. | [https://securityaffairs.com/199090/security/non-zero-day-vpn-flaw-left-japan-government-shared-network-platform-exposed-246000-records-at-risk.html](https://securityaffairs.com/199090/security/non-zero-day-vpn-flaw-left-japan-government-shared-network-platform-exposed-246000-records-at-risk.html) |
| **** | N/A | N/A | FALSE | Produits Apple couverts par les bulletins de sécurité Apple 148353 (17 août 2026) et 149034 à 149043 (14 septembre 2026) — détail des produits et versions non précisé dans l'avis | Multiples vulnérabilités (non détaillées dans l'avis CERT-FR) | Non détaillé dans l'avis ; les correctifs Apple couvrent généralement des vulnérabilités d'exécution de code, d'élévation de privilèges et de divulgation d'informations affectant terminaux et navigateurs. | Theoretical | Appliquer les mises à jour Apple correspondant aux bulletins 148353 et 149034 à 149043 ; suivre les recommandations CERT-FR ; maintenir les flottes Apple à jour via MDM et vérifier la conformité du parc. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1172/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1172/) |
| **** | N/A | N/A | FALSE | Microsoft Edge (multiples versions — bulletins de sécurité Microsoft Edge des 11 et 14 septembre 2026) | Multiples vulnérabilités (CVE-2026-85892, CVE-2026-87536 et notamment CVE-2026-87429 à CVE-2026-87478) | Non détaillé CVE par CVE dans l'avis ; les correctifs Edge couvrent typiquement des vulnérabilités d'exécution de code à distance, de contournement de sandbox et d'élévation de privilèges dans le navigateur. | Theoretical | Mettre à jour Microsoft Edge vers la version corrigée (canal stable de septembre 2026) ; vérifier l'application automatique des mises à jour ; suivre le bulletin MSRC correspondant ; surveiller les tentatives d'exploitation de navigateur. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1173/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1173/) |
| **** | N/A | N/A | FALSE |  |  |  |  |  |  |
| **** | N/A | N/A | FALSE |  |  |  |  |  |  |
| **** | N/A | N/A | FALSE | LiteSpeed Web Server Enterprise (versions < 6.3.7) sur serveurs d'hébergement partagé cPanel/CloudLinux | Élévation de privilèges — contournement de l'isolation des comptes d'hébergement (dont CageFS) menant à root | Un compte d'hébergement compromis ou malveillant peut accéder aux autres sites du serveur, les modifier et compromettre le serveur lui-même (privilèges root). | None | Mettre à jour manuellement vers la version 6.3.7 (/usr/local/lsws/admin/misc/lsup.sh -f -v 6.3.7), la diffusion automatique étant retardée ; reprendre ensuite les mises à jour stables. Aucun workaround ni IOC communiqué ; OpenLiteSpeed n'est pas couvert par un correctif à ce jour. | [https://thehackernews.com/2026/09/litespeed-enterprise-flaw-could-let-one.html](https://thehackernews.com/2026/09/litespeed-enterprise-flaw-could-let-one.html) |
| **** | N/A | N/A | FALSE | Nintendo Switch | Exécution de code à distance et vol de données par un attaquant à proximité (canal sans fil probable) | Exécution de code sur la console et vol de données par un attaquant à proximité. | None | Appliquer les mises à jour du firmware Nintendo dès publication ; désactiver les communications sans fil lorsque non nécessaires ; surveiller les bulletins de l'éditeur. | [https://thecyberexpress.com/nintendo-switch-vulnerability/](https://thecyberexpress.com/nintendo-switch-vulnerability/) |
| **** | N/A | N/A | FALSE | Sites WordPress d'entreprises à Singapour (cœur, plugins, thèmes) | Vulnérabilités multiples WordPress (étude de prévalence — aucun CVE spécifique identifié) | Surface d'attaque étendue des sites WordPress d'entreprises : compromission de sites, dépôt de webshells, vol de données. | None | Inventorier et mettre à jour WordPress, plugins et thèmes ; retirer les plugins non maintenus ; scanner régulièrement (ex. WPScan) ; déployer un WAF. | [https://thecyberexpress.com/wordpress-vulnerabilities-singapore-study/](https://thecyberexpress.com/wordpress-vulnerabilities-singapore-study/) |
| **** | N/A | N/A | FALSE | Microsoft Windows (suivi agrégé de 125 CVE) | Tableau de bord statistique — exposition CVE agrégée de l'éditeur (aucune vulnérabilité spécifique détaillée) | Indicateur de surface d'attaque et de rythme de correction de l'éditeur ; pas d'impact direct en soi. | None | Utiliser ces indicateurs pour prioriser le patch management Windows ; suivre MSRC et traiter en priorité les CVE critiques avec PoC public. | [https://www.valtersit.com/vendors/windows/](https://www.valtersit.com/vendors/windows/)<br>[https://mastodon.social/@hugovalters/117277026312739945](https://mastodon.social/@hugovalters/117277026312739945) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="cyberacteurs-iraniens-ciblage-de-dissidents-activistes-et-journalistes-et-usage-de-telegram-comme-c2-pour-distribuer-du-malware"></div>

## Cyberacteurs iraniens : ciblage de dissidents, activistes et journalistes et usage de Telegram comme C2 pour distribuer du malware

### Résumé

Le 15 septembre 2026, l'IC3 du FBI a publié deux alertes (Cybersecurity Advisories) consacrées aux cyberacteurs du gouvernement iranien. La première décrit le ciblage cyber de dissidents, d'activistes et de journalistes. La seconde constitue une mise à jour sur le déploiement par ces mêmes acteurs d'un canal de command and control (C2) via Telegram afin de pousser du malware vers des cibles identifiées. Les deux documents sont diffusés sous forme de PDF sur ic3.gov.

---

### Analyse opérationnelle

Les équipes SOC doivent récupérer les deux CSA et en exploiter le contenu (IOC, TTP, profils de victimes). Points de détection prioritaires : usage de Telegram comme canal C2 (connexions vers les API Telegram, téléchargements puis exécution de fichiers via l'application), avec une vigilance accrue sur les terminaux d'utilisateurs exposés (journalistes, activistes, diaspora). Règles EDR sur les processus enfants de Telegram, corrélation des IOC publiés avec les télémétries proxy/DNS/EDR, et blocage des infrastructures listées.

---

### Implications stratégiques

Ces alertes confirment la poursuite des opérations iraniennes de surveillance et de répression transnationale visant la société civile à l'étranger. Toute organisation employant, hébergeant ou partenaires de journalistes, activistes ou chercheurs sensibles doit traiter ce risque comme une menace étatique persistante. L'abus de Telegram — application légitime difficile à bloquer — illustre la tendance des acteurs étatiques à détourner des infrastructures grand public pour le C2, ce qui complique les politiques de filtrage et la détection réseau.

---

### Recommandations

* Télécharger et diffuser les deux CSA IC3 du 15/09/2026 aux équipes détection et aux populations à risque
* Restreindre et journaliser l'usage de Telegram sur les terminaux professionnels
* Déployer des détections EDR/NDR sur l'exécution de fichiers reçus via messagerie
* Sensibiliser spécifiquement journalistes, activistes et employés exposés au risque de ciblage iranien
* Signaler tout incident suspect à l'IC3 et partager les IOC avec la communauté de défense

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Récupérer et diffuser en interne les deux CSA de l'IC3 (IOC, TTP, profils de cibles)
* Identifier dans l'organisation les personnes à risque (journalistes, activistes, membres de la diaspora, chercheurs) et les sensibiliser spécifiquement
* Définir une politique MDM/application encadrant l'usage de Telegram et des messageries grand public sur les terminaux professionnels
* Former les analystes SOC aux TTP des cyberacteurs iraniens et au trafic Telegram légitime vs suspect
* Préparer des règles de blocage/réputation pour les fichiers reçus via messageries et les domaines de C2 publiés

#### Phase 2 — Détection et analyse

* Surveiller les connexions vers les API et domaines Telegram depuis les postes sensibles (api.telegram.org, t.me)
* Alerter sur tout téléchargement et exécution de fichiers transitant par Telegram (processus enfants de l'application)
* Corréler les IOC du CSA avec les télémétries proxy, DNS, EDR et passerelle de messagerie
* Détecter les communications chiffrées anormales ou persistantes vers des services de messagerie depuis des hôtes non concernés
* Suivre les signalements de comptes/bots Telegram malveillants identifiés dans les CSA

#### Phase 3 — Confinement, éradication et récupération

* Isoler du réseau les machines ayant exécuté un artefact reçu via Telegram
* Bloquer au niveau proxy/firewall les infrastructures C2 listées dans les CSA
* Révoquer sessions, tokens et identifiants potentiellement compromis
* Signaler les comptes et bots Telegram malveillants à la plateforme et conserver les preuves
* Mettre en quarantaine les fichiers suspects pour analyse

#### Phase 4 — Activités post-incident

* Mener une analyse forensique du malware déposé (capacités, persistance, exfiltration)
* Déterminer l'étendue de l'accès et les données potentiellement exfiltrées
* Informer et accompagner les personnes ciblées (mesures de protection physique et numérique)
* Partager les IOC et le contexte avec les autorités (IC3) et la communauté de défense
* Réviser les politiques d'usage des messageries et les contrôles de sécurité sur les populations à risque

#### Phase 5 — Threat Hunting (proactif)

* Chasser les arbres de processus où Telegram est parent d'un binaire exécutable
* Rechercher des mécanismes de persistance inhabituels sur les hôtes des utilisateurs ciblés
* Rechercher les connexions historiques vers les infrastructures C2 publiées dans les CSA
* Écrire des règles YARA/Sigma à partir des artefacts partagés et balayer le parc
* Vérifier les tentatives antérieures de contact/phishing visant les profils à risque (messagerie, réseaux sociaux)

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1102** | Utilisation de Telegram, service web légitime, comme canal de command and control (C2) pour pousser du malware vers des cibles identifiées |

---

### Sources

* [https://www.ic3.gov/CSA/2026/260915-2.pdf](https://www.ic3.gov/CSA/2026/260915-2.pdf)
* [https://www.ic3.gov/CSA/2026/260915.pdf](https://www.ic3.gov/CSA/2026/260915.pdf)


---

<div id="macos-27-golden-gate-analyse-du-trafic-reseau-emis-au-premier-demarrage-avant-connexion-utilisateur"></div>

## macOS 27 « Golden Gate » : analyse du trafic réseau émis au premier démarrage, avant connexion utilisateur

### Résumé

Le 15 septembre 2026, Johannes Ullrich (SANS ISC) a publié une analyse du trafic réseau généré par macOS 27 « Golden Gate » au démarrage, avant toute connexion utilisateur. Environ 300 paquets ont été capturés (volume gonflé par l'usage simultané du Wi-Fi et de l'Ethernet, chaque interface effectuant sa propre découverte DHCP/IP). Sont documentés : la découverte d'adresses dupliquées IPv6 avec ICMPv6 nonces anti-spoofing, les résolutions DNS au boot (_dns.resolver.arpa en SVCB pour la découverte de résolveurs DoH, 1-courier.push.apple.com et 1-courier.sandbox.push.apple.com pour le push Apple, albert.apple.com pour l'activation, appleid.apple.com, ipv4only.arpa pour NAT64, www.apple.com pour la détection de portail captif), quatre connexions TCP (TLS vers albert.apple.com, OCSP vers ocsp.digicert.com en HTTP port 80, TLS vers init.push.apple.com, TLS vers courier.push.apple.com port 5223), l'absence d'annonce mDNS de services, et les user-agents observés (com.apple.trustd/3.0 pour l'OCSP ; Safari signalé en version 27.0 avec un user-agent mentionnant encore « Intel Mac OS X 10_15_7 » sur une machine à CPU « M »).

---

### Analyse opérationnelle

Ce document sert de baseline de détection : les équipes SOC peuvent l'utiliser pour différencier le trafic légitime de boot d'une activité malveillante pré-authentification (implants, beacons, résolutions DNS suspectes). Points opérationnels clés : ne pas bloquer albert.apple.com (activation du device, avec certificate pinning — toute interception TLS échouera), s'attendre à de l'OCSP en HTTP clair sur le port 80, et anticiper le double DHCP lié aux interfaces multiples. Les règles NDR/IDS doivent être mises à jour pour macOS 27 afin de réduire les faux positifs et détecter les écarts.

---

### Implications stratégiques

Chaque nouvelle version d'OS modifie le comportement réseau de référence : sans mise à jour des baselines, les organisations s'exposent soit à des angles morts, soit à une inflation de faux positifs. La connaissance fine du trafic attendu reste un pilier de la détection d'anomalies, particulièrement pour les parcs macOS en croissance dans les entreprises. L'incohérence du user-agent Safari (version 27.0 sur base 10_15_7) rappelle aussi l'importance de ne pas bâtir de règles de détection fragiles sur les seuls user-agents.

---

### Recommandations

* Capturer le trafic de boot de macOS 27 dans un lab isolé et constituer une baseline interne
* Mettre à jour les règles pare-feu/NAC/IDS avec les flux Apple légitimes documentés
* Exclure albert.apple.com de l'interception TLS (certificate pinning)
* Alerter sur toute connexion réseau pré-login ne correspondant pas à la baseline
* Réviser les baselines à chaque mise à jour majeure d'OS

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Constituer des images de référence macOS 27 et capturer le trafic de démarrage dans un lab isolé pour chaque nouvelle version de l'OS
* Documenter les résolutions DNS et connexions TLS légitimes au boot (albert.apple.com, services push Apple, OCSP) comme baseline de référence
* Configurer les pare-feu/NAC pour autoriser explicitement les flux Apple d'activation et de push documentés
* Exclure albert.apple.com de toute interception TLS (certificate pinning) dans les appliances de inspection

#### Phase 2 — Détection et analyse

* Comparer le trafic de boot observé à la baseline publiée et alerter sur toute résolution DNS ou connexion TLS inattendue avant login
* Surveiller les tentatives de connexion vers des domaines imitant les domaines Apple légitimes (albert.apple.com, courier.push.apple.com)
* Alerter sur un volume de paquets de boot anormalement élevé ou des interfaces réseau inactives qui s'activent seules

#### Phase 3 — Confinement, éradication et récupération

* Bloquer immédiatement tout domaine/IP non référencé dans la baseline contacté au démarrage
* Isoler tout hôte émettant du trafic réseau anormal avant l'authentification utilisateur

#### Phase 4 — Activités post-incident

* Documenter les écarts constatés entre le trafic observé et la baseline macOS 27
* Mettre à jour la baseline et les règles de détection après chaque mise à jour majeure de l'OS
* Analyser tout binaire ou configuration modifiée ayant pu altérer le comportement réseau au boot

#### Phase 5 — Threat Hunting (proactif)

* Rechercher sur le parc les hôtes établissant des connexions TLS non-Apple avant login utilisateur
* Chasser les résolutions DNS de domaines proches des domaines Apple légitimes (typosquatting)
* Vérifier l'absence de services mDNS inattendus annoncés sur le port 5353/udp
* Contrôler la cohérence des user-agents observés (com.apple.trustd/3.0, Safari 27.0) avec la baseline

---

### Sources

* [https://isc.sans.edu/diary/rss/33340](https://isc.sans.edu/diary/rss/33340)


---

<div id="persistance-macos-via-manconf-preuve-de-concept-dune-execution-pilotee-par-configuration"></div>

## Persistance macOS via man.conf : preuve de concept d'une exécution pilotée par configuration

### Résumé

Le 15 septembre 2026, le chercheur « cocomelonc » a publié la 13e partie de sa série sur la persistance macOS, démontrant une technique via /private/etc/man.conf. L'utilitaire man lit ce fichier, qui peut définir via la directive MANPAGER le programme utilisé pour afficher les pages de manuel : en pointant MANPAGER vers un payload (ici un binaire C compilé dans /Users/Shared/meow écrivant une preuve d'exécution dans /tmp/meow.txt), le payload s'exécute lorsque l'utilisateur invoque man. La modification du fichier global requiert des privilèges root et le déclenchement dépend de l'utilisateur lançant la commande (mécanisme événementiel, non lié au login). L'auteur précise que la technique a été documentée publiquement mais jamais démontrée en pratique, et qu'il n'existe aucune attribution confirmée à un groupe APT ou une famille de malware.

---

### Analyse opérationnelle

Pour les équipes bleues : surveiller l'intégrité de /private/etc/man.conf et alerter sur toute directive MANPAGER inhabituelle ; détecter l'exécution de binaires depuis /Users/Shared et les arbres de processus où man est parent d'un exécutable inattendu. Le prérequis root signifie qu'une telle persistance indique une élévation de privilèges antérieure — à corréler avec les alertes sudo/ESCALATION. Pour les équipes rouges, c'est une primitive de persistance discrète, hors des chemins classiques LaunchAgents/cron, utile pour tester la couverture de détection macOS.

---

### Implications stratégiques

Cette publication illustre l'élargissement de la surface d'attaque macOS vers des mécanismes de persistance de niche, difficiles à couvrir avec les règles génériques orientées LaunchAgents/LaunchDaemons. Les organisations fortement équipées en Mac doivent investir dans la visibilité des modifications de fichiers de configuration système et dans un EDR macOS mature. L'absence d'attribution connue n'exclut pas un usage futur par des acteurs de menace : la technique est désormais démontrée publiquement et peut être reprise par des opérateurs réels ou des frameworks offensifs.

---

### Recommandations

* Déployer un contrôle d'intégrité de fichiers sur /private/etc/man.conf
* Alerter sur toute directive MANPAGER pointant hors des pagineurs standards (less, more, etc.)
* Restreindre l'exécution de binaires depuis /Users/Shared et autres répertoires inscriptibles
* Vérifier la couverture EDR macOS sur les processus enfants de man
* Inclure les mécanismes de persistance par configuration dans les scénarios de tests d'intrusion et de threat hunting internes

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer la surveillance d'intégrité de fichiers (FIM) sur /private/etc/man.conf et les fichiers de configuration système macOS
* Restreindre et journaliser l'usage des privilèges root/sudo sur les postes macOS
* S'assurer de la couverture EDR des hôtes macOS (processus, modifications de fichiers système)
* Sensibiliser les équipes à la persistance macOS hors LaunchAgents/LaunchDaemons (mécanismes de configuration)

#### Phase 2 — Détection et analyse

* Alerter sur toute modification de /private/etc/man.conf, notamment l'ajout ou la modification d'une directive MANPAGER
* Détecter l'exécution de binaires depuis des répertoires non standards comme /Users/Shared
* Surveiller les arbres de processus où man est parent d'un exécutable inattendu
* Corréler les modifications de man.conf avec une élévation de privilèges récente

#### Phase 3 — Confinement, éradication et récupération

* Restaurer /private/etc/man.conf depuis une copie saine connue ou une image de référence
* Supprimer les binaires malveillants identifiés (ex. binaires déposés dans /Users/Shared)
* Isoler l'hôte compromis du réseau
* Révoquer et renouveler les identifiants et secrets accessibles depuis le compte compromis

#### Phase 4 — Activités post-incident

* Déterminer le vecteur d'accès initial et le chemin d'élévation de privilèges ayant permis la modification du fichier système
* Rechercher d'autres mécanismes de persistance sur l'hôte (LaunchAgents, cron, PAM, etc.)
* Documenter l'incident et renforcer les contrôles FIM et EDR sur les fichiers de configuration
* Partager les artefacts et règles de détection avec les équipes de détection et la communauté

#### Phase 5 — Threat Hunting (proactif)

* Balayer le parc macOS à la recherche de valeurs MANPAGER non standards dans /private/etc/man.conf
* Rechercher les exécutions historiques de binaires depuis /Users/Shared
* Chasser les processus enfants de man anormaux dans les télémétries EDR
* Comparer les fichiers man.conf des hôtes à une copie de référence d'installation propre

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1546** | Event Triggered Execution : détournement de la directive MANPAGER dans /private/etc/man.conf pour exécuter un payload lorsque l'utilisateur invoque la commande man |

---

### Sources

* [https://cocomelonc.github.io/macos/2026/09/15/mac-malware-persistence-13.html](https://cocomelonc.github.io/macos/2026/09/15/mac-malware-persistence-13.html)


---

<div id="levolution-de-lidentite-etendre-liam-aux-personnes-aux-machines-et-aux-agents-ia"></div>

## L'évolution de l'identité : étendre l'IAM aux personnes, aux machines et aux agents IA

### Résumé

Le 15 septembre 2026, GuidePoint Security a publié un article (Elizabeth Strickland, avec contributions de Randall Gamby, James Hauswirth et Kevin Converse) sur l'expansion du périmètre de la gestion des identités et des accès (IAM). L'article soutient que l'IAM ne porte plus seulement sur « qui a accès » mais sur « quoi a accès et que peut faire cette identité » : les deepfakes et identités synthétiques compliquent l'établissement de confiance dans les personnes, les identités non humaines (NHI) se multiplient dans les applications, l'infrastructure et le cloud, et l'IA agentique introduit des identités capables de décider, d'invoquer des workflows et d'agir de manière autonome sans intervention humaine. Trois disciplines sont présentées comme composantes d'une stratégie IAM moderne : la vérification d'identité (IDV) pour établir la confiance, les programmes NHI pour gouverner ce qui a accès, et la sécurité de l'IA agentique pour encadrer ce que les identités autonomes peuvent faire. Un expert souligne que des programmes matures (revues d'accès, RBAC, MFA) restent attaqués avec succès car leurs contrôles sont construits autour du « compte » et non de la « personne derrière ».

---

### Analyse opérationnelle

Concrètement pour les équipes : établir un inventaire exhaustif des identités non humaines (comptes de service, clés API, workload identities) avec propriétaire et cycle de vie ; étendre les revues d'accès aux NHI ; déployer une MFA résistante au phishing et renforcer l'IDV sur les événements critiques (onboarding, transactions à risque) face aux deepfakes ; mettre en place une détection des anomalies comportementales sur les comptes de service et une gouvernance des permissions des agents IA (périmètres d'action, approbations humaines pour les actions sensibles) ; déployer des capacités ITDR pour détecter l'abus d'identités légitimes.

---

### Implications stratégiques

L'identité devient le nouveau périmètre de sécurité : la prolifération des NHI et l'arrivée d'agents IA autonomes créent une surface d'attaque que l'IAM traditionnel centré sur les humains ne couvre plus. Les risques business incluent la fraude par deepfake ciblant les processus financiers et RH, l'abus de comptes de service surexposés comme vecteur d'intrusion majeur, et des actions autonomes d'IA hors de contrôle pouvant causer des incidents à grande échelle. Les organisations doivent arbitrer des investissements en gouvernance des identités machines, ITDR et vérification d'identité renforcée, et intégrer la sécurité de l'IA agentique dans leurs programmes de risque avant généralisation de ces agents en production.

---

### Recommandations

* Réaliser un inventaire complet des identités non humaines avec propriétaire et cycle de vie définis
* Étendre les revues d'accès et le RBAC aux identités machines et aux agents IA
* Déployer une MFA résistante au phishing et renforcer la vérification d'identité sur les événements à haut risque
* Mettre en œuvre des capacités ITDR pour détecter l'abus d'identités légitimes
* Définir un cadre de gouvernance pour les agents IA autonomes (permissions, approbations humaines, journalisation)

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier toutes les identités : humaines, non humaines (comptes de service, clés API, workload identities) et agents IA
* Attribuer un propriétaire et un cycle de vie à chaque identité non humaine
* Déployer une MFA résistante au phishing et des processus de vérification d'identité (IDV) renforcés pour les événements critiques
* Définir des politiques de permissions et d'approbation pour les actions autonomes des agents IA
* Mettre en place des capacités ITDR (Identity Threat Detection and Response)

#### Phase 2 — Détection et analyse

* Détecter les anomalies comportementales sur les comptes de service et identités non humaines (heures, volumes, ressources accédées)
* Alerter sur les tentatives d'ingénierie sociale assistée par IA ou deepfake lors des authentifications et transactions à risque
* Surveiller les actions des agents IA sortant de leur périmètre ou rôle autorisé
* Détecter les secrets et clés API exposés dans les dépôts de code, pipelines ou variables d'environnement

#### Phase 3 — Confinement, éradication et récupération

* Révoquer ou suspendre immédiatement les identités compromises (humaines et non humaines)
* Effectuer une rotation des secrets, clés API et certificats associés aux identités affectées
* Suspendre ou restreindre les agents IA autonomes impliqués dans un comportement anormal
* Imposer une réauthentification forte sur les sessions à risque

#### Phase 4 — Activités post-incident

* Mener un post-mortem sur l'abus d'identité (vérification d'identité contournée, NHI détournée, agent IA abusé)
* Réviser les modèles de permissions et les revues d'accès pour intégrer les identités non humaines
* Ajuster la gouvernance des agents IA (périmètres d'action, approbations humaines)
* Mettre à jour les procédures IDV pour les événements à haut risque (onboarding, transactions sensibles)

#### Phase 5 — Threat Hunting (proactif)

* Chasser les usages de comptes de service incohérents avec leur fonction d'origine
* Rechercher les identités non humaines sans propriétaire ou sans revue d'accès récente
* Rechercher les authentifications réussies suite à des signaux de vérification d'identité faibles ou contournés
* Auditer les journaux d'actions des agents IA pour des workflows invoqués hors de leur usage prévu

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078** | Valid Accounts : abus d'identités légitimes, y compris les identités non humaines (comptes de service, clés API) et les agents IA autonomes, pour accéder aux ressources |

---

### Sources

* [https://www.guidepointsecurity.com/blog/evolution-of-identity-extending-iam/](https://www.guidepointsecurity.com/blog/evolution-of-identity-extending-iam/)


---

<div id="google-doc-avec-sidebar-malveillante-amos-sur-macos-et-loader-powershell-sur-windows-via-des-dm-x"></div>

## Google Doc avec sidebar malveillante : AMOS sur macOS et loader PowerShell sur Windows via des DM X

### Résumé

Des chercheurs de Huntress ont été ciblés en fin de DEFCON via des DM X par un compte se faisant passer pour le VP/Head of Marketing de CoinDesk, utilisant le nom d'une personne et la photo d'une autre. Le compte @HartmansDoeke a contacté plusieurs chercheurs en sécurité avec un leurre générique de conférence crypto ; des signalements publics de comportement scam remontent à octobre 2025, ce que Huntress qualifie de « volume play » plutôt que de ciblage spécifique. La victime reçoit un lien vers un Google Doc légitime accompagné d'une « clé d'accès » : une sidebar (Google Apps Script lié au document) affiche un faux échec de déchiffrement avec des instructions de remédiation selon l'OS, invitant à copier-coller des commandes dans le Terminal (leurre ClickFix) ou à cliquer sur un bouton « manual update ». Sur macOS la charge est l'infostealer AMOS, sur Windows une chaîne de loader PowerShell. Le script s'exécute côté client dans le navigateur sans prompt de consentement OAuth, collecte l'IP publique, la géolocalisation et détecte les wallets MetaMask/Ethereum, Phantom, Tron et Solana, puis envoie les données à l'acteur via l'API Telegram (codes d'action, dont VIEW qui signale la simple ouverture du document connecté). Le chercheur n'a rien exécuté ; l'acteur a ensuite envoyé d'autres malwares puis une offre d'un million de dollars, et un certificat CA rogue a fini dans l'environnement de test de Huntress.

---

### Analyse opérationnelle

Point critique : la simple ouverture du document en étant connecté, sans cliquer ni télécharger, suffit à fuiter l'IP et la géolocalisation via un beacon Telegram (code VIEW). Pour le SOC : surveiller l'egress vers api.telegram[.]org depuis les postes et navigateurs, alerter sur les Google Docs embarquant des Apps Scripts aux comportements inhabituels, détecter les commandes ClickFix collées dans Terminal/PowerShell (téléchargements, iex, osascript), et chasser les binaires AMOS (macOS) et loaders PowerShell. Surface d'attaque particulière : le vecteur utilise un domaine légitime (docs.google[.]com), invisible pour les passerelles mail/url basées sur la réputation. Mesures : sensibilisation anti-ClickFix, restriction des extensions de wallets sur les postes pro, analyse des documents non sollicités en VM isolée sans session SSO, monitoring des certificats racine installés.

---

### Implications stratégiques

La campagne illustre la tendance « living off trusted services » : exploitation de Google Workspace comme infrastructure d'attaque, contournant la réputation de domaine et les filtres classiques. Le ciblage en volume de la communauté sécurité/crypto post-conférences (Black Hat/DEFCON), les tentatives de corruption (offre d'un million de dollars) et le déploiement d'une CA rogue en laboratoire signalent une escalade visant spécifiquement les défenseurs. Risques : vol de wallets et de sessions, compromission d'analystes, atteinte réputationnelle. Décisionnel : revoir les politiques d'ouverture de documents externes, investir dans la détection comportementale navigateur et la visibilité egress, et encadrer les pratiques OSINT des équipes de recherche.

---

### Recommandations

* Sensibiliser aux leurres ClickFix et aux documents externes avec scripts intégrés
* Surveiller et restreindre le trafic sortant vers l'API Telegram depuis les postes non justifiés
* Détecter l'exécution de Google Apps Script côté navigateur et alerter sur les sidebars demandant des actions système
* Déployer des règles de détection pour AMOS et les loaders PowerShell post-événements de conférence
* Imposer l'analyse de contenus non sollicités sur des postes dédiés et isolés, sans session Google

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser utilisateurs et chercheurs aux leurres ClickFix et aux DM de « recruteurs/marketing » post-conférence
* Journaliser côté proxy/DNS les accès à docs.google[.]com et api.telegram[.]org depuis le parc
* Déployer des couvertures EDR macOS (AMOS) et Windows (loaders PowerShell) avec politiques de blocage
* Restreindre l'usage de wallets crypto et d'extensions navigateur sur les postes d'entreprise
* Définir une procédure d'analyse de documents externes en environnement isolé (VM sans SSO ni session Google)

#### Phase 2 — Détection et analyse

* Alerter sur les beacons vers l'API Telegram émis depuis des navigateurs ou postes utilisateurs
* Détecter les commandes collées dans Terminal/PowerShell typiques de ClickFix (curl hxxp, iex, osascript, encodage base64)
* Surveiller les ouvertures de Google Docs externes contenant des Apps Scripts et les fuites d'IP/géolocalisation qui suivent
* Corréler les signalements de comptes X usurpant des marques avec les campagnes en cours
* Vérifier la présence d'artefacts AMOS (LaunchAgents, accès Keychain) et de loaders PowerShell

#### Phase 3 — Confinement, éradication et récupération

* Isoler les postes ayant ouvert le document ou exécuté des commandes
* Révoquer et renouveler les sessions et jetons exposés (SSO, Google, extensions de wallets)
* Bloquer les infrastructures de distribution identifiées et restreindre l'egress Telegram non justifié
* Faire migrer les wallets exposés vers des adresses neuves si des seed phrases ont pu être saisies
* Supprimer les LaunchAgents/binaires AMOS et les mécanismes de persistance PowerShell

#### Phase 4 — Activités post-incident

* Documenter l'étendue de la fuite (IP, géolocalisation, wallets, credentials navigateur)
* Partager IOC et TTP avec la communauté (ISAC, CERT) et signaler le compte X usurpé
* Réviser les politiques d'ouverture de documents tiers et la formation anti-phishing
* Évaluer l'efficacité des contrôles EDR/proxy face au vecteur « SaaS de confiance »

#### Phase 5 — Threat Hunting (proactif)

* Chasser les requêtes POST vers api.telegram[.]org avec des payloads JSON inhabituels
* Rechercher les exécutions PowerShell encodées ou les téléchargements depuis des domaines récents
* Sur macOS, chercher les artefacts AMOS (processus infostealer, accès Keychain anormaux)
* Identifier les ouvertures de Google Docs externes suivies de connexions Telegram dans la même fenêtre temporelle
* Vérifier l'installation de certificats racine inattendus (CA rogue) sur les postes d'analyse

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `api.telegram[.]org` | Low |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Spearphishing Link : DM sur X contenant un lien vers un Google Doc légitime piégé |
| **T1204.004** | Malicious Copy and Paste : leurre ClickFix invitant à coller des commandes dans le Terminal ou à cliquer sur un bouton « manual update » |
| **T1059.007** | JavaScript/JScript : Google Apps Script lié au document exécuté côté client dans le navigateur, sans prompt de consentement OAuth |
| **T1567.002** | Exfiltration Over Web Service : envoi de l'IP publique, de la géolocalisation et des données de wallets vers l'acteur via l'API Telegram |

---

### Sources

* [https://www.huntress.com/blog/google-doc-sidebar-malware-mac-windows](https://www.huntress.com/blog/google-doc-sidebar-malware-mac-windows)


---

<div id="resetspy-enumeration-des-comptes-et-des-methodes-mfa-via-le-portail-sspr-de-microsoft"></div>

## ResetSpy : énumération des comptes et des méthodes MFA via le portail SSPR de Microsoft

### Résumé

ResetSpy est un outil open source (Python) qui interroge le endpoint SSPR (Self-Service Password Reset) de Microsoft pour énumérer des comptes et les méthodes de vérification enregistrées, et signaler celles qui n'ont pas de second facteur fort ; il fournit une approximation de la posture MFA des comptes Entra ID. Le projet note qu'en août 2026 Microsoft a retiré le CAPTCHA legacy du flux SSPR, remplacé par du throttling backend et de la détection comportementale d'abus (référence MC1400824). L'outil prend en charge proxy, export CSV, délais avec jitter, back-off exponentiel sur les réponses 429 et rotation de 16 User-Agents courants. Du fait de l'enregistrement combiné (défaut depuis 2020), les méthodes visibles via SSPR reflètent généralement celles qui protègent la connexion. Limites documentées : FIDO2 et l'authentification par certificat ne sont pas couverts (faux négatifs possibles), les comptes guest/fédérés et les comptes où SSPR est désactivé ne sont pas entièrement visibles.

---

### Analyse opérationnelle

L'outil démontre que le endpoint SSPR permet à un attaquant non authentifié de confirmer l'existence de comptes et de cartographier leur couverture MFA, prérequis typique des campagnes de password spraying et de push bombing. Côté défense : surveiller les journaux SSPR/Sign-in pour des volumes anormaux, des codes 429 répétés et des User-Agents rotatifs ; activer smart lockout et throttling ; auditer la couverture MFA forte (FIDO2/CBA) et corriger les comptes sans second facteur ; homogénéiser les politiques de méthodes entre SSPR et MFA. ResetSpy peut être utilisé en interne, avec autorisation, pour auditer sa propre surface d'énumération et valider les contrôles.

---

### Implications stratégiques

L'énumération préalable est un multiplicateur de risque : une cartographie précise des comptes sans MFA fort permet des intrusions initiales ciblées et des attaques de type MFA fatigue. Le retrait du CAPTCHA au profit de contrôles backend déplace la responsabilité vers les protections du fournisseur ; les organisations ne doivent pas s'y fier seules. Enjeu de gouvernance : la qualité du registre des méthodes d'authentification devient un indicateur de risque à part entière, à intégrer dans les programmes de gestion des identités et dans les rapports aux directions.

---

### Recommandations

* Auditer la couverture MFA forte (FIDO2/CBA) et cibler en priorité les comptes sans second facteur
* Surveiller les journaux SSPR/Sign-in pour des patterns d'énumération (volumes, 429, User-Agents rotatifs)
* Activer le smart lockout et les protections anti-password spraying
* Restreindre SSPR aux populations nécessaires et aligner les politiques de méthodes SSPR/MFA
* Tester sa surface d'énumération en interne via un exercice red team autorisé

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les comptes Entra ID et leurs méthodes d'authentification enregistrées
* Activer l'enregistrement combiné et centraliser les journaux SSPR/Sign-inLogs dans le SIEM
* Définir des politiques de méthodes autorisées en privilégiant FIDO2, CBA et Authenticator
* Configurer le smart lockout et revoir les seuils de throttling côté tenant

#### Phase 2 — Détection et analyse

* Alerter sur les volumes anormaux de requêtes SSPR et les codes 429 répétés (signe d'énumération automatisée)
* Détecter la rotation de User-Agents et l'usage de proxies sur le flux SSPR
* Corréler l'énumération SSPR avec des campagnes ultérieures de password spraying ou de MFA fatigue

#### Phase 3 — Confinement, éradication et récupération

* Bloquer ou throttler les adresses IP sources d'énumération via Conditional Access et listes de blocage
* Désactiver temporairement SSPR pour les populations ciblées si nécessaire
* Forcer la ré-authentification et le ré-enregistrement des méthodes des comptes exposés

#### Phase 4 — Activités post-incident

* Déterminer quels comptes ont été énumérés et leur posture MFA réelle
* Corriger les comptes sans facteur fort et homogénéiser les politiques SSPR/MFA
* Documenter l'incident et ajuster les seuils de détection

#### Phase 5 — Threat Hunting (proactif)

* Chasser les requêtes SSPR ciblant des utilisateurs inexistants pour repérer les tentatives de différentiation
* Rechercher les comptes ne disposant que de méthodes faibles (email/SMS) exposés à l'énumération
* Vérifier les tentatives de réinitialisation de mot de passe anormales sur les comptes énumérés

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1087.004** | Cloud Account Discovery : énumération de comptes Entra ID et de leurs méthodes de vérification via le endpoint SSPR |

---

### Sources

* [https://github.com/mlcsec/ResetSpy](https://github.com/mlcsec/ResetSpy)


---

<div id="0xcr0sscrush-deux-drivers-signes-vulnerables-dcrcvdrvsys-alinubxsys-abuses-par-le-loader-maas-cruciferra"></div>

## 0xCr0ssCrush : deux drivers signés vulnérables (DCRCVDrv.sys, Alinubx.sys) abusés par le loader MaaS Cruciferra

### Résumé

Le projet de recherche 0xCr0ssCrush documente deux drivers Windows signés vulnérables — DCRCVDrv.sys (MOCOMSYS/DCRC) et Alinubx.sys (CnCrypt) — abusés par le loader Malware-as-a-Service Cruciferra, documenté par eSentire TRU le 19 août 2026 comme terminant les processus AV/EDR avant la livraison du payload. DCRCVDrv.sys expose le device \\.\DCRCVDRV_U avec l'IOCTL 0x2205C0 (PID sur 4 octets) menant à ZwTerminateProcess ; Alinubx.sys expose \\.\Alinubx avec l'IOCTL 0x222024 ({pid, exit_status}) via PsLookupProcessByProcessId, ObOpenObjectByPointer puis ZwTerminateProcess. Les deux drivers exposent la même famille de primitive (PROCESS_CONTROL / PROCESS_TERMINATION). Aucun des deux fichiers ne figurait dans la blocklist Microsoft des drivers vulnérables au 8 septembre 2026 (entrées LOLDrivers du 27 août 2026). Le harness reproduit la tactique de redondance des opérateurs : si un driver est refusé par l'hôte, il bascule sur l'autre.

---

### Analyse opérationnelle

Détection : surveiller le chargement de DCRCVDrv.sys et Alinubx.sys (Sysmon Event ID 6/7, hashes à ajouter aux blocklists et à WDAC), la création des devices \\.\DCRCVDRV_U et \\.\Alinubx, et les IOCTL 0x2205C0/0x222024 émis depuis des processus non légitimes. Alerter sur la terminaison anormale des processus AV/EDR (exit codes inhabituels, morts corrélées à l'installation d'un driver). Vérifier que la blocklist Microsoft est en mode enforced et à jour. Surface d'attaque : tout poste Windows où un processus avec privilèges admin peut charger un driver signé. Mesures : activer HVCI/VBS, restreindre le chargement de drivers non nécessaires, surveiller les services de drivers récemment créés.

---

### Implications stratégiques

Le BYOVD demeure un pilier des chaînes MaaS pour neutraliser les EDR avant la livraison du payload ; la redondance multi-drivers témoigne de l'industrialisation et de la résilience des kits malveillants. L'absence des deux drivers de la blocklist Microsoft au moment de la recherche illustre le décalage entre l'abus observé in the wild et la mise à jour des défenses centralisées. Risque business : une EDR neutralisée ouvre la voie à un déploiement de ransomware ou d'infostealer sans détection. Décisionnel : ne pas dépendre uniquement de la blocklist du fournisseur ; investir dans le durcissement local (HVCI, contrôle des drivers signés) et la détection comportementale kernel.

---

### Recommandations

* Ajouter les hashes de DCRCVDrv.sys et Alinubx.sys aux blocklists et à la politique WDAC
* Activer HVCI/VBS et la Microsoft vulnerable driver blocklist en mode enforced
* Alerter sur la création des devices \\.\DCRCVDRV_U et \\.\Alinubx et sur les IOCTL de terminaison
* Surveiller la terminaison anormale des processus EDR/AV et les services de drivers récents
* Suivre LOLDrivers et eSentire TRU pour les mises à jour sur Cruciferra

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir la blocklist Microsoft des drivers vulnérables à jour et en mode enforced
* Activer HVCI/VBS et la journalisation Sysmon (chargement de drivers, création de devices)
* Inventorier les drivers signés présents dans le parc et les comparer à LOLDrivers
* Définir des alertes sur la terminaison anormale des processus de sécurité

#### Phase 2 — Détection et analyse

* Détecter le chargement de DCRCVDrv.sys et Alinubx.sys (hash, nom de service, Event ID 6/7 Sysmon)
* Alerter sur l'ouverture des devices \\.\DCRCVDRV_U et \\.\Alinubx et sur les IOCTL 0x2205C0 / 0x222024
* Corréler la mort inexpliquée de processus EDR/AV avec l'installation récente d'un driver

#### Phase 3 — Confinement, éradication et récupération

* Isoler les hôtes où un driver vulnérable a été chargé
* Supprimer le service/driver, bloquer le binaire par hash et empêcher son rechargement
* Redémarrer les agents EDR et vérifier l'intégrité des protections avant reprise d'activité

#### Phase 4 — Activités post-incident

* Rechercher le payload livré après la terminaison des EDR (loaders, ransomware, infostealer)
* Analyser la persistance et les privilèges admin utilisés pour installer le driver
* Partager les hashes et TTP avec les communautés de défense (ISAC, LOLDrivers)

#### Phase 5 — Threat Hunting (proactif)

* Chasser les services de drivers récemment créés aux noms ou hashes inconnus
* Rechercher les processus user mode émettant des DeviceIoControl vers des devices non standard
* Identifier les hôtes où des processus de sécurité se sont terminés avec des exit codes inhabituels
* Comparer l'inventaire drivers au snapshot de la blocklist Microsoft pour repérer les absents

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1068** | Exploitation for Privilege Escalation : abus de drivers signés vulnérables (BYOVD) pour obtenir un contrôle kernel |
| **T1562.001** | Impair Defenses : terminaison des processus AV/EDR avant livraison du payload via IOCTL en user mode |
| **T1553.005** | Subvert Trust Controls: Code Signing : exploitation de drivers légitimement signés pour contourner les contrôles de chargement |

---

### Sources

* [https://github.com/DeathShotXD/0xCr0ssCrush/](https://github.com/DeathShotXD/0xCr0ssCrush/)


---

<div id="sindrikit-v200-framework-c-reorganise-autour-des-couches-abi-windows-syscalls-et-injection"></div>

## SindriKit v2.0.0 : framework C réorganisé autour des couches ABI Windows, syscalls et injection

### Résumé

SindriKit v2.0.0 est la première rupture de version majeure d'un framework C open source destiné à découpler la logique des techniques de leur mécanique d'exécution. Cette version introduit une stratification ABI Windows (internal/windows, internal/win32, internal/nt) sans inclusion implicite de <windows.h>, un système de statuts facility-encoded (snd_status_t via SND_MAKE_STATUS), une primitive fichier unifiée avec backends Win32, NTDLL et syscall (NtCreateFile, NtReadFile, NtQueryInformationFile), un parser d'environnement NTDLL gérant l'image PEB active et une image propre mappée pour la découverte de numéros de service système et de gadgets, une architecture PoC unifiée (unified load, unified inject, unified hg) et la création de processus NT native via NtCreateUserProcess. Changements breaking : suppression de common/status.h, remplacement de l'API disque par snd_file_api_t, résolveur de syscalls opérant sans adresse de base NTDLL, suppression des PoC par technique (loader_winapi, loader_coff, inject_classic, inject_apc, heavens_gate, etc.) au profit d'un exécutable unique, et entry point CRT-less basé PEB.

---

### Analyse opérationnelle

Ce type de framework industrialise des techniques d'évasion (syscalls directs, NTDLL propre remappée, Heaven's Gate, injection multi-backends) qui dégradent la visibilité user mode des EDR basés sur les hooks. Pour la détection : privilégier la télémétrie kernel (ETW Threat Intelligence, minifilters), alerter sur les modifications de la NTDLL en mémoire et les images remappées, détecter les créations de processus via NtCreateUserProcess sans chemin kernel32 visible, et surveiller les écritures mémoire cross-process et les sections RWX. Les binaires CRT-less sans imports Win32 classiques constituent un signal statique exploitable. Le framework peut aussi servir aux équipes purple team pour tester la résilience de leurs EDR face aux syscalls directs.

---

### Implications stratégiques

La disponibilité open source de frameworks modulaires de ce type abaisse le coût d'entrée au développement de loaders et de malwares, et accélère la diffusion de techniques d'évasion dans l'écosystème criminel. Tendance de fond : passage d'outils monolithiques à des bibliothèques réutilisables, ce qui complique l'attribution et réduit la durée de vie des signatures statiques. Décisionnel : orienter les investissements vers la visibilité kernel et la détection comportementale plutôt que vers les seules signatures, et intégrer ces frameworks dans les exercices purple team réguliers.

---

### Recommandations

* Renforcer la télémétrie kernel (ETW TI, minifilter) pour compenser la perte de visibilité user mode
* Détecter les modifications de la NTDLL en mémoire et les images propres remappées
* Tester les capacités EDR contre les syscalls directs et l'injection multi-backends (purple team)
* Surveiller les processus sans imports Win32 classiques ou entry points CRT-less

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Activer ETW Threat Intelligence et la journalisation des événements d'injection et d'accès mémoire suspects
* Établir une baseline des images NTDLL et des modules chargés sur les postes sensibles
* Définir des règles de détection comportementale (création de processus cross-parent, mémoire RWX)

#### Phase 2 — Détection et analyse

* Alerter sur les hooks NTDLL modifiés en mémoire ou les copies propres remappées
* Détecter les créations de processus via NtCreateUserProcess sans appel kernel32 visible
* Surveiller les écritures mémoire cross-process et les sections mappées exécutables

#### Phase 3 — Confinement, éradication et récupération

* Isoler les hôtes présentant des processus avec mémoire RWX suspecte ou injection confirmée
* Capturer la mémoire des processus suspects avant toute terminaison
* Bloquer le binaire fautif par hash et empêcher son réexécution

#### Phase 4 — Activités post-incident

* Reconstituer la chaîne d'exécution (loader, payload, persistance) à partir des artefacts mémoire
* Évaluer quels contrôles EDR ont été contournés et documenter les lacunes
* Mettre à jour les cas de détection avec les primitives observées

#### Phase 5 — Threat Hunting (proactif)

* Chasser les processus dont la NTDLL en mémoire diffère du fichier sur disque
* Rechercher les threads démarrant sur des adresses de gadgets hors image mappée
* Identifier les sections mémoire RWX créées hors des chemins de chargement standards
* Comparer les invocations syscall directes aux traces ETW pour repérer les appels non instrumentés

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1106** | Native API : résolution et invocation directe de syscalls NT (NtCreateFile, NtCreateUserProcess, etc.) |
| **T1055** | Process Injection : backends d'injection unifiés (Win32, NT, syscall) partageant le même frontend |
| **T1562.001** | Impair Defenses : parser NTDLL avec image propre mappée et découverte de gadgets facilitant l'unhooking et l'évasion des hooks user mode |

---

### Sources

* [https://github.com/youssefnoob003/SindriKit/releases/tag/v2.0.0](https://github.com/youssefnoob003/SindriKit/releases/tag/v2.0.0)


---

<div id="kage-console-de-triage-dfir-windows-automatisant-la-premiere-heure-dinvestigation"></div>

## Kage : console de triage DFIR Windows automatisant la première heure d'investigation

### Résumé

Kage est une console de triage DFIR Windows open source présentée sur le subreddit r/blueteamsec. En une seule exécution, l'outil collecte les preuves (journaux d'événements, registre, etc.) même sur des fichiers verrouillés, construit une timeline confrontée à des milliers de règles de détection, scanne le disque à la recherche d'outils malveillants connus, inventorie les connexions réseau et les processus, vérifie les IP et fichiers contre du threat intel, et produit un rapport noté transmissible. L'outil ne requiert aucune clé API, dispose de sa propre interface web et propose un mode démo simulant un incident pour test sans machine réelle.

---

### Analyse opérationnelle

Outil de premier niveau pour les SOC dépourvus d'équipe DFIR dédiée : il accélère la qualification initiale (collecte, timeline, corrélation de règles, enrichissement TI) et produit un livrable exploitable pour l'escalade. À intégrer dans les runbooks de première réponse et les kits de réponse sur support contrôlé. Points d'attention opérationnels : valider les résultats sur des cas connus avant usage en production (risque de faux positifs avec des milliers de règles), ne pas traiter le score du rapport comme un verdict final, contrôler la provenance et les mises à jour de l'outil, et encadrer la chaîne de conservation des preuves collectées.

---

### Implications stratégiques

La démocratisation d'outils de triage automatisés réduit le temps moyen de qualification des incidents et permet à des équipes réduites de couvrir la première heure d'investigation, historiquement réservée aux spécialistes DFIR. Enjeux : standardisation des sorties de triage pour faciliter l'escalade vers les CERT et prestataires IR, et montée en maturité des SOC de niveau 1. Risque associé : une fausse confiance si l'automatisation se substitue à l'analyse humaine sur des incidents complexes.

---

### Recommandations

* Intégrer Kage (ou équivalent) au kit de réponse à incident et aux runbooks de triage
* Valider les résultats sur des cas d'usage connus avant déploiement en production
* Encadrer l'usage (autorisation, chaîne de conservation des preuves collectées)
* Compléter avec un enrichissement TI interne pour contextualiser IP et fichiers

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Préparer un kit de réponse à incident (portable, clé USB) avec Kage et ses dépendances
* Former les analystes SOC niveau 1 au triage assisté et à l'interprétation du rapport noté
* Définir les critères d'escalade vers l'IR à partir du score et des constats du rapport

#### Phase 2 — Détection et analyse

* Exécuter Kage sur les hôtes suspects pour construire une timeline et la confronter aux règles de détection
* Croiser les IP et fichiers remontés avec le threat intel interne et externe

#### Phase 3 — Confinement, éradication et récupération

* Sur la base du rapport, isoler les hôtes présentant des outils malveillants connus ou des connexions suspectes
* Préserver les preuves collectées (copie horodatée) avant toute remédiation destructive

#### Phase 4 — Activités post-incident

* Archiver le rapport de triage et l'intégrer au dossier d'incident
* Affiner les règles de détection à partir des faux positifs et faux négatifs observés

#### Phase 5 — Threat Hunting (proactif)

* Réexécuter le triage sur un échantillon de postes pour détecter des compromissions passées inaperçues
* Comparer les timelines entre hôtes pour identifier un mouvement latéral commun

---

### Sources

* [https://www.reddit.com/r/blueteamsec/comments/1whfnw4/kage_windows_dfir_triage_console/](https://www.reddit.com/r/blueteamsec/comments/1whfnw4/kage_windows_dfir_triage_console/)
* [https://github.com/karim852/Kage-DFIR-toolkit](https://github.com/karim852/Kage-DFIR-toolkit)


---

<div id="cisa-ressource-detecting-and-mitigating-active-directory-compromises-revision-du-15-septembre-2026"></div>

## CISA : ressource « Detecting and Mitigating Active Directory Compromises » (révision du 15 septembre 2026)

### Résumé

La CISA a publié une révision, datée du 15 septembre 2026, de sa ressource « Detecting and Mitigating Active Directory Compromises ». La ressource est classée dans les rubriques « Cyber Threats and Response », « Incident Response » et « Industrial Control Systems », le contenu détaillé étant hébergé via un lien externe.

---

### Analyse opérationnelle

Cette ressource sert de référentiel pour auditer la capacité de détection des compromissions AD : journalisation des événements critiques (4624/4625, 4662, 4768/4769/4771 Kerberos), détection des techniques classiques (DCSync, Kerberoasting, golden/silver ticket, élévation via ACL et GPO) et mitigations associées (tiering administratif, LAPS, restriction de NTLM, durcissement des délégations). Les équipes SOC peuvent l'utiliser pour cartographier leurs cas de détection existants, identifier les lacunes sur les chemins d'attaque AD et prioriser la collecte de journaux des contrôleurs de domaine.

---

### Implications stratégiques

La mise à jour par la CISA confirme qu'Active Directory reste la cible centrale des intrusions (ransomware, espionnage) et un point de contrôle critique pour les environnements OT/ICS connectés. Pour les directions, le guide constitue un référentiel de priorisation des investissements identité (comptes à privilèges, passwordless, monitoring Kerberos) et un appui de conformité pour les organisations régulées. La classification de la ressource sous « Industrial Control Systems » souligne la convergence croissante entre sécurité IT et OT autour de l'annuaire.

---

### Recommandations

* Comparer la couverture de détection AD actuelle au guide CISA et combler les lacunes
* Prioriser les mitigations : tiering administratif, Windows LAPS, durcissement Kerberos et délégations
* Journaliser et surveiller les événements critiques AD (4662, 4769, réplications suspectes)
* Étendre la gouvernance AD aux environnements OT/ICS connectés

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les composants AD critiques (contrôleurs de domaine, comptes privilégiés, trusts, GPO)
* Centraliser les journaux des contrôleurs de domaine dans le SIEM
* Mettre en œuvre le tiering administratif, Windows LAPS et la gestion des comptes admin

#### Phase 2 — Détection et analyse

* Alerter sur DCSync (event 4662 avec GUID de réplication), Kerberoasting (4769 avec chiffrement RC4) et force brute Kerberos (4771)
* Détecter les modifications d'ACL privilégiées et les créations de comptes admin anormales

#### Phase 3 — Confinement, éradication et récupération

* Réinitialiser le compte krbtgt (deux fois, avec intervalle) en cas de compromission de credentials de domaine
* Isoler les contrôleurs de domaine compromis, révoquer les tickets et forcer la ré-authentification
* Désactiver les comptes et délégations abusées

#### Phase 4 — Activités post-incident

* Reconstruire les contrôleurs de domaine compromis depuis des sources saines
* Analyser le chemin d'attaque initial et les mouvements latéraux passés par AD
* Réviser les GPO/ACL et formaliser les leçons apprises

#### Phase 5 — Threat Hunting (proactif)

* Chasser les réplications anormales (event 4662) et les usages de tickets anormaux (4769/4776)
* Rechercher les délégations Kerberos non contraintes abusées
* Identifier les comptes privilégiés dormants et les trusts inutilisés

---

### Sources

* [https://www.cisa.gov/resources-tools/resources/detecting-and-mitigating-active-directory-compromises](https://www.cisa.gov/resources-tools/resources/detecting-and-mitigating-active-directory-compromises)


---

<div id="hey-you-hacked-a-hacker-are-you-ready-for-my-revenge-compromission-dun-red-teamer-via-un-depot-github-malveillant"></div>

## Hey, You Hacked a Hacker! Are You Ready For My Revenge? — compromission d'un red teamer via un dépôt GitHub malveillant

### Résumé

Un professionnel de la sécurité offensive relate sa propre compromission : en cherchant une alternative open source de lecture/édition PDF, il a exécuté la commande d'installation en une ligne d'un dépôt GitHub apparemment légitime (stars et forks nombreux, README concis). Pendant l'installation, il a relevé plusieurs signaux d'alerte : README sans rapport avec un logiciel PDF, domaine externe référencé inhabituel, compte GitHub très récent malgré la popularité du dépôt. Il a interrompu le script, mais une exécution partielle avait déjà eu lieu. Le premier étage était un script PowerShell récupéré et exécuté via Invoke-Expression, sélectionnant TLS 1.2. En s'appuyant sur le profilage de l'acteur (qualité de code, OPSEC, maturité d'ingénierie), l'auteur a rapidement localisé le payload et les mécanismes de persistance et coupé l'accès hôte. Il identifie également son angle mort : les acteurs réels monétisent n'importe quelle donnée volée sans nécessairement viser les « crown jewels ». Une seconde partie décrit sa contre-enquête, sans pirater en retour : cartographie du réseau info-stealer, traçage de l'infrastructure et des identités publiques associées, jusqu'à l'identification d'un individu impliqué dans cette économie.

---

### Analyse opérationnelle

Points opérationnels : (1) vérification systématique avant toute exécution d'un one-liner open source — âge du compte vs popularité du dépôt, cohérence du README, réputation du domaine d'installation ; (2) détection PowerShell : alerte sur Invoke-Expression/DownloadString, transcription des scripts, AMSI, Constrained Language Mode ; (3) réponse au rythme : interrompre le script reste utile même après exécution partielle, isoler l'hôte rapidement et chasser la persistance (clés Run, tâches planifiées, services) ; (4) post-compromission : considérer tout secret accessible (mots de passe, cookies, tokens) comme volé et le révoquer intégralement, car un info-stealer monétise chaque élément et pas uniquement les données critiques ; (5) traçage de l'infrastructure (domaines de staging, C2) pour alimenter le blocage et les signalements.

---

### Implications stratégiques

L'incident illustre la viabilité de l'économie info-stealer : toute compromission est rentable, y compris celle de professionnels de la sécurité, ce qui élargit la surface de menace au-delà des cibles à forte valeur. La campagne confirme la tendance à l'abus des plateformes de confiance (GitHub) via de faux dépôts populaires distribuant des chargeurs en une ligne de commande. Pour les organisations, cela renforce la nécessité d'une politique de gestion des risques liés à l'open source (vérification des dépôts, formation, SBOM). Enfin, l'auteur démontre une réponse « intelligence-led » légale : profilage de l'acteur, cartographie de l'infrastructure et identification d'individus sans contre-attaque, soulignant les limites éthiques et juridiques du hack-back.

---

### Recommandations

* Ne jamais exécuter une commande d'installation sans vérifier l'âge du compte, la cohérence du README et le domaine référencé.
* Restreindre et journaliser PowerShell (transcription, AMSI, CLM, blocage d'Invoke-Expression).
* Après toute exécution suspecte : isoler le poste, supprimer les persistances et révoquer l'ensemble des secrets accessibles.
* Signaler les dépôts malveillants à GitHub et partager les IOC (domaines, URL, hachages) avec la communauté.
* Intégrer la vérification des dépôts open source dans la politique de gestion des risques de la chaîne d'approvisionnement logicielle.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser toutes les équipes (y compris techniques) aux dépôts GitHub malveillants : vérifier l'âge du compte, la cohérence du README et la réputation du domaine d'installation avant toute exécution.
* Durcir les postes de travail : transcription et journalisation PowerShell, AMSI, Constrained Language Mode, restriction d'Invoke-Expression via AppLocker/WDAC.
* Déployer une télémétrie EDR complète (processus, lignes de commande, mécanismes de persistance, connexions sortantes).
* Définir une procédure de réponse rapide à la compromission d'un poste : isolation réseau, préservation des preuves, révocation des secrets.

#### Phase 2 — Détection et analyse

* Alerter sur les lignes de commande PowerShell téléchargeant et exécutant du code distant (IEX, DownloadString, iwr | iex, forçage TLS 1.2).
* Détecter les installations one-liner (curl | bash, iwr | iex) provenant de domaines externes non corporates ou récemment enregistrés.
* Surveiller l'apparition de mécanismes de persistance inhabituels (clés Run, tâches planifiées, services, profils shell) après une installation logicielle.
* Corréler les connexions sortantes vers des domaines à réputation inconnue ou incohérents avec le logiciel censé être installé.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement le poste du réseau en préservant la mémoire et les artefacts pour l'analyse.
* Interrompre les processus malveillants et supprimer les mécanismes de persistance identifiés (l'interruption d'un script reste utile même après exécution partielle).
* Révoquer et renouveler tous les secrets accessibles depuis le poste : mots de passe, tokens, cookies de session, clés SSH/VPN.
* Bloquer au niveau proxy/DNS les domaines de staging et de C2 observés durant l'analyse.

#### Phase 4 — Activités post-incident

* Mener l'analyse forensique du poste (timeline, artefacts d'exécution, payloads récupérés) et documenter la chaîne d'infection complète.
* Profiler l'acteur (qualité de code, OPSEC, maturité d'ingénierie, infrastructure) pour orienter la chasse et les signalements.
* Signaler le dépôt malveillant à GitHub et partager les IOC (domaines, URL, hachages) avec les communautés de renseignement pertinentes.
* Revoir les contrôles défaillants (vérifications pré-installation, restrictions PowerShell) et mettre à jour les procédures et la formation.

#### Phase 5 — Threat Hunting (proactif)

* Chasser sur l'ensemble du parc les exécutions PowerShell avec IEX/DownloadString sur les 30 derniers jours.
* Rechercher les postes ayant contacté des dépôts ou domaines liés à la campagne ou des domaines au schéma similaire (TLD inhabituels, enregistrements récents).
* Identifier les comptes et sessions utilisés depuis des postes compromis (connexions anormales, réutilisations de cookies, MFA anormal).
* Croiser les hachages des fichiers téléchargés avec les bases de renseignement sur les logs d'info-stealers (credentials leak databases).

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1204.002** | User Execution: Malicious File — exécution d'une commande d'installation en une ligne piégée issue d'un dépôt GitHub malveillant |
| **T1059.001** | Command and Scripting Interpreter: PowerShell — récupération et exécution d'un script distant via Invoke-Expression (TLS 1.2 forcé) |
| **T1105** | Ingress Tool Transfer — téléchargement du script/payload depuis un domaine externe contrôlé par l'acteur |

---

### Sources

* [https://winslow1984.com/books/threat-intelligence/page/hey-you-hacked-a-hacker-are-you-ready-for-my-revenge](https://winslow1984.com/books/threat-intelligence/page/hey-you-hacked-a-hacker-are-you-ready-for-my-revenge)


---

<div id="feuille-de-travail-gratuite-lister-ses-actifs-exposes-sur-internet-et-les-prioriser-face-au-catalogue-kev"></div>

## Feuille de travail gratuite : lister ses actifs exposés sur Internet et les prioriser face au catalogue KEV

### Résumé

Publication gratuite d'une feuille de travail destinée à produire la liste des actifs d'une organisation qui répondent sur Internet. L'argument central : un score de sévérité est attribué une seule fois par une personne qui n'a jamais vu votre réseau, alors que l'exposition est un fait propre à votre environnement et l'exploitation un fait avéré du monde — deux données vérifiables et déterminantes pour la priorisation. La méthode proposée s'appuie sur quatre routes, quatre tags et environ vingt minutes de travail contre le catalogue KEV (Known Exploited Vulnerabilities).

---

### Analyse opérationnelle

Utilisation concrète : inventorier les actifs joignables depuis Internet, croiser chaque actif avec les vulnérabilités présentes puis avec le KEV afin de prioriser les correctifs sur les failles à la fois exposées et activement exploitées, plutôt que sur la seule base CVSS. Les quatre routes/tags permettent de catégoriser rapidement l'exposition (service exposé, version vulnérable, mitigation, statut de correction). À intégrer dans le cycle de gestion des vulnérabilités : revue régulière des nouveaux ajouts au KEV confrontés à l'inventaire des actifs exposés.

---

### Implications stratégiques

La démarche illustre le déplacement de la gestion des vulnérabilités vers une priorisation fondée sur l'exposition et l'exploitation avérée (KEV, EPSS) plutôt que sur la sévérité théorique. Pour les directions, cela permet un arbitrage budgétaire plus défendable : traiter en priorité ce qui est réellement attaquable et documenter le risque résiduel du reste. Cela contribue aussi à réduire le délai de remédiation sur les failles réellement armées par les acteurs de menace.

---

### Recommandations

* Construire et maintenir l'inventaire des actifs exposés sur Internet (découverte continue, DNS, certificats, scans externes).
* Croiser systématiquement les CVE détectées avec le catalogue CISA KEV et prioriser les correctifs des actifs exposés.
* Adopter des tags d'exposition dans la CMDB pour automatiser la priorisation.
* Ne pas traiter la sévérité CVSS comme unique critère de décision de remédiation.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire à jour des actifs exposés sur Internet (CMDB, scans de surface externe, DNS, certificats).
* S'abonner au catalogue CISA KEV et aux avis d'exploitation active des éditeurs.
* Définir des tags d'exposition (internet-facing, interne, critique métier) applicables à l'ensemble du parc.

#### Phase 2 — Détection et analyse

* Croiser quotidiennement les vulnérabilités détectées avec le KEV pour repérer les failles activement exploitées présentes sur des actifs exposés.
* Alerter sur les nouveaux ajouts au KEV concernant des produits présents dans l'inventaire exposé.
* Surveiller les scans et tentatives d'exploitation ciblant les actifs exposés (WAF, IDS, logs de bordure).

#### Phase 3 — Confinement, éradication et récupération

* Pour toute vulnérabilité du KEV présente sur un actif exposé sans correctif disponible : appliquer des mitigations (règles WAF, restriction d'accès, désactivation de fonctionnalité, segmentation).
* Retirer de l'exposition Internet les services non nécessaires (minimisation de la surface d'attaque).

#### Phase 4 — Activités post-incident

* En cas d'exploitation avérée : analyser l'impact sur les actifs concernés, réinitialiser les identifiants exposés et reconstruire les systèmes compromis.
* Documenter les écarts entre sévérité théorique et exploitation réelle pour affiner la politique de priorisation.

#### Phase 5 — Threat Hunting (proactif)

* Chasser dans les logs des actifs exposés les traces d'exploitation des CVE du KEV sur la période antérieure à la remédiation.
* Rechercher les actifs inconnus ou oubliés répondant sur Internet (shadow IT) via découvertes externes et sources certifiées.

---

### Sources

* [https://mastodon.social/@BigG_TheCreator/117277537109237334](https://mastodon.social/@BigG_TheCreator/117277537109237334)


---

<div id="18696194192-ip-a-activite-mixte-signalee-par-un-flux-de-renseignement-confiance-45"></div>

## 186.96.194.192 — IP à activité mixte signalée par un flux de renseignement (confiance 45 %)

### Résumé

Un rapport de renseignement sur IP signale que 186.96.194.192 présente une activité malveillante mixte avec un niveau de confiance de 45 %, suivie par un seul flux. L'adresse est hébergée chez Cooperativa De Electricidad De Pedro Luro (AS52490, Argentine). La recommandation publiée est de la bloquer ou de la journaliser au niveau du pare-feu plutôt que de l'ignorer.

---

### Analyse opérationnelle

Traiter l'IOC avec prudence compte tenu de la confiance faible (45 %) et de la source unique : privilégier une règle de journalisation + alerte plutôt qu'un blocage dur afin d'éviter les faux positifs (IP appartenant à un FAI régional, potentiellement partagée). Corréler les logs pare-feu, proxy, EDR et DNS pour détecter toute communication passée ou présente avec cette adresse ; en cas de connexion confirmée depuis le parc, identifier le processus et le poste émetteurs, puis basculer en blocage effectif.

---

### Implications stratégiques

Ce type de publication illustre les limites des IOC mono-source à faible confiance : les décisions de blocage doivent être pondérées par la fiabilité pour ne pas perturber des services légitimes hébergés sur des IP d'ISP ou d'hébergement partagé. Cela plaide pour une politique de scoring multi-sources des IOC et pour l'intégration du contexte (ASN, type d'hébergement, géolocalisation) dans les décisions de filtrage.

---

### Recommandations

* Ajouter l'IP en surveillance (log + alerte) plutôt qu'en blocage immédiat, vu la confiance de 45 %.
* Corréler avec d'autres sources de renseignement avant toute décision de blocage définitif.
* Vérifier dans les historiques de logs (pare-feu, proxy, EDR) toute communication antérieure avec cette adresse.
* Surveiller d'autres IP de l'AS52490 présentant un comportement analogue.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Intégrer les flux de renseignement IP dans le SIEM/pare-feu avec une gestion formalisée des faux positifs (exceptions métier documentées).
* Définir une politique de traitement des IOC selon leur niveau de confiance (blocage dur vs journalisation + alerte).

#### Phase 2 — Détection et analyse

* Alerter sur toute connexion sortante ou entrante impliquant 186.96.194.192 (pare-feu, proxy, EDR, DNS).
* Corréler avec d'autres sources de renseignement pour confirmer ou infirmer l'activité malveillante (confiance actuelle : 45 %, flux unique).

#### Phase 3 — Confinement, éradication et récupération

* En cas de connexion confirmée depuis le parc : bloquer l'IP en sortie, isoler le poste concerné et identifier le processus responsable.
* Si un blocage préventif est retenu, préférer une règle de log + alerte plutôt qu'un drop silencieux afin de conserver la visibilité.

#### Phase 4 — Activités post-incident

* Analyser le contexte des communications (protocole, volume, destination initiale) pour déterminer s'il s'agit de C2, de scan ou d'un faux positif.
* Documenter l'incident et ajuster la politique de confiance accordée aux IOC mono-source.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les historiques de logs (90 jours) toute communication antérieure avec cette adresse.
* Surveiller d'autres IP de l'AS52490 présentant un comportement similaire (activité mixte, réputation dégradée).

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| IP | `186.96.194.192` | Low |

---

### Sources

* [https://www.valtersit.com/threat-ip/186.96.194.192/](https://www.valtersit.com/threat-ip/186.96.194.192/)


---

<div id="injection-sql-union-based-methodologie-dextraction-de-donnees-decrite-dans-un-guide-codelivly"></div>

## Injection SQL UNION-based : méthodologie d'extraction de données décrite dans un guide Codelivly

### Résumé

La publication décrit la méthodologie d'extraction de données après confirmation d'une injection SQL de type UNION : détermination du nombre de colonnes via ORDER BY N jusqu'à obtention d'une erreur, identification de la colonne réfléchissante en remplaçant les NULL par des chaînes de caractères, puis interrogation de information_schema.tables à travers cette colonne pour énumérer les tables et extraire des données réelles. La publication renvoie à un guide professionnel payant édité par Codelivly.

---

### Analyse opérationnelle

Pour les équipes SOC/IT : cette chaîne d'exploitation est directement détectable — alerter sur les motifs ORDER BY itératifs, UNION SELECT et information_schema dans les logs HTTP/WAF ; corréler les erreurs SQL avec des réponses 200 anormalement riches ; déployer des règles WAF SQLi en mode blocage ; imposer les requêtes paramétrées ; limiter les privilèges du compte applicatif en base et restreindre l'accès à information_schema ; journaliser les payloads pour l'analyse post-incident.

---

### Implications stratégiques

L'injection SQL reste un vecteur d'intrusion majeur (OWASP A03:2021) et ces techniques d'extraction UNION-based sont employées indifféremment par les pentesters et les attaquants, y compris pour l'exfiltration massive de bases de données clients. L'investissement dans la formation sécuritaire des développeurs et les tests d'intrusion applicatifs réguliers constitue un facteur de réduction du risque direct.

---

### Recommandations

* Généraliser les requêtes paramétrées et interdire la concaténation SQL dynamique
* Déployer/ajuster les règles WAF SQLi avec journalisation des payloads
* Restreindre les privilèges du compte applicatif en base et l'accès à information_schema
* Intégrer des tests d'injection SQL (SAST/DAST) dans le CI/CD
* Former les développeurs aux défauts d'injection (OWASP A03:2021)

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Généraliser les requêtes paramétrées (prepared statements) et bannir la concaténation dynamique SQL
* Intégrer SAST/DAST avec tests d'injection SQL dans le pipeline CI/CD
* Comptes applicatifs de base de données à privilèges minimaux, restriction de l'accès à information_schema
* WAF en mode blocage avec règles SQLi et journalisation complète des payloads

#### Phase 2 — Détection et analyse

* Alerte sur les motifs SQLi dans les logs HTTP : UNION SELECT, ORDER BY N itératifs, information_schema, guillemets anormaux
* Corrélation entre erreurs SQL (syntaxe, conversion) et réponses 200 anormalement riches (extraction réussie)
* Surveillance des chaînes de requêtes répétées énumérant des colonnes et des volumes de réponses inhabituels

#### Phase 3 — Confinement, éradication et récupération

* Blocage des IP/sessions à l'origine des payloads et durcissement immédiat du WAF
* Isolement ou suspension de l'endpoint vulnérable, passage en mode maintenance
* Révocation des sessions applicatives et rotation des secrets potentiellement exposés

#### Phase 4 — Activités post-incident

* Correction par requêtes paramétrées avec tests de non-régression
* Analyse des logs de base de données pour déterminer les tables consultées et les données exfiltrées
* Notification réglementaire si des données personnelles ont été compromises (RGPD, 72 h)

#### Phase 5 — Threat Hunting (proactif)

* Chasse de requêtes historiques contenant UNION, ORDER BY ou information_schema dans les logs WAF et base de données
* Recherche d'exports massifs ou de comptes créés via l'application pendant la période suspecte
* Scan des applications web exposées pour identifier d'autres points d'injection

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploitation d'une application exposée publiquement via injection SQL de type UNION-based |
| **T1213** | Extraction de données depuis les référentiels d'information (énumération via information_schema) |

---

### Sources

* [https://resources.codelivly.com/product/sql-injection-notes-professional-guide-by-codelivly/](https://resources.codelivly.com/product/sql-injection-notes-professional-guide-by-codelivly/)


---

<div id="un-groupe-ransomware-revendique-lattaque-du-cedar-county-memorial-hospital-missouri-apres-une-panne-informatique"></div>

## Un groupe ransomware revendique l'attaque du Cedar County Memorial Hospital (Missouri) après une panne informatique

### Résumé

Selon DataBreaches.net, un groupe ransomware a revendiqué une cyberattaque contre le Cedar County Memorial Hospital, établissement de santé situé dans le Missouri (États-Unis), survenue dans le contexte d'une interruption des systèmes informatiques de l'hôpital. Le texte détaillé de l'article étant inaccessible (blocage anti-bot), le nom du groupe, l'étendue du chiffrement, l'exfiltration éventuelle de données et les preuves de la revendication ne sont pas confirmés à ce stade.

---

### Analyse opérationnelle

Pour les équipes SOC/Santé : croiser toute interruption IT inexpliquée avec les indicateurs d'un déploiement ransomware (suppression des shadow copies, extensions modifiées, comptes inhabituels) ; surveiller les sites de fuite pour détecter la publication de données de l'établissement ; vérifier la segmentation entre le SIH et les dispositifs médicaux ; s'assurer de l'intégrité des sauvegardes hors ligne avant toute restauration ; préparer le mode dégradé clinique en cas d'isolement réseau.

---

### Implications stratégiques

Le secteur hospitalier reste une cible privilégiée en raison de la pression d'exploitation continue qui favorise le paiement des rançons. Au-delà du chiffrement, le risque de double extorsion expose des données patients (PHI) avec des conséquences réglementaires (HIPAA/OCR) et un risque direct sur la sécurité des patients. La revendication publique non encore confirmée illustre également l'usage de la pression médiatique par les groupes ransomware.

---

### Recommandations

* Vérifier l'intégrité des sauvegardes hors ligne et tester la restauration
* Surveiller les sites de fuite ransomware et les mentions de l'établissement
* Renforcer la segmentation IT/dispositifs médicaux et le contrôle des accès distants
* Préparer la procédure de notification HIPAA/OCR et la communication de crise

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sauvegardes 3-2-1 hors ligne testées pour les systèmes hospitaliers critiques (SIH, imagerie, laboratoire)
* Segmentation réseau entre IT, dispositifs médicaux connectés (IoMT) et bureautique
* Gestion des comptes à privilèges (PAM), MFA sur les accès distants (VPN, RDP)
* Contrats de réponse à incident, cyberassurance et contacts légaux (HIPAA/OCR) préparés

#### Phase 2 — Détection et analyse

* Surveillance des sites de fuite des groupes ransomware pour les mentions de l'établissement
* Alerte sur chiffrement massif, extensions de fichiers modifiées, suppression des shadow copies (vssadmin)
* Corrélation d'une interruption IT inexpliquée avec des indicateurs d'accès initial (VPN, RDP, comptes inhabituels)
* Monitoring EDR sur les serveurs critiques et les comptes administrateurs

#### Phase 3 — Confinement, éradication et récupération

* Isolement réseau des segments touchés avec coupure contrôlée préservant les preuves
* Bascule en mode dégradé clinique sécurisé (procédures papier, systèmes de secours)
* Blocage des comptes compromis et réinitialisation des identifiants à privilèges
* Suspendre toute restauration/paiement avant validation forensique

#### Phase 4 — Activités post-incident

* Reconstruction depuis des sauvegardes saines après purge de la persistance
* Notification OCR/HIPAA, patients et régulateurs si des données de santé (PHI) sont compromises
* Rapport d'incident, retour d'expérience et mise à jour du plan de réponse
* Évaluation de l'exfiltration de données en vue d'une double extorsion

#### Phase 5 — Threat Hunting (proactif)

* Chasse de comptes récemment créés ou utilisés et d'outils RMM légitimes détournés
* Recherche d'artefacts d'exfiltration (rclone, curl, volumes anormaux vers le cloud)
* Analyse des journaux VPN/edge pour identifier l'accès initial et rapprocher les TTP du groupe revendicateur

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Chiffrement de données pour impact (revendication d'attaque ransomware après une panne IT) |
| **T1657** | Extorsion financière via revendication publique sur les canaux du groupe |

---

### Sources

* [https://databreaches.net/2026/09/15/ransomware-group-claims-attack-on-missouris-cedar-county-memorial-hospital-after-it-outage/](https://databreaches.net/2026/09/15/ransomware-group-claims-attack-on-missouris-cedar-county-memorial-hospital-after-it-outage/)


---

<div id="des-membres-du-groupe-cybercriminel-black-axe-extrades-dafrique-du-sud"></div>

## Des membres du groupe cybercriminel « Black Axe » extradés d'Afrique du Sud

### Résumé

Des membres du groupe cybercriminel « Black Axe » ont été extradés d'Afrique du Sud, rapporte DataBreaches.net. Black Axe est une organisation criminelle d'origine nigériane connue pour la fraude en ligne à grande échelle : escroqueries sentimentales (romance scams), fraude au président/BEC, et blanchiment via des réseaux de mules financières. Le texte détaillé de l'article étant inaccessible (blocage anti-bot), les identités des extradés, les chefs d'accusation et les juridictions de destination ne sont pas précisés.

---

### Analyse opérationnelle

Pour les équipes fraude/SOC : les arrestations peuvent entraîner une recomposition du réseau et une reprise des campagnes par des affiliés ; surveiller les schémas BEC et romance scam, les changements de coordonnées bancaires et les mouvements via des mules financières ; comparer les campagnes récentes aux TTP historiques du groupe ; partager les indicateurs avec les partenaires bancaires et les autorités.

---

### Implications stratégiques

L'extradition depuis l'Afrique du Sud illustre le renforcement de la coopération judiciaire internationale contre la cybercriminalité financière organisée. Toutefois, l'effet disruptif des arrestations reste limité dans la durée : le modèle économique de Black Axe (fraude en ligne transnationale, blanchiment) se recompose rapidement. Les secteurs bancaire et financier demeurent en première ligne, avec des pertes directes et un risque de conformité LCB-FT.

---

### Recommandations

* Renforcer la double validation hors bande des virements sensibles
* Sensibiliser les collaborateurs aux schémas BEC et romance scam
* Partager les indicateurs de fraude avec FS-ISAC/CERT et les autorités
* Surveiller les réseaux de mules et les changements de coordonnées bancaires

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibilisation aux fraudes BEC et romance scam, procédure de validation des virements hors bande
* Contrôles anti-fraude : vérification des changements de coordonnées bancaires, règles de détection des virements atypiques
* Veille sur les actions judiciaires internationales et les réseaux de mules financières

#### Phase 2 — Détection et analyse

* Alerte sur les demandes de virement urgentes accompagnées d'un changement de coordonnées bancaires
* Détection des domaines typosquats et des identités usurpées de dirigeants dans les passerelles e-mail
* Signalement des tentatives de fraude aux équipes conformité et aux autorités

#### Phase 3 — Confinement, éradication et récupération

* Gel des virements suspects et demande de rappel de transaction (recall) auprès des banques
* Blocage des domaines et adresses e-mail à l'origine des tentatives
* Préservation des preuves (en-têtes, faux ordres de virement) pour plainte

#### Phase 4 — Activités post-incident

* Analyse du circuit des fonds en coopération avec les institutions financières
* Dépôt de plainte et partage d'indicateurs avec la communauté (FS-ISAC, CERT)
* Renforcement des procédures de validation des paiements suite au retour d'expérience

#### Phase 5 — Threat Hunting (proactif)

* Chasse de messages BEC dans l'historique des passerelles e-mail (mots-clés : virement, IBAN, urgent, confidential)
* Recherche de comptes externes similaires aux dirigeants (lookalike domains)
* Corrélation des indicateurs de fraude avec les campagnes attribuées à Black Axe

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing et ingénierie sociale au cœur des campagnes de fraude attribuées à Black Axe |
| **T1656** | Usurpation d'identité (fraude au président/BEC, escroqueries sentimentales) comme modèle opérationnel du groupe |

---

### Sources

* [https://databreaches.net/2026/09/15/members-of-black-axe-cybercriminal-group-extradited-from-south-africa/](https://databreaches.net/2026/09/15/members-of-black-axe-cybercriminal-group-extradited-from-south-africa/)


---

<div id="photos-deleves-et-coordonnees-bancaires-derobees-apres-une-cyberattaque-contre-st-james-anglican-school-a-perth"></div>

## Photos d'élèves et coordonnées bancaires dérobées après une cyberattaque contre St James Anglican School à Perth

### Résumé

L'école anglicane St James Anglican School à Perth (Australie) a été victime d'une cyberattaque ayant conduit au vol de photos d'élèves et de coordonnées bancaires, rapporte DataBreaches.net. Le texte détaillé de l'article étant inaccessible (blocage anti-bot), le vecteur d'intrusion, le volume exact de données concernées et l'identité des auteurs ne sont pas précisés.

---

### Analyse opérationnelle

Pour les équipes IT des établissements scolaires : auditer les accès aux systèmes d'information scolaire (SIS) et aux espaces de stockage contenant des données d'élèves ; imposer le MFA sur les comptes du personnel ; surveiller les téléchargements massifs et les règles de transfert e-mail suspectes ; préparer la notification des familles et la coordination avec l'OAIC (Notifiable Data Breaches scheme) et l'ACSC.

---

### Implications stratégiques

Les établissements d'enseignement sont des cibles de plus en plus fréquentées : les données personnelles de mineurs (photos, coordonnées bancaires des familles) ont un fort impact émotionnel et réputationnel, alors que leurs moyens de défense sont souvent limités. L'incident souligne l'exposition des données bancaires détenues par les écoles (frais de scolarité) et le risque de fraude secondaire visant les familles.

---

### Recommandations

* Imposer le MFA et revoir les accès aux systèmes contenant des données d'élèves
* Chiffrer et minimiser les données sensibles (photos, coordonnées bancaires)
* Préparer la notification conforme au NDB scheme australien
* Sensibiliser les familles au risque de fraude secondaire

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventaire et minimisation des données sensibles détenues (photos d'élèves, coordonnées bancaires des familles)
* MFA sur les comptes du personnel, contrôle des accès distants et des prestataires informatiques
* Sauvegardes testées et plan de réponse adapté au secteur scolaire
* Maîtrise des obligations australiennes (Privacy Act, Notifiable Data Breaches scheme)

#### Phase 2 — Détection et analyse

* Alerte sur les accès anormaux aux systèmes d'information scolaire (SIS) et aux partages de fichiers, téléchargements massifs
* Surveillance des fuites publiques et des forums pour les données de l'établissement
* Détection des compromissions de comptes e-mail (règles de transfert suspectes)

#### Phase 3 — Confinement, éradication et récupération

* Réinitialisation des identifiants, révocation des sessions et des tokens
* Isolement des systèmes compromis et blocage du vecteur identifié
* Coordination avec le prestataire informatique, l'ACSC et l'OAIC

#### Phase 4 — Activités post-incident

* Notification des familles concernées et mesures d'accompagnement (surveillance bancaire)
* Analyse forensique de l'étendue exacte des données exfiltrées
* Renforcement des contrôles d'accès et chiffrement des données sensibles

#### Phase 5 — Threat Hunting (proactif)

* Chasse d'accès non autorisés historiques sur les partages de fichiers et le SIS
* Recherche d'exfiltrations vers des services cloud personnels ou des destinataires externes inconnus
* Vérification de la réutilisation des identifiants compromis sur d'autres services

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1213** | Exfiltration de données depuis les référentiels de l'établissement (photos d'élèves, coordonnées bancaires ; vecteur d'intrusion non précisé) |

---

### Sources

* [https://databreaches.net/2026/09/15/student-photos-bank-details-stolen-by-hackers-after-st-james-anglican-school-in-perth-hit-by-cyber-attack/](https://databreaches.net/2026/09/15/student-photos-bank-details-stolen-by-hackers-after-st-james-anglican-school-in-perth-hit-by-cyber-attack/)


---

<div id="rohto-pharmaceutical-acces-non-autorise-au-systeme-de-vente-en-ligne-un-pirate-revendique-4-to-de-donnees-dont-395-millions-de-fiches-clients-salesforce"></div>

## Rohto Pharmaceutical : accès non autorisé au système de vente en ligne, un pirate revendique ~4 To de données dont ~3,95 millions de fiches clients Salesforce

### Résumé

Rohto Pharmaceutical a annoncé le 11 septembre 2026 avoir détecté le 10 septembre un possible accès non autorisé à son système de vente en ligne (commerce électronique) ; l'accès a été restreint, les systèmes concernés et le périmètre d'impact sont en cours d'investigation, et aucune incidence majeure sur les activités n'était constatée au 11 septembre. Aucune fuite de données n'est officiellement confirmée par la société au 15 septembre. Le 14 septembre, un individu revendiquant l'attaque a publié sur un forum criminel étranger avoir exfiltré environ 4 To de données : ~3,95 millions de fiches clients Salesforce, ~850 000 enregistrements d'appels du service client (~3,5 To), ~439 Go de documents SharePoint (~52 000 fichiers), données de sites départementaux (~15 Go), données de systèmes internes (~6,5 Go), messages Outlook (~197 fichiers), données de recherche conjointe avec des universités (~87 Go, ~12 580 fichiers) et historiques de ventes (~22 Go). Le média Security Measures Lab a vérifié un échantillon de 1 000 enregistrements JSON dont la structure correspond à l'API REST Salesforce (objets Account, chemin /services/data/v57.0/sobjects/Account/), ainsi que des images de vidéosurveillance intérieure et des captures d'écran de visioconférence avec partage de documents internes. Le volume total, les chemins d'entrée, la compromission éventuelle de Salesforce lui-même et la qualité d'intrus du revendicateur restent non confirmés. Rohto met en garde contre d'éventuels appels, e-mails et SMS frauduleux usurpant la société.

---

### Analyse opérationnelle

Impact SOC/IT : auditer en priorité les intégrations et tokens OAuth Salesforce (applications connectées, périmètres API) ; surveiller les exports REST massifs (Event Monitoring, Setup Audit Trail) et les téléchargements SharePoint anormaux ; vérifier les journaux d'accès du système e-commerce et des comptes de service ; anticiper une vague de phishing/SMS/appels usurpant la marque Rohto (déjà alertée par la victime) et bloquer proactivement les domaines typosquats ; préserver les logs avant remédiation pour rapprocher les échantillons publiés (structure sObject Account v57.0) des accès API réels.

---

### Implications stratégiques

L'incident illustre le risque de concentration SaaS : une compromission côté client donne accès à un périmètre étendu (CRM, collaboration, téléphonie, recherche universitaire) et alimente une extorsion à fort effet médiatique (chiffres non vérifiés mais échantillons plausibles). Pour l'industrie pharmaceutique, l'exposition de données de recherche conjointe touche la propriété intellectuelle et les partenariats académiques. L'asymétrie d'information (attaquant bavard, victime discrète) crée un risque réputationnel et réglementaire (APPI) et favorise la fraude secondaire contre les clients.

---

### Recommandations

* Roter immédiatement tokens OAuth, secrets et identifiants des intégrations Salesforce/SharePoint/Outlook
* Activer la journalisation API (Event Monitoring) et alerter sur les exports massifs
* Restreindre les API Salesforce par allowlisting IP et MFA résistant au phishing
* Surveiller les forums de fuite et préparer la notification APPI/clients
* Bloquer les campagnes d'usurpation de marque (e-mails, SMS, appels) et informer les clients

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Gouvernance SaaS : inventaire des intégrations Salesforce/SharePoint, tokens OAuth et applications connectées
* MFA résistant au phishing et allowlisting IP pour les accès API Salesforce
* DLP sur les exports massifs et journalisation complète des événements API (Event Monitoring)
* Plan de communication de crise incluant la gestion des campagnes d'usurpation de marque

#### Phase 2 — Détection et analyse

* Alerte sur les exports API anormaux (volumes de requêtes REST, requêtes sObject massives, chemins /services/data/)
* Surveillance des forums criminels et des sites de fuite pour les échantillons de données de l'organisation
* Détection des accès inhabituels aux comptes de service et des téléchargements SharePoint massifs
* Monitoring des campagnes de phishing usurpant la marque (appels, e-mails, SMS)

#### Phase 3 — Confinement, éradication et récupération

* Rotation immédiate des identifiants, tokens OAuth et secrets Salesforce/SharePoint/Outlook
* Restriction d'accès au système de vente en ligne et durcissement des périmètres API
* Blocage des domaines d'usurpation et coordination avec les registrars et services anti-phishing
* Préservation des preuves (logs API, journaux d'accès) avant toute remédiation destructive

#### Phase 4 — Activités post-incident

* Vérification indépendante du périmètre exact exfiltré (rapprochement des logs avec les revendications de ~4 To)
* Notification des personnes concernées et des autorités (APPI) si la fuite est confirmée
* Communication transparente pour réduire l'asymétrie d'information exploitée par l'attaquant
* Analyse de l'impact sur les données de recherche conjointe (propriété intellectuelle, partenaires universitaires)

#### Phase 5 — Threat Hunting (proactif)

* Chasse dans les logs Salesforce (Setup Audit Trail, Event Monitoring) des accès et exports anormaux
* Recherche de connexions géographiquement anormales et d'applications connectées inconnues
* Corrélation des échantillons publiés (structure sObject Account, /services/data/v57.0) avec les journaux d'accès API
* Balayage OSINT défensif des infrastructures et contacts de l'attaquant (liens de fuite, canaux de contact)

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Accès non autorisé présumé au système de vente en ligne (vecteur d'intrusion non confirmé) |
| **T1213** | Extraction de données depuis les référentiels d'information : Salesforce, SharePoint, Outlook, données de recherche conjointe |
| **T1657** | Revendication publique d'exfiltration massive (~4 To) sur un forum criminel étranger à des fins de pression/extorsion |

---

### Sources

* [https://rocket-boys.co.jp/security-measures-lab/rohto-4tb-ec-site-data-access-report/](https://rocket-boys.co.jp/security-measures-lab/rohto-4tb-ec-site-data-access-report/)
