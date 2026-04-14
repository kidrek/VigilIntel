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
  * [Exploitation active d'une zero-day dans Adobe Acrobat et Reader](#exploitation-active-dune-zero-day-dans-adobe-acrobat-et-reader)
  * [Campagne PhantomPulse : abus de l'écosystème de plugins d'Obsidian](#campagne-phantompulse-abus-de-lecosysteme-de-plugins-dobsidian)
  * [Attaque de la chaîne d'approvisionnement Axios et impact sur OpenAI](#attaque-de-la-chaine-dapprovisionnement-axios-et-impact-sur-openai)
  * [Handala : escalade cyber contre les infrastructures critiques des EAU](#handala-escalade-cyber-contre-les-infrastructures-critiques-des-eau)
  * [Démantèlement de la plateforme de phishing W3LL](#demantelement-de-la-plateforme-de-phishing-w3ll)
  * [CyberAv3ngers : menaces persistantes sur les systèmes industriels d'eau](#cyberav3ngers-menaces-persistantes-sur-les-systemes-industriels-deau)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage actuel des menaces est marqué par une hybridation croissante entre conflits géopolitiques et opérations cyber-offensives, particulièrement autour de l'axe États-Unis-Israël-Iran. L'escalade des tensions se traduit par des attaques destructrices d'envergure, comme celles menées par le groupe Handala contre les infrastructures critiques de Dubaï. Parallèlement, on observe une sophistication accrue des attaques sur la chaîne d'approvisionnement, illustrée par la compromission du package Axios et l'abus des plugins de l'application Obsidian par des acteurs étatiques. Le ciblage des environnements cloud, notamment via le détournement de tokens d'accès (Snowflake/Anodot), expose les données de millions d'utilisateurs chez des géants tels que Rockstar Games. Les acteurs de ransomware et d'extorsion, comme SRG et Anubis, maintiennent une pression constante sur les secteurs stratégiques de la santé et du droit. La rapidité d'exploitation des vulnérabilités critiques (Marimo, Cisco FMC) met à rude épreuve les capacités de réponse des organisations. Le démantèlement du service W3LL souligne toutefois l'efficacité de la coopération policière internationale contre le Phishing-as-a-Service. Enfin, la sécurité des systèmes industriels (ICS) demeure une priorité absolue face aux activités de groupes comme CyberAv3ngers.

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
| Anubis | Santé (Hôpitaux) | Ransomware, exfiltration de données massives (2TB) | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| CyberAv3ngers (Storm-0784) | Infrastructures critiques (Eau, Énergie) | Exploitation de PLC (Rockwell, Unitronics), malware IOCONTROL | [Cybersecurity News](https://cybersecuritynews.com/iran-linked-cyberav3ngers-sets-sights/) |
| Handala (Void Manticore) | Gouvernements, Infrastructures critiques (Israël, EAU) | Wiper destructeur, exfiltration de données, phishing | [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-takedown-of-w3ll-phishing-service-leads-to-developer-arrest/) / [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Interlock Ransomware Group | Réseaux d'entreprise | Exploitation de zero-day (Cisco FMC), déploiement de RAT personnalisés | [Recorded Future](https://www.recordedfuture.com/blog/march-2026-cve-landscape) |
| REF6598 | Finance, Cryptomonnaie | Abus de plugins Obsidian, déploiement du RAT PhantomPulse | [Elastic Security](https://www.elastic.co/security-labs/phantom-in-the-vault) |
| ShinyHunters | Technologie, Jeux vidéo | Vol de tokens d'authentification cloud (Snowflake/Anodot) | [BleepingComputer](https://www.bleepingcomputer.com/news/security/stolen-rockstar-games-analytics-data-leaked-by-extortion-gang/) |
| Silent Ransom Group (SRG) | Cabinets d'avocats | Extorsion sans chiffrement, menace de fuite de données | [DataBreaches](https://databreaches.net/2026/04/13/a-silent-threat-loud-consequences-ransom-group-hits-law-firms-hard/) |
| Storm-1175 | Éducation, Santé, Finance | Exploitation de CVE Microsoft (Exchange), Medusa Ransomware | [The Register](https://go.theregister.com/feed/www.theregister.com/2026/04/13/ransomware_gang_other_crims_attacking/) |
| UNC1069 (Corée du Nord) | Développeurs, Open Source | Supply chain attack (NPM/Axios), ingénierie sociale | [BleepingComputer](https://www.bleepingcomputer.com/news/security/openai-rotates-macos-certs-after-axios-attack-hit-code-signing-workflow/) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Gouvernemental | Blocus Naval | Les États-Unis ont instauré un blocus naval des ports iraniens via le détroit d'Ormuz. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Gouvernemental | Cyber-représailles | Handala affirme avoir détruit 6PB de données aux Émirats Arabes Unis en réponse à leur alignement politique. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Télécommunications | Blackout Internet | L'Iran maintient un blackout internet national depuis 45 jours, dépassant 1000 heures de coupure. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Ressources Naturelles | Stratégie Minière | Montée en gamme de la stratégie américaine en Afrique pour sécuriser les métaux critiques face à la Chine. | [IRIS](https://www.iris-france.org/de-lobito-a-project-vault-la-montee-en-gamme-de-la-strategie-miniere-etats-unienne-en-afrique/) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet des articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Avis du CERT-FR (Plusieurs) | CERT-FR | 13/04/2026 | France | Alerte de sécurité | Notification officielle des vulnérabilités critiques affectant Microsoft, Adobe et Python. | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/) |
| Seizure of W3LL Store | FBI | 13/04/2026 | USA / Indonésie | 18 U.S.C. §§ 981, 982 | Mandat de saisie des domaines et infrastructures liés au service de phishing W3LL. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-takedown-of-w3ll-phishing-service-leads-to-developer-arrest/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Éducation | Spring Lake Park Schools | Fermeture des écoles suite à une attaque suspectée de ransomware. | [DataBreaches](https://databreaches.net/2026/04/13/mn-spring-lake-park-schools-closed-after-suspected-ransomware-attack/) |
| Juridique | Wood Smith Henning & Berman | Exfiltration de 3.6 GB de données juridiques confidentielles par Silent Ransom Group. | [DataBreaches](https://databreaches.net/2026/04/13/a-silent-threat-loud-consequences-ransom-group-hits-law-firms-hard/) |
| Loisirs | Basic-Fit | Fuite de données affectant 1 million de membres (noms, emails, coordonnées bancaires). | [Le Monde](https://www.lemonde.fr/pixels/article/2026/04/13/fuite-de-donnees-chez-basic-fit-un-million-de-membres-concernes-des-coordonnees-bancaires-piratees_6679702_4408996.html) |
| Santé | Signature Healthcare | Vol de 2TB de données patient par le groupe Anubis. Systèmes toujours en mode dégradé. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Technologie | Rockstar Games | Fuite de 78 millions d'enregistrements (analytics, comportement joueurs) via Anodot/Snowflake. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/stolen-rockstar-games-analytics-data-leaked-by-extortion-gang/) |
| Tourisme | Booking.com | Accès non autorisé à des données de réservation sensibles, forçant la réinitialisation des codes PIN. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-bookingcom-data-breach-forces-reservation-pin-resets/) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées.
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2026-34621 | 8.6 - 9.6 | Non mentionné | TRUE | Adobe Acrobat & Reader | Exécution de code à distance (RCE) | T1203, T1059.003 | Exploitation active via des fichiers PDF malveillants contournant la sandbox. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/adobe-rolls-out-emergency-fix-for-acrobat-reader-zero-day-flaw/) |
| CVE-2026-27681 | 9.9 | Non mentionné | FALSE | SAP BPC & BW | Injection SQL | T1190 | Absence de vérification d'autorisation permettant de manipuler la base de données. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-27681) |
| CVE-2026-20131 | 9.8 | Non mentionné | TRUE | Cisco Secure FMC | Désérialisation de données non fiables | T1190 | Permet l'exécution de code arbitraire avec les privilèges root. | [Recorded Future](https://www.recordedfuture.com/blog/march-2026-cve-landscape) |
| CVE-2026-39987 | 9.3 | Non mentionné | TRUE | Marimo (Python notebook) | Exécution de code à distance (RCE) | T1210 | Absence d'authentification sur le point de terminaison WebSocket /terminal/ws. | [Check Point](https://research.checkpoint.com/2026/13th-april-threat-intelligence-report/) |
| CVE-2026-5194 | Critical | Non mentionné | FALSE | wolfSSL | Validation cryptographique | T1557 | Mauvaise vérification de la taille du hash ECDSA permettant des certificats forgés. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-flaw-in-wolfssl-library-enables-forged-certificate-use/) |
| CVE-2026-22564 | 9.8 | Non mentionné | FALSE | UniFi Play PowerAmp/Audio Port | Contrôle d'accès incorrect | T1068 | Permet l'activation non autorisée de SSH pour modifier le système. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-22564) |
| CVE-2021-22681 | 9.8 | Non mentionné | TRUE | Rockwell Automation Logix | Contournement d'authentification | T1210 | Exploitation d'une clé cryptographique pour un accès non autorisé aux automates. | [Cybersecurity News](https://cybersecuritynews.com/iran-linked-cyberav3ngers-sets-sights/) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Adobe rolls out emergency fix for Acrobat, Reader zero-day flaw | Vulnérabilité zero-day activement exploitée. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/adobe-rolls-out-emergency-fix-for-acrobat-reader-zero-day-flaw/) |
| FBI takedown of W3LL phishing service leads to developer arrest | Succès majeur de la lutte contre le phishing-as-a-service. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/fbi-takedown-of-w3ll-phishing-service-leads-to-developer-arrest/) |
| Iran-Linked CyberAv3ngers Sets Sights on Water Utilities | Menace critique sur les infrastructures vitales. | [Cybersecurity News](https://cybersecuritynews.com/iran-linked-cyberav3ngers-sets-sights/) |
| Monitoring Cyberattacks Directly Linked to the US-Israel-Iran Military Conflict | Analyse géopolitique essentielle du conflit en cours. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| OpenAI rotates macOS certs after Axios attack hit code-signing workflow | Supply chain attack majeure touchant des outils de développement. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/openai-rotates-macos-certs-after-axios-attack-hit-code-signing-workflow/) |
| Phantom in the vault: Obsidian abused to deliver PhantomPulse RAT | Nouveau vecteur d'attaque original via des applications de productivité. | [Elastic Security](https://www.elastic.co/security-labs/phantom-in-the-vault) |
| Stolen Rockstar Games analytics data leaked by extortion gang | Compromission cloud via supply chain (Anodot/Snowflake). | [BleepingComputer](https://www.bleepingcomputer.com/news/security/stolen-rockstar-games-analytics-data-leaked-by-extortion-gang/) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| ISC Stormcast | Podcast sans contenu textuel détaillé pour analyse. | [SANS](https://isc.sans.edu/diary/rss/32894) |
| The Registry Analyst's Toolkit | Article éducatif sur des outils de forensic, pas d'actualité menace immédiate. | [Cyberengage](https://www.cyberengage.org/post/the-registry-analyst-s-toolkit-choosing-your-weapon) |
| Une politique étrangère gériatrique | Analyse politique pure sans dimension cyber technique. | [IRIS](https://www.iris-france.org/une-politique-etrangere-geriatrique/) |

<br>
<br>
<div id="articles"></div>

# ARTICLES

<div id="exploitation-active-dune-zero-day-dans-adobe-acrobat-et-reader"></div>

## Exploitation active d'une zero-day dans Adobe Acrobat et Reader
Adobe a publié une mise à jour d'urgence pour corriger la vulnérabilité CVE-2026-34621, exploitée depuis décembre 2025. Cette faille critique permet à des fichiers PDF malveillants de contourner les restrictions de la sandbox pour invoquer des API JavaScript privilégiées. L'attaque observée permet l'exécution de code arbitraire ainsi que le vol de fichiers locaux. Les campagnes actives utilisent des leurres en langue russe liés à l'industrie pétrolière et gazière. Aucun acte de la part de l'utilisateur n'est requis au-delà de l'ouverture du document. Le chercheur Haifei Li de EXPMON a identifié la faille après une soumission sur VirusTotal. Adobe a initialement noté la faille à 9.6 avant de la ramener à 8.6 suite à un changement de vecteur. Les versions Windows et macOS sont toutes deux impactées. Les administrateurs doivent déployer les correctifs immédiatement via le menu d'aide de l'application.

**Analyse de l'impact** : Impact critique sur la confidentialité et l'intégrité des systèmes utilisant Adobe Acrobat. La capacité de vol de données locales sans interaction complexe rend cette menace particulièrement dangereuse pour les entreprises.

**Recommandations** :
* Mettre à jour Adobe Acrobat et Reader vers les versions 26.001.21411 (DC) ou 24.001.30362 (2024).
* Sensibiliser les utilisateurs à ne pas ouvrir de documents PDF provenant de sources non sollicitées.
* Isoler l'ouverture de documents externes dans des environnements virtualisés ou restreints (VDI).

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié (indices suggérant un acteur lié à des intérêts russes) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1203: Exploitation for Client Execution <br/> * T1059.003: JavaScript <br/> * T1083: File and Directory Discovery |
| Observables & Indicateurs de compromission | * yummy_adobe_exploit_uwu.pdf |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/adobe-rolls-out-emergency-fix-for-acrobat-reader-zero-day-flaw/
* https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0429/

<br>
<br>

<div id="campagne-phantompulse-abus-de-lecosysteme-de-plugins-dobsidian"></div>

## Campagne PhantomPulse : abus de l'écosystème de plugins d'Obsidian
Elastic Security Labs a découvert une campagne nommée REF6598 ciblant les secteurs de la finance et des cryptomonnaies. L'attaque utilise l'application de prise de notes Obsidian comme vecteur d'accès initial par ingénierie sociale sur LinkedIn et Telegram. Les attaquants invitent les victimes à rejoindre un "coffre" (vault) partagé contenant des plugins malveillants (Shell Commands et Hider). Une fois le coffre ouvert et la synchronisation des plugins activée, du code malveillant est exécuté silencieusement. L'attaque est multiplateforme (Windows et macOS). Sur Windows, elle déploie un nouveau RAT appelé PHANTOMPULSE, généré par IA, qui utilise la blockchain Ethereum pour résoudre l'adresse de son serveur C2. Sur macOS, un dropper AppleScript est utilisé avec un mécanisme de secours via Telegram. Le chargeur PHANTOMPULL assure la persistance et le chargement en mémoire des payloads.

**Analyse de l'impact** : Risque élevé de compromission totale du poste de travail. L'utilisation d'applications de confiance et de configurations JSON pour l'exécution rend la détection par les antivirus traditionnels très difficile.

**Recommandations** :
* Surveiller la création de processus enfants suspects à partir de l'exécutable Obsidian.exe.
* Restreindre l'utilisation de plugins communautaires non vérifiés dans les outils de productivité.
* Auditer les connexions réseau sortantes vers des explorateurs de blockchain (Blockscout, Etherscan) à partir de processus utilisateurs.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | REF6598 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.003: Spearphishing via Service <br/> * T1059.001: PowerShell <br/> * T1105: Ingress Tool Transfer <br/> * T1584.005: Botnet (Blockchain C2) |
| Observables & Indicateurs de compromission | ```* 195.3.222.251 * panel.fefea22134.net * syncobs.exe (70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980) * Wallet: 0xc117688c530b660e15085bF3A2B664117d8672aA``` |

### Source (url) du ou des articles
* https://www.elastic.co/security-labs/phantom-in-the-vault

<br>
<br>

<div id="attaque-de-la-chaine-dapprovisionnement-axios-et-impact-sur-openai"></div>

## Attaque de la chaîne d'approvisionnement Axios et impact sur OpenAI
OpenAI a dû procéder à la rotation de ses certificats de signature de code macOS après une attaque supply chain. Un workflow GitHub Actions légitime a exécuté une version compromise du package npm Axios (v1.14.1) le 31 mars 2026. Cette version malveillante, liée à l'acteur nord-coréen UNC1069, déployait un cheval de Troie d'accès distant (RAT). Bien qu'aucune preuve d'exfiltration de données d'utilisateurs d'OpenAI n'ait été trouvée, les certificats utilisés pour signer les applications macOS (ChatGPT Desktop, Codex) ont été jugés potentiellement exposés. Par ailleurs, une vulnérabilité CVE-2026-40175 a été découverte dans Axios, permettant l'exfiltration de métadonnées cloud via la pollution de prototype. Cette faille permet d'injecter des en-têtes HTTP malveillants pour voler des identifiants IAM sur AWS. OpenAI demande à tous les utilisateurs macOS de mettre à jour leurs applications avant le 8 mai 2026, date à laquelle les anciens certificats seront révoqués.

**Analyse de l'impact** : Risque de distribution de logiciels malveillants signés avec l'identité légitime d'OpenAI. La vulnérabilité d'Axios expose potentiellement des milliers d'applications cloud à des prises de contrôle de comptes AWS.

**Recommandations** :
* Mettre à jour Axios vers la version 1.15.0 ou ultérieure.
* Mettre à jour les applications desktop OpenAI pour macOS.
* Auditer les dépendances npm pour détecter d'éventuelles pollutions de prototype.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UNC1069 (Corée du Nord) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Software Supply Chain Compromise <br/> * T1553.002: Code Signing <br/> * T1555: Credentials from Password Stores |
| Observables & Indicateurs de compromission | * Malicious Axios v1.14.1 |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/openai-rotates-macos-certs-after-axios-attack-hit-code-signing-workflow/
* https://cybersecuritynews.com/axios-vulnerability-poc-released/

<br>
<br>

<div id="handala-escalade-cyber-contre-les-infrastructures-critiques-des-eau"></div>

## Handala : escalade cyber contre les infrastructures critiques des EAU
Le groupe hacktiviste pro-iranien Handala a revendiqué une attaque cybernétique massive contre les Émirats Arabes Unis le 12 avril 2026. L'opération a ciblé trois institutions majeures de Dubaï : les autorités judiciaires (Dubai Courts), foncières (Dubai Land) et des transports (RTA). Handala prétend avoir détruit 6 pétaoctets de données et exfiltré 149 téraoctets de documents classifiés. Cette action est présentée comme une punition contre le leadership des EAU pour son alignement politique dans le conflit opposant les États-Unis, Israël et l'Iran. Bien que ces chiffres ne soient pas encore vérifiés indépendamment, ils marquent une escalade significative. Le groupe utilise des techniques de "wiper" (effacement de données) et de "hack-and-leak". Cette attaque survient juste après l'échec de négociations de paix et l'annonce d'un blocus naval américain contre l'Iran.

**Analyse de l'impact** : Risque de paralysie majeure des services publics et juridiques d'un État allié. L'impact psychologique et la perte de confiance dans les infrastructures critiques sont les objectifs premiers de cette opération d'influence.

**Recommandations** :
* Renforcer la surveillance des accès distants pour les organisations opérant dans la région du Golfe.
* Valider l'intégrité et la disponibilité des sauvegardes hors ligne (offline/air-gapped).
* Bloquer les communications vers les infrastructures connues de Handala et du groupe Void Manticore.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Handala (lié à l'Iran/Void Manticore) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1565: Data Manipulation <br/> * T1485: Data Destruction <br/> * T1560: Archive Collected Data |
| Observables & Indicateurs de compromission | * Aucun IoC technique spécifique fourni dans le rapport public. |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict
* https://securityaffairs.com/190716/hacking/iran-linked-group-handala-claims-to-have-breached-three-major-uae-organizations.html

<br>
<br>

<div id="demantelement-de-la-plateforme-de-phishing-w3ll"></div>

## Démantèlement de la plateforme de phishing W3LL
Le FBI et les autorités indonésiennes ont démantelé "W3LL Store", une plateforme mondiale de Phishing-as-a-Service (PhaaS). L'opération a conduit à la saisie des infrastructures et à l'arrestation du développeur présumé en Indonésie. W3LL permettait aux cybercriminels de déployer des kits de phishing sophistiqués capables de contourner l'authentification multi-facteurs (MFA) via des attaques de type "Adversary-in-the-Middle" (AitM). La plateforme a facilité la compromission de plus de 25 000 comptes d'entreprise entre 2019 et 2023, générant des tentatives de fraude estimées à 20 millions de dollars. Les cibles principales étaient les comptes Microsoft 365, utilisés ensuite pour des fraudes au virement bancaire (BEC). Le kit était vendu environ 500 dollars. Malgré la fermeture du site web initial, le groupe continuait de vendre ses outils via des messageries chiffrées.

**Analyse de l'impact** : Réduction significative de l'offre d'outils de phishing haut de gamme, bien que la menace BEC reste persistante via d'autres plateformes.

**Recommandations** :
* Utiliser des méthodes d'authentification résistantes au phishing (FIDO2/Clés de sécurité physiques).
* Configurer des politiques d'accès conditionnel strictes pour les accès à Microsoft 365.
* Sensibiliser les employés à la détection des URL de portails de connexion suspects.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | W3LL |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.002: Phishing: Spearphishing Link <br/> * T1556: Modify Authentication Process <br/> * T1557: Adversary-in-the-Middle |
| Observables & Indicateurs de compromission | * w3ll.store |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/fbi-takedown-of-w3ll-phishing-service-leads-to-developer-arrest/

<br>
<br>

<div id="cyberav3ngers-menaces-persistantes-sur-les-systemes-industriels-deau"></div>

## CyberAv3ngers : menaces persistantes sur les systèmes industriels d'eau
Le groupe CyberAv3ngers, affilié au Corps des Gardiens de la révolution islamique d'Iran (IRGC-CEC), intensifie ses attaques contre les infrastructures critiques américaines. Une alerte conjointe du FBI, de la CISA et de la NSA confirme l'exploitation active de contrôleurs logiques programmables (PLC) Rockwell Automation et Unitronics. Le groupe utilise la vulnérabilité CVE-2021-22681 pour contourner l'authentification des automates Rockwell Logix et manipuler les données HMI/SCADA. Plus de 3 000 appareils Rockwell restent exposés sur internet sans protection adéquate. Le groupe déploie également le malware modulaire IOCONTROL, conçu pour les environnements IoT et OT basés sur Linux, utilisant le protocole MQTT sur TLS pour masquer ses communications C2. Des perturbations opérationnelles et des pertes financières ont été signalées dans les secteurs de l'eau et de l'énergie.

**Analyse de l'impact** : Risque critique de sabotage physique et d'interruption de services vitaux (eau potable, électricité).

**Recommandations** :
* Déconnecter immédiatement tous les PLC et dispositifs OT de l'internet public.
* Mettre les commutateurs de mode physique des automates sur "Run" pour bloquer les modifications logiques à distance.
* Surveiller le trafic MQTT sur le port 8883 dans les segments réseau industriels.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | CyberAv3ngers (Storm-0784) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T0812: Default Credentials <br/> * T0843: Program Upload <br/> * T0859: Valid Accounts |
| Observables & Indicateurs de compromission | * Port: 8883 (MQTT TLS) <br/> * Malware: IOCONTROL |

### Source (url) du ou des articles
* https://cybersecuritynews.com/iran-linked-cyberav3ngers-sets-sights/
* https://research.checkpoint.com/2026/13th-april-threat-intelligence-report/