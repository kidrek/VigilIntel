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
  * [Compromission massive de la chaîne d'approvisionnement npm : le cas axios](#compromission-massive-de-la-chaine-dapprovisionnement-npm--le-cas-axios)
  * [Campagne teampcp : quand les outils de sécurité deviennent des armes](#campagne-teampcp--quand-les-outils-de-securite-deviennent-des-armes)
  * [Escalade cyber dans le conflit us-israël-iran](#escalade-cyber-dans-le-conflit-us-israël-iran)
  * [Novoice : un rootkit android infectant des millions de terminaux](#novoice--un-rootkit-android-infectant-des-millions-de-terminaux)
  * [Eviltokens : industrialisation du phishing par code d'appareil microsoft](#eviltokens--industrialisation-du-phishing-par-code-dappareil-microsoft)
  * [Nocobase : évasion de sandbox critique et accès root](#nocobase--evasion-de-sandbox-critique-et-acces-root)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage cyber de mars 2026 est marqué par une industrialisation sans précédent des attaques sur la chaîne d'approvisionnement logicielle, illustrée par la compromission majeure du paquet npm `axios` par la Corée du Nord. Cette opération, attribuée à UNC1069, démontre la capacité des acteurs étatiques à exploiter des comptes de mainteneurs de confiance pour diffuser des chevaux de Troie multiplateformes à une échelle globale. Parallèlement, le groupe TeamPCP a transformé des outils de sécurité comme le scanner Trivy en vecteurs d'exfiltration de secrets CI/CD, provoquant des vagues de compromissions en cascade chez des acteurs majeurs. Sur le front géopolitique, le conflit Iran-Israël-États-Unis génère une activité cyber d'une intensité rare, mêlant hacktivisme d'État, wipers destructeurs et opérations d'influence synchronisées avec des frappes cinétiques. L'émergence du service "EvilTokens" signale une sophistication accrue du Phishing-as-a-Service, ciblant spécifiquement les flux d'autorisation OAuth 2.0 de Microsoft pour contourner le MFA. On observe également une persistance inquiétante des vulnérabilités de type "Use-After-Free" dans les moteurs de rendu web, Chrome ayant dû corriger son quatrième zero-day de l'année. Enfin, la condamnation historique des dirigeants d'Intellexa en Grèce marque un tournant juridique dans la lutte contre l'impunité des fournisseurs de logiciels espions commerciaux en Europe.

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
| APT28 (FancyBear) | Gouvernements, Militaires | XSS personnalisé, vol d'identifiants, exfiltration d'emails | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-04/) |
| APT Iran | Secteur de la défense (Lockheed Martin) | Exfiltration de données, ciblage d'ICS, vente sur le Dark Web | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| ByteToBreach | Administration publique (Suède) | Vol et vente de données gouvernementales | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-04/) |
| Cyber Av3ngers | Infrastructures critiques (ICS/OT) | Compromission de PLC, sabotage de systèmes d'alerte | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Handala Hack Team | Santé, Défense, Industrie | Attaques par wiper, doxxing, compromission de comptes admin | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-04/), [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Homeland Justice | Parlement (Albanie) | Wiper de données, perturbation de services emails | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-04/) |
| Kimsuky | Éducation, Gouvernement | Fichiers LNK malveillants, scripts PowerShell, backdoors Python | [AhnLab](https://asec.ahnlab.com/en/93151/) |
| Pay2Key | Santé, Infrastructures critiques | Pseudo-ransomware à but destructeur | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Red Menshen | Télécommunications | Backdoor noyau Linux (BPFdoor) | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-04/) |
| Sapphire Sleet (UNC1069) | Finance, Crypto, Tech | Supply chain npm (Axios), RAT WAVESHAPER | [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/), [Elastic](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all) |
| Silver Dragon | Administration publique (Asie/Europe) | Phishing, Cobalt Strike, backdoors Google Drive | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-04/) |
| TeamPCP | Technologie, Cloud, CI/CD | Supply chain (Trivy, LiteLLM, Telnyx), vol de secrets | [SANS ISC](https://isc.sans.edu/diary/rss/32856) |
| UAC-0255 | Secteur public et privé (Ukraine) | Phishing usurpant le CERT-UA, RAT AGEWHEEZE | [SOC Prime](https://socprime.com/blog/uac-0255-distributing-agewheeze-rat/) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Administration publique | Conflit cyber | Attaque de Homeland Justice contre le parlement albanais en représailles à l'accueil de l'opposition iranienne. | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-04/) |
| Énergie / Transport | Sanctions | Les États-Unis placent le pétrole vénézuélien sous licence stricte (GL52) en réponse à la crise énergétique mondiale. | [Portail de l'IE](https://www.portail-ie.fr/univers/enjeux-de-puissances-et-geoeconomie/2026/general-license-52-le-petrole-du-venezuela-sous-licence/) |
| Gouvernement | Sanctions | Le Conseil de l'UE sanctionne des entités chinoises et iraniennes pour des cyberattaques contre les États membres. | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-04/) |
| Télécommunications | Censure | L'Iran impose un black-out internet national de 33 jours suite aux frappes israélo-américaines. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Transport | Sabotage informationnel | Compromission d'écrans dans des gares israéliennes pour diffuser de fausses alertes de missiles. | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-04/) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| AI Omnibus Proposal | EDRi | 01/04/2026 | Union Européenne | AI Act / AI Omnibus | Accélération du processus législatif pour réglementer les systèmes d'IA à risque. | [EDRi](https://edri.org/our-work/edri-gram-1-april-2026/) |
| Condamnation Predatorgate | EDRi | 01/04/2026 | Grèce | Droit pénal grec | Condamnation historique des dirigeants d'Intellexa pour surveillance illégale. | [EDRi](https://edri.org/our-work/predatorgate-breaking-the-chain-of-impunity-of-the-spyware-underworld/) |
| Digital Fairness Act (DFA) | EDRi / Bits of Freedom | 01/04/2026 | Union Européenne | DFA | Proposition visant à réguler le design addictif et la gamification des réseaux sociaux. | [EDRi](https://edri.org/our-work/new-study-reveals-how-young-people-are-influenced-by-gamification-features-on-snapchat/) |
| Global Coalition on Telecoms | GCOT | 03/03/2026 | International | Principes de sécurité 6G | Établissement de principes volontaires pour la résilience et la sécurité des futurs réseaux 6G. | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-04/) |
| US General License 52 | Trésor US (OFAC) | 18/03/2026 | États-Unis / Venezuela | GL52 / EO 14373 | Régulation des transactions pétrolières vénézuéliennes via des fonds séquestres américains. | [Portail de l'IE](https://www.portail-ie.fr/univers/enjeux-de-puissances-et-geoeconomie/2026/general-license-52-le-petrole-du-venezuela-sous-licence/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Administration publique | Ministère des Finances (Pays-Bas) | Brèche confirmée de certains systèmes ; services critiques épargnés. | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-04/) |
| Forces de l'ordre | Police Nationale (Pays-Bas) | Brèche suite à une campagne de phishing réussie ; pas de données sensibles exposées. | [CERT-EU](https://cert.europa.eu/publications/threat-intelligence/cb26-04/) |
| Média / Développement personnel | SUCCESS | Exposition de 250 000 emails, noms, adresses physiques et hachages bcrypt pour le personnel. | [HIBP](https://haveibeenpwned.com/Breach/SUCCESS) |
| Technologie / IA | Mercor AI | Exfiltration de 4 To de données (code source, documents d'identité) via des identifiants VPN volés. | [SANS ISC](https://isc.sans.edu/diary/rss/32856) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2026-34156 | 10.0 | N/A | FALSE | NocoBase | Sandbox Escape / RCE | T1211: Exploitation for Privilege Escalation | Évasion de sandbox Node.js via l'objet console permettant un accès root. | [SecurityOnline](https://securityonline.info/nocobase-critical-rce-sandbox-escape-cve-2026-34156/) |
| CVE-2026-21962 | 10.0 | N/A | TRUE | Oracle WebLogic | Remote Code Execution | T1190: Exploit Public-Facing Application | RCE non authentifiée via la console d'administration WebLogic. | [CybersecurityNews](https://cybersecuritynews.com/hackers-exploiting-weblogic-rce-vulnerabilities/) |
| CVE-2026-1579 | 9.8 | N/A | FALSE | PX4 Autopilot | Unauthenticated Shell | T1210: Exploitation of Remote Services | Accès shell non authentifié via le protocole MAVLink non sécurisé. | [SecurityOnline](https://securityonline.info/px4-autopilot-mavlink-vulnerability-cve-2026-1579/) |
| CVE-2026-5281 | 8.8 | N/A | TRUE | Google Chrome | Use-after-free | T1189: Drive-by Compromise | Vulnérabilité critique dans le composant Dawn (WebGPU) exploitée activement. | [CISA](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-google-chrome-could-allow-for-arbitrary-code-execution_2026-028) |
| CVE-2026-21765 | 8.8 | N/A | FALSE | HCL BigFix | Insecure Permissions | T1552.004: Private Keys | Permissions excessives sur les clés cryptographiques privées sous Windows. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-21765) |
| CVE-2026-3987 | 8.6 | N/A | FALSE | WatchGuard Firebox | Path Traversal | T1083: File and Directory Discovery | Traversée de répertoires permettant l'exécution de code privilégié. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-3987) |
| CVE-2025-15101 | 8.5 | N/A | FALSE | Routeurs ASUS | CSRF | T1204.001: Malicious Link | Cross-Site Request Forgery permettant de prendre le contrôle de l'interface de gestion. | [SecurityOnline](https://securityonline.info/asus-router-firmware-update-csrf-cve-2025-15101/) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Compromission massive de la chaîne d'approvisionnement npm : le cas axios | Menace critique sur un paquet ultra-répandu (100M downloads/semaine) attribuée à la Corée du Nord. | [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/) |
| Campagne teampcp : quand les outils de sécurité deviennent des armes | Analyse technique d'une campagne de vol de secrets via des outils de scan (Trivy). | [SANS ISC](https://isc.sans.edu/diary/rss/32856) |
| Escalade cyber dans le conflit us-israël-iran | Synthèse des opérations cyber synchronisées avec des tensions cinétiques majeures. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Novoice : un rootkit android infectant des millions de terminaux | Découverte d'un malware de masse sur Google Play avec des capacités de rootkit. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/novoice-android-malware-on-google-play-infected-23-million-devices/) |
| Eviltokens : industrialisation du phishing par code d'appareil microsoft | Nouvelle tendance PhaaS exploitant les flux d'autorisation OAuth 2.0. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-eviltokens-service-fuels-microsoft-device-code-phishing-attacks/) |
| Nocobase : évasion de sandbox critique et accès root | Vulnérabilité majeure avec score CVSS 10.0 impactant les plateformes extensibles. | [SecurityOnline](https://securityonline.info/nocobase-critical-rce-sandbox-escape-cve-2026-34156/) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| Free VPNs leak your data while claiming privacy | Analyse générale sans indicateurs techniques nouveaux ou menace spécifique immédiate. | [Security Affairs](https://securityaffairs.com/190239/security/free-vpns-leak-your-data-while-claiming-privacy.html) |
| SUCCESS - 253,510 breached accounts | Notification de violation de données pure (traitée en synthèse). | [HIBP](https://haveibeenpwned.com/Breach/SUCCESS) |
| Malicious Script That Gets Rid of ADS | Analyse de script isolée de faible envergure par rapport aux autres menaces sélectionnées. | [SANS ISC](https://isc.sans.edu/diary/rss/32854) |
| The Shift: An Era of Quantum Geopolitics | Article de réflexion stratégique sans éléments techniques actionnables. | [Recorded Future](https://www.recordedfuture.com/blog/the-shift-an-era-of-quantum-geopolitics) |

<br>
<br>
<div id="articles"></div>

# ARTICLES

<div id="compromission-massive-de-la-chaine-dapprovisionnement-npm--le-cas-axios"></div>

## Compromission massive de la chaîne d'approvisionnement npm : le cas axios
Le populaire client HTTP Axios, utilisé par des millions de développeurs, a subi une attaque par empoisonnement de la chaîne d'approvisionnement. Un compte de mainteneur compromis a permis de publier les versions malveillantes 1.14.1 et 0.30.4. Ces versions injectent une dépendance factice appelée `plain-crypto-js` qui déclenche un script `postinstall` sans interaction de l'utilisateur. L'attaque déploie un cheval de Troie d'accès à distance (RAT) multiplateforme sur Windows, macOS et Linux. L'infrastructure C2 est attribuée à l'acteur nord-coréen Sapphire Sleet (UNC1069). Le malware effectue un nettoyage anti-forensic agressif après installation pour masquer ses traces. Les attaquants ont utilisé des versions "propres" de la dépendance factice auparavant pour réduire la méfiance. Des centaines de milliers de systèmes pourraient être infectés via des builds automatisés ou des mises à jour automatiques. Microsoft et Elastic ont publié des détections comportementales pour contrer cette menace.

**Analyse de l'impact** : Impact critique global. Axios compte plus de 70 millions de téléchargements hebdomadaires. Toute organisation utilisant des versions non épinglées ou des processus CI/CD automatisés est potentiellement compromise, avec un risque de vol de code source, de secrets cloud et de persistence à long terme.

**Recommandations** :
*   Rétrograder immédiatement vers les versions saines : 1.14.0 ou 0.30.3.
*   Épingler les versions exactes dans `package.json` et utiliser `package-lock.json`.
*   Effectuer une rotation complète de tous les secrets (clés AWS, tokens npm, clés SSH) exposés sur les machines de build et de développement.
*   Utiliser l'option `--ignore-scripts` lors de l'installation de paquets dans les pipelines CI/CD.
*   Surveiller les connexions sortantes vers le domaine `sfrclak[.]com` sur le port 8000.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Sapphire Sleet (UNC1069) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.001: Supply Chain Compromise * T1059.007: JavaScript * T1059.001: PowerShell * T1547.001: Registry Run Keys * T1027: Obfuscated Files |
| Observables & Indicateurs de compromission | ```* sfrclak[.]com * 142.11.206[.]73 * SHA256: 92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a (macOS) * SHA256: ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c (Windows) * Path: /tmp/ld.py (Linux)``` |

### Source (url) du ou des articles
* https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/
* https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all
* https://unit42.paloaltonetworks.com/axios-supply-chain-attack/
* https://fieldeffect.com/blog/axios-npm-package-compromised-unc1069

<br>
<br>

<div id="campagne-teampcp--quand-les-outils-de-securite-deviennent-des-armes"></div>

## Campagne teampcp : quand les outils de sécurité deviennent des armes
Le groupe TeamPCP mène une campagne agressive ciblant les environnements CI/CD en compromettant des outils de sécurité et des bibliothèques populaires. Ils ont réussi à injecter des portes dérobées dans le scanner de vulnérabilités Trivy, ainsi que dans les paquets LiteLLM et Telnyx sur PyPI. L'objectif principal est le vol d'identifiants VPN, de jetons d'accès cloud et de secrets Kubernetes. La start-up Mercor AI a confirmé une fuite de 4 To de données suite à cette campagne. TeamPCP utilise l'outil légitime TruffleHog pour valider immédiatement les secrets volés. Les attaquants agissent rapidement, effectuant des opérations de découverte cloud dans les 24 heures suivant l'obtention des accès. Des variantes malveillantes utilisent la stéganographie dans des fichiers WAV pour dissimuler leurs payloads. Le groupe adopte une signature opérationnelle audacieuse, utilisant des noms de ressources explicites comme "massive-exfil". Cette campagne met en lumière la fragilité de la confiance accordée aux outils de sécurité open-source.

**Analyse de l'impact** : Impact élevé sur la confidentialité des données cloud. La compromission d'outils de scan comme Trivy permet une infection transversale de milliers de pipelines CI/CD, entraînant une exfiltration massive de secrets permettant des accès persistants aux infrastructures AWS et Azure.

**Recommandations** :
*   Vérifier l'intégrité des versions de Trivy et des paquets Python (LiteLLM < 1.82.7, Telnyx).
*   Rechercher dans les logs cloud des appels API inhabituels provenant de TruffleHog ou d'outils de découverte.
*   Mettre en place une rotation systématique des secrets CI/CD tous les 30 à 90 jours.
*   Auditer les environnements pour détecter des ressources nommées "pawn" ou "massive-exfil".
*   Utiliser des mécanismes de signature de code et de vérification d'attestation SLSA pour les dépendances.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TeamPCP |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Compromise Software Supply Chain * T1552.001: Credentials In Files * T1087.004: Cloud Account Discovery * T1027.003: Steganography |
| Observables & Indicators of compromise | ```* CVE-2026-33634 * Package: LiteLLM v1.82.7 / v1.82.8 * Package: Telnyx v4.87.1 / v4.87.2 * Resource names: "pawn", "massive-exfil"``` |

### Source (url) du ou des articles
* https://isc.sans.edu/diary/rss/32856
* https://cert.europa.eu/publications/threat-intelligence/cb26-04/

<br>
<br>

<div id="escalade-cyber-dans-le-conflit-us-israël-iran"></div>

## Escalade cyber dans le conflit us-israël-iran
Le conflit militaire actuel entre les États-Unis, Israël et l'Iran a déclenché une vague sans précédent d'opérations cyber offensives. Le groupe pro-iranien Handala Hack Team a mené des attaques destructrices par wiper, supprimant 50 To de données chez Stryker, une entreprise médicale américaine. L'Iran subit un black-out internet quasi total depuis plus de 30 jours, visant à limiter la visibilité des événements sur le terrain. Les groupes d'État iraniens adoptent désormais des outils et des structures inspirés du cybercrime, comme le ransomware Pay2Key utilisé à des fins purement destructrices. Des campagnes d'influence massives ont été observées sur X (ex-Twitter), utilisant du contenu altéré par IA pour simuler des attaques de missiles. Le groupe Cyber Av3ngers prétend avoir saboté les systèmes d'alerte aux raids aériens en Israël. Ces attaques ne visent plus seulement le renseignement mais cherchent à causer des dommages psychologiques et physiques directs aux populations civiles. Le niveau de menace pour les infrastructures critiques mondiales est actuellement jugé critique et détérioré.

**Analyse de l'impact** : Risque élevé de dommages collatéraux pour les entreprises ayant des liens indirects avec les zones de conflit. Les attaques par wiper et le sabotage d'ICS/OT représentent un danger de mort direct pour les civils et une menace de rupture pour les chaînes logistiques maritimes et énergétiques.

**Recommandations** :
*   Renforcer la segmentation réseau entre les systèmes IT et OT (systèmes industriels).
*   Encaisser les identifiants d'administration dans des coffres-forts sécurisés avec approbation multi-admin.
*   Maintenir des sauvegardes hors-ligne (offline) pour contrer les attaques par wiper.
*   Auditer l'exposition OSINT du personnel clé dans les secteurs de la défense et de la santé.
*   Enforcer le MFA résistant au phishing (FIDO2) sur tous les accès VPN.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Handala Hack, Cyber Av3ngers, Pay2Key, Homeland Justice |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1485: Data Destruction * T1565: Data Manipulation * T1531: Account Access Removal * T0814: Control PLC |
| Observables & Indicateurs de compromission | ```* Domaine: cert-ua[.]tech * Email targeting: Kash Patel (FBI) * Malware: SHADOWSNIFF, SALATSTEALER * Video proof (53.5 MB) de sabotage d'ICS``` |

### Source (url) du ou des articles
* https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict
* https://cert.europa.eu/publications/threat-intelligence/cb26-04/

<br>
<br>

<div id="novoice--un-rootkit-android-infectant-des-millions-de-terminaux"></div>

## Novoice : un rootkit android infectant des millions de terminaux
Plus de 50 applications sur Google Play, téléchargées plus de 2,3 millions de fois, transportaient le malware NoVoice. Ces applications semblaient légitimes (nettoyeurs, galeries) mais contenaient une charge utile cachée via la stéganographie dans des images PNG. NoVoice exploite des vulnérabilités Android anciennes (2016-2021) pour obtenir des privilèges root sur le terminal. Une fois rooté, le malware remplace les bibliothèques système critiques par des wrappers malveillants. Il installe une persistance multicouche qui survit même à une réinitialisation d'usine en se logeant dans la partition système. Sa fonction principale observée est le vol de sessions WhatsApp en exfiltrant les bases de données chiffrées et les clés de protocole Signal. Le malware dispose d'un watchdog qui vérifie l'intégrité du rootkit toutes les 60 secondes. NoVoice partage des similitudes de code avec le cheval de Troie Triada, suggérant des auteurs expérimentés.

**Analyse de l'impact** : Impact élevé sur la vie privée. Le malware permet un contrôle total de l'appareil et une usurpation d'identité via le clonage de comptes WhatsApp, ciblant principalement les utilisateurs n'ayant pas mis à jour leurs correctifs de sécurité depuis 2021.

**Recommandations** :
*   Mettre à jour immédiatement les appareils Android vers une version disposant d'un patch de sécurité postérieur à mai 2021.
*   Effectuer un audit des applications installées et supprimer celles provenant de développeurs peu connus.
*   Surveiller les anomalies de consommation batterie et de trafic réseau en arrière-plan.
*   Éviter d'accorder des permissions excessives aux applications de type "Utility" ou "Games".

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non mentionné (Similitudes avec Triada) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1398: Rootkit * T1406: Obfuscated Files or Information * T1417: Input Capture * T1533: Data from Local System |
| Observables & Indicateurs de compromission | ```* Package: com.facebook.utils (malveillant) * Fichiers: h.apk, enc.apk * Bibliothèques modifiées: libandroid_runtime.so, libmedia_jni.so``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/novoice-android-malware-on-google-play-infected-23-million-devices/

<br>
<br>

<div id="eviltokens--industrialisation-du-phishing-par-code-dappareil-microsoft"></div>

## Eviltokens : industrialisation du phishing par code d'appareil microsoft
Un nouveau kit de Phishing-as-a-Service (PhaaS) nommé "EvilTokens" automatise le vol de sessions Microsoft via le flux d'autorisation OAuth 2.0. Les victimes reçoivent des leurres PDF ou HTML contenant des QR codes ou des liens vers de faux documents DocuSign/SharePoint. Au lieu de demander un mot de passe, la page de phishing affiche un code de vérification et dirige l'utilisateur vers la page légitime de connexion d'appareil Microsoft. Lorsque l'utilisateur entre le code, l'attaquant reçoit un jeton d'accès et un jeton de rafraîchissement (refresh token). Cela permet un accès persistant sans avoir besoin de bypasser le MFA traditionnel, car le jeton est déjà validé par l'utilisateur. EvilTokens inclut des fonctionnalités avancées pour mener des attaques de Business Email Compromise (BEC) de manière automatisée. Les campagnes observées touchent principalement les rôles administratifs, financiers et RH. Le service est promu activement sur Telegram avec des plans pour supporter Gmail et Okta.

**Analyse de l'impact** : Impact moyen à élevé. Cette technique contourne efficacement de nombreux déploiements de MFA classiques en exploitant la confiance de l'utilisateur envers les URLs légitimes de Microsoft. Elle facilite des intrusions BEC rapides et difficiles à détecter.

**Recommandations** :
*   Désactiver le flux d'autorisation de code d'appareil Microsoft si l'usage n'est pas requis (PowerShell: `Set-MsolDeviceRegistrationServicePolicy`).
*   Sensibiliser les utilisateurs à ne jamais saisir de code d'appareil reçu par un lien non sollicité.
*   Utiliser des politiques d'Accès Conditionnel restreignant les connexions aux appareils gérés et conformes.
*   Rechercher les évènements de connexion "Device Code" suspects dans les logs Azure AD.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non mentionné (Opérateurs de PhaaS) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.002: Spearphishing Link * T1528: Steal Application Access Token * T1078.004: Cloud Accounts |
| Observables & Indicateurs de compromission | ```* "Continue to Microsoft" button in lures * EvilTokens PhaaS templates * suspicious OAuth token grants``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/new-eviltokens-service-fuels-microsoft-device-code-phishing-attacks/

<br>
<br>

<div id="nocobase--evasion-de-sandbox-critique-et-acces-root"></div>

## Nocobase : évasion de sandbox critique et accès root
Une vulnérabilité de score CVSS 10.0 a été découverte dans NocoBase, une plateforme de gestion de données et d'IA. La faille CVE-2026-34156 réside dans le nœud de script de flux de travail, qui permet d'exécuter du JavaScript. Bien qu'un bac à sable (sandbox) Node.js vm ait été utilisé, l'objet `console` de l'hôte y était passé directement. Un attaquant peut utiliser les flux `_stdout` ou `_stderr` pour remonter la chaîne de prototypes et accéder au constructeur de fonction de l'hôte. Une fois l'évasion réussie, l'attaquant peut charger n'importe quel module via `require()`. Cela permet l'exécution de code à distance (RCE) avec les privilèges root (`uid=0`) à l'intérieur du conteneur Docker. L'impact inclut le vol de variables d'environnement critiques comme les mots de passe de base de données. NocoBase a publié un correctif dans la version 2.0.28 pour corriger cette mauvaise configuration.

**Analyse de l'impact** : Impact critique sur l'intégrité et la confidentialité des serveurs NocoBase. La compromission permet un accès total au système de fichiers et au réseau interne de l'organisation via des shells inversés.

**Recommandations** :
*   Mettre à jour NocoBase vers la version 2.0.28 ou supérieure immédiatement.
*   Ne jamais passer d'objets globaux de l'hôte (comme `console`) directement dans une sandbox ; utiliser des proxys isolés.
*   Appliquer le principe de moindre privilège en exécutant les processus d'application en tant qu'utilisateurs non-root dans Docker.
*   Utiliser des modules de sandbox plus robustes comme `isolated-vm` au lieu de `vm` de base.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1211: Exploitation for Privilege Escalation * T1059.003: Windows Command Shell * T1059.004: Unix Shell |
| Observables & Indicateurs de compromission | ```* CVE-2026-34156 * process.env (DB_PASSWORD exfiltration) * usage de require('fs') dans les scripts de workflow``` |

### Source (url) du ou des articles
* https://securityonline.info/nocobase-critical-rce-sandbox-escape-cve-2026-34156/