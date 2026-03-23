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
  * [VoidStealer : une nouvelle technique de contournement de l'A-BE de Chrome](#voidstealer--une-nouvelle-technique-de-contournement-de-la-be-de-chrome)
  * [Campagne de phishing russe ciblant WhatsApp et Signal](#campagne-de-phishing-russe-ciblant-whatsapp-et-signal)
  * [Vulnérabilité critique RCE dans Oracle Identity Manager](#vulnerabilite-critique-rce-dans-oracle-identity-manager)
  * [Compromission massive de l'organisation GitHub d'Aqua Security par TeamPCP](#compromission-massive-de-lorganisation-github-daqua-security-par-teampcp)
  * [DarkSword : un kit d'exploitation iOS sophistiqué utilisé à l'échelle mondiale](#darksword--un-kit-dexploitation-ios-sophistique-utilise-a-lechelle-mondiale)
  * [Alerte critique de Rockwell Automation sur les contrôleurs industriels](#alerte-critique-de-rockwell-automation-sur-les-controleurs-industriels)
  * [Prise de contrôle totale via les commutateurs IP-KVM non sécurisés](#prise-de-controle-totale-via-les-commutateurs-ip-kvm-non-securises)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage actuel des cybermenaces est marqué par une sophistication accrue des techniques d'exfiltration et de persistance. L'émergence de VoidStealer démontre une capacité d'innovation technique notable, utilisant des points d'arrêt matériels pour neutraliser les protections récentes de Google Chrome. Parallèlement, la sécurité de la chaîne d'approvisionnement logicielle reste une vulnérabilité majeure, comme l'illustre la compromission d'Aqua Security via des jetons CI/CD dérobés. Les infrastructures critiques sont sous une pression constante, Rockwell Automation appelant à une déconnexion immédiate des automates exposés pour contrer des activités adverses ciblées. Sur le plan de l'espionnage, le kit DarkSword révèle une utilisation intensive de chaînes d'exploitation iOS multi-villes par des acteurs étatiques et commerciaux. Les services de renseignement russes intensifient leurs efforts contre les communications chiffrées (Signal, WhatsApp) des officiels et journalistes par le biais de l'ingénierie sociale. Enfin, les vulnérabilités critiques dans les solutions de gestion d'identité (Oracle) soulignent l'importance vitale de la gestion des correctifs hors cycle pour les actifs "joyaux de la couronne". Les décideurs doivent prioriser l'isolation des réseaux industriels et le renforcement de la sécurité des environnements de développement DevOps.

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
| Interlock | Firewalls d'entreprise | Exploitation de vulnérabilités Zero-day (Cisco FMC) | [Help Net Security](https://www.helpnetsecurity.com/2026/03/22/week-in-review-screenconnect-servers-open-to-attack-exploited-microsoft-sharepoint-flaw/) |
| MuddyWater (Iran) | Diplomatie, Énergie, Finance | Exploitation de vulnérabilités de code injection (Laravel) | [Security Affairs](https://securityaffairs.com/189776/security/u-s-cisa-adds-apple-laravel-livewire-and-craft-cms-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| Renseignement Russe (APT) | Gouvernement, Militaire, Journalisme | Phishing et détournement de comptes Signal/WhatsApp | [Security Affairs](https://securityaffairs.com/189808/intelligence/russia-linked-actors-target-whatsapp-and-signal-in-phishing-campaign.html) |
| Secp0 | Logiciels de gestion de mots de passe | Exploitation de faiblesses de chiffrement | [CTI.fyi](https://infosec.exchange/@CTI_FYI/116275376219129794) |
| Spacebears | Santé, Divers | Ransomware-as-a-Service | [CTI.fyi](https://infosec.exchange/@CTI_FYI/116275819546238241) |
| TeamPCP | Cloud-native, DevOps | Empoisonnement de la chaîne d'approvisionnement (GitHub Actions) | [OpenSourceMalware](https://opensourcemalware.com/blog/teampcp-aquasec-com-github-org-compromise) |
| UNC6353 (Russie) | Surveillance ciblée | Utilisation du kit d'exploitation iOS DarkSword | [Security Online](https://securityonline.info/unmasking-darksword-gtig-exposes-full-chain-ios-exploit-zero-day/) |
| VoidStealer | Utilisateurs finaux | Malware-as-a-Service (MaaS) - Infostealer | [BleepingComputer](https://www.bleepingcomputer.com/news/security/voidstealer-malware-steals-chrome-master-key-via-debugger-trick/) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Défense | Espionnage maritime | Le porte-avions Charles de Gaulle localisé en temps réel via les données de l'application Strava. | [Security Affairs](https://securityaffairs.com/189765/breaking-news/security-affairs-newsletter-round-568-by-pierluigi-paganini-international-edition.html) |
| Diplomatie / Militaire | Cyber-espionnage | Les services russes ciblent activement les communications Signal et WhatsApp des officiels de l'OTAN. | [Security Affairs](https://securityaffairs.com/189808/intelligence/russia-linked-actors-target-whatsapp-and-signal-in-phishing-campaign.html) |
| Infrastructure critique | Ukraine | Campagne d'espionnage russe utilisant le backdoor DRILLAPP contre des entités ukrainiennes. | [Security Affairs](https://securityaffairs.com/189765/breaking-news/security-affairs-newsletter-round-568-by-pierluigi-paganini-international-edition.html) |
| International | Sanctions EU | L'Union Européenne sanctionne des entités chinoises et iraniennes pour des cyberattaques contre les États membres. | [Security Affairs](https://securityaffairs.com/189765/breaking-news/security-affairs-newsletter-round-568-by-pierluigi-paganini-international-edition.html) |
| Souveraineté | Autriche | Vienne identifiée comme un hub majeur pour l'espionnage russe ciblant les communications de l'OTAN. | [Security Affairs](https://securityaffairs.com/189765/breaking-news/security-affairs-newsletter-round-568-by-pierluigi-paganini-international-edition.html) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| 4chan shrugs off UK regulator | Ofcom | 22/03/2026 | Royaume-Uni | Online Safety Act | Amende de 450 000 £ pour défaut de vérification de l'âge et accès des enfants à des contenus inappropriés. | [Help Net Security](https://www.helpnetsecurity.com/2026/03/22/week-in-review-screenconnect-servers-open-to-attack-exploited-microsoft-sharepoint-flaw/) |
| Binding Operational Directive 22-01 | CISA | 22/03/2026 | États-Unis | BOD 22-01 | Obligation pour les agences fédérales de corriger les vulnérabilités exploitées (KEV) avant le 3 avril 2026. | [Security Affairs](https://securityaffairs.com/189776/security/u-s-cisa-adds-apple-laravel-livewire-and-craft-cms-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| EU sanctions on Chinese and Iranian actors | Conseil de l'UE | 22/03/2026 | Union Européenne | Régime de sanctions cyber de l'UE | Sanctions contre 3 entités et 2 individus impliqués dans des cyberattaques contre l'UE. | [Security Affairs](https://securityaffairs.com/189765/breaking-news/security-affairs-newsletter-round-568-by-pierluigi-paganini-international-edition.html) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Administration publique | City of Los Angeles | Violation de données par le groupe de ransomware WorldLeaks. | [Security Affairs](https://securityaffairs.com/189765/breaking-news/security-affairs-newsletter-round-568-by-pierluigi-paganini-international-edition.html) |
| Administration publique | Companies House (UK) | Exposition potentielle des données personnelles de millions d'entreprises via le service WebFiling. | [Help Net Security](https://www.helpnetsecurity.com/2026/03/22/week-in-review-screenconnect-servers-open-to-attack-exploited-microsoft-sharepoint-flaw/) |
| Cybersécurité | Aqua Security | Compromission de 44 dépôts GitHub internes, exposition de code source propriétaire et secrets CI/CD. | [OpenSourceMalware](https://opensourcemalware.com/blog/teampcp-aquasec-com-github-org-compromise) |
| Santé | Navia Benefit Solutions | Violation de données impactant près de 2,7 millions de personnes. | [Security Affairs](https://securityaffairs.com/189765/breaking-news/security-affairs-newsletter-round-568-by-pierluigi-paganini-international-edition.html) |
| Santé | Royal Bahrain Hospital | Revendication de piratage par le groupe Payload Ransomware. | [Security Affairs](https://securityaffairs.com/189765/breaking-news/security-affairs-newsletter-round-568-by-pierluigi-paganini-international-edition.html) |
| Santé / Technologie | Intuitive (Chirurgie robotique) | Violation de données suite à une attaque de phishing ciblée. | [Security Affairs](https://securityaffairs.com/189765/breaking-news/security-affairs-newsletter-round-568-by-pierluigi-paganini-international-edition.html) |
| Sécurité en ligne | Aura | Accès non autorisé à 900 000 enregistrements de contacts suite à un phishing téléphonique. | [Help Net Security](https://www.helpnetsecurity.com/2026/03/22/week-in-review-screenconnect-servers-open-to-attack-exploited-microsoft-sharepoint-flaw/) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par score CVSS.
| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|
| CVE-2025-32432 | 10.0 | Craft CMS | Injection de code / RCE | [Security Affairs](https://securityaffairs.com/189776/security/u-s-cisa-adds-apple-laravel-livewire-and-craft-cms-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| CVE-2026-21992 | 9.8 | Oracle Identity Manager | Remote Code Execution (RCE) | [Security Affairs](https://securityaffairs.com/189796/security/oracle-fixes-critical-rce-flaw-cve-2026-21992-in-identity-manager.html) |
| CVE-2025-54068 | 9.8 | Laravel Livewire | Injection de code | [Security Affairs](https://securityaffairs.com/189776/security/u-s-cisa-adds-apple-laravel-livewire-and-craft-cms-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| CVE-2026-32297 | 9.8 | Angeet ES3 KVM | Accès fichier non authentifié | [Security Online](https://securityonline.info/below-edr-unsecured-ip-kvm-switches-total-system-takeover/) |
| CVE-2026-4558 | 9.0 | Linksys MR9600 | OS Command Injection | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-4558) |
| CVE-2026-4551 | 9.0 | Tenda F453 | Stack-based buffer overflow | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-4551) |
| CVE-2026-4555 | 9.0 | D-Link DIR-513 | Stack-based buffer overflow (EOL) | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-4555) |
| CVE-2025-31277 | 8.8 | Apple Multiple Products | Buffer Overflow | [Security Affairs](https://securityaffairs.com/189776/security/u-s-cisa-adds-apple-laravel-livewire-and-craft-cms-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| CVE-2026-33295 | 8.2 | AVideo | Stored XSS via CDN plugin | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-33295) |
| CVE-2026-33293 | 8.1 | AVideo | Path Traversal / File Deletion | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-33293) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| VoidStealer malware steals Chrome master key via debugger trick | Technique innovante de contournement de l'ABE de Chrome via hardware breakpoints. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/voidstealer-malware-steals-chrome-master-key-via-debugger-trick/) |
| Oracle fixes critical RCE flaw CVE-2026-21992 in Identity Manager | Alerte de sécurité critique hors cycle pour un composant d'identité vital. | [Security Affairs](https://securityaffairs.com/189796/security/oracle-fixes-critical-rce-flaw-cve-2026-21992-in-identity-manager.html) |
| TeamPCP Defaces Aqua Security's Internal GitHub Org | Escalade majeure d'une attaque de chaîne d'approvisionnement ciblant un éditeur cyber. | [OpenSourceMalware](https://opensourcemalware.com/blog/teampcp-aquasec-com-github-org-compromise) |
| Russia-linked actors target WhatsApp and Signal in phishing campaign | Menace persistante contre les communications chiffrées des officiels et journalistes. | [Security Affairs](https://securityaffairs.com/189808/intelligence/russia-linked-actors-target-whatsapp-and-signal-in-phishing-campaign.html) |
| Unmasking DarkSword: Full-Chain iOS Exploit | Analyse d'un kit d'exploitation mobile sophistiqué utilisé par des acteurs étatiques. | [Security Online](https://securityonline.info/unmasking-darksword-gtig-exposes-full-chain-ios-exploit-zero-day/) |
| Rockwell Automation Issues Urgent Warning | Alerte proactive cruciale pour la sécurité des infrastructures industrielles (OT). | [Security Online](https://securityonline.info/rockwell-automation-urgent-warning-disconnect-industrial-controllers-ot-security/) |
| How Unsecured IP-KVM Switches Grant Total System Takeover | Exposition de vulnérabilités "sous l'EDR" affectant la gestion à distance du matériel. | [Security Online](https://securityonline.info/below-edr-unsecured-ip-kvm-switches-total-system-takeover/) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| SECURITY AFFAIRS MALWARE NEWSLETTER ROUND 89 | Synthèse de synthèse (liste d'articles sans analyse propre). | [Security Affairs](https://securityaffairs.com/189771/security/security-affairs-malware-newsletter-round-89.html) |
| Security Affairs newsletter Round 568 | Synthèse de synthèse (liste d'articles sans analyse propre). | [Security Affairs](https://securityaffairs.com/189765/breaking-news/security-affairs-newsletter-round-568-by-pierluigi-paganini-international-edition.html) |
| Week in review: ScreenConnect servers open to attack | Résumé hebdomadaire d'informations déjà traitées individuellement. | [Help Net Security](https://www.helpnetsecurity.com/2026/03/22/week-in-review-screenconnect-servers-open-to-attack-exploited-microsoft-sharepoint-flaw/) |
| ISC Stormcast For Monday, March 23rd, 2026 | Podcast quotidien généraliste sans détails techniques spécifiques supplémentaires. | [ISC SANS](https://isc.sans.edu/podcastdetail/9860) |
| New ransom group blog post! spacebears | Notification de violation traitée dans la synthèse des violations. | [CTI.fyi](https://infosec.exchange/@CTI_FYI/116275819546238241) |
| Ensuring robust compliance & governance | Article d'opinion/conseil générique sans actualité cyber spécifique. | [Mastodon](https://mastodon.social/@archibaldtitan/116275624564204770) |

<br>
<br>
<div id="articles"></div>

# ARTICLES

<div id="voidstealer--une-nouvelle-technique-de-contournement-de-la-be-de-chrome"></div>

## VoidStealer : une nouvelle technique de contournement de l'A-BE de Chrome
VoidStealer est un nouveau malware-as-a-service (MaaS) qui utilise une méthode furtive pour contourner l'Application-Bound Encryption (ABE) de Google Chrome. Cette protection, introduite en juin 2024, vise à sécuriser les cookies et les données sensibles. VoidStealer parvient à extraire la clé de chiffrement `v20_master_key` directement depuis la mémoire du navigateur lors de son exécution. Pour ce faire, il utilise des points d'arrêt matériels (hardware breakpoints) via une technique de débogage. Le malware lance un processus de navigation suspendu, s'y attache comme débogueur et attend le chargement des DLL cibles (`chrome.dll` ou `msedge.dll`). Il scanne ensuite la mémoire pour identifier l'instruction exacte où la clé apparaît en clair. Cette approche permet l'extraction sans nécessiter d'élévation de privilèges ou d'injection de code complexe. La technique semble inspirée du projet open-source ElevationKatz. Google travaille continuellement sur des correctifs pour bloquer ces méthodes de contournement.

**Analyse de l'impact** : L'impact est majeur pour la confidentialité des utilisateurs, car l'ABE était considéré comme un rempart solide contre les infostealers. Cette technique rend inefficace une protection clé de Chrome, facilitant le vol massif de sessions de connexion (cookies) et de mots de passe enregistrés.

**Recommandations** :
- Surveiller les processus suspects s'attachant en tant que débogueur aux navigateurs Web (Chrome, Edge).
- Utiliser des solutions EDR capables de détecter l'utilisation inhabituelle de points d'arrêt matériels (hardware breakpoints).
- Encourager l'utilisation de gestionnaires de mots de passe externes au navigateur et l'activation systématique de la double authentification (2FA).

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | VoidStealer (MaaS) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1539: Steal Web Session Cookie <br/> * T1003.001: OS Credential Dumping (LSASS/Browser) <br/> * T1056.004: Credential API Hooking |
| Observables & Indicateurs de compromission | ```* chrome.dll <br/> * msedge.dll <br/> * ReadProcessMemory calls targetting browser memory``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/voidstealer-malware-steals-chrome-master-key-via-debugger-trick/

<br/>
<div id="campagne-de-phishing-russe-ciblant-whatsapp-et-signal"></div>

## Campagne de phishing russe ciblant WhatsApp et Signal
Le FBI et les agences de renseignement néerlandaises ont émis une alerte concernant des campagnes de phishing russes ciblant les utilisateurs de Signal et WhatsApp. Les acteurs, liés aux services de renseignement russes, visent des cibles à haute valeur ajoutée, notamment des responsables gouvernementaux, des militaires, des politiciens et des journalistes. L'objectif n'est pas de casser le chiffrement de bout en bout, mais de prendre le contrôle des comptes. Les attaquants se font passer pour des comptes de support technique officiels des applications. Ils incitent les victimes à partager des codes de vérification, des codes PIN ou à cliquer sur des liens malveillants. Une technique courante consiste à abuser de la fonction "appareils liés" pour ajouter le dispositif de l'attaquant au compte de la victime. Une fois l'accès obtenu, les attaquants peuvent lire les messages, accéder aux contacts et usurper l'identité de la victime. Cette campagne illustre l'efficacité continue de l'ingénierie sociale pour contourner des protections techniques robustes.

**Analyse de l'impact** : L'impact est critique sur le plan de la sécurité nationale et de l'espionnage. Le détournement de communications sensibles peut mener à l'exfiltration d'informations classifiées, à la surveillance de diplomates et à la compromission de sources journalistiques.

**Recommandations** :
- Sensibiliser les personnels sensibles au fait que les supports techniques d'applications ne demandent jamais de codes de vérification par message.
- Activer systématiquement le verrouillage de l'enregistrement (code PIN) sur Signal et WhatsApp.
- Vérifier régulièrement la liste des "Appareils liés" dans les paramètres de l'application.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Services de renseignement russes (suspecté UNC6353 ou similaire) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.002: Spearphishing Link <br/> * T1566.003: Spearphishing Service <br/> * T1098.005: Account Manipulation: Device Registration |
| Observables & Indicateurs de compromission | ```Aucun IoC spécifique n'est fourni``` |

### Source (url) du ou des articles
* https://securityaffairs.com/189808/intelligence/russia-linked-actors-target-whatsapp-and-signal-in-phishing-campaign.html

<br/>
<div id="vulnerabilite-critique-rce-dans-oracle-identity-manager"></div>

## Vulnérabilité critique RCE dans Oracle Identity Manager
Oracle a publié un correctif d'urgence pour une vulnérabilité critique, identifiée sous le nom CVE-2026-21992, affectant Oracle Identity Manager (OIM) et Web Services Manager. Cette faille présente un score CVSS de 9.8, indiquant une gravité maximale. Elle permet à un attaquant distant et non authentifié d'exécuter du code arbitraire via des requêtes HTTP. L'exploitation réussie peut entraîner une prise de contrôle totale du système, compromettant l'ensemble de l'infrastructure d'identité de l'entreprise. Cette alerte est particulièrement sérieuse car elle fait suite à une vulnérabilité similaire (CVE-2025-61757) qui a déjà été activement exploitée par des groupes d'attaquants comme Interlock. Oracle a choisi une publication hors cycle (Security Alert), soulignant l'imminence de la menace. Des honeypots ont déjà détecté des tentatives de scan sur les points de terminaison OIM associés. Les organisations utilisant les versions 12.2.1.4.0 et 14.1.2.1.0 sont directement impactées.

**Analyse de l'impact** : L'impact est potentiellement catastrophique car OIM constitue le "joyau de la couronne" de l'infrastructure. Une compromission permet non seulement l'accès aux données, mais aussi la création de comptes privilèges et le mouvement latéral vers tous les systèmes fédérés.

**Recommandations** :
- Appliquer immédiatement le correctif Oracle hors cycle sans attendre la prochaine mise à jour trimestrielle.
- Isoler les interfaces OIM du réseau public et restreindre l'accès aux segments internes de confiance.
- Déployer des règles WAF pour bloquer les requêtes HTTP suspectes ciblant les API REST d'OIM.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Acteurs non nommés (scans observés depuis 89.238.132[.]76, 185.245.82[.]81) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br/> * T1210: Exploitation of Remote Services |
| Observables & Indicateurs de compromission | ```* 89.238.132.76 <br/> * 185.245.82.81 <br/> * 138.199.29.153``` |

### Source (url) du ou des articles
* https://securityaffairs.com/189796/security/oracle-fixes-critical-rce-flaw-cve-2026-21992-in-identity-manager.html
* https://thecyberthrone.in/2026/03/22/oracle-patches-cve-2026-21992-unauthenticated-rce/

<br/>
<div id="compromission-massive-de-lorganisation-github-daqua-security-par-teampcp"></div>

## Compromission massive de l'organisation GitHub d'Aqua Security par TeamPCP
L'organisation GitHub interne d'Aqua Security (`aquasec-com`) a été victime d'une attaque de défaçage et d'exfiltration massive par le groupe TeamPCP. En l'espace de deux minutes, 44 dépôts privés ont été renommés avec le préfixe `tpcp-docs-` et leurs descriptions ont été modifiées. L'analyse médico-légale suggère que l'attaque a été rendue possible par le vol d'un jeton (PAT) du compte de service `Argon-DevOps-Mgt`. Ce jeton aurait été collecté lors d'une précédente compromission de la chaîne d'approvisionnement ciblant les GitHub Actions de Trivy. L'attaquant a testé le jeton sept heures avant l'attaque finale en créant et supprimant une branche furtive. Cette compromission expose des codes sources propriétaires, des configurations CI/CD, des bibliothèques Go partagées et des bases de connaissances internes. TeamPCP, déjà connu pour ses attaques contre les écosystèmes cloud-native, démontre une fois de plus sa capacité à cibler les acteurs mêmes de la cybersécurité.

**Analyse de l'impact** : L'impact est extrêmement préjudiciable pour la propriété intellectuelle d'Aqua Security. L'exposition des pipelines CI/CD et des secrets associés (clés AWS, tokens API) pourrait permettre des attaques ultérieures encore plus graves contre l'infrastructure de production ou les clients de l'éditeur.

**Recommandations** :
- Révoquer immédiatement tous les jetons d'accès personnels (PAT) et les secrets associés aux comptes de service compromis.
- Auditer l'ensemble des dépôts pour détecter l'insertion de code malveillant ou de backdoors.
- Verrouiller les actions GitHub sur des commits SHA spécifiques plutôt que sur des tags de version.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TeamPCP (alias DeadCatx3, PCPcat, CanisterWorm) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Supply Chain Compromise: Software Dependencies <br/> * T1567: Exfiltration Over Web Service <br/> * T1078.004: Valid Accounts: Cloud Accounts |
| Observables & Indicateurs de compromission | ```* Argon-DevOps-Mgt (GitHub ID: 139343333) <br/> * tpcp-docs- <br/> * /tmp/pglog <br/> * 18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a``` |

### Source (url) du ou des articles
* https://opensourcemalware.com/blog/teampcp-aquasec-com-github-org-compromise

<br/>
<div id="darksword--un-kit-dexploitation-ios-sophistique-utilise-a-lechelle-mondiale"></div>

## DarkSword : un kit d'exploitation iOS sophistiqué utilisé à l'échelle mondiale
Le Google Threat Intelligence Group (GTIG) a révélé l'existence de "DarkSword", un kit d'exploitation iOS "full-chain" actif depuis novembre 2025. Utilisé par divers vendeurs de surveillance commerciale et des acteurs étatiques, ce kit a ciblé des individus en Arabie saoudite, en Turquie, en Malaisie et en Ukraine. DarkSword exploite une séquence complexe de six vulnérabilités (dont certaines Zero-day) pour obtenir un contrôle total de l'appareil, du navigateur jusqu'au noyau (kernel). Il supporte les versions iOS 18.4 à 18.7. L'attaque commence par un compromis de site Web ("watering hole") qui déclenche une chaîne d'exécution en plusieurs étapes. Une fois l'appareil compromis, le kit peut livrer trois familles de malwares : GHOSTBLADE, GHOSTKNIFE et GHOSTSABER. Ces payloads permettent l'exfiltration de messages chiffrés, la surveillance de la localisation et l'activation à distance du microphone et de la caméra. Apple a corrigé l'ensemble des vulnérabilités avec iOS 26.3.

**Analyse de l'impact** : L'impact est significatif pour la protection de la vie privée et la sécurité des données mobiles. La prolifération de tels kits "clés en main" permet à des acteurs moins sophistiqués de mener des opérations d'espionnage de niveau étatique contre des cibles stratégiques.

**Recommandations** :
- Mettre à jour immédiatement tous les appareils iOS vers la version 26.3 ou ultérieure.
- Pour les profils à haut risque, activer le "Lockdown Mode" d'Apple qui bloque la plupart des chaînes d'exploitation complexes basées sur le Web.
- Éviter de cliquer sur des liens provenant de sources non sollicitées, même via des messageries chiffrées.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UNC6353 (suspecté), Vendeurs de surveillance commerciale |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1203: Exploitation for Client Execution <br/> * T1068: Exploitation for Privilege Escalation <br/> * T1512: Endpoint Denial of Service (via kernel panic) |
| Observables & Indicateurs de compromission | ```* GHOSTBLADE <br/> * GHOSTKNIFE <br/> * GHOSTSABER <br/> * rce_module.js``` |

### Source (url) du ou des articles
* https://securityonline.info/unmasking-darksword-gtig-exposes-full-chain-ios-exploit-zero-day/

<br/>
<div id="alerte-critique-de-rockwell-automation-sur-les-controleurs-industriels"></div>

## Alerte critique de Rockwell Automation sur les contrôleurs industriels
Rockwell Automation a émis un avertissement urgent demandant à ses clients de déconnecter immédiatement leurs contrôleurs industriels (PLC) de l'internet public. Cette mesure proactive fait suite à l'observation d'activités malveillantes ciblant spécifiquement ces équipements de technologie opérationnelle (OT). Les automates programmables sont les composants critiques gérant les processus physiques dans les usines, les centrales d'eau ou les infrastructures d'énergie. L'exposition directe de ces appareils sur internet facilite les attaques par balayage (scanning) et l'exploitation de vulnérabilités connues ou non. Rockwell souligne que la sécurité de sa base installée dépend crucialement de la suppression du vecteur d'attaque le plus courant : l'accès distant non sécurisé. La société recommande une stratégie de "défense en profondeur", incluant la segmentation réseau et l'activation des protections natives des contrôleurs. Plusieurs CVE critiques (CVE-2025-13823, CVE-2021-22681) sont citées comme exemples de risques persistants pour les gammes Micro800 et Logix.

**Analyse de l'impact** : L'impact sur la sécurité industrielle est majeur. Une prise de contrôle d'automates peut entraîner des interruptions de service critiques, des dommages physiques aux installations ou poser des risques pour la sécurité publique (cas des usines de traitement des eaux).

**Recommandations** :
- Vérifier qu'aucun contrôleur Rockwell (PLC) n'est accessible directement depuis l'internet public (Shodan, Censys).
- Mettre en œuvre des passerelles VPN sécurisées avec authentification multi-facteurs pour tout accès de maintenance à distance.
- Appliquer la segmentation réseau (VLAN dédiés OT) pour isoler les systèmes de contrôle du réseau d'entreprise.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Acteurs non nommés (cyber-adversaires ciblant l'ICS/OT) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T0866: Network Scanning <br/> * T0815: Remote System Discovery <br/> * T0812: Default Credentials |
| Observables & Indicateurs de compromission | ```Accès sur ports CIP/Modbus (port 44818, 502)``` |

### Source (url) du ou des articles
* https://securityonline.info/rockwell-automation-urgent-warning-disconnect-industrial-controllers-ot-security/

<br/>
<div id="prise-de-contre-totale-via-les-commutateurs-ip-kvm-non-securises"></div>

## Prise de contrôle totale via les commutateurs IP-KVM non sécurisés
Des chercheurs d'Eclypsium ont publié une analyse technique alarmante sur la sécurité des commutateurs IP-KVM (Keyboard, Video, Mouse). Ces dispositifs, utilisés pour la gestion à distance des serveurs, présentent des vulnérabilités critiques souvent ignorées car elles se situent "sous l'EDR". En compromettant un KVM, un attaquant obtient l'équivalent d'un accès physique direct à la machine ciblée. Cela inclut le contrôle du clavier, de la vidéo et de la souris au niveau du BIOS, permettant de désactiver le Secure Boot ou de contourner les écrans de verrouillage. L'étude a révélé neuf vulnérabilités chez quatre vendeurs majeurs (GL-iNet, Angeet, Sipeed, JetKVM), allant de l'injection de commandes OS à l'absence de vérification de l'authenticité des firmwares. Une fonctionnalité particulièrement dangereuse est l'émulation de périphériques USB (BadUSB), permettant au KVM d'injecter des commandes à très haute vitesse. Le FBI et Microsoft ont déjà signalé l'utilisation de ces appareils par des acteurs nord-coréens (DPRK) pour maintenir une présence furtive.

**Analyse de l'impact** : L'impact est total car la menace est invisible pour les solutions de sécurité logicielles classiques. Un attaquant peut persister dans le matériel, modifier le BIOS et prendre le contrôle total des serveurs avant même que le système d'exploitation ne démarre.

**Recommandations** :
- Placer tous les dispositifs IP-KVM sur un VLAN de gestion dédié et strictement isolé.
- Ne jamais exposer les interfaces Web des KVM directement sur internet; utiliser des tunnels VPN sécurisés.
- Auditer l'inventaire matériel pour détecter les KVM "fantômes" ou non autorisés installés par des tiers.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Acteurs étatiques (DPRK suspecté), Hackeurs indépendants |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1498: Direct Hardware Access <br/> * T1200: Hardware Additions <br/> * T1542.001: Pre-OS Boot: System Firmware |
| Observables & Indicateurs de compromission | ```* CVE-2026-32297 (ES3 KVM) <br/> * CVE-2026-32298 (OS command injection)``` |

### Source (url) du ou des articles
* https://securityonline.info/below-edr-unsecured-ip-kvm-switches-total-system-takeover/