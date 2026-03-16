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
  * [FortiGate Firewalls Exploited in Wave of Attacks](#fortigate-firewalls-exploited-in-wave-of-attacks)
  * [Betterleaks a new open source secrets scanner](#betterleaks-a-new-open-source-secrets-scanner)
  * [Microsoft Releases Out-of-Band Patch for RRAS](#microsoft-releases-out-of-band-patch-for-rras)
  * [OpenAI says ChatGPT ads are not rolling out globally](#openai-says-chatgpt-ads-are-not-rolling-out-globally)
  * [Foreign Information Manipulation and Interference explained](#foreign-information-manipulation-and-interference-explained)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage cyber de la mi-mars 2026 est marqué par une intensification des tensions géopolitiques au Moyen-Orient, se traduisant par des attaques ciblées contre des infrastructures critiques et de santé, notamment par les groupes Handala et Payload. L'exploitation massive de vulnérabilités critiques sur les équipements de bordure, tels que les pare-feux FortiGate, confirme que ces dispositifs restent des points d'entrée privilégiés pour des courtiers d'accès (IAB) et des groupes d'espionnage. Parallèlement, l'écosystème du ransomware fait face à une crise de confiance interne suite à l'inculpation d'un négociateur d'incidents accusé de collusion avec le groupe BlackCat. Sur le plan technologique, l'automatisation de la détection de secrets (Betterleaks) et l'introduction de la publicité dans l'IA générative (OpenAI) soulignent une mutation des outils de défense et de monétisation. Enfin, la publication de la stratégie cyber de l'administration Trump et les avertissements européens sur les opérations d'influence (FIMI) indiquent une volonté étatique de durcir les réponses face aux menaces hybrides. Les entreprises doivent prioriser le patching immédiat des systèmes RRAS et FortiOS face à des menaces de plus en plus automatisées.

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
| APT28 | Forces armées | Espionnage à long terme via des malwares personnalisés | [Security Affairs](https://securityaffairs.com/189451/breaking-news/security-affairs-newsletter-round-567-by-pierluigi-paganini-international-edition.html) |
| APT36 | Gouvernemental / Militaire | Utilisation de "Vibeware" | [Security Affairs](https://securityaffairs.com/189451/breaking-news/security-affairs-newsletter-round-567-by-pierluigi-paganini-international-edition.html) |
| BlackCat (ALPHV) | Multiples | Ransomware-as-a-service, collusion avec des négociateurs d'incidents | [DataBreaches.net](https://databreaches.net/2026/03/15/ransomware-incident-responder-gave-info-to-blackcat-cybercriminals-during-negotiations-doj-alleges/) |
| Handala | Santé / Médical | Hacktivisme pro-palestinien, attaques de perturbation (Stryker) | [Security Affairs](https://securityaffairs.com/189451/breaking-news/security-affairs-newsletter-round-567-by-pierluigi-paganini-international-edition.html) |
| Nightspire | Comptabilité, Éducation, Microfinance | Ransomware, publications sur blog de fuites | [CTI.FYI](https://infosec.exchange/@CTI_FYI/116236394215607588) |
| Payload Ransomware | Santé, Logistique, Immobilier | Double extorsion (chiffrement ChaCha20 + vol de données) | [Security Affairs](https://securityaffairs.com/189467/cyber-crime/payload-ransomware-claims-the-hack-of-royal-bahrain-hospital.html) |
| ShinyHunters | Services Cloud | Ciblage de Salesforce Experience Cloud | [Help Net Security](https://www.helpnetsecurity.com/2026/03/15/week-in-review-aitm-phishing-kit-used-to-hijack-aws-accounts-year-long-malware-campaign-targets-hr/) |
| Storm-2561 | Entreprises | Phishing via de faux sites VPN pour vol d'identifiants | [Security Affairs](https://securityaffairs.com/189451/breaking-news/security-affairs-newsletter-round-567-by-pierluigi-paganini-international-edition.html) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Défense / Espace | Menaces hybrides | Airbus alerte sur les menaces spatiales et les failles de la supply chain | [Help Net Security](https://www.helpnetsecurity.com/2026/03/15/week-in-review-aitm-phishing-kit-used-to-hijack-aws-accounts-year-long-malware-campaign-targets-hr/) |
| Gouvernemental | Conflit Moyen-Orient | Augmentation du niveau de menace lié aux hostilités Iran-USA/Israël | [Security Boulevard](https://securityboulevard.com/2026/03/update-iranian-u-s-israeli-hostilities-lead-to-increased-threat-landscape/) |
| Gouvernemental | Stratégie Nationale | Publication de la nouvelle stratégie cyber de l'administration Trump | [Help Net Security](https://www.helpnetsecurity.com/2026/03/15/week-in-review-aitm-phishing-kit-used-to-hijack-aws-accounts-year-long-malware-campaign-targets-hr/) |
| Santé | Conflit Moyen-Orient | Revendication par un groupe lié à l'Iran de l'attaque contre le géant médical Stryker | [Help Net Security](https://www.helpnetsecurity.com/2026/03/15/week-in-review-aitm-phishing-kit-used-to-hijack-aws-accounts-year-long-malware-campaign-targets-hr/) |
| Transports | Cyber-espionnage | Hackers russes ciblant les comptes Signal et WhatsApp de diplomates | [Help Net Security](https://www.helpnetsecurity.com/2026/03/15/week-in-review-aitm-phishing-kit-used-to-hijack-aws-accounts-year-long-malware-campaign-targets-hr/) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| CSAM detection rules extension | Parlement Européen | 15/03/2026 | Union Européenne | Exemption Vie Privée | Extension des règles de détection volontaire des contenus pédopornographiques jusqu'en 2027 | [Help Net Security](https://www.helpnetsecurity.com/2026/03/15/week-in-review-aitm-phishing-kit-used-to-hijack-aws-accounts-year-long-malware-campaign-targets-hr/) |
| Incident responder accused of helping ransomware gangs | DOJ | 15/03/2026 | États-Unis | Computer Fraud and Abuse Act | Accusation criminelle contre un expert en réponse à incident pour collusion avec BlackCat | [DataBreaches.net](https://databreaches.net/2026/03/15/ransomware-incident-responder-gave-info-to-blackcat-cybercriminals-during-negotiations-doj-alleges/) |
| President Trump’s Cyber Strategy for America | Maison Blanche | 15/03/2026 | États-Unis | Stratégie Cyber | Nouveau cadre politique renforçant la réponse coordonnée et agressive face aux menaces étatiques | [Help Net Security](https://www.helpnetsecurity.com/2026/03/15/week-in-review-aitm-phishing-kit-used-to-hijack-aws-accounts-year-long-malware-campaign-targets-hr/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Alimentation | Baydöner | Fuite de 1,2 million d'e-mails, noms, téléphones et mots de passe en clair | [HIBP](https://haveibeenpwned.com/Breach/Baydoner) |
| Automobile | F-One (エフワン) | Compromission de 170 000 dossiers clients par BlackShrantac | [SecurityLab_jp](https://mastodon.social/@securityLab_jp/116236384517595018) |
| Café / Retail | Starbucks | Accès non autorisé à 889 comptes d'employés via phishing | [Security Affairs](https://securityaffairs.com/189451/breaking-news/security-affairs-newsletter-round-567-by-pierluigi-paganini-international-edition.html) |
| Jeux Vidéo | Divine Skins | Vol de 105 814 comptes (e-mails, pseudos, historique d'achats) | [HIBP](https://haveibeenpwned.com/Breach/DivineSkins) |
| Santé | Royal Bahrain Hospital | Vol de 110 Go de données patient par le groupe Payload | [Security Affairs](https://securityaffairs.com/189467/cyber-crime/payload-ransomware-claims-the-hack-of-royal-bahrain-hospital.html) |
| Santé | TriZetto (Cognizant) | Violation impactant plus de 3,4 millions de patients | [Security Affairs](https://securityaffairs.com/189451/breaking-news/security-affairs-newsletter-round-567-by-pierluigi-paganini-international-edition.html) |
| Technologie | Ericsson US | Confirmation de violation via un fournisseur tiers | [Security Affairs](https://securityaffairs.com/189451/breaking-news/security-affairs-newsletter-round-567-by-pierluigi-paganini-international-edition.html) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité.
| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|
| CVE-2025-59718 | 9.8 | Fortinet FortiGate | Défaut de vérification de signature SAML | [Cybersecurity News](https://cybersecuritynews.com/fortigate-firewalls-exploited/) |
| CVE-2025-59719 | 9.8 | Fortinet FortiGate | Défaut de vérification de signature SAML | [Cybersecurity News](https://cybersecuritynews.com/fortigate-firewalls-exploited/) |
| CVE-2017-20223 | 9.8 | Telesquare SKT LTE Router | Insecure Direct Object Reference (IDOR) | [CVEFeed.io](https://cvefeed.io/vuln/detail/CVE-2017-20223) |
| CVE-2017-20224 | 9.8 | Telesquare SKT LTE Router | Arbitrary File Upload via WebDAV | [CVEFeed.io](https://cvefeed.io/vuln/detail/CVE-2017-20224) |
| CVE-2026-24858 | 9.8 | Fortinet FortiGate | Zero-day d'authentification FortiCloud | [Cybersecurity News](https://cybersecuritynews.com/fortigate-firewalls-exploited/) |
| CVE-2015-20120 | 8.8 | RealtyScript 4.0.2 | Blind SQL Injection (Time-based) | [CVEFeed.io](https://cvefeed.io/vuln/detail/CVE-2015-20120) |
| CVE-2017-20222 | 8.7 | Telesquare SKT LTE Router | Remote Reboot (DoS) sans authentification | [CVEFeed.io](https://cvefeed.io/vuln/detail/CVE-2017-20222) |
| CVE-2017-20220 | 8.7 | Serviio PRO 1.8 | Changement de mot de passe REST API non authentifié | [CVEFeed.io](https://cvefeed.io/vuln/detail/CVE-2017-20220) |
| CVE-2026-25172 | 8.5 | Windows 11 RRAS | Exécution de code à distance (RCE) | [Cybersecurity News](https://cybersecuritynews.com/windows-11-out-of-band-update/) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Betterleaks, a new open-source secrets scanner | Présentation d'un outil de défense majeur (successeur de Gitleaks). | [BleepingComputer](https://www.bleepingcomputer.com/news/security/betterleaks-a-new-open-source-secrets-scanner-to-replace-gitleaks/) |
| OpenAI says ChatGPT ads are not rolling out globally | Information stratégique sur la monétisation et la confidentialité de l'IA. | [BleepingComputer](https://www.bleepingcomputer.com/news/artificial-intelligence/openai-says-chatgpt-ads-are-not-rolling-out-globally-for-now/) |
| FortiGate Firewalls Exploited in Wave of Attacks | Menace critique active sur des équipements réseau critiques. | [Cybersecurity News](https://cybersecuritynews.com/fortigate-firewalls-exploited/) |
| Microsoft Releases Out-of-Band Patch for RRAS | Alerte sur une vulnérabilité RCE critique sur Windows 11. | [Cybersecurity News](https://cybersecuritynews.com/windows-11-out-of-band-update/) |
| Foreign Information Manipulation and Interference explained | Analyse de fond sur les menaces hybrides et la désinformation. | [EUvsDisinfo](https://euvsdisinfo.eu/foreign-information-manipulation-and-interference-fimi-explained/) |
| Week in review: AiTM phishing, malware campaign | Synthèse exhaustive des menaces hebdomadaires. | [Help Net Security](https://www.helpnetsecurity.com/2026/03/15/week-in-review-aitm-phishing-kit-used-to-hijack-aws-accounts-year-long-malware-campaign-targets-hr/) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| Security Affairs newsletter Round 567 | Newsletter généraliste compilant des articles déjà traités individuellement. | [Security Affairs](https://securityaffairs.com/189451/breaking-news/security-affairs-newsletter-round-567-by-pierluigi-paganini-international-edition.html) |
| SECURITY AFFAIRS MALWARE NEWSLETTER ROUND 88 | Liste de liens sans analyse profonde, contenu redondant. | [Security Affairs](https://securityaffairs.com/189459/breaking-news/security-affairs-malware-newsletter-round-88.html) |
| Nightspire ransom group blog posts | Notifications brèves de ransomware sans détails techniques. | [CTI.FYI](https://infosec.exchange/@CTI_FYI/116236394215607588) |

<br>
<br/>
<div id="articles"></div>

# ARTICLES

<div id="fortigate-firewalls-exploited-in-wave-of-attacks"></div>

## FortiGate Firewalls Exploited in Wave of Attacks to Breach Networks and Steal Credentials
Une vague d'attaques en début d'année 2026 a ciblé les pare-feux FortiGate en exploitant trois vulnérabilités majeures, dont la zero-day CVE-2026-24858. Les attaquants utilisent des jetons SAML falsifiés ou des comptes FortiCloud pour obtenir des privilèges administratifs sans authentification valide. Une fois l'accès établi, ils extraient les fichiers de configuration contenant des identifiants de comptes LDAP et Active Directory. Ces identifiants sont souvent déchiffrables en raison d'un schéma de chiffrement réversible dans FortiOS. Les attaquants pivotent ensuite vers le réseau interne pour déployer des outils RMM (Pulseway, MeshAgent) et exfiltrer la base NTDS.dit des contrôleurs de domaine. SentinelOne souligne que des courtiers d'accès (IAB) maintiennent des accès persistants pendant plusieurs mois. Le manque de rétention des journaux sur les équipements FortiGate entrave l'analyse post-incident. Les recommandations incluent la rotation immédiate de tous les secrets stockés dans les configurations FortiGate.

**Analyse de l'impact** : L'impact est critique car il permet un accès direct et privilégié au cœur du réseau d'entreprise (AD) depuis l'extérieur, contournant totalement les barrières de sécurité traditionnelles.

**Recommandations** : 
* Appliquer immédiatement les correctifs pour CVE-2025-59718, CVE-2025-59719 et CVE-2026-24858.
* Augmenter la rétention des logs FortiGate à un minimum de 14 jours (idéalement 60+).
* Surveiller la création de comptes administrateurs locaux suspects (ex: "support", "ssl-admin").
* Restreindre l'attribut mS-DS-MachineAccountQuota pour limiter la jonction de postes malveillants au domaine.
* Rotation systématique des mots de passe AD/LDAP utilisés par les appliances après patching.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non spécifié (IAB probables) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br/> * T1552.001: Credentials In Files <br/> * T1021.002: SMB/Windows Admin Shares <br/> * T1543.003: Windows Service |
| Observables & Indicateurs de compromission | ```* 193.24.211.61 (IP attaquante) * 172.67.196.232 (IP exfiltration Cloudflare) * ndibstersoft.com * neremedysoft.com * WIN-X8WRBOSK0OF (Rogue Host) * WIN-YRSXLEONJY2 (Rogue Host)``` |

### Source (url) du ou des articles
* https://cybersecuritynews.com/fortigate-firewalls-exploited/
<br>
<br>

<div id="betterleaks-a-new-open-source-secrets-scanner"></div>

## Betterleaks, a new open-source secrets scanner to replace Gitleaks
Zach Rice, le créateur de Gitleaks, a lancé "Betterleaks", un nouvel outil open-source conçu pour surpasser son prédécesseur en termes de rapidité et d'efficacité. Développé en Go pur sans dépendances complexes comme CGO, Betterleaks utilise la tokenisation BPE plutôt que l'entropie classique, atteignant un taux de rappel de 98,6 %. L'outil permet de scanner des répertoires, des fichiers et des dépôts Git pour identifier des clés API, des jetons et des secrets accidentellement exposés. Il intègre la validation des règles via CEL (Common Expression Language) et gère automatiquement les secrets multi-encodés. Le projet est soutenu par Aikido Security et bénéficie de contributions provenant de Red Hat et Amazon. Des fonctionnalités futures prévoient l'assistance par IA (LLM) pour la classification et la révocation automatique des secrets via API.

**Analyse de l'impact** : Outil stratégique pour le DevSecOps, permettant de réduire drastiquement la surface d'exposition des secrets dans les chaînes CI/CD avec une meilleure précision que les outils actuels.

**Recommandations** : 
* Intégrer Betterleaks dans les pipelines de pré-commit pour empêcher l'envoi de secrets vers les dépôts.
* Configurer des règles personnalisées via CEL pour les formats de jetons internes spécifiques à l'entreprise.
* Utiliser les capacités de scan parallèle pour auditer l'historique complet des dépôts Git volumineux.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | T1552: Unsecured Credentials |
| Observables & Indicateurs de compromission | Aucun IoC spécifique n'est fourni |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/betterleaks-a-new-open-source-secrets-scanner-to-replace-gitleaks/
<br>
<br>

<div id="microsoft-releases-out-of-band-patch-for-rras"></div>

## Microsoft Releases Out-of-Band Patch to Fix Critical RRAS RCE Vulnerabilities in Windows 11
Microsoft a publié un correctif d'urgence (out-of-band) le 13 mars 2026 pour corriger trois vulnérabilités critiques dans le service de routage et d'accès distant (RRAS) de Windows 11 (24H2 et 25H2). Les failles, notamment CVE-2026-25172, CVE-2026-25173 et CVE-2026-26111, permettent à un serveur distant malveillant d'exécuter du code à distance lorsqu'un utilisateur s'y connecte via l'outil de gestion RRAS. Ce correctif est diffusé via la technologie "hotpatch", permettant une application en mémoire sans nécessiter de redémarrage du système. Cette méthode est particulièrement avantageuse pour les environnements d'entreprise afin de minimiser les interruptions. Seuls les appareils configurés pour le hotpatching reçoivent cette mise à jour spécifique. Microsoft recommande une vérification immédiate de l'application de KB5084597.

**Analyse de l'impact** : Risque élevé d'exécution de code pour les administrateurs réseau utilisant RRAS, pouvant mener à une compromission totale de la station de travail administrative.

**Recommandations** : 
* Vérifier l'activation de la fonctionnalité hotpatch sur les flottes Windows 11 éligibles.
* Appliquer KB5084597 (OS Builds 26200.7982/26100.7982) sans délai.
* À défaut de patch, limiter l'utilisation de l'outil de gestion RRAS vers des serveurs non certifiés ou inconnus.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | T1210: Exploitation of Remote Services |
| Observables & Indicateurs de compromission | Aucun IoC spécifique n'est fourni |

### Source (url) du ou des articles
* https://cybersecuritynews.com/windows-11-out-of-band-update/
<br>
<br>

<div id="openai-says-chatgpt-ads-are-not-rolling-out-globally"></div>

## OpenAI says ChatGPT ads are not rolling out globally for now
OpenAI a précisé que l'introduction de publicités dans ChatGPT est actuellement limitée aux utilisateurs des plans "Free" et "Go" situés exclusivement aux États-Unis. Cette clarification fait suite à des inquiétudes sur Reddit après une mise à jour de la politique de confidentialité mentionnant la publicité. Bien que les publicités soient personnalisées en fonction des requêtes, OpenAI affirme qu'elles n'influencent pas les réponses du modèle de langage. Les publicités apparaissent sous les réponses et ne sont pas visibles pour les utilisateurs de moins de 18 ans. L'entreprise adopte une approche délibérée par étapes pour évaluer l'impact sur l'expérience utilisateur avant toute expansion mondiale. Aucun partage de données de conversation avec les annonceurs n'est effectué selon OpenAI.

**Analyse de l'impact** : Impact modéré sur la confidentialité ; bien que les données ne soient pas "partagées", la personnalisation implique une analyse des intentions de l'utilisateur à des fins commerciales au sein de l'interface.

**Recommandations** : 
* Pour les entreprises, privilégier les plans Enterprise ou Business où la publicité est absente.
* Sensibiliser les utilisateurs sur le fait que les suggestions "post-réponse" peuvent être des placements payants.
* Surveiller les futures mises à jour des conditions d'utilisation pour les juridictions hors USA.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | Non mentionnées |
| Observables & Indicateurs de compromission | Aucun IoC spécifique n'est fourni |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/artificial-intelligence/openai-says-chatgpt-ads-are-not-rolling-out-globally-for-now/
<br>
<br>

<div id="foreign-information-manipulation-and-interference-explained"></div>

## Foreign Information Manipulation and Interference (FIMI) explained
L'Union Européenne définit le concept de FIMI comme un comportement coordonné et trompeur d'acteurs étrangers visant à manipuler l'environnement informationnel d'un État. Contrairement à la simple désinformation qui se concentre sur le contenu, le FIMI met l'accent sur les acteurs et leurs comportements (réseaux de bots, faux comptes, IA générative). La Russie est identifiée comme l'acteur le plus prolifique, utilisant ces tactiques pour saper la confiance dans les institutions démocratiques et polariser les sociétés occidentales. La Chine utilise également le FIMI pour réduire au silence les critiques à l'étranger et pousser ses propres récits. Les campagnes FIMI sont souvent couplées à des cyberattaques et des fuites de données opportunistes. La réponse démocratique repose sur la détection, la résilience sociétale (littératie médiatique) et des mesures diplomatiques comme les sanctions.

**Analyse de l'impact** : Menace stratégique majeure pour la cohésion sociale et la légitimité des processus électoraux, augmentant la volatilité politique.

**Recommandations** : 
* Mettre en œuvre une veille informationnelle pour détecter les narratifs hostiles ciblant l'entreprise ou son secteur.
* Former les employés à la détection de deepfakes et de contenus synthétiques (vishing/phishing AI).
* Collaborer avec les autorités nationales en cas de détection de campagnes d'influence coordonnées.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Russie (Services de renseignement), Chine |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1585: Establish Accounts <br/> * T1566: Phishing <br/> * T1584: Compromise Infrastructure |
| Observables & Indicateurs de compromission | Aucun IoC spécifique n'est fourni |

### Source (url) du ou des articles
* https://euvsdisinfo.eu/foreign-information-manipulation-and-interference-fimi-explained/