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
  * [Attaque de l'acteur UAC-0255 via le malware AGEWHEEZE](#attaque-de-lacteur-uac0255-via-le-malware-agewheeze)
  * [Campagne TeamPCP : Transition vers la phase de monétisation](#campagne-teampcp-transition-vers-la-phase-de-monetisation)
  * [Infinity Stealer : Nouvelle menace macOS via ClickFix](#infinity-stealer-nouvelle-menace-macos-via-clickfix)
  * [Alerte Apple : Exploitations actives Coruna et DarkSword](#alerte-apple-exploitations-actives-coruna-et-darksword)
  * [Compromission majeure de la Commission Européenne par ShinyHunters](#compromission-majeure-de-la-commission-europeenne-par-shinyhunters)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
Le paysage cyber actuel est marqué par une transition majeure des groupes d'attaquants, passant de l'expansion de l'accès initial vers une phase agressive de monétisation, comme l'illustre la campagne TeamPCP via le ransomware Vect. Parallèlement, les institutions internationales et gouvernementales restent des cibles prioritaires, avec des compromissions revendiquées contre la Commission Européenne et le directeur du FBI, soulignant la vulnérabilité persistante des infrastructures cloud et des comptes personnels à privilèges. En Ukraine, l'acteur UAC-0255 innove en usurpant l'identité du CERT-UA pour diffuser le RAT AGEWHEEZE, démontrant une sophistication accrue dans l'ingénierie sociale. L'écosystème macOS voit apparaître Infinity Stealer, utilisant le compilateur Nuitka pour échapper aux analyses statiques, confirmant la montée en puissance des malwares sur cette plateforme. L'urgence de mise à jour sur iOS est soulignée par Apple face aux kits d'exploitation "Coruna" et "DarkSword" ciblant des failles noyau. Globalement, le "credential fan-out" observé dans les attaques de chaîne d'approvisionnement montre qu'un seul secret volé peut désormais exposer des milliers d'organisations en cascade. Les décideurs doivent impérativement renforcer la surveillance des pipelines CI/CD et accélérer la rotation des secrets d'infrastructure. Enfin, l'intégration systématique de techniques d'évasion comme la stéganographie WAV ou l'usage d'API légitimes (GitHub Releases) pour l'exfiltration complexifie radicalement la détection périmétrique traditionnelle.

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
| Handala (Void Manticore) | Gouvernement, Santé | Phishing, vol de données, wipers (Stryker), ciblage de comptes Gmail personnels | [Security Affairs](https://securityaffairs.com/190088/intelligence/iran-linked-group-handala-hacked-fbi-director-kash-patels-personal-email-account.html) |
| LAPSUS$ | Pharmacie, Technologie | Extorsion, vol de données (AstraZeneca suspecté) | [SANS ISC](https://isc.sans.edu/diary/rss/32842) |
| ShinyHunters | Institutions Publiques, Éducation | Vol de données massif via infrastructure cloud (AWS), fuites sur sites Tor | [Security Affairs](https://securityaffairs.com/190095/data-breach/shinyhunters-claims-the-hack-of-the-european-commission.html) |
| TeamPCP | Chaîne d'approvisionnement (Software), CI/CD | Compromission de paquets (PyPI, npm), vol de credentials, stéganographie | [SANS ISC](https://isc.sans.edu/diary/rss/32842) |
| UAC-0255 | Gouvernement, Santé, Finance (Ukraine) | Usurpation d'identité (CERT-UA), phishing via Files.fm, RAT AGEWHEEZE (Go) | [CERT-UA](https://cert.gov.ua/article/6288047) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Défense / Gouvernement | Conflit Iran-Israël-USA | Le groupe Handala, lié à l'Iran, a fuité des données du compte Gmail personnel du directeur du FBI | [Security Affairs](https://securityaffairs.com/190088/intelligence/iran-linked-group-handala-hacked-fbi-director-kash-patels-personal-email-account.html) |
| Gouvernemental | Conflit Ukraine-Russie | Campagne de cyberespionnage massive contre les institutions ukrainiennes utilisant l'image du CERT-UA | [CERT-UA](https://cert.gov.ua/article/6288047) |
| Institutions Internationales | Souveraineté Européenne | Revendication de vol de 350 Go de données appartenant à la Commission Européenne par ShinyHunters | [Security Affairs](https://securityaffairs.com/190095/data-breach/shinyhunters-claims-the-hack-of-the-european-commission.html) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet des articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Directive BOD 22-01 | CISA | 28/03/2026 | États-Unis | BOD 22-01 | Obligation pour les agences fédérales de corriger les vulnérabilités du catalogue KEV avant échéance | [Security Affairs](https://securityaffairs.com/190076/uncategorized/u-s-cisa-adds-a-flaw-in-f5-big-ip-amp-to-its-known-exploited-vulnerabilities-catalog.html) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Éducation | Infinite Campus | Vol de données via ShinyHunters, impactant principalement les informations d'annuaires étudiants | [DataBreaches](https://databreaches.net/2026/03/28/thankfully-the-infinite-campus-incident-did-not-involve-a-lot-of-non-directory-student-information/) |
| Gouvernemental | Commission Européenne | Vol revendiqué de 350 Go de données (e-mails, contrats) via une brèche sur un compte AWS | [Security Affairs](https://securityaffairs.com/190095/data-breach/shinyhunters-claims-the-hack-of-the-european-commission.html) |
| Gouvernemental | Kash Patel (Directeur FBI) | Compromission d'un compte Gmail personnel et fuite de fichiers historiques | [Security Affairs](https://securityaffairs.com/190088/intelligence/iran-linked-group-handala-hacked-fbi-director-kash-patels-personal-email-account.html) |
| Santé | AstraZeneca | Revendication non confirmée de vol de 3 Go de données par LAPSUS$ | [SANS ISC](https://isc.sans.edu/diary/rss/32842) |
| Santé | Corewell Health | Violation de données via le consultant Pinnacle Holdings impactant des milliers de patients | [DataBreaches](https://databreaches.net/2026/03/28/thousands-of-corewell-health-patients-affected-by-security-breach/) |
| Santé | Woodfords Family Services | Notification d'une attaque par ransomware datant d'avril 2024 | [DataBreaches](https://databreaches.net/2026/03/28/woodfords-family-services-notifying-patients-and-families-about-2024-ransomware-attack/) |
| Technologie | Anthropic | Fuite d'informations sur le futur modèle d'IA "Claude Mythos" | [DataBreaches](https://databreaches.net/2026/03/28/meet-claude-mythos-leaked-anthropic-post-reveals-the-powerful-upcoming-model/) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2025-53521 | 9.8 | Non spécifié | TRUE | F5 BIG-IP APM | Remote Code Execution (RCE) | T1190: Exploit Public-Facing Application | Permet l'exécution de code à distance via du trafic malveillant sur les serveurs virtuels avec politique d'accès activée | [Security Affairs](https://securityaffairs.com/190076/uncategorized/u-s-cisa-adds-a-flaw-in-f5-big-ip-amp-to-its-known-exploited-vulnerabilities-catalog.html) |
| CVE-2018-25223 | 9.8 | Non spécifié | FALSE | Crashmail 1.6 | Stack-based Buffer Overflow | T1210: Exploitation of Remote Services | Permet l'exécution de code à distance via des entrées malveillantes | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2018-25223) |
| CVE-2018-25221 | 9.8 | Non spécifié | FALSE | EChat Server 3.1 | Buffer Overflow | T1210: Exploitation of Remote Services | Dépassement de tampon via le paramètre 'username' sur l'endpoint chat.ghp | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2018-25221) |
| CVE-2018-25220 | 9.8 | Non spécifié | FALSE | Bochs 2.6-5 | Stack-based Buffer Overflow | T1210: Exploitation of Remote Services | Exécution de code via chaîne ROP après injection de 1200 octets | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2018-25220) |
| CVE-2026-5004 | 9.0 | Non spécifié | FALSE | Wavlink WL-WN579X3-C | Stack-based Buffer Overflow | T1210: Exploitation of Remote Services | Dépassement via l'argument 'UpnpEnabled' dans firewall.cgi | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2026-5004) |
| CVE-2018-25225 | 8.6 | Non spécifié | FALSE | SIPP 3.3 | Stack-based Buffer Overflow | T1203: Exploitation for Client Execution | Injection de code via fichier de configuration malveillant | [CVE Feed](https://cvefeed.io/vuln/detail/CVE-2018-25225) |
| CVE-2026-33634 | Non spécifié | Non spécifié | TRUE | CI/CD Ecosystem (TeamPCP) | Supply Chain Vulnerability | T1195.002: Compromise Software Supply Chain | Liée à la campagne TeamPCP, échéance de remédiation CISA fixée au 08 avril 2026 | [SANS ISC](https://isc.sans.edu/diary/rss/32842) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Apple issues urgent lock screen warnings for unpatched iPhones and iPads | Alerte critique sur des exploitations actives ("Coruna", "DarkSword") ciblant le noyau iOS | [Security Affairs](https://securityaffairs.com/190109/security/apple-issues-urgent-lock-screen-warnings-for-unpatched-iphones-and-ipads.html) |
| Кібератака UAC-0255 під виглядом сповіщення від CERT-UA із застосуванням програмного засобу AGEWHEEZE | Campagne d'espionnage sophistiquée utilisant une usurpation d'autorité cyber nationale | [CERT-UA](https://cert.gov.ua/article/6288047) |
| New Infinity Stealer malware grabs macOS data via ClickFix lures | Nouvelle menace macOS utilisant des techniques d'évasion avancées (Nuitka) et ingénierie sociale | [Bleeping Computer](https://www.bleepingcomputer.com/news/security/new-infinity-stealer-malware-grabs-macos-data-via-clickfix-lures/) |
| ShinyHunters claims the hack of the European Commission | Incident géopolitique majeur impactant les institutions européennes et le cloud AWS | [Security Affairs](https://securityaffairs.com/190095/data-breach/shinyhunters-claims-the-hack-of-the-european-commission.html) |
| TeamPCP Supply Chain Campaign: Update 003 | Suivi d'une campagne de chaîne d'approvisionnement mondiale entrant en phase de monétisation | [SANS ISC](https://isc.sans.edu/diary/rss/32842) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| 2026-03-28 RDP Honeypot IOCs | Données brutes de honeypot sans analyse contextuelle | [Mastodon / RDP Snitch](https://infosec.exchange/@rdpsnitch/116309589550476564) |
| Cloud security is more critical than ever | Publication de type sensibilisation générale sans nouvelle menace spécifique | [Mastodon](https://mastodon.social/@archibaldtitan/116309564514976682) |
| Possible Phishing on robiox.com | Notification isolée d'un seul IoC de phishing | [Mastodon / URLDNA](https://infosec.exchange/@urldna/116309636258124505) |
| The Run Dialog: Small Key, Loud Evidence | Article à visée éducative/forensics, pas une actualité de veille | [CyberEngage](https://www.cyberengage.org/post/the-run-dialog-small-key-loud-evidence) |
| TIAMAT: The First Autonomous AI Operating System | Contenu promotionnel pour un projet technologique | [Mastodon](https://mastodon.social/@TiamatEnity/116309734013107423) |

<br>
<br>
<div id="articles"></div>

# ARTICLES

<div id="attaque-de-lacteur-uac0255-via-le-malware-agewheeze"></div>

## Attaque de l'acteur UAC-0255 sous couvert du CERT-UA via le malware AGEWHEEZE
Le CERT-UA a détecté une campagne malveillante sophistiquée les 26 et 27 mars 2026 ciblant de nombreux secteurs en Ukraine. Les attaquants utilisent des e-mails de phishing usurpant l'identité du CERT-UA, invitant les victimes à installer un prétendu "outil de protection" depuis la plateforme Files.fm. Un site miroir frauduleux, cert-ua[.]tech, a également été mis en place pour renforcer la crédibilité de l'attaque. Le fichier téléchargé installe AGEWHEEZE, un outil de contrôle à distance (RAT) écrit en Go. Ce malware permet le contrôle de l'écran, la manipulation de fichiers, l'exfiltration du presse-papier et l'exécution de commandes système. L'infrastructure de commande (C2) est hébergée chez OVH et présente des traces en langue russe. La persistance est assurée par des tâches planifiées nommées "SvcHelper" ou "CoreService". Des liens avec le groupe "Cyber Serp" sont suspectés via des commentaires dans le code HTML.

**Analyse de l'impact** : Impact critique pour la souveraineté numérique ukrainienne. L'usurpation d'une autorité de réponse aux incidents (CERT) brise la chaîne de confiance et peut paralyser les efforts de remédiation légitimes tout en offrant un accès total aux systèmes compromis.

**Recommandations** : 
* Bloquer les domaines cert-ua[.]tech et creepy[.]ltd au niveau du DNS/Proxy.
* Rechercher la présence des exécutables SysSvc.exe et service.exe dans %APPDATA%.
* Monitorer les tâches planifiées inhabituelles nommées SvcHelper et CoreService.
* Sensibiliser les utilisateurs sur le fait que le CERT-UA ne demande jamais l'installation d'outils via des liens tiers type Files.fm.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UAC-0255 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.002: Phishing: Malicious Link <br/> * T1059: Command and Scripting Interpreter <br/> * T1053.005: Scheduled Task <br/> * T1105: Ingress Tool Transfer |
| Observables & Indicateurs de compromission | ```* IP: 54.36.237.92 <br/> * Domain: cert-ua[.]tech <br/> * Hash (AGEWHEEZE): 5f16463f5c463f5f2f69f31c6ce7d3040d07876156a265b5521737f1c7a2a9b3 <br/> * Path: %APPDATA%\SysSvc\SysSvc.exe``` |

### Source (url) du ou des articles
* https://cert.gov.ua/article/6288047

<br>
<br>

<div id="campagne-teampcp-transition-vers-la-phase-de-monetisation"></div>

## Campagne TeamPCP : Transition vers la phase de monétisation
La campagne de chaîne d'approvisionnement TeamPCP observe une pause opérationnelle de 48 heures sans nouvelle compromisison, suggérant un passage à la phase de monétisation des données volées (environ 300 Go). Cette évolution est marquée par un partenariat avec l'affilié de ransomware Vect. Palo Alto Networks a publié des règles comportementales pour détecter ces attaques CI/CD, se concentrant sur l'énumération anormale de secrets et les transferts de données vers des domaines récents. Parallèlement, la Cloud Security Alliance a analysé un "wiper" Kubernetes ciblant spécifiquement les systèmes paramétrés en langue farsi. L'analyse de GitGuardian révèle un "credential fan-out" de 10 000 pour 1, signifiant qu'un seul token volé a pu exposer des milliers de secrets en aval. L'exfiltration via les "GitHub Releases" est confirmée comme une technique de contournement des solutions DLP. Enfin, l'intrusion chez AstraZeneca reste à confirmer malgré les revendications de LAPSUS$.

**Analyse de l'impact** : Risque systémique élevé pour les entreprises utilisant des pipelines DevOps. Le passage au ransomware signifie que les accès volés ces 10 derniers jours vont maintenant être transformés en attaques destructrices ou extorsions.

**Recommandations** : 
* Réaliser une rotation complète des secrets et tokens PAT utilisés dans les pipelines CI/CD.
* Déployer des politiques d'admission Kubernetes pour bloquer les DaemonSets privilégiés montant le hostPath /.
* Rechercher les archives nommées tpcp.tar.gz sur les runners.
* Monitorer les accès au processus memory de Runner.Worker.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TeamPCP, Vect (Affilié), LAPSUS$ (suspecté) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Compromise Software Supply Chain <br/> * T1567.001: Exfiltration to Cloud Repository (GitHub Releases) <br/> * T1485: Data Destruction (Kubernetes Wiper) |
| Observables & Indicateurs de compromission | ```* Domain: api.github.com (exfiltration channel) <br/> * File: tpcp.tar.gz <br/> * CVE: CVE-2026-33634``` |

### Source (url) du ou des articles
* https://isc.sans.edu/diary/rss/32842

<br>
<br>

<div id="infinity-stealer-nouvelle-menace-macos-via-clickfix"></div>

## Infinity Stealer : Nouvelle menace macOS via ClickFix
Une nouvelle campagne d'info-stealer baptisée "Infinity Stealer" cible les utilisateurs de macOS en utilisant la technique d'ingénierie sociale ClickFix. L'attaque commence par une fausse page de vérification CAPTCHA Cloudflare (sur update-check[.]com) qui incite l'utilisateur à copier-coller une commande curl malveillante dans son Terminal. Cette commande exécute un chargeur écrit en Python et compilé avec Nuitka, ce qui transforme le script en binaire natif Mach-O, rendant l'analyse statique et la détection très difficiles. Le malware effectue des vérifications anti-analyse avant de décompresser le payload final. Il est capable de voler les mots de passe des navigateurs (Chrome, Firefox), les trousseaux d'accès Keychain, les portefeuilles crypto et les fichiers de configuration (.env) contenant des secrets de développement. L'exfiltration se fait via HTTP POST avec une notification envoyée aux attaquants sur Telegram.

**Analyse de l'impact** : Risque élevé pour les développeurs et administrateurs utilisant macOS. La technique de compilation Nuitka marque une évolution dans la sophistication des malwares macOS, cherchant à contourner les protections Gatekeeper et les EDR par l'exécution de commandes Terminal par l'utilisateur lui-même.

**Recommandations** : 
* Interdire l'utilisation de commandes Terminal copiées-collées depuis des sources web non vérifiées.
* Surveiller les connexions sortantes vers le domaine update-check[.]com.
* Déployer des règles EDR détectant l'exécution de scripts Bash via curl | bash vers le répertoire /tmp.
* Rechercher la présence de binaires inhabituels générés par Nuitka (UpdateHelper.bin).

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non mentionné |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1204.002: User Execution: Malicious File <br/> * T1059.004: Unix Shell <br/> * T1555: Credentials from Password Stores <br/> * T1140: Deinstall or Deactivate Security Software |
| Observables & Indicateurs de compromission | ```* Domain: update-check[.]com <br/> * Binary: UpdateHelper.bin <br/> * Technique: Nuitka-compiled Python payload``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/new-infinity-stealer-malware-grabs-macos-data-via-clickfix-lures/

<br>
<br>

<div id="alerte-apple-exploitations-actives-coruna-et-darksword"></div>

## Alerte Apple : Exploitations actives Coruna et DarkSword
Apple a émis des avertissements urgents via des notifications sur l'écran de verrouillage pour les utilisateurs d'iPhones et d'iPads non patchés. Ces alertes concernent des exploitations actives basées sur le web ciblant des versions obsolètes d'iOS (de la version 13 à 17.2.1). Les kits d'exploitation identifiés, "Coruna" et "DarkSword", utilisent du contenu web malveillant pour déclencher des chaînes d'infection permettant le vol de données sensibles. Les chercheurs de Kaspersky ont révélé que "Coruna" utilise une version mise à jour d'un exploit de noyau déjà vu dans la campagne "Operation Triangulation" de 2023. Bien que les versions iOS 18.x soient protégées contre Coruna, elles resteraient cibles potentielles pour DarkSword sur les versions antérieures à 18.7. Apple insiste sur l'installation immédiate des mises à jour de sécurité critiques pour rompre ces attaques.

**Analyse de l'impact** : Risque critique de compromission de la confidentialité des données mobiles. La réutilisation de frameworks d'exploitation d'élite suggère que ces outils sont désormais industrialisés ou partagés entre groupes d'espionnage.

**Recommandations** : 
* Forcer la mise à jour immédiate de tous les appareils iOS vers la dernière version disponible (iOS 17.7+ ou 18.x).
* Activer le "Lockdown Mode" (Mode Isolement) pour les utilisateurs à haut risque, ce qui bloque ces vecteurs d'attaque web.
* Activer la fonction "Safe Browsing" de Safari par défaut via MDM.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Operation Triangulation (liens suspectés) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1204.001: User Execution: Malicious Link <br/> * T1068: Exploitation for Privilege Escalation <br/> * T1430: Location Tracking |
| Observables & Indicateurs de compromission | ```* Exploit Kits: Coruna, DarkSword <br/> * Vulnerability: Kernel exploits (ref. Operation Triangulation)``` |

### Source (url) du ou des articles
* https://securityaffairs.com/190109/security/apple-issues-urgent-lock-screen-warnings-for-unpatched-iphones-and-ipads.html

<br>
<br>

<div id="compromission-majeure-de-la-commission-europeenne-par-shinyhunters"></div>

## Compromission majeure de la Commission Européenne par ShinyHunters
Le groupe de cybercriminalité ShinyHunters revendique une intrusion massive dans l'infrastructure de la Commission Européenne. Les attaquants affirment avoir volé plus de 350 Go de données, incluant des serveurs de messagerie, des bases de données, des documents confidentiels et des contrats. La Commission a confirmé avoir détecté une attaque le 24 mars ciblant l'infrastructure cloud hébergeant les sites Europa.eu. Bien que l'institution affirme que ses systèmes internes n'ont pas été touchés, ShinyHunters a publié des captures d'écran suggérant une compromission de leur compte AWS. AWS a nié toute faille de sa propre infrastructure, suggérant une erreur de configuration ou un vol de credentials côté client. ShinyHunters est connu pour utiliser le vishing (phishing vocal) et l'ingénierie sociale pour accéder aux plateformes SaaS comme Okta ou Microsoft 365.

**Analyse de l'impact** : Impact géopolitique et réputationnel majeur. La fuite potentielle de correspondances diplomatiques et de contrats européens représente un risque de chantage et d'espionnage économique à long terme.

**Recommandations** : 
* Renforcer l'authentification multi-facteurs (MFA) sur tous les comptes à privilèges cloud (AWS, Azure).
* Auditer les configurations S3 et les politiques IAM pour détecter des accès non autorisés ou des expositions publiques.
* Sensibiliser le personnel aux techniques de social engineering (vishing) ciblant les administrateurs IT.
* Surveiller les sites de fuite Tor de ShinyHunters pour toute publication d'échantillons de données.

Voici quelques indicateurs clés au sein du tableau ci-dessous :
| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | ShinyHunters |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.003: Phishing: Voice <br/> * T1078.004: Valid Accounts: Cloud Accounts <br/> * T1537: Transfer Data to Cloud Account |
| Observables & Indicateurs de compromission | ```* Target: europa.eu cloud infrastructure <br/> * Platform: AWS <br/> * Volume: 350 GB+``` |

### Source (url) du ou des articles
* https://securityaffairs.com/190095/data-breach/shinyhunters-claims-the-hack-of-the-european-commission.html