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
  * [uac-0247  campagne d'espionnage contre les infrastructures ukrainiennes](#uac-0247-campagne-despionnage-contre-les-infrastructures-ukrainiennes)
  * [compromission critique de nginx ui via le protocole mcp](#compromission-critique-de-nginx-ui-via-le-protocole-mcp)
  * [teampcp  offensive majeure sur la supply chain logicielle et les outils ai](#teampcp-offensive-majeure-sur-la-supply-chain-logicielle-et-les-outils-ai)
  * [dragon boss solutions  l'usage de logiciels signés pour neutraliser les antivirus](#dragon-boss-solutions-lusage-de-logiciels-signes-pour-neutraliser-les-antivirus)
  * [mirax  evolution du malware-as-a-service android vers les proxys résidentiels](#mirax-evolution-du-malware-as-a-service-android-vers-les-proxys-residentiels)
  * [abus de n8n et de l'automatisation ai pour le phishing sophistique](#abus-de-n8n-et-de-lautomatisation-ai-pour-le-phishing-sophistique)

<br/>
<br/>
<div id="analyse-strategique"></div>

# Analyse Stratégique
L'intégration de l'IA générative dans les cycles d'attaque et de défense redéfinit la menace, illustrée par la capacité de modèles comme "Mythos" à déceler des failles logicielles vieilles de 20 ans. La chaîne d'approvisionnement logicielle reste la vulnérabilité systémique majeure, les acteurs ciblant désormais les outils de développement critiques comme GitHub Actions et les packages d'intégration IA. Parallèlement, le conflit israélo-iranien se transpose dans le cyberespace avec des opérations de destruction de données massives (6 pétaoctets revendiqués par Handala) et des menaces directes contre les entreprises technologiques américaines. L'exploitation de certificats de signature légitimes pour désactiver les antivirus montre une sophistication accrue des logiciels malveillants publicitaires. En Europe, la pression réglementaire via le "Digital Omnibus" suscite des inquiétudes sur l'affaiblissement potentiel du RGPD et de l'IA Act. Le secteur des transports et de la logistique émerge comme une cible prioritaire, où la cybercriminalité facilite désormais le vol de cargaisons physiques. La professionnalisation des cyber-extorqueurs se confirme avec un ciblage intensif des PME allemandes (Mittelstand), souvent moins protégées que les grands groupes. Enfin, l'abus des plateformes d'automatisation (n8n, webhooks) permet aux attaquants de contourner les filtres de sécurité traditionnels via des infrastructures de confiance.
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
| **Handala Hack** | Gouvernements (EAU, US), Israël | Wiper, exfiltration massive, compromission de serveurs fax cloud | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| **TeamPCP** | Développeurs, Supply Chain, IA | Vol de tokens GitHub, empoisonnement de repositories (LiteLLM, Checkmarx) | [Recorded Future](https://www.recordedfuture.com/blog/your-supply-chain-breach-is-someone-else-payday) |
| **UAC-0247** | Santé, Gouvernements locaux (Ukraine), Défense | Phishing (humanitaire), XSS, malware AgingFly, DLL side-loading | [CERT-UA](https://cert.gov.ua/article/6288271) |
| **Vovan & Lexus** | Diplomatie, Dirigeants mondiaux | FIMI (Information Manipulation), ingénierie sociale par faux appels téléphoniques | [EUvsDisinfo](https://euvsdisinfo.eu/pranked-by-the-kremlin-fake-phone-calls-as-a-fimi-instrument/) |

<br/>
<br/>
<div id="synthese-geopolitique"></div>

## Synthèse de l'actualité géopolitique
Voici un tableau récapitulatif de l'actualité géopolitique de ce jour :
| Secteur d'activité | Thème | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Défense | Conflit Ukraine-Russie | Analyse sur l'émergence des sociétés militaires privées ukrainiennes comme levier d'influence post-guerre. | [Portail de l'IE](https://www.portail-ie.fr/univers/2026/les-societes-militaires-privees-ukrainiennes-entre-heritage-de-guerre-et-futur-levier-dinfluence-partie-2-2/) |
| Défense | Conflit US-Israël-Iran | Blocus naval américain, cyber-attaques de rétorsion iraniennes et blackout internet en Iran (jour 47). | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Diplomatie | Vatican | Bilan de la première année du pontificat de Léon XIV et son repositionnement vers le Sud global (Afrique). | [IRIS](https://www.iris-france.org/un-pontificat-en-recomposition-bilan-de-la-premiere-annee-de-leon-xiv-entre-repositionnement-diplomatique-tensions-transatlantiques-et-recentrage-africain/) |
| Diplomatie | Négociations Iran-USA | Échec des discussions à Islamabad concernant le programme nucléaire iranien. | [IRIS](https://www.iris-france.org/que-veut-negocier-teheran-les-mardis-de-liris/) |

<br/>
<br/>

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridiques
Voici un tableau récapitulatif complet de tous les articles juridiques relatifs à la réglementation « CYBER » :
| Titre de l'article | Auteur | Date de publication | Juridiction | Référence législative / normative | Description du texte réglementaire | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|
| Chile’s Cybersecurity Framework Law | ANY.RUN | 15/04/2026 | Chili | Loi n° 21.663 | Cadre imposant des obligations de détection, réponse et rapports (3h à 72h) pour les opérateurs d'importance vitale. | [ANY.RUN](https://any.run/cybersecurity-blog/chile-cybersecurity-framework-law/) |
| Comdribus Ruling | CJEU | 19/03/2026 | Union Européenne / France | Article 55-1 Code Procédure Pénale | La CJUE juge disproportionnée la collecte systématique d'empreintes et photos par la police française. | [EDRi](https://edri.org/our-work/the-court-of-justice-of-the-european-union-condemns-frances-police-profiling-practices/) |
| Digital Omnibus Proposal | EDRi | 15/04/2026 | Union Européenne | GDPR / AI Act / Data Act | Projet de simplification risquant d'affaiblir les protections sur les données personnelles et les systèmes IA à haut risque. | [EDRi](https://edri.org/our-work/europe-shouldnt-move-fast-and-break-things-with-fundamental-rights/) |

<br/>
<br/>
<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données
Voici un tableau récapitulatif des violations de données constatées :
| Secteur d'activité | Victime | Description de la menace/incident | Source(s)/Url(s) |
|:---|:---|:---|:---|
| Education | **McGraw Hill** | Fuite de 13,5 millions de comptes (emails, noms) via une mauvaise configuration Salesforce. | [HIBP](https://haveibeenpwned.com/Breach/McGrawHill) |
| Gouvernement local | **St. Joseph County, Indiana** | Vol de dossiers médicaux et rapports de police via un serveur fax cloud par Handala. | [Flare](https://flare.io/learn/resources/blog/cyberattacks-us-israel-iran-military-conflict) |
| Jeux Vidéo | **Rockstar Games** | Revendication de piratage et début de fuite de données par ShinyHunters (mention). | [SecurityAffairs](https://securityaffairs.com/190841/hacking/cve-2026-33032-severe-nginx-ui-bug-grants-unauthenticated-server-access.html) |
| Sport / Loisirs | **Basic-Fit** | Compromission des données personnelles d'un million de membres. | [SecurityAffairs](https://securityaffairs.com/190841/hacking/cve-2026-33032-severe-nginx-ui-bug-grants-unauthenticated-server-access.html) |

<br/>
<br/>
<div id="synthese-des-vulnerabilites"></div>

## Synthèse des vulnérabilités
Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).
| CVE-ID | Score CVSS | EPSS | CISA Kev | Produit affecté | Type de vulnérabilité | Tactiques Techniques et Procédures MITRE ATT&CK | Description | Source(s)/Url(s) |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| CVE-2026-39842 | 10.0 | N/A | FALSE | OpenRemote | Expression Injection | Non mentionnées | Injection de code via les moteurs Nashorn et Groovy sans sandboxing. | [SecurityOnline](https://securityonline.info/openremote-cvss-10-vulnerability-iot-security-rce/) |
| CVE-2026-33032 | 9.8 | N/A | TRUE | Nginx UI | Auth Bypass | T1190: Exploit Public-Facing Application | L'endpoint /mcp_message ne vérifie pas l'authentification, permettant un takeover complet du serveur. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-nginx-ui-auth-bypass-flaw-now-actively-exploited-in-the-wild/) |
| CVE-2026-33824 | 9.8 | N/A | FALSE | Windows IKE | RCE | Non mentionnées | Exécution de code à distance via les extensions du service IKE. | [SecurityAffairs](https://securityaffairs.com/190831/security/microsoft-patch-tuesday-for-april-2026-fixed-actively-exploited-sharepoint-zero-day.html) |
| CVE-2026-40173 | 9.4 | N/A | FALSE | Dgraph | Information Disclosure | Non mentionnées | Fuite du token admin via l'endpoint pprof non authentifié. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-40173) |
| CVE-2009-0238 | 9.3 | N/A | TRUE | MS Excel | RCE | Non mentionnées | Vulnérabilité historique de corruption de mémoire réajoutée au catalogue KEV. | [CISA](https://securityaffairs.com/190852/hacking/u-s-cisa-adds-microsoft-sharepoint-server-and-microsoft-office-excel-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| CVE-2026-6388 | 9.1 | N/A | FALSE | ArgoCD Image Updater | PrivEsc | Non mentionnées | Escalation inter-namespace via une validation insuffisante des ressources. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-6388) |
| CVE-2026-39808 | 9.1 | N/A | FALSE | FortiSandbox | OS Command Injection | Non mentionnées | Injection de commandes via des requêtes HTTP malveillantes. | [The Register](https://go.theregister.com/feed/www.theregister.com/2026/04/15/critical_fortinet_sandbox_bugs/) |
| CVE-2026-40316 | 8.8 | N/A | FALSE | OWASP BLT | RCE | Non mentionnées | Exécution de code via les workflows GitHub Actions et des modèles Django non fiables. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-40316) |
| CVE-2026-40261 | 8.8 | N/A | FALSE | PHP Composer | Command Injection | Non mentionnées | Injection de commandes via des références Perforce malveillantes dans les métadonnées. | [SecurityAffairs](https://securityaffairs.com/190824/security/php-composer-flaws-enable-remote-command-execution-via-perforce-vcs.html) |
| CVE-2026-6363 | 8.8 | N/A | FALSE | Chrome V8 | Memory Access | Non mentionnées | Confusion de type permettant un accès mémoire hors limites. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-6363) |
| CVE-2026-40192 | 8.7 | N/A | FALSE | Pillow (Python) | DoS | Non mentionnées | Bombe de décompression GZIP sur les images FITS provoquant un crash OOM. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-40192) |
| CVE-2026-34622 | 8.6 | N/A | FALSE | Adobe Acrobat | RCE | Non mentionnées | Prototype Pollution permettant l'exécution de code arbitraire. | [CybersecurityNews](https://cybersecuritynews.com/adobe-acrobat-reader-vulnerabilities-patch/) |
| CVE-2026-22676 | 8.5 | N/A | FALSE | Barracuda RMM | PrivEsc | Non mentionnées | Permissions de répertoire non sécurisées permettant de gagner des privilèges SYSTEM. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-22676) |
| CVE-2026-33825 | 7.8 | N/A | TRUE | MS Defender | PrivEsc | Non mentionnées | "BlueHammer" : abus du mécanisme de mise à jour des signatures pour obtenir SYSTEM. | [Field Effect](https://fieldeffect.com/blog/microsoft-april-2026-patch-tuesday-bluehammer) |
| CVE-2026-32201 | 6.5 | N/A | TRUE | MS SharePoint | Spoofing | T1190: Exploit Public-Facing Application | Vulnérabilité de spoofing (XSS probable) exploitée activement. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-flags-windows-task-host-vulnerability-as-exploited-in-attacks/) |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés
| Titre de l'article | Raison | Url |
|:---|:---|:---|
| Лікарні, органи місцевого самоврядування та оператори FPV - у фокусі кластера UAC-0247 | Rapport technique détaillé sur une menace étatique ciblant des infrastructures critiques. | [CERT-UA](https://cert.gov.ua/article/6288271) |
| Critical Nginx UI auth bypass flaw now actively exploited in the wild | Alerte sur une vulnérabilité critique de prise de contrôle de serveur exploitée activement. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-nginx-ui-auth-bypass-flaw-now-actively-exploited-in-the-wild/) |
| Your Supply Chain Breach Is Someone Else's Payday | Analyse stratégique sur une nouvelle vague d'attaques supply chain ciblant les outils de développement. | [Recorded Future](https://www.recordedfuture.com/blog/your-supply-chain-breach-is-someone-else-payday) |
| Signed software abused to deploy antivirus-killing scripts | Analyse d'une technique de contournement sophistiquée utilisant des certificats légitimes. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/signed-software-abused-to-deploy-antivirus-killing-scripts/) |
| Mirax malware campaign hits 220K accounts, enables full remote control | Découverte d'un nouveau RAT Android massif avec des fonctionnalités de proxy résidentiel. | [SecurityAffairs](https://securityaffairs.com/190842/uncategorized/mirax-malware-campaign-hits-220k-accounts-enables-full-remote-control.html) |
| The n8n n8mare: How threat actors are misusing AI workflow automation | Recherche originale sur le détournement des outils d'automatisation IA pour le phishing. | [Cisco Talos](https://blog.talosintelligence.com/the-n8n-n8mare/) |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés
| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| GPT-5.4 Cyber is a more permissive model... | Publication de réseau social (Mastodon), information non vérifiée. | [Mastodon](https://mastodon.social/@techglimmer/116411839300139760) |
| McGraw Hill - 13,500,136 breached accounts | Violation de données (traité en synthèse). | [HIBP](https://haveibeenpwned.com/Breach/McGrawHill) |
| Multiples vulnérabilités dans Tenable Identity Exposure | Liste brute de vulnérabilités (traité en synthèse). | [CERT-FR](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0436/) |
| Building a $40 Stingray Detector | Article de blog sur un projet DIY, moins pertinent pour une veille entreprise. | [cha1nc0der](https://cha1nc0der.wordpress.com/2026/04/15/building-a-40-stingray-detector-that-fits-in-an-altoids-tin/) |
| ISC Stormcast For Thursday, April 16th | Format podcast, résumé trop succinct. | [SANS ISC](https://isc.sans.edu/podcastdetail/9894) |

<br>
<br/>
<div id="articles"></div>

# ARTICLES
<div id="uac-0247-campagne-despionnage-contre-les-infrastructures-ukrainiennes"></div>

## [CERT-UA] Лікарні, органи місцевого самоврядування та оператори FPV - у фокусі кластера UAC-0247
Le CERT-UA a identifié une intensification des attaques du cluster UAC-0247 ciblant les municipalités et les hôpitaux ukrainiens. L'attaque débute par un e-mail de phishing proposant de l'aide humanitaire, redirigeant vers des sites compromis via XSS ou générés par IA. Un archive ZIP contenant un fichier LNK déclenche l'exécution de fichiers HTA via mshta.exe. Un injecteur déploie ensuite le malware **AgingFly** (écrit en C#) ou des scripts PowerShell nommés **SilentLoop**. L'attaquant utilise des outils open-source comme ChromElevator pour voler les mots de passe et ZAPiDESK pour extraire les données WhatsApp. La reconnaissance réseau est effectuée via RustScan, et des tunnels cachés sont créés avec Ligolo-ng ou Chisel. Notablement, des opérateurs de drones FPV ont été ciblés via une fausse mise à jour du logiciel "BACHU" distribuée sur Signal. AgingFly se distingue par sa capacité à compiler dynamiquement des handlers de commandes reçus directement de son serveur C2.

**Analyse de l'impact** : Menace critique pour la continuité des soins hospitaliers et la sécurité des opérations militaires (drones). L'exfiltration de données d'authentification et de communications WhatsApp permet un espionnage profond et des mouvements latéraux au sein des réseaux gouvernementaux.

**Recommandations** :
* Bloquer l'exécution des extensions .lnk, .hta et .js via les politiques de restriction logicielle (AppLocker/WDAC).
* Surveiller les processus mshta.exe, powershell.exe et wscript.exe pour des connexions réseau inhabituelles.
* Rechercher la présence de répertoires `%LOCALAPPDATA%\OneDriveUpdater` et de tâches planifiées nommées "OneDrive Updater".
* Imposer l'authentification multi-facteurs (MFA) pour limiter l'impact du vol de sessions Chromium via ChromElevator.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | UAC-0247 |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.001: Phishing: Spearphishing Attachment <br/> * T1218.005: System Binary Proxy Execution: Mshta <br/> * T1574.002: DLL Side-Loading <br/> * T1021.001: Remote Services: Remote Desktop Protocol <br/> * T1059.001: PowerShell |
| Observables & Indicateurs de compromission | ```* 57c6b2e25330b2385a0f3bcd8c7ae531b745a3e7e50657d7f78eaef7ad3d3f8d (AgingFly) * ukrvarta[.]online * nazk.linkpc[.]net * 109[.]237.97.43``` |

### Source (url) du ou des articles
* https://cert.gov.ua/article/6288271
* https://www.bleepingcomputer.com/news/security/new-agingfly-malware-used-in-attacks-on-ukraine-govt-hospitals/

<br>
<br>

<div id="compromission-critique-de-nginx-ui-via-le-protocole-mcp"></div>

## Critical Nginx UI auth bypass flaw now actively exploited in the wild
Une vulnérabilité critique (CVE-2026-33032) affecte Nginx UI, une interface de gestion web populaire, permettant une prise de contrôle totale du serveur sans authentification. Le problème réside dans l'exposition non protégée de l'endpoint `/mcp_message`, lié au protocole Model Context Protocol (MCP) pour les assistants IA. Un attaquant peut établir une session et envoyer des requêtes pour modifier, créer ou supprimer des fichiers de configuration Nginx. Cela permet notamment d'injecter des blocs de serveurs malveillants pour intercepter le trafic ou forcer des rechargements de configuration. Environ 2 600 instances sont actuellement exposées sur Internet, principalement en Chine et aux États-Unis. L'exploitation est extrêmement simple et ne nécessite que deux requêtes HTTP. Le correctif a été introduit dans la version 2.3.4 de Nginx UI.

**Analyse de l'impact** : Risque maximal (CVSS 9.8). Une exploitation réussie permet de détourner tout le trafic web géré par le serveur Nginx, de voler des secrets ou de paralyser les services web d'une organisation.

**Recommandations** :
* Mettre à jour immédiatement Nginx UI vers la version 2.3.6 ou supérieure.
* Restreindre l'accès à l'interface de gestion (port 9000 par défaut) via un VPN ou une liste blanche d'IP.
* Vérifier l'intégrité des fichiers de configuration Nginx pour détecter toute modification non autorisée.
* Désactiver les fonctionnalités MCP si elles ne sont pas nécessaires à l'exploitation.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non applicable |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1190: Exploit Public-Facing Application <br/> * T1078: Valid Accounts (Bypass) |
| Observables & Indicators of compromise | ```* URI: /mcp_message * Port: 9000 * User-Agent: PlutoSecurity-Scanner (pour les tests bénins)``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/critical-nginx-ui-auth-bypass-flaw-now-actively-exploited-in-the-wild/
* https://fieldeffect.com/blog/critical-nginx-ui-vulnerability

<br>
<br>

<div id="teampcp-offensive-majeure-sur-la-supply-chain-logicielle-et-les-outils-ai"></div>

## Your Supply Chain Breach Is Someone Else's Payday
Le groupe TeamPCP a mené une campagne foudroyante en mars 2026, compromettant cinq écosystèmes logiciels en cinq jours. Ils ont utilisé des identifiants GitHub volés pour injecter du code malveillant dans LiteLLM (97 millions de téléchargements/mois) et empoisonner les workflows GitHub Actions de Checkmarx. Le malware visait spécifiquement à récolter des clés API IA, des secrets cloud et des tokens de service. TeamPCP semble opérer comme un affilié ransomware, menaçant de divulguer 300 Go de données volées, potentiellement en collaboration avec Lapsus$. L'attaque souligne que l'identité du développeur est devenue le nouveau périmètre de sécurité. Les outils de sécurité eux-mêmes sont devenus des cibles privilégiées car ils possèdent des accès étendus aux infrastructures sensibles.

**Analyse de l'impact** : Impact systémique sur la supply chain. La compromission d'outils de test de sécurité (AppSec) et d'intégration IA permet aux attaquants de s'infiltrer chez des milliers de clients finaux simultanément pour des fraudes financières ou de l'extorsion.

**Recommandations** :
* Rotation immédiate de tous les secrets et clés API si LiteLLM, Aqua Trivy ou Checkmarx GitHub Actions sont utilisés.
* Imposer la signature cryptographique de tous les commits et artefacts de build.
* Auditer les pipelines CI/CD pour détecter toute injection de commande inhabituelle.
* Utiliser des versions figées (pinning) et vérifiées par hash pour les dépendances logicielles.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | TeamPCP |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1195.002: Supply Chain Compromise: Compromise Software Dependencies <br/> * T1552.001: Unsecured Credentials: Private Keys <br/> * T1199: Trusted Relationship |
| Observables & Indicateurs de compromission | ```* Telegram: TeamPCP * Domaines de destination des données chiffrées (non spécifiés en clair)``` |

### Source (url) du ou des articles
* https://www.recordedfuture.com/blog/your-supply-chain-breach-is-someone-else-payday

<br>
<br>

<div id="dragon-boss-solutions-lusage-de-logiciels-signes-pour-neutraliser-les-antivirus"></div>

## Signed software abused to deploy antivirus-killing scripts
Une campagne massive impliquant plus de 23 500 hôtes infectés utilise des logiciels publicitaires (PUP) signés numériquement par "Dragon Boss Solutions LLC". Ces programmes (Chromstera, Chromnius) incluent un mécanisme de mise à jour silencieux via l'outil commercial Advanced Installer. Le processus déploie un script PowerShell nommé `ClockRemoval.ps1` avec des privilèges SYSTEM. Ce script désactive et désinstalle agressivement les solutions de sécurité de Malwarebytes, Kaspersky, McAfee et ESET. Il modifie également le fichier `hosts` pour null-router (0.0.0.0) les domaines des éditeurs antivirus, empêchant toute mise à jour ou réinstallation. Des centaines d'infections ont été détectées dans des réseaux de haute valeur, incluant des infrastructures critiques et des entreprises du Fortune 500. Huntress a pu sinkholer le domaine de mise à jour principal car il n'avait pas été enregistré par les attaquants.

**Analyse de l'impact** : Très haute. La neutralisation des protections EDR/AV sur des milliers de serveurs laisse le champ libre à des déploiements ultérieurs de ransomwares ou d'outils d'espionnage sans aucune résistance technique.

**Recommandations** :
* Rechercher les abonnements d'événements WMI contenant "MbRemoval" ou "MbSetup".
* Vérifier la présence de tâches planifiées référençant "WMILoad" ou "ClockRemoval".
* Auditer les exclusions Microsoft Defender pour des chemins suspects comme "DGoogle" ou "EMicrosoft".
* Révoquer ou bloquer l'exécution des certificats signés par "Dragon Boss Solutions LLC".

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Dragon Boss Solutions LLC |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1562.001: Impair Defenses: Disable or Modify Tools <br/> * T1553.002: Subvert Trust Controls: Code Signing <br/> * T1053.005: Scheduled Task/Job: Scheduled Task |
| Observables & Indicateurs de compromission | ```* chromsterabrowser[.]com * worldwidewebframework3[.]com * Setup.msi (déguisé en GIF)``` |

### Source (url) du ou des articles
* https://www.bleepingcomputer.com/news/security/signed-software-abused-to-deploy-antivirus-killing-scripts/

<br>
<br>

<div id="mirax-evolution-du-malware-as-a-service-android-vers-les-proxys résidentiels"></div>

## Mirax malware campaign hits 220K accounts, enables full remote control
Mirax est un nouveau cheval de Troie d'accès à distance (RAT) Android distribué via des publicités Meta (Facebook, Instagram). Ciblant principalement les utilisateurs hispanophones, il se déguise en applications de streaming sportif illégales. Le malware utilise une chaîne d'infection en deux étapes avec des droppers hébergés sur GitHub Releases. Une fois installé, il demande des permissions d'accessibilité pour prendre le contrôle total de l'appareil (capture d'écran, vol de données bancaires, gestion des applications). Sa caractéristique la plus innovante est la transformation des appareils infectés en nœuds de proxy résidentiels SOCKS5. Cela permet aux cybercriminels de router leur trafic malveillant via les adresses IP légitimes des victimes, facilitant ainsi les fraudes et les attaques DDoS tout en restant anonymes. Le modèle de distribution est exclusif et limité à quelques affiliés.

**Analyse de l'impact** : Massive. Avec 220 000 comptes touchés, cette campagne crée un botnet de proxys difficilement détectable, capable de compromettre la réputation des IP résidentielles et de faciliter des fraudes bancaires à grande échelle.

**Recommandations** :
* Interdire le "sideloading" d'applications (APK) sur les terminaux mobiles d'entreprise via les MDM.
* Sensibiliser les utilisateurs aux dangers des publicités pour des services illégaux sur les réseaux sociaux.
* Surveiller les pics de trafic SOCKS5 sortant inhabituel sur les segments réseau Wi-Fi invités.
* Utiliser des solutions de sécurité mobile (MTD) pour détecter les abus de l'Accessibilité Android.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Mirax (MaaS privé) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1470: User Execution <br/> * T1624.001: Event Triggered Execution: Accessibility Service <br/> * T1090: Proxy |
| Observables & Indicateurs de compromission | ```* APK Packaged with: Golden Encryption * C2 communication via WebSockets * GitHub Releases abuse``` |

### Source (url) du ou des articles
* https://securityaffairs.com/190842/uncategorized/mirax-malware-campaign-hits-220k-accounts-enables-full-remote-control.html

<br>
<br>

<div id="abus-de-n8n-et-de-lautomatisation-ai-pour-le-phishing-sophistique"></div>

## The n8n n8mare: How threat actors are misusing AI workflow automation
Cisco Talos a révélé une augmentation de 686% de l'abus de la plateforme d'automatisation n8n pour des campagnes de phishing. Les attaquants utilisent les webhooks de n8n pour masquer l'origine réelle de leurs charges utiles malveillantes. En envoyant des liens pointant vers des sous-domaines légitimes de `n8n.cloud`, ils contournent les filtres d'e-mail traditionnels basés sur la réputation de domaine. Les workflows n8n présentent des pages de phishing sophistiquées avec CAPTCHA avant de délivrer des malwares comme ITarian RMM ou Datto RMM détournés. Une autre utilisation courante identifiée est le "fingerprinting" d'appareils via des pixels espions invisibles intégrés dans des e-mails, permettant d'identifier précisément les cibles qui ouvrent les messages pour affiner les attaques ultérieures.

**Analyse de l'impact** : Élevée. Le détournement d'outils de productivité "low-code" permet de créer des infrastructures d'attaque dynamiques et hautement crédibles, rendant le phishing technique plus difficile à détecter pour les utilisateurs et les systèmes automatiques.

**Recommandations** :
* Déclencher une alerte SOC lorsqu'un trafic important est dirigé vers `n8n.cloud` depuis des sources internes non autorisées.
* Analyser les structures d'URL de webhooks dans les journaux de proxy.
* Mettre en œuvre une solution de sécurité d'e-mail avec détection comportementale basée sur l'IA pour repérer les anomalies de redirection.
* Bloquer les outils de gestion à distance (RMM) non approuvés au niveau de l'endpoint.

| Indicateurs | Descriptions |
|:---|:---|
| Groupe ou acteur malveillant | Non mentionnés (plusieurs clusters) |
| Tactiques, Techniques et Procédures (TTP) MITRE ATT&CK | * T1566.002: Phishing: Spearphishing Link <br/> * T1204.001: User Execution: Malicious Link <br/> * T1071.001: Application Layer Protocol: Web Protocols |
| Observables & Indicateurs de compromission | ```* tti.app.n8n[.]cloud * centrastage[.]net * monicasue.app.n8n[.]cloud``` |

### Source (url) du ou des articles
* https://blog.talosintelligence.com/the-n8n-n8mare/