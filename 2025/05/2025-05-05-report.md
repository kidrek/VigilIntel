# ⚠️Important Vulnerabilities (CVSS > 7.5)⚠️
* 🐛 Vulnérabilité Critique dans BlueWave Checkmate Permettant la Modification de Rôle (CVE-2025-47245)
* 🐛 Multiples Vulnérabilités dans les Chipsets MediaTek (Mai 2025)
* 🐛 Vulnérabilité Critique dans Apache Parquet Java Permettant l'Exécution de Code Arbitraire (CVE-2025-46762)
* 🐛 Vulnérabilité Critique dans Webmin Permettant l'Élévation de Privilèges au Niveau Root (CVE-2025-2774)
* 🐛 Vulnérabilité Critique d'Injection SQL dans la Bibliothèque PHP ADOdb (CVE-2025-46337)
* 🐛 Chaîne d'Exploitation SonicWall Expose un Risque de Détournement Admin via CVE-2023-44221 et CVE-2024-38475
* 🐛 Vulnérabilités Critique et Haute Signalées comme Activement Exploitées (CISA KEV)

## Table of Contents
* [Vulnérabilité Critique dans BlueWave Checkmate Permettant la Modification de Rôle (CVE-2025-47245)](#vulnérabilité-critique-dans-bluewave-checkmate-permettant-la-modification-de-rôle-cve-2025-47245)
* [Multiples Vulnérabilités dans les Chipsets MediaTek (Mai 2025)](#multiples-vulnérabilités-dans-les-chipsets-mediatek-mai-2025)
* [Vulnérabilité Critique dans Apache Parquet Java Permettant l'Exécution de Code Arbitraire (CVE-2025-46762)](#vulnérabilité-critique-dans-apache-parquet-java-permettant-lexécution-de-code-arbitraire-cve-2025-46762)
* [Vulnérabilité Critique dans Webmin Permettant l'Élévation de Privilèges au Niveau Root (CVE-2025-2774)](#vulnérabilité-critique-dans-webmin-permettant-lélévation-de-privilèges-au-niveau-root-cve-2025-2774)
* [Vulnérabilité Critique d'Injection SQL dans la Bibliothèque PHP ADOdb (CVE-2025-46337)](#vulnérabilité-critique-dinjection-sql-dans-la-bibliothèque-php-adodb-cve-2025-46337)
* [Campagne 'Operation Deceptive Prospect' de l'Acteur de Menace RomCom Ciblant le Royaume-Uni via des Portails de Feedback](#campagne-operation-deceptive-prospect-de-lacteur-de-menace-romcom-ciblant-le-royaume-uni-via-des-portails-de-feedback)
* [Chaîne d'Exploitation SonicWall Expose un Risque de Détournement Admin via CVE-2023-44221 et CVE-2024-38475](#chaîne-dexploitation-sonicwall-expose-un-risque-de-détournement-admin-via-cve-2023-44221-et-cve-2024-38475)
* [Vulnérabilité macOS Expose par Microsoft Permettant l'Évasion du Sandbox d'Application (CVE-2025-31191)](#vulnérabilité-macos-expose-par-microsoft-permettant-lévation-du-sandbox-dapplication-cve-2025-31191)
* [SocGholish Reloaded: Campagne de Loader Orientée Ransomware Découverte par Darktrace](#socgholish-reloaded-campagne-de-loader-orientée-ransomware-découverte-par-darktrace)
* [Groupe APT Iranien Porte Atteinte à l'Infrastructure Critique au Moyen-Orient dans une Campagne Furtive](#groupe-apt-iranien-porte-atteinte-à-linfrastructure-critique-au-moyen-orient-dans-une-campagne-furtive)
* [Améliorations Furtives et Outils de Vol de Données pour le Malware StealC V2](#améliorations-furtives-et-outils-de-vol-de-données-pour-le-malware-stealc-v2)
* [Golden Chickens Déploie TerraStealerV2 pour Voler les Identifiants de Navigateur et les Données de Portefeuilles Crypto](#golden-chickens-déploie-terrastealerv2-pour-voler-les-identifiants-de-navigateur-et-les-données-de-portefeuilles-crypto)
* [Vulnérabilités Critique et Haute Signalées comme Activement Exploitées (CISA KEV)](#vulnérabilités-critique-et-haute-signalées-comme-activement-exploitées-cisa-kev)
* [Vulnérabilités 'AirBorne' dans le Protocole Apple AirPlay](#vulnérabilités-airborne-dans-le-protocole-apple-airplay)
* [Ancienne Backdoor Magento Exploite dans une Attaque de Chaîne d'Approvisionnement E-commerce](#ancienne-backdoor-magento-exploite-dans-une-attaque-de-chaîne-dapprovisionnement-e-commerce)
* [Le FBI Publie une Liste de Domaines LabHost](#le-fbi-publie-une-liste-de-domaines-labhost)

## Vulnérabilité Critique dans BlueWave Checkmate Permettant la Modification de Rôle (CVE-2025-47245)
Une vulnérabilité (CVE-2025-47245) a été découverte dans BlueWave Checkmate versions <= 2.0.2 avant le commit `d4a6072`. Cette faille permet à un attaquant de modifier une requête d'invitation pour spécifier un rôle privilégié, contournant ainsi les contrôles d'accès prévus. La vulnérabilité est classée comme Haute avec un score CVSS de 8.1 et est exploitable à distance. Bien qu'aucune donnée spécifique sur les produits affectés n'ait été enregistrée dans la base de données cvefeed.io, la faille est présente dans le logiciel Checkmate. Des correctifs sont disponibles via les dépôts GitHub du projet.
* Publication date : 2025/05/04
* 🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-47245, https://github.com/bluewave-labs/Checkmate
* 🆔 CVE : [CVE-2025-47245](https://cvefeed.io/vuln/detail/CVE-2025-47245)
* 💻 CVE IMPACTED PRODUCT : BlueWave Checkmate
* 💯 CVSS : 8.1
* ✅ Security recommandations : Appliquer le correctif dans la version 2.0.2 après le commit `d4a6072`. Les références vers les pull requests et les avis de sécurité sont disponibles sur GitHub.
* 📄 FILE_HASH_SHA1 : d4a60723f490502b3fe6f7f780a85d29bf5d1385

## Multiples Vulnérabilités dans les Chipsets MediaTek (Mai 2025)
Le bulletin de sécurité MediaTek de Mai 2025 révèle six vulnérabilités affectant une large gamme de dispositifs (smartphones, tablettes, AIoT, etc.). Parmi celles-ci, CVE-2025-20666 est jugée Haute (CVSS non spécifié mais décrit comme "High severity"), permettant un déni de service à distance dans le sous-système Modem si un appareil se connecte à une station de base malveillante. Les autres vulnérabilités (CVE-2025-20671, CVE-2025-20670, CVE-2025-20668, CVE-2025-20667, CVE-2025-20665) sont classées comme Medium, couvrant des risques de divulgation d'informations, d'élévation de privilèges locaux (nécessitant des privilèges système préalables), et de contournement de permissions. Elles affectent de nombreux chipsets et versions Android.
* Publication date : 2025/05/05
* 🔗 Source : https://securityonline.info/mediatek-may-2025-security-bulletin-chipset-vulnerabilities-disclosed/, https://cvefeed.io/vuln/detail/CVE-2025-20666, https://cvefeed.io/vuln/detail/CVE-2025-20671, https://cvefeed.io/vuln/detail/CVE-2025-20670, https://cvefeed.io/vuln/detail/CVE-2025-20668, https://cvefeed.io/vuln/detail/CVE-2025-20667, https://cvefeed.io/vuln/detail/CVE-2025-20665
* 🆔 CVE : [CVE-2025-20666](https://cvefeed.io/vuln/detail/CVE-2025-20666), [CVE-2025-20671](https://cvefeed.io/vuln/detail/CVE-2025-20671), [CVE-2025-20670](https://cvefeed.io/vuln/detail/CVE-2025-20670), [CVE-2025-20668](https://cvefeed.io/vuln/detail/CVE-2025-20668), [CVE-2025-20667](https://cvefeed.io/vuln/detail/CVE-2025-20667), [CVE-2025-20665](https://cvefeed.io/vuln/detail/CVE-2025-20665)
* 💻 CVE IMPACTED PRODUCT : Chipsets MediaTek (Modem, thermal, scp, devinfo)
* ✅ Security recommandations : Mettre à jour les appareils avec les derniers logiciels fournis par les fabricants.

## Vulnérabilité Critique dans Apache Parquet Java Permettant l'Exécution de Code Arbitraire (CVE-2025-46762)
Une vulnérabilité de sécurité critique (CVE-2025-46762) a été découverte dans le module `parquet-avro` d'Apache Parquet Java, versions <= 1.15.1. Cette faille permet l'exécution de code arbitraire via des fichiers Parquet spécialement conçus contenant des schémas Avro malveillants. L'exploit est possible si le code client utilise les modèles "specific" ou "reflect" pour lire les fichiers. Bien qu'une correction partielle ait été introduite en 1.15.1 pour restreindre les packages non fiables, la liste par défaut des packages fiables restait permissive. Un score CVSS de 10.0 est associé à cette vulnérabilité. Une faille similaire (CVE-2025-30065) avait été signalée précédemment.
* Publication date : 2025/05/05
* 🔗 Source : https://cybersecuritynews.com/apache-parquet-java-vulnerability/, https://securityonline.info/cve-2025-46762-apache-parquet-java-flaw-allows-potential-rce-via-avro-schema/, https://cvefeed.io/vuln/detail/CVE-2025-46762
* 🆔 CVE : [CVE-2025-46762](https://cvefeed.io/vuln/detail/CVE-2025-46762), [CVE-2025-30065](https://cvefeed.io/vuln/detail/CVE-2025-30065)
* 💻 CVE IMPACTED PRODUCT : Apache Parquet Java (module parquet-avro)
* 💯 CVSS : 10.0
* ✅ Security recommandations : Mettre à niveau vers Apache Parquet Java 1.15.2 ou, pour les utilisateurs de 1.15.1, définir la propriété système `org.apache.parquet.avro.SERIALIZABLE_PACKAGES` sur une chaîne vide.

## Vulnérabilité Critique dans Webmin Permettant l'Élévation de Privilèges au Niveau Root (CVE-2025-2774)
Une vulnérabilité critique (CVE-2025-2774) a été identifiée dans Webmin, un outil d'administration système web populaire, affectant les versions antérieures à 2.302. Cette faille de type CRLF Injection dans la gestion des requêtes CGI permet à des attaquants distants authentifiés d'élever leurs privilèges au niveau root et d'exécuter du code arbitraire sur le serveur. La vulnérabilité a un score CVSS de 8.8. L'exploitation réussie peut entraîner un contrôle total du serveur, des modifications de configuration, l'installation de logiciels malveillants, et des accès non autorisés aux données sensibles. Cette faille s'ajoute à d'autres problèmes de sécurité antérieurs dans Webmin, notamment CVE-2024-12828.
* Publication date : 2025/05/05
* 🔗 Source : https://securityonline.info/cve-2025-2774-webmin-vulnerability-allows-root-level-privilege-escalation/, https://cybersecuritynews.com/webmin-vulnerability-escalate-privileges/, https://cvefeed.io/vuln/detail/CVE-2025-2774
* 🆔 CVE : [CVE-2025-2774](https://cvefeed.io/vuln/detail/CVE-2025-2774), [CVE-2024-12828](https://cvefeed.io/vuln/detail/CVE-2024-12828)
* 💻 CVE IMPACTED PRODUCT : Webmin
* 💯 CVSS : 8.8
* ✅ Security recommandations : Mettre à jour immédiatement vers Webmin version 2.302. Examiner les journaux système pour toute activité suspecte. Restreindre l'accès à Webmin aux réseaux de confiance et renforcer l'authentification.

## Vulnérabilité Critique d'Injection SQL dans la Bibliothèque PHP ADOdb (CVE-2025-46337)
Une faille critique d'injection SQL (CVE-2025-46337) a été divulguée dans la bibliothèque d'abstraction de base de données PHP ADOdb, spécifiquement dans la méthode `pg_insert_id()` du pilote PostgreSQL. Avec un score CVSS maximal de 10.0, cette vulnérabilité affecte les pilotes postgres64, postgres7, postgres8 et postgres9. Elle est déclenchée lorsque des entrées contrôlées par l'utilisateur sont passées au paramètre `$fieldname` sans désinfection appropriée, permettant aux attaquants d'exécuter des commandes SQL arbitraires. Dans le pire des cas, cela peut mener au vol de données, à la suppression, ou même à l'exécution de code à distance.
* Publication date : 2025/05/05
* 🔗 Source : https://securityonline.info/critical-sql-injection-vulnerability-found-in-adodb-php-library-cve-2025-46337-cvss-10-0/, https://cvefeed.io/vuln/detail/CVE-2025-46337
* 🆔 CVE : [CVE-2025-46337](https://cvefeed.io/vuln/detail/CVE-2025-46337)
* 💻 CVE IMPACTED PRODUCT : ADOdb PHP library (pilotes PostgreSQL)
* 💯 CVSS : 10.0
* ✅ Security recommandations : Mettre à niveau vers ADOdb version 5.22.9 ou ultérieure. Si la mise à niveau immédiate n'est pas possible, s'assurer que seules des données contrôlées sont passées au paramètre `$fieldname` ou les échapper avec `pg_escape_identifier()`.

## Campagne 'Operation Deceptive Prospect' de l'Acteur de Menace RomCom Ciblant le Royaume-Uni via des Portails de Feedback
Le groupe APT RomCom (également connu sous les noms Storm-0978, Tropical Scorpius, UNC2596, Void Rabisu et UAC-0180) mène une nouvelle campagne d'espionnage cybernétique appelée "Operation Deceptive Prospect". Celle-ci cible des organisations au Royaume-Uni dans les secteurs du commerce de détail, de l'hôtellerie et des infrastructures nationales critiques (CNI). La tactique employée est l'utilisation de portails de feedback client pour soumettre des e-mails de phishing convaincants, potentiellement générés par IA, qui contiennent des liens malveillux se faisant passer pour des documents sur Google Drive ou OneDrive. Ces liens mènent à une chaîne de redirection complexe pour finalement livrer des malwares, potentiellement le backdoor SnipBot (RomCom 5.0), via des exécutables Windows signés avec un certificat volé.
* Publication date : 2025/05/05
* 🔗 Source : https://securityonline.info/bridewell-uncovers-operation-deceptive-prospect-targeting-uk-organizations-via-feedback-portals/
* 🎭 Threat Actor : RomCom, Storm-0978, Tropical Scorpius, UNC2596, Void Rabisu, UAC-0180
* 🗺️ Threat Tactic : Phishing, Ingénierie Sociale, Utilisation de portails de feedback client, Liens malveillants, Chaînes de redirection, Livraison de malware
* 🎯 Threat Target : Organisations au Royaume-Uni (commerce de détail, hôtellerie, infrastructures nationales critiques - CNI)
* 🛠️ Threat Tools : SnipBot backdoor (RomCom 5.0), Exécutables Windows signés, potentiellement outils d'IA pour la génération de leurres
* ✅ Security recommandations : Sensibiliser les employés aux e-mails de phishing, même s'ils proviennent de canaux légitimes comme les portails de feedback. Vérifier la légitimité des expéditeurs et des liens, surtout si les domaines semblent légèrement décalés (ex: gdrive-share[.]online vs drive.google.com). Mettre en place des protections aux points de terminaison capables de détecter les malwares via des signatures comportementales et statiques. Mettre à jour les systèmes pour mitiger les vulnérabilités précédemment exploitées par RomCom (CVE-2023-36884, CVE-2024-9680, CVE-2024-49039).
* 🌐 DOMAIN : opn[.]to, 1dv365[.]live, gdrive-share[.]online, gcloud-drive[.]com, cloudedrive[.]com, datadrv1[.]com
* 📄 FILE_NAME : Evidence File april.exe, Medical Report scan april.exe, Attachment_Harassment evidence april.exe
* ✍️ FILE_SIGNER : GMC CONSTRUCTION AND TRADING COMPANY LIMITED

## Chaîne d'Exploitation SonicWall Expose un Risque de Détournement Admin via CVE-2023-44221 et CVE-2024-38475
Une chaîne d'exploitation a été publiée par watchTowr Labs ciblant les appliances SonicWall Secure Mobile Access (SMA). Elle combine deux vulnérabilités : CVE-2024-38475, une faille critique (CVSS 9.1) dans mod_rewrite d'Apache HTTP Server (versions <= 2.4.59) permettant un contournement d'authentification via échappement incorrect de sortie, et CVE-2023-44221, une injection de commande post-authentification dans l'interface de gestion SMA. CVE-2024-38475 permet à un attaquant non authentifié d'accéder à des pages d'administration et de potentiellement voler des tokens de session, tandis que CVE-2023-44221 permet d'exécuter des commandes arbitraires avec des privilèges admin détournés. En combinant les deux, un attaquant non authentifié peut détourner une session admin et exécuter du code. Un PoC est disponible. Les appareils affectés incluent SMA 200, 210, 400, 410, 500v. Ces deux CVEs ont été ajoutées au catalogue KEV de la CISA.
* Publication date : 2025/05/05
* 🔗 Source : https://securityonline.info/sonicwall-exploit-chain-exposes-admin-hijack-risk-via-cve-2023-44221-and-cve-2024-38475/, https://www.helpnetsecurity.com/2025/05/04/week-in-review-critical-sap-netweaver-flaw-exploited-rsac-2025-conference/, https://go.theregister.com/feed/www.theregister.com/2025/05/04/security_news_in_brief/, https://cvefeed.io/vuln/detail/CVE-2024-38475, https://cvefeed.io/vuln/detail/CVE-2023-44221
* 🆔 CVE : [CVE-2024-38475](https://cvefeed.io/vuln/detail/CVE-2024-38475), [CVE-2023-44221](https://cvefeed.io/vuln/detail/CVE-2023-44221)
* 💻 CVE IMPACTED PRODUCT : SonicWall SMA appliances (200, 210, 400, 410, 500v), Apache HTTP Server (mod_rewrite)
* 💯 CVSS : 9.1 (pour CVE-2024-38475)
* ✅ Security recommandations : Mettre à jour le firmware des appliances SonicWall SMA vers la version 10.2.1.14-75sv ou ultérieure. Appliquer les correctifs pour Apache HTTP Server versions <= 2.4.59. Les agences fédérales américaines ont jusqu'au 22 mai 2025 pour appliquer les correctifs.

## Vulnérabilité macOS Expose par Microsoft Permettant l'Évasion du Sandbox d'Application (CVE-2025-31191)
Microsoft Threat Intelligence a divulgué une vulnérabilité significative (CVE-2025-31191) dans macOS permettant de contourner l'App Sandbox sans interaction utilisateur. La faille réside dans la manière dont macOS gère les "security-scoped bookmarks", un mécanisme qui permet aux applications sandboxed d'accéder à des fichiers/dossiers avec l'autorisation de l'utilisateur. En manipulant l'entrée du trousseau `com.apple.scopedbookmarksagent.xpc`, un attaquant peut remplacer le secret de signature, créer de fausses entrées de signets sécurisés et les faire valider par `ScopedBookmarkAgent`, accordant ainsi un accès arbitraire aux fichiers et permettant l'évasion du sandbox. Apple a corrigé cette vulnérabilité dans ses mises à jour de sécurité du 31 mars 2025.
* Publication date : 2025/05/05
* 🔗 Source : https://securityonline.info/cve-2025-31191-microsoft-exposes-macos-vulnerability-allowing-app-sandbox-escape/, https://cvefeed.io/vuln/detail/CVE-2025-31191
* 🆔 CVE : [CVE-2025-31191](https://cvefeed.io/vuln/detail/CVE-2025-31191)
* 💻 CVE IMPACTED PRODUCT : macOS, Applications sandboxed utilisant des security-scoped bookmarks (incluant potentiellement Microsoft Office avec des exploits complexes)
* ✅ Security recommandations : Appliquer les mises à jour de sécurité d'Apple publiées le 31 mars 2025 ou ultérieurement.

## SocGholish Reloaded: Campagne de Loader Orientée Ransomware Découverte par Darktrace
Darktrace a documenté une campagne sophistiquée utilisant le loader JavaScript SocGholish, désormais exploité par des affiliés de ransomware (comme RansomHub) pour établir une persistance et un mouvement latéral. SocGholish est typiquement distribué via de fausses mises à jour de navigateur sur des sites web compromis, redirigeant les victimes vers des domaines Keitaro TDS qui servent les charges utiles finales. Une fois établi, il utilise des tactiques de collecte d'identifiants internes, notamment l'abus de WebDAV (pour l'authentification NTLM) et de fichiers SCF (comme Thumbs.scf) sur SMB, permettant de récolter des identifiants simplement en ouvrant un dossier partagé. Pour l'évasion du C2, il utilise le port-hopping. Cette activité précède le déploiement d'un backdoor basé sur Python par les affiliés de RansomHub.
* Publication date : 2025/05/05
* 🔗 Source : https://securityonline.info/socgholish-reloaded-darktrace-uncovers-ransomware-primed-loader-campaign/
* 🎭 Threat Actor : Affiliés de Ransomware (e.g., RansomHub)
* 🗺️ Threat Tactic : Fausse mise à jour de navigateur, Malvertising, Compromis de sites web, Collecte d'identifiants (WebDAV, SCF/SMB), Mouvement latéral, Communication C2, Port-hopping
* 🎯 Threat Target : Réseaux d'entreprise, Sites web CMS obsolètes ou mal sécurisés
* 🛠️ Threat Tools : SocGholish (loader JavaScript), Keitaro TDS (système de distribution de trafic), RansomHub (ransomware), Backdoor Python, Fichiers SCF
* 🌐 DOMAIN : packedbrick[.]com, rednosehorse[.]com, blackshelter[.]org, blacksaltys[.]com, garagebevents[.]com
* 📄 FILE_NAME : Thumbs.scf

## Groupe APT Iranien Porte Atteinte à l'Infrastructure Critique au Moyen-Orient dans une Campagne Furtive
Le FortiGuard Incident Response (FGIR) a analysé une intrusion prolongée, attribuée à un groupe APT iranien, probablement Lemon Sandstorm, ciblant les infrastructures critiques (CNI) au Moyen-Orient depuis potentiellement Mai 2021, activement depuis Mai 2023. L'accès initial a été obtenu via des identifiants compromis pour le VPN SSL. Le groupe a utilisé une panoplie d'outils, incluant des webshells (.aspx), et plusieurs familles de malwares sur mesure comme HanifNet (.NET backdoor), NeoExpressRAT (chargé via DLL side-loading), HXLibrary (module IIS), RemoteInjector (pour charger Havoc), et CredInterceptor (harvesting d'identifiants LSASS). Ils ont également modifié des fichiers JavaScript OWA légitimes (`flogon.js`) pour siphonner des identifiants. Le groupe a fait preuve d'une discipline opérationnelle notable, changeant fréquemment d'outils et d'infrastructures.
* Publication date : 2025/05/05
* 🔗 Source : https://securityonline.info/iranian-apt-group-breaches-middle-eastern-critical-infrastructure-in- stealth-campaign/
* 🎭 Threat Actor : Groupe APT Iranien (probable Lemon Sandstorm)
* 🗺️ Threat Tactic : Identifiants compromis (Accès Initial), Persistance (Webshells, Backdoors), Communication C2, Collecte d'identifiants (OWA, LSASS), Mouvement latéral, Utilisation de Proxies, Réponse d'adversaire, Phishing, Exploitation de serveurs web
* 🎯 Threat Target : Infrastructures Critiques (CNI) au Moyen-Orient (serveurs on-premise, Microsoft Exchange, réseau OT segmenté)
* 🛠️ Threat Tools : Webshells (default.aspx, UpdateChecker.aspx), HanifNet, NeoExpressRAT, HXLibrary, RemoteInjector, CredInterceptor, plink, Ngrok, ReverseSocks5, Havoc, Fichiers JavaScript OWA modifiés (flogon.js)
* 🌐 DOMAIN : encore[.]com

## Améliorations Furtives et Outils de Vol de Données pour le Malware StealC V2
La version 2 de StealC, un info-stealer et téléchargeur de malware répandu, introduit plusieurs améliorations axées sur la furtivité et le vol de données. Disponible depuis Mars 2025 (et mis à jour jusqu'à v2.2.4), cette version prend en charge la livraison de charges utiles via EXE, MSI et scripts PowerShell. La communication C2 est désormais chiffrée en RC4 avec des paramètres aléatoires pour l'évasion. Les payloads sont compilés pour 64 bits, résolvent les fonctions API dynamiquement, et incluent une routine d'auto-suppression. Une nouvelle fonctionnalité permet aux opérateurs de construire des versions personnalisées avec des règles de vol de données spécifiques et un support bot Telegram pour les alertes. La capture d'écran du bureau multi-écrans a été ajoutée. Certaines fonctionnalités comme les contrôles anti-VM et le téléchargement/exécution de DLL ont été retirées, potentiellement pour affiner le malware. StealC a été observé déployé par le loader Amadey.
* Publication date : 2025/05/04
* 🔗 Source : https://www.bleepingcomputer.com/news/security/stealc-malware-enhanced-with-stealth-upgrades-and-data-theft-tools/
* 🗺️ Threat Tactic : Vol d'informations, Téléchargement de malware, Exécution de code, Communication C2 chiffrée, Auto-suppression, Capture d'écran, Vol de cookies (Chrome App-Bound Encryption bypass)
* 🛠️ Threat Tools : StealC (v2.x), Amadey (loader)
* ✅ Security recommandations : Éviter de stocker des informations sensibles dans le navigateur. Utiliser l'authentification multi-facteurs. Ne jamais télécharger de logiciels provenant de sources douteuses ou piratées.
* 🌐 DOMAIN : booking[.]com

## Golden Chickens Déploie TerraStealerV2 pour Voler les Identifiants de Navigateur et les Données de Portefeuilles Crypto
Le groupe d'acteurs de menace Golden Chickens est associé à deux nouvelles familles de malwares : TerraStealerV2 et TerraLogger. TerraStealerV2 est spécifiquement conçu pour collecter les identifiants de navigateur, les données de portefeuilles de cryptomonnaies et les informations d'extensions de navigateur. L'existence de ces nouveaux outils suggère des efforts continus du groupe pour diversifier et affiner son arsenal. TerraLogger, quant à lui, est mentionné comme ayant une fonction différente, mais sans plus de détails dans l'extrait fourni.
* Publication date : 2025/05/05
* 🔗 Source : https://thehackernews.com/2025/05/golden-chickens-deploy-terrastealerv2.html
* 🎭 Threat Actor : Golden Chickens
* 🗺️ Threat Tactic : Vol d'informations, Vol d'identifiants, Vol de données financières
* 🎯 Threat Target : Identifiants de navigateur, Données de portefeuilles de cryptomonnaies, Informations d'extensions de navigateur
* 🛠️ Threat Tools : TerraStealerV2, TerraLogger

## Vulnérabilités Critique et Haute Signalées comme Activement Exploitées (CISA KEV)
Plusieurs vulnérabilités, notées comme critiques ou hautes, ont été ajoutées au catalogue des vulnérabilités activement exploitées connues (KEV) de la CISA, signalant leur exploitation active dans la nature :
*   CVE-2025-31324 : Vulnérabilité critique dans SAP NetWeaver Visual Composer (CVSS 10.0) qui est activement exploitée pour déployer des webshells, permettant l'exécution de code arbitraire à distance sans authentification en raison d'un contrôle d'autorisation manquant.
*   CVE-2025-42599 : Vulnérabilité de débordement de tampon basé sur la pile dans Active! Mail 6 (<= 6.60.05008561) avec un score CVSS de 9.8, également exploitée activement.
*   CVE-2025-3928 : Vulnérabilité non spécifiée dans Commvault Web Server (CVSS 8.8) permettant l'exploitation via un webshell, ajoutée au KEV de la CISA.
*   CVE-2025-1976 : Vulnérabilité d'injection de code dans Brocade FabricOS (versions 9.1.0 à 9.1.1d6) avec un score CVSS de 8.6, ajoutée au KEV de la CISA.

* Publication date : 2025/05/04
* 🔗 Source : https://go.theregister.com/feed/www.theregister.com/2025/05/04/security_news_in_brief/, https://www.helpnetsecurity.com/2025/05/04/week-in-review-critical-sap-netweaver-flaw-exploited-rsac-2025-conference/, https://cvefeed.io/vuln/detail/CVE-2025-31324, https://cvefeed.io/vuln/detail/CVE-2025-42599, https://cvefeed.io/vuln/detail/CVE-2025-3928, https://cvefeed.io/vuln/detail/CVE-2025-1976
* 🆔 CVE : [CVE-2025-31324](https://cvefeed.io/vuln/detail/CVE-2025-31324), [CVE-2025-42599](https://cvefeed.io/vuln/detail/CVE-2025-42599), [CVE-2025-3928](https://cvefeed.io/vuln/detail/CVE-2025-3928), [CVE-2025-1976](https://cvefeed.io/vuln/detail/CVE-2025-1976)
* 💻 CVE IMPACTED PRODUCT : SAP NetWeaver Visual Composer, Active! Mail 6, Commvault Web Server, Brocade FabricOS
* 💯 CVSS : 10.0 (CVE-2025-31324), 9.8 (CVE-2025-42599), 8.8 (CVE-2025-3928), 8.6 (CVE-2025-1976)
* ✅ Security recommendations : Appliquer d'urgence les correctifs pour les versions affectées de SAP NetWeaver, Active! Mail, Commvault Web Server et Brocade FabricOS. Surveiller les systèmes pour détecter les signes d'exploitation (ex: présence de webshells).

## Vulnérabilités 'AirBorne' dans le Protocole Apple AirPlay
Un ensemble de vulnérabilités, surnommées "AirBorne" par Oligo, ont été trouvées dans le protocole Apple AirPlay et le SDK AirPlay. Ces failles affectent les appareils Apple et tiers utilisant AirPlay, représentant potentiellement des milliards de dispositifs. L'exploitation peut permettre l'exécution de code à distance "zero-click", le vol de fichiers, le déni de service, et des attaques de type Man-in-the-Middle (MITM) sur n'importe quel appareil compatible AirPlay sur le même réseau. Bien qu'Apple ait publié des correctifs, de nombreux appareils tiers pourraient rester vulnérables pendant des années.
* Publication date : 2025/05/04
* 🔗 Source : https://go.theregister.com/feed/www.theregister.com/2025/05/04/security_news_in_brief/, https://www.helpnetsecurity.com/2025/05/04/week-in-review-critical-sap-netweaver-flaw-exploited-rsac-2025-conference/
* 💻 CVE IMPACTED PRODUCT : Appareils Apple et tiers utilisant AirPlay et AirPlay SDK
* 🗺️ Threat Tactic : Exécution de code à distance (zero-click), Vol de fichiers, Déni de service, Attaques MITM
* ✅ Security recommendations : Appliquer les correctifs disponibles pour les appareils Apple. Pour les appareils tiers non patchés, restreindre la communication AirPlay sur le port 7000 aux appareils de confiance, désactiver les points d'accès AirPlay non utilisés, et limiter les paramètres AirPlay aux utilisateurs actuels.

## Ancienne Backdoor Magento Exploite dans une Attaque de Chaîne d'Approvisionnement E-commerce
Sansec a détecté une nouvelle vague d'attaques ciblant une backdoor vieille de six ans affectant entre 500 et 1 000 boutiques en ligne basées sur la plateforme open source Magento. Cette backdoor a été injectée il y a six ans via une attaque de chaîne d'approvisionnement qui a infecté 21 packages provenant de trois fournisseurs (Tigren, Magesolution, Meetanshi). Tout site e-commerce ayant téléchargé un de ces packages au cours des six dernières années est potentiellement affecté. La backdoor est souvent cachée dans les fichiers `License.php` ou `LicenseApi.php`.
* Publication date : 2025/05/04
* 🔗 Source : https://go.theregister.com/feed/www.theregister.com/2025/05/04/security_news_in_brief/
* 🗺️ Threat Tactic : Attaque de chaîne d'approvisionnement, Injection de backdoor
* 🎯 Threat Target : Boutiques en ligne basées sur Magento, clients utilisant des packages de Tigren, Magesolution, Meetanshi
* 🛠️ Threat Tools : Backdoor cachée (souvent dans License.php ou LicenseApi.php)
* ✅ Security recommendations : Examiner immédiatement les systèmes utilisant des logiciels de Tigren, Magesolution ou Meetanshi pour détecter la présence de la backdoor. Effectuer des audits de sécurité réguliers sur les plugins et extensions e-commerce.

## Le FBI Publie une Liste de Domaines LabHost
Le FBI a publié un fichier CSV contenant une liste d'environ 42 000 domaines qui étaient utilisés par la plateforme de phishing-as-a-service défunte, LabHost. Cette publication vise à sensibiliser et à fournir des données historiques aux professionnels de la cybersécurité et aux experts en cybermenaces. Bien que ces domaines ne soient plus actifs, ils peuvent fournir des informations précieuses sur les tactiques et techniques utilisées par les acteurs de menace exploitant ce type de service. LabHost avait été démantelé l'année précédente, entraînant des arrestations dans le monde entier.
* Publication date : 2025/05/04
* 🔗 Source : https://go.theregister.com/feed/www.theregister.com/2025/05/04/security_news_in_brief/
* 🎭 Threat Actor : Utilisateurs de la plateforme LabHost (acteurs de phishing)
* 🗺️ Threat Tactic : Phishing-as-a-service
* 🛠️ Threat Tools : Plateforme LabHost, Domaines malveillants
* ✅ Security recommendations : Utiliser la liste publiée par le FBI pour l'analyse historique des menaces et l'amélioration des règles de détection.

