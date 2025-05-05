# ⚠️Important Vulnerabilities (CVSS > 7.5)⚠️
* 🛡️ Injection SQL Critique dans la Bibliothèque PHP ADOdb (CVE-2025-46337)
* 🛡️ Exploitation Critique de SAP NetWeaver Actuellement Observée (CVE-2025-31324)
* 🛡️ Vulnérabilité Critique de Dépassement de Tampon dans Active! Mail 6 (CVE-2025-42599)
* 🛡️ Chaîne d'Exploits SonicWall SMA (CVE-2023-44221 & CVE-2024-38475)
* 🛡️ Vulnérabilité de RCE Potentielle via Schema Avro dans Apache Parquet Java (CVE-2025-46762)
* 🛡️ Vulnérabilité d'Échappement du Sandbox macOS Révélée par Microsoft (CVE-2025-31191)
* 🛡️ Vulnérabilités 'AirBorne' dans AirPlay Permettant le RCE Zero-Click
* 🛡️ Vulnérabilités de Haute Gravité dans React Router (CVE-2025-43864 & CVE-2025-43865)
* 🛡️ Vulnérabilité d'Injection CRLF dans Webmin Permettant l'Escalade de Privilèges Root (CVE-2025-2774)
* 🛡️ Vulnérabilité Commvault Web Server ajoutée au Catalogue KEV de CISA (CVE-2025-3928)
* 🛡️ Vulnérabilité Brocade FabricOS ajoutée au Catalogue KEV de CISA (CVE-2025-1976)
* 🛡️ Vulnérabilité de Modification de Rôle BlueWave Checkmate (CVE-2025-47245)

## Table of Contents
* [Injection SQL Critique dans la Bibliothèque PHP ADOdb (CVE-2025-46337)](#injection-sql-critique-dans-la-bibliothèque-php-adodb-cve-2025-46337)
* [Exploitation Critique de SAP NetWeaver Actuellement Observée (CVE-2025-31324)](#exploitation-critique-de-sap-netweaver-actuellement-observée-cve-2025-31324)
* [Vulnérabilité Critique de Dépassement de Tampon dans Active! Mail 6 (CVE-2025-42599)](#vulnérabilité-critique-de-dépassement-de-tampon-dans-active-mail-6-cve-2025-42599)
* [Chaîne d'Exploits SonicWall SMA (CVE-2023-44221 & CVE-2024-38475)](#chaîne-dexploits-sonicwall-sma-cve-2023-44221--cve-2024-38475)
* [Vulnérabilité de RCE Potentielle via Schema Avro dans Apache Parquet Java (CVE-2025-46762)](#vulnérabilité-de-rce-potentielle-via-schema-avro-dans-apache-parquet-java-cve-2025-46762)
* [Vulnérabilité d'Échappement du Sandbox macOS Révélée par Microsoft (CVE-2025-31191)](#vulnérabilité-déchappement-du-sandbox-macos-révélée-par-microsoft-cve-2025-31191)
* [Vulnérabilités 'AirBorne' dans AirPlay Permettant le RCE Zero-Click](#vulnérabilités-airborne-dans-airplay-permettant-le-rce-zero-click)
* [Vulnérabilités de Haute Gravité dans React Router (CVE-2025-43864 & CVE-2025-43865)](#vulnérabilités-de-haute-gravité-dans-react-router-cve-2025-43864--cve-2025-43865)
* [Vulnérabilité d'Injection CRLF dans Webmin Permettant l'Escalade de Privilèges Root (CVE-2025-2774)](#vulnérabilité-dinjection-crlf-dans-webmin-permettant-lescalade-de-privilèges-root-cve-2025-2774)
* [Vulnérabilité Commvault Web Server ajoutée au Catalogue KEV de CISA (CVE-2025-3928)](#vulnérabilité-commvault-web-server-ajoutée-au-catalogue-kev-de-cisa-cve-2025-3928)
* [Vulnérabilité Brocade FabricOS ajoutée au Catalogue KEV de CISA (CVE-2025-1976)](#vulnérabilité-brocade-fabricos-ajoutée-au-catalogue-kev-de-cisa-cve-2025-1976)
* [Vulnérabilité de Modification de Rôle BlueWave Checkmate (CVE-2025-47245)](#vulnérabilité-de-modification-de-rôle-bluewave-checkmate-cve-2025-47245)
* [Campagne "Operation Deceptive Prospect" du Groupe APT RomCom](#campagne-operation-deceptive-prospect-du-groupe-apt-romcom)
* [Campagne du Loader SocGholish Reloaded Orientée Ransomware](#campagne-du-loader-socgholish-reloaded-orientée-ransomware)
* [Campagne Furtive d'un Groupe APT Iranien (Lemon Sandstorm) Ciblant les Infrastructures Critiques](#campagne-furtive-dun-groupe-apt-iranien-lemon-sandstorm-ciblant-les-infrastructures-critiques)
* [StealC Malware V2 Amélioré avec des Capacités Furtives et de Vol de Données](#stealc-malware-v2-amélioré-avec-des-capacités-furtives-et-de-vol-de-données)
* [Vulnérabilité Apache Tomcat Permettant des Attaques DoS (CVE-2025-31650)](#vulnérabilité-apache-tomcat-permettant-des-attaques-dos-cve-2025-31650)
* [Vulnérabilité d'Escalade de Privilèges dans Avast Antivirus (CVE-2025-3500)](#vulnérabilité-descalade-de-privilèges-dans-avast-antivirus-cve-2025-3500)
* [Une Backdoor Magento Vieille de Six Ans Réapparaît](#une-backdoor-magento-vieille-de-six-ans-réapparaît)
* [Résumé des Vulnérabilités Notables de la Semaine](#résumé-des-vulnérabilités-notables-de-la-semaine)

## Injection SQL Critique dans la Bibliothèque PHP ADOdb (CVE-2025-46337)
Une faille de sécurité critique a été découverte dans ADOdb, une bibliothèque d'abstraction de base de données PHP très utilisée. 🐞 La vulnérabilité, suivie sous CVE-2025-46337, se trouve dans la méthode `pg_insert_id()` du pilote PostgreSQL et permet à un attaquant d'exécuter des commandes SQL arbitraires. L'exploitation est possible lorsque des données fournies par l'utilisateur ne sont pas correctement échappées et sont passées au paramètre `$fieldname`. Cette faille a reçu le score CVSS le plus élevé, indiquant une criticité maximale. 💥
* Publication date : 2025/05/05
* Source : https://securityonline.info/critical-sql-injection-vulnerability-found-in-adodb-php-library-cve-2025-46337-cvss-10-0/
* 🔗 CVE : [CVE-2025-46337](https://cvefeed.io/vuln/detail/CVE-2025-46337)
* 💻 CVE IMPACTED PRODUCT : ADOdb PHP Library (PostgreSQL drivers: postgres64, postgres7, postgres8, postgres9), versions antérieures à 5.22.9
* 📊 CVSS : 10.0
* 📝 Security recommandations : Mettre à jour vers ADOdb version 5.22.9 ou ultérieure. Si la mise à jour immédiate est impossible, ne passez que des données contrôlées au paramètre `$fieldname` de `pg_insert_id()` ou échappez-les avec `pg_escape_identifier()` au préalable.

## Exploitation Critique de SAP NetWeaver Actuellement Observée (CVE-2025-31324)
Une vulnérabilité zero-day critique dans SAP NetWeaver Visual Composer (CVE-2025-31324) est activement exploitée. 🚨 Cette faille permet aux attaquants de télécharger des webshells en raison d'un contrôle d'autorisation manquant, conduisant à l'exécution de code non autorisée. La vulnérabilité a été ajoutée au catalogue KEV (Known Exploited Vulnerabilities) de la CISA, confirmant son exploitation dans la nature, potentiellement par des courtiers en accès initial (Initial Access Brokers). 📉
* Publication date : 2025/05/04
* Source : https://cybersecuritynews.com/cybersecurity-weekly-digest/, https://www.helpnetsecurity.com/2025/05/04/week-in-review-critical-sap-netweaver-flaw-exploited-rsac-2025-conference/, https://go.theregister.com/feed/www.theregister.com/2025/05/04/security_news_in_brief/
* 🔗 CVE : [CVE-2025-31324](https://cvefeed.io/vuln/detail/CVE-2025-31324)
* 💻 CVE IMPACTED PRODUCT : SAP NetWeaver Visual Composer
* 📊 CVSS : 10.0
* 🎭 Threat Actor : Courtiers en Accès Initial (suspecté)
* 📝 Security recommandations : Appliquer d'urgence les correctifs fournis par SAP.

## Vulnérabilité Critique de Dépassement de Tampon dans Active! Mail 6 (CVE-2025-42599)
Une vulnérabilité critique de dépassement de tampon basé sur la pile a été identifiée dans Active! Mail 6, affectant les versions 6.60.05008561 et antérieures. ⚠️ Suivie sous CVE-2025-42599 (CVSS 9.8), cette faille a été ajoutée au catalogue KEV de la CISA, indiquant son exploitation active. Un attaquant pourrait potentiellement exécuter du code arbitraire en raison de cette vulnérabilité. 📈
* Publication date : 2025/05/04
* Source : https://go.theregister.com/feed/www.theregister.com/2025/05/04/security_news_in_brief/, https://www.helpnetsecurity.com/2025/05/04/week-in-review-critical-sap-netweaver-flaw-exploited-rsac-2025-conference/
* 🔗 CVE : [CVE-2025-42599](https://cvefeed.io/vuln/detail/CVE-2025-42599)
* 💻 CVE IMPACTED PRODUCT : Active! Mail 6 versions 6.60.05008561 et antérieures
* 📊 CVSS : 9.8
* 📝 Security recommandations : Mettre à jour Active! Mail 6 vers une version corrigée.

## Chaîne d'Exploits SonicWall SMA (CVE-2023-44221 & CVE-2024-38475)
Une nouvelle chaîne d'exploits ciblant les appliances SonicWall Secure Mobile Access (SMA) a été publiée. 🔗 Elle combine deux vulnérabilités, CVE-2023-44221 et CVE-2024-38475, permettant à des attaquants distants non authentifiés de détourner des sessions d'administration et d'exécuter du code arbitraire. 🔓 CVE-2024-38475 (CVSS 9.1) est une faille d'Apache HTTP Server (mod_rewrite <= 2.4.59) permettant de contourner l'authentification, tandis que CVE-2023-44221 est une injection de commande post-authentification. La chaîne a été ajoutée au catalogue KEV de la CISA. 💣
* Publication date : 2025/05/05
* Source : https://securityonline.info/sonicwall-exploit-chain-exposes-admin-hijack-risk-via-cve-2023-44221-and-cve-2024-38475/, https://www.helpnetsecurity.com/2025/05/04/week-in-review-critical-sap-netweaver-flaw-exploited-rsac-2025-conference/
* 🔗 CVE : [CVE-2023-44221](https://cvefeed.io/vuln/detail/CVE-2023-44221), [CVE-2024-38475](https://cvefeed.io/vuln/detail/CVE-2024-38475)
* 💻 CVE IMPACTED PRODUCT : SonicWall SMA appliances (200, 210, 400, 410, 500v), Apache HTTP Server 2.4.59 et versions antérieures (dans le contexte de SMA)
* 📊 CVSS : 9.1 (pour CVE-2024-38475)
* 📝 Security recommandations : Mettre à jour le firmware de SonicWall SMA vers la version 10.2.1.14-75sv ou ultérieure.

## Vulnérabilité de RCE Potentielle via Schema Avro dans Apache Parquet Java (CVE-2025-46762)
Une faille de sécurité critique (CVE-2025-46762) a été identifiée dans le module `parquet-avro` d'Apache Parquet Java (versions <= 1.15.1). ⚠️ Cette vulnérabilité peut permettre l'exécution de code arbitraire à distance lors du traitement de schémas Avro malveillants intégrés dans les métadonnées de fichiers Parquet, si les modèles de désérialisation 'specific' ou 'reflect' sont utilisés. Elle n'est pas exploitable par défaut mais présente un risque élevé dans des configurations spécifiques. 📄
* Publication date : 2025/05/05
* Source : https://securityonline.info/cve-2025-46762-apache-parquet-java-flaw-allows-potential-rce-via-avro-schema/
* 🔗 CVE : [CVE-2025-46762](https://cvefeed.io/vuln/detail/CVE-2025-46762)
* 💻 CVE IMPACTED PRODUCT : Apache Parquet Java, module parquet-avro, versions <= 1.15.1
* 📝 Security recommandations : Mettre à jour vers Apache Parquet Java 1.15.2 ou ultérieure. Pour les utilisateurs de la version 1.15.1, définir explicitement la propriété système `org.apache.parquet.avro.SERIALIZABLE_PACKAGES=""`.

## Vulnérabilité d'Échappement du Sandbox macOS Révélée par Microsoft (CVE-2025-31191)
Microsoft Threat Intelligence a divulgué une vulnérabilité significative dans macOS (CVE-2025-31191) permettant aux attaquants de contourner le Sandbox d'Application et d'exécuter du code non autorisé. 🍎 Cette faille exploite les marque-pages à portée de sécurité et l'entrée du trousseau `com.apple.scopedbookmarksagent.xpc`, permettant à un attaquant de manipuler les entrées et d'obtenir un accès arbitraire aux fichiers sans interaction utilisateur. 🔑 Apple a publié des correctifs en mars 2025.
* Publication date : 2025/05/05
* Source : https://securityonline.info/cve-2025-31191-microsoft-exposes-macos-vulnerability-allowing-app-sandbox-escape/, https://cybersecuritynews.com/cybersecurity-weekly-digest/
* 🔗 CVE : [CVE-2025-31191](https://cvefeed.io/vuln/detail/CVE-2025-31191)
* 💻 CVE IMPACTED PRODUCT : macOS (versions affectées corrigées le 31 mars 2025), Applications sandboxed utilisant les marque-pages à portée de sécurité
* 🎭 Threat Actor : Non spécifié (découverte par Microsoft Threat Intelligence)
* 📝 Security recommandations : Appliquer les mises à jour de sécurité d'Apple publiées le 31 mars 2025.

## Vulnérabilités 'AirBorne' dans AirPlay Permettant le RCE Zero-Click
Des chercheurs ont découvert une série de vulnérabilités, nommées "AirBorne", dans le protocole AirPlay d'Apple et son SDK. ✈️ Ces failles peuvent permettre l'exécution de code à distance (RCE) sans interaction utilisateur (zero-click) sur des appareils compatibles AirPlay, y compris les appareils Apple et tiers. 📱💻 Une fois qu'un appareil infecté rejoint un réseau, l'attaque peut potentiellement se propager, impactant des milliards d'appareils. 🌍
* Publication date : 2025/05/04
* Source : https://www.helpnetsecurity.com/2025/05/04/week-in-review-critical-sap-netweaver-flaw-exploited-rsac-2025-conference/, https://cybersecuritynews.com/cybersecurity-weekly-digest/
* 💻 CVE IMPACTED PRODUCT : Appareils Apple et tiers utilisant le protocole AirPlay, AirPlay SDK, CarPlay Communication Plug-in
* 📝 Security recommandations : Appliquer les correctifs Apple disponibles. Restreindre les communications AirPlay sur le port 7000 aux appareils de confiance. Désactiver les points d'extrémité AirPlay inutilisés. Restreindre les paramètres AirPlay aux utilisateurs actuels uniquement.
* 🔑 Indicators of Compromise :
    * PORT : 7000

## Vulnérabilités de Haute Gravité dans React Router (CVE-2025-43864 & CVE-2025-43865)
Deux vulnérabilités de haute gravité ont été signalées dans la bibliothèque JavaScript React Router. ⚛️ Suivies sous CVE-2025-43864 et CVE-2025-43865, ces failles peuvent permettre à des attaquants de corrompre le contenu, d'empoisonner les caches et d'usurper des données pré-rendues dans les applications utilisant le rendu côté serveur. 🖼️ L'exploitation ne nécessite ni privilèges ni interaction utilisateur.
* Publication date : 2025/05/04
* Source : https://cybersecuritynews.com/cybersecurity-weekly-digest/
* 🔗 CVE : [CVE-2025-43864](https://nvd.nist.gov/vuln/detail/CVE-2025-43864), [CVE-2025-43865](https://nvd.nist.gov/vuln/detail/CVE-2025-43865)
* 💻 CVE IMPACTED PRODUCT : React Router, versions antérieures à 7.5.2
* 📝 Security recommandations : Mettre à jour immédiatement vers React Router version 7.5.2.

## Vulnérabilité d'Injection CRLF dans Webmin Permettant l'Escalade de Privilèges Root (CVE-2025-2774)
Une vulnérabilité critique (CVE-2025-2774) a été découverte dans Webmin, un outil d'administration système basé sur le web largement utilisé. 🛠️ Affectant les versions antérieures à 2.302, cette faille d'injection CRLF dans la gestion des requêtes CGI permet à un attaquant authentifié d'escalader ses privilèges au niveau root et d'exécuter du code arbitraire. 😈 Le score CVSS de 8.8 souligne sa gravité élevée.
* Publication date : 2025/05/05
* Source : https://securityonline.info/cve-2025-2774-webmin-vulnerability-allows-root-level-privilege-escalation/, https://cybersecuritynews.com/webmin-vulnerability-escalate-privileges/
* 🔗 CVE : [CVE-2025-2774](https://nvd.nist.gov/vuln/detail/CVE-2025-2774)
* 💻 CVE IMPACTED PRODUCT : Webmin versions antérieures à 2.302
* 📊 CVSS : 8.8
* 📝 Security recommandations : Mettre à jour immédiatement Webmin vers la version 2.302. Examiner les journaux système. Restreindre l'accès à Webmin aux réseaux de confiance et appliquer une authentification forte. Appliquer le principe du moindre privilège.

## Vulnérabilité Commvault Web Server ajoutée au Catalogue KEV de CISA (CVE-2025-3928)
Une vulnérabilité non spécifiée (CVE-2025-3928) affectant Commvault Web Server a été ajoutée par la CISA à son catalogue des vulnérabilités connues exploitées (KEV). 📄 Cette faille, avec un score CVSS de 8.8, permet à un acteur malveillant d'exploiter les systèmes affectés via un webshell. 🕸️ Son inclusion dans le KEV souligne qu'elle est activement utilisée dans des attaques réelles.
* Publication date : 2025/05/04
* Source : https://go.theregister.com/feed/www.theregister.com/2025/05/04/security_news_in_brief/, https://www.helpnetsecurity.com/2025/05/04/week-in-review-critical-sap-netweaver-flaw-exploited-rsac-2025-conference/
* 🔗 CVE : [CVE-2025-3928](https://cvefeed.io/vuln/detail/CVE-2025-3928)
* 💻 CVE IMPACTED PRODUCT : Commvault Web Server
* 📊 CVSS : 8.8
* 📝 Security recommandations : Appliquer les correctifs fournis par le fournisseur. Les agences fédérales américaines sont tenues de patcher avant le 22 mai 2025 (exigence CISA KEV).

## Vulnérabilité Brocade FabricOS ajoutée au Catalogue KEV de CISA (CVE-2025-1976)
Une vulnérabilité d'injection de code (CVE-2025-1976) dans Brocade FabricOS (versions 9.1.0 à 9.1.1d6) a été ajoutée au catalogue KEV de la CISA. 📄 Avec un score CVSS de 8.6, cette faille est due à la suppression de l'accès root sans restrictions appropriées pour les utilisateurs locaux disposant de privilèges d'administration. Son exploitation dans la nature a été confirmée par la CISA. 📉
* Publication date : 2025/05/04
* Source : https://go.theregister.com/feed/www.theregister.com/2025/05/04/security_news_in_brief/, https://www.helpnetsecurity.com/2025/05/04/week-in-review-critical-sap-netweaver-flaw-exploited-rsac-2025-conference/
* 🔗 CVE : [CVE-2025-1976](https://cvefeed.io/vuln/detail/CVE-2025-1976)
* 💻 CVE IMPACTED PRODUCT : Brocade FabricOS versions 9.1.0 à 9.1.1d6
* 📊 CVSS : 8.6
* 📝 Security recommandations : Appliquer les correctifs fournis par le fournisseur. Les agences fédérales américaines sont tenues de patcher avant le 22 mai 2025 (exigence CISA KEV).

## Vulnérabilité de Modification de Rôle BlueWave Checkmate (CVE-2025-47245)
Une vulnérabilité (CVE-2025-47245) a été découverte dans BlueWave Checkmate (versions jusqu'à 2.0.2 avant le commit d4a6072). 🛡️ Cette faille, d'une gravité ÉLEVÉE (CVSS 8.1), permet la modification d'une requête d'invitation pour spécifier un rôle privilégié, conduisant à une escalade de privilèges. L'exploitation est possible à distance avec une complexité faible. 🔓
* Publication date : 2025/05/04
* Source : https://cvefeed.io/vuln/detail/CVE-2025-47245
* 🔗 CVE : [CVE-2025-47245](https://cvefeed.io/vuln/detail/CVE-2025-47245)
* 💻 CVE IMPACTED PRODUCT : BlueWave Checkmate versions jusqu'à 2.0.2 avant le commit d4a6072
* 📊 CVSS : 8.1
* 📝 Security recommandations : Mettre à jour vers la version de BlueWave Checkmate incluant le commit d4a6072 ou ultérieure.
* 🔑 Indicators of Compromise :
    * FILE_HASH_SHA1 : d4a60723f490502b3fe6f7f780a85d29bf5d1385
    * URL : hxxps[:]//github[.]com/bluewave-labs/Checkmate/commit/d4a60723f490502b3fe6f7f780a85d29bf5d1385
    * URL : hxxps[:]//github[.]com/bluewave-labs/Checkmate/pull/2160
    * URL : hxxps[:]//github[.]com/bluewave-labs/Checkmate/security/advisories/GHSA-7x3q-g6gq-f4mm

## Campagne "Operation Deceptive Prospect" du Groupe APT RomCom
Le groupe de cybermenace RomCom (alias Storm-0978, Tropical Scorpius, UNC2596, Void Rabisu, UAC-0180) a lancé une nouvelle campagne d'espionnage cybernétique, nommée "Operation Deceptive Prospect". 🕵️ Ciblant les organisations britanniques des secteurs de la vente au détail, de l'hôtellerie et des infrastructures critiques (CNI), la campagne utilise une approche novatrice en exploitant les portails de commentaires clients comme vecteur d'attaque. 📧 RomCom soumet de fausses plaintes par e-mail, utilisant de fausses adresses Yahoo, contenant des liens vers de faux services de stockage cloud (Google Drive, OneDrive) hébergeant des malwares (.exe déguisés en PDF). Le malware final est signé avec un certificat probablement volé ou compromis. La campagne utilise des techniques de social engineering, des redirections multi-étapes et le toolset SnipBot. 🤖
* Publication date : 2025/05/05
* Source : https://securityonline.info/bridewell-uncovers-operation-deceptive-prospect-targeting-uk-organizations-via-feedback-portals/
* 🎭 Threat Actor : RomCom (Storm-0978, Tropical Scorpius, UNC2596, Void Rabisu, UAC-0180)
* 🗺️ Threat Tactic : Phishing (via portails de commentaires), Ingénierie Sociale, Redirections Malveillantes, Livraison de Malware, Compromission de la Chaîne d'Approvisionnement (certificat), Exploitation de Vulnérabilités (CVE-2023-36884, CVE-2024-9680, CVE-2024-49039 - historiques)
* 🎯 Threat Target : Organisations britanniques des secteurs de la vente au détail, de l'hôtellerie et des Infrastructures Nationales Critiques (CNI)
* 🛠️ Threat Tools : SnipBot (RomCom 5.0), Exécutables personnalisés, potentiellement des outils d'IA (pour la rédaction d'e-mails)
* 🔑 Indicators of Compromise :
    * DOMAIN : gdrive-share[.]online
    * DOMAIN : 1dv365[.]live
    * DOMAIN : gcloud-drive[.]com
    * DOMAIN : cloudedrive[.]com
    * DOMAIN : datadrv1[.]com
    * DOMAIN : opn[.]to

## Campagne du Loader SocGholish Reloaded Orientée Ransomware
SocGholish, un loader JavaScript actif depuis 2017, est désormais utilisé par des affiliés de ransomware, notamment RansomHub. 🌐 Une récente campagne détaillée par Darktrace montre comment SocGholish est utilisé pour l'accès initial, la persistance et le mouvement latéral, menant finalement au déploiement de ransomware. 💼 L'infection commence souvent par de fausses mises à jour de navigateur sur des sites web compromis, redirigeant vers des systèmes de distribution de trafic (Keitaro TDS) qui livrent le payload. 👾 Une fois à l'intérieur, SocGholish utilise des techniques de récolte de credentials (abus de WebDAV et de fichiers SCF) et communique avec son C2 en utilisant du port-hopping pour l'évasion. 💾
* Publication date : 2025/05/05
* Source : https://securityonline.info/socgholish-reloaded-darktrace-uncovers-ransomware-primed-loader-campaign/, https://cybersecuritynews.com/cybersecurity-weekly-digest/
* 🎭 Threat Actor : Opérateurs de SocGholish, Affiliés de RansomHub
* 🗺️ Threat Tactic : Malvertising, Fausse Mise à Jour de Navigateur, Loader, Récolte de Credentials (WebDAV, Fichiers SCF), Mouvement Latéral, Communication C2 (Port-hopping), Déploiement de Ransomware
* 🎯 Threat Target : Réseaux d'entreprise, utilisateurs visitant des sites web compromis
* 🛠️ Threat Tools : SocGholish (JavaScript loader), Keitaro TDS, Backdoor Python, RansomHub, Fichiers SCF
* 🔑 Indicators of Compromise :
    * DOMAIN : garagebevents[.]com
    * DOMAIN : packedbrick[.]com
    * DOMAIN : rednosehorse[.]com
    * DOMAIN : blackshelter[.]org
    * DOMAIN : blacksaltys[.]com
    * PORT : 443
    * PORT : 2308
    * PORT : 2311
    * PORT : 2313

## Campagne Furtive d'un Groupe APT Iranien (Lemon Sandstorm) Ciblant les Infrastructures Critiques
FortiGuard Incident Response a analysé une intrusion prolongée d'un groupe APT iranien, probablement Lemon Sandstorm, dans les Infrastructures Nationales Critiques (CNI) au Moyen-Orient. 🏭 L'attaque, active depuis mai 2023 (potentiellement mai 2021), a utilisé des credentials compromis pour accéder au VPN SSL, déployant des webshells et des backdoors personnalisées (HanifNet, NeoExpressRAT, HXLibrary, etc.).  stealth Le groupe a fait preuve d'une discipline opérationnelle élevée, changeant fréquemment d'outils et d'infrastructure, et a utilisé diverses techniques (proxy chaining, harvest de credentials via JS OWA modifié). 🌐 Ils ont établi un pied-à-terre dans le réseau OT segmenté.
* Publication date : 2025/05/05
* Source : https://securityonline.info/iranian-apt-group-breaches-middle-eastern-critical-infrastructure-in-stealth-campaign/
* 🎭 Threat Actor : Groupe Iranien Soutenu par l'État, Probablement Lemon Sandstorm
* 🗺️ Threat Tactic : Credentials Compromis, Accès VPN SSL, Déploiement de Webshells, Backdoors Personnalisées, Proxy Chaining, Récolte de Credentials (Hooking LSASS, Modification JS OWA), Phishing (tentative de ré-entrée), Exploitation de Serveurs Web (tentative de ré-entrée), Mouvement Latéral
* 🎯 Threat Target : Infrastructures Nationales Critiques (CNI) au Moyen-Orient, y compris serveurs on-premise, Microsoft Exchange, réseau OT segmenté.
* 🛠️ Threat Tools : HanifNet (.NET backdoor), NeoExpressRAT (RAT), HXLibrary (module IIS), RemoteInjector (loader pour Havoc), CredInterceptor (harvester de mots de passe), SystemBC, Webshells (.aspx), plink, Ngrok, ReverseSocks5, MeshCentral, JavaScript OWA modifié (`flogon.js`)
* 📝 Security recommandations : Donner la priorité aux défenses contre les méthodes d'attaque courantes (credentials compromis, patching). Surveiller l'activité réseau. Sécuriser les VPN SSL. Surveiller les serveurs web. Mettre en œuvre une authentification forte. Segmenter les réseaux.
* 🔑 Indicators of Compromise :
    * DOMAIN : format[.]com
    * DOMAIN : u2018encore[.]com

## StealC Malware V2 Amélioré avec des Capacités Furtives et de Vol de Données
Les créateurs de StealC, un infostealer et downloader de malware très répandu, ont lancé sa deuxième version majeure (v2), avec des améliorations significatives en matière de furtivité et de vol de données. 🕵️ Lancée en mars 2025 (v2.2.4 est la dernière), cette version prend en charge de nouvelles méthodes de livraison (EXE, MSI, PowerShell), utilise le chiffrement RC4 pour les communications C2 et les chaînes de code, et inclut des paramètres aléatoires pour une meilleure évasion. 🛠️ StealC v2 inclut un builder intégré, la prise en charge des alertes par bot Telegram et la capture d'écran du bureau. 📸 Il a été observé délivré par le loader Amadey dans des attaques récentes. 👾
* Publication date : 2025/05/04
* Source : https://www.bleepingcomputer.com/news/security/stealc-malware-enhanced-with-stealth-upgrades-and-data-theft-tools/
* 🎭 Threat Actor : Créateurs de StealC (Malware-as-a-Service), Opérateurs utilisant le loader Amadey
* 🗺️ Threat Tactic : Vol d'Informations, Téléchargement de Malware, Evasion, Malvertising (historique), Attaques Kiosk Mode (historique), Bypass de Défenses (ex: Chrome Cookie Encryption)
* 🛠️ Threat Tools : StealC (versions 2.x), Amadey (loader), RC4 (chiffrement), Bot Telegram
* 📝 Security recommandations : Éviter de stocker des informations sensibles dans les navigateurs. Utiliser l'authentification multi-facteurs (MFA). Ne jamais télécharger de logiciels piratés ou provenant de sources obscures.
* 🔑 Indicators of Compromise :
    * DOMAIN : booking[.]com (Mentionné dans un article connexe, potentiellement lié au malvertising passé)

## Vulnérabilité Apache Tomcat Permettant des Attaques DoS (CVE-2025-31650)
Une vulnérabilité (CVE-2025-31650) a été découverte dans Apache Tomcat, affectant les versions 9.0.76–9.0.102, 10.1.10–10.1.39 et 11.0.0-M2–11.0.5. 💥 Cette faille permet à un attaquant de contourner les règles de sécurité et de déclencher une condition de déni de service (DoS) en envoyant des en-têtes HTTP priority malformés. L'exploitation peut entraîner des fuites de mémoire et des plantages du serveur. 📉
* Publication date : 2025/05/04
* Source : https://cybersecuritynews.com/cybersecurity-weekly-digest/
* 🔗 CVE : [CVE-2025-31650](https://nvd.nist.gov/vuln/detail/CVE-2025-31650)
* 💻 CVE IMPACTED PRODUCT : Apache Tomcat versions 9.0.76–9.0.102, 10.1.10–10.1.39, and 11.0.0-M2–11.0.5
* 📝 Security recommandations : Mettre à jour vers la dernière version d'Apache Tomcat (9.0.103+, 10.1.40+, 11.0.6+).

## Vulnérabilité d'Escalade de Privilèges dans Avast Antivirus (CVE-2025-3500)
Une vulnérabilité d'escalade de privilèges (CVE-2025-3500) a été signalée dans Avast Free Antivirus. 🛡️ Cette faille, située dans le pilote noyau `aswbidsdriver`, permet à un attaquant local d'obtenir des privilèges au niveau du noyau. 🔓 Le correctif a été publié dans la version 25.3.9983.922.
* Publication date : 2025/05/04
* Source : https://cybersecuritynews.com/cybersecurity-weekly-digest/
* 🔗 CVE : [CVE-2025-3500](https://nvd.nist.gov/vuln/detail/CVE-2025-3500)
* 💻 CVE IMPACTED PRODUCT : Avast Free Antivirus versions antérieures à 25.3.9983.922
* 📝 Security recommandations : Mettre à jour immédiatement Avast Free Antivirus vers la version 25.3.9983.922 ou ultérieure.

## Une Backdoor Magento Vieille de Six Ans Réapparaît
Une nouvelle vague d'attaques cible une backdoor vieille de six ans affectant des packages de commerce électronique populaires basés sur la plateforme open source Magento. 🛒 Entre 500 et 1000 boutiques en ligne pourraient être concernées. Cette backdoor, résultant d'une attaque de la chaîne d'approvisionnement il y a six ans, se cache dans les fichiers `License.php` ou `LicenseApi.php` de 21 packages provenant des fournisseurs Tigren, Magesolution et Meetanshi. 🕵️ Une multinationale valorisée à 40 milliards de dollars aurait été victime.
* Publication date : 2025/05/04
* Source : https://go.theregister.com/feed/www.theregister.com/2025/05/04/security_news_in_brief/
* 🗺️ Threat Tactic : Attaque de la Chaîne d'Approvisionnement (historique), Backdoor
* 🎯 Threat Target : Boutiques en ligne utilisant des packages affectés de Tigren, Magesolution, Meetanshi sur la plateforme Magento
* 🔑 Indicators of Compromise :
    * FILE_PATH : License.php
    * FILE_PATH : LicenseApi.php

## Résumé des Vulnérabilités Notables de la Semaine
Un bulletin hebdomadaire résume les principales attaques et vulnérabilités découvertes la semaine dernière. 📄 Il mentionne l'exploitation active d'une faille critique dans SAP NetWeaver (CVE-2025-31324), des vulnérabilités de haute gravité dans React Router (CVE-2025-43864, CVE-2025-43865), une faille DoS dans Apache Tomcat (CVE-2025-31650), une escalade de privilèges dans Avast Antivirus (CVE-2025-3500), et une vulnérabilité d'échappement du sandbox macOS (CVE-2025-31191). 📊 De plus, il souligne les 75 zero-days exploités en 2024 selon Google Threat Intelligence, ainsi que les vulnérabilités AirPlay permettant le RCE zero-click. 📰
* Publication date : 2025/05/04
* Source : https://cybersecuritynews.com/cybersecurity-weekly-digest/, https://www.helpnetsecurity.com/2025/05/04/week-in-review-critical-sap-netweaver-flaw-exploited-rsac-2025-conference/, https://go.theregister.com/feed/www.theregister.com/2025/05/04/security_news_in_brief/
* 🔗 CVE : [CVE-2025-31324](https://cvefeed.io/vuln/detail/CVE-2025-31324), [CVE-2025-43864](https://nvd.nist.gov/vuln/detail/CVE-2025-43864), [CVE-2025-43865](https://nvd.nist.gov/vuln/detail/CVE-2025-43865), [CVE-2025-31650](https://nvd.nist.gov/vuln/detail/CVE-2025-31650), [CVE-2025-3500](https://nvd.nist.gov/vuln/detail/CVE-2025-3500), [CVE-2025-31191](https://cvefeed.io/vuln/detail/CVE-2025-31191), [CVE-2025-3928](https://cvefeed.io/vuln/detail/CVE-2025-3928), [CVE-2025-42599](https://cvefeed.io/vuln/detail/CVE-2025-42599), [CVE-2025-1976](https://cvefeed.io/vuln/detail/CVE-2025-1976), [CVE-2024-38475](https://cvefeed.io/vuln/detail/CVE-2024-38475)
* 💻 CVE IMPACTED PRODUCT : SAP NetWeaver Visual Composer, React Router (versions antérieures à 7.5.2), Apache Tomcat (versions 9.0.76–11.0.5), Avast Free Antivirus (versions antérieures à 25.3.9983.922), macOS, Commvault Web Server, Active! Mail 6 (versions antérieures à 6.60.05008561), Brocade FabricOS (versions 9.1.0-9.1.1d6), Apache HTTP Server (dans le contexte de SonicWall SMA), Appareils compatibles AirPlay.
* 🎭 Threat Actor : Divers (SocGholish, APTs Asiatiques, Lazarus, APT37, RansomHub, Gremlin Stealer, Konni APT, MintsLoader, GhostWeaver, Opérateurs de backdoor Magento)
* 🗺️ Threat Tactic : Divers (Malvertising, Phishing, Fausse Mise à Jour, Loader, Ransomware, Vol d'Informations, Attaques ciblées, Exploitation de Vulnérabilités connues/zero-day, Attaques DoS, Escalade de Privilèges, Backdoor, Attaques de la Chaîne d'Approvisionnement)
* 🎯 Threat Target : Divers (Sites web, Entreprises, Infrastructures Critiques, Utilisateurs, Secteur Financier, Santé, Utilisateurs WordPress, Systèmes Windows, Systèmes macOS, Serveurs Unix-like, Appareils compatibles AirPlay)
* 🛠️ Threat Tools : Divers (SocGholish, Ransomware, Gremlin Stealer, Backdoors, Loaders, Webshells, Tools d'harvester de credentials)
* 📝 Security recommandations : Rester informé, appliquer les correctifs rapidement, renforcer la sécurité (MFA, principe du moindre privilège, segmentation réseau), éduquer les utilisateurs, surveiller les systèmes, adopter des pratiques de sécurité robustes (Zero Trust).