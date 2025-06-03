# ⚠️Important Vulnerabilities (CVSS > 8)⚠️
* 🐞 Vulnérabilités critiques dans Google Chrome activement exploitées
* 🐞 Vulnérabilité critique dans les processeurs Samsung Exynos
* 🐞 Vulnérabilité importante dans les enceintes Sonos Era 300
* 🐞 Vulnérabilité critique dans DELMIA Apriso
* 🐞 Vulnérabilité importante dans Splunk Universal Forwarder pour Windows
* 🐞 Vulnérabilité importante dans Catdoc
* 🐞 Vulnérabilité critique dans les appareils Instantel Micromate
* 🐞 Vulnérabilité critique dans Cisco IOS XE WLC

## Table of Contents
* [Vulnerabilities](#vulnerabilities)
    * [Vulnérabilités critiques dans Google Chrome activement exploitées](#vulnérabilités-critiques-dans-google-chrome-activement-exploitées)
    * [Vulnérabilité critique dans les processeurs Samsung Exynos](#vulnérabilité-critique-dans-les-processeurs-samsung-exynos)
    * [Vulnérabilité importante dans les enceintes Sonos Era 300](#vulnérabilité-importante-dans-les-enceintes-sonos-era-300)
    * [Vulnérabilité critique dans DELMIA Apriso](#vulnérabilité-critique-dans-delmia-apriso)
    * [Vulnérabilité importante dans Splunk Universal Forwarder pour Windows](#vulnérabilité-importante-dans-splunk-universal-forwarder-pour-windows)
    * [Vulnérabilité importante dans Catdoc](#vulnérabilité-importante-dans-catdoc)
    * [Vulnérabilité critique dans les appareils Instantel Micromate](#vulnérabilité-critique-dans-les-appareils-instantel-micromate)
    * [Vulnérabilité critique dans Cisco IOS XE WLC](#vulnérabilité-critique-dans-cisco-ios-xe-wlc)
* [Threats](#threats)
    * [Violations de données dans le secteur de la distribution (Cartier, The North Face)](#violations-de-données-dans-le-secteur-de-la-distribution-cartier-the-north-face)
    * [Le "Russian Market" devient une plateforme majeure pour les identifiants volés](#le-russian-market-devient-une-plateforme-majeure-pour-les-identifiants-volés)
    * [Démantèlement de services de contournement d'antivirus (CAV)](#démantèlement-de-services-de-contournement-dantivirus-cav)
    * [Cyberattaque contre les hôpitaux de Covenant Health](#cyberattaque-contre-les-hôpitaux-de-covenant-health)
    * [Exploitation d'une chaîne de vulnérabilités dans les routeurs FiberGateway](#exploitation-dune-chaîne-de-vulnérabilités-dans-les-routeurs-fibergateway)
    * [Le CISA ajoute des vulnérabilités activement exploitées à son catalogue KEV](#le-cisa-ajoute-des-vulnérabilités-activement-exploitées-à-son-catalogue-kev)

## Category : Vulnerabilities
### Vulnérabilités critiques dans Google Chrome activement exploitées {#vulnérabilités-critiques-dans-google-chrome-activement-exploitées}
Plusieurs vulnérabilités, dont une zero-day activement exploitée, ont été corrigées dans Google Chrome version 137.0.7151.68/.69. La vulnérabilité zero-day (CVE-2025-5419), de haute gravité, est une lecture/écriture hors limites dans le moteur V8, permettant une corruption de la mémoire heap potentiellement exploitable via une page HTML malveillante. Google a confirmé son exploitation active dans la nature et a déployé des mesures d'atténuation d'urgence avant le patch complet. Une autre vulnérabilité (CVE-2025-5068), une utilisation après libération dans Blink, a également été corrigée.
* Publication date : 2025/06/02
* 📰 Sources : hxxps[:]//cvefeed[.]io/vuln/detail/CVE-2025-5419, hxxps[:]//cvefeed[.]io/vuln/detail/CVE-2025-5068, hxxps[:]//cybersecuritynews[.]com/chrome-0-day-vulnerability-exploited-in-the-wild/, hxxps[:]//securityonline[.]info/chrome-zero-day-alert-cve-2025-5419-actively-exploited-in-the-wild/
* 🐞 CVE : [CVE-2025-5419](https://nvd.nist.gov/vuln/detail/CVE-2025-5419), [CVE-2025-5068](https://nvd.nist.gov/vuln/detail/CVE-2025-5068)
* 💻 CVE Impacted Product : Google Chrome < 137.0.7151.68/.69 (Windows, Mac, Linux)
* 📈 CVSS : 8.8
* 👨‍💻 Threat Actor : Inconnu (potentiellement acteurs étatiques selon securityonline.info)
* 💥 Threat Tactic : Exploitation de vulnérabilité (zero-day)
* 🛡️ Security recommandations : Mettre à jour Google Chrome vers la version 137.0.7151.68 ou supérieure immédiatement. Pour les entreprises, prioriser ce patch.

### Vulnérabilité critique dans les processeurs Samsung Exynos {#vulnérabilité-critique-dans-les-processeurs-samsung-exynos}
Une vulnérabilité critique a été découverte dans les processeurs mobiles Samsung Exynos 1480 et 2400. Un manque de vérification de longueur dans le traitement des données conduit à des écritures hors limites.
* Publication date : 2025/06/02
* 📰 Source : hxxps[:]//cvefeed[.]io/vuln/detail/CVE-2025-23099
* 🐞 CVE : [CVE-2025-23099](https://nvd.nist.gov/vuln/detail/CVE-2025-23099)
* 💻 CVE Impacted Product : Samsung Mobile Processor Exynos 1480, Samsung Mobile Processor Exynos 2400
* 📈 CVSS : 9.1
* 🛡️ Security recommandations : Appliquer les mises à jour fournies par Samsung dès qu'elles sont disponibles.

### Vulnérabilité importante dans les enceintes Sonos Era 300 {#vulnérabilité-importante-dans-les-enceintes-sonos-era-300}
Une vulnérabilité de débordement de tampon basé sur le heap a été découverte dans les enceintes Sonos Era 300. Elle permet à des attaquants adjacents au réseau d'exécuter du code arbitraire sans authentification. Le défaut réside dans le traitement des données ALAC, dû à un manque de validation de la longueur des données fournies par l'utilisateur avant de les copier dans un tampon sur le heap. L'exploitation permet l'exécution de code dans le contexte de l'utilisateur 'anacapa'.
* Publication date : 2025/06/02
* 📰 Source : hxxps[:]//cvefeed[.]io/vuln/detail/CVE-2025-1051
* 🐞 CVE : [CVE-2025-1051](https://nvd.nist.gov/vuln/detail/CVE-2025-1051)
* 💻 CVE Impacted Product : Sonos Era 300
* 📈 CVSS : 8.8
* 🛡️ Security recommandations : Appliquer les mises à jour logicielles de Sonos dès qu'elles sont disponibles. Isoler les appareils sur un réseau séparé si possible.

### Vulnérabilité critique dans DELMIA Apriso {#vulnérabilité-critique-dans-delmia-apriso}
Une vulnérabilité de désérialisation de données non fiables affectant DELMIA Apriso (Release 2020 à Release 2025) pourrait mener à une exécution de code arbitraire à distance.
* Publication date : 2025/06/02
* 📰 Source : hxxps[:]//cvefeed[.]io/vuln/detail/CVE-2025-5086
* 🐞 CVE : [CVE-2025-5086](https://nvd.nist.gov/vuln/detail/CVE-2025-5086)
* 💻 CVE Impacted Product : DELMIA Apriso Release 2020, DELMIA Apriso Release 2021, DELMIA Apriso Release 2022, DELMIA Apriso Release 2023, DELMIA Apriso Release 2024, DELMIA Apriso Release 2025
* 📈 CVSS : 10.0
* 🛡️ Security recommandations : Appliquer les correctifs ou mises à jour du fournisseur dès que possible.

### Vulnérabilité importante dans Splunk Universal Forwarder pour Windows {#vulnérabilité-importante-dans-splunk-universal-forwarder-pour-windows}
Dans les versions de Splunk Universal Forwarder pour Windows antérieures à 9.4.2, 9.3.4, 9.2.6 et 9.1.9, une nouvelle installation ou une mise à niveau vers une version affectée peut entraîner une attribution de permissions incorrecte dans le répertoire d'installation. Cela permet aux utilisateurs non-administrateurs d'accéder au répertoire et à son contenu, conduisant à une escalade de privilèges.
* Publication date : 2025/06/02
* 📰 Source : hxxps[:]//cvefeed[.]io/vuln/detail/CVE-2025-20298
* 🐞 CVE : [CVE-2025-20298](https://nvd.nist.gov/vuln/detail/CVE-2025-20298)
* 💻 CVE Impacted Product : Splunk Universal Forwarder for Windows < 9.4.2, 9.3.4, 9.2.6, 9.1.9
* 📈 CVSS : 8.0
* 🛡️ Security recommandations : Mettre à jour Splunk Universal Forwarder pour Windows vers une version corrigée (9.4.2+, 9.3.4+, 9.2.6+, 9.1.9+).

### Vulnérabilité importante dans Catdoc {#vulnérabilité-importante-dans-catdoc}
Une vulnérabilité de dépassement d'entier existe dans la fonctionnalité du parseur OLE Document DIFAT de catdoc 0.95. Un fichier malformé spécialement conçu peut entraîner une corruption de la mémoire heap. Un attaquant peut fournir un fichier malveillant pour déclencher cette vulnérabilité.
* Publication date : 2025/06/02
* 📰 Source : hxxps[:]//cvefeed[.]io/vuln/detail/CVE-2024-54028
* 🐞 CVE : [CVE-2024-54028](https://nvd.nist.gov/vuln/detail/CVE-2024-54028)
* 💻 CVE Impacted Product : catdoc 0.95
* 📈 CVSS : 8.4
* 🛡️ Security recommandations : Mettre à jour catdoc vers une version corrigée. Être prudent avec les fichiers provenant de sources non fiables.

### Vulnérabilité critique dans les appareils Instantel Micromate {#vulnérabilité-critique-dans-les-appareils-instantel-micromate}
Le CISA a émis un avis concernant une vulnérabilité critique affectant toutes les versions d'Instantel Micromate, un appareil de surveillance des vibrations et du bruit. Le défaut (CVE-2025-1907, CVSS 9.8) est une absence de mécanisme d'authentification sur le port de configuration, permettant à un attaquant non authentifié d'accéder et d'exécuter des commandes si un accès réseau au port est possible. Cela pourrait permettre la manipulation de l'appareil, l'altération de données et l'utilisation de l'appareil comme point de pivot.
* Publication date : 2025/06/03
* 📰 Sources : hxxps[:]//securityonline[.]info/cisa-warns-of-critical-unauthenticated-access-vulnerability-in-instantel-micromate-devices/, hxxps[:]//microsec[.]io
* 🐞 CVE : [CVE-2025-1907](https://nvd.nist.gov/vuln/detail/CVE-2025-1907)
* 💻 CVE Impacted Product : Instantel Micromate (toutes versions)
* 📈 CVSS : 9.8
* 🛡️ Security recommandations : Isoler l'appareil sur un réseau protégé ou un VLAN séparé, et restreindre l'accès réseau au port de configuration. Surveiller les mises à jour firmware du fournisseur pour un correctif.

### Vulnérabilité critique dans Cisco IOS XE WLC {#vulnérabilité-critique-dans-cisco-ios-xe-wlc}
Des détails techniques sur une vulnérabilité critique (CVE-2025-20188, CVSS 10.0) dans Cisco IOS XE WLC ont été rendus publics, augmentant le risque d'exploitation. La vulnérabilité est due à un JWT codé en dur et une validation de chemin faible dans la fonction Out-of-Band Access Point (AP) Image Download. Cela permet à un attaquant distant non authentifié de télécharger des fichiers arbitraires, d'effectuer du path traversal et d'exécuter des commandes avec les privilèges root.
* Publication date : 2025/06/02
* 📰 Source : hxxps[:]//securityaffairs[.]com/178497/security/cisco-ios-xe-wlc-flaw-cve-2025-20188.html
* 🐞 CVE : [CVE-2025-20188](https://nvd.nist.gov/vuln/detail/CVE-2025-20188)
* 💻 CVE Impacted Product : Cisco IOS XE Software for Wireless LAN Controllers (WLCs)
* 📈 CVSS : 10.0
* 🛡️ Security recommandations : Désactiver la fonction Out-of-Band AP Image Download si possible. Appliquer les mises à jour logicielles de Cisco dès que possible. Évaluer l'impact de la désactivation avant de l'appliquer.
* 🧬 Indicator of Compromise :
    * DOMAIN : pvp[.]sh

## Category : Threats
### Violations de données dans le secteur de la distribution (Cartier, The North Face) {#violations-de-données-dans-le-secteur-de-la-distribution-cartier-the-north-face}
La marque de luxe Cartier a révélé avoir subi une violation de données exposant les informations personnelles de ses clients suite à une compromission de ses systèmes. Parallèlement, The North Face, détaillant de vêtements d'extérieur, a alerté ses clients d'une attaque par "credential stuffing" en avril, au cours de laquelle des informations personnelles ont été volées. Adidas a également signalé une violation de données le mois précédent via un fournisseur tiers, exposant des informations de contact.
* Publication date : 2025/06/02
* 📰 Sources : hxxps[:]//www[.]bleepingcomputer[.]com/news/security/cartier-discloses-data-breach-amid-fashion-brand-cyberattacks/, hxxps[:]//www[.]bleepingcomputer[.]com/news/security/the-north-face-warns-customers-of-april-credential-stuffing-attack/
* 🎯 Threat Target : Clients de Cartier, The North Face, Timberland, Adidas
* 💥 Threat Tactic : Compromission de systèmes (Cartier), Credential stuffing (The North Face), Compromission d'un fournisseur tiers (Adidas)
* 🛡️ Security recommandations : Les clients doivent être vigilants face aux tentatives de phishing. The North Face devrait envisager l'application de l'authentification multi-facteurs (MFA).
* 🧬 Indicator of Compromise :
    * DOMAIN : thenorthface[.]com, timberland[.]com

### Le "Russian Market" devient une plateforme majeure pour les identifiants volés {#le-russian-market-devient-une-plateforme-majeure-pour-les-identifiants-volés}
Le marché cybercriminel "Russian Market" est devenu une plateforme populaire pour la vente d'identifiants volés par des logiciels espions (infostealers). Sa popularité a augmenté, en partie à cause du démantèlement du Genesis Market. Bien que la majorité des identifiants soient "recyclés", la plateforme offre une large sélection de logs d'infostealers contenant mots de passe, cookies, données de carte de crédit, crypto-monnaie et données de profil système. Les logs contiennent souvent des identifiants pour les services SaaS (Google Workspace, Zoom, Salesforce) et SSO.
* Publication date : 2025/06/02
* 📰 Source : hxxps[:]//www[.]bleepingcomputer[.]com/news/security/russian-market-emerges-as-a-go-to-shop-for-stolen-credentials/
* 👤 Threat Actor : Vendeurs sur le "Russian Market" (utilisant des infostealers comme Lumma, Acreed)
* 🎯 Threat Target : Utilisateurs infectés par des infostealers
* 💥 Threat Tactic : Vente d'identifiants volés via marketplace
* 🛠️ Threat Tools : Infostealers (Lumma, Acreed, etc.)
* 🛡️ Security recommandations : Utiliser l'authentification multi-facteurs pour les comptes sensibles. Être vigilant face aux emails de phishing, malvertising et téléchargements de logiciels provenant de sources non fiables pour éviter l'infection par infostealers.

### Démantèlement de services de contournement d'antivirus (CAV) {#démantèlement-de-services-de-contournement-dantivirus-cav}
Dans le cadre de l'Opération Endgame, une opération internationale menée par le département de la Justice américain, plusieurs sites offrant des services de cryptage et de contournement d'antivirus (CAV) ont été saisis le 27 mai 2025, notamment AvCheck, Cryptor et Crypt.guru. Ces services permettaient aux cybercriminels de tester et rendre leurs malwares indétectables par les programmes antivirus, facilitant ainsi les accès non autorisés et les attaques furtives. Des liens avec des groupes de ransomware ont été établis. Le démantèlement vise à perturber les activités des cybercriminels dès les premières étapes.
* Publication date : 2025/06/02
* 📰 Source : hxxps[:]//securityaffairs[.]com/178518/cyber-crime/police-took-down-several-popular-counter-antivirus-cav-services-including-avcheck.html
* 👤 Threat Actor : Fournisseurs de services CAV, groupes de ransomware
* 💥 Threat Tactic : Fourniture d'outils et services pour l'évasion de détection de malware
* 🛠️ Threat Tools : Services de cryptage et de CAV (AvCheck, Cryptor, Crypt.guru)
* 🛡️ Security recommandations : Les défenseurs peuvent utiliser les informations sur ces services démantelés pour mieux comprendre les techniques d'évasion utilisées par les malwares.
* 🧬 Indicator of Compromise :
    * DOMAIN : avcheck[.]net, cryptor[.]biz, crypt[.]guru

### Cyberattaque contre les hôpitaux de Covenant Health {#cyberattaque-contre-les-hôpitaux-de-covenant-health}
Une cyberattaque a frappé trois hôpitaux gérés par Covenant Health (St. Mary's, St. Joseph Hospital), les forçant à arrêter leurs systèmes pour contenir l'incident. L'attaque, débutée le 26 mai 2025, a perturbé les systèmes (téléphones, documentation, laboratoires externes) à travers les hôpitaux, cliniques et cabinets. L'organisation a engagé des experts en cybersécurité pour enquêter. Il n'est pas clair si des données ont été volées ou si des ransomwares ont été utilisés, bien que le secteur de la santé soit une cible fréquente de ransomwares.
* Publication date : 2025/06/02
* 📰 Source : hxxps[:]//securityaffairs[.]com/178507/cyber-crime/a-cyberattack-hit-hospitals-operated-by-covenant-health.html
* 🎯 Threat Target : Hôpitaux de Covenant Health (St. Mary's Health System, St. Joseph Hospital)
* 💥 Threat Tactic : Cyberattaque (potentiellement ransomware ou autre) provoquant l'arrêt des systèmes
* 🛡️ Security recommandations : Les organisations du secteur de la santé doivent renforcer leurs défenses contre les ransomwares et autres cyberattaques, y compris la segmentation du réseau, les sauvegardes régulières et les plans de réponse aux incidents.

### Exploitation d'une chaîne de vulnérabilités dans les routeurs FiberGateway {#exploitation-dune-chaîne-de-vulnérabilités-dans-les-routeurs-fibergateway}
Un chercheur en sécurité a publié une analyse détaillée d'une chaîne d'exploitation complète affectant le routeur FiberGateway GR241AG, utilisé par plus de 1,6 million de foyers au Portugal (clients Meo). La chaîne, partie d'une frustration DNS personnelle, a mené à l'accès root et à l'exécution de code à distance (RCE) via WiFi public. Les techniques utilisées incluent l'accès via UART, le dumping de firmware révélant des identifiants admin en clair, l'exploitation d'une vulnérabilité d'injection de paramètre dans `tcpdump`, l'utilisation d'IPv6 NDP pour la découverte d'adresses IP internes et l'obtention d'un reverse shell. Les découvertes ont été divulguées et Meo/CNCS ont corrigé les vulnérabilités dans les semaines qui ont suivi.
* Publication date : 2025/06/03
* 📰 Source : hxxps[:]//securityonline[.]info/fibergateway-router-hacked-portugals-1-6m-homes-at-risk/
* 🎯 Threat Target : Routeurs FiberGateway GR241AG (clients Meo, Portugal)
* 💥 Threat Tactic : Exploitation de vulnérabilités, accès physique (UART), reverse engineering, injection de commandes (`tcpdump`), découverte d'adresses IP (IPv6 NDP), exécution de code à distance, obtention d'accès root
* 🛡️ Security recommandations : Appliquer les mises à jour firmware du routeur. Séparer les réseaux publics (WiFi invité) des réseaux privés.
* 🧬 Indicator of Compromise :
    * DOMAIN : securityonline[.]info

### Le CISA ajoute des vulnérabilités activement exploitées à son catalogue KEV {#le-cisa-ajoute-des-vulnérabilités-activement-exploitées-à-son-catalogue-kev}
Le CISA a ajouté cinq nouvelles vulnérabilités à son catalogue KEV (Known Exploited Vulnerabilities), indiquant une exploitation active dans la nature. L'article met en évidence des campagnes d'exploitation, notamment le botnet "AyySSHush" ciblant plus de 9000 routeurs ASUS (ainsi que des appareils Cisco, D-Link, Linksys, QNAP, Araknis) par force brute et exploitation pour injecter des clés SSH et ouvrir un backdoor persistant. D'autres vulnérabilités ajoutées au KEV incluent `CVE-2024-56145` et `CVE-2025-35939` affectant Craft CMS, et `CVE-2025-3935` affectant ConnectWise ScreenConnect, qui peuvent conduire à l'exécution de code à distance dans certaines configurations ou en étant chaînées.
* Publication date : 2025/06/03
* 📰 Source : hxxps[:]//securityonline[.]info/cisa-adds-5-actively-exploited-vulnerabilities-to-kev-catalog-asus-routers-craft-cms-and-connectwise-targeted/
* 👤 Threat Actor : Botnet "AyySSHush" (selon GreyNoise et Sekoia), acteurs exploitant les vulnérabilités KEV
* 🎯 Threat Target : Routeurs ASUS (et potentiellement Cisco, D-Link, Linksys, QNAP, Araknis), Craft CMS, ConnectWise ScreenConnect
* 💥 Threat Tactic : Force brute, exploitation de vulnérabilités (injection de code, désérialisation dangereuse), injection de clé SSH, création de backdoor
* 🐞 CVE : [CVE-2025-3935](https://nvd.nist.gov/vuln/detail/CVE-2025-3935), [CVE-2024-56145](https://nvd.nist.gov/vuln/detail/CVE-2024-56145), [CVE-2025-35939](https://nvd.nist.gov/vuln/detail/CVE-2025-35939)
* 🛡️ Security recommandations : Appliquer immédiatement les correctifs pour les vulnérabilités listées par le CISA KEV. Utiliser des mots de passe forts et l'authentification multi-facteurs pour les routeurs et les systèmes de gestion à distance. Vérifier les configurations (e.g., `register_argc_argv` dans PHP pour Craft CMS).
* 🧬 Indicator of Compromise :
    * DOMAIN : securityonline[.]info, asp[.]net