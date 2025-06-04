# ⚠️Important Vulnerabilities (CVSS > 8)⚠️
* 🚨 Vulnérabilités multiples zero-day activement exploitées dans Google Chrome
* 🔐 Vulnérabilité critique de contournement d'authentification dans HPE StoreOnce (CVE-2025-37093)
* 💥 Vulnérabilité de débordement de tampon basé sur la pile dans Tenda RX3 (CVE-2025-5527)
* 📱 Vulnérabilités de double libération et d'écriture hors limites dans les processeurs Samsung Exynos (CVE-2025-23102, CVE-2025-23107)
* 📞 Vulnérabilité d'exécution de code à distance critique dans Audiocodes Mediapack (CVE-2025-32106)
* 📞 Vulnérabilité d'exécution de code à distance critique dans le serveur HTTP Sangoma IMG2020 (CVE-2025-32105)
* 📁 Vulnérabilité d'exécution de code à distance par téléchargement de fichier dans JEHC-BPM (CVE-2025-45854)
* 📧 Vulnérabilité de Cross Site Scripting (XSS) dans MailEnable (CVE-2025-44148)
* 📰 Analyse du Patch Tuesday Microsoft de mai 2025 : Cinq zero-days et vulnérabilités critiques
* 🛡️ Vulnérabilités critiques dans IBM QRadar et Cloud Pak for Security
* 🇺🇸 Nouvelles vulnérabilités ajoutées au catalogue CISA KEV, dont ASUS RT-AX55 et ConnectWise ScreenConnect
* ☁️ Problème de résolution DNS dans Azure OpenAI potentiellement critique

## Table of Contents
* [Category : VULNERABILITIES](#category--vulnerabilities)
    * [Vulnérabilités multiples zero-day activement exploitées dans Google Chrome](#vulnrabilits-multiples-zero-day-activement-exploites-dans-google-chrome)
    * [Vulnérabilité critique de contournement d'authentification dans HPE StoreOnce (CVE-2025-37093)](#vulnrabilit-critique-de-contournement-dauthentification-dans-hpe-storeonce-cve-2025-37093)
    * [Vulnérabilité de débordement de tampon basé sur la pile dans Tenda RX3 (CVE-2025-5527)](#vulnrabilit-de-dbordement-de-tampon-bas-sur-la-pile-dans-tenda-rx3-cve-2025-5527)
    * [Vulnérabilités de double libération et d'écriture hors limites dans les processeurs Samsung Exynos (CVE-2025-23102, CVE-2025-23107)](#vulnrabilits-de-double-libration-et-dcriture-hors-limites-dans-les-processeurs-samsung-exynos-cve-2025-23102--cve-2025-23107)
    * [Vulnérabilité d'exécution de code à distance critique dans Audiocodes Mediapack (CVE-2025-32106)](#vulnrabilit-dexcution-de-code-distance-critique-dans-audiocodes-mediapack-cve-2025-32106)
    * [Vulnérabilité d'exécution de code à distance critique dans le serveur HTTP Sangoma IMG2020 (CVE-2025-32105)](#vulnrabilit-dexcution-de-code-distance-critique-dans-le-serveur-http-sangoma-img2020-cve-2025-32105)
    * [Vulnérabilité d'exécution de code à distance par téléchargement de fichier dans JEHC-BPM (CVE-2025-45854)](#vulnrabilit-dexcution-de-code-distance-par-tlchargement-de-fichier-dans-jehc-bpm-cve-2025-45854)
    * [Vulnérabilité de Cross Site Scripting (XSS) dans MailEnable (CVE-2025-44148)](#vulnrabilit-de-cross-site-scripting-xss-dans-mailenable-cve-2025-44148)
    * [Analyse du Patch Tuesday Microsoft de mai 2025 : Cinq zero-days et vulnérabilités critiques](#analyse-du-patch-tuesday-microsoft-de-mai-2025--cinq-zero-days-et-vulnrabilits-critiques)
    * [Vulnérabilités critiques dans IBM QRadar et Cloud Pak for Security](#vulnrabilits-critiques-dans-ibm-qradar-et-cloud-pak-for-security)
    * [Nouvelles vulnérabilités ajoutées au catalogue CISA KEV, dont ASUS RT-AX55 et ConnectWise ScreenConnect](#nouvelles-vulnrabilits-ajoutes-au-catalogue-cisa-kev--dont-asus-rt-ax55-et-connectwise-screenconnect)
    * [Problème de résolution DNS dans Azure OpenAI potentiellement critique](#problme-de-rsolution-dns-dans-azure-openai-potentiellement-critique)
* [Category : THREATS](#category--threats)
    * [Violation de données chez Coinbase liée à la corruption d'agents de support TaskUs](#violation-de-donnes-chez-coinbase-lie-la-corruption-dagents-de-support-taskus)
    * [Packages RubyGems malveillants se faisant passer pour Fastlane pour voler des données CI/CD](#packages-rubygems-malveillants-se-faisant-passer-pour-fastlane-pour-voler-des-donnes-ci-cd)
    * [Le cheval de Troie bancaire Android Crocodilus évolue rapidement et devient mondial](#le-cheval-de-troie-bancaire-android-crocodilus-volue-rapidement-et-devient-mondial)
    * [Campagne de cryptojacking ciblant les outils DevOps exposés](#campagne-de-cryptojacking-ciblant-les-outils-devops-exposs)

## Category : VULNERABILITIES
### Vulnérabilités multiples zero-day activement exploitées dans Google Chrome
Des vulnérabilités multiples ont été découvertes dans Google Chrome, dont plusieurs sont activement exploitées en tant que zero-days. L'une d'elles, CVE-2025-5419, est une faille de lecture et d'écriture hors limites dans le moteur V8 JavaScript, permettant potentiellement une exécution de code arbitraire via une page HTML piégée. Google TAG a signalé cette vulnérabilité et une mise à jour de configuration a été déployée pour la mitiger. Deux autres zero-days activement exploités depuis début 2025 sont également mentionnés : CVE-2025-2783, une faille dans Mojo sur Windows permettant l'évasion de sandbox, et CVE-2025-4664, une application de politique insuffisante dans Loader. Ces vulnérabilités soulignent l'importance de maintenir les navigateurs à jour en raison des menaces actives.
* Publication date : 2025/06/03
* 📚 Sources : https://www.cert.ssi.gouv.fr/avis/CERTFR-2025-AVI-0471/, https://securityaffairs.com/178560/hacking/google-fixed-the-second-actively-exploited-chrome-zero-day-since-the-start-of-the-year.html, https://go.theregister.com/feed/www.theregister.com/2025/06/03/google_chrome_zero_day_emergency_fix/
* 🧩 CVE : CVE-2025-5419 (Activement exploitée) [https://nvd.nist.gov/vuln/detail/CVE-2025-5419](https://nvd.nist.gov/vuln/detail/CVE-2025-5419)
* 💻 CVE Impacted Product : Google Chrome, Moteur V8 JavaScript, Mojo (Windows), Loader
* 💥 CVE : CVE-2025-2783 (Activement exploitée) [https://nvd.nist.gov/vuln/detail/CVE-2025-2783](https://nvd.nist.gov/vuln/detail/CVE-2025-2783)
* 💻 CVE Impacted Product : Google Chrome (Windows), Mojo
* 💥 CVE : CVE-2025-4664 (Activement exploitée) [https://nvd.nist.gov/vuln/detail/CVE-2025-4664](https://nvd.nist.gov/vuln/detail/CVE-2025-4664)
* 💻 CVE Impacted Product : Google Chrome, Loader
* 🛡️ Security recommandations : Appliquer immédiatement les mises à jour ou correctifs disponibles. Être vigilant face aux pages HTML suspectes.

### Vulnérabilité critique de contournement d'authentification dans HPE StoreOnce (CVE-2025-37093)
Hewlett Packard Enterprise (HPE) a publié un bulletin de sécurité concernant plusieurs vulnérabilités dans sa solution de sauvegarde et de déduplication sur disque StoreOnce. La plus critique est un contournement d'authentification de gravité critique (CVSS 9.8), suivi sous le nom de CVE-2025-37093. Cette faille, découverte par Zero Day Initiative (ZDI), réside dans l'implémentation de la méthode `machineAccountCheck` suite à une implémentation incorrecte d'un algorithme d'authentification. Bien que les correctifs aient mis sept mois à être disponibles après leur signalement, aucune exploitation active n'a été signalée à ce jour.
* Publication date : 2025/06/03
* 📚 Sources : https://www.bleepingcomputer.com/news/security/hewlett-packard-enterprise-warns-of-critical-storeonce-auth-bypass/, https://cvefeed.io/news/52064/thumbnail.jpg
* 🧩 CVE : CVE-2025-37093 [https://nvd.nist.gov/vuln/detail/CVE-2025-37093](https://nvd.nist.gov/vuln/detail/CVE-2025-37093)
* 💻 CVE Impacted Product : HPE StoreOnce
* 💯 CVSS : 9.8
* 🛡️ Security recommandations : Appliquer les correctifs fournis par HPE dès que possible.

### Vulnérabilité de débordement de tampon basé sur la pile dans Tenda RX3 (CVE-2025-5527)
Une vulnérabilité de débordement de tampon basé sur la pile, classée comme critique (CVSS 8.8), a été découverte dans le routeur Tenda RX3 (version 16.03.13.11_multi_TDE01). Le problème affecte la fonction `save_staticroute_data` dans le fichier `/goform/SetStaticRouteCfg`. La manipulation de l'argument 'list' peut entraîner le débordement. L'attaque peut être initiée à distance et un exploit public a été divulgué.
* Publication date : 2025/06/03
* 📚 Sources : https://cvefeed.io/vuln/detail/CVE-2025-5527
* 🧩 CVE : CVE-2025-5527 [https://nvd.nist.gov/vuln/detail/CVE-2025-5527](https://nvd.nist.gov/vuln/detail/CVE-2025-5527)
* 💻 CVE Impacted Product : Tenda RX3 16.03.13.11_multi_TDE01
* 💯 CVSS : 8.8
* 🛡️ Security recommandations : Consulter le fournisseur (Tenda) pour obtenir un correctif ou une mitigation. Limiter l'accès à l'interface d'administration.

### Vulnérabilités de double libération et d'écriture hors limites dans les processeurs Samsung Exynos (CVE-2025-23102, CVE-2025-23107)
Des vulnérabilités affectant plusieurs processeurs mobiles Samsung Exynos ont été signalées. CVE-2025-23102 (CVSS 8.8, HIGH) est un problème de double libération (Double Free) pouvant entraîner une élévation de privilèges. CVE-2025-23107 (CVSS 8.6, HIGH) est un problème d'écriture hors limites (Out-of-Bounds Write) causé par un manque de vérification de longueur.
* Publication date : 2025/06/03
* 📚 Sources : https://cvefeed.io/vuln/detail/CVE-2025-23102, https://cvefeed.io/vuln/detail/CVE-2025-23107
* 🧩 CVE : CVE-2025-23102 [https://nvd.nist.gov/vuln/detail/CVE-2025-23102](https://nvd.nist.gov/vuln/detail/CVE-2025-23102)
* 💻 CVE Impacted Product : Samsung Mobile Processor Exynos 9820, 9825, 980, 990, 1080, 2100, 1280, 2200, 1380
* 💯 CVSS : 8.8
* 💥 CVE : CVE-2025-23107 [https://nvd.nist.gov/vuln/detail/CVE-2025-23107](https://nvd.nist.gov/vuln/detail/CVE-2025-23107)
* 💻 CVE Impacted Product : Samsung Mobile Processor Exynos 1480, 2400
* 💯 CVSS : 8.6
* 🛡️ Security recommandations : Appliquer les mises à jour logicielles fournies par Samsung ou les fabricants d'appareils utilisant ces processeurs.

### Vulnérabilité d'exécution de code à distance critique dans Audiocodes Mediapack (CVE-2025-32106)
Une vulnérabilité critique (CVSS 9.8) a été découverte dans les appareils Audiocodes Mediapack MP-11x (versions jusqu'à 6.60A.369.002). Un attaquant non authentifié peut exécuter du code non autorisé à distance en envoyant une requête POST spécifiquement conçue.
* Publication date : 2025/06/03
* 📚 Sources : https://cvefeed.io/vuln/detail/CVE-2025-32106
* 🧩 CVE : CVE-2025-32106 [https://nvd.nist.gov/vuln/detail/CVE-2025-32106](https://nvd.nist.gov/vuln/detail/CVE-2025-32106)
* 💻 CVE Impacted Product : Audiocodes Mediapack MP-11x through 6.60A.369.002
* 💯 CVSS : 9.8
* 🛡️ Security recommandations : Appliquer les correctifs disponibles du fournisseur. Restreindre l'accès réseau aux appareils affectés.

### Vulnérabilité d'exécution de code à distance critique dans le serveur HTTP Sangoma IMG2020 (CVE-2025-32105)
Un débordement de tampon (Buffer Overflow) dans le serveur HTTP de Sangoma IMG2020 (versions jusqu'à 2.3.9.6) permet à un attaquant non authentifié d'obtenir une exécution de code à distance. Cette vulnérabilité est classée comme critique (CVSS 9.8).
* Publication date : 2025/06/03
* 📚 Sources : https://cvefeed.io/vuln/detail/CVE-2025-32105
* 🧩 CVE : CVE-2025-32105 [https://nvd.nist.gov/vuln/detail/CVE-2025-32105](https://nvd.nist.gov/vuln/detail/CVE-2025-32105)
* 💻 CVE Impacted Product : Sangoma IMG2020 HTTP server through 2.3.9.6
* 💯 CVSS : 9.8
* 🛡️ Security recommandations : Appliquer les correctifs disponibles du fournisseur. Restreindre l'accès réseau au serveur HTTP affecté.

### Vulnérabilité d'exécution de code à distance par téléchargement de fichier dans JEHC-BPM (CVE-2025-45854)
Une vulnérabilité critique de téléchargement de fichier arbitraire (CVSS 9.8) a été identifiée dans JEHC-BPM v2.0.1. La faille se trouve dans le composant `/server/executeExec` et permet aux attaquants d'exécuter du code arbitraire en téléchargeant un fichier malveillant.
* Publication date : 2025/06/03
* 📚 Sources : https://cvefeed.io/vuln/detail/CVE-2025-45854
* 🧩 CVE : CVE-2025-45854 [https://nvd.nist.gov/vuln/detail/CVE-2025-45854](https://nvd.nist.gov/vuln/detail/CVE-2025-45854)
* 💻 CVE Impacted Product : JEHC-BPM v2.0.1
* 💯 CVSS : 9.8
* 🛡️ Security recommandations : Rechercher les mises à jour ou correctifs du fournisseur. Restreindre l'accès au composant vulnérable.

### Vulnérabilité de Cross Site Scripting (XSS) dans MailEnable (CVE-2025-44148)
Une vulnérabilité de Cross Site Scripting (XSS) de gravité critique (CVSS 9.8) a été découverte dans MailEnable avant la version v10. Un attaquant distant peut exécuter du code arbitraire via le composant `failure.aspx`.
* Publication date : 2025/06/03
* 📚 Sources : https://cvefeed.io/vuln/detail/CVE-2025-44148
* 🧩 CVE : CVE-2025-44148 [https://nvd.nist.gov/vuln/detail/CVE-2025-44148](https://nvd.nist.gov/vuln/detail/CVE-2025-44148)
* 💻 CVE Impacted Product : MailEnable before v10
* 💯 CVSS : 9.8
* 🛡️ Security recommandations : Mettre à jour MailEnable vers la version v10 ou supérieure.

### Analyse du Patch Tuesday Microsoft de mai 2025 : Cinq zero-days et vulnérabilités critiques
Microsoft a publié des correctifs pour 72 vulnérabilités lors du Patch Tuesday de mai 2025, dont cinq zero-days activement exploités et cinq vulnérabilités critiques. Parmi les zero-days, plusieurs sont des élévations de privilèges dans le système de fichiers CLFS (CVE-2025-32706, CVE-2025-32701), dans AFD (CVE-2025-32709), dans DWM Core Library (CVE-2025-30400), et une corruption de mémoire dans Scripting Engine (CVE-2025-30397) affectant Edge en mode IE. Les vulnérabilités critiques (CVSS >= 8) incluent des RCE dans Windows Remote Desktop Services (CVE-2025-29966, CVE-2025-29967, CVSS 8.8), et des RCE dans Microsoft Office (CVE-2025-30377, CVE-2025-30386, CVSS 8.4), souvent exploitées via l'ouverture de fichiers malveillants.
* Publication date : 2025/06/03, 2025/06/04
* 📚 Sources : https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-may-2025/, https://cvefeed.io/news/52103/thumbnail.jpg
* 💥 CVE : CVE-2025-32706 (Activement exploitée) [https://cvefeed.io/vuln/detail/CVE-2025-32706](https://cvefeed.io/vuln/detail/CVE-2025-32706)
* 💻 CVE Impacted Product : Windows Common Log File System
* 💯 CVSS : 7.8
* 💥 CVE : CVE-2025-32701 (Activement exploitée) [https://cvefeed.io/vuln/detail/CVE-2025-32701](https://cvefeed.io/vuln/detail/CVE-2025-32701)
* 💻 CVE Impacted Product : Windows Common Log File System
* 💯 CVSS : 7.8
* 💥 CVE : CVE-2025-32709 (Activement exploitée) [https://cvefeed.io/vuln/detail/CVE-2025-32709](https://cvefeed.io/vuln/detail/CVE-2025-32709)
* 💻 CVE Impacted Product : Windows Ancillary Function Driver for WinSock
* 💯 CVSS : 7.8
* 💥 CVE : CVE-2025-30400 (Activement exploitée) [https://cvefeed.io/vuln/detail/CVE-2025-30400](https://cvefeed.io/vuln/detail/CVE-2025-30400)
* 💻 CVE Impacted Product : Microsoft Desktop Windows Manager (DWM) Core Library
* 💯 CVSS : 7.8
* 💥 CVE : CVE-2025-30397 (Activement exploitée) [https://cvefeed.io/vuln/detail/CVE-2025-30397](https://cvefeed.io/vuln/detail/CVE-2025-30397)
* 💻 CVE Impacted Product : Microsoft Scripting Engine
* 💯 CVSS : 7.5
* 🧩 CVE : CVE-2025-29966 [https://cvefeed.io/vuln/detail/CVE-2025-29966](https://cvefeed.io/vuln/detail/CVE-2025-29966)
* 💻 CVE Impacted Product : Microsoft Windows Remote Desktop Services
* 💯 CVSS : 8.8
* 🧩 CVE : CVE-2025-29967 [https://cvefeed.io/vuln/detail/CVE-2025-29967](https://cvefeed.io/vuln/detail/CVE-2025-29967)
* 💻 CVE Impacted Product : Microsoft Windows Remote Desktop Services
* 💯 CVSS : 8.8
* 🧩 CVE : CVE-2025-30377 [https://cvefeed.io/vuln/detail/CVE-2025-30377](https://cvefeed.io/vuln/detail/CVE-2025-30377)
* 💻 CVE Impacted Product : Microsoft Office
* 💯 CVSS : 8.4
* 🧩 CVE : CVE-2025-30386 [https://cvefeed.io/vuln/detail/CVE-2025-30386](https://cvefeed.io/vuln/detail/CVE-2025-30386)
* 💻 CVE Impacted Product : Microsoft Office
* 💯 CVSS : 8.4
* 🛡️ Security recommandations : Appliquer toutes les mises à jour de sécurité Microsoft du Patch Tuesday de mai 2025. Envisager la migration des systèmes Windows 10 avant la fin du support en octobre 2025.

### Vulnérabilités critiques dans IBM QRadar et Cloud Pak for Security
IBM a publié un avis de sécurité concernant plusieurs vulnérabilités affectant ses plateformes QRadar Suite Software et Cloud Pak for Security, dont certaines sont classées comme critiques (CVSS jusqu'à 9.6). Ces failles présentent des risques tels que l'exécution de code à distance, la divulgation d'informations et les attaques par déni de service.
* Publication date : 2025/06/04
* 📚 Sources : https://securityonline.info/critical-cvss-9-6-ibm-qradar-cloud-pak-security-flaws-exposed/, https://upload.cvefeed.io/news/52104/thumbnail.jpg
* 🧩 CVE : CVE-2025-25022 [https://cvefeed.io/vuln/detail/CVE-2025-25022](https://cvefeed.io/vuln/detail/CVE-2025-25022)
* 💻 CVE Impacted Product : IBM QRadar Suite Software, Cloud Pak for Security
* 🧩 CVE : CVE-2025-25021 [https://cvefeed.io/vuln/detail/CVE-2025-25021](https://cvefeed.io/vuln/detail/CVE-2025-25021)
* 💻 CVE Impacted Product : IBM QRadar Suite Software, Cloud Pak for Security
* 🧩 CVE : CVE-2025-25020 [https://cvefeed.io/vuln/detail/CVE-2025-25020](https://cvefeed.io/vuln/detail/CVE-2025-25020)
* 💻 CVE Impacted Product : IBM QRadar Suite Software, Cloud Pak for Security
* 🧩 CVE : CVE-2025-25019 [https://cvefeed.io/vuln/detail/CVE-2025-25019](https://cvefeed.io/vuln/detail/CVE-2025-25019)
* 💻 CVE Impacted Product : IBM QRadar Suite Software, Cloud Pak for Security
* 🧩 CVE : CVE-2025-1334 [https://cvefeed.io/vuln/detail/CVE-2025-1334](https://cvefeed.io/vuln/detail/CVE-2025-1334)
* 💻 CVE Impacted Product : IBM QRadar Suite Software, Cloud Pak for Security
* 💯 CVSS : 9.6 (au moins une vulnérabilité a ce score)
* 🛡️ Security recommandations : Consulter l'avis de sécurité d'IBM et appliquer les correctifs nécessaires pour QRadar Suite Software et Cloud Pak for Security.

### Nouvelles vulnérabilités ajoutées au catalogue CISA KEV, dont ASUS RT-AX55 et ConnectWise ScreenConnect
La CISA américaine a ajouté plusieurs vulnérabilités à son catalogue Known Exploited Vulnerabilities (KEV), signalant leur exploitation active dans la nature. Parmi elles figurent des failles affectant les appareils ASUS RT-AX55 et ConnectWise ScreenConnect. La vulnérabilité ConnectWise ScreenConnect, CVE-2025-3935, est une potentielle exécution de code à distance via des clés machine volées, liée à une activité suspecte détectée par ConnectWise attribuée à un acteur étatique avancé. La faille ASUS RT-AX55, CVE-2023-39780, est exploitée par le botnet AyySSHush pour installer une backdoor SSH persistante sur plus de 9 000 routeurs ASUS compromis. Les agences FCEB (Federal Civilian Executive Branch) sont tenues de corriger ces vulnérabilités avant les dates limites spécifiées.
* Publication date : 2025/06/03
* 📚 Sources : https://securityaffairs.com/178591/hacking/u-s-cisa-adds-asus-rt-ax55-devices-craft-cms-and-connectwise-screenconnect-flaws-to-its-known-exploited-vulnerabilities-catalog.html
* 🇺🇸 CVE : CVE-2025-3935 (Activement exploitée, ajoutée au CISA KEV)
* 💻 CVE Impacted Product : ConnectWise ScreenConnect
* 🌐 CVE : CVE-2023-39780 (Activement exploitée, ajoutée au CISA KEV)
* 💻 CVE Impacted Product : ASUS RT-AX55
* 🎭 Threat Actor : Acteur étatique avancé (lié à CVE-2025-3935), Botnet AyySSHush (lié à CVE-2023-39780)
* 🛡️ Security recommandations : Appliquer immédiatement les correctifs pour ConnectWise ScreenConnect et ASUS RT-AX55. Surveiller l'activité réseau pour détecter les signes d'exploitation du botnet AyySSHush.

### Problème de résolution DNS dans Azure OpenAI potentiellement critique
Une configuration erronée a été découverte dans Azure OpenAI qui permettait potentiellement des fuites de données inter-tenants et des attaques de type "meddler-in-the-middle" (MitM). Le problème provenait d'une incohérence entre l'API et l'interface utilisateur d'Azure OpenAI concernant l'application de noms de domaine personnalisés uniques. Une seule exception permettait à plusieurs tenants de partager le domaine `test.openai.azure[.]com`, qui résolvait de manière inattendue vers une adresse IP externe non fiable (66.66.66[.]66) au lieu d'une IP Azure. Cela exposait potentiellement les appels API, les données sensibles et les identifiants à une interception par une entité externe. Microsoft a rapidement corrigé le problème en supprimant l'enregistrement DNS pointant vers l'IP externe. Bien qu'il ne s'agisse pas d'une vulnérabilité logicielle traditionnelle, cette misconfiguration a eu un impact potentiel critique.
* Publication date : 2025/06/03
* 📚 Sources : https://unit42.paloaltonetworks.com/azure-openai-dns-resolution/, https://unit42.paloaltonetworks.com/azure-openai-dns-resolution/
* 💻 CVE Impacted Product : Azure OpenAI API/UI
* 💯 CVSS : Potentiellement > 8 (Basé sur la description de l'impact : fuite de données, MitM)
* 🛡️ Security recommandations : Surveiller et valider régulièrement les résolutions DNS des ressources cloud. Examiner attentivement les workflows basés sur l'API. Auditer les services gérés pour les erreurs de configuration.
* 📡 Indicator of Compromise :
    * DOMAIN : test[.]openai[.]azure[.]com
    * DOMAIN : name[.]api[.]cognitive[.]microsoft[.]com
    * DOMAIN : likemargol[.]openai[.]azure[.]com
    * IPv4 : 66[.]66[.]66[.]66

## Category : THREATS
### Violation de données chez Coinbase liée à la corruption d'agents de support TaskUs
Une violation de données récemment divulguée chez Coinbase est liée à la corruption d'agents de support client basés en Inde, travaillant pour l'entreprise d'externalisation TaskUs. Des acteurs de la menace ont soudoyé ces employés pour voler des données d'utilisateurs de Coinbase. Les agents ont été surpris en train de prendre des photos d'écrans d'ordinateur, et une enquête a révélé que deux d'entre eux transmettaient des données sensibles à des hackers externes en échange de pots-de-vin. Les données volées incluent noms, e-mails, informations financières partielles, SSN, historique des transactions et scans de documents d'identité. Les attaquants ont utilisé ces informations pour des attaques d'ingénierie sociale. Coinbase a estimé les pertes potentielles jusqu'à 400 millions de dollars et a mis fin à ses opérations avec TaskUs dans la localisation affectée.
* Publication date : 2025/06/03
* 📚 Sources : https://www.bleepingcomputer.com/news/security/coinbase-breach-tied-to-bribed-taskus-support-agents-in-india/
* 🎭 Threat Actor : Acteurs de la menace (non nommés), Agents de support internes corrompus
* 🧍 Threat Target : Utilisateurs de Coinbase
* 🏹 Threat Tactic : Corruption, Menace interne, Ingénierie sociale, Vol de données
* 🛡️ Security recommandations : Renforcer la surveillance de l'activité des employés ayant accès aux données sensibles. Mettre en place des contrôles stricts sur l'accès aux données par les sous-traitants et les partenaires. Sensibiliser les employés aux risques d'ingénierie sociale et de corruption. Limiter la possibilité de photographier les écrans ou d'extraire des données vers des appareils personnels.

### Packages RubyGems malveillants se faisant passer pour Fastlane pour voler des données CI/CD
Deux packages RubyGems malveillants, `fastlane-plugin-telegram-proxy` et `fastlane-plugin-proxy_teleram`, se font passer pour des plugins Fastlane légitimes pour les développeurs d'applications mobiles. Ces packages interceptent et redirigent les requêtes API Telegram (normalement utilisées pour la notification dans les pipelines CI/CD) vers des serveurs contrôlés par les attaquants. L'objectif est de voler des données sensibles, notamment les jetons d'API de bot Telegram, qui pourraient être utilisés pour usurper l'identité du bot, supprimer ou manipuler des communications. Cette attaque de chaîne d'approvisionnement ciblant les développeurs est attribuée à un acteur utilisant des pseudonymes vietnamiens.
* Publication date : 2025/06/03, 2025/06/04
* 📚 Sources : https://www.bleepingcomputer.com/news/security/malicious-rubygems-pose-as-fastlane-to-steal-telegram-api-data/, https://securityonline.info/alert-malicious-rubygems-impersonate-fastlane-plugins-steal-ci-cd-data/, https://upload.cvefeed.io/news/52098/thumbnail.jpg
* 🎭 Threat Actor : Acteur utilisant les pseudonymes Bùi nam, buidanhnam, si_mobile
* 🧍 Threat Target : Développeurs utilisant Fastlane et RubyGems, Pipelines CI/CD, Données API Telegram, Jetons de bot Telegram
* 🏹 Threat Tactic : Attaque de chaîne d'approvisionnement (Supply Chain Attack), Usurpation de package (Typosquatting probable), Interception de données, Redirection de trafic
* 🛠️ Threat Tools : Packages RubyGems malveillants (`fastlane-plugin-telegram-proxy`, `fastlane-plugin-proxy_teleram`), Serveur proxy contrôlé par l'attaquant
* 🛡️ Security recommandations : Supprimer immédiatement les packages RubyGems malveillants. Recompiler les binaires mobiles produits après l'installation des gems. Faire pivoter tous les jetons de bot Telegram utilisés avec Fastlane. Vérifier l'authenticité des packages avant de les installer.
* 📡 Indicator of Compromise :
    * DOMAIN : api[.]telegram[.]org
    * DOMAIN : rough-breeze-0c37[.]buidanhnam95[.]workers[.]dev
    * URL : hxxps[:]//api[.]telegram[.]org/

### Le cheval de Troie bancaire Android Crocodilus évolue rapidement et devient mondial
Crocodilus est un nouveau cheval de Troie bancaire Android qui gagne rapidement du terrain, ciblant initialement l'Europe et l'Amérique du Sud, mais étendant sa portée à d'autres régions, y compris les États-Unis, l'Indonésie et l'Inde. Le malware se propage via des publicités malveillantes sur les réseaux sociaux, se déguisant en fausses applications bancaires ou de shopping, ou en mises à jour de navigateur. Les nouvelles variantes incluent des techniques d'obfuscation améliorées (empaquetage de code, chiffrement XOR) pour échapper à la détection. Une fonctionnalité clé est la capacité à modifier la liste de contacts de la victime pour ajouter de faux contacts ("Bank Support") et faciliter l'ingénierie sociale. Le malware cible également les portefeuilles de crypto-monnaies, capable d'extraire des phrases de récupération et des clés privées.
* Publication date : 2025/06/03
* 📚 Sources : https://securityaffairs.com/178578/malware/android-banking-trojan-crocodilus-evolves-fast-and-goes-global.html
* 🛠️ Threat Tools : Cheval de Troie bancaire Android Crocodilus
* 🧍 Threat Target : Utilisateurs Android en Europe, Amérique du Sud, et potentiellement d'autres régions ; Utilisateurs d'applications bancaires et de portefeuilles crypto
* 🏹 Threat Tactic : Distribution via publicité malveillante sur réseaux sociaux, Applications malveillantes, Usurpation d'identité (applications/mises à jour), Ingénierie sociale, Obfuscation, Vol de données (identifiants bancaires, informations personnelles, phrases de récupération/clés privées)
* 🛡️ Security recommandations : Éviter de cliquer sur des publicités suspectes ou des liens non sollicités sur les réseaux sociaux. Télécharger des applications uniquement depuis les boutiques officielles (Google Play Store). Être prudent avec les demandes de mise à jour de navigateur inattendues. Vérifier l'authenticité des contacts et des communications des banques ou des services financiers. Utiliser un logiciel de sécurité mobile réputé.

### Campagne de cryptojacking ciblant les outils DevOps exposés
Une campagne de cryptojacking, nommée JINX-0132, cible les serveurs DevOps exposés tels que Nomad, Consul, Docker et Gitea pour miner secrètement des crypto-monnaies. Les attaquants exploitent des configurations erronées et des vulnérabilités connues sur ces plateformes pour télécharger et exécuter des mineurs. Ils utilisent une approche "living-off-open-source", téléchargeant des outils comme XMRig directement depuis des dépôts GitHub publics, ce qui complique l'attribution et la détection par les IoCs traditionnels. L'abus des fonctionnalités par défaut (comme la file d'attente de tâches Nomad sans authentification) permet l'exécution de commandes arbitraires. Des milliers d'instances Consul et Nomad exposées sont trouvées en ligne, dont beaucoup sont mal configurées.
* Publication date : 2025/06/03
* 📚 Sources : https://securityaffairs.com/178548/cyber-crime/cryptojacking-campaign-relies-on-devops-tools.html
* 🎭 Threat Actor : JINX-0132
* 🧍 Threat Target : Serveurs DevOps exposés et mal configurés (Nomad, Consul, Docker, Gitea)
* 🏹 Threat Tactic : Exploitation de misconfigurations et vulnérabilités, Abus de fonctionnalités (job queue Nomad, service registration/health check Consul, Docker Engine API), Living off open source, Cryptojacking
* 🛠️ Threat Tools : XMRig (mineur de crypto-monnaie), Outils GitHub publics
* 🛡️ Security recommandations : Sécuriser correctement l'accès aux API des outils DevOps (Nomad, Consul, Docker). Appliquer les configurations recommandées par les fournisseurs. Éviter d'exposer les interfaces d'administration ou les API sensibles à Internet. Surveiller l'activité des processus sur les serveurs DevOps pour détecter l'exécution inattendue de mineurs ou de commandes.
* 📡 Indicator of Compromise :
    * IPv4 : 0[.]0[.]0[.]0
    * URL : hxxp[:]//0[.]0[.]0[.]0[:]2375