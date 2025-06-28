# ⚠️Important Vulnerabilities (CVSS > 8)⚠️
*   🚨 Cisco ISE and ISE-PIC : Vulnérabilités RCE Critiques
*   🚨 Vulnérabilité d'exécution de code à distance et de suppression de fichiers dans le plugin WordPress Game Users Share Buttons
*   🚨 Vulnérabilité d'élévation de privilèges dans le plugin WordPress PT Project Notebooks
*   🚨 Vulnérabilité de traversée de répertoire dans le plugin WordPress BeeTeam368 Extensions
*   🚨 Vulnérabilité de traversée de répertoire dans le plugin WordPress BeeTeam368 Extensions Pro
*   🚨 Vulnérabilité d'exécution de code à distance non authentifiée dans Dover Fueling Solutions ProGauge MagLink LX Consoles
*   🚨 Vulnérabilité de Cross-Site Scripting (XSS) TabberNeue
*   🚨 Vulnérabilité de téléchargement de fichier PHP dans MikoPBX
*   🚨 Vulnérabilités de juin 2025 du Patch Tuesday de Microsoft : une 0-Day et neuf critiques parmi 66 CVE
*   🚨 Vulnérabilité non divulguée dans Linux (ZDI-CAN-27392)
*   🚨 Vulnérabilité non divulguée dans Siemens (ZDI-CAN-26570)

## Table of Contents
*   [Category : Vulnérabilités](#category--vulnérabilités)
    *   [La faille "Citrix Bleed 2" serait exploitée dans des attaques, multiples vulnérabilités dans les produits Citrix](#la-faille-citrix-bleed-2-serait-exploitée-dans-des-attaques-multiples-vulnérabilités-dans-les-produits-citrix)
    *   [Prise de contrôle de millions de développeurs exploitant une faille du registre Open VSX](#prise-de-contrôle-de-millions-de-développeurs-exploitant-une-faille-du-registre-open-vsx)
    *   [Cisco ISE et ISE-PIC : Vulnérabilités RCE Critiques](#cisco-ise-et-ise-pic--vulnérabilités-rce-critiques)
    *   [Vulnérabilité d'exécution de code à distance et de suppression de fichiers dans le plugin WordPress Game Users Share Buttons](#vulnérabilité-dexécution-de-code-à-distance-et-de-suppression-de-fichiers-dans-le-plugin-wordpress-game-users-share-buttons)
    *   [Vulnérabilité d'élévation de privilèges dans le plugin WordPress PT Project Notebooks](#vulnérabilité-délévation-de-privilèges-dans-le-plugin-wordpress-pt-project-notebooks)
    *   [Vulnérabilité de traversée de répertoire dans le plugin WordPress BeeTeam368 Extensions](#vulnérabilité-de-traversée-de-répertoire-dans-le-plugin-wordpress-beeteam368-extensions)
    *   [Vulnérabilité de traversée de répertoire dans le plugin WordPress BeeTeam368 Extensions Pro](#vulnérabilité-de-traversée-de-répertoire-dans-le-plugin-wordpress-beeteam368-extensions-pro)
    *   [Vulnérabilité d'exécution de code à distance non authentifiée dans Dover Fueling Solutions ProGauge MagLink LX Consoles](#vulnérabilité-dexécution-de-code-à-distance-non-authentifiée-dans-dover-fueling-solutions-progauge-maglink-lx-consoles)
    *   [Vulnérabilité de Cross-Site Scripting (XSS) TabberNeue](#vulnérabilité-de-cross-site-scripting-xss-tabberneue)
    *   [Vulnérabilité de téléchargement de fichier PHP dans MikoPBX](#vulnérabilité-de-téléchargement-de-fichier-php-dans-mikopbx)
    *   [Comment Falcon Next-Gen SIEM protège les entreprises des attaques VMware vCenter](#comment-falcon-next-gen-siem-protège-les-entreprises-des-attaques-vmware-vcenter)
    *   [Juin 2025 Patch Tuesday : une 0-Day et neuf vulnérabilités critiques parmi 66 CVE](#juin-2025-patch-tuesday--une-0-day-et-neuf-vulnérabilités-critiques-parmi-66-cve)
    *   [Vulnérabilités à venir du Zero Day Initiative](#vulnérabilités-à-venir-du-zero-day-initiative)
*   [Category : Menaces](#category--menaces)
    *   [Les hackers de Scattered Spider ciblent désormais les entreprises de l'aviation et du transport](#les-hackers-de-scattered-spider-ciblent-désormais-les-entreprises-de-laviation-et-du-transport)
    *   [Le géant de la distribution Ahold Delhaize déclare une violation de données affectant 2,2 millions de personnes](#le-géant-de-la-distribution-ahold-delhaize-déclare-une-violation-de-données-affectant-22-millions-de-personnes)
    *   [Le fournisseur de Whole Foods, UNFI, restaure ses systèmes essentiels après une cyberattaque](#le-fournisseur-de-whole-foods-unfi-restaure-ses-systèmes-essentiels-après-une-cyberattaque)
    *   [Hawaiian Airlines révèle une cyberattaque, les vols ne sont pas affectés](#hawaiian-airlines-révèle-une-cyberattaque-les-vols-ne-sont-pas-affectés)
    *   [La campagne APT "OneClik" cible le secteur de l'énergie avec des backdoors furtives](#la-campagne-apt-oneclik-cible-le-secteur-de-lénergie-avec-des-backdoors-furtives)
    *   [L'APT42 se fait passer pour des professionnels de la cybersécurité afin de hameçonner des universitaires et journalistes israéliens](#lapt42-se-fait-passer-pour-des-professionnels-de-la-cybersécurité-afin-de-hameçonner-des-universitaires-et-journalistes-israéliens)
    *   [Dévoilement de RIFT : Amélioration de l'analyse des malwares Rust par la correspondance de motifs](#dévoilement-de-rift--amélioration-de-lanalyse-des-malwares-rust-par-la-correspondance-de-motifs)
    *   [Le ralentissement de Cloudflare par la Russie rend les sites inaccessibles](#le-ralentissement-de-cloudflare-par-la-russie-rend-les-sites-inaccessibles)

## Category : Vulnérabilités
### La faille "Citrix Bleed 2" serait exploitée dans des attaques, multiples vulnérabilités dans les produits Citrix
Une vulnérabilité critique de type "out-of-bounds memory read" surnommée "Citrix Bleed 2" (CVE-2025-5777) est désormais soupçonnée d'être exploitée dans des attaques, selon la société de cybersécurité ReliaQuest. Cette faille permet aux attaquants non authentifiés d'accéder à des portions de mémoire normalement inaccessibles, pouvant conduire au vol de jetons de session, de credentials et d'autres données sensibles, permettant de détourner des sessions utilisateur et de contourner l'authentification multifacteur (MFA). Des vulnérabilités similaires ont été découvertes dans les produits Citrix, les plus graves pouvant entraîner la divulgation de données sensibles via une lecture excessive de la mémoire (memory overread), ce qui pourrait donner aux attaquants un accès supplémentaire à l'appliance ou aux systèmes.
*   Publication date : 2025/06/27
*   🔗 Sources : https://www.bleepingcomputer.com/news/security/citrix-bleed-2-flaw-now-believed-to-be-exploited-in-attacks/, https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-citrix-products-could-allow-for-disclosure-of-sensitive-data_2025-060
*   🐞 CVE : CVE-2025-5777, CVE-2023-4966
*   💻 CVE Impacted Product : NetScaler ADC, NetScaler Gateway, Citrix ADC
*   📈 CVSS : Non spécifié (Critique, exploitation active implicite)
*   🛡️ Security recommandations : Surveillance accrue des sessions suspectes sur les dispositifs Citrix. Appliquer les correctifs dès leur disponibilité.
*   Indicators of compromise :
    *   CVE : CVE-2023-4966
    *   CVE : CVE-2025-5777

### Prise de contrôle de millions de développeurs exploitant une faille du registre Open VSX
Une faille critique dans le registre Open VSX (open-vsx.org) pourrait permettre à des attaquants de prendre le contrôle du hub d'extensions VS Code, exposant des millions de développeurs à des attaques de la chaîne d'approvisionnement. 💥 Les chercheurs de Koi Security ont découvert cette vulnérabilité, qui réside dans le processus d'auto-publication d'Open VSX. Un workflow GitHub Actions exécute `npm install` sur du code d'extension non fiable, exposant un jeton secret (OVSX_PAT) avec l'autorisation de publier ou d'écraser n'importe quelle extension. Cela pourrait permettre à un acteur malveillant de publier des mises à jour malveillantes pour chaque extension sur Open VSX, menant à une prise de contrôle complète du marché. 😈 Le MITRE a ajouté les "Extensions IDE" à son cadre ATT&CK en avril 2025, soulignant le risque.
*   Publication date : 2025/06/27
*   🔗 Source : https://securityaffairs.com/179398/hacking/taking-over-millions-of-developers-exploiting-an-open-vsx-registry-flaw.html
*   🐞 CVE : Non spécifié (Considéré comme critique au vu de l'impact)
*   💻 CVE Impacted Product : Open VSX Registry, Extensions VS Code
*   📈 CVSS : Non spécifié (Impact critique implicite, similaire à SolarWinds)
*   🛠️ Threat Tactic : Attaque de la chaîne d'approvisionnement (Supply Chain Attack)
*   🛡️ Security recommandations : Appliquer les correctifs dès leur disponibilité. Traiter les éléments du marché comme des dépendances logicielles avec le même niveau de diligence que d'autres paquets tiers.
*   Indicators of compromise :
    *   DOMAIN : open-vsx[.]org

### Cisco ISE et ISE-PIC : Vulnérabilités RCE Critiques
De multiples failles critiques ont été découvertes dans Cisco Identity Services Engine (ISE) et ISE Passive Identity Connector (ISE-PIC). 🚨 Les CVE-2025-20281 et CVE-2025-20282, notées respectivement 9.8 et 10.0 CVSS, permettent à des attaquants non authentifiés d'obtenir un accès root aux systèmes ciblés sans interaction utilisateur. La CVE-2025-20281 est due à une validation insuffisante de l'entrée utilisateur dans une API publique, permettant l'exécution de commandes arbitraires. La CVE-2025-20282 est causée par une validation de fichier inadéquate dans une API interne, permettant le téléchargement et l'exécution de fichiers arbitraires. 💥 Ces vulnérabilités affectent des produits largement utilisés dans les grandes entreprises et les infrastructures critiques, ce qui augmente le risque de compromission à distance.
*   Publication date : 2025/06/27
*   🔗 Source : https://socprime.com/blog/cve-2025-20281-and-cve-2025-20282-vulnerabilities/
*   🐞 CVE : CVE-2025-20281 (CVSS 9.8), CVE-2025-20282 (CVSS 10.0)
*   💻 CVE Impacted Product : Cisco Identity Services Engine (ISE) versions 3.3 et 3.4, ISE Passive Identity Connector (ISE-PIC) versions 3.3 et 3.4
*   📈 CVSS : 9.8 (CVE-2025-20281), 10.0 (CVE-2025-20282)
*   🛡️ Security recommandations : Appliquer les correctifs : CVE-2025-20281 est résolue dans ISE/ISE-PIC 3.3 Patch 6 et 3.4 Patch 2. CVE-2025-20282 est résolue dans ISE/ISE-PIC 3.4 Patch 2. Aucune solution de contournement n'est disponible.
*   Indicators of compromise :
    *   DOMAIN : delay[.]as

### Vulnérabilité d'exécution de code à distance et de suppression de fichiers dans le plugin WordPress Game Users Share Buttons
Le plugin "Game Users Share Buttons" pour WordPress est vulnérable à la suppression arbitraire de fichiers (CVE-2025-6755) en raison d'une validation insuffisante du chemin de fichier dans la fonction `ajaxDeleteTheme()`. 💀 Cela permet à des attaquants de niveau "Subscriber" d'ajouter des chemins de fichiers arbitraires (comme `../../../../wp-config.php`) au paramètre `themeNameId` de la requête AJAX, pouvant mener à une exécution de code à distance.
*   Publication date : 2025/06/28
*   🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-6755
*   🐞 CVE : CVE-2025-6755
*   💻 CVE Impacted Product : Game Users Share Buttons plugin for WordPress, toutes versions jusqu'à 1.3.0 incluse.
*   📈 CVSS : 8.8 (HIGH)
*   🛡️ Security recommandations : Mettre à jour le plugin vers une version corrigée dès que possible.

### Vulnérabilité d'élévation de privilèges dans le plugin WordPress PT Project Notebooks
Le plugin "PT Project Notebooks" pour WordPress présente une vulnérabilité d'élévation de privilèges (CVE-2025-5304) due à une autorisation manquante dans la fonction `wpnb_pto_new_users_add()`. 🚀 Cette faille permet à des attaquants non authentifiés d'élever leurs privilèges au niveau d'administrateur.
*   Publication date : 2025/06/28
*   🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-5304
*   🐞 CVE : CVE-2025-5304
*   💻 CVE Impacted Product : PT Project Notebooks plugin for WordPress, versions 1.0.0 à 1.1.3 incluses.
*   📈 CVSS : 9.8 (CRITICAL)
*   🛡️ Security recommandations : Mettre à jour le plugin vers une version corrigée dès que possible.

### Vulnérabilité de traversée de répertoire dans le plugin WordPress BeeTeam368 Extensions
Le plugin "BeeTeam368 Extensions" pour WordPress est vulnérable à la traversée de répertoire (CVE-2025-6381) via la fonction `handle_remove_temp_file()`. Cela permet à des attaquants authentifiés, avec un accès de niveau "Subscriber" ou supérieur, d'effectuer des actions sur des fichiers en dehors du répertoire prévu, notamment de supprimer le fichier `wp-config.php`, ce qui peut entraîner une prise de contrôle du site. 💀
*   Publication date : 2025/06/28
*   🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-6381
*   🐞 CVE : CVE-2025-6381
*   💻 CVE Impacted Product : BeeTeam368 Extensions plugin for WordPress, toutes versions jusqu'à 2.3.4 incluses.
*   📈 CVSS : 8.8 (HIGH)
*   🛡️ Security recommandations : Mettre à jour le plugin vers une version corrigée dès que possible.

### Vulnérabilité de traversée de répertoire dans le plugin WordPress BeeTeam368 Extensions Pro
Le plugin "BeeTeam368 Extensions Pro" pour WordPress est vulnérable à la traversée de répertoire (CVE-2025-6379) via la fonction `handle_live_fn()`. 😈 Similaire à la version standard du plugin, cette faille permet à des attaquants authentifiés, avec un accès de niveau "Subscriber" ou supérieur, d'effectuer des actions sur des fichiers en dehors du répertoire prévu, notamment de supprimer le fichier `wp-config.php`, ce qui peut entraîner une prise de contrôle du site.
*   Publication date : 2025/06/28
*   🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-6379
*   🐞 CVE : CVE-2025-6379
*   💻 CVE Impacted Product : BeeTeam368 Extensions Pro plugin for WordPress, toutes versions jusqu'à 2.3.4 incluses.
*   📈 CVSS : 8.8 (HIGH)
*   🛡️ Security recommandations : Mettre à jour le plugin vers une version corrigée dès que possible.

### Vulnérabilité d'exécution de code à distance non authentifiée dans Dover Fueling Solutions ProGauge MagLink LX Consoles
Les consoles "Dover Fueling Solutions ProGauge MagLink LX" exposent une interface `target communication framework` (TCF) non documentée et non authentifiée sur un port spécifique (CVE-2025-5310). 💥 Cette vulnérabilité permet de créer, supprimer ou modifier des fichiers, pouvant potentiellement entraîner une exécution de code à distance (RCE).
*   Publication date : 2025/06/27
*   🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-5310
*   🐞 CVE : CVE-2025-5310
*   💻 CVE Impacted Product : Dover Fueling Solutions ProGauge MagLink LX Consoles
*   📈 CVSS : 9.8 (CRITICAL)
*   🛡️ Security recommandations : Appliquer les correctifs du fournisseur dès qu'ils sont disponibles. Isoler les systèmes si possible pour limiter l'exposition.

### Vulnérabilité de Cross-Site Scripting (XSS) TabberNeue
L'extension MediaWiki "TabberNeue", qui permet de créer des onglets, est vulnérable au Cross-Site Scripting (XSS) (CVE-2025-53093). 🐞 À partir de la version 3.0.0 et avant la version 3.1.1, tout utilisateur peut insérer du code HTML arbitraire dans le DOM en injectant une charge utile dans n'importe quel attribut autorisé de la balise `<tab>`.
*   Publication date : 2025/06/27
*   🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-53093
*   🐞 CVE : CVE-2025-53093
*   💻 CVE Impacted Product : TabberNeue MediaWiki extension, versions 3.0.0 à 3.1.0 incluses.
*   📈 CVSS : 8.6 (HIGH)
*   🛡️ Security recommandations : Mettre à jour l'extension vers la version 3.1.1 ou ultérieure.

### Vulnérabilité de téléchargement de fichier PHP dans MikoPBX
"MikoPBX" à travers la version 2024.1.114 permet le téléchargement d'un script PHP vers un répertoire arbitraire via `PBXCoreREST/Controllers/Files/PostController.php` (CVE-2025-52207). 🚨 Cette vulnérabilité de téléchargement de fichier peut conduire à une exécution de code à distance.
*   Publication date : 2025/06/27
*   🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-52207
*   🐞 CVE : CVE-2025-52207
*   💻 CVE Impacted Product : MikoPBX, versions jusqu'à 2024.1.114 incluses.
*   📈 CVSS : 9.9 (CRITICAL)
*   🛡️ Security recommandations : Mettre à jour MikoPBX vers une version corrigée. Implémenter une validation stricte des téléchargements de fichiers et restreindre les permissions d'écriture.

### Comment Falcon Next-Gen SIEM protège les entreprises des attaques VMware vCenter
Des vulnérabilités critiques dans VMware vCenter, comme la CVE-2023-34048, peuvent donner aux attaquants un contrôle total sur l'infrastructure virtuelle d'une organisation. 🚨 Cette CVE, bien que corrigée en octobre 2023, a été activement exploitée en janvier 2024, permettant l'exécution de code à distance sans authentification. CrowdStrike propose sa solution Falcon Next-Gen SIEM pour détecter et répondre à ces menaces. Les techniques d'exploitation incluent l'établissement de persistance via le téléchargement et le montage d'images ISO non gérées, la création de machines virtuelles "fantômes" (rogue VMs) pour échapper à la détection, et l'accès aux credentials en ciblant les bases de données NTDS.dit des contrôleurs de domaine virtuels.
*   Publication date : 2025/06/27
*   🔗 Source : https://www.crowdstrike.com/en-us/blog/falcon-next-gen-siem-protects-against-vmware-vcenter-attacks/
*   🐞 CVE : CVE-2023-34048
*   💻 CVE Impacted Product : VMware vCenter Server, ESXi
*   📈 CVSS : Critiqué (selon la description de l'article pour CVE-2023-34048)
*   🛡️ Security recommandations : Utiliser des solutions SIEM pour la détection et la réponse aux menaces. Collecter et analyser les journaux vCenter. Surveiller les activités liées aux VM (création, attachement d'ISO, démarrage). Détecter la création de VM non autorisées et le détournement de contrôleurs de domaine virtuels.
*   Indicators of compromise :
    *   CVE : CVE-2023-34048

### Juin 2025 Patch Tuesday : une 0-Day et neuf vulnérabilités critiques parmi 66 CVE
Microsoft a publié son Patch Tuesday de juin 2025, corrigeant 66 vulnérabilités, dont une vulnérabilité "zero-day" activement exploitée et neuf vulnérabilités critiques. 🚨 Parmi les vulnérabilités critiques notables :
*   **CVE-2025-33053 (WebDAV, CVSS 8.8)** : Exécution de code à distance non authentifiée.
*   **CVE-2025-47162, CVE-2025-47164, CVE-2025-47167, CVE-2025-47953 (Microsoft Office, CVSS 8.4)** : Exécution de code malveillant à distance par des exploits déclenchés localement, sans privilèges ni interaction utilisateur.
*   **CVE-2025-33070 (Windows Netlogon, CVSS 8.1)** : Élévation de privilèges critique, permettant un accès administrateur de domaine sans authentification.
*   **CVE-2025-29828 (Windows Cryptographic Services/Schannel, CVSS 8.1)** : Exécution de code à distance non authentifiée via une fuite de mémoire (TLS).
*   **CVE-2025-32710 (Windows Remote Desktop Services, CVSS 8.1)** : Exécution de code à distance non authentifiée via une condition "use-after-free".
*   **CVE-2025-33071 (Windows KDC Proxy Service/KPSSVC, CVSS 8.1)** : Exécution de code à distance non authentifiée via une condition "use-after-free".
*   **CVE-2025-47172 (Microsoft SharePoint Server, CVSS 8.8)** : Exécution de code à distance via injection SQL, avec des permissions minimales.
*   **CVE-2025-33073 (Windows SMB Client, CVSS 8.8)** : Élévation de privilèges permettant un accès SYSTEM depuis des privilèges faibles.
*   Publication date : 2025/06/27
*   🔗 Source : https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-june-2025/
*   🐞 CVE : CVE-2025-47953, CVE-2025-47172, CVE-2025-47167, CVE-2025-47164, CVE-2025-47162, CVE-2025-33073, CVE-2025-33071, CVE-2025-33070, CVE-2025-33053, CVE-2025-32710, CVE-2025-29828
*   💻 CVE Impacted Product : Microsoft (WebDAV, Office, Windows Netlogon, Cryptographic Services, Remote Desktop Services, KDC Proxy Service, SharePoint Server, SMB Client)
*   📈 CVSS : 8.8 (CVE-2025-33053, CVE-2025-47172, CVE-2025-33073), 8.4 (CVE-2025-47162, CVE-2025-47164, CVE-2025-47167, CVE-2025-47953), 8.1 (CVE-2025-33070, CVE-2025-29828, CVE-2025-32710, CVE-2025-33071)
*   🛡️ Security recommandations : Appliquer les mises à jour de sécurité de Microsoft sans délai. Mettre en place une gestion continue des vulnérabilités et des stratégies de détection proactives. Préparer un plan de réponse pour les vulnérabilités non corrigées. Prévoir la mise à niveau des systèmes Windows 10 avant la fin du support en octobre 2025.
*   Indicators of compromise :
    *   DOMAIN : countries[.]watch

### Vulnérabilités à venir du Zero Day Initiative
Zero Day Initiative (ZDI) a rapporté de nouvelles vulnérabilités non divulguées dans des produits Linux et Siemens. ⏳ Ces alertes précèdent la publication des correctifs par les fournisseurs, mais les clients de Trend Micro sont déjà protégés par des filtres IPS.
*   Publication date : 2025/06/27
*   🔗 Source : http://www.zerodayinitiative.com/advisories/upcoming/
*   🐞 CVE : ZDI-CAN-27392 (Linux), ZDI-CAN-26570 (Siemens)
*   💻 CVE Impacted Product : Linux, Siemens
*   📈 CVSS : 9.0 (Linux), 8.8 (Siemens)
*   🛡️ Security recommandations : Les clients de Trend Micro sont protégés par des filtres IPS. Attendre les correctifs officiels des fournisseurs d'ici le 25 octobre 2025.

## Category : Menaces
### Les hackers de Scattered Spider ciblent désormais les entreprises de l'aviation et du transport
Les hackers affiliés aux tactiques de Scattered Spider (également connus sous les noms de 0ktapus, Starfraud, UNC3944, Scatter Swine, Octo Tempest et Muddled Libra) ont étendu leur ciblage aux industries de l'aviation et du transport, après avoir précédemment attaqué les secteurs de l'assurance et de la distribution (M&S, Co-op). ✈️ Le groupe est connu pour ses attaques d'ingénierie sociale sophistiquées, de phishing, de "MFA bombing" (fatigue MFA ciblée) et de "SIM swapping" pour obtenir un accès initial aux réseaux. 😈 Des entreprises comme Hawaiian Airlines et United Natural Foods (UNFI) ont été récemment touchées par des cyberattaques qui pourraient être attribuées à ce même groupe. Scattered Spider est également connu pour s'associer à des gangs de ransomware russophones tels que BlackCat, RansomHub, Qilin et DragonForce.
*   Publication date : 2025/06/27
*   🔗 Sources : https://www.bleepingcomputer.com/news/security/scattered-spider-hackers-shift-focus-to-aviation-transportation-firms/, https://www.bleepingcomputer.com/news/security/whole-foods-supplier-unfi-restores-core-systems-after-cyberattack/, https://www.bleepingcomputer.com/news/security/hawaiian-airlines-discloses-cyberattack-flights-not-affected/
*   🎭 Threat Actor : Scattered Spider (0ktapus, Starfraud, UNC3944, Scatter Swine, Octo Tempest, Muddled Libra)
*   🎯 Threat Target : Aviation, transport (Hawaiian Airlines), distribution (Ahold Delhaize, UNFI, M&S, Co-op), assurance.
*   🛠️ Threat Tactic : Ingénierie sociale, phishing, MFA bombing, SIM swapping, réinitialisation de mot de passe en libre-service, accès à distance via Citrix, partenariat avec des gangs de ransomware.
*   🔪 Threat Tools : Ransomware (BlackCat, RansomHub, Qilin, DragonForce).
*   🛡️ Security recommandations : Renforcer les processus de vérification d'identité des services d'assistance avant d'ajouter de nouveaux numéros de téléphone. Réinitialiser les mots de passe. Ajouter des dispositifs aux solutions MFA. Éviter de fournir des informations d'employés (ex: identifiants) qui pourraient être utilisées pour des attaques d'ingénierie sociale ultérieures.

### Le géant de la distribution Ahold Delhaize déclare une violation de données affectant 2,2 millions de personnes
Ahold Delhaize, l'une des plus grandes chaînes de distribution alimentaire au monde, notifie plus de 2,2 millions de personnes que leurs informations personnelles, financières et de santé ont été volées lors d'une attaque par ransomware en novembre dernier, qui a impacté ses systèmes américains. 💸 Bien que l'entreprise n'ait pas confirmé le groupe cybercriminel derrière la violation, le groupe de ransomware INC Ransom a ajouté Ahold Delhaize à son portail d'extorsion sur le dark web en avril, divulguant des échantillons de documents prétendument volés.
*   Publication date : 2025/06/27
*   🔗 Source : https://www.bleepingcomputer.com/news/security/retail-giant-ahold-delhaize-says-data-breach-affects-22-million-people/
*   🎭 Threat Actor : INC Ransom (non confirmé par l'entreprise)
*   🎯 Threat Target : Ahold Delhaize (distribution alimentaire), 2,2 millions d'individus.
*   🛠️ Threat Tactic : Attaque par ransomware, vol de données, extorsion.
*   🛡️ Security recommandations : Surveiller les communications du fournisseur et les annonces de violation de données.

### Le fournisseur de Whole Foods, UNFI, restaure ses systèmes essentiels après une cyberattaque
United Natural Foods (UNFI), géant américain de la vente en gros de produits alimentaires et principal distributeur pour Whole Foods d'Amazon, a annoncé avoir restauré ses systèmes essentiels et remis en ligne les systèmes de commande électronique et de facturation affectés par une cyberattaque survenue le 5 juin 2025. 🚛 L'incident a entraîné une réduction du volume des ventes et une augmentation des coûts opérationnels. Bien que UNFI n'ait pas divulgué la nature de l'attaque ni le groupe de ransomware responsable, l'article mentionne que les acteurs de la menace Scattered Spider et l'opération de ransomware DragonForce ont ciblé les détaillants britanniques et se tournent désormais vers les détaillants et les compagnies d'assurance américaines.
*   Publication date : 2025/06/27
*   🔗 Source : https://www.bleepingcomputer.com/news/security/whole-foods-supplier-unfi-restores-core-systems-after-cyberattack/
*   🎯 Threat Target : United Natural Foods (UNFI), secteur de la distribution alimentaire.
*   🛠️ Threat Tactic : Cyberattaque (potentiellement ransomware, service disruption).
*   🛡️ Security recommandations : Renforcer la résilience opérationnelle et les capacités de reprise après sinistre.

### Hawaiian Airlines révèle une cyberattaque, les vols ne sont pas affectés
Hawaiian Airlines, la dixième plus grande compagnie aérienne commerciale des États-Unis, enquête sur une cyberattaque qui a perturbé l'accès à certains de ses systèmes. ✈️ Bien que les vols n'aient pas été affectés, l'entreprise a pris des mesures pour protéger ses opérations. Une source a indiqué à BleepingComputer que les mêmes acteurs de la menace que ceux impliqués dans le changement de cible des hackers Scattered Spider vers l'aviation et le transport pourraient être responsables.
*   Publication date : 2025/06/27
*   🔗 Source : https://www.bleepingcomputer.com/news/security/hawaiian-airlines-discloses-cyberattack-flights-not-affected/
*   🎯 Threat Target : Hawaiian Airlines (secteur de l'aviation).
*   🛠️ Threat Tactic : Cyberattaque.
*   🛡️ Security recommandations : Mener une enquête approfondie, engager les autorités et les experts en cybersécurité pour la remédiation.

### La campagne APT "OneClik" cible le secteur de l'énergie avec des backdoors furtives
Des chercheurs en cybersécurité de Trellix ont découvert une nouvelle campagne de malware APT, "OneClik", ciblant les secteurs de l'énergie, du pétrole et du gaz. ⛽ Elle abuse de la technologie de déploiement ClickOnce de Microsoft et utilise des backdoors Golang personnalisées. Des liens avec des acteurs affiliés à la Chine sont suspectés (possible lien avec APT41 à faible confiance). Les acteurs de la menace utilisent des tactiques furtives de "living off the land" et des services cloud (AWS CloudFront, API Gateway, Lambda) pour échapper à la détection. 👻 La campagne montre une évolution progressive des techniques d'évasion, y compris l'anti-débogage et la détection de sandbox.
*   Publication date : 2025/06/27
*   🔗 Source : https://securityaffairs.com/179388/hacking/oneclik-apt-campaign-targets-energy-sector-with-stealthy-backdoors.html
*   🎭 Threat Actor : Campagne OneClik (liée à la Chine, possiblement APT41 avec faible confiance)
*   🎯 Threat Target : Secteurs de l'énergie, du pétrole et du gaz (ciblé au Moyen-Orient en septembre 2023).
*   🛠️ Threat Tactic : Abus de Microsoft ClickOnce (installation furtive d'applications), ingénierie sociale (emails de phishing avec faux outils d'analyse matérielle), injection AppDomainManager de .NET, tactiques "living off the land", évasion via services cloud (AWS CloudFront, API Gateway, Lambda), anti-débogage, détection de sandbox.
*   🔪 Threat Tools : Backdoors Golang ("RunnerBeacon"), chargeur .NET ("OneClikNet"). Ressemble à Geacon (variante Go de Cobalt Strike).
*   🛡️ Security recommandations : Surveiller les tactiques "living off the land" et les communications anormales avec les services cloud légitimes. Mettre en place une analyse comportementale approfondie pour détecter les backdoors. Renforcer la sécurité des e-mails et la sensibilisation au phishing.

### L'APT42 se fait passer pour des professionnels de la cybersécurité afin de hameçonner des universitaires et journalistes israéliens
Le groupe APT42 (également connu sous les noms d'Educated Manticore, Charming Kitten et Mint Sandstorm), lié à l'Iran, cible les journalistes, experts en cybersécurité et universitaires israéliens avec des attaques de phishing. 🎣 Ils se font passer pour des professionnels de la sécurité pour voler les identifiants de messagerie et les codes 2FA. 🎭 Les cyberespions iraniens ont utilisé des messages élaborés, rédigés par IA, pour attirer les victimes vers de fausses pages de connexion Gmail ou des invitations Google Meet. Le groupe utilise des kits de phishing personnalisés basés sur React SPA avec des "keyloggers" en temps réel et des connexions WebSocket pour collecter les données volées.
*   Publication date : 2025/06/27
*   🔗 Source : https://securityaffairs.com/179372/apt/apt42-impersonates-cyber-professionals-to-phish-israeli-academics-and-journalists.html
*   🎭 Threat Actor : APT42 (Educated Manticore, Charming Kitten, Mint Sandstorm) - lié à l'Iran.
*   🎯 Threat Target : Journalistes israéliens, experts en cybersécurité, universitaires.
*   🛠️ Threat Tactic : Spear-phishing ciblé, ingénierie sociale (usurpation d'identité), collecte de credentials, surveillance, déploiement de malware (non détaillé), utilisation de l'IA pour les messages.
*   🔪 Threat Tools : Kits de phishing personnalisés (Gmail, Outlook, Yahoo), React SPA, keyloggers en temps réel, WebSocket, Google Sites (pour héberger de fausses invitations Google Meet).
*   🛡️ Security recommandations : Sensibiliser les utilisateurs aux attaques de phishing d'ingénierie sociale sophistiquées. Vérifier attentivement les adresses e-mail et les domaines. Utiliser des solutions de sécurité qui détectent les kits de phishing avancés et les tentatives de contournement de la 2FA.
*   Indicators of compromise :
    *   DOMAIN : Plus de 130 domaines liés au phishing (beaucoup via NameCheap).

### Dévoilement de RIFT : Amélioration de l'analyse des malwares Rust par la correspondance de motifs
Les acteurs de la menace adoptent de plus en plus Rust pour le développement de malwares, ce qui représente un défi croissant pour les analystes en rétro-ingénierie en raison de la complexité et de la taille des binaires Rust. 🛠️ Microsoft Threat Intelligence Center a publié RIFT, un outil open-source conçu pour aider à automatiser l'identification du code écrit par l'attaquant dans les binaires Rust. RIFT, composé de plugins IDA Pro et de scripts Python, utilise la génération de signatures FLIRT et la comparaison binaire (binary diffing) pour différencier le code de bibliothèque standard du code malveillant, améliorant ainsi l'efficacité et la précision de l'analyse des malwares basés sur Rust.
*   Publication date : 2025/06/27
*   🔗 Source : https://www.microsoft.com/en-us/security/blog/2025/06/27/unveiling-rift-enhancing-rust-malware-analysis-through-pattern-matching/
*   🎭 Threat Actor : Groupes à motivation financière et entités étatiques utilisant Rust pour le développement de malwares (ex: ransomware BlackCat).
*   🛠️ Threat Tactic : Développement de malwares en Rust pour la performance, la sécurité et l'évasion de détection.
*   🔪 Threat Tools : RIFT (outil d'analyse des malwares Rust), IDA Pro, Diaphora.
*   🛡️ Security recommandations : Utiliser des outils spécialisés comme RIFT pour l'analyse des malwares Rust. Renforcer les mesures de sécurité avancées pour contrer la sophistication croissante des cybermenaces.

### Le ralentissement de Cloudflare par la Russie rend les sites inaccessibles
À partir du 9 juin 2025, les fournisseurs de services Internet (FAI) russes ont commencé à ralentir l'accès aux sites web et services protégés par Cloudflare. 🌐 Cette action est considérée par Cloudflare comme faisant partie de la stratégie plus large de la Russie visant à évincer les entreprises technologiques occidentales du marché intérieur. Les FAI russes, notamment Rostelecom, Megafon, Vimpelcom, MTS et MGTS, utilisent plusieurs mécanismes de ralentissement et de blocage, y compris l'injection et le blocage de paquets, ce qui entraîne des délais d'attente. Cloudflare déclare ne pas être en mesure de remédier à la situation car le ralentissement échappe à son contrôle.
*   Publication date : 2025/06/27
*   🔗 Source : https://www.bleepingcomputer.com/news/technology/russias-throttling-of-cloudflare-makes-sites-inaccessible/
*   🎭 Threat Actor : Russie (FAI russes : Rostelecom, Megafon, Vimpelcom, MTS, MGTS)
*   🎯 Threat Target : Cloudflare, sites web et services protégés par Cloudflare, utilisateurs russes, outils anti-censure (VPN, Psiphon, Hetzner, DigitalOcean).
*   🛠️ Threat Tactic : Ralentissement d'accès, injection de paquets, blocage de paquets.
*   🛡️ Security recommandations : Les utilisateurs russes peuvent chercher des alternatives de contournement de la censure non affectées ou des services VPN auto-hébergés. Pour les entreprises, la diversification des fournisseurs CDN ou l'exploration de solutions multi-cloud peut réduire la dépendance à un seul fournisseur.