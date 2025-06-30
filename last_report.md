# ⚠️Important Vulnerabilities (CVSS > 8)⚠️
*   👂 Multiple Failles Bluetooth dans les Chipsets Airoha : Risque d'Espionnage et RCE
*   🌐 Vulnérabilité de D-Link DIR-513 : Dépassement de Tampon (CVE-2025-6882)
*   💻 Vulnérabilité de D-Link DI-8100 : Dépassement de Tampon PPPoE (CVE-2025-6881)
*   SQLi Multiples Vulnérabilités d'Injection SQL Authentifiées dans UISP (CVE-2025-24290)
*   📂 Vulnérabilité de Traversée de Répertoire WinRAR (CVE-2025-6218)
*   🔒 Vulnérabilités Critiques dans le Firmware AMI MegaRAC et les Imprimantes Multifonctions Brother
*   ⚠️ Citrix Bleed 2 : Exploitation Active de Vulnérabilités Critiques dans NetScaler Gateway (CVE-2025-5777 et CVE-2025-6543)
*   🚫 Multiples Failles Critiques dans les Routeurs D-Link DIR-816 (RCE, PAS DE CORRECTIFS)
*   🔑 Faille Synology ABM (CVE-2025-4679) : Fuite de Secret Client et Exposition des Locataires Microsoft 365

## Table of Contents
*   [Category : Threats](#category--threats)
    *   [Hide Your RDP: Password Spray Leads to RansomHub Deployment](#hide-your-rdp-password-spray-leads-to-ransomhub-deployment)
*   [Category : Vulnerabilities](#category--vulnerabilities)
    *   [Multiple Failles Bluetooth dans les Chipsets Airoha : Risque d'Espionnage et RCE](#multiple-failles-bluetooth-dans-les-chipsets-airoha-risque-despionnage-et-rce)
    *   [Vulnérabilité de D-Link DIR-513 : Dépassement de Tampon (CVE-2025-6882)](#vulnerabilite-de-d-link-dir-513--depassement-de-tampon-cve-2025-6882)
    *   [Vulnérabilité de D-Link DI-8100 : Dépassement de Tampon PPPoE (CVE-2025-6881)](#vulnerabilite-de-d-link-di-8100--depassement-de-tampon-pppoe-cve-2025-6881)
    *   [Multiples Vulnérabilités d'Injection SQL Authentifiées dans UISP (CVE-2025-24290)](#multiples-vulnerabilites-dinjection-sql-authentifiees-dans-uisp-cve-2025-24290)
    *   [Vulnérabilité de Traversée de Répertoire WinRAR (CVE-2025-6218)](#vulnerabilite-de-traversee-de-repertoire-winrar-cve-2025-6218)
    *   [Vulnérabilités Critiques dans le Firmware AMI MegaRAC et les Imprimantes Multifonctions Brother](#vulnerabilites-critiques-dans-le-firmware-ami-megarac-et-les-imprimantes-multifonctions-brother)
    *   [Citrix Bleed 2 : Exploitation Active de Vulnérabilités Critiques dans NetScaler Gateway (CVE-2025-5777 et CVE-2025-6543)](#citrix-bleed-2--exploitation-active-de-vulnerabilites-critiques-dans-netscaler-gateway-cve-2025-5777-et-cve-2025-6543)
    *   [Multiples Failles Critiques dans les Routeurs D-Link DIR-816 (RCE, PAS DE CORRECTIFS)](#multiples-failles-critiques-dans-les-routeurs-d-link-dir-816-rce-pas-de-correctifs)
    *   [Faille Synology ABM (CVE-2025-4679) : Fuite de Secret Client et Exposition des Locataires Microsoft 365](#faille-synology-abm-cve-2025-4679--fuite-de-secret-client-et-exposition-des-locataires-microsoft-365)

## Category : Threats
### Hide Your RDP: Password Spray Leads to RansomHub Deployment
Ce rapport d'incident détaille une intrusion ayant conduit au déploiement du rançongiciel RansomHub. L'attaque a commencé en novembre 2024 par une attaque par pulvérisation de mots de passe ciblant un serveur RDP exposé à Internet. L'acteur de la menace a ensuite utilisé le RDP pour des mouvements latéraux, la découverte de réseau, la récolte d'identifiants à l'aide de Mimikatz et Nirsoft CredentialsFileView, l'installation d'outils RMM (Atera, Splashtop) pour la persistance, et l'exfiltration de données via Rclone sur SFTP. L'opération s'est conclue par le déploiement du rançongiciel, le chiffrement des fichiers, la suppression des clichés instantanés et l'effacement des journaux d'événements. 🔐
*   Publication date : 2025/06/30
*   Source : 🔗 https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/
*   Threat Actor : 👤 RansomHub
*   Threat Tactic : 👾 Pulvérisation de mots de passe, Mouvement latéral RDP, Collecte d'identifiants, Persistance (RMM), Exfiltration de données, Déploiement de rançongiciel
*   Threat Target : 🎯 Serveurs RDP exposés, contrôleurs de domaine, serveurs de sauvegarde, serveurs de fichiers, hyperviseurs
*   Threat Tools : 🛠️ Mimikatz, Nirsoft CredentialsFileView, Advanced IP Scanner, SoftPerfect NetScan, Atera RMM, Splashtop RMM, Rclone, RansomHub ransomware (amd64.exe)
*   MITRE ATT&CK : 🎯 T1110.003 (Password Spraying), T1021.001 (RDP), T1059.003 (Windows Command Shell), T1087.001 (Account Discovery), T1003.001 (LSASS Credential Dumping), T1071.001 (Application Layer Protocol), T1560.001 (Archive via Utility), T1574.008 (Services Registry Permissions Weakness), T1567.002 (Exfiltration Over Web Service), T1486 (Data Encrypted for Impact)
*   Security recommandations : 🛡️ Surveiller les journaux d'événements de sécurité pour les connexions RDP externes, filtrer le protocole RDP et le port 3389, surveiller les modifications des clés de registre pour l'activation RDP, surveiller les paramètres de pare-feu pour l'accès RDP entrant. Inspecter les en-têtes d'e-mail pour identifier les messages de phishing envoyés par abus de "Direct Send". Désactiver "Direct Send" si ce n'est pas strictement nécessaire.
*   FILE_NAME : 📄 nocmd.vbs, rcl.bat, include.txt, amd64.exe, delete[.]me
*   Indicator of Compromise :
    *   IPv4 : 185[.]190[.]24[.]54, 185[.]190[.]24[.]33, 164[.]138[.]90[.]2, 10[.]0[.]2[.]15
    *   DOMAIN : delete[.]me, plan[.]it

## Category : Vulnerabilities
### Multiple Failles Bluetooth dans les Chipsets Airoha : Risque d'Espionnage et RCE
Des vulnérabilités non divulguées, découvertes par les chercheurs d'ERNW, affectent les chipsets Airoha Systems on a Chip (SoCs) largement utilisés dans les écouteurs True Wireless Stereo (TWS) de plus de deux douzaines d'appareils audio de dix fournisseurs. Ces failles pourraient permettre l'écoute clandestine, le vol d'informations sensibles, le détournement de connexion entre le téléphone mobile et un appareil Bluetooth audio, l'émission de commandes au téléphone via le profil HFP (Hands-Free Profile), et potentiellement l'exécution de code à distance (RCE) via une réécriture du firmware, facilitant un exploit de type ver capable de se propager. 👂
*   Publication date : 2025/06/29
*   Source : 🔗 https://www.bleepingcomputer.com/news/security/bluetooth-flaws-could-let-hackers-spy-through-your-microphone/
*   CVE Impacted Product : 📱 Chipsets Airoha SoCs (dans plus de deux douzaines d'appareils audio de dix fournisseurs)
*   CVSS : Non spécifié (impact élevé dû à la RCE et la propagation potentielle)
*   Security recommandations : 🛡️ Mettre à jour le firmware des appareils affectés dès que possible (bien que de nombreux appareils n'aient pas encore reçu les mises à jour nécessaires).

### Vulnérabilité de D-Link DIR-513 : Dépassement de Tampon (CVE-2025-6882)
Une vulnérabilité classée comme critique a été découverte dans D-Link DIR-513 version 1.0. Cette faille, un dépassement de tampon, affecte une partie inconnue du fichier `/goform/formSetWanPPTP` et est déclenchée par la manipulation de l'argument `curTime`. L'attaque peut être initiée à distance, et l'exploit a été divulgué publiquement, le rendant potentiellement utilisable. 🌐
*   Publication date : 2025/06/30
*   Source : 🔗 https://cvefeed.io/vuln/detail/CVE-2025-6882
*   CVE identifier : 🆔 [CVE-2025-6882](https://cve.org/CVERecord?id=CVE-2025-6882)
*   CVE Impacted Product : 💻 D-Link DIR-513 version 1.0 (Produit en fin de vie - EOL)
*   CVSS : 8.8 | HIGH

### Vulnérabilité de D-Link DI-8100 : Dépassement de Tampon PPPoE (CVE-2025-6881)
Une vulnérabilité critique a été identifiée dans D-Link DI-8100 version 16.07.21. Le problème est un dépassement de tampon affectant une fonctionnalité inconnue du fichier `/pppoe_base.asp` du composant `jhttpd`, via la manipulation de l'argument `mschap_en`. L'attaque peut être lancée à distance, et l'exploit a été rendu public et est potentiellement utilisable. 💻
*   Publication date : 2025/06/30
*   Source : 🔗 https://cvefeed.io/vuln/detail/CVE-2025-6881
*   CVE identifier : 🆔 [CVE-2025-6881](https://cve.org/CVERecord?id=CVE-2025-6881)
*   CVE Impacted Product : 💻 D-Link DI-8100 version 16.07.21
*   CVSS : 8.8 | HIGH

### Multiples Vulnérabilités d'Injection SQL Authentifiées dans UISP (CVE-2025-24290)
Plusieurs vulnérabilités d'injection SQL authentifiées ont été découvertes dans l'application UISP (version 2.4.206 et antérieures). Ces failles pourraient permettre à un acteur malveillant disposant de faibles privilèges d'escalader ses privilèges au sein de l'application. SQLi
*   Publication date : 2025/06/29
*   Source : 🔗 https://cvefeed.io/vuln/detail/CVE-2025-24290
*   CVE identifier : 🆔 [CVE-2025-24290](https://cve.org/CVERecord?id=CVE-2025-24290)
*   CVE Impacted Product : 💻 UISP Application (Version 2.4.206 et antérieures)
*   CVSS : 9.9 | CRITICAL

### Vulnérabilité de Traversée de Répertoire WinRAR (CVE-2025-6218)
La vulnérabilité CVE-2025-6218 est une faille de traversée de répertoire découverte dans WinRAR. Elle permet aux attaquants de créer des fichiers d'archive malveillants (par exemple, .rar, .zip) qui, une fois extraits, placent des fichiers en dehors du répertoire d'extraction prévu, potentiellement dans des emplacements système critiques. Bien qu'une interaction utilisateur soit requise, la simplicité d'inciter les utilisateurs à extraire une archive rend l'exploitation de masse plausible via le phishing ou les téléchargements furtifs. 📂
*   Publication date : 2025/06/30
*   Source : 🔗 https://thecyberthrone.in/2025/06/30/cve-2025-6218-winrar-directory-traversal-vulnerability/
*   CVE identifier : 🆔 [CVE-2025-6218](https://cve.org/CVERecord?id=CVE-2025-6218)
*   CVE Impacted Product : 💻 WinRAR (versions non spécifiées, mais implique des versions générales)
*   CVSS : Non spécifié (impact élevé)
*   Security recommandations : 🛡️ Éviter d'extraire des archives provenant de sources non fiables.

### Vulnérabilités Critiques dans le Firmware AMI MegaRAC et les Imprimantes Multifonctions Brother
Un rapport indique que malgré les avertissements, les cybercriminels exploitent activement deux vulnérabilités critiques. La CVE-2024-54085 est une faille dans le firmware AMI MegaRAC (CVSS 10.0) qui permet de contourner l'authentification via un problème avec l'interface Redfish Host. Des milliers de systèmes exposés n'ont pas été patchés. De plus, la CVE-2024-51978 est une vulnérabilité (CVSS 9.8) dans les imprimantes multifonctions (MFP) Brother, permettant à un attaquant de voler le mot de passe administrateur par défaut, généré à partir du numéro de série de l'appareil. Des mises à jour du firmware sont disponibles pour ces appareils, ainsi que pour d'autres MFP affectés de Fujifilm, Ricoh, Toshiba et Konica Minolta. 🔒
*   Publication date : 2025/06/30
*   Source : 🔗 https://go.theregister.com/feed/www.theregister.com/2025/06/30/information_security_in_brief/
*   CVE identifier :
    *   🆔 [CVE-2024-54085](https://cve.org/CVERecord?id=CVE-2024-54085)
    *   🆔 [CVE-2024-51978](https://cve.org/CVERecord?id=CVE-2024-51978)
*   CVE Impacted Product : 💻 AMI MegaRAC firmware, Imprimantes Multifonctions (MFP) Brother, Fujifilm, Ricoh, Toshiba et Konica Minolta
*   CVSS :
    *   10.0 | CRITICAL (pour CVE-2024-54085)
    *   9.8 | CRITICAL (pour CVE-2024-51978)
*   Security recommandations : 🛡️ Appliquer immédiatement les correctifs disponibles pour les systèmes et les imprimantes multifonctions.

### Citrix Bleed 2 : Exploitation Active de Vulnérabilités Critiques dans NetScaler Gateway (CVE-2025-5777 et CVE-2025-6543)
Une nouvelle vulnérabilité, CVE-2025-5777, surnommée "Citrix Bleed 2", suscite de vives inquiétudes de sécurité. ReliaQuest avertit que des attaquants l'exploitent activement pour détourner des sessions utilisateur et contourner l'authentification multi-facteurs (MFA) dans les environnements d'entreprise. Cette faille est une lecture hors-limites dans NetScaler ADC et NetScaler Gateway (CVSS 9.2), permettant d'extraire des jetons d'authentification de la mémoire pour des accès prolongés et polyvalents. Parallèlement, Citrix a également divulgué CVE-2025-6543, une vulnérabilité de déni de service (DoS) avec un CVSS de 9.3, qui serait également exploitée activement. ⚠️
*   Publication date : 2025/06/30
*   Source : 🔗 https://securityonline.info/citrix-bleed-2-reliaquest-warns-of-active-exploitation-in-netscaler-gateway-vulnerability/
*   CVE identifier :
    *   🆔 [CVE-2025-5777](https://cve.org/CVERecord?id=CVE-2025-5777)
    *   🆔 [CVE-2025-6543](https://cve.org/CVERecord?id=CVE-2025-6543)
*   CVE Impacted Product : 💻 NetScaler ADC, NetScaler Gateway
*   CVSS :
    *   9.2 | HIGH (pour CVE-2025-5777)
    *   9.3 | HIGH (pour CVE-2025-6543)
*   Security recommandations : 🛡️ Appliquer immédiatement les correctifs disponibles pour NetScaler ADC et NetScaler Gateway. Surveiller les activités suspectes d'authentification et de session.

### Multiples Failles Critiques dans les Routeurs D-Link DIR-816 (RCE, PAS DE CORRECTIFS)
D-Link a confirmé la découverte de multiples vulnérabilités critiques dans ses routeurs sans fil DIR-816, désormais en fin de vie (EOL). Ces failles, affectant toutes les révisions matérielles et versions de firmware, incluent des dépassements de tampon basés sur la pile et des vulnérabilités d'injection de commandes OS qui pourraient permettre aux attaquants distants d'exécuter du code arbitraire. Les CVEs concernées sont CVE-2025-5622, CVE-2025-5623, CVE-2025-5624, CVE-2025-5630 (CVSS 9.8). Étant donné que le produit est EOL, aucun correctif ne sera publié. 🚫
*   Publication date : 2025/06/30
*   Source : 🔗 https://securityonline.info/d-link-dir-816-router-alert-6-critical-flaws-cvss-9-8-allow-remote-code-execution-no-patches/
*   CVE identifier :
    *   🆔 [CVE-2025-5630](https://cve.org/CVERecord?id=CVE-2025-5630)
    *   🆔 [CVE-2025-5624](https://cve.org/CVERecord?id=CVE-2025-5624)
    *   🆔 [CVE-2025-5623](https://cve.org/CVERecord?id=CVE-2025-5623)
    *   🆔 [CVE-2025-5622](https://cve.org/CVERecord?id=CVE-2025-5622)
*   CVE Impacted Product : 💻 Routeurs D-Link DIR-816 (toutes les révisions matérielles et versions de firmware, produit EOL)
*   CVSS : 9.8 | CRITICAL (pour les CVEs listées)
*   Security recommandations : 🛡️ Remplacer immédiatement les routeurs D-Link DIR-816 par des modèles supportés et patchés.

### Faille Synology ABM (CVE-2025-4679) : Fuite de Secret Client et Exposition des Locataires Microsoft 365
Une vulnérabilité de sécurité dans le logiciel Active Backup for Microsoft 365 (ABM) de Synology (CVE-2025-4679) a exposé les données cloud d'innombrables organisations à un accès non autorisé. La faille a permis aux attaquants d'exploiter des identifiants d'application divulgués pour infiltrer n'importe quel locataire Microsoft ayant ABM installé, sans nécessiter d'accès préalable. Le service middleware `synooauth.synology.com` a divulgué un `client_secret` statique dans une URL de redirection. 🔑
*   Publication date : 2025/06/30
*   Source : 🔗 https://securityonline.info/synology-abm-flaw-cve-2025-4679-leaks-global-client-secret-exposing-all-microsoft-365-tenants/
*   CVE identifier : 🆔 [CVE-2025-4679](https://cve.org/CVERecord?id=CVE-2025-4679)
*   CVE Impacted Product : 💻 Synology Active Backup for Microsoft 365 (ABM)
*   CVSS : Non spécifié (impact critique)
*   Security recommandations : 🛡️ Appliquer les mises à jour de sécurité de Synology dès que possible pour ABM. Vérifier les journaux d'accès aux locataires Microsoft 365 pour toute activité suspecte.
*   Indicator of Compromise :
    *   DOMAIN : synooauth[.]synology[.]com