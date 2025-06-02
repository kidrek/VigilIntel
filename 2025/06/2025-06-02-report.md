# ⚠️Important Vulnerabilities (CVSS > 8)⚠️
* Deux failles dans le logiciel de forum vBulletin sont attaquées
* CVE-2025-5408 - WAVLINK QUANTUM D2G, QUANTUM D3G, WL-WN530G3A, WL-WN530HG3, WL-WN532A3 et WL-WN576K1 HTTP POST Request Handler Buffer Overflow
* CVE-2025-40908 - LibYAML YAML File Modification Vulnerability
* May 2025 Patch Tuesday: Five Zero-Days and Five Critical Vulnerabilities Among 72 CVEs
* Critical Linux Vulnerabilities Expose Password Hashes on Millions of Linux Systems Worldwide
* CISA Alert: Critical Flaws in Consilium Safety CS5000 Fire Panel Could Enable Remote Takeover, No Patch
* Critical RCE Flaws in MICI NetFax Server Unpatched, Vendor Refuses Fix
* NetSPI Details Multiple Local Privilege Escalation Vulnerabilities in SonicWall NetExtender

## Table of Contents
* [Category : Threats](#category--threats)
  * [Meta’s Q1 2025 Report: Dismantling Covert Influence Campaigns from China, Iran, and Romania](#meta-s-q1-2025-report--dismantling-covert-influence-campaigns-from-china--iran--and-romania)
* [Category : Vulnerabilities](#category--vulnerabilities)
  * [Two flaws in vBulletin forum software are under attack](#two-flaws-in-vbulletin-forum-software-are-under-attack)
  * [CVE-2025-5408 - WAVLINK QUANTUM D2G, QUANTUM D3G, WL-WN530G3A, WL-WN530HG3, WL-WN532A3 and WL-WN576K1 HTTP POST Request Handler Buffer Overflow](#cve-2025-5408---wavlink-quantum-d2g--quantum-d3g--wl-wn530g3a--wl-wn530hg3--wl-wn532a3-and-wl-wn576k1-http-post-request-handler-buffer-overflow)
  * [CVE-2025-40908 - LibYAML YAML File Modification Vulnerability](#cve-2025-40908---libyaml-yaml-file-modification-vulnerability)
  * [May 2025 Patch Tuesday: Five Zero-Days and Five Critical Vulnerabilities Among 72 CVEs](#may-2025-patch-tuesday--five-zero-days-and-five-critical-vulnerabilities-among-72-cves)
  * [Critical Linux Vulnerabilities Expose Password Hashes on Millions of Linux Systems Worldwide](#critical-linux-vulnerabilities-expose-password-hashes-on-millions-of-linux-systems-worldwide)
  * [CISA Alert: Critical Flaws in Consilium Safety CS5000 Fire Panel Could Enable Remote Takeover, No Patch](#cisa-alert--critical-flaws-in-consilium-safety-cs5000-fire-panel-could-enable-remote-takeover--no-patch)
  * [Critical RCE Flaws in MICI NetFax Server Unpatched, Vendor Refuses Fix](#critical-rce-flaws-in-mici-netfax-server-unpatched--vendor-refuses-fix)
  * [NetSPI Details Multiple Local Privilege Escalation Vulnerabilities in SonicWall NetExtender](#netspi-details-multiple-local-privilege-escalation-vulnerabilities-in-sonicwall-netextender)

## Category : Threats
### Meta’s Q1 2025 Report: Dismantling Covert Influence Campaigns from China, Iran, and Romania
📰 Meta a démantelé trois campagnes d'influence coordonnées (CIBs) originaires de Chine, d'Iran et de Roumanie au cours du premier trimestre 2025. Ces opérations utilisaient de faux comptes, des personas générés par IA et des récits trompeurs pour manipuler le discours public. La campagne iranienne a ciblé les communautés azerbaïdjanaises et turques, la campagne chinoise s'est concentrée sur le Myanmar, Taïwan et le Japon, et l'opération roumaine visait des audiences locales. Les tactiques incluaient l'utilisation de hashtags populaires et des efforts de OpSec sophistiqués. Meta a publié des indicateurs pour aider la communauté de sécurité.
* Publication date : 2025/06/02
* 🔗 Source : https://securityonline.info/metas-q1-2025-report-dismantling-covert-influence-campaigns-from-china-iran-and-romania/
* 🎭 Threat Actor : Campagnes d'influence (probablement étatiques ou parrainées par l'État) de Chine, d'Iran (lié à STORM-2035), et de Roumanie.
* 🛡️ Threat Tactic : Manipulation du discours public, Utilisation de faux comptes/personas, Opérations d'influence coordonnées (CIB), Ingérence étrangère/nationale.
* 🎯 Threat Target : Audiences sur Facebook, Instagram, X (Twitter), YouTube, TikTok ; communautés locales en Roumanie, communautés azerbaïdjanaises et turques, audiences au Myanmar, à Taïwan et au Japon.
* 🛠️ Threat Tools : Faux comptes, Contenu généré par IA, Sites web dédiés, Utilisation de hashtags, Adresses IP proxy.
* 📜 Indicator of Compromise :
    * DOMAIN: israelboycottvoice[.]com

## Category : Vulnerabilities
### Two flaws in vBulletin forum software are under attack
📰 Deux failles critiques, CVE-2025-48827 (CVSS 10) et CVE-2025-48828, ont été découvertes dans le logiciel de forum vBulletin. La première faille (CVE-2025-48827), classée comme critique (CVSS 10), permet l'abus d'API et l'exécution de code à distance (RCE) sur les versions de PHP 8.1 ou ultérieures. Elle permet à un utilisateur non authentifié d'appeler des méthodes de contrôleur API protégées. Un exploit PoC a été publié publiquement et la faille est activement exploitée dans la nature. Les experts conseillent aux défenseurs et développeurs de revoir leurs cadres et API personnalisés pour s'assurer que les restrictions d'accès sont robustes, en particulier pour les méthodes routées dynamiquement via Reflection, et de tester le comportement sur différentes versions de PHP.
* Publication date : 2025/06/01
* 🔗 Source : https://securityaffairs.com/178481/security/two-flaws-in-vbulletin-forum-software-are-under-attack.html
* 🔥 CVE : CVE-2025-48827 | https://nvd.nist.gov/vuln/detail/CVE-2025-48827, CVE-2025-48828 | https://nvd.nist.gov/vuln/detail/CVE-2025-48828
* 💻 CVE Impacted Poduct : Logiciel de forum vBulletin
* 📊 CVSS : 10
* 📝 Security recommandations : Examiner les cadres et les API personnalisés pour le routage dynamique des méthodes via Reflection. Auditer l'application des restrictions d'accès. Analyser le comportement de l'application sur différentes versions de PHP. Supposer que la visibilité des méthodes seule n'est pas une limite de sécurité.
* 📜 Indicator of Compromise :
    * IPv4: 195[.]3[.]221[.]137

### CVE-2025-5408 - WAVLINK QUANTUM D2G, QUANTUM D3G, WL-WN530G3A, WL-WN530HG3, WL-WN532A3 and WL-WN576K1 HTTP POST Request Handler Buffer Overflow
📰 Une vulnérabilité critique (CVE-2025-5408) a été découverte dans plusieurs routeurs et points d'accès WAVLINK (QUANTUM D2G, QUANTUM D3G, WL-WN530G3A, WL-WN530HG3, WL-WN532A3 et WL-WN576K1 jusqu'à la version V1410_240222). La faille est un débordement de tampon (buffer overflow) dans la fonction `sys_login` du fichier `/cgi-bin/login.cgi` (composant HTTP POST Request Handler), déclenché par la manipulation de l'argument `login_page`. L'attaque peut être lancée à distance. L'exploit a été divulgué publiquement. Le fournisseur n'a pas répondu aux contacts concernant cette divulgation.
* Publication date : 2025/06/01
* 🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-5408
* 🔥 CVE : CVE-2025-5408 | https://nvd.nist.gov/vuln/detail/CVE-2025-5408
* 💻 CVE Impacted Poduct : WAVLINK QUANTUM D2G, QUANTUM D3G, WL-WN530G3A, WL-WN530HG3, WL-WN532A3, WL-WN576K1 (jusqu'à V1410_240222)
* 📊 CVSS : 9.8

### CVE-2025-40908 - LibYAML YAML File Modification Vulnerability
📰 Une vulnérabilité critique (CVE-2025-40908) affecte YAML-LibYAML pour Perl avant la version 0.903.0. Elle est due à l'utilisation de la fonction `open` avec 2 arguments, ce qui permet de modifier des fichiers existants. Cette faille a un score CVSS de 9.1, la classant comme critique.
* Publication date : 2025/06/01
* 🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-40908
* 🔥 CVE : CVE-2025-40908 | https://nvd.nist.gov/vuln/detail/CVE-2025-40908
* 💻 CVE Impacted Poduct : YAML-LibYAML pour Perl (versions antérieures à 0.903.0)
* 📊 CVSS : 9.1
* 📝 Security recommandations : Mettre à jour YAML-LibYAML pour Perl vers la version 0.903.0 ou ultérieure.

### May 2025 Patch Tuesday: Five Zero-Days and Five Critical Vulnerabilities Among 72 CVEs
📰 Microsoft a publié ses mises à jour de sécurité de mai 2025, corrigeant 72 vulnérabilités, dont cinq zero-days activement exploités et cinq vulnérabilités critiques (CVSS >= 8). Parmi les critiques (CVSS >= 8) détaillées, on trouve CVE-2025-29966 et CVE-2025-29967 (CVSS 8.8), des failles d'exécution de code à distance (RCE) dans les services Bureau à distance de Microsoft Windows (client-side, sans authentification ni interaction requise) et CVE-2025-30377 et CVE-2025-30386 (CVSS 8.4), des failles RCE dans Microsoft Office (use-after-free, nécessitant une interaction utilisateur ou via le volet d'aperçu). L'article souligne l'importance de l'application des correctifs et d'une stratégie de sécurité globale.
* Publication date : 2025/06/02
* 🔗 Source : https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-may-2025/
* 🔥 CVE : CVE-2025-29966 | https://cvefeed.io/vuln/detail/CVE-2025-29966, CVE-2025-29967 | https://cvefeed.io/vuln/detail/CVE-2025-29967, CVE-2025-30377 | https://cvefeed.io/vuln/detail/CVE-2025-30377, CVE-2025-30386 | https://cvefeed.io/vuln/detail/CVE-2025-30386
* 💻 CVE Impacted Poduct : Microsoft Windows Remote Desktop Services, Microsoft Office
* 📊 CVSS : 8.8 (CVE-2025-29966, CVE-2025-29967), 8.4 (CVE-2025-30377, CVE-2025-30386)
* 📝 Security recommandations : Appliquer les correctifs Microsoft. Revoir la stratégie de patching. Améliorer la posture de sécurité globale. Planifier la mise à niveau des systèmes Windows 10 en raison de la fin du support.
* 📜 Indicator of Compromise :
    * DOMAIN: countries[.]watch

### Critical Linux Vulnerabilities Expose Password Hashes on Millions of Linux Systems Worldwide
📰 Deux vulnérabilités locales critiques de divulgation d'informations (CVE-2025-5054 et CVE-2025-4598) affectant des millions de systèmes Linux ont été découvertes par Qualys. Ces failles, basées sur des conditions de course (race conditions) dans les gestionnaires de core dump (Apport d'Ubuntu et systemd-coredump utilisé par RHEL 9/10 et Fedora), permettent d'extraire les hachages de mot de passe via la manipulation de core dump, notamment en ciblant le processus `unix_chkpwd`. L'impact potentiel inclut l'escalade de privilèges et le mouvement latéral. Une mitigation immédiate est de définir le paramètre `/proc/sys/fs/suid_dumpable` sur 0 pour désactiver les core dumps pour les programmes SUID.
* Publication date : 2025/06/02
* 🔗 Source : https://cybersecuritynews.com/linux-vulnerabilities-expose-password-hashes/
* 🔥 CVE : CVE-2025-5054 | https://nvd.nist.gov/vuln/detail/CVE-2025-5054, CVE-2025-4598 | https://nvd.nist.gov/vuln/detail/CVE-2025-4598
* 💻 CVE Impacted Poduct : Distributions Linux utilisant Apport (Ubuntu) ou systemd-coredump (Red Hat Enterprise Linux 9 et 10, Fedora)
* 📝 Security recommandations : Définir immédiatement `/proc/sys/fs/suid_dumpable` à 0. Appliquer les correctifs officiels dès qu'ils sont disponibles. Tester les scripts de mitigation fournis par Qualys dans des environnements contrôlés.

### CISA Alert: Critical Flaws in Consilium Safety CS5000 Fire Panel Could Enable Remote Takeover, No Patch
📰 La CISA a émis un avertissement concernant deux vulnérabilités de sécurité critiques (CVE-2025-41438 et CVE-2025-46352) affectant toutes les versions du panneau de contrôle incendie Consilium Safety CS5000. La CVE-2025-41438 concerne un compte par défaut hautement privilégié avec une configuration non sécurisée qui reste souvent inchangée. La CVE-2025-46352 est due à des identifiants codés en dur dans un composant serveur VNC, qui ne peuvent pas être modifiés. L'exploitation réussie de ces failles pourrait permettre à un attaquant distant d'obtenir un accès de haut niveau, de contrôler l'appareil et potentiellement de le rendre non fonctionnel, posant un risque significatif pour les infrastructures critiques de sécurité incendie. Le fournisseur n'a pas encore fourni de correctif.
* Publication date : 2025/06/02
* 🔗 Source : https://securityonline.info/cisa-alert-critical-flaws-in-consilium-safety-cs5000-fire-panel-could-enable-remote-takeover-no-patch/
* 🔥 CVE : CVE-2025-41438 | https://nvd.nist.gov/vuln/detail/CVE-2025-41438, CVE-2025-46352 | https://nvd.nist.gov/vuln/detail/CVE-2025-46352
* 💻 CVE Impacted Poduct : Panneau de contrôle incendie Consilium Safety CS5000 (toutes versions)
* 📝 Security recommandations : Aucune solution de contournement ou mitigation spécifique n'est mentionnée dans le texte de l'article, autre que l'alerte de la CISA signalant le risque et l'absence de correctif.

### Critical RCE Flaws in MICI NetFax Server Unpatched, Vendor Refuses Fix
📰 Des chercheurs de Rapid7 ont découvert un trio de vulnérabilités critiques d'exécution de code à distance (RCE) dans le serveur MICI NetFax (versions < 3.0.1.0). Ces failles (CVE-2025-48047, CVE-2025-48046, CVE-2025-48045) permettent d'obtenir un accès de niveau root via une chaîne d'attaque authentifiée. Un GET request vers `/client.php` expose les identifiants administratifs par défaut en clair (CVE-2025-48047). L'injection de commandes via des backticks dans des paramètres comme `ETHNAMESERVER` permet ensuite une RCE via `/test.php`. Le fournisseur a refusé de corriger les failles, conseillant aux utilisateurs d'éviter l'exposition à Internet.
* Publication date : 2025/06/02
* 🔗 Source : https://securityonline.info/critical-rce-flaws-in-mici-netfax-server-unpatched-vendor-refuses-fix/
* 🔥 CVE : CVE-2025-48047 | https://nvd.nist.gov/vuln/detail/CVE-2025-48047, CVE-2025-48046 | https://nvd.nist.gov/vuln/detail/CVE-2025-48046, CVE-2025-48045 | https://nvd.nist.gov/vuln/detail/CVE-2025-48045
* 💻 CVE Impacted Poduct : MICI Network Co., Ltd.’s NetFax server (versions antérieures à 3.0.1.0)
* 📝 Security recommandations : Éviter l'exposition du serveur NetFax à Internet. Mettre en place une segmentation réseau et des contrôles d'accès.

### NetSPI Details Multiple Local Privilege Escalation Vulnerabilities in SonicWall NetExtender
📰 Des chercheurs de sécurité de NetSPI ont découvert plusieurs vulnérabilités d'escalade de privilèges locale (LPE) à haut risque dans le client VPN SonicWall NetExtender pour Windows (CVE-2025-23009 et CVE-2025-23010). Ces failles, qui font suite à un bug connexe précédent (CVE-2025-23007), pourraient permettre à un utilisateur peu privilégié d'obtenir un accès de niveau SYSTEM ou de perturber les services via des primitives de suppression et d'écrasement de fichiers arbitraires, exploitant la logique des opérations de fichiers dans le service `NEService.exe` (qui s'exécute avec les privilèges SYSTEM) à l'aide de jonctions NTFS et de pseudo-symlinks.
* Publication date : 2025/06/02
* 🔗 Source : https://securityonline.info/netspi-details-multiple-local-privilege-escalation-vulnerabilities-in-sonicwall-netextender/
* 🔥 CVE : CVE-2025-23009 | https://nvd.nist.gov/vuln/detail/CVE-2025-23009, CVE-2025-23010 | https://nvd.nist.gov/vuln/detail/CVE-2025-23010, CVE-2025-23007 | https://nvd.nist.gov/vuln/detail/CVE-2025-23007
* 💻 CVE Impacted Poduct : SonicWall NetExtender VPN client for Windows (versions affectées non spécifiées dans le résumé)
* 📝 Security recommandations : Appliquer les correctifs fournis par SonicWall pour les vulnérabilités CVE-2025-23009 et CVE-2025-23010. S'assurer que les correctifs pour les failles précédentes (comme CVE-2025-23007) sont également appliqués.