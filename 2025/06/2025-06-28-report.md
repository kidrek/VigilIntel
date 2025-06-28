# ⚠️Important Vulnerabilities (CVSS > 8)⚠️
*   🎯 Multiple Critical Vulnerabilities in Citrix NetScaler ADC and Gateway
*   🎯 Critical Vulnerability in Open VSX Registry Endangers Developers
*   🎯 Critical RCE Flaws Discovered in Cisco ISE and ISE-PIC
*   🎯 Multiple High and Critical Vulnerabilities in WordPress Plugins
*   🎯 Critical RCE Vulnerability in Dover Fueling Solutions ProGauge MagLink LX Consoles
*   🎯 Critical PHP File Upload Vulnerability in MikoPBX
*   🎯 Multiple Zero-Day Vulnerabilities Impacting Marvell QConvergeConsole
*   🎯 Microsoft June 2025 Patch Tuesday Addresses Zero-Day and Critical Vulnerabilities

## Table of Contents
*   [Category : Vulnerabilities](#category--vulnerabilities)
    *   [Multiple Critical Vulnerabilities in Citrix NetScaler ADC and Gateway](#multiple-critical-vulnerabilities-in-citrix-netscaler-adc-and-gateway)
    *   [Critical Vulnerability in Open VSX Registry Endangers Developers](#critical-vulnerability-in-open-vsx-registry-endangers-developers)
    *   [Critical RCE Flaws Discovered in Cisco ISE and ISE-PIC](#critical-rce-flaws-discovered-in-cisco-ise-and-ise-pic)
    *   [Multiple High and Critical Vulnerabilities in WordPress Plugins](#multiple-high-and-critical-vulnerabilities-in-wordpress-plugins)
    *   [Critical RCE Vulnerability in Dover Fueling Solutions ProGauge MagLink LX Consoles](#critical-rce-vulnerability-in-dover-fueling-solutions-progauge-maglink-lx-consoles)
    *   [Critical PHP File Upload Vulnerability in MikoPBX](#critical-php-file-upload-vulnerability-in-mikopbx)
    *   [Multiple Zero-Day Vulnerabilities Impacting Marvell QConvergeConsole](#multiple-zero-day-vulnerabilities-impacting-marvell-qconvergeconsole)
    *   [Microsoft June 2025 Patch Tuesday Addresses Zero-Day and Critical Vulnerabilities](#microsoft-june-2025-patch-tuesday-addresses-zero-day-and-critical-vulnerabilities)
*   [Category : Threats](#category--threats)
    *   [Scattered Spider Targets Aviation and Transportation Sectors](#scattered-spider-targets-aviation-and-transportation-sectors)
    *   [Retail Giant Ahold Delhaize Suffers Data Breach Affecting 2.2 Million Individuals](#retail-giant-ahold-delhaize-suffers-data-breach-affecting-2.2-million-individuals)
    *   [UNFI Restores Systems After Cyberattack](#unfi-restores-systems-after-cyberattack)
    *   [Hawaiian Airlines Discloses Cyberattack](#hawaiian-airlines-discloses-cyberattack)
    *   [OneClik APT Campaign Targets Energy Sector](#oneclik-apt-campaign-targets-energy-sector)
    *   [APT42 Impersonates Cyber Professionals to Phish Israeli Experts](#apt42-impersonates-cyber-professionals-to-phish-israeli-experts)
    *   [Qilin Ransomware Attack Linked to Patient Death at UK NHS Hospitals](#qilin-ransomware-attack-linked-to-patient-death-at-uk-nhs-hospitals)
*   [Category : Geopolitics](#category--geopolitics)
    *   [Russia Throttles Cloudflare Access Affecting Websites](#russia-throttles-cloudflare-access-affecting-websites)

## Category : Vulnerabilities
### Multiple Critical Vulnerabilities in Citrix NetScaler ADC and Gateway
Plusieurs vulnérabilités critiques, dont une potentiellement exploitée activement (Citrix Bleed 2, CVE-2025-5777), ont été identifiées dans les produits Citrix NetScaler ADC et Gateway. Ces failles pourraient permettre la divulgation de données sensibles, notamment des jetons de session authentifiés via une lecture excessive de mémoire, offrant un accès ultérieur à l'appliance ou aux systèmes. 🚨 La détection d'une augmentation des sessions suspectes sur les appareils Citrix suggère que ces vulnérabilités sont activement ciblées dans des attaques.
*   Publication date : 2025/06/27
*   🔗 Source : https://www.bleepingcomputer.com/news/security/citrix-bleed-2-flaw-now-believed-to-be-exploited-in-attacks/, https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-citrix-products-could-allow-for-disclosure-of-sensitive-data_2025-060
*    CVE : CVE-2025-5777
*   💻 CVE Impacted Product : Citrix NetScaler ADC, Citrix NetScaler Gateway, Citrix ADC
*   ❗ CVSS : non spécifié (mais décrit comme "critique")
*   🛡️ Security recommandations : Surveiller activement les sessions Citrix pour détecter toute activité suspecte. Appliquer les mises à jour et correctifs dès qu'ils sont disponibles pour les produits Citrix NetScaler ADC et Gateway.

### Critical Vulnerability in Open VSX Registry Endangers Developers
Une faille critique a été découverte dans Open VSX Registry (open-vsx.org), le hub d'extensions pour Visual Studio Code. Cette vulnérabilité pourrait permettre à des attaquants de détourner le marché des extensions, exposant des millions de développeurs à des attaques de chaîne d'approvisionnement. 💥
*   Publication date : 2025/06/27
*   🔗 Source : https://securityaffairs.com/179398/hacking/taking-over-millions-of-developers-exploiting-an-open-vsx-registry-flaw.html
*   💻 CVE Impacted Product : Open VSX Registry (open-vsx.org)
*   ❗ CVSS : non spécifié (mais décrit comme "critique")
*   🛡️ Security recommandations : Les développeurs doivent rester vigilants quant aux extensions qu'ils installent et aux mises à jour disponibles pour Open VSX Registry.

### Critical RCE Flaws Discovered in Cisco ISE and ISE-PIC
Deux vulnérabilités critiques (CVE-2025-20281 et CVE-2025-20282) ont été révélées dans Cisco Identity Services Engine (ISE) et ISE Passive Identity Connector (ISE-PIC). Ces failles permettent l'exécution de code à distance (RCE) et l'obtention d'un accès root, représentant une menace significative pour les infrastructures réseau. 🚨
*   Publication date : 2025/06/27
*   🔗 Source : https://socprime.com/blog/cve-2025-20281-and-cve-2025-20282-vulnerabilities/
*   CVE : CVE-2025-20281, CVE-2025-20282
*   💻 CVE Impacted Product : Cisco Identity Services Engine (ISE), Cisco ISE Passive Identity Connector (ISE-PIC)
*   ❗ CVSS : non spécifié (mais décrit comme "critique")
*   🛡️ Security recommandations : Appliquer immédiatement les correctifs fournis par Cisco pour ISE et ISE-PIC afin de prévenir l'exploitation de ces vulnérabilités critiques.

### Multiple High and Critical Vulnerabilities in WordPress Plugins
Plusieurs vulnérabilités critiques et de gravité élevée ont été découvertes dans divers plugins WordPress, permettant des attaques allant de l'exécution de code à distance à l'élévation de privilèges et à la suppression de fichiers arbitraires, pouvant mener à une prise de contrôle complète du site. ⚙️
*   Publication date : 2025/06/28, 2025/06/27
*   🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-6755, https://cvefeed.io/vuln/detail/CVE-2025-5304, https://cvefeed.io/vuln/detail/CVE-2025-6381, https://cvefeed.io/vuln/detail/CVE-2025-6379, https://cvefeed.io/vuln/detail/CVE-2025-53093
*   CVE : CVE-2025-6755, CVE-2025-5304, CVE-2025-6381, CVE-2025-6379, CVE-2025-53093
*   💻 CVE Impacted Product :
    *   CVE-2025-6755 : Plugin WordPress Game Users Share Buttons (versions jusqu'à 1.3.0)
    *   CVE-2025-5304 : Plugin WordPress PT Project Notebooks (versions 1.0.0 à 1.1.3)
    *   CVE-2025-6381 : Plugin WordPress BeeTeam368 Extensions (versions jusqu'à 2.3.4)
    *   CVE-2025-6379 : Plugin WordPress BeeTeam368 Extensions Pro (versions jusqu'à 2.3.4)
    *   CVE-2025-53093 : Extension MediaWiki TabberNeue (versions 3.0.0 à 3.1.0, corrigée en 3.1.1)
*   ❗ CVSS :
    *   CVE-2025-6755 : 8.8 (HIGH)
    *   CVE-2025-5304 : 9.8 (CRITICAL)
    *   CVE-2025-6381 : 8.8 (HIGH)
    *   CVE-2025-6379 : 8.8 (HIGH)
    *   CVE-2025-53093 : 8.6 (HIGH)
*   🛡️ Security recommandations : Mettre à jour immédiatement tous les plugins WordPress concernés vers les dernières versions stables. Pour TabberNeue, la version 3.1.1 corrige la vulnérabilité XSS.

### Critical RCE Vulnerability in Dover Fueling Solutions ProGauge MagLink LX Consoles
Une vulnérabilité critique (CVE-2025-5310) a été identifiée dans les consoles ProGauge MagLink LX de Dover Fueling Solutions. Cette faille expose une interface de communication non documentée et non authentifiée sur un port spécifique, permettant la création, la suppression ou la modification de fichiers, et potentiellement l'exécution de code à distance. ⛽
*   Publication date : 2025/06/27
*   🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-5310
*   CVE : CVE-2025-5310
*   💻 CVE Impacted Product : Dover Fueling Solutions ProGauge MagLink LX Consoles
*   ❗ CVSS : 9.8 (CRITICAL)
*   🛡️ Security recommandations : Isoler ces consoles des réseaux non sécurisés, restreindre l'accès au port vulnérable et surveiller toute activité anormale. Contacter le fournisseur pour des correctifs ou des mesures d'atténuation.

### Critical PHP File Upload Vulnerability in MikoPBX
Une vulnérabilité critique (CVE-2025-52207) a été découverte dans MikoPBX (versions jusqu'à 2024.1.114). Cette faille permet de télécharger un script PHP dans un répertoire arbitraire via `PBXCoreREST/Controllers/Files/PostController.php`, ce qui peut conduire à une exécution de code à distance. 📞
*   Publication date : 2025/06/27
*   🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-52207
*   CVE : CVE-2025-52207
*   💻 CVE Impacted Product : MikoPBX (versions jusqu'à 2024.1.114)
*   ❗ CVSS : 9.9 (CRITICAL)
*   🛡️ Security recommandations : Mettre à jour MikoPBX vers une version corrigée et restreindre les permissions d'écriture sur les répertoires sensibles.

### Multiple Zero-Day Vulnerabilities Impacting Marvell QConvergeConsole
Plusieurs vulnérabilités zero-day, dont la plupart sont critiques, ont été découvertes dans Marvell QConvergeConsole. Ces failles (CVE-2025-6809, CVE-2025-6808, CVE-2025-6802) permettent l'exécution de code à distance sans authentification. D'autres (CVE-2025-6806, CVE-2025-6805, CVE-2025-6801) permettent l'écriture ou la suppression arbitraire de fichiers via des traversées de répertoire, également sans authentification. 💾
*   Publication date : 2025/06/27
*   🔗 Source : http://www.zerodayinitiative.com/advisories/ZDI-25-466/, http://www.zerodayinitiative.com/advisories/ZDI-25-465/, http://www.zerodayinitiative.com/advisories/ZDI-25-464/, http://www.zerodayinitiative.com/advisories/ZDI-25-462/, http://www.zerodayinitiative.com/advisories/ZDI-25-461/, http://www.zerodayinitiative.com/advisories/ZDI-25-460/
*   CVE : CVE-2025-6809, CVE-2025-6808, CVE-2025-6802, CVE-2025-6806, CVE-2025-6805, CVE-2025-6801
*   💻 CVE Impacted Product : Marvell QConvergeConsole
*   ❗ CVSS :
    *   CVE-2025-6809 : 9.8 (CRITICAL)
    *   CVE-2025-6808 : 9.8 (CRITICAL)
    *   CVE-2025-6802 : 9.8 (CRITICAL)
    *   CVE-2025-6806 : 8.2 (HIGH)
    *   CVE-2025-6805 : 8.2 (HIGH)
    *   CVE-2025-6801 : 8.2 (HIGH)
*   🛡️ Security recommandations : Limiter l'exposition des consoles Marvell QConvergeConsole aux réseaux externes. Appliquer toutes les mises à jour et correctifs dès qu'ils sont disponibles. Mettre en œuvre une surveillance stricte pour détecter toute activité suspecte liée à l'exécution de code ou aux modifications de fichiers.

### Microsoft June 2025 Patch Tuesday Addresses Zero-Day and Critical Vulnerabilities
La mise à jour de sécurité de juin 2025 de Microsoft, publiée lors du Patch Tuesday, a corrigé un total de 66 vulnérabilités. Parmi celles-ci, une vulnérabilité zero-day est activement exploitée, et neuf vulnérabilités sont classées comme critiques. 🛡️ Ces correctifs couvrent diverses failles qui pourraient permettre des exécutions de code à distance, des élévations de privilèges ou d'autres impacts sévères.
*   Publication date : 2025/06/28
*   🔗 Source : https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-june-2025/
*   CVE : CVE-2025-47953, CVE-2025-47172, CVE-2025-47167, CVE-2025-47164, CVE-2025-47162, CVE-2025-33073, CVE-2025-33071, CVE-2025-33070, CVE-2025-33053, CVE-2025-32710, CVE-2025-29828
*   💻 CVE Impacted Product : Produits Microsoft variés
*   ❗ CVSS : non spécifié individuellement pour chaque CVE, mais neuf sont "critiques" et une est une "zero-day activement exploitée".
*   🛡️ Security recommandations : Appliquer immédiatement toutes les mises à jour du Patch Tuesday de juin 2025 sur tous les systèmes Microsoft concernés.

## Category : Threats
### Scattered Spider Targets Aviation and Transportation Sectors
Le groupe de hackers Scattered Spider, connu pour ses tactiques d'ingénierie sociale et d'accès initial, a étendu ses cibles aux industries de l'aviation et du transport, après avoir précédemment visé les secteurs de l'assurance et de la vente au détail. 🕷️ Ce changement de cible indique une diversification des opérations du groupe et une menace accrue pour les infrastructures critiques.
*   Publication date : 2025/06/27
*   🎭 Threat Actor : Scattered Spider
*   🎯 Threat Target : Aviation, transport, assurance, vente au détail

### Retail Giant Ahold Delhaize Suffers Data Breach Affecting 2.2 Million Individuals
Ahold Delhaize, une chaîne de distribution alimentaire mondiale majeure, a notifié plus de 2,2 millions de personnes que leurs informations personnelles, financières et de santé ont été volées lors d'une attaque par rançongiciel en novembre 2024 qui a impacté ses systèmes américains. 💰
*   Publication date : 2025/06/27
*   🎯 Threat Target : Ahold Delhaize (détail alimentaire), 2.2 millions d'individus
*   💥 Threat Tactic : Attaque par rançongiciel, vol de données

### UNFI Restores Systems After Cyberattack
United Natural Foods (UNFI), un géant américain de la vente en gros de produits d'épicerie, a annoncé avoir restauré ses systèmes essentiels et remis en ligne les systèmes de commande électronique et de facturation affectés par une cyberattaque. 🛒
*   Publication date : 2025/06/27
*   🎯 Threat Target : United Natural Foods (UNFI)
*   💥 Threat Tactic : Cyberattaque (non spécifiée, affectant les systèmes de commande et de facturation)

### Hawaiian Airlines Discloses Cyberattack
Hawaiian Airlines, la dixième plus grande compagnie aérienne commerciale des États-Unis, a annoncé enquêter sur une cyberattaque qui a perturbé l'accès à certains de ses systèmes. Les opérations de vol n'ont pas été affectées. ✈️
*   Publication date : 2025/06/27
*   🎯 Threat Target : Hawaiian Airlines
*   💥 Threat Tactic : Cyberattaque (non spécifiée)

### OneClik APT Campaign Targets Energy Sector
Une nouvelle campagne APT, nommée OneClik, probablement menée par un acteur lié à la Chine, cible les secteurs de l'énergie, du pétrole et du gaz. Cette campagne utilise la technologie de déploiement ClickOnce de Microsoft et des backdoors Golang personnalisées pour des attaques furtives. ⛽
*   Publication date : 2025/06/27
*   🎭 Threat Actor : OneClik (acteur lié à la Chine)
*   🎯 Threat Target : Secteurs de l'énergie, du pétrole et du gaz
*   💥 Threat Tactic : Utilisation de Microsoft ClickOnce, déploiement de backdoors
*   🛠️ Threat Tools : Backdoors Golang, Microsoft ClickOnce

### APT42 Impersonates Cyber Professionals to Phish Israeli Experts
Le groupe APT42 (également connu sous les noms d'Educated Manticore, Charming Kitten et Mint Sandstorm), lié à l'Iran, cible des journalistes, des experts en cybersécurité et des universitaires israéliens. Le groupe utilise des attaques de phishing en se faisant passer pour des professionnels de la sécurité afin de voler les identifiants de messagerie et les codes 2FA. 🕵️
*   Publication date : 2025/06/27
*   🎭 Threat Actor : APT42 (Educated Manticore, Charming Kitten, Mint Sandstorm) (Iran-linked)
*   🎯 Threat Target : Journalistes israéliens, experts en cybersécurité, universitaires
*   💥 Threat Tactic : Phishing, ingénierie sociale (usurpation d'identité), vol de credentials, contournement de 2FA
*   🛠️ Threat Tools : Phishing

### Qilin Ransomware Attack Linked to Patient Death at UK NHS Hospitals
Un décès de patient a été officiellement lié à une cyberattaque menée par le groupe de rançongiciel Qilin, qui a paralysé les services de pathologie de plusieurs grands hôpitaux du NHS à Londres l'année dernière. 💔
*   Publication date : 2025/06/28
*   🎭 Threat Actor : Groupe de rançongiciel Qilin
*   🎯 Threat Target : Hôpitaux du NHS à Londres
*   💥 Threat Tactic : Attaque par rançongiciel, perturbation des services de pathologie
*   🛠️ Threat Tools : Rançongiciel Qilin
*   CVE : CVE-2019-19781 (mentionnée dans l'article, mais sans lien direct avec l'exploitation spécifique dans cette attaque par Qilin)

## Category : Geopolitics
### Russia Throttles Cloudflare Access Affecting Websites
Depuis le 9 juin 2025, les fournisseurs d'accès internet (FAI) russes ont commencé à restreindre l'accès aux sites web et services protégés par Cloudflare. Cette mesure rend inaccessibles de nombreux sites pour les utilisateurs russes, affectant la connectivité globale. 🇷🇺🌐
*   Publication date : 2025/06/27
*   🎭 Threat Actor : Fournisseurs d'accès Internet russes (potentiellement dirigés par l'État)
*   🎯 Threat Target : Sites web et services protégés par Cloudflare en Russie
*   💥 Threat Tactic : Limitation de l'accès (throttling)