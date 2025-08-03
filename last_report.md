# Table des matières
* [Analyse transversale](#analyse-transversale)
* [Synthèses](#syntheses)
  * [Synthèse des vulnérabilités](#synthese-des-vulnerabilites)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Articles sélectionnés](#articles-selectionnes)
  * [Articles non sélectionnés](#articles-non-selectionnes)
* [Articles](#articles)
  * [Akira Ransomware targets SonicWall VPNs in likely zero-day attacks](#akira-ransomware-targets-sonicwall-vpns-in-likely-zero-day-attacks)
  * [China Presses Nvidia Over Alleged Backdoors in H20 Chips Amid Tech Tensions](#china-presses-nvidia-over-alleged-backdoors-in-h20-chips-amid-tech-tensions)
  * [CrowdStrike Detects and Blocks Initial SharePoint Zero-Day Exploitation](#crowdstrike-detects-and-blocks-initial-sharepoint-zero-day-exploitation)
  * [CrowdStrike Falcon Prevents Supply Chain Attack Involving Compromised NPM Packages](#crowdstrike-falcon-prevents-supply-chain-attack-involving-compromised-npm-packages)
  * [New Linux backdoor Plague bypasses auth via malicious PAM module](#new-linux-backdoor-plague-bypasses-auth-via-malicious-pam-module)
  * [Preventing Container Escape Attempts with Falcon Cloud Security's Enhanced Runtime Capabilities](#preventing-container-escape-attempts-with-falcon-cloud-securitys-enhanced-runtime-capabilities)

<br/>
<br/>
<div id="analyse-transversale"></div>

# Analyse transversale
L'analyse des articles de cette veille met en lumière plusieurs tendances et menaces cyber émergentes et persistantes. Les menaces clés observées incluent l'exploitation active de vulnérabilités zero-day, la persistance des attaques sur la chaîne d'approvisionnement logicielle, l'évolution des tactiques de ransomware, les menaces spécifiques aux environnements cloud et Linux, ainsi que les implications géopolitiques croissantes dans la cybersécurité.

Les incidents notables sont marqués par l'exploitation de **vulnérabilités zero-day**, comme celles ciblant les VPN SonicWall par le groupe de ransomware Akira, et les vulnérabilités multiples affectant Microsoft SharePoint. Ces attaques soulignent la réactivité et la sophistication des acteurs malveillants, capables de cibler des systèmes même entièrement patchés.

Les **attaques sur la chaîne d'approvisionnement** restent une préoccupation majeure, illustrée par la compromission de packages NPM populaires via le phishing de mainteneurs, menant à la distribution de malwares comme "Scavenger". Cette tactique permet aux attaquants d'atteindre un grand nombre de victimes en tirant parti de la confiance dans les écosystèmes logiciels légitimes.

L'utilisation de l'**IA** ne se manifeste pas directement comme une technique d'attaque dans les articles sélectionnés, mais les puces IA deviennent un point de tension géopolitique, avec des allégations de "backdoors" dans les puces Nvidia, ce qui soulève des questions de sécurité nationale et de souveraineté technologique.

Les **systèmes Linux et les environnements conteneurisés** sont des cibles privilégiées, comme le montre la découverte de la backdoor "Plague" qui contourne l'authentification PAM sur Linux, ou l'analyse des techniques d'évasion de conteneurs dans le cloud. Ces menaces exigent une attention particulière aux configurations et à la surveillance comportementale.

Enfin, la **vulnérabilités liées à l'authentification et aux élévations de privilèges** restent courantes et critiques, touchant des produits variés comme WordPress ou OpenNebula, offrant des portes d'entrée ou des moyens de persistance aux attaquants.

En conclusion, l'état général des menaces est marqué par une intensification des attaques sophistiquées, notamment les zero-days et les compromissions de la chaîne d'approvisionnement, nécessitant une vigilance constante, des stratégies de défense en profondeur robustes et une conscience accrue des dynamiques géopolitiques impactant le cyberespace.

<br>
<br>
<div id="syntheses"></div>

# Synthèses

## Synthèse des vulnérabilités

<div id="synthese-des-vulnerabilites"></div>

Voici un tableau récapitulatif des vulnérabilités identifiées, classées par ordre de criticité (score CVSS).

| CVE-ID | Score CVSS | Produit affecté | Type de vulnérabilité | Source de l'article | 
|:---|:---|:---|:---|:---|
| CVE-2025-7710 | 9.8 | Brave Conversion Engine (PRO) plugin for WordPress | Authentication Bypass | https://cvefeed.io/vuln/detail/CVE-2025-7710 |
| CVE-2025-53399 | 9.3 | Rtpengine | RTP Inject / RTP Bleed (Execution de code à distance / Injection) | https://seclists.org/fulldisclosure/2025/Aug/1 |
| CVE-2025-53770 | Critical | Microsoft SharePoint Server 2016, 2019 Core, Subscription Edition | Remote Code Execution | https://www.crowdstrike.com/en-us/blog/crowdstrike-detects-blocks-sharepoint-zero-day-exploitation/ |
| CVE-2025-54313 | High | eslint-config-prettier (NPM package) | Supply Chain Compromise (Distribution de Malware) | https://www.crowdstrike.com/en-us/blog/crowdstrike-falcon-prevents-npm-package-supply-chain-attacks/ |
| CVE-2025-54351 | 8.9 | Iperf | Buffer Overflow | https://cvefeed.io/vuln/detail/CVE-2025-54351 |
| CVE-2025-6754 | 8.8 | SEO Metrics plugin for WordPress | Privilege Escalation | https://cvefeed.io/vuln/detail/CVE-2025-6754 |
| CVE-2025-54955 | 8.1 | OpenNebula Community Edition (CE) before 7.0.0 and Enterprise Edition (EE) before 6.10.3 | JWT Authentication Bypass / Race Condition (Account Takeover) | https://cvefeed.io/vuln/detail/CVE-2025-54955 |
| CVE-2025-53771 | N/A | Microsoft SharePoint Server 2016, 2019 Core, Subscription Edition | Server Spoofing | https://www.crowdstrike.com/en-us/blog/crowdstrike-detects-blocks-sharepoint-zero-day-exploitation/ |

<br>
<br>
<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants
Voici un tableau récapitulatif des acteurs malveillants identifiés :

| Nom de l'acteur | Secteur d'activité ciblé | Mode opératoire privilégié | Source de l'article |
|:---|:---|:---|:---|
| Akira ransomware | Éducation, Finance, Immobilier | Exploitation de zero-day (SonicWall VPN), rançongiciels, Linux encryptor (VMware ESXi) | https://securityaffairs.com/180724/cyber-crime/akira-ransomware-targets-sonicwall-vpns-in-likely-zero-day-attacks.html |

<br/>
<br/>
<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| Akira Ransomware targets SonicWall VPNs in likely zero-day attacks | Article d'analyse d'incident, ciblage d'un groupe de ransomware actif et exploitation de vulnérabilités zero-day. | https://securityaffairs.com/180724/cyber-crime/akira-ransomware-targets-sonicwall-vpns-in-likely-zero-day-attacks.html |
| China Presses Nvidia Over Alleged Backdoors in H20 Chips Amid Tech Tensions | Article traitant de tensions géopolitiques et de préoccupations en matière de supply chain et de sécurité nationale liées aux technologies d'IA. | https://securityaffairs.com/180694/intelligence/china-presses-nvidia-over-alleged-backdoors-in-h20-chips-amid-tech-tensions.html |
| CrowdStrike Detects and Blocks Initial SharePoint Zero-Day Exploitation | Rapport d'incident détaillé sur l'exploitation active de vulnérabilités zero-day, incluant des informations sur les TTPs et les mesures de détection. | https://www.crowdstrike.com/en-us/blog/crowdstrike-detects-blocks-sharepoint-zero-day-exploitation/ |
| CrowdStrike Falcon Prevents Supply Chain Attack Involving Compromised NPM Packages | Analyse d'une campagne malveillante axée sur une attaque de la chaîne d'approvisionnement via des packages NPM compromis, décrivant les méthodes d'attaque et d'impact. | https://www.crowdstrike.com/en-us/blog/crowdstrike-falcon-prevents-npm-package-supply-chain-attacks/ |
| New Linux backdoor Plague bypasses auth via malicious PAM module | Analyse technique approfondie d'une nouvelle backdoor ciblant les systèmes Linux, décrivant ses fonctionnalités de persistance et d'évasion. | https://securityaffairs.com/180701/malware/new-linux-backdoor-plague-bypasses-auth-via-malicious-pam-module.html |
| Preventing Container Escape Attempts with Falcon Cloud Security's Enhanced Runtime Capabilities | Rapport technique sur une catégorie de menaces critiques (évasion de conteneurs) dans les environnements cloud, avec analyse des vecteurs d'attaque et des défenses. | https://www.crowdstrike.com/en-us/blog/preventing-container-escape-attempts-falcon-cloud-runtime-security/ |

<br/>
<br/>
<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre de l'article | Raison | Source/Url |
|:---|:---|:---|
| Anthropic says OpenAI engineers using Claude Code ahead of GPT-5 launch | Actualité sur l'IA et les relations entre entreprises, sans incident cyber direct ou analyse de menace. | https://www.bleepingcomputer.com/news/artificial-intelligence/anthropic-says-openai-engineers-using-claude-code-ahead-of-gpt-5-launch/ |
| CVE-2025-54351 - Iperf Buffer Overflow | Article de pure actualité CVE, sans contexte d'incident ou d'acteur de la menace. | https://cvefeed.io/vuln/detail/CVE-2025-54351 |
| CVE-2025-54955 - OpenNebula FireEdge JWT Authentication Bypass | Article de pure actualité CVE, sans contexte d'incident ou d'acteur de la menace. | https://cvefeed.io/vuln/detail/CVE-2025-54955 |
| CVE-2025-6754 - "WordPress SEO Metrics Privilege Escalation" | Article de pure actualité CVE, sans contexte d'incident ou d'acteur de la menace. | https://cvefeed.io/vuln/detail/CVE-2025-6754 |
| CVE-2025-7710 - "Brave Conversion Engine WordPress Facebook Authentication Bypass" | Article de pure actualité CVE, sans contexte d'incident ou d'acteur de la menace. | https://cvefeed.io/vuln/detail/CVE-2025-7710 |
| OpenAI prepares new open weight models along with GPT-5 | Actualité sur les développements de l'IA, sans incident cyber direct ou analyse de menace. | https://www.bleepingcomputer.com/news/artificial-intelligence/openai-prepares-new-open-weight-models-along-with-gpt-5/ |
| Rtpengine: RTP Inject and RTP Bleed vulnerabilities despite proper configuration (CVSS v4.0 Score: 9.3 / Critical) | Article de pure actualité CVE, sans contexte d'incident ou d'acteur de la menace. | https://seclists.org/fulldisclosure/2025/Aug/1 |
| SECURITY AFFAIRS MALWARE NEWSLETTER ROUND 56 | Newsletter agrégée, ne présentant pas une analyse originale d'un incident ou d'un acteur. | https://securityaffairs.com/180717/malware/security-affairs-malware-newsletter-round-56.html |
| Security Affairs newsletter Round 535 by Pierluigi Paganini – INTERNATIONAL EDITION | Newsletter agrégée, ne présentant pas une analyse originale d'un incident ou d'un acteur. | https://securityaffairs.com/180711/breaking-news/security-affairs-newsletter-round-535-by-pierluigi-paganini-international-edition.html |

<br>
<br>
<div id="articles"></div>

# ARTICLES

<div id="akira-ransomware-targets-sonicwall-vpns-in-likely-zero-day-attacks"></div>

## Akira Ransomware targets SonicWall VPNs in likely zero-day attacks

### Résumé de l’attaque (type, cible, méthode, impact)
Le groupe de ransomware Akira cible les VPN SonicWall en exploitant ce qui semble être des vulnérabilités zero-day, y compris sur des appareils entièrement patchés et configurés avec MFA et rotation des identifiants. Plusieurs intrusions ont été observées fin juillet 2025, avec une recrudescence d'activité depuis le 15 juillet 2025. Les attaquants utilisent souvent des hébergements VPS pour les connexions VPN, contrastant avec les accès légitimes. Le groupe Akira, actif depuis mars 2023, cible divers secteurs (éducation, finance, immobilier) et a développé un chiffreur Linux pour les serveurs VMware ESXi.

### Groupe ou acteur malveillant identifié (si applicable)
Akira ransomware

### Indicateurs de compromission (IoCs) : domaines, IP, fichiers, etc. (sous forme de liste si présents)
*   Aucun IoC spécifique n'est fourni, à part la mention de l'utilisation de VPS hosting pour les logins VPN.

### Tactiques, Techniques et Procédures (TTP) utilisées selon MITRE ATT&CK (si mentionnées)
*   **Initial Access**: Exploitation de vulnérabilités (potentielle zero-day) dans les VPN SonicWall, potentiellement associée à des attaques de force brute ou de credential stuffing.
*   **Defense Evasion**: Compromission de systèmes même avec MFA activé et identifiants renouvelés.
*   **Impact**: Data Encryption for Impact (utilisation de rançongiciels).

### Analyse de l’impact (sur les secteurs visés, potentiel géographique ou stratégique)
L'impact est significatif en raison de l'exploitation de zero-days sur des infrastructures VPN critiques (SonicWall), ce qui permet des compromissions initiales même sur des systèmes à jour. Le ciblage de multiples secteurs (éducation, finance, immobilier) indique une approche opportuniste et un risque de perturbation étendue. La capacité à chiffrer les serveurs VMware ESXi avec un chiffreur Linux montre une sophistication et une adaptation aux environnements d'entreprise modernes.

### Recommandations de détection ou de mitigation (concrètes et opérationnelles)
*   Activer les services de sécurité tels que Botnet Protection sur les VPN SonicWall.
*   Appliquer l'authentification multifacteur (MFA) pour tous les accès à distance.
*   Supprimer les comptes firewall inutilisés.
*   Mettre à jour régulièrement les mots de passe.
*   Envisager de bloquer l'authentification VPN provenant d'ASNs liés à l'hébergement pour limiter l'exposition, bien que cela puisse impacter les opérations légitimes.

### Source (url) du ou des articles
*   https://securityaffairs.com/180724/cyber-crime/akira-ransomware-targets-sonicwall-vpns-in-likely-zero-day-attacks.html

<div id="china-presses-nvidia-over-alleged-backdoors-in-h20-chips-amid-tech-tensions"></div>

## China Presses Nvidia Over Alleged Backdoors in H20 Chips Amid Tech Tensions

### Résumé de l’attaque (type, cible, méthode, impact)
Le régulateur chinois de l'internet a convoqué Nvidia concernant des préoccupations de sécurité autour de ses puces H20 AI, conçues pour le marché chinois. Des experts américains en IA affirment que ces puces pourraient contenir des fonctionnalités de suivi, de localisation et d'arrêt à distance, potentiellement exploitables pour surveiller ou désactiver des systèmes chinois. Cette démarche intervient alors que les États-Unis avaient récemment levé une interdiction d'exportation de puces avancées vers la Chine, et reflète les tensions technologiques croissantes entre les deux pays.

### Groupe ou acteur malveillant identifié (si applicable)
Non applicable (accusation d'intégration de fonctionnalités de surveillance par des acteurs étatiques, pas un groupe d'attaque cyber traditionnel).

### Indicateurs de compromission (IoCs) : domaines, IP, fichiers, etc. (sous forme de liste si présents)
*   Aucun IoC spécifique n'est fourni, car il s'agit d'allégations de fonctionnalités intégrées plutôt que d'un incident d'attaque direct.

### Tactiques, Techniques et Procédures (TTP) utilisées selon MITRE ATT&CK (si mentionnées)
*   **Supply Chain Compromise**: T1195.001 (Compromise Software Supply Chain), concernant l'intégration de "backdoors" dans le matériel/logiciel avant la distribution.
*   **Backdoor**: T1197 (Backdoor), si les allégations de fonctionnalités de suivi et d'arrêt à distance sont avérées.

### Analyse de l’impact (sur les secteurs visés, potentiel géographique ou stratégique)
L'impact est potentiellement majeur et stratégique, touchant la souveraineté technologique et la sécurité nationale de la Chine. Si les allégations sont fondées, cela signifie une vulnérabilité inhérente aux infrastructures critiques et aux systèmes d'IA chinois, pouvant entraîner une surveillance non autorisée ou une désactivation à distance. Cela met en lumière la militarisation potentielle des technologies et le besoin accru de vigilance sur l'intégrité de la supply chain pour les composants stratégiques.

### Recommandations de détection ou de mitigation (concrètes et opérationnelles)
*   La Chine exige des explications et une documentation de la part de Nvidia, en vertu de ses lois sur la cybersécurité, la sécurité des données et la protection des informations personnelles.
*   Pour d'autres entités, cela souligne l'importance d'une vérification approfondie de l'intégrité de la supply chain, en particulier pour les composants provenant de régions soumises à des tensions géopolitiques ou à des réglementations de contrôle des exportations.

### Source (url) du ou des articles
*   https://securityaffairs.com/180694/intelligence/china-presses-nvidia-over-alleged-backdoors-in-h20-chips-amid-tech-tensions.html

<div id="crowdstrike-detects-and-blocks-initial-sharepoint-zero-day-exploitation"></div>

## CrowdStrike Detects and Blocks Initial SharePoint Zero-Day Exploitation

### Résumé de l’attaque (type, cible, méthode, impact)
CrowdStrike a détecté et bloqué une vague d'exploitations zero-day ciblant Microsoft SharePoint à partir du 18 juillet 2025. Un attaquant inconnu a enchaîné deux vulnérabilités zero-day, une exécution de code à distance critique (CVE-2025-53770) et une usurpation de serveur (CVE-2025-53771), une attaque surnommée "ToolShell". L'exploitation implique une attaque par désérialisation pour écrire un webshell malveillant (.aspx) sur l'hôte, `spinstall0.aspx`, afin de voler les clés IIS Machine, permettant d'autres attaques post-exploitation. Des centaines de tentatives ont été bloquées dans plus de 160 environnements clients.

### Groupe ou acteur malveillant identifié (si applicable)
Adversaire inconnu

### Indicateurs de compromission (IoCs) : domaines, IP, fichiers, etc. (sous forme de liste si présents)
*   Fichiers: `spinstall0.aspx`
*   Domaines: `exprt[.]ai` (mentionné dans le contexte de notation de sévérité ExPRT.AI)

### Tactiques, Techniques et Procédures (TTP) utilisées selon MITRE ATT&CK (si mentionnées)
*   **Initial Access**: T1190 (Exploit Public-Facing Application) - Exploitation de vulnérabilités zero-day dans SharePoint.
*   **Persistence**: T1505.003 (Server Software Component: Web Shell) - Écriture d'un webshell malveillant.
*   **Credential Access**: T1539 (Steal Web Session Cookie) - Vol des clés IIS Machine.
*   **Execution**: PowerShell command execution spawned from SharePoint IIS process.

### Analyse de l’impact (sur les secteurs visés, potentiel géographique ou stratégique)
L'impact est critique et répandu, affectant potentiellement de nombreuses organisations utilisant SharePoint. L'exploitation de zero-days permet un accès initial très efficace et des capacités d'exécution de code à distance, menant au vol de clés d'authentification et à des actions post-exploitation étendues. La détection généralisée par CrowdStrike indique une campagne d'exploitation active et à grande échelle, soulignant la criticité des mises à jour rapides et des défenses comportementales.

### Recommandations de détection ou de mitigation (concrètes et opérationnelles)
*   Appliquer immédiatement les correctifs Microsoft publiés pour Microsoft SharePoint Server 2019 Core, Microsoft SharePoint Server Subscription Edition et Microsoft SharePoint Enterprise Server 2016.
*   Ingérer les journaux du serveur Microsoft IIS dans le SIEM pour une visibilité accrue et pour détecter les actions malveillantes.
*   Pour les clients CrowdStrike Falcon, utiliser les détections comportementales avancées de Falcon Insight XDR et le tableau de bord personnalisé dans Falcon Exposure Management pour identifier les hôtes vulnérables et les tentatives d'exploitation.
*   Déployer des détections comportementales supplémentaires se concentrant sur les activités post-exploitation et les vecteurs d'attaque alternatifs.

### Source (url) du ou des articles
*   https://www.crowdstrike.com/en-us/blog/crowdstrike-detects-blocks-sharepoint-zero-day-exploitation/

<div id="crowdstrike-falcon-prevents-supply-chain-attack-involving-compromised-npm-packages"></div>

## CrowdStrike Falcon Prevents Supply Chain Attack Involving Compromised NPM Packages

### Résumé de l’attaque (type, cible, méthode, impact)
Cinq packages NPM populaires ont été compromis et modifiés pour distribuer une DLL malveillante nommée "Scavenger". Cette attaque de la chaîne d'approvisionnement a été rendue possible suite à une campagne de phishing d'identifiants réussie ciblant un mainteneur de package NPM, utilisant une page de connexion falsifiée et un domaine typosquatté du site NPM. La DLL "Scavenger" exécute une charge utile en deux étapes : un chargeur initial suivi d'un infostealer de deuxième étape qui lit et exfiltre le fichier de configuration `.npmrc` de l'utilisateur (contenant souvent des jetons d'authentification NPM) et cible les données du navigateur (URL visitées, contenu mis en cache).

### Groupe ou acteur malveillant identifié (si applicable)
Adversaire inconnu

### Indicateurs de compromission (IoCs) : domaines, IP, fichiers, etc. (sous forme de liste si présents)
*   Fichiers: DLL malveillante "Scavenger", `rundll32.exe` (spawné par `install.js`).
*   Aucun domaine ou IP spécifique n'est fourni, à l'exception de la mention d'un domaine typosquatté de NPM.

### Tactiques, Techniques et Procédures (TTP) utilisées selon MITRE ATT&CK (si mentionnées)
*   **Initial Access**: T1566.002 (Phishing: Spearphishing Link) - Phishing d'identifiants du mainteneur NPM.
*   **Impact**: T1195.002 (Supply Chain Compromise: Compromise Software Dependencies and Development Tools) - Modification de packages NPM légitimes.
*   **Execution**: `rundll32.exe` execution via `install.js`.
*   **Discovery**: T1083 (File and Directory Discovery) - Lecture du fichier `.npmrc`.
*   **Collection**: T1005 (Data from Local System) - Cible les données du navigateur.
*   **Exfiltration**: Exfiltration de données (NPM tokens, données de navigateur).

### Analyse de l’impact (sur les secteurs visés, potentiel géographique ou stratégique)
L'impact est potentiellement très large et transversal, affectant les développeurs et les organisations utilisant les packages NPM compromis. Le package `eslint-config-prettier` seul compte plus de 30 millions de téléchargements par semaine, ce qui indique une surface d'attaque massive. La compromission de jetons d'authentification NPM peut mener à d'autres attaques sur la chaîne d'approvisionnement ou à l'accès à d'autres ressources. Le vol de données de navigateur représente également un risque important pour la vie privée et la sécurité des utilisateurs individuels.

### Recommandations de détection ou de mitigation (concrètes et opérationnelles)
*   Renforcer la sécurité des comptes des mainteneurs de packages (MFA robuste, détection de phishing).
*   Mettre en œuvre des solutions de sécurité des points de terminaison (EDR) avec des capacités de détection comportementale (comme CrowdStrike Falcon) pour identifier et bloquer l'exécution de DLL malveillantes et les comportements anormaux des processus.
*   Vérifier l'intégrité des packages logiciels utilisés dans les environnements de développement et de production.
*   Sensibiliser les développeurs aux risques de phishing et de typosquatting.

### Source (url) du ou des articles
*   https://www.crowdstrike.com/en-us/blog/crowdstrike-falcon-prevents-npm-package-supply-chain-attacks/

<div id="new-linux-backdoor-plague-bypasses-auth-via-malicious-pam-module"></div>

## New Linux backdoor Plague bypasses auth via malicious PAM module

### Résumé de l’attaque (type, cible, méthode, impact)
Une nouvelle backdoor furtive pour Linux, nommée "Plague", a été découverte par les chercheurs de Nextron Systems. Elle se dissimule en tant que module PAM (Pluggable Authentication Module) malveillant, permettant aux attaquants de contourner l'authentification et de maintenir un accès SSH persistant. "Plague" intègre des fonctionnalités avancées telles que l'anti-débogage, l'obfuscation de chaînes de caractères (de plus en plus complexe au fil des versions), une empreinte de mot de passe statique pour un accès discret, et la capacité d'effacer les artéfacts de session pour éviter la détection (ex: modification des variables d'environnement, redirection de l'historique shell vers `/dev/null`). L'attribution à un groupe d'acteurs est inconnue.

### Groupe ou acteur malveillant identifié (si applicable)
Non attribué (la "Plague" est le nom de la backdoor elle-même, pas d'un groupe d'acteurs).

### Indicateurs de compromission (IoCs) : domaines, IP, fichiers, etc. (sous forme de liste si présents)
*   **Fichiers**: Module PAM malveillant.
*   **Comportements**: Vérification de `ld.so.preload`, renommage du processus, modification des variables d'environnement de session SSH, redirection de l'historique shell vers `/dev/null`.
*   **Contenus**: Chaînes de caractères obfusquées nécessitant une désobfuscation (ex: avec un plugin IDA Pro).

### Tactiques, Techniques et Procédures (TTP) utilisées selon MITRE ATT&CK (si mentionnées)
*   **Persistence**: T1546.006 (Event Triggered Execution: PAM Module) - Installation comme module PAM.
*   **Defense Evasion**: T1027 (Obfuscated Files or Information) - Utilisation d'obfuscation de chaînes. T1070.004 (Indicator Removal on Host: File Deletion) - Effacement des traces de session. T1497 (Virtualization/Sandbox Evasion) - Fonctions anti-débogage (ex: vérification de `ld.so.preload`).
*   **Credential Access**: T1552 (Unsecured Credentials) - Utilisation d'un mot de passe statique pour l'accès furtif.

### Analyse de l’impact (sur les secteurs visés, potentiel géographique ou stratégique)
L'impact est critique pour les infrastructures Linux, car "Plague" permet un contournement d'authentification et une persistance furtive à un niveau système très bas (via PAM). La difficulté de détection due à ses techniques d'évasion avancées (obfuscation, anti-débogage, effacement de traces) en fait une menace sophistiquée et persistante, capable de compromettre la sécurité et l'intégrité des systèmes Linux sur le long terme.

### Recommandations de détection ou de mitigation (concrètes et opérationnelles)
*   Mettre en place des mesures de détection comportementales avancées, car les méthodes conventionnelles sont difficiles.
*   Surveiller les modifications inhabituelles des modules PAM.
*   Utiliser des outils d'analyse statique et dynamique avec des capacités de désobfuscation pour les binaires système.
*   Renforcer la sécurité des accès SSH et surveiller les tentatives de connexion anormale, même si l'authentification est contournée.
*   Effectuer des analyses de l'intégrité des fichiers système critiques.

### Source (url) du ou des articles
*   https://securityaffairs.com/180701/malware/new-linux-backdoor-plague-bypasses-auth-via-malicious-pam-module.html

<div id="preventing-container-escape-attempts-with-falcon-cloud-securitys-enhanced-runtime-capabilities"></div>

## Preventing Container Escape Attempts with Falcon Cloud Security's Enhanced Runtime Capabilities

### Résumé de l’attaque (type, cible, méthode, impact)
L'article analyse les techniques d'évasion de conteneurs, une menace majeure dans les environnements de cloud computing modernes. Les attaquants exploitent des défauts de configuration (ex: API Docker exposées, exécution en mode privilégié), des vulnérabilités d'applications/bibliothèques ou des faiblesses du noyau pour briser l'isolation des conteneurs et accéder au système hôte sous-jacent. Un scénario courant implique l'exploitation d'une API Docker exposée, menant à une compromission complète de l'environnement cloud via des opérations `chroot` pour pivoter du conteneur vers l'hôte.

### Groupe ou acteur malveillant identifié (si applicable)
Adversaires (terme générique, aucun groupe spécifique identifié)

### Indicateurs de compromission (IoCs) : domaines, IP, fichiers, etc. (sous forme de liste si présents)
*   Aucun IoC spécifique n'est fourni, l'article se concentre sur les techniques et les vulnérabilités.

### Tactiques, Techniques et Procédures (TTP) utilisées selon MITRE ATT&CK (si mentionnées)
*   **Initial Access**: T1552.001 (Unsecured Credentials: Exposed API) - Exploitation d'API Docker/Kubernetes exposées. T1190 (Exploit Public-Facing Application) - Exploitation de vulnérabilités dans des applications conteneurisées. T1204 (User Execution) - Via registre d'images compromis.
*   **Privilege Escalation / Defense Evasion**: Techniques d'évasion de conteneurs (par exemple, conteneurs privilégiés, exploitation de vulnérabilités du noyau, montage de systèmes de fichiers hôtes, opérations `chroot`).

### Analyse de l’impact (sur les secteurs visés, potentiel géographique ou stratégique)
L'évasion de conteneurs représente une menace significative car elle permet aux attaquants de dépasser les limites d'isolation d'un conteneur pour compromettre le système hôte, et potentiellement l'ensemble de l'infrastructure cloud. Cela peut entraîner une prise de contrôle totale des comptes et une exfiltration de données massives. L'adoption généralisée des conteneurs rend cette vulnérabilité critique pour toutes les organisations qui déploient des architectures basées sur les microservices et le cloud.

### Recommandations de détection ou de mitigation (concrètes et opérationnelles)
*   **Durcissement des configurations**: Ne pas exécuter de conteneurs en mode privilégié, sécuriser les endpoints des API Docker et Kubernetes, appliquer des contrôles d'accès basés sur les rôles (RBAC) robustes.
*   **Application des correctifs**: Appliquer rapidement les correctifs pour les vulnérabilités des applications, bibliothèques et du noyau.
*   **Sécurité en profondeur**: Utiliser des couches de sécurité additionnelles comme les namespaces Linux, cgroups, Linux capabilities, Seccomp, AppArmor/SELinux.
*   **Détection au runtime**: Utiliser des solutions de sécurité cloud (comme CrowdStrike Falcon Linux sensor) avec des capacités de détection comportementale avancées pour identifier les tentatives d'évasion de conteneurs et les activités suspectes entre conteneurs et hôtes en temps réel.
*   **Surveillance**: Surveiller les lancements de scripts distants non autorisés depuis des serveurs C2 et les opérations `chroot` suspectes.

### Source (url) du ou des articles
*   https://www.crowdstrike.com/en-us/blog/preventing-container-escape-attempts-falcon-cloud-runtime-security/