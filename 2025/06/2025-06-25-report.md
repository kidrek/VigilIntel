# ⚠️Important Vulnerabilities (CVSS > 8)⚠️
* 🚨 Vulnérabilités Critiques multiples dans Citrix NetScaler ADC et Gateway
* 🚨 Vulnérabilité XSS dans Discourse via les Connexions Sociales
* 🚨 Vulnérabilité dans Cyberduck et Mountain Duck affectant le Certificate Pinning TLS
* 🚨 Divulgation du Mot de Passe Administrateur par Défaut dans les Imprimantes Brother/Konica Minolta
* 🚨 Vulnérabilité d'Escalade de Privilèges dans IBM Facsimile Support for i
* 🚨 Vulnérabilités Critiques multiples dans Hikka Telegram Userbot
* 🚨 Vulnérabilité d'Exécution de Code Arbitraire dans KnowledgeGPT
* 🚨 Vulnérabilité Critique dans Elastic Kibana permettant RCE et Corruption de Heap

## Table of Contents
* [Category : Vulnerabilities](#category--vulnerabilities)
    * [Vulnérabilités Critiques multiples dans Citrix NetScaler ADC et Gateway](#vulnérabilités-critiques-multiples-dans-citrix-netscaler-adc-et-gateway)
    * [Vulnérabilité XSS dans Discourse via les Connexions Sociales](#vulnérabilité-xss-dans-discourse-via-les-connexions-sociales)
    * [Vulnérabilité dans Cyberduck et Mountain Duck affectant le Certificate Pinning TLS](#vulnérabilité-dans-cyberduck-et-mountain-duck-affectant-le-certificate-pinning-tls)
    * [Divulgation du Mot de Passe Administrateur par Défaut dans les Imprimantes Brother/Konica Minolta](#divulgation-du-mot-de-passe-administrateur-par-défaut-dans-les-imprimantes-brotherkonica-minolta)
    * [Vulnérabilité d'Escalade de Privilèges dans IBM Facsimile Support for i](#vulnérabilité-descalade-de-privilèges-dans-ibm-facsimile-support-for-i)
    * [Vulnérabilités Critiques multiples dans Hikka Telegram Userbot](#vulnérabilités-critiques-multiples-dans-hikka-telegram-userbot)
    * [Vulnérabilité d'Exécution de Code Arbitraire dans KnowledgeGPT](#vulnérabilité-dexécution-de-code-arbitraire-dans-knowledgegpt)
    * [Vulnérabilité Critique dans Elastic Kibana permettant RCE et Corruption de Heap](#vulnérabilité-critique-dans-elastic-kibana-permettant-rce-et-corruption-de-heap)
* [Category : Threats](#category--threats)
    * [Arrestations Signalées des Opérateurs du Forum de Hacking BreachForums](#arrestations-signalées-des-opérateurs-du-forum-de-hacking-breachforums)
    * [Alerte concernant un Client SonicWall NetExtender Trojanisé Volant des Identifiants VPN](#alerte-concernant-un-client-sonicwall-netextender-trojanisé-volant-des-identifiants-vpn)
    * [Phishing OAuth Microsoft Entra ID et Détections](#phishing-oauth-microsoft-entra-id-et-détections)
    * [Cyberattaques ciblant les PME en 2025 : Tendances et Techniques](#cyberattaques-ciblant-les-pme-en-2025--tendances-et-techniques)
    * [Violation de Données chez Mainline Health Systems](#violation-de-données-chez-mainline-health-systems)
    * [Hausse d'Activité du Botnet Prometei](#hausse-dactivité-du-botnet-prometei)
    * [Le Groupe APT28 (UAC-0001) Cible les Entités Gouvernementales Ukrainiennes via Phishing et Malware](#le-groupe-apt28-uac-0001-cible-les-entités-gouvernementales-ukrainiennes-via-phishing-et-malware)
    * [Le Groupe APT Salt Typhoon lié à la Chine Cible les Entreprises de Télécommunications Canadiennes](#le-groupe-apt-salt-typhoon-lié-à-la-chine-cible-les-entreprises-de-télécommunications-canadiennes)
    * [Avertissement Américain sur les Cybermenaces Potentielles suite aux Frappes contre l'Iran](#avertissement-américain-sur-les-cybermenaces-potentielles-suite-aux-frappes-contre-liran)
    * [Violation de Données chez Robinsons Malls](#violation-de-données-chez-robinsons-malls)
    *   [Violation de Données chez Have Fun Teaching](#violation-de-données-chez-have-fun-teaching)
    * [Abus Cybercriminel des Modèles de Langage Large (LLMs)](#abus-cybercriminel-des-modèles-de-langage-large-llms)
    * [Cybercriminels ciblent le secteur financier africain en abusant d'outils Open Source](#cybercriminels-ciblent-le-secteur-financier-africain-en-abusant-doutils-open-source)


## Category : Vulnerabilities
### Vulnérabilités Critiques multiples dans Citrix NetScaler ADC et Gateway
Plusieurs vulnérabilités affectent les produits Citrix NetScaler ADC et Gateway. La vulnérabilité critique CVE-2025-6543 (CVSS 9.2) est un débordement de mémoire qui peut entraîner un déni de service et affecte plusieurs versions supportées et EOL. Les vulnérabilités CVE-2025-5777 et CVE-2025-5349, surnommées "CitrixBleed 2", sont des problèmes de contrôle d'accès qui permettent le vol de tokens de session et d'informations sensibles, similaire à la vulnérabilité exploitée activement CVE-2023-4966 (CitrixBleed) 🩸. L'exploitation de CVE-2025-5777 est active dans la nature.
* Publication date : 2025/06/25
* 🔗 Source : https://www.bleepingcomputer.com/news/security/new-citrixbleed-2-netscaler-flaw-let-hackers-hijack-sessions/, https://cybersecuritynews.com/netscaler-adc-and-gateway-vulnerability/, https://thehackernews.com/2025/06/citrix-bleed-2-flaw-enables-token-theft.html
* 💥 CVE : [CVE-2025-6543](https://cvefeed.io/vuln/detail/CVE-2025-6543), [CVE-2025-5777](https://cvefeed.io/vuln/detail/CVE-2025-5777), [CVE-2025-5349](https://cvefeed.io/vuln/detail/CVE-2025-5349), [CVE-2023-4966](https://cvefeed.io/vuln/detail/CVE-2023-4966), [CVE-2023-3519](https://cvefeed.io/vuln/detail/CVE-2023-3519)
* Affected Products : NetScaler ADC and Gateway versions 14.1 before 14.1-43.56/14.1-47.46+, 13.1 before 13.1-58.32/13.1-59.19+, 13.1-FIPS/NDcPP before 13.1-37.235-FIPS/NDcPP/13.1-37.236+. Versions 12.1 and 13.0 (EOL) sont également impactées.
* 💯 CVSS : 9.2 (CVE-2025-6543), 9.4 (CVE-2023-4966)
* 🛡️ Security recommandations : Appliquer immédiatement les mises à jour (14.1-47.46+, 13.1-59.19+, 13.1-FIPS/NDcPP 13.1-37.236+). Terminer toutes les sessions ICA et PCoIP actives après la mise à jour. Les utilisateurs des versions EOL 12.1 et 13.0 doivent migrer vers une version supportée.
* 🦠 Indicator of Compromise :
    * CVE:
        * CVE-2025-5349
        * CVE-2023-4966
        * CVE-2025-5777
        * CVE-2023-3519
        * CVE-2025-6543

### Vulnérabilité XSS dans Discourse via les Connexions Sociales
Une vulnérabilité de Cross-Site Scripting (XSS) (CVE-2025-48954) a été découverte dans la plateforme de discussion open source Discourse. Elle affecte les versions antérieures à la 3.5.0.beta6 lorsque la politique de sécurité de contenu (CSP) n'est pas activée 🚨.
* Publication date : 2025/06/25
* 🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-48954
* 💥 CVE : [CVE-2025-48954](https://cvefeed.io/vuln/detail/CVE-2025-48954)
* Affected Products : Discourse versions antérieures à 3.5.0.beta6.
* 💯 CVSS : 8.1
* 🛡️ Security recommandations : Mettre à jour vers la version 3.5.0.beta6. Activer la politique de sécurité de contenu (CSP) comme solution de contournement.
* 🦠 Indicator of Compromise :
    * CVE:
        * CVE-2025-48954

### Vulnérabilité dans Cyberduck et Mountain Duck affectant le Certificate Pinning TLS
Cyberduck (jusqu'à 9.1.6) et Mountain Duck (jusqu'à 4.17.5) gèrent incorrectement le certificate pinning TLS pour les certificats non approuvés (auto-signés par exemple) (CVE-2025-41255) 🔓. Cela entraîne une installation inutile du certificat dans le magasin de certificats Windows de l'utilisateur actuel sans restriction.
* Publication date : 2025/06/25
* 🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-41255
* 💥 CVE : [CVE-2025-41255](https://cvefeed.io/vuln/detail/CVE-2025-41255)
* Affected Products : Cyberduck versions jusqu'à 9.1.6, Mountain Duck versions jusqu'à 4.17.5.
* 💯 CVSS : 8.0
* 🛡️ Security recommandations : Mettre à jour vers les versions corrigées (pas de versions spécifiques mentionnées, se référer aux advisories officiels).
* 🦠 Indicator of Compromise :
    * CVE:
        * CVE-2025-41255

### Divulgation du Mot de Passe Administrateur par Défaut dans les Imprimantes Brother/Konica Minolta
Une vulnérabilité critique (CVE-2024-51978) affecte des centaines de modèles d'imprimantes Brother et quelques modèles Konica Minolta 🔑. Un attaquant non authentifié connaissant le numéro de série de l'appareil peut générer le mot de passe administrateur par défaut. Le numéro de série peut être découvert via une autre vulnérabilité (CVE-2024-51977) ou d'autres méthodes (PJL, SNMP).
* Publication date : 2025/06/25
* 🔗 Source : https://cvefeed.io/vuln/detail/CVE-2024-51978, https://www.security.nl/posting/893697/Kritiek+lek+in+honderden+Brother-printers+kan+aanvaller+admintoegang+geven?channel=rss
* 💥 CVE : [CVE-2024-51978](https://cvefeed.io/vuln/detail/CVE-2024-51978), [CVE-2024-51977](https://cvefeed.io/vuln/detail/CVE-2024-51977)
* Affected Products : Des centaines de modèles d'imprimantes Brother et certains modèles Konica Minolta.
* 💯 CVSS : 9.8
* 🛡️ Security recommandations : Appliquer les mises à jour firmware disponibles immédiatement. Modifier le mot de passe administrateur par défaut après la mise à jour. Pour les modèles sans mise à jour, appliquer les solutions de contournement recommandées par le fabricant (Brother recommande un nouveau processus de production pour les modèles concernés car le firmware seul ne corrige pas entièrement le problème).
* 🦠 Indicator of Compromise :
    * CVE:
        * CVE-2024-51977
        * CVE-2024-51978

### Vulnérabilité d'Escalade de Privilèges dans IBM Facsimile Support for i
IBM i 7.2, 7.3, 7.4 et 7.5 sont vulnérables à une élévation de privilèges (CVE-2025-36004) due à un appel de librairie non qualifié dans IBM Facsimile Support for i 📈. Un acteur malveillant peut exécuter du code contrôlé par l'utilisateur avec des privilèges d'administrateur.
* Publication date : 2025/06/25
* 🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-36004
* 💥 CVE : [CVE-2025-36004](https://cvefeed.io/vuln/detail/CVE-2025-36004)
* Affected Products : IBM i 7.2, 7.3, 7.4, 7.5.
* 💯 CVSS : 8.8
* 🛡️ Security recommandations : Appliquer les mises à jour fournies par IBM.
* 🦠 Indicator of Compromise :
    * CVE:
        * CVE-2025-36004

### Vulnérabilités Critiques multiples dans Hikka Telegram Userbot
Deux vulnérabilités critiques affectent Hikka, un userbot Telegram, et la plupart de ses forks 🔥. CVE-2025-52571 (CVSS 9.6) permet à un attaquant non authentifié de prendre le contrôle du compte Telegram de la victime et d'accéder entièrement au serveur dans les versions antérieures à 1.6.2. CVE-2025-52572 (CVSS 10.0) permet l'exécution de code à distance et la prise de contrôle de compte même avec une session authentifiée, exploitant un manque d'avertissement dans le processus d'authentification web. Le scénario 2 de CVE-2025-52572 est activement exploité dans la nature 💥.
* Publication date : 2025/06/24
* 🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-52572, https://cvefeed.io/vuln/detail/CVE-2025-52571
* 💥 CVE : [CVE-2025-52572](https://cvefeed.io/vuln/detail/CVE-2025-52572), [CVE-2025-52571](https://cvefeed.io/vuln/detail/CVE-2025-52571)
* Affected Products : Hikka Telegram userbot versions antérieures à 1.6.2 et la plupart des forks (CVE-2025-52571). Toutes les versions de Hikka (CVE-2025-52572).
* 💯 CVSS : 10.0 (CVE-2025-52572), 9.6 (CVE-2025-52571)
* 🛡️ Security recommandations : Mettre à jour vers la version 1.6.2 (corrige CVE-2025-52571). Pour CVE-2025-52572 (pas de patch connu), utiliser le flag `--no-web`, fermer le port du serveur après l'authentification web, et ne pas cliquer sur "Allow" dans le bot d'assistance sauf si c'est une action explicite.
* 🦠 Indicator of Compromise :
    * CVE:
        * CVE-2025-52572
        * CVE-2025-52571

### Vulnérabilité d'Exécution de Code Arbitraire dans KnowledgeGPT
Une vulnérabilité (CVE-2024-37743) dans mmzdev KnowledgeGPT V.0.0.5 permet à un attaquant distant d'exécuter du code arbitraire via le composant Document Display 💻.
* Publication date : 2025/06/24
* 🔗 Source : https://cvefeed.io/vuln/detail/CVE-2024-37743
* 💥 CVE : [CVE-2024-37743](https://cvefeed.io/vuln/detail/CVE-2024-37743)
* Affected Products : mmzdev KnowledgeGPT V.0.0.5.
* 💯 CVSS : 9.8
* 🛡️ Security recommandations : Mettre à jour vers une version corrigée.
* 🦠 Indicator of Compromise :
    * CVE:
        * CVE-2024-37743

### Vulnérabilité Critique dans Elastic Kibana permettant RCE et Corruption de Heap
Une vulnérabilité critique (CVE-2025-2135) affecte Elastic Kibana, permettant une corruption de heap et une exécution de code arbitraire à distance via des pages HTML spécialement conçues 🌐💥. Le problème vient d'une confusion de types.
* Publication date : 2025/06/25
* 🔗 Source : https://cybersecuritynews.com/kibana-vulnerabilities-allows-code-execution/, https://www.cert.ssi.gouv.fr/avis/CERTFR-2025-AVI-0533/
* 💥 CVE : [CVE-2025-2135](https://cvefeed.io/vuln/detail/CVE-2025-2135)
* Affected Products : Kibana versions 7.17.0 à 7.17.28, 8.0.0 à 8.17.7, 8.18.0 à 8.18.2, 9.0.0 à 9.0.2. Produits Elastic affectés (détails non spécifiés par CERTFR).
* 💯 CVSS : 9.2
* 🛡️ Security recommandations : Mettre à jour immédiatement vers les versions 7.17.29, 8.17.8, 8.18.3 ou 9.0.3. Des options de mitigation sont disponibles pour les organisations ne pouvant pas mettre à jour immédiatement.
* 🦠 Indicator of Compromise :
    * CVE:
        * CVE-2025-2135

## Category : Threats
### Arrestations Signalées des Opérateurs du Forum de Hacking BreachForums
La police française aurait arrêté cinq opérateurs du forum cybercriminel BreachForums 🚓🔗, une plateforme utilisée pour divulguer et vendre des données volées. Des rumeurs suggèrent également l'arrestation du cybercriminel "IntelBroker" en février 2025. BreachForums a servi de communauté pour échanger des données volées, vendre l'accès à des réseaux d'entreprise et d'autres services illégaux. Des acteurs comme ShinyHunters et IntelBroker étaient admins/propriétaires.
* Publication date : 2025/06/25
* 🔗 Source : https://www.bleepingcomputer.com/news/security/breachforums-hacking-forum-operators-reportedly-arrested-in-france/
* 🕵️ Threat Actor : Opérateurs de BreachForums, IntelBroker, ShinyHunters, Hollow, depressed, noct
* 🎯 Threat Target : Millions de personnes (via données volées), entreprises (accès aux réseaux).
* 👹 Threat Tactic : Vente/Divulgation de données volées, vente d'accès initiaux, services cybercriminels.
* 📍 Indicator of Compromise :
    * Threat Actor:
        * IntelBroker
        * ShinyHunters

### Alerte concernant un Client SonicWall NetExtender Trojanisé Volant des Identifiants VPN
SonicWall alerte ses clients sur la distribution d'une version trojanisée de son client SSL VPN NetExtender, conçue pour voler les identifiants VPN 🛡️🎣. Le logiciel malveillant cible le personnel distant, les administrateurs informatiques et les contractants, et vole les informations de configuration du VPN (nom d'utilisateur, mot de passe, domaine, etc.).
* Publication date : 2025/06/24
* 🔗 Source : https://www.bleepingcomputer.com/news/security/sonicwall-warns-of-trojanized-netextender-stealing-vpn-logins/
* 🎯 Threat Target : Utilisateurs du client SonicWall NetExtender SSL VPN (personnel distant, admins IT, contractants).
* 👹 Threat Tactic : Distribution de logiciel trojanisé, vol d'identifiants.
* ⚒️ Threat Tools : Version trojanisée de SonicWall NetExtender.
* 🛡️ Security recommandations : Ne télécharger le client NetExtender qu'à partir de sources officielles et vérifier son intégrité. Mettre en œuvre l'authentification multifacteur (MFA) pour les accès VPN.

### Phishing OAuth Microsoft Entra ID et Détections
Cet article explore les techniques de phishing OAuth et d'abus de tokens dans Microsoft Entra ID (Azure AD), inspiré par des campagnes attribuées à des acteurs comme UTA0352 ☁️🎣. Les attaquants abusent des flux OAuth légitimes et d'outils comme ROADtools/ROADtx pour récolter des tokens, enregistrer des appareils virtuels, obtenir des PRTs (Primary Refresh Tokens) et accéder à des données sensibles via Microsoft Graph (emails, SharePoint) sans interaction utilisateur ultérieure. L'émulation de ces techniques a permis de surface des indicateurs comportementaux pour la détection.
* Publication date : 2025/06/25
* 🔗 Source : https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection
* 🕵️ Threat Actor : UTA0352 (inspiration)
* 🎯 Threat Target : Utilisateurs de Microsoft Entra ID/Microsoft 365.
* 👹 Threat Tactic : Phishing OAuth, Vol de tokens, Enregistrement de dispositif, Abus de PRT, Accès aux données cloud.
* ⚒️ Threat Tools : ROADtools, ROADtx
* 🛡️ Security recommandations : Surveiller les journaux de connexion et d'audit Entra ID pour les activités suspectes (connexions multiples IPs sur même session, utilisation de clients first-party inhabituels, enregistrements de dispositifs inattendus, usage de refresh tokens/PRTs). Mettre en œuvre des politiques d'accès conditionnel (CAP) robustes. Éduquer les utilisateurs sur les risques du phishing OAuth. Restreindre l'exécution de macros (vector initial possible). Analyser et limiter le trafic réseau vers des services cloud légitimes potentiellement utilisés pour le C2 (Koofr, Icedrive). Utiliser MFA.
* 📍 Indicator of Compromise :
    * URL:
        * hxxps[:]//graph[.]microsoft[.]com/[.]defaultinstructs
        * hxxps[:]//login[.]microsoftonline[.]com/[tenant_id]/oauth2/v2[.]0/token
    * DOMAIN:
        * login[.]microsoftonline[.]com
        * mail[.]read
        * graph[.]microsoft[.]com
        * enterpriseregistration[.]windows[.]net

### Cyberattaques ciblant les PME en 2025 : Tendances et Techniques
Un rapport met en évidence les tendances des cyberattaques ciblant les petites et moyennes entreprises (PME) en 2025 🏢🎯. Les PME sont considérées comme des cibles plus faciles. Les attaques basées sur les relations de confiance restent une méthode clé. Les attaques basées sur l'IA et l'usurpation d'outils légitimes (IA, plateformes de collaboration comme Zoom, Microsoft Office) sont en augmentation. Les menaces principales incluent les downloaders, les Trojans, et les adwares. Les campagnes de phishing et d'arnaques restent courantes, imitant des marques populaires pour voler des identifiants ou manipuler les victimes. Le Trojan-Downloader "TookPS" est distribué via de faux sites web.
* Publication date : 2025/06/25
* 🔗 Source : https://securelist.com/smb-threat-report-2025/116830/
* 🎯 Threat Target : Petites et Moyennes Entreprises (PME).
* 👹 Threat Tactic : Attaques basées sur les relations de confiance, Usurpation de logiciels légitimes (IA, collaboration, Office), Phishing, Scams, Distribution de malware via faux sites web.
* ⚒️ Threat Tools : Downloaders, Trojans, Adware, Trojan-Dropper, Backdoor, Trojan-Downloader, HackTool, Trojan-PSW, PSW-Tool, TookPS.
* 🛡️ Security recommandations : Investir dans des solutions de cybersécurité complètes. Renforcer la sensibilisation des employés (phishing, scams). Mettre en œuvre des filtres anti-spam, des protocoles d'authentification email, et des procédures de vérification strictes. Promouvoir des pratiques de mots de passe robustes et la MFA. Interdire le téléchargement de logiciels depuis des sources non officielles ; centraliser les installations par l'équipe IT.
* 📍 Indicator of Compromise :
    * DOMAIN:
        * sqlx[.]ps
        * asslr[.]ps
        * sav[.]ps1andcfg[.]ps

### Violation de Données chez Mainline Health Systems
Mainline Health Systems, un centre de santé à but non lucratif, a divulgué une violation de données ayant affecté plus de 100 000 personnes 🏥💔. L'incident, remontant à mai 2025, a exposé des informations personnelles protégées. Le groupe de ransomware INC RANSOM a revendiqué la responsabilité de cette violation. Ce groupe est connu pour avoir ciblé d'autres organisations par le passé.
* Publication date : 2025/06/25
* 🔗 Source : https://securityaffairs.com/179322/data-breach/mainline-health-systems-disclosed-a-data-breach.html
* 🕵️ Threat Actor : INC RANSOM
* 🎯 Threat Target : Mainline Health Systems
* 👹 Threat Tactic : Ransomware, Violation de données.
* 📍 Indicator of Compromise :
    * Threat Actor:
        * INC RANSOM

### Hausse d'Activité du Botnet Prometei
Une augmentation significative de l'activité du botnet Prometei est observée depuis mars 2025 👀📈, avec une nouvelle variante se propageant rapidement. Prometei cible les systèmes Linux pour le minage de Monero et le vol d'identifiants. Le bot est activement développé, utilisant une architecture modulaire, des algorithmes de génération de domaine (DGA) et des fonctionnalités d'auto-mise à jour pour l'évasion. Il exploite notamment les vulnérabilités EternalBlue et SMB.
* Publication date : 2025/06/25
* 🔗 Source : https://securityaffairs.com/179303/cyber-crime/prometei-botnet-activity-has-surged-since-march-2025.html
* 🕵️ Threat Actor : Prometei botnet operators
* 🎯 Threat Target : Systèmes Linux.
* 👹 Threat Tactic : Cryptomining (Monero), Vol d'identifiants, Exploitation de vulnérabilités (EternalBlue, SMB), Brute-force, Distribution HTTP, Utilisation de UPX pour obfuscation.
* ⚒️ Threat Tools : Prometei malware (variante Linux), UPX packer, DGA, JSON config trailer.
* 🛡️ Security recommandations : Appliquer les patchs pour les vulnérabilités connues (EternalBlue, SMB). Mettre en œuvre des politiques de mot de passe robustes pour contrer le brute-force. Utiliser une règle YARA pour détecter les échantillons packés avec UPX et comportant le trailer JSON. Surveiller le trafic réseau pour les communications liées au minage de crypto et aux C2.
* 📍 Indicator of Compromise :
    * FILE_NAME:
        * .php (disguise)

### Le Groupe APT28 (UAC-0001) Cible les Entités Gouvernementales Ukrainiennes via Phishing et Malware
Le groupe cyberespion russe APT28 (également connu sous les noms UAC-0001, Fancy Bear, Forest Blizzard, STRONTIUM, Pawn Storm) cible les entités gouvernementales ukrainiennes 🇺🇦🇷🇺 via du phishing et des malwares sophistiqués 📧😈. Récemment observé utilisant des chats Signal comme vecteur de livraison pour des documents malveillants (contenant des macros), le groupe déploie les malwares BEARDSHELL et COVENANT. BEARDSHELL exécute des scripts PowerShell et utilise l'API Icedrive pour l'exfiltration. COVENANT déploie d'autres composants et utilise l'API Koofr comme canal C2. Le groupe utilise le COM hijacking et les tâches planifiées pour la persistance et a été observé exploitant CVE-2022-38028 (Windows Print Spooler).
* Publication date : 2025/06/24, 2025/06/24
* 🔗 Source : https://securityaffairs.com/179288/apt/russia-linked-apt28-use-signal-chats-to-target-ukraine-official-with-malware.html, https://socprime.com/blog/detect-uac-0001-aka-apt28-attacks-against-ukraine/
* 🕵️ Threat Actor : APT28 (UAC-0001, Fighting Ursa, Fancy Bear, Forest Blizzard, STRONTIUM, Pawn Storm)
* 🎯 Threat Target : Entités gouvernementales ukrainiennes, Organisations en Europe de l'Ouest et Amérique du Nord (campagnes précédentes).
* 👹 Threat Tactic : Phishing, Exploitation de vulnérabilités (CVE-2022-38028), Distribution de malware via chat Signal, Utilisation de macros malveillantes, COM hijacking, Tâches planifiées, Utilisation d'APIs cloud légitimes pour le C2 (Icedrive, Koofr), Vol de captures d'écran, Chiffrement de données.
* ⚒️ Threat Tools : BEARDSHELL (backdoor), SLIMAGENT (capture d'écran, chiffrement), COVENANT (framework), METASPLOIT, GooseEgg.
* 💥 CVE : [CVE-2022-38028](https://cve.mitre.org/cgi-bin/cnnvdname.cgi?CVE-2022-38028)
* 🛡️ Security recommandations : Auditer, surveiller et restreindre l'exécution des macros. Appliquer les mises à jour de sécurité, notamment pour CVE-2022-38028. Analyser et limiter le trafic réseau vers les services cloud légitimes potentiellement abusés pour le C2 (app.koofr.net, api.icedrive.net). Mettre en œuvre une défense en profondeur.
* 📍 Indicator of Compromise :
    * DOMAIN:
        * gov[.]ua
        * specificallyapp[.]koofr[.]netandapi[.]icedrive[.]net

### Le Groupe APT Salt Typhoon lié à la Chine Cible les Entreprises de Télécommunications Canadiennes
Le groupe APT Salt Typhoon, lié à la Chine, cible les entreprises de télécommunications canadiennes dans le cadre d'opérations d'espionnage cybernétique 🇨🇦🇨🇳. Ce groupe est actif depuis 1 à 2 ans et a également ciblé des fournisseurs de télécommunications américains. Ils exploitent notamment la vulnérabilité CVE-2023-20198 dans les périphériques réseau Cisco IOS XE pour voler des configurations et mettre en place des tunnels GRE pour la collecte de trafic. L'activité d'espionnage devrait se poursuivre.
* Publication date : 2025/06/24
* 🔗 Source : https://securityaffairs.com/179278/apt/china-linked-apt-salt-typhoon-targets-canadian-telecom-companies.html
* 🕵️ Threat Actor : Salt Typhoon (Groupe lié à la Chine)
* 🎯 Threat Target : Entreprises de télécommunications canadiennes, Entreprises de télécommunications américaines, clients des télécoms.
* 👹 Threat Tactic : Cyberespionnage, Exploitation de vulnérabilités (CVE-2023-20198), Vol de configurations, Mise en place de tunnels (GRE) pour la collecte de données, Reconnaissance réseau.
* 💥 CVE : [CVE-2023-20198](https://cve.mitre.org/cgi-bin/cnnvdname.cgi?CVE-2023-20198)
* 🛡️ Security recommandations : Appliquer les mises à jour pour les périphériques réseau Cisco IOS XE vulnérables à CVE-2023-20198. Surveiller le trafic réseau pour les activités inhabituelles, notamment la mise en place de tunnels non autorisés. Mettre en œuvre une segmentation réseau pour limiter les mouvements latéraux.
* 📍 Indicator of Compromise :
    * CVE:
        * CVE-2023-20198

### Avertissement Américain sur les Cybermenaces Potentielles suite aux Frappes contre l'Iran
Le DHS américain met en garde contre une augmentation des cybermenaces potentielles contre les réseaux et infrastructures critiques américains 🇺🇸🇮🇷 suite aux frappes aériennes américaines sur des sites nucléaires iraniens 💥. Des attaques de faible intensité par des hacktivistes pro-iraniens sont probables, et des cyberacteurs affiliés au gouvernement iranien pourraient mener des attaques plus importantes. L'Iran reste déterminé à cibler les responsables américains liés à la mort d'un commandant militaire en 2020. Le conflit actuel pourrait également exacerber la violence extrémiste intérieure.
* Publication date : 2025/06/24
* 🔗 Source : https://securityaffairs.com/179266/cyber-warfare-2/u-s-warns-of-incoming-cyber-threats-following-iran-airstrikes.html
* 🕵️ Threat Actor : Hacktivistes pro-iraniens, Acteurs affiliés au gouvernement iranien.
* 🎯 Threat Target : Réseaux américains, Infrastructures critiques américaines, Responsables gouvernementaux américains.
* 👹 Threat Tactic : Cyberattaques (potentiellement disruptives), Espionnage, Plots intérieurs.
* 🛡️ Security recommandations : Augmenter la vigilance. Examiner les plans de réponse aux incidents. Renforcer les défenses contre les attaques courantes et les tactiques connues des acteurs iraniens. Surveiller les indicateurs liés aux groupes pro-iraniens.

### Violation de Données chez Robinsons Malls
En juin 2024, Robinsons Malls, le plus grand opérateur de centres commerciaux aux Philippines, a subi une violation de données via son application mobile 🛍️📉. L'incident a exposé 195 597 adresses email uniques ainsi que des noms, numéros de téléphone, dates de naissance, genres et informations de ville/province des utilisateurs. Aucun acteur spécifique n'a été mentionné comme responsable.
* Publication date : 2025/06/25
* 🔗 Source : https://haveibeenpwned.com/Breach/RobinsonsMalls
* 🎯 Threat Target : Utilisateurs de l'application mobile Robinsons Malls.
* 👹 Threat Tactic : Violation de données.
* 📍 Indicator of Compromise :
    * EMAIL (Count):
        * 195597

### Violation de Données chez Have Fun Teaching
En août 2021, le site de ressources pédagogiques Have Fun Teaching a subi une violation de données 🍎📚. 80 000 transactions WooCommerce ont été divulguées et publiées sur un forum de hacking. Les données contenaient 27 126 adresses email uniques, des adresses physiques et IP, des noms, des méthodes de paiement et les articles achetés. Le site est conscient de l'incident.
* Publication date : 2025/06/25
* 🔗 Source : https://haveibeenpwned.com/Breach/HaveFunTeaching
* 🎯 Threat Target : Utilisateurs du site Have Fun Teaching (clients WooCommerce).
* 👹 Threat Tactic : Violation de données, Fuite de données.
* 📍 Indicator of Compromise :
    * EMAIL (Count):
        * 27126

### Abus Cybercriminel des Modèles de Langage Large (LLMs)
Les cybercriminels exploitent de plus en plus les modèles de langage large (LLMs) pour améliorer leurs attaques 🤖🔓. Ils se tournent vers les LLMs non censurés, développent leurs propres LLMs dédiés à la cybercriminalité (FraudGPT, DarkestGPT, etc.) ou tentent de "jailbreaker" les LLMs légitimes via des techniques d'injection de prompt, d'obfuscation ou d'usurpation de persona. Les LLMs sont utilisés pour générer du code malveillant (ransomware, RATs), des emails de phishing, et pour la reconnaissance. De plus, des risques émergent liés à l'empoisonnement des bases de données RAG et à l'inclusion de malware dans les fichiers modèles.
* Publication date : 2025/06/25
* 🔗 Source : https://blog.talosintelligence.com/cybercriminal-abuse-of-large-language-models/
* 🕵️ Threat Actor : Cybercriminels (utilisateurs/développeurs de LLMs malveillants), CanadianKingpin12 (scammer).
* 🎯 Threat Target : Utilisateurs de LLMs, systèmes ciblés via des attaques facilitées par les LLMs.
* 👹 Threat Tactic : Utilisation de LLMs pour la création de malware/scripts, génération de contenu de phishing, reconnaissance, Scams, Injection de prompt/Jailbreaking LLM, Empoisonnement RAG, Distribution de malware via fichiers modèles.
* ⚒️ Threat Tools : LLMs non censurés (Llama 2 Uncensored, WhiteRabbitNeo), LLMs cybercriminels (GhostGPT, WormGPT, DarkGPT, DarkestGPT, FraudGPT), Techniques de jailbreaking (DAN, Grandma, basé sur les maths, etc.), Nmap (intégré aux LLMs).
* 🛡️ Security recommandations : Sensibiliser aux risques liés aux LLMs non sécurisés. Télécharger les modèles AI uniquement depuis des sources fiables. Scanner les modèles téléchargés pour détecter les codes malveillants potentiels. Utiliser des sandboxes pour exécuter des modèles non fiables. Être vigilant face aux contenus générés potentiellement malveillants (emails, messages).
* 📍 Indicator of Compromise :
    * Threat Actor:
        * CanadianKingpin12
    * Tools:
        * GhostGPT
        * WormGPT
        * DarkGPT
        * DarkestGPT
        * FraudGPT
        * Ollama
        * Llama 2 Uncensored
        * WhiteRabbitNeo

### Cybercriminels ciblent le secteur financier africain en abusant d'outils Open Source
Un groupe cybercriminel, suivi sous le nom de CL-CRI-1014, cible les organisations financières à travers l'Afrique 🌍💰. L'objectif serait d'obtenir un accès initial aux réseaux des institutions financières pour ensuite le vendre sur les marchés du dark web. Le groupe utilise un ensemble cohérent d'outils open source et publiquement disponibles dans son "playbook", notamment PoshC2, Chisel et Classroom Spy. Ils forgent les signatures de fichiers pour dissimuler leurs activités et utilisent PowerShell pour déployer et installer leurs outils.
* Publication date : 2025/06/24
* 🔗 Source : https://unit42.paloaltonetworks.com/cybercriminals-attack-financial-sector-across-africa/
* 🕵️ Threat Actor : CL-CRI-1014 (Cluster d'activité)
* 🎯 Threat Target : Organisations financières en Afrique.
* 👹 Threat Tactic : Obtention d'accès initial, Vente d'accès sur le dark web, Utilisation d'outils open source, Forgerie de signatures, Création de tunnels (SOCKS proxy via Chisel), Administration à distance, Déploiement via scripts PowerShell, Packing binaire, Anti-analyse (vérification domaine AD).
* ⚒️ Threat Tools : PoshC2 (framework C2), Chisel (outil de tunneling), Classroom Spy (outil d'administration à distance), MeshAgent (outil de gestion à distance), Scripts PowerShell (slr.ps1, sqlx.ps1, sav.ps1, cfg.ps1), Packer basé sur Nim.
* 📍 Indicator of Compromise :
    * FILE_NAME:
        * slr[.]ps1
        * sqlx[.]ps1
        * sav[.]ps1
        * cfg[.]ps1
        * CortexUpdater[.]exe
    * DOMAIN:
        * sqlx[.]ps
        * asslr[.]ps
        * sav[.]ps1andcfg[.]ps
    * Threat Actor:
        * CL-CRI-1014
    * Tools:
        * PoshC2
        * Chisel
        * Classroom Spy
        * MeshAgent

