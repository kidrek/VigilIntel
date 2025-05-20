# ⚠️Important Vulnerabilities (CVSS > 8)⚠️
* 💥 CVE-2025-39402, CVE-2025-39401, CVE-2025-39395 - Multiples vulnérabilités critiques dans Mojoomla WPAMS
* 🛡️ CVE-2025-48340 - Vulnérabilité critique de type CSRF et d'escalade de privilèges dans Danny Vink User Profile Meta Manager
* 💾 CVE-2025-39389 - Vulnérabilité critique d'injection SQL dans Solid Plugins AnalyticsWP
* 🖨️ CVE-2025-3079 - Vulnérabilité d'impression "Passback" à haute gravité dans les imprimantes HP
* 🖨️ CVE-2025-3078 - Vulnérabilité d'impression "Passback" à haute gravité dans les imprimantes Xerox

## Table of Contents
* [Category : Vulnerabilities](#category--vulnerabilities)
    * [CVE-2025-39402, CVE-2025-39401, CVE-2025-39395 - Multiples vulnérabilités critiques dans Mojoomla WPAMS](#cve-2025-39402-cve-2025-39401-cve-2025-39395---multiples-vulnérabilités-critiques-dans-mojoomla-wpams)
    * [CVE-2025-48340 - Vulnérabilité critique de type CSRF et d'escalade de privilèges dans Danny Vink User Profile Meta Manager](#cve-2025-48340---vulnérabilité-critique-de-type-csrf-et-descalade-de-privilèges-dans-danny-vink-user-profile-meta-manager)
    * [CVE-2025-39389 - Vulnérabilité critique d'injection SQL dans Solid Plugins AnalyticsWP](#cve-2025-39389---vulnérabilité-critique-dinjection-sql-dans-solid-plugins-analyticscp)
    * [CVE-2025-3079 - Vulnérabilité d'impression "Passback" à haute gravité dans les imprimantes HP](#cve-2025-3079---vulnérabilité-dimpression-passback-à-haute-gravité-dans-les-imprimantes-hp)
    * [CVE-2025-3078 - Vulnérabilité d'impression "Passback" à haute gravité dans les imprimantes Xerox](#cve-2025-3078---vulnérabilité-dimpression-passback-à-haute-gravité-dans-les-imprimantes-xerox)
* [Category : Threats](#category--threats)
    * [Campagne de Ransomware ESXi via un faux gestionnaire de mots de passe KeePass](#campagne-de-ransomware-esxi-via-un-faux-gestionnaire-de-mots-de-passe-keepass)
    * [Attaque de Ransomware ELPACO-team exploitant une vulnérabilité Confluence non patchée](#attaque-de-ransomware-elpaco-team-exploitant-une-vulnérabilité-confluence-non-patchée)
    * [Cyberattaque confirmée chez Arla Foods](#cyberattaque-confirmée-chez-arla-foods)

## Category : Vulnerabilities
### <a id="cve-2025-39402-cve-2025-39401-cve-2025-39395---multiples-vulnérabilités-critiques-dans-mojoomla-wpams"></a>CVE-2025-39402, CVE-2025-39401, CVE-2025-39395 - Multiples vulnérabilités critiques dans Mojoomla WPAMS
De multiples vulnérabilités critiques ont été découvertes dans le plugin WPAMS de Mojoomla. 😱 Ces failles, notamment des injections SQL et des téléchargements de fichiers non restreints, peuvent permettre à un attaquant de télécharger un shell web, d'exécuter du code arbitraire à distance ou de provoquer une injection SQL. Les versions affectées vont jusqu'à la version 44.0. 📉
* Publication date : 2025/05/19
* 🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-39402, https://cvefeed.io/vuln/detail/CVE-2025-39401, https://cvefeed.io/vuln/detail/CVE-2025-39395
* 🐞 CVE : CVE-2025-39402 ([https://nvd.nist.gov/vuln/detail/CVE-2025-39402](https://nvd.nist.gov/vuln/detail/CVE-2025-39402)), CVE-2025-39401 ([https://nvd.nist.gov/vuln/detail/CVE-2025-39401](https://nvd.nist.gov/vuln/detail/CVE-2025-39401)), CVE-2025-39395 ([https://nvd.nist.gov/vuln/detail/CVE-2025-39395](https://nvd.nist.gov/vuln/detail/CVE-2025-39395))
*  affected_product : Mojoomla WPAMS (versions jusqu'à 44.0)
* 📊 CVSS : 9.9, 10.0, 9.3
* 💡 Security recommandations : Appliquer les mises à jour du fournisseur dès que possible. Réviser les configurations de sécurité pour restreindre les téléchargements de fichiers aux types autorisés et implémenter des mesures contre les injections SQL.

### <a id="cve-2025-48340---vulnérabilité-critique-de-type-csrf-et-descalade-de-privilèges-dans-danny-vink-user-profile-meta-manager"></a>CVE-2025-48340 - Vulnérabilité critique de type CSRF et d'escalade de privilèges dans Danny Vink User Profile Meta Manager
Une vulnérabilité critique de type Cross-Site Request Forgery (CSRF) a été découverte dans le plugin User Profile Meta Manager de Danny Vink. 💀 Cette faille permet une escalade de privilèges. Les versions affectées vont jusqu'à la version 1.02.
* Publication date : 2025/05/19
* 🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-48340
* 🐞 CVE : CVE-2025-48340 ([https://nvd.nist.gov/vuln/detail/CVE-2025-48340](https://nvd.nist.gov/vuln/detail/CVE-2025-48340))
* affected_product : Danny Vink User Profile Meta Manager (versions jusqu'à 1.02)
* 📊 CVSS : 9.8
* 💡 Security recommandations : Appliquer les mises à jour du fournisseur. Mettre en place des protections contre les attaques CSRF (tokens, vérification de l'origine).

### <a id="cve-2025-39389---vulnérabilité-critique-dinjection-sql-dans-solid-plugins-analyticscp"></a>CVE-2025-39389 - Vulnérabilité critique d'injection SQL dans Solid Plugins AnalyticsWP
Une vulnérabilité critique d'injection SQL a été signalée dans le plugin AnalyticsWP de Solid Plugins. 💾 Cette faille est due à une neutralisation incorrecte des éléments spéciaux dans les commandes SQL. Elle affecte les versions jusqu'à 2.1.2. Un attaquant pourrait potentiellement exploiter cette vulnérabilité pour accéder à des données sensibles ou modifier la base de données. 🚨
* Publication date : 2025/05/19
* 🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-39389
* 🐞 CVE : CVE-2025-39389 ([https://nvd.nist.gov/vuln/detail/CVE-2025-39389](https://nvd.nist.gov/vuln/detail/CVE-2025-39389))
* affected_product : Solid Plugins AnalyticsWP (versions jusqu'à 2.1.2)
* 📊 CVSS : 9.3
* 💡 Security recommandations : Appliquer les correctifs disponibles. Utiliser des requêtes préparées et une validation stricte des entrées utilisateur pour prévenir les injections SQL.

### <a id="cve-2025-3079---vulnérabilité-dimpression-passback-à-haute-gravité-dans-les-imprimantes-hp"></a>CVE-2025-3079 - Vulnérabilité d'impression "Passback" à haute gravité dans les imprimantes HP
Une vulnérabilité de type "passback" a été identifiée dans plusieurs modèles d'imprimantes multifonctions de bureau/petite entreprise et d'imprimantes laser HP. 🖨️ Bien que les détails techniques spécifiques ne soient pas entièrement divulgués dans l'article, la gravité élevée (CVSS 8.7) suggère un risque significatif pour la confidentialité ou l'intégrité des données traitées par les imprimantes affectées. ⚠️
* Publication date : 2025/05/20
* 🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-3079
* 🐞 CVE : CVE-2025-3079 ([https://nvd.nist.gov/vuln/detail/CVE-2025-3079](https://nvd.nist.gov/vuln/detail/CVE-2025-3079))
* affected_product : Imprimantes multifonctions et laser HP (modèles non spécifiés dans l'article)
* 📊 CVSS : 8.7
* 💡 Security recommandations : Consulter l'avis de sécurité du fournisseur (HP) pour obtenir la liste exacte des produits affectés et appliquer les correctifs ou atténuations recommandés. Isoler les imprimantes sur un réseau séparé si possible.

### <a id="cve-2025-3078---vulnérabilité-dimpression-passback-à-haute-gravité-dans-les-imprimantes-xerox"></a>CVE-2025-3078 - Vulnérabilité d'impression "Passback" à haute gravité dans les imprimantes Xerox
Une vulnérabilité de type "passback" a été découverte dans les imprimantes de production et les imprimantes multifonctions de bureau Xerox. 🖨️ Similaire à la vulnérabilité HP, cette faille présente une gravité élevée (CVSS 8.7). Les implications exactes du "passback" ne sont pas détaillées, mais la gravité indique un risque potentiel sérieux. 🛡️
* Publication date : 2025/05/20
* 🔗 Source : https://cvefeed.io/vuln/detail/CVE-2025-3078
* 🐞 CVE : CVE-2025-3078 ([https://nvd.nist.gov/vuln/detail/CVE-2025-3078](https://nvd.nist.gov/vuln/detail/CVE-2025-3078))
* affected_product : Imprimantes de production et imprimantes multifonctions de bureau Xerox (modèles non spécifiés dans l'article)
* 📊 CVSS : 8.7
* 💡 Security recommandations : Consulter l'avis de sécurité du fournisseur (Xerox) pour les détails précis sur les produits affectés et les mesures correctives. Examiner les options d'isolement réseau pour ces appareils.

## Category : Threats
### <a id="campagne-de-ransomware-esxi-via-un-faux-gestionnaire-de-mots-de-passe-keepass"></a>Campagne de Ransomware ESXi via un faux gestionnaire de mots de passe KeePass
Des acteurs de la menace distribuent des versions piégées du gestionnaire de mots de passe KeePass depuis au moins huit mois. 😈 Ces logiciels malveillants, nommés KeeLoader, installent des beacons Cobalt Strike, volent les identifiants et déploient ultimement des ransomwares (potentiellement liés à Black Basta) sur le réseau des victimes, ciblant notamment les systèmes ESXi. Les attaquants utilisent la malvertising sur Bing et des domaines en typosquatting pour tromper les utilisateurs. 🕵️‍♂️
* Publication date : 2025/05/19
* 🔗 Source : https://www.bleepingcomputer.com/news/security/fake-keepass-password-manager-leads-to-esxi-ransomware-attack/
* 👤 Threat Actor : UNC4696 (attribution modérée), Initial Access Brokers (potentiellement liés à Black Basta)
* 📈 Threat Tactic : Distribution de logiciels piégés (Trojanized Software), Publicité malveillante (Malvertising), Vol d'identifiants (Credential Theft), Mouvement latéral (Lateral Movement), Déploiement de Ransomware.
* 🎯 Threat Target : Réseaux d'entreprise, systèmes ESXi.
* 🛠️ Threat Tools : KeeLoader (version piégée de KeePass), Cobalt Strike beacon, Mimikatz (implicite pour vol d'identifiants), AnyDesk, Ransomware ESXi.
* 💡 Security recommandations : Éviter de télécharger des logiciels via des publicités sur les moteurs de recherche. Télécharger toujours les logiciels depuis les sites officiels des éditeurs. Sensibiliser les utilisateurs aux risques de typosquatting et de malvertising. Déployer une solution EDR pour détecter les activités suspectes (installation d'outils d'accès à distance, beacons, vol d'identifiants). Mettre en place une segmentation réseau pour protéger les systèmes critiques comme ESXi.
* compromise :
    *   DOMAIN : `aenys[.]com`
    *   DOMAIN : `keegass[.]com`
    *   DOMAIN : `keepass[.]me`
    *   DOMAIN : `keeppaswrd[.]com`

### <a id="attaque-de-ransomware-elpaco-team-exploitant-une-vulnérabilité-confluence-non-patchée"></a>Attaque de Ransomware ELPACO-team exploitant une vulnérabilité Confluence non patchée
Le rapport DFIR détaille une attaque de ransomware menée par l'équipe ELPACO, qui a débuté par l'exploitation d'une vulnérabilité non patchée dans un serveur Atlassian Confluence (CVE-2023-22527). 💥 L'attaque a impliqué une série de tactiques post-exploitation, notamment l'exécution de code arbitraire, l'escalade de privilèges via diverses techniques (dont l'impersonation de named pipe), la découverte du réseau (scan SMB, rpcdump), le vol d'identifiants (Mimikatz, Secretsdump) et le mouvement latéral (wmiexec, RDP). 🔑 Des outils comme Metasploit (Meterpreter), AnyDesk, NetScan et plusieurs outils d'Impacket ont été utilisés. Le ransomware ELPACO-team (identifié comme une variante de Mimic ransomware) a été déployé environ 62 heures après l'intrusion initiale, ciblant les serveurs de sauvegarde et de fichiers. Fait inhabituel, peu d'exfiltration de données a été observée avant le chiffrement. 📉
* Publication date : 2025/05/19
* 🔗 Source : https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/
* 👤 Threat Actor : ELPACO-team, potentiellement lié à UNC4696 ou des groupes associés à Black Basta/ALPHV.
* 📈 Threat Tactic : Exploitation de vulnérabilités (CVE-2023-22527), Exécution de code à distance, Persistance (Installation AnyDesk en service, création utilisateur), Escalade de privilèges (Impersonation Named Pipe, Token Duplication), Découverte (Scan réseau, Énumération SMB/RPC), Accès aux identifiants (LSASS dump, Secretsdump), Mouvement latéral (wmiexec, RDP), Déploiement de Ransomware, Impact (Chiffrement de données, arrêt de VMs).
* 🎯 Threat Target : Serveurs Atlassian Confluence (non patchés), serveurs de sauvegarde, serveurs de fichiers, contrôleurs de domaine.
* 🛠️ Threat Tools : Metasploit (Meterpreter loader), curl, AnyDesk, SoftPerfect’s NetScan, zero.exe (outil Zerologon), Mimikatz, ProcessHacker, Impacket (Secretsdump, wmiexec, rpcdump.exe), RDP, PowerShell cmdlets (Get-VM, Stop-VM, Get-VHD, Get-DiskImage, Dismount-DiskImage), DefenderControl, ELPACO-team.exe (Mimic ransomware).
* 💡 Security recommandations : Appliquer immédiatement les correctifs pour CVE-2023-22527, CVE-2020-1472 et CVE-2021-34527. Mettre en place une surveillance réseau et endpoint robuste pour détecter les TTPs observés (tentatives d'escalade, utilisation d'outils post-exploitation, accès à LSASS, installation d'outils d'accès à distance non autorisés comme AnyDesk, création d'utilisateurs inhabituels). Segmenter le réseau pour limiter le mouvement latéral en cas de compromission initiale. Sauvegardes hors ligne et testées.
* 🐞 CVE : CVE-2023-22527 ([https://nvd.nist.gov/vuln/detail/CVE-2023-22527](https://nvd.nist.gov/vuln/detail/CVE-2023-22527)), CVE-2020-1472 ([https://nvd.nist.gov/vuln/detail/CVE-2020-1472](https://nvd.nist.gov/vuln/detail/CVE-2020-1472)), CVE-2021-34527 ([https://nvd.nist.gov/vuln/detail/CVE-2021-34527](https://nvd.nist.gov/vuln/detail/CVE-2021-34527))
* 🔪 Indicator of Compromise :
    *   DOMAIN : `delete[.]me`
    *   IPv4 : `185[.]228[.]19[.]244`
    *   IPv4 : `45[.]227[.]254[.]124`
    *   IPv4 : `91[.]191[.]209[.]46`

### <a id="cyberattaque-confirmée-chez-arla-foods"></a>Cyberattaque confirmée chez Arla Foods
Arla Foods a confirmé avoir été victime d'une cyberattaque. L'incident a entraîné des perturbations dans leurs opérations de production et causé des retards. 🏭 Les détails spécifiques sur le type d'attaque (ransomware, etc.), les auteurs ou l'impact complet ne sont pas fournis dans cet article. 📰
* Publication date : 2025/05/19
* 🔗 Source : https://www.bleepingcomputer.com/news/security/arla-foods-confirms-cyberattack-disrupts-production-causes-delays/
* 🎯 Threat Target : Arla Foods (secteur agroalimentaire)
* 📈 Threat Tactic : Cyberattaque (type non spécifié)
* 💡 Security recommandations : Renforcer les défenses cyber. Mettre en place un plan de réponse aux incidents pour minimiser l'impact des attaques.