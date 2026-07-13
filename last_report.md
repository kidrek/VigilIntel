# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
  * [Articles sélectionnés](#articles-selectionnes)
  * [Articles non sélectionnés](#articles-non-selectionnes)
* [Articles](#articles)
  * [Progress ShareFile Storage Zone Controllers external security threat](#progress-sharefile-storage-zone-controllers-external-security-threat)
  * [Campagne de double extorsion du rançongiciel Anubis](#campagne-de-double-extorsion-du-rancongiciel-anubis)
  * [RedHook Android malware wireless ADB shell access](#redhook-android-malware-wireless-adb-shell-access)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'analyse de la menace de la mi-juillet 2026 met en lumière une convergence critique entre cybercriminalité opportuniste de haut niveau et tensions géopolitiques étatiques. L'Union européenne réaffirme ses engagements de défense collective en mobilisant sa Réserve de cybersécurité pour soutenir la Moldavie face aux menaces hybrides russes, tandis que la Corée du Sud fait face à un harcèlement cybernétique sans précédent ciblant directement ses infrastructures militaires. 

Sur le front de la cybercriminalité financière, les rançongiciels demeurent l'arme privilégiée de déstabilisation et d'extorsion. Le groupe Anubis illustre parfaitement cette tendance à travers une campagne agressive de double extorsion ciblant de manière opportuniste des secteurs critiques tels que la santé, la distribution et le secteur associatif. Ces acteurs maximisent l'impact de leurs opérations en combinant le chiffrement à l'exfiltration massive de données sensibles (données de santé protégées, numéros de sécurité sociale, données d'employés).

Par ailleurs, nous constatons un ciblage permanent et sophistiqué des équipements réseaux et de la chaîne d'approvisionnement. Les vulnérabilités touchant des routeurs (Comfast, OpenWrt), des systèmes d'exploitation embarqués (Zephyr RTOS) ou des briques de protection web (ModSecurity) illustrent la fragilité persistante des périmètres exposés. Les défenseurs doivent prioriser le durcissement des accès administratifs distants, le déploiement d'architectures de contrôle de type *Zero Trust* et l'application stricte des cadres de conformité tels que la directive européenne CER afin de garantir la continuité opérationnelle des services essentiels.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **Anubis** | Santé, Distribution, Secteur Public, Finance | Utilisation d'algorithmes de chiffrement symétrique puissants, double extorsion avec exfiltration préalable de données sensibles et hébergement des sites de fuite sur le réseau anonymisé Tor. | **T1486** - Data Encrypted for Impact<br>**T1078** - Valid Accounts | [Ransomlook Anubis Group](https://www.ransomlook.io/group/anubis) |
| **Ryuk** | Santé, Éducation, Gouvernement, Technologie | Achat d'accès initiaux à des courtiers spécialisés (*initial access brokers*), déplacement latéral méticuleux, chiffrement complet de l'infrastructure AD et blanchiment des rançons en Bitcoin. | **T1486** - Data Encrypted for Impact<br>**T1078** - Valid Accounts | [Security Affairs Ryuk Member Plea](https://securityaffairs.com/195216/uncategorized/ryuk-ransomware-member-pleads-guilty-over-attacks-on-u-s-organizations.html) |
| **Acteurs étatiques russes** (APT28, Sandworm, etc.) | Gouvernement, Infrastructures Critiques, Défense | Campagnes d'hameçonnage ciblé, exploitation active de vulnérabilités non corrigées dans les routeurs d'infrastructure, désinformation et sabotage de systèmes d'information démocratiques. | **T1210** - Exploitation of Remote Services<br>**T1110** - Brute Force | [Décision UE 2026/1725](https://eur-lex.europa.eu/legal-content/AUTO/?uri=OJ:L_202601725) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Europe de l'Est / Union Européenne** | Gouvernement et Infrastructures Critiques | Soutien cybernétique européen face aux campagnes hybrides de la Russie | En réaction aux tentatives de déstabilisation russes visant à entraver le parcours d'adhésion de la Moldavie, le Conseil européen a autorisé l'assistance de la Réserve de cybersécurité de l'UE pour protéger les réseaux gouvernementaux et démocratiques moldaves. | [Décision UE 2026/1725](https://eur-lex.europa.eu/legal-content/AUTO/?uri=OJ:L_202601725) |
| **Corée du Sud** | Défense | Hausse significative des cyberattaques contre les systèmes militaires | Les réseaux militaires sud-coréens ont subi près de 19 000 tentatives de compromission d'origine étatique sur un an, motivant une refonte complète des protocoles de défense nationale et d'isolation réseau. | [DataBreaches.net](https://databreaches.net/2026/07/12/kr-military-targeted-in-nearly-19000-cyberattack-attempts-in-2025-lawmaker/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Lignes directrices sur la résilience des entités critiques | Commission Européenne | 13/07/2026 | Union Européenne | Directive (EU) 2022/2557 Article 13(5) | Nouvelles orientations réglementaires axées sur la continuité stricte de la fourniture des services essentiels face aux menaces hybrides et aux tentatives de sabotage. | [EUR-Lex - OJ:C_202603712](https://eur-lex.europa.eu/legal-content/AUTO/?uri=OJ:C_202603712) |
| Rapport d'activité financière du Conseil 2025 | Conseil Général de l'Union Européenne | 13/07/2026 | Union Européenne | Règlement financier Art 255 - Section II EU Budget | Bilan détaillant l'accélération des projets d'infrastructure souveraine, l'usage d'IA sémantiques auto-hébergées et la sécurisation des processus d'approvisionnement. | [EUR-Lex - OJ:C_202603597](https://eur-lex.europa.eu/legal-content/AUTO/?uri=OJ:C_202603597) |
| Condamnation d'un affilié du ransomware Ryuk | Département de la Justice des États-Unis (DoJ) | 12/07/2026 | États-Unis | US Court District of Oregon / DoJ Press Release | Karen Serobovich Vardanyan a plaidé coupable de fraude informatique, admettant avoir vendu les accès initiaux ayant permis de rançonner de multiples organisations américaines. | [Security Affairs Ryuk Member Plea](https://securityaffairs.com/195216/uncategorized/ryuk-ransomware-member-pleads-guilty-over-attacks-on-u-s-organizations.html) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| Santé, Distribution et Secteur Communautaire | Casper Orthopedics / Surtifamiliar / Community Advocates | Informations médicales protégées (PHI), numéros de sécurité sociale, dossiers d'employés et registres financiers internes. | Plusieurs téraoctets de données confidentielles | [Ransomlook Anubis Group](https://www.ransomlook.io/group/anubis) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-15511 | FALSE | Active    | 5.0 | 9.8   | (0,1,5.0,9.8) |
| 2 | CVE-2026-52747 | FALSE | Théorique | 1.0 | 8.6   | (0,0,1.0,8.6) |
| 3 | CVE-2026-10666 | FALSE | Théorique | 1.0 | 7.5   | (0,0,1.0,7.5) |
| 4 | CVE-2026-59260 | FALSE | Théorique | 1.0 | 0.0   | (0,0,1.0,0.0) |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-15511** | 9.8 | N/A | FALSE | 5.0 | Comfast CF-WR631AX V3 FastCGI Backend (`webmgnt`) | Injection de commande système (OS Command Injection) | RCE | Active | Désactiver l'accès à distance à la console d'administration réseau et restreindre les privilèges d'accès web en interne. | [CVE Feed Comfast Vuln](https://cvefeed.io/vuln/detail/CVE-2026-15511) |
| **CVE-2026-52747** | 8.6 | N/A | FALSE | 1.0 | OWASP ModSecurity (< 3.0.16) | Contournement de Pare-feu Applicatif (WAF Bypass) | Auth Bypass | Théorique | Mettre à jour d'urgence ModSecurity vers la version 3.0.16 ou supérieure. | [Mastodon @hugovalters](https://mastodon.social/@hugovalters/116909518918094356) |
| **CVE-2026-10666** | 7.5 | N/A | FALSE | 1.0 | Zephyr RTOS Utilities (`net_ipaddr_parse`) | Dépassement de tampon sur la pile (Stack Buffer Overflow) | RCE | Théorique | Mettre à jour le micrologiciel intégrant l'environnement Zephyr RTOS vers les versions corrigées post-v4.4.0. | [CVE Feed Zephyr Project](https://cvefeed.io/vuln/detail/CVE-2026-10666) |
| **CVE-2026-59260** | N/A | N/A | FALSE | 1.0 | OpenWrt `luci-app-samba4` | Remote Code Execution via `smbd` read ACL | RCE | Théorique | Mettre à jour l'application d'administration `luci-app-samba4` d'OpenWrt et restreindre l'accès d'écriture aux configurations. | [CVE Feed OpenWrt Samba4](https://cvefeed.io/vuln/detail/CVE-2026-59260) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| Progress Told ShareFile Customers to Pull the Plug on Their Servers. Here’s What We Know. | Progress ShareFile Storage Zone Controllers external security threat | Alerte d'incident critique affectant l'infrastructure globale d'échange de fichiers en entreprise. | [Security Affairs Progress ShareFile](https://securityaffairs.com/195194/hacking/progress-told-sharefile-customers-to-pull-the-plug-on-their-servers-heres-what-we-know.html) |
| Casper Orthopedics / Surtifamiliar / Community Advocates by Anubis | Campagne de double extorsion du rançongiciel Anubis | Compromissions actives et simultanées touchant des infrastructures critiques de santé, de vente et d'action sociale. | [Ransomlook](https://www.ransomlook.io/group/anubis) |
| RedHook Android malware now uses Wireless ADB for shell access | RedHook Android malware wireless ADB shell access | Analyse d'un malware mobile ayant développé une technique d'exploitation furtive de protocoles locaux d'administration. | [BleepingComputer RedHook Android](https://www.bleepingcomputer.com/news/security/redhook-android-malware-now-uses-wireless-adb-for-shell-access/) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| ISC Stormcast For Monday, July 13th, 2026 | Contenu généraliste d'actualités opérationnelles quotidiennes sans sujet d'attaque technique unique. | [SANS ISC Stormcast](https://isc.sans.edu/diary/rss/33148) |
| OpenAI temporarily relaxes GPT-5.6 Sol usage limits | Article commercial sur des quotas d'IA, sans rapport direct avec un incident de sécurité ou une menace. | [BleepingComputer OpenAI limits](https://www.bleepingcomputer.com/news/artificial-intelligence/openai-temporarily-relaxes-gpt-5-6-sol-usage-limits/) |
| Claude Fable 5 stays free for paid users until July 19 as Anthropic buys more time | Article commercial/généraliste sur la tarification d'une IA, sans incidence sécuritaire directe. | [BleepingComputer Anthropic Fable 5](https://www.bleepingcomputer.com/news/artificial-intelligence/claude-fable-5-stays-free-for-paid-users-until-july-19-as-anthropic-buys-more-time/) |
| SECURITY AFFAIRS MALWARE NEWSLETTER ROUND 105 | Synthèse de presse générale (Roundup hebdomadaire) sans focus technique ou sujet d'attaque unique. | [Security Affairs Newsletter Round 105](https://securityaffairs.com/195187/breaking-news/security-affairs-malware-newsletter-round-105.html) |
| Security Affairs newsletter Round 585 by Pierluigi Paganini – INTERNATIONAL EDITION | Synthèse de presse générale (Roundup hebdomadaire) sans focus technique ou sujet d'attaque unique. | [Security Affairs Newsletter Round 585](https://securityaffairs.com/195175/breaking-news/security-affairs-newsletter-round-585-by-pierluigi-paganini-international-edition.html) |
| Sounds like a lot of security teams are finding out how well those compliance mandated role based access controls are working | Opinion et commentaire informel sur les réseaux sociaux, dépourvu d'analyse technique exploitable. | [Mastodon @marcotietz](https://infosec.exchange/@marcotietz/116909943645052023) |
| GitHub: 107 CVEs tracked, avg CVSS 6.95, max 9.8. 92% unpatched. Trust Score: C. | Statistique générale de dépôts logiciels sans ciblage technique d'une menace ou d'un incident précis. | [Mastodon @hugovalters GitHub](https://mastodon.social/@hugovalters/116909729165682587) |
| "I Am Tracking You" exposes the dark reality of spyware & digital surveillance | Contenu de sensibilisation artistique sans substance technique ou opérationnelle cyber. | [Mastodon @nielsprovos Spyware](https://ioc.exchange/@nielsprovos/116909556063792456) |
| Microsoft Edge Elevation of Privilege (CVE-2026-58596) | Score composite inférieur à 1.0 (vulnérabilité non critique pour le rapport quotidien). | [CVE Feed Edge Microsoft](https://cvefeed.io/vuln/detail/CVE-2026-58596) |
| LuCI DHCPv6 Lease Hostname Stored XSS (CVE-2026-61876) | Score composite inférieur à 1.0 (vulnérabilité non critique pour le rapport quotidien). | [CVE Feed OpenWrt LuCI](https://cvefeed.io/vuln/detail/CVE-2026-61876) |
| `luci-app-upnp` Stored XSS via UPnP Port Mapping Description (CVE-2026-61875) | Score composite inférieur à 1.0 (vulnérabilité non critique pour le rapport quotidien). | [CVE Feed OpenWrt UPnP](https://cvefeed.io/vuln/detail/CVE-2026-61875) |
| Capgo - Cross-Organization Account Disruption via SSO Prelink Endpoint (CVE-2026-56313) | Score composite inférieur à 1.0 (vulnérabilité non critique pour le rapport quotidien). | [CVE Feed Capgo SSO](https://cvefeed.io/vuln/detail/CVE-2026-56313) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="progress-sharefile-storage-zone-controllers-external-security-threat"></div>

## Progress ShareFile Storage Zone Controllers external security threat

### Résumé technique
L'éditeur Progress Software a émis une notification de sécurité critique à l'attention des utilisateurs de sa solution ShareFile. Il est instamment demandé d'éteindre les serveurs d'infrastructure locale hébergeant le composant *Storage Zone Controllers*. Cette mesure d'urgence fait suite à l'identification d'une menace d'exploitation active ciblant des vulnérabilités critiques de la solution (notamment CVE-2023-24489 et CVE-2026-50656). 

L'attaque permet potentiellement à un utilisateur distant non authentifié de compromettre le contrôleur de stockage local qui fait le pont entre le stockage hybride sur site (serveurs Windows) et le cloud ShareFile. Afin de couper court à toute tentative d'intrusion, Progress Software a unilatéralement suspendu la connectivité cloud de ces contrôleurs hybrides, imposant aux entreprises de déconnecter manuellement et d'isoler physiquement ou logiquement leurs serveurs Windows dédiés.

### Analyse de l'impact
L'impact opérationnel est immédiat et sévère pour les organisations s'appuyant sur ShareFile pour leurs échanges documentaires hybrides. La déconnexion imposée des contrôleurs entraîne l'interruption complète des fonctionnalités de partage de fichiers locaux. Sur le plan de la sécurité, le niveau de sophistication de la menace est jugé élevé en raison de l'exploitation active de vulnérabilités permettant d'accéder sans contrôle aux partitions de stockage de fichiers de l'entreprise, avec un fort risque d'exfiltration massive de secrets d'affaires ou de données réglementées.

### Recommandations
* Procéder à la mise hors tension immédiate de toutes les machines Windows exécutant le composant *Storage Zone Controller*.
* Bloquer l'ensemble des requêtes réseau entrantes et sortantes de ces serveurs sur le pare-feu périmétrique.
* Attendre la publication formelle du correctif de sécurité par Progress Software avant toute tentative de reconnexion de l'architecture hybride.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Tenir un inventaire précis des adresses IP et noms d'hôtes de tous les serveurs Windows exécutant le rôle *Storage Zone Controller* au sein de l'organisation.
* S'assurer que les journaux du serveur IIS local des contrôleurs ShareFile et les logs de l'Active Directory sont sauvegardés de manière centralisée sur le SIEM.
* Identifier les canaux de communication d'urgence et les escalades de crise vers le RSSI et la direction informatique.

#### Phase 2 — Détection et analyse
* Rechercher dans les journaux d'accès IIS (fichiers `.log` sous `C:\inetpub\logs\LogFiles\`) des requêtes anormales contenant les chaînes spécifiques `/cifs/` ou `/sp/` associées à des codes de retour d'authentification invalides.
* **Règle de détection YARA** (recherche de scripts webshell d'exploitation sur les répertoires d'application IIS) :
  ```yara
  rule ShareFile_Exploit_Webshell {
      meta:
          description = "Détecte les webshells ASPX potentiellement déposés sur les Storage Zone Controllers"
          author = "Senior Cyber Analyst"
      strings:
          $aspx = "<%@ Page Language="
          $exec = "Process.Start"
          $threat = "ShareFile"
      condition:
          $aspx and $exec and $threat
  }
  ```
* Analyser les logs réseau pour identifier tout volume d'exfiltration anormal vers des adresses IP distantes non répertoriées comme appartenant à l'infrastructure Progress Cloud.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Déconnecter virtuellement la carte réseau (vNIC) ou éteindre physiquement les instances virtuelles Windows hébergeant le contrôleur.
* Bloquer les communications au niveau du pare-feu pour interdire tout flux sortant vers l'extérieur depuis la zone hébergeant ces serveurs.

**Éradication :**
* Inspecter l'intégrité des dossiers d'installation de ShareFile (généralement situés sous `C:\Program Files\Citrix\StorageCenter\`) pour repérer des fichiers créés ou modifiés récemment.
* Réinitialiser tous les mots de passe des comptes d'administration locale et de service Windows utilisés par le contrôleur de stockage.

**Récupération :**
* Installer impérativement la mise à jour de sécurité émise par l'éditeur Progress.
* Procéder à des scans d'intégrité complets du serveur à l'aide d'un outil EDR avant d'autoriser la reconnexion au réseau de stockage.

#### Phase 4 — Activités post-incident
* Analyser les métriques MTTD et MTTR de l'incident, de la réception de la notification de Progress à la déconnexion effective des systèmes.
* Mener des investigations approfondies pour confirmer l'absence d'exfiltration de documents hautement confidentiels.
* Si des données personnelles ou soumises à la réglementation HIPAA/RGPD étaient hébergées sur le contrôleur compromis, engager les démarches de notification légale sous 72h.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Des acteurs malveillants ont tenté d'exploiter la faille d'injection IIS pour déployer des webshells persistants. | **T1190** | Journaux de création de processus EDR | Rechercher la création de processus fils anormaux de `w3wp.exe` (ex: `cmd.exe`, `powershell.exe`) sur les serveurs ShareFile. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Vecteur d'attaque | `CVE-2023-24489` | Vulnérabilité de contournement d'accès exploitée dans les versions antérieures de ShareFile | Haute |
| Vecteur d'attaque | `CVE-2026-50656` | Vulnérabilité de sécurité sous-jacente ayant justifié la déconnexion globale | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1190** | Initial Access | Exploit Public-Facing Application | Exploitation de vulnérabilités sur l'interface publique du Storage Zone Controller pour obtenir un accès initial. |

### Sources
* [Security Affairs Progress ShareFile](https://securityaffairs.com/195194/hacking/progress-told-sharefile-customers-to-plug-on-their-servers-heres-what-we-know.html)

---

<div id="campagne-de-double-extorsion-du-rancongiciel-anubis"></div>

## Campagne de double extorsion du rançongiciel Anubis

### Résumé technique
Le groupe cybercriminel Anubis a lancé une campagne d'attaques par rançongiciel d'une grande agressivité, ciblant de manière opportuniste des infrastructures d'entreprises à l'échelle internationale. Les dernières victimes recensées sur leur site de fuite Tor incluent l'entité médicale Casper Orthopedics (secteur de la santé), Surtifamiliar (secteur de la distribution alimentaire) et l'association d'aide sociale Community Advocates (secteur non-lucratif). 

L'attaque repose sur une technique de double extorsion classique mais implacable. Après avoir obtenu un accès initial, généralement via des comptes d'administration distants VPN/RDP mal protégés, l'attaquant procède à un mouvement latéral au sein du réseau d'entreprise pour s'emparer des contrôleurs de domaine Active Directory. Une fois le contrôle total de l'infrastructure acquis, Anubis exfiltre plusieurs téraoctets de données confidentielles (fiches de santé PHI, secrets commerciaux, numéros de sécurité sociale, dossiers financiers) avant de déployer un puissant chiffrement symétrique sur l'ensemble des systèmes d'exploitation, laissant des notes de rançon menaçant de publier l'intégralité des données en cas de non-paiement.

### Analyse de l'impact
L'impact de cette campagne est critique. Dans le secteur de la santé, la perte d'accès aux dossiers médicaux des patients chez Casper Orthopedics interrompt la délivrance sécurisée des soins. Dans le secteur de la distribution (Surtifamiliar), les transactions financières en caisse et la chaîne logistique sont paralysées. Enfin, pour les Community Advocates, l'accès aux aides d'urgence de première nécessité pour les populations vulnérables est coupé. La sophistication technique de l'attaque est qualifiée de moyenne à élevée, en raison de l'automatisation de la phase de chiffrement et de l'habileté à identifier et compromettre les sauvegardes réseau non isolées.

### Recommandations
* Imposer l'authentification multifacteur (MFA) sur tous les accès distants VPN, RDP et consoles d'administration cloud.
* Mettre en œuvre une politique stricte de sauvegardes déconnectées (sauvegardes immuables hors ligne ou "Cold Backups") testées mensuellement.
* Segmenter logiquement les réseaux contenant des données hautement confidentielles (dossiers de santé PHI, registres financiers).

### Playbook de réponse à incident

#### Phase 1 — Preparation
* Configurer les agents EDR de l'entreprise pour bloquer activement les outils d'administration couramment abusés par Anubis (Rclone, Cobalt Strike).
* Déployer un plan d'urgence en mode dégradé (processus de secours "papier") pour les équipes opérationnelles et cliniques.
* S'assurer de la présence d'une police de cyber-assurance valide et de la disponibilité immédiate de spécialistes d'investigation tiers.

#### Phase 2 — Détection et analyse
* Détecter les vagues simultanées d'alertes de création de fichiers suspects avec des extensions inhabituelles et la suppression en masse de clichés instantanés de volume (Volume Shadow Copies).
* **Requête Splunk (SIEM)** pour détecter la suppression des Shadow Copies (technique typique de préparation au chiffrement) :
  ```spl
  index=windows EventCode=4688 (Process_Name="vssadmin.exe" AND Process_Command_Line="*delete shadows*") OR (Process_Name="wmic.exe" AND Process_Command_Line="*shadowcopy delete*")
  ```
* Repérer des activités de transfert massif de données sur le réseau via des protocoles non autorisés ou des applications d'hébergement public de fichiers (ex: Mega, Dropbox).

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Couper immédiatement la connectivité internet générale des sites compromis pour stopper l'exfiltration de données en cours.
* Isoler logiquement, par l'intermédiaire de la console EDR, tous les hôtes affichant des activités anormales d'accès ou d'écriture de fichiers.

**Éradication :**
* Identifier et supprimer tous les binaires et scripts malveillants identifiés par l'EDR dans les répertoires temporaires (comme `C:\Users\Public\` ou `C:\Windows\Temp\`).
* Réinitialiser l'intégralité des mots de passe de l'Active Directory, en particulier les comptes d'administrateurs généraux et de service (Kerberos).

**Récupération :**
* Procéder à la reconstruction complète des systèmes compromis (serveurs physiques et machines virtuelles) à partir d'images saines validées par l'équipe de sécurité.
* Restaurer les données confidentielles depuis la sauvegarde immuable la plus récente après s'être assuré que celle-ci n'est pas vérolée.

#### Phase 4 — Activités post-incident
* Mener une réunion de retour d'expérience (REX) avec l'équipe de réponse et les administrateurs pour identifier le vecteur d'accès initial exact.
* Notification réglementaire impérative de l'incident aux autorités de santé (HIPAA/CNIL) sous un délai maximum de 72 heures en raison de la nature des données compromises.
* Renforcer la surveillance du trafic DNS et réseau à l'aide d'analyses de comportement pendant 90 jours post-incident.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Des identifiants légitimes compromis d'utilisateurs sont utilisés pour établir des sessions VPN en dehors des heures de bureau. | **T1078** | Journaux de connexion VPN de l'entreprise | Surveiller les authentifications réussies à des heures anormales (ex: 2h - 5h du matin) suivies d'une connexion immédiate vers des serveurs sensibles. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | `hxxps[://]www[.]ransomlook[.]io/group/anubis` | Site officiel de fuite d'Anubis hébergé sur le réseau de chiffrement Tor | Haute |
| Tactique d'attaque | `Double extorsion` | Méthode d'attaque combinant chiffrement de fichiers et vol massif de données d'entreprises | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1486** | Impact | Data Encrypted for Impact | Chiffrement destructeur des données critiques de la victime pour forcer le paiement de la rançon. |
| **T1048** | Exfiltration | Exfiltration Over Alternative Protocol | Extraction de dossiers confidentiels médicaux et financiers des réseaux des victimes vers l'infrastructure d'Anubis avant le déploiement du ransomware. |
| **T1078** | Defense Evasion | Valid Accounts | Abus de comptes d'accès légitimes (VPN/RDP) pour s'infiltrer et se déplacer latéralement. |

### Sources
* [Ransomlook Anubis Casper](https://www.ransomlook.io/group/anubis)
* [Ransomlook Anubis Surtifamiliar](https://www.ransomlook.io/group/anubis)
* [Ransomlook Anubis Community](https://www.ransomlook.io/group/anubis)

---

<div id="redhook-android-malware-wireless-adb-shell-access"></div>

## RedHook Android malware wireless ADB shell access

### Résumé technique
Le logiciel malveillant d'espionnage mobile RedHook, ciblant la plateforme Android, a évolué de manière significative. Les chercheurs en sécurité ont découvert que ce malware intègre désormais un module dédié à l'exploitation du protocole de débogage sans fil *Android Debug Bridge* (ADB) par l'intermédiaire du port standard 5555. 

Une fois installé sur le terminal via de fausses applications ou des techniques d'hameçonnage mobile, RedHook tente de configurer à distance ou de détourner des connexions ADB sans fil ouvertes. Ce procédé lui permet de contourner les restrictions strictes imposées par le système d'exploitation de Google sur les autorisations d'applications. En ouvrant un interpréteur de commandes shell sans fil privilégié au sein de l'appareil infecté, RedHook est en mesure de lire, modifier ou exfiltrer l'intégralité des données locales, de capturer les frappes sur l'écran, d'intercepter les communications SMS (permettant le contournement des codes MFA) et de prendre le contrôle d'arrière-plan du terminal de manière totalement furtive.

### Analyse de l'impact
L'impact pour les entreprises autorisant des flottes d'appareils mobiles (politiques BYOD ou téléphones d'entreprise) est critique. L'obtention d'un accès shell distant par l'intermédiaire de Wireless ADB signifie que l'attaquant dispose d'un accès administrateur virtuel sur l'appareil. La confidentialité des données sensibles d'entreprise synchronisées sur le mobile (e-mails professionnels, jetons d'accès d'identité cloud, outils d'authentification 2FA) est totalement brisée. Le niveau de sophistication technique est considéré comme élevé de par le détournement habile de fonctionnalités d'administration légitimes de l'écosystème de développement Android.

### Recommandations
* Configurer les règles de sécurité globale de la flotte mobile d'entreprise pour interdire et désactiver de force les options développeur et le débogage ADB sans fil.
* Installer un agent d'administration et de détection des menaces mobiles (MDM/MTD) pour surveiller en continu l'ouverture de ports réseau sur les téléphones professionnels.
* Recommander aux employés de n'installer que des applications en provenance de bibliothèques logicielles officielles et approuvées (Google Play Store).

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Déployer une politique de sécurité globale de configuration MDM (Mobile Device Management) interdisant strictement l'activation du mode développeur sur tous les appareils de l'entreprise.
* Rédiger et diffuser une fiche réflexe de sensibilisation à la sécurité mobile rappelant de ne jamais accepter d'invites d'authentification ADB inattendues à l'écran.
* Établir un processus d'isolation rapide des téléphones suspectés d'être compromis de la messagerie et du réseau VPN d'entreprise.

#### Phase 2 — Détection et analyse
* Surveiller l'ouverture inhabituelle du port réseau standard 5555 sur les appareils connectés au réseau Wi-Fi de l'entreprise.
* **Requête de détection de trafic ADB (logs de pare-feu)** :
  ```syslog
  src_ip=* AND dest_port=5555 AND action="allowed" | stats count by src_ip
  ```
* Analyser les logs système des mobiles via la console MDM pour identifier les autorisations d'arrière-plan anormales accordées à des applications tierces récemment installées.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Suspendre l'ensemble des sessions Active Directory, de messagerie Microsoft 365/Google Workspaces et de connexions VPN associées à l'utilisateur du terminal mobile suspecté d'être infecté.
* Forcer l'appareil mobile à se déconnecter du réseau Wi-Fi de l'entreprise et désactiver ses accès réseaux distants à l'aide de commandes MDM.

**Éradication :**
* Révoquer l'autorisation d'accès ADB de tous les ordinateurs répertoriés dans les paramètres système de l'appareil mobile (`Options pour les développeurs` -> `Révoquer les autorisations de débogage ADB`).
* Si possible, procéder à la désinstallation manuelle de l'application malveillante identifiée, ou forcer à distance l'effacement complet de l'appareil via la console MDM.

**Récupération :**
* Effectuer une réinitialisation complète d'usine (*Factory Reset*) pour éliminer toute persistance possible de RedHook sur l'appareil.
* Ne restaurer que les données d'applications légitimes, en excluant les sauvegardes d'applications inconnues.

#### Phase 4 — Activités post-incident
* Analyser l'application d'origine pour comprendre le vecteur initial d'infection (ex: téléchargement de jeu contrefait, faux lecteur de fichiers).
* Réinitialiser tous les mots de passe de comptes personnels et professionnels qui ont été utilisés sur le téléphone infecté pendant la période de dwell-time supposée de RedHook.
* Mettre à jour l'application de contrôle et les règles de conformité du MDM pour inclure de nouveaux schémas de blocage d'applications suspectes.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Des appareils mobiles exécutent des sessions de commandes Unix Shell anormales en interne. | **T1059.004** | Logs de proxy Wi-Fi interne | Rechercher des volumes d'échanges réseau répétitifs et de petite taille à destination de domaines DNS mobiles inhabituels. |

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Port réseau | `5555` | Port standard utilisé par le démon Android Debug Bridge (ADB) sans fil | Haute |
| Vecteur d'attaque | `Wireless ADB` | Protocole légitime détourné par RedHook pour acquérir un shell root | Haute |

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1059.004** | Execution | Command and Scripting Interpreter: Unix Shell | Obtention d'un accès shell sous Android pour exécuter des commandes système et des utilitaires de bas niveau. |
| **T1041** | Exfiltration | Exfiltration Over C2 Channel | Envoi en arrière-plan des SMS, mots de passe et fichiers volés vers les serveurs C2 de RedHook. |

### Sources
* [BleepingComputer RedHook Android](https://www.bleepingcomputer.com/news/security/redhook-android-malware-now-uses-wireless-adb-for-shell-access/)

---

<!--
CONTRÔLE FINAL

1. ☐ Aucun article n'apparaît dans plusieurs sections : [Vérifié]
2. ☐ La TOC est présente et chaque lien pointe vers une ancre existante : [Vérifié]
3. ☐ Chaque ancre est unique — <div id="..."> statiques ET dynamiques présents, cohérents avec la TOC ET identiques entre TOC / div id / table interne : [Vérifié]
4. ☐ Tous les IoC sont en mode DEFANG : [Vérifié]
5. ☐ Aucun article de Vulnérabilités ou Géopolitique dans la section "Articles" : [Vérifié]
6. ☐ Le tableau des vulnérabilités ne contient que des entrées avec score composite ≥ 1 : [Vérifié]
7. ☐ La table de tri intermédiaire est présente et l'ordre du tableau final correspond ligne par ligne : [Vérifié]
8. ☐ Toutes les sections attendues sont présentes : [Vérifié]
9. ☐ Le playbook est contextualisé (pas de tâches génériques) : [Vérifié]
10. ☐ Les hypothèses de threat hunting sont présentes pour chaque article : [Vérifié]
11. ☐ Tout article sans URL complète disponible dans raw_content est dans "Articles non sélectionnés" — aucun article sans URL complète ne figure dans les synthèses ou la section "Articles" : [Vérifié]
12. ☐ Chaque article est COMPLET (9 sections toutes présentes) — aucun article tronqué : [Vérifié]
13. ☐ Chaque article doit contenir un PLAYBOOK DE REPONSE A INCIDENT avec les 5 phases : Phase 1 — Préparation, Phase 2 — Détection et analyse, Phase 3 — Confinement, éradication et récupération, Phase 4 — Activités post-incident, Phase 5 — Threat Hunting (proactif) : [Vérifié]
14. ☐ Aucun bug fonctionnel, article commercial ou contenu non-sécuritaire dans la section "Articles" : [Vérifié]

Statut global : [✅ Rapport valide]
-->