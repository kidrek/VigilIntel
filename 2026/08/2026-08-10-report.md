# Brief quotidien de veille cyber - 2026-08-10

* **Domaine :** cyber SOC/CERT
* **Date :** 2026-08-10
* **Entrée :** 54 articles scrapés
* **Sortie :** 13 clusters produits (4 vulnérabilités, 8 menaces, signaux géopolitiques et réglementaires)

## Table des matières

- [Géopolitique](#geopolitique)
- [Réglementaire et légal](#reglementaire-et-legal)
- [Vulnérabilités](#vulnerabilites)
- [Menaces SOC/CERT](#menaces-soc-cert)

<a id="analyse-strategique"></a>
## Analyse stratégique

L'actualité du jour est dominée par une vague d'attaques par ingénierie sociale ciblant l'humain plutôt que les systèmes : Levi Strauss & Co. confirmé compromis via trois simples appels téléphoniques (sans exploit, sans malware), et un rapport fait état de dizaines de grandes firmes financières américaines (Blackstone, CME) compromises par du vishing ransomware. Le signal est clair : le maillon humain et les processus d'assistance téléphonique deviennent le vecteur d'accès initial privilégié, contournant les défenses techniques. Les SOC/CERT doivent traiter la sensibilisation au vishing et le contrôle des procédures de réinitialisation/support comme une priorité opérationnelle, au même rang que le patch de CVE critiques.

Le second signal fort est la pression continue sur le secteur santé et l'identité numérique : AnMed Health (83 établissements en arrêt depuis le 26 juillet 2026), DentaQuest (plus grosse breach santé 2026, ShinyHunters), Alcon (218k comptes, ShinyHunters), American Addiction Centers (Salesforce, SSN exposés), et la divulgation DEF CON de failles critiques dans l'eID belge Connective (2M utilisateurs, 8 banques sur 10, 60 agences gouvernementales). Côté vulnérabilités éditaires, le lot MSI Radix AXE6600 (10 CVE en RCE racine, CVSS 9.8) illustre la persistance d'une surface d'attaque IoT/routeur grand public négligée. Contexte français à surveiller : ZATAZ rapporte 1,7 milliard d'identifiants français uniques découverts dans un cloud pirate et 43 revendications de rançongiciels contre la France en un mois, dont Stade Français (Qilin).

<a id="geopolitique"></a>
## Géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Chine / US** | Cybersécurité / Tech | Revue de cybersécurité chinoise sur Palo Alto Networks | Palo Alto Networks fait l'objet d'une revue de cybersécurité par la Chine dans un contexte de tensions technologiques croissantes entre Pékin et Washington. Mesure qui s'inscrit dans la dynamique de réciprocité sur les audits et exclusions de fournisseurs étrangers, déjà observée avec Kaspersky, Huawei et les éditeurs occidentaux visés par les régulations américaines. | [securityaffairs](https://securityaffairs.com/196890/cyber-crime/u-s-defense-manufacturer-ieh-hit-by-phishing-attack-exposing-potentially-export-controlled-data.html) |
| **UK** | Industrie manufacturière | 30 % des manufacturiers britanniques cyberattaqués en 12 mois | Sondage MakeUK : près d'un tiers des manufacturiers britanniques ont subi un incident cyber sur 12 mois, dont JLR (arrêt production plusieurs semaines en août 2025). Seule la moitié dispose d'un plan de réponse. Le coût du cybercrime pour l'économie UK est évalué à 14,7 Mds £/an. L'IA générative (capable de pirater de façon autonome) aggrave l'urgence. | [The Guardian](https://www.theguardian.com/technology/2026/aug/10/uk-companies-cyber-attack-third-jlr) |

<a id="reglementaire-et-legal"></a>
## Réglementaire et légal

La régime NIS2 et le RGPD pèsent sur la vague française de breaches : ZATAZ recense 43 revendications de rançongiciels contre la France en un mois, et 1,7 milliard d'identifiants français uniques dans un cloud pirate. Les victimes françaises identifiées du jour (Stade Français via Qilin, avec exposition de pièces d'identité) sont soumises à notification obligatoire à la CNIL sous 72h en cas de breach de données personnelles, et notification d'incident significatif à l'ANSSI sous 24h au titre de NIS2 (si entité essentielle/importante).

**Thaïlande - MFA obligatoire après fuite de 60 millions d'identifiants :** le gouvernement thaïlandais envisage d'imposer l'authentification multi-facteurs à la suite d'une fuite majeure de credentials. Le MFA reste l'une des défenses les plus efficaces contre le credential stuffing et le takeover de comptes. Source : [infosec.exchange/@cloud](https://infosec.exchange/@cloud/117068170813559935) (Nation Thailand).

<a id="vulnerabilites"></a>
## Vulnérabilités

### MSI (Vulncheck, 10 CVE sur RadiX AXE6600)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-71993](https://www.cve.org/CVERecord?id=CVE-2026-71993) | 9.8 (CRITICAL, v3.1) | N/A | Non | **MSI** RadiX AXE6600 | v781521 | Command injection (openvpn) | RCE racine distante | MAJ firmware ; restreindre accès OpenVPN | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-71993)<br>[Vulncheck](https://www.vulncheck.com/advisories/msi-radix-axe6600-v781521-command-injection-via-openvpn-function) |
| [CVE-2026-71992](https://www.cve.org/CVERecord?id=CVE-2026-71992) | 9.8 (CRITICAL, v3.1) | N/A | Non | **MSI** RadiX AXE6600 | v781521 | Command injection (macfilter) | RCE racine distante | MAJ firmware ; restreindre macfilter | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-71992)<br>[Vulncheck](https://www.vulncheck.com/advisories/msi-radix-axe6600-v781521-command-injection-via-macfilter) |
| [CVE-2026-71991](https://www.cve.org/CVERecord?id=CVE-2026-71991) | 9.8 (CRITICAL, v3.1) | N/A | Non | **MSI** RadiX AXE6600 | v781521 | Command injection (TelnetSSH, Telnet) | RCE racine distante | MAJ firmware ; désactiver Telnet | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-71991)<br>[Vulncheck](https://www.vulncheck.com/advisories/msi-radix-axe6600-v781521-command-injection-via-telnetssh-function-used-for-telnet-configuration) |
| [CVE-2026-71990](https://www.cve.org/CVERecord?id=CVE-2026-71990) | 9.8 (CRITICAL, v3.1) | N/A | Non | **MSI** RadiX AXE6600 | v781521 | Command injection (TelnetSSH, SSH) | RCE racine distante | MAJ firmware ; restreindre SSH | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-71990)<br>[Vulncheck](https://www.vulncheck.com/advisories/msi-radix-axe6600-v781521-command-injection-via-telnetssh-function) |
| [CVE-2026-71989](https://www.cve.org/CVERecord?id=CVE-2026-71989) | 9.8 (CRITICAL, v3.1) | N/A | Non | **MSI** RadiX AXE6600 | v781521 | Command injection (porTrigger/alg) | RCE racine distante | MAJ firmware ; désactiver port triggering | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-71989)<br>[Vulncheck](https://www.vulncheck.com/advisories/msi-radix-axe6600-v781521-command-injection-via-portrigger-function) |
| [CVE-2026-71988](https://www.cve.org/CVERecord?id=CVE-2026-71988) | 9.8 (CRITICAL, v3.1) | N/A | Non | **MSI** RadiX AXE6600 | v781521 | Command injection (portFw/alg) | RCE racine distante | MAJ firmware ; restreindre alg | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-71988)<br>[Vulncheck](https://www.vulncheck.com/advisories/msi-radix-axe6600-v781521-command-injection-via-portfw-function) |
| [CVE-2026-71987](https://www.cve.org/CVERecord?id=CVE-2026-71987) | 9.8 (CRITICAL, v3.1) | N/A | Non | **MSI** RadiX AXE6600 | v781521 | Command injection (alg) | RCE racine distante | MAJ firmware ; désactiver alg si inutile | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-71987)<br>[Vulncheck](https://www.vulncheck.com/advisories/msi-radix-axe6600-v781521-command-injection-via-alg-function) |
| [CVE-2026-71986](https://www.cve.org/CVERecord?id=CVE-2026-71986) | 9.8 (CRITICAL, v3.1) | N/A | Non | **MSI** RadiX AXE6600 | v781521 | Command injection (dmz) | RCE racine distante | MAJ firmware ; désactiver DMZ | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-71986)<br>[Vulncheck](https://www.vulncheck.com/advisories/msi-radix-axe6600-v781521-command-injection-via-dmz-function) |
| [CVE-2026-71985](https://www.cve.org/CVERecord?id=CVE-2026-71985) | 9.8 (CRITICAL, v3.1) | N/A | Non | **MSI** RadiX AXE6600 | v781521 | Command injection (accesscontrol) | RCE racine distante | MAJ firmware ; restreindre accesscontrol | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-71985)<br>[Vulncheck](https://www.vulncheck.com/advisories/msi-radix-axe6600-v781521-command-injection-via-accesscontrol-function) |
| [CVE-2026-71984](https://www.cve.org/CVERecord?id=CVE-2026-71984) | 9.8 (CRITICAL, v3.1) | N/A | Non | **MSI** RadiX AXE6600 | v781521 | Command injection (urlfilter) | RCE racine distante | MAJ firmware ; restreindre interface admin | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-71984)<br>[Vulncheck](https://www.vulncheck.com/advisories/msi-radix-axe6600-v781521-command-injection-via-urlfilter) |

### UTT (Vuldb)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-19341](https://www.cve.org/CVERecord?id=CVE-2026-19341) | 8.8 (HIGH, v3.1) | N/A | Non | **UTT** HiPER 1200GW | <= 2.5.3-170306 | Stack-based buffer overflow (strcpy, /goform/pptpSrvGlobalConfig, arg EncryptionMode) | RCE distante (exploit public) | Patcher strcpy ; MAJ firmware ; contacter éditeur (sans réponse) | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-19341)<br>[Vuldb](https://vuldb.com/cve/CVE-2026-19341)<br>[PoC](https://github.com/7wkajk/CVE-VUL/blob/main/104.md) |

### Tenda (cvefeed)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-19346](https://www.cve.org/CVERecord?id=CVE-2026-19346) | N/A | N/A | Non | **Tenda** CH22 | N/A | Command injection (formCertListInfo) | RCE (probable) | Contacter éditeur ; restreindre interface admin | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-19346) |

### Shenzhen Aitemi (cvefeed)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-19348](https://www.cve.org/CVERecord?id=CVE-2026-19348) | N/A | N/A | Non | **Shenzhen Aitemi** M300 Wi-Fi Repeater | N/A | Command injection (protocol.csp, sprintf) | RCE (probable) | Contacter éditeur ; isoler le répéteur | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-19348) |

### Connective / Nitro Software Belgium (eID belge, divulgation DEF CON, failles corrigées)

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| N/A (failles non-CVE détaillées) | N/A (critique selon chercheur) | N/A | N/A | **Nitro Software Belgium** Connective (extension eID) | Versions antérieures au correctif | Contournement de vérification d'origine (absence de check du site appelant) ; spoofing de boîtes de dialogue d'authentification | Vol de données eID et carte de paiement ; vol de PIN eID ; forgery de signatures électroniques à valeur légale ; compromission de CSAM.be et Itsme | Correctif appliqué (failles résolues) ; surveiller les abus passés ; vérifier les signatures émises sur la période d'exposition | [SecurityWeek](https://www.securityweek.com/critical-flaws-discovered-in-belgian-eid-software-used-by-2-million-people/) |

> Le système Connective est utilisé par 2 millions d'utilisateurs, 8 des 10 plus grandes banques belges et plus de 60 agences gouvernementales. Un site malveillant ou une publicité en ligne pouvait lire silencieusement les données eID et carte de paiement, et déclencher des pop-ups d'authentification contrefaits pour soutirer le PIN eID, puis générer des tokens de signature électronique à valeur légale tant que la carte était insérée. Impact trust model large sur l'écosystème numérique belge (CSAM.be, Itsme). Divulgation par James Arnott (Bay Area Labs) à DEF CON. Voir aussi [Menaces SOC/CERT](#menaces-soc-cert) pour la dimension opérationnelle.

<a id="menaces-soc-cert"></a>
## Menaces SOC/CERT

<a id="levi-strauss-social-engineering"></a>
### Levi Strauss & Co. - Compromission par ingénierie sociale (3 appels téléphoniques)

#### Résumé technique

Levi Strauss & Co. a disclosed une breach de données corporate résultant d'une attaque d'ingénierie sociale ciblant trois employés. Selon le compte-rendu détaillé, trois appels téléphoniques ont suffi : aucun exploit technique, aucun malware. Les attaquants ont manipulé les employés pour exfiltrer des données corporate non spécifiées. Les données consommateurs ne sont pas impactées selon la société.

#### Analyse de l'impact

L'incident démontre que l'ingénierie sociale téléphonique reste un vecteur d'accès initial à haut rendement, contournant l'ensemble des contrôles techniques (EDR, pare-feu, MFA). Pour les SOC/CERT, cela signifie que la détection doit s'appuyer sur des signaux comportementaux et processus (anomalies de workflow, demandes d'accès inhabituelles, transferts de données) plutôt que sur des IOCs techniques. Le ciblage du retail et des fonctions support (IT, RH, finance) est à anticiper.

#### Recommandations

* Renforcer la sensibilisation au vishing et aux procédures d'assistance téléphonique (vérification en retour, callback sur numéro officiel).
* Imposer une validation hors-bande pour toute demande de transfert de données ou d'action privilégiée initiée par téléphone.
* Consigner et corréler les appels suspects remontés par les employés (canal de signalement dédié).
* Mettre en place la détection d'exfiltration de données corporate (DLP, anomalies de trafic sortant).

#### Playbook de réponse à incident

##### Phase 1 - Préparation
* Définir une procédure de vérification d'identité pour les demandes téléphoniques sensibles (token de validation, callback authentifié).
* Former les fonctions support (IT, RH, finance) aux scénarios de vishing ciblé.
* Activer la journalisation des accès données et des transferts externes.
* Préparer un canal de signalement rapide des appels suspects.

##### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle DLP : alerte sur transferts de données corporate volumineux ou inhabituels initiés dans les heures suivant un ticket d'assistance téléphonique.
  * Règle SIEM : corrélation entre ouverture de ticket support et accès données atypiques hors périmètre habituel de l'employé.
* Analyser la chronologie : horodatage des appels, actions effectuées par les employés ciblés, volume et nature des données exfiltrées.
* Identifier les comptes ayant servi de relais et les éventuels accès cédés.

##### Phase 3 - Confinement, éradication et récupération

**Confinement :**
* Révoquer les accès éventuellement cédés pendant l'appel (comptes, sessions, tokens).
* Isoler les postes des employés ciblés le temps de l'analyse.

**Éradication :**
* Supprimer les éventuels relais de persistance (aucun malware confirmé ici, mais vérifier les règles de forwarding email, accès OAuth, sessions actives).

**Récupération :**
* Réinitialiser les credentials des employés ciblés et de leur chaîne managériale.
* Surveiller 72h les accès données des fonctions support pour détecter un retour d'attaquant.

##### Phase 4 - Activités post-incident
* Rédiger le rapport d'incident avec chronologie des appels et actions.
* Évaluer MTTD/MTTR.
* REX avec fonctions support et direction.
* Notifications RGPD si données personnelles corporate impliquées (évaluer la qualification).
* Partage au CERT national si campagne coordonnée (voir [Vishing services financiers](#vishing-services-financiers)).

##### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres employés ont reçu des appels de vishing sans signalement. | T1566.004 - Spearphishing Voice | Tickets support / logs téléphonie | Croiser tickets support récents avec accès données atypiques sur 30 jours. |
| Des règles de forwarding ou accès OAuth ont été créés pendant l'appel. | T1098 - Account Manipulation | Logs Identity Provider (Entra ID, Google Workspace) | `OAuth grants` et `mail forwarding rules` créés sur la fenêtre de l'incident. |

#### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC technique publié dans les sources) | N/A | L'attaque est purement sociale, aucun IOC réseau/fichier à ce stade. | N/A |

#### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566.004 | Initial Access | Spearphishing Voice | Accès initial via appels téléphoniques manipulateurs ciblant trois employés. |

#### Sources
* [GBHackers](https://gbhackers.com/levi-strauss-hit-by-cyberattack/)
* [CyberNetsecIO](https://mastodon.social/@netsecio/117066849977054546)
* [infosec.exchange/@cloud](https://infosec.exchange/@cloud/117067677848788899)
* [securityLab_jp (rocket-boys)](https://mastodon.social/@securityLab_jp/117069487769983516)

---

<a id="vishing-services-financiers"></a>
### Vishing et extorsion contre les services financiers (Blackstone, CME et dizaines d'autres)

#### Résumé technique

Un acteur rançongiciel aurait compromis des dizaines de grandes firmes financières américaines, dont Blackstone et CME, via du vishing (appels téléphoniques d'ingénierie sociale). Le rapport décrit les employés acceptant systématiquement les appels et les attaquants déployant ensuite des ransomwares. Le mode opératoire cible les fonctions support et IT via téléphone, dans la lignée du cluster [Levi Strauss](#levi-strauss-social-engineering). Un pulse OTX distinct (« Multi-Brand Vishing Extortion Targets Financial Services and Enterprise Cloud Environments ») confirme la tendance sur les environnements cloud d'entreprise.

#### Analyse de l'impact

Le secteur financier est sous attaque soutenue. Le coût d'un arrêt d'activité chez un opérateur de marché (CME) ou un gestionnaire d'actifs (Blackstone) est systémique. La convergence vishing + ransomware + cloud crée un scénario de compromission rapide sans besoin d'exploit technique. Priorité absolue de durcissement des processus de support et de gestion d'identité.

#### Recommandations

* Imposer le callback obligatoire sur numéro officiel pour toute demande de support impliquant un accès ou un transfert.
* Renforcer l'authentification des administrateurs (MFA phishing-resistant : FIDO2) et réduire les privilèges des fonctions support.
* Segmenter les environnements cloud de gestion (console admin) et journaliser toutes les actions IAM.
* Former les équipes support aux scénarios de vishing rançongiciel (exercices red team téléphone).

#### Playbook de réponse à incident

##### Phase 1 - Préparation
* Déployer MFA phishing-resistant (FIDO2/WebAuthn) sur tous les comptes à privilèges et comptes support.
* Procédure de vérification d'identité téléphone avec token jetable.
* Sauvegardes hors-ligne testées pour les environnements cloud (snapshots immuables).
* Plan de coupure des consoles d'administration cloud en cas de détection.

##### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle SIEM : corrélation ticket support téléphone + élévation de privilège IAM dans les 2h.
  * Règle cloud : alerte sur créations de clés d'accès AWS/GCP ou sessions Angular console hors heures ouvrées par compte support.
  * Détection EDR : exécution d'outils de découverte (AdFind, BloodHound, Cobalt Strike) post-ticket support.
* Chronologie : identifier le premier appel, le compte compromis, le dwell time avant déploiement du rançongiciel.

##### Phase 3 - Confinement, éradication et récupération

**Confinement :**
* Isoler les postes et comptes compromis ; désactiver les clés d'accès cloud créées pendant l'attaque.
* Couper l'accès Internet des consoles d'administration si déploiement ransomware avéré.

**Éradication :**
* Révoquer sessions et tokens (Entra ID, AWS STS, GCP).
* Supprimer implants et canaux de persistance (tâches planifiées, services malveillants).
* Patch les éventuelles failles d'accès initial si exploitation complémentaire.

**Récupération :**
* Restaurer les systèmes chiffrés depuis snapshots immuables hors-ligne.
* Reconstruire les contrôleurs de domaine et comptes admin si compromis.
* Surveillance EDR/cloud continue 72h post-restauration.

##### Phase 4 - Activités post-incident
* Rapport d'incident distinguant phase vishing et phase ransomware.
* MTTD/MTTR.
* REX direction + régulateurs (DORA pour entités financières EU, notification banque centrale).
* Notifications RGPD/NIS2 selon impact. Partage IOCs au CERT national et FS-ISAC.

##### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Des clés d'accès cloud ont été créées par des comptes support récemment ciblés. | T1098.001 - Additional Cloud Credentials | CloudTrail / GCP Audit Logs | `CreateAccessKey` ou `CreateServiceAccountKey` par comptes support sur 30 jours. |
| Des forwards email ou règles de transport ont été créés pour l'exfiltration. | T1098 - Account Manipulation | Logs Exchange / Entra ID | Règles `InboxRule` créées par comptes support. |

#### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC technique publié dans les sources) | N/A | Les sources ne détaillent pas d'IOC réseau/fichier. | N/A |

#### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566.004 | Initial Access | Spearphishing Voice | Vishing ciblant les fonctions support. |
| T1486 | Impact | Data Encrypted for Impact | Déploiement de rançongiciel post-compromission. |

#### Sources
* [infosec.exchange/@security_crawler_carl](https://infosec.exchange/@security_crawler_carl/117067911501578424)
* [OTX Pulse - Multi-Brand Vishing Extortion](https://otx.alienvault.com/pulse/6a7951b6bfc33f720a4723ea)

---

<a id="shinyhunters-extorsion"></a>
### ShinyHunters - Campagne d'extorsion « pay or leak » (Alcon, DentaQuest)

#### Résumé technique

Le groupe ShinyHunters mène une campagne d'extorsion « pay or leak » nommant plusieurs victimes. Alcon (société suisse de soins oculaires) : 218 395 adresses email uniques publiées avec noms, numéros de téléphone et adresses physiques (données B2B corporate). DentaQuest : décrite comme la plus grosse breach santé de 2026 selon le compte-rendu. Les données sont publiées en cas de non-paiement.

#### Analyse de l'impact

ShinyHunters privilégie l'extorsion pure (exfiltration + menace de publication) sans chiffrement, ce qui échappe aux défenses anti-ransomware classiques. Le secteur santé est ciblé pour la sensibilité des données (SSN, dossiers patients). L'impact réglementaire RGPD/HIPAA est majeur, et la réputation forte pour les victimes corporate.

#### Recommandations

* Surveiller les accès bulk aux bases de données et l'exfiltration vers des destinations externes (DLP, anomaly detection).
* Renforcer le contrôle d'accès aux entrepôts de données (MFA, moindre privilège, segmentation).
* Mettre en place un plan de réponse à l'extorsion (négociation, communication, notification) distinct du plan ransomware.

#### Playbook de réponse à incident

##### Phase 1 - Préparation
* Inventorier les entrepôts de données sensibles et leur exposition (cloud, APIs, comptes service).
* Sauvegardes immuables + journalisation d'accès données (CloudTrail, Snowflake access history).
* Plan de communication de breach pré-approuvé (juridique, RP, régulateurs).

##### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle cloud : alerte sur requêtes bulk `SELECT *` ou exports massifs depuis entrepôts (Snowflake, BigQuery, RDS) hors plage ouvrée.
  * Règle IAM : alerte sur usage de token de service pour accéder à des données hors périmètre.
* Chronologie : identifier le point d'entrée (credential stuffing, token leak, supply chain comme Snowflake 2024), le volume exfiltré, le dwell time.

##### Phase 3 - Confinement, éradication et récupération

**Confinement :**
* Révoquer les credentials/tokens compromis.
* Couper l'accès externe aux entrepôts (whitelist IP temporaire).

**Éradication :**
* Supprimer les comptes malveillants créés.
* Pivoter toutes les clés d'accès suspectes.

**Récupération :**
* Pas de restauration système (pas de chiffrement), mais surveiller les tentatives de reconnexion.
* Vérifier l'intégrité des données (anti-falsification).

##### Phase 4 - Activités post-incident
* Notifications RGPD (72h CNIL/autorités) et HIPAA (HHS) selon juridiction.
* Communication aux personnes concernées (Alcon : 218k individus).
* Partage IOCs au CERT national et sectoriel (H-CIRT pour santé).

##### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres comptes ont été créés via credential stuffing sur des services exposés. | T1110.004 - Credential Stuffing | Logs IDP / WAF | Échecs d'authentification massifs suivis d'un succès sur comptes à privilèges. |
| Des tokens de service ont été utilisés pour exfiltrer des données. | T1528 - Steal Application Access Token | Logs cloud / SIEM | Tokens de service accédant à des données hors périmètre attendu. |

#### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC technique publié dans les sources) | N/A | Les sources sont des notifications de breach, pas des rapports techniques. | N/A |

#### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1530 | Collection | Data from Cloud Storage | Exfiltration de données depuis un entrepôt (mode opératoire ShinyHunters). |
| T1652 | Exfiltration | Device Driver Discovery (n/a ici) - préférer T1567 Exfiltration Over Web Service | Publication des données sur un cloud pirate (ZATAZ : 1,7 Md identifiants FR dans un cloud pirate). |

#### Sources
* [HIBP - Alcon](https://haveibeenpwned.com/Breach/Alcon)
* [RedPacketSecurity](https://mastodon.social/@RedPacketSecurity/117068742871734295)
* [infosec.exchange/@security_crawler_carl (DentaQuest)](https://infosec.exchange/@security_crawler_carl/117066479912269962)

---

<a id="vague-ransomware-breaches"></a>
### Vague de rançongiciels et breaches - santé, énergie, datacenter, retail

#### Résumé technique

Plusieurs incidents simultanés signalés ce jour, sans lien d'acteur établi mais illustrant une pression opérationnelle continue :
- **AnMed Health** (Anderson, Caroline du Sud) : malware/disruption cyber depuis le 26 juillet 2026, 83 établissements en downtime, AnMed Medical Group et AnMed Imaging fermés, urgences et urgences-cures sous procédure de downtime.
- **Stade Français Paris** (rugby, France) : rançongiciel, restauration depuis backups propres, échantillon de données volées publié en ligne, pièces d'identité exposées. Attribution Qilin selon ZATAZ.
- **CEC** (Japon, datacenter) : incident de service confirmé comme rançongiciel, notification à la commission protection des données.
- **Origin Energy** (Australie) : ~900 000 clients potentiellement compromis.
- **3Pro TV** (Corée du Sud, média financier) : 460 000 enregistrements dont 2 979 comptes bancaires et 317 cartes bancaires.
- **Innovation** (Japon) : breach GitHub, 62 691 individus, authentification hardcodée + PII stockée dans le repo.
- **American Addiction Centers** : breach Salesforce, SSN et descriptions de santé exposés.
- **Everest** revendique 1 To extrait d'Omnicell (source code, credentials, firmware) - non confirmé par la victime.

#### Analyse de l'impact

La concentration d'incidents sur le secteur santé (AnMed, AAC, DentaQuest déjà couvert, Omnicell) et les infrastructures (datacenter CEC, énergie Origin) crée un risque systémique. Les SOC/CERT doivent anticiper des demandes de support simultanées et la saturation des capacités de réponse. Le pattern « breach via supply chain SaaS » (AAC via Salesforce, Innovation via GitHub) confirme que la surface d'attaque tierce reste sous-contrôlée.

#### Recommandations

* Prioriser le durcissement des accès tiers SaaS (MFA, audit des tokens, rotation des credentials, GitHub secret scanning).
* Vérifier la résilience des sauvegardes (AnMed et Stade Français ont restauré depuis backups - cas d'école positifs).
* Segmenter les datacenters et isoler les clients mutuels en cas d'incident sur l'infrastructure (CEC).
* Renforcer la détection d'exfiltration sur les environnements SaaS (Salesforce, GitHub).

#### Playbook de réponse à incident

##### Phase 1 - Préparation
* Inventaire des dépendances SaaS tierces et de leurs périmètres de données.
* Sauvegardes hors-ligne immuables testées mensuellement.
* Plan de continuité d'activité « mode dégradé » pour les établissements de santé (procédures papier, downtime procedures documentées).

##### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle EDR : détection de chiffrement massif (Event ID 4663 modifications en rafale, extension de fichiers).
  * Règle SaaS : alerte sur exports massifs depuis Salesforce/GitHub (API bulk, clonage de repo).
  * Règle réseau : détection de mouvements latéraux post-initial (PsExec, WMI, SMB admin shares) sur les datacenters.
* Chronologie par victime : identifier le patient zéro, le dwell time, le volume exfiltré.

##### Phase 3 - Confinement, éradication et récupération

**Confinement :**
* Isoler les segments impactés (établissements AnMed, clients du datacenter CEC).
* Couper les accès externes SaaS compromise (révoquer tokens Salesforce, GitHub).

**Éradication :**
* Supprimer les implants ransomware et les comptes malveillants.
* Pivoter toutes les credentials exposées (GitHub, Salesforce, AD).
* Fermer les canaux de persistance (tâches planifiées, services malveillants).

**Récupération :**
* Restaurer depuis backups propres (Stade Français et AnMed : cas réussis).
* Reconstruire les systèmes chiffrés ou non fiables.
* Surveillance 72h post-restauration.

##### Phase 4 - Activités post-incident
* Notifications RGPD/CNIL (Stade Français, 72h), NIS2 si entité essentielle, HHS/HIPAA (AnMed, AAC), loi japonaise (CEC, Innovation), PIPEDA/coren (selon juridiction).
* Partage IOCs au CERT national (CERT-FR pour Stade Français, JPCERT/CC pour CEC/Innovation, KOISC pour 3Pro TV).
* REX et métriques MTTD/MTTR.

##### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Des credentials GitHub hardcodés sont exposés dans d'autres repos. | T1552.001 - Credentials In Files | GitHub secret scanning / truffleHog | Scan tous les repos internes pour credentials et PII. |
| Des exports Salesforce massifs ont eu lieu sur d'autres comptes. | T1530 - Data from Cloud Storage | Salesforce audit trails | `DataExport` et `Bulk API` par comptes non-admin sur 90 jours. |

#### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC technique publié dans les sources agrégées) | N/A | Les sources sont des notifications de breach, pas des rapports techniques avec IOCs. | N/A |

#### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1486 | Impact | Data Encrypted for Impact | Chiffrement ransomware (AnMed, Stade Français/Qilin, CEC). |
| T1552.001 | Credential Access | Credentials In Files | Credentials hardcodés dans repo GitHub (Innovation). |
| T1530 | Collection | Data from Cloud Storage | Exfiltration depuis SaaS (Salesforce pour AAC). |

#### Sources
* [infosec.exchange/@security_crawler_carl (AnMed)](https://infosec.exchange/@security_crawler_carl/117069523836575501)
* [infosec.exchange/@cyberworldops (Stade Français)](https://infosec.exchange/@cyberworldops/117068778767645331)
* [ZATAZ](https://infosec.exchange/@cloud/117068696752506272)
* [securityLab_jp (CEC)](https://mastodon.social/@securityLab_jp/117067972040464177)
* [securityLab_jp (Innovation)](https://mastodon.social/@securityLab_jp/117069306948348008)
* [databreaches.net (3Pro TV)](https://databreaches.net/2026/08/09/kr-3pro-tv-data-breach-exposes-460000-records-including-2979-bank-accounts/)
* [infosec.exchange/@security_crawler_carl (Omnicell/Origin)](https://infosec.exchange/@security_crawler_carl/117066479912269962)
* [mastodon.social/@netsecio (American Addiction Centers)](https://mastodon.social/@netsecio/117066849226034795)

---

<a id="vanta-stealer"></a>
### Vanta Stealer - Malware de vol d'informations en Python (cross-platform)

#### Résumé technique

Un pulse OTX décrit « Vanta Stealer », un malware de vol d'informations écrit en Python et cross-platform (Windows, Linux, macOS potentiellement). Le pulse est non vérifié (préliminaire). Les détails techniques (vecteur d'accès initial, cibles, TTP) ne sont pas fournis dans la source.

#### Analyse de l'impact

Les stealers cross-platform en Python sont de plus en plus courants (phase d'infection via faux installers, scripts pip malveillants). Pour SOC/CERT, la détection repose sur l'observation de comportements (accès navigateurs, lecture de wallets crypto) plus que sur des IOCs fixes. Les données volées alimentent les campagnes de takeover et d'extorsion.

#### Recommandations

* Surveiller les exécutions de scripts Python non signés et les accès aux répertoires de navigateurs et wallets crypto.
* Restreindre l'exécution de Python hors des chemins approuvés sur les postes utilisateurs.
* Déployer des règles YARA sur les binaires PyInstaller suspectés.

#### Playbook de réponse à incident

##### Phase 1 - Préparation
* Journaliser les exécutions de processus Python (Sysmon Event ID 1) et les accès aux répertoires sensibles (browsers, wallets).
* EDR avec détection comportementale sur accès en chaîne aux fichiers de session/passwords.

##### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle Sysmon : `Image = python.exe` accédant à `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`.
  * Règle YARA : signatures sur PyInstaller compilé avec motifs Vanta Stealer (à enrichir dès publication technique).
* Analyser le vecteur d'entrée (faux installer, package pip malveillant, phishing).

##### Phase 3 - Confinement, éradication et récupération

**Confinement :**
* Isoler le poste compromis.
* Révoquer les sessions navigateur et wallets exposés.

**Éradication :**
* Supprimer le binaire PyInstaller et les dropped files.
* Pivoter les passwords stockés dans les navigateurs compromise.

**Récupération :**
* Réinitialiser toutes les credentials exposées.
* Surveillance 72h sur les tentatives de takeover.

##### Phase 4 - Activités post-incident
* Notifications RGPD si données personnelles volées.
* Partage du sample au CERT national.

##### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres postes ont exécuté un binaire PyInstaller suspect. | T1027.002 - Software Packing | Sysmon Event ID 1 | `Image endswith python.exe` avec accès fichiers browser sur 30 jours. |

#### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC publié dans la source OTX préliminaire) | N/A | Pulse OTX non vérifié, sans IOC ni hash. | N/A |

#### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1005 | Collection | Data from Local System | Vol de données depuis le poste (navigateurs, wallets). |
| T1027.002 | Defense Evasion | Software Packing (PyInstaller) | Conditionnement du malware en exécutable PyInstaller. |

#### Sources
* [OTX Pulse - Vanta Stealer](https://otx.alienvault.com/pulse/6a7951a3cb8e961a30c583bb)

---

<a id="mac-malware-captcha-zoom"></a>
### Mac malware - Fake CAPTCHA (crypto) et fake Zoom Installer (Overlord RAT)

#### Résumé technique

Deux pulses OTX (non vérifiés) ciblant macOS :
- « Mac Malware Drains Crypto Wallets Via Fake CAPTCHA Scam » : un faux CAPTCHA sert de leurre pour exécuter un malware drainant les wallets crypto.
- « Fake Zoom Installer Delivers Overlord RAT on macOS » : un faux installer Zoom déploie le RAT Overlord sur macOS.

#### Analyse de l'impact

Le parc macOS est historiquement sous-couvert par les EDR et la sensibilisation. Les faux installers et faux CAPTCHA sont des vecteurs efficaces contre les utilisateurs non techniques. Le vol de wallets crypto a un impact financier direct et irréversible ; un RAT persistant permet l'exfiltration long terme et le mouvement latéral.

#### Recommandations

* Renforcer la détection EDR macOS (Jamf, CrowdStrike, Microsoft Defender pour Endpoint).
* Bloquer les installers non signés/notarisés (Gatekeeper strict, XProtect à jour).
* Sensibiliser aux faux CAPTCHA et aux installers téléchargés hors stores officiels.

#### Playbook de réponse à incident

##### Phase 1 - Préparation
* Vérifier Gatekeeper, XProtect et le déploiement EDR sur tout le parc macOS.
* Inventorier les wallets crypto utilisés sur les postes pro.

##### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle macOS : `process_name = screencapture` ou accès au trousseau (`security` CLI) par un processus non signé.
  * Règle EDR : exécution de binaire non notarisé + connexion C2 sortante.
  * Détection YARA : signatures Overlord RAT (à enrichir).
* Analyser le vecteur d'entrée (site de téléchargement, email, fake CAPTCHA).

##### Phase 3 - Confinement, éradication et récupération

**Confinement :**
* Isoler le Mac compromise du réseau.
* Couper l'accès Internet pour stopper le C2.

**Éradication :**
* Supprimer le binaire malveillant et les LaunchAgents/LaunchDaemons de persistance.
* Vérifier les profils de configuration macOS installés (vecteur de persistance courant).

**Récupération :**
* Restaurer depuis Time Machine si doute sur l'intégrité.
* Migrer les wallets crypto vers un nouveau wallet propre (clés présumées compromises).

##### Phase 4 - Activités post-incident
* Notifications si données pro accessibles.
* Partage du sample à Apple (product-security@apple.com) et au CERT national.

##### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres Mac ont des LaunchAgents non signés persistants. | T1547.011 - Plist File Modification | Logs macOS / Jamf | `LaunchAgents` et `LaunchDaemons` plists avec binaire non signé. |
| Des binaires non notarisés ont été exécutés via quarantine bypass. | T1553.001 - Gatekeeper Bypass | Unified Logs macOS | Événements `syspolicyd` avec `result = allow` sur binaires non notarisés. |

#### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC publié dans les sources OTX préliminaires) | N/A | Pulses OTX non vérifiés, sans IOC ni hash. | N/A |

#### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1204.002 | Execution | User Execution: Malicious File | Exécution par l'utilisateur du faux installer Zoom / fake CAPTCHA. |
| T1547.011 | Persistence | Plist File Modification | Persistance via LaunchAgents/LaunchDaemons macOS. |
| T1059.004 | Execution | Command and Scripting Interpreter: Unix Shell | Scripts shell/macOS pour le RAT et le drainer. |

#### Sources
* [OTX Pulse - Mac Malware Fake CAPTCHA](https://otx.alienvault.com/pulse/6a7951aad7b05814243eb26a)
* [OTX Pulse - Fake Zoom Installer Overlord RAT](https://otx.alienvault.com/pulse/6a7951c3648b349f44da270a)

---

<a id="signaux-otx-non-verifies"></a>
### Signaux OTX non vérifiés - BEC, espionnage, worm npm

#### Résumé technique

Trois pulses OTX supplémentaires (auteur Tr1sa111, préliminaires et non vérifiés) signalent des menaces émergentes sans détail technique dans la source :
- **Payroll Pirates** : nouvelles vagues de Business Email Compromise (BEC) ciblant les process de paie.
- **Analysis of a Modular Cyber Espionage Framework** : framework d'espionnage modulaire (APT probable, attribution non précisée).
- **Inside a Self-Propagating npm Worm** : ver auto-propageant sur l'écosystème npm (chaîne d'approvisionnement JavaScript).

#### Analyse de l'impact

Faible densité informationnelle mais signaux à surveiller. Le ver npm est particulièrement préoccupant pour les SOC/CERT ayant un parc de développement Node.js (risque de propagation transverse dans la supply chain). Le framework d'espionnage modulaire suggère activité APT, à corréler avec les signaux de campagne étatique.

#### Recommandations

* Ver npm : auditer les dépendances npm en production (`npm audit`, lockfile integrity), restreindre l'installation de packages non vérifiés, activer npm two-factor auth pour les mainteneurs internes.
* BEC Paie : renforcer la validation hors-bande des changements de coordonnées bancaires employés (callback RH).
* Espionnage : activer la détection de persistance avancée (WMI subscriptions, rootkits, double-use tools).

#### Playbook de réponse à incident

##### Phase 1 - Préparation
* Inventorier les dépendances npm critiques et leurs mainteneurs.
* Procédure de validation des changements de coordonnées bancaires employés (double validation + callback).
* Capacité de détection WMI Event Subscription (Event ID 5861).

##### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle SIEM (ver npm) : alerte sur `npm install` exécuté par un compte service + connexion sortante vers un registry non officiel.
  * Règle SIEM (BEC Paie) : corrélation entre email demandant changement de coordonnées bancaires et modification effective dans le RH/PAIIE.
  * Règle Sysmon (espionnage) : `EventID 5861` WMI Event Consumer Creation avec commandes PowerShell obfusquées.

##### Phase 3 - Confinement, éradication et récupération

**Confinement :**
* Ver npm : isoler les machines de dev, bloquer les registrys non officiels.
* BEC : bloquer les transferts financiers en cours vers les nouvelles coordonnées suspectes.
* Espionnage : isoler les hôtes suspectés de persistance WMI.

**Éradication :**
* Ver npm : supprimer les packages malveillants, forcer `npm ci` depuis lockfile propre.
* BEC : restaurer les coordonnées bancaires légitimes.
* Espionnage : supprimer les Event Subscriptions WMI malveillants, pivoter les credentials compromis.

**Récupération :**
* Surveillance 72h post-éradication.

##### Phase 4 - Activités post-incident
* Notifications (RGPD/NIS2 selon impact, notamment si BEC réussi).
* Partage IOCs au CERT national et à l'écosystème npm (GitHub Advisory).

##### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres packages npm malveillants sont installés en dev. | T1195.002 - Compromise Software Supply Chain (Package Manager) | Logs npm / EDR | `npm install` hors lockfile ou depuis registry non officiel. |
| Des Event Subscriptions WMI suspectes sont présentes. | T1546.003 - WMI Event Subscription | WMI Activity Logs | `EventID 5861` avec commandes PowerShell obfusquées. |

#### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| (aucun IOC publié dans les sources OTX préliminaires) | N/A | Pulses non vérifiés, sans IOC. | N/A |

#### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566.004 | Initial Access | Spearphishing Voice (BEC Paie) | Ingénierie sociale email/téléphone sur processus paie. |
| T1546.003 | Persistence | WMI Event Subscription | Persistance du framework d'espionnage. |
| T1195.002 | Initial Access | Compromise Software Supply Chain: Package Manager | Ver via packages npm malveillants. |

#### Sources
* [OTX Pulse - Payroll Pirates BEC](https://otx.alienvault.com/pulse/6a7951bc005392716e86f842)
* [OTX Pulse - Modular Cyber Espionage Framework](https://otx.alienvault.com/pulse/6a7951ce6a424ce1daf4cd8d)
* [OTX Pulse - Self-Propagating npm Worm](https://otx.alienvault.com/pulse/6a7951d7e4e9679263bf13be)

---

<a id="llm-env-scanning"></a>
### Signal émergent - Crawler LLM (ChatGPT-User) scannant les fichiers .env et credentials AWS

#### Résumé technique

Le honeypot CyberVeille.ch a détecté une IP `34.16.197.255` (Google Cloud, AS396982, US) avec un User-Agent `ChatGPT-User/1.0` ciblant les chemins `.env`, credentials AWS et path traversal `/_next/..`. Le signal suggère qu'un LLM/crawler utilisant un UA ChatGPT effectue des scans opportunistes sur des ressources sensibles. Source communautaire (honeypot, niveau 2 mais à requalifier comme signal émergent de niveau 3).

#### Analyse de l'impact

Si l'UA est authentique (et non spoofé), cela pose une question de gouvernance des crawlers IA : exposition involontaire de données par les LLM eux-mêmes, et risque de légitimation de scans malveillants via UA usurpé. Pour les SOC/CERT, le signal est à corréler avec toute exposition `.env` publique dans le périmètre. Impact faible en soi mais indicateur d'une tendance (crawlers IA comme vecteur passif d'exposition).

#### Recommandations

* Bloquer ou rate-limiter les UA de crawlers IA connus (ChatGPT-User, GPTBot, ClaudeBot, etc.) sur les chemins sensibles.
* Vérifier qu'aucun fichier `.env` n'est exposé publiquement (scan du périmètre web externe).
* Journaliser et alerter sur les accès aux chemins `.env`, `/_next/..`, `/.aws/credentials`.

#### Playbook de réponse à incident

##### Phase 1 - Préparation
* Inventorier les chemins sensibles exposés (`.env`, config, credentials) via scan externe.
* Définir une politique de blocage des crawlers IA sur les endpoints sensibles.

##### Phase 2 - Détection et analyse
* **Règles de détection contextualisées :**
  * Règle WAF : alerte sur `User-Agent = ChatGPT-User` + accès à `/.env`, `/.aws/`, `/_next/..`.
  * Règle SIEM : corrélation entre IP Google Cloud et accès à chemins sensibles.
* Vérifier si l'exfiltration a réussi (statut 200 sur `.env`).

##### Phase 3 - Confinement, éradication et récupération

**Confinement :**
* Bloquer l'IP source et l'AS396982 sur les endpoints sensibles.
* Restreindre l'accès aux chemins `.env` (404 générique au lieu de 200).

**Éradication :**
* Si `.env` exfiltré : pivoter toutes les credentials AWS/DB exposées immédiatement.
* Supprimer l'exposition publique du fichier.

**Récupération :**
* Surveiller l'usage des credentials pivotées sur 72h.
* Vérifier les logs AWS CloudTrail pour usage abusif post-exposition.

##### Phase 4 - Activités post-incident
* Si credentials AWS utilisées : notifications clients et régulateurs si données personnelles impactées.
* Partage du signal au CERT national et à la communauté honeypot.

##### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| D'autres crawlers IA ont accédé à des chemins sensibles. | T1595.001 - Active Scanning: Scanning IP Blocks | WAF / logs web | `User-Agent` matching `*Bot*` ou `GPT*` avec accès à `.env`, `.aws`, `/_next/..`. |
| Des credentials ont été exfiltrées via `.env` exposé. | T1552.001 - Credentials In Files | CloudTrail / SIEM | Accès AWS venant d'IP hors périmètre après la fenêtre de scan. |

#### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| IP | `34[.]16[.]197[.]255` | IP source du scan, Google Cloud (AS396982), UA `ChatGPT-User/1.0`. | Moyenne (honeypot, UA potentiellement spoofé) |
| AS | AS396982 (Google Cloud) | AS d'origine du scan. | Moyenne |

#### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1595.001 | Reconnaissance | Active Scanning: Scanning IP Blocks | Scan opportuniste de chemins sensibles (.env, credentials). |
| T1592.004 | Reconnaissance | Gather Victim Host Information: Client Configuration | Ciblage des fichiers de configuration et credentials. |

#### Sources
* [mastobot.ping.moi/@Bobe_bot (CyberVeille.ch honeypot)](https://mastobot.ping.moi/@Bobe_bot/117069683647452837)
