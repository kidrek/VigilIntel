# Brief quotidien de veille cyber - 2026-08-24

**Domaine :** cyber SOC/CERT
**Date :** 2026-08-24
**Entrée :** 129 articles scrapés (0 source_level 1, 25 level 2, 104 level 3)
**Sortie :** 16 clusters produits (CVE éditeurs : 3, menaces : 6, fuites : 7). 102 articles filtrés (chrome_only : 1, no_corroboration : 99).

## Table des matières
- [Analyse stratégique](#analyse-strategique)
- [Géopolitique](#geopolitique) — *aucun signal*
- [Réglementaire et légal](#reglementaire-et-legal) — *aucun signal*
- [Vulnérabilités](#vulnerabilites) (3)
- [Menaces SOC/CERT](#menaces-soc-cert) (13)

<a id="analyse-strategique"></a>

## Analyse stratégique

La surface de menace du jour se bifurque entre extorsion active et exposition vulnérabilitaire latente. D'un côté, onze victimes revendiquées, qilin en tête avec cinq cibles, modes opératoires dominés par chiffrement de fichiers (3) et exfiltration par service web (2). De l'autre, trois CVE publiées dont deux sans correctif éditeur, sur WordPress et GitLab, aucune exploitation active confirmée. Les défenseurs tiennent deux fronts simultanés : contenir des exfiltrations en cours et réduire l'exposition sur des flaws divulgués non patchés. L'ubiquité des produits touchés rend cette double posture applicable au-delà du périmètre français, absent du corpus.

Qilin industrialise l'extorsion multi-cibles plutôt que le coup unique. Cinq des onze victimes revendiquées lui reviennent, sur trois clusters, avec chiffrement (3) et exfiltration web (2). Les cibles couvrent ingénierie, développement et services techniques — Aurore Development, Black Cat Engineering, Tecnici Associati. La détection doit se concentrer sur le staging de données et les canaux d'exfiltration avant le chiffrement, indicateur trop tardif. Les IOC post-chiffrement ne suffisent plus face à des acteurs qui exfiltrent d'abord.

Deux vulnérabilités critiques sans correctif dans des produits ubiquitaires créent une fenêtre de remédiation qui se referme. CVE-2026-16149 (CVSS 8.8, Security Hardener WordPress) et CVE-2026-10053 (CVSS 8.5, GitLab CE/EE, RCE) sont publiées, sans patch, sans exploitation active confirmée. La posture défensive doit assumer l'imminence : les CVE publiques suffisent à armer des acteurs opportunistes. À vérifier sous sept jours : si aucune exploitation de CVE-2026-10053 n'est signalée d'ici le 2026-08-31, alors la fenêtre de remédiation volontaire aura tenu ; sinon, le délai disclosure-exploitation se confirme sous sept jours pour un produit sans correctif.

<a id="geopolitique"></a>

## Géopolitique

*Aucun signal étatique identifié dans le corpus du jour.*

<a id="reglementaire-et-legal"></a>

## Réglementaire et légal

*Aucune actualité réglementaire dans le corpus du jour.*

<a id="vulnerabilites"></a>

## Vulnérabilités

| CVE | Score CVSS | EPSS | CISA KEV | Éditeur / Produit affecté | Versions affectées | Type de vulnérabilité | Impact | Mesures de contournement / Correctif | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-10053](https://www.cve.org/CVERecord?id=CVE-2026-10053) | 8.5 (HIGH, v3.1) | N/A | N/A | **GitLab** / Improper Limitation of a Pathname to a Restricted Directory  | 18.8 → 19.0.6 | Exécution de code à distance (CWE-94) | GitLab a corrigé une vulnérabilité de traversée de répertoire (CVE-2026-10053) dans le registre de paquets de GitLab CE/EE. | Aucun correctif publié à la date de ce rapport. | [cvefeed.io](https://cvefeed.io/vuln/detail/CVE-2026-10053)<br>[infosec.exchange](https://infosec.exchange/@suriq/117145643611931978) |
| [CVE-2026-0551](https://www.cve.org/CVERecord?id=CVE-2026-0551)<br>[CVE-2026-5388](https://www.cve.org/CVERecord?id=CVE-2026-5388)<br>[CVE-2026-78050](https://www.cve.org/CVERecord?id=CVE-2026-78050)<br>[CVE-2026-7808](https://www.cve.org/CVERecord?id=CVE-2026-7808)<br>[CVE-2026-8445](https://www.cve.org/CVERecord?id=CVE-2026-8445) | 9.8 (CRITICAL, v3.1) | N/A | N/A | **justhtml** / before 1.12.0 Sanitizer Bypass via Markdown | < 1.12.0 | Injection de code indirecte (XSS) (CWE-79) | Le plugin WordPress PPWP – Password Protect Pages dans ses versions jusqu'à 1.9.18 inclus est vulnérable à une injection d'objet PHP via la désérialisation d'une entrée non fiable depuis le paramètre 'post_protection_rol… | Mise à jour 1 | [cvefeed.io](https://cvefeed.io/vuln/detail/CVE-2026-0551)<br>[cvefeed.io](https://cvefeed.io/vuln/detail/CVE-2026-5388)<br>[cvefeed.io](https://cvefeed.io/vuln/detail/CVE-2026-78050)<br>[cvefeed.io](https://cvefeed.io/vuln/detail/CVE-2026-7808)<br>[cvefeed.io](https://cvefeed.io/vuln/detail/CVE-2026-8445)<br>[infosec.exchange](https://infosec.exchange/@offseq/117141879828855162)<br>[mastodon.social](https://mastodon.social/@stemshop/117145681650942382)<br>[mastodon.social](https://mastodon.social/@thehackerwire/117145418496251422) |
| [CVE-2026-16149](https://www.cve.org/CVERecord?id=CVE-2026-16149) | 8.8 (HIGH, v3.1) | N/A | N/A | **Security** / Hardener <= 2.4.4 - Authenticated (Subscriber+) | Non précisé par la source. | Élévation de privilèges (CWE-269) | Le plugin WordPress Security Hardener, dans ses versions jusqu'à 2.4.4 incluse, présente une vulnérabilité d'autorisation manquante. | Aucun correctif publié à la date de ce rapport. | [cvefeed.io](https://cvefeed.io/vuln/detail/CVE-2026-16149)<br>[infosec.exchange](https://infosec.exchange/@offseq/117144710268059473) |

<a id="menaces-soc-cert"></a>

## Menaces SOC/CERT

12 sujet(s) marquant(s) traité(s) en bloc complet, 1 regroupé(s) en fin de section.

<a id="qilin-5-victimes-revendiquees"></a>

### qilin — 5 victimes revendiquées

### Résumé technique

Le groupe de rançongiciels qilin a revendiqué cinq nouvelles victimes sur son site de fuite (leak site) le 2026-08-23. Les victimes identifiées sont Aurore Development S.p.A., Black Cat Engineering & Construction WLL, Euroflora srl, Studio BOLDRIN PAOLO et Tecnici Associati STP, opérant dans les secteurs de l'architecture, de l'ingénierie civile, de la construction, de l'immobilier et des services aux entreprises. Aucun détail technique sur le mécanisme d'intrusion, le vecteur d'accès initial, les versions ou configurations concernées n'a été publié par les sources à ce stade. Aucun indicateur de compromission (IOC) n'est disponible. Le modèle opérationnel de qilin s'inscrit dans le schéma de double extorsion : chiffrement des données de la victime et exfiltration préalable pour exercer une pression via la publication sur le leak site. La source unique est ransomlook.io.

### Analyse de l'impact

Les cinq victimes revendiquées appartiennent à des secteurs sensibles en termes de propriété intellectuelle et de données de conception : architecture, ingénierie civile, immobilier et services aux entreprises. Pour ces organisations, la perte associée à un rançongiciel va au-delà de l'indisponibilité des systèmes : les plans, schémas techniques, dossiers de clients et données financières exfiltrés peuvent être publiés sur le leak site de qilin, exposant des informations confidentielles sur des projets d'infrastructure. Les cabinets d'ingénierie et d'architecture constituent des cibles privilégiées en raison de la valeur de leurs données de conception et de leur dépendance opérationnelle aux fichiers numériques. Le coût d'un incident inclut la rançon potentielle, l'arrêt des chantiers, la perte de confiance client et les obligations de notification RGPD.

**Priorité : moyenne.**

### Recommandations

**Stratégiques**

* Intégrer les prestataires d'ingénierie, d'architecture et de construction à la cartographie des risques de la chaîne d'approvisionnement, ces secteurs étant activement ciblés par qilin.
* Exiger des fournisseurs critiques un plan de continuité d'activité testé incluant la restauration de sauvegardes hors ligne et la gestion d'une fuite de données.
* Renforcer les exigences contractuelles de cybersécurité pour les partenaires du BTP et de l'ingénierie, incluant des audits de sauvegarde et des délais de notification d'incident.

**Opérationnelles**

* Vérifier immédiatement l'intégrité et l'isolabilité des sauvegardes, y compris les copies hors ligne (offline), face à un scénario de chiffrement massif.
* Surveiller les journaux d'authentification pour détecter des connexions inhabituelles, notamment en dehors des heures ouvrées, sur les postes d'architectes et d'ingénieurs.
* Déployer des règles de détection EDR (Endpoint Detection and Response) sur les comportements de chiffrement volumétrique et de suppression de copies d'ombre (Volume Shadow Copies).
* Cartographier les partages de fichiers contenant des données de conception (CAO/DAO, plans, dossiers techniques) pour prioriser leur protection et leur journalisation d'accès.

### Playbook de réponse à incident

#### Phase 1 - Préparation

* Recenser les actifs des secteurs architecture, ingénierie, construction, immobilier et services aux entreprises exposés à Internet, notamment les accès RDP et VPN.
* Vérifier l'existence et la testabilité de sauvegardes hors ligne (règle 3-2-1) pour les serveurs de fichiers et bases de données métier.
* Activer la journalisation Sysmon sur les postes Windows et auditd sur les serveurs Linux avec collecte centralisée vers le SIEM.
* Maintenir à jour la liste de contacts d'astreinte incluant le RSSI, le DPO, le prestataire forensique et le numéro du CERT-FR.
* Cartographier les accès externes VPN, RDP et SMB exposés et restreindre par allowlist IP et MFA obligatoire.

#### Phase 2 - Détection et analyse

* **Règles de détection contextualisées :**

  * Règle [Sigma] :

    ```yaml
    title: Potential_Ransomware_Mass_File_Modification
    status: experimental
    description: Detects rapid successive file modification events indicative of ransomware encryption
    logsource:
        product: windows
        category: file_event
    detection:
        selection:
            EventID: 2
        filter_legitimate:
            Image|endswith:
                - winzip.exe
                - 7z.exe
                - explorer.exe
        condition: selection and not filter_legitimate
    level: high
    ```

  * Règle [YARA] :

    ```
    rule Generic_Ransom_Note
    {
        meta:
            description = "Generic ransom note detection"
        strings:
            $a = "your files" nocase
            $b = "encrypted" nocase
            $c = "bitcoin" nocase
            $d = "recover your" nocase
            $e = "how to decrypt" nocase
        condition:
            3 of ($a, $b, $c, $d, $e)
    }
    ```

  * Règle [SIEM] :

    ```
    index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=2
    | bin _time span=1m
    | stats count as file_events dc(TargetFilename) as unique_files values(Image) as processes by host, _time
    | where unique_files > 50
    | sort - unique_files
    ```

  * Règle [auditd] :

    ```bash
    -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F dir=/home -k potential_ransomware
    -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F dir=/var/www -k potential_ransomware
    -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F dir=/srv -k potential_ransomware
    ```

* Corréler les alertes de modification massive de fichiers avec les sessions utilisateur et les processus parents pour identifier le point d'entrée initial.
* Exécuter la règle YARA sur les fichiers récents des partages affectés pour détecter d'éventuelles notes de rançon déposées par qilin.
* Examiner les journaux d'authentification VPN et RDP des 72 heures précédant l'alerte pour identifier les connexions suspectes.
* Isoler les hôtes présentant plus de 50 modifications de fichiers par minute et capturer la mémoire vive avant toute extinction.
* Documenter la chaîne d'attaque observée et la transmettre au CERT-FR pour corrélation avec les victimes revendiquées par qilin.

#### Phase 3 - Confinement, éradication et récupération

**Confinement :**

* Isoler immédiatement les hôtes affectés du réseau en conservant l'alimentation électrique pour préserver la mémoire volatile.
* Désactiver les comptes compromis et révoquer toutes les sessions VPN et RDP actives associées à ces comptes.
* Capturer une image forensique complète des disques et de la mémoire avant toute action de nettoyage.
* Bloquer les adresses IP source identifiées dans les journaux d'authentification au pare-feu périmétrique.
* Notifier le RSSI et déclencher la cellule de crise si plus d'un hôte est affecté simultanément.

**Éradication :**

* Supprimer les tâches planifiées, les services et les clés de registre créés par l'attaquant pour maintenir la persistance.
* Réinitialiser tous les mots de passe des comptes ayant accédé aux hôtes affectés pendant la fenêtre d'attaque.
* Reconstruire les hôtes compromis à partir d'une image gold clean plutôt que de nettoyer en place.
* Appliquer les derniers correctifs de sécurité sur les systèmes reconstruits avant réintégration réseau.
* Vérifier l'absence de backdoors en analysant les binaires avec la règle YARA et un scan EDR complet.

**Récupération :**

* Restaurer les données depuis les sauvegardes hors ligne après validation de leur intégrité par hachage.
* Réintégrer les hôtes reconstruits sur le réseau par lots, en commençant par les serveurs les moins critiques.
* Maintenir une surveillance renforcée de 72 heures après remédiation avec alerte sur toute modification de fichier supérieure à 20 par minute.
* Valider la cohérence des données restaurées avec les utilisateurs métier avant ouverture aux utilisateurs finaux.
* Documenter la chronologie complète de la récupération pour alimenter le retour d'expérience.

#### Phase 4 - Activités post-incident

* Calculer le MTTD et le MTTR à partir des horodatages des journaux d'authentification et des alertes SIEM.
* Évaluer l'obligation de notification RGPD à la CNIL sous 72 heures si des données personnelles ont été compromises.
* Évaluer l'applicabilité de la directive NIS2 pour les entités essentielles des secteurs construction et ingénierie et notifier l'ANSSI si requis.
* Partager les indicateurs de compromission collectés avec le CERT-FR via le canal de partage approprié.
* Organiser un retour d'expérience avec l'ensemble des parties prenantes dans les 15 jours suivant la clôture de l'incident.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| L'attaquant a obtenu l'accès initial via des comptes valides compromis, notamment par credential stuffing ou achat sur le marché clandestin. | T1078 | Journaux d'authentification VPN, RDP et Active Directory (Event ID 4624 et 4625). | SPL: index=auth (sourcetype=winsecurity EventCode=4624 OR EventCode=4625) LogonType=10 OR LogonType=3 \| bin _time span=1h \| stats count as attempts dc(src_ip) as distinct_ips by user _time \| where distinct_ips > 2 \| sort - distinct_ips |
| Le rançongiciel a chiffré les fichiers en masse sur les partages réseau et les postes de travail des victimes revendiquées par qilin. | T1486 | Événements Sysmon de création et modification de fichiers (Event ID 2) et télémétrie EDR. | KQL: DeviceFileEvents \| where Timestamp > ago(72h) \| summarize FileCount = count(), DistinctPaths = dcount(FolderPath) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m) \| where FileCount > 100 \| order by FileCount desc |
| L'attaquant a supprimé les copies shadow et désactivé les services de récupération pour empêcher la restauration des données. | T1490 | Journaux de création de processus Sysmon (Event ID 1) et journaux de sécurité Windows (Event ID 4688). | EQL: process where event.type == "start" and (process.name : "vssadmin.exe" and process.command_line : "*delete shadows*") or (process.name : "wbadmin.exe" and process.command_line : "*delete catalog*") or (process.name : "bcdedit.exe" and process.command_line : "*recoveryenabled no*") |

### Indicateurs de compromission (DEFANG obligatoire)

*Aucun IOC technique publié par les sources pour ce cluster.*

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| [T1486](https://attack.mitre.org/techniques/T1486/) | Impact | Data Encrypted for Impact | qilin chiffre les données des cinq victimes revendiquées pour provoquer l'indisponibilité opérationnelle et motiver le paiement de la rançon, conformément au modèle de double extorsion observé sur son leak site. |
| [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration | Exfiltration Over Web Service | Les données des victimes sont exfiltrées vers des services web avant d'être menacées de publication sur le leak site de qilin, mécanisme de pression caractéristique de la double extorsion. |

### Sources

* [ransomlook.io](https://www.ransomlook.io//group/qilin)

<a id="frucastro-sl"></a>

### FRUCASTRO SL

### Résumé technique

Le groupe de rançongiciel « emperador » a revendiqué l'exfiltration de 540,1 Mo de données auprès de FRUCASTRO SL, entreprise du secteur manufacturier. Les données comprennent des bases de données récentes et des documents importants. La publication sur le site de fuite du groupe est programmée pour le 6 septembre 2026 à 11:40:43 UTC. Aucun indicateur de compromission (IOC) n'a été publié par les sources à ce stade. Le vecteur d'accès initial n'est pas documenté : les sources ne précisent ni méthode d'intrusion, ni présence d'un chiffrement des systèmes. Il s'agit d'un schéma d'extorsion de données où l'acteur menace de divulguer les informations volées pour contraindre la victime au paiement. L'attribution se limite au nom du groupe revendiquant l'attaque (« emperador »), sans qualification par les sources au-delà de cette revendication.

### Analyse de l'impact

FRUCASTRO SL, entreprise manufacturière, subit une menace de divulgation publique de bases de données et documents internes. L'exposition de données opérationnelles — potentiellement de propriété intellectuelle, de processus de fabrication ou d'informations clients — peut entraîner un préjudice concurrentiel direct, des sanctions sous le RGPD si des données personnelles sont concernées, et une dégradation de la réputation. Le volume de 540,1 Mo suggère une exfiltration ciblée plutôt qu'un vidage massif. La fenêtre avant publication (23 août – 6 septembre 2026) laisse un délai court pour qualifier l'incident, contenir l'exfiltration et notifier les parties prenantes. Le secteur manufacturier est particulièrement sensible à la compromission de propriété intellectuelle.

**Priorité : moyenne.**

### Recommandations

**Stratégiques**

* Activer le plan de réponse à incident et convoquer la cellule de crise pour décider de la posture de négociation et de la communication publique.
* Mandater un prestataire d'investigation numérique pour confirmer l'ampleur de l'exfiltration et identifier le vecteur d'intrusion.
* Évaluer les obligations de notification auprès de la CNIL si des données personnelles sont confirmées dans le périmètre exfiltré.
* Préparer une communication à destination des clients et partenaires concernés par une éventuelle fuite de leurs données.

**Opérationnelles**

* Préserver les journaux d'accès, flux réseau et sauvegardes sans altérer les artefacts potentiels pour l'investigation.
* Rechercher dans les SIEM et EDR des signes d'exfiltration : transferts volumineux vers des destinations externes, connexions vers des services de stockage cloud non autorisés.
* Vérifier l'intégrité et la disponibilité des sauvegardes, et les isoler du réseau principal.
* Surveiller le site de fuite « emperador » via RansomLook pour suivre l'évolution et d'éventuelles publications d'IOCs.
* Auditer les accès aux bases de données et partages de fichiers pour identifier les comptes compromis ou les accès anormaux récents.

### Playbook de réponse à incident

#### Phase 1 - Préparation

* Recenser l'inventaire des actifs de FRUCASTRO SL, en priorisant les serveurs de bases de données et les partages de documents du secteur manufacturier.
* Vérifier l'activation des journaux EDR, des journaux d'authentification Active Directory et des journaux d'audit des bases de données sur le périmètre concerné.
* Confirmer l'existence et l'intégrité de sauvegardes hors ligne testées, couvrant les bases de données et les documents revendiqués par le groupe emperador.
* Établir la chaîne de contact d'astreinte : CERT-FR, DPO, direction juridique et prestataire d'intervention le cas échéant.
* Cartographier le périmètre des données potentiellement exfiltrées : bases de données et documents représentant environ 540,1 Mo.

#### Phase 2 - Détection et analyse

* **Règles de détection contextualisées :**

  * Règle [Sigma] :

    ```yaml
    title: Suspicious Archive Creation in Temp Directories
    status: experimental
    description: Detects compressed archives in temporary or public directories consistent with data staging before exfiltration
    logsource:
        product: windows
        category: file_event
    detection:
        selection:
            TargetFilename|contains:
                - '\Temp\'
                - '\AppData\Local\Temp\'
                - 'C:\Users\Public\'
            TargetFilename|endswith:
                - '.zip'
                - '.7z'
                - '.rar'
                - '.tar.gz'
        condition: selection
    level: high
    tags:
        - attack.exfiltration
        - attack.t1074
    ```

  * Règle [SIEM] :

    ```
    index=* sourcetype IN (mysql:audit, postgresql:log, mssql:audit)
    | stats count, sum(bytes) as total_bytes by user, src_ip, database_name
    | where total_bytes > 104857600
    | sort - total_bytes
    ```

  * Règle [Sigma] :

    ```yaml
    title: Network Connection to File-Sharing or Cloud Storage Services
    status: experimental
    description: Detects outbound connections to cloud storage and file-sharing services commonly used for data exfiltration
    logsource:
        product: windows
        category: network_connection
    detection:
        selection:
            DestinationHostname|endswith:
                - '.s3.amazonaws.com'
                - '.blob.core.windows.net'
                - 'storage.googleapis.com'
                - 'mega.nz'
                - 'file.io'
                - 'transfer.sh'
                - 'gofile.io'
                - 'wetransfer.com'
        filter:
            Image|startswith:
                - 'C:\Program Files\'
                - 'C:\Program Files (x86)\'
        condition: selection and not filter
    level: high
    tags:
        - attack.exfiltration
        - attack.t1567
    ```

  * Règle [EDR] :

    ```
    sequence by host.name, user.name with maxspan=1h
      [file where event.action == 'read' and file.size > 10485760]
      [file where event.action == 'read' and file.size > 10485760]
      [file where event.action == 'read' and file.size > 10485760]
    ```

* Corréler les alertes de création d'archives dans les répertoires temporaires avec les connexions réseau sortantes vers des services de stockage cloud.
* Examiner les journaux d'audit des bases de données pour identifier tout volume anormal de requêtes ou d'exportations supérieur à 100 Mo par session.
* Vérifier les authentifications récentes sur le périmètre FRUCASTRO SL à la recherche de comptes valides utilisés à des heures inhabituelles ou depuis des adresses inconnues.
* Croiser les horodatages des accès massifs aux fichiers avec les fenêtres de connexion suspectes pour reconstituer la chronologie de l'exfiltration.
* Documenter chaque artéfact identifié pour transmission au CERT-FR et appui aux notifications réglementaires.

#### Phase 3 - Confinement, éradication et récupération

**Confinement :**

* Isoler les serveurs de bases de données et les partages de documents concernés du réseau sans éteindre les machines afin de préserver les artéfacts en mémoire volatile.
* Révoquer immédiatement les sessions actives et les jetons d'authentification associés aux comptes suspectés d'avoir servi à l'exfiltration.
* Capturer une image mémoire et une image disque des systèmes compromis avant toute modification pour préservation des preuves.
* Bloquer les domaines de services de partage de fichiers identifiés au niveau du proxy et du pare-feu de sortie.
* Conserver les journaux d'audit des bases de données et les journaux réseau dans un dépôt forensique dédié.

**Éradication :**

* Réinitialiser tous les mots de passe des comptes ayant accédé aux bases de données et documents revendiqués par le groupe emperador.
* Supprimer toute persistance identifiée : tâches planifiées, services malveillants, clés de registre Run, comptes créés récemment.
* Appliquer les correctifs de sécurité manquants sur les serveurs de bases de données et les applications exposées.
* Vérifier l'absence de backdoors ou de webshells sur les serveurs web et les serveurs de fichiers du périmètre FRUCASTRO SL.
* Réviser les règles de pare-feu pour restreindre l'accès aux bases de données aux seules adresses internes légitimes.

**Récupération :**

* Restaurer les bases de données et documents depuis les sauvegardes hors ligne validées, en priorisant les systèmes critiques au manufacturing.
* Vérifier l'intégrité des données restaurées par comparaison avec les sauvegardes et contrôle de hash.
* Remettre en service les systèmes progressivement, en validant à chaque étape l'absence d'indicateurs de compromission.
* Maintenir une surveillance renforcée de 72 heures après remédiation : alertes EDR, flux réseau sortant, authentifications anormales.
* Confirmer auprès des équipes métier la continuité des opérations de fabrication et la disponibilité des données restaurées.

#### Phase 4 - Activités post-incident

* Calculer le MTTD et le MTTR à partir des premiers journaux d'accès suspect et de la date de remédiation effective.
* Notifier la CNIL sous 72 heures si les bases de données ou documents exfiltrés contiennent des données personnelles au sens du RGPD.
* Évaluer l'applicabilité de NIS2 : FRUCASTRO SL opérant dans le secteur manufacturier, déterminer si le seuil d'entité essentielle est atteint.
* Transmettre au CERT-FR l'ensemble des artéfacts et indicateurs collectés, y compris les horodatages et volumes observés.
* Organiser un retour d'expérience formel avec les équipes SOC, IR et métier pour documenter les leçons apprises et les axes d'amélioration.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Le groupe emperador a pu utiliser des comptes valides compromis pour accéder aux bases de données et documents de FRUCASTRO SL. | T1078 | Journaux d'authentification Active Directory et journaux de connexion des bases de données. | SPL: index=windows_logs sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4625) \| stats count, values(src_ip) as src_ips, dc(src_ip) as distinct_ips by user \| where distinct_ips > 3 OR count > 50 \| sort - count |
| Les 540,1 Mo de données revendiquées ont pu être regroupées et compressées dans un répertoire temporaire avant exfiltration. | T1074 | Journaux EDR et événements de création de fichiers Sysmon. | EQL: file where event.action == 'creation' and file.extension in ('zip', '7z', 'rar', 'tar.gz') and file.size > 10485760 |
| Les données volées ont pu être transférées vers un service de stockage en ligne ou de partage de fichiers avant la publication programmée du 6 septembre 2026. | T1567 | Journaux de proxy sortant et journaux de pare-feu. | KQL: event.category:"network" AND network.protocol:"tls" AND (destination.domain:*amazonaws* OR destination.domain:*core.windows* OR destination.domain:*mega.nz* OR destination.domain:*gofile* OR destination.domain:*transfer.sh*) |

### Indicateurs de compromission (DEFANG obligatoire)

*Aucun IOC technique publié par les sources pour ce cluster.*

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| [T1005](https://attack.mitre.org/techniques/T1005/) | Collection | Data from Local System | Les bases de données et documents de FRUCASTRO SL ont été collectés depuis les systèmes de la victime par le groupe emperador, comme en attestent les 540,1 Mo de données revendiquées. |
| [T1074](https://attack.mitre.org/techniques/T1074/) | Collection | Data Staged | Les données exfiltrées ont été rassemblées et préparées en vue de leur publication programmée sur le site de fuite du groupe emperador. |
| [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration | Exfiltration Over Web Service | Les données volées ont été transférées vers une infrastructure externe contrôlée par le groupe emperador pour publication sur son site de fuite ; le canal exact d'exfiltration n'est pas documenté par les sources. |

### Sources

* [ransomlook.io](https://www.ransomlook.io//group/emperador)

<a id="reliaquest-llc"></a>

### ReliaQuest, LLC

### Résumé technique

Le groupe ShinyHunters a publié une annonce sur la plateforme RansomLook désignant ReliaQuest, LLC comme cible. Le message daté du 2026-08-23 ne contient aucune description technique du mode opératoire, aucun indicateur de compromission (IOC) et aucun détail sur l'ampleur de l'atteinte. Le texte se distingue par une provocation adressée à Mandiant, sommé de « rapporter et conseiller avec exactitude » avant de se retirer. Une clause de non-responsabilité standard est jointe, précisant l'absence d'endossement de toute entité commerciale. Aucune chronologie d'exploitation, aucun vecteur d'accès initial et aucun prérequis technique ne sont documentés par les sources à ce stade. L'attribution repose uniquement sur la revendication de l'acteur lui-même ; aucune attribution indépendante par un tiers n'est mentionnée.

### Analyse de l'impact

ReliaQuest, LLC est désignée comme cible par ShinyHunters dans une publication à caractère provocateur. L'absence d'IOC et de détail technique ne permet pas d'évaluer l'impact réel à ce stade. La provocation explicite envers Mandiant suggère une dimension de communication et de notoriété dans cette revendication. Pour une organisation cliente ou partenaire de ReliaQuest, le risque principal résiderait dans une éventuelle exposition de données confiées à ce prestataire. Aucune information publiée ne permet toutefois de confirmer une compromission effective.

**Priorité : moyenne.**

### Recommandations

**Stratégiques**

* Évaluer la relation d'affaires avec ReliaQuest et le volume de données ou d'accès confiés à ce prestataire.
* Anticiper un scénario de notification réglementaire au cas où des données confiées à ReliaQuest s'avéreraient compromises.
* Maintenir ce signalement en veille et non en mode incident confirmé, dans l'attente d'éléments techniques corroborants.

**Opérationnelles**

* Surveiller les canaux de publication de ShinyHunters pour détecter toute diffusion de données ou d'indicateurs techniques.
* Recenser les intégrations, comptes de service et flux de données liés à ReliaQuest dans le SI pour préparer une isolation rapide.
* Activer une détection prioritaire sur les tentatives d'usurpation exploitant le nom de ReliaQuest ou de ses services.
* Consigner cet événement dans le registre de veille pour corrélation avec de futures publications de l'acteur.

### Playbook de réponse à incident

#### Phase 1 - Préparation

* Recenser les actifs ReliaQuest exposés sur Internet et les services cloud associés.
* Activer la journalisation des accès sur les dépôts de code, stockages cloud et annuaires d'identité.
* Vérifier l'intégrité et la testabilité des sauvegardes hors ligne pour les systèmes critiques.
* Confirmer la chaîne d'escalade CERT et les contacts juridiques pour notification de violation de données.
* Cartographier les comptes à privilèges et les accès tiers pouvant être ciblés par exfiltration de données.

#### Phase 2 - Détection et analyse

* **Règles de détection contextualisées :**

  * Règle [Sigma] :

    ```yaml
    title: Authentification Anormale Depuis Localisation Inedite
    status: experimental
    description: Detecte les authentifications reussies depuis une localisation geographique jamais observee auparavant
    logsource:
        product: okta
        service: authentication
    detection:
        selection:
            event_type: user.authentication.sso
            outcome: SUCCESS
        condition: selection
        timeframe: 7d
    falsepositives:
        - Deplacements legitimes
        - Changements de VPN
    level: medium
    ```

  * Règle [SIEM] :

    ```
    index=* sourcetype=aws:cloudtrail eventSource=s3.amazonaws.com eventName=GetObject
    | stats count as acces_count dc(bucketName) as buckets_distincts by userIdentity.arn _time
    | where acces_count > 1000
    | sort -acces_count
    ```

  * Règle [Sigma] :

    ```yaml
    title: Staging de Donnees dans Repertoires Temporaires
    status: experimental
    description: Detecte des operations de fichiers volumineuses dans des repertoires temporaires pouvant indiquer un staging de donnees avant exfiltration
    logsource:
        category: file_event
        product: windows
    detection:
        selection:
            TargetFilename|contains:
                - '\Temp\'
                - '\tmp\'
                - '\AppData\Local\Temp\'
        filter:
            Image|startswith:
                - 'C:\Windows\System32\'
                - 'C:\Program Files\'
        condition: selection and not filter
    falsepositives:
        - Installations logicielles legitimes
        - Mises a jour systeme
    level: medium
    ```

  * Règle [SIEM] :

    ```
    index=firewall action=allowed direction=outbound
    | stats sum(bytes_out) as volume_total count as nb_connexions by src_ip dest_ip dest_port
    | where volume_total > 104857600
    | sort -volume_total
    ```

* Noter l'absence d'IOC publiés dans le dossier ShinyHunters ; baser la détection sur des signaux comportementaux liés à l'exfiltration de données.
* Corréler les authentifications réussies avec les localisations IP historiques pour identifier les accès depuis des points de sortie inédits.
* Analyser les journaux CloudTrail pour détecter des téléchargements massifs depuis les buckets S3 dépassant un seuil de 1000 objets par session.
* Surveiller les répertoires temporaires pour identifier un staging de données précédant une exfiltration.
* Croiser les volumes de trafic sortant avec les heures ouvrées pour isoler les transferts anormaux de plus de 100 Mo.

#### Phase 3 - Confinement, éradication et récupération

**Confinement :**

* Isoler les systèmes identifiés comme compromis sans éteindre les machines afin de préserver les artefacts forensiques.
* Désactiver immédiatement les comptes suspectés d'être utilisés pour l'exfiltration.
* Bloquer les adresses IP de destination des transferts de données anormaux au pare-feu périmétrique.
* Suspendre les clés d'accès cloud associées aux comptes compromis.

**Éradication :**

* Révoquer toutes les sessions actives des comptes compromis via l'annuaire d'identité.
* Pivoter tous les secrets et mots de passe des comptes à privilèges impactés.
* Auditer et retirer les règles de transfert ou les tokens de persistance créés pendant la fenêtre d'attaque.

**Récupération :**

* Restaurer les systèmes affectés depuis des sauvegardes vérifiées comme saines.
* Valider l'intégrité des données restaurées par comparaison avec les instantanés antérieurs.
* Maintenir une surveillance renforcée de 72 heures après remédiation pour détecter toute tentative de réaccès.

#### Phase 4 - Activités post-incident

* Mesurer le MTTD et le MTTR à partir des horodatages des journaux et des actions de remédiation.
* Évaluer l'obligation de notification RGPD à la CNIL sous 72 heures si des données personnelles sont concernées.
* Évaluer l'applicabilité de NIS2 pour notification à l'ANSSI si l'entité relève d'un secteur essentiel.
* Partager les indicateurs et le récit de l'incident avec le CERT-FR via le canal approprié.
* Organiser une session de retour d'expérience avec les équipes SOC, CERT et juridiques.

#### Phase 5 - Threat Hunting (proactif)

* N/A

### Indicateurs de compromission (DEFANG obligatoire)

*Aucun IOC technique publié par les sources pour ce cluster.*

### TTP MITRE ATT&CK

*Aucune technique ATT&CK rattachée par les sources.*

### Sources

* [ransomlook.io](https://www.ransomlook.io//group/shinyhunters)

<a id="hospitality-health-er-longview"></a>

### Hospitality Health ER (Longview)

### Résumé technique

Le groupe ransomware Genesis a publié une revendication d'attaque contre Hospitality Health ER (Longview), établissement de santé, sur sa page de fuite référencée par ransomlook.io. La revendication est datée du 2026-08-23. Aucun détail technique n'est publié par les sources à ce stade : ni vecteur d'entrée, ni outil de chiffrement, ni mécanisme d'exfiltration, ni chronologie d'exploitation. Aucun indicateur de compromission (IOC) n'est disponible. Le mode opératoire précis de Genesis — initial access, déplacement latéral, persistance, exfiltration — n'est pas documenté dans ce dossier. La seule source est la page de revendication sur ransomlook.io, qui ne fournit qu'une description générique de la victime (« A healthcare organization »). Aucune attribution à un acteur étatique n'est formulée. La volumétrie des données exfiltrées ou chiffrées n'est pas communiquée.

### Analyse de l'impact

Hospitality Health ER (Longview) est un établissement de santé, ce qui soulève des enjeux spécifiques au-delà de la simple indisponibilité informatique. Une attaque ransomware sur un service d'urgences (ER) peut directement impacter la prise en charge des patients : ralentissement des admissions, indisponibilité des dossiers médicaux électroniques (EMR), report d'actes cliniques. Le secteur santé est soumis à des obligations réglementaires strictes de notification en cas de fuite de données de santé, considérées comme données personnelles sensibles. Le coût d'une telle attaque combine rançon éventuelle, coûts de remédiation, interruption d'activité clinique et impact réputationnel auprès des patients et de la communauté locale.

**Priorité : moyenne.**

### Recommandations

**Stratégiques**

* Valider que le plan de continuité d'activité (PCA) couvre explicitement les scénarios d'indisponibilité des systèmes cliniques critiques (EMR, PACS, systèmes d'admission) face à un ransomware.
* Vérifier la conformité des exigences de notification réglementaire auprès des autorités sanitaires et de la CNIL en cas de fuite de données de santé, et s'assurer que les délais contractuels d'assurance cyber sont compatibles.
* Imposer aux prestataires IT et éditeurs de logiciels médicaux des exigences de sécurité contractualisées (segmentation, sauvegardes isolées, tests de restauration) et un droit d'audit.

**Opérationnelles**

* Surveiller la page de fuite de Genesis sur ransomlook.io et les flux de threat intelligence pour détecter toute publication de données ou d'indicateurs liés à cet incident.
* Vérifier immédiatement l'intégrité, l'isolation et la testabilité des sauvegardes des systèmes cliniques critiques de l'établissement.
* Corréler les journaux EDR, SIEM et Active Directory des dernières 30 jours pour détecter toute activité anormale (exécution de PowerShell, création de comptes, accès massifs à partages) compatible avec une phase de reconnaissance post-compromission.
* Renforcer la vigilance du personnel soignant et administratif face aux tentatives de phishing, en particulier les pièces jointes et liens suspects, vecteur d'entrée récurrent dans le secteur santé.

### Playbook de réponse à incident

#### Phase 1 - Préparation

* Inventorier les actifs critiques de l'établissement de santé : serveurs de dossiers patients, dispositifs médicaux connectés et postes administratifs.
* Activer la collecte centralisée des journaux Windows Security, Sysmon et EDR sur tous les hôtes du périmètre santé.
* Constituer et tester la chaîne d'astreinte : RSSI, DSI, juriste, CERT-FR et prestataire forensique.
* Vérifier l'existence et la testabilité de sauvegardes hors ligne (air-gapped) pour les systèmes hébergeant les données patients.
* Cartographier le périmètre réseau : VLAN métiers, accès VPN et interconnexions avec prestataires de santé.

#### Phase 2 - Détection et analyse

* **Règles de détection contextualisées :**

  * Règle [Sigma] :

    ```yaml
    title: Modification massive de fichiers par processus suspect
    status: experimental
    description: Détecte un processus modifiant un volume anormal de fichiers en peu de temps, comportement typique d'un chiffrement rançongiciel.
    logsource:
      product: windows
      category: file_event
    detection:
      selection:
        EventID: 4663
      timeframe: 1m
      condition: selection | count(TargetFilename) by process > 100
    falsepositives:
      - Sauvegarde programmée
      - Indexation de fichiers
    level: high
    ```

  * Règle [SIEM] :

    ```
    index=windows source="WinEventLog:Security" EventCode=4624 LogonType IN (3,10)
    | stats count by dest_ip, user, src_ip
    | where count > 50
    | eval suspicion="authentifications multiples depuis une source unique vers un hôte de santé"
    | sort - count
    ```

  * Règle [Sysmon] :

    ```xml
    title: Exécution d'outils de découverte post-compromission
    status: experimental
    description: Détecte l'exécution en chaîne d'outils de reconnaissance système via cmd ou PowerShell.
    logsource:
      product: windows
      category: process_creation
    detection:
      selection_img:
        Image|endswith:
          - '\\whoami.exe'
          - '\\nltest.exe'
          - '\\net.exe'
          - '\\systeminfo.exe'
      selection_parent:
        ParentImage|endswith:
          - '\\powershell.exe'
          - '\\cmd.exe'
      condition: selection_img and selection_parent
    falsepositives:
      - Scripts d'administration légitimes
    level: medium
    ```

  * Règle [EDR] :

    ```
    title: Tentative de désactivation de solutions de sécurité
    status: experimental
    description: Détecte les tentatives d'arrêt ou de modification de services antivirus, EDR ou de sauvegarde.
    logsource:
      product: windows
      category: process_creation
    detection:
      selection_cmd:
        CommandLine|contains:
          - 'sc stop'
          - 'sc config'
          - 'Set-MpPreference -DisableRealtimeMonitoring'
          - 'taskkill /F /im'
      selection_target:
        CommandLine|contains:
          - 'Defender'
          - 'Antivirus'
          - 'backup'
      condition: selection_cmd and selection_target
    falsepositives:
      - Maintenance planifiée du système de sécurité
    level: critical
    ```

* Corréler les alertes EDR avec les journaux d'authentification Windows pour identifier le compte initial compromis.
* Vérifier la présence de notes de rançon ou de fichiers à extension modifiée sur les partages réseau de l'établissement.
* Isoler l'hôte suspect et capturer une image mémoire volatile avant toute extinction.
* Documenter la chaîne d'événements avec horodatage précis pour alimenter le rapport d'incident.

#### Phase 3 - Confinement, éradication et récupération

**Confinement :**

* Isoler les hôtes confirmés compromis du réseau sans les éteindre, afin de préserver les artefacts forensiques.
* Désactiver les comptes utilisateurs et de service suspectés d'être utilisés par l'attaquant.
* Bloquer les adresses IP et domaines identifiés comme malveillants au pare-feu périmétrique.
* Conserver une copie forensique des disques des machines compromises avant toute désinfection.

**Éradication :**

* Rechercher et supprimer toutes les persiances : tâches planifiées, services malveillants, clés de registre Run, subscriptions WMI.
* Réinitialiser tous les mots de passe des comptes ayant accédé aux hôtes compromis, y compris les comptes de service.
* Révoquer les tickets Kerberos et fermer les sessions RDP actives via klist et déconnexion.
* Appliquer les correctifs de sécurité manquants sur les systèmes concernés avant remise en service.

**Récupération :**

* Restaurer les systèmes à partir des sauvegardes hors line validées, en priorité les serveurs de dossiers patients.
* Vérifier l'intégrité des données restaurées et confirmer l'absence de notes de rançon résiduelles.
* Remettre les systèmes en service de manière progressive avec surveillance renforcée de 72 heures.
* Surveiller activement toute réapparition d'activité suspecte pendant la période de 72 heures post-remédiation.

#### Phase 4 - Activités post-incident

* Mesurer le MTTD et le MTTR à partir des horodatages des journaux et des alertes EDR.
* Notifier la CNIL sous 72 heures si des données de santé personnelles ont été compromises, conformément au RGPD.
* Évaluer l'applicabilité de NIS2 : l'établissement de santé relève des entités essentielles, notification à l'ANSSI requise.
* Partager les IOC et indicateurs comportementaux observés avec le CERT-FR via la plateforme appropriée.
* Rédiger un retour d'expérience formalisé couvrant la chronologie, les lacunes de détection et les axes d'amélioration.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| L'attaquant a utilisé des comptes valides pour se déplacer latéralement vers les serveurs de dossiers médicaux. | T1078 | Journaux d'authentification Windows (EventID 4624, 4625) et journaux EDR. | index=windows source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625) LogonType=3 \| stats count by user, src_ip, dest_host \| where count > 20 \| sort - count |
| L'attaquant a chiffré ou détruit des données sur les partages réseau de l'établissement avant ou pendant la revendication. | T1486 | Événements de modification de fichiers Sysmon (EventID 2) et journaux des serveurs de fichiers. | index=sysmon EventID=2 \| stats count(TargetFilename) by process, Computer \| where count > 200 \| sort - count |
| L'attaquant a désactivé les outils de sécurité et de sauvegarde avant l'exécution du rançongiciel. | T1562.001 | Journaux de création de processus Sysmon (EventID 1) et journaux de services Windows. | index=sysmon EventID=1 (CommandLine="*sc stop*" OR CommandLine="*Set-MpPreference*" OR CommandLine="*taskkill*") \| table _time, Computer, Image, CommandLine |

### Indicateurs de compromission (DEFANG obligatoire)

*Aucun IOC technique publié par les sources pour ce cluster.*

### TTP MITRE ATT&CK

*Aucune technique ATT&CK rattachée par les sources.*

### Sources

* [ransomlook.io](https://www.ransomlook.io//group/genesis)

<a id="leau-en-bouteille-chere-est-elle-vraiment-meilleure-pour-vous"></a>

### L'eau en bouteille chère est-elle vraiment meilleure pour vous ?

### Résumé technique

Le dossier soumis ne porte pas sur une menace informatique. Il s'agit d'un article du magazine Wired publié le 2026-08-23, intitulé « Is Expensive Bottled Water Actually Better for You? », qui examine si l'eau en bouteille de luxe offre une meilleure hydratation. L'article indique que l'eau de luxe peut contenir différents minéraux et avoir un goût nettement différent, mais qu'une source éloignée, un pH alcalin et un prix élevé ne signifient pas nécessairement une meilleure hydratation. Aucun mécanisme d'attaque, aucune vulnérabilité logicielle, aucune configuration concernée, aucun prérequis d'exploitation, aucune chronologie de divulgation, aucune attribution à un acteur de menace, et aucune volumétrie ne sont mentionnés dans ce dossier. Détail technique non publié par les sources à ce stade.

### Analyse de l'impact

Ce dossier n'a aucun impact identifié sur la sécurité des systèmes d'information d'une organisation. Aucun produit, aucune architecture, aucune population exposée ne sont concernés. Aucun effet de pivot, aucun coût d'attaque, et aucune perte organisationnelle concrète ne peuvent être déduits du contenu de l'article, qui traite de la qualité de l'eau en bouteille de luxe et non de cybersécurité. Détail non publié par les sources à ce stade.

**Priorité : moyenne.**

### Recommandations

**Stratégiques**

* Exclure les flux d'actualité générale non liés à la cybersécurité du pipeline de veille threat intelligence pour éviter la dilution de l'analyse.
* Mettre en place un filtre de classification automatique des articles entrants pour distinguer les dossiers techniques de menace des contenus hors-sujet.

**Opérationnelles**

* Vérifier la pertinence cyber de chaque article avant de l'intégrer au brief quotidien du CERT.
* Archiver ce dossier hors du référentiel de menaces actives, sans IOC ni TTP à corréler.
* Ne pas créer de règle de détection ni d'alerte SOC sur la base de ce dossier.

### Playbook de réponse à incident

#### Phase 1 - Préparation

* Constater que ce dossier ne contient aucun élément de cybersécurité : article de vulgarisation sur l'eau en bouteille, sans IOC, CVE, acteur ou technique d'attaque.
* Ne mobiliser aucune ressource de préparation spécifique à ce dossier, car aucun actif informatique n'est concerné.
* Maintenir en permanence l'inventaire des actifs critiques et la cartographie du périmètre SOC conformément à la doctrine NIST 800-61, indépendamment de ce dossier.

#### Phase 2 - Détection et analyse

* Constater qu'aucune règle de détection ne peut être rédigée à partir de ce dossier : aucun IOC, aucune technique MITRE ATT&CK, aucun indicateur de compromission n'y figure.
* Ne pas créer de règles de corrélation sur la base de ce dossier, car aucune donnée technique n'est disponible pour étayer une logique de détection.
* Transmettre ce dossier au pôle de veille pour exclusion future du flux de cybermenaces si ce type d'article remonte récurrentiellement dans la pipeline de collecte.

#### Phase 3 - Confinement, éradication et récupération

**Confinement :**

* Constater qu'aucun incident de cybersécurité n'est décrit dans ce dossier ; aucune mesure de confinement n'est applicable.

**Éradication :**

* Vérifier qu'aucune persistance ni accès malveillant n'est documenté dans ce dossier ; aucune éradication n'est nécessaire.

**Récupération :**

* Confirmer qu'aucun service à remettre en ligne n'est identifié dans ce dossier ; aucune surveillance renforcée de 72 h n'est déclenchée.

#### Phase 4 - Activités post-incident

* Clôturer ce dossier comme hors périmètre de réponse à incident du CERT.
* Ne déclencher aucune notification réglementaire RGPD/CNIL sous 72 h ni NIS2 car aucun incident n'est constaté.
* Ne partager aucun IOC au CERT-FR car aucune donnée technique n'est présente dans ce dossier.
* Documenter le faux positif dans la base de connaissance du SOC pour affiner le filtrage des flux de veille à l'avenir.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Vérifier si l'URL de l'article Wired figurant dans le dossier a été utilisée comme leurre dans des campagnes de phishing ciblant l'organisation. | T1566 | Journaux de la passerelle de messagerie et du proxy web. | SPL: index=email OR index=proxy "wired.com/story/is-expensive-bottled-water-actually-better-for-you" \| stats count by src_user, sender, dest |
| Rechercher des domaines lookalike imitant wired.com ayant fait l'objet de requêtes DNS par les actifs internes. | T1583.001 | Journaux des résolveurs DNS internes et logs du proxy web. | KQL: dns_logs \| where query matches regex "(?i)(w[0-9]?red\|wiredd\|wir3d\|w-ired).*\.(com\|net\|org\|info)" \| summarize count by query, client_ip |

### Indicateurs de compromission (DEFANG obligatoire)

*Aucun IOC technique publié par les sources pour ce cluster.*

### TTP MITRE ATT&CK

*Aucune technique ATT&CK rattachée par les sources.*

### Sources

* [wired.com](https://www.wired.com/story/is-expensive-bottled-water-actually-better-for-you/)

<a id="semp-srl"></a>

### S.E.M.P. s.r.l.

### Résumé technique

Le groupe de rançongiciel Qilin a revendiqué le 23 août 2026 la compromission de S.E.M.P. s.r.l., société italienne du secteur des services aux entreprises (Business Services), via une publication sur la plateforme RansomLook. Aucun détail technique sur le vecteur d'accès initial, les outils déployés, la chronologie de l'intrusion ou la durée de présence avant chiffrement n'a été diffusé. Aucun indicateur de compromission (IOC) n'a été publié par les sources. L'éventuelle exfiltration de données, pratique courante en double extorsion, n'est pas confirmée par le dossier. Le mécanisme d'attaque précis et les prérequis d'exploitation restent non documentés à ce stade.

### Analyse de l'impact

S.E.M.P. s.r.l. opère dans les services aux entreprises, un secteur où la continuité opérationnelle et la confidentialité des données clients sont critiques. Un incident de rançongiciel peut paralyser la prestation de services, compromettre les données de clients et partenaires, et déclencher des obligations de notification réglementaire sous le RGPD. Le coût englobe les pertes d'exploitation, les frais de remédiation forensique, l'éventuelle rançon et l'atteinte réputationnelle. L'absence d'IOC publiés restreint la capacité de détection proactive des défenseurs face à d'éventuelles réutilisations d'infrastructure.

**Priorité : moyenne.**

### Recommandations

**Stratégiques**

* Évaluer l'exposition de la chaîne d'approvisionnement si S.E.M.P. s.r.l. est un prestataire de l'organisation et activer les clauses de notification d'incident contractuelles.
* Maintenir un plan de continuité d'activité (PCA) testé annuellement, incluant des sauvegardes immuables hors ligne et des procédures de bascule.
* Renforcer les exigences de cybersécurité dans les contrats avec les prestataires de services aux entreprises, incluant audits de sécurité et délais de notification d'incident.

**Opérationnelles**

* Surveiller les flux réseau sortants et les communications vers les infrastructures connues associées au groupe Qilin via les flux de veille en menaces.
* Vérifier l'absence d'artefacts de compromission dans les environnements si une relation d'affaires existe avec S.E.M.P. s.r.l.
* Appliquer le principe du moindre privilège et segmenter le réseau pour limiter la propagation latérale en cas d'intrusion initiale.
* Tester régulièrement les procédures de restauration depuis des sauvegardes immuables isolées du réseau de production.

### Playbook de réponse à incident

#### Phase 1 - Préparation

* Recenser l'ensemble des actifs de S.E.M.P. s.r.l. incluant postes de travail, serveurs de fichiers et contrôleurs de domaine Active Directory.
* Activer la journalisation PowerShell (ScriptBlock Logging, Module Logging) et déployer Sysmon avec une configuration couvrant les EventID 1, 3, 7, 8, 10, 11, 13, 22.
* Vérifier la chaîne d'astreinte du CERT et confirmer que le contact CERT-FR est joignable hors heures ouvrées.
* Tester la restauration d'au moins une sauvegarde hors ligne sur un environnement isolé et mesurer le temps de récupération effectif.
* Cartographier le périmètre d'exposition externe de S.E.M.P. s.r.l. en listant les accès VPN, sessions RDP exposées et services web publics.

#### Phase 2 - Détection et analyse

* **Règles de détection contextualisées :**

  * Règle [Sigma] :

    ```yaml
    title: Suppression des clichés instantanés via vssadmin
    status: experimental
    description: Détecte la suppression des VSS, technique d'inhibition de récupération courante en phase pré-chiffrement ransomware.
    logsource:
      product: windows
      category: process_creation
    detection:
      selection:
        Image|endswith: '\\vssadmin.exe'
        CommandLine|contains|all:
          - 'delete'
          - 'shadows'
      condition: selection
    level: high
    ```

  * Règle [SIEM] : `index=windows sourcetype=WinEventLog:Security EventCode=4663 ObjectType=File | stats count as file_ops, dc(TargetFilename) as unique_files by Image, host | where file_ops > 500 AND unique_files > 200 | sort -file_ops`
  * Règle [Sigma] :

    ```yaml
    title: Altération de Windows Defender via PowerShell
    status: experimental
    description: Détecte la modification des paramètres de Windows Defender via PowerShell, étape fréquente avant déploiement d'un ransomware.
    logsource:
      product: windows
      category: process_creation
    detection:
      selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
          - 'Set-MpPreference'
          - 'DisableRealtimeMonitoring'
          - 'Add-MpPreference'
          - 'ExclusionPath'
      condition: selection
    level: high
    ```

  * Règle [Sigma] :

    ```yaml
    title: Création de tâche planifiée distante via schtasks
    status: experimental
    description: Détecte la création de tâches planifiées avec ciblage distant, technique de propagation latérale utilisée par les opérateurs ransomware.
    logsource:
      product: windows
      category: process_creation
    detection:
      selection:
        Image|endswith: '\\schtasks.exe'
        CommandLine|contains|all:
          - '/create'
          - '/s '
      condition: selection
    level: medium
    ```

* Corréler les alertes de suppression de VSS avec les événements de connexion réseau pour identifier le système source du déploiement ransomware.
* Analyser les journaux d'authentification Windows (EventCode 4624 et 4625) pour détecter des connexions anormales sur les comptes à privilèges de S.E.M.P. s.r.l.
* Examiner la chronologie des événements EDR pour reconstituer la chaîne d'exécution depuis l'accès initial jusqu'au chiffrement.
* Considérer l'absence d'IOC publié comme une contrainte et baser la détection sur les comportements plutôt que sur des indicateurs statiques.

#### Phase 3 - Confinement, éradication et récupération

**Confinement :**

* Isoler immédiatement les hôtes affectés du réseau en conservant leur alimentation pour préserver la mémoire volatile et les artefacts forensiques.
* Désactiver les comptes utilisateurs compromis dans Active Directory sans supprimer les objets pour conserver les preuves d'audit.
* Bloquer les communications sortantes des hôtes suspects au niveau du pare-feu périmétrique pour empêcher toute exfiltration complémentaire.
* Segmenter le réseau de S.E.M.P. s.r.l. pour isoler les partages de fichiers et limiter la propagation latérale.

**Éradication :**

* Identifier et supprimer tous les mécanismes de persistance déployés : tâches planifiées, services malveillants, clés de registre Run, abonnements WMI.
* Réinitialiser les mots de passe de tous les comptes à privilèges et comptes de service après purge des tickets Kerberos via klist purge.
* Reconstruire les hôtes compromis à partir d'une image gold clean plutôt que de tenter un nettoyage en place.
* Vérifier l'absence de backdoors sur les contrôleurs de domaine via une analyse des délégations et des comptes DCSync potentiels.

**Récupération :**

* Restaurer les systèmes à partir des sauvegardes hors ligne vérifiées en priorisant les serveurs métier de S.E.M.P. s.r.l.
* Valider l'intégrité des données restaurées en comparant les sommes de contrôle avec les sauvegardes source.
* Reconnecter les systèmes restaurés au réseau par étapes en commençant par un segment isolé pour validation fonctionnelle.
* Maintenir une surveillance renforcée de 72 heures après remédiation avec alerting EDR en mode haute sensibilité sur les hôtes restaurés.

#### Phase 4 - Activités post-incident

* Calculer le MTTD et le MTTR à partir des horodatages des premiers événements EDR et de la déclaration de remédiation complète.
* Notifier la CNIL sous 72 heures si des données personnelles sont confirmées exfiltrées, conformément à l'article 33 du RGPD.
* Évaluer l'applicabilité de la directive NIS2 pour S.E.M.P. s.r.l. et notifier l'autorité compétente si l'entité relève d'un secteur essentiel.
* Partager les IOC collectés durant l'investigation et le résumé de l'incident avec le CERT-FR via le canal de partage approprié.
* Organiser un retour d'expérience formel avec les équipes SOC, IT et direction pour mettre à jour le PRA et les règles de détection.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| L'attaquant a utilisé des comptes valides compromis pour obtenir un accès initial au réseau de S.E.M.P. s.r.l. via VPN ou RDP exposé. | T1078 | Journaux d'authentification Windows (EventCode 4624 et 4625), journaux VPN, télémétrie EDR | index=windows sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4625) (LogonType=10 OR LogonType=3) \| stats count, values(src_ip), dc(dest_host) as hosts_accessed by user \| where count > 20 OR hosts_accessed > 5 \| sort -count |
| L'attaquant a exfiltré des données métier de S.E.M.P. s.r.l. vers un service externe avant de déployer le chiffrement, dans un schéma de double extorsion. | T1567.002 | Journaux de proxy sortant, journaux de pare-feu, journaux de processus EDR | index=proxy \| stats sum(bytes_out) as total_exfil, dc(dest_domain) as unique_domains by src_ip, user \| where total_exfil > 104857600 \| sort -total_exfil |
| L'attaquant a propagé le ransomware via les partages administratifs SMB et PsExec pour exécuter le chargeur sur plusieurs hôtes simultanément. | T1021.002 | Journaux Sysmon (EventID 1 et 3), journaux de partage administratif Windows (EventCode 5140 et 5145) | (index=sysmon EventID=1 (Image=*psexec* OR CommandLine=*ADMIN$*)) OR (index=windows sourcetype=WinEventLog:Security EventCode=5145 ShareName=*ADMIN*) \| stats count by src_ip, dest_host, Image, CommandLine \| sort -count |

### Indicateurs de compromission (DEFANG obligatoire)

*Aucun IOC technique publié par les sources pour ce cluster.*

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| [T1486](https://attack.mitre.org/techniques/T1486/) | Impact | Data Encrypted for Impact | Chiffrement des données de la victime par le rançongiciel Qilin dans le cadre de la revendication publiée sur RansomLook ; aucune précision sur l'algorithme ou l'étendue du chiffrement n'est disponible. |

### Sources

* [ransomlook.io](https://www.ransomlook.io//group/qilin)

<a id="clear-align"></a>

### Clear Align

### Résumé technique

Le groupe de rançongiciel Qilin a revendiqué, le 2026-08-23, la compromission de Clear Align, entreprise du secteur manufacturier, via sa page de fuite référencée par RansomLook. Aucun indicateur de compromission (IOC), vecteur d'accès initial, mécanisme d'attaque, chronologie d'exploitation ou volume de données exfiltrées n'a été publié par les sources à ce stade. L'attribution repose uniquement sur la revendication publiée par Qilin sur sa plateforme de fuite. Le secteur manufacturier est identifié comme catégorie de victime. Aucune configuration, version ou prérequis d'exploitation spécifique n'est documenté dans ce dossier.

### Analyse de l'impact

Clear Align, acteur du secteur manufacturier, fait face à un incident de rançongiciel revendiqué par Qilin. L'impact opérationnel potentiel inclut l'arrêt de chaînes de production, la perte d'accès aux données industrielles et des perturbations de la chaîne d'approvisionnement. La publication des données volées sur le leak site de Qilin exposerait à un risque de divulgation d'informations sensibles (propriété intellectuelle, données clients). Aucune information sur l'étendue du chiffrement ou le volume des données exfiltrées n'est disponible à ce stade.

**Priorité : moyenne.**

### Recommandations

**Stratégiques**

* Activer le plan de réponse à incident et notifier l'ANSSI conformément aux obligations réglementaires applicables (NIS2, RGPD).
* Évaluer les obligations contractuelles de notification vis-à-vis des clients et partenaires potentiellement impactés par une fuite de données.
* Considérer le recours à un prestataire spécialisé en négociation de rançon et en médiation avec le groupe Qilin.

**Opérationnelles**

* Isoler immédiatement les systèmes potentiellement compromis du réseau pour contenir la propagation du rançongiciel.
* Collecter et préserver les artefacts forensiques (journaux, images mémoire, captures réseau) avant toute action de remédiation.
* Vérifier l'intégrité et la disponibilité des sauvegardes, puis tester une procédure de restauration sur un environnement isolé.
* Surveiller le leak site de Qilin pour identifier les données effectivement exfiltrées et publiées.
* Déployer des règles de détection Endpoint Detection and Response (EDR) basées sur les comportements génériques de rançongiciel en attendant la publication d'IOCs spécifiques.

### Playbook de réponse à incident

#### Phase 1 - Préparation

* Recenser l'ensemble des actifs IT et OT du périmètre manufacturing de Clear Align, incluant serveurs de production, postes et automates.
* Activer la collecte centralisée des journaux Sysmon, EDR et pare-feu sur tous les systèmes Windows critiques de l'usine.
* Vérifier que les sauvegardes hors ligne (air-gapped) sont récentes, testées et restaurables sur un environnement isolé.
* Mettre à jour la liste de contacts d'astreinte : RSSI, DSI, CERT-FR, prestataire IR et éditeur EDR.
* Cartographier les flux réseau entre la zone IT et la zone OT pour identifier les points de passage à isoler en cas de chiffrement.

#### Phase 2 - Détection et analyse

* **Règles de détection contextualisées :**

  * Règle [Sigma] :

    ```yaml
    title: Suppression de copies shadow de volume
    status: experimental
    description: Détecte la suppression des copies shadow via vssadmin ou wmic, technique d'impact ransomware
    logsource:
        product: windows
        category: process_creation
    detection:
        selection_vssadmin:
            Image|endswith: '\vssadmin.exe'
            CommandLine|contains: 'delete shadows'
        selection_wmic:
            Image|endswith: '\wmic.exe'
            CommandLine|contains: 'shadowcopy delete'
        condition: selection_vssadmin or selection_wmic
    level: critical
    tags:
        - attack.impact
        - attack.t1490
    ```

  * Règle [SIEM] :

    ```
    index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=2
    | bucket _time span=1m
    | stats dc(TargetFilename) as fichiers_distincts, count as total_events by host, Image, _time
    | where fichiers_distincts > 200
    | sort - fichiers_distincts
    | eval risque=case(fichiers_distincts > 1000, "critique", fichiers_distincts > 500, "eleve", 1=1, "moyen")
    ```

  * Règle [EDR] :

    ```
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("schtasks /create", "schtasks /run", "sc create", "sc start")
    | where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "wmic.exe", "rundll32.exe")
    | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName
    | top 100 by Timestamp
    ```

  * Règle [auditd] :

    ```bash
    -w /etc/crontab -p wa -k persistance_ransomware
    -w /etc/cron.d/ -p wa -k persistance_ransomware
    -w /var/spool/cron/ -p wa -k persistance_ransomware
    -w /etc/systemd/system/ -p wa -k persistance_ransomware
    -w /usr/local/bin/ -p wa -k persistance_ransomware
    ```

* Corréler les alertes de suppression de shadow copies avec les événements Sysmon de création de processus pour identifier le processus initial.
* Analyser les sessions d'authentification récentes sur les contrôleurs de domaine pour identifier les comptes compromis.
* Examiner les journaux de pare-feu pour détecter des exfiltrations de données vers des destinations inhabituelles.
* Vérifier les alertes EDR pour des activités de découverte réseau telles que nmap, net view ou nltest.
* Croiser les horodatages des premières alertes avec la revendication publiée par Qilin sur RansomLook pour confirmer la chronologie.

#### Phase 3 - Confinement, éradication et récupération

**Confinement :**

* Isoler immédiatement les hôtes affectés du réseau en conservant leur alimentation pour préserver la mémoire volatile.
* Désactiver les comptes utilisateurs compromis identifiés lors de l'analyse sans supprimer les journaux d'authentification.
* Bloquer les adresses IP et domaines C2 identifiés aux pare-feu périmétriques et aux proxies.
* Prélever une image forensique des premiers hôtes compromis avant toute désinfection.
* Segmenter dynamiquement le réseau OT pour empêcher la propagation du chiffrement vers les automates.

**Éradication :**

* Supprimer toutes les tâches planifiées et services malveillants créés par l'attaquant sur les hôtes affectés.
* Réinitialiser tous les mots de passe des comptes ayant eu des sessions actives pendant la fenêtre d'attaque.
* Purger les outils de découverte et d'exfiltration déposés sur les systèmes compromis.
* Vérifier l'absence de persistance via clés de registre Run, WMI et tâches planifiées.
* Appliquer les correctifs de sécurité manquants sur les vecteurs d'accès initial identifiés.

**Récupération :**

* Restaurer les systèmes affectés depuis les sauvegardes hors ligne validées, en priorisant les serveurs de production manufacturing.
* Réintégrer les hôtes restaurés par lots avec validation fonctionnelle avant reconnexion au réseau de production.
* Surveiller en mode renforcé pendant 72 heures tous les systèmes restaurés via EDR et SIEM pour détecter toute réinfection.
* Vérifier l'intégrité des automates OT avant remise en service de la ligne de production.
* Confirmer la restauration complète auprès des responsables d'atelier avant déclaration de fin d'incident.

#### Phase 4 - Activités post-incident

* Calculer le MTTD et le MTTR à partir des horodatages des premières alertes et de la remise en service des systèmes.
* Évaluer l'obligation de notification à la CNIL sous 72 heures si des données personnelles ont été compromises lors de l'exfiltration.
* Déterminer l'applicabilité de NIS2 et notifier l'autorité compétente si Clear Align relève d'un secteur essentiel.
* Partager les IOC découverts avec le CERT-FR via la plateforme appropriée pour enrichir la base communautaire.
* Organiser une session de retour d'expérience avec les équipes IT, OT et la direction dans les 15 jours suivant l'incident.

#### Phase 5 - Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| L'attaquant a utilisé des comptes valides compromis pour accéder au réseau manufacturing de Clear Align. | T1078 | Journaux d'authentification Windows Security Event ID 4624/4625, journaux VPN. | index=windows sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4625) \| stats count, values(src_ip) as src_ips, earliest(_time) as first_login, latest(_time) as last_login by user, dest \| where count > 10 \| sort - count |
| Le ransomware a chiffré des fichiers sur les systèmes manufacturing, détectable par des motifs de modification massive de fichiers. | T1486 | Sysmon Event ID 2 (création de fichiers), télémétrie EDR des opérations sur fichiers. | DeviceFileEvents \| where Timestamp > ago(7d) \| summarize FileCount = count(), DistinctFolders = dcount(FolderPath) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m) \| where FileCount > 500 \| order by FileCount desc |
| L'attaquant a supprimé les copies shadow ou désactivé les services de sauvegarde pour empêcher la récupération. | T1490 | Journaux de création de processus Sysmon, journaux Windows System et Application. | process where event.type == "start" and (process.name == "vssadmin.exe" and process.command_line like "%delete shadows%") or (process.name == "wbadmin.exe" and process.command_line like "%delete catalog%") or (process.name == "bcdedit.exe" and process.command_line like "%recoveryenabled no%") |

### Indicateurs de compromission (DEFANG obligatoire)

*Aucun IOC technique publié par les sources pour ce cluster.*

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| [T1486](https://attack.mitre.org/techniques/T1486/) | Impact | Data Encrypted for Impact | Le rançongiciel Qilin a revendiqué la compromission de Clear Align, impliquant le chiffrement des données de la victime pour extorquer une rançon. Aucun détail sur l'algorithme ou l'étendue du chiffrement n'est publié. |

### Sources

* [ransomlook.io](https://www.ransomlook.io//group/qilin)

<a id="signaux-faibles"></a>

### Signaux faibles et fuites diverses

1 sujet(s) sous le seuil de notabilité : ni exploitation active, ni exposition du périmètre français, ni indicateurs techniques publiés.

**el-group** — Victimes revendiquées : el-group. Sources : [ransomlook.io](https://www.ransomlook.io//group/inc%20ransom).

#### Phases 1-4 (condensées)

* Vérifier l'exposition du périmètre aux services concernés.
* Surveiller la publication d'IOC techniques par les sources primaires.
* Notifier si des données personnelles gérées par l'entité sont concernées (RGPD, 72 h).
* Classer sans suite si aucun actif n'est exposé.
