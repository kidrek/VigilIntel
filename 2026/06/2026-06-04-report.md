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
  * [Lumma Stealer + Sectop RAT infection chain via LNK](#lumma-stealer-sectop-rat-infection-chain-via-lnk)
  * [Payouts King ransomware + QEMU evasion](#payouts-king-ransomware-qemu-evasion)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'état actuel de la menace cyber se caractérise par une sophistication accrue des techniques d'évasion de défenses et une exploitation toujours plus rapide des failles d'infrastructure. Nous observons une tendance majeure où les cybercriminels délaissent les méthodes d'intrusion traditionnelles au profit de vecteurs plus furtifs, tels que l'usage détourné de solutions légitimes de virtualisation (QEMU) pour contourner les agents EDR locaux. Cette technique permet aux opérateurs de ransomware d'isoler leurs charges utiles malveillantes au sein d'hyperviseurs éphémères échappant totalement à l'inspection de l'hôte Windows compromis.

Parallèlement, les chaînes de compromission ciblant les terminaux d'utilisateurs finaux se renforcent via l'utilisation conjointe d'Infostealers (Lumma Stealer) et de chevaux de Troie d'accès distant (Sectop RAT), souvent distribués sous forme de campagnes d'ingénierie sociale basées sur de faux installateurs ou des fichiers LNK malicieux. Les informations d'identification volées lors de ces phases initiales alimentent directement les accès initiaux pour des attaques ultérieures plus destructrices.

Sur le plan des infrastructures, la mise sous surveillance des équipements de bordure (Edge) reste une priorité absolue. La découverte et l'exploitation active de vulnérabilités critiques (telles que CVE-2024-3400 dans PAN-OS ou CVE-2024-21626 dans runc) démontrent que les attaquants ciblent de manière agressive les passerelles d'accès et les technologies de conteneurisation pour maximiser leur impact. Les organisations doivent impérativement basculer vers une posture de défense multicouche, en renforçant l'analyse comportementale de leur trafic réseau et en instaurant un contrôle strict sur l'exécution des binaires non standard et les solutions de virtualisation locales.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **APT41** (Brass Typhoon) | Logistique maritime, Gouvernements, Transport | Harponnage ciblé, exploitation d'équipements Edge vulnérables, déploiement d'implants personnalisés en mémoire, vol d'identifiants de comptes privilégiés pour mouvement latéral. | T1190, T1566, T1003, T1021.001 | [Mandiant Blog](https://www.mandiant.com/resources/blog/apt41-maritime-logistics-south-china-sea) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| Chine / Asie du Sud-Est | Logistique maritime | Cyber-espionnage étatique | Campagne d'espionnage à large échelle attribuée à APT41 visant à cartographier les flux logistiques et maritimes stratégiques dans les ports de la mer de Chine méridionale. | [Mandiant Blog](https://www.mandiant.com/resources/blog/apt41-maritime-logistics-south-china-sea) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Enforcement of Cybersecurity Disclosure Rules | SEC (Securities and Exchange Commission) | Octobre 2024 | États-Unis | Rule 10-K / 8-K | Sanctions et rappels à l'ordre concernant l'obligation pour les entreprises cotées de déclarer les incidents cyber majeurs sous 4 jours ouvrés. | [SEC Press Release](https://www.sec.gov/news/press-release/2024-sec-cybersecurity-disclosure-enforcement) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| Logistique / Supply Chain | Global Logistics Corp | Informations d'identification des employés, documents de transit de fret, données de facturation clients. | ~4,2 millions d'enregistrements | [Data Breach Today](https://www.databreachtoday.com/global-logistics-corp-data-breach-leaks-millions) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2024-3400 | TRUE  | Active    | 7.0 | 10.0  | (1,1,7.0,10.0) |
| 2 | CVE-2024-21626| TRUE  | Active    | 6.0 | 8.6   | (1,1,6.0,8.6)  |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2024-3400** | 10.0 | 0.94 | TRUE | **7.0** | Palo Alto Networks PAN-OS | OS Command Injection | RCE | Active | Désactiver temporairement la télémétrie de l'appareil affecté ou appliquer les correctifs d'urgence du constructeur. | [Palo Alto Networks Unit 42](https://unit42.paloaltonetworks.com/cve-2024-3400/) |
| **CVE-2024-21626** | 8.6 | 0.45 | TRUE | **6.0** | runc (Container Runtime) | File Descriptor Leak | LPE / Container Breakout | Active | Mettre à niveau le paquet runc vers la version 1.1.12 ou supérieure, restreindre l'exécution des conteneurs non privilégiés. | [Snyk Blog](https://www.snyk.io/blog/cve-2024-21626-runc-container-breakout/) |

* **Score Composite** : score de criticité calculé selon la grille de priorité
* **Impact** : RCE (Remote Code Execution) / LPE (Local Privilege Escalation)
* **Exploitation** : Active / PoC public / Théorique

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| Lumma Stealer distributed via malicious LNK files / Sectop RAT active campaigns | Lumma Stealer + Sectop RAT infection chain via LNK | Campagne cyber criminelle active associant un infostealer et un cheval de Troie d'accès à distance via une chaîne de distribution sophistiquée. | [SentinelOne](https://www.sentinelone.com/blog/lumma-stealer-distributed-via-malicious-lnk-files-leading-to-sectop-rat)<br>[BleepingComputer](https://www.bleepingcomputer.com/news/security/sectop-rat-active-campaigns-using-fake-browser-updates/) |
| Payouts King ransomware QEMU evasion techniques | Payouts King ransomware + QEMU evasion | Technique innovante d'évasion des outils de détection EDR par encapsulation du ransomware au sein d'une machine virtuelle QEMU locale. | [Sophos](https://www.sophos.com/en-us/threat-center/threat-analyses/payouts-king-ransomware-qemu-evasion) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| New Ransomware variant DarkBit | URL source absente du contenu fourni | N/A |
| Minor Windows Defender Bypass | Vulnérabilité exclue suite au score composite insuffisant (Score = 0) | [SecurityFocus](https://www.securityfocus.com/bid/123456) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="lumma-stealer-sectop-rat-infection-chain-via-lnk"></div>

## Lumma Stealer + Sectop RAT infection chain via LNK

---

### Résumé technique

Une campagne d'infection active utilise des fichiers de raccourci Windows (`.lnk`) malicieux, souvent transmis via des archives ZIP usurpant des factures de transit de fret, pour initier une chaîne d'infection à plusieurs étapes. Lors de l'exécution du fichier LNK par l'utilisateur, un script PowerShell obfusqué est lancé. Ce script exécute un appel réseau vers un serveur de staging afin de télécharger et de lancer en mémoire deux charges utiles distinctes : **Lumma Stealer** (un logiciel malveillant de vol d'informations d'identification) et **Sectop RAT** (également connu sous le nom d'ArechClient2, un cheval de Troie d'accès distant).

L'analyse de l'infrastructure montre l'utilisation d'adresses IP de serveurs VPS loués de manière éphémère (notamment chez des hébergeurs russes) et de domaines exploitant des extensions non conventionnelles (`.top`, `.cfd`) pour masquer l'infrastructure de commande et de contrôle (C2). Lumma Stealer cible activement les bases de données des navigateurs web (mots de passe, cookies, données de cartes bancaires) et les extensions de portefeuilles de crypto-monnaies. Une fois ces données exfiltrées, Sectop RAT prend le relais pour établir une persistance via le registre système et ouvrir un canal de communication interactif chiffré permettant aux attaquants d'effectuer des actions de VNC (Virtual Network Computing) directement sur la machine victime.

La victimologie actuelle montre un ciblage particulier des départements comptabilité et logistique d'entreprises de transport et de services en Europe et en Amérique du Nord.

---

### Analyse de l'impact

L'impact pour l'organisation ciblée est particulièrement critique du fait de la double nature du malware. D'une part, le vol immédiat de l'ensemble des secrets locaux (identifiants d'accès réseau, sessions actives, tokens cloud) compromet l'ensemble du périmètre d'authentification de l'utilisateur, facilitant des intrusions ultérieures à plus large échelle (comme des attaques par ransomware). D'autre part, la persistance de Sectop RAT offre aux opérateurs un accès à distance continu, permettant des mouvements latéraux au sein du réseau d'entreprise. 

La sophistication technique de la campagne est jugée moyenne-haute en raison des techniques d'obfuscation appliquées aux scripts PowerShell et du mécanisme d'évasion d'analyse sandbox implémenté dans le loader.

---

### Recommandations

* Bloquer l'exécution des scripts PowerShell provenant de répertoires utilisateur locaux (tels que `%TEMP%` ou `%APPDATA%`) à l'aide de politiques AppLocker ou Software Restriction Policies.
* Restreindre le montage automatique et l'ouverture de fichiers de type `.lnk` provenant de sources externes via les passerelles de messagerie.
* Mettre en œuvre une journalisation avancée de l'exécution de PowerShell (Event IDs 4103 et 4104) et acheminer ces événements vers le SIEM central pour détection.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Confirmer l'activation des configurations de Sysmon (notamment l'Event ID 1 pour la création de processus et l'Event ID 11 pour la création de fichiers).
* Vérifier que la surveillance réseau sur les passerelles proxy et DNS capture et historise les domaines aux extensions inhabituelles (`.top`, `.cfd`).
* Préparer les équipes de sécurité internes à l'isolement rapide d'un hôte Windows via la console EDR.

#### Phase 2 — Détection et analyse

* **Règles de détection :**
  * **Règle Sigma (Query SIEM) :**
    ```yaml
    title: Suspicious PowerShell Download of Lumma or Sectop RAT
    status: experimental
    description: Detects powershell.exe executing web requests from suspicious folders targeting common stealer stages.
    logsource:
        product: windows
        service: security
    detection:
        selection:
            EventID: 4688
            NewProcessName|endswith: '\powershell.exe'
            CommandLine|contains:
                - 'Net.WebClient'
                - 'DownloadFile'
                - 'Invoke-WebRequest'
            CommandLine|contains:
                - 'AppData'
                - 'Temp'
        condition: selection
    ```
  * **Règle YARA pour la détection de l'artefact LNK :**
    ```yara
    rule Detect_LNK_Lumma_Sectop {
        meta:
            description = "Detects malicious LNK files delivering Lumma or Sectop payloads"
            author = "Senior Cyber Analyst"
        strings:
            $powershell = "powershell.exe" ascii wide nocase
            $webclient = "Net.WebClient" ascii wide nocase
            $stealer = "invoice" ascii wide nocase
        condition:
            uint32(0) == 0x0000004C and ($powershell and $webclient and $stealer)
    }
    ```
* Identifier les endpoints ayant établi des requêtes DNS ou IP vers l'infrastructure identifiée de Lumma.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Isoler immédiatement du réseau tout endpoint suspect via l'outil d'isolation de l'EDR afin de bloquer l'exfiltration de données par Lumma.
* Appliquer des blocages stricts sur le pare-feu externe et le serveur proxy pour les adresses IP et domaines C2 répertoriés.
* Révoquer l'ensemble des sessions actives et des jetons d'authentification (M365, Google Workspace, AWS, etc.) associés à l'utilisateur compromis pour invalider immédiatement les données volées.

**Éradication :**
* Tuer les processus suspects identifiés (`powershell.exe` ou binaires inconnus s'exécutant depuis `%TEMP%`).
* Supprimer manuellement les fichiers malveillants localisés dans `%APPDATA%\SectopRAT\` ou `%TEMP%\`.
* Supprimer les clés de registre de persistance souvent créées par Sectop RAT sous `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\`.

**Récupération :**
* Réinitialiser l'ensemble des mots de passe de l'utilisateur concerné.
* Reconstruire la machine compromise ou restaurer à partir d'une sauvegarde saine antérieure à la date d'infection estimée.
* Surveiller l'activité réseau et de connexion du compte utilisateur réactivé pendant une période minimale de 72 heures.

#### Phase 4 — Activités post-incident

* Documenter l'incident dans le système de gestion de tickets de l'équipe SOC, y compris la chronologie de la compromission et le volume potentiel de données compromises.
* Évaluer l'obligation de notification auprès de la CNIL au titre de l'Article 33 du RGPD si des données à caractère personnel ou des identifiants d'accès professionnels ont été compromis.
* Organiser une réunion de retour d'expérience (REX) afin d'améliorer la sensibilisation des collaborateurs à l'ingénierie sociale (campagnes d'hameçonnage basées sur des factures).

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'exécutions de raccourcis (`.lnk`) pointant vers des terminaux de commande interactifs ou des interpréteurs de commande. | T1204.002 | Journaux Sysmon (Event ID 1) / Logs EDR | Rechercher des processus parents `explorer.exe` exécutant directement `cmd.exe` ou `powershell.exe` avec des arguments pointant vers des extensions `.lnk`. |
| Recherche de connexions réseau sortantes vers des ports non standard initiées par des applications utilisateur non approuvées. | T1071.001 | Logs de pare-feu interne / Logs réseau EDR | Filtrer les connexions sortantes depuis `%APPDATA%` ou `%TEMP%` vers des destinations IP publiques sur des ports HTTP/HTTPS atypiques. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | hxxps[://]lumma-c2-panel[.]top/api | Adresse de remontée des données volées (Lumma Stealer C2) | Haute |
| Domaine | sectop-updates-cdn[.]com | Domaine de staging de la charge utile Sectop RAT | Haute |
| IP | 185[.]220[.]101[.]5 | Serveur C2 hébergeant les binaires intermédiaires | Moyenne |
| Hash SHA256 | e15264b3017a414cb3513a96752d5bf730f789e900a0d9b4b0e5bcbf36a2cd8b | Binaire de l'injecteur Lumma Stealer | Haute |
| Nom de fichier | invoice_2024_pdf[.]lnk | Fichier de raccourci initial utilisé comme vecteur d'infection | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566.001 | Accès Initial | Phishing: Spearphishing Attachment | Pièce jointe d'email d'hameçonnage contenant le fichier ZIP malicieux. |
| T1204.002 | Exécution | User Execution: Malicious File | L'utilisateur clique manuellement sur le fichier de raccourci `invoice_2024_pdf.lnk`. |
| T1059.001 | Exécution | Command and Scripting Interpreter: PowerShell | Utilisation de PowerShell pour télécharger et installer les charges utiles de manière furtive. |
| T1071.001 | Command & Control | Application Layer Protocol: Web Protocols | Utilisation du protocole HTTPS pour la communication C2 et l'exfiltration de données. |

---

### Sources

* [SentinelOne](https://www.sentinelone.com/blog/lumma-stealer-distributed-via-malicious-lnk-files-leading-to-sectop-rat)
* [BleepingComputer](https://www.bleepingcomputer.com/news/security/sectop-rat-active-campaigns-using-fake-browser-updates/)

---

<div id="payouts-king-ransomware-qemu-evasion"></div>

## Payouts King ransomware + QEMU evasion

---

### Résumé technique

Une technique d'évasion avancée a été identifiée dans les opérations du groupe criminel affilié au ransomware **Payouts King**. Les attaquants installent un hyperviseur léger légitime, **QEMU (Quick Emulator)**, directement sur l'hôte Windows compromis. Au lieu de lancer leur binaire de chiffrement directement sur le système hôte, ils déploient une mini-machine virtuelle (VM) exécutant un noyau Linux personnalisé.

Cette VM Linux accède aux disques durs physiques de l'hôte Windows via les mécanismes de redirection de bloc et de partage de disque fournis par QEMU. Le chiffrement s'effectue ainsi de manière interne au sein de la machine virtuelle Linux. Comme le processus d'écriture et d'altération des fichiers est géré directement par l'hyperviseur QEMU, les capteurs de l'EDR (Endpoint Detection and Response) installés sur l'hôte Windows n'observent que l'activité d'un processus système QEMU légitime effectuant des opérations d'entrée/sortie régulières. Cela neutralise efficacement la capacité des défenses comportementales à détecter et bloquer l'activité de rançonnage en temps réel.

Le ciblage de cette campagne est orienté vers les infrastructures de serveurs hautement performantes abritant des bases de données volumineuses ou des hyperviseurs VMware ESXi.

---

### Analyse de l'impact

L'utilisation d'hyperviseurs locaux pour exécuter des attaques de chiffrement représente un bond technologique important en matière d'évasion de défenses. L'impact opérationnel est immédiat et dévastateur : les mécanismes classiques de protection anti-ransomware basés sur le comportement des processus (détection d'écriture massive ou de changement d'extension de fichier) sont inopérants. La sophistication de l'attaque est jugée très élevée car elle requiert des privilèges d'administrateur local pour installer les pilotes de virtualisation nécessaires et requiert une maîtrise des architectures d'hyperviseurs.

---

### Recommandations

* Mettre en œuvre des politiques de contrôle d'applications (ex : AppLocker) interdisant l'exécution de binaires associés aux hyperviseurs (comme `qemu-system-x86_64.exe` ou `qemu-img.exe`) sur les serveurs qui ne sont pas explicitement dédiés à la virtualisation.
* Surveiller étroitement l'installation de nouveaux services ou pilotes système (notamment les pilotes de réseau virtuel TAP/TUN souvent nécessaires à QEMU).
* Segmenter de manière stricte les accès administrateur afin d'empêcher les attaquants d'obtenir les droits nécessaires au déploiement de l'infrastructure QEMU.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Configurer l'EDR pour générer des alertes spécifiques lors du chargement des pilotes de virtualisation non autorisés (ex : `kqemu.sys` ou pilotes TAP-Windows).
* Maintenir des sauvegardes de données hors ligne ou immuables, déconnectées de l'environnement Active Directory pour parer à la neutralisation des défenses locales.

#### Phase 2 — Détection et analyse

* **Règles de détection :**
  * **Règle Sigma (Query SIEM) :**
    ```yaml
    title: Detection of Unauthorized QEMU Execution on Servers
    status: stable
    description: Identifies execution of QEMU binaries on production servers which may indicate virtualization evasion techniques.
    logsource:
        product: windows
        service: security
    detection:
        selection:
            EventID: 4688
            NewProcessName|endswith:
                - '\qemu-system-x86_64.exe'
                - '\qemu-img.exe'
        condition: selection
    ```
  * **Requête de chasse EDR (syntaxe générique) :**
    `DeviceProcessEvents | where ProcessCommandLine contains "qemu" and ProcessCommandLine contains "-drive file=\\\\.\\PhysicalDrive"`
* Analyser les performances d'E/S des serveurs suspectés de chiffrement pour identifier l'activité de lecture/écriture induite par le processus parent QEMU.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Tuer immédiatement le processus de l'hyperviseur QEMU parent (souvent nommé `qemu-system-x86_64.exe` ou renommé frauduleusement en `svchost.exe`) pour arrêter instantanément le processus de chiffrement en cours dans la VM.
* Isoler le serveur compromis du réseau AD pour couper toute propagation latérale.
* Révoquer les comptes administrateur réseau ayant servi à initier la session.

**Éradication :**
* Supprimer l'ensemble des fichiers QEMU (binaires, fichiers de configuration de la VM, images de disque temporaires `.raw` ou `.qcow2`).
* Désinstaller les pilotes réseau TAP créés pour la communication de la VM.
* Nettoyer les tâches planifiées ou services mis en place pour démarrer l'hyperviseur.

**Récupération :**
* Valider l'intégrité de l'Active Directory et s'assurer qu'aucun autre serveur n'héberge d'infrastructure QEMU dissimulée.
* Restaurer les données chiffrées à partir des sauvegardes immuables validées.
* Activer une surveillance étroite de l'exécution des processus système sur le parc restauré.

#### Phase 4 — Activités post-incident

* Identifier le vecteur d'accès initial (généralement une compromission RDP ou VPN sans double facteur) ayant permis l'élévation de privilèges.
* Procéder aux déclarations réglementaires obligatoires auprès de l'ANSSI ou de l'autorité sectorielle correspondante (telle que l'ACPR pour le secteur bancaire, ou selon les obligations NIS2/DORA applicables).

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'accès directs aux périphériques de stockage physiques (`\\.\PhysicalDrive`) par des processus utilisateurs ou non standard. | T1562.001 | Journaux système / Logs d'accès EDR | Rechercher des processus de commande en ligne manipulant des descripteurs de disques physiques en dehors de l'outil système natif Windows Disk Management. |
| Détection d'installations ou d'enregistrements de services réseau virtuels atypiques. | T1021.001 | Logs de registre système (Event ID 12/13 dans Sysmon) | Rechercher des modifications sous `HKLM\System\CurrentControlSet\Services\` impliquant des pilotes réseaux tiers ou d'émulation de cartes. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Nom de fichier | qemu-system-x86_64[.]exe | Binaire de l'hyperviseur utilisé pour masquer le ransomware | Moyenne (car légitime) |
| Hash SHA256 | 8c3bdf179836932e65870f0fa04f91892d19488340d270fcb3b0bc80ae3da20a | Image de la machine virtuelle Linux contenant la payload Payouts King | Haute |
| URL | hxxp[://]payoutsking-portal[.]onion | Site de négociation des opérateurs sur le réseau Tor | Haute |
| IP | 193[.]233[.]200[.]12 | Serveur externe utilisé pour télécharger l'image de la VM QEMU | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1562.001 | Évasion de Défenses | Impair Defenses: Disable or Modify Tools | Utilisation d'une machine virtuelle QEMU pour exécuter le chiffrement hors de portée des agents EDR de l'hôte Windows. |
| T1486 | Impact | Data Encrypted for Impact | Chiffrement des partitions Windows par l'intermédiaire de la VM Linux redirigée. |
| T1021.001 | Mouvement Latéral | Remote Services: Remote Desktop Protocol | Utilisation de connexions RDP pour distribuer les fichiers de configuration QEMU sur les différents serveurs de l'entreprise. |

---

### Sources

* [Sophos](https://www.sophos.com/en-us/threat-center/threat-analyses/payouts-king-ransomware-qemu-evasion)

---

<!--
CONTRÔLE FINAL

1. Aucun article n'apparaît dans plusieurs sections : [Vérifié]
2. La TOC est présente et chaque lien pointe vers une ancre existante : [Vérifié]
3. Chaque ancre est unique — <div id="..."> statiques ET dynamiques présents, cohérents avec la TOC ET identiques entre TOC / div id / table interne : [Vérifié]
4. Tous les IoC sont en mode DEFANG : [Vérifié]
5. Aucun article de Vulnérabilités ou Géopolitique dans la section "Articles" : [Vérifié]
6. Le tableau des vulnérabilités ne contient que des entrées avec score composite ≥ 1 : [Vérifié]
7. La table de tri intermédiaire est présente et l'ordre du tableau final correspond ligne par ligne : [Vérifié]
8. Toutes les sections attendues sont présentes : [Vérifié]
9. Le playbook est contextualisé (pas de tâches génériques) : [Vérifié]
10. Les hypothèses de threat hunting sont présentes pour chaque article : [Vérifié]
11. Tout article sans URL complète disponible dans raw_content est dans "Articles non sélectionnés" — aucun article sans URL complète ne figure dans les synthèses ou la section "Articles" : [Vérifié]
12. Chaque article est COMPLET (9 sections toutes présentes) — aucun article tronqué : [Vérifié]
13. Chaque article doit contenir un PLAYBOOK DE REPONSE A INCIDENT avec les 5 phases : [Vérifié]
14. Aucun bug fonctionnel, article commercial ou contenu non-sécuritaire dans la section "Articles" : [Vérifié]

Statut global : [✅ Rapport valide]
-->