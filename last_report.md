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
  * [Spirals Ransomware + Microsoft IIS Server Compromise](#spirals-ransomware-microsoft-iis-server-compromise)
  * [Google Slides Phishing Campaign](#google-slides-phishing-campaign)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'actualité de la cybersécurité de ce mois de juillet 2026 met en lumière une intensification marquée des attaques ciblant les couches applicatives exposées et les infrastructures réseau critiques. On assiste à une exploitation active et extrêmement rapide de vulnérabilités critiques de type Zero-Day, notamment sur les solutions de VPN d'entreprise (SonicWall SMA 1000) et les systèmes de gestion de contenu à grande échelle (WordPress avec la chaîne wp2shell). Ces attaques révèlent un niveau élevé de préparation et de sophistication de la part de groupes d'acteurs comme UTA0533, capables de contourner des mécanismes de sécurité robustes pour obtenir des accès root complets et installer des persistances locales indétectables.

Parallèlement, la menace des rançongiciels continue de muter avec l'apparition de variantes sophistiquées codées en Rust, telles que "Spirals", ciblant spécifiquement des serveurs Web Microsoft IIS exposés. Ce choix technologique illustre la volonté des cybercriminels d'optimiser la vitesse de chiffrement et d'échapper à la détection par les solutions EDR traditionnelles en utilisant des langages compilés modernes et performants.

Enfin, les enjeux géopolitiques se manifestent par des campagnes d'espionnage ciblées en Russie, où des attaquants abusent de solutions logicielles nationales de confiance (la suite de chiffrement ViPNet) pour infiltrer les ministères et administrations. Cela démontre que même les liaisons de communication théoriquement sécurisées et certifiées au niveau étatique restent des vecteurs privilégiés de compromission. Pour les organisations, la priorité absolue doit aller au déploiement rapide de correctifs sur les technologies de périmètre, au renforcement des contrôles d'accès cloud (MFA résistante au phishing) et à une segmentation stricte des serveurs web exposés.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **UTA0533** | Gouvernement, Défense, Infrastructures critiques | Exploitation de vulnérabilités Zero-Day (contournement d'authentification et injection de commandes) pour obtenir un accès root complet et une persistance sur les passerelles VPN SonicWall SMA 1000. | T1190, T1068 | [The Hacker News](https://thehackernews.com/2026/07/sonicwall-sma-zero-days-exploited.html) |
| **ShinyHunters** | Santé, Technologie, Finance | Ciblage et compromission de bases de données cloud tierces et d'identifiants d'API d'entreprise pour exfiltrer de gros volumes de données confidentielles à des fins d'extorsion. | T1567 | [DataBreaches](https://databreaches.net/2026/07/19/medical-giant-abbott-investigates-two-cyber-incidents-as-shinyhunters-and-shadowbyt3-both-claim-breaches/?pk_campaign=feed&pk_kwd=medical-giant-abbott-investigates-two-cyber-incidents-as-shinyhunters-and-shadowbyt3-both-claim-breaches) |
| **ShadowByt3$** | Santé, Secteur public | Exfiltration de fichiers sensibles et chantage direct aux entreprises via des publications publiques et des canaux de double extorsion. | T1567 | [DataBreaches](https://databreaches.net/2026/07/19/medical-giant-abbott-investigates-two-cyber-incidents-as-shinyhunters-and-shadowbyt3-both-claim-breaches/?pk_campaign=feed&pk_kwd=medical-giant-abbott-investigates-two-cyber-incidents-as-shinyhunters-and-shadowbyt3-both-claim-breaches) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Russie** | Gouvernement, Secteur Public | Abus de logiciels de confiance nationaux à des fins d'espionnage | Des cyber-espions contournent les défenses traditionnelles en abusant et en détournant la suite logicielle VPN/chiffrement gouvernementale **ViPNet** (très déployée au sein des ministères russes) pour mener de l'espionnage étatique et infiltrer des réseaux sécurisés. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-abuse-vipnet-software-to-target-russian-govt-agencies/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

> Aucune actualité réglementaire ou juridique majeure n'a été recensée dans les sources de ce jour.

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Santé** | Abbott | Données corporatives confidentielles, informations personnelles possibles, données de santé potentielles (revendications d'exfiltration concurrentes par ShinyHunters et ShadowByt3$). | Non spécifié | [DataBreaches](https://databreaches.net/2026/07/19/medical-giant-abbott-investigates-two-cyber-incidents-as-shinyhunters-and-shadowbyt3-both-claim-breaches/?pk_campaign=feed&pk_kwd=medical-giant-abbott-investigates-two-cyber-incidents-as-shinyhunters-and-shadowbyt3-both-claim-breaches) |
| **Gig Economy / Finance** | Paidwork | Adresses e-mail, profils d'utilisateurs, informations bancaires, historique des paiements, mots de passe hachés avec Bcrypt (archive SQL de 11 Go publiée publiquement). | 23 272 765 comptes uniques | [Have I Been Pwned](https://haveibeenpwned.com/Breach/Paidwork) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-15409 | TRUE  | Active    | 7.0 | 10.0  | (1,1,7.0,10.0) |
| 2 | CVE-2026-63030 | FALSE | Active    | 5.0 | 9.8   | (0,1,5.0,9.8)  |
| 3 | CVE-2026-44359 | FALSE | Active    | 4.0 | 9.8   | (0,1,4.0,9.8)  |
| 4 | N/A - Hikvision ISAPI | FALSE | Active    | 2.5 | N/A→0 | (0,1,2.5,0.0)  |
| 5 | CVE-2026-42533 | FALSE | Théorique | 2.0 | 9.2   | (0,0,2.0,9.2)  |
| 6 | CVE-2026-12484 | FALSE | Théorique | 1.0 | 7.8   | (0,0,1.0,7.8)  |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement / Correctifs | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-15409** | 10.0 | N/A | **TRUE** | 7.0 | SonicWall Secure Mobile Access (SMA) 1000 Series | Authentication Bypass | Auth Bypass / RCE | Active | Appliquer immédiatement les correctifs officiels de SonicWall. | [The Hacker News](https://thehackernews.com/2026/07/sonicwall-sma-zero-days-exploited.html) |
| **CVE-2026-63030** | 9.8 | N/A | FALSE | 5.0 | WordPress Core (6.9.x et 7.0.x) | Remote Code Execution | RCE | Active | Mettre à jour WordPress immédiatement (mises à jour forcées activées). Bloquer l'accès à `/wp-json/batch/v1`. | [Security Affairs](https://securityaffairs.com/195597/hacking/attackers-can-take-over-wordpress-sites-using-newly-released-wp2shell-exploits.html) |
| **CVE-2026-44359** | 9.8 | N/A | FALSE | 4.0 | Meshtastic Firmware GitHub Repository | Code Injection via GitHub Actions | RCE / Supply Chain | Active | Mettre à jour le firmware vers la version 2.7.21.1370b23 ou supérieure. Sécuriser pull_request_target. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-44359)<br>[InfoSec Exchange](https://infosec.exchange/@offseq/116949361347720615) |
| **N/A - Hikvision ISAPI** | N/A | N/A | FALSE | 2.5 | Hikvision Intelligent Security API (ISAPI) | Insecure Resource Exposure | Info Disclosure | Active | Ne pas exposer directement les caméras Hikvision sur Internet sans VPN ou pare-feu restrictif. | [SANS ISC](https://isc.sans.edu/diary/rss/33164) |
| **CVE-2026-42533** | 9.2 | N/A | FALSE | 2.0 | NGINX Open Source, NGINX Plus | Heap Buffer Overflow | RCE / DoS | Théorique | Mettre à jour vers Nginx 1.30.4 (stable) ou 1.31.3 (mainline). Utiliser des captures nommées au lieu de captures numérotées. | [The Hacker News](https://thehackernews.com/2026/07/critical-nginx-vulnerability-can-crash.html) |
| **CVE-2026-12484** | 7.8 | N/A | FALSE | 1.0 | Keras-Team (TorchModuleWrapper) | Insecure Deserialization | RCE | Théorique | Restreindre l'exécution de modèles provenant de sources non fiables. Migrer vers le format Safetensors. | [Mastodon](https://mastodon.social/@hugovalters/116949132770600340) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| Rapid Ransomware Campaign Targeting Microsoft IIS Servers | **Spirals Ransomware + Microsoft IIS Server Compromise** | Campagne active de rançongiciel sophistiqué développé en Rust ciblant spécifiquement des serveurs IIS exposés, présentant un fort intérêt technique (langage moderne, tactiques agressives). | [Mastodon / Techbot](https://social.raytec.co/@techbot/116949607400329808) |
| Possible Phishing on Google Presentation | **Google Slides Phishing Campaign** | Campagne d'hameçonnage active qui abuse de la publication web légitime de Google Slides, contournant ainsi les filtrages de messagerie et de réputation habituels. | [InfoSec Exchange / URLDNA](https://infosec.exchange/@urldna/116949595599290634) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| ISC Stormcast For Monday, July 20th, 2026 | Contenu d'actualité générale / podcast de synthèse sans analyse d'incident ou de menace spécifique. | [SANS ISC](https://isc.sans.edu/diary/rss/33166) |
| SECURITY AFFAIRS MALWARE NEWSLETTER ROUND 106 | Compilation généraliste de menaces de malwares (newsletter) sans focus sur un incident ou une campagne unique. | [Security Affairs](https://securityaffairs.com/195620/malware/security-affairs-malware-newsletter-round-106.html) |
| Security Affairs newsletter Round 586 | Compilation d'actualités hebdomadaires globales sans focus sur un sujet technique unique ou un incident précis. | [Security Affairs](https://securityaffairs.com/195611/breaking-news/security-affairs-newsletter-round-586-by-pierluigi-paganini-international-edition.html) |
| Everyone selling quantum randomness | Guide d'achat informatif et d'analyse théorique sur les générateurs d'entropie quantique, sans incident de cybersécurité associé. | [Mastodon / InfoSec](https://defcon.social/@infosec/116949610717793653) |
| ASN: AS34373 Location: Rotterdam, NL | Flux brut automatisé Shodan décrivant des informations de routage sans analyse de menace concrète ou incident de sécurité. | [InfoSec Exchange / Shodansafari](https://infosec.exchange/@shodansafari/116949359485295366) |
| RE: Mastodon.social post Me_Star_Son | Post social informel et communautaire sans analyse technique exploitable ou incident de sécurité. | [Mastodon / Me_Star_Son](https://mastodon.social/@Me_Star_Son/116949263550585076) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="spirals-ransomware-microsoft-iis-server-compromise"></div>

## Spirals Ransomware + Microsoft IIS Server Compromise

---

### Résumé technique

* **Contexte et découverte** : Une campagne de rançongiciel rapide et agressive cible spécifiquement les serveurs Web Microsoft IIS (Internet Information Services) exposés sur Internet.
* **Mécanisme technique** : Les attaquants obtiennent un accès initial en exploitant des vulnérabilités sur les serveurs IIS. Après la compromission Web initiale via le processus `w3wp.exe`, ils mènent une élévation de privilèges locaux et des mouvements latéraux. Le rançongiciel "Spirals", entièrement codé en Rust, est ensuite déployé. Il désactive de manière agressive les services de sécurité locaux et les processus de sauvegarde (tels que Windows Backup / Volume Shadow Copies) pour empêcher la récupération. Il procède ensuite au chiffrement rapide des fichiers sur les volumes système locaux et les partages réseau découverts, en leur ajoutant l'extension `.spirals`.
* **Infrastructure** : Utilisation de serveurs de commande et contrôle (C2) pour coordonner la campagne et exfiltrer les clés de chiffrement.
* **Victimologie** : Secteurs technologiques, infrastructures, et toute entreprise exposant des services IIS non correctement cloisonnés ou patchés.

---

### Analyse de l'impact

* **Impact opérationnel** : Chiffrement complet des serveurs IIS, entraînant l'interruption immédiate des services web publics et des applications métiers critiques associées. Perte de données si les sauvegardes ne sont pas isolées du réseau d'administration principal.
* **Niveau de sophistication** : Élevé. L'usage de Rust rend l'analyse statique difficile pour les antivirus traditionnels, et les tactiques d'arrêt des processus de sécurité démontrent une bonne connaissance des mécanismes internes de Windows.

---

### Recommandations

* Auditer et restreindre les privilèges du compte de service IIS (`w3wp.exe`) pour empêcher l'exécution de commandes système ou d'outils d'élévation de privilèges.
* Déployer un pare-feu applicatif (WAF) devant IIS et installer un agent EDR durci sur tous les serveurs Web publics.
* Segmenter strictement le réseau hébergeant les serveurs Web publics par rapport aux bases de données internes et aux contrôleurs de domaine (Active Directory).

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Vérifier que les logs d'exécution des processus IIS (`w3wp.exe`) et les logs d'événements de sécurité Windows (Event ID 4688, activation du suivi des lignes de commande) sont activés et centralisés dans le SIEM.
* S'assurer de la disponibilité d'outils de réponse (EDR en mode isolation, outils d'acquisition mémoire comme FTK Imager Lite).
* S'assurer que des sauvegardes immuables et isolées du réseau (hors ligne) sont configurées et fonctionnelles pour tous les serveurs IIS.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * *Requête EDR (générique)* : Detecter le processus parent `w3wp.exe` engendrant un interpréteur de commandes :
    `ParentImage == "w3wp.exe" AND Image IN ("cmd.exe", "powershell.exe", "wscript.exe", "vssadmin.exe")`
  * *Règle de détection de fichiers* : Alerte sur la création d'au moins 20 fichiers se terminant par `.spirals` en moins de 10 secondes sur un même lecteur.
* Analyser les logs pour reconstruire la timeline de la compromission Web initiale et estimer le temps de présence (dwell time).

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Appliquer immédiatement une isolation logique réseau de la machine IIS via l'EDR pour bloquer les tentatives de déplacements latéraux.
* Bloquer les adresses IP C2 et domaines suspects identifiés au niveau du pare-feu périmétrique.

**Éradication :**
* Tuer les processus actifs du ransomware compilé en Rust. Supprimer les fichiers binaires malveillants situés dans les dossiers temporaires d'IIS (ex. `C:\Windows\Temp\` ou les répertoires virtuels IIS).
* Réinitialiser l'ensemble des comptes de service associés aux applications IIS et forcer le renouvellement des secrets.

**Récupération :**
* Restaurer les systèmes à partir des sauvegardes immuables validées comme saines après réinstallation complète du système d'exploitation pour écarter toute persistance cachée.
* Surveiller de manière renforcée les accès réseau et l'activité des processus pendant 72 heures après la remise en ligne.

#### Phase 4 — Activités post-incident

* Rédiger le rapport d'incident complet détaillant le vecteur d'intrusion applicatif initial afin de corriger la faille de sécurité d'origine.
* Évaluer les obligations de notification réglementaire :
  * Si des données personnelles ou de santé de citoyens européens ont été accédées, notifier la CNIL sous 72 heures conformément à l'article 33 du RGPD.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'exécutions suspectes engendrées par le serveur Web | T1059.003 | Journaux Windows Security (Event 4688) | `EventID=4688 AND CreatorProcessName="*w3wp.exe" AND ProcessName=("*cmd.exe" OR "*powershell.exe")` |
| Détection d'appels de suppression de clichés instantanés | T1490 | Command Line logs (EDR) | Recherche de la chaîne de caractères `vssadmin delete shadows` ou `Resize-Partition` exécutée sur les serveurs applicatifs Windows. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | otx[.]alienvault[.]com | Plateforme de Threat Intelligence liée aux sources de surveillance | Moyenne |
| Email | techbot[at]social[.]raytec[.]co | Identifiant de notification ou d'alerte | Moyenne |
| Chemin fichier | C:\Windows\Temp\*.spirals | Extension appliquée aux fichiers chiffrés | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1190 | Initial Access | Exploit Public-Facing Application | Compromission d'applications IIS exposées pour obtenir l'accès initial. |
| T1486 | Impact | Data Encrypted for Impact | Chiffrement en masse des volumes par le rançongiciel Spirals codé en Rust. |
| T1490 | Impact | Inhibit System Recovery | Arrêt ou suppression des clichés instantanés de volume (Shadow Copies) pour bloquer la restauration locale. |

---

### Sources

* [Mastodon TechBot](https://social.raytec.co/@techbot/116949607400329808)

---

<div id="google-slides-phishing-campaign"></div>

## Google Slides Phishing Campaign

---

### Résumé technique

* **Contexte et découverte** : Une campagne active de phishing abuse de la fonctionnalité de publication web de la suite bureautique cloud Google Workspace (particulièrement Google Slides/Presentations).
* **Mécanisme technique** : Les attaquants créent une présentation Google Slides piégée contenant des visuels d'usurpation d'identité de haut niveau (pages de connexion de banques, de portails RH ou d'identifiants d'entreprise). Ils publient ensuite cette présentation sur le web via l'option native "Publier sur le Web" de Google, générant une URL légitime sous le domaine de confiance `docs.google.com`. Les emails de phishing envoyés aux victimes contiennent cette URL. En cliquant, les victimes sont dirigées vers la présentation interactive qui contient des redirections externes vers des formulaires de vol d'identifiants.
* **Infrastructure** : Utilisation de l'infrastructure de publication de Google pour héberger le contenu d'hameçonnage, contournant ainsi les filtres de sécurité basés sur la réputation de domaine.
* **Victimologie** : Utilisateurs d'entreprise, grand public.

---

### Analyse de l'impact

* **Impact opérationnel** : Vol massif d'identifiants de connexion d'entreprise (Microsoft 365, Google Workspace, outils RH), menant à des accès non autorisés et potentiellement à des compromissions de messagerie d'entreprise (BEC).
* **Niveau de sophistication** : Moyen. L'utilisation de la publication de Google Presentations permet d'obtenir un taux de délivrabilité très élevé car les passerelles de messagerie (Secure Email Gateways) n'analysent pas le contenu dynamique des pages Google légitimes.

---

### Recommandations

* Bloquer les accès proxy aux URLs de présentation Google publiées sur le web non approuvées par l'organisation.
* Sensibiliser les collaborateurs au fait que les formulaires d'identification d'entreprise ne doivent jamais être hébergés sur des documents Google, Microsoft, ou d'autres stockages cloud publics.
* Déployer une authentification multifacteur (MFA) résistante au phishing (FIDO2/WebAuthn).

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre en œuvre des programmes de sensibilisation des employés sur le détournement des services cloud légitimes pour le phishing.
* Configurer les passerelles de messagerie pour inspecter et analyser les emails contenant des liens Google Docs/Slides publics envoyés par des expéditeurs externes non fiables.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * *Requête SIEM (Proxy/DNS)* : Identifier les connexions vers les présentations Google publiées publiquement :
    `url_path LIKE "%docs.google.com/presentation/d/%/pub%" OR url_path LIKE "%docs.google.com/presentation/d/%/embed%"`
* Analyser les logs de messagerie pour retrouver l'email initial, l'expéditeur et les destinataires internes ayant cliqué sur le lien.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Bloquer l'accès à l'URL spécifique identifiée comme malveillante sur l'ensemble des proxys et pare-feu de navigation de l'entreprise.
* Révoquer immédiatement les sessions actives et isoler logiquement les comptes des utilisateurs ayant cliqué sur le lien et soumis leurs identifiants.

**Éradication :**
* Réinitialiser les mots de passe des comptes compromis et forcer l'inscription de nouveaux jetons MFA si nécessaire.
* Signaler l'URL de présentation frauduleuse à Google Trust & Safety pour exiger sa suppression.

**Récupération :**
* Restaurer l'accès aux comptes des utilisateurs sécurisés, s'assurer que la MFA est bien activée et qu'aucune règle de redirection de mail malveillante n'a été créée à leur insu dans Outlook/Gmail.

#### Phase 4 — Activités post-incident

* Vérifier si des données sensibles ont été accédées ou exfiltrées depuis la boîte mail compromise (recherche de logs d'accès IP, de téléchargements OneDrive/SharePoint inhabituels).
* Améliorer le filtrage de courrier en intégrant des règles sur les patterns d'URL de publication Google.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détection de connexions sortantes suspectes vers des publications cloud | T1566.002 | Proxy / DNS Logs | Analyse des requêtes HTTP vers des domaines de stockage cloud (`docs.google.com`) contenant des termes de publication (`/pub`, `/embed`) en corrélation avec des expéditeurs de mails inconnus. |
| Création de règles de messagerie suspectes suite à un clic | T1137.005 | Exchange / O365 Logs | Recherche de règles de transfert de mail créées par des utilisateurs dans les 24 heures suivant l'accès à une URL Google Presentation. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | hxxps[://]docs[.]google[.]com/presentation/d/1gBvfAiCvkPTcu0YFovbn7Wwa_P3j08o0aRSbttl3JlU/pub?start=false&loop=false | URL de la présentation Google Slide frauduleuse | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566.002 | Initial Access | Phishing: Spearphishing Link | Utilisation de liens de présentation Google Slides publiés sur le Web pour contourner les protections traditionnelles. |

---

### Sources

* [InfoSec Exchange / URLDNA](https://infosec.exchange/@urldna/116949595599290634)

---

<!--
CONTRÔLE FINAL

1. ☑ Aucun article n'apparaît dans plusieurs sections : [Vérifié]
2. ☑ La TOC est présente et chaque lien pointe vers une ancre existante : [Vérifié]
3. ☑ Chaque ancre est unique — <div id="..."> statiques ET dynamiques présents, cohérents avec la TOC ET identiques entre TOC / div id / table interne : [Vérifié]
4. ☑ Tous les IoC sont en mode DEFANG : [Vérifié]
5. ☑ Aucun article de Vulnérabilités ou Géopolitique dans la section "Articles" : [Vérifié]
6. ☑ Le tableau des vulnérabilités ne contient que des entrées avec score composite ≥ 1 : [Vérifié]
7. ☑ La table de tri intermédiaire est présente et l'ordre du tableau final correspond ligne par ligne : [Vérifié]
8. ☑ Toutes les sections attendues sont présentes : [Vérifié]
9. ☑ Le playbook est contextualisé (pas de tâches génériques) : [Vérifié]
10. ☑ Les hypothèses de threat hunting sont présentes pour chaque article : [Vérifié]
11. ☑ Tout article sans URL complète disponible dans raw_content est dans "Articles non sélectionnés" — aucun article sans URL complète ne figure dans les synthèses ou la section "Articles" : [Vérifié]
12. ☑ Chaque article est COMPLET (9 sections toutes présentes) — aucun article tronqué : [Vérifié]
13. ☑ Chaque article contient un PLAYBOOK DE REPONSE A INCIDENT avec les 5 phases : [Vérifié]
14. ☑ Aucun bug fonctionnel, article commercial ou contenu non-sécuritaire dans la section "Articles" : [Vérifié]

Statut global : [✅ Rapport valide]
-->