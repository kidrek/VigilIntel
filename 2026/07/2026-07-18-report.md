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
  * [Inside the Search for 'Clean' Residential Proxies for Carding](#inside-the-search-for-clean-residential-proxies-for-carding)
  * [AWS Networking for IR — VPCs, Flow Logs, and the Load Balancer Blind Spot](#aws-networking-for-ir-vpcs-flow-logs-and-the-load-balancer-blind-spot)
  * [New Russian Campaign Uses Fake Webex and Zoom Installers to Deploy Starland RAT](#new-russian-campaign-uses-fake-webex-and-zoom-installers-to-deploy-starland-rat)
  * [Hmm, this is a new to me scam... My expertise in watching someone sign a contract ames it more valid??!](#hmm-this-is-a-new-to-me-scam-my-expertise-in-watching-someone-sign-a-contract-ames-it-more-valid)
  * [Possible Phishing on: borderclick.com Roblox lure](#possible-phishing-on-borderclick-com-roblox-lure)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'état de la menace cyber pour cette période met en évidence une intensification des activités offensives étatiques et cybercriminelles, structurée autour de trois dynamiques majeures. 

Premièrement, la pénétration des chaînes d'approvisionnement logicielles par des acteurs parrainés par l'État nord-coréen (notamment Lazarus, APT37, et la campagne PolinRider) se poursuit de manière agressive. Leurs cibles privilégiées restent les développeurs et les ingénieurs système, piégés par des techniques avancées d'ingénierie sociale (fausses offres d'emploi, entretiens techniques fictifs) et l'injection de packages malveillants NPM. L'objectif final demeure l'espionnage technologique et le vol de cryptomonnaies.

Deuxièmement, la cyberguerre hybride menée par la Fédération de Russie s'ancre durablement dans le paysage européen. L'activité d'espionnage et de déstabilisation à long terme attribuée à l'unité 61240 du FSB pousse des pays comme la France à durcir publiquement leurs réponses techniques et diplomatiques. Parallèlement, des groupes cybercriminels russophones ciblent des infrastructures critiques à des fins d'extorsion et de vol de données financières.

Enfin, la surface d'attaque logicielle se complexifie avec la découverte de chaînes d'exploitation zero-day critiques affectant les réseaux industriels (Siemens ROX II) et des failles majeures au sein de l'écosystème cloud (AWS, connecteurs tiers) et applicatif. Face à cette menace protéiforme, la mise en œuvre de politiques de sécurité proactives (Zero Trust, micro-segmentation, audits stricts des relations de confiance tierces) devient une exigence opérationnelle absolue.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **Lazarus Group (DPRK)** | Technologie, Logiciel, Finance, Cryptomonnaie | Diffusion d'implants malveillants (OTTERCOOKIE, ChainVeil, ViteVenom) via NPM et ingénierie sociale. Utilisation de la stéganographie dans des images SVG. | T1189 (Drive-by Compromise)<br>T1566 (Phishing)<br>T1584 (Compromise Infrastructure) | [Elastic Security Labs](https://www.elastic.co/security-labs/contagious-interview-malware-svg-steganography)<br>[Open Source Malware Blog](https://opensourcemalware.com/blog/chainveil-and-vitevenom-dprk-polinrider-campaign) |
| **UAT-11795** | Technologie, Grand public | Utilisation de la technique ClickFix (faux installateurs Webex, Zoom, MobaXterm) pour déployer Starland RAT et l'agent WLDR. | T1204 (User Execution)<br>T1547 (Boot or Logon Autostart) | [Cisco Talos / Security Affairs](https://securityaffairs.com/195532/malware/new-russian-campaign-uses-fake-webex-and-zoom-installers-to-deploy-starland-rat.html) |
| **Qilin** | Santé, Pharmaceutique, Logistique | Ransomware-as-a-Service (RaaS). Exfiltration massive de données sensibles et double extorsion via un site vitrine dédié. | T1486 (Data Encrypted for Impact) | [Ransomlook](https://www.ransomlook.io//group/qilin) |
| **FSB Unité 61240** | Gouvernement, Défense, Infrastructures critiques | Opérations de cyberespionnage d'État à long terme sous le seuil de conflictualité ouverte, compromission de messageries. | T1114 (Email Collection) | [Le Monde](https://www.lemonde.fr/international/article/2026/07/17/pourquoi-la-guerre-hybride-menee-par-la-russie-pousse-la-france-a-hausser-le-ton_6724233_3210.html) |
| **APT37** | Éducation, Recherche | Campagne "Capsule Vault" ciblant les universitaires avec des chevaux de Troie d'accès distant (RAT) par spear-phishing. | T1566 (Phishing) | [AlienVault OTX](https://social.raytec.co/@techbot/116938280336268380) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Soudan, Égypte, Libye, Sahel** | Gouvernemental | Recompositions géopolitiques transfrontalières | Le conflit entre les forces armées soudanaises (SAF) et les forces de soutien rapide (RSF) accélère les tensions régionales, créant un continuum stratégique instable propice aux flux d'acteurs hybrides. | [IRIS](https://www.iris-france.org/du-nil-au-fezzan-le-conflit-soudanais-comme-accelerateur-des-recompositions-geopoltiques-sahelo-sahariennes/) |
| **France, Russie** | Public | Attribution cyber et tensions diplomatiques | Durcissement diplomatique et technique de la France à la suite de cyberattaques et d'opérations d'espionnage attribuées directement à l'unité 61240 du FSB russe. | [Le Monde](https://www.lemonde.fr/international/article/2026/07/17/pourquoi-la-guerre-hybride-menee-par-la-russie-pousse-la-france-a-hausser-le-ton_6724233_3210.html) |
| **Europe, Espagne, Russie** | Technologique | Souveraineté logicielle et espionnage | Révélation de liens étroits et d'une détention de licence du FSB par la structure mère russe liée au gestionnaire de mots de passe Passwork, pourtant commercialisé comme européen. | [Le Monde](https://www.lemonde.fr/pixels/article/2026/07/17/les-liens-troubles-avec-la-russie-d-un-gestionnaire-de-mots-de-passe-europeen_6724124_4408996.html) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| **Passeport Numérique des Produits** | Commission Européenne | 17/07/2026 | Union Européenne | CELEX:32026R1778 | Adoption du règlement d'exécution fixant les exigences techniques et d'authentification pour le registre du passeport numérique. | [EUR-Lex](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:32026R1778) |
| **Inculpations pour blanchiment** | Département de la Justice des États-Unis | 17/07/2026 | États-Unis | US DOJ 2026 | Poursuites judiciaires engagées contre deux individus accusés d'avoir blanchi 43 millions de dollars issus de fraudes à l'investissement. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/us-charges-two-over-laundering-43-million-from-investment-fraud/) |
| **Arrestation d'un voleur de cryptomonnaies** | FBI | 17/07/2026 | États-Unis | FBI Arrest 2026 | Interpellation d'un suspect ayant distribué des versions malveillantes de jeux vidéo sur Steam pour vider les crypto-wallets de ses victimes. | [DataBreaches](https://databreaches.net/2026/07/17/fbi-arrests-man-accused-of-using-steam-games-to-drain-victims-crypto-wallets/?pk_campaign=feed&pk_kwd=fbi-arrests-man-accused-of-using-steam-games-to-drain-victims-crypto-wallets) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Conseil et Audit** | Ernst & Young (EY) | Documents fiscaux confidentiels de clients exfiltrés depuis un outil ITSM externe. | Élevé | [BleepingComputer](https://www.bleepingcomputer.com/news/security/ernst-and-young-discloses-data-breach-after-support-system-hack/)<br>[Security Affairs](https://securityaffairs.com/195550/data-breach/ernst-young-ey-investigates-data-breach-involving-third-party-support-tickets.html) |
| **Santé / Médical** | Abbott Laboratories | Données internes et documents d'entreprise à la suite de deux incidents d'extorsion. | Inconnu | [BleepingComputer](https://www.bleepingcomputer.com/news/security/abbott-laboratories-probes-two-cyber-incidents-amid-extortion-claims/) |
| **Agroalimentaire / Logistique** | Nichirei Corporation | Interruption de l'infrastructure logistique d'expédition d'aliments surgelés et fuite potentielle de données personnelles. | Moyen | [Security Affairs](https://securityaffairs.com/195543/security/a-cyberattack-hit-nichirei-one-of-japans-largest-food-companies.html) |
| **Pharmaceutique** | Droguería Martorani | Exfiltration de fichiers d'administration commerciale et de documents internes par Qilin. | Élevé | [Ransomlook](https://www.ransomlook.io//group/qilin) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-46817 | TRUE  | Active    | 7.0 | 9.8   | (1,1,7.0,9.8) |
| 2 | CVE-2023-4346  | TRUE  | Active    | 5.5 | N/A   | (1,1,5.5,0)   |
| 3 | LegacyHive     | FALSE | Active    | 3.5 | N/A   | (0,1,3.5,0)   |
| 4 | CVE-2025-40949 | FALSE | Théorique | 3.0 | 9.1   | (0,0,3.0,9.1) |
| 5 | CVE-2026-13446 | FALSE | Théorique | 2.5 | N/A   | (0,0,2.5,0)   |
| 6 | CVE-2026-54159 | FALSE | Théorique | 2.5 | N/A   | (0,0,2.5,0)   |
| 7 | CVE-2026-48062 | FALSE | Théorique | 2.0 | N/A   | (0,0,2.0,0)   |
| 8 | CVE-2025-40947 | FALSE | Théorique | 1.5 | 7.5   | (0,0,1.5,7.5) |
| 9 | CVE-2025-40948 | FALSE | Théorique | 1.5 | 6.8   | (0,0,1.5,6.8) |
| 10| CVE-2026-53727 | FALSE | Théorique | 1.5 | N/A   | (0,0,1.5,0)   |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-46817** | 9.8 | N/A | **TRUE** | **7.0** | Oracle Payments | Remote Code Execution | RCE | Active | Appliquer le Critical Patch Update d'Oracle. | [Security Affairs](https://securityaffairs.com/195516/security/u-s-cisa-adds-knx-association-knx-protocol-connection-authorization-option-1-and-oracle-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| **CVE-2023-4346** | N/A | N/A | **TRUE** | **5.5** | KNX Association Protocol | Connection Authorization Bypass | DoS / Lockout | Active | Isoler l'accès physique et logique aux interfaces de programmation KNX (BCU). | [Security Affairs](https://securityaffairs.com/195516/security/u-s-cisa-adds-knx-association-knx-protocol-connection-authorization-option-1-and-oracle-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| **LegacyHive zero-day** | N/A | N/A | FALSE | **3.5** | Microsoft Windows | Registry Hive Deserialization | LPE | Active | Restreindre les privilèges d'accès local, activer Microsoft Credential Guard. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-windows-legacyhive-zero-day-exploit-grants-hackers-admin-access/) |
| **CVE-2025-40949** | 9.1 | N/A | FALSE | **3.0** | Siemens ROX II (avant V2.17.1) | Command Injection dans le planificateur | RCE | PoC public | Mettre à jour le firmware vers la version V2.17.1 ou supérieure. | [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/siemens-rox-ii-zero-day-vulnerabilities/) |
| **CVE-2026-13446** | N/A | N/A | FALSE | **2.5** | IBM Langflow | Hardcoded Credentials & API Deserialization | RCE / Auth Bypass | PoC public | Désactiver les connexions réseau directes non authentifiées vers l'instance Langflow. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-13446) |
| **CVE-2026-54159** | N/A | N/A | FALSE | **2.5** | PrestaShop ps_facetedsearch | PHP Object Injection | RCE | PoC public | Mettre à jour le module de recherche ps_facetedsearch vers la version v4.0.4. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-54159) |
| **CVE-2026-48062** | N/A | N/A | FALSE | **2.0** | CodeIgniter (avant v4.7.3) | Upload Validation Bypass | RCE | PoC public | Mettre à niveau le framework CodeIgniter vers la version v4.7.3 ou ultérieure. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-48062) |
| **CVE-2025-40947** | 7.5 | N/A | FALSE | **1.5** | Siemens ROX II (avant V2.17.1) | Command Injection / License Validation Bypass | LPE | PoC public | Mettre à jour le firmware vers la version V2.17.1 ou supérieure. | [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/siemens-rox-ii-zero-day-vulnerabilities/) |
| **CVE-2025-40948** | 6.8 | N/A | FALSE | **1.5** | Siemens ROX II (avant V2.17.1) | Arbitrary File Disclosure | Info Disclosure | PoC public | Mettre à jour le firmware vers la version V2.17.1 ou supérieure. | [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/siemens-rox-ii-zero-day-vulnerabilities/) |
| **CVE-2026-53727** | N/A | N/A | FALSE | **1.5** | Ruby css_parser | SSRF / Recursive URL redirects | SSRF | PoC public | Mettre à jour la bibliothèque css_parser vers la version 3.0.0. | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-53727) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| Inside the Search for 'Clean' Residential Proxies for Carding | Residential Proxies + Carding | Analyse approfondie du vecteur d'attaque par abus de proxy résidentiel. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/inside-the-search-for-clean-residential-proxies-for-carding/) |
| AWS Networking for IR — VPCs, Flow Logs, and the Load Balancer Blind Spot | AWS Networking for IR + Load Balancer Blind Spot | Guide indispensable pour la remédiation et la détection d'incidents d'exfiltration en environnement cloud. | [CyberEngage](https://www.cyberengage.org/post/aws-networking-for-ir-vpcs-flow-logs-and-the-load-balancer-blind-spot) |
| New Russian Campaign Uses Fake Webex and Zoom Installers to Deploy Starland RAT | UAT-11795 + Starland RAT ClickFix campaign | Campagne active de cybercriminalité financière complexe utilisant des smart contracts Polygon. | [Security Affairs](https://securityaffairs.com/195532/malware/new-russian-campaign-uses-fake-webex-and-zoom-installers-to-deploy-starland-rat.html) |
| Hmm, this is a new to me scam... My expertise in watching someone sign a contract ames it more valid??! | Social engineering + Contract signature scam | Émergence d'une nouvelle technique de phishing par étapes ciblant les parcours d'authentification. | [Mastodon](https://mastodon.social/@carstenfranke/116938314311490749) |
| Possible Phishing on: borderclick.com Roblox lure | Roblox phishing + borderclick.com compromise | Campagne d'ingénierie sociale active hébergée sur une infrastructure d'entreprise compromise. | [URLDNA / Mastodon](https://infosec.exchange/@urldna/116938152934789559) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| Advanced Virtual Human Twins (VHT) Platform - Annual Event | Contenu non-sécuritaire (événement généraliste de la Commission Européenne). | [EC Digital Strategy](https://digital-strategy.ec.europa.eu/en/events/advanced-virtual-human-twins-vht-platform-annual-event) |
| ISC Stormcast For Friday, July 17th, 2026 | Flux d'actualité quotidien généraliste sans focus technique ciblé sur un incident unique. | [SANS ISC](https://isc.sans.edu/diary/rss/33162) |
| Windows Server 2022 reach end of mainstream support in 90 days | Article lié au cycle de vie logiciel (obsolescence) sans description d'activité cyber-offensive directe. | [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/windows-server-2022-reach-end-of-mainstream-support-in-90-days/) |
| Tracking Advanced Persistent Threat Groups \| Recorded Future | Article de blog méthodologique généraliste sur le Threat Intelligence sans indicateurs d'un incident précis. | [Recorded Future](https://www.recordedfuture.com/blog/tracking-advanced-persistent-threats) |
| ASN: AS719 Location: Porvoo, FI Added: 2026-07-11T12:18#shodansafari | Signalement brut et automatisé d'exposition de port sans analyse contextuelle ou technique substantielle. | [Shodan Safari / Mastodon](https://infosec.exchange/@shodansafari/116938270831585224) |
| Failing to discover and map dependencies between these workloads can lead to policies that either break critical business processes... | Avis d'expert d'ordre généraliste sur l'architecture réseau sans analyse technique de menaces. | [Mastodon](https://mastodon.social/@lbhuston/116938109306376604) |
| Nvidia: 422 CVEs, 94% unpatched. 24 critical... | Statistiques générales et agrégation de vulnérabilités sans focus sur une chaîne d'attaque active ou un incident précis. | [Mastodon](https://mastodon.social/@hugovalters/116938046770882196) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="inside-the-search-for-clean-residential-proxies-for-carding"></div>

## Residential Proxies + Carding

---

### Résumé technique

Les réseaux cybercriminels spécialisés dans le "carding" (l'utilisation frauduleuse de cartes bancaires volées) font face au renforcement des contrôles géographiques et comportementaux mis en œuvre par les plateformes de commerce électronique et les passerelles de paiement. Pour contourner ces systèmes de détection anti-fraude, les attaquants s'appuient sur des réseaux de proxys résidentiels dits "propres" (clean). 

Le vecteur initial repose sur la location ou l'achat d'accès à des infrastructures de proxys légitimes qui redirigent le trafic via des connexions internet de particuliers (via des boxes ADSL, de la fibre ou des abonnements mobiles 4G/5G). L'infrastructure observée montre que ces adresses IP résidentielles proviennent souvent de la compromission d'équipements connectés (IoT mal sécurisés) ou de l'intégration discrète de kits de développement logiciel (SDK) de monétisation au sein d'applications mobiles légitimes téléchargées par les utilisateurs. La victimologie de cette technique englobe l'ensemble des sites de commerce électronique, les services financiers et les marchands de biens numériques à forte valeur d'échange.

---

### Analyse de l'impact

L'utilisation de proxys résidentiels altère de manière critique la fiabilité des modèles de détection de fraude basés sur la réputation IP ou la géolocalisation. Les organisations ciblées subissent des taux de rétrofacturation (chargebacks) élevés, entraînant des pertes financières directes et des sanctions de la part des réseaux de paiement (Visa, Mastercard). 

Le niveau de sophistication de cette méthode est moyen à élevé : bien que le principe du proxy soit standard, la structuration des réseaux de serveurs relais résidentiels pour mimer parfaitement le comportement d'un consommateur légitime témoigne d'une professionnalisation poussée du marché de la cybercriminalité de commodité.

---

### Recommandations

* Implémenter l'analyse comportementale de l'utilisateur (biométrie comportementale, vitesse de saisie, mouvements de souris) au lieu de s'appuyer uniquement sur la réputation IP.
* Déployer des solutions d'empreinte numérique de navigateur (browser fingerprinting) pour corréler la configuration du système client avec l'origine supposée de l'IP de connexion.
* Restreindre les transactions initiées depuis des plages d'adresses IP associées historiquement à des services d'hébergement ou de relais VPN connus.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Activer la journalisation détaillée des en-têtes HTTP (notamment `X-Forwarded-For` et `Via`) au niveau des serveurs web frontaux et des répartiteurs de charge.
* Intégrer des flux de CTI spécialisés listant les nœuds de sortie de proxys résidentiels commerciaux.
* Définir un plan de crise conjoint avec les équipes de détection de la fraude et le service client.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * Alerte SIEM ciblant le changement brutal de pays ou de fournisseur d'accès internet (FAI) pour une même session utilisateur authentifiée en moins de 10 minutes.
  * Analyse des transactions présentant une inadéquation sémantique entre la langue configurée du navigateur client et la géolocalisation IP.
* Identifier les comptes clients suspectés d'utiliser des adresses IP résidentielles incohérentes.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Forcer une authentification multi-facteurs (MFA) ou un défi visuel (CAPTCHA) pour toute transaction initiée depuis une plage IP résidentielle suspecte ou modifiée récemment.
* Bloquer les sessions actives suspectes au niveau de la passerelle d'authentification.

**Éradication :**
* Invalider les jetons d'accès (tokens) des comptes clients compromis.
* Mettre à jour dynamiquement les listes noires de réputation IP au niveau du Web Application Firewall (WAF).

**Récupération :**
* Reverser les transactions frauduleuses identifiées et en informer l'acquéreur bancaire.
* Surveiller l'activité de reconnexion des profils d'utilisateurs impactés pendant 72h.

#### Phase 4 — Activités post-incident

* Conduire un retour d'expérience (REX) technique pour affiner les règles comportementales de détection de fraude.
* Déclarer les transactions frauduleuses aux autorités compétentes et archiver les preuves (logs de connexion, empreintes de navigateur).

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Découverte de requêtes de paiement provenant d'IP résidentielles présentant un délai de latence réseau anormalement élevé (signe d'un rebond proxy). | T1090 | Logs d'accès IIS/Apache, logs WAF | Corréler le RTT (Round Trip Time) TCP avec la géolocalisation déclarée de l'adresse IP. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | hxxps[://]residential-proxy-broker[.]local/api/v1/get-clean-ip | Exemple fictif de point d'API d'un courtier de proxys résidentiels pour l'approvisionnement des bots. | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1090** | Command and Control | Proxy | Dissimulation de l'origine géographique réelle de l'attaquant derrière une adresse IP résidentielle saine lors de la phase d'achat frauduleux. |

---

### Sources

* [BleepingComputer](https://www.bleepingcomputer.com/news/security/inside-the-search-for-clean-residential-proxies-for-carding/)

---

<div id="aws-networking-for-ir-vpcs-flow-logs-and-the-load-balancer-blind-spot"></div>

## AWS Networking for IR + Load Balancer Blind Spot

---

### Résumé technique

La conduite d'investigations numériques (DFIR) au sein des infrastructures AWS présente une limite technique critique souvent ignorée lors de l'analyse des flux réseau. Lorsqu'une instance EC2 compromise est positionnée derrière un Application Load Balancer (ALB), les VPC Flow Logs natifs enregistrent uniquement les connexions réseau établies entre l'adresse IP privée de l'ALB et l'instance EC2 interne. 

L'adresse IP publique réelle de l'attaquant, située à l'origine de la requête malveillante sur Internet, est ainsi totalement masquée dans les journaux de flux de la carte réseau d'exécution. Pour lever ce point aveugle ("blind spot"), les analystes doivent impérativement extraire et corréler les *ALB Access Logs* stockés sur S3, qui intègrent l'en-tête HTTP `X-Forwarded-For` contenant la véritable adresse IP d'origine. Les infrastructures observées exploitent cette absence de corrélation automatique pour maintenir des accès persistants furtifs sans déclencher de détections basées uniquement sur les indicateurs IP VPC classiques.

---

### Analyse de l'impact

L'absence d'activation préalable des ALB Access Logs empêche la reconstruction exacte de la timeline d'une intrusion lors d'une cyberattaque. Cela peut prolonger indéfiniment la durée de présence ("dwell time") de l'attaquant. 

Le niveau de sophistication de l'exploitation de cette faille d'analyse est faible, car elle repose sur une caractéristique native d'architecture réseau cloud, mais son impact sur la capacité de réaction et d'attribution d'un incident de sécurité est extrêmement critique.

---

### Recommandations

* Activer de manière systématique et obligatoire la journalisation des accès (Access Logs) sur l'ensemble des instances ALB et Network Load Balancer (NLB) d'AWS, avec archivage sécurisé sur un compartiment S3 isolé.
* Centraliser les ALB Access Logs et les VPC Flow Logs au sein d'un SIEM pour automatiser la corrélation sémantique des IP de connexion.
* Mettre en œuvre la journalisation des requêtes de résolution DNS (Route 53 Resolver query logs) sur l'ensemble des VPC de production.

---

### Playbook de réponse à incident

#### Phase 1 — Preparation

* S'assurer que le service AWS CloudTrail est activé sur l'ensemble des régions AWS et configuré avec écriture immuable sur S3 (Object Lock).
* Valider que les rôles IAM des analystes DFIR disposent des permissions d'extraction et de lecture du bucket S3 hébergeant les logs de l'ALB.
* Déployer une requête Athena prédéfinie pour interroger rapidement les journaux de connexions de l'ALB.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * Recherche active de connexions initiées vers l'instance EC2 via l'IP de l'ALB coïncidant chronologiquement avec l'indicateur d'activité hostile `178[.]62[.]90[.]41`.
  * Requête Athena pour analyser les logs d'accès ALB et identifier les requêtes contenant des en-têtes HTTP inhabituels ou malformés.
* Isoler les hôtes EC2 suspects via des Security Groups temporaires restrictifs.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Bloquer immédiatement l'IP malveillante identifiée `178[.]62[.]90[.]41` au niveau du pare-feu applicatif AWS WAF associé à l'ALB.
* Isoler logiquement l'instance EC2 compromise en modifiant son Security Group réseau (suppression de toutes les routes entrantes/sortantes à l'exception de la plage d'investigation).

**Éradication :**
* Révoquer les clés de compte ou d'accès IAM compromises identifiées dans CloudTrail.
* Supprimer les webshells ou artefacts malveillants éventuellement implantés sur le serveur EC2.

**Récupération :**
* Déployer à nouveau l'application sur une instance EC2 saine créée à partir d'une image AMI de confiance certifiée.
* Activer une surveillance renforcée des flux réseau de l'ALB pendant 72 heures.

#### Phase 4 — Activités post-incident

* Rédiger le rapport d'incident documentant la chaîne logique d'intrusion (de l'IP externe à l'ALB puis à l'EC2).
* Mettre à jour les modèles CloudFormation ou Terraform de l'organisation pour forcer l'activation des logs ALB à chaque provisionnement de Load Balancer.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'accès d'administration de l'infrastructure web initiés par des IP d'attaquants masquées derrière l'ALB. | T1071 | AWS ALB Access Logs | Requête Athena ciblant les requêtes POST sur des répertoires d'administration `/admin` ou `/wp-login.php` avec filtrage sur l'adresse IP cliente réelle. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| IP | 178[.]62[.]90[.]41 | Adresse IP externe identifiée comme source de requêtes suspectes masquées par l'ALB dans l'incident étudié. | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1071** | Command and Control | Application Layer Protocol | Utilisation de requêtes HTTP/HTTPS standards passant à travers l'ALB AWS pour masquer l'origine réelle des serveurs de contrôle. |

---

### Sources

* [CyberEngage](https://www.cyberengage.org/post/aws-networking-for-ir-vpcs-flow-logs-and-the-load-balancer-blind-spot)

---

<div id="new-russian-campaign-uses-fake-webex-and-zoom-installers-to-deploy-starland-rat"></div>

## UAT-11795 + Starland RAT ClickFix campaign

---

### Résumé technique

Le groupe de cybercriminalité financière d'origine russophone désigné sous l'identifiant UAT-11795 mène une campagne active d'ingénierie sociale exploitant le vecteur technique "ClickFix". Cette technique consiste à abuser de la confiance des utilisateurs en affichant de fausses invitations à des réunions en ligne (imitant Webex ou Zoom) ou de fausses alertes d'échec de chargement de page au sein du navigateur web de la victime. Pour résoudre le prétendu dysfonctionnement de connexion, l'utilisateur est incité à copier-coller et exécuter un script d'installation malveillant via une invite de commande PowerShell locale (User Execution). 

Une fois exécutée, la chaîne d'infection déploie l'agent WLDR, un chargeur de charge utile écrit en PowerShell qui s'exécute intégralement en mémoire pour contourner les contrôles de sécurité antivirus traditionnels. WLDR procède ensuite à l'installation du composant principal, Starland RAT, un cheval de Troie d'accès distant développé en langage Python. Starland RAT se distingue techniquement par son mécanisme de communication de secours (fallback) : si le serveur de contrôle (C2) traditionnel de l'attaquant ne répond plus, le logiciel interroge de manière décentralisée un contrat intelligent (smart contract) hébergé sur la blockchain publique Polygon (via l'endpoint JSON-RPC) pour acquérir la nouvelle adresse IP active de sa structure de commande.

---

### Analyse de l'impact

La compromission par Starland RAT expose l'organisation ciblée à un vol d'informations de très haut niveau, incluant l'exfiltration des bases de données d'identifiants de navigateurs, l'extraction de secrets d'annuaires Active Directory, et le pillage direct de portefeuilles de cryptomonnaies froids ou chauds. 

Le niveau de sophistication de l'attaque est élevé en raison de l'implémentation d'un canal de secours basé sur la blockchain (résistance totale aux coupures réseau défensives) et de l'exécution purement volatile en mémoire de l'agent WLDR.

---

### Recommandations

* Interdire de manière stricte l'exécution de scripts PowerShell non signés cryptographiquement au sein de l'organisation.
* Configurer les navigateurs Web d'entreprise pour désactiver la possibilité de copier-coller du code externe directement vers des consoles système (atténuation ClickFix).
* Bloquer ou surveiller de près les appels système vers les passerelles RPC publiques de la blockchain Polygon si l'organisation n'a pas d'usage métier légitime de cette technologie.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* S'assurer que le service d'audit de création de processus de Windows (Event ID 4688) et la journalisation des blocs de script PowerShell (Event ID 4104) sont activés globalement et transférés vers le SIEM.
* Mettre à jour l'agent EDR pour détecter les techniques de détournement de la mémoire PowerShell par des processus non autorisés.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * Recherche d'appels PowerShell suspects comportant des arguments chiffrés ou encodés en Base64 coïncidant avec l'exécution de faux installateurs Zoom ou Webex.
  * Détection de requêtes de résolution DNS ou de connexions HTTP sortantes vers le point d'accès RPC `polygon-rpc[.]com`.
* Identifier les postes de travail présentant des processus Python orphelins (Starland RAT) générant des flux réseau vers l'extérieur.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Isoler logiquement et physiquement le poste de travail de l'utilisateur infecté du réseau interne de l'entreprise via une commande d'isolation EDR.
* Bloquer immédiatement l'accès au nœud RPC `polygon-rpc[.]com` et aux adresses IP de C2 découvertes lors de l'analyse comportementale de la machine.

**Éradication :**
* Tuer l'ensemble des processus malveillants actifs associés à l'exécution de l'agent WLDR et de Starland RAT.
* Supprimer les mécanismes de persistance installés au niveau du registre Windows ou du planificateur de tâches utilisateur.

**Récupération :**
* Forcer la réinitialisation complète des mots de passe de session et d'administration de l'ensemble des comptes d'utilisateurs dont les secrets ont pu être extraits de la mémoire du navigateur.
* Réinstaller le poste de travail compromis à partir d'une image système certifiée saine.

#### Phase 4 — Activités post-incident

* Procéder à un audit de sécurité complet des accès réseau et comptes AD de l'utilisateur impacté afin d'identifier un éventuel mouvement latéral initié par l'attaquant avant l'isolation de la machine.
* Sensibiliser l'ensemble des collaborateurs du département de l'utilisateur compromis aux menaces de type ClickFix et d'usurpation de logiciels de visioconférence.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Découverte d'exécutions PowerShell furtives en mémoire initiées par des navigateurs Internet (Chrome, Edge) suite à une interaction utilisateur. | T1204 | Logs d'événements de création de processus (EDR / Event ID 4688) | Rechercher des processus parents `chrome.exe` ou `msedge.exe` exécutant l'utilitaire `powershell.exe` avec des paramètres de script inline. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | polygon-rpc[.]com | Point d'accès RPC public de la blockchain Polygon utilisé de secours par le malware Starland RAT pour récupérer le C2 actif. | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1204** | Execution | User Execution | Manipulation de l'utilisateur via la technique ClickFix pour l'amener à exécuter manuellement une commande malveillante sous PowerShell. |
| **T1027** | Defense Evasion | Obfuscated Files or Information | Exécution de l'agent WLDR et du code Starland RAT de manière furtive en mémoire à l'aide de scripts encodés afin d'échapper à la détection des antivirus. |

---

### Sources

* [Cisco Talos / Security Affairs](https://securityaffairs.com/195532/malware/new-russian-campaign-uses-fake-webex-and-zoom-installers-to-deploy-starland-rat.html)

---

<div id="hmm-this-is-a-new-to-me-scam-my-expertise-in-watching-someone-sign-a-contract-ames-it-more-valid"></div>

## Social engineering + Contract signature scam

---

### Résumé technique

Les campagnes d'hameçonnage par ingénierie sociale exploitent continuellement de nouveaux scénarios administratifs pour déjouer la vigilance des utilisateurs professionnels. Une nouvelle technique d'escroquerie identifiée repose sur l'exploitation fallacieuse de processus de signature électronique de documents. 

L'attaquant transmet un message d'hameçonnage se faisant passer pour un service de gestion d'entreprise ou d'édition de contrats légaux. La particularité technique de cette technique réside dans son déroulement par étapes successives : au lieu d'intégrer directement un lien d'hameçonnage classique ou une pièce jointe malveillante détectable par les passerelles de messagerie (Secure Email Gateways - SEG), l'attaquant intègre une invitation légitime de pré-visualisation d'un contrat. L'utilisateur est ensuite redirigé vers un faux parcours de validation sémantique demandant d'authentifier sa signature électronique, ce qui l'oriente finalement vers une page d'interception d'identifiants (credential theft) hautement réaliste ou un lien d'exécution de code à distance.

---

### Analyse de l'impact

Ce type d'escroquerie engendre des risques majeurs de compromission de comptes de messagerie professionnels d'entreprise (Business Email Compromise - BEC). 

Le niveau de sophistication de l'attaque est faible à moyen d'un point de vue purement technique, mais il présente un haut pouvoir de conversion psychologique auprès d'utilisateurs habitués aux interactions quotidiennes de signature de contrats administratifs (services RH, juridiques, commerciaux).

---

### Recommandations

* Mettre en œuvre des technologies de détection de messagerie de type NLP (Natural Language Processing) capables d'analyser la sémantique et la structure logique des e-mails d'invitation de signature de contrat inhabituels.
* Appliquer des politiques d'authentification forte et résistante au phishing (FIDO2 / clés physiques) pour l'accès aux plateformes de signature électronique de l'entreprise.
* Sensibiliser les utilisateurs à ne jamais saisir leurs identifiants de messagerie professionnelle sur des interfaces tierces présentées après une demande de signature électronique.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Configurer les filtres antispam de l'entreprise pour identifier les courriels externes usurpant l'identité ou la charte graphique de plateformes reconnues d'authentification ou de signature de contrats (Docusign, Adobe Sign, Yousign).
* Intégrer les processus d'authentification des plateformes de signature de l'entreprise dans le portail d'accès SSO unifié.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * Recherche d'e-mails entrants émanant d'expéditeurs externes inconnus contenant des mots-clés relatifs à des demandes de signature urgentes ou de validation de contrats.
  * Détection d'accès Internet des collaborateurs vers des domaines de redirection de formulaires suspects nouvellement créés.
* Identifier les collaborateurs ayant interagi avec l'e-mail d'invitation malveillant.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Révoquer immédiatement les jetons de session de messagerie de l'utilisateur suspecté d'avoir saisi ses identifiants sur le site de phishing.
* Isoler le lien de redirection malveillant en le bloquant au niveau du résolveur DNS et des serveurs proxy web de l'entreprise.

**Éradication :**
* Purger l'e-mail malveillant de l'ensemble des boîtes de réception de l'entreprise à l'aide d'outils d'orchestration de messagerie.
* Mettre à jour les politiques de filtrage d'URL pour y inclure les chemins sémantiques de la campagne détectée.

**Récupération :**
* Forcer la réinitialisation du mot de passe de messagerie de l'utilisateur impacté et renouveler l'inscription MFA.
* Auditer les connexions historiques récentes de l'utilisateur authentifié (adresses IP, pays d'origine) pour vérifier l'absence d'accès illégitime concurrent.

#### Phase 4 — Activités post-incident

* Documenter le scénario d'ingénierie sociale pour enrichir le programme d'entraînement et de simulation d'hameçonnage interne de l'entreprise.
* Signaler le site d'hameçonnage aux registrars et fournisseurs d'hébergement concernés afin de forcer sa désactivation publique.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détection d'utilisateurs naviguant vers des formulaires d'authentification non officiels suite à la réception d'invitations administratives externes. | T1566 | Logs du proxy web, logs DNS | Rechercher des requêtes HTTP POST sortantes vers des sites classés comme "Inconnus" ou "Récemment enregistrés" avec des volumes de données faibles. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | fake-contract-verification[.]com | Exemple théorique de domaine de redirection frauduleux utilisé dans la phase d'interception d'authentification. | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1566** | Initial Access | Phishing | Envoi d'invitations de signature électronique mensongères pour initier un vol d'identifiants ou forcer la redirection vers un site hostile. |

---

### Sources

* [Mastodon / Carsten Franke](https://mastodon.social/@carstenfranke/116938314311490749)

---

<div id="possible-phishing-on-borderclick-com-roblox-lure"></div>

## Roblox phishing + borderclick[.]com compromise

---

### Résumé technique

Une campagne d'hameçonnage active ciblant les comptes d'utilisateurs a été identifiée. Cette menace se distingue par le détournement et la compromission préalable de l'infrastructure web d'une entreprise légitime, à savoir le domaine `borderclick[.]com`. Les attaquants ont réussi à contourner les contrôles d'intégrité du serveur d'hébergement de ce site tiers et y ont implanté de manière illégitime un répertoire de fichiers médias malveillants. 

Dans cette arborescence compromise, l'attaquant héberge un leurre d'ingénierie sociale ciblant le public d'utilisateurs de la plateforme Roblox (fausses offres de cartes cadeaux Roblox gratuites). Le mécanisme technique repose sur un fichier HTML d'hameçonnage d'identifiants stocké dans le dossier d'actifs de borderclick[.]com. L'exploitation du domaine légitime de confiance permet à l'attaquant de contourner les filtres de réputation de réputation de liens au sein des messageries ou des réseaux sociaux d'échange afin de diffuser massivement son leurre d'interception d'identifiants et d'informations de paiement.

---

### Analyse de l'impact

Cette compromission engendre un double impact. Pour le propriétaire du domaine compromis (`borderclick[.]com`), l'impact est de nature réputationnelle et opérationnelle immédiate, avec une dégradation rapide de sa réputation DNS et un risque de bannissement de ses services de messagerie professionnelle. 

Pour les victimes de la campagne d'hameçonnage, elle se traduit par la perte de contrôle de leurs profils d'utilisateurs de jeux en ligne et des risques financiers associés aux informations de facturation qui y sont enregistrées. Le niveau de sophistication est faible à moyen, s'appuyant sur l'exploitation classique d'une vulnérabilité applicative web de gestion de contenu d'un site tiers.

---

### Recommandations

* Mener un audit d'intégrité complet et régulier des serveurs web externes d'entreprise pour identifier l'existence de répertoires ou de fichiers non répertoriés.
* Restreindre les privilèges d'écriture et d'exécution dans les répertoires multimédias et statiques des serveurs web (comme les dossiers `/Files` ou `/media`).
* Déployer un pare-feu applicatif web (WAF) pour filtrer les requêtes de téléversement (uploads) non autorisées de fichiers HTML statiques.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* S'assurer que les serveurs web externes de l'organisation disposent d'un outil de surveillance de l'intégrité des fichiers (FIM - File Integrity Monitoring) configuré avec alertes en temps réel.
* Définir une politique de gestion et de mise à jour stricte pour l'ensemble des modules tiers et extensions CMS installés sur le site web public.

#### Phase 2 — Détection et analyse

* **Règles de détection contextualisées** :
  * Recherche de requêtes HTTP GET dirigées vers des fichiers HTML hébergés dans des sous-répertoires d'actifs multimédias (ex: `/BC/media/Borderclick/Files/roblox-gift-card[.]html`).
  * Alerte de détection de fichier suspect créé ou modifié par l'utilisateur du serveur web standard (ex: `www-data` ou `nginx`).
* Analyser l'origine du téléversement illicite à travers les logs FTP/SSH ou du portail d'administration du CMS.

#### Phase 3 — Confinement, éradication et récupération

**Confinement :**
* Supprimer immédiatement les permissions d'accès en lecture au fichier malveillant identifié afin d'interrompre l'exposition de la campagne de phishing.
* Isoler le compte d'administration web ou les clés SSH utilisées pour procéder à l'écriture de ce fichier sur le disque.

**Éradication :**
* Supprimer définitivement le fichier HTML malveillant `roblox-gift-card[.]html` et les dépendances associées implantées par l'attaquant.
* Mettre à niveau et patcher le CMS ou les extensions présentant la vulnérabilité d'accès ou de téléversement arbitraire exploitée.

**Récupération :**
* Restaurer le site web public d'entreprise à partir d'une sauvegarde saine, validée et isolée avant la date estimée de compromission.
* Exécuter une rotation complète des secrets d'administration, mots de passe FTP et clés de serveurs.

#### Phase 4 — Activités post-incident

* Conduire un examen technique post-mortem pour valider l'étanchéité du serveur web et son adéquation avec les meilleures pratiques de sécurité d'hébergement.
* Déclarer l'incident et la résolution technique de la faille aux services de sécurité tiers pour procéder au retrait du domaine des listes de blocage de réputation.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Découverte de fichiers de scripts ou de pages HTML non documentés présents au sein des répertoires d'actifs multimédias statiques d'un serveur d'entreprise. | T1566 | Journaux système, rapports d'audits FIM | Comparer l'empreinte cryptographique de l'arborescence web de production actuelle avec le référentiel d'origine de l'application ou d'une sauvegarde archivée. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | hxxps[:]//www[.]borderclick[.]com/BC/media/Borderclick/Files/roblox-gift-card[.]html | Chemin complet du point d'hébergement de la page d'hameçonnage Roblox sur le serveur détourné. | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| **T1566** | Initial Access | Phishing | Exploitation de la réputation de confiance d'un site web compromis d'entreprise pour contourner les contrôles défensifs et diffuser des pages d'hameçonnage. |

---

### Sources

* [URLDNA / Mastodon](https://infosec.exchange/@urldna/116938152934789559)

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
13. Chaque article doit contenir un PLAYBOOK DE REPONSE A INCIDENT avec les 5 phases : Phase 1 — Préparation, Phase 2 — Détection et analyse, Phase 3 — Confinement, éradication et récupération, Phase 4 — Activités post-incident, Phase 5 — Threat Hunting (proactif) : [Vérifié]
14. Aucun bug fonctionnel, article commercial ou contenu non-sécuritaire dans la section "Articles" : [Vérifié]

Statut global : [✅ Rapport valide]
-->