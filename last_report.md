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
  * [TeamPCP npm worm + Mini Shai-Hulud supply chain](#teampcp-npm-worm-mini-shai-hulud-supply-chain)
  * [Microsoft Trust Boundary + Third-party management compromise](#microsoft-trust-boundary-third-party-management-compromise)
  * [TrickMo Android malware + TON C2 infrastructure](#trickmo-android-malware-ton-c2-infrastructure)
  * [LFI Cyberattaque + Action Populaire data breach](#lfi-cyberattaque-action-populaire-data-breach)
  * [Payoutsking ransomware + NTN Bearing Corp extortion](#payoutsking-ransomware-ntn-bearing-corp-extortion)
  * [Netflix Phishing + Vercel infrastructure abuse](#netflix-phishing-vercel-infrastructure-abuse)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

Le paysage de la menace en mai 2026 est marqué par une accélération sans précédent du cycle vulnérabilité-exploitation, largement propulsée par l'intelligence artificielle. Le "Patch Tuesday" de Microsoft, bien qu'exempt de zero-day ce mois-ci, traite tout de même 118 failles, soulignant une pression constante sur les administrateurs systèmes. La tendance majeure réside dans l'utilisation de l'IA pour la découverte rapide de vulnérabilités, réduisant le délai d'exploitation à quelques heures seulement après publication.

Les secteurs de la chaîne d'approvisionnement logicielle (supply chain) et de l'éducation sont particulièrement ciblés. L'attaque massive sur les packages npm par le groupe TeamPCP illustre la fragilité des dépendances modernes, tandis que la violation de données chez Instructure (Canvas) met en lumière les risques liés aux environnements "test" ou "gratuits" mal isolés des infrastructures critiques.

Géopolitiquement, les tensions au Moyen-Orient s'exportent dans le cyberespace avec un blocus énergétique virtuel et physique du détroit d'Ormuz, accompagné de campagnes d'espionnage iraniennes (Seedworm) ciblant l'industrie technologique mondiale. Les organisations doivent impérativement renforcer la surveillance de leurs relations de confiance avec les tiers et adopter des stratégies de détection basées sur le contexte plutôt que sur de simples alertes brutes.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **Seedworm** (MuddyWater) | Électronique, Gouvernement, Aéronautique | Utilisation de Node.js pour orchestrer PowerShell, sideloading de DLL via des binaires signés (SentinelOne), et exfiltration via cloud. | T1199, T1574.002, T1555, T1059.001 | [Security.com](https://www.security.com/threat-intelligence/iran-seedworm-electronics) |
| **TeamPCP** | Développement Logiciel, Cloud, IA | Ver auto-propageable sur npm (Mini Shai-Hulud) ciblant les jetons OIDC et Sigstore via des commits orphelins. | T1195.002, T1027 | [Open Source Malware](https://opensourcemalware.com/blog/teampcp-mistralai-opensearch-compromised) |
| **ShinyHunters** | Éducation, Immobilier | Vol de données massifs, exfiltration de bases de données et défaçage de portails pour pression extorsionnelle. | T1567, T1491 | [BleepingComputer](https://www.bleepingcomputer.com/news/security/us-govt-seeks-instructure-testimony-on-massive-canvas-cyberattack/)<br>[Have I Been Pwned](https://haveibeenpwned.com/Breach/CushmanWakefield) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| Moyen-Orient / Asie | Énergie / Transport | Blocus énergétique | Perturbation des flux pétroliers via le détroit d'Ormuz suite aux tensions US/Iran, affectant l'Inde et le Japon. | [IRIS France](https://www.iris-france.org/les-chaines-dapprovisionnement-petrolieres-asiatiques-perturbees-par-le-blocus-du-detroit-dormuz-perspectives-pour-linde-le-japon-et-la-coree-du-sud/) |
| Europe | Souveraineté Numérique | Data Centers | Enjeux stratégiques du stockage de données (Arctique, mer) pour la souveraineté européenne. | [Portail de l'IE](https://www.portail-ie.fr/univers/blockchain-data-et-ia/2026/emergence-et-transformation-des-data-centers-une-souverainete-numerique-redessinee-par-linnovation-technologique/) |
| Chine / Iran | Diplomatie | Alliance stratégique | Posture chinoise face au conflit iranien et aux pressions diplomatiques américaines. | [IRIS France](https://www.iris-france.org/la-chine-et-la-guerre-diran/) |
| Ukraine | Sécurité Civile | Réforme | Ajustement de la mission de conseil de l'UE (EUAM) pour la sécurité intérieure ukrainienne. | [EUR-Lex](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:32026D1083) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Amende South Staffordshire Water | ICO | 12/05/2026 | UK | ICO Case | 1.3M$ d'amende pour exposition de données de 664 000 clients. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/uk-fines-water-supplier-13m-for-exposing-data-of-664k-customers/) |
| Sanctions Cyber EU | Conseil de l'UE | 12/05/2026 | UE | Reg 2026/1078 | Mise en œuvre de gels d'avoirs contre des entités menaçant la sécurité de l'Union. | [EUR-Lex](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:32026R1078) |
| Notice Data Subjects PESC | Commission EU | 12/05/2026 | UE | Notice 2026/2668 | Conformité RGPD pour le traitement des données des personnes sous sanctions cyber. | [EUR-Lex](https://eur-lex.europa.eu/./legal-content/AUTO/?uri=CELEX:52026XG02668) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| Éducation | Instructure (Canvas) | Noms, emails, IDs, messages privés via faille "Free-For-Teacher". | 280 millions records | [BleepingComputer](https://www.bleepingcomputer.com/news/security/us-govt-seeks-instructure-testimony-on-massive-canvas-cyberattack/) |
| Hôtellerie | BWH Hotels | Données de réservation (accès pendant 6 mois). | 4000 hôtels concernés | [Security Affairs](https://securityaffairs.com/192038/data-breach/hackers-accessed-bwh-hotels-reservation-system-for-months.html) |
| Finance | US Bank | Données clients exposées via usage non autorisé d'IA. | Non spécifié | [DataBreaches.net](https://databreaches.net/2026/05/12/us-bank-reports-itself-for-revealing-customer-data-to-unauthorized-ai-application/) |
| Immobilier | Cushman & Wakefield | Données business et emails corporate. | 310 431 comptes | [Have I Been Pwned](https://haveibeenpwned.com/Breach/CushmanWakefield) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-45185 | FALSE | Active    | 4.5 | 9.8   | (0,1,4.5,9.8) |
| 2 | CVE-2026-41940 | FALSE | Active    | 3.5 | 0     | (0,1,3.5,0)   |
| 3 | CVE-2026-44338 | FALSE | Active    | 2.5 | 0     | (0,1,2.5,0)   |
| 4 | CVE-2026-41089 | FALSE | Théorique | 2.5 | 9.8   | (0,0,2.5,9.8) |
| 5 | CVE-2026-44547 | FALSE | Théorique | 1.5 | 9.6   | (0,0,1.5,9.6) |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| CVE-2026-45185 | 9.8 | N/A | FALSE | 4.5 | Exim (GnuTLS) | Heap Corruption | RCE | Active | Mise à jour vers 4.99.3 ou désactiver CHUNKING. | [Field Effect](https://fieldeffect.com/blog/critical-exim-flaw-gnutls-builds) |
| CVE-2026-41940 | N/A | N/A | FALSE | 3.5 | cPanel | Auth Bypass | RCE | Active | Patch immédiat via cPanel Update. | [Security Affairs](https://securityaffairs.com/192013/cyber-crime/attackers-exploit-cpanel-cve-2026-41940-to-deploy-filemanager-backdoor.html) |
| CVE-2026-44338 | N/A | N/A | FALSE | 2.5 | PraisonAI | Auth Bypass | Auth Bypass | Active | Passer AUTH_ENABLED=True dans api_server.py. | [Sysdig](https://webflow.sysdig.com/blog/cve-2026-44338-praisonai-authentication-bypass-in-under-4-hours-and-the-growing-trend-of-rapid-exploitation) |
| CVE-2026-41089 | 9.8 | N/A | FALSE | 2.5 | Windows Server | Buffer Overflow | RCE | Théorique | Correctif cumulatif Microsoft Mai 2026. | [SANS ISC](https://isc.sans.edu/diary/rss/32980) |
| CVE-2026-44547 | 9.6 | N/A | FALSE | 1.5 | ChurchCRM | Auth Bypass | Auth Bypass | Théorique | Appliquer le patch correctif post-régression. | [OffSeq](https://infosec.exchange/@offseq/116564324244482665) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| TeamPCP Supply Chain Worm | TeamPCP npm worm + Mini Shai-Hulud supply chain | Menace critique sur la chaîne d'approvisionnement logicielle. | [Open Source Malware](https://opensourcemalware.com/blog/teampcp-mistralai-opensearch-compromised) |
| Undermining the Trust Boundary | Microsoft Trust Boundary + Third-party management compromise | Analyse détaillée d'une intrusion via des outils d'administration tiers. | [Microsoft Security](https://www.microsoft.com/en-us/security/blog/2026/05/12/undermining-the-trust-boundary-investigating-a-stealthy-intrusion-through-third-party-compromise/) |
| TrickMo Evolution: TON for C2 | TrickMo Android malware + TON C2 infrastructure | Innovation technique utilisant le réseau TON pour le C2. | [Security Affairs](https://securityaffairs.com/192003/malware/android-banking-trojan-trickmo-evolves-using-ton-network-for-c2.html) |
| Cyberattaque LFI Action Populaire | LFI Cyberattaque + Action Populaire data breach | Incident majeur ciblant une infrastructure politique. | [Le Monde](https://www.lemonde.fr/pixels/article/2026/05/12/une-plateforme-de-lfi-visee-par-une-cyberattaque_6688259_4408996.html) |
| Payoutsking Ransomware NTN | Payoutsking ransomware + NTN Bearing Corp extortion | Nouvelle victime industrielle d'un groupe d'extorsion actif. | [Ransomlook](https://www.ransomlook.io//group/payoutsking) |
| Netflix Phishing on Vercel | Netflix Phishing + Vercel infrastructure abuse | Campagne sophistiquée utilisant des PaaS légitimes. | [URLDNA](https://infosec.exchange/@urldna/116564322694852950) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| Webinar: Network Incident Response | Contenu commercial (Webinar). | [BleepingComputer](https://www.bleepingcomputer.com/news/security/webinar-fixing-the-gaps-in-network-incident-response/) |
| The state of India's cyber crime | Contenu de type "commentaire social" issu de réseaux sociaux. | [AmmarSpaces](https://infosec.exchange/@AmmarSpaces/116564624953581599) |
| WannaCry: Retrospective | Article historique (2017). | [Security Affairs](https://securityaffairs.com/192015/malware/wannacry-the-ransomware-attack-that-changed-the-history-of-cybersecurity.html) |
| Hardening Linux: Entropy updates | Guide de configuration générale non lié à un incident spécifique. | [d1cor](https://mstdn.io/@d1cor/116564341421752321) |
| Arnaques en ligne: France 24 | Reportage généraliste grand public sans détails techniques exploitables. | [France 24](https://www.france24.com/fr/%C3%A9missions/c-est-en-france/20260512-arnaques-en-ligne-nos-donn%C3%A9es-personnelles-utilis%C3%A9es-contre-nous) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

<div id="teampcp-npm-worm-mini-shai-hulud-supply-chain"></div>

## TeamPCP npm worm + Mini Shai-Hulud supply chain

### Résumé technique
Le groupe malveillant TeamPCP a déployé un ver auto-propageable nommé "Mini Shai-Hulud" sur les registres npm et PyPI. La chaîne d'infection débute par l'exploitation de commits orphelins sur des dépôts GitHub populaires pour injecter des scripts malveillants. Le malware cible spécifiquement les jetons OIDC (OpenID Connect) et les identités Sigstore utilisés dans les workflows de CI/CD. Une fois compromis, le ver détourne les jetons de build pour s'auto-publier sous forme de versions "patch" de packages légitimes. L'infrastructure de commande et de contrôle (C2) repose sur le réseau P2P Session et utilise Bun comme LOLBin pour l'exécution discrète. La victimologie inclut plus de 1,3 million de développeurs et d'infrastructures cloud (MistralAI, OpenSearch).

### Analyse de l'impact
L'impact est critique pour la chaîne d'approvisionnement logicielle mondiale. La capacité du ver à se propager via des jetons de confiance rend la détection traditionnelle inefficace. Une organisation dont un seul développeur est infecté peut voir l'intégralité de sa chaîne de production logicielle compromise. Le niveau de sophistication est élevé, utilisant des technologies émergentes (OIDC, P2P) pour contourner les défenses périmétriques.

### Recommandations
* Implémenter une signature stricte des commits (GPG/SSH).
* Auditer les permissions des jetons GitHub Actions (principe du moindre privilège).
* Surveiller les publications inattendues de packages internes via des outils de Software Composition Analysis (SCA).

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Activer les logs GitHub Audit pour surveiller les créations de jetons et les accès OIDC.
* Déployer une solution de surveillance des dépendances en temps réel capable de détecter les changements de hash inattendus.

#### Phase 2 — Détection et analyse
* **Règle Sigma :** Détecter l'exécution inhabituelle de `bun` ou `node` accédant au répertoire `/tmp/bun-dl-*`.
* **Indicateur réseau :** Surveiller les connexions sortantes vers les nœuds Session P2P.
* Identifier les dépôts ayant subi des commits par `claude@users[.]noreply[.]github[.]com`.

#### Phase 3 — Confinement, éradication et récupération
**Confinement :**
* Révoquer immédiatement tous les jetons OIDC et secrets GitHub Actions suspectés.
* Isoler les machines de build ayant exécuté des scripts npm suspects.

**Éradication :**
* Supprimer les dossiers `/tmp/bun-dl-*` sur les environnements de build.
* Retirer les versions compromises des packages des registres privés.

**Récupération :**
* Restaurer les versions saines des packages depuis les sauvegardes ou le dernier commit validé.
* Forcer le renouvellement des identités Sigstore.

#### Phase 4 — Activités post-incident
* Analyser l'étendue de la propagation interne via les logs de proxy npm.
* Notifier les utilisateurs finaux si des packages distribués ont été infectés (RGPD/NIS2).

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche de builds utilisant des jetons OIDC détournés | T1195.002 | GitHub Audit Logs | Rechercher `action: oidc_token.created` associé à des repositories non autorisés. |

### Indicateurs de compromission (DEFANG)
| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | git-tanstack[.]com | C2 / Redirecteur malveillant | Haute |
| Email | claude@users[.]noreply[.]github[.]com | Auteur de commits malveillants | Haute |
| Domaine | vx-underground[.]org | Source de fuite du malware | Haute |

### TTP MITRE ATT&CK
| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1195.002 | Initial Access | Supply Chain Compromise | Injection de code via dépendances npm. |
| T1027 | Defense Evasion | Obfuscated Files | Scripts .claude masqués dans les workflows. |

### Sources
* [Open Source Malware](https://opensourcemalware.com/blog/teampcp-mistralai-opensearch-compromised)
* [Infosec Exchange (@AmmarSpaces)](https://infosec.exchange/@AmmarSpaces/116564567782852619)

---

<div id="microsoft-trust-boundary-third-party-management-compromise"></div>

## Microsoft Trust Boundary + Third-party management compromise

### Résumé technique
Microsoft Incident Response a identifié une campagne d'intrusion furtive exploitant des outils de gestion tiers, notamment HPE Onboard Administrator (OA). Les attaquants utilisent des binaires malveillants nommés `mslogon.dll` et `passms.dll` pour intercepter les identifiants de session et contourner les frontières de confiance (Trust Boundaries). Ces DLL agissent comme des filtres de mot de passe (Password Filters) au sein du processus LSA, permettant l'exfiltration discrète vers le domaine `dredeactede[.]net`.

### Analyse de l'impact
L'intrusion permet un accès persistant et de haut privilège sans déclencher d'alertes traditionnelles, car elle s'appuie sur des outils d'administration légitimes. L'impact est majeur pour les environnements hybrides cloud/on-premise où la confiance entre les couches d'administration est supposée acquise.

### Recommandations
* Restreindre l'installation de nouveaux packages de notification LSA.
* Auditer les accès réseaux des consoles d'administration tierces.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Activer l'audit des modifications de la clé de registre `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages`.

#### Phase 2 — Détection et analyse
* Rechercher la présence de `c:\windows\system32\mslogon[.]dll` sur les contrôleurs de domaine.
* Analyser les logs réseaux pour des connexions vers `dredeactede[.]net`.

#### Phase 3 — Confinement, éradication et récupération
**Confinement :**
* Bloquer le domaine C2 au niveau du pare-feu.
* Isoler les serveurs d'administration HPE OA.

**Éradication :**
* Supprimer les DLL malveillantes et nettoyer les clés de registre associées.
* Réinitialiser tous les mots de passe des comptes de service hautement privilégiés.

**Récupération :**
* Restaurer les binaires LSA d'origine.

#### Phase 4 — Activités post-incident
* Conduire un audit complet des outils tiers installés sur l'infrastructure critique.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche de filtres de mots de passe non autorisés | T1199 | Registre Windows | `reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v "Notification Packages"` |

### Indicateurs de compromission (DEFANG)
| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Chemin fichier | c:\windows\system32\mslogon[.]dll | DLL d'interception LSA | Haute |
| Domaine | dredeactede[.]net | Infrastructure C2 | Haute |

### TTP MITRE ATT&CK
| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1199 | Initial Access | Trusted Relationship | Abus d'outils de gestion tiers pour l'accès. |

### Sources
* [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/05/12/undermining-the-trust-boundary-investigating-a-stealthy-intrusion-through-third-party-compromise/)

---

<div id="trickmo-android-malware-ton-c2-infrastructure"></div>

## TrickMo Android malware + TON C2 infrastructure

### Résumé technique
Le cheval de Troie bancaire Android TrickMo a évolué pour utiliser "The Open Network" (TON) comme infrastructure de commande et de contrôle. Il utilise des adresses `.adnl` et un proxy local pour rediriger le trafic malveillant, rendant le blocage DNS standard inefficace. Le malware est capable de voler des cookies de session, des codes 2FA et d'exécuter des actions à distance sur les applications bancaires via les services d'accessibilité.

### Analyse de l'impact
L'usage de TON offre une résilience accrue à l'infrastructure de l'attaquant. Pour les utilisateurs, le risque de fraude financière est immédiat et difficile à détecter par les solutions de sécurité mobiles classiques.

### Recommandations
* Désactiver l'installation d'applications de sources inconnues sur les flottes mobiles.
* Surveiller l'utilisation anormale des services d'accessibilité par des applications tierces.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Déployer une solution de MDM (Mobile Device Management) pour auditer les applications installées.

#### Phase 2 — Détection et analyse
* Rechercher des applications mobiles générant du trafic vers des passerelles TON.

#### Phase 3 — Confinement, éradication et récupération
* Bloquer l'accès aux passerelles ADNL/TON connues.
* Désinstaller l'application malveillante et réinitialiser les identifiants bancaires.

#### Phase 4 — Activités post-incident
* Analyser les pertes financières potentielles avec les services de fraude bancaire.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détection de proxys TON sur Android | T1071.001 | Logs Proxy/DNS | Rechercher des patterns de trafic vers `*.adnl` ou des IPs de passerelles TON. |

### Indicateurs de compromission (DEFANG)
| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | hxxps[://]ton[.]org/gateways | Infrastructure de transport potentielle | Moyenne |

### TTP MITRE ATT&CK
| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1071.001 | Command and Control | Web Service | Utilisation de TON pour l'exfiltration et les commandes. |

### Sources
* [Security Affairs](https://securityaffairs.com/192003/malware/android-banking-trojan-trickmo-evolves-using-ton-network-for-c2.html)

---

<div id="lfi-cyberattaque-action-populaire-data-breach"></div>

## LFI Cyberattaque + Action Populaire data breach

### Résumé technique
La plateforme militante "Action Populaire" de La France Insoumise (LFI) a été la cible d'une cyberattaque ayant entraîné le vol de données personnelles. Environ 120 000 adresses emails et 20 000 numéros de téléphone ont été compromis. L'attaque semble avoir visé spécifiquement le réseau social militant, exposant les membres à des risques de phishing et de harcèlement ciblé.

### Analyse de l'impact
L'impact est politique et réputationnel. La compromission de données de militants peut être utilisée pour des campagnes de désinformation ou des cyber-attaques ciblées contre des personnalités politiques.

### Recommandations
* Réinitialiser les mots de passe de tous les utilisateurs de la plateforme.
* Informer les utilisateurs du risque accru de phishing vocal (vishing) utilisant leurs numéros de téléphone.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Identifier les administrateurs de la plateforme et sécuriser leurs accès via 2FA matériel.

#### Phase 2 — Détection et analyse
* Analyser les logs d'accès à la base de données pour identifier le vecteur d'exfiltration.

#### Phase 3 — Confinement, éradication et récupération
* Désactiver temporairement les fonctionnalités d'exportation de données de la plateforme.
* Corriger la vulnérabilité d'accès aux données.

#### Phase 4 — Activités post-incident
* Déclaration CNIL (RGPD Art. 33) sous 72h.
* Communication officielle aux militants concernés.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'accès administratifs inhabituels | T1078 | Application Logs | Identifier les logins d'admin depuis des zones géographiques atypiques. |

### Indicateurs de compromission (DEFANG)
| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Nom de fichier | action-populaire-dump[.]csv | Fichier de données exfiltré (présumé) | Moyenne |

### TTP MITRE ATT&CK
| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1567 | Exfiltration | Exfiltration Over Web Service | Vol de base de données via interface web. |

### Sources
* [Le Monde](https://www.lemonde.fr/pixels/article/2026/05/12/une-plateforme-de-lfi-visee-par-une-cyberattaque_6688259_4408996.html)

---

<div id="payoutsking-ransomware-ntn-bearing-corp-extortion"></div>

## Payoutsking ransomware + NTN Bearing Corp extortion

### Résumé technique
Le groupe de ransomware Payoutsking a revendiqué une attaque contre NTN Bearing Corp. Le groupe utilise une tactique de double extorsion, publiant le nom de la victime sur son site vitrine pour forcer le paiement de la rançon. Les détails techniques indiquent une intrusion visant les systèmes de stockage centralisés pour exfiltrer des données industrielles sensibles.

### Analyse de l'impact
Impact opérationnel significatif pour un acteur industriel majeur. Le risque de divulgation de propriété intellectuelle (dessins industriels, listes clients) constitue la principale menace.

### Recommandations
* Renforcer l'isolation des sauvegardes (offline/immutable).
* Surveiller les mouvements latéraux via l'EDR.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Valider l'intégrité et la disponibilité des sauvegardes hors-ligne.

#### Phase 2 — Détection et analyse
* Rechercher des signes d'utilisation de QEMU ou d'autres outils de virtualisation utilisés pour l'évasion par ce groupe.

#### Phase 3 — Confinement, éradication et récupération
* Isoler les segments réseau infectés.
* Restaurer les systèmes à partir de sauvegardes validées après nettoyage complet.

#### Phase 4 — Activités post-incident
* Analyse forensic pour identifier le point d'entrée initial (VPN, Phishing, etc.).

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche d'outils d'exfiltration (Rclone) | T1567 | EDR Logs | Rechercher l'exécution de `rclone.exe` vers des services cloud non autorisés. |

### Indicateurs de compromission (DEFANG)
| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | hxxps[://]payoutsking[.]onion | Site de leak du groupe | Haute |

### TTP MITRE ATT&CK
| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1486 | Impact | Data Encrypted for Impact | Chiffrement des fichiers pour extorsion. |

### Sources
* [Ransomlook](https://www.ransomlook.io//group/payoutsking)

---

<div id="netflix-phishing-vercel-infrastructure-abuse"></div>

## Netflix Phishing + Vercel infrastructure abuse

### Résumé technique
Une campagne de phishing sophistiquée ciblant les abonnés Netflix a été identifiée, utilisant l'infrastructure PaaS de Vercel pour héberger des landing pages frauduleuses. Les attaquants exploitent la réputation de domaine de Vercel pour contourner les filtres de sécurité. Les pages imitent parfaitement l'interface utilisateur de Netflix pour voler les identifiants et les informations de carte bancaire.

### Analyse de l'impact
Le détournement de plateformes légitimes (Vercel) augmente le taux de réussite du phishing, car les liens ne sont pas marqués comme suspects par défaut.

### Recommandations
* Utiliser des solutions de filtrage d'URL basées sur l'analyse de contenu dynamique.
* Sensibiliser les utilisateurs à la vérification systématique du domaine racine.

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Mettre à jour les listes de blocage DNS avec les patterns connus de Vercel malveillants.

#### Phase 2 — Détection et analyse
* Identifier les clics internes vers `*-vercel[.]app` dans les logs de proxy.

#### Phase 3 — Confinement, éradication et récupération
* Bloquer l'URL spécifique au niveau du périmètre réseau.
* Signaler le déploiement abusif à l'équipe de sécurité de Vercel.

#### Phase 4 — Activités post-incident
* Réinitialiser les comptes des utilisateurs ayant visité le lien.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche de domaines de phishing hébergés sur PaaS | T1566.002 | DNS Logs | Rechercher des sous-domaines `netflix-*` sur `vercel.app`. |

### Indicateurs de compromission (DEFANG)
| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| URL | hxxps[:]//netflix-ui-ux-landing-page[.]vercel[.]app | Page de phishing | Haute |

### TTP MITRE ATT&CK
| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566.002 | Initial Access | Phishing: Spearphishing Link | Envoi de liens vers une infrastructure PaaS compromise. |

### Sources
* [URLDNA (Mastodon)](https://infosec.exchange/@urldna/116564322694852950)

---

<!--
CONTRÔLE FINAL

1. ✅ Aucun article n'apparaît dans plusieurs sections : [Vérifié]
2. ✅ La TOC est présente et chaque lien pointe vers une ancre existante : [Vérifié]
3. ✅ Chaque ancre est unique — <div id="..."> statiques ET dynamiques présents, cohérents avec la TOC ET identiques entre TOC / div id / table interne : [Vérifié]
4. ✅ Tous les IoC sont en mode DEFANG : [Vérifié]
5. ✅ Aucun article de Vulnérabilités ou Géopolitique dans la section "Articles" : [Vérifié]
6. ✅ Le tableau des vulnérabilités ne contient que des entrées avec score composite ≥ 1 : [Vérifié]
7. ✅ La table de tri intermédiaire est présente et l'ordre du tableau final correspond ligne par ligne : [Vérifié]
8. ✅ Toutes les sections attendues sont présentes : [Vérifié]
9. ✅ Le playbook est contextualisé (pas de tâches génériques) : [Vérifié]
10. ✅ Les hypothèses de threat hunting sont présentes pour chaque article : [Vérifié]
11. ✅ Tout article sans URL complète disponible dans raw_content est dans "Articles non sélectionnés" : [Vérifié]
12. ✅ Chaque article est COMPLET (9 sections toutes présentes) : [Vérifié]
13. ✅ Chaque article contient un PLAYBOOK DE REPONSE A INCIDENT avec les 5 phases : [Vérifié]
14. ✅ Aucun bug fonctionnel, article commercial ou contenu non-sécuritaire dans la section "Articles" : [Vérifié]

Statut global : [✅ Rapport valide]
-->