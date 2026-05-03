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
  * [ConsentFix v3 + Automated Azure OAuth Phishing](#consentfix-v3-automated-azure-oauth-phishing)
  * [Deep#Door RAT + Stealthy Python infection](#deepdoor-rat-stealthy-python-infection)
  * [TeamPCP + npm supply chain compromise via Shai-Hulud](#teampcp-npm-supply-chain-compromise-via-shai-hulud)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

Le paysage cyber de début mai 2026 est marqué par une exploitation massive et coordonnée de vulnérabilités critiques affectant les infrastructures de base du web. La faille d'authentification cPanel (CVE-2026-41940) et la vulnérabilité du noyau Linux surnommée « Copy Fail » (CVE-2026-31431) constituent les deux piliers d'une menace systémique, permettant respectivement une compromission à grande échelle de serveurs d'hébergement et des élévations de privilèges critiques sur des millions de systèmes Linux.

L'évolution des tactiques des acteurs de menace montre une professionnalisation accrue de la chaîne d'approvisionnement logicielle. Le groupe TeamPCP illustre cette tendance en utilisant des vers auto-propagateurs pour infecter l'écosystème npm, ciblant spécifiquement les outils de sécurité. Parallèlement, le phishing évolue vers l'automatisation du vol de jetons OAuth (ConsentFix v3), contournant les protections traditionnelles basées sur les mots de passe dans les environnements Azure.

Enfin, la réponse des autorités s'intensifie. Les condamnations d'affiliés du ransomware ALPHV BlackCat, y compris des experts en cybersécurité, ainsi que l'arrestation de jeunes acteurs de menace en France, soulignent une pression judiciaire croissante visant à briser l'impunité opérationnelle des cybercriminels, qu'ils soient étatiques ou indépendants.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **ALPHV BlackCat** | Santé, Ingénierie, Pharmacie | Ransomware-as-a-Service, utilisation d'affiliés experts, blanchiment via crypto. | T1486, T1021.002 | [Security Affairs](https://securityaffairs.com/191591/cyber-crime/two-us-cybersecurity-experts-sentenced-in-ransomware-case-third-awaits-july-ruling.html) |
| **TeamPCP** | Technologie, Éditeurs de sécurité | Compromission de la chaîne d'approvisionnement npm, ver Shai-Hulud, vol de tokens CI/CD. | T1195.001, T1552.001 | [Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) |
| **ShinyHunters** | Services aux entreprises, Cloud | Extorsion de données massives via plateformes Cloud (Snowflake, Salesforce). | T1567 | [HIBP](https://haveibeenpwned.com/Breach/ZenBusiness) |
| **Sorry Ransomware** | Hébergement Web, E-commerce | Exploitation de vulnérabilités cPanel (CVE-2026-41940) pour accès root et chiffrement. | T1190 | [BleepingComputer](https://www.bleepingcomputer.com/news/security/critrical-cpanel-flaw-mass-exploited-in-sorry-ransomware-attacks/) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| Asie du Sud-Est / Chine | Gouvernement & Militaire | Espionnage Régional | Campagne utilisant Adaptix C2 et Ligolo contre les infrastructures de défense et de transport. | [CybersecurityNews](https://cybersecuritynews.com/cpanel-vulnerability-exploited/) |
| Russie / Ukraine / USA | Infrastructures Critiques | État-Nation | Plaidoyer de culpabilité du hacker russe 'Digit' pour des attaques contre l'Ukraine et les USA. | [DataBreaches](https://databreaches.net/2026/05/02/russian-hacker-known-as-digit-pleads-guilty-to-cyberattacks-on-ukraine-and-the-us/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Condamnation experts ALPHV | DoJ | 2026-05-02 | USA | US DOJ Press Release | 4 ans de prison pour deux experts cyber ayant agi comme affiliés ALPHV. | [Security Affairs](https://securityaffairs.com/191591/cyber-crime/two-us-cybersecurity-experts-sentenced-in-ransomware-case-third-awaits-july-ruling.html) |
| Inculpation Matthew Bathula | USAO Maryland | 2026-05-02 | USA | Matthew Bathula Indictment | Pharmacien inculpé pour vol d'identité et accès illégal aux dossiers médicaux. | [DataBreaches](https://databreaches.net/2026/05/02/maryland-pharmacist-indicted-on-unauthorized-computer-access-related-to-u-maryland-medical-center/) |
| Arrestation Hacker ANTS | Procureur de la République | 2026-04-25 | France | ANTS Breach Investigation | Arrestation d'un mineur (breach3d) pour le vol de 11,7 millions de comptes ANTS. | [Cyber Insider](https://cyberinsider.com/france-arrests-15-year-old-hacker-who-stole-data-of-11-7-million-people/) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| Cybersécurité | Trellix | Portion du code source (dépôts GitHub/GitLab). | Inconnu | [Trellix](https://www.trellix.com/statement/)<br>[The Hacker News](https://thehackernews.com/2026/05/trellix-confirms-source-code-breach.html) |
| Services aux entreprises | ZenBusiness | Emails, noms, numéros de téléphone (CRM). | 5 118 184 comptes | [HIBP](https://haveibeenpwned.com/Breach/ZenBusiness) |
| Gouvernement | Elections Alberta | Liste des électeurs (identités, adresses). | Inconnu | [Elections Alberta](https://www.elections.ab.ca/resources/media/news-releases/update-unauthorized-use-of-list-of-electors/) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

<!--
**Ordre de tri calculé :**

| # | CVE-ID | CISA KEV | Exploitation | Score Composite | CVSS | Clé de tri |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-41940 | TRUE  | Active    | 7.0 | 9.8   | (1,1,7.0,9.8) |
| 2 | CVE-2026-31431 | TRUE  | Active    | 5.5 | 7.8   | (1,1,5.5,7.8) |
| 3 | CVE-2026-34159 | FALSE | Théorique | 3.0 | 9.8   | (0,0,3.0,9.8) |
| 4 | CVE-2026-2052  | FALSE | Théorique | 2.0 | 9.8   | (0,0,2.0,9.8) |
| 5 | CVE-2026-7567  | FALSE | Théorique | 1.5 | 9.8   | (0,0,1.5,9.8) |
| 6 | CVE-2026-7647  | FALSE | Théorique | 1.0 | N/A   | (0,0,1.0,0.0) |
| 7 | CVE-2026-7641  | FALSE | Théorique | 1.0 | N/A   | (0,0,1.0,0.0) |
| 8 | Exim DNS Vulns | FALSE | Théorique | 1.0 | N/A   | (0,0,1.0,0.0) |
| 9 | CVE-2026-7607  | FALSE | Théorique | 1.0 | N/A   | (0,0,1.0,0.0) |
-->

| CVE-ID | Score CVSS | EPSS | CISA KEV | Score Composite | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| CVE-2026-41940 | 9.8 | N/A | TRUE | 7.0 | cPanel & WHM | CRLF Injection | Auth Bypass / Root RCE | Active | Mise à jour cPanel 11.40+ | [BleepingComputer](https://www.bleepingcomputer.com/news/security/critrical-cpanel-flaw-mass-exploited-in-sorry-ransomware-attacks/) |
| CVE-2026-31431 | 7.8 | N/A | TRUE | 5.5 | Linux Kernel | Logic Bug (Page Cache) | LPE (Root) | Active | Update Linux Kernel | [SecurityOnline](https://securityonline.info/copy-fail-cve-2026-31431-exploited-in-wild-linux-root-privileges-millions/) |
| CVE-2026-34159 | 9.8 | N/A | FALSE | 3.0 | llama.cpp RPC | Buffer Error | RCE | Théorique | Patch b8492 | [ValtersIT](https://www.valtersit.com/cve/2026/04/cve-2026-34159/) |
| CVE-2026-2052 | 9.8 | N/A | FALSE | 2.0 | Widget Options (WP) | Eval() injection | RCE | Théorique | Désactiver Display Logic | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-2052) |
| CVE-2026-7567 | 9.8 | N/A | FALSE | 1.5 | Temporary Login (WP) | Array Bypass | Account Takeover | Théorique | Désactiver le plugin | [SecurityOnline](https://securityonline.info/wordpress-temporary-login-cve-2026-7567-account-takeover-alert/) |
| CVE-2026-7647 | N/A | N/A | FALSE | 1.0 | Profile Builder Pro | PHP Object Injection | RCE | Théorique | Mise à jour plugin | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-7647) |
| CVE-2026-7641 | N/A | N/A | FALSE | 1.0 | Import/Export Users | Meta-key bypass | Privilege Escalation | Théorique | Désactiver 'Show fields' | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-7641) |
| Exim DNS | N/A | N/A | FALSE | 1.0 | Exim Mail Server | DNS processing error | Crash / DoS | Théorique | Mise à jour Exim | [CybersecurityNews](https://cybersecuritynews.com/exim-mail-server-vulnerabilities/) |
| CVE-2026-7607 | N/A | N/A | FALSE | 1.0 | TRENDnet TEW-821DAP | Buffer Overflow | RCE | Théorique | Remplacement matériel | [CVEFeed](https://cvefeed.io/vuln/detail/CVE-2026-7607) |

---

<div id="articles-selectionnes"></div>

## Articles sélectionnés

| Titre | Sujet canonique | Raison de sélection | Source(s) |
|---|---|---|---|
| ConsentFix v3 : Phishing OAuth sur Azure | ConsentFix v3 + Automated Azure OAuth Phishing | Nouvelle technique de vol de tokens Azure sans mot de passe. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/consentfix-v3-attacks-target-azure-with-automated-oauth-abuse/) |
| Nouveau RAT Deep#Door ciblant Windows | Deep#Door RAT + Stealthy Python infection | Malware Python utilisant des tunnels TCP pour l'évasion. | [Security Affairs](https://securityaffairs.com/191567/malware-new-deepdoor-rat-uses-stealth-and-persistence-to-target-windows.html) |
| Menaces sur npm et TeamPCP | TeamPCP + npm supply chain compromise via Shai-Hulud | Groupe actif ciblant la supply chain via des vers auto-propagateurs. | [Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/) |

---

<div id="articles-non-selectionnes"></div>

## Articles non sélectionnés

| Titre | Raison d'exclusion | Source(s) |
|---|---|---|
| Vérification E2EE sur Matrix | Contenu éducatif/généraliste sur l'usage des émojis. | [Mastodon](https://dragonscave.space/@somegregariousdude/116507878604628029) |
| Rémunération et sécurité | Opinion/RH non technique sur les salaires Infosec. | [Mastodon](https://hachyderm.io/@unixorn/116507812680315329) |
| Épistémologie de Copyfail | Débat philosophique sur l'IA vs Humains. | [Mastodon](https://mastodon.social/@bms48/116507727276665989) |
| Limites de l'abduction chez les LLM | Analyse théorique/philosophique des capacités de l'IA. | [Mastodon](https://mastodon.social/@bms48/116507712999404070) |
| Chiffrement avant upload Cloud | Conseil générique de sécurité pour le grand public. | [Mastodon](https://mastobot.ping.moi/@Bobe_bot/116507699551648693) |
| Passage aux agents de code IA locaux | Guide d'utilisation d'outils de développement (Qwen/Claude Code). | [The Register](https://www.theregister.com/2026/05/02/local_ai_coding_agents/) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

<div id="consentfix-v3-automated-azure-oauth-phishing"></div>

## ConsentFix v3 + Automated Azure OAuth Phishing

---

### Résumé technique

**Contexte et découverte :**
Une nouvelle version du kit de phishing automatisé, ConsentFix v3, a été identifiée comme ciblant activement les environnements Microsoft Azure. Cette menace exploite la confiance des utilisateurs dans les flux d'authentification OAuth pour obtenir des accès persistants sans nécessiter le vol de mots de passe traditionnels.

**Mécanisme technique :**
L'attaque utilise le flux "ClickFix". L'utilisateur est dirigé vers une page malveillante hébergée sur Cloudflare qui imite une interface Microsoft légitime. Le kit automatise l'enregistrement et le consentement d'une application Azure malveillante. Une fois le consentement accordé, les jetons OAuth (Access et Refresh tokens) sont exfiltrés et importés directement dans le "Specter Portal", une infrastructure de gestion d'attaques.

**Victimologie :**
La campagne cible principalement les administrateurs cloud et les développeurs disposant de privilèges élevés dans les tenants Azure d'entreprise.

---

### Analyse de l'impact

L'utilisation de jetons OAuth permet aux attaquants de maintenir un accès prolongé aux ressources cloud (Emails, fichiers SharePoint, infrastructures Azure) même si l'utilisateur change son mot de passe. Le niveau de sophistication est élevé en raison de l'automatisation du flux et de l'utilisation d'infrastructures de distribution légitimes (Cloudflare).

---

### Recommandations

* Restreindre la capacité des utilisateurs non-administrateurs à enregistrer des applications tierces dans Entra ID.
* Mettre en œuvre des politiques de "Verified Publisher" pour toutes les applications demandant des consentements.
* Surveiller les pics de création de jetons OAuth et les enregistrements d'applications suspectes.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Vérifier que les journaux d'audit Azure AD (Sign-in logs et Audit logs) sont conservés au moins 30 jours.
* Préparer les scripts PowerShell (Az Module) pour la révocation rapide des jetons.
* Identifier les comptes à haut privilège nécessitant une surveillance renforcée.

#### Phase 2 — Détection et analyse
* **Règle de détection :** Rechercher les requêtes vers Azure CLI ou des applications de premier plan incluant des redirections vers des URLs `localhost` ou des domaines suspects dans les logs de proxy.
* Analyser les journaux d'audit Entra ID pour l'événement `Add app role assignment to service principal` lié à des applications inconnues.
* Vérifier l'apparition de l'IoC `hunter[.]io` dans les flux réseau.

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Supprimer immédiatement l'application Azure malveillante du tenant compromis.
* **Éradication :** Utiliser la commande `Revoke-MgUserSignInSession` pour invalider tous les jetons actifs du compte victime.
* **Récupération :** Réinitialiser les mots de passe et le MFA par précaution, bien que l'attaque cible les jetons.

#### Phase 4 — Activités post-incident
* Rédiger un rapport détaillant l'application malveillante identifiée et son ID.
* Notifier les autorités (RGPD) si des données personnelles ont été accédées via l'application.
* Organiser une session de sensibilisation sur le phishing de consentement (Consent Phishing).

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Recherche de consentements accordés à des applications non vérifiées | T1566.002 | Azure Audit Logs | `AuditLogs \| where OperationName == "Consent to application"` |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | hxxps[://]hunter[.]io | Domaine utilisé pour le ciblage ou l'infrastructure | Moyenne |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1566.002 | Initial Access | Phishing: Spearphishing Link | Utilisation de liens Cloudflare pour initier le flux OAuth malveillant. |

---

### Sources

* [BleepingComputer](https://www.bleepingcomputer.com/news/security/consentfix-v3-attacks-target-azure-with-automated-oauth-abuse/)

---

<div id="deepdoor-rat-stealthy-python-infection"></div>

## Deep#Door RAT + Stealthy Python infection

---

### Résumé technique

**Contexte et découverte :**
Un nouveau cheval de Troie d'accès à distance (RAT), baptisé Deep#Door, a été découvert ciblant les systèmes Windows. Il se distingue par son utilisation intensive de scripts Python et de mécanismes de tunneling pour échapper aux détections périmétriques.

**Mécanisme technique :**
L'infection débute par un dropper batch qui déploie un interpréteur Python minimal. Le payload Deep#Door est un script Python obfusqué qui utilise des tunnels TCP publics (via le service `bore`) pour communiquer avec son serveur de commande et contrôle (C2). Il désactive activement Windows Defender via des modifications de registre et utilise des tâches planifiées pour garantir sa persistance après redémarrage.

**Victimologie :**
Utilisateurs Windows, sans secteur géographique spécifique identifié à ce jour, suggérant une campagne opportuniste.

---

### Analyse de l'impact

L'impact est critique pour les endpoints infectés : vol de données, exécution de commandes arbitraires et possibilité de déploiement de payloads supplémentaires (ransomware). L'utilisation de tunnels TCP publics rend le blocage IP difficile car le trafic semble provenir de services de tunneling légitimes.

---

### Recommandations

* Bloquer les domaines de tunneling connus comme `bore[.]pub` au niveau du pare-feu.
* Restreindre l'exécution de Python sur les postes de travail non-développeurs via des politiques AppLocker.
* Surveiller les modifications suspectes des clés de registre liées à Windows Defender.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Activer la surveillance de l'exécution de l'interpréteur Python (`python.exe`) via l'EDR.
* Configurer le SIEM pour alerter sur l'utilisation du service de tunneling `bore`.
* S'assurer que les sauvegardes hors-ligne sont fonctionnelles.

#### Phase 2 — Détection et analyse
* **Règle de détection :** Rechercher des connexions sortantes vers `bore[.]pub` sur les ports dans la plage `41234-41243`.
* Identifier les processus Python suspects ayant des connexions réseau actives.
* Rechercher des tâches planifiées nouvellement créées avec des noms génériques ou aléatoires.

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Isoler le poste infecté du réseau. Bloquer le domaine `bore[.]pub` sur l'ensemble du périmètre.
* **Éradication :** Supprimer les fichiers Python malveillants, les droppers batch et les tâches planifiées identifiées. Restaurer les clés de registre de Defender.
* **Récupération :** Analyser l'intégrité du système avant reconnexion.

#### Phase 4 — Activités post-incident
* Analyser le script Python récupéré pour identifier d'autres adresses C2.
* Mettre à jour les règles YARA/Sigma avec les artefacts trouvés lors de l'analyse.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détection de persistance par tâche planifiée Python | T1053.005 | EDR Logs | Rechercher `schtasks.exe` créant des tâches appelant `python.exe`. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Domaine | bore[.]pub | Service de tunneling TCP utilisé pour le C2 | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1027.002 | Defense Evasion | Obfuscated Files or Information: Software Packing | Utilisation de scripts Python obfusqués et de packers batch. |

---

### Sources

* [Security Affairs](https://securityaffairs.com/191567/malware-new-deepdoor-rat-uses-stealth-and-persistence-to-target-windows.html)

---

<div id="teampcp-npm-supply-chain-compromise-via-shai-hulud"></div>

## TeamPCP + npm supply chain compromise via Shai-Hulud

---

### Résumé technique

**Contexte et découverte :**
L'équipe de recherche Unit 42 a identifié une recrudescence d'attaques contre la chaîne d'approvisionnement npm, attribuées au groupe TeamPCP (ou pcpcats). Le groupe cible activement des outils de sécurité et des bibliothèques populaires.

**Mécanisme technique :**
L'acteur utilise un ver auto-propagateur nommé "Shai-Hulud". Une fois qu'un développeur installe un paquet infecté, le ver s'exécute via les hooks `preinstall`. Il scanne les fichiers locaux à la recherche de jetons d'accès CI/CD (GitHub, npm) et de credentials dans les fichiers de configuration (Bitwarden CLI, Checkmarx). Si des jetons sont trouvés, le ver les utilise pour publier automatiquement des versions malveillantes de tous les paquets auxquels le développeur a accès.

**Victimologie :**
Développeurs de logiciels, entreprises de technologie et éditeurs de solutions de sécurité.

---

### Analyse de l'impact

L'impact est exponentiel en raison de l'auto-propagation. Un seul compte de développeur compromis peut entraîner l'infection de dizaines de projets d'entreprise, affectant potentiellement des millions d'utilisateurs finaux. Le vol de jetons CI/CD permet un accès total aux environnements de production.

---

### Recommandations

* Interdire l'utilisation des hooks `preinstall` lors de l'installation de paquets npm (`npm install --ignore-scripts`).
* Utiliser un proxy npm privé (ex: Artifactory) pour valider les paquets avant leur mise à disposition interne.
* Mettre en œuvre le MFA pour toutes les publications sur les registres de paquets.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation
* Auditer les accès des développeurs aux dépôts npm d'entreprise.
* Configurer les outils de scan de secrets (Secret Scanning) sur tous les dépôts.
* Établir une procédure de révocation d'urgence des tokens GitHub/npm.

#### Phase 2 — Détection et analyse
* **Règle de détection :** Surveiller les logs de `npm audit` pour des paquets signalés comme malveillants ou publiés très récemment par des tiers.
* Rechercher le hash SHA256 `167ce57ef59a32a6a0ef4137785828077879092d7f83ddbc1755d6e69116e0ad` dans les environnements de build.
* Alerter sur toute connexion sortante vers `audit[.]checkmarx[.]cx`.

#### Phase 3 — Confinement, éradication et récupération
* **Confinement :** Révoquer immédiatement tous les jetons CI/CD du développeur suspecté. Retirer les versions malveillantes du registre npm.
* **Éradication :** Nettoyer les environnements locaux des développeurs et les serveurs de build. Supprimer les fichiers de configuration compromis.
* **Récupération :** Republier des versions saines après audit complet du code.

#### Phase 4 — Activités post-incident
* Analyser l'étendue de la propagation (combien de paquets ont été republiés avec le ver).
* Notifier les clients si des versions malveillantes ont été téléchargées.

#### Phase 5 — Threat Hunting (proactif)

| Hypothèse | TTP associé | Source de données | Requête / Méthode de recherche |
|---|---|---|---|
| Détection de paquets npm malveillants par version | T1195.001 | npm Audit Logs | Rechercher des paquets `@bitwarden/cli` ou similaires en version `2026.4.0`. |

---

### Indicateurs de compromission (DEFANG obligatoire)

| Type | Valeur (DEFANG) | Description | Fiabilité |
|---|---|---|---|
| Hash SHA256 | 167ce57ef59a32a6a0ef4137785828077879092d7f83ddbc1755d6e69116e0ad | Artefact du ver Shai-Hulud | Haute |
| Domaine | audit[.]checkmarx[.]cx | Domaine C2 usurpant Checkmarx | Haute |

---

### TTP MITRE ATT&CK

| ID TTP | Tactique | Technique | Description contextuelle |
|---|---|---|---|
| T1195.001 | Initial Access | Supply Chain Compromise: Compromise Software Dependencies | Injection de code malveillant dans des paquets npm via des scripts preinstall. |

---

### Sources

* [Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)

---

<!--
CONTRÔLE FINAL

1. [Vérifié] Aucun article n'apparaît dans plusieurs sections.
2. [Vérifié] La TOC est présente et chaque lien pointe vers une ancre existante.
3. [Vérifié] Chaque ancre est unique et cohérente entre TOC / div id.
4. [Vérifié] Tous les IoC sont en mode DEFANG.
5. [Vérifié] Aucun article de Vulnérabilités ou Géopolitique dans la section "Articles".
6. [Vérifié] Le tableau des vulnérabilités ne contient que des entrées avec score composite ≥ 1.
7. [Vérifié] La table de tri intermédiaire est présente et l'ordre correspond.
8. [Vérifié] Toutes les sections attendues sont présentes.
9. [Vérifié] Le playbook est contextualisé.
10. [Vérifié] Les hypothèses de threat hunting sont présentes pour chaque article.
11. [Vérifié] Tout article sans URL complète est exclu (Matrix E2EE, etc. ont été validés car l'URL Mastodon est complète).
12. [Vérifié] Chaque article est COMPLET (9 sections).
13. [Vérifié] Chaque article contient un PLAYBOOK DE REPONSE A INCIDENT avec les 5 phases.
14. [Vérifié] Aucun bug fonctionnel ou contenu non-sécuritaire dans "Articles".

Statut global : [✅ Rapport valide]
-->