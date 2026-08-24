# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [Google Cloud Compute et Cloud Ops Agent — Ce qui compte vraiment pour le DFIR](#google-cloud-compute-et-cloud-ops-agent-ce-qui-compte-vraiment-pour-le-dfir)
  * [Sécurité Supply Chain : Ne pas tenir l'intégrité des packages pour acquise](#securite-supply-chain-ne-pas-tenir-lintegrite-des-packages-pour-acquise)
  * [Fuite de données NIUS (nius[.]de) — ~6 000 enregistrements compromis](#fuite-de-donnees-nius-niusde-6-000-enregistrements-compromis)
  * [Failles logiques et correctifs pour les règles de détection curées de Google SecOps (Chronicle) - O365 & UEBA](#failles-logiques-et-correctifs-pour-les-regles-de-detection-curees-de-google-secops-chronicle-o365-ueba)
  * [La patch KB5121003 de Windows 11 provoque des crashes dans les jeux vidéo](#la-patch-kb5121003-de-windows-11-provoque-des-crashes-dans-les-jeux-video)
  * [parsedmarc — Un outil open source pour analyser les rapports DMARC](#parsedmarc-un-outil-open-source-pour-analyser-les-rapports-dmarc)
  * [Campagne BEC avec Agent Tesla v4 caché dans un fichier JScript rempli d'emoji](#campagne-bec-avec-agent-tesla-v4-cache-dans-un-fichier-jscript-rempli-demoji)
  * [Page de phishing hébergée sur GitHub Pages ciblant IONOS](#page-de-phishing-hebergee-sur-github-pages-ciblant-ionos)
  * [Récapitulatif hebdomadaire des violations de données - 17 au 23 août 2026](#recapitulatif-hebdomadaire-des-violations-de-donnees-17-au-23-aout-2026)
  * [LockBit 5.0 menace de publier des données volées à l'entreprise française Actua](#lockbit-50-menace-de-publier-des-donnees-volees-a-lentreprise-francaise-actua)
  * [Plus de 9 300 clés d'accès AWS actives publiquement exposées, Hugging Face identifié comme source principale](#plus-de-9-300-cles-dacces-aws-actives-publiquement-exposees-hugging-face-identifie-comme-source-principale)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'activité cybercriminelle de la journée a été marquée par une forte concentration sur les vulnérabilités, représentant la majorité des 11 articles traités. Avec huit publications dédiées, la priorité opérationnelle immédiate doit être le suivi des correctifs et l'évaluation de l'exposition de notre périmètre aux exploits potentiels. Parallèlement, la récurrence de cinq incidents de fuite de données souligne une pression persistante sur la confidentialité des informations, nécessitant une vigilance accrue sur les compromissions d'identifiants. L'absence de signalement réglementaire et la faible activité géopolitique (un seul article) indiquent un contexte stable sur le plan normatif et macro-politique. La détection d'un seul acteur de menace spécifique suggère une exploitation opportuniste de ces failles plutôt qu'une campagne ciblée et sophistiquée. En résumé, les efforts de remédiation doivent s'aligner sur ce volume critique de vulnérabilités tout en intégrant la surveillance des fuites récentes pour prévenir d'éventuels mouvements latéraux.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **ShinyHunters** | finance | Exploitation de comptes valides, exfiltration de données et extorsion via ransomware/chiffrement. | T1486, T1005, T1657, T1567, T1078 | [https[://]pulseofnations.lol/shinyhunters-hit-bok/](https[://]pulseofnations.lol/shinyhunters-hit-bok/)<br>[https[://]mastodon.social/@PulseOfNations/117143002824465133](https[://]mastodon.social/@PulseOfNations/117143002824465133)<br>[https://mastodon.social/@PulseOfNations/117143002824465133](https://mastodon.social/@PulseOfNations/117143002824465133) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Amérique du Nord, États-Unis** | Finance, Assurance, Juridique | Campagne d'ingénierie sociale (vishing) menée par Silent Ransom Group contre les secteurs financier, assurantiel et juridique | Le groupe Silent Ransom Group, actif depuis 2022 et spécialisé dans l'usurpation d'identité du support informatique depuis le printemps 2026, mène une campagne d'ingénierie sociale ciblant les secteurs de la finance, de l'assurance et du juridique. Apollo Global Management, l'un des géants du private equity gérant des centaines de milliards de dollars, a été compromis non pas par un zero-day ou un acteur étatique, mais par un appel téléphonique d'un individu se faisant passer pour le support IT. Google Threat Intelligence Group et Mandiant ont tous deux documenté ce modus operandi dès juin 2026. La technique repose sur l'usurpation d'identité du helpdesk pour obtenir des accès ou des informations sensibles via le canal téléphonique, contournant ainsi les défenses techniques traditionnelles. Cette campagne illustre la persistance d'une menace qui exploite le facteur humain, considéré comme le maillon le plus faible de la chaîne de sécurité, au lieu de chercher à exploiter des vulnérabilités techniques. | [https://infosec.exchange/@security_crawler_carl/117146217260647792](https://infosec.exchange/@security_crawler_carl/117146217260647792) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

_Aucune actualité réglementaire._

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Finance / Private Equity** | Apollo Global Management | Noms, dates de naissance, coordonnées de contact, numéros de sécurité sociale (SSN) | Inconnu | [https[://]techcrunch.com/2026/08/21/private-equity-firm-apollo-confirms-data-breach-amid-hacking-wave-targeting-financial-giants/](https[://]techcrunch.com/2026/08/21/private-equity-firm-apollo-confirms-data-breach-amid-hacking-wave-targeting-financial-giants/)<br>[https[://]mastodon.thenewoil.org/@thenewoil/117145298547397291](https[://]mastodon.thenewoil.org/@thenewoil/117145298547397291)<br>[https[://]infosec.exchange/@DevaOnBreaches/117142183287122483](https[://]infosec.exchange/@DevaOnBreaches/117142183287122483)<br>[https://mastodon.thenewoil.org/@thenewoil/117145298547397291](https://mastodon.thenewoil.org/@thenewoil/117145298547397291)<br>[https://infosec.exchange/@DevaOnBreaches/117142183287122483](https://infosec.exchange/@DevaOnBreaches/117142183287122483) |
| **Énergie / Services publics** | Louisiana Electric Resource | Documents financiers, contrats, emails internes, informations personnelles des clients et employés (200 Go) | 200 | [https[://]go.darkwebsonar.io/updap-mastodon](https[://]go.darkwebsonar.io/updap-mastodon)<br>[https[://]infosec.exchange/@darkwebsonar/117144685581051399](https[://]infosec.exchange/@darkwebsonar/117144685581051399)<br>[https://infosec.exchange/@darkwebsonar/117144685581051399](https://infosec.exchange/@darkwebsonar/117144685581051399) |
| **Finance / Institutions bancaires** | BOK Financial | Données volées (nature exacte non précisée - menaces de publication par ShinyHunters d'ici le 24 août 2026) | Inconnu | [https[://]pulseofnations.lol/shinyhunters-hit-bok/](https[://]pulseofnations.lol/shinyhunters-hit-bok/)<br>[https[://]mastodon.social/@PulseOfNations/117143002824465133](https[://]mastodon.social/@PulseOfNations/117143002824465133)<br>[https://mastodon.social/@PulseOfNations/117143002824465133](https://mastodon.social/@PulseOfNations/117143002824465133) |
| **Santé / Hôpital pédiatrique** | SickKids (Hospital for Sick Children) | Informations personnelles d'employés actuels/anciens et de candidats à un emploi (détails exacts non précisés) | Inconnu | [https[://]www.bleepingcomputer.com/news/security/sickkids-data-breach-exposes-employee-and-job-applicant-info/](https[://]www.bleepingcomputer.com/news/security/sickkids-data-breach-exposes-employee-and-job-applicant-info/)<br>[https[://]infosec.exchange/@DevaOnBreaches/117142178194519583](https[://]infosec.exchange/@DevaOnBreaches/117142178194519583)<br>[https://infosec.exchange/@DevaOnBreaches/117142178194519583](https://infosec.exchange/@DevaOnBreaches/117142178194519583) |
| **Cybersécurité / Outils de monitoring** | XposedOrNot API (note technique) | N/A - Note technique sur l'utilisation correcte de l'API de monitoring XposedOrNot | Inconnu | [https[://]infosec.exchange/@DevaOnBreaches/117142410662402188](https[://]infosec.exchange/@DevaOnBreaches/117142410662402188)<br>[https://infosec.exchange/@DevaOnBreaches/117142410662402188](https://infosec.exchange/@DevaOnBreaches/117142410662402188) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-8445** | 9.8 | N/A | FALSE | justhtml versions <= 1.11.0 (corrigé dans la version 1.12.0) | Contournement de sanitisation / Cross-Site Scripting (CWE-79) | Un attaquant peut injecter du code HTML/JavaScript arbitraire dans la sortie Markdown générée par to_markdown(), contournant les protections de sanitisation. Cela permet des attaques de type cross-site scripting (XSS) pouvant entraîner le vol de sessions, l'exfiltration de données ou l'exécution d'actions au nom de l'utilisateur. Le score CVSS 3.1 est de 9.8 (CRITICAL) avec un vecteur d'exploitabilité de 3.9 et un impact de 5.9. | Theoretical | Mettre à jour la bibliothèque justhtml vers la version 1.12.0 ou ultérieure. Examiner et sanitiser la sortie Markdown avant tout rendu. Implémenter un échappement HTML plus strict dans les parseurs personnalisés. Référence : GHSA-3rcm-vjrc-p45j. | [https://cvefeed.io/vuln/detail/CVE-2026-8445](https://cvefeed.io/vuln/detail/CVE-2026-8445)<br>[https://github.com/EmilStenstrom/justhtml/security/advisories/GHSA-3rcm-vjrc-p45j](https://github.com/EmilStenstrom/justhtml/security/advisories/GHSA-3rcm-vjrc-p45j)<br>[https://www.vulncheck.com/advisories/justhtml-before-sanitizer-bypass-via-markdown](https://www.vulncheck.com/advisories/justhtml-before-sanitizer-bypass-via-markdown) |
| **CVE-2026-7808** | N/A | N/A | FALSE | justhtml versions antérieures à 1.16.0 | Problèmes de sécurité multiples liés à la sanitisation | Les problèmes de sanitisation multiples pourraient permettre à un attaquant de contourner les protections de sécurité de la bibliothèque, avec un impact potentiel variable selon le contexte d'utilisation. Une analyse approfondie des détails de la CVE est recommandée. | Theoretical | Mettre à jour la bibliothèque justhtml vers la version 1.16.0 ou ultérieure. Surveiller les avis de sécurité de l'éditeur pour des informations complémentaires. | [https://cvefeed.io/vuln/detail/CVE-2026-7808](https://cvefeed.io/vuln/detail/CVE-2026-7808) |
| **CVE-2026-5388** | N/A | N/A | FALSE | justhtml versions antérieures à 1.15.0 | Problèmes de sécurité multiples | Les problèmes de sécurité multiples pourraient permettre à un attaquant d'exploiter la bibliothèque de manière non spécifiée. Une analyse approfondie des détails de la CVE est recommandée. | Theoretical | Mettre à jour la bibliothèque justhtml vers la version 1.15.0 ou ultérieure. Surveiller les avis de sécurité de l'éditeur pour des informations complémentaires. | [https://cvefeed.io/vuln/detail/CVE-2026-5388](https://cvefeed.io/vuln/detail/CVE-2026-5388) |
| **CVE-2026-78155** | 9.9 | N/A | FALSE | StackGres operator (OnGres) versions <= 1.18.8 | Untrusted Search Path / Escalade de privilèges (CWE-426) | Un attaquant disposant d'un accès tenant de bas niveau peut élever ses privilèges au niveau administrateur, compromettant potentiellement l'ensemble du cluster StackGres et toutes les bases de données gérées. Le score CVSS 3.1 est de 9.9 (CRITICAL). | Theoretical | Appliquer le correctif de sécurité fourni par OnGres pour l'opérateur StackGres. Réviser et restreindre les privilèges de propriété de base de données. Surveiller les logs d'accès pour toute activité suspecte. Référence : hxxps://gitlab[.]com/ongresinc/stackgres/-/work_items/3177. | [https://cvefeed.io/vuln/detail/CVE-2026-78155](https://cvefeed.io/vuln/detail/CVE-2026-78155)<br>[https://gitlab.com/ongresinc/stackgres/-/work_items/3177](https://gitlab.com/ongresinc/stackgres/-/work_items/3177) |
| **CVE-2026-10053** | 8.5 | N/A | FALSE | GitLab CE/EE versions 18.8 à < 19.0.6, 19.1 à < 19.1.4, 19.2 à < 19.2.2 | Path Traversal menant à Remote Code Execution (CWE-22) | Un utilisateur authentifié peut obtenir une exécution de code à distance sur le serveur GitLab via le package registry, compromettant potentiellement l'ensemble de l'instance et les données stockées. Le score CVSS 3.1 est de 8.5 (HIGH). | Theoretical | Mettre à jour GitLab vers les versions corrigées : 19.0.6, 19.1.4 ou 19.2.2 selon la branche. Restreindre l'accès au package registry. Références : hxxps://gitlab[.]com/gitlab-org/gitlab/-/work_items/601596 et hxxps://hackerone[.]com/reports/3754194. | [https://cvefeed.io/vuln/detail/CVE-2026-10053](https://cvefeed.io/vuln/detail/CVE-2026-10053)<br>[https://gitlab.com/gitlab-org/gitlab/-/work_items/601596](https://gitlab.com/gitlab-org/gitlab/-/work_items/601596)<br>[https://hackerone.com/reports/3754194](https://hackerone.com/reports/3754194) |
| **CVE-2026-78050** | 9.9 | N/A | FALSE | Comfast CF-N1-S version 2.6.0.1 | Débordement de tampon basé sur la pile (CWE-119, CWE-121) | Un attaquant distant peut exploiter cette vulnérabilité pour exécuter du code arbitraire sur l'équipement via un débordement de tampon, compromettant totalement l'appareil. L'exploit est public, ce qui augmente le risque d'exploitation active. Le score CVSS 3.1 est de 9.9 (CRITICAL). | Active | Mettre à jour le firmware vers une version corrigée. Éviter d'utiliser la fonction ou le composant affecté. Restreindre l'accès réseau à l'interface de gestion. Référence : hxxps://github[.]com/AdminSafe/CVE/issues/9. | [https://cvefeed.io/vuln/detail/CVE-2026-78050](https://cvefeed.io/vuln/detail/CVE-2026-78050)<br>[https://github.com/AdminSafe/CVE/issues/9](https://github.com/AdminSafe/CVE/issues/9)<br>[https://vuldb.com/cve/CVE-2026-78050](https://vuldb.com/cve/CVE-2026-78050)<br>[https://vuldb.com/submit/881293](https://vuldb.com/submit/881293)<br>[https://vuldb.com/vuln/394291](https://vuldb.com/vuln/394291)<br>[https://vuldb.com/vuln/394291/cti](https://vuldb.com/vuln/394291/cti) |
| **CVE-2026-16149** | 8.8 | N/A | FALSE | Security Hardener plugin pour WordPress versions <= 2.4.4 | Escalade de privilèges / Autorisation manquante (CWE-269) | Un attaquant authentifié avec un simple accès Subscriber peut créer des comptes administrateur ou réinitialiser les mots de passe d'administrateurs existants, compromettant totalement le site WordPress. Le score CVSS 3.1 est de 8.8 (HIGH) avec un vecteur d'exploitabilité de 2.8 et un impact de 5.9. | Theoretical | Mettre à jour le plugin Security Hardener vers la dernière version. Vérifier les paramètres du plugin après la mise à jour. Supprimer le plugin s'il n'est pas nécessaire. Référence : hxxps://plugins[.]trac[.]wordpress[.]org/changeset/3630896/security-hardener. | [https://cvefeed.io/vuln/detail/CVE-2026-16149](https://cvefeed.io/vuln/detail/CVE-2026-16149)<br>[https://plugins.trac.wordpress.org/browser/security-hardener/tags/2.4.4/security-hardener.php#L107](https://plugins.trac.wordpress.org/browser/security-hardener/tags/2.4.4/security-hardener.php#L107)<br>[https://plugins.trac.wordpress.org/browser/security-hardener/tags/2.4.4/security-hardener.php#L180](https://plugins.trac.wordpress.org/browser/security-hardener/tags/2.4.4/security-hardener.php#L180)<br>[https://plugins.trac.wordpress.org/browser/security-hardener/tags/2.4.4/security-hardener.php#L204](https://plugins.trac.wordpress.org/browser/security-hardener/tags/2.4.4/security-hardener.php#L204)<br>[https://plugins.trac.wordpress.org/browser/security-hardener/tags/2.4.4/security-hardener.php#L428](https://plugins.trac.wordpress.org/browser/security-hardener/tags/2.4.4/security-hardener.php#L428)<br>[https://plugins.trac.wordpress.org/browser/security-hardener/tags/2.4.4/security-hardener.php#L433](https://plugins.trac.wordpress.org/browser/security-hardener/tags/2.4.4/security-hardener.php#L433)<br>[https://plugins.trac.wordpress.org/browser/security-hardener/tags/2.4.4/security-hardener.php#L439](https://plugins.trac.wordpress.org/browser/security-hardener/tags/2.4.4/security-hardener.php#L439)<br>[https://plugins.trac.wordpress.org/changeset/3630896/security-hardener](https://plugins.trac.wordpress.org/changeset/3630896/security-hardener)<br>[https://www.wordfence.com/threat-intel/vulnerabilities/id/64f1a71f-e210-4191-bfb4-56f8568180ed?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/64f1a71f-e210-4191-bfb4-56f8568180ed?source=cve) |
| **CVE-2026-0551** | 8.8 | N/A | FALSE | PPWP – Password Protect Pages plugin pour WordPress versions <= 1.9.18 | Injection d'objet PHP / Désérialisation de données non fiables (CWE-502) | Un attaquant authentifié (Contributor+) peut injecter un objet PHP via désérialisation. L'impact dépend de la présence d'une POP chain dans un autre plugin ou thème : suppression de fichiers arbitraires, exfiltration de données ou exécution de code à distance. Le score CVSS 3.1 est de 8.8 (HIGH) avec un vecteur d'exploitabilité de 2.8 et un impact de 5.9. | Theoretical | Mettre à jour le plugin PPWP vers une version supérieure à 1.9.18. Examiner les plugins et thèmes installés pour identifier d'éventuelles POP chains. Référence : hxxps://plugins[.]trac[.]wordpress[.]org/changeset/3567221/password-protect-page. | [https://cvefeed.io/vuln/detail/CVE-2026-0551](https://cvefeed.io/vuln/detail/CVE-2026-0551)<br>[https://plugins.trac.wordpress.org/browser/password-protect-page/trunk/includes/services/class-ppw-passwords.php#L699](https://plugins.trac.wordpress.org/browser/password-protect-page/trunk/includes/services/class-ppw-passwords.php#L699)<br>[https://plugins.trac.wordpress.org/changeset/3567221/password-protect-page](https://plugins.trac.wordpress.org/changeset/3567221/password-protect-page)<br>[https://www.wordfence.com/threat-intel/vulnerabilities/id/b8f53282-740e-4ac3-a2e1-7a97893e3355?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/b8f53282-740e-4ac3-a2e1-7a97893e3355?source=cve) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="google-cloud-compute-et-cloud-ops-agent-ce-qui-compte-vraiment-pour-le-dfir"></div>

## Google Cloud Compute et Cloud Ops Agent — Ce qui compte vraiment pour le DFIR

### Résumé

L'article détaille les pratiques de forensique numérique et de réponse à incident (DFIR) dans l'environnement Google Cloud, en se concentrant sur les services de type Compute. Il distingue trois catégories : IaaS (Compute Engine, Shielded VMs) offrant une visibilité forensique maximale au niveau OS, PaaS (App Engine, GKE, Cloud Run) avec des logs mais peu d'évidence au niveau hôte, et FaaS (Cloud Functions, Cloud Workflows) fonctionnant comme une boîte noire avec des logs mais quasiment aucune visibilité disque/mémoire. L'article utilise un cas pratique : une alerte de facturation détecte un pic d'usage Compute Engine inattendu sur un projet nommé fernbridge-prod, révélant des VMs nouvellement créées par un acteur non autorisé. La procédure de capture d'évidence cloud est décrite : snapshot du disque persistant, partage avec un projet DFIR, conversion en disque, attachement en lecture seule à une VM forensique. Les configurations VM spécifiques sont abordées : les GPUs (utiles pour le traitement forensique accéléré), les VMs préemptibles (dont la disparition soudaine peut créer des trous dans les logs), et les Shielded VMs (Secure Boot, vTPM, monitoring d'intégrité).

---

### Analyse opérationnelle

Les équipes SOC/DFIR doivent adapter leurs pratiques forensiques au modèle cloud. Pour Compute Engine, les snapshots remplacent l'imagerie disque traditionnelle et permettent une analyse forensique complète au niveau OS. Les VMs préemptibles peuvent créer de fausses lacunes dans les logs — il faut distinguer une réclamation Google d'une suppression malveillante. Les Shielded VMs génèrent des logs d'intégrité supplémentaires à intégrer dans le triage. La détection repose fortement sur Cloud Audit Logs (création de VMs) et les alertes de facturation. Les équipes doivent préparer un projet forensique séparé avec les permissions IAM appropriées pour recevoir et analyser les snapshots. La surface d'attaque inclut le provisioning non autorisé de VMs, potentiellement pour du cryptojacking ou comme point de pivot.

---

### Implications stratégiques

La migration cloud transforme les pratiques DFIR : les compétences traditionnelles doivent s'adapter aux API et modèles de partage cloud. L'absence de visibilité hôte sur PaaS/FaaS crée des angles morts forensiques que les organisations doivent compenser par une instrumentation applicative renforcée. Le coût d'investigation cloud (snapshots, VMs forensiques, stockage) doit être budgété. La gouvernance IAM devient critique : un compromis d'identité permettant la création de VMs ouvre la porte à des coûts non maîtrisés et à des exfiltrations. Les organisations multi-cloud doivent harmoniser leurs runbooks DFIR (AWS, Azure, GCP) tout en adaptant les spécificités de chaque fournisseur.

---

### Recommandations

* Maintenir un projet GCP forensique dédié avec VM d'analyse préconfigurée
* Automatiser la création de snapshots et leur partage inter-projet via scripts
* Surveiller activement les alertes de facturation comme signal de détection précoce
* Restreindre les permissions IAM de création de VMs au strict nécessaire
* Documenter les différences forensiques entre IaaS, PaaS et FaaS pour guider les investigations

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un projet GCP forensique dédié avec VM d'analyse préconfigurée (Linux/Windows)
* Préparer des scripts d'automatisation pour snapshot/clone de disques persistants
* Documenter les permissions IAM nécessaires pour accès inter-projet en lecture
* Établir des runbooks spécifiques par type de compute (IaaS, PaaS, FaaS)

#### Phase 2 — Détection et analyse

* Surveiller les alertes de facturation anormales (spikes d'usage Compute Engine)
* Configurer Cloud Audit Logs pour détecter la création de VMs non autorisées
* Mettre en place des alertes sur provisioning de VMs en dehors des heures ouvrées
* Corréler les logs VPC Flow avec les nouvelles instances pour détecter des connexions C2

#### Phase 3 — Confinement, éradication et récupération

* Snapshot immédiat du disque persistant de la VM suspecte
* Isolation réseau de la VM (tags réseau, règles firewall) sans éteindre l'instance
* Partager le snapshot avec le projet forensique dédié
* Vérifier si des Shielded VMs sont impliquées (logs d'intégrité additionnels)

#### Phase 4 — Activités post-incident

* Convertir le snapshot en disque et l'attacher en lecture seule à une VM forensique
* Analyser les artefacts OS-level (logs, processus, utilisateurs, cron jobs)
* Documenter la chaîne d'événements depuis le provisioning jusqu'à la détection
* Mettre à jour les politiques IAM pour restreindre la création de VMs

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des VMs préemptibles créées puis supprimées (trous dans les logs)
* Auditer tous les projets pour des configurations similaires à l'incident
* Chercher des patterns de création/destruction rapides de VMs (cryptojacking)
* Vérifier les images personnalisées utilisées pour le provisioning suspect

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `access[.]in` | Low |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1087** | Account Discovery - découverte de comptes lors d'investigations forensiques cloud |
| **T1057** | Process Discovery - analyse des processus lors d'investigations sur VM |

---

### Sources

* [https://www.cyberengage.org/post/google-cloud-compute-and-cloud-ops-agent-what-actually-matters-for-dfir](https://www.cyberengage.org/post/google-cloud-compute-and-cloud-ops-agent-what-actually-matters-for-dfir)


---

<div id="securite-supply-chain-ne-pas-tenir-lintegrite-des-packages-pour-acquise"></div>

## Sécurité Supply Chain : Ne pas tenir l'intégrité des packages pour acquise

### Résumé

Un message de sensibilisation publié par CVEDatabase[.]com rappelle que les attaques sur la chaîne d'approvisionnement ciblent fréquemment la phase de distribution. Si un miroir de téléchargement est compromis, un attaquant peut substituer un package légitime par une version backdoorée. Le message recommande de toujours vérifier les checksums SHA-256 et les signatures GPG fournies par les développeurs officiels, et d'intégrer cette vérification dans les pipelines CI/CD comme couche de défense critique.

---

### Analyse opérationnelle

Les équipes SOC et DevSecOps doivent traiter la vérification d'intégrité des packages comme un contrôle obligatoire et non optionnel. L'absence de vérification de checksum/signature dans un pipeline CI/CD constitue une surface d'attaque exploitable par des acteurs menaçant via des techniques de compromission supply chain (T1195). La détection nécessite de corréler les échecs de vérification de hash avec des alertes de sécurité. Les équipes doivent maintenir un inventaire des sources de téléchargement approuvées et alerter sur tout téléchargement depuis un miroir non répertorié. Les pipelines CI/CD doivent bloquer automatiquement tout package dont la signature ou le checksum ne correspond pas.

---

### Implications stratégiques

Les attaques supply chain (SolarWinds, Codecov, npm) ont démontré que la chaîne d'approvisionnement logicielle est un vecteur stratégique privilégié. Les organisations doivent adopter une approche zero-trust vis-à-vis des dépendances externes. L'investissement dans des outils de SBOM (Software Bill of Materials) et de vérification automatisée d'intégrité devient un requirement réglementaire dans plusieurs juridictions. Le risque organisationnel inclut la compromission de l'ensemble de l'infrastructure via un seul package backdooré, avec des conséquences potentielles sur la continuité business et la conformité.

---

### Recommandations

* Intégrer la vérification SHA-256 et GPG comme étape bloquante dans tous les pipelines CI/CD
* Maintenir un registre approuvé des miroirs et sources de téléchargement
* Implémenter un SBOM pour cartographier toutes les dépendances et leurs origines
* Surveiller les alertes des gestionnaires de packages (npm audit, safety, pip-audit)
* Former les équipes de développement aux risques supply chain et aux bonnes pratiques de vérification

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire à jour de tous les packages et leurs sources officielles
* Stocker de manière sécurisée les clés GPG des éditeurs de confiance
* Intégrer la vérification SHA-256 et GPG dans les pipelines CI/CD comme étape obligatoire
* Documenter les procédures de vérification d'intégrité pour chaque dépendance critique

#### Phase 2 — Détection et analyse

* Mettre en place des alertes sur échec de vérification de checksum dans le pipeline CI/CD
* Surveiller les changements de miroirs de téléchargement et de métadonnées de packages
* Corréler les alertes de sécurité des gestionnaires de packages (npm audit, pip-audit, etc.)
* Détecter les packages installés en dehors des canaux officiels

#### Phase 3 — Confinement, éradication et récupération

* Isoler les systèmes ayant installé des packages depuis un miroir compromis
* Bloquer les miroirs de téléchargement compromis au niveau réseau (proxy, firewall)
* Supprimer et réinstaller les packages affectés depuis une source vérifiée
* Suspendre les déploiements CI/CD jusqu'à validation de l'intégrité des dépendances

#### Phase 4 — Activités post-incident

* Effectuer une analyse forensique des packages compromis pour identifier d'éventuelles backdoors
* Rotations des credentials et tokens présents sur les systèmes affectés
* Auditer l'ensemble des dépendances installées sur l'infrastructure
* Renforcer les contrôles d'intégrité dans les pipelines CI/CD (signature obligatoire, politiques d'admission)

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des packages installés sans vérification de checksum à travers tout le parc
* Analyser l'historique des téléchargements pour identifier des patterns d'empoisonnement
* Surveiller les registres de packages internes pour des modifications non autorisées
* Chercher des indicateurs de compromission liés à des campagnes de supply chain connues

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `cvedatabase[.]com` | Low |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1195** | Supply Chain Compromise - compromission de la chaîne d'approvisionnement logicielle |
| **T1195.002** | Compromise Software Supply Chain - compromission via miroir de téléchargement ou package modifié |
| **T1027** | Obfuscated Files or Information - backdoor potentiellement masqué dans un package compromis |

---

### Sources

* [https://techhub.social/@cvedatabase/117147186067751595](https://techhub.social/@cvedatabase/117147186067751595)


---

<div id="fuite-de-donnees-nius-niusde-6-000-enregistrements-compromis"></div>

## Fuite de données NIUS (nius[.]de) — ~6 000 enregistrements compromis

### Résumé

BeeSINT rapporte une fuite de données vérifiée affectant NIUS (nius[.]de), un site d'actualité en ligne. Environ 6 000 enregistrements ont été compromis, incluant des numéros de comptes bancaires, des adresses email, des noms, et des données partielles de cartes de crédit, ainsi que deux autres catégories de données non précisées. L'incident date du 13 juillet 2025 et a été divulgué 406 jours après l'événement. L'infrastructure du site utilise Cloudflare. Aucune configuration SPF/DMARC n'était en place au moment de la divulgation.

---

### Analyse opérationnelle

La fuite expose des données financières sensibles (numéros de comptes bancaires, données CB partielles) et des PII (noms, emails). L'absence de SPF/DMARC augmente le risque d'exploitation post-fuite via du phishing ciblé usurpant l'identité de niu[.]de. Le délai de divulgation de 406 jours suggère soit une détection tardive, soit une divulgation retardée. Les équipes SOC doivent surveiller l'utilisation des données exfiltrées (credentials, emails) dans des campagnes de phishing ou de credential stuffing. La présence de Cloudflare suggère que l'attaquant a pu exploiter une vulnérabilité applicative ou des credentials valides pour contourner la protection WAF.

---

### Implications stratégiques

Cette fuite illustre les risques auxquels sont exposés les sites médias : stockage de données abonnés (incluant des données de paiement) avec des configurations de sécurité insuffisantes (absence de SPF/DMARC). Le délai de divulgation de plus d'un an pose la question de la détection et de la transparence. L'exposition de données bancaires et de cartes de crédit expose l'organisation à des risques juridiques (RGPD, DSP2) et de réputation. La tendance des attaques contre les plateformes médias se confirme, motivée par la valeur des données d'abonnés payants sur les marchés illicites.

---

### Recommandations

* Configurer immédiatement SPF, DMARC et DKIM sur le domaine nius[.]de
* Mener un audit de sécurité complet des systèmes stockant les données de paiement
* Implémenter une détection d'exfiltration de données (DLP) sur les bases de données clients
* Notifier les autorités de protection des données et les individus affectés selon les obligations RGPD
* Surveiller les marchés illicites pour détecter la revente ou l'exploitation des données exfiltrées

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire des données PII stockées et de leur localisation
* Préparer des templates de notification de violation (RGPD, autorités de protection des données)
* Établir des procédures de rotation de credentials et de blocage d'accès
* Disposer d'une équipe de réponse à violation prête à intervenir

#### Phase 2 — Détection et analyse

* Surveiller les fuites de données sur les forums, marketplaces dark web et plateformes OSINT
* Configurer des alertes sur des accès anormaux aux bases de données contenant des PII
* Détecter des exfiltrations via Cloudflare ou autres CDN (anomalies de trafic)
* Mettre en place des règles de détection pour des accès massifs à des données clients

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les accès compromis et rotation immédiate de tous les credentials
* Isoler les systèmes stockant les données PII affectées
* Configurer SPF/DMARC pour prévenir l'usurpation d'identité par email
* Notifier les autorités de protection des données dans les délais réglementaires (72h RGPD)

#### Phase 4 — Activités post-incident

* Mener une investigation forensique pour identifier le vecteur d'entrée et l'étendue de la fuite
* Notifier les individus affectés (noms, emails, données bancaires, données CB partielles)
* Mettre en place une surveillance de crédit pour les victimes
* Auditer la configuration de sécurité (SPF/DMARC, Cloudflare, accès aux bases de données)

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des accès suspects aux bases de données dans les logs antérieurs à la détection
* Surveiller le dark web et les plateformes OSINT pour des fuites de données supplémentaires
* Vérifier si d'autres propriétés ou sous-domaines sont affectés
* Chercher des indicateurs de persistance ou d'accès continu après la fuite initiale

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `nius[.]de` | High |
| DOMAIN | `beesint[.]com` | Low |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078** | Valid Accounts - utilisation potentielle de comptes compromis pour accéder aux données |
| **T1567** | Exfiltration Over Web Service - exfiltration des données via un service web |
| **T1589** | Gather Victim Identity Information - collecte d'informations d'identité (noms, emails, données bancaires) |
| **T1530** | Data from Cloud Storage Object - données potentiellement stockées derrière Cloudflare |

---

### Sources

* [https://mastodon.social/@BeeSINT/117147172974427621](https://mastodon.social/@BeeSINT/117147172974427621)


---

<div id="failles-logiques-et-correctifs-pour-les-regles-de-detection-curees-de-google-secops-chronicle-o365-ueba"></div>

## Failles logiques et correctifs pour les règles de détection curées de Google SecOps (Chronicle) - O365 & UEBA

### Résumé

Un post publié sur r/blueteamsec discute des failles logiques identifiées dans les règles de détection curées de Google SecOps (Chronicle) pour Office 365 et UEBA, ainsi que des correctifs proposés pour ces règles.

---

### Analyse opérationnelle

Les failles logiques dans les règles de détection curées de Google SecOps peuvent entraîner des faux positifs, des faux négatifs ou des détections manquées pour les menaces O365 et UEBA. Les équipes SOC utilisant Chronicle doivent auditer leurs règles importées, vérifier la logique YARA-L, et appliquer les correctifs suggérés pour maintenir une couverture de détection efficace. Une revue systématique des règles curées est nécessaire avant déploiement en production.

---

### Implications stratégiques

La dépendance aux règles de détection pré-construites sans validation approfondie expose les organisations à des angles morts de détection. Cette problématique souligne l'importance d'une gouvernance rigoureuse des règles SIEM/XDR et de l'investissement continu dans le tuning des détections. Les équipes SOC doivent équilibrer rapidité de déploiement et qualité des règles.

---

### Recommandations

* Auditer toutes les règles de détection curées importées dans Google SecOps / Chronicle
* Mettre en place un processus de validation des règles avant déploiement en production
* Suivre les publications de la communauté blueteamsec pour les correctifs de règles
* Établir des métriques de qualité des détections (taux de faux positifs, couverture TTP)

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier l'ensemble des règles de détection curées Google SecOps (Chronicle) déployées dans l'environnement
* Identifier les règles O365 et UEBA spécifiquement mentionnées dans le post
* Mettre en place un processus formel de revue périodique des règles de détection importées

#### Phase 2 — Détection et analyse

* Comparer la logique des règles curées avec les comportements attendus et les TTPs couverts
* Identifier les faux positifs et faux négatifs générés par les règles défectueuses
* Mettre en place des alertes de qualité sur les détections produites par les règles suspectées

#### Phase 3 — Confinement, éradication et récupération

* Désactiver ou corriger immédiatement les règles produisant des faux négatifs critiques (menaces non détectées)
* Ajuster le seuil de sévérité des règles défectueuses en attendant le correctif
* Documenter les règles corrigées et leur nouvelle logique

#### Phase 4 — Activités post-incident

* Appliquer les correctifs publiés par la communauté pour les règles O365 et UEBA
* Mettre en place un processus de validation systématique avant importation de nouvelles règles curées
* Documenter les leçons apprises et partager avec l'équipe SOC

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétroactivement les IOCs et TTPs qui auraient pu être manqués à cause des failles logiques
* Effectuer une chasse sur les comportements UEBA anormaux non détectés par les règles défectueuses
* Corréler avec les alertes de sécurité O365 pour identifier les activités malveillantes potentiellement manquées

---

### Sources

* [https://www.reddit.com/r/blueteamsec/comments/1vw2g9h/logic_flaws_fixes_for_google_secops_chronicle/](https://www.reddit.com/r/blueteamsec/comments/1vw2g9h/logic_flaws_fixes_for_google_secops_chronicle/)


---

<div id="la-patch-kb5121003-de-windows-11-provoque-des-crashes-dans-les-jeux-video"></div>

## La patch KB5121003 de Windows 11 provoque des crashes dans les jeux vidéo

### Résumé

La mise à jour de sécurité KB5121003 pour Windows 11 provoque des crashes dans les jeux vidéo et des problèmes avec les imprimantes. Cela crée un dilemme entre l'application immédiate des correctifs de sécurité et la stabilité du système.

---

### Analyse opérationnelle

Les équipes IT doivent évaluer l'impact de la KB5121003 avant déploiement massif. Recommandation de tester en environnement de pré-production, en particulier pour les postes utilisant des applications graphiques ou des jeux. Maintenir un processus de rollback rapide via wusa /uninstall. Surveiller les canaux de télémétrie Windows (Event Viewer, WER) pour détecter les crashs post-patch. Le report du patch laisse une surface d'attaque ouverte, nécessitant des contrôles compensatoires.

---

### Implications stratégiques

Ce type d'incident illustre le compromis permanent entre sécurité et stabilité opérationnelle. Les organisations doivent disposer d'une stratégie de patch management par paliers (ring deployment) pour minimiser l'impact sur la productivité tout en réduisant la surface d'attaque. La communication entre équipes sécurité et IT est essentielle pour gérer ces trade-offs.

---

### Recommandations

* Tester la KB5121003 en environnement de pré-production avant déploiement large
* Mettre en place un déploiement par paliers (canary group → pilot group → production)
* Préparer un script de rollback automatisé pour désinstallation rapide
* Documenter les applications impactées et communiquer aux utilisateurs

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les postes Windows 11 concernés par le déploiement de la KB5121003
* Identifier les applications critiques potentiellement impactées (jeux, applications graphiques, pilotes d'impression)
* Préparer un plan de rollback et des images système de référence

#### Phase 2 — Détection et analyse

* Surveiller les événements de crash applicatif post-déploiement (Event ID 1000 Application Error, 1001 Windows Error Reporting)
* Détecter les pics de tickets helpdesk liés aux crashes de jeux ou problèmes d'impression
* Mettre en place des alertes sur les redémarrages inattendus de postes patchés

#### Phase 3 — Confinement, éradication et récupération

* Suspendre le déploiement de la KB5121003 sur les postes non encore patchés
* Désinstaller la KB5121003 sur les postes impactés via wusa /uninstall
* Communiquer aux utilisateurs sur la situation et les workarounds temporaires

#### Phase 4 — Activités post-incident

* Documenter l'impact de la KB5121003 sur le parc
* Établir un calendrier de redéploiement une fois un correctif Microsoft disponible
* Mettre à jour la politique de patch management avec des critères de validation applicative

#### Phase 5 — Threat Hunting (proactif)

* Vérifier qu'aucun acteur malveillant n'a exploité le délai de patching pour cibler des postes non mis à jour
* Rechercher des activités suspectes sur les postes où la KB5121003 a été désinstallée (surface d'attaque réouverte)
* Corréler les désinstallations de patchs avec des indicateurs de compromission

---

### Sources

* [https://mastobot.ping.moi/@Bobe_bot/117147068866236846](https://mastobot.ping.moi/@Bobe_bot/117147068866236846)


---

<div id="parsedmarc-un-outil-open-source-pour-analyser-les-rapports-dmarc"></div>

## parsedmarc — Un outil open source pour analyser les rapports DMARC

### Résumé

parsedmarc est un package Python et un outil CLI pour parser les rapports DMARC agrégés (RUA) et forensiques (RUF), les transformant en données exploitables. L'outil permet de visualiser l'alignement SPF/DKIM à grande échelle et d'améliorer la posture de sécurité email d'un domaine.

---

### Analyse opérationnelle

parsedmarc permet aux équipes SOC et IT d'automatiser l'analyse des rapports DMARC, d'identifier les sources d'usurpation d'identité email, et de visualiser l'alignement SPF/DKIM. Intégration possible avec ELK/Splunk/Grafana pour la visualisation. Permet de détecter les tentatives de spoofing et d'affiner progressivement les politiques DMARC (de none vers quarantine/reject). L'outil fournit une visibilité indispensable sur le flux email entrant et sortant.

---

### Implications stratégiques

Le DMARC est devenu un standard de facto pour la sécurisation de l'email. Disposer d'outils d'analyse automatisés permet aux organisations de durcir leur posture email security, de réduire le risque de BEC et de phishing, et de répondre aux exigences réglementaires croissantes en matière d'authentification email. L'investissement dans ce type d'outillage est un levier de réduction de risque à fort ROI.

---

### Recommandations

* Déployer parsedmarc et configurer la collecte des rapports RUA/RUF
* Intégrer les données parsedmarc dans le SIEM pour corrélation avec les alertes phishing
* Établir une feuille de route de durcissement DMARC : monitoring → quarantine → reject
* Surveiller les nouveaux services d'envoi email tiers pour mise à jour SPF/DKIM

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Vérifier que les enregistrements DMARC (RUA/RUF) sont configurés pour tous les domaines propriétaires
* Déployer parsedmarc sur un serveur dédié avec accès aux boîtes de réception de rapports DMARC
* Configurer l'intégration avec ELK/Splunk/Grafana pour la visualisation des données

#### Phase 2 — Détection et analyse

* Collecter et parser automatiquement les rapports DMARC agrégés (RUA) et forensiques (RUF)
* Identifier les sources d'envoi non autorisées (échec SPF/DKIM) et les tentatives d'usurpation
* Mettre en place des alertes sur les pics d'échecs d'authentification email

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les sources d'envoi non autorisées identifiées via les rapports DMARC
* Ajuster la politique DMARC de none vers quarantine puis reject de manière progressive
* Notifier les fournisseurs de services email tiers dont les envois échouent l'alignement

#### Phase 4 — Activités post-incident

* Documenter les sources légitimes et illégitimes d'envoi email identifiées
* Affiner les enregistrements SPF et DKIM pour couvrir toutes les sources légitimes
* Mettre en place un processus de revue périodique des rapports DMARC

#### Phase 5 — Threat Hunting (proactif)

* Corréler les échecs DMARC avec les campagnes de phishing ou BEC identifiées
* Rechercher des patterns d'usurpation ciblant des domaines similaires (typosquatting)
* Identifier les adresses IP sources récurrentes dans les échecs DMARC pour blocage proactif

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing - visibilité sur l'usurpation d'identité email via rapports DMARC |

---

### Sources

* [https://kitploit.com/en/tools/github/domainaware/parsedmarc](https://kitploit.com/en/tools/github/domainaware/parsedmarc)


---

<div id="campagne-bec-avec-agent-tesla-v4-cache-dans-un-fichier-jscript-rempli-demoji"></div>

## Campagne BEC avec Agent Tesla v4 caché dans un fichier JScript rempli d'emoji

### Résumé

Les chercheurs de KnowBe4 ont identifié une campagne de compromission d'email professionnel (BEC) ciblant le personnel financier avec une fausse demande urgente de confirmation d'un document bancaire. La pièce jointe JScript de 6,94 Mo, nommée 'SWIFT Payment Maker 103 - 10.06.26.JS', usurpe l'identité de Metropolitan Bank and Trust Company et cache le code d'Agent Tesla v4 derrière de grandes quantités d'emoji Unicode. Windows Script Host ignore ces caractères lors de l'analyse JScript.

---

### Analyse opérationnelle

Détection : surveiller les emails avec pièces jointes .JS de grande taille (>5 Mo), bloquer les fichiers JScript via règles de transport email, activer AMSI pour JScript. L'obfuscation par emoji Unicode nécessite des règles de détection spécifiques au-delà des signatures classiques. Surveiller l'exécution de wscript.exe/cscript.exe avec des fichiers de grande taille. Agent Tesla v4 exfiltre via SMTP/FTP/HTTP — surveiller les connexions C2 sortantes inhabituelles depuis les postes finance. Le nom de fichier 'SWIFT Payment Maker 103 - 10.06.26.JS' est un indicateur de compromission à bloquer.

---

### Implications stratégiques

Cette campagne illustre l'évolution des techniques d'obfuscation des menaces par email, ciblant spécifiquement les départements financiers. Les organisations du secteur bancaire et financier sont particulièrement exposées. L'usurpation d'identité SWIFT/bancaire souligne l'importance de la formation de sensibilisation et des contrôles techniques multi-couches pour les équipes finance. La technique d'obfuscation par emoji Unicode montre que les attaquants adaptent leurs méthodes pour contourner les sandbox et les gateways email traditionnels.

---

### Recommandations

* Bloquer tous les fichiers .JS/.JScript au niveau de la passerelle email
* Surveiller wscript.exe/cscript.exe avec des fichiers de grande taille (>5 Mo)
* Former le personnel finance à la détection des emails BEC usurpant des institutions bancaires
* Déployer des règles de détection spécifiques pour l'obfuscation par emoji Unicode dans les scripts
* Surveiller les connexions C2 sortantes Agent Tesla (SMTP/FTP/HTTP non standard)

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Former le personnel financier à la détection des emails BEC usurpant des institutions bancaires
* Bloquer les fichiers .JS/.JScript au niveau des passerelles email (règles de transport)
* Activer AMSI pour les scripts JScript et surveiller wscript.exe/cscript.exe
* Maintenir une liste blanche stricte des scripts autorisés à s'exécuter sur les postes finance

#### Phase 2 — Détection et analyse

* Surveiller les emails avec pièces jointes .JS de grande taille (>5 Mo) - indicateur d'obfuscation par emoji
* Détecter l'exécution de wscript.exe/cscript.exe avec des fichiers JScript de grande taille
* Surveiller les connexions réseau sortantes inhabituelles depuis les postes du département finance (C2 Agent Tesla via SMTP/FTP/HTTP)
* Analyser les emails usurpant Metropolitan Bank and Trust Company ou utilisant le nom de fichier 'SWIFT Payment Maker 103 - 10.06.26.JS'

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les postes ayant exécuté le fichier JScript malveillant
* Bloquer les adresses IP et domaines C2 d'Agent Tesla identifiés
* Supprimer les emails de phishing de toutes les boîtes aux lettres via purge centralisée
* Réinitialiser les identifiants stockés sur les postes compromis (navigateurs, clients mail, applications locales)

#### Phase 4 — Activités post-incident

* Effectuer une analyse forensique complète du poste compromis pour identifier l'étendue de l'exfiltration
* Vérifier si des identifiants bancaires ou SWIFT ont été compromis
* Notifier les institutions financières concernées en cas de fraude avérée
* Mettre à jour les règles de détection avec les IOCs de cette campagne

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétroactivement d'autres emails avec des pièces jointes JScript de grande taille dans les 30-90 derniers jours
* Chercher des processus wscript.exe/cscript.exe avec des arguments suspects ou des fichiers de grande taille
* Corréler les connexions sortantes vers des serveurs SMTP/FTP inconnus avec l'activité de wscript.exe
* Rechercher d'autres variantes d'Agent Tesla utilisant des techniques d'obfuscation similaires (emoji, Unicode)

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxps://en[.]hacks[.]gr/kampania-bec-me-trapeziko-email-kryvei-ton-agent-tesla-se-archeio-jscript-gemato-emoji/` | Low |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.001** | Spearphishing Attachment - pièce jointe JScript envoyée par email |
| **T1059.005** | Command and Scripting Interpreter: Visual Basic - exécution JScript via Windows Script Host |
| **T1027** | Obfuscated Files or Information - code Agent Tesla caché derrière des emoji Unicode |
| **T1005** | Data from Local System - Agent Tesla collecte les identifiants et données locales |
| **T1041** | Exfiltration Over C2 Channel - Agent Tesla exfiltre via SMTP/FTP/HTTP |

---

### Sources

* [https://en.hacks.gr/kampania-bec-me-trapeziko-email-kryvei-ton-agent-tesla-se-archeio-jscript-gemato-emoji/](https://en.hacks.gr/kampania-bec-me-trapeziko-email-kryvei-ton-agent-tesla-se-archeio-jscript-gemato-emoji/)


---

<div id="page-de-phishing-hebergee-sur-github-pages-ciblant-ionos"></div>

## Page de phishing hébergée sur GitHub Pages ciblant IONOS

### Résumé

Une page de phishing imitant IONOS a été identifiée, hébergée sur GitHub Pages via un chemin d'URL imbriqué. L'URL hxxps://shakugxgd[.]github[.]io/jgjuybrdhim[.]github[.]io/IONOSDE[.]html a été signalée pour analyse par urldna.io.

---

### Analyse opérationnelle

Bloquer l'URL hxxps://shakugxgd[.]github[.]io/jgjuybrdhim[.]github[.]io/IONOSDE[.]html au niveau des proxies web et des passerelles email. Surveiller les accès sortants vers github[.]io avec des chemins d'URL suspects. Les pages de phishing hébergées sur GitHub Pages bénéficient de la réputation du domaine github.io, contournant potentiellement certains filtres de réputation URL. Vérifier si des identifiants IONOS ont été compromis via cette page et procéder à des réinitialisations de mots de passe si nécessaire.

---

### Implications stratégiques

L'abus de plateformes légitimes comme GitHub Pages pour l'hébergement de phishing est une tendance croissante. Les organisations doivent sensibiliser leurs utilisateurs aux URL même lorsqu'elles proviennent de domaines de confiance. Les fournisseurs de services doivent collaborer avec GitHub pour le retrait rapide de ce type de contenu. La confiance accordée aux domaines légitimes crée une surface d'attaque difficile à maîtriser par les contrôles traditionnels.

---

### Recommandations

* Bloquer l'URL identifiée sur tous les points de contrôle réseau
* Signaler la page à GitHub pour retrait rapide
* Surveiller les accès vers github[.]io avec des chemins d'URL contenant des noms de marques
* Renforcer la formation anti-phishing en incluant les scénarios de phishing sur domaines légitimes

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Bloquer les domaines github[.]io avec des chemins d'URL suspects au niveau des proxies web
* Former les utilisateurs à la détection de phishing même sur des domaines de réputation (github.io)
* Mettre en place des règles de prévention de credential harvesting sur les passerelles web

#### Phase 2 — Détection et analyse

* Bloquer l'URL hxxps://shakugxgd[.]github[.]io/jgjuybrdhim[.]github[.]io/IONOSDE[.]html au niveau des proxies et firewalls
* Surveiller les accès sortants vers github[.]io avec des chemins d'URL contenant des noms de marque (IONOS, etc.)
* Détecter les soumissions de formulaires vers des pages GitHub Pages suspectes

#### Phase 3 — Confinement, éradication et récupération

* Bloquer l'URL au niveau de tous les points de contrôle (proxy, firewall, DNS, email gateway)
* Signaler la page de phishing à GitHub pour retrait (abuse@github[.]com)
* Vérifier si des identifiants IONOS ont été soumis via cette page et réinitialiser les comptes concernés

#### Phase 4 — Activités post-incident

* Documenter la page de phishing et ses indicateurs
* Vérifier si d'autres pages similaires existent sur GitHub Pages (même pattern d'URL)
* Mettre à jour les listes de blocage avec les IOCs identifiés
* Notifier IONOS de l'usurpation de leur marque

#### Phase 5 — Threat Hunting (proactif)

* Rechercher d'autres pages de phishing hébergées sur github[.]io avec des patterns d'URL similaires (chemins imbriqués, noms de marques)
* Corréler les accès vers github[.]io avec des soumissions de formulaires suspectes
* Surveiller les nouveaux dépôts GitHub créés avec des noms aléatoires pouvant héberger du phishing

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxps://shakugxgd[.]github[.]io/jgjuybrdhim[.]github[.]io/IONOSDE[.]html` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Spearphishing Link - page de phishing diffusée via lien |
| **T1583.006** | Acquire Infrastructure: Web Services - abus de GitHub Pages pour l'hébergement |
| **T1189** | Drive-by Compromise - page de phishing pour vol d'identifiants |

---

### Sources

* [https://infosec.exchange/@urldna/117146714681334464](https://infosec.exchange/@urldna/117146714681334464)


---

<div id="recapitulatif-hebdomadaire-des-violations-de-donnees-17-au-23-aout-2026"></div>

## Récapitulatif hebdomadaire des violations de données - 17 au 23 août 2026

### Résumé

Nick Espinosa présente un récapitulatif hebdomadaire des violations de données couvrant 297 incidents au total, incluant ASCII Group, Sears, Kingston et Columbia University. La vidéo couvre la période du 17 au 23 août 2026.

---

### Analyse opérationnelle

297 incidents en une semaine indiquent un volume élevé d'activité malveillante. Les équipes SOC doivent vérifier si leur organisation ou ses partenaires/tiers sont mentionnés dans ces incidents. Surveiller les exfiltrations de données et les activités ransomware. Vérifier la présence de données d'organisation sur les forums dark web. Les secteurs touchés (retail avec Sears, éducation avec Columbia University, technologie avec Kingston et ASCII Group) suggèrent une large surface d'attaque multi-sectorielle.

---

### Implications stratégiques

Le volume de 297 incidents hebdomadaires souligne l'ampleur continue du risque de violation de données. Les organisations doivent maintenir une veille threat intelligence active, évaluer l'exposition de leurs tiers et fournisseurs (supply chain risk), et renforcer les programmes de cyber-résilience. Les secteurs retail et éducation restent des cibles privilégiées. La diversité des organisations touchées (MSP, retail, hardware, université) montre qu'aucun secteur n'est épargné.

---

### Recommandations

* Vérifier si l'organisation ou ses tiers sont mentionnés dans les 297 incidents
* Maintenir une veille dark web pour détecter des fuites de données organisationnelles
* Évaluer l'exposition supply chain (fournisseurs, partenaires MSP comme ASCII Group)
* Renforcer les contrôles de prévention ransomware (backups, segmentation réseau, EDR)
* Partager les leçons apprises avec les équipes de direction et le conseil d'administration

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire à jour des tiers et partenaires (ASCII Group, Kingston, etc.) pour évaluation d'impact de violation en chaîne
* Mettre en place une veille threat intelligence sur les violations de données publiées
* Préparer des playbooks de réponse pour les scénarios de violation de données et ransomware

#### Phase 2 — Détection et analyse

* Vérifier si l'organisation ou ses partenaires/tiers sont mentionnés dans les 297 incidents de la semaine
* Surveiller les forums dark web et les sites de leak pour des données appartenant à l'organisation
* Détecter les activités anormales pouvant indiquer une intrusion en cours (exfiltration, chiffrement de masse)

#### Phase 3 — Confinement, éradication et récupération

* Si l'organisation est impactée ou liée à un tiers impacté, isoler les systèmes concernés
* Bloquer les IOCs associés aux incidents identifiés
* Notifier les équipes de réponse à incident et activer le plan de continuité d'activité si nécessaire

#### Phase 4 — Activités post-incident

* Analyser les leçons apprises des 297 incidents pour identifier les tendances et vecteurs d'attaque courants
* Mettre à jour les contrôles de sécurité en fonction des TTPs observés dans les incidents
* Communiquer aux parties prenantes sur l'exposition potentielle via les tiers

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des TTPs similaires à ceux utilisés dans les incidents de la semaine (ASCII Group, Sears, Kingston, Columbia University)
* Corréler les indicateurs de ces incidents avec le trafic réseau interne
* Identifier les vecteurs d'attaque émergents et adapter les détections en conséquence

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact - ransomware |
| **T1567** | Exfiltration Over Web Service - exfiltration de données |

---

### Sources

* [https://youtu.be/a_OQYvDwS10](https://youtu.be/a_OQYvDwS10)


---

<div id="lockbit-50-menace-de-publier-des-donnees-volees-a-lentreprise-francaise-actua"></div>

## LockBit 5.0 menace de publier des données volées à l'entreprise française Actua

### Résumé

Le groupe ransomware LockBit 5.0 menace de publier des données attribuées à l'entreprise française Actua, concernant plus de 100 000 personnes. Le groupe affirme détenir des documents sensibles et a fixé une deadline à l'entreprise pour répondre à ses exigences. La publication est annoncée pour la fin du mois d'août 2026.

---

### Analyse opérationnelle

Les équipes SOC doivent surveiller activement les indicateurs de compromission associés à LockBit 5.0 et les sites de fuite du groupe pour détecter toute publication de données. La surface d'attaque de l'organisation Actua doit être auditée pour identifier le vecteur d'intrusion initial (VPN, RDP, phishing, exploitation de vulnérabilités). Les équipes de réponse à incident doivent préparer un plan de containment incluant l'isolation des systèmes potentiellement compromis, la rotation des credentials, et la préservation des preuves forensiques. La détection d'activités d'exfiltration de données volumineuses doit être renforcée via la surveillance des flux réseau sortants et l'analyse des journaux de sécurité.

---

### Implications stratégiques

Cet incident souligne la persistance et la résilience du groupe LockBit malgré les opérations de démantèlement menées par les autorités internationales. L'impact pour Actua est majeur : risque réglementaire RGPD avec notification obligatoire à la CNIL et information des personnes concernées, atteinte à la réputation, et potentielles poursuites civiles. Le secteur français doit anticiper une recrudescence des attaques ransomware ciblant les entreprises détenant des données personnelles massives. La capacité de LockBit 5.0 à maintenir ses opérations démontre l'adaptabilité des groupes criminels et la nécessité d'une posture de défense proactive.

---

### Recommandations

* Vérifier l'intégrité des sauvegardes et leur isolation du réseau principal
* Renforcer l'authentification multifacteur sur tous les accès distants (VPN, RDP, services cloud)
* Mettre en place une surveillance des sites de fuite de LockBit pour détecter toute publication de données
* Préparer un plan de notification RGPD et de communication de crise
* Effectuer un audit de sécurité complet pour identifier le vecteur d'entrée initial

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir des sauvegardes hors ligne et immuables, testées régulièrement
* Établir et maintenir un plan de réponse aux incidents ransomware à jour
* Former les équipes SOC/IT aux TTP spécifiques de LockBit 5.0
* Maintenir un inventaire des actifs critiques et des données sensibles (cartographie RGPD)
* Préparer des modèles de notification CNIL et de communication de crise

#### Phase 2 — Détection et analyse

* Surveiller les indicateurs de compromission associés à LockBit 5.0 (hashs, mutex, persistance)
* Détecter les activités d'exfiltration de données volumineuses (spikes réseau, connexions C2)
* Surveiller les sites de fuite de LockBit pour des annonces concernant l'organisation
* Analyser les journaux d'authentification pour des accès anormaux ou hors heures ouvrées
* Détecter l'utilisation d'outils d'exfiltration type rclone, MEGAsync ou outils personnalisés LockBit

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les systèmes compromis du réseau
* Désactiver et réinitialiser tous les comptes compromis ou suspects
* Bloquer les adresses IP et domaines C2 connus de LockBit au niveau des pare-feu
* Segmenter le réseau pour empêcher la propagation latérale
* Préserver les preuves forensiques avant toute restauration

#### Phase 4 — Activités post-incident

* Restaurer les systèmes depuis des sauvegardes vérifiées et hors ligne
* Mener une analyse forensique complète pour identifier le vecteur d'entrée initial
* Notifier la CNIL dans les 72h conformément au RGPD pour la fuite de données personnelles
* Informer les personnes affectées (>100 000 individus) selon les obligations légales
* Réviser et renforcer les contrôles de sécurité suite aux leçons apprises

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les TTP de LockBit 5.0 dans l'environnement (persistance, exfiltration, chiffrement)
* Chasser les mécanismes de persistance (clés de registre, services, tâches planifiées)
* Identifier les vecteurs d'entrée initiale (phishing, exploitation de VPN, RDP exposé)
* Analyser les mouvements latéraux et l'escalade de privilèges
* Surveiller les forums dark web pour toute fuite ou revente des données exfiltrées

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact |
| **T1567.002** | Exfiltration to Cloud Storage |
| **T1657** | Financial Theft |
| **T1485** | Data Destruction |

---

### Sources

* [https://www.zataz.com/lockbit-5-0-menace-de-publier-des-donnees-dactua/](https://www.zataz.com/lockbit-5-0-menace-de-publier-des-donnees-dactua/)


---

<div id="plus-de-9-300-cles-dacces-aws-actives-publiquement-exposees-hugging-face-identifie-comme-source-principale"></div>

## Plus de 9 300 clés d'accès AWS actives publiquement exposées, Hugging Face identifié comme source principale

### Résumé

Une investigation de Truffle Security a découvert plus de 9 300 clés d'accès AWS actives et publiquement exposées, dont 768 accordant un contrôle administratif complet. Hugging Face a été identifié comme la source principale d'exposition, avec 88% des credentials exposés restant non rotés pendant une médiane de cinq ans. Cette exposition a entraîné des dépenses non autorisées significatives et un manque d'alertes budgétaires chez les organisations affectées.

---

### Analyse opérationnelle

Les équipes SOC et cloud doivent immédiatement auditer leurs dépôts de code et plateformes ML (notamment Hugging Face) pour détecter des clés d'accès AWS exposées. La rotation des credentials compromis doit être prioritaire, en particulier pour les 768 clés à privilèges administratifs. AWS CloudTrail doit être analysé pour détecter toute utilisation non autorisée des clés exposées, notamment des créations de ressources ou des élévations de privilèges. Les équipes doivent mettre en place des scans automatisés de secrets (TruffleHog, GitLeaks) dans les pipelines CI/CD et configurer des alertes budgétaires AWS pour détecter les dépenses anormales. La surface d'attaque cloud s'étend désormais aux plateformes de partage de modèles ML, nécessitant une surveillance dédiée.

---

### Implications stratégiques

Cette découverte révèle un risque systémique majeur pour l'écosystème cloud et IA : les plateformes de partage de modèles ML comme Hugging Face deviennent un vecteur d'exposition de credentials critique. La médiane de cinq ans sans rotation démontre un échec fondamental de la gouvernance des secrets dans de nombreuses organisations. Les conséquences financières (dépenses non autorisées) et sécuritaires (accès administratif complet) sont potentiellement dévastatrices. Les organisations doivent intégrer la sécurité des secrets dans leur stratégie DevSecOps et ML Ops, et reconsidérer leurs politiques de gestion des clés d'accès cloud. Cette tendance souligne l'urgence d'une régulation des plateformes de partage de modèles ML en matière de détection de secrets exposés.

---

### Recommandations

* Effectuer un audit immédiat de tous les dépôts publics (GitHub, Hugging Face, GitLab) pour des clés AWS exposées
* Roter toutes les clés d'accès AWS identifiées comme exposées, en priorité celles à privilèges administratifs
* Implémenter des scans automatisés de secrets dans les pipelines CI/CD avec blocage des commits contenant des credentials
* Activer AWS Budgets, Cost Anomaly Detection et des alertes CloudWatch sur les dépenses anormales
* Migrer vers des rôles IAM à court terme (STS) plutôt que des clés d'accès persistantes
* Former les équipes data science et ML aux risques d'exposition de credentials sur les plateformes de partage

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre en place une politique de gestion des secrets avec coffre-fort (AWS Secrets Manager, HashiCorp Vault)
* Former les développeurs et data scientists aux risques d'exposition de clés dans les dépôts publics
* Implémenter des scans automatisés de secrets dans les pipelines CI/CD (TruffleHog, GitLeaks)
* Définir une politique de moindre privilège pour toutes les clés d'accès AWS
* Activer AWS Budgets et Cost Anomaly Detection pour détecter les dépenses anormales

#### Phase 2 — Détection et analyse

* Scanner les dépôts publics (GitHub, Hugging Face, GitLab) pour des clés AWS exposées
* Surveiller les dépenses AWS anormales via AWS Cost Explorer et CloudWatch
* Configurer des alertes sur l'utilisation de clés d'accès depuis des adresses IP inconnues via AWS CloudTrail
* Détecter les créations de ressources non autorisées (instances EC2, buckets S3, lambdas)
* Surveiller les appels API AWS sensibles (iam:CreateUser, iam:AttachUserPolicy, ec2:RunInstances)

#### Phase 3 — Confinement, éradication et récupération

* Roter immédiatement toutes les clés d'accès AWS exposées via IAM
* Révoquer toutes les sessions actives associées aux clés compromises
* Restreindre les politiques IAM au principe du moindre privilège
* Activer MFA pour tous les comptes IAM et root
* Bloquer les adresses IP suspectes dans les Security Groups et NACLs

#### Phase 4 — Activités post-incident

* Auditer toutes les actions effectuées avec les clés compromises via CloudTrail
* Évaluer les dommages financiers et les ressources créées/modifiées sans autorisation
* Supprimer les ressources non autorisées créées par les attaquants
* Renforcer les contrôles de gouvernance cloud (AWS Config, AWS GuardDuty)
* Documenter l'incident et mettre à jour les politiques de sécurité cloud

#### Phase 5 — Threat Hunting (proactif)

* Rechercher d'autres clés exposées dans tous les dépôts de code et plateformes ML
* Analyser les logs CloudTrail historiques pour identifier des activités suspectes passées
* Identifier les ressources AWS créées ou modifiées par les clés compromises
* Cartographier la surface d'attaque cloud complète (buckets S3 publics, instances exposées)
* Rechercher des backdoors laissées par les attaquants (utilisaux IAM cachés, rôles assumables)

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1552.001** | Unsecured Credentials: Credentials In Files |
| **T1078.004** | Valid Accounts: Cloud Accounts |
| **T1552.007** | Unsecured Credentials: Container API Keys |

---

### Sources

* [https://www.scworld.com/brief/thousands-of-active-aws-access-keys-remain-publicly-exposed](https://www.scworld.com/brief/thousands-of-active-aws-access-keys-remain-publicly-exposed)
