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
  * [Sécurité de la chaîne d'approvisionnement : ne pas tenir l'intégrité des paquets pour acquise](#securite-de-la-chaine-dapprovisionnement-ne-pas-tenir-lintegrite-des-paquets-pour-acquise)
  * [Fuite de données NIUS (nius.de) — ~6 000 enregistrements compromis](#fuite-de-donnees-nius-niusde-6-000-enregistrements-compromis)
  * [Audit des changements de configuration Microsoft Defender et Intune](#audit-des-changements-de-configuration-microsoft-defender-et-intune)
  * [The Cure for Exceptional Zeek Package Testing (Parties 1 à 3)](#the-cure-for-exceptional-zeek-package-testing-parties-1-a-3)
  * [BRIDGEHEAD : Campagne de typosquatting npm traversant WSL vers Windows pour installer un voleur de crypto-wallets](#bridgehead-campagne-de-typosquatting-npm-traversant-wsl-vers-windows-pour-installer-un-voleur-de-crypto-wallets)
  * [natural-language-nmap : Modèle SLM local convertissant le langage naturel en commandes nmap](#natural-language-nmap-modele-slm-local-convertissant-le-langage-naturel-en-commandes-nmap)
  * [fortitool : Cracking de bout en bout du firmware FortiOS et découverte d'une clé inédite](#fortitool-cracking-de-bout-en-bout-du-firmware-fortios-et-decouverte-dune-cle-inedite)
  * [Anatomie d'un Crimekit macOS ClickFix exploitant l'EtherHiding](#anatomie-dun-crimekit-macos-clickfix-exploitant-letherhiding)
  * [Failles logiques et correctifs pour les règles de détection curées Google SecOps (Chronicle) - O365 & UEBA](#failles-logiques-et-correctifs-pour-les-regles-de-detection-curees-google-secops-chronicle-o365-ueba)
  * [Patch Windows 11 KB5121003 : crashes dans les jeux vidéo et problèmes d'imprimantes](#patch-windows-11-kb5121003-crashes-dans-les-jeux-video-et-problemes-dimprimantes)
  * [parsedmarc : outil open source d'analyse des rapports DMARC](#parsedmarc-outil-open-source-danalyse-des-rapports-dmarc)
  * [Campagne BEC diffusant Agent Tesla v4 via un fichier JScript truffé d'emojis Unicode](#campagne-bec-diffusant-agent-tesla-v4-via-un-fichier-jscript-truffe-demojis-unicode)
  * [Page de phishing hébergée sur GitHub Pages usurpant potentiellement IONOS](#page-de-phishing-hebergee-sur-github-pages-usurpant-potentiellement-ionos)
  * [Revue hebdomadaire des incidents de sécurité : 297 incidents incluant ASCII Group, Sears, Kingston et Columbia University](#revue-hebdomadaire-des-incidents-de-securite-297-incidents-incluant-ascii-group-sears-kingston-et-columbia-university)
  * [Podcast hebdomadaire : 297 incidents dont ASCII Group, Sears, Kingston, Columbia University](#podcast-hebdomadaire-297-incidents-dont-ascii-group-sears-kingston-columbia-university)
  * [Centaines de clés AWS leakées donnant un contrôle total sur des comptes corporate](#centaines-de-cles-aws-leakees-donnant-un-controle-total-sur-des-comptes-corporate)
  * [ShinyHunters revendique le piratage de Logitech et Streamlabs](#shinyhunters-revendique-le-piratage-de-logitech-et-streamlabs)
  * [LockBit 5.0 revendique une attaque contre Actua, groupe français de recrutement](#lockbit-50-revendique-une-attaque-contre-actua-groupe-francais-de-recrutement)
  * [Chess.com : un pirate revendique 7,3 millions de profils volés](#chesscom-un-pirate-revendique-73-millions-de-profils-voles)
  * [Golf Canada : 568 972 comptes compromis](#golf-canada-568-972-comptes-compromis)
  * [Sakura Internet : piratage exposant jusqu'à 1,36 million de comptes](#sakura-internet-piratage-exposant-jusqua-136-million-de-comptes)
  * [LockBit 5.0 menace de publier des données d'Actua concernant plus de 100 000 personnes](#lockbit-50-menace-de-publier-des-donnees-dactua-concernant-plus-de-100-000-personnes)
  * [Plus de 9 300 clés d'accès AWS exposées publiquement selon Truffle Security](#plus-de-9-300-cles-dacces-aws-exposees-publiquement-selon-truffle-security)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

La volumétrie quotidienne s'établit à 24 articles, marquée par une forte prévalence des vulnérabilités (8) et des fuites de données (8). Cette concentration exceptionnelle sur les failles techniques et les compromissions indique une journée dominée par l'exploitation active et l'impact opérationnel direct, nécessitant une vigilance accrue de nos équipes de réponse. À l'inverse, le faible nombre de signaux liés aux acteurs de la menace (1) et à la géopolitique (1) suggère une accalmie relative dans les campagnes d'attribution ou de manipulation informationnelle à grande échelle. L'absence totale de signalements réglementaires (0) confirme un focus exclusif sur la dynamique tactique plutôt que sur les évolutions de conformité. Stratégiquement, la priorité immédiate doit être accordée à la remédiation des vulnérabilités publiées et à l'évaluation de l'impact des fuites de données répertoriées sur notre périmètre. Nous recommandons de maintenir une posture de défense proactive pour anticiper d'éventuelles vagues d'exploitation secondaires découlant de ces publications massives.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **ShinyHunters** | finance, banking, cybersecurity_firm, streamers | Compromission de comptes valides (T1078), exfiltration via services web (T1567), exploitation de la chaîne d'approvisionnement (T1195), déploiement de ransomware (T1486), et manipulation de processus métier pour l'extorsion (T1656, T1657). | T1567, T1078, T1195, T1486, T1656, T1657 | [https://databreaches.net/2026/08/23/shinyhunters-claims-hack-of-reliaquest-but-provides-no-proof/](https://databreaches.net/2026/08/23/shinyhunters-claims-hack-of-reliaquest-but-provides-no-proof/)<br>[https[://]pulseofnations.lol/shinyhunters-hit-bok/](https[://]pulseofnations.lol/shinyhunters-hit-bok/)<br>[https://mastodon.social/@PulseOfNations/117143002824465133](https://mastodon.social/@PulseOfNations/117143002824465133)<br>[https://www.zataz.com/shinyhunters-menace-logitech-et-streamlabs/](https://www.zataz.com/shinyhunters-menace-logitech-et-streamlabs/) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Amérique du Nord** | Finance, assurance, juridique | Campagne d'ingénierie sociale ciblant le secteur financier | Le groupe Silent Ransom Group (SRG), actif depuis 2022 et pratiquant l'usurpation d'identité du support informatique depuis le printemps 2026, mène une campagne d'ingénierie sociale par vishing contre Apollo Global Management, un géant du private equity gérant des centaines de milliards de dollars. L'attaque repose sur un appel téléphonique où l'attaquant se fait passer pour le support IT interne afin d'obtenir des accès ou des informations sensibles. Google Threat Intelligence Group et Mandiant ont tous deux documenté ce modus operandi en juin 2026. La campagne cible plus largement les secteurs de la finance, de l'assurance et du juridique. Aucun zero-day ni acteur étatique n'est impliqué ; la faille exploitée est humaine. La réussite de l'attaque repose entièrement sur l'absence de vérification de l'identité de l'appelant par la victime. | [https://infosec.exchange/@security_crawler_carl/117146217260647792](https://infosec.exchange/@security_crawler_carl/117146217260647792) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

_Aucune actualité réglementaire._

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Santé, construction, IT, services financiers, immobilier** | Hospitality Health ER (Longview) et autres organisations | Données organisationnelles extraites des systèmes victimes (détails spécifiques non publiés pour chaque victime). Le groupe publie les données les plus sensibles dans un dossier 'parsed' dédié et sur des forums du dark web. | Inconnu | [https://www.ransomlook.io//group/genesis](https://www.ransomlook.io//group/genesis) |
| **Cybersécurité** | ReliaQuest, LLC | Non confirmé. ShinyHunters a publié trois captures d'écran montrant un accès à l'interface Okta de ReliaQuest, mais aucune donnée exfiltrée n'a été présentée à ce stade. | Inconnu | [https://databreaches.net/2026/08/23/shinyhunters-claims-hack-of-reliaquest-but-provides-no-proof/](https://databreaches.net/2026/08/23/shinyhunters-claims-hack-of-reliaquest-but-provides-no-proof/) |
| **Médias / Service de presse** | NIUS | Adresses e-mail, noms, adresses physiques, détails d'achat, numéros de comptes bancaires (IBAN), données partielles de cartes de crédit (numéro masqué, type, date d'expiration) | 6090 | [https://haveibeenpwned.com/Breach/NIUS](https://haveibeenpwned.com/Breach/NIUS) |
| **Banque / Services financiers** | U.S. Bank | Non confirmé. LockBit affirme avoir obtenu des fichiers mais n'a fourni aucune preuve d'exfiltration à ce stade. | Inconnu | [https://mastodon.social/@hacksgr/117147034661656533](https://mastodon.social/@hacksgr/117147034661656533) |
| **Finance / Private Equity** | Apollo Global Management | Noms, dates de naissance, coordonnées de contact, numéros de sécurité sociale (SSN) | Inconnu | [https[://]techcrunch.com/2026/08/21/private-equity-firm-apollo-confirms-data-breach-amid-hacking-wave-targeting-financial-giants/](https[://]techcrunch.com/2026/08/21/private-equity-firm-apollo-confirms-data-breach-amid-hacking-wave-targeting-financial-giants/)<br>[https[://]infosec.exchange/@DevaOnBreaches/117142183287122483](https[://]infosec.exchange/@DevaOnBreaches/117142183287122483)<br>[https://mastodon.thenewoil.org/@thenewoil/117145298547397291](https://mastodon.thenewoil.org/@thenewoil/117145298547397291)<br>[https://infosec.exchange/@DevaOnBreaches/117142183287122483](https://infosec.exchange/@DevaOnBreaches/117142183287122483) |
| **Énergie / Services publics** | Louisiana Electric Resource | Documents financiers, contrats, emails internes, informations personnelles des clients et employés | 200 | [https[://]go.darkwebsonar.io/updap-mastodon](https[://]go.darkwebsonar.io/updap-mastodon)<br>[https://infosec.exchange/@darkwebsonar/117144685581051399](https://infosec.exchange/@darkwebsonar/117144685581051399) |
| **Finance / Services bancaires** | BOK Financial | Données volées non spécifiées en détail (données clients et/ou opérationnelles probables) | Inconnu | [https[://]pulseofnations.lol/shinyhunters-hit-bok/](https[://]pulseofnations.lol/shinyhunters-hit-bok/)<br>[https://mastodon.social/@PulseOfNations/117143002824465133](https://mastodon.social/@PulseOfNations/117143002824465133) |
| **Santé** | SickKids (Hospital for Sick Children) | Informations personnelles d'employés actuels/anciens et de candidats à un emploi | Inconnu | [https[://]www.bleepingcomputer.com/news/security/sickkids-data-breach-exposes-employee-and-job-applicant-info/](https[://]www.bleepingcomputer.com/news/security/sickkids-data-breach-exposes-employee-and-job-applicant-info/)<br>[https://infosec.exchange/@DevaOnBreaches/117142178194519583](https://infosec.exchange/@DevaOnBreaches/117142178194519583) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-8445** | 9.8 | N/A | FALSE | justhtml versions <= 1.11.0 (corrigé dans la version 1.12.0) | CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) - Contournement de sanitization via Markdown | Un attaquant distant peut injecter du code HTML/JavaScript arbitraire via la sortie Markdown de to_markdown(), entraînant une vulnérabilité XSS. Le score CVSS 3.1 est de 9.8 (CRITICAL) avec un vecteur indiquant une exploitabilité distante sans interaction utilisateur. L'impact couvre la confidentialité, l'intégrité et la disponibilité élevées. | Theoretical | Mettre à jour la bibliothèque justhtml vers la version 1.12.0 ou ultérieure. Réviser et sanitiser la sortie Markdown avant tout rendu. Implémenter un échappement HTML plus strict dans les parseurs personnalisés. Référence: GHSA-3rcm-vjrc-p45j. | [https://cvefeed.io/vuln/detail/CVE-2026-8445](https://cvefeed.io/vuln/detail/CVE-2026-8445)<br>[https://github.com/EmilStenstrom/justhtml/security/advisories/GHSA-3rcm-vjrc-p45j](https://github.com/EmilStenstrom/justhtml/security/advisories/GHSA-3rcm-vjrc-p45j)<br>[https://www.vulncheck.com/advisories/justhtml-before-sanitizer-bypass-via-markdown](https://www.vulncheck.com/advisories/justhtml-before-sanitizer-bypass-via-markdown) |
| **CVE-2026-7808** | N/A | N/A | FALSE | justhtml versions antérieures à 1.16.0 | Problèmes de sécurité multiples liés à la sanitization | Les problèmes de sanitization multiples pourraient permettre à un attaquant de contourner les mécanismes de sécurité de la bibliothèque et potentiellement d'injecter du contenu malveillant dans les sorties HTML ou Markdown. | Theoretical | Mettre à jour la bibliothèque justhtml vers la version 1.16.0 ou ultérieure. Réviser les politiques de sanitization des entrées utilisateur. | [https://cvefeed.io/vuln/detail/CVE-2026-7808](https://cvefeed.io/vuln/detail/CVE-2026-7808) |
| **CVE-2026-5388** | N/A | N/A | FALSE | justhtml versions antérieures à 1.15.0 | Problèmes de sécurité multiples | Les problèmes de sécurité multiples pourraient permettre à un attaquant d'exploiter la bibliothèque pour compromettre l'intégrité ou la confidentialité des données traitées. | Theoretical | Mettre à jour la bibliothèque justhtml vers la version 1.15.0 ou ultérieure. Réviser les politiques de sécurité applicative. | [https://cvefeed.io/vuln/detail/CVE-2026-5388](https://cvefeed.io/vuln/detail/CVE-2026-5388) |
| **CVE-2026-78155** | 9.9 | N/A | FALSE | StackGres operator (toutes versions <= 1.18.8) | CWE-426: Untrusted Search Path - Élévation de privilèges dans StackGres operator | Un tenant à faible privilège peut escalader ses privilèges vers le niveau administrateur, compromettant potentiellement l'ensemble du cluster Kubernetes et toutes les bases de données gérées par StackGres. Le score CVSS 3.1 est de 9.9 (CRITICAL). | Theoretical | Appliquer le correctif de sécurité fourni par le vendeur pour StackGres operator. Réviser et restreindre les privilèges de propriété de base de données. Surveiller les journaux d'accès pour des activités suspectes. Référence: https://gitlab[.]com/ongresinc/stackgres/-/work_items/3177. | [https://cvefeed.io/vuln/detail/CVE-2026-78155](https://cvefeed.io/vuln/detail/CVE-2026-78155)<br>[https://gitlab.com/ongresinc/stackgres/-/work_items/3177](https://gitlab.com/ongresinc/stackgres/-/work_items/3177) |
| **CVE-2026-10053** | 8.5 | N/A | FALSE | GitLab CE/EE versions 18.8 à < 19.0.6, 19.1 à < 19.1.4, 19.2 à < 19.2.2 | CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) permettant une exécution de code à distance (RCE) | Un utilisateur authentifié peut exploiter cette vulnérabilité de path traversal dans le package registry pour exécuter du code à distance sur le serveur GitLab, compromettant potentiellement l'ensemble de l'instance et tous les projets hébergés. Le score CVSS 3.1 est de 8.5 (HIGH). | Theoretical | Mettre à jour GitLab vers la version 19.0.6, 19.1.4 ou 19.2.2 selon la branche concernée. Restreindre l'accès au package registry. Références: https://gitlab[.]com/gitlab-org/gitlab/-/work_items/601596 et https://hackerone[.]com/reports/3754194. | [https://cvefeed.io/vuln/detail/CVE-2026-10053](https://cvefeed.io/vuln/detail/CVE-2026-10053)<br>[https://gitlab.com/gitlab-org/gitlab/-/work_items/601596](https://gitlab.com/gitlab-org/gitlab/-/work_items/601596)<br>[https://hackerone.com/reports/3754194](https://hackerone.com/reports/3754194) |
| **CVE-2026-78050** | 9.9 | N/A | FALSE | Comfast CF-N1-S version 2.6.0.1 (composant Web Management, fonction sub_41AD7C du fichier /cgi-bin/mbox-config?method=SET&section=ntp_timezone) | CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer / CWE-121: Stack-based Buffer Overflow | Un attaquant distant non authentifié peut exploiter cette vulnérabilité pour provoquer un débordement de tampon basé sur la pile via l'interface de gestion web, pouvant entraîner une exécution de code à distance, un crash de l'équipement (déni de service), ou une compromission complète du routeur. L'exploit est public. | Active | Mettre à jour le firmware vers une version corrigée dès disponibilité. Éviter d'utiliser la fonction ou le composant affecté. Restreindre l'accès réseau à l'interface de gestion. Référence: https://github[.]com/AdminSafe/CVE/issues/9. | [https://cvefeed.io/vuln/detail/CVE-2026-78050](https://cvefeed.io/vuln/detail/CVE-2026-78050)<br>[https://github.com/AdminSafe/CVE/issues/9](https://github.com/AdminSafe/CVE/issues/9)<br>[https://vuldb.com/cve/CVE-2026-78050](https://vuldb.com/cve/CVE-2026-78050)<br>[https://vuldb.com/submit/881293](https://vuldb.com/submit/881293)<br>[https://vuldb.com/vuln/394291](https://vuldb.com/vuln/394291)<br>[https://vuldb.com/vuln/394291/cti](https://vuldb.com/vuln/394291/cti) |
| **CVE-2026-16149** | 8.8 | N/A | FALSE | Plugin WordPress Security Hardener versions <= 2.4.4 | CWE-269: Improper Privilege Management - Élévation de privilèges authentifiée via l'API REST WordPress | Un attaquant authentifié avec un compte de niveau Subscriber (le plus bas niveau) peut créer des comptes administrateur ou réinitialiser les mots de passe d'administrateurs existants, conduisant à une prise de contrôle complète du site WordPress. Le score CVSS 3.1 est de 8.8 (HIGH). | Theoretical | Mettre à jour le plugin Security Hardener vers une version corrigée. Vérifier les paramètres du plugin après la mise à jour. Retirer le plugin s'il n'est pas nécessaire. Référence: https://www[.]wordfence[.]com/threat-intel/vulnerabilities/id/64f1a71f-e210-4191-bfb4-56f8568180ed. | [https://cvefeed.io/vuln/detail/CVE-2026-16149](https://cvefeed.io/vuln/detail/CVE-2026-16149)<br>[https://plugins.trac.wordpress.org/changeset/3630896/security-hardener](https://plugins.trac.wordpress.org/changeset/3630896/security-hardener)<br>[https://www.wordfence.com/threat-intel/vulnerabilities/id/64f1a71f-e210-4191-bfb4-56f8568180ed?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/64f1a71f-e210-4191-bfb4-56f8568180ed?source=cve) |
| **CVE-2026-0551** | 8.8 | N/A | FALSE | Plugin WordPress PPWP – Password Protect Pages versions <= 1.9.18 | CWE-502: Deserialization of Untrusted Data - Injection d'objet PHP via le paramètre post_protection_roles | Un attaquant authentifié (Contributor+) peut injecter un objet PHP. L'impact réel dépend de la présence d'une chaîne POP dans un autre plugin ou thème installé sur le site cible. En présence d'une telle chaîne, l'attaquant peut obtenir une exécution de code à distance, une suppression de fichiers arbitraires ou une exfiltration de données sensibles. Le score CVSS 3.1 est de 8.8 (HIGH). | Theoretical | Mettre à jour le plugin PPWP vers une version supérieure à 1.9.18. Réviser les plugins et thèmes installés pour identifier d'éventuelles chaînes POP. Référence: https://www[.]wordfence[.]com/threat-intel/vulnerabilities/id/b8f53282-740e-4ac3-a2e1-7a97893e3355. | [https://cvefeed.io/vuln/detail/CVE-2026-0551](https://cvefeed.io/vuln/detail/CVE-2026-0551)<br>[https://plugins.trac.wordpress.org/changeset/3567221/password-protect-page](https://plugins.trac.wordpress.org/changeset/3567221/password-protect-page)<br>[https://www.wordfence.com/threat-intel/vulnerabilities/id/b8f53282-740e-4ac3-a2e1-7a97893e3355?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/b8f53282-740e-4ac3-a2e1-7a97893e3355?source=cve) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="google-cloud-compute-et-cloud-ops-agent-ce-qui-compte-vraiment-pour-le-dfir"></div>

## Google Cloud Compute et Cloud Ops Agent — Ce qui compte vraiment pour le DFIR

### Résumé

L'article détaille les pratiques DFIR dans Google Cloud Platform en se concentrant sur les services Compute. Il distingue trois catégories de compute : IaaS (Compute Engine, où les artefacts forensics sont riches), PaaS (App Engine, GKE, Cloud Run — logs disponibles mais peu d'évidence au niveau hôte) et FaaS (Cloud Functions — boîte noire forensique). Un cas pratique est utilisé : une alerte de facturation signale un pic d'usage Compute Engine sur le projet « fernbridge-prod » sans qu'aucune VM n'ait été provisionnée légitimement. L'enquête révèle des VMs Compute Engine frauduleusement créées. L'article couvre les types de VMs (générales, haute mémoire, haute CPU), les configurations spéciales (GPU, VMs préemptibles, Shielded VMs avec Secure Boot et vTPM) et la procédure de capture de preuves par snapshots de disques : snapshotter le disque persistant, le partager avec un projet DFIR, le copier, le convertir en disque et l'attacher en lecture seule à une VM forensique.

---

### Analyse opérationnelle

Pour les équipes SOC/IT, cet article souligne l'importance de surveiller Cloud Audit Logs pour détecter les créations de VMs non autorisées (compute.instances.insert). Les VMs préemptibles peuvent fausser les timelines forensiques car elles disparaissent sans préavis, créant des gaps dans les logs. Les Shielded VMs ajoutent des logs supplémentaires (intégrité, Secure Boot) qu'il faut intégrer aux pipelines de détection. La procédure de snapshot forensique doit être automatisée et testée : les équipes doivent préparer un projet DFIR dédié avec des VMs forensiques pré-configurées. Les alertes Cloud Billing constituent un détecteur précieux mais tardif — il faut les compléter par des règles temps réel sur Cloud Audit Logs. La capacité à partager des snapshots entre projets (même inter-organisations) facilite l'externalisation des analyses forensiques.

---

### Implications stratégiques

L'article illustre un risque majeur du cloud : un acteur disposant d'identifiants compromis peut provisionner des ressources compute à grande échelle, générant des coûts significatifs et potentiellement exfiltrant des données. Les organisations doivent imposer des politiques Organization Policy restrictives sur la création de VMs, segmenter les projets par sensibilité, et mettre en place des garde-fous budgétaires. La dépendance aux artefacts cloud-native (logs, snapshots) plutôt qu'aux méthodes forensiques traditionnelles nécessite une montée en compétence des équipes IR sur les spécificités GCP. Le modèle de responsabilité partagée signifie que sur PaaS/FaaS, la visibilité forensique est considérablement réduite — les choix d'architecture influencent directement la capacité de réponse à incident.

---

### Recommandations

* Automatiser la procédure de snapshot forensique et la tester régulièrement
* Configurer des alertes temps réel sur Cloud Audit Logs pour les créations de VMs non planifiées
* Maintenir un projet DFIR dédié avec VMs forensiques pré-configurées
* Appliquer des Organization Policies restreignant la création de VMs par projet et par utilisateur
* Intégrer les logs des Shielded VMs (intégrité, Secure Boot) dans le SIEM
* Former les équipes IR aux spécificités forensiques GCP (snapshots, Cloud Audit Logs, VPC Flow Logs)

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un projet GCP dédié aux analyses forensiques (DFIR project) avec VMs forensiques pré-configurées (Linux/Windows)
* Documenter et automatiser la procédure de snapshot → partage → copie → attachement read-only sur VM forensique
* Définir des rôles IAM minimum privilège pour le partage de snapshots entre projets
* Pré-configurer des règles d'alerting Cloud Billing sur seuils de consommation anormaux
* Tenir un inventaire à jour des projets GCP et de leurs propriétaires

#### Phase 2 — Détection et analyse

* Surveiller Cloud Audit Logs pour les événements compute.instances.insert non planifiés
* Configurer des alertes Cloud Billing sur pics de consommation Compute Engine inattendus
* Détecter la création de VMs en dehors des fenêtres de changement planifié
* Surveiller les connexions SSH/RDP sur des VMs nouvellement créées
* Corréler les logs VPC Flow avec la création de nouvelles VMs pour identifier des flux C2 ou d'exfiltration

#### Phase 3 — Confinement, éradication et récupération

* Isoler la VM suspecte en appliquant des règles de firewall deny-all ou en détachant les interfaces réseau
* Réaliser un snapshot du disque persistant avant toute autre action
* Désactiver les comptes de service ou utilisateurs compromis ayant provisionné les VMs
* Bloquer les adresses IP de destination identifiées dans les VPC Flow Logs
* Préserver l'état mémoire si possible (capture mémoire avant arrêt de la VM)

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des VMs préemptibles créées et détruites rapidement pour masquer une activité malveillante
* Analyser l'historique Cloud Audit Logs sur 90 jours pour identifier d'autres créations de VMs non planifiées
* Chercher des images personnalisées ou des conteneurs Docker déployés sur des VMs suspectes
* Vérifier la présence de Shielded VMs désactivées ou de configurations Secure Boot modifiées
* Corréler les snapshots de disques existants avec des indicateurs de compromission connus

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `access[.]in` | Low |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1578** | Modify Cloud Compute Infrastructure — création non autorisée de VMs Compute Engine dans un projet GCP |
| **T1078** | Valid Accounts — utilisation d'identifiables compromis pour provisionner des ressources cloud |
| **T1087** | Account Discovery — énumération des comptes et identités dans l'environnement cloud lors de l'investigation |

---

### Sources

* [https://www.cyberengage.org/post/google-cloud-compute-and-cloud-ops-agent-what-actually-matters-for-dfir](https://www.cyberengage.org/post/google-cloud-compute-and-cloud-ops-agent-what-actually-matters-for-dfir)


---

<div id="securite-de-la-chaine-dapprovisionnement-ne-pas-tenir-lintegrite-des-paquets-pour-acquise"></div>

## Sécurité de la chaîne d'approvisionnement : ne pas tenir l'intégrité des paquets pour acquise

### Résumé

Un message de sensibilisation publié par CVEDatabase rappelle que les attaques par chaîne d'approvisionnement ciblent fréquemment la phase de distribution. Si un miroir de téléchargement est compromis, les utilisateurs peuvent installer des backdoors. Le message recommande de toujours vérifier les checksums SHA-256 et les signatures GPG fournies par les développeurs officiels, et d'intégrer cette vérification dans les pipelines CI/CD comme couche de défense critique.

---

### Analyse opérationnelle

Les équipes SOC et DevOps doivent intégrer la vérification d'intégrité des paquets (SHA-256, GPG) directement dans les pipelines CI/CD de manière automatisée et bloquante. Les miroirs de paquets internes (Artifactory, Nexus, ProGet) doivent être configurés pour exiger et valider les signatures avant de mettre en cache un artefact. La détection doit surveiller les échecs de vérification de hash ou de signature comme indicateurs de compromission potentielle. Les équipes doivent maintenir un SBOM (Software Bill of Materials) à jour pour permettre l'identification rapide des systèmes exposés lorsqu'une compromission de paquet est découverte. Les alertes sur téléchargements depuis des sources non officielles doivent être implémentées au niveau des proxies et firewalls.

---

### Implications stratégiques

Les attaques sur la chaîne d'approvisionnement logicielle (SolarWinds, 3CX, XZ Utils) représentent une tendance majeure avec des conséquences systémiques : un seul paquet compromis peut affecter des milliers d'organisations. La confiance implicite dans les dépôts publics (npm, PyPI, Docker Hub) constitue un risque organisationnel élevé. Les régulateurs (UE avec le Cyber Resilience Act, USA avec l'Executive Order 14028) imposent de plus en plus des exigences de transparence et d'intégrité de la chaîne d'approvisionnement. Les organisations doivent adopter une posture de « zero trust » vis-à-vis des dépendances externes et investir dans des outils de SBOM et de scanning continu.

---

### Recommandations

* Intégrer la vérification SHA-256 et GPG de manière bloquante dans tous les pipelines CI/CD
* Maintenir un SBOM à jour pour chaque application en production
* Configurer des miroirs internes avec validation automatique des signatures
* Surveiller et alerter sur les échecs de vérification d'intégrité des paquets
* Établir une liste blanche des empreintes GPG des mainteneurs de paquets critiques
* Mettre en place un processus de revue manuelle pour les mises à jour de dépendances sensibles

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire complet des dépendances logicielles (SBOM) pour tous les projets
* Intégrer la vérification systématique des checksums SHA-256 et signatures GPG dans les pipelines CI/CD
* Configurer des miroirs internes de paquets signés et vérifiés
* Documenter les empreintes officielles des développeurs et mainteneurs de paquets critiques
* Mettre en place un processus de validation manuelle pour les mises à jour de paquets sensibles

#### Phase 2 — Détection et analyse

* Surveiller les échecs de vérification de signature GPG ou de checksum SHA-256 dans les pipelines CI/CD
* Détecter les téléchargements de paquets depuis des miroirs non officiels ou non listés
* Corréler les changements de hash de paquets entre le téléchargement et l'installation
* Surveiller les modifications inattendues de fichiers binaires après installation de paquets
* Alerte sur les paquets dont la signature ne correspond pas à l'identité du mainteneur attendu

#### Phase 3 — Confinement, éradication et récupération

* Bloquer immédiatement le miroir ou le dépôt compromis au niveau du proxy/cache interne
* Isoler les systèmes ayant installé des paquets depuis le miroir compromis
* Restaurer les systèmes affectés depuis des images connues saines
* Bloquer les communications réseau vers les infrastructures de C2 potentiellement déployées via les paquets backdoorés
* Révoquer les credentials potentiellement exposés sur les systèmes compromis

#### Phase 4 — Activités post-incident

* Auditer tous les paquets installés sur l'infrastructure pour identifier d'autres compromissions
* Mettre à jour les listes de checksums et signatures de référence avec les versions officielles saines
* Documenter la chaîne d'approvisionnement compromise et notifier les parties prenantes
* Renforcer les contrôles CI/CD avec des étapes de vérification obligatoires et bloquantes
* Effectuer une revue de tous les accès aux dépôts internes et miroirs de paquets

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des paquets installés sans vérification de signature sur l'ensemble du parc
* Analyser les logs de téléchargement de paquets pour identifier des téléchargements depuis des sources non standards
* Chercher des processus backdoorés ou des comportements anormaux sur les systèmes ayant récemment installé des mises à jour
* Vérifier l'intégrité des images de conteneurs de base utilisées dans les pipelines CI/CD
* Corréler avec les IOCs publiés pour les campagnes de supply chain connues (SolarWinds, 3CX, etc.)

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1195.002** | Compromise Software Supply Chain — compromission des miroirs de distribution de paquets pour injecter des backdoors |
| **T1195** | Supply Chain Compromise — exploitation de la chaîne d'approvisionnement logicielle |

---

### Sources

* [https://techhub.social/@cvedatabase/117147186067751595](https://techhub.social/@cvedatabase/117147186067751595)


---

<div id="fuite-de-donnees-nius-niusde-6-000-enregistrements-compromis"></div>

## Fuite de données NIUS (nius.de) — ~6 000 enregistrements compromis

### Résumé

BeeSINT rapporte une fuite de données vérifiée affectant NIUS (nius.de), classée comme sensible. Environ 6 000 enregistrements ont été compromis, incluant des numéros de compte bancaire, des adresses email, des noms, des données partielles de cartes de crédit et deux autres catégories de données non précisées. L'incident s'est produit le 13 juillet 2025 et a été divulgué 406 jours après l'événement. L'infrastructure du site utilise Cloudflare et aucun SPF/DMARC n'était configuré au moment de l'incident.

---

### Analyse opérationnelle

L'absence de SPF/DMARC sur le domaine nius[.]de facilite l'usurpation d'identité par email, pouvant servir de vecteur d'attaque initial (spearphishing) ou de persistance post-compromission. Les données compromises (numéros de compte bancaire, données cartographiques partielles, emails) présentent un risque élevé de fraude financière et d'usurpation d'identité. Les équipes SOC doivent vérifier si leur organisation ou leurs employés ont interagi avec le domaine nius[.]de et surveiller toute activité suspecte liée aux comptes bancaires ou cartes potentiellement exposées. Le délai de divulgation de 406 jours est extrêmement préoccupant — il suggère soit une détection tardive, soit une dissimulation délibérée, laissant les victimes exposées sans mesure de protection pendant plus d'un an.

---

### Implications stratégiques

Cette fuite illustre les risques persistants dans le secteur média où les plateformes collectent des données d'abonnés et de paiement sans toujours appliquer les contrôles de sécurité de base (SPF/DMARC, chiffrement des données sensibles). Le délai de divulgation de 406 jours soulève des questions de conformité RGPD, qui impose une notification sous 72 heures. Les organisations médiatiques doivent considérer les données financières de leurs abonnés comme des actifs critiques nécessitant un chiffrement au repos, un accès strictement contrôlé et une surveillance continue. L'absence de SPF/DMARC est un échec de configuration de base qui expose l'ensemble de l'écosystème email à l'usurpation. Cette fuite peut entraîner des poursuites réglementaires, une perte de confiance des abonnés et des coûts de remédiation significatifs.

---

### Recommandations

* Implémenter SPF, DKIM et DMARC sur tous les domaines de l'organisation
* Chiffrer toutes les données financières (numéros de compte, données de carte) au repos
* Mettre en place des contrôles DLP pour détecter l'exfiltration de PII
* Réduire le délai de détection et de notification des incidents (objectif < 72h conforme RGPD)
* Surveiller les dark web forums pour détecter la revente des données exfiltrées
* Mettre en place une authentification multi-facteurs sur tous les accès aux bases de données de PII

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Implémenter SPF, DKIM et DMARC sur tous les domaines de l'organisation
* Chiffrer les données sensibles au repos (numéros de compte bancaire, données cartographiques)
* Mettre en place un inventaire des bases de données contenant des PII
* Configurer des règles de détection d'exfiltration de données (DLP) sur les bases critiques
* Préparer un plan de notification de violation de données conforme RGPD

#### Phase 2 — Détection et analyse

* Surveiller les accès anormaux aux bases de données contenant des PII
* Détecter les requêtes SQL inhabituelles ou les exports massifs de données
* Surveiller le trafic sortant anormal depuis les serveurs hébergeant des données sensibles
* Mettre en place des alertes sur les tentatives d'authentification échouées répétées
* Corréler les logs d'accès applicatifs avec les logs d'infrastructure (Cloudflare, serveurs web)

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les systèmes compromis du réseau
* Bloquer les adresses IP identifiées comme source de l'attaque
* Révoquer et réinitialiser tous les credentials potentiellement compromis
* Faire pivoter les clés API et les secrets d'application
* Mettre en place des règles de firewall temporaires pour limiter l'accès aux systèmes affectés

#### Phase 4 — Activités post-incident

* Notifier les utilisateurs affectés conformément aux obligations RGPD (72h)
* Déclarer la violation à l'autorité de protection des données compétente
* Réaliser un audit complet de sécurité de l'infrastructure
* Implémenter SPF, DKIM et DMARC si non déjà en place
* Effectuer une revue des contrôles d'accès et des privilèges sur les bases de données
* Communiquer de manière transparente avec les parties prenantes sur l'incident

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des traces de persistance sur les systèmes ayant hébergé les données compromises
* Analyser les logs historiques pour identifier la fenêtre d'accès initiale et l'étendue de l'exfiltration
* Vérifier si les données exfiltrées circulent sur les forums dark web ou les marketplaces
* Chercher des tentatives d'usurpation d'identité utilisant les données volées (emails, noms)
* Corréler avec d'autres incidents similaires dans le secteur média pour identifier des campagnes ciblées

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `nius[.]de` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1584** | Compromise Infrastructure — exploitation potentielle d'une infrastructure mal sécurisée (absence SPF/DMARC) |
| **T1566** | Phishing — vecteur d'attaque possible via usurpation d'identité facilitée par l'absence de SPF/DMARC |

---

### Sources

* [https://mastodon.social/@BeeSINT/117147172974427621](https://mastodon.social/@BeeSINT/117147172974427621)


---

<div id="audit-des-changements-de-configuration-microsoft-defender-et-intune"></div>

## Audit des changements de configuration Microsoft Defender et Intune

### Résumé

L'article aborde l'importance de l'audit des changements de configuration appliqués à Microsoft Defender et Microsoft Intune. Il s'inscrit dans une démarche Blue Team visant à surveiller et détecter les modifications non autorisées ou suspectes des politiques de sécurité des endpoints, notamment les exclusions antivirus, les règles de réduction de la surface d'attaque (ASR) et les profils de gestion des appareils mobiles (MDM).

---

### Analyse opérationnelle

Les équipes SOC doivent surveiller en continu les journaux d'audit unifiés (Unified Audit Log) de Microsoft 365 pour détecter toute modification des configurations Defender et Intune. Les changements de configuration représentent une surface d'attaque critique : un acteur de menace ayant obtenu des privilèges administratifs peut désactiver des protections en temps réel, ajouter des exclusions malveillantes ou modifier des profils Intune pour déployer des payloads. La détection repose sur la corrélation des événements 'UpdatePolicy', 'Set-MDMPolicy' et des modifications d'exclusions avec le contexte d'authentification (IP source, compte, MFA). Les équipes doivent maintenir une baseline des configurations validées et alerter sur tout écart non documenté via un processus de gestion des changements formel.

---

### Implications stratégiques

La compromission des consoles d'administration de sécurité (Defender, Intune) constitue un risque majeur pour la posture de sécurité globale de l'organisation. Un acteur capable de modifier ces configurations peut neutraliser silencieusement les défenses endpoint, créant un aveuglement durable des équipes SOC. La supervision des changements de configuration de sécurité doit être intégrée dans la stratégie de gouvernance IT et de cybersécurité, avec une séparation des tâches (SoD) stricte entre les administrateurs de sécurité et les équipes de gestion des endpoints. La conformité réglementaire (NIS2, ISO 27001) exige désormais une traçabilité complète et une alerte en temps réel sur les altérations des contrôles de sécurité.

---

### Recommandations

* Activer l'Unified Audit Log dans Microsoft 365 et exporter les événements de modification de configuration Defender/Intune vers le SIEM
* Créer des règles de corrélation SIEM alertant sur toute modification de politique de sécurité en dehors des fenêtres de changement approuvées
* Mettre en place un processus de gestion des changements (Change Advisory Board) pour toute modification des configurations Defender et Intune
* Appliquer le principe du moindre privilège sur les rôles d'administration Intune et Defender (RBAC strict)
* Surveiller spécifiquement les ajouts d'exclusions de chemins, extensions ou processus dans Defender comme indicateurs de compromission potentielle

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Définir une baseline des configurations Microsoft Defender et Intune (politiques, exclusions, règles ASR, profils MDM)
* Mettre en place un système d'audit centralisé via Microsoft Graph API et Unified Audit Log (UAL) pour capturer les événements de modification de configuration
* Documenter les comptes autorisés à modifier les politiques Defender et Intune et établir un processus de changement contrôlé (CAB)

#### Phase 2 — Détection et analyse

* Surveiller les événements d'audit Unified Audit Log : 'UpdatePolicy', 'UpdateConfiguration', 'Set-MDMPolicy', modifications d'exclusions Defender, changements de règles ASR
* Créer des alertes SIEM sur les modifications de configuration Defender/Intune en dehors des fenêtres de changement approuvées
* Détecter les désactivations de protections en temps réel (Real-time Protection, Cloud-delivered Protection, Tamper Protection)
* Corréler les changements de configuration avec les activités utilisateur suspectes (connexions depuis IPs inhabituelles, utilisation de comptes privilégiés inhabituels)

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les endpoints dont la configuration Defender a été modifiée de manière non autorisée
* Restaurer les politiques Defender et Intune depuis la baseline validée
* Révoquer les sessions et tokens des comptes ayant effectué les modifications non autorisées
* Bloquer les comptes compromis suspectés d'avoir altéré les configurations de sécurité

#### Phase 4 — Activités post-incident

* Analyser le journal d'audit complet pour identifier l'étendue temporelle et la portée des modifications non autorisées
* Vérifier l'intégrité des endpoints affectés via scans complets et analyse comportementale
* Mettre à jour les règles de détection SIEM avec les IOCs et patterns observés
* Renforcer le contrôle d'accès basé sur les rôles (RBAC) pour les administrateurs Defender/Intune
* Documenter les leçons apprises et affiner le processus de gestion des changements de sécurité

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans l'UAL toute modification d'exclusions de chemins, extensions ou processus Defender sur les 90 derniers jours
* Chercher des désactivations temporaires de Tamper Protection suivies de modifications de configuration
* Corréler les changements de politiques Intune avec des déploiements d'applications ou scripts suspects sur les endpoints
* Identifier les endpoints où les règles ASR ont été désactivées et vérifier la présence de signes de compromission
* Rechercher des patterns de modifications de configuration répétées pouvant indiquer une persistance ou un accès initial par un acteur de menace

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1562** | Impair Defenses - modification ou désactivation d'outils de sécurité |
| **T1106** | Native API - utilisation d'API natives pour interagir avec Defender/Intune |

---

### Sources

* [https://www.reddit.com/r/blueteamsec/comments/1vwfc9y/auditing_microsoft_defender_and_intune/](https://www.reddit.com/r/blueteamsec/comments/1vwfc9y/auditing_microsoft_defender_and_intune/)


---

<div id="the-cure-for-exceptional-zeek-package-testing-parties-1-a-3"></div>

## The Cure for Exceptional Zeek Package Testing (Parties 1 à 3)

### Résumé

Cette série d'articles en trois parties présente une méthodologie complète pour tester les paquets Zeek (anciennement Bro) de manière rigoureuse. Les articles couvrent les bonnes pratiques de développement, de test et de validation des paquets Zeek utilisés pour la surveillance de sécurité réseau (NSM). La série aborde les frameworks de test, la gestion des erreurs, la validation des analyseurs de protocoles et l'assurance qualité des paquets déployés en environnement de production.

---

### Analyse opérationnelle

Les paquets Zeek constituent un élément fondamental de la détection réseau pour les équipes SOC. Un paquet mal testé peut générer des faux positifs massifs, rater des détections critiques ou provoquer des crashes du moteur Zeek entraînant une perte de télémétrie réseau. Les équipes SecOps doivent mettre en place un pipeline de tests automatisés pour valider chaque paquet Zeek avant déploiement : tests unitaires des analyseurs, tests d'intégration avec des captures PCAP de référence, tests de performance pour évaluer l'impact sur le débit de traitement, et tests de régression pour s'assurer que les mises à jour ne cassent pas les détections existantes. La séparation entre environnements de développement, de staging et de production est essentielle pour maintenir l'intégrité de la surveillance réseau.

---

### Implications stratégiques

La qualité de la télémétrie réseau conditionne directement la capacité de détection de l'organisation. Des paquets Zeek défectueux créent des angles morts exploitables par les attaquants pour exfiltrer des données ou maintenir une persistance indétectée. L'investissement dans des processus de test rigoureux pour les paquets Zeek réduit le risque opérationnel et améliore la fiabilité de la détection. La standardisation des pratiques de test au sein de la communauté Blue Team contribue à élever le niveau global de maturité des équipes NSM. Les organisations doivent considérer la maintenance des paquets Zeek comme une activité continue et non comme un projet ponctuel, en intégrant les tests dans leur cycle de vie DevSecOps.

---

### Recommandations

* Mettre en place un pipeline CI/CD pour les paquets Zeek avec tests automatisés (unitaires, intégration, performance)
* Maintenir une bibliothèque de captures PCAP de référence couvrant les protocoles et scénarios d'attaque pertinents pour l'organisation
* Établir un environnement de staging Zeek séparé de la production pour valider les nouveaux paquets
* Surveiller en continu la santé des processus Zeek (CPU, mémoire, taux de traitement) pour détecter les paquets problématiques
* Participer à la communauté Zeek pour partager les retours d'expérience et bénéficier des améliorations communautaires

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un environnement de test Zeek séparé de l'environnement de production avec des captures PCAP de référence
* Documenter les paquets Zeek déployés en production, leurs versions et leurs dépendances
* Établir un pipeline CI/CD pour les tests automatisés des paquets Zeek avant déploiement en production

#### Phase 2 — Détection et analyse

* Surveiller les logs Zeek pour détecter les erreurs d'analyse (zeek.log, stderr) indiquant un paquet défectueux
* Créer des alertes sur les baisses anormales du volume de logs Zeek pouvant indiquer un crash d'analyseur
* Détecter les anomalies dans les logs Zeek (champs manquants, valeurs aberrantes) pouvant résulter d'un paquet mal testé
* Surveiller les performances du système Zeek (CPU, mémoire, latence de traitement des paquets) pour identifier les paquets inefficaces

#### Phase 3 — Confinement, éradication et récupération

* Désactiver ou retirer le paquet Zeek défectueux causant des erreurs ou des baisses de performance
* Restaurer la configuration Zeek précédente validée depuis le système de gestion de versions
* Redémarrer les processus Zeek affectés et vérifier la reprise normale de la capture et de l'analyse du trafic
* Isoler les capteurs Zeek impactés pour éviter toute perte de données de télémétrie réseau

#### Phase 4 — Activités post-incident

* Analyser les logs Zeek et les captures PCAP pour identifier la cause racine de l'échec du paquet
* Corriger le paquet Zeek défectueux et le soumettre au pipeline de tests automatisés avant redéploiement
* Mettre à jour la suite de tests avec les cas limites identifiés lors de l'incident
* Documenter l'incident et les mesures correctives dans la base de connaissances SecOps
* Vérifier l'absence de gaps de détection pendant la période d'indisponibilité du paquet

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les archives PCAP les activités malveillantes potentiellement manquées pendant la période d'indisponibilité de l'analyseur Zeek
* Corréler les logs Zeek avec les autres sources de télémétrie (EDR, firewall, proxy) pour combler les gaps de visibilité réseau
* Identifier les protocoles ou applications non couverts par les paquets Zeek actuels et évaluer le risque de détection manquée
* Tester de nouveaux paquets Zeek communautaires contre le trafic de production capturé pour évaluer leur pertinence et leur fiabilité

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1040** | Network Sniffing - capture et analyse du trafic réseau avec Zeek pour la détection |
| **T1071** | Application Layer Protocol - protocoles surveillés par les analyseurs Zeek |

---

### Sources

* [https://www.reddit.com/r/blueteamsec/comments/1vwf9vv/the_cure_for_exceptional_zeek_package_testing/](https://www.reddit.com/r/blueteamsec/comments/1vwf9vv/the_cure_for_exceptional_zeek_package_testing/)
* [https://www.reddit.com/r/blueteamsec/comments/1vwfagw/the_cure_for_exceptional_zeek_package_testing/](https://www.reddit.com/r/blueteamsec/comments/1vwfagw/the_cure_for_exceptional_zeek_package_testing/)
* [https://www.reddit.com/r/blueteamsec/comments/1vwfb3v/the_cure_for_exceptional_zeek_package_testing/](https://www.reddit.com/r/blueteamsec/comments/1vwfb3v/the_cure_for_exceptional_zeek_package_testing/)


---

<div id="bridgehead-campagne-de-typosquatting-npm-traversant-wsl-vers-windows-pour-installer-un-voleur-de-crypto-wallets"></div>

## BRIDGEHEAD : Campagne de typosquatting npm traversant WSL vers Windows pour installer un voleur de crypto-wallets

### Résumé

Une campagne baptisée BRIDGEHEAD exploite le typosquatting sur le registre npm pour distribuer des packages malveillants. Ces packages utilisent le Windows Subsystem for Linux (WSL) comme pont d'entrée vers l'environnement Windows hôte afin d'y déployer un voleur de crypto-wallets. La campagne démontre une technique de cross-contamination entre l'environnement Linux (WSL) et Windows, contournant potentiellement certaines mesures de sécurité natives de Windows.

---

### Analyse opérationnelle

Les équipes SOC doivent surveiller activement les installations de packages npm présentant des noms typosquattés. La surface d'attaque inclut les postes de développement utilisant WSL sous Windows : le passage WSL → Windows est un vecteur de contournement qui nécessite une visibilité spécifique. Les EDR doivent couvrir l'activité WSL et ses interactions avec le système de fichiers Windows (/mnt/c/, \\wsl$\). La détection doit inclure la surveillance des accès aux fichiers de wallets crypto (wallet.dat, keystore, extensions de navigateur type MetaMask). Les pipelines CI/CD doivent intégrer des scans de dépendances et des listes blanches de packages npm.

---

### Implications stratégiques

Cette campagne illustre l'évolution des attaques sur la chaîne d'approvisionnement logicielle (supply chain) via les registres de paquets open-source. L'utilisation de WSL comme pont d'attaque vers Windows élargit la surface d'attaque pour les organisations ayant adopté WSL dans leurs flux de travail de développement. Le ciblage des crypto-wallets indique une motivation financière, avec un impact direct sur les actifs numériques des utilisateurs compromis. Les organisations doivent reconsidérer leur posture de sécurité autour des outils de développement et des environnements hybrides Linux/Windows.

---

### Recommandations

* Implémenter un proxy npm privé avec validation des packages et listes blanches
* Déployer des règles EDR couvrant l'activité WSL et ses interactions avec Windows
* Surveiller les accès aux fichiers de wallets crypto sur les postes de développement
* Sensibiliser les développeurs aux risques de typosquatting et à la vérification des noms de packages
* Intégrer des outils de scan de dépendances (Socket, Snyk) dans les pipelines CI/CD

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir une liste blanche des packages npm autorisés dans les pipelines CI/CD
* Mettre en place des outils de scan de dépendances (ex. npm audit, Snyk, Socket)
* Sensibiliser les développeurs au risque de typosquatting sur les registres de paquets
* Surveiller l'activation de WSL sur les postes Windows et restreindre son usage si non nécessaire

#### Phase 2 — Détection et analyse

* Détecter les installations de packages npm présentant des noms proches de paquets légitimes (typosquatting)
* Surveiller les processus WSL lançant des exécutables Windows ou accédant au système de fichiers Windows (\\wsl$\, /mnt/c/)
* Corréler les téléchargements de packages npm avec une activité réseau sortante anormale post-installation
* Détecter l'accès ou la lecture de fichiers de wallets crypto (ex. wallet.dat, keystore) sur les postes Windows

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les postes ayant installé le package malveillant
* Bloquer les domaines et adresses IP C2 identifiés au niveau des pare-feu et proxies
* Supprimer le package npm malveillant des registres internes (proxy npm privé, cache)
* Révoquer et régénérer les clés/wallets crypto potentiellement compromis

#### Phase 4 — Activités post-incident

* Analyser le package malveillant pour extraire les IOC et TTP complets
* Vérifier l'intégrité des wallets crypto et des identifiants stockés sur les machines affectées
* Mettre à jour les règles de détection EDR/SIEM avec les indicateurs extraits
* Documenter l'incident et mener une revue post-mortem avec les équipes développement et sécurité

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs npm/proxy tous les téléchargements de packages avec des noms typosquattés sur les 90 derniers jours
* Chercher des processus WSL exécutant des binaires Windows ou accédant à /mnt/c/ de manière inhabituelle
* Identifier d'éventuels packages npm malveillants supplémentaires publiés par le même acteur ou compte npm
* Analyser les chaînes de dépendances (dependency tree) pour détecter des packages compromis transitivement

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1588.006** | Obtain Capabilities - Vulnerabilities (typosquatting de packages npm) |
| **T1059.007** | Command and Scripting Interpreter - JavaScript (exécution via packages npm) |
| **T1027** | Obfuscated Files or Information |
| **T1105** | Ingress Tool Transfer |
| **T1555** | Credentials from Password Stores (vol de crypto-wallets) |

---

### Sources

* [https://www.reddit.com/r/blueteamsec/comments/1vwf6ny/bridgehead_an_npm_typosquatting_campaign_that/](https://www.reddit.com/r/blueteamsec/comments/1vwf6ny/bridgehead_an_npm_typosquatting_campaign_that/)


---

<div id="natural-language-nmap-modele-slm-local-convertissant-le-langage-naturel-en-commandes-nmap"></div>

## natural-language-nmap : Modèle SLM local convertissant le langage naturel en commandes nmap

### Résumé

Un projet expérimental de fine-tuning d'un Small Language Model (SLM) fonctionnant uniquement sur CPU en local a été publié. Cet outil, baptisé natural-language-nmap, permet de convertir des requêtes en langage naturel en commandes nmap prêtes à l'emploi. Le modèle tourne localement sans dépendance cloud, ce qui en fait un outil potentiellement utile pour les équipes blue team souhaitant automatiser ou simplifier la génération de commandes de reconnaissance réseau.

---

### Analyse opérationnelle

Cet outil peut réduire la barrière technique pour les analystes SOC/junior dans la génération de commandes nmap complexes. Cependant, il présente un risque d'utilisation abusive : un acteur malveillant disposant d'un accès initial pourrait s'en servir pour automatiser la reconnaissance réseau interne. Les équipes doivent évaluer l'outil en environnement contrôlé avant déploiement, et s'assurer que les commandes générées ne contiennent pas d'options destructrices ou excessivement bruyantes (ex. -T5, scripts NSE agressifs). L'exécution locale sur CPU est un avantage pour la confidentialité mais limite la vélocité.

---

### Implications stratégiques

L'émergence de SLM fine-tunés pour des tâches de sécurité offensive et défensive marque une tendance d'industrialisation des outils SecOps par l'IA. Les organisations doivent anticiper une démocratisation de ce type d'outils, tant pour la défense que pour l'attaque. La capacité à exécuter localement sans infrastructure cloud réduit les coûts et les risques de fuite de données, mais facilite également l'adoption par des acteurs malveillants. Une politique de gouvernance des outils IA en environnement sécurité doit être définie.

---

### Recommandations

* Évaluer l'outil en environnement de test isolé avant tout déploiement opérationnel
* Définir une politique d'utilisation encadrant les outils d'IA pour les tâches de sécurité
* Surveiller l'émergence d'outils similaires pouvant être détournés à des fins offensives
* Former les équipes SOC à la validation manuelle des commandes générées par IA

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Évaluer l'outil dans un environnement isolé avant tout déploiement
* Vérifier que le modèle SLM ne génère pas de commandes nmap destructrices (ex. -T5 agressif, scripts NSE dangereux)

#### Phase 2 — Détection et analyse

* Surveiller l'utilisation de l'outil via les logs d'audit système
* Corréler les commandes nmap générées avec les politiques de scan autorisées

#### Phase 3 — Confinement, éradication et récupération

* Restreindre l'utilisation de l'outil aux équipes autorisées via contrôle d'accès

#### Phase 4 — Activités post-incident

* Documenter les cas où l'outil a généré des commandes inattendues ou non conformes

#### Phase 5 — Threat Hunting (proactif)

* Vérifier qu'aucun acteur malveillant n'exploite un outil similaire pour automatiser la reconnaissance interne

---

### Sources

* [https://www.reddit.com/r/blueteamsec/comments/1vwddk7/naturallanguagenmap_experimental_slm_fine_tune/](https://www.reddit.com/r/blueteamsec/comments/1vwddk7/naturallanguagenmap_experimental_slm_fine_tune/)


---

<div id="fortitool-cracking-de-bout-en-bout-du-firmware-fortios-et-decouverte-dune-cle-inedite"></div>

## fortitool : Cracking de bout en bout du firmware FortiOS et découverte d'une clé inédite

### Résumé

Un outil baptisé fortitool permet le cracking de bout en bout du firmware FortiOS de Fortinet. L'outil inclut la découverte d'une clé de chiffrement qui n'avait pas été publiquement identifiée auparavant. Cette recherche ouvre la voie à l'analyse approfondie du firmware FortiOS, potentiellement à des fins d'audit de sécurité, de recherche de vulnérabilités, ou inversement, d'exploitation par des acteurs malveillants.

---

### Analyse opérationnelle

La divulgation d'une clé de déchiffrement du firmware FortiOS facilite l'extraction et l'analyse du contenu du firmware par tout acteur, légitime ou malveillant. Les équipes SOC doivent s'attendre à une augmentation potentielle des recherches de vulnérabilités dans FortiOS, pouvant mener à des exploits ou des PoC publics. Les administrateurs doivent vérifier que leurs équipements Fortinet exécutent des versions de firmware à jour et appliquer les correctifs dès leur disponibilité. La surveillance des équipements Fortinet doit être renforcée, en particulier sur les accès administratifs et les modifications de configuration.

---

### Implications stratégiques

La publication d'outils de cracking de firmware pour des équipements réseau largement déployés comme Fortinet soulève des enjeux critiques pour la sécurité des infrastructures. Fortinet étant un acteur majeur des pare-feu et routeurs enterprise, toute vulnérabilité découverte via cet outil pourrait avoir un impact sectoriel massif. Cette recherche souligne l'importance de la sécurité par transparence et de la collaboration entre chercheurs et éditeurs. Les organisations doivent anticiper la publication potentielle de vulnérabilités FortiOS et préparer des plans de remédiation accélérés.

---

### Recommandations

* Mettre à jour immédiatement tous les équipements Fortinet avec les dernières versions de firmware
* Renforcer le contrôle d'accès aux équipements Fortinet (MFA, restriction IP, logs d'audit)
* Surveiller les avis de sécurité Fortinet (PSIRT) de manière proactive
* Préparer un plan de remédiation accéléré en cas de publication de vulnérabilités FortiOS
* Évaluer la posture de sécurité des équipements Fortinet exposés sur Internet

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier tous les équipements Fortinet (FortiGate, FortiAnalyzer, etc.) et leurs versions de firmware
* Maintenir une veille active sur les avis de sécurité Fortinet (PSIRT)
* Segmenter et restreindre l'accès administratif aux équipements Fortinet

#### Phase 2 — Détection et analyse

* Surveiller les accès non autorisés au firmware FortiOS (téléchargements, extractions)
* Détecter les tentatives d'extraction de clés de chiffrement du firmware
* Corréler les activités de reverse engineering avec des comportements anormaux sur les équipements

#### Phase 3 — Confinement, éradication et récupération

* Isoler les équipements Fortinet dont le firmware aurait été compromis ou altéré
* Appliquer immédiatement les correctifs Fortinet dès leur disponibilité
* Réinitialiser les credentials et clés de chiffrement des équipements potentiellement affectés

#### Phase 4 — Activités post-incident

* Analyser les versions de firmware déployées pour identifier celles vulnérables
* Mettre à jour les signatures IDS/IPS avec les indicateurs issus de la recherche
* Documenter les clés et méthodes de déchiffrement découvertes pour les futures analyses

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des traces d'extraction ou d'analyse de firmware FortiOS dans les logs réseau
* Identifier des équipements Fortinet exécutant des versions de firmware non supportées ou obsolètes
* Surveiller les repositories publics pour détecter la publication de clés ou d'outils de cracking FortiOS

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1588.006** | Obtain Capabilities - Vulnerabilities (recherche de vulnérabilités dans le firmware) |

---

### Sources

* [https://www.reddit.com/r/blueteamsec/comments/1vwda2a/fortitool_cracking_fortios_firmware_end_to_end/](https://www.reddit.com/r/blueteamsec/comments/1vwda2a/fortitool_cracking_fortios_firmware_end_to_end/)


---

<div id="anatomie-dun-crimekit-macos-clickfix-exploitant-letherhiding"></div>

## Anatomie d'un Crimekit macOS ClickFix exploitant l'EtherHiding

### Résumé

Une analyse détaillée d'un crimekit ciblant macOS a été publiée. Ce kit combine deux techniques : ClickFix, une technique d'ingénierie sociale utilisant de fausses boîtes de dialogue (type CAPTCHA ou erreur) incitant l'utilisateur à copier-coller une commande malveillante, et EtherHiding, qui consiste à cacher des payloads malveillants dans la blockchain Ethereum (via des contrats intelligents ou des données de transactions). Cette combinaison rend la détection et le blocage traditionnels plus difficiles, car le payload est servi depuis une infrastructure décentralisée résiliente.

---

### Analyse opérationnelle

Les équipes SOC doivent étendre leur détection au-delà des infrastructures C2 traditionnelles : la blockchain Ethereum comme canal de distribution de payloads échappe aux listes de blocage DNS/IP classiques. La détection doit se concentrer sur le comportement : exécution de commandes shell sur macOS initiées depuis un navigateur, requêtes vers des nœuds Ethereum ou des API blockchain (etherscan, infura) depuis des processus inhabituels. Les EDR macOS doivent surveiller la création de LaunchAgents/LaunchDaemons et l'exécution de commandes osascript/terminal post-navigation web. La technique ClickFix contourne les protections traditionnelles car l'utilisateur exécute volontairement la commande, rendant l'EDR moins efficace sans analyse comportementale.

---

### Implications stratégiques

L'utilisation de la blockchain Ethereum comme infrastructure de stockage de payloads (EtherHiding) représente une évolution significative des techniques d'évasion, exploitant la résilience et la décentralisation de la blockchain pour rendre le retrait de contenu malveillant quasi impossible. Le ciblage de macOS indique une diversification des plateformes d'attaque au-delà de Windows. Les organisations avec une flotte macOS significative doivent reconsidérer leur posture de sécurité, souvent moins mature que sur Windows. La combinaison ClickFix + EtherHiding démontre une sophistication croissante des crimekits disponibles sur le marché criminel, abaissant la barrière technique pour les attaquants.

---

### Recommandations

* Déployer des règles EDR macOS détectant l'exécution de commandes shell initiées depuis un navigateur
* Surveiller les requêtes vers des nœuds Ethereum et API blockchain depuis des processus non liés à des applications crypto légitimes
* Sensibiliser les utilisateurs macOS aux attaques ClickFix et aux fausses boîtes de dialogue CAPTCHA
* Mettre en place une liste blanche des applications autorisées à exécuter des scripts shell sur macOS
* Surveiller la création de LaunchAgents/LaunchDaemons suspects sur les postes macOS

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer des solutions EDR couvrant macOS avec détection comportementale
* Sensibiliser les utilisateurs macOS aux attaques ClickFix (fausses boîtes de dialogue CAPTCHA/copier-coller)
* Surveiller les accès aux portefeuilles Ethereum et aux explorateurs de blockchain depuis les postes macOS

#### Phase 2 — Détection et analyse

* Détecter les exécutions de commandes shell sur macOS initiées depuis un navigateur (copier-coller de code malveillant)
* Surveiller les requêtes vers des nœuds Ethereum ou des API blockchain (ex. etherscan[.]io, infura[.]io) depuis des processus inhabituels
* Corréler les alertes de ClickFix (fausses boîtes de dialogue) avec une activité shell postérieure
* Détecter les modifications de la chaîne de keychain macOS ou l'accès à des données de wallets crypto

#### Phase 3 — Confinement, éradication et récupération

* Isoler les postes macOS affectés du réseau
* Bloquer les adresses Ethereum et les contrats intelligents malveillants identifiés au niveau des proxies
* Supprimer les payloads et persistance installés (LaunchAgents, LaunchDaemons, profils de configuration)
* Révoquer les credentials et clés crypto potentiellement compromis

#### Phase 4 — Activités post-incident

* Analyser le crimekit pour extraire les IOC, adresses Ethereum et TTP complets
* Vérifier l'intégrité des wallets crypto et des identifiants stockés sur les machines affectées
* Mettre à jour les règles de détection EDR/SIEM avec les indicateurs extraits
* Documenter l'incident et identifier les vecteurs initiaux (site web de phishing, fausse boîte de dialogue)

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs réseau les connexions vers des nœuds Ethereum ou des API blockchain depuis des postes macOS
* Chercher des LaunchAgents/LaunchDaemons suspects installés récemment sur les postes macOS
* Identifier d'éventuelles variantes du crimekit ClickFix en analysant les alertes similaires sur les 90 derniers jours
* Analyser les transactions Ethereum associées aux adresses malveillantes pour cartographier l'infrastructure de l'acteur

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1204.002** | User Execution - Malicious File (ClickFix : incitation à exécuter une commande via fausse boîte de dialogue) |
| **T1027** | Obfuscated Files or Information (EtherHiding : payload caché dans la blockchain Ethereum) |
| **T1105** | Ingress Tool Transfer (récupération du payload via des transactions Ethereum) |
| **T1059.004** | Command and Scripting Interpreter - Unix Shell (exécution de commandes sur macOS) |

---

### Sources

* [https://www.reddit.com/r/blueteamsec/comments/1vwd9gl/anatomy_of_a_macos_clickfix_crimekit_that/](https://www.reddit.com/r/blueteamsec/comments/1vwd9gl/anatomy_of_a_macos_clickfix_crimekit_that/)


---

<div id="failles-logiques-et-correctifs-pour-les-regles-de-detection-curees-google-secops-chronicle-o365-ueba"></div>

## Failles logiques et correctifs pour les règles de détection curées Google SecOps (Chronicle) - O365 & UEBA

### Résumé

Un post publié sur le subreddit r/blueteamsec discute de failles logiques identifiées dans les règles de détection curées de Google SecOps (Chronicle) pour Office 365 et UEBA (User and Entity Behavior Analytics), ainsi que des correctifs proposés pour ces règles.

---

### Analyse opérationnelle

Les équipes SOC utilisant Google SecOps/Chronicle doivent auditer leurs règles de détection curées pour O365 et UEBA afin d'identifier les failles logiques mentionnées. Des règles de détection défectueuses peuvent générer des faux positifs ou, plus grave, manquer des détections critiques. Recommandation : appliquer les correctifs publiés, tester la couverture de détection après modification, et valider que les règles corrigées n'introduisent pas de régressions.

---

### Implications stratégiques

La fiabilité des règles de détection tierces (curated rules) est un enjeu de confiance majeur pour les plateformes SIEM/XDR. Les organisations ne doivent pas considérer les règles pré-packagées comme infaillibles et doivent maintenir un processus de revue et de validation systématique des règles importées.

---

### Recommandations

* Auditer immédiatement les règles de détection curées Google SecOps pour O365 et UEBA
* Appliquer les correctifs publiés et tester la couverture post-modification
* Mettre en place un processus de validation continue des règles de détection tierces

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les règles de détection Google SecOps/Chronicle déployées pour O365 et UEBA
* Mettre en place un processus de revue périodique des règles curées

#### Phase 2 — Détection et analyse

* Comparer les règles curées actuelles avec les correctifs publiés
* Identifier les failles logiques pouvant causer des faux négatifs ou faux positifs

#### Phase 3 — Confinement, éradication et récupération

* Appliquer les correctifs aux règles défectueuses
* Désactiver temporairement les règles identifiées comme problématiques si nécessaire

#### Phase 4 — Activités post-incident

* Documenter les failles identifiées et les correctifs appliqués
* Mettre en place un processus de validation des règles avant déploiement

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs historiques les événements qui auraient dû être détectés par les règles défectueuses
* Évaluer la couverture de détection globale après application des correctifs

---

### Sources

* [https://www.reddit.com/r/blueteamsec/comments/1vw2g9h/logic_flaws_fixes_for_google_secops_chronicle/](https://www.reddit.com/r/blueteamsec/comments/1vw2g9h/logic_flaws_fixes_for_google_secops_chronicle/)


---

<div id="patch-windows-11-kb5121003-crashes-dans-les-jeux-video-et-problemes-dimprimantes"></div>

## Patch Windows 11 KB5121003 : crashes dans les jeux vidéo et problèmes d'imprimantes

### Résumé

La mise à jour de sécurité KB5121003 pour Windows 11 provoque des crashes dans les jeux vidéo et des problèmes avec les imprimantes. Ce correctif de sécurité introduit une instabilité applicative, soulevant le dilemme entre appliquer immédiatement les patchs de sécurité et attendre leur stabilisation.

---

### Analyse opérationnelle

Les équipes IT doivent évaluer le risque de ne pas patcher (surface d'attaque exposée) versus l'impact métier des crashes applicatifs. Recommandation de tester KB5121003 en environnement de pré-production avant déploiement massif. Surveiller les rapports de stabilité post-patch et prévoir un plan de rollback.

---

### Implications stratégiques

Le compromis entre sécurité et stabilité opérationnelle est un enjeu récurrent du patch management. Les organisations doivent disposer d'une stratégie de patching graduée (ring deployment) pour minimiser les disruptions tout en réduisant la surface d'attaque. Le retard de patching expose à l'exploitation de vulnérabilités connues.

---

### Recommandations

* Tester KB5121003 en pré-production avant déploiement généralisé
* Mettre en place un déploiement par paliers (ring deployment)
* Préparer un plan de rollback en cas d'instabilité confirmée
* Surveiller les vulnérabilités corrigées par ce patch et évaluer le risque d'exposition

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire à jour des postes Windows 11 et des applications critiques
* Mettre en place un environnement de test pour valider les patches avant déploiement

#### Phase 2 — Détection et analyse

* Surveiller les rapports de crashes applicatifs post-déploiement de KB5121003
* Détecter les augmentations anormales de tickets support liés aux jeux vidéo ou imprimantes

#### Phase 3 — Confinement, éradication et récupération

* Suspendre le déploiement de KB5121003 si des instabilités sont confirmées
* Envisager le rollback du patch sur les systèmes affectés

#### Phase 4 — Activités post-incident

* Documenter l'impact métier du patch et la décision de rollback/déploiement
* Attendre une version corrigée du patch avant redéploiement

#### Phase 5 — Threat Hunting (proactif)

* Vérifier si des systèmes non patchés présentent des signes d'exploitation active
* Évaluer l'exposition aux vulnérabilités corrigées par KB5121003 sur les systèmes où le patch a été rollback

---

### Sources

* [https://mastobot.ping.moi/@Bobe_bot/117147068866236846](https://mastobot.ping.moi/@Bobe_bot/117147068866236846)


---

<div id="parsedmarc-outil-open-source-danalyse-des-rapports-dmarc"></div>

## parsedmarc : outil open source d'analyse des rapports DMARC

### Résumé

parsedmarc est un package Python et un CLI open source permettant de parser et analyser les rapports DMARC agrégés (RUA) et forensiques (RUF). L'outil transforme ces rapports en données exploitables, offrant une visibilité à grande échelle sur l'alignement SPF/DKIM des domaines.

---

### Analyse opérationnelle

Les équipes SOC et IT peuvent utiliser parsedmarc pour automatiser l'analyse des rapports DMARC, identifier les sources d'usurpation d'emails, et visualiser l'alignement SPF/DKIM à grande échelle. Cela améliore la détection des tentatives de phishing et de BEC via l'analyse des échecs d'authentification email. L'outil permet de transformer des rapports XML bruts en données structurées exploitables pour le monitoring continu.

---

### Implications stratégiques

Le renforcement de la posture email security via DMARC est un enjeu critique pour la protection de la marque et la prévention des attaques BEC. La capacité à analyser les rapports à grande échelle permet une gouvernance email plus mature et une réduction du risque d'usurpation de domaine.

---

### Recommandations

* Déployer parsedmarc pour automatiser l'analyse des rapports DMARC
* Mettre en place un monitoring continu de l'alignement SPF/DKIM
* Progresser vers une politique DMARC p=reject après validation des sources légitimes

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer parsedmarc dans l'environnement d'analyse SOC
* Configurer la réception des rapports DMARC RUA/RUF pour les domaines de l'organisation

#### Phase 2 — Détection et analyse

* Analyser régulièrement les rapports DMARC pour identifier les échecs d'authentification SPF/DKIM
* Détecter les sources non autorisées envoyant des emails au nom des domaines de l'organisation

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les sources identifiées comme usurpatrices via les politiques DMARC
* Passer la politique DMARC de p=none à p=quarantine puis p=reject de manière progressive

#### Phase 4 — Activités post-incident

* Documenter les sources d'usurpation identifiées et les actions correctives
* Affiner les configurations SPF/DKIM en fonction des rapports analysés

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les rapports DMARC historiques des patterns d'usurpation non détectés
* Corréler les échecs DMARC avec les campagnes de phishing ou BEC observées

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing - DMARC aide à prévenir l'usurpation d'identité email |

---

### Sources

* [https://mastobot.ping.moi/@Bobe_bot/117147068777977245](https://mastobot.ping.moi/@Bobe_bot/117147068777977245)


---

<div id="campagne-bec-diffusant-agent-tesla-v4-via-un-fichier-jscript-truffe-demojis-unicode"></div>

## Campagne BEC diffusant Agent Tesla v4 via un fichier JScript truffé d'emojis Unicode

### Résumé

Des chercheurs de KnowBe4 ont identifié une campagne de compromission d'emails professionnels (BEC) ciblant le personnel financier avec une fausse demande urgente de confirmation d'un document bancaire. La pièce jointe JScript de 6,94 MB, nommée « SWIFT Payment Maker 103 - 10.06.26.JS », usurpe l'identité de Metropolitan Bank and Trust Company et cache le code d'Agent Tesla v4 derrière de grandes quantités d'emojis Unicode. Windows Script Host ignore ces caractères lors de l'analyse JScript, permettant l'exécution du payload malveillant.

---

### Analyse opérationnelle

Détection : surveiller les emails avec pièces jointes .JS de grande taille, bloquer les extensions JScript au niveau de la passerelle email. L'analyse des fichiers .JS doit inclure la recherche de payloads obfusqués par emojis Unicode. Agent Tesla v4 est un infostealer exfiltrant des credentials via des protocoles SMTP/FTP. Déployer des règles YARA pour détecter les patterns d'obfuscation par emojis. Surveiller les connexions réseau sortantes inhabituelles depuis wscript.exe/cscript.exe. Le dropper exploite la légitimité perçue d'un message SWIFT/bancaire pour augmenter le taux de clic.

---

### Implications stratégiques

Les campagnes BEC ciblant les équipes financières représentent un risque financier direct et un risque de compromission de credentials d'entreprise. L'utilisation de techniques d'obfuscation par emojis Unicode démontre l'évolution continue des techniques d'évasion des acteurs de menace. Le secteur financier reste une cible privilégiée, et l'usurpation d'institutions bancaires (Metropolitan Bank and Trust Company) exploite la confiance dans les flux SWIFT.

---

### Recommandations

* Bloquer toutes les pièces jointes .JS/.JScript au niveau de la passerelle email
* Déployer des règles de détection pour l'obfuscation par emojis Unicode dans les fichiers script
* Surveiller l'exécution de wscript.exe/cscript.exe et les connexions sortantes associées
* Former le personnel financier à la reconnaissance des emails BEC usurpant des institutions bancaires
* Mettre en place des règles YARA pour détecter les variantes d'Agent Tesla v4

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Bloquer les pièces jointes .JS/.JScript au niveau de la passerelle email
* Désactiver Windows Script Host sur les postes utilisateurs si possible
* Former le personnel financier à reconnaître les emails BEC usurpant des institutions bancaires

#### Phase 2 — Détection et analyse

* Surveiller les emails avec pièces jointes .JS de grande taille (>5 MB)
* Détecter l'exécution de wscript.exe/cscript.exe avec des fichiers JScript
* Surveiller les connexions SMTP/FTP sortantes inhabituelles depuis des processus de scripting
* Rechercher les patterns d'obfuscation par emojis Unicode dans les fichiers JScript

#### Phase 3 — Confinement, éradication et récupération

* Isoler les postes compromis du réseau
* Bloquer les domaines/IPs de C2 d'Agent Tesla identifiés
* Révoquer les credentials potentiellement exfiltrés (email, navigateurs, applications)
* Supprimer les emails de phishing de toutes les boîtes aux lettres

#### Phase 4 — Activités post-incident

* Analyser le fichier JScript pour extraire les IOC complets (C2, protocoles d'exfiltration)
* Évaluer l'étendue de l'exfiltration de credentials
* Renforcer les règles de filtrage email pour les futurs emails similaires

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs email les messages avec pièces jointes .JS contenant des emojis Unicode
* Corréler les exécutions de wscript.exe avec des connexions réseau sortantes suspectes
* Rechercher d'autres variantes d'Agent Tesla v4 dans l'environnement

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.001** | Spearphishing Attachment - email avec pièce jointe JScript |
| **T1059.005** | Command and Scripting Interpreter: Visual Basic - exécution via Windows Script Host |
| **T1027** | Obfuscated Files or Information - obfuscation par emojis Unicode |
| **T1056.001** | Input Capture: Keylogging - Agent Tesla v4 capture les frappes clavier |
| **T1048** | Exfiltration Over Alternative Protocol - Agent Tesla exfiltre via SMTP/FTP |

---

### Sources

* [https://mastodon.social/@hacksgr/117146984600585410](https://mastodon.social/@hacksgr/117146984600585410)


---

<div id="page-de-phishing-hebergee-sur-github-pages-usurpant-potentiellement-ionos"></div>

## Page de phishing hébergée sur GitHub Pages usurpant potentiellement IONOS

### Résumé

Une page de phishing potentiel a été identifiée à l'adresse hxxps[://]shakugxgd[.]github[.]io/jgjuybrdhim[.]github[.]io/IONOSDE[.]html, ciblant potentiellement les clients IONOS. Une analyse de la page est disponible sur urldna.io.

---

### Analyse opérationnelle

IOC à bloquer : domaine shakugxgd[.]github[.]io et l'URL complète de la page de phishing. Vérifier si des utilisateurs ont accédé à cette URL via les logs proxy/DNS. Le phishing hébergé sur GitHub Pages est une technique d'abus de services légitimes courante, contournant potentiellement certains filtres basés sur la réputation de domaine. L'analyse urldna.io peut fournir des détails supplémentaires sur les techniques de phishing employées.

---

### Implications stratégiques

L'abus de plateformes légitimes comme GitHub Pages pour le phishing souligne le défi de bloquer des infrastructures de confiance. Les organisations doivent s'appuyer sur des analyses URL dynamiques et l'inspection de contenu plutôt que sur des listes de blocage statiques basées sur la réputation de domaine.

---

### Recommandations

* Bloquer le domaine shakugxgd[.]github[.]io au niveau des proxies et firewalls
* Vérifier les logs d'accès pour identifier les utilisateurs ayant visité cette page
* Signaler la page à GitHub pour suppression
* Renforcer le filtrage URL pour les sous-domaines github.io suspects

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre en place un filtrage URL dynamique pour les sous-domaines github.io
* Configurer les proxies web pour analyser le contenu des pages GitHub Pages suspectes

#### Phase 2 — Détection et analyse

* Vérifier si des utilisateurs ont accédé à shakugxgd[.]github[.]io via les logs proxy/DNS
* Surveiller le trafic vers des sous-domaines github.io avec des patterns d'URL suspects
* Analyser la page de phishing via urldna.io pour identifier les techniques et IOC associés

#### Phase 3 — Confinement, éradication et récupération

* Bloquer le domaine shakugxgd[.]github[.]io au niveau des proxies et firewalls
* Signaler la page de phishing à GitHub pour suppression
* Isoler les postes ayant potentiellement interagi avec la page

#### Phase 4 — Activités post-incident

* Documenter l'infrastructure de phishing et les techniques utilisées
* Vérifier si des credentials ont été saisis sur la page de phishing

#### Phase 5 — Threat Hunting (proactif)

* Rechercher d'autres pages de phishing hébergées sur github.io ciblant l'organisation
* Corréler avec d'autres campagnes de phishing utilisant des services d'hébergement légitimes

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `shakugxgd[.]github[.]io` | Medium |
| URL | `hxxps[://]shakugxgd[.]github[.]io/jgjuybrdhim[.]github[.]io/IONOSDE[.]html` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Spearphishing Link - page de phishing hébergée sur GitHub Pages |
| **T1204.002** | User Execution: Malicious File - si l'utilisateur interagit avec la page |

---

### Sources

* [https://infosec.exchange/@urldna/117146714681334464](https://infosec.exchange/@urldna/117146714681334464)


---

<div id="revue-hebdomadaire-des-incidents-de-securite-297-incidents-incluant-ascii-group-sears-kingston-et-columbia-university"></div>

## Revue hebdomadaire des incidents de sécurité : 297 incidents incluant ASCII Group, Sears, Kingston et Columbia University

### Résumé

Une revue hebdomadaire des violations de données et incidents de sécurité couvrant la période du 17 au 23 août 2026 recense 297 incidents au total, incluant des violations affectant ASCII Group, Sears, Kingston et Columbia University. Les incidents couvrent des catégories telles que les fuites de données, le ransomware et le hacking.

---

### Analyse opérationnelle

Les équipes SOC doivent vérifier si leur organisation ou ses partenaires/tiers sont mentionnés dans ces incidents. Le volume de 297 incidents en une semaine indique un niveau d'activité malveillante élevé. Surveiller les expositions de credentials liées à ces violations via le dark web monitoring. Les organisations mentionnées (Sears, Kingston, Columbia University) suggèrent une diversité de vecteurs d'attaque et de secteurs ciblés.

---

### Implications stratégiques

Le volume élevé d'incidents (297/semaine) souligne l'accentuation continue de la menace cybercriminelle. La diversité des victimes (retail, éducation, technologie) démontre qu'aucun secteur n'est épargné. Les organisations doivent renforcer leur posture de cybersécurité, leur résilience opérationnelle et leur stratégie de gestion des risques tiers.

---

### Recommandations

* Vérifier si l'organisation ou ses partenaires sont mentionnés dans les incidents rapportés
* Renforcer le monitoring du dark web pour les credentials exposés
* Analyser les vecteurs d'attaque des incidents similaires pour adapter les défenses
* Renforcer la stratégie de gestion des risques tiers

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre en place un monitoring du dark web pour détecter les expositions de données liées à l'organisation
* Maintenir un inventaire des tiers et partenaires pouvant être affectés par ces violations

#### Phase 2 — Détection et analyse

* Vérifier si l'organisation, ses employés ou ses partenaires sont mentionnés dans les 297 incidents
* Surveiller les fuites de credentials sur les forums et marketplaces du dark web

#### Phase 3 — Confinement, éradication et récupération

* Si l'organisation est affectée, activer le plan de réponse aux incidents
* Révoquer les credentials potentiellement compromis

#### Phase 4 — Activités post-incident

* Analyser les leçons apprises des incidents affectant des organisations similaires
* Renforcer les contrôles de sécurité en fonction des vecteurs d'attaque observés

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs des indicateurs d'attaque similaires aux incidents rapportés
* Corréler les TTPs observés dans les violations avec les détections internes

---

### Sources

* [https://mastodon.social/@NickAEsp/117146706590905933](https://mastodon.social/@NickAEsp/117146706590905933)


---

<div id="podcast-hebdomadaire-297-incidents-dont-ascii-group-sears-kingston-columbia-university"></div>

## Podcast hebdomadaire : 297 incidents dont ASCII Group, Sears, Kingston, Columbia University

### Résumé

Podcast hebdomadaire du 17 au 23 août 2026 recensant 297 incidents de cybersécurité incluant des fuites de données et attaques ransomware visant ASCII Group, Sears, Kingston et Columbia University.

---

### Analyse opérationnelle

Le volume élevé d'incidents (297 en une semaine) indique une activité cybercriminelle soutenue. Les équipes SOC doivent corréler les IOCs publiés avec leurs logs et vérifier l'exposition de leur organisation vis-à-vis des entités compromises. Les chaînes d'approvisionnement liées à Kingston (stockage/mémoire) et Sears (retail) méritent une attention particulière.

---

### Implications stratégiques

Le volume d'incidents illustre l'intensification continue des campagnes malveillantes à l'échelle mondiale. Les organisations doivent maintenir une veille threat intelligence active et renforcer leur posture de sécurité globale.

---

### Recommandations

* Surveiller les publications d'IOCs liées aux 297 incidents de la semaine
* Vérifier les relations fournisseurs avec Kingston et Sears
* Mettre à jour les règles de détection SIEM avec les indicateurs publiés

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir une veille threat intelligence hebdomadaire sur les incidents recensés
* Tenir à jour l'inventaire des actifs et dépendances vis-à-vis des organisations mentionnées (Sears, Kingston, Columbia University, ASCII Group)

#### Phase 2 — Détection et analyse

* Corréler les IOCs publiés dans le cadre des 297 incidents avec les logs SIEM
* Surveiller les indicateurs de compromission liés aux campagnes ransomware et data breach de la semaine

#### Phase 3 — Confinement, éradication et récupération

* Isoler tout système présentant des indicateurs liés aux incidents signalés
* Bloquer les domaines/IPs malveillants identifiés dans le cadre des incidents

#### Phase 4 — Activités post-incident

* Documenter les leçons apprises des incidents de la semaine
* Mettre à jour les règles de détection SIEM avec les nouveaux IOC

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans l'environnement des TTPs communs aux 297 incidents recensés
* Analyser les tendances hebdomadaires pour anticiper les prochaines vagues d'attaques

---

### Sources

* [https://mastodon.social/@NickAEsp/117146706409056029](https://mastodon.social/@NickAEsp/117146706409056029)


---

<div id="centaines-de-cles-aws-leakees-donnant-un-controle-total-sur-des-comptes-corporate"></div>

## Centaines de clés AWS leakées donnant un contrôle total sur des comptes corporate

### Résumé

Des centaines de clés d'accès AWS ont fuité, offrant un contrôle total sur des comptes d'entreprises. Les clés exposées permettraient à des acteurs malveillants d'accéder aux infrastructures cloud et aux données des organisations concernées.

---

### Analyse opérationnelle

Vérifier immédiatement la présence de clés AWS exposées dans les dépôts publics, logs, conteneurs et configurations. Activer AWS CloudTrail pour détecter toute utilisation anormale de clés. Déployer AWS IAM Access Analyzer pour identifier les ressources exposées. Rotater toutes les clés potentiellement compromises et implémenter une politique de moindre privilège avec MFA obligatoire.

---

### Implications stratégiques

L'exposition massive de clés cloud souligne les risques systémiques liés à la mauvaise gestion des secrets en environnement cloud. Les organisations doivent adopter des solutions de gestion des secrets (Vault, AWS Secrets Manager) et intégrer des contrôles automatisés dans les pipelines CI/CD pour prévenir les fuites. L'impact financier et réputationnel d'une compromission cloud peut être majeur.

---

### Recommandations

* Auditer toutes les clés AWS actives et leur exposition potentielle
* Implémenter AWS Secrets Manager pour la gestion centralisée des secrets
* Activer MFA sur tous les comptes root et IAM
* Déployer des outils de détection de secrets dans les pipelines CI/CD
* Mettre en place une politique de rotation automatique des clés

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Implémenter AWS IAM Access Analyzer pour détecter les ressources exposées
* Mettre en place une politique de rotation automatique des clés AWS
* Déployer un outil de détection de secrets dans les dépôts (GitLeaks, TruffleHog)

#### Phase 2 — Détection et analyse

* Surveiller AWS CloudTrail pour toute utilisation anormale de clés d'accès
* Configurer des alertes sur les appels API sensibles (CreateUser, PutBucketPolicy, AssumeRole) depuis des IP inconnues
* Scanner les dépôts publics GitHub/GitLab pour des clés AWS exposées

#### Phase 3 — Confinement, éradication et récupération

* Désactiver et rotater immédiatement toutes les clés AWS identifiées comme leakées
* Révoquer les sessions actives associées aux clés compromises
* Bloquer les IPs sources ayant utilisé les clés compromises
* Isoler les ressources cloud ayant fait l'objet d'accès non autorisés

#### Phase 4 — Activités post-incident

* Auditer toutes les actions effectuées avec les clés compromises (CloudTrail)
* Évaluer l'étendue de l'exfiltration de données et des modifications d'infrastructure
* Mettre en place MFA obligatoire pour tous les comptes IAM
* Documenter l'incident et notifier les parties prenantes

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des patterns d'utilisation suspects dans l'historique CloudTrail des 90 derniers jours
* Identifier d'autres secrets potentiellement exposés dans les dépôts et conteneurs
* Surveiller les forums et marketplaces pour des clés organisationnelles en vente

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1552** | Unsecured Credentials - Credentials in files or repositories |

---

### Sources

* [https://www.bleepingcomputer.com/news/security/hundreds-of-leaked-aws-keys-give-full-control-over-corporate-accounts/](https://www.bleepingcomputer.com/news/security/hundreds-of-leaked-aws-keys-give-full-control-over-corporate-accounts/)


---

<div id="shinyhunters-revendique-le-piratage-de-logitech-et-streamlabs"></div>

## ShinyHunters revendique le piratage de Logitech et Streamlabs

### Résumé

Le groupe ShinyHunters revendique le piratage de Logitech et Streamlabs et menace de publier les données volées. Les streameurs seraient particulièrement visés selon Zataz.

---

### Analyse opérationnelle

Surveiller les fuites de données potentielles sur les forums et plateformes de leak. Vérifier si des comptes liés à Logitech/Streamlabs sont utilisés dans l'infrastructure de l'organisation. Sensibiliser les utilisateurs de Streamlabs/OBS aux risques de phishing ciblant les streameurs. Surveiller les indicateurs de compromission associés aux TTPs historiques de ShinyHunters.

---

### Implications stratégiques

Le ciblage de l'écosystème streaming/jeu vidéo par ShinyHunters (acteur récidiviste) souligne l'attractivité des données de créateurs de contenu. Les entreprises technologiques doivent renforcer leur posture de sécurité et préparer leur communication de crise. Le ciblage spécifique des streameurs peut avoir des conséquences économiques directes pour l'écosystème de création de contenu.

---

### Recommandations

* Surveiller les forums pour l'apparition des données Logitech/Streamlabs
* Sensibiliser les streameurs aux risques de phishing post-fuite
* Vérifier la réutilisation de mots de passe entre Streamlabs et services professionnels
* Mettre à jour les règles SIEM avec les IOC historiques de ShinyHunters

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir une veille sur les revendications de ShinyHunters sur les forums et plateformes de leak
* Cartographier les dépendances avec Logitech et Streamlabs dans l'infrastructure

#### Phase 2 — Détection et analyse

* Surveiller les canaux de leak pour l'apparition des données Logitech/Streamlabs
* Détecter les tentatives de phishing ciblant les streameurs exploitant les données volées
* Corréler les IOCs historiques de ShinyHunters avec les logs SIEM

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les domaines et adresses IP associés aux infrastructures de ShinyHunters
* Isoler les comptes et systèmes liés à Streamlabs/Logitech présentant une activité suspecte
* Révoquer les tokens d'authentification liés aux services Streamlabs

#### Phase 4 — Activités post-incident

* Évaluer l'exposition des données organisationnelles via les comptes Logitech/Streamlabs des employés
* Notifier les utilisateurs concernés si des données internes sont identifiées dans le leak
* Mettre à jour les règles de détection avec les nouveaux IOC de ShinyHunters

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des indicateurs d'activité ShinyHunters dans l'environnement (TTPs historiques)
* Surveiller les marketplaces de données pour des jeux de données liés à Logitech/Streamlabs
* Identifier les comptes d'employés utilisant des services Logitech/Streamlabs avec réutilisation de mots de passe

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1567** | Exfiltration over Web Service |
| **T1657** | Financial Theft |

---

### Sources

* [https://www.zataz.com/shinyhunters-menace-logitech-et-streamlabs/](https://www.zataz.com/shinyhunters-menace-logitech-et-streamlabs/)


---

<div id="lockbit-50-revendique-une-attaque-contre-actua-groupe-francais-de-recrutement"></div>

## LockBit 5.0 revendique une attaque contre Actua, groupe français de recrutement

### Résumé

Le ransomware LockBit 5.0 revendique une attaque contre Actua, groupe français de recrutement et travail temporaire (37 agences). Le groupe menace de publier fin août des passeports, diplômes, CV et attestations d'assurance de plus de 100 000 personnes.

---

### Analyse opérationnelle

Vérifier l'exposition de l'organisation aux TTPs de LockBit 5.0. Surveiller les publications sur le site de leak de LockBit. Les données compromises incluant des documents d'identité (passeports) constituent un risque d'usurpation d'identité à grande échelle. Mettre en place une détection des TTPs LockBit (chiffrement rapide, exploitation de vulnérabilités, utilisation d'outils comme Cobalt Strike). Vérifier les sauvegardes et leur intégrité.

---

### Implications stratégiques

Le ciblage d'un groupe français de recrutement par LockBit 5.0 expose des données PII massives (passeports, CV) créant un risque d'usurpation d'identité à grande échelle. L'impact RGPD est majeur avec obligation de notification à la CNIL dans les 72 heures. Les organisations du secteur RH doivent renforcer leur résilience face au ransomware et préparer des plans de réponse incluant notification CNIL et communication aux personnes concernées. La menace de publication de passeports expose à des risques d'usurpation d'identité pouvant affecter les individus au-delà du périmètre professionnel.

---

### Recommandations

* Vérifier immédiatement l'intégrité et l'isolabilité des sauvegardes
* Surveiller le site de leak LockBit pour l'apparition des données Actua
* Préparer un plan de notification CNIL et communication aux personnes concernées
* Renforcer la détection des TTPs LockBit (Cobalt Strike, PsExec, SMB exploitation)
* Sensibiliser les collaborateurs aux risques de phishing post-incident exploitant les PII

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir une veille sur le site de leak de LockBit 5.0
* Vérifier l'intégrité et la testabilité des sauvegardes régulièrement
* Implémenter des règles de détection pour les TTPs connus de LockBit (Cobalt Strike, PsExec, exploitation de vulnérabilités SMB)

#### Phase 2 — Détection et analyse

* Surveiller les indicateurs de chiffrement massif de fichiers
* Détecter l'utilisation d'outils d'exfiltration et de mouvement latéral caractéristiques de LockBit
* Corréler les alertes EDR avec les TTPs LockBit 5.0
* Surveiller le site de leak LockBit pour l'apparition des données Actua

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les systèmes affectés du réseau
* Désactiver les comptes compromis et révoquer les sessions actives
* Bloquer les adresses IP et domaines C2 associés à LockBit
* Préserver les preuves forensiques avant tout nettoyage

#### Phase 4 — Activités post-incident

* Évaluer l'étendue de l'exfiltration de données PII (passeports, diplômes, CV, attestations)
* Préparer la notification à la CNIL dans les 72 heures (RGPD)
* Préparer la communication aux personnes concernées (100 000+ individus)
* Restaurer les systèmes à partir de sauvegardes vérifiées
* Documenter l'incident pour les autorités judiciaires (ANSSI, OCLCTIC)

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des traces d'activité LockBit dans les logs des 30-90 derniers jours
* Identifier les vecteurs d'entrée initiaux (phishing, exploitation de vulnérabilité, accès RDP)
* Surveiller les tentatives d'extorsion secondaire via les données publiées
* Analyser les outils déployés par l'attaquant pour identifier la chaîne d'intrusion complète

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact |
| **T1561** | Disk Wipe |
| **T1657** | Financial Theft |

---

### Sources

* [https://www.zataz.com/lockbit-5-0-menace-de-publier-des-donnees-dactua/](https://www.zataz.com/lockbit-5-0-menace-de-publier-des-donnees-dactua/)


---

<div id="chesscom-un-pirate-revendique-73-millions-de-profils-voles"></div>

## Chess.com : un pirate revendique 7,3 millions de profils volés

### Résumé

Un pirate revendique sur un forum un jeu de données attribué à Chess.com : 7,3 millions de profils dont environ 4 millions d'adresses email, avec noms, localisations et classements. Annonce du 16 août 2026, revendication non confirmée. Un précédent piratage du site concernait environ 800 000 emails.

---

### Analyse opérationnelle

Revendication non confirmée à traiter avec prudence. Surveiller les forums et plateformes de revente de données pour validation. Vérifier si des comptes professionnels utilisent des adresses email liées à Chess.com (risque de credential stuffing). Surveiller les tentatives de phishing exploitant les données potentiellement leakées (noms, localisations).

---

### Implications stratégiques

La répétition des attaques contre Chess.com (800k puis 7,3M potentiellement) souligne la persistance du ciblage des plateformes de gaming. Les organisations doivent sensibiliser leurs collaborateurs sur la réutilisation de mots de passe entre services personnels et professionnels, vecteur d'attaque majeur pour le credential stuffing vers les systèmes d'entreprise.

---

### Recommandations

* Surveiller les forums pour validation de la revendication
* Vérifier la présence d'emails professionnels dans le jeu de données
* Sensibiliser les collaborateurs sur la réutilisation de mots de passe
* Renforcer la détection de credential stuffing sur les services internes

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir une veille sur les forums de revente de données pour les revendications Chess.com
* Sensibiliser les collaborateurs sur la réutilisation de mots de passe entre services personnels et professionnels

#### Phase 2 — Détection et analyse

* Surveiller les tentatives de credential stuffing utilisant des emails potentiellement issus du leak Chess.com
* Corréler les adresses email professionnelles avec les données potentiellement compromises
* Détecter les tentatives de connexion anormales sur les services internes

#### Phase 3 — Confinement, éradication et récupération

* Forcer la réinitialisation des mots de passe pour les comptes identifiés dans le leak
* Bloquer les IPs associées aux tentatives de credential stuffing
* Activer la MFA pour les comptes à risque

#### Phase 4 — Activités post-incident

* Évaluer le périmètre des données confirmées vs revendiquées
* Mettre à jour les listes de surveillance pour les emails compromis
* Communiquer aux collaborateurs sur les risques de réutilisation de mots de passe

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des tentatives de connexion utilisant des credentials Chess.com sur les services internes
* Surveiller les attaques de phishing exploitant les informations personnelles issues du leak (noms, localisations)
* Identifier les comptes professionnels utilisant la même adresse email que Chess.com

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1567** | Exfiltration over Web Service |

---

### Sources

* [https://www.zataz.com/chess-com-un-nouveau-pirate-revendique-73-millions-de-profils/](https://www.zataz.com/chess-com-un-nouveau-pirate-revendique-73-millions-de-profils/)


---

<div id="golf-canada-568-972-comptes-compromis"></div>

## Golf Canada : 568 972 comptes compromis

### Résumé

Mi-2026, des centaines de milliers d'enregistrements d'utilisateurs provenant de Golf Canada ont commencé à circuler via Telegram. Les données incluent 569 000 emails uniques.

---

### Analyse opérationnelle

Surveiller les canaux Telegram pour identifier les jeux de données diffusés. Vérifier la présence d'adresses email professionnelles dans le jeu de données (risque de phishing ciblé). Intégrer les emails compromis dans les listes de surveillance pour détection de credential stuffing.

---

### Implications stratégiques

La diffusion de données via Telegram illustre l'utilisation croissante de plateformes de messagerie chiffrée pour la distribution de données volées, compliquant le travail de surveillance des équipes CTI. Les organisations doivent intégrer ces canaux dans leur stratégie de threat intelligence.

---

### Recommandations

* Surveiller les canaux Telegram pour le jeu de données Golf Canada
* Vérifier la présence d'emails professionnels dans les 569 000 comptes compromis
* Intégrer les emails dans les listes de surveillance credential stuffing
* Renforcer la détection anti-phishing

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Surveiller les canaux Telegram pour la diffusion de données volées
* Maintenir une veille OSINT sur les fuites de données via des plateformes de messagerie chiffrée

#### Phase 2 — Détection et analyse

* Corréler les adresses email compromises avec les comptes internes
* Détecter les tentatives de phishing exploitant les données Golf Canada (noms, emails)
* Surveiller les tentatives de credential stuffing utilisant les emails leakés

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les adresses IP associées aux tentatives de phishing post-fuite
* Forcer la réinitialisation des mots de passe pour les comptes identifiés dans le leak
* Activer la MFA pour les comptes à risque

#### Phase 4 — Activités post-incident

* Intégrer les 569 000 emails compromis dans les listes de surveillance HIBP
* Mettre à jour les règles de détection anti-phishing avec les indicateurs liés au leak
* Documenter l'exposition organisationnelle au jeu de données

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des tentatives de connexion utilisant les credentials Golf Canada sur les services internes
* Surveiller les canaux Telegram pour d'autres jeux de données liés à l'organisation
* Identifier les comptes d'employés membres de Golf Canada et évaluer le risque de phishing ciblé

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1567** | Exfiltration over Web Service |

---

### Sources

* [https://www.redpacketsecurity.com/golf-canada-568-972-breached-accounts/](https://www.redpacketsecurity.com/golf-canada-568-972-breached-accounts/)


---

<div id="sakura-internet-piratage-exposant-jusqua-136-million-de-comptes"></div>

## Sakura Internet : piratage exposant jusqu'à 1,36 million de comptes

### Résumé

Sakura Internet, fournisseur japonais d'hébergement, indique que des pirates ont accédé à son système de gestion des ventes, exposant potentiellement les données de jusqu'à 1,36 million de comptes membres.

---

### Analyse opérationnelle

Vérifier si l'organisation utilise des services Sakura Internet et évaluer l'exposition. Surveiller les accès anormaux aux systèmes de gestion interne. Mettre en place une détection des mouvements latéraux depuis des systèmes de gestion compromis. Vérifier l'intégrité des systèmes de gestion commerciale et CRM.

---

### Implications stratégiques

L'attaque d'un fournisseur d'hébergement japonais majeur souligne les risques de chaîne d'approvisionnement dans le secteur des télécommunications. Les organisations dépendantes de fournisseurs d'hébergement doivent évaluer leur exposition, diversifier leurs fournisseurs critiques et intégrer des clauses de sécurité et de notification d'incident dans leurs contrats.

---

### Recommandations

* Vérifier l'utilisation de services Sakura Internet et évaluer l'exposition
* Surveiller les accès anormaux aux systèmes de gestion des ventes/CRM
* Évaluer la diversification des fournisseurs d'hébergement
* Renforcer la détection des mouvements latéraux depuis les systèmes de gestion interne

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les services Sakura Internet utilisés par l'organisation
* Évaluer l'exposition des données hébergées chez Sakura Internet
* Préparer un plan de bascule vers des fournisseurs alternatifs

#### Phase 2 — Détection et analyse

* Surveiller les accès anormaux aux systèmes de gestion interne et CRM
* Détecter les mouvements latéraux depuis des systèmes de gestion commerciale compromis
* Corréler les alertes EDR avec les indicateurs d'accès non autorisés aux systèmes de vente
* Surveiller les tentatives d'exfiltration de données depuis les systèmes de gestion

#### Phase 3 — Confinement, éradication et récupération

* Isoler les systèmes de gestion des ventes compromis
* Révoquer les credentials et sessions associés aux comptes affectés
* Bloquer les adresses IP des attaquants identifiés
* Restreindre l'accès aux bases de données membres

#### Phase 4 — Activités post-incident

* Évaluer l'étendue de l'exposition des 1,36 million de comptes
* Notifier les autorités japonaises compétentes et les utilisateurs concernés
* Auditer les modifications apportées aux systèmes de gestion des ventes
* Restaurer les systèmes à partir de sauvegardes vérifiées

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des accès non autorisés aux systèmes CRM et de gestion des ventes dans les logs des 90 derniers jours
* Identifier les vecteurs d'entrée initiaux utilisés pour compromettre le système de gestion
* Surveiller les tentatives d'exploitation des données membres compromises (phishing, credential stuffing)
* Analyser les outils déployés par l'attaquant pour cartographier la chaîne d'intrusion

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078** | Valid Accounts |
| **T1213** | Data from Information Repositories |

---

### Sources

* [https://www.bleepingcomputer.com/news/security/sakura-internet-hack-exposes-data-of-up-to-136-million-accounts/](https://www.bleepingcomputer.com/news/security/sakura-internet-hack-exposes-data-of-up-to-136-million-accounts/)


---

<div id="lockbit-50-menace-de-publier-des-donnees-dactua-concernant-plus-de-100-000-personnes"></div>

## LockBit 5.0 menace de publier des données d'Actua concernant plus de 100 000 personnes

### Résumé

Le groupe ransomware LockBit 5.0 a publié une menace indiquant détenir des données sensibles appartenant à Actua, une entreprise française. Le groupe affirme que ces données concernent plus de 100 000 personnes et a fixé une deadline de fin août 2026 pour la publication publique si la rançon n'est pas payée. L'annonce a été relayée sur le site de fuite de LockBit, confirmant la double extorsion (chiffrement + menace de publication).

---

### Analyse opérationnelle

Cette campagne confirme la poursuite des opérations de LockBit sous sa version 5.0, avec un mode opératoire de double extorsion. Les équipes SOC doivent prioritairement vérifier si des indicateurs de compromission associés à LockBit sont présents dans leur environnement, notamment des pics de trafic sortant (exfiltration), des suppressions de Volume Shadow Copies, et l'exécution d'outils de découverte réseau. La surface d'attaque inclut potentiellement des accès initiaux via exploitation de vulnérabilités publiques (VPN, RDP), compromission de credentials, ou partenaires tiers. Les équipes IT doivent s'assurer de l'intégrité et de la disponibilité des sauvegardes immuables hors ligne. La détection doit se concentrer sur les TTP connus de LockBit : exécution de l'encryptor, création de mutex spécifiques, modification de wallpaper, et exfiltration via Mega.nz ou services similaires.

---

### Implications stratégiques

L'attaque contre Actua illustre la persistance de LockBit comme acteur majeur du paysage ransomware malgré les opérations de démantèlement (Operation Cronos). Le passage à la version 5.0 suggère une capacité d'adaptation et de résilience opérationnelle du groupe. Pour les organisations françaises, le risque sectoriel est élevé : LockBit cible prioritairement les entreprises européennes avec des données personnelles massives pour maximiser la pression d'extorsion. Les implications RGPD sont significatives avec plus de 100 000 personnes potentiellement impactées, nécessitant une notification à la CNIL dans les 72 heures si la fuite est confirmée. Cette campagne renforce la nécessité d'une stratégie de cyber-résilience incluant cyber-assurance, plans de continuité d'activité, et exercices de simulation d'attaque ransomware au niveau direction.

---

### Recommandations

* Vérifier immédiatement la présence d'IOCs LockBit 5.0 dans les environnements SIEM/EDR
* Confirmer l'intégrité et la disponibilité des sauvegardes offline et immuables
* Renforcer la supervision des flux sortants pour détecter toute exfiltration en cours
* Préparer le plan de notification CNIL et de communication de crise
* Mettre à jour les règles de détection avec les TTPs LockBit 5.0 les plus récents
* Conduire un audit des accès privilégiés et des points d'entrée externes (VPN, RDP, services exposés)

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire à jour des actifs de données sensibles et de leur classification
* Vérifier la disponibilité et l'intégrité des sauvegardes hors ligne (offline/immutable)
* S'abonner aux flux CTI surveillant les publications du blog de fuite LockBit
* Définir un plan de communication de crise et de notification RGPD pré-approuvé
* Mettre en place une veille sur les forums et sites de fuite (ransom leak sites)

#### Phase 2 — Détection et analyse

* Surveiller l'apparition du nom « Actua » sur les sites de fuite LockBit et autres groupes ransomware
* Activer les alertes SIEM sur les indicateurs de comportement d'exfiltration (pics de trafic sortant anormaux, connexions vers infrastructures inconnues)
* Rechercher dans les logs les artefacts associés aux TTP connus de LockBit (utilisation d'outils comme LockBit encryptor, suppression de VSS via vssadmin)
* Corréler les événements EDR avec les IOCs connus de LockBit 5.0
* Mettre en place des règles de détection sur la création/modification massive de fichiers (signature de chiffrement)

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les systèmes potentiellement compromis du réseau
* Désactiver les comptes utilisateurs compromis et réinitialiser les credentials
* Bloquer les adresses IP et domaines C2 identifiés associés à LockBit
* Préserver les preuves forensiques (images disque, mémoire volatile) avant tout nettoyage
* Évaluer l'étendue de l'exfiltration via analyse des logs de flux réseau et proxy
* Engager le plan de réponse à incident incluant notification CNIL si données personnelles confirmées

#### Phase 4 — Activités post-incident

* Conduire une analyse post-incident complète (root cause analysis)
* Restaurer les systèmes à partir de sauvegardes vérifiées et immuables
* Renforcer les contrôles d'accès et appliquer le principe du moindre privilège
* Mettre à jour les règles de détection SIEM/EDR avec les IOCs et TTPs observés
* Réaliser un exercice de retour d'expérience (lessons learned) avec toutes les parties prenantes
* Notifier les autorités de régulation (CNIL) et les personnes concernées si requis par le RGPD

#### Phase 5 — Threat Hunting (proactif)

* Rechercher proactivement les artefacts LockBit (mutex, fichiers de configuration, dropped executables) sur l'ensemble du parc
* Chasser les traces de mouvement latéral via PsExec, WMI, RDP non autorisé
* Analyser les connexions réseau sortantes vers des infrastructures de type bulletproof hosting
* Surveiller les tentatives d'accès aux sauvegardes (Veeam, Backup Exec) et aux contrôleurs de domaine
* Rechercher les outils de découverte (AdFind, BloodHound, SharpHound) dans les logs EDR

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact - Chiffrement des données victimes pour perturbation opérationnelle |
| **T1567** | Exfiltration Over Web Service - Exfiltration des données via services cloud avant chiffrement |
| **T1657** | Financial Theft - Extortion financière via rançon |
| **T1041** | Exfiltration Over C2 Channel - Communication avec infrastructure de commande et contrôle |
| **T1490** | Inhibit System Recovery - Suppression des sauvegardes et clichés instantanés |

---

### Sources

* [https://www.zataz.com/lockbit-5-0-menace-de-publier-des-donnees-dactua/](https://www.zataz.com/lockbit-5-0-menace-de-publier-des-donnees-dactua/)


---

<div id="plus-de-9-300-cles-dacces-aws-exposees-publiquement-selon-truffle-security"></div>

## Plus de 9 300 clés d'accès AWS exposées publiquement selon Truffle Security

### Résumé

Une investigation de Truffle Security a révélé la présence de plus de 9 300 clés d'accès AWS actives et publiquement exposées. Parmi elles, 768 accordent un contrôle administratif complet sur les comptes AWS concernés. La plateforme Hugging Face a été identifiée comme la source principale d'exposition, avec 88 % des credentials exposés restant non rotés pendant une durée médiane de cinq ans. Cette exposition a conduit à des dépenses non autorisées significatives et à une absence d'alertes budgétaires sur les comptes compromis.

---

### Analyse opérationnelle

Cette découverte met en lumière une vulnérabilité critique dans les pratiques de gestion des secrets au sein des équipes data/ML. Les clés AWS exposées sur Hugging Face (notebooks, modèles, datasets) constituent une surface d'attaque directement exploitable : un acteur malveillant peut utiliser ces credentials pour déployer des instances EC2 pour le cryptominage, exfiltrer des données depuis S3, ou établir une persistance via création de nouveaux utilisateurs IAM. Les équipes SOC doivent prioritairement déployer des outils de scanning de secrets (TruffleHog, GitGuardian) sur l'ensemble des dépôts de code et plateformes de partage ML. La détection côté AWS repose sur CloudTrail : surveiller les appels API depuis IP inconnues, création d'instances dans des régions inhabituelles, et pics de facturation. Les équipes IT doivent imposer l'utilisation d'AWS IAM Roles au lieu d'access keys statiques, et activer AWS GuardDuty pour la détection des accès anormaux.

---

### Implications stratégiques

L'exposition massive de credentials AWS sur des plateformes de ML comme Hugging Face souligne un risque organisationnel majeur : le fossé entre les pratiques de développement ML (rapidité, partage ouvert) et les exigences de sécurité cloud. La durée médiane de cinq ans sans rotation révèle une absence quasi totale de gouvernance des secrets dans de nombreuses organisations. Les conséquences business incluent des coûts cloud non maîtrisés (cryptominage, ressources frauduleuses), des risques de fuite de données propriétaires, et une exposition à des attaques en chaîne si les comptes AWS sont liés à d'autres services SaaS. Cette situation appelle à une refonte des politiques de gestion des secrets, incluant l'adoption obligatoire de solutions de secret management (AWS Secrets Manager, HashiCorp Vault), la formation des équipes data aux risques de sécurité, et l'intégration de contrôles automatisés dans les pipelines CI/CD pour bloquer tout commit contenant des credentials en clair.

---

### Recommandations

* Déployer immédiatement un scanner de secrets sur tous les dépôts de code et comptes Hugging Face
* Révoquer et faire tourner toutes les clés AWS identifiées comme exposées
* Migrer les workflows utilisant des access keys statiques vers des IAM Roles temporaires
* Activer AWS GuardDuty et configurer des alertes CloudWatch sur les appels API sensibles
* Mettre en place des alertes budgétaires AWS sur tous les comptes pour détecter les dépenses anormales
* Imposer une politique de rotation des clés à 90 jours maximum via AWS Config Rules
* Sensibiliser les équipes data/ML aux risques d'exposition de credentials sur les plateformes publiques

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre en place un programme de gestion des secrets (secret management) avec rotation automatique des clés AWS
* Déployer des outils de détection de secrets exposés (TruffleHog, GitGuardian, AWS Macie) sur les dépôts de code et plateformes ML
* Définir une politique de moindre privilège pour les IAM roles et access keys AWS
* Mettre en place des alertes budget AWS et CloudWatch pour détecter toute dépense anormale
* Former les équipes data/ML aux bonnes pratiques de gestion des credentials dans les notebooks et modèles

#### Phase 2 — Détection et analyse

* Surveiller les dépôts GitHub, GitLab et Hugging Face pour la présence de clés AWS via des outils de scanning automatisés
* Activer AWS CloudTrail et configurer des alertes sur les appels API sensibles (CreateAccessKey, PutBucketPolicy, RunInstances)
* Mettre en place des détections sur les connexions AWS depuis des IP inconnues ou des régions non habituelles
* Surveiller les métriques de facturation AWS pour détecter des pics d'utilisation suspects
* Corréler les événements CloudTrail avec les alertes de fuite de credentials depuis les plateformes publiques

#### Phase 3 — Confinement, éradication et récupération

* Désactiver et révoquer immédiatement les clés AWS exposées via IAM console ou CLI
* Identifier et supprimer les ressources AWS créées frauduleusementemment (instances EC2, buckets S3, lambdas)
* Bloquer les adresses IP associées aux accès non autorisés via NACL et Security Groups
* Réinitialiser tous les credentials potentiellement compromis (clés API, tokens, mots de passe)
* Analyser les logs CloudTrail pour déterminer l'étendue des actions effectuées avec les clés exposées
* Isoler les comptes AWS impactés et appliquer des politiques SCP restrictives

#### Phase 4 — Activités post-incident

* Conduire une analyse forensique des logs CloudTrail pour identifier toutes les actions malveillantes
* Restaurer les politiques IAM selon le principe du moindre privilège
* Mettre en place une rotation obligatoire et périodique des access keys (maximum 90 jours)
* Implémenter AWS Organizations avec Service Control Policies pour empêcher la création de clés non autorisées
* Documenter l'incident et mener un exercice de retour d'expérience
* Évaluer l'impact financier et réclamer auprès du support AWS si des frais frauduleux ont été générés

#### Phase 5 — Threat Hunting (proactif)

* Rechercher proactivement des secrets exposés sur Hugging Face, GitHub, Pastebin et autres plateformes publiques
* Analyser les logs CloudTrail pour des patterns d'accès inhabituels (API calls hors heures ouvrées, fréquence anormale)
* Chasser les instances EC2 non répertoriées ou les buckets S3 nouvellement créés
* Surveiller les modifications de politiques IAM et la création de nouveaux utilisateurs ou rôles
* Rechercher des credentials AWS dans des conteneurs Docker publics ou des artefacts de CI/CD exposés

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1552** | Unsecured Credentials - Identifiants non sécurisés exposés publiquement |
| **T1552.001** | Credentials In Files - Clés d'accès stockées dans des fichiers exposés (notebooks, scripts) |
| **T1078** | Valid Accounts - Utilisation de credentials légitimes pour l'accès initial et la persistance |
| **T1530** | Data from Cloud Storage - Récupération de données depuis des services cloud compromis |

---

### Sources

* [https://www.scworld.com/brief/thousands-of-active-aws-access-keys-remain-publicly-exposed](https://www.scworld.com/brief/thousands-of-active-aws-access-keys-remain-publicly-exposed)
