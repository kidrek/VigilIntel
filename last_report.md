# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [DFIR : d'une alerte Defender (Behavior:Win32/RegDump.SA) à la découverte d'un dump SAM via Impacket secretsdump.py](#dfir-dune-alerte-defender-behaviorwin32regdumpsa-a-la-decouverte-dun-dump-sam-via-impacket-secretsdumppy)
  * [Advisory CISA « deux SOC » : une alerte légitime étouffée par un inventaire d'actifs défaillant](#advisory-cisa-deux-soc-une-alerte-legitime-etouffee-par-un-inventaire-dactifs-defaillant)
  * [Veille vulnérabilités : CVE critiques en tendance (Cisco SD-WAN, n8n, Ivanti EPMM, Crawl4AI) et rappel sur les conteneurs non-root](#veille-vulnerabilites-cve-critiques-en-tendance-cisco-sd-wan-n8n-ivanti-epmm-crawl4ai-et-rappel-sur-les-conteneurs-non-root)
  * [Site compromis expédiant du phishing : les signalements n'aboutissent pas (MX absent, abuse@ rejeté)](#site-compromis-expediant-du-phishing-les-signalements-naboutissent-pas-mx-absent-abuse-rejete)
  * [PH4NTXM : anatomie d'une distribution live Debian durcie — identité de session, modes de boot et réseau protégé](#ph4ntxm-anatomie-dune-distribution-live-debian-durcie-identite-de-session-modes-de-boot-et-reseau-protege)
  * [Accès initial sous macOS : phishing, faux installeurs et contournement de Gatekeeper (BSides Frankfurt 2026)](#acces-initial-sous-macos-phishing-faux-installeurs-et-contournement-de-gatekeeper-bsides-frankfurt-2026)
  * [Parse Server : 70 CVEs non corrigées dont 5 critiques/élevées et un score CVSS maximal de 10.0](#parse-server-70-cves-non-corrigees-dont-5-critiqueselevees-et-un-score-cvss-maximal-de-100)
  * [Le HHS publie une version mise à jour de son Security Risk Assessment Tool (SRA)](#le-hhs-publie-une-version-mise-a-jour-de-son-security-risk-assessment-tool-sra)
  * [INC Ransom revendique Kyokuto Kaihatsu Kogyo ; accès non autorisé confirmé chez sa filiale Nippon Trex](#inc-ransom-revendique-kyokuto-kaihatsu-kogyo-acces-non-autorise-confirme-chez-sa-filiale-nippon-trex)
  * [Hameçonnage thématique « passkey » : vol de données Microsoft 365 (BleepingComputer)](#hameconnage-thematique-passkey-vol-de-donnees-microsoft-365-bleepingcomputer)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'activité CTI du jour est dominée par le volet vulnérabilités avec 44 publications recensées, un volume qui impose une priorisation immédiate des correctifs sur les actifs exposés et Internet-facing. Les 12 incidents de fuite de données traduisent une pression soutenue des campagnes d'exfiltration, probablement à des fins d'extorsion ou de revente, et justifient une vigilance accrue sur la chaîne d'approvisionnement et les données personnelles de nos entités. Aucun nouvel acteur de la menace n'a été profilé aujourd'hui, mais la récurrence des compromissions suggère une activité opérationnelle stable des groupes établis plutôt qu'une émergence nouvelle. Le volet géopolitique se limite à une seule publication, sans signal d'escalade majeur à intégrer aux scénarios de crise à ce stade. Deux publications réglementaires appellent un suivi conformité, notamment au regard des échéances NIS2 et DORA pour les entités concernées. Les 10 articles d'analyse générale confirment la tendance de fond : l'exploitation de vulnérabilités connues demeure le vecteur initial privilégié des intrusions. Recommandation opérationnelle : concentrer le triage sur les CVE exploitables ou weaponisées et vérifier l'exposition éventuelle de nos données dans les fuites du jour.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

_Aucun acteur identifié._

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Australie, Océanie** | Académique / Recherche — intégrité des processus électoraux | Désinformation assistée par IA : simulation de campagnes d'influence électoralles pilotées par des bots LLM | Des chercheurs de l'UNSW Sydney (Hammond Pearce et Rahat Masood) présenteront à la conférence [un]prompted.au (18-19 septembre 2026) « Capture the Narrative », un wargame massivement multijoueur de type CTF dans lequel 288 étudiants universitaires australiens ont conçu et déployé des campagnes de bots propulsés par des LLM afin de faire basculer une élection simulée. Cette initiative, à vocation pédagogique et scientifique, illustre la démocratisation rapide des capacités d'influence informationnelle : des acteurs non étatiques et peu dotés (ici, des étudiants) peuvent désormais industrialiser la production de contenu narratif et la coordination de comptes automatisés à très faible coût. L'événement a également produit un jeu de données destiné à la recherche future, ressource précieuse pour l'étude des signatures comportementales et textuelles des campagnes d'influence générées par IA. Pour la communauté CTI, cette démonstration confirme la pertinence de la menace de désinformation synthétique ciblant les cycles électoraux réels (Australie et au-delà), et souligne l'intérêt des exercices de type wargame pour former analystes et défenseurs à la détection de ces opérations. | [https://unprompted.au/schedule?utm_source=mastodon&utm_medium=social&utm_campaign=speakers&utm_content=pearce-masood](https://unprompted.au/schedule?utm_source=mastodon&utm_medium=social&utm_campaign=speakers&utm_content=pearce-masood) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Revolut – divulgation de données clients à la suite d'une fausse demande de données émanant d'un domaine gouvernemental authentique | Revolut (entreprise concernée, notification aux clients) – aucune autorité de régulation citée dans le signalement | 2026-09-13 | Non précisée (fintech d'origine britannique à clientèle internationale) | Revolut – divulgation de données clients à la suite d'une fausse demande de données émanant d'un domaine gouvernemental authentique | Revolut a confirmé avoir transmis des fichiers clients à un individu ayant soumis une demande de données depuis un domaine d'agence gouvernementale authentique. Aucune intrusion ni aucun malware n'est en cause : la demande s'est authentifiée et le personnel l'a traitée comme une demande légitime. L'accès à de vraies boîtes mail gouvernementales et de police constitue une catégorie de vente établie de longue date sur les forums criminels. Les données divulguées incluent passeports, permis de conduire, selfies de vérification, adresses domicile, IBAN, historiques de retraits et historiques complets de transactions incluant des transactions en Bitcoin : il ne s'agit pas d'un simple dump d'identifiants mais d'un paquet d'identité complet avec historique de portefeuille. Point clé : la plupart des institutions considèrent encore qu'un contrôle de domaine réussi prouve l'identité du demandeur derrière la boîte mail, ce qui est insuffisant face à la compromission ou la revente d'accès à de vraies boîtes officielles. | `hxxps://infosec[.]exchange/@darkwebsonar/117263915246484179` |
| Delaware HB 380 et HB 381 – réforme de la loi sur la vie privée des consommateurs (DPDPA) et de la notification des violations de données | Gouverneur et législature de l'État du Delaware ; procureur général du Delaware (nouveau destinataire des notifications) | 2026-09-13 | États-Unis – État du Delaware | Delaware HB 380 et HB 381 – réforme de la loi sur la vie privée des consommateurs (DPDPA) et de la notification des violations de données | Le 2 septembre 2026, le gouverneur du Delaware a signé les projets de loi HB 380 et HB 381. HB 380 amende le Delaware Personal Data Privacy Act (DPDPA), adopté en 2023 et entré en vigueur le 1er janvier 2025 ; ses amendements prennent effet le 1er janvier 2027. HB 381 amende la loi de notification des violations de sécurité informatique et prend effet dès sa signature. Ensemble, ces textes élargissent les entreprises et les données couvertes, renforcent la protection des données sensibles, imposent de nouvelles exigences de gestion des prestataires (vendor management) et de décisions automatisées, et renforcent les obligations de notification de violation. HB 381 impose désormais, dans le cadre de la notification de substitution (coût > 75 000 USD, plus de 100 000 résidents concernés ou coordonnées insuffisantes), une notification au procureur général du Delaware. Lorsqu'une organisation ne peut identifier dans un délai de 60 jours que des données personnelles de résidents du Delaware sont concernées, elle doit notifier dès que possible après cette détermination, et HB 381 ajoute l'obligation d'informer le procureur général dans les 60 jours suivant cette détermination. Enfin, HB 381 restreint l'exemption pour les entités régulées (HIPAA, Gramm-Leach-Bliley Act) : la conformité aux procédures de violation établies par les régulateurs fédéraux ne satisfait plus que l'exigence de délai de 60 jours, et non plus l'intégralité de la loi étatique. | `hxxps://databreaches[.]net/2026/09/13/delaware-consumer-privacy-and-data-breach-law-updates/` |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Technologie / Hébergement de modèles et datasets IA** | Hugging Face | Identifiants cloud et de cluster, secrets Spaces (jetons d'authentification API de développeurs et d'organisations), accès à un ensemble limité de datasets internes. | Inconnu | [https://www.cyberengage.org/post/i-use-ai-every-single-day-the-hugging-face-breach-still-scared-me](https://www.cyberengage.org/post/i-use-ai-every-single-day-the-hugging-face-breach-still-scared-me) |
| **Fintech / Services financiers (Royaume-Uni)** | Revolut | Copies de pièces d'identité (passeports, permis de conduire), images de vérification faciale/selfies, relevés de compte, IBAN, dates d'ouverture de compte, enregistrements de retraits, historiques complets de transactions (y compris transactions Bitcoin), noms complets, dates de naissance, professions, adresses postales, adresses e-mail et numéros de téléphone. Nombre exact de personnes affectées non divulgué (« nombre limité » selon Revolut). | Inconnu | [https://www.reuters.com/legal/litigation/revolut-confirms-sensitive-customer-data-breach-falling-fake-government-requests-2026-09-12](https://www.reuters.com/legal/litigation/revolut-confirms-sensitive-customer-data-breach-falling-fake-government-requests-2026-09-12)<br>[https://infosec.exchange/@security_crawler_carl/117265780089615969](https://infosec.exchange/@security_crawler_carl/117265780089615969)<br>[https://newisty.com/blog/report-revolut-leaked-passports-and-bitcoin-history-to-fake-government-request?utm_source=social&utm_campaign=crypto_news](https://newisty.com/blog/report-revolut-leaked-passports-and-bitcoin-history-to-fake-government-request?utm_source=social&utm_campaign=crypto_news)<br>[https://theperimetersite.com/report/255](https://theperimetersite.com/report/255)<br>[https://beyondmachines.net/event_details/revolut-discloses-sensitive-customer-data-following-fraudulent-government-requests-l-t-k-6-q/gD2P6Ple2L](https://beyondmachines.net/event_details/revolut-discloses-sensitive-customer-data-following-fraudulent-government-requests-l-t-k-6-q/gD2P6Ple2L)<br>[https://techcrunch.com/2026/09/12/revolut-confirms-customer-data-breach-through-fake-government-requests/](https://techcrunch.com/2026/09/12/revolut-confirms-customer-data-breach-through-fake-government-requests/) |
| **Santé / Hôpitaux et cliniques (Colombie)** | Institutions de santé en Colombie (hôpitaux et cliniques) | Non applicable (publication statistique) ; cible principale rapportée : informations médicales. | Inconnu | [https://databreaches.net/2026/09/13/six-in-10-cyberattacks-in-colombia-target-hospitals/](https://databreaches.net/2026/09/13/six-in-10-cyberattacks-in-colombia-target-hospitals/) |
| **Gouvernement / Santé publique (nutrition) - Indonésie** | Agence nationale de la nutrition d'Indonésie (Badan Gizi Nasional - BGN) | Base de données revendiquée (format CSV/XLSX) ; nature exacte et volume non confirmés. | Inconnu | [https://go.darkwebsonar.io/bjorka-mastodon](https://go.darkwebsonar.io/bjorka-mastodon)<br>[https://infosec.exchange/@darkwebsonar/117264845175237387](https://infosec.exchange/@darkwebsonar/117264845175237387) |
| **Gouvernement / Administration publique (Berlin)** | Administration gouvernementale de Berlin | Données gouvernementales sensibles (volume et nature exacts non précisés). | Inconnu | [https://tech-insider.org/rhysida-ransomware-berlin-government-breach-2026](https://tech-insider.org/rhysida-ransomware-berlin-government-breach-2026)<br>[https://infosec.exchange/@security_crawler_carl/117264818816249967](https://infosec.exchange/@security_crawler_carl/117264818816249967) |
| **Gouvernement / Transport et identification (DMV)** | Florida Department of Highway Safety and Motor Vehicles (DMV de Floride) | Données de la base DMV consultées via un compte de police volé (registres de conducteurs/véhicules potentiels ; détails non précisés). | Inconnu | [https://www.bleepingcomputer.com/news/security/florida-confirms-dmv-database-breached-via-stolen-police-account/](https://www.bleepingcomputer.com/news/security/florida-confirms-dmv-database-breached-via-stolen-police-account/)<br>[https://mastodon.thenewoil.org/@thenewoil/117264561128458039](https://mastodon.thenewoil.org/@thenewoil/117264561128458039) |
| **Jeux en ligne / Échecs en ligne** | Chess.com | Adresses e-mail, pseudonymes, noms, pays et données relatives aux comptes chess[.]com (aucun mot de passe signalé). | 4653212 | [https://haveibeenpwned.com/Breach/Chess2026](https://haveibeenpwned.com/Breach/Chess2026) |
| **Éducation (plateforme e-learning, Kazakhstan)** | Daryn.online (plateforme éducative, Kazakhstan) | Noms, numéros de téléphone, adresses e-mail, dates de naissance, numéros d'identification nationale, informations scolaires, notes et années d'admission (4,2 M d'enregistrements revendiqués). | 4200000 | [https://go.darkwebsonar.io/other-and-other-mastodon](https://go.darkwebsonar.io/other-and-other-mastodon) |
| **Transport (Inde)** | Organisation indienne du secteur des transports (alias partiellement masqué « vi***in ») | Non spécifié : aucune nature de données ni volume divulgué, aucun échantillon ni preuve d'exfiltration publié. | Inconnu | [https://www.yazoul.net/intel/claim/2026-09-13-vi-in-ransomware-claim-by-auditteam-sep-2026](https://www.yazoul.net/intel/claim/2026-09-13-vi-in-ransomware-claim-by-auditteam-sep-2026) |
| **Transport et logistique (Inde, Mumbai)** | Capricorn Logistics Pvt. Ltd. | Non spécifié : volume non divulgué, aucune preuve d'exfiltration confirmée ; exposition potentielle de données opérationnelles, de routage, tarifaires, clients et partenaires si la revendication s'avérait exacte. | Inconnu | [https://www.yazoul.net/intel/claim/2026-09-12-capricorn-logistics-ransomware-claim-by-krybit-sep-2026](https://www.yazoul.net/intel/claim/2026-09-12-capricorn-logistics-ransomware-claim-by-krybit-sep-2026) |
| **Éducation supérieure / Agence gouvernementale (Mississippi, États-Unis)** | Mississippi Institutions of Higher Learning (IHL) | En cours d'investigation : données confidentielles ou sensibles (à confirmer), dossiers d'aide financière étudiante (potentiel), fichiers administratifs internes (potentiel). Nombre de personnes affectées non divulgué. | Inconnu | [https://beyondmachines.net/event_details/mississippi-higher-education-agency-investigates-security-incident-affecting-financial-aid-services-j-s-z-5-j/gD2P6Ple2L](https://beyondmachines.net/event_details/mississippi-higher-education-agency-investigates-security-incident-affecting-financial-aid-services-j-s-z-5-j/gD2P6Ple2L) |
| **Vérification d'identité / Services cloud SaaS (secteurs clients : finance, hôtellerie, jeux, commerce de détail, conformité KYC)** | IDScan (IDScan.net) | Noms complets ; numéros de permis de conduire ; autres numéros de pièces d'identité gouvernementales. Inventaire revendiqué par le marketplace Nexus : plus de 153 millions de scans de permis de conduire US/Canada, environ 10 millions de scans de cartes d'identité, plus de 3 millions de documents de voyage ou pièces d'identité internationales, au moins 579 000 cartes médicales. IDScan n'a pas confirmé la proportion de ces enregistrements provenant de sa plateforme ni l'authenticité de tous les documents annoncés. | 153000000 | [https://cyberworldops.eu/en/idscan-confirms-cloud-breach-amid-claims-of-153-million-stolen-driver](https://cyberworldops.eu/en/idscan-confirms-cloud-breach-amid-claims-of-153-million-stolen-driver) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-85706** | 10.0 | N/A | TRUE | GitLab Community Edition (CE) et Enterprise Edition (EE) - toutes les versions à partir de la branche 18.7 antérieures aux versions corrigées (19.1.8 et suivantes pour la branche 19.1 ; branches 19.2 et ultérieures également concernées) | Path traversal (traversée de répertoires) dans l'API repository commits - lecture de fichiers arbitraires sans authentification | Exposition de données hautement sensibles : clés SSH, identifiants de base de données, deploy tokens, variables CI/CD et autres configurations critiques. Cette fuite peut mener à la compromission complète de la chaîne de développement (pipelines, dépôts, infrastructure) et à des mouvements latéraux. | Active | Appliquer immédiatement les correctifs GitLab (19.1.8 et versions ultérieures des branches concernées) ou supprimer l'accès public aux instances auto-hébergées ; bloquer/filtrer les requêtes POST vers l'API commits avec paramètre file.path ; rechercher dans les logs les tentatives d'exploitation ; révoquer et renouveler l'ensemble des secrets potentiellement exposés. | [https://securityaffairs.com/198945/hacking/gitlab-cve-2026-85706-one-http-request-no-authentication-full-file-read-exploited-within-24-hours.html](https://securityaffairs.com/198945/hacking/gitlab-cve-2026-85706-one-http-request-no-authentication-full-file-read-exploited-within-24-hours.html)<br>[https://securityaffairs.com/198980/breaking-news/security-affairs-malware-newsletter-round-114.html](https://securityaffairs.com/198980/breaking-news/security-affairs-malware-newsletter-round-114.html)<br>[https://securityaffairs.com/198957/security/security-affairs-newsletter-round-594-by-pierluigi-paganini-international-edition.html](https://securityaffairs.com/198957/security/security-affairs-newsletter-round-594-by-pierluigi-paganini-international-edition.html) |
| **CVE-2026-42016** | N/A | N/A | FALSE | JFrog Artifactory (versions affectées non précisées dans la source) | Non précisé dans la source - exploitation active in-the-wild rapportée | Compromission potentielle d'un référentiel d'artefacts (stockage et distribution de binaires), avec un risque d'empoisonnement de la chaîne d'approvisionnement logicielle et d'accès aux identifiants de déploiement. | Active | Appliquer les correctifs JFrog dès leur publication, restreindre l'exposition des instances Artifactory, surveiller les avis de sécurité de l'éditeur et auditer l'intégrité des artefacts ainsi que les jetons d'accès. | [https://securityaffairs.com/198980/breaking-news/security-affairs-malware-newsletter-round-114.html](https://securityaffairs.com/198980/breaking-news/security-affairs-malware-newsletter-round-114.html) |
| **CVE-2026-42018** | N/A | N/A | FALSE | JFrog Artifactory (versions affectées non précisées dans la source) | Non précisé dans la source - exploitation active in-the-wild rapportée | Compromission potentielle d'un référentiel d'artefacts (stockage et distribution de binaires), avec un risque d'empoisonnement de la chaîne d'approvisionnement logicielle et d'accès aux identifiants de déploiement. | Active | Appliquer les correctifs JFrog dès leur publication, restreindre l'exposition des instances Artifactory, surveiller les avis de sécurité de l'éditeur et auditer l'intégrité des artefacts ainsi que les jetons d'accès. | [https://securityaffairs.com/198980/breaking-news/security-affairs-malware-newsletter-round-114.html](https://securityaffairs.com/198980/breaking-news/security-affairs-malware-newsletter-round-114.html) |
| **CVE-2026-82329** | N/A | N/A | FALSE | JFrog Artifactory (versions affectées non précisées dans la source) | Non précisé dans la source - exploitation active in-the-wild rapportée | Compromission potentielle d'un référentiel d'artefacts (stockage et distribution de binaires), avec un risque d'empoisonnement de la chaîne d'approvisionnement logicielle et d'accès aux identifiants de déploiement. | Active | Appliquer les correctifs JFrog dès leur publication, restreindre l'exposition des instances Artifactory, surveiller les avis de sécurité de l'éditeur et auditer l'intégrité des artefacts ainsi que les jetons d'accès. | [https://securityaffairs.com/198980/breaking-news/security-affairs-malware-newsletter-round-114.html](https://securityaffairs.com/198980/breaking-news/security-affairs-malware-newsletter-round-114.html) |
| **CVE-2026-90780** | 8.7 | N/A | FALSE | SIPp, toutes versions jusqu'à 3.7.7 incluses | Dépassement de tampon (CWE-120) dans la fonction get_header() de src/sip_parser.cpp | Déni de service par crash du processus SIPp ; aucune exécution de code confirmée à ce stade. | Theoretical | Mettre à jour SIPp vers une version corrigeant le défaut de traitement des en-têtes ; valider et limiter la taille des en-têtes SIP ; restreindre l'exposition réseau des instances de test et surveiller les crashes anormaux. | [https://cvefeed.io/vuln/detail/CVE-2026-90780](https://cvefeed.io/vuln/detail/CVE-2026-90780) |
| **CVE-2026-90779** | 8.7 | N/A | FALSE | SIPp, toutes versions jusqu'à 3.7.7 incluses | Dépassement de tampon de pile (CWE-121) dans la fonction createAuthHeader() de src/auth.cpp | Crash du client SIPp (déni de service) induit par un serveur SIP malveillant ; corruption de la pile sans exécution de code confirmée. | Theoretical | Mettre à jour SIPp vers une version corrigée ; assurer une gestion sûre des paramètres des défis d'authentification ; ne connecter SIPp qu'à des serveurs de confiance et appliquer les correctifs de l'éditeur. | [https://cvefeed.io/vuln/detail/CVE-2026-90779](https://cvefeed.io/vuln/detail/CVE-2026-90779) |
| **CVE-2026-90778** | 8.7 | N/A | FALSE | SIPp, toutes versions jusqu'à 3.7.7 incluses | Dépassement de tampon (CWE-120) dans la fonction get_peer_tag() de src/sip_parser.cpp | Déni de service par crash du processus SIPp ; aucune exécution de code confirmée à ce stade. | Theoretical | Mettre à jour SIPp vers la version 3.7.8 ou ultérieure ; appliquer les correctifs de l'éditeur ; surveiller les crashes inattendus et filtrer les messages SIP à paramètres tag surdimensionnés. | [https://cvefeed.io/vuln/detail/CVE-2026-90778](https://cvefeed.io/vuln/detail/CVE-2026-90778) |
| **CVE-2026-88793** | 8.8 | N/A | FALSE | Extension WordPress YouTube Embed, versions 10.0 à 10.3 | XSS stocké non authentifié (injection de scripts web) via l'action AJAX youram_server | Exécution de scripts dans la session d'administrateurs : prise de contrôle potentielle du site WordPress, création de comptes frauduleux, injection de contenus, redirections vers des infrastructures malveillantes et vol de données de session. | Theoretical | Mettre à jour l'extension vers la version 10.4 ou ultérieure afin de corriger les défauts d'autorisation et d'échappement ; auditer et nettoyer les contenus stockés suspects ; réinitialiser les sessions et mots de passe des administrateurs en cas de suspicion de compromission. | [https://cvefeed.io/vuln/detail/CVE-2026-88793](https://cvefeed.io/vuln/detail/CVE-2026-88793) |
| **CVE-2026-85129** | 8.8 | N/A | FALSE | Hoo Companion (plugin WordPress) version 1.0.2 | XSS stockée non authentifiée via import des réglages du thème (absence d'autorisation et d'assainissement) | Exécution de scripts arbitraires dans le navigateur de tout visiteur du site, y compris les administrateurs (vol de session, création de comptes admin, redirections malveillantes), et destruction des réglages du thème actif entraînant une défiguration ou une indisponibilité du site. | None | Mettre à jour le plugin vers la dernière version, valider et assainir toutes les données importées, restreindre l'accès à la fonctionnalité d'import et restaurer les réglages du thème depuis une sauvegarde si nécessaire. | [https://cvefeed.io/vuln/detail/CVE-2026-85129](https://cvefeed.io/vuln/detail/CVE-2026-85129)<br>[https://wpscan.com/vulnerability/a50f6ec1-4297-453e-b45f-6fd889b6b0d2/](https://wpscan.com/vulnerability/a50f6ec1-4297-453e-b45f-6fd889b6b0d2/) |
| **CVE-2026-81648** | 10.0 | N/A | FALSE | CryptoPayment Gateway (plugin WordPress) versions 1.2.1 à 1.2.2 | Absence de contrôle d'autorisation sur un endpoint AJAX : suppression arbitraire de fichiers, écrasement de configuration et exposition d'identifiants non authentifiés | Compromission totale de la configuration de paiement, exposition d'identifiants de portefeuille en clair (risque de détournement de fonds), suppression de fichiers arbitraires pouvant entraîner une indisponibilité ou servir de tremplin vers une compromission plus large du serveur. | None | Mettre à jour le plugin vers la dernière version, restreindre les endpoints AJAX aux utilisateurs authentifiés avec vérifications d'autorisation, supprimer ou protéger les endpoints sensibles et faire pivoter immédiatement tous les identifiants et clés de portefeuille exposés. | [https://cvefeed.io/vuln/detail/CVE-2026-81648](https://cvefeed.io/vuln/detail/CVE-2026-81648)<br>[https://wpscan.com/vulnerability/9b1490a0-1381-4d22-8086-f75aade4e898/](https://wpscan.com/vulnerability/9b1490a0-1381-4d22-8086-f75aade4e898/) |
| **CVE-2026-74933** | 8.8 | N/A | FALSE | GenieWords (plugin WordPress) versions 1.5.27 à 1.5.34 | XSS stockée non authentifiée et écrasement de configuration via actions REST API et AJAX sans contrôle d'autorisation | Exécution de scripts arbitraires sur chaque page du site (compromission des visiteurs et des administrateurs, vol de cookies de session, redirections), et écrasement de la configuration du plugin pouvant défigurer le site ou détourner ses fonctionnalités. | None | Mettre à jour GenieWords vers la dernière version, appliquer des contrôles d'autorisation sur toutes les actions REST/AJAX, assainir les valeurs décodées avant affichage et auditer la configuration du plugin après mise à jour. | [https://cvefeed.io/vuln/detail/CVE-2026-74933](https://cvefeed.io/vuln/detail/CVE-2026-74933)<br>[https://wpscan.com/vulnerability/23dc45bb-e7b6-4cae-81ce-2c6394afb454/](https://wpscan.com/vulnerability/23dc45bb-e7b6-4cae-81ce-2c6394afb454/) |
| **CVE-2026-37008** | 8.1 | N/A | FALSE | CrewAI (framework d'agents IA) avant le commit fb2323b | Contournement de sandbox via manipulation du runtime Python (protection au mauvais niveau d'abstraction, CWE-424) | Un code exécuté dans le sandbox CrewAI peut échapper aux restrictions, charger des bibliothèques natives et exécuter du code arbitraire avec les privilèges du processus hôte, compromettant l'environnement d'exécution des agents IA et les données accessibles. | None | Mettre à jour CrewAI vers une version postérieure au commit fb2323b, réévaluer l'approche de sandboxing pour couvrir l'ensemble du runtime Python, isoler l'exécution des agents dans des conteneurs/VM dédiés et restreindre les appels ctypes et les chargements de bibliothèques natives. | [https://cvefeed.io/vuln/detail/CVE-2026-37008](https://cvefeed.io/vuln/detail/CVE-2026-37008)<br>[https://yerangamage.com/cves/detail/?slug=crewai-sandbox-escape](https://yerangamage.com/cves/detail/?slug=crewai-sandbox-escape) |
| **CVE-2026-90783** | 8.5 | N/A | FALSE | MKVToolNix jusqu'à la version 101.0 incluse (bibliothèque avilib embarquée, avilib.c) | Débordement de tampon dans le tas (heap buffer overflow) dû à un contournement d'entier 32 bits (CWE-680) dans l'analyseur de superindex ODML d'avilib | Crash de mkvmerge et potentiellement exécution de code arbitraire sur la machine analysant un fichier AVI malveillant, avec les privilèges de l'utilisateur exécutant l'outil. | None | Mettre à jour MKVToolNix vers la dernière version, éviter l'analyse de fichiers AVI non fiables et recompiler avilib avec une arithmétique 64 bits si une version personnalisée est utilisée. | [https://cvefeed.io/vuln/detail/CVE-2026-90783](https://cvefeed.io/vuln/detail/CVE-2026-90783)<br>[https://www.vulncheck.com/advisories/mkvtoolnix-through-101.0-heap-buffer-overflow-via-avilib-odml-superindex-integer-wraparound](https://www.vulncheck.com/advisories/mkvtoolnix-through-101.0-heap-buffer-overflow-via-avilib-odml-superindex-integer-wraparound) |
| **CVE-2026-90777** | 8.8 | N/A | FALSE | ESPnet avant la version 202609 | Exécution de code à distance par désérialisation non sûre (CWE-502) via torch.load avec weights_only=False | Exécution de code arbitraire sur les environnements chargeant des checkpoints malveillants (initialisation ou fine-tuning), compromission des postes de data scientists et des clusters d'entraînement, vol de données, de modèles et de credentials. | None | Mettre à jour ESPnet vers la version 202609 ou ultérieure, ne charger que des checkpoints provenant de sources fiables, vérifier l'intégrité (hachage/signature) des fichiers de modèles et privilégier torch.load avec weights_only=True lorsque possible. | [https://cvefeed.io/vuln/detail/CVE-2026-90777](https://cvefeed.io/vuln/detail/CVE-2026-90777)<br>[https://www.vulncheck.com/advisories/espnet-before-202609-remote-code-execution-via-unsafe-deserialization](https://www.vulncheck.com/advisories/espnet-before-202609-remote-code-execution-via-unsafe-deserialization)<br>[https://github.com/espnet/espnet/security/advisories/GHSA-64f6-3gqc-r926](https://github.com/espnet/espnet/security/advisories/GHSA-64f6-3gqc-r926) |
| **CVE-2026-90776** | 8.7 | N/A | FALSE | Nodemailer versions 9.1.0 à 10.0.4 (composant addressparser) | Déni de service par complexité algorithmique quadratique (CWE-407) dans l'analyse des adresses e-mail avec commentaires RFC 5322 | Blocage de la boucle d'événements Node.js et épuisement CPU, entraînant un déni de service des applications utilisant Nodemailer (files d'attente d'e-mails, API, services backend) et une dégradation globale de disponibilité. | None | Mettre à jour Nodemailer vers la version 10.0.5 ou ultérieure, surveiller les performances après mise à jour et limiter/normaliser les en-têtes e-mail traités par les applications. | [https://cvefeed.io/vuln/detail/CVE-2026-90776](https://cvefeed.io/vuln/detail/CVE-2026-90776)<br>[https://www.vulncheck.com/advisories/nodemailer-9.1.0-through-10.0.4-denial-of-service-via-quadratic-address-parsing](https://www.vulncheck.com/advisories/nodemailer-9.1.0-through-10.0.4-denial-of-service-via-quadratic-address-parsing)<br>[https://github.com/nodemailer/nodemailer/security/advisories/GHSA-prgh-xp8r-p3m5](https://github.com/nodemailer/nodemailer/security/advisories/GHSA-prgh-xp8r-p3m5) |
| **CVE-2026-90774** | 8.7 | N/A | FALSE | rustypaste avant la version 0.18.1 | Traversée de répertoire (path traversal, CWE-22) via l'en-tête HTTP de nom de fichier personnalisé | Écriture de fichiers arbitraires sur le serveur (webshells, tâches cron, clés SSH selon les permissions), pouvant mener à l'exécution de code et à la compromission complète du serveur hébergeant le service de paste. | None | Mettre à jour rustypaste vers la version 0.18.1 ou ultérieure, valider tous les chemins fournis par l'utilisateur après application de l'en-tête filename, restreindre les permissions du répertoire d'upload et surveiller les écritures hors répertoire. | [https://cvefeed.io/vuln/detail/CVE-2026-90774](https://cvefeed.io/vuln/detail/CVE-2026-90774)<br>[https://www.vulncheck.com/advisories/rustypaste-before-0.18.1-path-traversal-via-filename-header](https://www.vulncheck.com/advisories/rustypaste-before-0.18.1-path-traversal-via-filename-header)<br>[https://github.com/orhun/rustypaste/issues/622](https://github.com/orhun/rustypaste/issues/622) |
| **CVE-2026-90772** | 8.3 | N/A | FALSE | Amundsen Frontend versions jusqu'à 4.3.0 incluses | Cross-Site Scripting stocké (XSS) — CWE-79 | Exécution de JavaScript dans le navigateur de chaque utilisateur consultant les résultats de recherche : vol de cookies de session, actions effectuées à l'insu des utilisateurs, exfiltration de données du catalogue et potentiel pivot vers les comptes de l'organisation. | None | Mettre à jour le frontend Amundsen vers une version postérieure à 4.3.0 ; sanitiser tout le HTML fourni en entrée des descriptions ; valider et nettoyer les descriptions provenant du service de métadonnées ; s'assurer que les données indexées dans Elasticsearch sont correctement assainies avant rendu. | [https://cvefeed.io/vuln/detail/CVE-2026-90772](https://cvefeed.io/vuln/detail/CVE-2026-90772)<br>[https://www.vulncheck.com/advisories/amundsen-frontend-through-4.3.0-stored-xss-via-description](https://www.vulncheck.com/advisories/amundsen-frontend-through-4.3.0-stored-xss-via-description) |
| **CVE-2026-90770** | 8.8 | N/A | FALSE | Spug versions jusqu'à 3.4.0 incluses | Exécution de code à distance par injection de commandes OS — CWE-78 | Exécution de commandes arbitraires sur le serveur hébergeant Spug sous l'identité du processus applicatif : compromission du serveur, accès aux credentials stockés par l'outil d'automatisation, pivot vers les machines supervisées et mouvement latéral. | None | Mettre à jour Spug vers la version 3.4.1 ou ultérieure ; valider toutes les entrées utilisateur destinées à des commandes shell ; restreindre au maximum les permissions de supervision accordées aux comptes. | [https://cvefeed.io/vuln/detail/CVE-2026-90770](https://cvefeed.io/vuln/detail/CVE-2026-90770)<br>[https://www.vulncheck.com/advisories/spug-through-3.4.0-remote-code-execution-via-ping-check](https://www.vulncheck.com/advisories/spug-through-3.4.0-remote-code-execution-via-ping-check) |
| **CVE-2026-90769** | 8.3 | N/A | FALSE | Open Notebook versions antérieures à 1.11.0 | Server-Side Request Forgery (SSRF) — CWE-918 | Lecture du service de métadonnées cloud (récupération potentielle de credentials IAM), cartographie et accès aux services internes et localhost, contournement de la segmentation réseau pouvant mener à une compromission plus large de l'infrastructure. | None | Mettre à jour Open Notebook vers la version 1.11.0 ou ultérieure ; appliquer les correctifs de validation d'URL fournis par l'éditeur ; restreindre l'accès réseau du serveur applicatif aux services internes sensibles. | [https://cvefeed.io/vuln/detail/CVE-2026-90769](https://cvefeed.io/vuln/detail/CVE-2026-90769)<br>[https://www.vulncheck.com/advisories/open-notebook-before-1.11.0-server-side-request-forgery-via-link-source](https://www.vulncheck.com/advisories/open-notebook-before-1.11.0-server-side-request-forgery-via-link-source) |
| **CVE-2026-90768** | 8.6 | N/A | FALSE | CAPEv2 jusqu'au commit 471ee4b inclus | Contrôle d'accès manquant (Missing Authorization) sur les endpoints REST API — CWE-862 | Atteinte à la confidentialité et à l'intégrité des analyses de la sandbox : divulgation d'informations sur les échantillons et investigations en cours (y compris internes), sabotage possible des analyses par suppression arbitraire, perturbation des opérations de réponse aux incidents. | None | Appliquer une validation de propriété des tâches avant toute action sur les endpoints REST ; mettre en œuvre des contrôles d'accès sur les endpoints de tâches ; revoir et corriger la logique d'autorisation de l'API sur tous les endpoints concernés. | [https://cvefeed.io/vuln/detail/CVE-2026-90768](https://cvefeed.io/vuln/detail/CVE-2026-90768)<br>[https://www.vulncheck.com/advisories/capev2-through-commit-471ee4b-rest-api-task-endpoints-missing-ownership-check](https://www.vulncheck.com/advisories/capev2-through-commit-471ee4b-rest-api-task-endpoints-missing-ownership-check) |
| **CVE-2026-90562** | 9.2 | N/A | FALSE | LangBot versions antérieures à 4.10.11 | Contournement d'authentification via clé de récupération à entropie insuffisante — CWE-331 | Prise de contrôle du compte administrateur de l'instance LangBot : contrôle complet de la plateforme (agents, canaux, intégrations), accès aux données traitées, possibilité de déployer des fonctionnalités malveillantes ou d'exfiltrer des informations. | None | Mettre à jour LangBot vers la version 4.10.11 ou ultérieure ; implémenter une limitation de débit sur l'endpoint de réinitialisation de mot de passe ; restreindre l'exposition de l'interface d'administration. | [https://cvefeed.io/vuln/detail/CVE-2026-90562](https://cvefeed.io/vuln/detail/CVE-2026-90562)<br>[https://www.vulncheck.com/advisories/langbot-before-4.10.11-authentication-bypass-via-weak-recovery-key](https://www.vulncheck.com/advisories/langbot-before-4.10.11-authentication-bypass-via-weak-recovery-key) |
| **CVE-2026-90561** | 9.3 | N/A | FALSE | Strapi 4.x jusqu'à 4.26.2 et 5.x antérieures à 5.48.1 | Cross-Site Scripting stocké (XSS) via le composant d'aperçu WYSIWYG — CWE-79 | Prise de contrôle de comptes Strapi privilégiés (Editor, Super Admin) : manipulation du contenu du site, création de comptes administrateurs persistants, vol de jetons API, compromission de l'ensemble du CMS et potentiellement du site publié. | None | Mettre à jour Strapi vers la version 4.26.3 ou ultérieure pour la branche 4.x, ou 5.48.1 ou ultérieure pour la branche 5.x ; restreindre les privilèges du rôle Author ; déployer une CSP sur l'interface d'administration. | [https://cvefeed.io/vuln/detail/CVE-2026-90561](https://cvefeed.io/vuln/detail/CVE-2026-90561)<br>[https://www.vulncheck.com/advisories/strapi-4-x-through-4.26.2-and-5-x-before-5.48.1-stored-xss-via-wysiwyg](https://www.vulncheck.com/advisories/strapi-4-x-through-4.26.2-and-5-x-before-5.48.1-stored-xss-via-wysiwyg) |
| **CVE-2026-90510** | 8.3 | N/A | FALSE | dromara orion-visor versions jusqu'à 2.5.7 incluses | Utilisation de clé cryptographique codée en dur — CWE-321 | Déchiffrement des clés privées SSH et des mots de passe d'hôtes gérés par la plateforme : compromission de l'ensemble des actifs supervisés, mouvements latéraux à grande échelle avec des credentials légitimes, persistance difficile à détecter. | Theoretical | Mettre à jour orion-visor vers une version postérieure à 2.5.7 dès disponibilité d'un correctif ; supprimer les secrets codés en dur du code ; mettre en œuvre une gestion de clés sécurisée (coffre-fort de secrets) ; faire pivoter toutes les clés SSH et mots de passe stockés, considérés comme compromis. | [https://cvefeed.io/vuln/detail/CVE-2026-90510](https://cvefeed.io/vuln/detail/CVE-2026-90510)<br>[https://vuldb.com/vuln/403098](https://vuldb.com/vuln/403098) |
| **CVE-2026-90493** | 8.8 | N/A | FALSE | Tonec Internet Download Manager jusqu'à 6.42 Build 63 (Windows) — pilote noyau idmwfp.sys | Contrôle d'accès incorrect dans un pilote noyau (élévation de privilèges locale) — CWE-266 / CWE-284 | Élévation de privilèges locale permettant à un utilisateur ou un malware disposant d'un accès limité d'obtenir des privilèges élevés (jusqu'à SYSTEM/kernel) : désactivation des solutions de sécurité, déploiement de persistance, préparation d'un mouvement latéral ou d'un déploiement de ransomware. | Theoretical | Appliquer les correctifs éditeur dès leur disponibilité ; revoir et renforcer les mécanismes de contrôle d'accès ; limiter l'accès local aux composants système sensibles ; envisager la désactivation du pilote idmwfp.sys sur les postes à risque en l'absence de correctif. | [https://cvefeed.io/vuln/detail/CVE-2026-90493](https://cvefeed.io/vuln/detail/CVE-2026-90493)<br>[https://vuldb.com/vuln/403081](https://vuldb.com/vuln/403081)<br>[https://github.com/KnCRJVirX/IDM_LPE_PoC/tree/main/poc](https://github.com/KnCRJVirX/IDM_LPE_PoC/tree/main/poc) |
| **CVE-2026-85199** | N/A | N/A | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact non évalué par la source ; l'existence d'un PoC public sans correctif rend une exploitation opportuniste plausible selon la nature de la faille. | Theoretical | Aucun correctif publié à ce jour : appliquer des mesures compensatoires (WAF, restriction d'accès, durcissement), limiter l'exposition Internet des composants Eclipse et surveiller la publication d'un patch. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-82958** | N/A | N/A | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact non évalué par la source ; la disponibilité d'un PoC public sans correctif rend une exploitation opportuniste plausible. | Theoretical | Aucun correctif publié : appliquer des mesures compensatoires (WAF, restriction d'accès, durcissement), limiter l'exposition Internet des composants Eclipse et surveiller la publication d'un patch. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-82217** | 8.8 | 0.38% | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact potentiel élevé sur la confidentialité, l'intégrité ou la disponibilité du composant affecté ; l'exploit public rend le risque immédiat en cas d'exposition Internet. | Theoretical | Aucun correctif publié : appliquer des mesures compensatoires (WAF, restriction d'accès, durcissement), limiter l'exposition Internet et surveiller la publication d'un patch. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-19884** | N/A | 0.13% | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact non évalué par la source en l'absence de scoring ; à réévaluer dès publication des détails techniques. | None | Correctif en cours de validation côté éditeur : appliquer des mesures compensatoires (WAF, filtrage, durcissement) et déployer le patch dès sa publication. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-12605** | 9.6 | N/A | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact potentiel critique : compromission complète du composant affecté possible (jusqu'à l'exécution de code à distance selon la nature de la faille, non précisée par la source). | None | Correctif disponible : mettre à jour les composants Eclipse concernés vers la version corrigée, puis vérifier l'absence d'exploitation antérieure dans les journaux. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-61891** | 7.5 | 0.46% | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact potentiel élevé sur la confidentialité, l'intégrité ou la disponibilité du composant affecté ; probabilité d'exploitation non négligeable selon l'EPSS. | None | Correctif disponible : mettre à jour les composants Eclipse concernés vers la version corrigée, puis vérifier l'absence d'exploitation antérieure dans les journaux. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-60009** | 8.8 | N/A | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact potentiel élevé sur la confidentialité, l'intégrité ou la disponibilité du composant affecté ; exploitabilité démontrée par PoC public. | Theoretical | Correctif disponible : mettre à jour les composants Eclipse concernés vers la version corrigée, puis vérifier l'absence d'exploitation antérieure dans les journaux. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-14574** | 6.5 | 0.15% | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact modéré : exploitation conditionnelle avec effets limités sur la confidentialité, l'intégrité ou la disponibilité. | Theoretical | Correctif disponible : mettre à jour les composants Eclipse concernés vers la version corrigée dans le cycle de patching courant. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-63248** | 6.5 | N/A | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact modéré : exploitation conditionnelle avec effets limités sur la confidentialité, l'intégrité ou la disponibilité. | None | Correctif disponible : mettre à jour les composants Eclipse concernés vers la version corrigée dans le cycle de patching courant. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-61387** | 7.5 | N/A | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact potentiel élevé sur la confidentialité, l'intégrité ou la disponibilité du composant affecté ; exploitabilité à confirmer selon le contexte d'exposition. | None | Correctif disponible : mettre à jour les composants Eclipse concernés vers la version corrigée, puis vérifier l'absence d'exploitation antérieure dans les journaux. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-12606** | 5.3 | 0.19% | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact modéré : exploitation conditionnelle avec effets limités sur la confidentialité, l'intégrité ou la disponibilité. | None | Correctif disponible : mettre à jour les composants Eclipse concernés vers la version corrigée dans le cycle de patching courant. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-58465** | 8.7 | 0.56% | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact potentiel élevé sur la confidentialité, l'intégrité ou la disponibilité du composant affecté ; probabilité d'exploitation la plus forte du portefeuille Eclipse selon l'EPSS. | None | Correctif en cours de validation côté éditeur : appliquer des mesures compensatoires (WAF, filtrage, durcissement), limiter l'exposition Internet et déployer le patch dès sa publication. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-7412** | 8.6 | 0.04% | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact potentiel élevé sur la confidentialité, l'intégrité ou la disponibilité du composant affecté ; exploitabilité à confirmer selon le contexte d'exposition. | None | Correctif en cours de validation côté éditeur : appliquer des mesures compensatoires (WAF, filtrage, durcissement) et déployer le patch dès sa publication. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-7411** | 10.0 | 0.14% | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact potentiel maximal (CVSS 10.0) : compromission complète du composant affecté probable (jusqu'à l'exécution de code à distance selon la nature de la faille, non précisée par la source). | None | Correctif en cours de validation côté éditeur : appliquer des mesures compensatoires strictes (WAF, restriction d'accès, retrait d'exposition Internet si nécessaire) et déployer le patch dès sa publication. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2023-54344** | 9.8 | 0.22% | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact potentiel critique : compromission complète du composant affecté possible (jusqu'à l'exécution de code à distance selon la nature de la faille, non précisée par la source). | Theoretical | Aucun correctif publié : appliquer des mesures compensatoires strictes (WAF/virtual patching, restriction d'accès), limiter drastiquement l'exposition Internet et surveiller la publication d'un patch. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2023-54342** | 9.8 | 0.27% | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact potentiel critique : compromission complète du composant affecté possible (jusqu'à l'exécution de code à distance selon la nature de la faille, non précisée par la source). | Theoretical | Aucun correctif publié : appliquer des mesures compensatoires strictes (WAF/virtual patching, restriction d'accès), limiter drastiquement l'exposition Internet et surveiller la publication d'un patch. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-2332** | 7.4 | 0.02% | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact potentiel élevé sur la confidentialité, l'intégrité ou la disponibilité du composant affecté ; exploitabilité démontrée par PoC public mais probabilité faible selon l'EPSS. | Theoretical | Correctif disponible : mettre à jour les composants Eclipse concernés vers la version corrigée, puis vérifier l'absence d'exploitation antérieure dans les journaux. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-5795** | 7.4 | 0.53% | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact potentiel élevé sur la confidentialité, l'intégrité ou la disponibilité du composant affecté ; probabilité d'exploitation significative selon l'EPSS. | None | Correctif disponible : mettre à jour les composants Eclipse concernés vers la version corrigée, puis vérifier l'absence d'exploitation antérieure dans les journaux. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-24457** | 9.1 | 0.09% | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact potentiel critique : compromission complète du composant affecté possible (jusqu'à l'exécution de code à distance selon la nature de la faille, non précisée par la source). | Theoretical | Correctif en cours de validation côté éditeur : appliquer des mesures compensatoires strictes (WAF/virtual patching, restriction d'accès), limiter drastiquement l'exposition Internet et déployer le patch dès sa publication. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |
| **CVE-2026-1605** | 7.5 | 0.03% | FALSE | Composants open source de l'écosystème Eclipse (dont Eclipse Jetty) — périmètre exact du CVE non détaillé par la source | Non précisée dans la source (faiblesses dominantes chez Eclipse : CWE-79 XSS, CWE-400 consommation de ressources, CWE-20 validation d'entrée) | Impact potentiel élevé sur la confidentialité, l'intégrité ou la disponibilité du composant affecté ; exploitabilité à confirmer selon le contexte d'exposition. | None | Correctif disponible : mettre à jour les composants Eclipse concernés vers la version corrigée, puis vérifier l'absence d'exploitation antérieure dans les journaux. | [https://www.valtersit.com/vendors/eclipse/](https://www.valtersit.com/vendors/eclipse/)<br>[https://mastodon.social/@hugovalters/117265939151764533](https://mastodon.social/@hugovalters/117265939151764533)<br>`hxxps://www.valtersit[.]com/vendors/eclipse/` |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="dfir-dune-alerte-defender-behaviorwin32regdumpsa-a-la-decouverte-dun-dump-sam-via-impacket-secretsdumppy"></div>

## DFIR : d'une alerte Defender (Behavior:Win32/RegDump.SA) à la découverte d'un dump SAM via Impacket secretsdump.py

### Résumé

Une note d'incident réel détaille l'analyse d'une alerte Microsoft Defender « Behavior:Win32/RegDump.SA » attribuée au processus C:\Windows\System32\svchost.exe exécuté en tant que SYSTEM. L'analyse de la MFT (Master File Table) autour de l'horodatage de l'alerte a révélé un fichier C:\Windows\Temp\ASOWCIKI.tmp dont l'aperçu affiche la signature « regf » : une ruche SAM partielle, suggérant une opération de sauvegarde interrompue, possiblement par Defender. Le nommage, huit lettres ASCII aléatoires suivies de .tmp, correspond au schéma de génération des fichiers temporaires d'Impacket (secretsdump.py / RemoteOperations) lors de la sauvegarde à distance des ruches du registre. L'opération étant réalisée à distance via le service Remote Registry (protocole MS-RRP sur le pipe \pipe\winreg accessible par SMB), la télémétrie locale montre svchost.exe et non un binaire attaquant. Impacket supprime normalement le fichier temporaire après récupération ; sa présence résiduelle a fourni un artefact forensique de qualité. L'auteur précise que de nombreux outils offensifs réutilisent le code d'Impacket, sans que cela prouve l'exécution du script autonome, et référence un cas similaire publié par Huntress.

---

### Analyse opérationnelle

Exploiter chaque alerte AV/EDR comme point de pivot : collecter la télémétrie puis élargir l'analyse (MFT, artefacts système) autour de l'horodatage, en regardant avant et après l'alerte. Retenir que le processus émetteur de l'alerte (svchost.exe via MS-RRP) n'est pas nécessairement l'outil de l'attaquant. Pistes de détection : création de fichiers *.tmp à huit caractères ASCII aléatoires dans C:\Windows\Temp avec en-tête regf, accès SMB au pipe \pipe\winreg depuis des sources inhabituelles, usage du service Remote Registry. En cas de ruche SAM partielle, considérer que l'attaquant peut réitérer le dump et procéder à la rotation des credentials locaux.

---

### Implications stratégiques

Le dump de credentials à distance via Remote Registry reste une technique discrète qui contourne les détections centrées sur les binaires. La réutilisation massive du code Impacket par de nombreux frameworks offensifs complique l'attribution et impose une détection comportementale plutôt que signaturelle. Même lorsque l'attaquant nettoie ses traces, les métadonnées du système de fichiers (MFT) conservent des preuves : la préparation forensique (collecte MFT, rétention de télémétrie) doit être un investissement structurant pour toute organisation.

---

### Recommandations

* Restreindre ou désactiver le service Remote Registry à distance et filtrer l'accès au pipe \pipe\winreg
* Surveiller les créations de fichiers *.tmp à nommage aléatoire dans C:\Windows\Temp avec en-tête regf
* Corréler systématiquement les alertes AV/EDR avec une analyse MFT autour de l'horodatage
* Réinitialiser les credentials des comptes locaux des hôtes où un dump SAM est suspecté
* Détecter les connexions SMB vers \pipe\winreg depuis des hôtes non administratifs

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Activer la collecte et l'analyse de la MFT avec une rétention suffisante sur les endpoints
* Durcir le service Remote Registry (désactivation par défaut, filtrage réseau de l'accès au pipe winreg)
* Définir un runbook de triage des détections comportementales Defender (RegDump et équivalents)
* Activer la journalisation SMB (accès à \pipe\winreg, Event ID 5145) et Sysmon (création de fichiers)

#### Phase 2 — Détection et analyse

* Alerter sur les détections Behavior:Win32/RegDump* même lorsque le processus est svchost.exe/SYSTEM
* Détecter la création de fichiers C:\Windows\Temp\????????.tmp (huit lettres ASCII aléatoires) avec en-tête regf
* Surveiller les accès SMB distants au pipe \pipe\winreg et toute activation du service Remote Registry
* Corréler les logons réseau (4624 type 3) suivis d'un accès aux ruches du registre

#### Phase 3 — Confinement, éradication et récupération

* Isoler l'hôte cible et identifier/bloquer l'hôte source du dump
* Désactiver Remote Registry et restreindre l'administration distante sur l'hôte concerné
* Réinitialiser les mots de passe des comptes locaux (SAM) et des credentials potentiellement exposés

#### Phase 4 — Activités post-incident

* Construire une timeline MFT autour de l'horodatage de l'alerte (fichiers créés, modifiés, supprimés)
* Identifier le compte et l'hôte source, puis rechercher d'autres cibles présentant le même schéma
* Évaluer l'usage ultérieur des hashes récupérés (pass-the-hash, mouvements latéraux) et éradiquer la persistance

#### Phase 5 — Threat Hunting (proactif)

* Chasser sur l'ensemble du parc les fichiers *.tmp à nommage aléatoire dans C:\Windows\Temp et les fichiers regf partiels
* Rechercher les connexions historiques au pipe \pipe\winreg depuis des sources non administratives
* Réexaminer les détections RegDump clôturées sans investigation MFT préalable

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1003** | OS Credential Dumping : sauvegarde à distance de la ruche SAM via le service Remote Registry (MS-RRP sur \pipe\winreg), cohérente avec Impacket secretsdump.py |
| **T1070** | Indicator Removal : suppression du fichier temporaire de dump après récupération (échouée ici, laissant un artefact forensique) |

---

### Sources

* [https://dfir.ch/posts/field_notes_av_impacket/](https://dfir.ch/posts/field_notes_av_impacket/)


---

<div id="advisory-cisa-deux-soc-une-alerte-legitime-etouffee-par-un-inventaire-dactifs-defaillant"></div>

## Advisory CISA « deux SOC » : une alerte légitime étouffée par un inventaire d'actifs défaillant

### Résumé

Dans son advisory comparant deux SOC, la CISA décrit le cas d'une organisation en échec où une alerte était réelle : une activité de red team légitime détectée sur un serveur de gestion de configuration. Les défenseurs ont pris en charge l'alerte et tenté d'identifier le propriétaire du système et sa fonction, sans y parvenir ; l'alerte a été reclassée en faux positif. La détection a fonctionné et l'alerte était fondée, mais elle a été perdue parce que l'inventaire d'actifs (CMDB) ne permettait de rattacher le système à aucun responsable.

---

### Analyse opérationnelle

Enrichir chaque alerte avec le contexte d'actif (propriétaire nommé, fonction, criticité) avant toute décision de triage ; intégrer la CMDB et l'ITSM au SIEM et à l'EDR pour une corrélation automatique ; définir une voie d'escalade dédiée pour les alertes concernant des actifs sans propriétaire identifié, au lieu de les clore en faux positif ; auditer périodiquement la CMDB pour repérer les actifs non rattachés, en particulier les serveurs sensibles (gestion de configuration, PKI, annuaires).

---

### Implications stratégiques

La maturité d'un SOC ne se mesure pas seulement à sa capacité de détection mais à la chaîne complète alerte, contexte, décision. Un inventaire d'actifs défaillant transforme des vrais positifs en faux positifs et expose l'organisation à des intrusions non détectées. La gouvernance des actifs (ownership, recensement) doit être financée et pilotée au même titre que les outils de détection, sous peine de neutraliser leur retour sur investissement.

---

### Recommandations

* Rattacher un propriétaire nommé à chaque actif critique dans la CMDB et vérifier la donnée par des revues régulières
* Corréler automatiquement les alertes SIEM/EDR avec la CMDB pour enrichir le triage
* Interdire la clôture en faux positif d'une alerte sur un actif sans propriétaire sans escalade préalable
* Prioriser l'inventaire des serveurs sensibles (gestion de configuration, administration, identité)
* Suivre en KPI le taux d'alertes résolues avec un contexte d'actif complet

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir une CMDB exhaustive avec propriétaire nommé, fonction et criticité pour chaque actif, vérifiée par des revues périodiques
* Intégrer la CMDB au SIEM et à l'EDR pour un enrichissement automatique des alertes
* Définir une procédure de triage imposant le contexte d'actif avant toute clôture d'alerte
* Former les analystes à escalader les alertes portant sur des actifs orphelins

#### Phase 2 — Détection et analyse

* Surveiller en priorité les alertes sur les serveurs de gestion de configuration et d'administration
* Taguer les alertes sans contexte d'actif comme prioritaires pour enrichissement manuel
* Détecter les écarts entre les actifs actifs sur le réseau et ceux déclarés dans l'inventaire

#### Phase 3 — Confinement, éradication et récupération

* Isoler tout système générant une alerte jugée crédible mais non identifié dans l'inventaire
* Geler les changements sur l'actif concerné le temps d'identifier son propriétaire
* Escalader au RSSI toute alerte réelle concernant un actif orphelin

#### Phase 4 — Activités post-incident

* Analyser pourquoi l'alerte a été classée faux positif (processus, données, outils)
* Corriger la CMDB et le processus de triage à partir des enseignements
* Boucler avec l'équipe de détection pour ajuster les règles et les enrichissements

#### Phase 5 — Threat Hunting (proactif)

* Chasser proactivement les activités suspectes sur les actifs sans propriétaire identifié
* Réconcilier régulièrement les sources d'alertes avec l'inventaire pour repérer les angles morts
* Vérifier l'historique des alertes clôturées en faux positif sur des actifs sensibles

---

### Sources

* [https://mastodon.social/@BigG_TheCreator/117266212505028117](https://mastodon.social/@BigG_TheCreator/117266212505028117)


---

<div id="veille-vulnerabilites-cve-critiques-en-tendance-cisco-sd-wan-n8n-ivanti-epmm-crawl4ai-et-rappel-sur-les-conteneurs-non-root"></div>

## Veille vulnérabilités : CVE critiques en tendance (Cisco SD-WAN, n8n, Ivanti EPMM, Crawl4AI) et rappel sur les conteneurs non-root

### Résumé

Le portail cvedatabase.com publie une liste de CVE en tendance dans la communauté, incluant plusieurs critiques : CVE-2026-20127 (authentification de peering des Cisco Catalyst SD-WAN Controller/Manager, CVSS 10.0), CVE-2026-20182 (critique, CVSS 10.0), CVE-2026-21858 (n8n versions 1.65.0 à 1.121.0 permettant l'accès aux fichiers du système sous-jacent, CVSS 10.0), CVE-2026-1340 (injection de code dans Ivanti Endpoint Manager Mobile, RCE non authentifiée, CVSS 9.8) et CVE-2026-26216 (RCE dans Crawl4AI versions antérieures à 0.8.0 via le paramètre hooks du endpoint /crawl en déploiement Docker API, CVSS 10.0). Figurent également CVE-2026-20122 et CVE-2026-20133 (API et divulgation d'informations sur Cisco SD-WAN Manager), CVE-2026-20128 (fonction DCA de Cisco SD-WAN Manager), CVE-2026-5281 (use-after-free dans Dawn de Google Chrome antérieur à 146.0.7680.178, CVSS 8.8), CVE-2026-20805 (divulgation d'informations via Desktop Windows Manager), CVE-2025-48700 (XSS dans Zimbra Collaboration 8.8.15/9.0/10.0/10.1), CVE-2025-53521 (arrêt de TMM sur F5 BIG-IP APM, CVSS 8.7) et CVE-2024-27199 (path traversal JetBrains TeamCity antérieur à 2023.11.4). Le même portail rappelle une bonne pratique conteneurs : ne pas exécuter les conteneurs en root et ajouter une instruction USER au Dockerfile pour compliquer l'évasion de conteneur vers l'hôte après exploitation d'une vulnérabilité.

---

### Analyse opérationnelle

Prioriser le patch des surfaces exposées : instances n8n 1.65.0 à 1.121.0, déploiements Crawl4AI antérieurs à 0.8.0 avec endpoint /crawl accessible, serveurs Ivanti Endpoint Manager Mobile exposés, contrôleurs et managers Cisco SD-WAN (authentification de peering). Vérifier les versions en inventaire et appliquer les correctifs éditeurs ; mettre en place du virtual patching (WAF/IPS) en attendant. Côté conteneurs : auditer les Dockerfiles sans instruction USER et les pods s'exécutant en root, activer seccomp/AppArmor et l'exécution non-root.

---

### Implications stratégiques

Les plateformes d'automatisation (n8n, Crawl4AI) et les solutions d'administration d'infrastructure (Ivanti EPMM, Cisco SD-WAN) deviennent des cibles privilégiées car elles concentrent des accès et des capacités d'exécution. Une compromission de SD-WAN ou d'EPMM a un impact réseau et parc global. Les délais de patch sur les CVSS 10.0 exposés doivent être encadrés par des SLA contractuels, et la sécurité des chaînes d'automatisation constitue désormais un risque business à part entière.

---

### Recommandations

* Inventorier et patcher en priorité n8n (>= 1.121.0), Crawl4AI (>= 0.8.0), Ivanti EPMM et les composants Cisco Catalyst SD-WAN concernés
* Restreindre l'exposition Internet des interfaces d'administration (SD-WAN Manager, EPMM, n8n, Crawl4AI)
* Appliquer du virtual patching WAF/IPS sur les vulnérabilités critiques en attente de correctif
* Interdire l'exécution root des conteneurs (instruction USER, PodSecurity, seccomp) et auditer les images existantes
* Suivre les flux KEV/EPSS pour prioriser selon le risque d'exploitation réel

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire versionné des produits exposés (n8n, Crawl4AI, Ivanti EPMM, Cisco SD-WAN, Zimbra, TeamCity, F5 BIG-IP)
* S'abonner aux flux NVD, CISA KEV et EPSS ainsi qu'aux alertes éditeurs
* Définir des SLA de patch par criticité (ex. CVSS >= 9 exposé : 48-72 h)

#### Phase 2 — Détection et analyse

* Surveiller les tentatives d'exploitation sur les endpoints concernés (endpoint /crawl avec paramètre hooks, API SD-WAN Manager, interfaces EPMM)
* Corréler les scans et les accès anormaux aux interfaces d'administration
* Alerter sur les créations ou modifications de fichiers inattendues sur les serveurs n8n et les conteneurs Crawl4AI

#### Phase 3 — Confinement, éradication et récupération

* Restreindre ou couper l'exposition Internet des systèmes vulnérables non patchés
* Isoler les instances suspectées compromises (n8n, conteneurs) et révoquer les credentials associés
* Appliquer des règles WAF/IPS bloquant les vecteurs d'exploitation connus

#### Phase 4 — Activités post-incident

* Vérifier l'intégrité des instances (fichiers accédés via n8n, commandes exécutées via Crawl4AI)
* Rechercher des mouvements latéraux depuis les serveurs d'automatisation compromis
* Documenter la chronologie et mettre à jour les mesures de durcissement

#### Phase 5 — Threat Hunting (proactif)

* Chasser les accès fichiers anormaux sur les hôtes n8n en versions 1.65.0 à 1.121.0
* Rechercher les requêtes au endpoint /crawl de Crawl4AI contenant un paramètre hooks suspect
* Vérifier les journaux d'authentification de peering et d'API des contrôleurs Cisco SD-WAN

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploitation d'applications exposées publiquement (RCE non authentifiée Ivanti EPMM et Crawl4AI, accès fichiers n8n) |

---

### Sources

* [https://cvedatabase.com](https://cvedatabase.com)


---

<div id="site-compromis-expediant-du-phishing-les-signalements-naboutissent-pas-mx-absent-abuse-rejete"></div>

## Site compromis expédiant du phishing : les signalements n'aboutissent pas (MX absent, abuse@ rejeté)

### Résumé

Un chercheur raconte avoir tenté de prévenir une petite entreprise dont le site web avait été compromis et envoyait des courriels de phishing à des tiers. L'unique adresse publiée par l'entreprise se trouvait sur un domaine dépourvu d'enregistrement MX ; conformément au mécanisme d'« implicit MX » de la RFC 5321, le serveur expéditeur a tenté de livrer vers l'adresse web du domaine, sans réponse, avec relance pendant deux jours avant abandon. Le site compromis, lui, émettait le phishing sans difficulté. Une seconde tentative via le domaine du site a montré que postmaster@ était accepté mais abuse@ rejeté comme utilisateur inconnu, alors que la RFC 2142 (1997) impose ces deux boîtes de rôle. L'auteur recommande de vérifier les MX de tous les domaines publiés, d'utiliser le « null MX » (RFC 7505) pour les domaines ne recevant pas de courrier, de rendre postmaster et abuse réellement consultés, et de tester la délivrabilité en envoyant des messages depuis l'extérieur.

---

### Analyse opérationnelle

Vérifier les enregistrements MX de tous les domaines publiés (site, security.txt, pieds de page, PDF) ; publier un null MX (RFC 7505) sur les domaines sans réception de mail pour éviter les files d'attente et les échecs silencieux ; garantir que postmaster@ et abuse@ existent et sont lus ; surveiller l'émission de courriels depuis les serveurs web, indicateur classique de compromission ; tester périodiquement la délivrabilité des adresses de contact depuis un compte externe à l'organisation.

---

### Implications stratégiques

Des canaux de signalement inopérants retardent la détection de compromissions par des tiers bienveillants et allongent les délais de prise de conscience, avec un risque réglementaire (notification de violation, RGPD) et réputationnel. L'asymétrie sortant/entrant signifie qu'un attaquant peut exploiter votre domaine alors que personne ne peut vous prévenir. L'hygiène DNS/mail représente un investissement marginal pour un gain de résilience significatif.

---

### Recommandations

* Lister toutes les adresses publiées et vérifier le MX de chaque domaine (dig MX)
* Publier un null MX (RFC 7505) sur les domaines qui ne doivent pas recevoir de courrier
* Créer et superviser postmaster@ et abuse@ (RFC 2142) avec des boîtes réellement consultées
* Tester la délivrabilité des adresses de contact depuis un compte externe
* Surveiller le trafic SMTP sortant des serveurs web pour détecter une compromission

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Publier des contacts de sécurité joignables (security.txt, postmaster@, abuse@) et un null MX sur les domaines non mail
* Documenter une procédure de traitement des signalements externes (triage, escalade, délais)
* Séparer les fonctions d'envoi d'e-mails des serveurs web et authentifier les envois (SPF, DKIM, DMARC)

#### Phase 2 — Détection et analyse

* Alerter sur tout trafic SMTP sortant depuis les serveurs web ou sur des volumes anormaux d'e-mails émis
* Surveiller les listes de blocage et la réputation du domaine pour détecter un usage abusif
* Vérifier les retours NDR et les files d'attente sortantes anormales

#### Phase 3 — Confinement, éradication et récupération

* Suspendre l'envoi d'e-mails depuis l'infrastructure compromise et purger les files d'attente
* Retirer ou cloisonner le site compromis et révoquer les accès compromis
* Notifier les destinataires et plateformes anti-abuse pour faire retirer les campagnes

#### Phase 4 — Activités post-incident

* Identifier le vecteur de compromission du site (CMS, credentials, dépendances)
* Corriger, restaurer depuis une version saine et renforcer (MFA, WAF, mises à jour)
* Réévaluer la joignabilité des canaux de signalement après incident

#### Phase 5 — Threat Hunting (proactif)

* Rechercher d'autres envois de phishing depuis le domaine (logs SMTP, règles de boîtes, webshells)
* Vérifier l'absence d'autres domaines publiés sans MX ou sans boîtes de rôle
* Analyser les accès au site pour identifier une éventuelle persistance de l'attaquant

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing : le site web compromis était utilisé pour envoyer des courriels de phishing à des tiers |

---

### Sources

* [https://ftrcrp.org/signals/the-door-nobody-checks/](https://ftrcrp.org/signals/the-door-nobody-checks/)


---

<div id="ph4ntxm-anatomie-dune-distribution-live-debian-durcie-identite-de-session-modes-de-boot-et-reseau-protege"></div>

## PH4NTXM : anatomie d'une distribution live Debian durcie — identité de session, modes de boot et réseau protégé

### Résumé

Une série de trois publications « Inside PH4NTXM » détaille l'architecture interne de PH4NTXM, un système live basé sur Debian/Linux orienté confidentialité et opsec. (#1) Identité de session liée : au démarrage, le système valide le machine ID et le combine à de l'aléa frais pour dériver une graine de session reliant hostname, sélection matérielle et adresses MAC des interfaces physiques ; les composants aval consomment la même chaîne d'identité afin de réduire les contradictions entre les surfaces de reporting contrôlées par l'OS. (#2) Sélection du mode de boot : profils aligné Linux, aligné Windows et « Lonewolf » (Tor isolé) ; les modes normaux préparent un moteur de transformation de paquets avec Firefox ESR et Unbound, tandis que Lonewolf prépare une chaîne d'identité indépendante, le routage Tor et le Tor Browser ; le mode choisi reste fixe pour toute la session. (#3) Démarrage réseau protégé : abaissement des liens physiques et désactivation du swap ; la libération du réseau attend les contrôles d'identité, pare-feu, traitement de paquets, horloge et « Nuke-arming » ; la MAC protégée de chaque adaptateur est vérifiée avant activation, avec un délai aléatoire de 2 à 7 secondes apportant une variation temporelle.

---

### Analyse opérationnelle

Pour les défenseurs, ces publications fournissent une grille de lecture des capacités anti-corrélation et anti-forensique de ce type d'outil : démarrage sur média live, désactivation du swap (réduction des traces disque), randomisation et vérification des adresses MAC, routage Tor et variation temporelle du trafic. Les équipes de détection peuvent en dériver des signaux concrets : boot sur périphérique amovible, absence de disque persistant, changements d'adresse MAC, flux Tor et résolveurs DNS non standards (Unbound). À l'inverse, pour les équipes red team et les profils à risque, l'outil illustre un durcissement opsec de référence (cohérence d'identité, gating de démarrage, vérification MAC par adaptateur).

---

### Implications stratégiques

La disponibilité publique d'outillages opsec clé en main abaisse la barrière d'entrée pour des acteurs cherchant l'anonymisation complète de leurs opérations, y compris à des fins malveillantes. Les organisations doivent intégrer l'hypothèse d'un usage interne non autorisé de systèmes live anonymisants (contournement des contrôles endpoint, exfiltration hors traçabilité) dans leur modèle de risque, leurs politiques de contrôle des médias amovibles et leurs configurations de boot.

---

### Recommandations

* Verrouiller l'ordre de boot et désactiver le démarrage USB/externe dans BIOS/UEFI (Secure Boot)
* Alerter sur les flux Tor et les résolveurs DNS non autorisés depuis le réseau d'entreprise
* Surveiller les changements d'adresse MAC et les interfaces réseau non répertoriées
* Contrôler et journaliser l'usage des médias amovibles
* Sensibiliser aux risques liés à l'usage d'OS live non validés sur le parc

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les médias live autorisés et verrouiller les séquences de boot (BIOS/UEFI, Secure Boot, mot de passe firmware)
* Établir une baseline des adresses MAC, hostnames et flux DNS/Tor du parc
* Définir une politique sur les médias amovibles et les OS non gérés
* Déployer la visibilité réseau (NetFlow, DNS, proxy) pour détecter les schémas d'anonymisation

#### Phase 2 — Détection et analyse

* Alerter sur les boots hors disque système (PXE, USB) et les machines sans agent EDR remontant
* Détecter les variations d'adresse MAC d'un même poste ou des OUI incohérents
* Signaler les connexions vers des nœuds d'entrée Tor et les résolveurs de type Unbound non autorisés
* Surveiller les user-agents atypiques (Firefox ESR isolé, Tor Browser) sur les flux sortants

#### Phase 3 — Confinement, éradication et récupération

* Isoler au niveau réseau les équipements présentant un comportement d'anonymisation non autorisé
* Bloquer les sorties Tor et les proxys/DNS non validés au périmètre
* Prioriser la capture réseau (données volatiles) avant toute extinction, l'OS live ne laissant pas de traces disque
* Saisir et conserver le média amovible conformément aux procédures légales internes

#### Phase 4 — Activités post-incident

* Analyser les captures réseau pour reconstituer les activités menées depuis l'OS live
* Corréler adresses MAC, horodatages et identités pour attribuer l'usage
* Évaluer une éventuelle exfiltration de données et notifier selon les obligations
* Renforcer les contrôles boot et médias amovibles à partir des enseignements

#### Phase 5 — Threat Hunting (proactif)

* Chasser rétrospectivement les flux Tor et les schémas de timing atypiques dans les logs proxy/NetFlow
* Rechercher les requêtes DHCP avec hostnames génériques ou incohérents avec l'inventaire
* Identifier les postes ayant présenté des adresses MAC multiples sur une période donnée
* Corréler les absences d'agent de sécurité avec des activités réseau sortantes anormales

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1090** |  |

---

### Sources

* [https://infosec.exchange/@PH4NTXMOFFICIAL/117266096687282880](https://infosec.exchange/@PH4NTXMOFFICIAL/117266096687282880)
* [https://infosec.exchange/@PH4NTXMOFFICIAL/117266007708166888](https://infosec.exchange/@PH4NTXMOFFICIAL/117266007708166888)
* [https://infosec.exchange/@PH4NTXMOFFICIAL/117265986371045415](https://infosec.exchange/@PH4NTXMOFFICIAL/117265986371045415)
* [https://infosec.exchange/@PH4NTXMOFFICIAL/117265882881199568](https://infosec.exchange/@PH4NTXMOFFICIAL/117265882881199568)
* [https://infosec.exchange/@PH4NTXMOFFICIAL/117265915478565978](https://infosec.exchange/@PH4NTXMOFFICIAL/117265915478565978)
* [https://infosec.exchange/@PH4NTXMOFFICIAL/117265927243777973](https://infosec.exchange/@PH4NTXMOFFICIAL/117265927243777973)


---

<div id="acces-initial-sous-macos-phishing-faux-installeurs-et-contournement-de-gatekeeper-bsides-frankfurt-2026"></div>

## Accès initial sous macOS : phishing, faux installeurs et contournement de Gatekeeper (BSides Frankfurt 2026)

### Résumé

Lors de BSides Frankfurt 2026, le chercheur de dfir.ch a présenté une dissection des chaînes d'accès initial modernes ciblant macOS, mettant fin au mythe d'une immunité naturelle d'Apple aux malwares. Les vecteurs d'infection analysés incluent les publicités Google trompeuses (malvertising), les campagnes ClickFix et le phishing incitant les utilisateurs à baisser leur garde. La phase d'exécution s'appuie sur des langages de script traditionnels (Bash, Python) et natifs Apple (AppleScript, AppleScript compilé, Perl, JXA). Les mécanismes de livraison opposent l'abus de binaires natifs (Mach-O, applications empaquetées avec Platypus, frameworks Electron) à la trojanisation de formats d'installation et de stockage (DMG, PKG). L'élargissement de la surface d'attaque macOS est lié à sa popularité croissante en entreprise. Une vidéo YouTube de la présentation est annoncée comme à venir.

---

### Analyse opérationnelle

Les équipes SOC doivent étendre la couverture de détection aux postes macOS : journalisation unifiée, EDR compatible Mac et surveillance des interpréteurs de script (osascript/JXA, Python, Perl) lancés depuis des fichiers téléchargés ou des volumes montés. Points de détection prioritaires : tentatives de retrait de l'attribut de quarantaine (contournement Gatekeeper), montage de DMG/PKG suivi d'exécution de scripts, processus enfants issus de navigateurs ou d'installeurs, applications Platypus/Electron non signées. Une sensibilisation ciblée contre le ClickFix (fausses instructions de support) et le malvertising sur les moteurs de recherche est nécessaire. L'allowlisting applicatif et le blocage des installeurs non notariés réduisent concrètement la surface d'attaque.

---

### Implications stratégiques

La professionnalisation des chaînes d'accès initial macOS indique un déplacement progressif des investissements offensifs vers les parcs Apple en entreprise, longtemps négligés par les attaquants. Les organisations dont le modèle de menace reste centré Windows portent un angle mort structurel : budget, outillage et compétences dédiés à la sécurité macOS deviennent nécessaires. Les directions IT doivent réévaluer les politiques de gestion (MDM, notarisation, allowlisting) applicables aux flottes Mac, et les éditeurs EDR comme les équipes de threat intelligence couvrir ce segment en croissance.

---

### Recommandations

* Déployer un EDR et la journalisation unifiée sur l'ensemble des postes macOS
* Activer strictement Gatekeeper et la notarisation ; bloquer l'exécution d'installeurs non signés
* Restreindre et surveiller osascript/JXA, Python et Perl sur les postes utilisateurs
* Sensibiliser aux campagnes ClickFix et au malvertising (fausses publicités d'installeurs)
* Chasser les retraits d'attribut de quarantaine (xattr) et les montages DMG/PKG suspects

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer EDR et journalisation unifiée (Unified Log) sur toutes les flottes macOS
* Activer Gatekeeper en mode strict, notarisation obligatoire et allowlisting applicatif via MDM
* Former les utilisateurs aux campagnes ClickFix, faux installeurs et malvertising
* Définir des procédures de réponse à incident spécifiques macOS (collecte de preuves, isolation)
* Centraliser les télémétries macOS dans le SIEM avec règles de corrélation dédiées

#### Phase 2 — Détection et analyse

* Alerter sur l'exécution d'osascript/JXA ou de scripts Python/Perl issus de répertoires de téléchargement ou de volumes montés
* Détecter les montages DMG/PKG suivis d'un processus enfant inhabituel
* Surveiller les tentatives de contournement de Gatekeeper (suppression de l'attribut com.apple.quarantine)
* Signaler les applications Platypus/Electron non signées ou non notariées
* Corréler les téléchargements réseau (curl, python) initiés par des navigateurs ou des installeurs

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement l'hôte du réseau et suspendre les sessions utilisateur
* Bloquer les hachages, domaines et URLs d'infrastructure de livraison identifiés
* Supprimer les installeurs malveillants et révoquer les autorisations TCC accordées
* Réinitialiser les identifiants potentiellement exposés sur la machine compromise

#### Phase 4 — Activités post-incident

* Mener l'analyse forensique : base de quarantaine, Unified Log, mécanismes de persistance (LaunchAgents/LaunchDaemons), volumes montés
* Reconstituer la chaîne d'accès initial (vecteur, livraison, exécution) et documenter les IOC
* Mettre à jour les règles de détection et les listes de blocage
* Organiser un retour d'expérience avec les équipes IT et sécurité

#### Phase 5 — Threat Hunting (proactif)

* Chasser les exécutions JXA/AppleScript en une ligne dans les télémétries historiques
* Rechercher les binaires Mach-O exécutés depuis des répertoires utilisateurs ou des volumes montés
* Identifier les suppressions d'attribut de quarantaine et les overrides Gatekeeper
* Analyser l'historique de navigation pour des schémas ClickFix ou de fausses pages de téléchargement
* Corréler les campagnes de malvertising connues avec les téléchargements internes

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Hameçonnage et malvertising (publicités Google trompeuses, campagnes ClickFix) comme vecteurs d'infection initiale |
| **T1204** | Exécution par l'utilisateur d'installeurs trojanisés (DMG, PKG) et d'applications piégées |
| **T1059** | Abus d'interpréteurs de script : Bash, Python, AppleScript, AppleScript compilé, Perl et JXA |
| **T1553** | Subversion des contrôles de confiance : abus des permissions Gatekeeper et de la notarisation |

---

### Sources

* [https://dfir.ch/talks/bsides_frankfurt_2026/](https://dfir.ch/talks/bsides_frankfurt_2026/)


---

<div id="parse-server-70-cves-non-corrigees-dont-5-critiqueselevees-et-un-score-cvss-maximal-de-100"></div>

## Parse Server : 70 CVEs non corrigées dont 5 critiques/élevées et un score CVSS maximal de 10.0

### Résumé

Selon l'évaluation publiée par ValtersIT, Parse Server, un Backend-as-a-Service auto-hébergé, cumule 70 CVEs intégralement sans correctif (« 100% unpatched »), dont 5 de sévérité critique/élevée et un CVSS maximal de 10.0. Le trust score attribué est D, qualifié de risqué pour un BaaS auto-hébergé. Les faiblesses dominantes sont l'authentification faible (CWE-287) et l'injection SQL (CWE-89). La recommandation formulée est d'auditer tout déploiement avant mise en production.

---

### Analyse opérationnelle

Les équipes doivent inventorier toute instance Parse Server (y compris shadow IT), vérifier l'exposition internet et appliquer des contrôles compensatoires : WAF avec règles anti-SQLi, durcissement de l'authentification (MFA, politiques de mots de passe, rotation des clés maître), segmentation réseau et restriction des interfaces d'administration. Les logs applicatifs doivent être surveillés pour des tentatives d'injection SQL et des échecs d'authentification anormaux. Le composant doit être intégré au processus de gestion des vulnérabilités avec suivi des advisories et tests d'intrusion ciblés sur les chemins d'authentification.

---

### Implications stratégiques

Ce cas illustre le risque fournisseur lié aux composants auto-hébergés au maintien en condition défaillant : l'absence totale de correctifs transforme chaque CVE en porte d'entrée permanente. Les directions doivent arbitrer entre migration vers des offres managées, remplacement du composant ou acceptation d'un risque documenté avec contrôles compensatoires. La faiblesse de l'authentification (CWE-287) combinée à l'injection SQL (CWE-89) expose directement les données métier hébergées, avec des implications de conformité (RGPD, notification de violation) en cas de compromission.

---

### Recommandations

* Inventorier et cartographier toutes les instances Parse Server et leur exposition
* Restreindre l'accès internet et segmenter les instances par rapport aux données sensibles
* Renforcer l'authentification (MFA, rotation des secrets) pour traiter le CWE-287
* Déployer des règles WAF anti-injection SQL en attente de correctifs éditeurs
* Suivre les advisories et planifier une migration ou un remplacement si le maintien en condition reste impossible

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire exhaustif des instances Parse Server et de leurs dépendances (SBOM)
* Intégrer le composant au processus de gestion des vulnérabilités et au suivi des advisories
* Définir des seuils d'alerte sur les tentatives d'exploitation (SQLi, brute force auth)
* Préparer des procédures de virtual patching (WAF, reverse proxy)

#### Phase 2 — Détection et analyse

* Scanner régulièrement les instances (scans authentifiés) contre les 70 CVEs recensées
* Surveiller les logs applicatifs pour des motifs d'injection SQL et des anomalies d'authentification (CWE-287)
* Contrôler l'exposition externe (scans de surface d'attaque, moteurs d'exposition)
* Alerter sur les requêtes inhabituelles vers les classes et endpoints Parse Server

#### Phase 3 — Confinement, éradication et récupération

* Isoler ou couper l'exposition internet des instances vulnérables en cas d'indice d'exploitation
* Appliquer un virtual patching WAF ciblé sur les vecteurs SQLi et d'authentification faible
* Révoquer et renouveler les clés maître, jetons et comptes de service exposés
* Restreindre les interfaces d'administration aux réseaux de gestion

#### Phase 4 — Activités post-incident

* Analyser les logs pour déterminer une éventuelle exploitation antérieure (SQLi, contournements d'authentification)
* Procéder à une rotation générale des secrets et des accès aux bases sous-jacentes
* Évaluer la fuite potentielle de données et déclencher les obligations de notification
* Décider de la remédiation structurelle : migration, remplacement ou durcissement documenté

#### Phase 5 — Threat Hunting (proactif)

* Chasser les motifs SQLi (union select, sleep(), charges encodées) dans les historiques de logs
* Rechercher les succès d'authentification atypiques (comptes inusités, sources inhabituelles)
* Identifier les dumps ou requêtes massives sur les collections de données
* Corréler les tentatives d'exploitation de CVEs connues de Parse Server avec les télémétries internes

---

### Sources

* [https://www.valtersit.com/vendors/parse-server/](https://www.valtersit.com/vendors/parse-server/)


---

<div id="le-hhs-publie-une-version-mise-a-jour-de-son-security-risk-assessment-tool-sra"></div>

## Le HHS publie une version mise à jour de son Security Risk Assessment Tool (SRA)

### Résumé

Le département américain de la Santé et des Services sociaux (HHS) a publié une version mise à jour de son Security Risk Assessment Tool (SRA), l'outil d'aide à l'évaluation des risques de sécurité destiné aux entités couvertes par la règle de sécurité HIPAA. Les détails de la mise à jour (changements, fonctionnalités) ne sont pas détaillés dans la source collectée.

---

### Analyse opérationnelle

Les équipes sécurité et conformité du secteur santé peuvent s'appuyer sur cette version actualisée pour conduire ou rafraîchir leurs analyses de risques HIPAA : inventaire des actifs traitant des ePHI, identification des menaces et vulnérabilités, évaluation des mesures existantes et documentation des écarts pour les audits régulateurs.

---

### Implications stratégiques

La mise à jour régulière des outils d'évaluation de risques par les régulateurs américains signale l'évolution continue des attentes de conformité pour un secteur santé particulièrement ciblé par les ransomwares et les fuites de données médicales.

---

### Recommandations

* Actualiser l'analyse de risques HIPAA avec la dernière version de l'outil SRA
* Prioriser la remédiation des écarts critiques identifiés (accès, chiffrement, sauvegardes)
* Conserver les preuves d'évaluation et de remédiation pour les audits de conformité

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Télécharger et déployer la dernière version de l'outil SRA (Security Risk Assessment Tool) du HHS pour conduire les évaluations de risques HIPAA
* Planifier des évaluations de risques périodiques couvrant l'inventaire des actifs traitant des données de santé (ePHI), les menaces, les vulnérabilités et les mesures existantes
* Intégrer les résultats de l'outil au registre des risques et au plan de remédiation, avec conservation des preuves pour les audits
* Former les équipes sécurité/conformité à l'utilisation de l'outil et documenter la méthodologie d'évaluation

#### Phase 2 — Détection et analyse

* Prioriser la couverture de détection (journaux, alertes, EDR) sur les actifs ePHI identifiés comme critiques lors de l'évaluation de risques
* Vérifier que les écarts de contrôle relevés par l'outil (accès, chiffrement, journalisation) disposent de contre-mesures de détection associées

#### Phase 3 — Confinement, éradication et récupération

* Remédier en priorité aux écarts critiques identifiés (contrôles d'accès, chiffrement, segmentation, sauvegardes) afin de réduire la surface de propagation en cas d'incident
* Restreindre les accès aux systèmes ePHI conformément aux conclusions de l'évaluation (moindre privilège, MFA)

#### Phase 4 — Activités post-incident

* Réévaluer les risques avec l'outil SRA après tout incident de sécurité et mettre à jour le registre des risques
* Documenter les mesures correctives engagées pour démontrer la conformité auprès des régulateurs (OCR/HHS)

#### Phase 5 — Threat Hunting (proactif)

* Cibler les campagnes de threat hunting sur les actifs ePHI jugés à risque élevé lors de l'évaluation (comptes privilégiés, accès distants, flux d'exfiltration potentiels)

---

### Sources

* [https://databreaches.net/2026/09/13/hhs-releases-updated-security-risk-assessment-tool-2/](https://databreaches.net/2026/09/13/hhs-releases-updated-security-risk-assessment-tool-2/)


---

<div id="inc-ransom-revendique-kyokuto-kaihatsu-kogyo-acces-non-autorise-confirme-chez-sa-filiale-nippon-trex"></div>

## INC Ransom revendique Kyokuto Kaihatsu Kogyo ; accès non autorisé confirmé chez sa filiale Nippon Trex

### Résumé

Le 17 juillet 2026, le groupe ransomware INC Ransom a publié « Kyokuto Kaihatsu Kogyo » (fabricant de véhicules spéciaux : camions à benne, citernes, bennes à ordures ; chiffre d'affaires affiché : 790,3 M$) sur son site de revendication, sans préciser les données volées ni de montant de rançon ; l'entreprise n'a pas confirmé publiquement cette revendication, et Ransomfeed enregistre la victime sans données publiées. Environ sept semaines plus tard, le 8 septembre 2026, un incident de système est survenu chez Nippon Trex, filiale à 100 % de Kyokuto Kaihatsu Kogyo ; dans un second communiqué du 11 septembre, la maison mère a attribué la panne à un accès non autorisé par un tiers. Sont suspendus : les commandes via Internet, le système de réception de commandes de pièces destiné aux concessionnaires et l'envoi/réception d'e-mails avec clients et partenaires ; l'activité se poursuit via des moyens alternatifs (fax). Au 11 septembre, aucune fuite de données personnelles ou clients n'était confirmée, aucun lien officiel n'était établi avec INC Ransom, et aucune date de rétablissement n'était communiquée.

---

### Analyse opérationnelle

L'incident impose une investigation transversale au niveau groupe : bases d'identité communes, VPN/accès distants, comptes d'administration partagés, journaux de messagerie et de cloud, serveurs de fichiers et systèmes métier inter-filiales, comptes de maintenance de prestataires, avec recherche rétroactive de connexions et d'élévations de privilèges suspectes sur plusieurs semaines ou mois. Une revendication sur un site de fuite ne prouve pas une compromission, mais si une intrusion est confirmée dans le groupe, elle justifie d'élargir la période et le périmètre forensique. Surveiller l'infrastructure et les TTP connus d'INC Ransom (analyses HHS/MITRE ATT&CK), bloquer les IOC associés et contrôler les flux des systèmes de commande et de pièces. Maintenir la continuité opérationnelle par canaux alternatifs avec traçabilité.

---

### Implications stratégiques

Le cas illustre le risque de contamination à l'échelle d'un groupe industriel : une revendication visant la maison mère suivie d'un incident chez une filiale à 100 % met en lumière l'exposition liée aux dépendances transverses (identité, réseau, prestataires). La communication initiale en « panne système » avant reconnaissance d'un accès non autorisé souligne les enjeux de transparence et de disclosure pour les groupes cotés japonais. L'absence de confirmation formelle du lien avec INC Ransom maintient l'incertitude pour assureurs, partenaires et clients, tandis que la ciblation d'industriels japonais confirme la pression continue des groupes ransomware à double extorsion sur le pays.

---

### Recommandations

* Cartographier et restreindre les dépendances transverses maison mère/filiales (annuaire, VPN, comptes admin, prestataires)
* Étendre la forensique et la revue de journaux à l'ensemble du groupe sur plusieurs mois en arrière
* Renforcer MFA résistant au phishing et PAM sur les comptes transverses ; centraliser la journalisation
* Surveiller les sites de fuite (INC Ransom, Ransomfeed) pour les entités du groupe et préparer la communication de crise
* Tester les procédures de continuité hors-ligne (commandes, pièces) et la restaurabilité des sauvegardes

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire des actifs et des dépendances transverses entre maison mère et filiales (annuaire commun, VPN, messagerie, cloud, systèmes métier)
* Centraliser les journaux (authentification, VPN, EDR, proxy) dans un SIEM avec rétention suffisante pour des recherches rétroactives de plusieurs mois
* Segmenter le réseau entre entités du groupe et restreindre les comptes d'administration transverses et les comptes de maintenance des prestataires
* Définir un plan de réponse incident à l'échelle du groupe incluant les filiales, les contacts, les seuils de communication et les obligations de disclosure
* Tester régulièrement des sauvegardes hors-ligne restaurables pour les systèmes critiques (commandes en ligne, réception de pièces) et surveiller les sites de fuite des groupes ransomware

#### Phase 2 — Détection et analyse

* Alerter sur les connexions VPN/accès distants anormales (AS ou pays inhabituels, comptes de service, horaires atypiques)
* Détecter les créations de comptes et élévations de privilèges sur les annuaires partagés entre entités du groupe
* Surveiller les tentatives d'accès aux systèmes de commande en ligne et au système de réception de pièces des concessionnaires
* Corréler les alertes EDR (outils de tunneling, suppression de shadow copies, exfiltration) avec les journaux d'authentification

#### Phase 3 — Confinement, éradication et récupération

* Isoler les systèmes compromis et suspendre les accès distants et services exposés non essentiels (commandes Internet, système de pièces, flux e-mail externes)
* Réinitialiser les identifiants transverses du groupe (comptes admin, VPN, comptes de service) et révoquer les sessions actives
* Basculer sur des procédures alternatives (fax, canaux hors-ligne) en maintenant la traçabilité des échanges
* Préserver les preuves (images disque, mémoire, journaux) avant toute remédiation et bloquer l'infrastructure connue du groupe ransomware

#### Phase 4 — Activités post-incident

* Mener une investigation forensique à l'échelle du groupe (maison mère et filiales) pour déterminer le vecteur initial, la durée de présence et les données accédées
* Évaluer la corrélation entre la revendication d'INC Ransom de juillet et l'intrusion de septembre (infrastructures, TTP, horodatages)
* Notifier clients, partenaires et autorités selon les résultats, et honorer les obligations de disclosure financière si l'impact consolidé est avéré
* Documenter les enseignements et renforcer les architectures (segmentation, MFA résistant au phishing, PAM, journalisation centralisée)

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétroactivement (3 à 6 mois) les connexions et élévations de privilèges suspectes sur les bases d'identité communes du groupe
* Hunter sur les comptes de maintenance/prestataires utilisés simultanément dans plusieurs entités
* Rechercher les artefacts et TTP connus d'INC Ransom (notes de rançon, outils, infrastructure publiée dans les analyses HHS/MITRE ATT&CK)
* Analyser les journaux des serveurs de fichiers inter-filiales pour des accès massifs ou hors horaires et vérifier l'absence de publication de données sur les canaux de fuite

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Chiffrement de données pour impact — INC Ransom est un groupe ransomware (chiffrement non confirmé publiquement par la victime) |
| **T1041** | Exfiltration de données — le groupe revendique le vol de données sur son site de fuite (nature et volume non précisés) |

---

### Sources

* [https://rocket-boys.co.jp/security-measures-lab/nippon-trex-security-incident-report/](https://rocket-boys.co.jp/security-measures-lab/nippon-trex-security-incident-report/)


---

<div id="hameconnage-thematique-passkey-vol-de-donnees-microsoft-365-bleepingcomputer"></div>

## Hameçonnage thématique « passkey » : vol de données Microsoft 365 (BleepingComputer)

### Résumé

BleepingComputer rapporte des campagnes d'hameçonnage exploitant la thématique des passkeys (clés d'accès) qui aboutissent au vol de données dans des environnements Microsoft 365. La couverture souligne l'ironie de leurres s'appuyant sur une technologie conçue pour résister au hameçonnage.

---

### Analyse opérationnelle

Pour les équipes SOC : surveiller les enrôlements MFA/passkeys inattendus, les connexions avec anomalies de session (ASN résidentiel, user-agent incohérent), la création de règles de boîte ou de délégations et les consentements d'applications frauduleuses dans Entra ID. Déployer l'authentification résistante au phishing (FIDO2/passkeys) avec Conditional Access et conformité d'appareil, réduire la durée de vie des jetons de session et révoquer les sessions à la moindre suspicion. Bloquer les domaines d'hameçonnage via DNS/proxy/passerelle e-mail et corréler les clics signalés avec les connexions ultérieures.

---

### Implications stratégiques

La campagne confirme la migration des attaques du vol d'identifiants vers le vol de jetons de session et la manipulation des processus d'authentification : même les technologies anti-phishing deviennent des thèmes de leurre. Les organisations fortement dépendantes de Microsoft 365 doivent considérer la messagerie et les fichiers cloud comme exfiltrables même avec MFA activé, ce qui justifie l'investissement dans l'accès conditionnel, les appareils gérés et la détection comportementale d'identité.

---

### Recommandations

* Déployer passkeys/FIDO2 et Conditional Access avec conformité d'appareil ; bloquer l'authentification héritée
* Alerter sur les enrôlements d'authentification inattendus et les connexions à risque (impossible travel, anomalie de jeton)
* Réduire la durée de vie des sessions et révoquer les jetons en cas de suspicion
* Sensibiliser aux leurres liés à l'enrôlement de passkeys et aux fausses pages Microsoft
* Chasser rétroactivement les connexions sans MFA depuis des ASN inhabituels et les règles de boîte malveillantes

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer une authentification résistante au phishing (passkeys/FIDO2, authentification par certificat) et bloquer les méthodes d'authentification héritées
* Activer Conditional Access avec exigence de conformité de l'appareil et restrictions de session (durée de vie des jetons)
* Sensibiliser les utilisateurs aux leurres liés à l'enrôlement de passkeys et aux fausses pages de connexion Microsoft 365
* Centraliser les journaux Entra ID (connexions, consentements, règles de boîte) dans le SIEM et activer la détection de risque d'identité

#### Phase 2 — Détection et analyse

* Alerter sur les connexions M365 avec anomalies de session (ASN résidentiel inédit, user-agent incohérent, géolocalisation impossible)
* Détecter les enrôlements MFA/passkeys inattendus suivis de connexions depuis de nouvelles infrastructures
* Surveiller la création de règles de boîte suspectes, de délégations ou de consentements d'applications à haut privilège
* Détecter les clics vers des pages d'hameçonnage imitant les portails Microsoft (proxy DNS/web, passerelle e-mail)

#### Phase 3 — Confinement, éradication et récupération

* Révoquer les jetons de session et forcer la réauthentification des comptes suspectés
* Réinitialiser les méthodes MFA/passkeys des comptes compromis et bloquer les sessions non conformes
* Isoler les boîtes affectées, supprimer règles et délégations malveillantes, révoquer les consentements d'applications frauduleuses
* Bloquer les domaines d'hameçonnage identifiés au niveau DNS, proxy et passerelle e-mail

#### Phase 4 — Activités post-incident

* Évaluer les données consultées ou exfiltrées (courriels, SharePoint, OneDrive) et notifier selon les obligations applicables
* Analyser le vecteur (e-mail d'origine, page d'hameçonnage) et partager les IOC avec la communauté et les CERT
* Renforcer les stratégies d'accès conditionnel et réduire la durée de vie des jetons de session
* Capitaliser le retour d'expérience : mise à jour des scénarios de sensibilisation et des règles de détection

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétroactivement (30-90 jours) les connexions réussies sans MFA depuis des ASN ou résidentiels inhabituels
* Hunter sur la réutilisation de jetons d'accès/refresh depuis plusieurs localisations (token replay)
* Identifier les utilisateurs ayant visité des domaines récemment enregistrés imitant Microsoft
* Rechercher les boîtes avec transferts cachés, règles de suppression ou délégations créées après compromission

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Hameçonnage — campagnes utilisant des leurres thématiques autour des passkeys (clés d'accès) |
| **T1557** | Adversary-in-the-Middle — interception de sessions d'authentification Microsoft 365, schéma typique du vol de données post-hameçonnage (à confirmer selon l'article complet) |

---

### Sources

* [https://www.bleepingcomputer.com/news/security/passkey-themed-phishing-attacks-lead-to-microsoft-365-data-theft/](https://www.bleepingcomputer.com/news/security/passkey-themed-phishing-attacks-lead-to-microsoft-365-data-theft/)
