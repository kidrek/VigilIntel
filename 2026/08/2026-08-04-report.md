# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [Vulnérabilité XSS stockée dans Emlog CMS <= 2.6.84 (EUVD-2026-52484)](#vulnerabilite-xss-stockee-dans-emlog-cms-2684-euvd-2026-52484)
  * [Injection de commande OS dans Serverless-Devs @serverless-devs/s <= 3.1.11 (EUVD-2026-52481)](#injection-de-commande-os-dans-serverless-devs-serverless-devss-3111-euvd-2026-52481)
  * [Cyberattaque contre le registre des bénéficiaires effectifs du Liechtenstein : 31 000 enregistrements exfiltrés](#cyberattaque-contre-le-registre-des-beneficiaires-effectifs-du-liechtenstein-31-000-enregistrements-exfiltres)
  * [Revente sur le dark web des données de Bank of Baroda préalablement diffusées par TripleX](#revente-sur-le-dark-web-des-donnees-de-bank-of-baroda-prealablement-diffusees-par-triplex)
  * [Fuite de SplitVPN (ex-NotVPN) : 58 millions de logs de connexion et 23,4 millions d'enregistrements utilisateurs exposés malgré la promesse « no-logs »](#fuite-de-splitvpn-ex-notvpn-58-millions-de-logs-de-connexion-et-234-millions-denregistrements-utilisateurs-exposes-malgre-la-promesse-no-logs)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

La vigie CTI du jour est dominée par un volume exceptionnel de vulnérabilités (42 occurrences), signalant une activité de publication et d'exploitation potentiellement intense qui exige une priorisation immédiate des correctifs critiques. Les fuites de données (16 occurrences) constituent le second axe de tension, suggérant soit une recrudescence d'incidents soit une concentration de divulgations publiques nécessitant une veille d'attribution. Le segment réglementaire (5 occurrences) indique une dynamique normative modérée mais suivie, probablement liée à des échéances de conformité ou des consultations publiques. L'absence totale de signaux sur les acteurs de menace et la géopolitique peut traduire une période creuse de publications dédiées ou un décalage de cycle de collecte à surveiller. Le faible volume d'articles de fond (5) limite la contextualisation analytique disponible pour la journée. Recommandation : mobiliser les ressources sur le triage des vulnérabilités critiques et l'évaluation de l'impact des fuites signalées, tout en maintenant une surveillance passive sur les catégories muettes pour détecter tout retard de remontée.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

_Aucun acteur identifié._

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

_Aucun événement géopolitique._

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Council of the European Union - Sanctions Decision | Conseil de l'Union européenne / Haut Représentant de l'UE | 2026-07-13 | Union européenne | Council of the European Union - Sanctions Decision | Le 13 juillet 2026, le Haut Représentant au nom de l'Union européenne a condamné l'utilisation par la Russie d'un large écosystème cybernétique d'acteurs étatiques et non étatiques. Le 16e Centre du FSB a été identifié comme dirigeant des groupes de menaces cybernétiques, notamment Turla, qui ont mené des opérations d'espionnage, de sabotage et de ciblage d'infrastructures contre des États membres de l'UE et des partenaires internationaux. Le Conseil de l'Union européenne a imposé des sanctions à neuf individus et quatre entités liés aux activités cybernétiques russes. | [https://cert.europa.eu/publications/threat-intelligence/cb26-08/](https://cert.europa.eu/publications/threat-intelligence/cb26-08/) |
| Europol - Operation Referral Action Days | Europol | 2026-07-24 | Union européenne (9 agences nationales de répression) | Europol - Operation Referral Action Days | Le 24 juillet 2026, Europol a annoncé que 4 340 URL liées au groupe cybercriminel The Com avaient été signalées pour retrait dans le cadre de l'opération Referral Action Days. Neuf agences nationales de répression ont collaboré pour perturber l'écosystème en ligne de The Com. Cette action s'inscrit dans l'agenda anti-terrorisme ProtectEU de la Commission européenne. | [https://cert.europa.eu/publications/threat-intelligence/cb26-08/](https://cert.europa.eu/publications/threat-intelligence/cb26-08/) |
| US-German law enforcement - Kratos phishing platform takedown | Forces de l'ordre américaines et allemandes | 2026-07-21 | États-Unis, Allemagne | US-German law enforcement - Kratos phishing platform takedown | Le 21 juillet 2026, les forces de l'ordre américaines et allemandes ont collaboré au démantèlement de la plateforme de phishing Kratos Phishing-as-a-Service, qui ciblait les utilisateurs de Microsoft 365 dans plusieurs pays européens, principalement en Espagne. Les détails opérationnels complets n'étaient pas disponibles dans la source. | [https://cert.europa.eu/publications/threat-intelligence/cb26-08/](https://cert.europa.eu/publications/threat-intelligence/cb26-08/) |
| Elastic Security 9.5 - Compliance and Audit Features | Elastic Security (éditeur de solution) | 2026-08-03 | International | Elastic Security 9.5 - Compliance and Audit Features | Elastic Security 9.5 introduit la gestion de l'historique des règles de détection (Detection Rules History Management) en disponibilité générale, avec un journal immuable et en ajout seul qui capture chaque modification de règle (via UI ou API), incluant l'auteur, l'horodatage et le numéro de révision. Cette fonctionnalité fournit aux équipes de conformité une piste d'audit horodatée et défensible pour les normes ISO 27001, SOC 2 et DORA, sans configuration manuelle ni export. Parallèlement, le système de gestion de cas a été reconstruit avec des modèles d'investigation spécifiques, des champs personnalisés (sans limite de nombre ni de modèles), et des analytics de cas interrogeables nativement via trois indices globaux (au lieu de 12 par espace). | [https://www.elastic.co/security-labs/soc-case-management-detection-rule-history](https://www.elastic.co/security-labs/soc-case-management-detection-rule-history) |
| PNLD Data Breach - UK Police National Legal Database | Police Nationale Britannique (UK Police) / PNLD | 2026-08-03 | Royaume-Uni | PNLD Data Breach - UK Police National Legal Database | Le groupe de menaces ExfilSquad a divulgué sur le dark web plus de 135 000 enregistrements issus du portail du Police National Legal Database (PNLD) britannique. La fuite expose des informations de contact sensibles de plus de 100 000 membres du personnel de police, incluant noms, adresses e-mail professionnelles et détails organisationnels. Cette exposition facilite potentiellement la création de messages de phishing ciblant les agents de forces de l'ordre et les responsables gouvernementaux britanniques. | [https://osintsights.com/pnld-breach-reveals-uk-police-and-government-contacts-on-dark-web](https://osintsights.com/pnld-breach-reveals-uk-police-and-government-contacts-on-dark-web)<br>[https://beyondmachines.net/event_details/exfilsquad-leaks-over-100000-uk-police-records-on-dark-web-u-j-v-d-l/gD2P6Ple2L](https://beyondmachines.net/event_details/exfilsquad-leaks-over-100000-uk-police-records-on-dark-web-u-j-v-d-l/gD2P6Ple2L)<br>[https://mastodon.social/@Analyst207/117031365907392671](https://mastodon.social/@Analyst207/117031365907392671)<br>[https://infosec.exchange/@beyondmachines1/117031231060482621](https://infosec.exchange/@beyondmachines1/117031231060482621) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Secteur public / Services municipaux** | Seoul Facilities Corp. | Données personnelles d'environ 4,62 millions d'utilisateurs (détails exacts non spécifiés, probablement noms, coordonnées et informations d'identification) | 4620000 | [https://databreaches.net/2026/08/03/kr-seoul-lawmaker-criticizes-5000-won-compensation-for-4-62-million-person-data-breach/](https://databreaches.net/2026/08/03/kr-seoul-lawmaker-criticizes-5000-won-compensation-for-4-62-million-person-data-breach/) |
| **Gouvernement / Forces de l'ordre** | UK Police National Legal Database (PNLD) et organismes gouvernementaux britanniques | Noms complets, coordonnées, adresses e-mail professionnelles de plus de 100 000 officiers et membres du personnel de police, ainsi que des données du MoD, du Home Office, de la NCA et du CPS | 100000 | [https://databreaches.net/2026/08/03/uk-details-of-100000-police-staff-leaked-on-the-dark-web-after-hack/](https://databreaches.net/2026/08/03/uk-details-of-100000-police-staff-leaked-on-the-dark-web-after-hack/)<br>[https://mastodon.social/@netsecio/117032525291889116](https://mastodon.social/@netsecio/117032525291889116)<br>[https://mastodon.social/@Analyst207/117032423035694539](https://mastodon.social/@Analyst207/117032423035694539) |
| **Santé / Organismes de normalisation** | MIM Fertility (US) et CEN/Cenelec (EU) | Données patients sensibles de MIM Fertility et informations de normalisation de CEN/Cenelec (détails exacts à confirmer) | Inconnu | [https://mastodon.social/@netsecio/117032525720194789](https://mastodon.social/@netsecio/117032525720194789) |
| **Finance / Banque** | River Bank & Trust | Données bancaires potentiellement compromises (détails exacts non confirmés, enquête en cours) | Inconnu | [https://mastodon.social/@netsecio/117032525460057555](https://mastodon.social/@netsecio/117032525460057555) |
| **Gouvernement / Registre de transparence financière** | Registre des bénéficiaires effectifs du Liechtenstein (VwbP) | Informations d'identité et de propriété d'environ 31 000 entités juridiques (bénéficiaires effectifs) | 31000 | [https://infosec.exchange/@beyondmachines1/117032410816456823](https://infosec.exchange/@beyondmachines1/117032410816456823) |
| **VPN / Services de confidentialité** | SplitVPN | 865 000 adresses e-mail uniques d'utilisateurs et 58 millions de logs de connexion (base de données SQL de 17 Go) | 865000 | [https://infosec.exchange/@beyondmachines1/117032174894996865](https://infosec.exchange/@beyondmachines1/117032174894996865) |
| **Sécurité résidentielle / Alarmes** | Brinks Home | Fichiers d'entreprise et potentiellement des données clients (détails à confirmer) | Inconnu | [https://infosec.exchange/@AAKL/117032154115704678](https://infosec.exchange/@AAKL/117032154115704678)<br>[https://www.securityweek.com/brinks-home-discloses-data-breach-as-hackers-leak-files/](https://www.securityweek.com/brinks-home-discloses-data-breach-as-hackers-leak-files/)<br>[https://brinkshome.com/cybersecurity-update](https://brinkshome.com/cybersecurity-update) |
| **Grande distribution / Drive** | Intermarché Drive | Données personnelles des fichiers clients (identité, coordonnées, potentiellement historique de commandes) | 2000000 | [https://mastobot.ping.moi/@cyberveille/117032052743012183](https://mastobot.ping.moi/@cyberveille/117032052743012183)<br>[https://www.leparisien.fr/high-tech/fuite-de-donnees-intermarche-drive-touche-par-une-cyberattaque-2-millions-de-clients-concernes-03-08-2026-XS6ZY2H5JJCTDNLXNVRMJ4RZ6U.php](https://www.leparisien.fr/high-tech/fuite-de-donnees-intermarche-drive-touche-par-une-cyberattaque-2-millions-de-clients-concernes-03-08-2026-XS6ZY2H5JJCTDNLXNVRMJ4RZ6U.php) |
| **Pharmaceutique** | Amgen | Données de santé des patients, informations propriétaires de l'entreprise, données d'entreprise stockées dans des systèmes cloud tiers | Inconnu | [https://mastodon.social/@gtbarry/117031704052538166](https://mastodon.social/@gtbarry/117031704052538166)<br>[https://www.bleepingcomputer.com/news/security/amgen-says-cloud-data-breach-exposed-patient-health-proprietary-info/](https://www.bleepingcomputer.com/news/security/amgen-says-cloud-data-breach-exposed-patient-health-proprietary-info/) |
| **Multi-secteur (santé, gouvernement, municipalités)** | Six organisations (Argentine, Thaïlande, France, Indonésie, Brésil) | PII, dossiers d'assurance médicale, informations sur des retraités du gouvernement, registres municipaux | Inconnu | [https://infosec.exchange/@darkwebsonar/117030538247076861](https://infosec.exchange/@darkwebsonar/117030538247076861)<br>[https://go.darkwebsonar.io/apt-iran-mastodon](https://go.darkwebsonar.io/apt-iran-mastodon) |
| **Services de réservation (relaxation & esthétique)** | EPARK / PeakManager (système de réservation relaxation & esthétique) | Données personnelles des utilisateurs (noms, coordonnées, historiques de réservation, potentiellement informations de paiement) - jusqu'à 33 millions de records | 33000000 | [https://mastodon.social/@securityLab_jp/117030405171535932](https://mastodon.social/@securityLab_jp/117030405171535932)<br>[https://rocket-boys.co.jp/security-measures-lab/epark-peakmanager-unauthorized-access-dark-web-leak-claim/](https://rocket-boys.co.jp/security-measures-lab/epark-peakmanager-unauthorized-access-dark-web-leak-claim/) |
| **Santé / Services cloud médicaux** | CareCloud | Données de santé des patients (PHI), numéros de sécurité sociale, données de cartes de crédit | Inconnu | [https://gbhackers.com/carecloud-data-breach-exposes-patients-data/](https://gbhackers.com/carecloud-data-breach-exposes-patients-data/) |
| **Éducation / K-12** | Sumner County Schools (Tennessee) | Données du district scolaire (étendue exacte non confirmée - potentiellement données étudiants et personnel) | Inconnu | [https://mastodon.social/@threadlinqs/117029549301661172](https://mastodon.social/@threadlinqs/117029549301661172)<br>[https://intel.threadlinqs.com/threat/TL-2026-1824](https://intel.threadlinqs.com/threat/TL-2026-1824) |
| **Industrie / Manufacture** | Marutaka Kogyo (丸高興業) | Informations sur les contacts des partenaires commerciaux, historique des commandes et transactions (au moins 1,5 Go) | 1500000000 | [https://mastodon.social/@securityLab_jp/117028980819777904](https://mastodon.social/@securityLab_jp/117028980819777904)<br>[https://rocket-boys.co.jp/security-measures-lab/marutaka-kogyo-vpn-ransomware-attack-information-leak/](https://rocket-boys.co.jp/security-measures-lab/marutaka-kogyo-vpn-ransomware-attack-information-leak/) |
| **Application de la loi / Gouvernement (Royaume-Uni)** | Police National Legal Database (PNLD) / Ask the Police | Noms complets, organisations, adresses email professionnelles des officiers de police, personnel, professionnels de la justice pénale, partenaires gouvernementaux et clients PNLD. Noms et adresses email des utilisateurs ayant soumis des questions via Ask the Police. Numéros de commande et informations de facturation. | 135000 | [https://thehackernews.com/2026/08/pnld-breach-exposes-uk-police-and.html](https://thehackernews.com/2026/08/pnld-breach-exposes-uk-police-and.html)<br>[https://mastodon.social/@const_data/117031112224549636](https://mastodon.social/@const_data/117031112224549636)<br>[https://www.bleepingcomputer.com/news/security/exfilsquad-hackers-leak-info-of-over-100-000-uk-police-officers-staff/](https://www.bleepingcomputer.com/news/security/exfilsquad-hackers-leak-info-of-over-100-000-uk-police-officers-staff/)<br>[https://www.theregister.com/cyber-crime/2026/08/03/police-national-legal-database-confirms-data-theft-after-dark-web-leak/5282332](https://www.theregister.com/cyber-crime/2026/08/03/police-national-legal-database-confirms-data-theft-after-dark-web-leak/5282332)<br>[https://securityaffairs.com/196525/data-breach/pnld-confirms-data-breach-affecting-uk-police-and-justice-staff.html](https://securityaffairs.com/196525/data-breach/pnld-confirms-data-breach-affecting-uk-police-and-justice-staff.html) |
| **Grande distribution / E-commerce (France)** | Intermarché (Groupement Mousquetaires) — service Drive | Noms et prénoms, numéros de téléphone, adresses postales, dates de naissance, numéros de cartes de fidélité, numéros et montants de commandes en ligne, adresses de facturation. Aucune donnée bancaire, mot de passe, adresse électronique ou montant de cagnotte de fidélité n'est concerné. | 287605 | [https://www.lemonde.fr/pixels/article/2026/08/03/cyberattaque-300-000-clients-d-intermarche-concernes-par-une-fuite-de-donnees_6737677_4408996.html](https://www.lemonde.fr/pixels/article/2026/08/03/cyberattaque-300-000-clients-d-intermarche-concernes-par-une-fuite-de-donnees_6737677_4408996.html)<br>[https://www.20minutes.fr/societe/4237674-20260803-intermarche-enseigne-victime-cyberattaque-pres-300-000-clients-touches-fuite-donnees](https://www.20minutes.fr/societe/4237674-20260803-intermarche-enseigne-victime-cyberattaque-pres-300-000-clients-touches-fuite-donnees)<br>[https://www.leparisien.fr/high-tech/fuite-de-donnees-intermarche-drive-touche-par-une-cyberattaque-2-millions-de-clients-concernes-03-08-2026-XS6ZY2H5JJCTDNLXNVRMJ4RZ6U.php](https://www.leparisien.fr/high-tech/fuite-de-donnees-intermarche-drive-touche-par-une-cyberattaque-2-millions-de-clients-concernes-03-08-2026-XS6ZY2H5JJCTDNLXNVRMJ4RZ6U.php)<br>[https://www.lalibre.be/economie/entreprises-startup/2026/08/03/une-grande-enseigne-francaise-victime-dune-cyberattaque-pres-de-300000-clients-concernes-KNDAPNJOPJFMJHAURDKCQOQMLE/](https://www.lalibre.be/economie/entreprises-startup/2026/08/03/une-grande-enseigne-francaise-victime-dune-cyberattaque-pres-de-300000-clients-concernes-KNDAPNJOPJFMJHAURDKCQOQMLE/) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-48333** | 9.8 | N/A | FALSE | Adobe Campaign Classic | Incorrect Authorization (CWE-863) | Élévation de privilèges permettant à un attaquant non authentifié d'obtenir un accès administrateur sur l'instance ACC, compromettant la confidentialité, l'intégrité et la disponibilité des données. | Theoretical | Mettre à jour Adobe Campaign Classic vers la version 7.4.3 build 9399 ou supérieure. Appliquer les correctifs de sécurité Adobe (APSB26-120) dès leur disponibilité. Réviser et restreindre les privilèges administratifs. | [https://cvefeed.io/vuln/detail/CVE-2026-48333](https://cvefeed.io/vuln/detail/CVE-2026-48333) |
| **CVE-2026-48331** | 10.0 | N/A | FALSE | Adobe Campaign Classic | Server-Side Request Forgery (SSRF) (CWE-918) | Un attaquant non authentifié peut forcer le serveur ACC à effectuer des requêtes vers des ressources internes ou externes, permettant l'accès à des services non exposés, l'exfiltration de données ou l'élévation de privilèges. | Theoretical | Appliquer les correctifs Adobe pour Campaign Classic. Restreindre l'accès réseau externe. Implémenter une validation des entrées pour les URL fournies par l'utilisateur. Mettre à jour vers ACC v7 7.4.3 build 9399 ou supérieure. | [https://cvefeed.io/vuln/detail/CVE-2026-48331](https://cvefeed.io/vuln/detail/CVE-2026-48331) |
| **CVE-2026-48330** | 10.0 | N/A | FALSE | Adobe Campaign Classic | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') (CWE-89) | Exécution de code arbitraire à distance via injection SQL, permettant la compromission complète de la base de données et potentiellement du serveur sous-jacent. | Theoretical | Appliquer les derniers correctifs de sécurité Adobe pour Campaign Classic. Valider la sanitisation des entrées pour les requêtes SQL. Restreindre les privilèges du compte de base de données. Mettre à jour vers ACC v7 7.4.3 build 9399 ou supérieure. | [https://cvefeed.io/vuln/detail/CVE-2026-48330](https://cvefeed.io/vuln/detail/CVE-2026-48330) |
| **CVE-2026-48326** | 9.9 | N/A | FALSE | Adobe Campaign Classic | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') (CWE-89) | Un attaquant authentifié avec de faibles privilèges peut exécuter du code arbitraire via injection SQL, compromettant la base de données et potentiellement le serveur. | Theoretical | Appliquer les derniers correctifs de sécurité Adobe. Mettre à jour Adobe Campaign Classic vers la dernière version. Restreindre l'accès des utilisateurs à faibles privilèges. Surveiller les exécutions de code inattendues. Mettre à jour vers ACC v7 7.4.3 build 9399 ou supérieure. | [https://cvefeed.io/vuln/detail/CVE-2026-48326](https://cvefeed.io/vuln/detail/CVE-2026-48326) |
| **CVE-2026-48323** | 10.0 | N/A | FALSE | Adobe Campaign Classic | Improper Neutralization of Special Elements Used in a Template Engine (CWE-1336) | Exécution de code arbitraire à distance via injection dans le moteur de templates, permettant la compromission complète du serveur ACC. | Theoretical | Mettre à jour Adobe Campaign Classic vers la dernière version. Appliquer les correctifs du fournisseur dès leur disponibilité. Réviser les configurations système. Restreindre les privilèges utilisateur. Mettre à jour vers ACC v7 7.4.3 build 9399 ou supérieure. | [https://cvefeed.io/vuln/detail/CVE-2026-48323](https://cvefeed.io/vuln/detail/CVE-2026-48323) |
| **CVE-2026-48317** | 9.6 | N/A | FALSE | Adobe Campaign Classic | Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') (CWE-95) | Un attaquant authentifié avec de faibles privilèges peut exécuter du code arbitraire via eval injection, compromettant le serveur ACC et potentiellement l'infrastructure environnante. | Theoretical | Appliquer les derniers correctifs de sécurité Adobe. Restreindre l'accès au système affecté. Surveiller les activités suspectes. Mettre à jour vers ACC v7 7.4.3 build 9399 ou supérieure. | [https://cvefeed.io/vuln/detail/CVE-2026-48317](https://cvefeed.io/vuln/detail/CVE-2026-48317) |
| **CVE-2026-62870** | 8.8 | N/A | FALSE | Microsoft 365 Apps for Enterprise, Microsoft Excel 2016, Microsoft Office 2019 | CWE-416: Use After Free | Exécution de code arbitraire à distance via l'ouverture d'un fichier Excel malveillant, permettant la compromission du poste utilisateur. | Theoretical | Se référer au bulletin de sécurité Microsoft (hxxps://msrc[.]microsoft[.]com/update-guide/vulnerability/CVE-2026-62870) pour l'obtention des correctifs. Mettre à jour Microsoft Excel 2016 vers la version 16.0.5561.1001 ou supérieure. Appliquer les mises à jour de sécurité Microsoft pour Office 2019, LTSC 2021, LTSC 2024 et Microsoft 365 Apps. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0961/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0961/)<br>[https://cvefeed.io/vuln/detail/CVE-2026-62870](https://cvefeed.io/vuln/detail/CVE-2026-62870) |
| **CVE-2026-47746** | 8.9 | N/A | FALSE | misskey | CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition | Perte d'intégrité : des activités frauduleuses peuvent être acceptées comme valides au sein de la fédération, permettant potentiellement l'usurpation d'identité et la diffusion de contenu malveillant via les instances fédérées. | Theoretical | Mettre à jour Misskey vers la version 2026.5.4. Vérifier la cohérence du contexte JSON-LD entre la validation de signature et le traitement ultérieur. | [https://cvefeed.io/vuln/detail/CVE-2026-47746](https://cvefeed.io/vuln/detail/CVE-2026-47746)<br>[https://github.com/misskey-dev/misskey/security/advisories/GHSA-38jx-423m-g387](https://github.com/misskey-dev/misskey/security/advisories/GHSA-38jx-423m-g387)<br>[https://github.com/misskey-dev/misskey/releases/tag/2026.5.4](https://github.com/misskey-dev/misskey/releases/tag/2026.5.4) |
| **CVE-2026-46713** | 9.2 | N/A | FALSE | misskey | CWE-347: Improper Verification of Cryptographic Signature | Des attaquants peuvent usurper des activités fédérées, permettant l'envoi de contenu malveillant, l'usurpation d'identité d'utilisateurs ou d'instances, et potentiellement la compromission de la chaîne de confiance de la fédération. | Theoretical | Mettre à jour Misskey vers la version 2026.5.4 ou ultérieure. Appliquer les correctifs de sécurité pour les versions plus anciennes si nécessaire. Valider les processus de signature JSON-LD. | [https://cvefeed.io/vuln/detail/CVE-2026-46713](https://cvefeed.io/vuln/detail/CVE-2026-46713)<br>[https://github.com/misskey-dev/misskey/security/advisories/GHSA-w8x2-gpq6-jxvf](https://github.com/misskey-dev/misskey/security/advisories/GHSA-w8x2-gpq6-jxvf)<br>[https://github.com/misskey-dev/misskey/releases/tag/2026.5.4](https://github.com/misskey-dev/misskey/releases/tag/2026.5.4) |
| **CVE-2026-18733** | 7.5 | N/A | FALSE | strands-agents-tools | CWE-1427 Improper neutralization of input used for LLM prompting | Exécution arbitraire de commandes sur le système hôte de l'agent sans approbation de l'opérateur, pouvant mener à une compromission complète du système, un vol de données ou un déplacement latéral. | Theoretical | Mettre à jour strands-agents-tools vers la version 0.8.0. En attendant, ne pas exposer le shell tool aux agents traitant du contenu non fiable et exécuter les agents dans un environnement isolé à moindres privilèges. | [https://cvefeed.io/vuln/detail/CVE-2026-18733](https://cvefeed.io/vuln/detail/CVE-2026-18733)<br>[https://aws.amazon.com/security/security-bulletins/2026-072-aws/](https://aws.amazon.com/security/security-bulletins/2026-072-aws/)<br>[https://github.com/strands-agents/tools/security/advisories/GHSA-mqvc-p852-wf8x](https://github.com/strands-agents/tools/security/advisories/GHSA-mqvc-p852-wf8x)<br>[https://pypi.org/project/strands-agents-tools/0.8.0/](https://pypi.org/project/strands-agents-tools/0.8.0/) |
| **CVE-2026-59726** | 10.0 | 0.48% | FALSE | ruflo | CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | Exécution de commandes arbitraires, vol de clés API, accès aux conversations privées et altération de la mémoire AI, pouvant compromettre l'intégrité et la confidentialité de l'ensemble de la plateforme. | Theoretical | Mettre à jour Ruflo vers la version 3.16.3. Restreindre l'accès au MCP bridge et exiger une authentification. | [https://research.checkpoint.com/2026/3rd-august-threat-intelligence-report/](https://research.checkpoint.com/2026/3rd-august-threat-intelligence-report/) |
| **CVE-2026-20316** | 5.3 | 0.79% | TRUE | Cisco Secure Firewall Management Center (FMC) | CWE-259 Use of Hard-coded Password | Accès non autorisé à des informations sensibles des systèmes de gestion de pare-feu, potentiellement utilisable pour des attaques ultérieures ou un contournement des politiques de sécurité. | Active | Appliquer les hotfixes Cisco immédiatement. Désactiver ou restreindre le compte intégré à faibles privilèges. Surveiller les accès suspects. | [https://research.checkpoint.com/2026/3rd-august-threat-intelligence-report/](https://research.checkpoint.com/2026/3rd-august-threat-intelligence-report/) |
| **CVE-2026-59309** | 9.8 | 0.74% | FALSE | Cloud Foundation, vSphere Foundation, vCenter | CWE-303 Incorrect implementation of authentication algorithm | Compromission potentielle de l'infrastructure virtuelle complète, avec contournement d'authentification permettant un accès non autorisé et une exécution de code arbitraire. | Theoretical | Appliquer immédiatement les correctifs publiés par Broadcom. Restreindre l'accès réseau aux interfaces de gestion. | [https://research.checkpoint.com/2026/3rd-august-threat-intelligence-report/](https://research.checkpoint.com/2026/3rd-august-threat-intelligence-report/) |
| **CVE-2026-59310** | 9.8 | 1.14% | FALSE | Cloud Foundation, vSphere Foundation, vCenter | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Évasion de machine virtuelle permettant à un attaquant de compromettre l'hyperviseur et potentiellement l'ensemble de l'infrastructure virtualisée. | Theoretical | Appliquer immédiatement les correctifs publiés par Broadcom. Restreindre l'accès réseau aux interfaces de gestion et isoler les environnements virtuels. | [https://research.checkpoint.com/2026/3rd-august-threat-intelligence-report/](https://research.checkpoint.com/2026/3rd-august-threat-intelligence-report/) |
| **CVE-2026-63077** | 9.8 | 0.65% | FALSE | TeamCity | CWE-502 | Compromission complète du serveur TeamCity et des environnements de build connectés, pouvant mener à des attaques sur la chaîne d'approvisionnement logicielle (supply chain attacks). | Theoretical | Mettre à jour TeamCity On-Premises vers la version 2025.11.7 ou 2026.1.3. Restreindre l'accès réseau à l'interface TeamCity. | [https://research.checkpoint.com/2026/3rd-august-threat-intelligence-report/](https://research.checkpoint.com/2026/3rd-august-threat-intelligence-report/) |
| **CVE-2026-66066** | 9.5 | 1.70% | FALSE | rails | CWE-1188: Insecure Default Initialization of Resource | Divulgation de fichiers sensibles (variables d'environnement, credentials, secret_key_base) pouvant mener à une exécution de code à distance, un déplacement latéral vers des systèmes externes, et une compromission complète de l'application. | Theoretical | Appliquer immédiatement les mises à jour de sécurité Ruby on Rails. Restreindre les uploads d'images aux utilisateurs authentifiés. Bloquer les opérations libvips non sûres pour les fichiers non fiables. | [https://research.checkpoint.com/2026/3rd-august-threat-intelligence-report/](https://research.checkpoint.com/2026/3rd-august-threat-intelligence-report/)<br>[https://securityaffairs.com/196486/security/ruby-on-rails-patches-critical-active-storage-vulnerability-affecting-image-processing.html](https://securityaffairs.com/196486/security/ruby-on-rails-patches-critical-active-storage-vulnerability-affecting-image-processing.html) |
| **CVE-2026-8793** | 6.9 | 0.68% | FALSE | PaperCut NG/MF | CWE-307 Improper restriction of excessive authentication attempts | Compromission potentielle de la confidentialité des données et contournement des politiques de sécurité en place sur les serveurs d'impression PaperCut. | Theoretical | Se référer au bulletin de sécurité PaperCut papercut-ng-mf-security-bulletin-3-aug-2026 et appliquer les correctifs. Mettre à jour vers la version 26.0.3 ou ultérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0959/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0959/)<br>[https://www.papercut.com/kb/Main/papercut-ng-mf-security-bulletin-3-aug-2026/](https://www.papercut.com/kb/Main/papercut-ng-mf-security-bulletin-3-aug-2026/) |
| **CVE-2026-8794** | 6.9 | 0.68% | FALSE | PaperCut NG/MF | CWE-208 Observable timing discrepancy | Compromission potentielle de la confidentialité des données et contournement des politiques de sécurité en place sur les serveurs d'impression PaperCut. | Theoretical | Se référer au bulletin de sécurité PaperCut papercut-ng-mf-security-bulletin-3-aug-2026 et appliquer les correctifs. Mettre à jour vers la version 26.0.3 ou ultérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0959/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0959/)<br>[https://www.papercut.com/kb/Main/papercut-ng-mf-security-bulletin-3-aug-2026/](https://www.papercut.com/kb/Main/papercut-ng-mf-security-bulletin-3-aug-2026/) |
| **CVE-2026-18684** | 9.3 | N/A | FALSE | GL-MT3000 | CWE-77 Command Injection | Compromission complète du routeur à distance, permettant l'exécution de commandes arbitraires, l'interception de trafic, la persistence, et potentiellement le pivot vers le réseau interne. | Active | Mettre à jour le firmware du routeur vers une version corrigée dès sa disponibilité. Restreindre l'accès à l'interface d'administration aux réseaux de confiance. Désactiver l'accès distant si possible. Surveiller les journaux d'accès pour détecter toute tentative d'exploitation. | [https://cvefeed.io/vuln/detail/CVE-2026-18684](https://cvefeed.io/vuln/detail/CVE-2026-18684) |
| **CVE-2026-18667** | 9.3 | N/A | FALSE | Sensor Proxy | CWE-94 | Exécution de code arbitraire avec privilèges élevés à distance, compromission potentielle de l'infrastructure de monitoring Tenable, accès aux données de vulnérabilités collectées, pivot vers le réseau interne. | Theoretical | Mettre à jour Tenable Sensor Proxy vers la version 1.4.2 ou ultérieure. Ne jamais connecter le sensor à des hôtes non fiables. Vérifier toutes les connexions au Sensor Proxy. Appliquer les correctifs du vendeur dès leur disponibilité. | [https://cvefeed.io/vuln/detail/CVE-2026-18667](https://cvefeed.io/vuln/detail/CVE-2026-18667)<br>[https://www.tenable.com/security/tns-2026-21](https://www.tenable.com/security/tns-2026-21) |
| **CVE-2026-66318** | 8.1 | N/A | FALSE | Microsoft Edge (Chromium-based) | CWE-346: Origin Validation Error | Divulgation potentielle d'informations sensibles à un attaquant via le navigateur Microsoft Edge. | None | Appliquer les mises à jour de sécurité Microsoft Edge dès leur disponibilité. Surveiller les bulletins de sécurité Microsoft pour les détails et correctifs. | [https://cvefeed.io/vuln/detail/CVE-2026-66318](https://cvefeed.io/vuln/detail/CVE-2026-66318) |
| **CVE-2026-69249** | 8.7 | N/A | FALSE | cryptography | CWE-400: Uncontrolled Resource Consumption | Déni de service par épuisement des ressources CPU lors de la validation de chaînes de certificats malveillantes. Peut affecter tout service utilisant python-cryptography pour valider des certificats fournis par l'attaquant. | Theoretical | Mettre à jour python-cryptography vers la version 49.0.0 ou ultérieure. Réviser la logique de validation des certificats pour gérer les duplicatas. Limiter le taux de validation et surveiller les temps de réponse. | [https://cvefeed.io/vuln/detail/CVE-2026-69249](https://cvefeed.io/vuln/detail/CVE-2026-69249)<br>[https://github.com/pyca/cryptography/commit/4a12cf49675a184e47f912b00b04f3a629283582](https://github.com/pyca/cryptography/commit/4a12cf49675a184e47f912b00b04f3a629283582)<br>[https://github.com/pyca/cryptography/pull/14960](https://github.com/pyca/cryptography/pull/14960)<br>[https://github.com/pyca/cryptography/security/advisories/GHSA-jwv3-5hgf-82ww](https://github.com/pyca/cryptography/security/advisories/GHSA-jwv3-5hgf-82ww) |
| **CVE-2026-69247** | 8.2 | N/A | FALSE | cryptography | CWE-208: Observable Timing Discrepancy | Récupération potentielle de la clé de chiffrement de contenu via des requêtes adaptatives répétées, permettant le déchiffrement de communications S/MIME ou de données chiffrées. Impact critique sur la confidentialité. | Theoretical | Mettre à jour python-cryptography vers la version 50.0.0 ou ultérieure. Restreindre le déchiffrement d'EnvelopedData non fiables. Implémenter une gestion sécurisée des erreurs de déchiffrement (erreurs uniformes). Valider la logique de déchiffrement pour le padding et la longueur de clé. | [https://cvefeed.io/vuln/detail/CVE-2026-69247](https://cvefeed.io/vuln/detail/CVE-2026-69247)<br>[https://github.com/pyca/cryptography/commit/53fccd93413a8d7f07d6d8999681f27b75cffa3f](https://github.com/pyca/cryptography/commit/53fccd93413a8d7f07d6d8999681f27b75cffa3f)<br>[https://github.com/pyca/cryptography/pull/15369](https://github.com/pyca/cryptography/pull/15369)<br>[https://github.com/pyca/cryptography/security/advisories/GHSA-g6cj-pr64-35w5](https://github.com/pyca/cryptography/security/advisories/GHSA-g6cj-pr64-35w5) |
| **CVE-2026-10849** | 8.2 | N/A | FALSE | zephyr | CWE-122 bounds | Corruption du heap entraînant un déni de service (crash sur allocation/libération ultérieure). Possibilité limitée de corruption supplémentaire dépendante de l'allocateur. Attaquable à distance par un serveur de mise à jour compromis ou via MITM. | Theoretical | Appliquer le correctif qui dimensionne le buffer à la longueur du corps plus un byte et utilise memcpy. Sécuriser les serveurs hawkBit (authentification, TLS obligatoire). Mettre à jour le firmware Zephyr avec la version corrigée. | [https://cvefeed.io/vuln/detail/CVE-2026-10849](https://cvefeed.io/vuln/detail/CVE-2026-10849) |
| **CVE-2026-69240** | 9.8 | N/A | FALSE | sequelize | CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') | Exécution de requêtes SQL arbitraires sur la base de données Oracle, permettant l'exfiltration, la modification ou la suppression de données, et potentiellement l'exécution de commandes système via le SGBD. Compromission complète de la base de données. | Theoretical | Mettre à jour Sequelize vers la version 6.37.4 ou ultérieure. Appliquer les correctifs de sécurité. Utiliser des requêtes paramétrées. Mettre en place un WAF pour détecter et bloquer les tentatives d'injection via TO_TIMESTAMP/TO_DATE. | [https://cvefeed.io/vuln/detail/CVE-2026-69240](https://cvefeed.io/vuln/detail/CVE-2026-69240)<br>[https://github.com/sequelize/sequelize/commit/5deadd2410ae9136a21fb652db206d27bb715f26](https://github.com/sequelize/sequelize/commit/5deadd2410ae9136a21fb652db206d27bb715f26)<br>[https://github.com/sequelize/sequelize/releases/tag/v6.37.4](https://github.com/sequelize/sequelize/releases/tag/v6.37.4)<br>[https://github.com/sequelize/sequelize/security/advisories/GHSA-v8fg-2rw7-q452](https://github.com/sequelize/sequelize/security/advisories/GHSA-v8fg-2rw7-q452) |
| **CVE-2026-66065** | 8.4 | N/A | FALSE | ouroboros | CWE-15: External Control of System or Configuration Setting | Exécution de commandes arbitraires sur la machine du développeur via un dépôt malveillant contenant un fichier .env. Contournement des politiques de sécurité et d'approbation de l'agent IA. Compromission potentielle de la machine de développement et pivot vers l'infrastructure interne. | Theoretical | Mettre à jour Ouroboros vers la version 0.42.1 ou ultérieure. Réviser et compléter la denylist des variables d'environnement. Valider les configurations backend et plugin. Restreindre l'accès aux fichiers de configuration sensibles. Ne jamais cloner et importer des dépôts non fiables sans révision préalable des fichiers .env. | [https://cvefeed.io/vuln/detail/CVE-2026-66065](https://cvefeed.io/vuln/detail/CVE-2026-66065)<br>[https://github.com/Q00/ouroboros/releases/tag/v0.42.1](https://github.com/Q00/ouroboros/releases/tag/v0.42.1)<br>[https://github.com/Q00/ouroboros/security/advisories/GHSA-jv2h-4p9v-wf5w](https://github.com/Q00/ouroboros/security/advisories/GHSA-jv2h-4p9v-wf5w) |
| **CVE-2026-48113** | 8.5 | N/A | FALSE | chisel | CWE-863: Incorrect Authorization | Un attaquant authentifié peut tunneliser du trafic vers des destinations arbitraires accessibles depuis le serveur Chisel, contournant les politiques de sécurité définies par les ACL. Cela peut permettre l'accès à des services internes non exposés, le mouvement latéral et l'exfiltration de données. | Theoretical | Mettre à jour Chisel vers la version 1.11.5 ou ultérieure. Réviser et renforcer les configurations ACL. Appliquer le correctif disponible via le commit GitHub 44310b65667a97901874ffdf4815b3732c22eaa3. | [https://cvefeed.io/vuln/detail/CVE-2026-48113](https://cvefeed.io/vuln/detail/CVE-2026-48113)<br>[https://github.com/jpillora/chisel/security/advisories/GHSA-24fp-5v3p-rvpw](https://github.com/jpillora/chisel/security/advisories/GHSA-24fp-5v3p-rvpw)<br>[https://github.com/jpillora/chisel/commit/44310b65667a97901874ffdf4815b3732c22eaa3](https://github.com/jpillora/chisel/commit/44310b65667a97901874ffdf4815b3732c22eaa3) |
| **CVE-2026-48063** | 9.3 | N/A | FALSE | Baileys, @whiskeysockets/baileys | CWE-290: Authentication Bypass by Spoofing | Un attaquant peut usurper l'identité de messages, corrompre l'état de synchronisation de l'application et injecter de faux historiques de messages. Cela peut conduire à de la désinformation, de l'ingénierie sociale et à la compromission de l'intégrité des communications. | Theoretical | Mettre à jour Baileys vers la version 6.7.22 ou 7.0.0-rc12 ou ultérieure. Filtrer et valider les payloads protocolMessage reçus. | [https://cvefeed.io/vuln/detail/CVE-2026-48063](https://cvefeed.io/vuln/detail/CVE-2026-48063) |
| **CVE-2026-15409** | 10.0 | 78.44% | TRUE | SMA1000 | CWE-918: Server-Side Request Forgery (SSRF) | Compromission complète des appliances VPN, extraction de credentials à haute valeur, bases de données de sessions actives, configurations TOTP/MFA, accès persistant à long terme, mouvement latéral vers le réseau interne, déploiement de ransomware INC. | Active | Patcher immédiatement les appliances SMA 1000 vers la dernière version. Effectuer une chasse aux menaces complète, rotation des credentials et vérification d'intégrité. Identifier les adresses source externes ayant interagi avec /wsproxy. | [https://thehackernews.com/2026/08/inc-ransomware-emerges-as-dominant.html](https://thehackernews.com/2026/08/inc-ransomware-emerges-as-dominant.html) |
| **CVE-2026-15410** | 7.2 | 76.35% | TRUE | SMA1000 | CWE-94: Improper Control of Generation of Code ('Code Injection') | Compromission complète des appliances VPN, extraction de credentials, sessions actives et configurations MFA/TOTP, accès persistant, mouvement latéral, déploiement de ransomware INC avec 885 victimes revendiquées. | Active | Patcher immédiatement les appliances SMA 1000 vers la dernière version. Effectuer une chasse aux menaces, rotation des credentials et vérification d'intégrité. Identifier les adresses source externes ayant interagi avec /wsproxy. | [https://thehackernews.com/2026/08/inc-ransomware-emerges-as-dominant.html](https://thehackernews.com/2026/08/inc-ransomware-emerges-as-dominant.html) |
| **CVE-2026-51302** | 10.0 | N/A | FALSE | SQLite (serveless SQL database engine) | Fausse vulnérabilité (CVE hallucinée par IA) | Aucun impact réel — la vulnérabilité n'existe pas. Cependant, l'incident souligne le risque de pollution de la base CVE par des contenus générés par IA, pouvant entraîner des efforts de patching inutiles et une perte de confiance dans le système CVE. | None | Ne pas faire confiance aveuglément aux numéros CVE émis. Vérifier l'advisory, le proof-of-concept et la source avant de prioriser ou patcher. Le CVE a été retiré. | [https://www.security.nl/posting/947626/%27Kritiek+beveiligingslek%27+in+SQLite+blijkt+door+AI+gehallucineerd+te+zijn?channel=rss](https://www.security.nl/posting/947626/%27Kritiek+beveiligingslek%27+in+SQLite+blijkt+door+AI+gehallucineerd+te+zijn?channel=rss) |
| **CVE-2026-31431** | 7.8 | 94.55% | TRUE | Linux | Escalade de privilèges locale (LPE - Local Privilege Escalation) | Escalade de privilèges locale permettant à un attaquant d'obtenir des privilèges root sur des systèmes Linux vulnérables, facilitant le mouvement latéral, la persistance et l'exfiltration de données. | Active | Appliquer les correctifs du noyau Linux dès leur disponibilité. Surveiller les publications de PoC et accélérer les cycles de patching. Mettre en place une détection comportementale des tentatives d'escalade de privilèges. | [https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-threat-hunting-report/](https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-threat-hunting-report/) |
| **CVE-2026-17583** | 8.2 | N/A | FALSE | Applied Biosystems : 3500/3500xL (≤4.0.2), 3730/3730xL (≤5.0.2), SeqStudio Genetic Analyzer (≤1.2.5), SeqStudio Flex (≤1.2.0), GeneMapper ID-X (≤v1.7.3). Produits en fin de vie non patchés : 3130 (≤4.1), ABI PRISM 3100/3100-Avant (≤2.0), ABI PRISM 310 (≤3.1) | Altération de données avant chargement dans le logiciel d'analyse (CWE non précisé) | Altération quasi indétectable de fichiers de données ADN forensiques, pouvant compromettre l'intégrité de résultats d'identification humaine utilisés en justice. Les produits en fin de vie restent vulnérables sans correctif disponible. | None | Installer les mises à jour sur les produits supportés. Pour les produits en fin de vie ou incapables d'appliquer les mises à jour : maintenir la chaîne de custody, stocker les fichiers sur des supports chiffrés et protégés par mot de passe, restreindre l'accès, appliquer le moindre privilège et limiter la connectivité Internet aux sources de confiance. | [https://thehackernews.com/2026/08/thermo-fisher-patches-flaw-that-could.html](https://thehackernews.com/2026/08/thermo-fisher-patches-flaw-that-could.html) |
| **CVE-2026-18556** | 8.2 | 0.27% | FALSE | N-central | CWE-288 Authentication bypass using an alternate path or channel | Prise de contrôle administrative à distance des serveurs N-central sans authentification, accès aux endpoints gérés via Take Control, persistance via tunnels Cloudflare survivant au redémarrage et à la révocation des accès via N-central. | Active | Mettre à jour N-central vers la build 2026.3.1.7 ou ultérieure. La mise à jour vers 2026.3 ou 2026.2 n'est plus suffisante. Chasser et supprimer les tunnels Cloudflare malveillants des endpoints gérés. | [https://thehackernews.com/2026/08/n-able-says-attackers-take-over-n.html](https://thehackernews.com/2026/08/n-able-says-attackers-take-over-n.html) |
| **CVE-2026-18577** | 8.2 | 1.48% | TRUE | N-central | CWE-288 Authentication bypass using an alternate path or channel | Prise de contrôle administrative à distance des serveurs N-central, accès aux endpoints gérés via Take Control, persistance via tunnels Cloudflare survivant au redémarrage et à la révocation des accès via N-central. Le correctif initial (2026.2/2026.3) s'est révélé insuffisant. | Active | Mettre à jour N-central vers la build 2026.3.1.7 ou ultérieure. La mise à jour vers 2026.3 n'est plus suffisante. Chasser et supprimer les tunnels Cloudflare malveillants des endpoints gérés. Rechercher svchost[.]exe dans les dossiers Documents et les services nommés Cloudflared. | [https://thehackernews.com/2026/08/n-able-says-attackers-take-over-n.html](https://thehackernews.com/2026/08/n-able-says-attackers-take-over-n.html) |
| **CVE-2026-44827** | 8.8 | 0.56% | FALSE | diffusers | CWE-94: Improper Control of Generation of Code ('Code Injection') | Exécution de code arbitraire à distance sur toute machine chargeant un modèle malveillant depuis Hugging Face Hub. Compromission potentielle des pipelines de production, des systèmes CI/CD et des images de conteneurs intégrant Diffusers. La bibliothèque ayant été téléchargée plus de 8,1 millions de fois en juillet 2026, la surface d'attaque est considérable. | Theoretical | Mettre à jour Diffusers vers la version 0.38.0 ou supérieure. Ne jamais charger de modèles provenant de dépôts non vérifiés. Maintenir trust_remote_code=False. Mettre en place une allowlist de dépôts Hugging Face approuvés et un processus de revue des modèles avant chargement. | [https://thehackernews.com/2026/08/hugging-face-diffusers-flaws-could-let.html](https://thehackernews.com/2026/08/hugging-face-diffusers-flaws-could-let.html) |
| **CVE-2026-45804** | 7.5 | 0.27% | FALSE | diffusers | CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition | Exécution de code arbitraire à distance via manipulation de configuration entre deux requêtes de téléchargement. Compromission des environnements de production, CI/CD et conteneurs utilisant Diffusers pour charger des modèles depuis Hugging Face Hub. | Theoretical | Mettre à jour Diffusers vers la version 0.38.0 ou supérieure. Maintenir trust_remote_code=False. N'utiliser que des dépôts de modèles vérifiés et approuvés. Mettre en place une allowlist de dépôts Hugging Face. | [https://thehackernews.com/2026/08/hugging-face-diffusers-flaws-could-let.html](https://thehackernews.com/2026/08/hugging-face-diffusers-flaws-could-let.html) |
| **CVE-2026-44513** | 8.8 | 0.85% | FALSE | diffusers | CWE-94: Improper Control of Generation of Code ('Code Injection') | Exécution de code arbitraire à distance sur toute machine chargeant un modèle malveillant. Compromission des pipelines de production, des systèmes CI/CD et des conteneurs intégrant Diffusers. | Theoretical | Mettre à jour Diffusers vers la version 0.38.0 ou supérieure. Maintenir trust_remote_code=False. N'utiliser que des dépôts de modèles vérifiés et approuvés via une allowlist. | [https://thehackernews.com/2026/08/hugging-face-diffusers-flaws-could-let.html](https://thehackernews.com/2026/08/hugging-face-diffusers-flaws-could-let.html) |
| **CVE-2026-18655** | 7.1 | N/A | FALSE | amazon-mq-mcp-server | CWE-923: Improper Restriction of Communication Channel to Intended Endpoints | Divulgation de credentials de broker Amazon MQ et de tokens OAuth à un acteur malveillant, permettant un accès non autorisé aux infrastructures de messagerie. Un attaquant distant non authentifié peut exploiter cette vulnérabilité via prompt injection dans le contexte du client MCP. | Theoretical | Mettre à jour awslabs.amazon-mq-mcp-server vers la version 2.0.24 ou supérieure. Désactiver l'auto-approve pour les outils rabbitmq_broker_initialize_connection et rabbitmq_broker_initialize_connection_with_oauth afin de forcer une inspection visuelle du broker_hostname. Pivoter les credentials broker potentiellement compromis. Référence GHSA : GHSA-xwj6-8x5h-hjp6. | [https://aws.amazon.com/security/security-bulletins/rss/2026-070-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-070-aws/) |
| **CVE-2026-18654** | 6.9 | N/A | FALSE | aws-cli | CWE-322 Key exchange without entity authentication | Interception de sessions SSH et de transferts de fichiers vers les clusters AWS EMR par un attaquant en position de man-in-the-middle. Compromission potentielle de credentials, de données transférées et d'accès aux clusters EMR. | Theoretical | Mettre à jour AWS CLI v1 vers la version 1.45.28+ et AWS CLI v2 vers la version 2.35.3+. Aucun workaround n'est disponible car l'option SSH insecure était codée en dur. Référence GHSA : GHSA-hqvf-45jj-mccq. | [https://aws.amazon.com/security/security-bulletins/rss/2026-071-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-071-aws/) |
| **CVE-2026-28323** | 9.8 | 0.64% | FALSE | Web Help Desk | CWE-287 Improper Authentication | Contournement de l'authentification permettant à un attaquant non authentifié d'accéder au système SolarWinds Web Help Desk. Accès potentiel aux opérations de support IT, de gestion d'actifs et de base de connaissances. Nécessite SAML 2.0 activé pour exploitation. | None | Appliquer les mises à jour fournies par SolarWinds immédiatement (version 2026.2.1+). Si SAML 2.0 n'est pas nécessaire, désactiver cette méthode d'authentification. Effectuer des scans de vulnérabilités automatisés sur les assets exposés. Réaliser des tests de pénétration applicative. | [https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-solarwinds-web-help-desk-could-allow-for-authentication-bypass_2026-077](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-solarwinds-web-help-desk-could-allow-for-authentication-bypass_2026-077) |
| **CVE-2026-28299** | 8.2 | 0.43% | FALSE | Web Help Desk | CWE-770 Allocation of Resources Without Limits or Throttling | Crash du serveur SolarWinds Web Help Desk causant une indisponibilité du service de support IT, de gestion d'actifs et de base de connaissances. Impact opérationnel potentiel sur les équipes IT dépendant de cet outil. | None | Appliquer les mises à jour fournies par SolarWinds (version 2026.2.1+). Mettre en place un rate limiting et une surveillance de la consommation mémoire. Effectuer des scans de vulnérabilités réguliers. | [https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-solarwinds-web-help-desk-could-allow-for-authentication-bypass_2026-077](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-solarwinds-web-help-desk-could-allow-for-authentication-bypass_2026-077) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="vulnerabilite-xss-stockee-dans-emlog-cms-2684-euvd-2026-52484"></div>

## Vulnérabilité XSS stockée dans Emlog CMS <= 2.6.84 (EUVD-2026-52484)

### Résumé

La base de données européenne des vulnérabilités (EUVD) a publié l'avis EUVD-2026-52484 concernant une vulnérabilité de cross-site scripting (XSS) stockée dans Emlog CMS versions 2.6.14 et antérieures. La vulnérabilité se situe dans le module de publication d'articles (/admin/article.php). Un attaquant distant authentifié peut injecter du code JavaScript arbitraire via le contenu de l'article. Lorsqu'un administrateur consulte ou prévisualise l'article soumis dans le backend, le code malveillant s'exécute dans son navigateur.

---

### Analyse opérationnelle

Cette vulnérabilité XSS stockée nécessite une authentification préalable, ce qui réduit la surface d'attaque aux utilisateurs disposant d'un compte sur le CMS. Cependant, l'impact est élevé car l'exécution du code se produit dans le contexte de l'administrateur, permettant potentiellement le vol de session, la manipulation de contenu ou l'escalade de privilèges. Les équipes SOC doivent surveiller les soumissions d'articles contenant des payloads JavaScript, déployer des règles WAF sur les endpoints d'administration et s'assurer que toutes les instances Emlog CMS sont mises à jour au-delà de la version 2.6.14.

---

### Implications stratégiques

Cette vulnérabilité illustre les risques liés aux CMS open-source peu audités. Les organisations utilisant Emlog CMS pour des blogs ou sites publics doivent évaluer leur exposition. Le vecteur d'attaque (utilisateur authentifié → administrateur) souligne l'importance de contrôler les comptes utilisateurs ayant accès à la publication de contenu, notamment dans les contextes multi-contributeurs.

---

### Recommandations

* Mettre à jour Emlog CMS vers la dernière version disponible
* Restreindre les comptes pouvant publier des articles
* Déployer une solution WAF avec règles de filtrage XSS sur les endpoints d'administration
* Appliquer une sanitisation stricte des entrées côté serveur sur le champ de contenu d'article

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier toutes les instances Emlog CMS déployées et leur version
* Vérifier si la version est <= 2.6.14 (vulnérable)
* S'assurer que les administrateurs sont formés à la reconnaissance de vecteurs XSS

#### Phase 2 — Détection et analyse

* Surveiller les requêtes vers /admin/article[.]php pour détecter des payloads JavaScript anormaux dans le contenu d'articles
* Activer la journalisation des soumissions d'articles et inspecter les champs de contenu pour des balises <script> ou des handlers d'événements
* Déployer des règles WAF pour filtrer les payloads XSS courants sur les endpoints d'administration

#### Phase 3 — Confinement, éradication et récupération

* Mettre à jour Emlog CMS vers une version > 2.6.14 si disponible
* Restreindre l'accès au module de publication d'articles aux utilisateurs authentifiés de confiance
* Appliquer un filtrage/sanitisation des entrées côté serveur sur le champ de contenu d'article

#### Phase 4 — Activités post-incident

* Auditer les articles publiés récents pour identifier d'éventuels payloads XSS déjà injectés
* Vérifier les sessions administrateur pour détecter des activités anormales liées à un vol de session potentiel
* Documenter l'incident et mettre à jour les politiques de validation des contenus utilisateur

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs historiques des patterns d'injection JavaScript dans les soumissions d'articles
* Corréler les accès administrateur avec des soumissions d'articles suspectes pour identifier d'éventuelles exploitations passées
* Surveiller les comptes utilisateurs authentifiés ayant soumis du contenu anormal pour identifier un acteur malveillant persistant

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1059.007** | JavaScript - Injection de code JavaScript via XSS stocké |

---

### Sources

* [https://mastodon.social/@EUVD_Bot/117033827242932541](https://mastodon.social/@EUVD_Bot/117033827242932541)
* [https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-52484](https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-52484)


---

<div id="injection-de-commande-os-dans-serverless-devs-serverless-devss-3111-euvd-2026-52481"></div>

## Injection de commande OS dans Serverless-Devs @serverless-devs/s <= 3.1.11 (EUVD-2026-52481)

### Résumé

L'avis EUVD-2026-52481 décrit une vulnérabilité d'injection de commande OS dans le package npm Serverless-Devs @serverless-devs/s versions 3.1.11 et antérieures. La commande 's init' passe des entrées utilisateur non sanitizées à child_process.spawn() avec l'option shell: true. Une URL se terminant par '.git' contourne la seule vérification d'entrée implémentée, permettant l'injection de commandes OS lorsqu'un utilisateur exécute 's init' avec un argument contrôlé par l'attaquant.

---

### Analyse opérationnelle

Cette vulnérabilité cible les chaînes d'outils DevOps et peut être exploitée via des arguments de ligne de commande. Le vecteur d'attaque implique qu'un utilisateur de confiance exécute la commande 's init' avec un argument malveillant, ce qui peut se produire via du phishing, de la compromission de supply chain ou des instructions trompeuses. Les équipes SOC doivent surveiller l'exécution de 's init' dans les pipelines CI/CD, détecter les processus enfants anormaux et s'assurer que les versions de @serverless-devs/s sont mises à jour. La surface d'attaque inclut tous les environnements de développement utilisant cet outil.

---

### Implications stratégiques

Cette vulnérabilité souligne les risques de sécurité dans les outils de développement serverless et la chaîne d'approvisionnement npm. Les organisations adoptant des approches serverless doivent intégrer des audits de sécurité des outils CLI dans leurs processus DevSecOps. L'exploitation pourrait compromettre des environnements de développement, exposer des secrets et servir de point d'entrée pour des attaques plus larges sur l'infrastructure cloud.

---

### Recommandations

* Mettre à jour @serverless-devs/s vers une version > 3.1.11
* Restreindre l'utilisation de 's init' à des arguments provenant de sources de confiance uniquement
* Surveiller les exécutions de 's init' dans les pipelines CI/CD
* Intégrer des scans de vulnérabilités des dépendances npm dans le cycle de développement

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les environnements de développement utilisant Serverless-Devs @serverless-devs/s
* Vérifier si la version installée est <= 3.1.11 (vulnérable)
* Sensibiliser les équipes DevOps aux risques d'injection de commande via les outils CLI

#### Phase 2 — Détection et analyse

* Surveiller l'exécution de la commande 's init' dans les logs système et CI/CD
* Détecter les appels à child_process.spawn() avec shell: true dans les dépendances npm
* Surveiller les processus enfants inattendus lancés depuis le processus 's' (Serverless-Devs CLI)

#### Phase 3 — Confinement, éradication et récupération

* Mettre à jour @serverless-devs/s vers une version > 3.1.11 si disponible
* Restreindre l'utilisation de 's init' avec des arguments non vérifiés
* Isoler les environnements de développement ayant pu exécuter des commandes malveillantes

#### Phase 4 — Activités post-incident

* Analyser les logs de processus pour identifier d'éventuelles commandes injectées exécutées
* Vérifier l'intégrité des dépôts Git initialisés via 's init' pour détecter des modifications malveillantes
* Auditer les variables d'environnement et secrets accessibles lors de l'exécution de la commande

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs CI/CD les exécutions de 's init' avec des arguments se terminant par '.git'
* Corréler les exécutions de 's init' avec des processus enfants suspects (reverse shells, downloads, etc.)
* Surveiller les dépôts Git créés via 's init' pour des indicateurs de compromission

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1059.004** | Unix Shell - Injection de commande OS via child_process.spawn() avec shell: true |
| **T1204.002** | User Execution: Malicious File - L'utilisateur exécute la commande 's init' avec un argument contrôlé par l'attaquant |

---

### Sources

* [https://mastodon.social/@EUVD_Bot/117033827089071541](https://mastodon.social/@EUVD_Bot/117033827089071541)
* [https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-52481](https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-52481)


---

<div id="cyberattaque-contre-le-registre-des-beneficiaires-effectifs-du-liechtenstein-31-000-enregistrements-exfiltres"></div>

## Cyberattaque contre le registre des bénéficiaires effectifs du Liechtenstein : 31 000 enregistrements exfiltrés

### Résumé

Dans la nuit du 29 au 30 juillet 2026, des attaquants inconnus ont accédé de manière illicite au registre des bénéficiaires effectifs (VwbP) du Liechtenstein par des moyens numériques. Des irrégularités ont été remarquées le 30 juillet 2026 à l'Office de la Justice, conduisant à la mise hors ligne du système. Les investigations préliminaires ont confirmé que les attaquants ont exfiltré des copies de données relatives à environ 31 000 entités juridiques (sociétés, fondations et trusts). Le registre contient des informations sur les bénéficiaires effectifs des entités juridiques, mis en place pour la prévention du blanchiment d'argent et du financement du terrorisme conformément à la 5e directive anti-blanchiment de l'UE. Aucune indication de modification ou suppression de données n'a été constatée. Le gouvernement a convoqué une cellule de crise le 1er août 2026, dirigée par la Première ministre Brigitte Haas et le ministre de la Justice Emanuel Schädler. L'incident constitue une violation de données personnelles au sens de l'article 33 du RGPD. Aucune demande de rançon n'a été reçue et les données n'étaient pas apparues sur le dark web au moment de la publication.

---

### Analyse opérationnelle

L'attaque a ciblé un registre gouvernemental sensible contenant des données de bénéficiaires effectifs, utilisées pour le respect des obligations anti-blanchiment. Le vecteur d'accès initial n'est pas encore公开. Les équipes SOC doivent noter que l'attaque s'est produite de nuit et que la détection a été effectuée via des irrégularités remarquées par les utilisateurs métier plutôt que par des alertes de sécurité automatisées. Le système a été mis hors ligne rapidement. Les données exfiltrées incluent des informations d'identification des bénéficiaires effectifs de 31 000 entités, ce qui représente un risque élevé d'usurpation d'identité, de ingénierie sociale ciblée et de compromission de la confidentialité d'structures juridiques. La surveillance du dark web est essentielle pour détecter toute apparition ou revente des données.

---

### Implications stratégiques

Cette cyberattaque frappe un État connu pour son secteur financier et son historique de secret bancaire. Le registre des bénéficiaires effectifs est un outil central de transparence financière imposé par l'UE, et sa compromission sape la confiance dans les mécanismes de lutte anti-blanchiment. L'incident a des implications géopolitiques : le Liechtenstein, bien que hors UE, applique les directives européennes, et cette attaque pourrait être motivée par des intérêts étatiques ou criminels cherchant à accéder à des informations sur les structures de propriété. La constitution d'une cellule de crise au plus haut niveau gouvernemental souligne la gravité de l'incident. Les conséquences incluent des obligations de notification GDPR, un risque réputationnel pour la place financière liechtensteinoise et une potentielle révision des mesures de sécurité des registres gouvernementaux à travers l'Europe.

---

### Recommandations

* Renforcer l'authentification multi-facteurs et le contrôle d'accès sur tous les registres gouvernementaux sensibles
* Mettre en place une détection automatisée des extractions massives de données et des accès hors heures
* Surveiller activement le dark web pour détecter toute apparition des données exfiltrées
* Notifier les 31 000 entités juridiques concernées conformément à l'article 34 du RGPD
* Conduire un audit de sécurité complet de l'infrastructure gouvernementale liechtensteinoise

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les registres gouvernementaux contenant des données sensibles (bénéficiaires effectifs, données financières)
* Mettre en place une surveillance d'accès anormal et des alertes sur les extractions massives de données
* Définir un plan de réponse aux incidents gouvernementaux incluant une cellule de crise et des procédures de notification GDPR

#### Phase 2 — Détection et analyse

* Surveiller les accès au registre VwbP en dehors des heures normales (l'attaque s'est produite de nuit)
* Détecter les volumes anormaux de requêtes ou d'export de données depuis le registre
* Mettre en place des alertes sur les irrégularités système signalées par les utilisateurs métier (comme l'Office de la Justice)

#### Phase 3 — Confinement, éradication et récupération

* Mettre hors ligne le système compromis (le registre VwbP a été mis hors ligne)
* Isoler les segments réseau permettant l'accès au registre
* Convoquer une cellule de crise gouvernementale (dirigée par le Premier ministre et le ministre de la Justice)
* Sécuriser les sauvegardes et les systèmes liés

#### Phase 4 — Activités post-incident

* Notifier les personnes concernées conformément à l'article 34 du RGPD
* Mettre en place un point d'information central pour les personnes affectées
* Conduire une analyse forensique complète pour déterminer le vecteur d'attaque et l'étendue de l'exfiltration
* Vérifier qu'aucune donnée n'a été modifiée ou supprimée
* Surveiller le dark web pour détecter toute apparition des données exfiltrées

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs d'accès les patterns d'exfiltration similaires sur d'autres registres gouvernementaux
* Corréler les accès au registre avec des indicateurs de compromission réseau
* Surveiller les forums et marketplaces du dark web pour l'apparition des données des 31 000 entités juridiques
* Analyser les comptes d'accès au registre pour identifier d'éventuelles compromissions de credentials

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078** | Valid Accounts - Accès non autorisé au registre VwbP par des moyens numériques |
| **T1041** | Exfiltration Over C2 Channel - Exfiltration de copies de données relatives à 31 000 entités juridiques |
| **T1567** | Exfiltration Over Web Service - Exfiltration de données du registre des bénéficiaires effectifs |

---

### Sources

* [https://databreaches.net/2026/08/03/cyberattack-hits-liechtenstein-with-31000-records-stolen/](https://databreaches.net/2026/08/03/cyberattack-hits-liechtenstein-with-31000-records-stolen/)
* [https://www.regierung.li/medienportal-medium/16444/234654/0/medienmitteilung](https://www.regierung.li/medienportal-medium/16444/234654/0/medienmitteilung)
* [https://apnews.com/article/liechtenstein-cyberattack-data-register-ce499c6c1d87c3c952058dc86f31d6ff](https://apnews.com/article/liechtenstein-cyberattack-data-register-ce499c6c1d87c3c952058dc86f31d6ff)
* [https://www.swissinfo.ch/eng/foreign-affairs/31000-copies-of-data-belonging-to-legal-entities-stolen-in-liechtenstein/91838585](https://www.swissinfo.ch/eng/foreign-affairs/31000-copies-of-data-belonging-to-legal-entities-stolen-in-liechtenstein/91838585)


---

<div id="revente-sur-le-dark-web-des-donnees-de-bank-of-baroda-prealablement-diffusees-par-triplex"></div>

## Revente sur le dark web des données de Bank of Baroda préalablement diffusées par TripleX

### Résumé

Le compte Mastodon @cashlessconsumer rapporte que les données de Bank of Baroda (BoB), initialement diffusées gratuitement par l'acteur TripleX le 24 juillet 2026 (~1 To de données), font désormais l'objet d'une revente sur le forum PwnForums. Un utilisateur nommé 'dhando' liste le même dataset pour 8 crédits, ce qui correspond à la revente d'un dump gratuit à bas prix. Cette pratique illustre le cycle de vie des données volées sur les forums criminels, où des datasets initialement publiés gratuitement sont ensuite revendus par d'autres acteurs.

---

### Analyse opérationnelle

Les équipes SOC et les équipes de threat intelligence doivent surveiller les forums du dark web pour suivre la propagation des données Bank of Baroda. La revente par 'dhando' sur PwnForums indique que les données restent accessibles et circulent activement. Les organisations financières indiennes doivent corréler cette exposition avec des campagnes de phishing potentielles ciblant leurs clients, car les données (emails, informations de compte, etc.) peuvent être utilisées pour des attaques d'ingénierie sociale. La surveillance continue des forums criminels est nécessaire pour détecter de nouvelles redistributions.

---

### Implications stratégiques

Cet incident met en lumière l'écosystème de monétisation des données volées sur le dark web, où des datasets initialement gratuits sont recyclés et revendus. Pour Bank of Baroda, cela prolonge l'impact de la fuite initiale et maintient un risque persistant pour les clients concernés. Sur le plan sectoriel, les banques indiennes font face à une vague croissante de cyberattaques, et cet exemple démontre que la publication de données n'est pas un événement ponctuel mais un processus continu de redistribution. Les régulateurs indiens (RBI, CERT-In) pourraient renforcer les exigences de notification et de protection des données financières.

---

### Recommandations

* Surveiller en continu les forums du dark web pour détecter de nouvelles redistributions des données BoB
* Renforcer les contrôles d'accès et le chiffrement des données bancaires sensibles
* Sensibiliser les clients aux risques de phishing liés à l'exposition de leurs données
* Coordonner avec les autorités indiennes (CERT-In, RBI) pour une réponse sectorielle concertée

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les données sensibles stockées par la banque et leur exposition potentielle
* Mettre en place une surveillance du dark web pour détecter les fuites de données institutionnelles
* Définir des procédures de réponse en cas de publication de données sur des forums criminels

#### Phase 2 — Détection et analyse

* Surveiller les forums du dark web (PwnForums, Altenen, etc.) pour des mentions de Bank of Baroda ou de données bancaires indiennes
* Détecter les tentatives de revente ou de redistribution de datasets précédemment publiés
* Corréler les alertes de dark web avec les incidents de fuite de données connus

#### Phase 3 — Confinement, éradication et récupération

* Évaluer l'étendue des données déjà publiées et leur accessibilité publique
* Coordonner avec les autorités indiennes (CERT-In, RBI) pour une réponse concertée
* Informer les clients concernés des risques liés à l'exposition de leurs données

#### Phase 4 — Activités post-incident

* Évaluer l'impact de la redistribution des données sur les clients affectés
* Renforcer les mesures de sécurité pour prévenir de futures exfiltrations
* Documenter l'incident et la chaîne de revente pour les investigations judiciaires

#### Phase 5 — Threat Hunting (proactif)

* Surveiller en continu les forums criminels pour de nouvelles redistributions des données Bank of Baroda
* Corréler les données publiées avec des campagnes de phishing ciblant les clients de la banque
* Rechercher des indicateurs d'utilisation des données volées pour des attaques d'ingénierie sociale

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1567.002** | Exfiltration Over Web Service: Exfiltration to Cloud Storage - Publication des données sur le dark web |
| **T1588.006** | Obtain Capabilities: Vulnerabilities - Revente de données volées sur des forums criminels |

---

### Sources

* [https://freeradical.zone/@cashlessconsumer/117030465268638269](https://freeradical.zone/@cashlessconsumer/117030465268638269)


---

<div id="fuite-de-splitvpn-ex-notvpn-58-millions-de-logs-de-connexion-et-234-millions-denregistrements-utilisateurs-exposes-malgre-la-promesse-no-logs"></div>

## Fuite de SplitVPN (ex-NotVPN) : 58 millions de logs de connexion et 23,4 millions d'enregistrements utilisateurs exposés malgré la promesse « no-logs »

### Résumé

Un acteur de menace identifié sous le pseudo vhacker51 a publié sur le forum cybercriminel Altenen un dump SQL de 17 Go prétendument volé de SplitVPN (anciennement NotVPN), un VPN russe utilisé pour contourner la censure. L'équipe de recherche de Mysterium a obtenu une copie et vérifié son authenticité. La base de données contient environ 23,4 millions d'enregistrements utilisateurs (emails, adresses IP, localisation, statut d'abonnement), 13,6 millions d'enregistrements d'appareils (identifiants UUID Apple, hashes MD5, tokens de notification push), 2,6 millions d'enregistrements de paiement (cartes masquées via la passerelle Tinkoff, tokens de facturation récurrente) et 58 millions de logs de connexion (table deviceProxy) avec horodatage du juin 2025 au 21 juillet 2026. La table admin expose 5 comptes (pavel, valerii, maria, andrei, vladislav) avec des hashes bcrypt. Les numéros de carte complets ne sont pas présents (masqués BIN + 4 derniers). Le VPN promettait « No logs or history: We never store your activity or connection logs. 100% privacy guaranteed » mais conservait des logs de connexion par dizaines de millions. Les utilisateurs sont concentrés en Russie, Iran, Inde et Myanmar.

---

### Analyse opérationnelle

Cette fuite expose des métadonnées de connexion permettant de reconstituer qui s'est connecté, depuis quelle adresse IP, vers quel serveur VPN et quand, pour des dizaines de millions d'utilisateurs. Les équipes SOC doivent : (1) identifier les employés ayant utilisé SplitVPN/NotVPN, car leurs adresses email et IP sont désormais exposées sur un forum criminel ; (2) traiter les emails et IP comme compromis et exiger des changements de mots de passe ; (3) activer l'authentification multi-facteurs sur les comptes utilisant ces emails ; (4) surveiller les tentatives de phishing ciblant les utilisateurs exposés. Les 5 comptes administrateur (pavel, valerii, maria, andrei, vladislav) avec leurs hashes bcrypt sont exposés. Les tokens de facturation récurrente Tinkoff constituent un risque d'usurpation de paiement. Les identifiants d'appareils (UUID Apple, hashes MD5) permettent le suivi d'appareils spécifiques.

---

### Implications stratégiques

Cet incident démontre que les promesses « no-logs » des VPN sont non vérifiables et peuvent être fausses. Pour les organisations, cela soulève la question de la confiance accordée aux fournisseurs VPN tiers pour protéger les communications sensibles. Les utilisateurs exposés se trouvent dans des pays (Russie, Iran, Inde, Myanmar) où l'utilisation d'un VPN peut présenter des risques personnels, et la fuite de métadonnées reliant une personne à l'acte de contourner la censure étatique a des conséquences potentiellement graves sur le plan sécuritaire et des droits humains. Sur le plan géopolitique, la fuite de données d'utilisateurs de VPN anti-censure dans des pays autoritaires pourrait être exploitée par des services de renseignement étatiques. Le secteur VPN doit faire face à une crise de confiance qui pourrait conduire à des exigences réglementaires d'audit indépendant des politiques de journalisation.

---

### Recommandations

* Identifier et désactiver immédiatement les comptes SplitVPN/NotVPN utilisés par le personnel
* Exiger des changements de mots de passe sur tous les comptes utilisant les emails exposés
* Activer l'authentification multi-facteurs sur les comptes concernés
* Surveiller les tentatives de phishing ciblant les utilisateurs dont les données ont fuité
* Réévaluer la politique d'utilisation de VPN tiers pour les communications professionnelles
* Privilégier des solutions VPN auditées indépendamment ou des architectures zero-trust

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les services VPN utilisés par l'organisation et leurs politiques de journalisation
* Évaluer les risques liés à l'utilisation de VPN tiers pour les communications sensibles
* Mettre en place une surveillance des forums criminels pour détecter des fuites de données VPN

#### Phase 2 — Détection et analyse

* Surveiller les forums criminels (Altenen, etc.) pour des publications de dumps de données VPN
* Corréler les adresses email et IP des employés avec les données potentiellement exposées
* Détecter les tentatives de phishing utilisant des informations issues de la fuite VPN

#### Phase 3 — Confinement, éradication et récupération

* Identifier les employés ayant utilisé SplitVPN/NotVPN et leur demander de changer immédiatement leurs mots de passe
* Activer l'authentification multi-facteurs sur tous les comptes utilisant les emails exposés
* Bloquer les adresses IP et identifiants d'appareils compromis dans les règles de pare-feu et de détection

#### Phase 4 — Activités post-incident

* Évaluer l'impact de l'exposition des métadonnées de connexion (qui s'est connecté, depuis où, à quel serveur, quand)
* Documenter les comptes administrateur exposés (pavel, valerii, maria, andrei, vladislav) et leurs hashes bcrypt
* Réviser les politiques d'utilisation de VPN tiers pour les employés
* Notifier les utilisateurs concernés des risques de phishing ciblé

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs d'authentification les tentatives de connexion utilisant des credentials potentiellement compromis
* Corréler les adresses IP exposées avec des activités malveillantes détectées sur le réseau de l'organisation
* Surveiller les tentatives de phishing utilisant des informations personnelles issues du dump VPN
* Surveiller les forums criminels pour de nouvelles publications ou monétisations des données SplitVPN

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078** | Valid Accounts - Accès non autorisé à la base de données MySQL du VPN |
| **T1005** | Data from Local System - Exfiltration d'un dump SQL de 17 Go de la base de données notvpn |
| **T1567.002** | Exfiltration Over Web Service: Exfiltration to Cloud Storage - Publication du dump sur le forum Altenen |

---

### Sources

* [https://mastodon.social/@threadlinqs/117029458253676891](https://mastodon.social/@threadlinqs/117029458253676891)
* [https://intel.threadlinqs.com/threat/TL-2026-1823](https://intel.threadlinqs.com/threat/TL-2026-1823)
* [https://www.mysteriumvpn.com/blog/news/notvpn-splitvpn-breach-58-million-logs](https://www.mysteriumvpn.com/blog/news/notvpn-splitvpn-breach-58-million-logs)
* [https://securityaffairs.com/196197/security/vpn-breach-exposes-58-million-connection-logs-despite-no-logs-claims.html](https://securityaffairs.com/196197/security/vpn-breach-exposes-58-million-connection-logs-despite-no-logs-claims.html)
