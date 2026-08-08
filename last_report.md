# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [FirewallFalcon Manager : porte dérobée de chaîne d'approvisionnement dans l'infrastructure VPN underground](#firewallfalcon-manager-porte-derobee-de-chaine-dapprovisionnement-dans-linfrastructure-vpn-underground)
  * [Bug ICMP Timestamp dans Windows tcpip.sys : contournement du registre EnableICMPTimestampRep=0 et violation RFC 792](#bug-icmp-timestamp-dans-windows-tcpipsys-contournement-du-registre-enableicmptimestamprep0-et-violation-rfc-792)
  * [Sift : outil open-source de détection de credentials sur partages de fichiers avec file de révision](#sift-outil-open-source-de-detection-de-credentials-sur-partages-de-fichiers-avec-file-de-revision)
  * [Attaque de chaîne d'approvisionnement npm : compromission des packages keyv et cacheable via takeover de compte mainteneur](#attaque-de-chaine-dapprovisionnement-npm-compromission-des-packages-keyv-et-cacheable-via-takeover-de-compte-mainteneur)
  * [Compromission du compte TMC Metro Jaya (police indonésienne) pour promouvoir une arnaque crypto](#compromission-du-compte-tmc-metro-jaya-police-indonesienne-pour-promouvoir-une-arnaque-crypto)
  * [Remplacement silencieux d'exécutables d'applications macOS de confiance](#remplacement-silencieux-dexecutables-dapplications-macos-de-confiance)
  * [Backdoor ENDLESSDOORS dans les routeurs Zbtlink : shells root non authentifiés](#backdoor-endlessdoors-dans-les-routeurs-zbtlink-shells-root-non-authentifies)
  * [Campagne Wel1Dropper : 788 packages npm malveillants livrant un RAT cross-plateforme et infostealer](#campagne-wel1dropper-788-packages-npm-malveillants-livrant-un-rat-cross-plateforme-et-infostealer)
  * [UNC6671 : campagne de vishing multi-marques ciblant les SaaS pour extorsion de données](#unc6671-campagne-de-vishing-multi-marques-ciblant-les-saas-pour-extorsion-de-donnees)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'édition du jour est dominée par un volume exceptionnel de 92 vulnérabilités publiées, signalant une pression de remédiation élevée et un risque d'exploitation rapide, en particulier sur les produits exposés à Internet. Les 11 incidents de fuite de données recensés renforcent cette hypothèse : plusieurs d'entre eux pourraient résulter d'exploitations opportunistes de failles récentes non corrigées. L'absence totale de signalement sur les acteurs de menace (0) ne doit pas être interprétée comme une accalmie opérationnelle, mais plutôt comme un manque de visibilité ponctuel sur les campagnes actives. Le contexte géopolitique, avec 3 références, reste modéré mais mérite une veille continue pour anticiper d'éventuelles escalades cyber. Le volet réglementaire (1) est marginal aujourd'hui, sans impact immédiat sur les obligations de conformité. Les 9 articles de fond publiés constituent une ressource utile pour contextualiser les vulnérabilités majeures et prioriser les actions de remédiation. Recommandation : prioriser le triage des 92 vulnérabilités selon l'exposition des actifs et l'existence de PoC publics, et surveiller activement les corrélations avec les fuites de données signalées.

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
| **États-Unis** | Gouvernement / Diplomatie cyber | Nomination de l'ambassadeur américain pour la cybernétique et la politique numérique | Le Sénat américain a confirmé Adam Cassady au poste d'ambassadeur pour la cybernétique et la politique numérique par un vote de 51-47, dans le cadre d'un package regroupant plus de 70 nominations. Il est la deuxième personne à occuper ce poste d'ambassadeur itinérant, vacant depuis le départ du premier titulaire au début de l'administration Trump. Son influence réelle reste incertaine : le Bureau de la cybersphère et de la politique numérique a été restructuré en trois entités distinctes, dont un nouveau Bureau des menaces émergentes, et a vu ses effectifs réduits. Lors de son audition, Cassady s'est montré évasif sur la question de l'envoi de semi-conducteurs avancés vers la Chine, indiquant qu'il développerait rapidement une position sur ce sujet. Cette nomination intervient dans un contexte de tensions technologiques croissantes entre les États-Unis et la Chine, notamment sur les puces IA de Nvidia (H200) dont de premières livraisons vers la Chine et Hong Kong ont été signalées. | [https://therecord.media/adam-cassady-confirmed-senate-cyber-ambassador](https://therecord.media/adam-cassady-confirmed-senate-cyber-ambassador)<br>[https://infosec.exchange/@securityfeed/117056146443903456](https://infosec.exchange/@securityfeed/117056146443903456) |
| **États-Unis, Europe, Inde** | Défense / Industrie militaire | Compromission d'un fabricant de composants militaires par hameçonnage | IEH Corporation, fabricant américain de connecteurs spécialisés utilisés dans des satellites militaires, des missiles (programmes THAAD et Patriot), des avions de chasse, des radars et des torpodes, a divulgué un incident cybernétique à la SEC via un dépôt 8-K. L'attaque, découverte le mardi 4 août 2026, a été initiée par hameçonnage ciblant un employé, donnant aux attaquants l'accès à sa boîte mail contenant des communications clients, des bons de commande, de la documentation d'ingénierie et potentiellement des informations techniques soumises au contrôle des exportations. Bien qu'IEH indique ne pas avoir de preuve d'exfiltration, les données sensibles étaient accessibles durant la période de compromission. Les produits d'IEH sont utilisés par des pays européens et l'Inde, ce qui élargit la portée géopolitique potentielle de l'incident. L'entreprise a généré près de 30 millions de dollars de revenus en 2026. | [https://therecord.media/military-device-manufacturer-discloses-cyber-incident](https://therecord.media/military-device-manufacturer-discloses-cyber-incident)<br>[https://infosec.exchange/@securityfeed/117056146443903456](https://infosec.exchange/@securityfeed/117056146443903456) |
| **Moyen-Orient, Iran, États-Unis, Oman** | Géopolitique / Sécurité maritime | Rouverture du détroit d'Ormuz et recul de l'influence américaine au Moyen-Orient | Le détroit d'Ormuz, fermé par l'Iran à la suite des frappes israélo-américaines, devrait prochainement rouvrir à la circulation maritime. L'accord de rouverture a été négocié entre l'Iran et Oman, sans participation des États-Unis, bien que Donald Trump ait fait de cette réouverture un objectif stratégique majeur et présente l'avancée comme une victoire personnelle. Cette situation met en évidence l'érosion de l'influence américaine au Moyen-Orient : Washington n'a été ni partie prenante ni médiateur des négociations. L'Iran consolide ainsi sa position d'acteur incontournable dans la recomposition géopolitique régionale, utilisant le détroit comme levier stratégique et démontrant sa capacité à négocier directement avec des acteurs régionaux sans tutelle américaine. | [https://www.iris-france.org/trump-de-superman-a-la-mouche-du-coche/](https://www.iris-france.org/trump-de-superman-a-la-mouche-du-coche/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| 23 NYCRR Part 500 | New York State Department of Financial Services (NYS DFS) | 2026-08-05 | État de New York, États-Unis | 23 NYCRR Part 500 | Le NYS DFS a annoncé le 5 août 2026 une sanction pécuniaire de 250 000 USD à l'encontre d'Order Express, Inc., un transmetteur de fonds agréé, pour des violations du règlement de cybersécurité 23 NYCRR Part 500. L'enquête du DFS, déclenchée à la suite d'une attaque par ransomware subie par Order Express en 2022 (correctement signalée par l'entité), a révélé des carences significatives dans le programme de cybersécurité de l'entreprise : absence d'évaluation adéquate des risques, politiques de mise à jour des systèmes insuffisantes, et exposition à des vulnérabilités exploitables par des acteurs malveillants. Order Express a depuis remédié aux déficiences identifiées. En raison de ses revenus limités, l'entreprise est exemptée de plusieurs exigences de la Part 500. Le règlement de cybersécurité du DFS, en vigueur depuis mars 2017 et amendé en novembre 2023, sert de modèle national pour d'autres régulateurs, notamment la FTC, plusieurs États, la NAIC et la CSBS. | [https://databreaches.net/2026/08/07/new-york-state-department-of-financial-services-secures-cybersecurity-settlement-with-order-express-inc/](https://databreaches.net/2026/08/07/new-york-state-department-of-financial-services-secures-cybersecurity-settlement-with-order-express-inc/)<br>[https://infosec.exchange/@PogoWasRight/117055587412060643](https://infosec.exchange/@PogoWasRight/117055587412060643) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Technologie / IA / Plateforme de Machine Learning** | Hugging Face | Datasets internes limités, credentials de services internes Hugging Face, credentials exposés sur quatre services tiers (relais/payload staging, stockage de données, deux comptes en lecture seule). | Inconnu | [https://socprime.com/blog/hugging-face-breach-openai-agent-abused-exposed-credentials-across-four-services/](https://socprime.com/blog/hugging-face-breach-openai-agent-abused-exposed-credentials-across-four-services/) |
| **Gouvernement / Justice** | Court Services Victoria | Noms, adresses e-mail, titres/postes des participants aux audiences en ligne, noms des parties dans des affaires de violence familiale et du tribunal pour enfants, métadonnées WebEx (noms de dossiers, numéros, dates et heures d'audience, salles, rôles des participants). | 28600 | [https://databreaches.net/2026/08/07/au-hackers-leak-sensitive-victorian-court-data-to-dark-web/](https://databreaches.net/2026/08/07/au-hackers-leak-sensitive-victorian-court-data-to-dark-web/)<br>[https://www.abc.net.au/news/2026-08-07/victorian-court-personal-data-breach-dark-web/107004792](https://www.abc.net.au/news/2026-08-07/victorian-court-personal-data-breach-dark-web/107004792)<br>[https://www.cyberdaily.au/security/13979-exclusive-court-services-victoria-courts-data-breach-following-hacker-claims](https://www.cyberdaily.au/security/13979-exclusive-court-services-victoria-courts-data-breach-following-hacker-claims)<br>[https://infosec.exchange/@beyondmachines1/117055059882008378](https://infosec.exchange/@beyondmachines1/117055059882008378) |
| **Santé / Logiciel de gestion du cycle de revenus pour prestataires de santé spécialisés** | Unlimited Technology Systems | Noms complets, numéros de sécurité sociale (SSN), dates de naissance, adresses e-mail et postales, numéros de téléphone, informations démographiques, scans de permis de conduire et autres pièces d'identité gouvernementales, cartes d'assurance, formulaires d'admission, numéros de police d'assurance maladie, informations sur les demandes et prestations, numéros de dossiers médicaux, dates de service, informations de diagnostic. | 3803750 | [https://www.bleepingcomputer.com/news/security/unlimited-technology-systems-breach-impacts-38-million-people/](https://www.bleepingcomputer.com/news/security/unlimited-technology-systems-breach-impacts-38-million-people/)<br>[https://databreaches.net/2026/08/07/unlimited-technology-systems-data-breach-affects-3-8-million-patients/](https://databreaches.net/2026/08/07/unlimited-technology-systems-data-breach-affects-3-8-million-patients/)<br>[https://mastodon.social/@Analyst207/117055899106074324](https://mastodon.social/@Analyst207/117055899106074324)<br>[https://mastodon.social/@netsecio/117055508953376771](https://mastodon.social/@netsecio/117055508953376771)<br>[https://infosec.exchange/@cloud/117055993863612726](https://infosec.exchange/@cloud/117055993863612726) |
| **Gouvernement / Administration publique** | Gouvernement suisse (Federal Office for Information Technology and Telecommunication - BIT) | Credentials d'authentification d'environ 200 comptes. Aucune preuve d'exfiltration de données au-delà des credentials. | 200 | [https://www.bleepingcomputer.com/news/security/swiss-government-sharepoint-breach-compromised-200-accounts/](https://www.bleepingcomputer.com/news/security/swiss-government-sharepoint-breach-compromised-200-accounts/)<br>[https://mastodon.thenewoil.org/@thenewoil/117055645365303863](https://mastodon.thenewoil.org/@thenewoil/117055645365303863) |
| **Santé / Établissement de soins (critical access hospital, zone rurale)** | Heart of America Medical Center | Numéros de sécurité sociale (SSN), dossiers médicaux complets, informations d'identification personnelle (PII) et informations de santé protégées (PHI). Volume allégué : 800 Go de données. | Inconnu | [https://cyber.netsecops.io/articles/heart-of-america-medical-center-data-breach-exposes-patient-data/](https://cyber.netsecops.io/articles/heart-of-america-medical-center-data-breach-exposes-patient-data/)<br>[https://mastodon.social/@netsecio/117055511639653511](https://mastodon.social/@netsecio/117055511639653511) |
| **Cloud / SaaS** | Snowflake (clients) | Données clients (100M+ records) - détails exacts non spécifiés mais incluant potentiellement des informations personnelles et d'entreprise | 100000000 | [https://mastodon.social/@netsecio/117055508372223309](https://mastodon.social/@netsecio/117055508372223309) |
| **Retail / Mode** | Levi Strauss & Co. | Informations d'entreprise (nature exacte non spécifiée) - données consommateurs non impactées | Inconnu | [https://mastodon.social/@Analyst207/117055073133600712](https://mastodon.social/@Analyst207/117055073133600712) |
| **Santé / Public** | NHS Tayside (Ninewells Hospital) | Dossiers médicaux d'une patiente mineure (neuf ans) - accès non autorisé par le personnel | 1 | [https://mastodon.social/@Analyst207/117054723706740673](https://mastodon.social/@Analyst207/117054723706740673) |
| **Santé** | Brown Health Medical Group - MA | Informations personnelles, médicales (PHI) et financières de 311 000+ individus | 311000 | [https://infosec.exchange/@beyondmachines1/117053880192815423](https://infosec.exchange/@beyondmachines1/117053880192815423) |
| **Santé / Diagnostics** | Exact Sciences (Abbott Laboratories) | Adresses email (10,9M), noms, adresses postales, numéros de téléphone, dates de naissance, genres, données de santé personnelles (PHI) | 10869543 | [https://haveibeenpwned.com/Breach/ExactSciences](https://haveibeenpwned.com/Breach/ExactSciences) |
| **Électronique grand public / Tech** | Framework (modular laptop manufacturer) | Données clients (nature et volume exacts non spécifiés) - exfiltration via Metabase compromis | Inconnu | [https://infosec.exchange/@security_crawler_carl/117054181048405312](https://infosec.exchange/@security_crawler_carl/117054181048405312) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-64638** | 8.9 | N/A | FALSE | WordPress | CWE-79 Cross-site Scripting (XSS) - Reflected | Compromission complète du serveur WordPress via exécution de code à distance (RCE) si un administrateur authentifié interagit avec une page contrôlée par l'attaquant. Le XSS initial ne nécessite aucune authentification et s'exécute dans le navigateur du visiteur sur la page de connexion. L'attaquant peut ensuite installer des plugins malveillants, uploader des fichiers arbitraires, modifier la base de données et prendre le contrôle total du serveur. Les versions antérieures à 4.7 ne bénéficient pas de correctif rétroporté et restent vulnérables. | Theoretical | Mettre à jour immédiatement WordPress vers la version 7.0.3 ou ultérieure. Pour les versions 4.7 à 7.0.2, appliquer les correctifs rétroportés publiés par WordPress. Les installations avec mises à jour automatiques en arrière-plan activées devraient recevoir le correctif automatiquement. Pour les versions antérieures à 4.7, envisager une migration vers une version supportée. Déployer un WAF pour filtrer les payloads XSS sur la page de connexion. Sensibiliser les administrateurs aux risques d'ingénierie sociale visant à les amener sur des pages malveillantes. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0979/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0979/)<br>[https://cvefeed.io/vuln/detail/CVE-2026-64638](https://cvefeed.io/vuln/detail/CVE-2026-64638)<br>[https://thehackernews.com/2026/08/new-wordpress-pre-auth-xss-could-lead.html](https://thehackernews.com/2026/08/new-wordpress-pre-auth-xss-could-lead.html) |
| **CVE-2026-17603** | 8.7 | N/A | FALSE | Nexus Repository 3 | CWE-94 Improper Control of Generation of Code ('Code Injection') | Exécution de code arbitraire à distance (RCE) en tant qu'utilisateur du processus Nexus, compromission potentielle de l'intégrité, confidentialité et disponibilité du système. | Theoretical | Mettre à jour Nexus Repository 3 vers la dernière version (3.95.0+). Restreindre les propriétés HikariCP modifiables. Limiter la permission nx-datastores-update. Surveiller le SQL d'initialisation des connexions de base de données. | [https://cvefeed.io/vuln/detail/CVE-2026-17603](https://cvefeed.io/vuln/detail/CVE-2026-17603) |
| **CVE-2026-17601** | 8.9 | N/A | FALSE | Nexus Repository 3 | CWE-862 Missing Authorization | Escalade de privilèges vers accès administrateur complet sur Nexus Repository 3, permettant la compromission totale de l'instance et de ses données. | Theoretical | Mettre à jour Nexus Repository 3 vers la version 3.95.0+. Vérifier l'autorisation des utilisateurs avant les mises à jour de définitions de privilèges. Implémenter des contrôles d'accès granulaires. Auditer toutes les tentatives de modification de privilèges. | [https://cvefeed.io/vuln/detail/CVE-2026-17601](https://cvefeed.io/vuln/detail/CVE-2026-17601) |
| **CVE-2026-17600** | 8.7 | N/A | FALSE | Nexus Repository 3 | CWE-613 Insufficient Session Expiration | Accès non autorisé persistant au repository après révocation d'accès, permettant de lire, modifier ou supprimer du contenu du repository. | Theoretical | Mettre à jour Nexus Repository vers la dernière version. Implémenter la terminaison immédiate des sessions lors de modifications de compte. Révoquer les permissions en cache. Redémarrer les services Nexus après mise à jour. | [https://cvefeed.io/vuln/detail/CVE-2026-17600](https://cvefeed.io/vuln/detail/CVE-2026-17600) |
| **CVE-2026-17594** | 8.2 | N/A | FALSE | Nexus Repository 3 | CWE-863 Incorrect Authorization | Création de repositories non autorisés, pouvant permettre l'accès à des formats de repository non prévus et l'exfiltration ou l'altération de données. | Theoretical | Mettre à jour Nexus Repository Manager vers la version 3.95.0 ou supérieure. Vérifier les privilèges utilisateurs et les permissions de création de repository. | [https://cvefeed.io/vuln/detail/CVE-2026-17594](https://cvefeed.io/vuln/detail/CVE-2026-17594) |
| **CVE-2026-65400** | 7.1 | 0.30% | FALSE | macOS | An attacker on the network may be able to authenticate to Screen Sharing without valid credentials | Accès non authentifié à un Mac distant via Screen Sharing, permettant le contrôle de l'écran, l'ouverture de fichiers et le lancement d'applications sans credentials valides. | Theoretical | Mettre à jour vers macOS Sequoia 15.7.9, macOS Sonoma 14.8.9 ou macOS Tahoe 26.6.1. Désactiver Screen Sharing si non nécessaire. Restreindre l'accès réseau au service Screen Sharing. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0980/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0980/)<br>[https://www.security.nl/posting/948349/Apple+dicht+Screen+Sharing-lek+dat+aanvaller+toegang+tot+Macs+kan+geven?channel=rss](https://www.security.nl/posting/948349/Apple+dicht+Screen+Sharing-lek+dat+aanvaller+toegang+tot+Macs+kan+geven?channel=rss) |
| **CVE-2026-13181** | 8.1 | 0.48% | FALSE | Telerik UI for ASP.NET AJAX | CWE-470 Use of Externally-Controlled Input to Select Classes or Code | Exécution de code arbitraire à distance, atteinte à l'intégrité et à la confidentialité des données. | Theoretical | Mettre à jour Telerik UI pour ASP.NET AJAX vers la version 2026.2.708 (2026 Q2 SP1) ou supérieure. Se référer au bulletin de sécurité Progress. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/) |
| **CVE-2026-13182** | 7.5 | 0.32% | FALSE | Telerik UI for ASP.NET AJAX | CWE-209 Generation of Error Message Containing Sensitive Information | Atteinte à la confidentialité des données, possible exécution de code arbitraire à distance via chaîne d'exploitation. | Theoretical | Mettre à jour Telerik UI pour ASP.NET AJAX vers la version 2026.2.708 (2026 Q2 SP1) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/) |
| **CVE-2026-13183** | 7.5 | 0.32% | FALSE | Telerik UI for ASP.NET AJAX | CWE-208 Observable Timing Discrepancy | Atteinte à la confidentialité des données, possible exécution de code arbitraire à distance. | Theoretical | Mettre à jour Telerik UI pour ASP.NET AJAX vers la version 2026.2.708 (2026 Q2 SP1) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/) |
| **CVE-2026-13184** | 7.5 | 0.20% | FALSE | Telerik UI for ASP.NET AJAX | CWE-321 Use of Hard-coded Cryptographic Key | Exécution de code arbitraire à distance sans authentification, compromission complète du serveur web. | Theoretical | Mettre à jour Telerik UI pour ASP.NET AJAX vers la version 2026.2.708 (2026 Q2 SP1) ou supérieure. Exiger une authentification sur les endpoints RadAsyncUpload. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/) |
| **CVE-2026-13185** | 8.1 | 0.49% | FALSE | Telerik UI for ASP.NET AJAX | CWE-502 Deserialization of Untrusted Data | Exécution de code arbitraire à distance, atteinte à la confidentialité et l'intégrité des données. | Theoretical | Mettre à jour Telerik UI pour ASP.NET AJAX vers la version 2026.2.708 (2026 Q2 SP1) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/) |
| **CVE-2026-13186** | 8.1 | 0.53% | FALSE | Telerik UI for ASP.NET AJAX | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Exécution de code arbitraire à distance, lecture de fichiers arbitraires, compromission du serveur. | Theoretical | Mettre à jour Telerik UI pour ASP.NET AJAX vers la version 2026.2.708 (2026 Q2 SP1) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/) |
| **CVE-2026-13187** | 8.1 | 0.34% | FALSE | Telerik UI for ASP.NET AJAX | CWE-470 Use of Externally-Controlled Input to Select Classes or Code | Contournement de politique de sécurité, atteinte à la confidentialité et l'intégrité des données. | Theoretical | Mettre à jour Telerik UI pour ASP.NET AJAX vers la version 2026.2.708 (2026 Q2 SP1) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/) |
| **CVE-2026-13188** | 5.9 | 0.11% | FALSE | Telerik UI for ASP.NET AJAX | CWE-345 Insufficient Verification of Data Authenticity | Contournement de politique de sécurité, atteinte à la confidentialité et l'intégrité des données. | Theoretical | Mettre à jour Telerik UI pour ASP.NET AJAX vers la version 2026.2.708 (2026 Q2 SP1) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/) |
| **CVE-2026-13189** | 7.5 | 0.36% | FALSE | Telerik UI for ASP.NET AJAX | CWE-36 Absolute Path Traversal | Exécution de code arbitraire à distance, déni de service, contournement de politique de sécurité, SSRF, atteinte à la confidentialité et l'intégrité des données. | Theoretical | Mettre à jour Telerik UI pour ASP.NET AJAX vers la version 2026.2.708 (2026 Q2 SP1) ou supérieure. Se référer au bulletin de sécurité Progress. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/) |
| **CVE-2026-13190** | 8.1 | 0.48% | FALSE | Telerik UI for ASP.NET AJAX | CWE-502 Deserialization of Untrusted Data | Exécution de code arbitraire à distance, déni de service, contournement de politique de sécurité, SSRF, atteinte à la confidentialité et l'intégrité des données. | Theoretical | Mettre à jour Telerik UI pour ASP.NET AJAX vers la version 2026.2.708 (2026 Q2 SP1) ou supérieure. Se référer au bulletin de sécurité Progress. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/) |
| **CVE-2026-13192** | 6.5 | 0.24% | FALSE | Telerik UI for ASP.NET AJAX | CWE-918 Server-Side Request Forgery (SSRF) | Exécution de code arbitraire à distance, déni de service, contournement de politique de sécurité, SSRF, atteinte à la confidentialité et l'intégrité des données. | Theoretical | Mettre à jour Telerik UI pour ASP.NET AJAX vers la version 2026.2.708 (2026 Q2 SP1) ou supérieure. Se référer au bulletin de sécurité Progress. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/) |
| **CVE-2026-14865** | 5.3 | 0.26% | FALSE | Telerik UI for ASP.NET AJAX | CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion') | Exécution de code arbitraire à distance, déni de service, contournement de politique de sécurité, SSRF, atteinte à la confidentialité et l'intégrité des données. | Theoretical | Mettre à jour Telerik UI pour ASP.NET AJAX vers la version 2026.2.708 (2026 Q2 SP1) ou supérieure. Se référer au bulletin de sécurité Progress. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/) |
| **CVE-2026-14932** | 6.5 | 0.21% | FALSE | Telerik UI for ASP.NET AJAX | CWE-321 Use of Hard-coded Cryptographic Key | Lecture de fichiers arbitraires sur le serveur, atteinte à la confidentialité des données, possible exfiltration de credentials ou de configurations sensibles. | Theoretical | Mettre à jour Telerik UI pour ASP.NET AJAX vers la version 2026.2.708 (2026 Q2 SP1) ou supérieure. Remplacer les clés hardcoded. Restreindre l'accès aux fichiers sensibles. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/) |
| **CVE-2026-19137** | 8.3 | 0.40% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur, pouvant potentiellement permettre une exécution de code arbitraire ou un contournement de sécurité. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19138** | 8.3 | 0.33% | FALSE | Chrome | CWE-122 Heap buffer overflow | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19139** | 7.4 | 0.09% | FALSE | Chrome | CWE-362 Race | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19140** | 8.3 | 0.29% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19141** | 8.3 | 0.29% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19142** | 7.5 | 0.29% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19143** | 8.6 | 0.15% | FALSE | Chrome | CWE-20 Insufficient validation of untrusted input | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19144** | 8.8 | 0.24% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19145** | 8.8 | 0.37% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19146** | 5.3 | 0.32% | FALSE | Chrome | CWE-457 Uninitialized Use | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19147** | 8.3 | 0.24% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19148** | 8.3 | 0.24% | FALSE | Chrome | CWE-787 Out of bounds write | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19149** | 9.6 | 0.42% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19150** | 8.8 | 0.46% | FALSE | Chrome | Inappropriate implementation | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19151** | 8.8 | 0.46% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19152** | 8.3 | 0.24% | FALSE | Chrome | Inappropriate implementation | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19153** | 8.1 | 0.26% | FALSE | Chrome | CWE-20 Insufficient validation of untrusted input | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19154** | 8.3 | 0.32% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19155** | 8.3 | 0.29% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19156** | 7.5 | 0.17% | FALSE | Chrome | CWE-122 Heap buffer overflow | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19157** | 9.6 | 0.26% | FALSE | Chrome | CWE-787 Out of bounds write | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19158** | 7.5 | 0.29% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19159** | 7.5 | 0.29% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19160** | 3.1 | 0.31% | FALSE | Chrome | CWE-457 Uninitialized Use | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19161** | 3.1 | 0.26% | FALSE | Chrome | CWE-457 Uninitialized Use | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19162** | 8.8 | 0.37% | FALSE | Chrome | CWE-787 Out of bounds write | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19163** | 8.3 | 0.29% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19164** | 9.6 | 0.24% | FALSE | Chrome | CWE-20 Insufficient validation of untrusted input | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19165** | 7.5 | 0.26% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19166** | 9.6 | 0.29% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19167** | 3.1 | 0.29% | FALSE | Chrome | CWE-190 Integer overflow | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19168** | 8.8 | 0.46% | FALSE | Chrome | Inappropriate implementation | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19169** | 8.8 | 0.31% | FALSE | Chrome | CWE-20 Insufficient validation of untrusted input | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19170** | 9.6 | 0.33% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-19171** | 9.6 | 0.24% | FALSE | Chrome | CWE-416 Use after free | Problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Google Chrome vers la version 151.0.7922.108 (Windows/Linux) ou 151.0.7922.109 (Mac) ou supérieure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0978/) |
| **CVE-2026-45944** | 7.5 | 0.13% | FALSE | Linux | Multiples vulnérabilités du noyau Linux (élévation de privilèges, déni de service, atteinte à l'intégrité des données) | Un attaquant local ou distant pourrait élever ses privilèges pour obtenir un accès root, compromettre l'intégrité des données stockées sur le système, ou provoquer un déni de service rendant le système inopérant. La combinaison de ces vulnérabilités augmente significativement la surface d'attaque. | Theoretical | Mettre à jour le noyau Linux de Debian trixie vers la version 6.12.100-1 ou supérieure en suivant le bulletin de sécurité Debian msg00316. Redémarrer le système après l'application du correctif. Vérifier la version installée avec la commande 'uname -r'. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0981/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0981/)<br>[https://lists.debian.org/debian-security-announce/2026/msg00316.html](https://lists.debian.org/debian-security-announce/2026/msg00316.html) |
| **CVE-2022-49803** | N/A | 0.19% | FALSE | Linux | Multiples vulnérabilités du noyau Linux (élévation de privilèges, déni de service, atteinte à la confidentialité des données) | Un attaquant pourrait élever ses privilèges sur le système, accéder à des données confidentielles, ou provoquer un déni de service. Les versions LTS étant souvent déployées sur des infrastructures stables à long terme, l'impact peut être significatif si les correctifs ne sont pas appliqués rapidement. | Theoretical | Mettre à jour le noyau Linux : pour Debian 11 bullseye vers la version 5.10.262-1 ou supérieure, pour Debian 12 bookworm vers la version 6.1.180-1 ou supérieure. Suivre les bulletins de sécurité Debian LTS msg00007 et msg00008. Redémarrer le système après application. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0982/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0982/)<br>[https://lists.debian.org/debian-lts-announce/2026/08/msg00007.html](https://lists.debian.org/debian-lts-announce/2026/08/msg00007.html)<br>[https://lists.debian.org/debian-lts-announce/2026/08/msg00008.html](https://lists.debian.org/debian-lts-announce/2026/08/msg00008.html) |
| **CVE-2026-50540** | 9.6 | N/A | FALSE | kata-containers | CWE-20: Improper Input Validation | Un attaquant ayant la capacité de créer des pods avec des annotations personnalisées et de placer des fichiers sur l'hôte peut exécuter du code arbitraire sur la machine hôte, contournant complètement l'isolation du conteneur. Cela équivaut à une évasion de conteneur vers l'hôte avec exécution de code arbitraire, pouvant mener à une compromission totale du nœud et potentiellement du cluster Kubernetes entier. | Theoretical | Mettre à jour Kata Containers vers la version 4.0.0 ou supérieure. En attendant, bloquer l'annotation 'io[.]katacontainers[.]config_path' au niveau de l'admission Kubernetes via un ValidatingWebhook. Restreindre les utilisateurs autorisés à créer des pods avec des annotations personnalisées. Surveiller les pods utilisant cette annotation. | [https://cvefeed.io/vuln/detail/CVE-2026-50540](https://cvefeed.io/vuln/detail/CVE-2026-50540) |
| **CVE-2026-47664** | 8.6 | N/A | FALSE | pathling | CWE-20: Improper Input Validation | Un attaquant authentifié peut : (1) effectuer des requêtes SSRF vers des services internes non exposés, (2) détourner les credentials PNP configurés vers un serveur contrôlé par l'attaquant, entraînant une fuite d'identifiants, (3) empoisonner l'entrepôt de données avec des fichiers malveillants téléchargés depuis l'hôte de l'attaquant, compromettant l'intégrité des analyses de données de santé. | Theoretical | Mettre à jour Pathling Server vers la version 2.0.0 ou supérieure. En attendant, restreindre les exportUrl acceptées à une liste blanche de sources de confiance au niveau de la configuration ou d'un proxy inverse. Faire tourner les credentials PNP si une exploitation est suspectée. Surveiller les appels à l'opération '$import-pnp'. | [https://cvefeed.io/vuln/detail/CVE-2026-47664](https://cvefeed.io/vuln/detail/CVE-2026-47664) |
| **CVE-2026-47663** | 8.7 | N/A | FALSE | pathling | CWE-285: Improper Authorization | Exfiltration de données de santé (PHI) à l'échelle du serveur, mutation non autorisée de ressources FHIR, violation de la confidentialité et de l'intégrité des données cliniques. | Theoretical | Mettre à jour Pathling Server vers la version 2.0.0 ou ultérieure. Vérifier que toutes les autorités d'opération sont correctement associées aux autorités par ressource read/write correspondantes. S'assurer que les autorités par ressource sont effectivement appliquées. | [https[://]cvefeed.io/vuln/detail/CVE-2026-47663](https[://]cvefeed.io/vuln/detail/CVE-2026-47663)<br>[https[://]github.com/aehrc/pathling/security/advisories/GHSA-q62q-2m46-r7rv](https[://]github.com/aehrc/pathling/security/advisories/GHSA-q62q-2m46-r7rv)<br>[https://cvefeed.io/vuln/detail/CVE-2026-47663](https://cvefeed.io/vuln/detail/CVE-2026-47663) |
| **CVE-2026-47662** | 8.7 | N/A | FALSE | pathling | CWE-20: Improper Input Validation | Exfiltration de bearer tokens et de credentials OAuth client, empoisonnement persistant du warehouse de données, compromission de l'intégrité des données analytiques de santé. | Theoretical | Mettre à jour Pathling Server vers la version 2.0.0 ou ultérieure. Valider le paramètre oauthMetadataUrl de bulk-submit. Restreindre les sources de métadonnées OAuth autorisées. Réviser les credentials et accès des soumetteurs. | [https[://]cvefeed.io/vuln/detail/CVE-2026-47662](https[://]cvefeed.io/vuln/detail/CVE-2026-47662)<br>[https://cvefeed.io/vuln/detail/CVE-2026-47662](https://cvefeed.io/vuln/detail/CVE-2026-47662) |
| **CVE-2026-61808** | 9.8 | N/A | FALSE | LightRAG | CWE-306: Missing Authentication for Critical Function | Accès non authentifié complet à l'API LightRAG : lecture de documents indexés, modification du graphe de connaissances, suppression de données, consommation abusive de ressources LLM, compromission totale de l'intégrité et de la confidentialité du système. | Theoretical | Mettre à jour LightRAG vers la version 1.5.5rc1 ou ultérieure. Activer l'authentification pour l'API server. Restreindre l'accès réseau à l'API server. | [https[://]cvefeed.io/vuln/detail/CVE-2026-61808](https[://]cvefeed.io/vuln/detail/CVE-2026-61808)<br>[https[://]github.com/HKUDS/LightRAG/security/advisories/GHSA-mmg5-8x8q-v934](https[://]github.com/HKUDS/LightRAG/security/advisories/GHSA-mmg5-8x8q-v934)<br>[https[://]github.com/HKUDS/LightRAG/commit/0bd102401b4b28a02664e5b6af476bf7a4470292](https[://]github.com/HKUDS/LightRAG/commit/0bd102401b4b28a02664e5b6af476bf7a4470292)<br>[https://cvefeed.io/vuln/detail/CVE-2026-61808](https://cvefeed.io/vuln/detail/CVE-2026-61808) |
| **CVE-2026-48039** | 9.1 | N/A | FALSE | meta-ads-mcp | CWE-287: Improper Authentication | Fuite du jeton d'accès Meta de l'opérateur vers tout appelant réseau non authentifié, permettant l'usurpation de l'identité Meta et l'accès non autorisé aux comptes publicitaires et données associées. | Theoretical | Mettre à jour Meta Ads MCP vers la version 1.0.109 ou ultérieure. Réviser et valider les contrôles d'accès. Supprimer les tokens sensibles des journaux et réponses. | [https[://]cvefeed.io/vuln/detail/CVE-2026-48039](https[://]cvefeed.io/vuln/detail/CVE-2026-48039)<br>[https[://]github.com/pipeboard-co/meta-ads-mcp/security/advisories/GHSA-9gw6-46qc-99vr](https[://]github.com/pipeboard-co/meta-ads-mcp/security/advisories/GHSA-9gw6-46qc-99vr)<br>[https[://]github.com/pipeboard-co/meta-ads-mcp/releases/tag/1.0.109](https[://]github.com/pipeboard-co/meta-ads-mcp/releases/tag/1.0.109)<br>[https[://]github.com/pypa/advisory-database/tree/main/vulns/meta-ads-mcp/PYSEC-2026-413.yaml](https[://]github.com/pypa/advisory-database/tree/main/vulns/meta-ads-mcp/PYSEC-2026-413.yaml)<br>[https://cvefeed.io/vuln/detail/CVE-2026-48039](https://cvefeed.io/vuln/detail/CVE-2026-48039) |
| **CVE-2026-48007** | 8.6 | N/A | FALSE | element-call | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor | Fuite d'URLs complètes (incluant fragments) vers un serveur d'analytics tiers (PostHog), exposant potentiellement des informations sensibles telles que des identifiants de salle, des tokens ou des paramètres de session. | Theoretical | Mettre à jour Element Call vers une version corrigée. Reconfigurer ou désactiver l'intégration PostHog pour exclure les URLs complètes des données analytiques. Filtrer les fragments d'URL dans les payloads envoyés. | [https[://]cvefeed.io/vuln/detail/CVE-2026-48007](https[://]cvefeed.io/vuln/detail/CVE-2026-48007)<br>[https://cvefeed.io/vuln/detail/CVE-2026-48007](https://cvefeed.io/vuln/detail/CVE-2026-48007) |
| **CVE-2026-47661** | 8.7 | N/A | FALSE | pathling | CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Lecture arbitraire de fichiers du warehouse Pathling, exfiltration de données cliniques persistées, accès à des fichiers sensibles en dehors du répertoire de job autorisé. | Theoretical | Mettre à jour Pathling Server vers la version 2.0.0. Désactiver les opérations d'export asynchrone si la mise à jour n'est pas possible. Activer l'authentification et restreindre l'accès export aux appelants de confiance. | [https[://]cvefeed.io/vuln/detail/CVE-2026-47661](https[://]cvefeed.io/vuln/detail/CVE-2026-47661)<br>[https[://]github.com/aehrc/pathling/security/advisories/GHSA-8w85-f63v-3wh6](https[://]github.com/aehrc/pathling/security/advisories/GHSA-8w85-f63v-3wh6)<br>[https://cvefeed.io/vuln/detail/CVE-2026-47661](https://cvefeed.io/vuln/detail/CVE-2026-47661) |
| **CVE-2026-47660** | 8.7 | N/A | FALSE | pathling | CWE-522: Insufficiently Protected Credentials | Exfiltration de credentials OAuth client vers un serveur contrôlé par l'attaquant, permettant l'usurpation d'identité et l'accès non autorisé aux services OAuth dépendants. | Theoretical | Mettre à jour Pathling Server vers la version 2.0.0 ou ultérieure. Valider le paramètre oauthMetadataUrl de bulk-submit. Restreindre les sources de métadonnées OAuth autorisées. Réviser les credentials et accès des soumetteurs. | [https[://]cvefeed.io/vuln/detail/CVE-2026-47660](https[://]cvefeed.io/vuln/detail/CVE-2026-47660)<br>[https[://]github.com/aehrc/pathling/security/advisories/GHSA-245h-c573-9vr5](https[://]github.com/aehrc/pathling/security/advisories/GHSA-245h-c573-9vr5)<br>[https://cvefeed.io/vuln/detail/CVE-2026-47660](https://cvefeed.io/vuln/detail/CVE-2026-47660) |
| **CVE-2026-47659** | 8.7 | N/A | FALSE | pathling | CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Lecture arbitraire de fichiers du warehouse Pathling via path traversal, SSRF permettant l'accès à des ressources internes, exfiltration de données cliniques persistées. | Theoretical | Mettre à jour Pathling Server vers la version 2.0.0. Le gestionnaire $result résout et canonicalise désormais le chemin demandé et rejette toute requête s'échappant du répertoire jobs/<jobId>. Désactiver les opérations d'export asynchrone si la mise à jour n'est pas possible. Activer l'authentification et restreindre l'accès export aux appelants de confiance. | [https[://]cvefeed.io/vuln/detail/CVE-2026-47659](https[://]cvefeed.io/vuln/detail/CVE-2026-47659)<br>[https[://]github.com/aehrc/pathling/security/advisories/GHSA-5h9r-m7r5-8jxq](https[://]github.com/aehrc/pathling/security/advisories/GHSA-5h9r-m7r5-8jxq)<br>[https://cvefeed.io/vuln/detail/CVE-2026-47659](https://cvefeed.io/vuln/detail/CVE-2026-47659) |
| **CVE-2026-71851** | 9.0 | N/A | FALSE | crypto-js | CWE-331: Insufficient Entropy | Compromission totale des portefeuilles de cryptomonnaies utilisant crypto-js < 4.0.0 pour la génération de phrases de récupération BIP39. Un attaquant peut récupérer les clés privées et voler les fonds associés. La vulnérabilité est exploitable à distance. | Theoretical | Mettre à jour crypto-js vers la version 4.0.0 ou ultérieure. Régénérer toutes les clés privées et phrases de récupération créées avec des versions affectées. Vérifier que la génération d'aléa utilise une source cryptographiquement sûre (ex: crypto.getRandomValues). | [https://cvefeed.io/vuln/detail/CVE-2026-71851](https://cvefeed.io/vuln/detail/CVE-2026-71851) |
| **CVE-2026-71847** | 8.7 | N/A | FALSE | json | CWE-416: Use After Free | Déni de service : un attaquant non authentifié pouvant fournir des données JSON à une application utilisant JSON::ResumableParser peut provoquer le crash du processus Ruby via un heap-use-after-free. L'impact est limité à la disponibilité. | Theoretical | Mettre à jour la gem Ruby JSON vers la version 2.21.2. Éviter de parser des données JSON non fiables avec des clés dupliquées. Assurer une gestion mémoire correcte dans le parsing JSON. | [https://cvefeed.io/vuln/detail/CVE-2026-71847](https://cvefeed.io/vuln/detail/CVE-2026-71847) |
| **CVE-2026-64637** | 9.9 | N/A | FALSE | Plesk | CWE-269 Improper Privilege Management | Un revendeur authentifié peut obtenir un accès administratif complet (root) au serveur Plesk, compromettant l'ensemble du système et de tous les clients hébergés. L'attaquant obtient un contrôle total (confidentialité, intégrité, disponibilité). | None | Mettre à jour Plesk vers la version 18.0.80 ou ultérieure. S'assurer que les contrôles de session administrative sont correctement configurés. Restreindre l'accès à l'API XML-RPC aux adresses IP de confiance. | [https://cvefeed.io/vuln/detail/CVE-2026-64637](https://cvefeed.io/vuln/detail/CVE-2026-64637) |
| **CVE-2026-68772** | 8.5 | N/A | FALSE | ZenML | CWE-502 Deserialization of Untrusted Data | Exécution de code arbitraire à distance sur les systèmes exécutant des pipelines ZenML. Un attaquant avec accès en écriture à l'artifact store peut compromettre totalement l'environnement d'exécution ML, accéder aux données sensibles et pivoter vers d'autres systèmes. | Theoretical | Mettre à jour ZenML vers une version corrigée. Supprimer les fichiers pickle malveillants des artifact stores. Renforcer les contrôles d'accès aux artifact stores partagés. Sanitiser l'accès aux artifact stores. | [https://cvefeed.io/vuln/detail/CVE-2026-68772](https://cvefeed.io/vuln/detail/CVE-2026-68772) |
| **CVE-2026-67585** | 8.7 | N/A | FALSE | absinthe_federation | CWE-770 Allocation of Resources Without Limits or Throttling | Déni de service : un attaquant non authentifié peut provoquer l'arrêt complet du nœud BEAM. L'impact est limité à la disponibilité (aucune donnée lue ou altérée). La récupération nécessite le redémarrage de l'application. | Theoretical | Mettre à jour absinthe_federation vers la version 0.9.3 ou ultérieure. Appliquer les correctifs du fournisseur si disponibles. Surveiller l'utilisation de la table d'atomes BEAM. | [https://cvefeed.io/vuln/detail/CVE-2026-67585](https://cvefeed.io/vuln/detail/CVE-2026-67585) |
| **CVE-2026-18577** | 8.2 | 4.10% | TRUE | N-central | CWE-288 Authentication bypass using an alternate path or channel | Compromission totale du serveur N-central et de tous les systèmes gérés via celui-ci. Les attaquants obtiennent un accès administrateur non authentifié, peuvent déployer des tunnels Cloudflare pour la persistance, et pivoter vers les environnements clients des MSP. Exploitation active confirmée depuis le 31 juillet 2026. | Active | Installer la hotfix 2 de N-able N-central (même si la hotfix 1 était déjà installée). Vérifier l'absence de trafic vers Cloudflare Tunnel sur les systèmes gérés. Restreindre l'accès aux serveurs N-central aux adresses IP de confiance. Mettre les serveurs hors ligne si le patching immédiat est impossible. | [https://www.security.nl/posting/948432/N-able+komt+na+aanvallen+op+N-central+RMM-servers+met+tweede+hotfix?channel=rss](https://www.security.nl/posting/948432/N-able+komt+na+aanvallen+op+N-central+RMM-servers+met+tweede+hotfix?channel=rss) |
| **CVE-2026-18556** | 8.2 | 0.49% | TRUE | N-central | CWE-288 Authentication bypass using an alternate path or channel | Accès administrateur non authentifié au serveur N-central RMM, permettant la compromission de tous les systèmes gérés par les MSP via cette plateforme. | Active | S'assurer que les deux hotfix (1 et 2) sont installées sur tous les serveurs N-central. Restreindre l'accès aux adresses IP de confiance. Mettre les serveurs hors ligne si le patching immédiat est impossible. | [https://www.security.nl/posting/948432/N-able+komt+na+aanvallen+op+N-central+RMM-servers+met+tweede+hotfix?channel=rss](https://www.security.nl/posting/948432/N-able+komt+na+aanvallen+op+N-central+RMM-servers+met+tweede+hotfix?channel=rss) |
| **CVE-2026-64564** | 8.5 | 0.18% | FALSE | Linux | Use-After-Free / Élévation de privilèges locale / Échappement de conteneur (CWE-416) | Élévation de privilèges locale vers root et échappement de conteneur possible. Un attaquant local avec accès au protocole SCTP peut obtenir un contrôle total du système hôte. Le bogue existe depuis 18 ans dans tous les noyaux Linux publiés depuis 2008. | Theoretical | Mettre à jour le noyau Linux vers une version stable patchée (7.1.6, 6.18.42, 6.12.101, 6.6.148 ou ultérieure). Si SCTP n'est pas nécessaire, bloquer/désactiver le module pour supprimer la surface d'attaque. Vérifier le tracker de sa distribution car les correctifs peuvent être backportés sans changement de version amont. | [https://thehackernews.com/2026/08/18-year-old-linux-sctp-flaw-could-let.html](https://thehackernews.com/2026/08/18-year-old-linux-sctp-flaw-could-let.html) |
| **CVE-2026-63078** | N/A | N/A | FALSE | Apache Traffic Server (version spécifique non encore identifiée publiquement) | HTTP Desynchronization / Request Smuggling (désynchronisation HTTP) | Désynchronisation HTTP permettant le response queue poisoning (RQP), pouvant exposer les réponses d'autres utilisateurs incluant des cookies de session ou des clés API. Compromission potentielle de sessions et de données sensibles sur les infrastructures affectées. | Theoretical | Appliquer le correctif Apache Traffic Server dès identification de la version fixe. Éviter HTTP/1.1 en upstream. Si HTTP/1.1 est nécessaire, allow-lister les méthodes aux deux couches et restreindre les méthodes pouvant porter un corps de requête. Surveiller les patterns de requêtes malformées. | [https://thehackernews.com/2026/08/ai-assisted-http-terminator-finds-novel.html](https://thehackernews.com/2026/08/ai-assisted-http-terminator-finds-novel.html) |
| **CVE-2026-56181** | 8.3 | 0.24% | FALSE | Windows 11 Version 24H2, Windows 11 Version 25H2, Windows 11 version 26H1 | CWE-346: Origin Validation Error | Détournement de sessions TCP actives, usurpation de réponses DNS, exposition de ports mappés publiquement, et épuisement de la table NAT provoquant un déni de service. L'attaquant doit disposer d'un accès privilégié à un système derrière le même NAT que la victime, ce qui limite le vecteur d'attaque aux environnements multi-locataires ou aux postes compromis. | Theoretical | Appliquer les mises à jour Windows disponibles (builds ≥ 26100.8875 pour Win11 24H2, ≥ 26200.8875 pour 25H2, ≥ 28000.2525 pour 26H1, ≥ 26100.33158 pour Server 2025). Séparer les charges de travail non fiables des systèmes de confiance partageant la même infrastructure NAT. Chiffrer le trafic même au sein des réseaux internes. Activer IP Source Guard si applicable. Il n'existe pas de correctif unique pour la classe d'attaque NatJack dans son ensemble. | [https://thehackernews.com/2026/08/new-natjack-attacks-hijack-tcp-sessions.html](https://thehackernews.com/2026/08/new-natjack-attacks-hijack-tcp-sessions.html) |
| **CVE-2026-63913** | 8.2 | 0.62% | FALSE | Linux | Défaut de validation de direction dans la logique conntrack permettant la fermeture prématurée d'entrées NAT actives | Détournement de sessions TCP actives via remplacement de mappage NAT, usurpation de réponses DNS, exposition de ports mappés publiquement, et épuisement de la table conntrack provoquant un déni de service. L'attaquant doit disposer d'un accès privilégié à un système derrière le même NAT que la victime. | Theoretical | Mettre à jour le noyau Linux vers une version corrigée (5.10.259, 5.15.210, 6.1.176, 6.6.143, 6.12.93, 6.18.35, 7.0.12 ou 7.1). Séparer les charges de travail non fiables des systèmes de confiance. Chiffrer le trafic même en interne. Activer IP Source Guard si applicable. Le correctif atténue mais ne résout pas entièrement la classe d'attaque NatJack. | [https://thehackernews.com/2026/08/new-natjack-attacks-hijack-tcp-sessions.html](https://thehackernews.com/2026/08/new-natjack-attacks-hijack-tcp-sessions.html) |
| **CVE-2026-12537** | 10.0 | 0.15% | FALSE | Gemini CLI, run-gemini-cli GitHub Action | CWE-20 Improper Input Validation | Exécution de code arbitraire sur l'hôte CI avant le démarrage du sandbox, permettant à un attaquant sans privilèges sur le dépôt d'accéder aux secrets CI, aux credentials cloud, et de compromettre l'ensemble du pipeline CI/CD via une simple GitHub Issue. | None | Mettre à jour Gemini CLI vers 0.39.1 et run-gemini-cli vers 0.1.22. Auditer tous les workflows déclenchables par des utilisateurs externes. Considérer les fichiers d'instruction des agents comme des entrées non fiables. Désactiver le mode --yolo en production. | [https://thehackernews.com/2026/08/claude-code-and-gemini-cli-flaws-let.html](https://thehackernews.com/2026/08/claude-code-and-gemini-cli-flaws-let.html) |
| **CVE-2026-54316** | 6.0 | 0.40% | FALSE | claude-code | CWE-183: Permissive List of Allowed Inputs | Exfiltration de clés API et de secrets CI via un canal latéral discret (compteur de téléchargement Hugging Face), permettant à un attaquant sans privilèges sur le dépôt de compromettre des credentials sensibles via une simple GitHub Issue. | None | Mettre à jour Claude Code vers la version 2.1.163. Auditer tous les workflows déclenchables par des utilisateurs externes. Considérer les fichiers d'instruction des agents comme des entrées non fiables. Révoquer les clés API potentiellement exposées. | [https://thehackernews.com/2026/08/claude-code-and-gemini-cli-flaws-let.html](https://thehackernews.com/2026/08/claude-code-and-gemini-cli-flaws-let.html) |
| **CVE-2025-8088** | 8.4 | 94.55% | TRUE | WinRAR | CWE-35 Path traversal | Compromission complète du système via persistance dans le dossier Startup, conduisant à des attaques de cyberespionnage, de vol financier et de ransomware. Le groupe RomCom (lié à la Russie) exploite activement cette vulnérabilité. La difficulté de mise à jour de WinRAR en environnement d'entreprise crée une zone aveugle permanente dans la gestion des vulnérabilités. | Active | Mettre à jour WinRAR vers la version 7.13 ou supérieure sur tous les endpoints. Utiliser des outils tiers pour surveiller et forcer la mise à jour de WinRAR (pas de mise à jour automatique native). Sensibiliser les utilisateurs aux risques des archives provenant de sources non fiables. Déployer des règles EDR pour détecter les fichiers exécutables dans le dossier Startup. | [https://www.security.nl/posting/948359/WinRAR-lek+gebruikt+bij+ransomware-aanvallen%2C+meldt+Amerikaanse+overheid?channel=rss](https://www.security.nl/posting/948359/WinRAR-lek+gebruikt+bij+ransomware-aanvallen%2C+meldt+Amerikaanse+overheid?channel=rss) |
| **CVE-2026-20303** | 9.9 | 0.29% | FALSE | Cisco Catalyst SD-WAN Controller, Cisco Catalyst SD-WAN Manager | CWE-20 Improper Input Validation | Compromission potentielle des dispositifs SD-WAN occupant des positions privilégiées dans l'infrastructure IT, permettant potentiellement le détournement de trafic, l'interception de données ou l'accès à des segments réseau internes. | None | Appliquer les correctifs Cisco dans les versions 20.9.10, 20.12.8.1, 20.15.6, 20.18.4 ou 26.1.2 selon la version déployée. Aucun contournement n'est disponible. Restreindre l'accès de gestion aux dispositifs SD-WAN. | [https://fieldeffect.com/blog/cisco-patches-catalyst-sd-wan-ios-xe-flaws](https://fieldeffect.com/blog/cisco-patches-catalyst-sd-wan-ios-xe-flaws) |
| **CVE-2026-20304** | 9.9 | 0.25% | FALSE | Cisco Catalyst SD-WAN Controller, Cisco Catalyst SD-WAN Manager | CWE-284 Improper Access Control | Accès non autorisé aux dispositifs SD-WAN, permettant potentiellement la modification de configurations, l'interception de trafic ou l'accès à des segments réseau internes. | None | Appliquer les correctifs Cisco dans les versions 20.9.10, 20.12.8.1, 20.15.6, 20.18.4 ou 26.1.2. Aucun contournement n'est disponible. Renforcer les contrôles d'accès sur les dispositifs SD-WAN. | [https://fieldeffect.com/blog/cisco-patches-catalyst-sd-wan-ios-xe-flaws](https://fieldeffect.com/blog/cisco-patches-catalyst-sd-wan-ios-xe-flaws) |
| **CVE-2026-20310** | 9.1 | 0.37% | FALSE | Cisco Catalyst SD-WAN Controller, Cisco Catalyst SD-WAN Manager | CWE-59 Improper Link Resolution Before File Access ('Link Following') | Accès non autorisé à des fichiers sur les dispositifs SD-WAN, permettant potentiellement la lecture de configurations sensibles, l'exfiltration de données ou la modification de fichiers système. | None | Appliquer les correctifs Cisco dans les versions 20.9.10, 20.12.8.1, 20.15.6, 20.18.4 ou 26.1.2. Aucun contournement n'est disponible. Restreindre l'accès de gestion aux dispositifs SD-WAN. | [https://fieldeffect.com/blog/cisco-patches-catalyst-sd-wan-ios-xe-flaws](https://fieldeffect.com/blog/cisco-patches-catalyst-sd-wan-ios-xe-flaws) |
| **CVE-2026-20272** | 9.8 | 0.34% | FALSE | Cisco IOS XE Software | CWE-74 Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') | Exécution de commandes arbitraires sur les dispositifs IOS XE, permettant potentiellement la compromission complète du dispositif, l'interception de trafic, la modification de configurations ou l'accès à des segments réseau internes. | None | Appliquer les correctifs Cisco dans IOS XE 17.9.10, 17.12.8, 17.15.6, 17.18.4/17.18.4a ou 26.1.2. Aucun contournement n'est disponible. Désactiver les services de gestion non essentiels et restreindre l'accès de gestion. | [https://fieldeffect.com/blog/cisco-patches-catalyst-sd-wan-ios-xe-flaws](https://fieldeffect.com/blog/cisco-patches-catalyst-sd-wan-ios-xe-flaws) |
| **CVE-2026-20267** | 9.0 | 0.23% | FALSE | Cisco IOS XE Software | CWE-284 Improper Access Control | Accès non autorisé aux dispositifs IOS XE, permettant potentiellement la modification de configurations, l'interception de trafic ou l'accès à des segments réseau internes. | None | Appliquer les correctifs Cisco dans IOS XE 17.9.10, 17.12.8, 17.15.6, 17.18.4/17.18.4a ou 26.1.2. Aucun contournement n'est disponible. Renforcer les contrôles d'accès. | [https://fieldeffect.com/blog/cisco-patches-catalyst-sd-wan-ios-xe-flaws](https://fieldeffect.com/blog/cisco-patches-catalyst-sd-wan-ios-xe-flaws) |
| **CVE-2026-20200** | 8.8 | 0.84% | FALSE | Cisco Unified Computing System (Standalone) | CWE-141 Improper Neutralization of Parameter/Argument Delimiters | Exécution de commandes arbitraires en tant que root sur les serveurs UCS via l'interface web IMC, permettant la compromission complète du serveur au niveau matériel, la modification du firmware/BIOS, et l'accès à toutes les fonctions de gestion indépendamment de l'état du système d'exploitation. Un PoC public est disponible, augmentant le risque d'exploitation. | Theoretical | Appliquer les correctifs Cisco sur tous les IMC affectés. Restreindre l'accès réseau aux interfaces IMC (segmentation, ACL, VPN). Désactiver l'accès web si possible. Vérifier les comptes utilisateurs et appliquer le principe du moindre privilège. Surveiller activement les tentatives d'exploitation du PoC public. | [https://fieldeffect.com/blog/cisco-patches-catalyst-sd-wan-ios-xe-flaws](https://fieldeffect.com/blog/cisco-patches-catalyst-sd-wan-ios-xe-flaws) |
| **CVE-2026-20288** | 6.5 | 0.35% | FALSE | Cisco Unified Computing System (Standalone), Cisco Unified Computing System E-Series Software (UCSE) | CWE-146 Improper Neutralization of Expression/Command Delimiters | Exécution de commandes arbitraires en tant que root sur les serveurs UCS via l'interface web IMC par un utilisateur disposant de privilèges administrateur. L'impact est similaire à CVE-2026-20200 mais nécessite un niveau de privilège plus élevé. | None | Appliquer les correctifs Cisco sur tous les IMC affectés. Restreindre l'accès réseau et administrateur aux interfaces IMC. Surveiller les accès administrateur et les exécutions de commande. | [https://fieldeffect.com/blog/cisco-patches-catalyst-sd-wan-ios-xe-flaws](https://fieldeffect.com/blog/cisco-patches-catalyst-sd-wan-ios-xe-flaws) |
| **CVE-2025-3248** | 9.8 | 100.00% | TRUE | langflow | CWE-306 Missing Authentication for Critical Function | Exploitation active par des attaquants, permettant potentiellement l'exécution de code à distance, l'accès non autorisé aux données ou aux workflows, et la compromission de l'instance Langflow. La disponibilité d'un PoC public augmente le risque d'exploitation par des acteurs moins sophistiqués. | Active | Appliquer immédiatement les correctifs disponibles sur toutes les instances Langflow. Restreindre l'accès aux instances via segmentation réseau, authentification forte et WAF. Utiliser le template Nuclei d'Insikt Group pour identifier les instances vulnérables. Surveiller activement les tentatives d'exploitation. | [https://www.recordedfuture.com/blog/july-2026-cve-landscape](https://www.recordedfuture.com/blog/july-2026-cve-landscape) |
| **** | N/A | N/A | FALSE | Noyau Linux de Red Hat Enterprise Linux (RHEL 8, 9, 10 et variantes Extended Update Support) sur architectures x86_64, aarch64, s390x, ppc64le | Multiples vulnérabilités du noyau Linux (élévation de privilèges, exécution de code arbitraire, déni de service à distance, contournement de politique de sécurité, atteinte à la confidentialité) | Un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, contourner les politiques de sécurité, provoquer un déni de service à distance ou accéder à des données confidentielles. La vaste gamme de produits et d'architectures affectés augmente considérablement la surface d'attaque. | Theoretical | Appliquer les 16 bulletins RHSA publiés par Red Hat. Utiliser 'dnf update' ou 'yum update' pour installer les correctifs. Redémarrer les systèmes après mise à jour du noyau. Vérifier avec 'uname -r' que la version patchée est active. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0983/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0983/) |
| **** | N/A | N/A | FALSE | SUSE Linux Micro 6.2 (noyau Linux) | Multiples vulnérabilités du noyau Linux (contournement de politique de sécurité, problème de sécurité non spécifié) | Un attaquant pourrait contourner les politiques de sécurité en place sur le système, potentiellement accéder à des ressources restreintes, ou provoquer d'autres problèmes de sécurité non détaillés par l'éditeur. | Theoretical | Appliquer les 19 bulletins de sécurité SUSE via 'zypper update' ou 'zypper patch'. Redémarrer le système après mise à jour du noyau. Vérifier la version installée avec 'uname -r'. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0984/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0984/)<br>[https://www.suse.com/support/update/announcement/2026/suse-su-202622972-1](https://www.suse.com/support/update/announcement/2026/suse-su-202622972-1)<br>[https://www.suse.com/support/update/announcement/2026/suse-su-202622973-1](https://www.suse.com/support/update/announcement/2026/suse-su-202622973-1)<br>[https://www.suse.com/support/update/announcement/2026/suse-su-202622974-1](https://www.suse.com/support/update/announcement/2026/suse-su-202622974-1)<br>[https://www.suse.com/support/update/announcement/2026/suse-su-202622975-1](https://www.suse.com/support/update/announcement/2026/suse-su-202622975-1) |
| **** | N/A | N/A | FALSE | Noyau Linux d'Ubuntu | Multiples vulnérabilités du noyau Linux (détails non disponibles dans la source) | Impact non déterminé en raison du manque de détails dans la source. Les vulnérabilités du noyau Linux peuvent typiquement permettre une élévation de privilèges, un déni de service ou une atteinte à la confidentialité. | Theoretical | Consulter l'avis complet sur le site du CERT-FR et appliquer les correctifs Ubuntu dès leur disponibilité via 'apt update && apt upgrade'. Redémarrer le système après mise à jour du noyau. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0985/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0985/) |
| **** | N/A | N/A | FALSE | Produits IBM (multiples produits, détails non spécifiés) | Multiples vulnérabilités dans les produits IBM (types non spécifiés) | Impact non déterminé en raison du manque de détails sur les produits et vulnérabilités spécifiques. Les vulnérabilités IBM peuvent affecter divers produits middleware, serveurs d'applications, bases de données et solutions d'infrastructure. | Theoretical | Consulter les 34 bulletins de sécurité IBM référencés et appliquer les correctifs correspondants. Vérifier les configurations de sécurité des produits IBM. Suivre les recommandations du CERT-FR. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0986/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0986/) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="firewallfalcon-manager-porte-derobee-de-chaine-dapprovisionnement-dans-linfrastructure-vpn-underground"></div>

## FirewallFalcon Manager : porte dérobée de chaîne d'approvisionnement dans l'infrastructure VPN underground

### Résumé

FirewallFalcon Manager est présenté comme un outil open-source gratuit de gestion de serveurs Linux pour services VPN et proxy. En réalité, il dissimule une attaque multi-couches : une attaque Man-in-the-Middle via le serveur C2 de l'attaquant, un détournement DNS, une porte dérobée codée en dur installée avec privilèges sudo dans un dropper binaire obfusqué par SHC, et un bot Telegram de reconnaissance et exfiltration de credentials (versions antérieures). La cible est les revendeurs VPN et les acteurs de menace qui provisionnent des serveurs Linux compromis ou loués. L'outil usurpe l'identité du service proxy brésilien légitime DTunnel. Au moins 650 serveurs distincts sont directement liés à l'infrastructure de l'attaquant. Deux groupes Telegram totalisent près de 5 000 membres.

---

### Analyse opérationnelle

Les équipes SOC doivent surveiller les serveurs Linux exécutant des services VPN/proxy pour détecter des communications inattendues vers des serveurs C2, des modifications DNS non autorisées, et la présence de binaires SHC-obfusqués. La détection du bot Telegram nécessite de monitorer les connexions vers l'API Telegram depuis des serveurs d'infrastructure. Les credentials SSH stockés sur ces serveurs doivent être considérés comme compromis. La surface d'attaque s'étend à l'ensemble de l'infrastructure VPN gérée via cet outil. Les équipes doivent corréler les installations de paquets provenant de dépôts GitHub suspects avec des comportements anormaux réseau.

---

### Implications stratégiques

Cette campagne illustre la menace croissante de compromission de la chaîne d'approvisionnement dans l'écosystème cybercriminel lui-même : les outils utilisés par les acteurs de menace peuvent être instrumentalisés par d'autres acteurs. Les organisations utilisant des services VPN underground ou des proxy reselling sont exposées à une perte de contrôle totale de leur infrastructure. La confiance accordée aux outils open-source distribués via Telegram et GitHub doit être remise en question. Cette tendance souligne l'importance de l'attribution et du suivi des infrastructures criminelles pour les équipes CTI.

---

### Recommandations

* Auditer tous les serveurs Linux de l'organisation pour détecter la présence de FirewallFalcon Manager
* Implémenter une supervision DNS pour identifier tout détournement vers des serveurs non autorisés
* Bloquer les communications vers l'API Telegram depuis les serveurs d'infrastructure
* Révoquer et réinitialiser tous les credentials SSH sur les serveurs potentiellement affectés
* Sensibiliser les équipes à la risque d'outils open-source distribués via des canaux non officiels (Telegram, forums underground)

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier tous les serveurs Linux utilisés pour des services VPN/proxy et vérifier s'ils utilisent FirewallFalcon Manager
* Mettre en place une supervision des flux DNS sortants pour détecter un détournement vers des serveurs non autorisés
* Préparer des règles YARA pour détecter les binaires SHC-obfusqués et les indicateurs du dropper FirewallFalcon

#### Phase 2 — Détection et analyse

* Surveiller les connexions sortantes vers des serveurs C2 inconnus depuis les serveurs VPN/proxy
* Détecter les modifications de configuration DNS inattendues sur les serveurs Linux
* Rechercher la présence de bots Telegram ou de processus communiquant avec l'API Telegram
* Corréler les logs d'installation de paquets avec l'origine GitHub de FirewallFalcon

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les serveurs compromis identifiés (au moins 650 serveurs live référencés)
* Bloquer les adresses IP et domaines C2 identifiés dans l'analyse technique de Flare
* Révoquer tous les credentials SSH et clés stockés sur les serveurs compromis
* Désinstaller FirewallFalcon Manager et restaurer les configurations DNS d'origine

#### Phase 4 — Activités post-incident

* Effectuer une analyse forensique complète pour identifier les credentials exfiltrés via le bot Telegram
* Réinitialiser tous les credentials et clés SSH sur l'infrastructure affectée
* Auditer l'ensemble des dépendances open-source installées sur les serveurs de l'organisation
* Documenter la chaîne d'attaque et partager les IOCs avec les communautés CTI

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des binaires obfusqués SHC sur l'ensemble du parc Linux
* Chasser les processus utilisant l'API Telegram pour des communications inattendues
* Identifier d'autres outils de gestion VPN/proxy potentiellement compromis dans l'écosystème underground
* Surveiller les groupes Telegram promouvant des outils de gestion de serveurs VPN gratuits

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1557.001** | Adversary-in-the-Middle – hijack du trafic via le serveur C2 de l'attaquant |
| **T1565.002** | Transmitted Data Manipulation – détournement DNS |
| **T1071.001** | Web Protocols – routage du trafic API vers un serveur contrôlé par l'attaquant |
| **T1059.004** | Unix Shell – dropper binaire obfusqué par SHC |
| **T1005** | Data from Local System – découverte et exfiltration de credentials |
| **T1567.002** | Exfiltration to Cloud Storage – exfiltration via bot Telegram |

---

### Sources

* [https://flare.io/learn/resources/blog/firewallfalcon-manager-supply-chain-backdoor](https://flare.io/learn/resources/blog/firewallfalcon-manager-supply-chain-backdoor)


---

<div id="bug-icmp-timestamp-dans-windows-tcpipsys-contournement-du-registre-enableicmptimestamprep0-et-violation-rfc-792"></div>

## Bug ICMP Timestamp dans Windows tcpip.sys : contournement du registre EnableICMPTimestampRep=0 et violation RFC 792

### Résumé

Une vulnérabilité dans le pilote Windows tcpip.sys permet de contourner le paramètre de registre EnableICMPTimestampRep=0, qui est censé désactiver les réponses ICMP Timestamp. Le système continue de répondre aux requêtes ICMP Timestamp malgré cette configuration, en violation de la RFC 792. Cette faille au niveau kernel permet potentiellement le fingerprinting et l'énumération de systèmes Windows.

---

### Analyse opérationnelle

Les équipes SOC doivent être conscientes que les systèmes Windows configurés avec EnableICMPTimestampRep=0 peuvent toujours répondre aux requêtes ICMP Timestamp, exposant des informations sur le système. Les règles de détection réseau doivent surveiller les paquets ICMP Timestamp entrants et sortants. Les pare-feu périmétriques doivent filtrer explicitement ce type de paquets ICMP. Cette faille peut être exploitée pour le fingerprinting OS et la reconnaissance réseau pré-exploitation.

---

### Implications stratégiques

Cette vulnérabilité souligne que les mécanismes de durcissement Windows au niveau registre ne sont pas toujours fiables. Les organisations reposant sur EnableICMPTimestampRep=0 pour réduire leur surface d'attaque ont un faux sentiment de sécurité. Microsoft doit corriger la conformité de sa pile réseau avec la RFC 792. Cette faille peut faciliter la reconnaissance par des acteurs de menace avant des attaques ciblées.

---

### Recommandations

* Filtrer les paquets ICMP Timestamp au niveau des pare-feu périmétriques plutôt que de reposer uniquement sur le paramètre registre
* Surveiller les requêtes ICMP Timestamp anormales dans le trafic réseau
* Suivre les correctifs Microsoft pour tcpip.sys et les appliquer dès leur disponibilité

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les systèmes Windows exposés à Internet et vérifier la configuration EnableICMPTimestampRep
* Maintenir à jour le patching du composant tcpip.sys sur tous les postes et serveurs Windows
* Documenter la configuration de base des paramètres ICMP au niveau registre pour comparaison future

#### Phase 2 — Détection et analyse

* Surveiller les paquets ICMP Timestamp reçus sur les systèmes où EnableICMPTimestampRep=0
* Détecter les modifications du registre liées aux paramètres ICMP sur les systèmes Windows
* Corréler les logs de pare-feu avec les réponses ICMP Timestamp inattendues

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les paquets ICMP Timestamp entrants au niveau des pare-feu périmétriques
* Appliquer les correctifs Microsoft dès qu'ils sont disponibles pour tcpip.sys
* Isoler les systèmes présentant un comportement ICMP anormal

#### Phase 4 — Activités post-incident

* Analyser les logs réseau pour identifier toute exploitation antérieure de ce bug
* Vérifier l'intégrité des systèmes ayant reçu des paquets ICMP Timestamp suspects
* Documenter l'incident et mettre à jour les règles de détection réseau

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des traces de paquets ICMP Timestamp dans les captures réseau historiques
* Identifier les systèmes Windows avec EnableICMPTimestampRep=0 qui auraient pu répondre malgré la configuration
* Surveiller les outils de scan réseau utilisant ICMP Timestamp pour le fingerprinting

---

### Sources

* [https://www.reddit.com/r/redteamsec/comments/1vif260/windows_tcpipsys_icmp_timestamp_bug/](https://www.reddit.com/r/redteamsec/comments/1vif260/windows_tcpipsys_icmp_timestamp_bug/)


---

<div id="sift-outil-open-source-de-detection-de-credentials-sur-partages-de-fichiers-avec-file-de-revision"></div>

## Sift : outil open-source de détection de credentials sur partages de fichiers avec file de révision

### Résumé

Sift est un outil open-source de détection de credentials exposés sur les partages de fichiers, inspiré de Snaffler. Il combine la détection automatique de secrets avec une file de révision permettant aux analystes de valider les findings et de générer de nouvelles règles de détection à partir de leurs découvertes.

---

### Analyse opérationnelle

Sift peut être intégré dans les workflows SecOps pour automatiser la découverte de credentials exposés sur les partages de fichiers SMB/NFS. La file de révision permet d'affiner progressivement les règles de détection et de réduire les faux positifs. Les équipes SOC peuvent l'utiliser pour des audits réguliers de la surface d'exposition de credentials, complétant les outils DLP traditionnels. L'approche itérative (findings → règles) améliore la couverture au fil du temps.

---

### Implications stratégiques

L'exposition de credentials sur des partages de fichiers est un vecteur d'attaque majeur exploité par les acteurs de menace lors de mouvements latéraux. La disponibilité d'outils open-source comme Sift démocratise la détection proactive de cette surface d'attaque. Les organisations doivent intégrer ce type de scan dans leur gouvernance des identités et des accès pour réduire le risque de compromission via des credentials négligemment stockés.

---

### Recommandations

* Déployer Sift pour des scans réguliers des partages de fichiers de l'organisation
* Intégrer les findings dans le processus de rotation de credentials
* Former les équipes à la création de règles de détection personnalisées à partir de la file de révision

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer Sift sur les environnements de test pour évaluer sa couverture de détection de credentials
* Identifier les partages de fichiers sensibles prioritaires pour l'analyse
* Former les équipes SecOps à l'utilisation de l'outil et à la gestion de la file de révision

#### Phase 2 — Détection et analyse

* Exécuter Sift sur les partages de fichiers pour identifier les credentials exposés (mots de passe, clés API, tokens)
* Utiliser la file de révision pour valider les findings et générer de nouvelles règles de détection
* Corréler les credentials découverts avec les comptes Active Directory et les dépôts de secrets

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement les credentials identifiés comme exposés sur les partages de fichiers
* Restreindre les permissions d'accès aux partages contenant des credentials sensibles
* Déplacer les fichiers contenant des secrets vers des coffres-forts sécurisés

#### Phase 4 — Activités post-incident

* Documenter les credentials exposés et leur impact potentiel
* Mettre à jour les politiques de gestion des secrets pour interdire le stockage sur partages
* Intégrer Sift dans les processus d'audit régulier des partages de fichiers

#### Phase 5 — Threat Hunting (proactif)

* Utiliser Sift pour des scans périodiques de l'ensemble des partages de fichiers de l'organisation
* Rechercher des patterns de credentials correspondant aux conventions de nommage internes
* Surveiller l'apparition de nouveaux fichiers contenant des credentials sur les partages

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1552.001** | Credentials In Files – détection de credentials exposés sur les partages de fichiers |

---

### Sources

* [https://www.reddit.com/r/redteamsec/comments/1vhplgh/sift_opensource_credential_sleuth_for_file_shares/](https://www.reddit.com/r/redteamsec/comments/1vhplgh/sift_opensource_credential_sleuth_for_file_shares/)


---

<div id="attaque-de-chaine-dapprovisionnement-npm-compromission-des-packages-keyv-et-cacheable-via-takeover-de-compte-mainteneur"></div>

## Attaque de chaîne d'approvisionnement npm : compromission des packages keyv et cacheable via takeover de compte mainteneur

### Résumé

L'équipe de recherche de menaces de Socket a suivi une attaque active de chaîne d'approvisionnement qui a compromis un compte de mainteneur pour pousser des malwares via les packages npm largement utilisés keyv et cacheable, puis s'est propagée à d'autres mainteneurs via des tokens npm volés. Ces packages sont profondément intégrés dans les arbres de dépendances et totalisent des dizaines de millions de téléchargements hebdomadaires. Une campagne d'ingénierie sociale coordonnée a également ciblé des mainteneurs Node.js à fort impact plus tôt dans l'année. Des attaques pilotées par l'IA émergent, utilisant des agents qui social-engineer leur chemin vers des merges malveillants ou construisent patiemment un historique de contributions pour gagner la confiance d'un mainteneur. Socket annonce une mise à niveau gratuite vers son plan Business pour les projets open-source.

---

### Analyse opérationnelle

Les équipes SOC et DevSecOps doivent immédiatement vérifier la présence des packages keyv et cacheable dans leurs arbres de dépendances et épingler des versions sûres. Les tokens npm doivent être révoqués et réémis. Les pipelines CI/CD doivent intégrer un scanning automatique des dépendances avec blocage des packages malveillants. La détection des comportements anormaux dans les publications npm (nouvelles versions inattendues, nouveaux mainteneurs ajoutés) doit être mise en place. L'analyse de reachability permet de prioriser les vulnérabilités exploitables dans la chaîne de dépendances.

---

### Implications stratégiques

Les attaques de chaîne d'approvisionnement open-source s'accélèrent et ciblent désormais directement les mainteneurs humains, dernier rempart de la confiance dans l'écosystème logiciel. L'émergence d'agents IA capables de construire un historique de contributions légitimes pour infiltrer des projets open-source représente une évolution majeure du paysage de menace. Les organisations dépendant massivement de l'open-source doivent investir dans des outils de défense automatisés et repenser leur modèle de confiance vis-à-vis des dépendances transitives. Le fardeau de sécurité qui pèse sur des mainteneurs bénévoles est devenu un risque systémique.

---

### Recommandations

* Vérifier immédiatement la présence et la version des packages keyv et cacheable dans tous les projets
* Révoquer et réémettre tous les tokens npm de l'organisation
* Déployer une solution de scanning de dépendances avec blocage automatique dans les pipelines CI/CD
* Épingler les versions des dépendances critiques et exiger une revue manuelle pour toute mise à jour
* Sensibiliser les développeurs aux risques d'ingénierie sociale ciblant les mainteneurs open-source

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier toutes les dépendances npm dans les projets de l'organisation, en identifiant keyv et cacheable
* Mettre en place une solution de scanning des dépendances (type Socket) pour bloquer les packages malveillants
* Activer la vérification des signatures et l'analyse de reachability dans le pipeline CI/CD

#### Phase 2 — Détection et analyse

* Vérifier la présence des packages keyv et cacheable dans les arbres de dépendances et leur version
* Surveiller les mises à jour inattendues de packages npm dans les pipelines CI/CD
* Détecter les tokens npm compromis en surveillant les publications non autorisées

#### Phase 3 — Confinement, éradication et récupération

* Épingler (pin) les versions des packages affectés à des versions antérieures connues comme sûres
* Révoquer tous les tokens npm de l'organisation et des mainteneurs
* Isoler les systèmes ayant exécuté les versions malveillantes de keyv ou cacheable

#### Phase 4 — Activités post-incident

* Analyser les packages malveillants pour identifier les charges utiles et les comportements
* Auditer l'ensemble de l'arbre de dépendances pour identifier d'autres packages compromis par propagation
* Mettre en place un processus de revue obligatoire pour les mises à jour de dépendances critiques

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des indicateurs de compromission liés aux versions malveillantes de keyv et cacheable dans les environnements de build
* Surveiller les nouvelles publications de packages par les mainteneurs affectés
* Identifier d'autres packages npm potentiellement compromis via des tokens volés

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1195.002** | Compromise Software Supply Chain – compromission de packages npm via takeover de compte mainteneur |
| **T1556** | Modify Authentication Process – vol de tokens npm pour propagation latérale |
| **T1566** | Phishing – campagne d'ingénierie sociale ciblant les mainteneurs Node.js |

---

### Sources

* [https://socket.dev/blog/free-business-plan-upgrades-for-open-source-maintainers](https://socket.dev/blog/free-business-plan-upgrades-for-open-source-maintainers)


---

<div id="compromission-du-compte-tmc-metro-jaya-police-indonesienne-pour-promouvoir-une-arnaque-crypto"></div>

## Compromission du compte TMC Metro Jaya (police indonésienne) pour promouvoir une arnaque crypto

### Résumé

Le compte de la division TMC Metro Jaya, une unité de police indonésienne chargée de la surveillance du trafic routier, a été piraté pour promouvoir une arnaque cryptomonnaie. Au moment de la publication, le compte n'avait pas encore été récupéré.

---

### Analyse opérationnelle

Les équipes SOC doivent surveiller les comptes de réseaux sociaux officiels de leur organisation pour détecter des publications malveillantes. L'authentification multi-facteurs doit être imposée sur tous les comptes officiels. Un processus de récupération rapide de compte doit être défini avec les plateformes (X, Instagram, etc.). La détection d'activité anormale (publications hors horaires, contenu non conforme à la ligne éditoriale) doit être automatisée.

---

### Implications stratégiques

La compromission de comptes officiels d'institutions gouvernementales pour promouvoir des arnaques crypto exploite la crédibilité de l'entité usurpée et porte atteinte à sa réputation. Cette tendance souligne l'importance de la sécurité des comptes de réseaux sociaux comme composante de la cybersécurité organisationnelle. Les institutions publiques sont des cibles privilégiées en raison de leur forte visibilité et de la confiance du public.

---

### Recommandations

* Imposer l'authentification multi-facteurs sur tous les comptes de réseaux sociaux officiels
* Définir un processus de réponse d'urgence en cas de compromission de compte
* Surveiller en continu l'activité des comptes officiels pour détecter les publications malveillantes
* Sensibiliser le public aux risques d'arnaqus utilisant des comptes officiels compromis

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser les comptes de réseaux sociaux officiels de l'organisation et leurs administrateurs
* Mettre en place l'authentification multi-facteurs sur tous les comptes de réseaux sociaux officiels
* Définir un processus de réponse rapide en cas de compromission de compte officiel

#### Phase 2 — Détection et analyse

* Surveiller les publications inhabituelles sur les comptes de réseaux sociaux officiels
* Mettre en place des alertes sur les changements de mot de passe ou de sessions actives
* Détecter les publications faisant la promotion de cryptomonnaies ou de scams depuis des comptes officiels

#### Phase 3 — Confinement, éradication et récupération

* Récupérer immédiatement le contrôle du compte compromis via les procédures de la plateforme
* Supprimer les publications malveillantes et publier un avis de compromission
* Révoquer toutes les sessions actives et réinitialiser les credentials du compte

#### Phase 4 — Activités post-incident

* Analyser la méthode de compromission (phishing, credential stuffing, insider)
* Évaluer l'impact sur la réputation de l'organisation et le nombre de victimes du scam
* Renforcer les mesures de sécurité du compte (MFA, monitoring, accès restreint)

#### Phase 5 — Threat Hunting (proactif)

* Rechercher d'autres comptes officiels potentiellement ciblés par le même acteur
* Surveiller les plateformes de réseaux sociaux pour des impersonations de comptes officiels
* Identifier les campagnes de scams crypto utilisant des comptes compromis d'entités gouvernementales

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1656** | Impersonation – utilisation d'un compte officiel compromis pour promouvoir une arnaque crypto |

---

### Sources

* [https://infosec.exchange/@AmmarSpaces/117056657728329076](https://infosec.exchange/@AmmarSpaces/117056657728329076)


---

<div id="remplacement-silencieux-dexecutables-dapplications-macos-de-confiance"></div>

## Remplacement silencieux d'exécutables d'applications macOS de confiance

### Résumé

Des chercheurs en sécurité de Mysk ont découvert un comportement macOS permettant à un attaquant ayant déjà une exécution de code en tant qu'utilisateur courant de remplacer silencieusement l'exécutable principal de certaines applications installées. L'application modifiée peut toujours se lancer normalement et apparaître comme légitime. Le problème affecte les applications téléchargées depuis le web (Signal, Brave, Cursor, Slack, VS Code, Xcode, etc.) après leur premier lancement. Le remplacement malveillant peut déclencher des invites de permission macOS légitimes affichant le nom et l'icône de l'application de confiance, pouvant tromper l'utilisateur en lui accordant l'accès à des données sensibles (Keychain, fichiers protégés). Apple a évalué que ce comportement ne nécessite pas de correctif de sécurité, car l'attaque ne contourne pas Gatekeeper ou TCC et nécessite une exécution de code préalable.

---

### Analyse opérationnelle

Les équipes SOC doivent surveiller les modifications des bundles d'applications (.app) sur les postes macOS, en particulier les exécutables principaux. Les outils EDR doivent être configurés pour alerter sur les changements de hash des exécutables d'applications de confiance. Les demandes de permissions TCC (Keychain, fichiers protégés) provenant d'applications déjà lancées doivent être corréllées avec les modifications de bundles. La détection post-exploitation est essentielle car cette technique nécessite un accès initial. Les équipes doivent réévaluer leur modèle de confiance vis-à-vis des applications téléchargées hors App Store.

---

### Implications stratégiques

La décision d'Apple de ne pas corriger cette faille soulève des questions sur le modèle de sécurité macOS et la confiance accordée aux signatures de code. Les organisations utilisant massivement des applications macOS téléchargées depuis le web (Signal, Slack, VS Code) sont exposées à un risque de persistance et d'élévation de privilèges post-compromission. Cette faille démontre que la sécurité ne repose pas uniquement sur le bypass de protections mais aussi sur l'exploitation de la confiance utilisateur. Les équipes de sécurité doivent plaider pour une revalidation des signatures de code lors des modifications de bundles d'applications.

---

### Recommandations

* Déployer des outils EDR macOS capables de détecter les modifications d'exécutables d'applications
* Surveiller les demandes de permissions TCC inhabituelles depuis des applications de confiance
* Privilégier les applications distribuées via le Mac App Store lorsque possible
* Mettre en place une surveillance des modifications de bundles .app sur le parc macOS
* Documenter et remonter à Apple la nécessité d'une revalidation des signatures de code lors des modifications de bundles

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les applications macOS téléchargées depuis le web (hors App Store) sur le parc de l'organisation
* Mettre en place des outils EDR capables de détecter la modification d'exécutables d'applications
* Documenter les empreintes de code signature des applications de confiance pour comparaison future

#### Phase 2 — Détection et analyse

* Surveiller les modifications du bundle d'applications (.app) sur les postes macOS
* Détecter les changements de hash des exécutables principaux des applications de confiance
* Alerte sur les nouvelles demandes de permissions TCC (Keychain, fichiers protégés) depuis des applications déjà lancées

#### Phase 3 — Confinement, éradication et récupération

* Isoler les postes macOS où une modification d'exécutable d'application a été détectée
* Réinstaller les applications affectées depuis une source de confiance
* Révoquer les permissions TCC accordées aux applications potentiellement remplacées

#### Phase 4 — Activités post-incident

* Analyser l'exécutable remplacé pour identifier le code malveillant injecté
* Vérifier si des données sensibles (Keychain, fichiers protégés) ont été exfiltrées
* Mettre en place une surveillance renforcée des modifications de bundles d'applications

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des modifications d'exécutables d'applications sur l'ensemble du parc macOS
* Identifier les applications dont la signature de code ne correspond plus à l'originale
* Surveiller les demandes de permissions TCC inhabituelles depuis des applications de confiance

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1574** | Hijack Execution Flow – remplacement de l'exécutable principal d'une application de confiance |
| **T1553.002** | Code Signing – exploitation de la confiance accordée à la signature d'origine |

---

### Sources

* [https://c.im/@psoheil/117056524991286488](https://c.im/@psoheil/117056524991286488)
* [https://mysk.blog/2026/07/23/macos-overwrite-app-executables/](https://mysk.blog/2026/07/23/macos-overwrite-app-executables/)


---

<div id="backdoor-endlessdoors-dans-les-routeurs-zbtlink-shells-root-non-authentifies"></div>

## Backdoor ENDLESSDOORS dans les routeurs Zbtlink : shells root non authentifiés

### Résumé

VulnCheck a découvert qu'au moins 20 modèles de routeurs fabriqués par Shenzhen Zhibotong Electronics (marque Zbtlink/ZBT/Wiflyer) embarquent un implant backdoor nommé ENDLESSDOORS, basé sur l'outil open-source rctl (remote control linux). Cet implant, démarré au boot via un script init.d nommé skworker, se déguise en processus kworker (thread kernel Linux) et contacte un serveur C2 toutes les 35 secondes environ. Le protocole C2 est trivial : un paquet de 39 bytes (label de classe + MAC LAN), puis toute commande reçue est exécutée via popen() en root sans aucune authentification. Une commande spéciale 'rctlbash' ouvre un shell root interactif sur le port 7001. Les endpoints C2 identifiés sont zbtctl[.]epplink[.]net (47.100.190.96, Alibaba Cloud Shanghai), 47.107.224.89 (Alibaba Cloud Shenzhen), online-string[.]com (45.32.81.152, Vultr) et rbdg4nzqadui[.]wikaba[.]com (43.248.136.125). VulnCheck a attribué CVE-2026-66747. Aucun firmware corrigé n'existe. VulnCheck n'a pas notifié Zbtlink car la backdoor est intentionnellement intégrée par le fabricant.

---

### Analyse opérationnelle

L'implant ENDLESSDOORS contourne NAT et pare-feu car il initie des connexions sortantes vers le port 7000/TCP. Aucun port d'écoute n'est exposé, rendant la détection par scan inbound impossible. Les défenseurs doivent : (1) bloquer et alerter sur les 4 endpoints C2 au niveau egress et DNS ; (2) surveiller le trafic sortant sur ports 7000/7001 depuis les segments d'infrastructure réseau ; (3) vérifier la liste des processus sur les routeurs (kworker non entre crochets avec VSZ non nul = implant) ; (4) inspecter le système de fichiers pour /usr/sbin/kworker, /usr/lib/librctl.so, /etc/kworker.cfg, /etc/init.d/skworker. Des règles Suricata, Snort et YARA sont publiées par VulnCheck. Le risque est élevé car toute personne contrôlant la résolution DNS du domaine C2 peut prendre le contrôle de tous les implants. Les routeurs OEM/ODM rebadgés par d'autres marques sont également affectés.

---

### Implications stratégiques

Cette découverte soulève des questions critiques sur la sécurité de la chaîne d'approvisionnement IoT, en particulier pour les équipements réseau fabriqués en Chine et vendus sous multiples marques. Les routeurs Zbtlink sont vendus via Amazon, Alibaba, Shopify et en marque blanche OEM/ODM, rendant l'inventaire du parc affecté extrêmement difficile. Le secteur hôtelier, les filiales d'entreprise, les flottes véhicules et les sites distants utilisant ces CPE cellulaires sont particulièrement exposés. L'absence de firmware corrigé signifie que la seule mitigation fiable est le remplacement matériel. Cet incident illustre le risque systémique de backdoors matérielles dans l'IoT grand public et professionnel, et la nécessité de politiques d'approvisionnement sécurisé pour les équipements réseau.

---

### Recommandations

* Inventorier tous les routeurs par numéro de modèle (pas par marque) contre la liste des 20 modèles affectés
* Bloquer et alerter sur les 4 endpoints C2 au niveau egress et résolveur DNS
* Déployer les règles Suricata/Snort/YARA publiées par VulnCheck
* Remplacer les routeurs affectés ou les placer derrière un contrôle egress strict en traitant leur LAN comme non fiable
* Ne pas acheter de routeurs Zbtlink/ZBT/Wiflyer ou de CPE cellulaires de provenance incertaine

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier tous les routeurs Zbtlink/ZBT/Wiflyer dans le parc (modèles : CPE2801, WE1026-5G-WD, WE1326, WE2007, WE2008-DSIM, WE2416, WE3326, WE5927, WE5931, WE5931AC, WE826-T3-DSIM, WG108, WG1602, WG1608-DSIM, WG209, WG2105, WG2107, WG259, WG3526, Z8102AX-2DSIM)
* Vérifier les enregistrements d'achat, les filiales, les sites distants et les flottes véhicules
* Déployer des règles Suricata/Snort fournies par VulnCheck pour détecter le trafic C2 ENDLESSDOORS
* Sensibiliser les équipes IT à l'existence de cette backdoor matérielle

#### Phase 2 — Détection et analyse

* Surveiller le trafic sortant vers les ports 7000 et 7001 depuis les segments réseau d'infrastructure
* Déployer des règles DNS pour alerter sur les résolutions de zbtctl[.]epplink[.]net, online-string[.]com, rbdg4nzqadui[.]wikaba[.]com
* Si accès SSH possible, exécuter 'ps' et chercher des processus kworker non entre crochets avec VSZ non nul
* Vérifier la présence des fichiers /usr/sbin/kworker, /usr/lib/librctl.so, /etc/kworker.cfg, /etc/init.d/skworker
* Appliquer la règle YARA fournie par VulnCheck sur les firmwares téléchargés

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les 4 endpoints C2 au niveau du pare-feu egress et du résolveur DNS
* Isoler immédiatement les routeurs affectés du réseau de production
* Désactiver le script init.d skworker si accès shell disponible (mesure temporaire)
* Considérer le LAN du routeur comme non fiable et segmenter strictement

#### Phase 4 — Activités post-incident

* Remplacer les routeurs affectés par du matériel d'un fournisseur alternatif de confiance
* Auditer les logs réseau rétroactivement pour identifier toute activité C2 passée
* Vérifier si des commandes ont été exécutées ou des shells interactifs ouverts (port 7001)
* Documenter l'incident et notifier les parties prenantes de la chaîne d'approvisionnement

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des routeurs CPE cellulaires non marqués ou de provenance incertaine dans tout le parc
* Chercher des processus kworker supplémentaires sur tous les équipements réseau Linux/OpenWrt
* Analyser le trafic DNS historique pour les domaines wikaba.com et epplink.net
* Surveiller l'apparition de nouveaux modèles rebadgés OEM/ODM utilisant le même firmware

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| IP | `47[.]100[.]190[.]96` | High |
| IP | `47[.]107[.]224[.]89` | High |
| IP | `45[.]32[.]81[.]152` | High |
| IP | `43[.]248[.]136[.]125` | High |
| DOMAIN | `zbtctl[.]epplink[.]net` | High |
| DOMAIN | `online-string[.]com` | High |
| DOMAIN | `rbdg4nzqadui[.]wikaba[.]com` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1543** | Create or Modify System Process – init.d script skworker démarre l'implant au boot |
| **T1071** | Application Layer Protocol – communication C2 sur port 7000/TCP |
| **T1571** | Non-Standard Port – port 7000/7001 pour C2 et shell inverse |
| **T1059** | Command and Scripting Interpreter – exécution de commandes via popen() en root |
| **T1036** | Masquerading – processus kworker déguisé en thread kernel Linux |
| **T1105** | Ingress Tool Transfer – réception de commandes et shell interactif depuis le C2 |

---

### Sources

* [https://thehackernews.com/2026/08/chinese-made-zbtlink-routers-ship-with.html](https://thehackernews.com/2026/08/chinese-made-zbtlink-routers-ship-with.html)
* [https://www.vulncheck.com/blog/zbt-endlessdoors](https://www.vulncheck.com/blog/zbt-endlessdoors)
* [https://mastodon.social/@unzip/117056114613538082](https://mastodon.social/@unzip/117056114613538082)


---

<div id="campagne-wel1dropper-788-packages-npm-malveillants-livrant-un-rat-cross-plateforme-et-infostealer"></div>

## Campagne Wel1Dropper : 788 packages npm malveillants livrant un RAT cross-plateforme et infostealer

### Résumé

OpenSourceMalware (OSM) a documenté une campagne où un acteur de menace a publié plus de 700 (suivis à 788) packages npm malveillants en 48 heures, utilisant des noms typosquattés générés par IA ('AI slopsquatting'). Le package exemple checkout-mobile-bnpl se présente comme un SDK mobile mais exécute du code malveillant dès l'import via require(), sans utiliser de scripts preinstall/postinstall. Le downloader (NUL1DROPPER) supporte Windows, Linux et macOS, téléchargeant des payloads via 3 hôtes Cloudflare Workers en HTTPS avec fallback DNS TXT records hébergés sous wel1[.]ru. Le payload macOS est un Mach-O universel (Intel + ARM64) qui établit une persistance via LaunchAgent (com.apple.windowserver.helper), télécharge un beacon supplémentaire, et implémente des checks anti-analyse (lldb, frida, Wireshark, VMware). Le payload Linux est un ELF UPX-packed potentiellement lié à l'implant Sliver. OSM attribue cette campagne potentiellement à un acteur russe et la relie à la campagne Moika tech d'avril/mai 2026 (250+ packages). Des domaines d'institutions financières russes (tcsbank.ru, cloudpayments.ru) sont embarqués comme health checks ou leurres.

---

### Analyse opérationnelle

Cette campagne contourne les contrôles de lifecycle scripts npm car l'infection se déclenche à l'import du package, pas à l'installation. Les équipes SOC doivent : (1) scanner tous les lockfiles, SBOMs, caches npm et logs de build pour les 788 packages listés ; (2) surveiller les logs DNS pour les requêtes TXT vers wel1[.]ru et sous-domaines (sdk.dl, ext.dl, pkg.dl, net.dl) ; (3) alerter sur le trafic vers les 8 hôtes Cloudflare Workers ; (4) détecter les fichiers /var/tmp/.cache_<hex>, %TEMP%\dotnet_diag_<hex>.exe, /tmp/.analytics_state ; (5) sur macOS, chercher ~/Library/LaunchAgents/com.apple.windowserver.helper.plist et ~/.local/share/runtime/com.apple.runtime. Le fallback DNS TXT est particulièrement difficile à détecter car il ressemble à des requêtes DNS ordinaires. Les credentials des postes de développement et runners CI doivent être révoqués en cas de compromission confirmée. Le dernier stage pourrait être un implant Sliver (C2 Go open-source de Bishop Fox).

---

### Implications stratégiques

Cette campagne illustre l'évolution de la chaîne d'approvisionnement logicielle comme vecteur d'attaque majeur. L'utilisation de noms générés par IA ('slopsquatting') rend la détection par typosquatting traditionnel insuffisante. Le recours à Cloudflare Workers comme infrastructure C2 abuse de services légitimes difficiles à bloquer. Le fallback DNS TXT démontre une sophistication technique permettant de contourner les proxies HTTPS. L'attribution russe probable et le lien avec la campagne Moika suggèrent un acteur persistant investissant dans l'écosystème npm. Les organisations dépendant de npm pour le développement doivent reconsidérer leurs politiques de dépendances, imposer des revues manuelles des nouveaux packages, et surveiller activement les imports au runtime. Le risque pour les secteurs financier et technologique est élevé car les credentials de développement et de déploiement peuvent être compromis silencieusement.

---

### Recommandations

* Scanner immédiatement tous les projets npm pour les 788 packages malveillants listés par OSM
* Surveiller les logs DNS pour les requêtes TXT vers wel1[.]ru et sous-domaines
* Bloquer les 8 domaines Cloudflare Workers identifiés au niveau proxy/DNS
* Révoquer tous les credentials de développement et CI/CD en cas d'exposition confirmée
* Implémenter une politique de revue manuelle obligatoire pour tout nouveau package npm
* Surveiller les LaunchAgents macOS pour des entrées déguisées en composants Apple

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre en place une surveillance des registres de packages (npm) avec des outils de scan de dépendances
* Maintenir un SBOM (Software Bill of Materials) à jour pour tous les projets utilisant npm
* Former les développeurs sur les risques d'import de packages non vérifiés et le typosquatting
* Déployer des règles de blocage des lifecycle scripts npm (preinstall/postinstall) tout en sachant que cela ne suffit pas

#### Phase 2 — Détection et analyse

* Vérifier la présence des 788 packages malveillants dans les lockfiles, caches npm, logs de build et SBOMs
* Surveiller les logs DNS pour les requêtes TXT vers wel1[.]ru et ses sous-domaines (sdk.dl, ext.dl, pkg.dl, net.dl)
* Surveiller le trafic HTTPS vers les 8 hôtes Cloudflare Workers identifiés
* Détecter les fichiers /var/tmp/.cache_<hex>, %TEMP%\dotnet_diag_<hex>.exe, /tmp/.analytics_state, %TEMP%\analytics_state
* Sur macOS : chercher ~/.local/share/runtime/com.apple.runtime et ~/Library/LaunchAgents/com.apple.windowserver.helper.plist
* Surveiller les requêtes DNS TXT avec le pattern c.<domain> et <integer>.<domain>

#### Phase 3 — Confinement, éradication et récupération

* Supprimer immédiatement tous les packages malveillants des environnements de développement, CI/CD et production
* Bloquer les 8 domaines Cloudflare Workers et les 5 domaines wel1[.]ru au niveau du proxy/DNS
* Isoler les postes de développement et runners CI potentiellement compromis
* Révoquer tous les credentials accessibles depuis les machines affectées : tokens npm, tokens GitHub, credentials cloud, clés de signature, secrets de déploiement

#### Phase 4 — Activités post-incident

* Reconstruire les systèmes affectés depuis un état connu-sûr
* Analyser les binaires de second stage téléchargés pour déterminer l'ampleur de la compromission
* Vérifier si un implant Sliver (C2 Go de Bishop Fox) a été déployé comme dernier stade
* Auditer les accès et données exposés depuis les machines compromises
* Mettre à jour les politiques de dépendances npm pour exiger une revue manuelle des nouveaux packages

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans l'historique DNS les requêtes TXT vers wel1[.]ru remontant à avril 2026 (campagne Moika précédente)
* Chercher des packages npm avec des noms générés aléatoirement ou typosquattés dans tous les projets
* Surveiller l'apparition de nouveaux packages utilisant le pattern 'checkout-mobile-bnpl' ou des noms d'SDK mobile factices
* Analyser les fichiers LaunchAgents macOS pour des entrées déguisées en composants Apple légitimes
* Surveiller les processus utilisant libcurl et libresolv simultanément sur macOS comme indicateurs de beacon

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `oob-worker[.]cf103-070[.]workers[.]dev` | High |
| DOMAIN | `oob-worker[.]cf102-baf[.]workers[.]dev` | High |
| DOMAIN | `oob-worker[.]cf99-9b3[.]workers[.]dev` | High |
| DOMAIN | `package-proxy[.]cf5oobworker[.]workers[.]dev` | High |
| DOMAIN | `package-proxy[.]cf6oobworker[.]workers[.]dev` | High |
| DOMAIN | `package-proxy[.]cf7oobworker[.]workers[.]dev` | High |
| DOMAIN | `package-proxy[.]cf8oobworker[.]workers[.]dev` | High |
| DOMAIN | `package-proxy[.]cf11oobworker[.]workers[.]dev` | High |
| DOMAIN | `sdk[.]dl[.]wel1[.]ru` | High |
| DOMAIN | `ext[.]dl[.]wel1[.]ru` | High |
| DOMAIN | `pkg[.]dl[.]wel1[.]ru` | High |
| DOMAIN | `net[.]dl[.]wel1[.]ru` | High |
| DOMAIN | `dl[.]wel1[.]ru` | High |
| DOMAIN | `nexus[.]tcsbank[.]ru` | Low |
| DOMAIN | `repo-linux[.]tcsbank[.]ru` | Low |
| DOMAIN | `alertmanager[.]cloudpayments[.]ru` | Low |
| HASH_SHA256 | `7e486657f30594afda379b97030252a09a19fe8055e25c9e371544f59bd8e9e3` | High |
| HASH_SHA256 | `c214746c74cae8ece8bdaf69aa05da4db6ce013f9e77452d1eed1a002fd9ba00` | High |
| HASH_SHA256 | `0fc30f82e1fa5e51a6c0c43f3ed7f13592ea731cb331e43a4d085df60a4db8b6` | High |
| HASH_SHA256 | `94ef6b1c4a9d31f78f446d053048bcef34fd88f4376a1a46f7f777a9e9c83a29` | High |
| HASH_SHA256 | `b74c5675725911c62091bdf40714df760cc2af7a88360d21065f4e1c878aa8f0` | High |
| HASH_SHA256 | `e2650e9aa2f924433ba422857b22ee7c5996b5ad306f3f903283f6a13e248935` | High |
| HASH_SHA256 | `a3e2ffb440b779d30da3ff282affd649731088e8570df7b1aa72742d995b782c` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1195** | Supply Chain Compromise – publication de packages npm malveillants via typosquatting |
| **T1105** | Ingress Tool Transfer – téléchargement de payload via HTTPS et DNS TXT records |
| **T1071** | Application Layer Protocol – utilisation de Cloudflare Workers et DNS pour C2 |
| **T1547** | Boot or Logon Autostart Execution – LaunchAgent macOS com.apple.windowserver.helper pour persistance |
| **T1027** | Obfuscated Files or Information – XOR 0x9c pour cacher les strings d'infrastructure, UPX packing |
| **T1497** | Virtualization/Sandbox Evasion – détection de lldb, frida, Wireshark, VMware, vérification hw.memsize |
| **T1036** | Masquerading – noms de fichiers .cache_, dotnet_diag_, com.apple.windowserver.helper pour camouflage |
| **T1059** | Command and Scripting Interpreter – exécution via /bin/sh et cmd.exe |
| **T1106** | Native API – utilisation de ptrace, fork, setsid, execl pour exécution détachée et anti-debugging |

---

### Sources

* [https://opensourcemalware.com/blog/russian-ai-slopsquatting-npm-campaign](https://opensourcemalware.com/blog/russian-ai-slopsquatting-npm-campaign)
* [https://otx.alienvault.com/pulse/6a763860fd9d05bceee48cc7](https://otx.alienvault.com/pulse/6a763860fd9d05bceee48cc7)
* [https://social.raytec.co/@techbot/117056012986618992](https://social.raytec.co/@techbot/117056012986618992)


---

<div id="unc6671-campagne-de-vishing-multi-marques-ciblant-les-saas-pour-extorsion-de-donnees"></div>

## UNC6671 : campagne de vishing multi-marques ciblant les SaaS pour extorsion de données

### Résumé

Google Threat Intelligence Group (GTIG/Mandiant) a publié une analyse détaillée d'UNC6671, un acteur de menace menant des opérations de vishing et d'extorsion de données. Malgré l'annonce de retraite de la marque BlackFile en mai 2026, UNC6671 a diversifié ses opérations sous les marques Redact, Pink, Helix et Falcon. L'acteur cible les employés via leurs téléphones personnels en se faisant passer pour le helpdesk IT, avec un prétexte de migration urgente vers FIDO2 passkeys. Les victimes sont dirigées vers des portails AiTM (Adversary-in-the-Middle) qui interceptent credentials et tokens MFA. Une fois l'accès établi, des scripts automatisés exfiltrent des données depuis Microsoft 365, Okta et autres SaaS. L'analyse d'infrastructure révèle des chevauchements de domaines phishing entre les marques (ex: passkeyhelpdesk[.]com utilisé pour Falcon et Helix). Le ciblage a évolué : entreprises générales (avril-mai), technologie/transport/hôtellerie (juin), puis services financiers/private equity/juridique (juillet). Les demandes de rançon initiales vont de 1M$ à 3M$, réduites à ~750K$ en moyenne. 18 wallets Bitcoin BlackFile ont reçu 141.65 BTC (~10.69M$) entre janvier et mai 2026. De nouvelles techniques incluent le spoofing du numéro du helpdesk et la suppression systématique des emails de notification de reset de mot de passe.

---

### Analyse opérationnelle

Les équipes SOC doivent prioriser plusieurs détections : (1) surveiller les logs Okta/Entra ID pour les événements MFA registration (system.multifactor.factor.setup) précédés d'échecs d'authentification ou de push MFA abandonnés ; (2) traiter les FileAccessed avec User-Agent scripting (python-requests, WindowsPowerShell, Go-http-client) avec la même criticité que FileDownloaded ; (3) alerter sur les authentifications SSO depuis des VPN commerciaux ou proxies résidentiels hors baseline géographique ; (4) détecter les suppressions massives d'emails de notification de sécurité. Les défenseurs doivent imposer FIDO2 phishing-resistant, réduire les durées de session, exiger des appareils gérés (MDM/EDR), et restreindre l'authentification aux sources réseau de confiance. Les domaines phishing suivent un pattern prévisible (passkey/sso/mfa + verbe) permettant une détection proactive via passive DNS. Google SecOps propose des règles pack Okta et Microsoft 365 pour ces activités.

---

### Implications stratégiques

UNC6671 illustre la fluidité des marques d'extorsion et la persistance des TTP sous-jacents. La multiplication des marques (BlackFile→Redact→Pink/Helix/Falcon) vise probablement à compartimenter les opérations, masquer le volume global des breaches et isoler les retombées de négociation. Le ciblage croissant des services financiers, private equity et cabinets juridiques suggère une stratégie de maximisation du levier d'extorsion sur des données à haute valeur (M&A, litiges, capital). L'usage de téléphones personnels contourne les contrôles de sécurité d'entreprise. Les paiements de rançon continus après la 'retraite' de BlackFile démontrent que les opérations financières ne s'interrompent pas lors des rebrandings. Les organisations doivent investir dans l'authentification phishing-resistant et le monitoring comportemental SaaS comme priorités stratégiques.

---

### Recommandations

* Imposer FIDO2 phishing-resistant (clés roaming, passkeys, Windows Hello for Business, Okta Fastpass) sur tous les IdP
* Intégrer les applications SaaS critiques avec un SSO unique pour uniformiser les contrôles de sécurité
* Réduire les durées de session et imposer des timeouts d'inactivité pour les accès privilégiés
* Exiger l'accès SaaS depuis des appareils gérés par l'entreprise (MDM/EDR)
* Surveiller les logs IdP pour les patterns MFA registration anormaux et les User-Agents scripting
* Former les employés à reconnaître les appels vishing du faux helpdesk IT sur téléphones personnels

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Imposer l'authentification FIDO2 phishing-resistant (clés de sécurité roaming, passkeys, Windows Hello for Business, Okta Fastpass) sur tous les IdP
* Intégrer toutes les applications SaaS critiques avec un SSO unique (Entra ID ou Okta) pour uniformiser les contrôles
* Réduire la durée des sessions et imposer des timeouts d'inactivité, surtout pour les accès privilégiés
* Exiger l'accès SaaS depuis des appareils gérés par l'entreprise (MDM/EDR)
* Former les employés à reconnaître les appels vishing du faux helpdesk IT
* Déployer Google Workspace Password Alert et Microsoft Defender SmartScreen

#### Phase 2 — Détection et analyse

* Surveiller les logs IdP (Okta, Entra ID) pour les événements MFA registration (system.multifactor.factor.setup) précédés d'échecs d'authentification
* Détecter les FileAccessed avec User-Agent scripting (python-requests, WindowsPowerShell, Go-http-client) dans les logs Microsoft 365 UAL
* Surveiller les authentifications SSO depuis des IPs de VPN commerciaux (Mullvad, Private Layer) ou proxies résidentiels hors baseline géographique
* Surveiller les suppressions massives d'emails de notification de sécurité dans les boîtes compromises
* Alerte sur les modifications de configuration MFA suivies de suppressions d'alertes
* Surveiller les nouveaux enregistrements DNS correspondant aux patterns passkey/sso/mfa + verbe

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement toutes les sessions actives des comptes compromis
* Réinitialiser les mots de passe et réenregistrer les facteurs MFA des comptes affectés
* Bloquer les domaines phishing identifiés au niveau DNS/proxy web
* Isoler les comptes SaaS compromis et suspendre l'accès aux applications tierces
* Restaurer les règles de forwarding email et les suppressions d'alertes de sécurité

#### Phase 4 — Activités post-incident

* Auditer l'ensemble des données exfiltrées depuis Microsoft 365 et Okta (SharePoint, OneDrive, Exchange)
* Analyser les logs UAL pour identifier le volume exact de données accédées/téléchargées
* Évaluer l'impact de l'extorsion et préparer une réponse de négociation si nécessaire
* Notifier les parties prenantes (clients, régulateurs) selon les obligations de notification
* Renforcer les contrôles d'accès conditionnel basés sur le device et la localisation

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs IdP les patterns d'authentification anormaux : MFA push abandonnés suivis de réussites
* Chercher les FileAccessed/FileDownloaded avec des User-Agents non-humains sur les 90 derniers jours
* Surveiller l'enregistrement de nouveaux domaines correspondant aux patterns passkey*/sso*/mfa* + verbe
* Analyser les chaînes d'infrastructure partagée entre les marques d'extorsion (BlackFile, Redact, Pink, Helix, Falcon)
* Surveiller les tentatives de reset de mot de passe pour applications non-SSO suivies de suppressions d'emails

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| IP | `31[.]7[.]56[.]61` | High |
| IP | `31[.]7[.]56[.]52` | High |
| IP | `193[.]34[.]212[.]132` | High |
| IP | `185[.]178[.]208[.]153` | High |
| IP | `23[.]234[.]75[.]84` | High |
| IP | `195[.]140[.]213[.]114` | High |
| IP | `195[.]140[.]213[.]115` | High |
| IP | `107[.]128[.]45[.]122` | Medium |
| IP | `76[.]103[.]148[.]180` | Medium |
| IP | `38[.]42[.]59[.]171` | Medium |
| IP | `47[.]218[.]103[.]146` | Medium |
| DOMAIN | `passkeyhelpdesk[.]com` | High |
| DOMAIN | `portalpasskey[.]com` | High |
| DOMAIN | `addssopasskey[.]com` | High |
| DOMAIN | `passkeydeploy[.]com` | High |
| DOMAIN | `passkeyms[.]com` | High |
| DOMAIN | `mysecurepasskey[.]com` | High |
| DOMAIN | `oskeysync[.]com` | High |
| DOMAIN | `keysyncos[.]com` | High |
| DOMAIN | `setupsso[.]com` | High |
| DOMAIN | `idokta[.]com` | High |
| DOMAIN | `passkeyuser[.]com` | High |
| DOMAIN | `passkeyportal[.]com` | High |
| DOMAIN | `createssopasskey[.]com` | High |
| DOMAIN | `passkeyenroll[.]com` | High |
| DOMAIN | `hubpasskey[.]com` | High |
| DOMAIN | `passkeymfa[.]com` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing – vishing via appels téléphoniques sur téléphones personnels en se faisant passer pour le helpdesk IT |
| **T1556** | Modify Authentication Process – AiTM pour intercepter credentials et tokens MFA |
| **T1078** | Valid Accounts – utilisation de sessions persistantes pour accéder aux environnements SaaS |
| **T1530** | Data from Cloud Storage – exfiltration automatisée de données depuis Microsoft 365 et Okta via scripts |
| **T1090** | Proxy – utilisation de proxies résidentiels et VPN commerciaux pour l'accès SaaS |
| **T1565** | Data Manipulation – suppression des emails de notification de reset de mot de passe et alertes de sécurité |
| **T1583** | Acquire Infrastructure – enregistrement de domaines phishing avec patterns passkey/sso/mfa |
| **T1071** | Application Layer Protocol – exfiltration via API SaaS avec User-Agents scripting (python-requests, PowerShell) |

---

### Sources

* [https://thehackernews.com/2026/08/unc6671-vishing-attacks-target-personal.html](https://thehackernews.com/2026/08/unc6671-vishing-attacks-target-personal.html)
* [https://cloud.google.com/blog/topics/threat-intelligence/unc6671-targets-financial-services-and-enterprise-cloud-environments](https://cloud.google.com/blog/topics/threat-intelligence/unc6671-targets-financial-services-and-enterprise-cloud-environments)
* [https://otx.alienvault.com/pulse/6a7638701f931532a2e1f1c9](https://otx.alienvault.com/pulse/6a7638701f931532a2e1f1c9)
* [https://social.raytec.co/@techbot/117056012910949971](https://social.raytec.co/@techbot/117056012910949971)
