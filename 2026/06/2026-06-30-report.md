# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [ConsentFix : la nouvelle évolution de ClickFix cible Microsoft 365 via le détournement de flux OAuth](#consentfix-la-nouvelle-evolution-de-clickfix-cible-microsoft-365-via-le-detournement-de-flux-oauth)
  * [Vulnérabilités critiques sur les contrôleurs Daktronics : panneaux autoroutiers et billboards exposés au piratage à distance](#vulnerabilites-critiques-sur-les-controleurs-daktronics-panneaux-autoroutiers-et-billboards-exposes-au-piratage-a-distance)
  * [Analyse de malwares – partie 10 : parsing PE en pratique avec Python](#analyse-de-malwares-partie-10-parsing-pe-en-pratique-avec-python)
  * [CloudTrail, source de preuve principale pour les investigations sur AWS](#cloudtrail-source-de-preuve-principale-pour-les-investigations-sur-aws)
  * [Automatiser la reconnaissance d'hôtes via le hash de favicon.ico et Shodan](#automatiser-la-reconnaissance-dhotes-via-le-hash-de-faviconico-et-shodan)
  * [Mustang Panda vise les secteurs gouvernemental et énergétique indiens avec ZOHOMURK et MINIRECON](#mustang-panda-vise-les-secteurs-gouvernemental-et-energetique-indiens-avec-zohomurk-et-minirecon)
  * [Mark-of-the-Web : la protection change, les outils d'analyse suivent mal](#mark-of-the-web-la-protection-change-les-outils-danalyse-suivent-mal)
  * [Hyperviseurs malveillants, partie 2 : EPT/NPT, vues partagées et preuves de faults de second stage](#hyperviseurs-malveillants-partie-2-eptnpt-vues-partagees-et-preuves-de-faults-de-second-stage)
  * [Cyber Météo Suisse — DEFCON 4 : front ransomware modéré, phishing en hausse secondaire](#cyber-meteo-suisse-defcon-4-front-ransomware-modere-phishing-en-hausse-secondaire)
  * [Attaque supply chain Klue-Salesforce : le nombre de victimes grimpe à ~24 organisations et le groupe d'extorsion est lui-même compromis](#attaque-supply-chain-klue-salesforce-le-nombre-de-victimes-grimpe-a-24-organisations-et-le-groupe-dextorsion-est-lui-meme-compromis)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L’activité cybercriminelle demeure exceptionnellement dense avec 100 vulnérabilités recensées et 10 violations de données, signalant une pression élevée sur les défenseurs et une accélération probable de l’exploitation publique des CVE avant correctif. Les 10 articles de veille confirment une cadence de divulgation soutenue, exigeant un tri par criticité pour éviter la paralysie opérationnelle. L’équilibre entre les 4 sujets géopolitiques et les 2 actualités réglementaires suggère une convergence vers la normalisation : la régulation rythme l’action étatique, mais reste secondaire face à l’urgence technique immédiate. Les 2 actualités sur les acteurs de la menace, en apparence modestes, doivent être croisées avec la vague de vulnérabilités pour identifier d’éventuelles campagnes d’armement opportunistes. Priorité CTI : triage des CVE les plus exposées,監視 des chaînes d’exploitation alignées sur les secteurs régulés, et consolidation des IOCs liés aux brèches récentes.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **The Gentlemen** | Infrastructures critiques, Énergie, Santé | Chaîne d'intrusion complète orientée domaine AD : exploitation initiale, reconnaissance interne, extraction d'identifiants via sniffing SMB, mouvement latéral et déploiement de ransomware. | T1190, T1078, T1018, T1016, T1087, T1040, T1021.002, T1486 | [https://securelist.com/the-gentlemen-raas/120447/](https://securelist.com/the-gentlemen-raas/120447/) |
| **MUSTANG PANDA** | Gouvernement, Diplomatie, Défense | Spear-phishing d'installations gouvernementales indiennes avec implants ZOHOMURK/MINIRECON et exfiltration discrète via HTTPS. | T1566.001, T1059.003, T1083, T1027, T1071.001 | [https://www.reddit.com/r/blueteamsec/comments/1ujfmlv/mustang_panda_targets_indias_government_and/](https://www.reddit.com/r/blueteamsec/comments/1ujfmlv/mustang_panda_targets_indias_government_and/) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Russie, Ukraine, UE, OTAN, Kherson, Dnipropetrovsk** | Information et communication / Défense | Écosystème d'influence pro-Russie et guerre psychologique en Ukraine | L'écosystème d'influence pro-Russie, construit sur l'héritage des mesures actives soviétiques, se réoriente après quatre ans de guerre en Ukraine vers des objectifs stratégiques globaux visant l'UE, l'OTAN et la primauté occidentale. Il combine cyberattaques, opérations d'information (IO) et hacktivisme, avec un recours croissant à l'IA générative pour la planification et la création de contenu. Sur le terrain, les drones FPV russes illustrent la dualité du dispositif : utilisés à la fois comme armes létales contre les civils et infrastructures ukrainiennes, et comme vecteurs de propagande (tracts largués, radio, Telegram) dans les zones de front comme Kherson ou Nikopol. Cette stratégie articule pression physique, disruption informationnelle et message de « sauvetage » conditionnel pour manipuler les populations, affaiblir la résilience psychologique et faciliter l'acceptation de l'occupant. L'interconnexion des composantes (acteurs étatiques, indépendants, hacktivistes) rend l'écosystème résilient aux perturbations limitées. | [https://cloud.google.com/blog/topics/threat-intelligence/pro-russia-influence-ecosystem/](https://cloud.google.com/blog/topics/threat-intelligence/pro-russia-influence-ecosystem/)<br>[https://euvsdisinfo.eu/explosives-and-propaganda-russias-dual-use-drones/](https://euvsdisinfo.eu/explosives-and-propaganda-russias-dual-use-drones/) |
| **Europe, France, Landes** | Économie / Agriculture / Services | Impact économique des vagues de chaleur exceptionnelles en Europe | La vague de chaleur de juin 2026 (jusqu'à 44,3 °C dans les Landes) s'inscrit dans une tendance de multiplication des épisodes caniculaires liés au changement climatique. Selon une étude de la BCE, ces événements réduisent l'activité économique d'environ 1 % la première année et 1,5 % deux ans après, avec un effet durable également après sécheresses (-3 % à 4 ans) et inondations (-2,8 %). L'agriculture est la plus vulnérable (baisse des rendements, hausse des prix alimentaires : +0,7 pt en 2022, projection de +1,8 pt d'ici 2060). Le secteur tertiaire subit aussi un impact majeur, les investissements d'adaptation (climatisation) ne se traduisant pas par des gains de productivité. Les régions déjà chaudes sont les plus exposées, et avec un réchauffement de +3 °C, les étés européens pourraient voir leurs températures grimper de +6 °C d'ici la fin du siècle. | [https://www.iris-france.org/vagues-de-chaleur-exceptionnelles-quelles-consequences-pour-les-economies-europeennes/](https://www.iris-france.org/vagues-de-chaleur-exceptionnelles-quelles-consequences-pour-les-economies-europeennes/) |
| **Proche-Orient, Gaza, Israël, France** | Médias / Information | Biais et conformisme médiatique dans le traitement du conflit Proche-Orient | Depuis le 7 octobre 2023, le traitement médiatique français du conflit à Gaza illustre un fort conformisme éditorial : déférence envers les porte-paroles israéliens, marginalisation des spécialistes critiques du Proche-Orient, attaques contre les journalistes remettant en cause le discours officiel (jusqu'au renvoi d'un stagiaire pour mention conjointe otages israéliens/prisonniers palestiniens). Les récits sur le blocus, la famine et l'interdiction d'accès des journalistes à Gaza ont été minimisés. Trois facteurs expliquent ce biais : le communautarisme, un occidentalisme assimilant Israël à un rempart contre l'islamisme, et la prudence professionnelle des journalistes craignant d'être écartés des antennes. Cette dynamique a contribué à une forme de négation du droit international humanitaire et à un appauvrissement du débat public sur la question palestinienne. | [https://www.iris-france.org/proche-orient-extension-du-domaine-de-la-desinformation/](https://www.iris-france.org/proche-orient-extension-du-domaine-de-la-desinformation/) |
| **Caraïbe, Amérique latine, Chine, États-Unis** | Défense / Sécurité régionale | Doctrine de sécurité hémisphérique des États-Unis sous Trump 2 | La politique de sécurité régionale des États-Unis dans la Caraïbe s'inscrit dans la National Security Strategy de janvier 2026 et son « corollaire Trump » à la doctrine Monroe. L'objectif stratégique est de restaurer la prééminence américaine dans l'Hémisphère occidental et d'empêcher les compétiteurs extérieurs, au premier rang desquels la Chine, de déployer des forces ou de contrôler des actifs stratégiques vitaux. Washington entend mobiliser ses partenaires régionaux autour de trois axes : le contrôle des flux migratoires, la lutte contre les trafics de drogue et le renforcement de la stabilité terrestre et maritime. Cette approche marque un retour à une posture hégémonique unilatérale et une militarisation accrue de l'espace caribéen. | [https://www.iris-france.org/la-politique-de-securite-regionale-des-etats-unis-dans-la-caraibe-depuis-le-gouvernement-trump-2/](https://www.iris-france.org/la-politique-de-securite-regionale-des-etats-unis-dans-la-caraibe-depuis-le-gouvernement-trump-2/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| EDRi Annual Report 2025 | EDRi (European Digital Rights) et coalition d'organisations de la société civile, syndicats et groupes d'intérêt public | 2026-06-29 | Union européenne | EDRi Annual Report 2025 | Le rapport annuel 2025 d'EDRi documente les actions menées face à la vague de déréglementation numérique lancée par la nouvelle Commission européenne sous couvert de « simplification » et de « compétitivité ». EDRi a joué un rôle moteur dans une large coalition de la société civile et a organisé en octobre un sommet rassemblant plus de 100 délégués européens, suivi le 19 novembre d'une campagne d'affichage à Bruxelles lors du lancement du controversé Digital Omnibus. Sur le plan judiciaire, EDRi a engagé des actions contre Meta et X, obtenant une décision historique aux Pays-Bas avec Bits of Freedom confirmant la liberté de choix des utilisateurs face aux manquements de Meta à ses obligations DSA. EDRi a contribué à mettre fin au blocage pluriannuel du Conseil sur le règlement CSA (Chat Control), écartant l'obligation de scannage massif et l'affaiblissement du chiffrement, et s'est opposée au règlement Europol et aux amendements à la directive Facilitation. En juin, EDRi a publié un plaidoyer pour une interdiction paneuropéenne des spywares, menant à la création d'un groupe d'intérêt au Parlement européen. EDRi a défendu l'AI Act contre les tentatives de dilution et obtenu l'intégration de ses recommandations dans les lignes directrices sur les systèmes d'IA interdits, tout en combattant la surveillance biométrique de masse. EDRi a également défendu l'intégrité du RGPD, participé aux consultations sur le Digital Fairness Act (DFA, attendu en 2026) et contribué à la stratégie ProtectEU. | [https://edri.org/our-work/edri-annual-report-2025-championing-digital-rights-in-the-eu-deregulation-era/](https://edri.org/our-work/edri-annual-report-2025-championing-digital-rights-in-the-eu-deregulation-era/) |
| Fox Rothschild Data Breach - Silent Ransom Group | Silent Ransom Group (acteur cybercriminel) | 2026-06-29 | États-Unis (cabinet d'envergure nationale et internationale) | Fox Rothschild Data Breach - Silent Ransom Group | Le cabinet d'avocats Fox Rothschild, figurant parmi les 100 premiers cabinets américains, a subi une violation de données suivie d'une fuite attribuée au Silent Ransom Group (SRG). L'incident inclut une analyse des origines et des méthodes opérationnelles du SRG (hack-and-leak / extorsion). Des recommandations sont formulées aux cabinets juridiques et aux victimes sur la base des schémas d'attaque observés lors de multiples incidents. Les indicateurs d'observation renvoient au domaine databreaches[.]net et à l'adresse PogoWasRight[@]infosec[.]exchange. | [https://databreaches.net/2026/06/29/exclusive-top-100-law-firm-fox-rothschild-suffers-data-breach-and-leak-by-silent-ransom-group/](https://databreaches.net/2026/06/29/exclusive-top-100-law-firm-fox-rothschild-suffers-data-breach-and-leak-by-silent-ransom-group/)<br>[https://infosec.exchange/@PogoWasRight/116835745279468635](https://infosec.exchange/@PogoWasRight/116835745279468635) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Multi-sectoriel (grandes entreprises et infrastructures critiques)** | The Gentlemen RaaS victims (multi-sector) | Données d'identification Active Directory, secrets réseau capturés (mots de passe en clair), données métier hébergées sur les serveurs compromis avant chiffrement | Inconnu | [https://securelist.com/the-gentlemen-raas/120447/](https://securelist.com/the-gentlemen-raas/120447/) |
| **Technologie / Transfert sécurisé de fichiers** | Moveit (défendeurs - procès pour négligence) | Données personnelles d'utilisateurs de plateformes MOVEit (détails spécifiques non communiqués dans l'article) | Inconnu | [https://databreaches.net/2026/06/29/moveit-breach-defendants-lose-2nd-bid-to-toss-negligence-claims/](https://databreaches.net/2026/06/29/moveit-breach-defendants-lose-2nd-bid-to-toss-negligence-claims/) |
| **Banque centrale / Secteur financier souverain** | Banque centrale de Libye | Données financières et administratives de la banque centrale (nature exacte non confirmée) | Inconnu | [https://databreaches.net/2026/06/29/central-bank-of-libya-investigates-alleged-data-leak-after-cyberattack/](https://databreaches.net/2026/06/29/central-bank-of-libya-investigates-alleged-data-leak-after-cyberattack/) |
| **Multi-sectoriel (cadre réglementaire sud-africain)** | Organisations sud-africaines (jurisprudence sur les fuites par email) | Données personnelles pouvant inclure toute information contenue dans les emails mal adressés | Inconnu | [https://databreaches.net/2026/06/29/za-copying-the-wrong-person-on-an-email-could-be-considered-a-data-breach-in-south-africa/](https://databreaches.net/2026/06/29/za-copying-the-wrong-person-on-an-email-could-be-considered-a-data-breach-in-south-africa/) |
| **Santé (centre médical public au Japon)** | Saga Prefectural Medical Center Koseikan (Japon) | Informations sur l'hospitalisation et l'état de santé de patients (données sensibles de santé) | Inconnu | [https://rocket-boys.co.jp/security-measures-lab/medical-staff-verbal-leak-suspension/](https://rocket-boys.co.jp/security-measures-lab/medical-staff-verbal-leak-suspension/) |
| **Fabrication électronique / Supply chain** | Tata Electronics (fuite Apple iPhone 18 Pro) | Listes de fournisseurs, détails sur les composants, photos d'appareils iPhone 18 Pro, autres documents R&D | Inconnu | [https://securityonline.info/iphone-18-pro-leak-tata-breach/](https://securityonline.info/iphone-18-pro-leak-tata-breach/) |
| **Cannabis / Loisirs (clubs espagnols)** | Utilisateurs de cannabis clubs espagnols (Nefos / PuffPal) | Passeports, permis de conduire, photos d'identité, numéros de téléphone, adresses, préférences de consommation de cannabis | 985000 | [https://www.theverge.com/tech/947157/passports-data-breach-cannabis-club-systems-nefos-puffpal](https://www.theverge.com/tech/947157/passports-data-breach-cannabis-club-systems-nefos-puffpal) |
| **Télécommunications / Données de communication** | Softsu (ソフツー) - Serveur de test | Numéros de téléphone et enregistrements d'appels (métadonnées de communication) | 159850 | [https://rocket-boys.co.jp/security-measures-lab/softsu-call-records-leak-150k-numbers/](https://rocket-boys.co.jp/security-measures-lab/softsu-call-records-leak-150k-numbers/) |
| **Assurance / Services financiers** | Aflac Life Insurance (アフラック生命保険) | Données personnelles des clients (nom, adresse, date de naissance, numéro de police, coordonnées) ; pour environ 230 000 clients supplémentaires, informations du compte de prélèvement des primes (RIB/coordonnées bancaires) | 4380000 | [https://rocket-boys.co.jp/security-measures-lab/aflac-unauthorized-access-customer-data-leak/](https://rocket-boys.co.jp/security-measures-lab/aflac-unauthorized-access-customer-data-leak/)<br>[https://mastodon.social/@securityLab_jp/116837344317749215](https://mastodon.social/@securityLab_jp/116837344317749215) |
| **Automobile / Industrie** | Nissan | Données relatives au personnel Nissan (informations RH potentiellement nominatives : identité, fonction, données contractuelles) | Inconnu | [https://osintsights.com/nissan-breach-exposes-employee-data-after-oracle-peoplesoft-exploit](https://osintsights.com/nissan-breach-exposes-employee-data-after-oracle-peoplesoft-exploit)<br>[https://mastodon.social/@Analyst207/116835455691566940](https://mastodon.social/@Analyst207/116835455691566940) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-20245** | 7.8 | 9.92% | TRUE | Cisco Catalyst SD-WAN Controller, Cisco Catalyst SD-WAN Manager | CWE-116 Improper Encoding or Escaping of Output | Exécution de code arbitraire en contexte root sur le SD-WAN Manager, ouvrant la possibilité de prise en main complète de l'orchestrateur SD-WAN, d'exfiltration de configuration réseau, de modification de routes/tunnels VPN et de pivot vers le reste du SI. | Active | Appliquer immédiatement le correctif publié par Cisco sur toutes les instances SD-WAN Manager. Restreindre l'accès administrateur à un réseau de management segmenté, activer la MFA, journaliser finement les actions administratives, et déployer les signatures Check Point IPS Ubiquiti/Cisco SD-WAN correspondantes. Envisager un inventaire de tous les tunnels SD-WAN et la vérification de leur intégrité post-correctif. | [https://research.checkpoint.com/2026/29th-june-threat-intelligence-report-2/](https://research.checkpoint.com/2026/29th-june-threat-intelligence-report-2/)<br>[https://securityaffairs.com/194449/security/whatsapp-usernames-are-coming-you-can-reserve-yours-right-now.html](https://securityaffairs.com/194449/security/whatsapp-usernames-are-coming-you-can-reserve-yours-right-now.html)<br>[https://securityaffairs.com/194441/security/u-s-offers-10-million-reward-for-russian-hackers-behind-signal-and-whatsapp-phishing.html](https://securityaffairs.com/194441/security/u-s-offers-10-million-reward-for-russian-hackers-behind-signal-and-whatsapp-phishing.html)<br>[https://securityaffairs.com/194409/malware/stegoad-how-119-fake-browser-extensions-stole-credentials-and-ran-ad-fraud-for-two-years.html](https://securityaffairs.com/194409/malware/stegoad-how-119-fake-browser-extensions-stole-credentials-and-ran-ad-fraud-for-two-years.html)<br>[https://securityaffairs.com/194399/intelligence/ssu-and-fbi-uncover-russian-cyber-espionage-operation-against-officials-and-military-personnel.html](https://securityaffairs.com/194399/intelligence/ssu-and-fbi-uncover-russian-cyber-espionage-operation-against-officials-and-military-personnel.html) |
| **CVE-2026-41947** | 9.3 | 0.45% | FALSE | dify | CWE-639 Authorization Bypass Through User-Controlled Key | Divulgation d'informations sensibles cross-tenant : conversations de chat IA, fichiers uploadés, prompts et potentiellement données métier confidentielles. Risque d'exfiltration de propriété intellectuelle et de violation de confidentialité (RGPD). | Theoretical | Mettre à jour Dify vers la version 1.14.2 sans délai. Examiner l'historique des accès et la présence d'éventuelles compromissions antérieures. Segmenter les tenants, surveiller les logs d'accès et envisager un audit de conformité des données ayant pu être exposées. | [https://research.checkpoint.com/2026/29th-june-threat-intelligence-report-2/](https://research.checkpoint.com/2026/29th-june-threat-intelligence-report-2/) |
| **CVE-2026-41948** | 9.3 | 0.51% | FALSE | dify | CWE-23 Relative Path Traversal | Divulgation d'informations sensibles entre tenants hébergés sur la même instance Dify. Risque de violation de confidentialité pour les utilisateurs et organisations utilisant une instance partagée ou mal isolée. | Theoretical | Appliquer la mise à jour Dify 1.14.2. Auditer les logs d'accès et vérifier l'absence d'accès non autorisé entre tenants. Renforcer l'isolation des tenants, désactiver les partages implicites et surveiller en continu les flux de données. | [https://research.checkpoint.com/2026/29th-june-threat-intelligence-report-2/](https://research.checkpoint.com/2026/29th-june-threat-intelligence-report-2/) |
| **CVE-2026-34908** | 10.0 | 2.45% | TRUE | UniFi OS Server, UDM, UDM-Pro | CWE-284 Improper Access Control - Generic | Prise de contrôle partielle d'appliances UniFi OS, contournement des contrôles d'administration, pivot possible vers le réseau local et intégration potentielle dans un botnet Mirai (DDoS, scans de masse). | Active | Mettre à jour le firmware UniFi OS vers la dernière version publiée. Restreindre l'accès à l'interface de management via VPN/ACL, activer MFA, surveiller les modifications de configuration et déployer les signatures Check Point IPS correspondantes. Auditer le réseau local pour identifier d'éventuelles compromissions Mirai. | [https://research.checkpoint.com/2026/29th-june-threat-intelligence-report-2/](https://research.checkpoint.com/2026/29th-june-threat-intelligence-report-2/) |
| **CVE-2026-34909** | 10.0 | 2.27% | TRUE | UniFi OS Server, Express, UDM | CWE-22 Path Traversal | Accès non autorisé au système de fichiers de l'appliance, fuite potentielle de configurations, secrets WiFi, certificats et identifiants. Possibilité d'implanter un botnet Mirai sur le périphérique compromis. | Active | Mettre à jour immédiatement le firmware UniFi OS. Restreindre l'accès à l'interface de management, surveiller les logs HTTP pour les patterns de directory traversal, et déployer la signature Check Point IPS. Auditer les configurations WiFi et secrets après correction. | [https://research.checkpoint.com/2026/29th-june-threat-intelligence-report-2/](https://research.checkpoint.com/2026/29th-june-threat-intelligence-report-2/) |
| **CVE-2026-34910** | 10.0 | 78.55% | TRUE | UniFi OS Server, UDM, UDM-Pro | CWE-20 Improper Input Validation | Exécution de code arbitraire avec privilèges élevés sur les appliances UniFi OS, menant potentiellement à une compromission complète, à l'installation d'un botnet Mirai, à un pivot réseau et à l'exfiltration de secrets. | Active | Appliquer le correctif firmware Ubiquiti immédiatement. Bloquer l'accès WAN aux interfaces de management, déployer la signature Check Point IPS correspondante, surveiller les flux sortants suspects et révoquer l'ensemble des secrets stockés sur l'appliance. | [https://research.checkpoint.com/2026/29th-june-threat-intelligence-report-2/](https://research.checkpoint.com/2026/29th-june-threat-intelligence-report-2/) |
| **CVE-2026-55255** | 9.9 | 0.23% | FALSE | langflow | CWE-639: Authorization Bypass Through User-Controlled Key | Exécution non autorisée de pipelines IA, exfiltration de prompts, de modèles, de données et de secrets intégrés dans les workflows. Risque d'abus de la plateforme (coûts API, déni de service) et de compromission de propriété intellectuelle. | Active | Appliquer le correctif dès sa publication, restreindre l'accès réseau aux instances Langflow, journaliser les exécutions de pipelines et auditer régulièrement les flows. Renforcer l'authentification et mettre en place un WAF devant les instances exposées. | [https://research.checkpoint.com/2026/29th-june-threat-intelligence-report-2/](https://research.checkpoint.com/2026/29th-june-threat-intelligence-report-2/) |
| **CVE-2026-33017** | 9.3 | 98.41% | TRUE | langflow | CWE-94: Improper Control of Generation of Code ('Code Injection') | Exécution non autorisée de pipelines IA, fuite de données, de prompts et de secrets, potentiel pivot vers les modèles et services externes appelés par Langflow (LLM, bases vectorielles). | Active | Appliquer le correctif Langflow, durcir l'authentification, segmenter le réseau, journaliser et auditer les exécutions de pipelines. Détecter et bloquer les patterns d'exploitation dans le WAF en attendant la mise à jour. | [https://research.checkpoint.com/2026/29th-june-threat-intelligence-report-2/](https://research.checkpoint.com/2026/29th-june-threat-intelligence-report-2/) |
| **CVE-2026-13763** | 7.9 | N/A | FALSE | AWS Application Load Balancer | CWE-444 Inconsistent interpretation of HTTP requests ('HTTP Request/Response smuggling') | Bypass complet des règles AWS WAF sur les ALB HTTP/2 : possibilité de transmettre des charges malveillantes (SQLi, XSS, webshell, exfiltration) non détectées, compromission des applications protégées et contournement des protections gérées AWS WAF. | Theoretical | Activer immédiatement l'attribut 'Inspect after sufficient data' sur tous les target groups HTTP/2 associés à un ALB. Vérifier que les logs CloudWatch et S3 capturent bien l'ensemble des requêtes, auditer les anciennes requêtes à la recherche d'un bypass passé. Surveiller la publication par AWS d'un correctif server-side automatique. | [https://cvefeed.io/vuln/detail/CVE-2026-13763](https://cvefeed.io/vuln/detail/CVE-2026-13763)<br>[https://aws.amazon.com/security/security-bulletins/rss/2026-048-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-048-aws/) |
| **CVE-2026-13762** | 7.9 | N/A | FALSE | Amazon CloudFront | CWE-444 Inconsistent interpretation of HTTP requests ('HTTP Request/Response smuggling') | Bypass des règles AWS WAF sur les distributions CloudFront : transmissions de charges malveillantes non détectées vers les origines, compromission potentielle des applications web et APIs servies via CloudFront. | Theoretical | Aucune action client n'est requise pour CloudFront (correctif server-side). Vérifier la bonne application du correctif sur l'ensemble des distributions, auditer les anciens logs WAF/CloudFront pour identifier des bypass passés, et renforcer la surveillance des origines. | [https://aws.amazon.com/security/security-bulletins/rss/2026-048-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-048-aws/) |
| **CVE-2026-52912** | 7.8 | 0.14% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact potentiel d'élévation de privilèges, d'exécution de code arbitraire, de déni de service ou de fuite de données selon la nature de la CVE, survenant au sein de l'infrastructure Azure Linux hébergeant des workloads critiques (VM, AKS, services managés). | None | Appliquer les correctifs publiés par Microsoft le 27 juin 2026 pour Azure Linux. Surveiller la disponibilité des mises à jour via Microsoft Update / Azure Update Manager. Consulter les bulletins Microsoft associés pour les détails d'exposition et tester les correctifs en pré-production avant déploiement en production. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52913** | N/A | 0.18% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact variable selon la nature de la vulnérabilité : élévation de privilèges, exécution de code, déni de service ou compromission de données sur les workloads Azure Linux. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026 via Azure Update Manager. Vérifier la disponibilité des correctifs dans le canal d'update et prioriser les hôtes exposés à Internet. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52915** | 7.1 | 0.13% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact dépendant de la nature technique de la vulnérabilité : potentielle compromission d'intégrité, confidentialité ou disponibilité des workloads hébergés sur Azure Linux. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Vérifier la matrice de compatibilité et déployer via les canaux de mise à jour Azure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52916** | N/A | 0.18% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact dépendant de la catégorie de la vulnérabilité : risque d'élévation de privilèges, d'exécution de code ou de déni de service sur les instances Azure Linux. | None | Appliquer les correctifs Microsoft du 27 juin 2026 via Azure Update Manager et prioriser les hôtes exposés à Internet. Vérifier l'absence de redémarrage en attente. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52919** | 7.8 | 0.12% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact variable selon la nature technique précise : compromission potentielle de l'intégrité, de la confidentialité ou de la disponibilité des workloads Azure Linux. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Suivre le bulletin de sécurité Microsoft référencé pour les détails de la CVE. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52921** | N/A | 0.16% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact dépendant de la nature technique : potentielle compromission d'intégrité, confidentialité ou disponibilité des services Azure Linux. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026 via Azure Update Manager. Valider le redémarrage des instances pour chargement du nouveau noyau. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52922** | 7.5 | 0.39% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Risque d'impact sur la confidentialité, l'intégrité ou la disponibilité des workloads hébergés sur Azure Linux, selon le type de vulnérabilité sous-jacente. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Consulter le bulletin de sécurité Microsoft pour les détails de la CVE. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52923** | 7.8 | 0.12% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact variable selon la nature de la vulnérabilité. Risque potentiel de compromission d'éléments Azure Linux exposés. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Se référer au bulletin Microsoft pour les détails d'exposition et de remédiation. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52924** | 9.8 | 0.39% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé en l'absence de détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques à cette CVE. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52926** | N/A | 0.16% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. La priorité dépendra de la criticité de la CVE (CVSS) et de l'exposition des workloads. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026 via Azure Update Manager. Vérifier la complétude de l'application des correctifs sur l'ensemble du parc. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52927** | 7.8 | 0.12% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact variable selon la nature technique. Risque résiduel pour les workloads Azure Linux tant que le correctif n'est pas appliqué. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se référer au bulletin de sécurité Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52930** | N/A | 0.17% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque potentiel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52931** | 9.8 | 0.40% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détail technique. Le niveau d'exposition effectif dépendra du type de faille et de la surface d'attaque exposée. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Se référer au bulletin de sécurité Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52934** | 8.8 | 0.25% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que le correctif n'est pas appliqué. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails d'exposition et de remédiation. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52941** | N/A | 0.16% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52942** | 7.1 | 0.12% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que le correctif n'est pas appliqué. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52943** | 7.8 | 0.17% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas déployés. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails d'exposition et de remédiation. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-52947** | 7.8 | 0.14% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Le niveau d'exposition effectif dépendra de la nature de la faille et de la surface d'attaque. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Vérifier la bonne application des correctifs sur l'ensemble du parc Azure Linux. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53080** | N/A | 0.17% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se référer au bulletin de sécurité Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53133** | 7.8 | 0.13% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas déployés. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53135** | N/A | 0.18% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Consulter le bulletin de sécurité Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53143** | N/A | 0.18% | FALSE | Microsoft Azure Linux (CVE-2026-53143, parmi d'autres CVE du bulletin Microsoft du 27 juin 2026) | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Se référer au bulletin de sécurité Microsoft pour les détails d'exposition et de remédiation. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53146** | 7.1 | 0.24% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Le niveau de risque dépendra de la nature de la faille et de l'exposition du parc Azure Linux. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53147** | 8.1 | 0.28% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se référer au bulletin de sécurité Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53148** | N/A | 0.18% | FALSE | Microsoft Azure Linux (CVE-2026-53148, parmi d'autres CVE du bulletin Microsoft du 27 juin 2026) | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53149** | N/A | 0.18% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Le niveau de risque dépendra du type de faille et de l'exposition. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53150** | N/A | 0.18% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53154** | N/A | 0.17% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53158** | N/A | 0.17% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53159** | N/A | 0.17% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Se référer au bulletin de sécurité Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53160** | 7.8 | 0.12% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53161** | 7.8 | 0.14% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53176** | N/A | 0.60% | FALSE | Microsoft Azure Linux (CVE-2026-53176, parmi d'autres CVE du bulletin Microsoft du 27 juin 2026) | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53177** | N/A | 0.17% | FALSE | Microsoft Azure Linux (CVE-2026-53177, parmi d'autres CVE du bulletin Microsoft du 27 juin 2026) | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53181** | N/A | 0.18% | FALSE | Microsoft Azure Linux (CVE-2026-53181, parmi d'autres CVE du bulletin Microsoft du 27 juin 2026) | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53182** | N/A | 0.14% | FALSE | Microsoft Azure Linux (CVE-2026-53182, parmi d'autres CVE du bulletin Microsoft du 27 juin 2026) | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53183** | 7.5 | 0.51% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53184** | N/A | 0.51% | FALSE | Microsoft Azure Linux (CVE-2026-53184, parmi d'autres CVE du bulletin Microsoft du 27 juin 2026) | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53186** | N/A | 0.54% | FALSE | Microsoft Azure Linux (CVE-2026-53186, parmi d'autres CVE du bulletin Microsoft du 27 juin 2026) | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53194** | 7.8 | 0.14% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53196** | 7.0 | 0.20% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53199** | 7.5 | 0.53% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53207** | N/A | 0.18% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53209** | 7.8 | 0.14% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53213** | N/A | 0.18% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53214** | N/A | 0.17% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53215** | 9.8 | 0.55% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53217** | 8.6 | 0.40% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53218** | N/A | 0.18% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53219** | N/A | 0.18% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53221** | 9.8 | 0.56% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53225** | 9.1 | 0.54% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53227** | N/A | 0.20% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53228** | 9.8 | 0.56% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53230** | 8.7 | 0.13% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53236** | N/A | 0.18% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53237** | N/A | 0.18% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux tant que les correctifs ne sont pas appliqués. | None | Appliquer les correctifs Microsoft Azure Linux diffusés le 27 juin 2026. Se conformer au bulletin de sécurité Microsoft référencé. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-53238** | N/A | 0.18% | FALSE | Linux | Multiples vulnérabilités (détails non spécifiés par l'éditeur) | Impact indéterminé sans détails techniques. Risque résiduel pour les workloads Azure Linux non patchés. | None | Appliquer les correctifs Microsoft Azure Linux du 27 juin 2026. Consulter la documentation Microsoft pour les détails spécifiques. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0812/) |
| **CVE-2026-11800** | 8.1 | 0.19% | FALSE | Red Hat build of Keycloak 26.6, Red Hat build of Keycloak 26.6.4, Red Hat Build of Keycloak | CWE-347 Improper Verification of Cryptographic Signature | Impact potentiel d'exécution de code arbitraire à distance, d'élévation de privilèges, de contournement de la politique de sécurité, d'atteinte à la confidentialité/intégrité des données et de XSS sur les instances Keycloak vulnérables. | None | Mettre à jour Keycloak vers 26.0.10 ou 26.6.4 (versions corrigées). Consulter les bulletins GHSA Keycloak du 26 juin 2026 pour les détails de remédiation spécifiques. Restreindre l'accès aux interfaces d'administration et surveiller les journaux d'événements. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0815/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0815/) |
| **CVE-2026-9083** | 4.9 | 0.50% | FALSE | Red Hat build of Keycloak 26.4, Red Hat build of Keycloak 26.4.13, Red Hat build of Keycloak 26.6 | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Impact potentiel d'exécution de code arbitraire à distance, d'élévation de privilèges, de contournement de la politique de sécurité, d'atteinte à la confidentialité/intégrité des données et de XSS sur les instances Keycloak vulnérables. | None | Mettre à jour Keycloak vers 26.0.10 ou 26.6.4 (versions corrigées). Consulter les bulletins GHSA Keycloak du 26 juin 2026 pour les détails de remédiation spécifiques. Restreindre l'accès aux interfaces d'administration et surveiller les journaux d'événements. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0815/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0815/) |
| **CVE-2026-9086** | 7.3 | 0.41% | FALSE | Red Hat build of Keycloak 26.4, Red Hat build of Keycloak 26.4.13, Red Hat build of Keycloak 26.6 | CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') | Impact potentiel d'exécution de code arbitraire à distance, d'élévation de privilèges, de contournement de la politique de sécurité, d'atteinte à la confidentialité/intégrité des données et de XSS sur les instances Keycloak vulnérables. | None | Mettre à jour Keycloak vers 26.0.10 ou 26.6.4. Consulter les bulletins GHSA du 26 juin 2026 pour les détails de remédiation spécifiques. Restreindre l'accès aux interfaces d'administration et surveiller les journaux d'événements. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0815/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0815/) |
| **CVE-2026-9099** | 7.7 | 0.27% | FALSE | Red Hat build of Keycloak 26.4, Red Hat build of Keycloak 26.4.13, Red Hat build of Keycloak 26.6 | CWE-639 Authorization Bypass Through User-Controlled Key | Impact potentiel d'exécution de code arbitraire à distance, d'élévation de privilèges, de contournement de la politique de sécurité, d'atteinte à la confidentialité/intégrité des données et de XSS sur les instances Keycloak vulnérables. | None | Mettre à jour Keycloak vers 26.0.10 ou 26.6.4. Consulter les bulletins GHSA du 26 juin 2026 pour les détails de remédiation spécifiques. Restreindre l'accès aux interfaces d'administration et surveiller les journaux d'événements. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0815/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0815/) |
| **CVE-2026-9705** | 6.5 | 0.28% | FALSE | Red Hat build of Keycloak 26.4, Red Hat build of Keycloak 26.4.13, Red Hat build of Keycloak 26.6 | CWE-613 Insufficient Session Expiration | Impact potentiel d'exécution de code arbitraire à distance, d'élévation de privilèges, de contournement de la politique de sécurité, d'atteinte à la confidentialité/intégrité des données et de XSS sur les instances Keycloak vulnérables. | None | Mettre à jour Keycloak vers 26.0.10 ou 26.6.4. Consulter les bulletins GHSA du 26 juin 2026 pour les détails de remédiation spécifiques. Restreindre l'accès aux interfaces d'administration et surveiller les journaux d'événements. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0815/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0815/) |
| **CVE-2026-9795** | 7.3 | 0.29% | FALSE | Red Hat build of Keycloak 26.4, Red Hat build of Keycloak 26.4.13, Red Hat build of Keycloak 26.6 | CWE-266 Incorrect Privilege Assignment | Impact potentiel d'exécution de code arbitraire à distance, d'élévation de privilèges, de contournement de la politique de sécurité, d'atteinte à la confidentialité/intégrité des données et de XSS sur les instances Keycloak vulnérables. | None | Mettre à jour Keycloak vers 26.0.10 ou 26.6.4. Consulter les bulletins GHSA du 26 juin 2026 pour les détails de remédiation spécifiques. Restreindre l'accès aux interfaces d'administration et surveiller les journaux d'événements. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0815/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0815/) |
| **CVE-2026-9799** | 4.6 | 0.18% | FALSE | Red Hat build of Keycloak 26.4, Red Hat build of Keycloak 26.4.13, Red Hat build of Keycloak 26.6 | CWE-639 Authorization Bypass Through User-Controlled Key | Impact potentiel d'exécution de code arbitraire à distance, d'élévation de privilèges, de contournement de la politique de sécurité, d'atteinte à la confidentialité/intégrité des données et de XSS sur les instances Keycloak vulnérables. | None | Mettre à jour Keycloak vers 26.0.10 ou 26.6.4. Consulter les bulletins GHSA du 26 juin 2026 pour les détails de remédiation spécifiques. Restreindre l'accès aux interfaces d'administration et surveiller les journaux d'événements. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0815/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0815/) |
| **CVE-2026-9800** | 8.1 | 0.30% | FALSE | Red Hat build of Keycloak 26.4, Red Hat build of Keycloak 26.4.13, Red Hat build of Keycloak 26.6 | CWE-1025 Comparison Using Wrong Factors | Impact potentiel d'exécution de code arbitraire à distance, d'élévation de privilèges, de contournement de la politique de sécurité, d'atteinte à la confidentialité/intégrité des données et de XSS sur les instances Keycloak vulnérables. | None | Mettre à jour Keycloak vers 26.0.10 ou 26.6.4. Consulter les bulletins GHSA du 26 juin 2026 pour les détails de remédiation spécifiques. Restreindre l'accès aux interfaces d'administration et surveiller les journaux d'événements. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0815/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0815/) |
| **CVE-2026-6473** | 8.8 | 0.40% | FALSE | PostgreSQL | CWE-190 Integer Overflow or Wraparound | Impact potentiel d'exécution de code arbitraire, d'atteinte à la confidentialité et d'atteinte à l'intégrité des données sur le serveur SMC et, par transitivité, sur l'ensemble des appliances Stormshield managées. | None | Mettre à jour Stormshield Management Center vers la version 3.9.2. Consulter le bulletin Stormshield 2026-012 pour les détails de remédiation spécifiques. Restreindre l'accès à la console d'administration et surveiller les journaux d'événements. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0816/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0816/) |
| **CVE-2026-6475** | 8.8 | 0.32% | FALSE | PostgreSQL | CWE-61 UNIX Symbolic Link (Symlink) Following | Impact potentiel d'exécution de code arbitraire, d'atteinte à la confidentialité et d'atteinte à l'intégrité des données sur le serveur SMC et les appliances managées. | None | Mettre à jour Stormshield Management Center vers la version 3.9.2. Consulter le bulletin Stormshield 2026-012 pour les détails de remédiation spécifiques. Restreindre l'accès à la console d'administration et surveiller les journaux d'événements. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0816/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0816/) |
| **CVE-2026-6477** | 8.8 | 0.28% | FALSE | PostgreSQL | CWE-242 Use of Inherently Dangerous Function | Impact potentiel d'exécution de code arbitraire, d'atteinte à la confidentialité et d'atteinte à l'intégrité des données sur le serveur SMC et les appliances managées. | None | Mettre à jour Stormshield Management Center vers la version 3.9.2. Consulter le bulletin Stormshield 2026-012 pour les détails de remédiation spécifiques. Restreindre l'accès à la console d'administration et surveiller les journaux d'événements. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0816/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0816/) |
| **CVE-2026-6637** | 8.8 | 0.38% | FALSE | PostgreSQL | CWE-121 Stack-based Buffer Overflow | Impact potentiel d'exécution de code arbitraire, d'atteinte à la confidentialité et d'atteinte à l'intégrité des données sur le serveur SMC et les appliances managées. | None | Mettre à jour Stormshield Management Center vers la version 3.9.2. Consulter le bulletin Stormshield 2026-012 pour les détails de remédiation spécifiques. Restreindre l'accès à la console d'administration et surveiller les journaux d'événements. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0816/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0816/) |
| **CVE-2026-6638** | 3.7 | 0.18% | FALSE | PostgreSQL | CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') | Impact potentiel d'exécution de code arbitraire, d'atteinte à la confidentialité et d'atteinte à l'intégrité des données sur le serveur SMC et les appliances managées. | None | Mettre à jour Stormshield Management Center vers la version 3.9.2. Consulter le bulletin Stormshield 2026-012 pour les détails de remédiation spécifiques. Restreindre l'accès à la console d'administration et surveiller les journaux d'événements. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0816/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0816/) |
| **CVE-2026-55204** | 8.7 | 0.43% | FALSE | haproxy | CWE-476 NULL Pointer Dereference | Déni de service à distance via crash du processus HAProxy, impactant potentiellement la disponibilité des services en aval (sites web, API, reverse proxy). | None | Mettre à jour HAProxy vers les versions correctives selon la branche utilisée (ALOHA, HAPEE). Surveiller la disponibilité des correctifs pour la Community Edition. En attendant, restreindre ou désactiver HTTP/2 si non requis et mettre en place un WAF pour filtrer les requêtes HPACK malformées. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0814/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0814/) |
| **CVE-2026-58302** | 8.4 | N/A | FALSE | LinuxCNC | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Élévation de privilèges locale vers root sur les postes LinuxCNC industriels, permettant potentiellement la compromission totale du système hôte, la modification de programmes CNC et l'altération de processus de fabrication. | Theoretical | Mettre à jour LinuxCNC vers la version 2.9.9 ou ultérieure. En attendant la mise à jour, retirer le bit SUID root de rtapi_app (chmod u-s) et valider strictement les noms de modules chargés via dlopen(). | [https://cvefeed.io/vuln/detail/CVE-2026-58302](https://cvefeed.io/vuln/detail/CVE-2026-58302) |
| **CVE-2026-7656** | 8.1 | N/A | FALSE | zephyr | CWE-670 Always-Incorrect Control Flow Implementation | Usurpation de routeur, empoisonnement du neighbor cache IPv6, MITM, redirection de trafic et déni de service sur les équipements embarqués Zephyr (IoT, industriels). L'attaquant peut reconfigurer à distance la passerelle, les serveurs DNS et les préfixes réseau. | Theoretical | Mettre à jour Zephyr vers une version corrigée (split de la condition de validation ND). En attendant, isoler les équipements vulnérables du réseau, restreindre l'accès LAN, désactiver IPv6 SLAAC/RDNSS si non requis, et surveiller le trafic ND à la recherche de messages malformés. | [https://cvefeed.io/vuln/detail/CVE-2026-7656](https://cvefeed.io/vuln/detail/CVE-2026-7656) |
| **CVE-2026-34594** | 8.8 | N/A | FALSE | coolify | CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | Exécution de code arbitraire à distance en tant que root sur les serveurs managés par Coolify, menant à la compromission totale des applications et données hébergées (self-hosted apps, bases de données, services). | Theoretical | Mettre à jour Coolify vers la version 4.0.0-beta.471 ou ultérieure. Restreindre les permissions de gestion des destinations aux administrateurs de confiance. Sanitizer tous les inputs utilisateur utilisés dans des commandes shell. Auditer les serveurs managés pour détecter d'éventuelles compromissions. | [https://cvefeed.io/vuln/detail/CVE-2026-34594](https://cvefeed.io/vuln/detail/CVE-2026-34594) |
| **CVE-2026-34597** | 8.8 | N/A | FALSE | coolify | CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | Exécution de code arbitraire à distance avec privilèges au niveau de l'hôte, compromission totale de l'infrastructure Coolify, pivot potentiel vers les serveurs et bases de données gérés, exfiltration ou destruction de données. | Theoretical | Mettre à jour Coolify vers la version 4.0.0-beta.470 ou ultérieure. Assainir et valider les paramètres de build fournis par les utilisateurs. Restreindre l'exécution de commandes utilisateur arbitraires. Revoir et durcir les configurations de sécurité de l'hôte. | [https://cvefeed.io/vuln/detail/CVE-2026-34597](https://cvefeed.io/vuln/detail/CVE-2026-34597) |
| **CVE-2026-57498** | 9.6 | N/A | FALSE | coolify | CWE-639: Authorization Bypass Through User-Controlled Key | Déploiement non autorisé sur les serveurs d'autres équipes, compromission de l'isolation multi-tenant, exécution potentielle de code dans le contexte de l'équipe cible, exposition de données sensibles et pivot latéral au sein de l'organisation. | Theoretical | Mettre à jour Coolify vers la version 4.0.0-beta.474 ou ultérieure. Vérifier que la validation d'appartenance de serveur est appliquée uniformément côté serveur. Renforcer les contrôles d'autorisation sur tous les composants Livewire. | [https://cvefeed.io/vuln/detail/CVE-2026-57498](https://cvefeed.io/vuln/detail/CVE-2026-57498) |
| **CVE-2026-55200** | 9.2 | 0.92% | FALSE | libssh2 | CWE-680 Integer Overflow to Buffer Overflow | Corruption de mémoire heap menant à une potentielle exécution de code arbitraire à distance. Compte tenu de la large diffusion de libssh2 dans des outils d'automatisation, sauvegarde, CI/CD et orchestration, l'exposition est souvent cachée (risque de dépendance fantôme). Forte surface d'attaque dans les environnements à intégration SSH externe. | Theoretical | Mettre à jour libssh2 vers une version non vulnérable. Réaliser une cartographie complète des dépendances (SBOM) intégrant libssh2. Surveiller les tailles de paquets SSH et les anomalies d'exécution. Restreindre les flux SSH sortants non nécessaires. | [https://thecyberthrone.in/2026/06/29/cve-2026-55200-critical-libssh2-flaw-opens-remote-code-execution-path/](https://thecyberthrone.in/2026/06/29/cve-2026-55200-critical-libssh2-flaw-opens-remote-code-execution-path/) |
| **CVE-2026-43503** | 8.8 | 0.13% | FALSE | Linux | Escalade de privilèges locale via paquets clonés | Élévation de privilèges locale vers root, compromission totale de l'hôte, échappement de conteneurs possible dans les environnements Kubernetes, risque de mouvement latéral et d'accès aux secrets du cluster. | Active | Appliquer les correctifs noyau fournis par les distributions. Restreindre l'usage des user namespaces et des capacités CAP_NET_ADMIN. Durcir les configurations Kubernetes (PodSecurity Standards, AppArmor/SELinux). Surveiller les comportements d'élévation de privilèges. | [https://thehackernews.com/2026/06/weekly-recap-linux-kernel-flaws-ai.html](https://thehackernews.com/2026/06/weekly-recap-linux-kernel-flaws-ai.html) |
| **CVE-2026-12569** | 9.3 | 1.11% | TRUE | Windchill PDMLink, FlexPLM | CWE-20 Improper input validation | Exécution de code arbitraire à distance, déploiement de webshells JSP sur les serveurs vulnérables observé dans des attaques actives, compromission de données industrielles sensibles (propriété intellectuelle, conceptions, données fournisseurs). | Active | Appliquer immédiatement les correctifs PTC publiés. Isoler les serveurs PDM/PLM compromis. Surveiller la présence de webshells JSP. Restreindre l'exposition réseau des serveurs PTC et renforcer la détection côté WAF/IDS. | [https://thehackernews.com/2026/06/weekly-recap-linux-kernel-flaws-ai.html](https://thehackernews.com/2026/06/weekly-recap-linux-kernel-flaws-ai.html) |
| **CVE-2026-46817** | 9.8 | 0.42% | TRUE | Oracle Payments | Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Payments.  Successful attacks of this vulnerability can result in takeover of Oracle Payments. | Prise de contrôle à distance non authentiquée d'Oracle E-Business Suite, compromission massive de données ERP, risque d'extorsion et d'exfiltration (rappel : exploitation antérieure d'une autre faille EBS fin 2025 pour extorsion), impact potentiel sur la continuité d'activité. | Active | Appliquer immédiatement le correctif Oracle publié le 28 mai pour CVE-2026-46817. Isoler les instances Oracle Payments vulnérables. Renforcer la surveillance des accès ERP. Restreindre l'exposition réseau des services Oracle et auditer les comptes. | [https://www.security.nl/posting/942521](https://www.security.nl/posting/942521) |
| **CVE-2026-11979** | 1.8 | N/A | FALSE | libxml2 | CWE-121: Stack-based Buffer Overflow | Impact indéterminé en l'absence de détails techniques complets. Les vulnérabilités libxml2 peuvent historiquement permettre des attaques par XXE, DoS, SSRF, ou exécution de code selon la nature du défaut. | None | Consulter l'avis CERT.pl original pour obtenir les détails techniques. Mettre à jour libxml2 vers la dernière version corrigée dès que disponible. Surveiller les avis officiels de l'éditeur libxml2 et du CERT.pl. | [https://cert.pl/en/posts/2026/06/CVE-2026-11979/](https://cert.pl/en/posts/2026/06/CVE-2026-11979/) |
| **CVE-2026-13165** | 8.6 | N/A | FALSE | SzafirHost | CWE-434 Unrestricted Upload of File with Dangerous Type | Impact indéterminé en l'absence de détails techniques complets dans la source. Le risque dépend de la nature exacte de la vulnérabilité et de l'exposition des instances SzafirHost. | None | Consulter l'avis CERT.pl original pour obtenir les détails techniques. Appliquer les correctifs de l'éditeur dès leur publication. Restreindre l'exposition réseau de SzafirHost. | [https://cert.pl/en/posts/2026/06/CVE-2026-13165/](https://cert.pl/en/posts/2026/06/CVE-2026-13165/) |
| **CVE-2025-8088** | 8.4 | 85.78% | TRUE | WinRAR | CWE-35 Path traversal | Exécution de code malveillant via spear-phishing, persistance via Startup folder, infection de supports amovibles et partages réseau, exfiltration de données sensibles gouvernementales et militaires ukrainiennes, collaboration observée avec Turla. | Active | Mettre à jour WinRAR au-delà de la version vulnérable. Bloquer l'exécution automatique de LNK/HTA depuis le dossier Startup. Filtrer et analyser les archives entrantes. Surveiller les canaux d'exfiltration cloud (GoFile, Dropbox, Telegra.ph, Rentry.co, Write.as). | [https://thehackernews.com/2026/06/gamaredon-expands-ukraine-attacks-with.html](https://thehackernews.com/2026/06/gamaredon-expands-ukraine-attacks-with.html) |
| **CVE-2025-67038** | 9.8 | 1.13% | TRUE | Lantronix EDS5000 (firmware basé sur OpenWrt modifié, module LuCI HTTP JSON-RPC) | n/a | Exécution de code arbitraire en root à distance sans authentification, compromission totale de l'appliance edge, persistance, pivot vers le réseau OT/IT en aval, exposition des automates PLC et capteurs industriels connectés. Compromission potentielle de la passerelle entre réseau externe et infrastructures opérationnelles sensibles. | Active | Appliquer immédiatement le correctif éditeur Lantronix pour CVE-2025-67038. À défaut, désactiver ou restreindre l'accès WAN aux interfaces LuCI/JSON-RPC. Segmenter le réseau, isoler les interfaces de gestion derrière un VPN avec MFA, surveiller les logs d'authentification LuCI pour détecter les tentatives d'injection. Suivre le catalogue CISA KEV, auditer le parc pour identifier les équipements Lantronix EDS5000 et OpenWrt exposés sur Internet, et durcir les configurations (désactivation des services non essentiels, mise à jour du firmware). | [https://fieldeffect.com/blog/openwrt-edge-device-exploitation-ot-networks](https://fieldeffect.com/blog/openwrt-edge-device-exploitation-ot-networks) |
| **CVE-2023-1389** | 8.8 | 100.00% | TRUE | TP-Link Archer AX21 (AX1800) | Command Injection | Compromission du routeur, intégration à un botnet, redirection DNS, pivot réseau, potentielle perte de confidentialité du trafic local. | Active | Mettre à jour le firmware TP-Link vers la dernière version corrigée, désactiver l'accès distant à l'interface d'administration, isoler le routeur du réseau de production, surveiller le trafic sortant et envisager le remplacement des équipements en fin de support. | [https://fieldeffect.com/blog/openwrt-edge-device-exploitation-ot-networks](https://fieldeffect.com/blog/openwrt-edge-device-exploitation-ot-networks) |
| **CVE-2023-26360** | 8.6 | 97.11% | TRUE | ColdFusion | Improper Access Control (CWE-284) | Exécution de code à distance sur le serveur ColdFusion, déploiement de webshell stéganographique, point d'ancrage pour défense impairment (désactivation Defender, kill Sysmon, dump LSASS via Mimikatz), compromission potentielle de tout le domaine. | Active | Appliquer immédiatement les correctifs Adobe ColdFusion pour CVE-2023-26360, restreindre l'accès aux interfaces /CFIDE, segmenter le serveur ColdFusion, surveiller l'intégrité des fichiers et activer une journalisation exhaustive (IIS, application, système) pour permettre la détection et la forensique. | [https://www.huntress.com/blog/mimikatz-credential-dumping-defence-impairment](https://www.huntress.com/blog/mimikatz-credential-dumping-defence-impairment) |
| **CVE-2023-29298** | 7.5 | 99.75% | TRUE | ColdFusion | Improper Access Control (CWE-284) | Accès non autorisé à des fonctions administratives ColdFusion, exposition de configurations et de données sensibles, facilitation de l'exploitation ultérieure via RCE et désérialisation. | Active | Appliquer les correctifs Adobe pour CVE-2023-29298, renforcer le contrôle d'accès sur les endpoints /CFIDE/adminapi, restreindre par IP/MFA l'accès aux fonctions administratives, surveiller les logs pour les requêtes vers les endpoints sensibles. | [https://www.huntress.com/blog/mimikatz-credential-dumping-defence-impairment](https://www.huntress.com/blog/mimikatz-credential-dumping-defence-impairment) |
| **CVE-2023-29300** | 9.8 | 99.98% | TRUE | ColdFusion | Deserialization of Untrusted Data (CWE-502) | Exécution de code arbitraire à distance sur le serveur ColdFusion, déploiement de webshell, pivot vers l'Active Directory, compromission d'identifiants et potentielle prise de contrôle du domaine. | Active | Appliquer le correctif Adobe pour CVE-2023-29300, désactiver ou restreindre fortement l'accès aux endpoints de désérialisation (/CFIDE/adminapi/customtags, .cfc), surveiller les logs pour détecter les requêtes malformées, isoler les serveurs ColdFusion non patchés et reconstruire depuis une source maîtrisée après compromission. | [https://www.huntress.com/blog/mimikatz-credential-dumping-defence-impairment](https://www.huntress.com/blog/mimikatz-credential-dumping-defence-impairment) |
| **** | N/A | N/A | FALSE | Mattermost Server versions 10.11.x (< 10.11.21), 11.6.x (< 11.6.6), 11.7.x (< 11.7.5), 11.8.x (< 11.8.2) | Multiples vulnérabilités (problème de sécurité non spécifié par l'éditeur) | Impact indéterminé en l'absence de détails techniques de l'éditeur. Risque résiduel pour les instances Mattermost Server non patchées, en particulier celles exposées à Internet ou intégrant de nombreux utilisateurs et intégrations. | None | Mettre à jour Mattermost Server vers les versions correctives (10.11.21, 11.6.6, 11.7.5, 11.8.2 selon la branche). Consulter les bulletins MMSA référencés pour les détails de remédiation spécifiques. | [https://mattermost.com/security-updates/](https://mattermost.com/security-updates/)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0813/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0813/) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="consentfix-la-nouvelle-evolution-de-clickfix-cible-microsoft-365-via-le-detournement-de-flux-oauth"></div>

## ConsentFix : la nouvelle évolution de ClickFix cible Microsoft 365 via le détournement de flux OAuth

### Résumé

Huntress documente la campagne 'ConsentFix', évolution du mode opératoire ClickFix, qui abuse des flux d'authentification Microsoft 365. La victime reçoit un leurre (souvent via Dropbox ou DocSend, parfois protégé par mot de passe) et est invitée à glisser un lien localhost dans son navigateur, ce qui déclenche une cession de jetons OAuth à un attaquant. Celui-ci obtient alors l'accès à la messagerie, OneDrive et Teams sans compromettre le mot de passe ni MFA. En mars 2026, un tutoriel complet (code, captures, vidéo) a été publié sur un forum cybercriminel russophone, rendant l'attaque reproductible. L'infrastructure repose sur des services gratuits ou largement accessibles (Cloudflare Pages, workers.dev, Pipedream, Dropbox, DocSend) et le ciblage des victimes est préparé via LinkedIn, ZoomInfo et Hunter.io.

---

### Analyse opérationnelle

Les équipes SOC doivent détecter les consentements OAuth non maîtrisés et les URI de redirection localhost/127.0.0.1. Les filtres mail doivent bloquer Dropbox/DocSend non sollicités et les fichiers protégés par mot de passe. Le runbook Microsoft 365 doit inclure la révocation immédiate des jetons de la session compromise (Revoke-AzureADUserAllRefreshToken), la suppression de l'application OAuth frauduleuse et le changement forcé des credentials. Les politiques Conditional Access doivent imposer des facteurs résistants au phishing (FIDO2) et restreindre les consentements aux éditeurs vérifiés. Une surveillance renforcée des connexions post-consentement (géolocalisation, user agent, IP) doit être ajoutée au SIEM, couplée à des règles Defender for Cloud Apps pour bloquer les applications à haut risque.

---

### Implications stratégiques

La démocratisation du tutoriel sur les forums russophones accélère la diffusion massive de la technique et abaisse le niveau technique requis. Le modèle 'OAuth-consent-as-a-service' menace directement les organisations très dépendantes de Microsoft 365. La confiance accordée aux workflows familiers (glisser-déposer, prompts système) constitue désormais une surface d'attaque psychologique majeure. Les directions doivent investir dans la sensibilisation comportementale, durcir la gouvernance des identités cloud et intégrer le risque de vol de jetons dans leur cyber-assurance et leur modélisation de risque.

---

### Recommandations

* Restreindre les consentements OAuth aux applications validées par le tenant et auditer les consentements existants.
* Imposer l'authentification multifacteur résistante au phishing (FIDO2, Windows Hello for Business) pour les comptes Microsoft 365.
* Bloquer en passerelle mail les liens Dropbox/DocSend non sollicités et signaler les pièces jointes protégées par mot de passe.
* Activer Defender for Cloud Apps / Microsoft Defender for Identity et créer des alertes sur les consentements inhabituels.
* Former les utilisateurs au danger spécifique de glisser un lien dans le navigateur ('drag-and-drop trap').

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser les utilisateurs aux attaques de type ClickFix/ConsentFix (prompts Ctrl+V, liens localhost glissés dans le navigateur).
* Renforcer les politiques OAuth : restreindre les consentements aux applications vérifiées par l'éditeur ou l'organisation.
* Activer le Conditional Access Microsoft 365 imposant MFA résistante au phishing (FIDO2, certificats).
* Bloquer en mail gateway les liens vers Dropbox/DocSend non sollicités et surveiller l'usage sortant.
* Documenter la procédure de révocation de sessions OAuth dans le runbook IR.

#### Phase 2 — Détection et analyse

* Détecter les consentements OAuth inhabituels via les journaux Microsoft Entra (Activity: Consent to application).
* Alerter sur les flux impliquant des URI de redirection localhost ou des domaines workers.dev/Cloudflare Pages suspects.
* Corréler les connexions inhabituelles post-consentement (géolocalisation, user agent atypique, IP non répertoriée).
* Surveiller les accès anormaux à OneDrive, Outlook, Teams après un événement de consentement.
* Activer les règles Defender for Cloud Apps / MCAS sur les applications OAuth à haut risque.

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement les refresh tokens de la session compromise via Microsoft Entra (Revoke-AzureADUserAllRefreshToken).
* Désactiver l'application OAuth malveillante et bloquer son éditeur.
* Forcer la déconnexion globale du compte utilisateur (Revoke session) et imposer changement de mot de passe + ré-enrollment MFA.
* Isoler l'hôte de l'utilisateur pour analyse (EDR) en cas de doute sur compromission locale via ClickFix.
* Notifier les parties prenantes et préserver les journaux Unified Audit Log / CloudTrail pour analyse.

#### Phase 4 — Activités post-incident

* Auditer tous les consentements OAuth accordés récemment dans le tenant et supprimer les non maîtrisés.
* Examiner la boîte mail de la victime pour identifier d'éventuels autres destinataires du même leurre.
* Mettre à jour les signatures mail anti-phishing et bloquer les IOC identifiés (domaines, expéditeurs, templates).
* Revoir les politiques Conditional Access et imposer l'authentification résistante au phishing.
* Rédiger un rapport d'incident détaillant la chaîne d'attaque, l'impact et les enseignements.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux Entra les consentements accordés vers des applications sans éditeur vérifié.
* Chasser les connexions signin.microsoft.com avec redirect_uri contenant 'localhost' ou '127.0.0.1'.
* Rechercher les créations de fichiers inhabituels dans OneDrive/SharePoint post-consentement.
* Identifier les utilisateurs ayant interagi avec Dropbox/DocSend dans les 14 jours précédents l'incident.
* Surveiller les soumissions de domaines sur des services d'hébergement gratuit (Cloudflare Pages, workers.dev) imitant des marques.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `hxxps://workers[.]dev` | Medium |
| DOMAIN | `hxxps://hunter[.]io` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Hameçonnage |
| **T1204** | Exécution par l'utilisateur |
| **T1528** | Vol de jetons d'accès applicatifs |
| **T1078** | Comptes cloud valides abusés via jetons OAuth |
| **T1589** | Collecte d'informations sur les victimes (LinkedIn, ZoomInfo, Hunter.io) |

---

### Sources

* [https://www.huntress.com/blog/hacker-tactics-2026-dark-web-playbook](https://www.huntress.com/blog/hacker-tactics-2026-dark-web-playbook)


---

<div id="vulnerabilites-critiques-sur-les-controleurs-daktronics-panneaux-autoroutiers-et-billboards-exposes-au-piratage-a-distance"></div>

## Vulnérabilités critiques sur les contrôleurs Daktronics : panneaux autoroutiers et billboards exposés au piratage à distance

### Résumé

CISA a publié un avis concernant trois vulnérabilités affectant les contrôleurs Daktronics VFC-DMP-5000, DMP-5000 et DMP-8000 utilisés pour piloter panneaux autoroutiers, billboards et grands écrans. Les failles incluent un path traversal exploitable sans authentification, un upload de fichier arbitraire authentifié, et la présence d'identifiants administrateur par défaut. Selon le chercheur Thomas Jou (Princeton), plusieurs contrôleurs exposés sur Internet sont encore en mot de passe par défaut. L'exploitation combinée permet d'obtenir un accès root complet et d'altérer le contenu affiché. Daktronics a publié des correctifs firmware début mars 2026.

---

### Analyse opérationnelle

Les exploitants d'autoroutes, aéroports, stades et villes utilisant ces contrôleurs doivent appliquer sans délai les firmwares corrigés, changer tous les mots de passe par défaut et cartographier l'exposition Internet (Shodan, Censys). La segmentation réseau doit isoler les équipements OT du reste du SI. Les SOC doivent détecter les requêtes path traversal, les uploads non autorisés et les modifications inopinées de contenu. Une procédure de bascule vers message statique validé doit être prête pour les panneaux critiques. Un audit complet du parc d'afficheurs dynamiques (Daktronics et autres marques) est indispensable.

---

### Implications stratégiques

L'incident illustre la faiblesse persistante des composants OT/ICS exposés sur Internet et l'absence de gestion rigoureuse des identifiants par défaut. La falsification de panneaux autoroutiers constitue un risque direct pour la sécurité publique (fausses alertes, instructions dangereuses). Le secteur du transport et les opérateurs d'infrastructures critiques doivent intégrer la gestion du risque sur les équipements tiers d'affichage dans leurs programmes de cyber-résilience et dans leur conformité NIS2.

---

### Recommandations

* Appliquer immédiatement les firmwares patchés Daktronics sur tous les contrôleurs concernés.
* Changer sans délai les identifiants administrateur par défaut sur l'ensemble du parc.
* Cartographier l'exposition Internet des contrôleurs et supprimer tout accès non indispensable.
* Segmenter le réseau OT des afficheurs du reste du SI (VLAN dédié, pare-feu industriel).
* Établir une procédure de bascule rapide vers un message statique validé en cas d'incident.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier tous les contrôleurs Daktronics VFC-DMP-5000, DMP-5000 et DMP-8000 exposés sur Internet (Shodan, Censys, asset management).
* Vérifier que les firmwares sont à jour selon l'avis CISA publié fin juin 2026.
* Documenter et appliquer la procédure de changement des identifiants administrateur par défaut avant toute mise en service.
* Segmenter le réseau des afficheurs et panneaux du reste du SI (VLAN dédié, ACL, pas d'exposition Internet directe).
* Préparer une procédure de coupure/commutation vers message statique validé en cas de compromission d'un afficheur.

#### Phase 2 — Détection et analyse

* Détecter les requêtes contenant des séquences de path traversal (../) sur les contrôleurs Daktronics exposés.
* Surveiller les uploads non autorisés vers les interfaces d'administration (taille, extensions atypiques).
* Alerter sur les connexions d'administration depuis des IP ou pays inhabituels.
* Surveiller les modifications inopinées de contenu sur les panneaux (diffusion d'images non approuvées).
* Rechercher les authentifications avec les identifiants par défaut (admin/admin) dans les logs.

#### Phase 3 — Confinement, éradication et récupération

* Couper immédiatement l'accès réseau Internet aux contrôleurs affectés (firewall, NAT).
* Isoler le contrôleur du réseau de signalisation pour éviter tout déplacement latéral.
* Forcer la réinitialisation des identifiants administrateur et appliquer le firmware corrigé.
* Basculer les afficheurs critiques (panneaux autoroutiers) en mode message prédéfini validé.
* Notifier les autorités de sécurité publique si des panneaux de signalisation ont été altérés.

#### Phase 4 — Activités post-incident

* Confirmer l'intégrité du firmware et comparer avec une image propre connue.
* Auditer les autres contrôleurs du même parc (Daktronics et autres vendors) pour les mêmes faiblesses.
* Analyser les logs de trafic pour identifier d'éventuelles compromissions antérieures.
* Documenter l'incident et partager les IOC avec CISA / communautés sectorielles (ITSCC, ISAC transport).
* Renforcer la politique de gestion des identifiants par défaut pour tous les équipements OT.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher sur Internet (Shodan, Censys) les contrôleurs Daktronics toujours exposés et vérifier leur version firmware.
* Identifier toute tentative de path traversal dans les logs Web/WAF sur les équipements d'affichage.
* Chasser les uploads de fichiers vers les contrôleurs depuis des comptes internes non autorisés.
* Identifier les comptes n'ayant jamais eu leur mot de passe changé depuis l'installation (default credentials).
* Surveiller l'apparition de contenus ou de fichiers inhabituels sur les serveurs de gestion d'affichage.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploit d'application exposée sur Internet (contrôleurs Daktronics) |
| **T1083** | Reconnaissance de fichiers via path traversal |
| **T1078.001** | Abus de comptes administrateur par défaut |
| **T1505.003** | Upload malveillant de contenu/code sur le contrôleur |
| **T0836** | Modification de paramètres d'affichage (impact ICS sur signalisation routière) |

---

### Sources

* [https://www.securityweek.com/new-controller-flaws-expose-highway-signs-and-billboards-to-remote-hacking/](https://www.securityweek.com/new-controller-flaws-expose-highway-signs-and-billboards-to-remote-hacking/)


---

<div id="analyse-de-malwares-partie-10-parsing-pe-en-pratique-avec-python"></div>

## Analyse de malwares – partie 10 : parsing PE en pratique avec Python

### Résumé

L'article constitue un didacticiel expliquant comment analyser la structure d'un exécutable Windows (format PE) à l'aide de scripts Python simples. Il couvre la lecture des en-têtes, des sections, des imports et la détection d'indicateurs de packing (entropie élevée). Il s'inscrit dans une série pédagogique dédiée au reverse engineering de binaires malveillants.

---

### Analyse opérationnelle

Les analystes SOC de niveau 2/3 peuvent s'appuyer sur cette méthodologie pour automatiser le triage d'échantillons suspects et générer rapidement des indicateurs (hash de sections, imports caractéristiques) exploitables en YARA et Sigma. Les scripts Python proposés sont directement intégrables dans un pipeline de sandbox ou d'analyse statique. L'approche renforce la capacité d'identification de binaires packés, injecteurs et loaders, et alimente la base de connaissances en signatures internes.

---

### Implications stratégiques

Le renforcement des compétences en analyse PE dans les équipes de sécurité réduit la dépendance aux outils externes et accélère le délai de réponse sur les menaces personnalisées ou inédites. Il contribue à la maturité globale du SOC et à la capacité à traiter des malwares avancés en interne.

---

### Recommandations

* Intégrer les scripts de parsing PE dans le workflow de triage de la sandbox.
* Créer des règles YARA basées sur les caractéristiques PE couramment observées.
* Former régulièrement les analystes au reverse engineering de base (entropie, imports, sections).
* Maintenir une bibliothèque interne de signatures de packers.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Disposer d'un environnement de reverse engineering isolé (VM) avec Python, pefile, radare2 et Ghidra.
* Former les analystes SOC niveau 2/3 à l'analyse PE de base (sections, imports, entropie).
* Préparer des scripts Python réutilisables pour le parsing PE.
* Maintenir une bibliothèque de signatures de packers et d'anomalies PE connues.
* Définir un workflow d'analyse (statique → dynamique → YARA).

#### Phase 2 — Détection et analyse

* Utiliser les résultats de parsing PE pour alimenter les règles YARA sur les échantillons suspects.
* Détecter les entropies anormales par section (chiffrement/packing) dans les binaires collectés.
* Identifier les imports inhabituels (VirtualAlloc, WriteProcessMemory, etc.) via sandbox.
* Diffuser les empreintes (hash, sections caractéristiques) vers EDR et SIEM.
* Corréler les imports avec les TTPs MITRE suspectées.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les hôtes exécutant des binaires présentant des caractéristiques PE malveillantes identifiées.
* Mettre en quarantaine les échantillons dans l'environnement d'analyse.
* Bloquer en EDR les processus présentant des patterns d'import suspects.
* Désactiver les comptes/services liés à l'exécution du binaire.

#### Phase 4 — Activités post-incident

* Documenter les caractéristiques du binaire (sections, imports, entropie, signatures).
* Créer des règles YARA et Sigma dérivées et les déployer sur l'infrastructure de détection.
* Capitaliser les IOC associés (hash, C2) dans le référentiel threat intel.
* Partager les conclusions avec l'équipe de détection et le SOC externe si pertinent.

#### Phase 5 — Threat Hunting (proactif)

* Chasser dans l'historique des fichiers les binaires présentant des caractéristiques PE proches.
* Identifier les sections aux noms inhabituels ou aux entropies élevées sur les fichiers découverts.
* Rechercher les imports rares ou typiques de packers/loaders connus.
* Explorer les chaînes de compilation et les artefacts de packer résiduels.
* Diffuser les scripts de parsing adaptés aux particularités identifiées.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1027** | Obfuscation/encodage de binaires (analyse PE) |

---

### Sources

* [https://cocomelonc.github.io/malware/2026/06/29/malware-analysis-10.html](https://cocomelonc.github.io/malware/2026/06/29/malware-analysis-10.html)


---

<div id="cloudtrail-source-de-preuve-principale-pour-les-investigations-sur-aws"></div>

## CloudTrail, source de preuve principale pour les investigations sur AWS

### Résumé

L'article rappelle que CloudTrail est l'équivalent AWS des journaux d'événements Windows et enregistre chaque appel d'API passé dans l'environnement AWS. Il différencie les Management Events (plan de contrôle, activés par défaut, 90 jours) des Data Events (plan de données, désactivés par défaut) et insiste sur la nécessité d'activer ces derniers pour disposer d'une traçabilité complète lors d'incidents. Il détaille les champs clés (eventTime, userIdentity, eventSource, eventName, sourceIPAddress, userAgent) et précise que le SLA de latence est de 15 minutes. CloudTrail ne capture pas l'activité à l'intérieur d'une instance EC2 : EDR/XDR reste indispensable pour ce périmètre.

---

### Analyse opérationnelle

Les équipes SecOps doivent impérativement créer un trail CloudTrail avec rétention étendue, activer les Data Events sur les buckets S3 et fonctions Lambda sensibles, et centraliser les logs dans le SIEM. Le playbook d'incident doit explicitement vérifier l'activation de ces Data Events, sous peine de travailler avec des preuves partielles. Les détections doivent couvrir ConsoleLogin sans MFA, création d'AccessKey, modifications de SecurityGroup, exfiltration GetObject et usage de credentials depuis des user-agent atypiques. CloudTrail ne remplace pas l'EDR : un incident impliquant du code malveillant sur EC2 nécessite l'EDR et les journaux internes de l'instance.

---

### Implications stratégiques

La méconnaissance de la distinction Management/Data Events conduit à des angles morts majeurs lors d'enquêtes sur des fuites de données S3. Les directions doivent valider que la gouvernance Cloud inclut l'activation des Data Events et la conservation long terme des journaux pour les besoins de conformité (NIS2, RGPD, audits). L'article rappelle enfin que la supervision du cloud sans EDR sur les workloads expose à une réponse incomplète en cas d'intrusion.

---

### Recommandations

* Créer un trail CloudTrail multi-régions avec stockage S3 sécurisé et verrouillage d'objets.
* Activer les Data Events sur tous les buckets S3 contenant des données sensibles ou réglementées.
* Centraliser les logs CloudTrail dans le SIEM avec rétention > 90 jours.
* Combiner CloudTrail avec GuardDuty, Security Hub et EDR sur les workloads EC2.
* Vérifier systématiquement l'état d'activation des Data Events en début d'incident.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Créer un trail CloudTrail multi-régions avec stockage S3 et verrouillage d'objets (Object Lock).
* Activer les Data Events sur les buckets S3 sensibles et les fonctions Lambda critiques.
* Centraliser les logs CloudTrail dans un SIEM avec rétention supérieure à 90 jours.
* Activer GuardDuty et AWS Security Hub pour la détection continue.
* Documenter les champs clés CloudTrail (eventTime, userIdentity, eventName, sourceIPAddress) pour les analystes.

#### Phase 2 — Détection et analyse

* Détecter les ConsoleLogin sans MFA ou depuis des IP inhabituelles.
* Alerter sur la création d'AccessKey et d'utilisateurs IAM non planifiés (CreateAccessKey, CreateUser).
* Détecter les GetObject massifs ou depuis des IP atypiques (exfiltration S3).
* Identifier les modifications de SecurityGroup et les ouvertures de ports (AuthorizeSecurityGroupIngress).
* Corréler les RunInstances avec des User-Agent suspects (lambda.amazonaws.com sur activité interactive).

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement les AccessKey compromises via IAM.
* Désactiver l'utilisateur IAM impliqué et supprimer les clés associées.
* Isoler les instances EC2 compromises (security group dédié, deny all).
* Restaurer les buckets S3 affectés depuis une version antérieure ou via Object Versioning.
* Couper la session via AWS Console (force sign-out).

#### Phase 4 — Activités post-incident

* Reconstituer la timeline complète de l'incident à partir des événements CloudTrail archivés.
* Auditer l'ensemble des actions de l'utilisateur/role impliqué sur la période compromise.
* Calculer le périmètre de l'exfiltration S3 et notifier les parties prenantes (DPO, juridique).
* Durcir les politiques IAM (least privilege) et les règles de GuardDuty.
* Documenter l'incident, créer des playbooks spécifiques et partager les enseignements.

#### Phase 5 — Threat Hunting (proactif)

* Chasser les AssumeRole en cascade inhabituels et les chaînes de privilèges anormales.
* Identifier les Data Events S3 non activés mais montrant des GetObject suspects dans les logs d'accès.
* Rechercher les activités de reconnaissance (ListBuckets, DescribeInstances, GetCallerIdentity) en rafale.
* Identifier les ressources déployées hors des régions approuvées.
* Surveiller l'utilisation de credentials depuis des user-agent atypiques.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078.004** | Abus de comptes cloud (AWS) |
| **T1530** | Accès à des données stockées dans le cloud (exfiltration S3) |
| **T1580** | Découverte de l'infrastructure cloud |
| **T1098** | Manipulation de comptes cloud (création AccessKey, modification IAM) |

---

### Sources

* [https://www.cyberengage.org/post/cloudtrail-your-primary-source-of-evidence-in-aws](https://www.cyberengage.org/post/cloudtrail-your-primary-source-of-evidence-in-aws)


---

<div id="automatiser-la-reconnaissance-dhotes-via-le-hash-de-faviconico-et-shodan"></div>

## Automatiser la reconnaissance d'hôtes via le hash de favicon.ico et Shodan

### Résumé

Rob VandenBrink (SANS ISC) présente un script d'automatisation permettant d'extraire le hash mmh3 d'un favicon.ico puis de requêter l'API Shodan pour récupérer la liste des hostnames partageant ce même hash. Cette méthode, déjà documentée par Jan, permet d'élargir la surface découverte d'une cible lors d'un pentest, notamment dans les environnements cloud. L'exemple utilise le domaine canada.ca, illustrant comment retrouver plusieurs hôtes (cfc.forces.gc.ca, cfc.dnd.ca, etc.) à partir d'un seul hash.

---

### Analyse opérationnelle

Les Blue Teams doivent savoir que cette technique permet à un attaquant de découvrir des hôtes internes exposés mais absents des inventaires traditionnels. Il convient de surveiller les requêtes massives vers /favicon.ico depuis des IP non légitimes, de diversifier les favicons sur les domaines secondaires pour casser la corrélation, et de réaliser une chasse régulière sur Shodan pour identifier les hash de favicon associés à l'organisation. Les WAF doivent rate-limiter les accès aux fichiers statiques et bloquer les IP générant du scraping.

---

### Implications stratégiques

La démocratisation des techniques OSINT automatisées élève le niveau de base de la reconnaissance adverse et impose aux entreprises un inventaire en continu de leurs assets exposés. Les directions doivent intégrer la gestion des empreintes web (favicon, headers, TLS) dans leur stratégie de réduction de surface d'attaque et traiter les assets fantômes découverts par ces méthodes avec la même rigueur que les actifs inventoriés.

---

### Recommandations

* Auditer les hash de favicon associés à l'organisation sur Shodan et Censys.
* Diversifier les favicons sur les domaines secondaires pour limiter la corrélation.
* Activer le rate-limiting et la détection de scraping sur les fichiers statiques exposés.
* Maintenir un inventaire dynamique des assets exposés comparé aux assets internes autorisés.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser les équipes Blue Team à la méthode de reconnaissance par hash de favicon.ico.
* Cartographier en interne les assets exposés présentant le même hash de favicon.
* Auditer la diversité des favicons utilisés sur les domaines de l'organisation.
* Surveiller les expositions sur Shodan/Censys/Fofa pour les assets internes.

#### Phase 2 — Détection et analyse

* Détecter les requêtes massives vers /favicon.ico provenant d'IP non légitimes.
* Surveiller les accès anormaux aux fichiers statiques depuis des IP externes.
* Identifier dans les WAF les patterns de scraping (User-Agent, fréquence).
* Détecter les pics de trafic sur des assets internes non sensibles mais identiques (recon).

#### Phase 3 — Confinement, éradication et récupération

* Bloquer en WAF les IP sources de scraping / reconnaissance.
* Limiter l'exposition des favicons internes sur Internet (CDN, filtrage).
* Mettre en place du rate-limiting sur les fichiers statiques exposés.
* Couper les hôtes découverts comme exposés alors qu'ils ne devraient pas l'être.

#### Phase 4 — Activités post-incident

* Documenter les méthodes de reconnaissance observées pour affiner la défense.
* Renforcer la politique d'exposition des assets internes.
* Diversifier les favicons pour casser la corrélation multi-hôtes.
* Auditer régulièrement les inventaires d'assets vs. exposition réelle.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher sur Shodan les hash de favicon correspondant à l'organisation.
* Identifier des hôtes internes non inventoriés remontant par corrélation favicon.
* Chasser les requêtes /favicon.ico depuis des IP anonymisées (Tor, VPN).
* Identifier des patterns d'attaque par corrélation de favicons inter-secteurs.
* Suivre les nouveaux articles publics décrivant des techniques de fingerprinting similaires.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `shodan[.]io` | High |
| URL | `hxxps://api[.]shodan[.]io/shodan/host/search` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1595.002** | Collecte d'informations - empreinte de site web (favicon hash) |
| **T1590** | Collecte d'informations réseau (Shodan, DNS) |
| **T1592** | Collecte d'informations sur l'hôte |

---

### Sources

* [https://isc.sans.edu/diary/rss/33110](https://isc.sans.edu/diary/rss/33110)


---

<div id="mustang-panda-vise-les-secteurs-gouvernemental-et-energetique-indiens-avec-zohomurk-et-minirecon"></div>

## Mustang Panda vise les secteurs gouvernemental et énergétique indiens avec ZOHOMURK et MINIRECON

### Résumé

Le groupe APT Mustang Panda, attribué à la Chine, a conduit une campagne de cyberespionnage ciblant des entités gouvernementales et du secteur de l'énergie en Inde. Les chercheurs rapportent l'usage des malwares ZOHOMURK (loader/loader intermédiaire) et MINIRECON (implants de reconnaissance) déployés via des documents spear-phishés. La campagne illustre une nouvelle itération de l'arsenal historique du groupe, reconcentré sur des cibles étatiques et stratégiques sud-asiatiques.

---

### Analyse opérationnelle

Les équipes SOC doivent immédiatement déployer des règles de détection (Sigma/YARA) pour ZOHOMURK et MINIRECON et renforcer la surveillance EDR sur les endpoints exposés (chaînes Office → LOLBins → binaire signé anormal). Il faut auditer les flux sortants (HTTP/HTTPS, DNS) vers les IOC Mustang Panda, isoler les hôtes suspects via l'EDR et chasser rétrospectivement ces IOC sur 90+ jours. Les passerelles de messagerie doivent bloquer ISO/LNK/Chm dans les archives protégées par mot de passe et appliquer l'AMSI/EDR sur les scripts Office. Côté OT, segmenter strictement les réseaux énergie et journaliser toute connexion inhabituelle depuis les couches IT vers SCADA/ICS.

---

### Implications stratégiques

Cette campagne confirme la persistance de Mustang Panda sur l'axe Inde–Chine et l'élévation du cyberespionnage autour des infrastructures critiques (énergie) et des institutions étatiques. Pour les organisations indiennes et leurs partenaires internationaux, le risque d'exfiltration de données classifiées, de compromissions d'OT et d'effets de supply-chain est accru. Les décideurs doivent renforcer la coopération CERT-In/ANSSI, investir en threat hunting dédié APT-CN et intégrer un scénario Mustang Panda dans les exercices de crise. À moyen terme, cela impose une revue du risque géopolitique et une cartographie des dépendances critiques avec l'écosystème indien.

---

### Recommandations

* Déployer en urgence les règles de détection YARA/Sigma pour ZOHOMURK et MINIRECON
* Bloquer les IOC Mustang Panda au périmètre et auditer les logs historiques
* Durcir la messagerie : désactivation macros, sandbox ISO/LNK, MFA FIDO2
* Segmenter les réseaux OT/IT et surveiller les passerelles vers SCADA
* Mener une chasse rétroactive 90+ jours sur les endpoints du secteur énergie et gouvernement
* Notifier CERT-In et partager les IOC avec les communautés sectorielles ISAC

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir une cartographie des secteurs gouvernementaux et énergétiques exposés à l'APT Mustang Panda
* Constituer et tester une signature YARA et des règles Sigma dédiées aux familles ZOHOMURK et MINIRECON
* Durcir les passerelles de messagerie (sandboxing URL/pièces jointes, désactivation macros, bloqueurs de fichiers ISO/LNK)
* Segmenter les réseaux OT/SCADA et surveiller strictement les flux sortants vers Internet
* Planifier des exercices de table-top ciblant un scénario d'intrusion APT étatique sur énergie

#### Phase 2 — Détection et analyse

* Rechercher les artefacts ZOHOMURK/MINIRECON (noms de fichiers, clés Run/Persistence, mutex) sur les hôtes des entités cibles
* Alerter sur les processus enfants suspects issus de Winword/Excel/PowerShell et l'exécution de binaires depuis %TEMP%
* Détecter les connexions C2 sortantes vers les IOC connus (IPs/domaines Mustang Panda) via NDR/proxy/DNS logs
* Monitorer les téléchargements de loaders ddl/EXE depuis des liens raccourcis ou des archives protégées par mot de passe
* Corréler les alertes avec les secteurs gouvernement et énergie pour identifier une compromission sectorielle

#### Phase 3 — Confinement, éradication et récupération

* Isoler les endpoints compromis via EDR (network containment) et bloquer les comptes utilisateurs/identifiants exposés
* Révoquer les jetons, sessions et mots de passe des comptes impactés (Active Directory, VPN, applications métier)
* Bloquer en urgence les IOC réseau au niveau firewall, proxy, DNS et passerelle de messagerie
* Mettre en quarantaine les pièces jointes et URLs malveillantes dans toutes les boîtes aux lettres organisationnelles
* Préserver les preuves forensiques (images mémoire, disque, journaux EDR) avant toute remédiation

#### Phase 4 — Activités post-incident

* Mener une revue forensique complète pour identifier la chaîne d'attaque complète (vecteur initial → C2 → objectifs)
* Notifier les autorités nationales de cybersécurité (CERT-In pour l'Inde, ANSSI/partenaires internationaux)
* Communiquer aux parties prenantes gouvernementales et opérateurs énergétiques impactés
* Évaluer l'exfiltration de données sensibles (diplomatique, réglementaire, infrastructure énergie) et piloter la divulgation
* Mettre à jour le référentiel de threat intel avec les TTP/IOC de la campagne et durcir les contrôles résiduels

#### Phase 5 — Threat Hunting (proactif)

* Chasser les signatures ZOHOMURK/MINIRECON sur l'historique EDR (minage 90+ jours) sur tous les endpoints
* Rechercher des preuves de persistance (services, tâches planifiées, clés Run/RunOnce, WMI Event Consumers)
* Identifier les communications sortantes vers les IOC connus de Mustang Panda dans les journaux proxy/DNS/firewall historiques
* Détecter des anomalies sur les comptes à privilèges du secteur gouvernement et énergie
* Réaliser une cartographie MITRE ATT&CK des TTP observés et aligner les hypothèses de chasse sur les techniques manquantes

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.001** | Spear-phishing via pièce jointe malveillante |
| **T1059.003** | Exécution de commandes/scripts via Windows Command Shell |
| **T1083** | Énumération de fichiers et répertoires |
| **T1027** | Fichiers ou informations obfusquées |
| **T1071.001** | Protocole applicatif Web (C2 via HTTP/HTTPS) |

---

### Sources

* [https://www.reddit.com/r/blueteamsec/comments/1ujfmlv/mustang_panda_targets_indias_government_and/](https://www.reddit.com/r/blueteamsec/comments/1ujfmlv/mustang_panda_targets_indias_government_and/)


---

<div id="mark-of-the-web-la-protection-change-les-outils-danalyse-suivent-mal"></div>

## Mark-of-the-Web : la protection change, les outils d'analyse suivent mal

### Résumé

L'article analyse les changements récents de comportement de Windows vis-à-vis du Mark-of-the-Web (MOTW) — la zone de provenance Internet apposée par SmartScreen/Defender — et souligne que de nombreux outils de sécurité (EDR, sandboxes, scripts internes) n'ont pas encore aligné leurs règles de détection avec ces évolutions. Résultat : des fichiers téléchargés qui devraient déclencher des avertissements ne sont plus correctement flaggés, ouvrant une fenêtre pour des charges malveillantes, notamment via archives ZIP/ISO et raccourcis LNK. L'analyse détaille les mécanismes d'atténuation désormais attendus (et les angles morts persistants) pour les défenseurs.

---

### Analyse opérationnelle

Les équipes SOC doivent vérifier que leurs pipelines d'analyse intègrent bien les nouveaux flux MOTW et durcir les règles EDR/Defender contre le strip MOTW (ex: copie via shell, archives ré-encodées). Il faut auditer les scripts internes manipulant des fichiers téléchargés et s'assurer que les alertes restent pertinentes malgré l'évolution des heuristiques Microsoft. Les tests de validation de payload doivent explicitement couvrir le contournement MOTW (ISO, VHD, ZIP protégés par mot de passe, LNK dans ZIP). Côté Windows, renforcer SmartScreen, AMSI et la journalisation de l'Alternate Data Stream Zone.Identifier pour permettre la détection.

---

### Implications stratégiques

Le décalage entre l'évolution défensive de Microsoft et les outils tiers crée une fenêtre tactique pour les attaquants et expose les organisations matures à un faux sentiment de sécurité. Les RSSI doivent redéfinir leur politique de gestion des fichiers téléchargés, intégrer ce risque dans les comités Cyber et budgéter la mise à jour des outils de sécurité. Sur le plan sectoriel, cela touche particulièrement les secteurs fortement exposés au phishing (finance, santé, secteur public) qui s'appuient sur des workflows de fichiers issus du Web.

---

### Recommandations

* Vérifier l'alignement des règles EDR/Defender/Sigma avec les nouveaux comportements MOTW
* Auditer les scripts internes qui dépouillent/recopient les fichiers téléchargés
* Renforcer la journalisation Zone.Identifier via GPO et centraliser dans le SIEM
* Durcir la politique d'exécution sur ISO/VHD/ZIP protégés par mot de passe
* Intégrer des scénarios de bypass MOTW dans les exercices Red/Purple Team

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier l'usage des formats bureautiques téléchargés et les outils d'analyse présents dans le parc
* Vérifier les politiques SmartScreen, AMSI et les GPO liées au Mark-of-the-Web
* Configurer Microsoft Defender / EDR pour journaliser les événements MOTW et les contournements associés
* Former les utilisateurs à la signalisation des fichiers 'marqués' non bloqués
* Mettre en place une liste blanche stricte des applications autorisées à exécuter du contenu MOTW

#### Phase 2 — Détection et analyse

* Alerter sur les fichiers Internet Zone/MOTW ouverts sans avertissement SmartScreen
* Détecter l'usage de Mark-of-the-Web stripping via outils ou scripts (ex: copy/zip/réencodage)
* Identifier les binaires exécutés depuis %TEMP% / Downloads sans l'attribut MOTW attendu
* Surveiller les erreurs SmartScreen et les événements Defender liés au bypass MOTW
* Repérer les documents Office chargés de macros signés ou protégés par mot de passe

#### Phase 3 — Confinement, éradication et récupération

* Mettre en quarantaine les fichiers détectés comme suspects via EDR/Defender
* Bloquer les processus d'office automation suspects jusqu'à analyse forensique
* Isoler les hôtes présentant une exécution réussie post-bypass MOTW
* Désactiver temporairement l'usage de macros VBA et limiter l'exécution PowerShell non signée
* Préserver les fichiers originaux (avec et sans MOTW) pour analyse

#### Phase 4 — Activités post-incident

* Analyser les fichiers utilisés pour le bypass et identifier l'auteur/vecteur d'attaque
* Mettre à jour les règles Defender/EDR contre les techniques de strip MOTW connues
* Communiquer aux équipes IT sur les formats de fichiers sensibles (ISO, VHD, ZIP) et leur traitement
* Renforcer les GPO Windows pour réimposer le marquage MOTW (Zone.Identifier)
* Documenter le scénario de bypass dans le référentiel interne de threat intel

#### Phase 5 — Threat Hunting (proactif)

* Chercher dans l'historique EDR les ouvertures de fichiers MOTW suivies d'activités suspectes (LOLBins, WMI)
* Identifier les hôtes ayant ouvert un fichier 'Zone.Identifier=0' ou sans MOTW malgré provenance Internet
* Détecter les outils/utilitaires connus de strip MOTW (ex: motwfix, SigThief-like) dans le SI
* Rechercher les téléchargements d'archives protégées par mot de passe depuis webmail ou cloud
* Cartographier les techniques de bypass MOTW vs l'inventaire MITRE ATT&CK

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1218.011** | Exécution via fichier signé ou contournement de la marque Web (MOTW) |
| **T1553.005** | Subversion des contrôles de sécurité via fichiers téléchargés |
| **T1059.001** | Exécution PowerShell |

---

### Sources

* [https://www.reddit.com/r/blueteamsec/comments/1ujfl00/markoftheweb_the_rules_changed_the_tools_didnt/](https://www.reddit.com/r/blueteamsec/comments/1ujfl00/markoftheweb_the_rules_changed_the_tools_didnt/)


---

<div id="hyperviseurs-malveillants-partie-2-eptnpt-vues-partagees-et-preuves-de-faults-de-second-stage"></div>

## Hyperviseurs malveillants, partie 2 : EPT/NPT, vues partagées et preuves de faults de second stage

### Résumé

L'article est la deuxième partie d'une série technique analysant les 'hypervisor cheats' : des malwares qui s'installent en ring -1 sous l'OS via les mécanismes de virtualisation matérielle Intel (EPT) et AMD (NPT). Il décrit comment ces hyperviseurs cachent du contenu au système invité (split view mémoire), modifient silencieusement des pages et exposent des preuves via les faults de second stage exploitables pour la détection. L'auteur détaille les artefacts laissés (incohérences mémoire, anomalies CPU) et les approches défensives pour les repérer.

---

### Analyse opérationnelle

Pour les SOC/DFIR, l'enjeu est de détecter la présence d'hyperviseurs non légitimes (rootkits ring -1) en s'appuyant sur la forensique mémoire et l'analyse des structures VMCS/EPT/NPT. Il faut intégrer dans le SIEM des indicateurs d'environnement virtualisé inattendu (CPUID, MSR, anomalies de timing) et renforcer les contrôles d'intégrité (Secure Boot, TPM, driver signature enforcement). Les solutions EDR doivent être testées contre les scénarios de split view et les méthodes de bypass mémoire ; envisager la mémoire sécurisée et la protection kernel (HVCI, Credential Guard) sur les endpoints sensibles.

---

### Implications stratégiques

Les hyperviseurs malveillants représentent un saut qualitatif pour les attaquants APT, permettant de contourner les EDR modernes et de manipuler la mémoire sans détection. Les organisations fortement exposées (finance, défense, énergie, recherche) doivent réévaluer leur modèle de menace et investir dans des capacités forensiques mémoire avancées. Cela pose aussi la question stratégique de la souveraineté : dépendance à des technologies de virtualisation dont les implémentations matérielles (Intel/AMD) concentrent un risque systémique et justifient une veille active sur les vulnérabilités CPU.

---

### Recommandations

* Activer et imposer Secure Boot + TPM sur l'ensemble du parc sensible
* Renforcer la forensique mémoire (Volatility, Rekall, MemProcFS) dans les arsenaux DFIR
* Tester les solutions EDR face aux attaques ring -1 (hyperviseur caché)
* Activer HVCI / Credential Guard sur Windows et durcir la politique driver signing
* Cartographier les assets Virtualisation/Hyperviseurs et auditer les versions/patches

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les hyperviseurs approuvés (Hyper-V, ESXi, KVM) et leurs versions
* Vérifier l'activation d'Intel VT-x / AMD-V et IOMMU (VT-d/AMD-Vi) sur les hôtes sensibles
* Définir une politique de mise en liste blanche des hyperviseurs et de contrôle d'intégrité (TPM/Secure Boot)
* Sensibiliser les SOC analystes aux artefacts EPT/NPT et aux techniques de split-view
* Préparer des images forensics et des outils de détection de rootkits hyperviseur (memory forensics)

#### Phase 2 — Détection et analyse

* Détecter les chargements d'hyperviseurs non approuvés (signatures, hashes, drivers) sur endpoints et serveurs
* Rechercher les anomalies de performance/faults CPU compatibles avec un second-stage hypervisor
* Identifier les comportements 'split-view' : divergences entre mémoire vue OS vs mémoire réelle (EPT remapping)
* Alerter sur les modifications suspectes des structures de virtualisation (VMCS, EPT/NPT pointers)
* Monitorer les crash dumps inhabituels et les BSOD liés à des erreurs de virtualisation

#### Phase 3 — Confinement, éradication et récupération

* Isoler les hôtes potentiellement compromis par hyperviseur malveillant
* Bloquer les binaires/driver non signés tentant de charger un hyperviseur
* Désactiver VT-x/AMD-V si non requis sur les postes à haute confiance (à arbitrer)
* Restaurer depuis une image disque réputée saine
* Préserver les dumps mémoire volatils avant remédiation (image mémoire via WinPmem/DumpIt)

#### Phase 4 — Activités post-incident

* Mener une analyse forensique avancée (memory) pour confirmer la présence d'un hyperviseur caché
* Identifier le vecteur d'entrée et la persistance (bootkit, UEFI, driver signé)
* Mettre à jour les règles EDR et YARA pour les artefacts observés
* Réviser le Secure Boot / mesures d'intégrité BIOS/UEFI
* Documenter le TTPs dans la base interne de threat intel et partager avec les pairs

#### Phase 5 — Threat Hunting (proactif)

* Chasser la présence de drivers non-Microsoft chargeant des hyperviseurs sur le parc
* Rechercher les artefacts EPT/NPT inhabituels dans les dumps mémoire historiques
* Identifier des divergences de comportement OS vs VM (timing, exceptions, #VMEXIT anormaux)
* Détecter les tentatives de désactivation des protections mémoire (DEP, SMEP, SMAP)
* Cartographier les techniques d'obfuscation via hyperviseur face au framework MITRE ATT&CK

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1062** | Hyperviseur malveillant / exploitation de la virtualisation |
| **T1014** | Rootkit |
| **T1027.002** | Obfuscation logicielle via empaquetage |

---

### Sources

* [https://www.reddit.com/r/blueteamsec/comments/1ujfjpw/about_hypervisor_cheats_part_2_eptnpt_split_views/](https://www.reddit.com/r/blueteamsec/comments/1ujfjpw/about_hypervisor_cheats_part_2_eptnpt_split_views/)


---

<div id="cyber-meteo-suisse-defcon-4-front-ransomware-modere-phishing-en-hausse-secondaire"></div>

## Cyber Météo Suisse — DEFCON 4 : front ransomware modéré, phishing en hausse secondaire

### Résumé

Le bot Bobe publie sa 'Cyber Météo' suisse du 30 juin 2026 avec un niveau DEFCON 4 (modéré). Le front ransomware est qualifié de modéré avec 2 victimes CH sur 7 jours et 9 sur 30 jours. Trois groupes eCrime sont actifs au radar, accompagnés de perturbations secondaires liées au phishing. Le message recommande de vérifier les sauvegardes offline et le MFA en l'absence de tempête critique.

---

### Analyse opérationnelle

Les équipes SOC suisses doivent renforcer la veille sur les trois groupes eCrime identifiés et auditer la télémétrie EDR/SIEM sur 30 jours pour identifier des compromissions non encore détectées. La priorité immédiate est la vérification des sauvegardes offline (test de restauration, intégrité) et du MFA sur l'ensemble des comptes exposés. Les passerelles de messagerie doivent être reconfigurées face à la recrudescence de phishing signalée. Les accès VPN/RDP doivent être audités et restreints (jump hosts, conditional access, geo-fencing).

---

### Implications stratégiques

Le maintien d'un DEFCON 4 sur un mois avec 9 victimes ransomware illustre la pression persistante et l'écosystème suisse est devenu une cible récurrente pour l'eCrime international. Pour les décideurs, cela justifie un investissement continu dans les capacités de détection/réponse et un renforcement des obligations de notification et de coopération sectorielle (banque, santé, énergie, administrations cantonales). L'enjeu réputationnel et réglementaire (FINMA, nLPD) reste majeur pour les organisations helvétiques.

---

### Recommandations

* Tester sans délai les sauvegardes offline et immutables
* Imposer MFA FIDO2 sur tous les comptes à privilèges et accès distants
* Durcir les passerelles mail face à la vague de phishing en cours
* Auditer les expositions RDP/VPN et restreindre via conditional access
* Renforcer le partage TI sectoriel (ISAC suisses) sur les groupes eCrime actifs

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un référentiel à jour des groupes eCrime actifs ciblant la Suisse
* Vérifier l'application des sauvegardes offline (air-gap, immutables) et tester la restauration
* Imposer MFA (FIDO2) sur tous les comptes à privilèges et externes
* Cartographier les actifs exposés et appliquer durcissement Active Directory
* Définir un plan de communication et de notification (NCSC, FINMA, OFCOM selon secteur)

#### Phase 2 — Détection et analyse

* Détecter les IOC ransomware émergents via flux TI sectoriel (ISAC suisse, NCSC)
* Alerter sur les schémas de chiffrement massif (volume I/O disque anormal)
* Surveiller les indicateurs de phishing en hausse sur l'ensemble du parc
* Identifier les connexions RDP/VPN atypiques et tentatives de MOVEit-like exfiltration
* Détecter les communications avec les sites de leak connus des groupes eCrime

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les hôtes présentant des signes de chiffrement
* Couper les accès externes (VPN, exposition RDP) sur les segments impactés
* Bloquer les IOC et domaines leak site identifiés au périmètre
* Désactiver temporairement les comptes à privilèges exposés et révoquer les sessions
* Préserver les preuves (images disque, mémoire, logs EDR) avant toute remédiation

#### Phase 4 — Activités post-incident

* Notifier le NCSC suisse et les autorités sectorielles compétentes (FINMA, OFCOM, canton)
* Évaluer la propagation et l'exfiltration éventuelle pour piloter la divulgation
* Restaurer depuis les sauvegardes offline et vérifier l'intégrité avant remise en service
* Piloter la communication interne/externe et la gestion de crise
* Mettre à jour le référentiel TI et procéder au post-mortem avec la direction

#### Phase 5 — Threat Hunting (proactif)

* Chasser les IOC des groupes eCrime actifs sur 90 jours de logs proxy/DNS/EDR
* Rechercher les signes de prépositionnement (T1485/T1490 dormants)
* Détecter des outils de double extorsion (Cobalt Strike, SystemBC, IAB)
* Identifier des anomalies AD (Kerberoasting, ACL suspectes)
* Prioriser le suivi des secteurs suisses les plus touchés et leurs sous-traitants

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Chiffrement de données à des fins d'impact (ransomware) |
| **T1566** | Hameçonnage |

---

### Sources

* [https://mastobot.ping.moi/@Bobe_bot/116837292935555769](https://mastobot.ping.moi/@Bobe_bot/116837292935555769)


---

<div id="attaque-supply-chain-klue-salesforce-le-nombre-de-victimes-grimpe-a-24-organisations-et-le-groupe-dextorsion-est-lui-meme-compromis"></div>

## Attaque supply chain Klue-Salesforce : le nombre de victimes grimpe à ~24 organisations et le groupe d'extorsion est lui-même compromis

### Résumé

Une campagne d'attaque par supply chain via le fournisseur Klue, qui s'intègre à Salesforce, s'est élargie à environ 24 organisations victimes. Le groupe d'extorsion à l'origine de l'opération a lui-même été infiltré par un autre acteur malveillant, qui a ensuite exfiltré et publié des informations issues de cette intrusion, entraînant une fuite de données en cascade touchant les clients finaux de Klue/Salesforce.

---

### Analyse opérationnelle

Pour les SOC/IT : (1) auditer en urgence tout connecteur tiers (Klue et équivalents) sur les instances Salesforce et révoquer les jetons OAuth inutilisés ou trop permissifs ; (2) activer Salesforce Event Monitoring / Shield et corréler avec le SIEM pour détecter des requêtes Bulk API, téléchargements de rapports ou connexions depuis des ASNs inhabituels ; (3) renforcer la MFA sur les comptes admin et de service, segmenter par IP, et durcir les profils Salesforce (moindre privilège) ; (4) étendre la chasse aux IOCs à l'ensemble des intégrateurs CRM tiers ; (5) mettre en place un monitoring continu des leak sites et Telegram pour détecter toute publication impliquant l'organisation. La surface d'attaque supply chain via les SaaS intégrés reste largement sous-estimée.

---

### Implications stratégiques

L'incident illustre un effet domino « double supply chain » : un premier attaquant exploite un fournisseur (Klue) pour compromettre ~24 organisations, puis un second attaquant compromet le groupe extortionniste et amplifie la fuite. Conséquences business : risques RGPD/AI Act élevés (données client/CRM = PII massive), perte de confiance, obligations de notification, exposition sur les marchés. Décisionnel : imposer un SOC 2 Type II / ISO 27001 / audit de sécurité des sous-traitants SaaS critiques, contractualiser un droit d'audit et une notification < 24h, et intégrer la notation cyber des tiers (TPCRM) dans les appels d'offres. Tendance forte : la chaîne d'approvisionnement logicielle (intégrateurs, ISV, extensions CRM) devient l'un des vecteurs d'attaque les plus rentables.

---

### Recommandations

* Inventaire et revue immédiate de tous les connecteurs Salesforce tiers (Klue en particulier) avec révocation OAuth.
* Activer Salesforce Shield / Event Monitoring et corréler au SIEM.
* Imposer une clause de notification incidents < 24h dans tous les contrats SaaS/tierces.
* Évaluer la couverture cyber-assurance face à un scénario supply chain SaaS.
* Lancer un exercice de crise tabletop focalisé sur la compromission d'un sous-traitant CRM critique.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier tous les connecteurs et intégrations tierces vers les instances Salesforce (AppExchange, OAuth tokens, comptes de service).
* Maintenir un inventaire des tiers traitant des données CRM (Klue, outils d'intelligence concurrentielle, etc.).
* Définir des clauses de notification contractuelles < 24h pour les incidents chez les sous-traitants SaaS.
* Segmenter les permissions : limiter le scope OAuth/Connected Apps au strict nécessaire (least privilege).
* Sauvegardes hors ligne et export régulier des données Salesforce critiques.

#### Phase 2 — Détection et analyse

* Surveiller les accès OAuth anormaux depuis les comptes de service Klue (géolocalisation, heures, volumes).
* Détecter les téléchargements massifs de données CRM (SOQL queries anormales, Report/Dashboard exports volumineux).
* Activer et corréler les Event Monitoring Salesforce avec le SIEM (login, API, Bulk API 2.0).
* Alerter sur la création/modification de Connected Apps et de jetons.
* Veille sur les publications du groupe extortion (Telegram, forums) et corrélation avec leak sites.

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement les jetons OAuth et clés API de Klue et de tout connecteur suspect.
* Désactiver les comptes de service compromis et forcer la rotation des credentials Salesforce.
* Activer le gel des exports de données depuis l'org Salesforce (Restrict Data Export, IP restrictions).
* Isoler les endpoints d'administration Salesforce suspectés compromis (MFA renforcée, restriction IP).
* Notifier les parties prenantes internes (RSSI, DPO, juridique, communication de crise).

#### Phase 4 — Activités post-incident

* Conduire une revue forensique des logs Event Monitoring et API logs (Salesforce Shield).
* Identifier le périmètre exact des données exfiltrées (contacts, leads, opportunités, PII) pour notification CNIL/dest.
* Renforcer la gouvernance des tiers : audit sécurité annuel, revue des scopes OAuth, monitoring continu.
* Revoir la classification des données hébergées chez les sous-traitants CRM.
* Communiquer de manière transparente aux clients et partenaires impactés ; évaluer le devoir d'information.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les IOCs et TTPs associés au groupe (Telegram channels, leak sites référencés).
* Chasser des comportements anormaux sur tous les connecteurs Salesforce tiers (volume, fréquence, source IP).
* Rechercher des similarités avec les campagnes ShinyHunters/Lapsus$ antérieures (phishing vishing SIM-swap, recrutement d'initiés).
* Auditer périodiquement les autorisations des Connected Apps et les comptes de service dormants.
* Cartographier le risque supply chain sur l'ensemble des intégrateurs accédant au CRM.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `rocket-boys[.]co.jp` | Low |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploitation d'une application exposée sur Internet (Salesforce/CRM) |
| **T1078** | Abus de comptes valides (Salesforce) via accès tiers (Klue) |
| **TA0001** | Initial Access via supply chain tierce (Klue - intégration Salesforce) |
| **T1567** | Exfiltration vers service de partage/stockage cloud |

---

### Sources

* [https://rocket-boys.co.jp/security-measures-lab/klue-salesforce-supply-chain-attack/](https://rocket-boys.co.jp/security-measures-lab/klue-salesforce-supply-chain-attack/)
