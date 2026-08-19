# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [#StopRansomware : Advisory conjoint FBI/CISA/HHS sur le ransomware Medusa (mise à jour août 2026)](#stopransomware-advisory-conjoint-fbicisahhs-sur-le-ransomware-medusa-mise-a-jour-aout-2026)
  * [Mirage2FA : PhaaS AiTM ciblant les sessions Microsoft 365 avec plus de 4 000 victimes aux États-Unis](#mirage2fa-phaas-aitm-ciblant-les-sessions-microsoft-365-avec-plus-de-4-000-victimes-aux-etats-unis)
  * [Cyberattaque massive contre la CSDD lettone : vol des données personnelles de 1,2 million de personnes](#cyberattaque-massive-contre-la-csdd-lettone-vol-des-donnees-personnelles-de-12-million-de-personnes)
  * [Expel lance Ruxie AI : classification automatique du phishing bénin pour libérer le SOC](#expel-lance-ruxie-ai-classification-automatique-du-phishing-benin-pour-liberer-le-soc)
  * [TWINLOOT : nouveau malware Python exploitant SharePoint, Teams et Edge pour vol de credentials et mouvement latéral](#twinloot-nouveau-malware-python-exploitant-sharepoint-teams-et-edge-pour-vol-de-credentials-et-mouvement-lateral)
  * [VulnCheck : 1 335 CVE suivies, 209 critiques, 7% non patchées – XSS, path traversal et SQLi dominent](#vulncheck-1-335-cve-suivies-209-critiques-7-non-patchees-xss-path-traversal-et-sqli-dominent)
  * [MacSync Stealer : rotation de l'infrastructure C2 et analyse d'un nouveau loader zsh](#macsync-stealer-rotation-de-linfrastructure-c2-et-analyse-dun-nouveau-loader-zsh)
  * [Medusa Ransomware : advisory CISA/FBI/HHS mis à jour — plus de 500 victimes et nouvelles tactiques](#medusa-ransomware-advisory-cisafbihhs-mis-a-jour-plus-de-500-victimes-et-nouvelles-tactiques)
  * [TheHatman : vente de données Azure/Entra ID de 9 entreprises dont McDonald's, Vodafone et TCS](#thehatman-vente-de-donnees-azureentra-id-de-9-entreprises-dont-mcdonalds-vodafone-et-tcs)
  * [Clop : web shell Java sur mesure déployé sur les serveurs PTC Windchill/FlexPLM via CVE-2026-12569 — 43 organisations visées dont Shell, GE et Philips](#clop-web-shell-java-sur-mesure-deploye-sur-les-serveurs-ptc-windchillflexplm-via-cve-2026-12569-43-organisations-visees-dont-shell-ge-et-philips)
  * [Wallets hardware crypto : risques accrus après des vols de données personnelles chez les prestataires de livraison](#wallets-hardware-crypto-risques-accrus-apres-des-vols-de-donnees-personnelles-chez-les-prestataires-de-livraison)
  * [ChocoPoC cible les chercheurs en vulnérabilités](#chocopoc-cible-les-chercheurs-en-vulnerabilites)
  * [Piratage du fisc : protéger le pacte républicain et le consentement à l'impôt](#piratage-du-fisc-proteger-le-pacte-republicain-et-le-consentement-a-limpot)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L'actualité CTI de ce jour est dominée par un volume exceptionnel de vulnérabilités (88 signalements), porté notamment par la divulgation du zero-day Citrix NetScaler CVE-2025-6543 (CVSS 9,2), activement exploité et surnommé « CitrixBleed 2 », ainsi que par deux flaws critiques de score maximum (CVSS 10,0) affectant Cisco ISE permettant une exécution de code à distance sans authentification. Parallèlement, le segment des fuites de données (14 incidents) reste soutenu par la massive fuite agrégée de plus de 16 milliards de combinaisons d'identifiants issue d'infostealers, conjuguée à des campagnes de vishing ciblant les instances Salesforce (cluster UNC6040) dans une logique d'extorsion financière. L'exploitation active de CVE-2025-3248 dans Langflow pour déployer le botnet Flodrix illustre par ailleurs l'attrait croissant des acteurs pour les frameworks IA open-source comme vecteur d'entrée. L'absence totale de signaux sur les groupes d'acteurs de menace (0) contraste avec cette pression technique et suggère soit une latence de publication attributive, soit une focalisation de la communauté sur le patch management en urgence. Les volumes réglementaire (2) et géopolitique (1) restent marginaux, indiquant un cycle d'actualité centré sur la réponse opérationnelle plutôt que sur les évolutions de cadre normatif ou les tensions étatiques. Recommandation : prioriser l'application immédiate des correctifs Citrix NetScaler et Cisco ISE, auditer les sessions actives post-patch, et renforcer la détection des réutilisations d'identifiants issues de la fuite des 16 milliards de credentials.

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
| **Arménie, Russie, États-Unis, Caucase du Sud, Iran** | Infrastructure IA / Technologies émergentes / Centres de données | Opération d'influence russe (CopyCop / Storm-1516) visant le centre de données IA Firebird en Arménie pour entraver le rapprochement arméno-occidental | Le réseau d'influence russe CopyCop (également désigné Storm-1516) a très probablement ciblé le centre de données IA Firebird, un projet conjoint américano-arménien situé à Hrazdan (province de Kotayk), dans le cadre d'une campagne plus large visant à saper le réalignement géopolitique et économique de l'Arménie vers l'Occident. Entre le 24 juin et le 13 juillet 2026, l'Insikt Group a documenté trois instances distinctes d'usurpation médiatique par CopyCop, toutes dirigées contre cette infrastructure avant son ouverture prévue en juillet 2026.  Ces trois opérations ont successivement : (1) fabriqué un risque sismique imminent fictif autour du site ; (2) semé le doute sur la viabilité économique et infrastructurelle du projet ; (3) usurpé des communications militaires iraniennes officielles justifiant de traiter le centre de données comme une cible militaire légitime. La portée a crû de manière significative, passant d'un engagement initial limité à plus de 1,6 million de vues combinées lors de la troisième instance, indiquant une montée en puissance de l'audience au fil de la campagne.  Le projet Firebird représente un investissement d'environ 500 millions de dollars pour sa Phase One (plus de 6 000 GPU NVIDIA Blackwell, 110,6 exaflops de calcul IA, 18 MW) et jusqu'à 4 milliards de dollars pour la Phase Two (plus de 41 000 GPU supplémentaires), plaçant l'Arménie parmi les cinq premiers pays mondiaux en matière d'infrastructure de calcul IA. Ce projet s'inscrit dans le cadre d'un partenariat stratégique États-Unis–Arménie signé en août 2025 sur les semi-conducteurs et l'IA, consolidé par les visites du Vice-Président JD Vance (février 2026) et du Secrétaire d'État Marco Rubio (mai 2026), ce dernier signant une Charte de partenariat stratégique global et un cadre sur les minéraux critiques et terres rares.  Le rapprochement arménien vers l'Occident s'est fait au détriment de sa relation avec la Russie, notamment dans les domaines de la sécurité et de l'énergie. L'Arménie a gelé sa participation à l'OTSC (Organisation du Traité de sécurité collective) dirigée par la Russie depuis février 2024, le Premier ministre Nikol Pashinyan qualifiant ce changement de « irréversible » en décembre 2024. Le Kremlin a signalé que la tarification préférentielle du gaz arménien dépendrait du maintien dans les cadres d'intégration régionale russes.  CopyCop avait précédemment mené une campagne de plusieurs mois ciblant les élections législatives arméniennes du 7 juin 2026, cherchant à dégrader l'image publique de Pashinyan et du parti pro-occidental Civil Contract. Après la réélection de Pashinyan, CopyCop a presque certainement redirigé ses opérations vers le centre de données Firebird, exploitant l'attention médiatique accrue sur les investissements IA pour amplifier des narratives pro-russes. Le réseau a démontré une réutilisation du même réseau d'amplification sociale contre d'autres projets d'investissement occidental liés à l'Arménie, suggérant une continuité opérationnelle. | [https://www.recordedfuture.com/blog/copycop-targets-ai-investment](https://www.recordedfuture.com/blog/copycop-targets-ai-investment) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| DSA – Articles 16, 30(7), 31 | Commission européenne | 2026-08-18 | Union européenne | DSA – Articles 16, 30(7), 31 | La Commission européenne a publié un appel d'offres pour une étude empirique visant à évaluer comment la conception des plateformes de vente en ligne influence le comportement des utilisateurs au regard des mécanismes prévus par le Digital Services Act (DSA). L'étude portera spécifiquement sur l'article 16 (notification et action), l'article 30(7) (informations sur les commerçants) et l'article 31 (conformité par la conception) du DSA, sur des VLOP/VLOM sélectionnées. Le contrat d'une durée de 8 mois a une valeur maximale de 400 000 EUR. Les résultats seront présentés par plateforme, sans comparaison ni classement inter-plateformes. L'ouverture de l'appel est fixée au 17 août 2026 et la clôture au 23 septembre 2026. | [https://digital-strategy.ec.europa.eu/en/funding/call-tenders-study-how-online-marketplace-design-influences-user-behaviour](https://digital-strategy.ec.europa.eu/en/funding/call-tenders-study-how-online-marketplace-design-influences-user-behaviour) |
| EU Cyber Resilience Act (CRA) | Union européenne | 2026-08-18 | Union européenne | EU Cyber Resilience Act (CRA) | Un podcast de l'OpenSSF avec Roman Zhukov (co-président du Global Cyber Policy Working Group d'OpenSSF, Security Communities Lead chez Red Hat) aborde l'impact du Cyber Resilience Act (CRA) sur l'écosystème open source. Le rapport 2026 sur la sensibilisation et la préparation au CRA révèle que 66 % des organisations ignorent totalement l'approche des échéances réglementaires. L'épisode distingue les rôles de mainteneur, de steward et de fabricant sous la loi, et souligne que le modèle traditionnel de « consommation sans engagement » de l'open source est obsolète. Le maintien de forks privés représente un coût d'ingénierie estimé à plus de 250 000 USD. La collaboration active en amont devient une nécessité à la fois commerciale et légale. Des ressources éducatives gratuites sont mentionnées, notamment le cours LFEL1001 sur la compréhension du CRA, l'Open Source Project Security Baseline (OSPS), SLSA, ainsi que les guides du Global Cyber Policy Working Group. | [https://openssf.org/podcast/2026/08/18/whats-in-the-soss-podcast-69-s3e21-watering-the-community-garden-navigating-the-eu-cra-for-open-source-with-roman-zhukov/](https://openssf.org/podcast/2026/08/18/whats-in-the-soss-podcast-69-s3e21-watering-the-community-garden-navigating-the-eu-cra-for-open-source-with-roman-zhukov/) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Télécommunications** | Bouygues Telecom | Noms, prénoms, IBAN, BIC des abonnés Bouygues Telecom (issus de la fuite de l'été 2025). Les courriels de phishing exploitent ces données pour crédibiliser l'arnaque. | 64000000 | [https://www.tomsguide.fr/clients-bouygues-attention-a-cette-arnaque-qui-affiche-votre-veritable-iban/](https://www.tomsguide.fr/clients-bouygues-attention-a-cette-arnaque-qui-affiche-votre-veritable-iban/)<br>[https://mastobot.ping.moi/@cyberveille/117116751485225408](https://mastobot.ping.moi/@cyberveille/117116751485225408) |
| **Cryptomonnaies / Portefeuilles matériels (Hardware Wallets)** | SafePal | Noms, adresses e-mail, adresses de livraison, numéros de téléphone, détails d'achat (produits, dates). Aucune clé privée, phrase de récupération, mot de passe, identifiant de portefeuille, coordonnée bancaire ou pièce d'identité n'a été compromise. | 39798 | [https://www.cointribune.com/apres-trezor-safepal-revele-une-fuite-touchant-pres-de-40-000-clients/](https://www.cointribune.com/apres-trezor-safepal-revele-une-fuite-touchant-pres-de-40-000-clients/)<br>[https://mastobot.ping.moi/@cyberveille/117116633535257932](https://mastobot.ping.moi/@cyberveille/117116633535257932)<br>[https://osintsights.com/safepal-data-breach-exposes-40000-customer-records](https://osintsights.com/safepal-data-breach-exposes-40000-customer-records)<br>[https://mastodon.social/@Analyst207/117115910222539761](https://mastodon.social/@Analyst207/117115910222539761) |
| **Multi-secteur (Restauration rapide, Télécommunications, Services informatiques, Retail, Conseil)** | Multiple organisations Fortune 500 (McDonald's, Vodafone, Kyndryl, TCS, Gap Inc. et autres) | Noms complets et identifiants employés, adresses e-mail corporatives et structures .onmicrosoft[.]com, titres de poste, départements, informations hiérarchiques (managers), numéros de téléphone, adresses postales, enregistrements de comptes de service, noms d'administrateurs globaux. | 3640000 | [https://beyondmachines.net/event_details/hacker-claims-large-scale-azure-exfiltration-campaign-exposing-3-6-million-records-from-global-enterprises-h-8-d-f-a/gD2P6Ple2L](https://beyondmachines.net/event_details/hacker-claims-large-scale-azure-exfiltration-campaign-exposing-3-6-million-records-from-global-enterprises-h-8-d-f-a/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117116404133494379](https://infosec.exchange/@beyondmachines1/117116404133494379) |
| **Services financiers / Prêts personnels** | Heights Finance Holdings Co. | Noms, adresses, numéros de téléphone, numéros de sécurité sociale (SSN), numéros d'identité gouvernementaux, numéros de permis de conduire, informations de comptes bancaires, dates de naissance. | 1200000 | [https://radar.offseq.com/threat/heights-finance-data-breach-impacts-at-least-12-million-individuals-e3edf9e4bbb33546](https://radar.offseq.com/threat/heights-finance-data-breach-impacts-at-least-12-million-individuals-e3edf9e4bbb33546)<br>[https://infosec.exchange/@offseq/117116044857835396](https://infosec.exchange/@offseq/117116044857835396) |
| **Santé publique / Plateforme de santé numérique nationale** | MyDr (plateforme de santé polonaise) | Dossiers médicaux électroniques (EHR), ordonnances électroniques (e-prescriptions), numéros PESEL (identifiant national polonais), numéros de téléphone, informations d'identification personnelle. Données médicales sensibles : conditions de santé, traitements, médicaments prescrits. | 19000000 | [https://cyber.netsecops.io/articles/polands-mydr-healthcare-platform-suffers-major-data-breach/](https://cyber.netsecops.io/articles/polands-mydr-healthcare-platform-suffers-major-data-breach/)<br>[https://mastodon.social/@netsecio/117119108024458268](https://mastodon.social/@netsecio/117119108024458268) |
| **Manufacturing / Solutions réseau et sécurité (équipements de périphérie)** | LogicVein (株式会社ロジックベイン) | Noms, noms d'entreprise et départements, adresses e-mail, adresses postales, numéros de téléphone, autres informations de contact (clients, partenaires, visiteurs de salons). Potentiellement : échanges e-mail, historiques de vente, informations d'enregistrement de versions d'évaluation, informations de salons, données de contrats. Aucune carte de crédit ni MyNumber confirmé. | 97338 | [https://rocket-boys.co.jp/security-measures-lab/logicvein-qilin-ransomware-cyberattack-personal-data-leak/](https://rocket-boys.co.jp/security-measures-lab/logicvein-qilin-ransomware-cyberattack-personal-data-leak/)<br>[https://mastodon.social/@securityLab_jp/117119020775551877](https://mastodon.social/@securityLab_jp/117119020775551877) |
| **Divertissement / Idole 2.5D / Services de fan** | VOISING (株式会社VOISING – agence de l'idole 2.5D « Ireisu ») | Noms, adresses, numéros de téléphone, adresses e-mail, dates de naissance, sexe, historiques d'achat (dates, produits), montants de paiement, statuts d'abonnement, informations sur l'idole préférée (« oshi »). Aucune donnée de carte de crédit, de compte bancaire ou de mot de passe. | Inconnu | [https://rocket-boys.co.jp/security-measures-lab/voising-bi-tool-unauthorized-access-personal-data-leak/](https://rocket-boys.co.jp/security-measures-lab/voising-bi-tool-unauthorized-access-personal-data-leak/)<br>[https://mastodon.social/@securityLab_jp/117115992352148284](https://mastodon.social/@securityLab_jp/117115992352148284) |
| **Administration publique — Autorité fiscale (DGFiP)** | Direction générale des Finances publiques (DGFiP) / impots[.]gouv[.]fr | Données fiscales de particuliers : noms, prénoms, quotient familial, revenu fiscal de référence (RFR), taux de prélèvement à la source, composition du foyer fiscal. Données d'entreprises : raison sociale, numéro SIREN, adresse. Données cadastrales : identité et adresse des titulaires de droits sur des parcelles cadastrales, identifiant foncier, commune, section et numéro de parcelle, droits attachés au bien, surfaces de biens immobiliers. Données de successions vacantes : journaux de demandes et échanges sur la vacation de successions. Les identifiants et mots de passe des particuliers et professionnels n'ont pas été compromis. Les espaces Finances publiques des usagers n'ont pas été compromis. | 678000 | [https://www.lemonde.fr/politique/article/2026/08/18/piratage-du-fisc-bercy-presente-ses-excuses-mais-peine-a-contenir-la-crise_6749090_823448.html](https://www.lemonde.fr/politique/article/2026/08/18/piratage-du-fisc-bercy-presente-ses-excuses-mais-peine-a-contenir-la-crise_6749090_823448.html)<br>[https://www.lemonde.fr/pixels/live/2026/08/18/en-direct-piratage-du-site-des-impots-le-gouvernement-detaille-les-trois-fuites-de-donnees-qui-concernent-aussi-les-donnees-cadastrales-et-les-successions_6749047_4408996.html](https://www.lemonde.fr/pixels/live/2026/08/18/en-direct-piratage-du-site-des-impots-le-gouvernement-detaille-les-trois-fuites-de-donnees-qui-concernent-aussi-les-donnees-cadastrales-et-les-successions_6749047_4408996.html)<br>[https://www.lemonde.fr/pixels/article/2026/08/18/piratage-du-site-des-impots-la-direction-generale-des-finances-publiques-a-informe-les-contribuables-concernes_6749005_4408996.html](https://www.lemonde.fr/pixels/article/2026/08/18/piratage-du-site-des-impots-la-direction-generale-des-finances-publiques-a-informe-les-contribuables-concernes_6749005_4408996.html) |
| **Administration publique — Éducation nationale** | Ministère de l'Éducation nationale | Données d'élèves : identités, dates de naissance, adresses postales et électroniques, numéros de téléphone, informations scolaires et administratives. Données d'enseignants : identifiants personnels issus d'I-Prof (4,35 millions), comptes académiques (602 000). Données de parents et responsables légaux. Empreintes cryptographiques de mots de passe dans certains fichiers. Données couvrant une période de plus de vingt ans (début des années 2000 à juillet 2026). Sources : académie de Créteil, annuaires académiques de Créteil et Versailles, exports I-Prof des 33 académies françaises. | 346000000 | [https://www.lemonde.fr/pixels/article/2026/08/18/les-pirates-du-site-des-impots-affirment-avoir-aussi-derobe-des-informations-personnelles-de-millions-d-eleves-au-ministere-de-l-education-nationale_6749056_4408996.html](https://www.lemonde.fr/pixels/article/2026/08/18/les-pirates-du-site-des-impots-affirment-avoir-aussi-derobe-des-informations-personnelles-de-millions-d-eleves-au-ministere-de-l-education-nationale_6749056_4408996.html) |
| **** |  |  | Inconnu |  |
| **** |  |  | Inconnu |  |
| **** |  |  | Inconnu |  |
| **** |  |  | Inconnu |  |
| **** |  |  | Inconnu |  |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-73939** | 8.6 | N/A | FALSE | Oracle Helidon 3.2.20 (composant : Imperative Web Server) | Vulnérabilité d'intégrité non authentifiée via HTTP avec changement de portée | Compromission de l'intégrité des données critiques accessibles via Helidon. Un attaquant non authentifié peut créer, supprimer ou modifier des données critiques ou l'ensemble des données accessibles. Le changement de portée accroît le risque d'impact sur des produits tiers dépendant de Helidon. | Theoretical | Appliquer les correctifs disponibles dans le bulletin Oracle Critical Patch Update d'août 2026 (hxxps://www[.]oracle[.]com/security-alerts/cspuaug2026[.]html). Restreindre l'accès réseau aux instances Helidon exposées. Mettre en place un WAF pour filtrer les requêtes HTTP malveillantes. Surveiller activement les journaux d'accès pour détecter toute activité suspecte. | [https://cvefeed.io/vuln/detail/CVE-2026-73939](https://cvefeed.io/vuln/detail/CVE-2026-73939)<br>[https://www.oracle.com/security-alerts/cspuaug2026.html](https://www.oracle.com/security-alerts/cspuaug2026.html) |
| **CVE-2026-73937** | 8.2 | N/A | FALSE | Oracle Helidon 4.5.0 (composant : Imperative Web Server) | Déni de service et fuite de données via HTTP/2 non authentifié | Un attaquant non authentifié peut provoquer un déni de service complet (hang ou crash répété) de Helidon et obtenir un accès en lecture non autorisé à un sous-ensemble des données accessibles via Helidon. | Theoretical | Appliquer les correctifs du bulletin Oracle CPU d'août 2026 (hxxps://www[.]oracle[.]com/security-alerts/cspuaug2026[.]html). Limiter l'exposition HTTP/2 des instances Helidon. Mettre en place un rate limiting et un WAF. Surveiller la disponibilité des services et les journaux d'accès. | [https://cvefeed.io/vuln/detail/CVE-2026-73937](https://cvefeed.io/vuln/detail/CVE-2026-73937)<br>[https://www.oracle.com/security-alerts/cspuaug2026.html](https://www.oracle.com/security-alerts/cspuaug2026.html) |
| **CVE-2026-73931** | 8.3 | N/A | FALSE | Oracle Helidon 4.5.3 (composant : Imperative Web Server) | Vulnérabilité CIA non authentifiée via HTTP avec changement de portée | Un attaquant non authentifié peut obtenir un accès en lecture non autorisé à un sous-ensemble de données, modifier/insérer/supprimer des données accessibles via Helidon, et provoquer un déni de service partiel. Le changement de portée étend l'impact à des produits tiers. | Theoretical | Appliquer les correctifs du bulletin Oracle CPU d'août 2026 (hxxps://www[.]oracle[.]com/security-alerts/cspuaug2026[.]html). Restreindre l'accès réseau aux instances Helidon. Déployer un WAF. Surveiller les journaux d'accès et les modifications de données. | [https://cvefeed.io/vuln/detail/CVE-2026-73931](https://cvefeed.io/vuln/detail/CVE-2026-73931)<br>[https://www.oracle.com/security-alerts/cspuaug2026.html](https://www.oracle.com/security-alerts/cspuaug2026.html) |
| **CVE-2026-73930** | 9.9 | N/A | FALSE | Oracle Helidon 4.5.3 (composant : Imperative Web Server) | Vulnérabilité critique CIA non authentifiée via HTTP avec changement de portée | Compromission complète de l'intégrité des données critiques accessibles via Helidon, accès en lecture non autorisé à un sous-ensemble de données, et déni de service partiel. Le changement de portée étend l'impact à des produits tiers. Un attaquant non authentifié peut créer, supprimer ou modifier l'ensemble des données accessibles via Helidon. | Theoretical | Appliquer immédiatement les correctifs du bulletin Oracle CPU d'août 2026 (hxxps://www[.]oracle[.]com/security-alerts/cspuaug2026[.]html). Isoler ou désactiver les instances Helidon 4.5.3 exposées non corrigées. Déployer un WAF avec règles de blocage. Surveiller en temps réel les journaux d'accès et les modifications de données. | [https://cvefeed.io/vuln/detail/CVE-2026-73930](https://cvefeed.io/vuln/detail/CVE-2026-73930)<br>[https://www.oracle.com/security-alerts/cspuaug2026.html](https://www.oracle.com/security-alerts/cspuaug2026.html) |
| **CVE-2026-73929** | 8.3 | N/A | FALSE | Oracle Helidon 4.5.3 (composant : Imperative Web Server) | Vulnérabilité CIA non authentifiée via HTTP avec changement de portée | Un attaquant non authentifié peut obtenir un accès en lecture non autorisé à un sous-ensemble de données, modifier/insérer/supprimer des données accessibles via Helidon, et provoquer un déni de service partiel. Le changement de portée étend l'impact à des produits tiers. | Theoretical | Appliquer les correctifs du bulletin Oracle CPU d'août 2026 (hxxps://www[.]oracle[.]com/security-alerts/cspuaug2026[.]html). Restreindre l'accès réseau aux instances Helidon. Déployer un WAF. Surveiller les journaux d'accès et les modifications de données. | [https://cvefeed.io/vuln/detail/CVE-2026-73929](https://cvefeed.io/vuln/detail/CVE-2026-73929)<br>[https://www.oracle.com/security-alerts/cspuaug2026.html](https://www.oracle.com/security-alerts/cspuaug2026.html) |
| **CVE-2026-73925** | 8.2 | N/A | FALSE | Oracle Helidon 1.4.19 (composant : Imperative Web Server) | Vulnérabilité de confidentialité et d'intégrité non authentifiée via HTTP | Un attaquant non authentifié peut créer, supprimer ou modifier des données critiques ou l'ensemble des données accessibles via Helidon, et obtenir un accès en lecture non autorisé à un sous-ensemble de données. | Theoretical | Appliquer les correctifs du bulletin Oracle CPU d'août 2026 (hxxps://www[.]oracle[.]com/security-alerts/cspuaug2026[.]html). Restreindre l'accès réseau aux instances Helidon 1.4.19. Déployer un WAF. Surveiller les journaux d'accès et les modifications de données. | [https://cvefeed.io/vuln/detail/CVE-2026-73925](https://cvefeed.io/vuln/detail/CVE-2026-73925)<br>[https://www.oracle.com/security-alerts/cspuaug2026.html](https://www.oracle.com/security-alerts/cspuaug2026.html) |
| **CVE-2026-73924** | 9.1 | N/A | FALSE | Oracle Helidon 1.4.19 (composant : Imperative Web Server) | Vulnérabilité critique de confidentialité et d'intégrité non authentifiée via HTTP | Un attaquant non authentifié peut obtenir un accès complet aux données critiques ou à l'ensemble des données accessibles via Helidon, et créer, supprimer ou modifier des données critiques. Compromission totale de la confidentialité et de l'intégrité. | Theoretical | Appliquer immédiatement les correctifs du bulletin Oracle CPU d'août 2026 (hxxps://www[.]oracle[.]com/security-alerts/cspuaug2026[.]html). Isoler les instances Helidon 1.4.19 exposées non corrigées. Déployer un WAF. Surveiller en temps réel les journaux d'accès et les modifications de données. | [https://cvefeed.io/vuln/detail/CVE-2026-73924](https://cvefeed.io/vuln/detail/CVE-2026-73924)<br>[https://www.oracle.com/security-alerts/cspuaug2026.html](https://www.oracle.com/security-alerts/cspuaug2026.html) |
| **CVE-2026-73922** | 9.1 | N/A | FALSE | Oracle Helidon 1.4.19 (composant : Imperative Web Server) | Vulnérabilité critique de confidentialité et d'intégrité non authentifiée via HTTP | Un attaquant non authentifié peut obtenir un accès complet aux données critiques ou à l'ensemble des données accessibles via Helidon, et créer, supprimer ou modifier des données critiques. Compromission totale de la confidentialité et de l'intégrité. | Theoretical | Appliquer immédiatement les correctifs du bulletin Oracle CPU d'août 2026 (hxxps://www[.]oracle[.]com/security-alerts/cspuaug2026[.]html). Isoler les instances Helidon 1.4.19 exposées non corrigées. Déployer un WAF. Surveiller en temps réel les journaux d'accès et les modifications de données. | [https://cvefeed.io/vuln/detail/CVE-2026-73922](https://cvefeed.io/vuln/detail/CVE-2026-73922)<br>[https://www.oracle.com/security-alerts/cspuaug2026.html](https://www.oracle.com/security-alerts/cspuaug2026.html) |
| **CVE-2026-19478** | 9.4 | 0.72% | FALSE | GitLab | CWE-94: Improper Control of Generation of Code ('Code Injection') | Un attaquant non authentifié peut modifier ou supprimer des projets publics et des données utilisateur sur les instances GitLab self-managed. Cela entraîne une perte d'intégrité des données, un contournement de la politique de sécurité et potentiellement une interruption de service pour les équipes de développement utilisant ces projets. | None | Mettre à jour immédiatement vers les versions corrigées : 19.2.4, 19.1.6, 19.0.8 ou 18.11.11. Pour les versions 18.2 à 18.10, migrer vers une branche corrigée car aucun correctif ne sera publié. Restreindre l'accès public aux instances GitLab self-managed. Surveiller les logs GraphQL pour des activités suspectes. Consulter le bulletin de sécurité GitLab : hxxps://docs[.]gitlab[.]com/releases/patches/patch-release-gitlab-19-2-4-released/ | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1037/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1037/)<br>[https://securityaffairs.com/197454/hacking/gitlab-patches-critical-unauthenticated-graphql-vulnerability.html](https://securityaffairs.com/197454/hacking/gitlab-patches-critical-unauthenticated-graphql-vulnerability.html) |
| **CVE-2026-19650** | 7.1 | 0.24% | FALSE | GitLab | CWE-352: Cross-Site Request Forgery (CSRF) | Un attaquant peut, via un lien piégé, déclencher des mutations GraphQL dans la session authentifiée d'une victime, pouvant entraîner des modifications non autorisées de données ou de configurations dans GitLab. | None | Mettre à jour vers les versions corrigées : 19.2.4, 19.1.6, 19.0.8 ou 18.11.11. Renforcer les protections CSRF (SameSite cookies, CSP). Sensibiliser les utilisateurs aux risques de clic sur des liens non fiables. Consulter le bulletin de sécurité GitLab : hxxps://docs[.]gitlab[.]com/releases/patches/patch-release-gitlab-19-2-4-released/ | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1037/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1037/)<br>[https://securityaffairs.com/197454/hacking/gitlab-patches-critical-unauthenticated-graphql-vulnerability.html](https://securityaffairs.com/197454/hacking/gitlab-patches-critical-unauthenticated-graphql-vulnerability.html) |
| **CVE-2026-50191** | 8.8 | N/A | FALSE | 4gaBoards | CWE-287: Improper Authentication | Un attaquant peut prendre le contrôle d'un compte utilisateur légitime en créant préventivement un compte local avec l'email de la victime, puis en attendant que la victime se connecte via SSO. L'attaquant obtient alors accès aux projets, données et permissions de la victime via le mot de passe local qu'il a défini. | None | Mettre à jour 4gaBoards vers la version 3.3.8 ou ultérieure. Si la mise à jour est impossible, désactiver l'enregistrement SSO. Examiner les inscriptions de comptes existants pour détecter une activité suspecte. Consulter : hxxps://github[.]com/RARgames/4gaBoards/security/advisories/GHSA-f3p6-chc6-pc77 | [https://cvefeed.io/vuln/detail/CVE-2026-50191](https://cvefeed.io/vuln/detail/CVE-2026-50191) |
| **CVE-2026-50186** | 8.8 | N/A | FALSE | 4gaBoards | CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Un attaquant authentifié en tant que project manager peut lire des fichiers arbitraires sur le serveur (fichiers de configuration, secrets, données sensibles) et les supprimer, entraînant une fuite d'informations, une perte de données et potentiellement un déni de service. | None | Mettre à jour 4gaBoards vers la version 3.3.8 ou ultérieure. Appliquer les correctifs de l'éditeur si disponibles. Revoir les contrôles d'accès pour la gestion de projets. Consulter : hxxps://github[.]com/RARgames/4gaBoards/security/advisories/GHSA-rv7w-hhqv-65cf | [https://cvefeed.io/vuln/detail/CVE-2026-50186](https://cvefeed.io/vuln/detail/CVE-2026-50186) |
| **CVE-2026-21582** | 8.8 | N/A | FALSE | Crowd Data Center | BASM (Broken Authentication & Session Management) | Un attaquant non authentifié peut usurper l'identité d'autres utilisateurs et effectuer des actions en leur nom, compromettant l'intégrité du système d'authentification centralisé Crowd et potentiellement toutes les applications intégrées qui dépendent de Crowd pour l'authentification. | None | Mettre à jour Crowd Data Center vers la version 7.2.2 ou ultérieure, idéalement la dernière version. Consulter les notes de version : hxxps://confluence[.]atlassian[.]com/crowd/crowd-release-notes-199094[.]html. Télécharger depuis : hxxps://www[.]atlassian[.]com/software/crowd/download-archive | [https://cvefeed.io/vuln/detail/CVE-2026-21582](https://cvefeed.io/vuln/detail/CVE-2026-21582) |
| **CVE-2026-21580** | 8.6 | N/A | FALSE | Confluence Data Center, Confluence Server | Stored XSS | Un attaquant non authentifié peut exécuter du code malveillant dans le navigateur des victimes via du contenu XSS stocké, escalader ses privilèges pour agir en tant qu'utilisateur administrateur, et exploiter des misconfigurations pour accéder au système. Cela peut entraîner un compromission complète de l'instance Confluence, un vol de données, et un accès persistant au système. | None | Mettre à jour Confluence Data Center et Server vers la dernière version ou vers 9.2.21+ / 10.2.13+. Revoir les bonnes pratiques de sécurité. Appliquer les correctifs de l'éditeur. Consulter : hxxps://confluence[.]atlassian[.]com/doc/confluence-release-notes-327[.]html | [https://cvefeed.io/vuln/detail/CVE-2026-21580](https://cvefeed.io/vuln/detail/CVE-2026-21580) |
| **CVE-2026-24301** | 8.8 | N/A | FALSE | Copilot Web | CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') | Un attaquant peut, par un simple clic de la victime sur un lien malveillant, exécuter un prompt arbitraire dans sa session Copilot authentifiée. Ce prompt peut exfiltrer des données sensibles depuis les applications connectées (corps et métadonnées d'emails, informations de calendrier, fichiers Google Drive, historique de conversations, instructions mémoire) vers un serveur externe. L'empoisonnement de la mémoire permet également une persistance à long terme en influençant le comportement de Copilot dans les sessions futures. L'exfiltration est indétectable au niveau réseau car elle ressemble au trafic légitime de Copilot. | None | Appliquer les correctifs Microsoft publiés le 18 août 2026. Filtrer les URLs vers copilot[.]microsoft[.]com contenant le paramètre autorun=1. Restreindre les permissions des applications connectées à Copilot. Sensibiliser les utilisateurs aux risques de clic sur des liens suspects. Traiter les assistants IA comme des insiders privilégiés et appliquer des contrôles d'accès stricts. Envisager un filtrage ou une inspection des URLs des assistants IA au niveau du proxy d'entreprise. | [https://thehackernews.com/2026/08/microsoft-copilot-personal-flaws-could.html](https://thehackernews.com/2026/08/microsoft-copilot-personal-flaws-could.html)<br>[https://www.security.nl/posting/949587/Microsoft+verhelpt+kritiek+Copilot-lek+waardoor+informatie+kon+lekken](https://www.security.nl/posting/949587/Microsoft+verhelpt+kritiek+Copilot-lek+waardoor+informatie+kon+lekken) |
| **CVE-2025-62593** | 9.4 | 1.01% | TRUE | ray | CWE-94: Improper Control of Generation of Code ('Code Injection') | Exécution de code arbitraire à distance sur les machines des développeurs, escalade de privilèges, mouvement latéral sur le réseau interne, établissement de canaux C2, exfiltration de données, perturbation des opérations. Les instances compromises peuvent être transformées en botnets DDoS (RondoDox) ou en mines de cryptomonnaie (ShadowRay 2.0). L'impact technique est évalué comme total par CISA (SSVC: technicalImpact=total, automatable=yes). | Active | Mettre à jour Ray vers la version 2.52.0 ou supérieure. Activer l'authentification sur les endpoints critiques (token-auth). Restreindre l'accès réseau au dashboard/API Ray (port 8265). Surveiller le trafic DNS pour détecter les tentatives de DNS rebinding. Sensibiliser les développeurs aux risques de phishing et malvertising. Conformité BOD 26-04 requise pour les FCEB. | [https[://]thehackernews.com/2026/08/cisa-flags-actively-exploited-ray-flaw.html](https[://]thehackernews.com/2026/08/cisa-flags-actively-exploited-ray-flaw.html)<br>[https[://]securityaffairs.com/197419/security/u-s-cisa-adds-a-ray-project-ray-flaw-to-its-known-exploited-vulnerabilities-catalog.html](https[://]securityaffairs.com/197419/security/u-s-cisa-adds-a-ray-project-ray-flaw-to-its-known-exploited-vulnerabilities-catalog.html)<br>[https[://]github.com/ray-project/ray/security/advisories/GHSA-q279-jhrf-cc6v](https[://]github.com/ray-project/ray/security/advisories/GHSA-q279-jhrf-cc6v)<br>[https[://]nvd.nist.gov/vuln/detail/CVE-2025-62593](https[://]nvd.nist.gov/vuln/detail/CVE-2025-62593)<br>[https://thehackernews.com/2026/08/cisa-flags-actively-exploited-ray-flaw.html](https://thehackernews.com/2026/08/cisa-flags-actively-exploited-ray-flaw.html)<br>[https://securityaffairs.com/197419/security/u-s-cisa-adds-a-ray-project-ray-flaw-to-its-known-exploited-vulnerabilities-catalog.html](https://securityaffairs.com/197419/security/u-s-cisa-adds-a-ray-project-ray-flaw-to-its-known-exploited-vulnerabilities-catalog.html) |
| **CVE-2026-15305** | 6.3 | 0.17% | FALSE | TYPO3 CMS | CWE-351 Insufficient Type Distinction | Un attaquant peut télécharger des fichiers avec des types MIME non autorisés via les formulaires TYPO3, ce qui peut conduire à un contournement de la politique de sécurité. L'impact est limité car le téléchargement de fichiers PHP n'est pas possible, mais d'autres types de fichiers malveillants peuvent être téléchargés. | None | Mettre à jour TYPO3 CMS vers la version 14.3.5 ou supérieure. Vérifier la configuration des allowedMimeTypes dans les formulaires. Surveiller les fichiers téléchargés via le Form Framework. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1036/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1036/)<br>[https[://]news.typo3.com/security/advisory/typo3-core-sa-2026-020](https[://]news.typo3.com/security/advisory/typo3-core-sa-2026-020)<br>[https[://]github.com/TYPO3/typo3/security/advisories/GHSA-68jx-f42c-7599](https[://]github.com/TYPO3/typo3/security/advisories/GHSA-68jx-f42c-7599)<br>[https[://]nvd.nist.gov/vuln/detail/CVE-2026-15305](https[://]nvd.nist.gov/vuln/detail/CVE-2026-15305)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1036/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1036/) |
| **CVE-2026-19418** | 7.3 | 0.21% | FALSE | TYPO3 CMS | CWE-346 Origin Validation Error | Un attaquant disposant d'un vecteur XSS sur un domaine TYPO3 peut invoquer les endpoints backend et Install Tool avec les privilèges de la session d'un utilisateur authentifié, permettant l'escalade de privilèges, la modification de configuration et potentiellement la compromission complète du système. | None | Mettre à jour TYPO3 CMS vers 13.4.34 ou 14.3.6. Si la mise à jour est différée, restreindre l'accès au backend et à l'Install Tool par IP ou configurer le serveur web pour refuser l'accès à ces routes depuis d'autres domaines. Éliminer les vulnérabilités XSS sur les domaines TYPO3. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1036/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1036/)<br>[https[://]news.typo3.com/security/advisory/typo3-core-sa-2026-021](https[://]news.typo3.com/security/advisory/typo3-core-sa-2026-021)<br>[https[://]github.com/TYPO3/typo3/security/advisories/GHSA-mfqj-cqv3-h7xw](https[://]github.com/TYPO3/typo3/security/advisories/GHSA-mfqj-cqv3-h7xw)<br>[https[://]nvd.nist.gov/vuln/detail/CVE-2026-19418](https[://]nvd.nist.gov/vuln/detail/CVE-2026-19418)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1036/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1036/) |
| **CVE-2026-28947** | 8.8 | 0.38% | FALSE | Safari, iOS and iPadOS, macOS | Processing maliciously crafted web content may lead to an unexpected Safari crash | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-28958** | 5.5 | 0.14% | FALSE | Safari, iOS and iPadOS, macOS | An app may be able to access sensitive user data | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-28973** | 8.6 | 0.13% | FALSE | iOS and iPadOS, macOS, watchOS | A malicious app may be able to break out of its sandbox | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-28979** | 6.5 | 0.30% | FALSE | Safari, iOS and iPadOS, macOS | Processing maliciously crafted web content may lead to an unexpected process crash | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-28984** | 4.3 | 0.12% | FALSE | iOS and iPadOS | Processing maliciously crafted web content may lead to an unexpected Safari crash | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-28990** | 7.5 | 0.35% | FALSE | iOS and iPadOS, macOS, tvOS | Processing a maliciously crafted image may corrupt process memory | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-28996** | 5.5 | 0.11% | FALSE | iOS and iPadOS, macOS, tvOS | An app may be able to access sensitive user data | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-3783** | 5.3 | 0.33% | FALSE | curl | CWE-522 Insufficiently Protected Credentials | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-3784** | 6.5 | 0.30% | FALSE | curl | CWE-305 Authentication Bypass by Primary Weakness | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-39868** | 9.1 | 0.96% | FALSE | iOS and iPadOS, macOS, tvOS | An app may be able to cause unexpected system termination or corrupt kernel memory | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-39872** | 6.5 | 0.25% | FALSE | Safari, iOS and iPadOS, macOS | Processing maliciously crafted web content may lead to an unexpected process crash | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-39877** | 7.8 | 0.14% | FALSE | iOS and iPadOS, macOS | An app may be able to disclose kernel memory | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-43658** | 7.5 | 0.32% | FALSE | Safari, iOS and iPadOS, macOS | Processing maliciously crafted web content may lead to an unexpected Safari crash | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-43661** | 7.5 | 0.63% | FALSE | iOS and iPadOS, macOS, tvOS | Processing a maliciously crafted image may corrupt process memory | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-43663** | 6.5 | 0.25% | FALSE | Safari, iOS and iPadOS, macOS | Processing maliciously crafted web content may lead to an unexpected process crash | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-43667** | 6.5 | 0.15% | FALSE | iOS and iPadOS | An attacker in a privileged network position may be able to cause a denial-of-service | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-43673** | 7.8 | 0.12% | FALSE | iOS and iPadOS, macOS, tvOS | Processing a maliciously crafted audio file may corrupt process memory | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-43676** | 6.5 | 0.40% | FALSE | Safari, iOS and iPadOS, macOS | Processing maliciously crafted web content may lead to an unexpected Safari crash | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-43699** | 6.5 | 0.29% | FALSE | Safari, iOS and iPadOS, macOS | Processing maliciously crafted web content may lead to an unexpected process crash | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-43700** | 6.5 | 0.24% | FALSE | Safari, iOS and iPadOS, macOS | Processing maliciously crafted web content may disclose sensitive user information | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-43701** | 7.1 | 0.50% | FALSE | Safari, iOS and iPadOS, macOS | A malicious website may be able to process restricted web content outside the sandbox | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-43705** | 8.8 | 0.46% | FALSE | Safari, iOS and iPadOS, macOS | Processing maliciously crafted web content may lead to memory corruption | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-43708** | 4.3 | 0.37% | FALSE | Safari, iOS and iPadOS, macOS | A malicious website may exfiltrate data cross-origin | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-43711** | 7.8 | 0.12% | FALSE | iOS and iPadOS, macOS, tvOS | Processing a maliciously crafted video file may lead to unexpected app termination | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-43714** | 5.5 | 0.13% | FALSE | iOS and iPadOS, macOS, visionOS | A malicious app may be able to access protected user data | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-43717** | 6.5 | 0.24% | FALSE | Safari, iOS and iPadOS, macOS | Processing maliciously crafted web content may lead to an unexpected Safari crash | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-43720** | 6.5 | 0.56% | FALSE | Safari, iOS and iPadOS, macOS | Processing maliciously crafted web content may lead to an unexpected Safari crash | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-43722** | 5.5 | 0.26% | FALSE | iOS and iPadOS, macOS | An app may be able to leak sensitive kernel state | Selon la vulnérabilité spécifique, un attaquant pourrait exécuter du code arbitraire, élever ses privilèges, provoquer un déni de service, contourner les politiques de sécurité ou accéder à des données sensibles sur les appareils Apple non mis à jour. | None | Mettre à jour iOS vers 18.7.10 ou 26.6.1, iPadOS vers 18.7.10 ou 26.6.1, et macOS Tahoe vers 26.6.2. Se référer aux bulletins de sécurité Apple 148281, 148282 et 148287. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/)<br>[https[://]support.apple.com/en-us/148281](https[://]support.apple.com/en-us/148281)<br>[https[://]support.apple.com/en-us/148282](https[://]support.apple.com/en-us/148282)<br>[https[://]support.apple.com/en-us/148287](https[://]support.apple.com/en-us/148287)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1038/) |
| **CVE-2026-1199** | 6.9 | N/A | FALSE | Zabbix | CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') | Selon la vulnérabilité spécifique, un attaquant pourrait provoquer un déni de service, injecter du code via XSS, accéder à des données sensibles de monitoring ou contourner les politiques de sécurité du système Zabbix. | None | Mettre à jour Zabbix 6.x vers 6.0.48, Zabbix 7.4.x vers 7.4.13, et Zabbix 7.x vers 7.0.29. Se référer aux bulletins de sécurité Zabbix ZBX-28067 à ZBX-28077. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/)<br>[https[://]support.zabbix.com/browse/ZBX-28067](https[://]support.zabbix.com/browse/ZBX-28067)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/) |
| **CVE-2026-23922** | 2.1 | N/A | FALSE | Zabbix | CWE-522: Insufficiently Protected Credentials | Selon la vulnérabilité spécifique, un attaquant pourrait provoquer un déni de service, injecter du code via XSS, accéder à des données sensibles de monitoring ou contourner les politiques de sécurité du système Zabbix. | None | Mettre à jour Zabbix 6.x vers 6.0.48, Zabbix 7.4.x vers 7.4.13, et Zabbix 7.x vers 7.0.29. Se référer aux bulletins de sécurité Zabbix ZBX-28067 à ZBX-28077. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/)<br>[https[://]support.zabbix.com/browse/ZBX-28068](https[://]support.zabbix.com/browse/ZBX-28068)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/) |
| **CVE-2026-23929** | 8.5 | N/A | FALSE | Zabbix | CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ("Prototype Pollution") | Selon la vulnérabilité spécifique, un attaquant pourrait provoquer un déni de service, injecter du code via XSS, accéder à des données sensibles de monitoring ou contourner les politiques de sécurité du système Zabbix. | None | Mettre à jour Zabbix 6.x vers 6.0.48, Zabbix 7.4.x vers 7.4.13, et Zabbix 7.x vers 7.0.29. Se référer aux bulletins de sécurité Zabbix ZBX-28067 à ZBX-28077. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/)<br>[https[://]support.zabbix.com/browse/ZBX-28069](https[://]support.zabbix.com/browse/ZBX-28069)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/) |
| **CVE-2026-23930** | 5.3 | N/A | FALSE | Zabbix | CWE-405: Asymmetric Resource Consumption (Amplification) | Selon la vulnérabilité spécifique, un attaquant pourrait provoquer un déni de service, injecter du code via XSS, accéder à des données sensibles de monitoring ou contourner les politiques de sécurité du système Zabbix. | None | Mettre à jour Zabbix 6.x vers 6.0.48, Zabbix 7.4.x vers 7.4.13, et Zabbix 7.x vers 7.0.29. Se référer aux bulletins de sécurité Zabbix ZBX-28067 à ZBX-28077. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/)<br>[https[://]support.zabbix.com/browse/ZBX-28070](https[://]support.zabbix.com/browse/ZBX-28070)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/) |
| **CVE-2026-23931** | 5.3 | N/A | FALSE | Zabbix | CWE-203: Observable Discrepancy | Selon la vulnérabilité spécifique, un attaquant pourrait provoquer un déni de service, injecter du code via XSS, accéder à des données sensibles de monitoring ou contourner les politiques de sécurité du système Zabbix. | None | Mettre à jour Zabbix 6.x vers 6.0.48, Zabbix 7.4.x vers 7.4.13, et Zabbix 7.x vers 7.0.29. Se référer aux bulletins de sécurité Zabbix ZBX-28067 à ZBX-28077. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/)<br>[https[://]support.zabbix.com/browse/ZBX-28071](https[://]support.zabbix.com/browse/ZBX-28071)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/) |
| **CVE-2026-23933** | 7.7 | N/A | FALSE | Zabbix | CWE-259 CWE-259: Use of Hard-coded Password | Selon la vulnérabilité spécifique, un attaquant pourrait provoquer un déni de service, injecter du code via XSS, accéder à des données sensibles de monitoring ou contourner les politiques de sécurité du système Zabbix. | None | Mettre à jour Zabbix 6.x vers 6.0.48, Zabbix 7.4.x vers 7.4.13, et Zabbix 7.x vers 7.0.29. Se référer aux bulletins de sécurité Zabbix ZBX-28067 à ZBX-28077. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/)<br>[https[://]support.zabbix.com/browse/ZBX-28072](https[://]support.zabbix.com/browse/ZBX-28072)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/) |
| **CVE-2026-23934** | 5.1 | N/A | FALSE | Zabbix | CWE-405: Asymmetric Resource Consumption (Amplification) | Selon la vulnérabilité spécifique, un attaquant pourrait provoquer un déni de service, injecter du code via XSS, accéder à des données sensibles de monitoring ou contourner les politiques de sécurité du système Zabbix. | None | Mettre à jour Zabbix 6.x vers 6.0.48, Zabbix 7.4.x vers 7.4.13, et Zabbix 7.x vers 7.0.29. Se référer aux bulletins de sécurité Zabbix ZBX-28067 à ZBX-28077. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/)<br>[https[://]support.zabbix.com/browse/ZBX-28073](https[://]support.zabbix.com/browse/ZBX-28073)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/) |
| **CVE-2026-23935** | 6.8 | N/A | FALSE | Zabbix | CWE-125: Out-of-bounds Read | Selon la vulnérabilité spécifique, un attaquant pourrait provoquer un déni de service, injecter du code via XSS, accéder à des données sensibles de monitoring ou contourner les politiques de sécurité du système Zabbix. | None | Mettre à jour Zabbix 6.x vers 6.0.48, Zabbix 7.4.x vers 7.4.13, et Zabbix 7.x vers 7.0.29. Se référer aux bulletins de sécurité Zabbix ZBX-28067 à ZBX-28077. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/)<br>[https[://]support.zabbix.com/browse/ZBX-28074](https[://]support.zabbix.com/browse/ZBX-28074)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/) |
| **CVE-2026-23937** | 6.0 | N/A | FALSE | Zabbix | CWE-203: Observable Discrepancy | Selon la vulnérabilité spécifique, un attaquant pourrait provoquer un déni de service, injecter du code via XSS, accéder à des données sensibles de monitoring ou contourner les politiques de sécurité du système Zabbix. | None | Mettre à jour Zabbix 6.x vers 6.0.48, Zabbix 7.4.x vers 7.4.13, et Zabbix 7.x vers 7.0.29. Se référer aux bulletins de sécurité Zabbix ZBX-28067 à ZBX-28077. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/)<br>[https[://]support.zabbix.com/browse/ZBX-28075](https[://]support.zabbix.com/browse/ZBX-28075)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/) |
| **CVE-2026-23938** | 2.1 | N/A | FALSE | Zabbix | CWE-248: Uncaught Exception | Selon la vulnérabilité spécifique, un attaquant pourrait provoquer un déni de service, injecter du code via XSS, accéder à des données sensibles de monitoring ou contourner les politiques de sécurité du système Zabbix. | None | Mettre à jour Zabbix 6.x vers 6.0.48, Zabbix 7.4.x vers 7.4.13, et Zabbix 7.x vers 7.0.29. Se référer aux bulletins de sécurité Zabbix ZBX-28067 à ZBX-28077. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/)<br>[https[://]support.zabbix.com/browse/ZBX-28076](https[://]support.zabbix.com/browse/ZBX-28076)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/) |
| **CVE-2026-59781** | 5.4 | N/A | FALSE | Zabbix | CWE-427: Uncontrolled Search Path Element | Selon la vulnérabilité spécifique, un attaquant pourrait provoquer un déni de service, injecter du code via XSS, accéder à des données sensibles de monitoring ou contourner les politiques de sécurité du système Zabbix. | None | Mettre à jour Zabbix 6.x vers 6.0.48, Zabbix 7.4.x vers 7.4.13, et Zabbix 7.x vers 7.0.29. Se référer aux bulletins de sécurité Zabbix ZBX-28067 à ZBX-28077. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/)<br>[https[://]support.zabbix.com/browse/ZBX-28077](https[://]support.zabbix.com/browse/ZBX-28077)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1039/) |
| **CVE-2026-75587** | 3.6 | 0.10% | FALSE | Mattermost | CWE-200 Exposure of Sensitive Information to an Unauthorized Actor | Un attaquant local ayant accès aux rapports de diagnostic ou fichiers de log d'un utilisateur Mattermost peut obtenir le pre-auth secret en clair, lui permettant d'accéder au serveur Mattermost connecté avec les privilèges associés à ce secret. L'impact est limité (CVSS 3.6 Low) car il nécessite un accès local aux fichiers de l'utilisateur. | None | Mettre à jour Mattermost Desktop App vers la version 6.2.3.0 ou 6.3.0. Révoquer et régénérer les pre-auth secrets configurés sur les serveurs connectés. Sensibiliser les utilisateurs à ne pas partager leurs rapports de diagnostic. Surveiller les accès aux serveurs utilisant des pre-auth secrets. | [https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1040/](https[://]www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1040/)<br>[https[://]mattermost.com/security-updates/](https[://]mattermost.com/security-updates/)<br>[https[://]nvd.nist.gov/vuln/detail/CVE-2026-75587](https[://]nvd.nist.gov/vuln/detail/CVE-2026-75587)<br>[https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1040/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1040/) |
| **CVE-2026-66602** | 8.8 | N/A | FALSE | HashBar – WordPress Notification Bar | CWE-352 Cross-Site Request Forgery (CSRF) | Un attaquant peut exploiter cette vulnérabilité CSRF pour forcer un administrateur authentifié à effectuer des actions non autorisées sur le plugin HashBar, potentiellement modifier les configurations, supprimer des notifications ou effectuer d'autres actions administratives. Le score CVSS élevé (8.8) reflète l'impact significatif sur l'intégrité et la disponibilité. | Theoretical | Mettre à jour le plugin HashBar vers une version supérieure à 2.0.0 (2.0.1 ou plus). Vérifier la version du plugin installée. Mettre en place un WAF avec des règles CSRF. Surveiller les mises à jour de sécurité du plugin régulièrement. | [https[://]cvefeed.io/vuln/detail/CVE-2026-66602](https[://]cvefeed.io/vuln/detail/CVE-2026-66602)<br>[https[://]patchstack.com/database/wordpress/plugin/hashbar-wp-notification-bar/vulnerability/wordpress-hashbar-wordpress-notification-bar-plugin-2-0-0-cross-site-request-forgery-csrf-vulnerability?_s_id=cve](https[://]patchstack.com/database/wordpress/plugin/hashbar-wp-notification-bar/vulnerability/wordpress-hashbar-wordpress-notification-bar-plugin-2-0-0-cross-site-request-forgery-csrf-vulnerability?_s_id=cve)<br>[https://cvefeed.io/vuln/detail/CVE-2026-66602](https://cvefeed.io/vuln/detail/CVE-2026-66602) |
| **CVE-2026-62292** | 8.7 | N/A | FALSE | libheif | CWE-125: Out-of-bounds Read | Un attaquant pouvant fournir un fichier HEIF crafted peut faire crasher les applications qui décodent les tuiles d'images uncompressed avec libheif. L'impact directement observé est un déni de service (SIGSEGV). Aucun impact de confidentialité n'a été démontré car le crash se produit avant toute divulgation de données. Les distributions Linux affectées incluent Debian (bullseye, bookworm, trixie, forky) et SUSE. | Theoretical | Mettre à jour libheif vers la version 1.23.1 ou supérieure. Recompiler les applications affectées avec la version patchée. Appliquer les correctifs des distributions (Debian, SUSE). Valider les fichiers HEIF/AVIF en entrée et limiter les tailles de tuiles et indices acceptés. | [https[://]cvefeed.io/vuln/detail/CVE-2026-62292](https[://]cvefeed.io/vuln/detail/CVE-2026-62292)<br>[https[://]github.com/strukturag/libheif/security/advisories/GHSA-73p7-m7gg-w2jv](https[://]github.com/strukturag/libheif/security/advisories/GHSA-73p7-m7gg-w2jv)<br>[https[://]github.com/strukturag/libheif/releases/tag/v1.23.1](https[://]github.com/strukturag/libheif/releases/tag/v1.23.1)<br>[https[://]github.com/strukturag/libheif/commit/089a809bf6bed1abae102d5e97b6bb8c4f53b515](https[://]github.com/strukturag/libheif/commit/089a809bf6bed1abae102d5e97b6bb8c4f53b515)<br>[https://cvefeed.io/vuln/detail/CVE-2026-62292](https://cvefeed.io/vuln/detail/CVE-2026-62292) |
| **CVE-2026-52877** | 8.3 | N/A | FALSE | streambert | CWE-20: Improper Input Validation | Un attaquant ayant compromis le renderer peut exécuter des fichiers locaux, lancer des applications arbitraires, accéder à des ressources distantes et potentiellement obtenir une exécution de code à distance avec les privilèges de l'utilisateur courant. | Theoretical | Mettre à jour Streambert vers la version 2.6.0 ou ultérieure. La mise à jour ajoute la validation des protocoles avant l'appel à shell.openExternal. | [https://cvefeed.io/vuln/detail/CVE-2026-52877](https://cvefeed.io/vuln/detail/CVE-2026-52877) |
| **CVE-2026-52876** | 8.8 | N/A | FALSE | streambert | CWE-20: Improper Input Validation | Un attaquant ayant compromis le renderer peut exécuter des fichiers arbitraires (exécutables, scripts, raccourcis) avec les privilèges de l'utilisateur courant, menant potentiellement à une exécution de code à distance et une prise de contrôle du système. | Theoretical | Mettre à jour Streambert vers la version 2.6.0 ou ultérieure. La mise à jour ajoute la validation du type et de l'emplacement du filePath avant l'appel à shell.openPath. | [https://cvefeed.io/vuln/detail/CVE-2026-52876](https://cvefeed.io/vuln/detail/CVE-2026-52876) |
| **CVE-2026-52875** | 8.4 | N/A | FALSE | streambert | CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Un attaquant peut créer des répertoires arbitraires, écrire des fichiers contrôlés à des emplacements quelconques du système de fichiers, et supprimer des fichiers .json existants dont le nom correspond au pattern de pruning, pouvant entraîner une corruption de données, une exfiltration ou un déni de service. | Theoretical | Mettre à jour Streambert vers la version 2.6.0 ou ultérieure. Vérifier que le répertoire de backup est correctement restreint. Appliquer les correctifs de sécurité pour les applications Electron. | [https://cvefeed.io/vuln/detail/CVE-2026-52875](https://cvefeed.io/vuln/detail/CVE-2026-52875) |
| **CVE-2026-52872** | 8.8 | N/A | FALSE | streambert | CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Un attaquant peut exfiltrer des fichiers locaux sensibles (credentials, configurations, clés privées) vers des emplacements contrôlés, et écraser des fichiers existants, pouvant entraîner une compromission du système ou un déni de service. | Theoretical | Mettre à jour Streambert vers la version 2.5.0 ou ultérieure. Vérifier que la version installée est 2.5.0 ou plus récente. | [https://cvefeed.io/vuln/detail/CVE-2026-52872](https://cvefeed.io/vuln/detail/CVE-2026-52872) |
| **CVE-2026-52854** | 8.6 | N/A | FALSE | Maps | CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') | Un attaquant peut exécuter du code JavaScript arbitraire dans le navigateur des utilisateurs consultant les pages affectées, permettant le vol de sessions, l'accès à des données sensibles, et l'exécution d'actions au nom de la victime. | Theoretical | Mettre à jour l'extension Maps MediaWiki vers la version 12.1.3 ou ultérieure. S'assurer que la version installée est 12.1.3 ou plus récente. | [https://cvefeed.io/vuln/detail/CVE-2026-52854](https://cvefeed.io/vuln/detail/CVE-2026-52854) |
| **CVE-2026-15315** | 8.7 | N/A | FALSE | Tapo C200 v5 | CWE-287 Improper Authentication | Un attaquant local peut obtenir un accès administrateur complet à la caméra, permettant la visualisation du flux vidéo, la modification des configurations, le contrôle à distance du dispositif, et potentiellement causer un déni de service. | Theoretical | Mettre à jour le firmware du dispositif vers la dernière version disponible. Appliquer les correctifs du fabricant pour les vulnérabilités d'authentification. Restreindre l'accès réseau local au dispositif. Surveiller le dispositif pour détecter les tentatives d'accès non autorisées. | [https://cvefeed.io/vuln/detail/CVE-2026-15315](https://cvefeed.io/vuln/detail/CVE-2026-15315) |
| **CVE-2026-64849** | 9.3 | 0.35% | FALSE | mlflow | CWE-918: Server-Side Request Forgery (SSRF) | Un attaquant non authentifié peut accéder aux endpoints de métadonnées cloud internes (ex. 169.254.169.254), extraire des credentials cloud, des tokens de session et des secrets, permettant potentiellement un mouvement latéral dans l'infrastructure cloud, une exfiltration de données et une prise de contrôle complète de l'environnement cloud. | Active | Mettre à jour MLflow vers la version 3.15.0 ou ultérieure. Ne pas exposer les instances MLflow sur Internet sans authentification. Restreindre l'accès aux endpoints de métadonnées cloud. Révoquer et faire tourner tous les credentials potentiellement compromis. Examiner les journaux d'audit pour détecter des signes de compromission. | [https://thehackernews.com/2026/08/attackers-exploit-mlflow-ssrf-flaw-to.html](https://thehackernews.com/2026/08/attackers-exploit-mlflow-ssrf-flaw-to.html) |
| **CVE-2026-25895** | 9.5 | 3.91% | FALSE | FUXA | CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Un attaquant non authentifié peut écrire des fichiers arbitraires sur le serveur, écraser des fichiers critiques (comme main.js), et potentiellement obtenir une exécution de code à distance, compromettant entièrement le système SCADA/HMI et potentiellement l'infrastructure industrielle contrôlée. | Active | Mettre à jour FUXA vers une version supérieure à 1.2.9. Ne pas exposer les instances FUXA sur Internet. Segmenter le réseau OT. Surveiller les journaux pour détecter des signes de compromission. | [https://thehackernews.com/2026/08/attackers-exploit-mlflow-ssrf-flaw-to.html](https://thehackernews.com/2026/08/attackers-exploit-mlflow-ssrf-flaw-to.html) |
| **CVE-2026-25939** | 9.3 | 11.39% | FALSE | FUXA | CWE-862: Missing Authorization | L'exploitation active de cette vulnérabilité sur des instances FUXA exposées peut compromettre des systèmes SCADA/HMI, avec des conséquences potentielles sur l'infrastructure industrielle contrôlée. | Active | Mettre à jour FUXA vers la dernière version disponible. Ne pas exposer les instances FUXA sur Internet. Segmenter le réseau OT. Surveiller les journaux pour détecter des signes de compromission. | [https://thehackernews.com/2026/08/attackers-exploit-mlflow-ssrf-flaw-to.html](https://thehackernews.com/2026/08/attackers-exploit-mlflow-ssrf-flaw-to.html) |
| **CVE-2023-33831** | N/A | 13.75% | FALSE | FUXA (logiciel SCADA/HMI web open-source) | n/a | L'exploitation active et persistante de cette vulnérabilité depuis novembre 2025 sur des instances FUXA exposées peut compromettre des systèmes SCADA/HMI, avec des conséquences potentiellement graves sur l'infrastructure industrielle contrôlée. | Active | Mettre à jour FUXA vers la dernière version disponible corrigeant CVE-2023-33831. Ne pas exposer les instances FUXA sur Internet. Segmenter le réseau OT. Surveiller les journaux pour détecter des signes de compromission. | [https://thehackernews.com/2026/08/attackers-exploit-mlflow-ssrf-flaw-to.html](https://thehackernews.com/2026/08/attackers-exploit-mlflow-ssrf-flaw-to.html) |
| **CVE-2026-18929** | 6.9 | N/A | FALSE | Carbone | CWE-409 Improper handling of highly compressed data (data amplification) | Un attaquant peut provoquer un déni de service en soumettant un fichier .docx contenant une zip bomb, entraînant un épuisement de la mémoire et le crash du serveur applicatif Carbone, rendant le service indisponible. | Theoretical | Mettre à jour Carbone vers la version 3.8.2, 4.26.3 ou 5.4.4 selon la branche utilisée. Le correctif est disponible pour tous les types de distribution. Mettre en place une validation de la taille des entrées zip avant décompression. | [https://cert.pl/en/posts/2026/08/CVE-2026-18929/](https://cert.pl/en/posts/2026/08/CVE-2026-18929/) |
| **CVE-2026-8452** | 8.8 | 0.49% | FALSE | ADC, Gateway | Remote Code Execution (RCE) non authentifiée | Compromission complète de l'appliance NetScaler avec exécution de code en tant que root. Installation de webshells pour un accès persistant. Accès aux applications d'entreprise, environnements de travail et intranets via la passerelle NetScaler. Risque de mouvement latéral vers l'infrastructure interne. Vol potentiel de credentials et de jetons SAML. L'impact est particulièrement élevé car NetScaler Gateway est largement utilisé pour le télétravail et l'accès distant aux ressources d'entreprise. | Active | Appliquer immédiatement les correctifs Citrix publiés le 30 juin 2026. Vérifier que la configuration SAML IdP est nécessaire ; si ce n'est pas le cas, désactiver cette fonctionnalité. Restreindre l'accès réseau aux interfaces d'administration. Surveiller activement les journaux pour détecter toute exploitation. Réaliser un audit de sécurité des appliances NetScaler pour détecter d'éventuelles compromissions déjà en cours. | [https://www.security.nl/posting/949523/Kritieke+Citrix+NetScaler+RCE-kwetsbaarheid+misbruikt+bij+aanvallen?channel=rss](https://www.security.nl/posting/949523/Kritieke+Citrix+NetScaler+RCE-kwetsbaarheid+misbruikt+bij+aanvallen?channel=rss) |
| **CVE-2026-65346** | 8.8 | 0.17% | FALSE | iOS and iPadOS, macOS | Processing an image may lead to arbitrary code execution | Exécution de code arbitraire sur des appareils iOS, iPadOS et macOS via le simple traitement d'une image malveillante. Vol de données sensibles via l'exploitation de WebKit History par des sites web malveillants. Compromission potentielle des appareils sans interaction utilisateur significative selon le vecteur de livraison de l'image. | None | Mettre à jour immédiatement vers iOS/iPadOS 26.6.1, macOS Tahoe 26.6.2, ou iOS/iPadOS 18.7.10 pour les appareils plus anciens. Déployer les mises à jour via MDM. Éviter d'ouvrir des images provenant de sources non fiables. Surveiller la publication éventuelle de détails techniques ou de PoC. | [https://www.security.nl/posting/949519/Apple+dicht+lek+waardoor+afbeelding+code+op+iPhones+en+Macs+kan+uitvoeren?channel=rss](https://www.security.nl/posting/949519/Apple+dicht+lek+waardoor+afbeelding+code+op+iPhones+en+Macs+kan+uitvoeren?channel=rss) |
| **CVE-2026-75897** | 8.7 | N/A | FALSE | OpenSearch Dashboards, Amazon OpenSearch Service | CWE-1284: Improper Validation of Specified Quantity in Input | Déni de service rendant OpenSearch Dashboards indisponible. Interruption des opérations de visualisation et de gestion des données. Indisponibilité potentielle du panneau de gestion pour les équipes opérationnelles. Pas de compromission de données ou d'exécution de code, mais impact opérationnel significatif. | None | Mettre à niveau vers OpenSearch Dashboards 3.8.0 ou ultérieur (auto-géré). Appliquer la dernière mise à jour logicielle de service AWS OpenSearch (managé). Déployer une couche d'authentification (proxy inverse, SAML/OIDC/Cognito) devant OpenSearch Dashboards. Restreindre l'accès réseau aux sources de confiance. Amazon OpenSearch Serverless ne nécessite aucune action. | [https://aws.amazon.com/security/security-bulletins/rss/2026-082-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-082-aws/) |
| **CVE-2026-75935** | 8.7 | N/A | FALSE | Amazon Ion Java | CWE-789 Memory allocation with excessive size value | Déni de service des applications Java utilisant ion-java pour traiter des données non fiables. Épuisement de la mémoire pouvant entraîner un crash de l'application ou de la JVM. Indisponibilité des services dépendants. Pas d'exécution de code ou de compromission de données, mais impact opérationnel significatif. | None | Mettre à jour ion-java vers la version 1.12.0 ou ultérieure. Configurer une taille maximale de buffer via IonBufferConfiguration.withMaximumBufferSize. Désactiver la décompression GZIP automatique via IonReaderBuilder.withGzipDecompressionEnabled(false) si des entrées non fiables sont traitées. S'assurer que tout code forké ou dérivé intègre les correctifs. | [https://aws.amazon.com/security/security-bulletins/rss/2026-083-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-083-aws/) |
| **CVE-2026-75936** | 8.7 | N/A | FALSE | Amazon Ion Java | CWE-409 (Improper Handling of Highly Compressed Data) | Déni de service des applications Java utilisant ion-java pour traiter des données compressées non fiables. Épuisement de la mémoire par expansion de données compressées, entraînant un crash de l'application ou de la JVM. Indisponibilité des services dépendants. Impact opérationnel significatif, particulièrement pour les services acceptant des entrées GZIP. | None | Mettre à jour ion-java vers la version 1.12.0 ou ultérieure. Configurer une taille maximale de buffer via IonBufferConfiguration.withMaximumBufferSize. Désactiver la décompression GZIP automatique via IonReaderBuilder.withGzipDecompressionEnabled(false) si des entrées non fiables sont traitées. S'assurer que tout code forké ou dérivé intègre les correctifs. | [https://aws.amazon.com/security/security-bulletins/rss/2026-083-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-083-aws/) |
| **CVE-2026-13242** | 6.5 | 0.17% | FALSE | Geolocation Field | CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') | Impact non spécifié publiquement. Étant donné que la vulnérabilité a été trouvée dans des extensions web et projets open-source largement utilisés, l'impact potentiel pourrait être significatif selon la nature de la faille et sa exploitabilité. | Theoretical | Surveiller les advisories de sécurité pour les mises à jour des extensions web et projets open-source concernés. Appliquer les correctifs dès leur disponibilité. Maintenir les extensions et dépendances à jour. Mettre en place un processus de revue de sécurité pour les composants tiers. | [https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review/](https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review/) |
| **CVE-2026-55803** | 5.9 | 0.21% | FALSE | Drupal core | CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes | Impact non spécifié publiquement. Étant donné que la vulnérabilité a été trouvée dans des extensions web et projets open-source largement utilisés, l'impact potentiel pourrait être significatif selon la nature de la faille et sa exploitabilité. | Theoretical | Surveiller les advisories de sécurité pour les mises à jour des extensions web et projets open-source concernés. Appliquer les correctifs dès leur disponibilité. Maintenir les extensions et dépendances à jour. Mettre en place un processus de revue de sécurité pour les composants tiers. | [https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review/](https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review/) |
| **CVE-2007-3010** | 9.8 | 97.41% | TRUE | Alcatel OmniPCX Enterprise | n/a | Compromission complète de l'équipement Alcatel OmniPCX Enterprise avec exécution de code arbitraire. L'équipement compromis peut être utilisé pour des attaques DDoS, du brute-force SSH, du sniffing de credentials, ou comme proxy SOCKS5. Risque de mouvement latéral dans le réseau interne. | Active | Appliquer les correctifs firmware Alcatel disponibles. Segmenter et isoler les équipements VoIP. Restreindre l'accès réseau aux interfaces d'administration. Surveiller le trafic pour détecter les indicateurs d'Evooo1Bot. Mettre à jour tous les équipements IoT et réseau non patchés. | [https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html](https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html) |
| **CVE-2016-6277** | 8.8 | 99.78% | TRUE | Routeurs NETGEAR (modèles multiples) | n/a | Compromission complète du routeur NETGEAR avec exécution de code arbitraire. Le routeur compromis peut servir de relais SOCKS5, de sniffer de credentials, ou de plateforme d'attaques DDoS. Risque d'interception du trafic réseau transitant par le routeur compromis. | Active | Appliquer les correctifs firmware NETGEAR disponibles. Désactiver l'administration à distance si non nécessaire. Changer les mots de passe par défaut. Surveiller le trafic pour détecter les indicateurs d'Evooo1Bot. Remplacer les routeurs en fin de vie ne recevant plus de correctifs. | [https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html](https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html) |
| **CVE-2018-14558** | 9.8 | 8.67% | TRUE | Tenda AC7, AC9 et AC10 (routeurs) | n/a | Compromission complète du routeur Tenda avec injection de commandes. Le routeur compromis devient un nœud du botnet Evooo1Bot, capable de lancer des attaques DDoS, de sniffer le trafic, de servir de proxy SOCKS5 et de propager l'infection via brute-force SSH. | Active | Appliquer les correctifs firmware Tenda disponibles. Désactiver l'administration à distance. Changer les mots de passe par défaut. Surveiller le trafic pour détecter les indicateurs d'Evooo1Bot. Remplacer les routeurs en fin de vie. | [https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html](https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html) |
| **CVE-2019-14931** | N/A | 58.09% | FALSE | Mitsubishi Electric Europe B.V. ME-RTU et INEA ME-RTU | n/a | Compromission de dispositifs industriels ME-RTU avec injection de commandes à distance. Risque de perturbation des opérations industrielles. Le dispositif compromis peut servir de point d'entrée dans le réseau OT pour des attaques ultérieures. Capacités DDoS, proxy SOCKS5 et sniffing de credentials déployées via Evooo1Bot. | Active | Appliquer les correctifs firmware disponibles. Segmenter strictement les réseaux OT/ICS. Restreindre l'accès réseau aux dispositifs ME-RTU. Surveiller le trafic pour détecter les indicateurs d'Evooo1Bot. Mettre en place des contrôles de sécurité OT dédiés. | [https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html](https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html) |
| **CVE-2020-10987** | 9.8 | 79.81% | TRUE | Tenda AC1900 Router (modèle AC15) | n/a | Compromission complète du routeur Tenda AC15 avec exécution de code arbitraire. Le routeur compromis devient un nœud du botnet Evooo1Bot avec capacités DDoS, brute-force SSH, sniffing de credentials et proxy SOCKS5. Risque d'interception du trafic réseau. | Active | Appliquer les correctifs firmware Tenda disponibles. Désactiver l'administration à distance. Changer les mots de passe par défaut. Surveiller le trafic pour détecter les indicateurs d'Evooo1Bot. Remplacer les routeurs en fin de vie. | [https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html](https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html) |
| **CVE-2021-46422** | N/A | 94.63% | FALSE | Telesquare SDT-CW3B1 | n/a | Compromission de l'équipement Telesquare SDT-CW3B1 avec injection de commandes. L'équipement compromis devient un nœud du botnet Evooo1Bot avec capacités DDoS, brute-force SSH, sniffing de credentials et proxy SOCKS5. | Active | Appliquer les correctifs firmware Telesquare disponibles. Restreindre l'accès réseau aux équipements. Surveiller le trafic pour détecter les indicateurs d'Evooo1Bot. Remplacer les équipements en fin de vie. | [https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html](https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html) |
| **CVE-2022-37055** | 9.8 | 55.53% | TRUE | Routeurs D-Link (modèles multiples) | n/a | Compromission complète des routeurs D-Link via dépassement de tampon. Les routeurs compromis deviennent des nœuds du botnet Evooo1Bot avec capacités DDoS, brute-force SSH, sniffing de credentials et proxy SOCKS5. Risque d'interception et de manipulation du trafic réseau. | Active | Appliquer les correctifs firmware D-Link disponibles. Désactiver l'administration à distance. Changer les mots de passe par défaut. Surveiller le trafic pour détecter les indicateurs d'Evooo1Bot. Remplacer les routeurs en fin de vie ne recevant plus de correctifs. | [https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html](https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html) |
| **CVE-2024-29269** | 8.8 | 5.85% | FALSE | tlr-2005ksh_firmware | n/a | Compromission de l'équipement Telesquare TLR-2005KSH avec injection de commandes. L'équipement compromis devient un nœud du botnet Evooo1Bot avec capacités DDoS, brute-force SSH, sniffing de credentials et proxy SOCKS5. | Active | Appliquer les correctifs firmware Telesquare disponibles. Restreindre l'accès réseau aux équipements. Surveiller le trafic pour détecter les indicateurs d'Evooo1Bot. Remplacer les équipements en fin de vie. | [https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html](https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html) |
| **CVE-2025-10123** | 6.9 | 4.40% | FALSE | DIR-823X | CWE-77 Command Injection | Compromission du routeur D-Link DIR-823X avec injection de commandes. Le routeur compromis devient un nœud du botnet Evooo1Bot avec capacités DDoS, brute-force SSH, sniffing de credentials et proxy SOCKS5. Risque d'interception du trafic réseau. | Active | Appliquer les correctifs firmware D-Link disponibles. Désactiver l'administration à distance. Changer les mots de passe par défaut. Surveiller le trafic pour détecter les indicateurs d'Evooo1Bot. Remplacer les routeurs en fin de vie. | [https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html](https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html) |
| **CVE-2025-55583** | 9.8 | 6.48% | FALSE | D-Link DIR-868L B1 | n/a | Compromission du routeur D-Link DIR-868L B1 avec injection de commandes. Le routeur compromis devient un nœud du botnet Evooo1Bot avec capacités DDoS, brute-force SSH, sniffing de credentials et proxy SOCKS5. Risque d'interception du trafic réseau et de mouvement latéral. | Active | Appliquer les correctifs firmware D-Link disponibles. Désactiver l'administration à distance. Changer les mots de passe par défaut. Surveiller le trafic pour détecter les indicateurs d'Evooo1Bot. Remplacer les routeurs en fin de vie. | [https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html](https://securityaffairs.com/197434/malware/new-mirai-based-evooo1bot-botnet-targets-linux-devices.html) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="stopransomware-advisory-conjoint-fbicisahhs-sur-le-ransomware-medusa-mise-a-jour-aout-2026"></div>

## #StopRansomware : Advisory conjoint FBI/CISA/HHS sur le ransomware Medusa (mise à jour août 2026)

### Résumé

Le FBI, la CISA et le HHS publient une mise à jour de leur advisory conjoint #StopRansomware (AA25-071A) sur le ransomware Medusa, variant RaaS identifié depuis juin 2021. Cette mise à jour du 18 août 2026 intègre les résultats d'enquêtes FBI jusqu'en avril 2026. Medusa a impacté plus de 500 victimes dans des secteurs d'infrastructure critique (santé, éducation, juridique, assurance, technologie, manufacturing). Le modèle RaaS inclut des initial access brokers rémunérés entre 100 USD et 1 million USD. Medusa utilise un modèle de double-extortion (chiffrement + menace de publication). L'accès initial se fait par phishing et exploitation de CVE non patchées (CVE-2024-1709 ScreenConnect, CVE-2023-48788 Fortinet EMS, CVE-2025-10035 Fortra GoAnywhere, CVE-2026-1731 BeyondTrust). Les acteurs opèrent opportunistiquement, exploitant les vulnérabilités dans les 24h suivant leur annonce. Les TTPs incluent l'utilisation d'outils LOTL (PowerShell, certutil, WMI), d'outils RMM légitimes pour le mouvement latéral, de Ligolo-ng/Cloudflared/Nezha/MeshAgent pour le C2, de Mimikatz et comsvcs.dll pour le dump LSASS, de Rclone pour l'exfiltration, et de PDQ Deploy/BigFix/PsExec pour le déploiement de l'encrypteur gaze.exe. L'encrypteur chiffre en AES-256 avec extension .medusa, termine les services de backup/sécurité/BDD, supprime les shadow copies et éteint les VMs. Des indices de triple-extortion ont été observés (un acteur Medusa distinct réclamant un second paiement après rançon initiale).

---

### Analyse opérationnelle

L'advisory fournit une liste exhaustive d'IOCs (IPs, hashes, domaines) et un mapping MITRE ATT&CK complet. Pour les équipes SOC : (1) Intégrer les IOCs IP dans les SIEM/EDR/pare-feu — attention, certaines IPs peuvent être légitimes (VPN Mullvad/ExpressVPN), investigation requise avant blocage. (2) Déployer des règles de détection pour les commandes Medusa documentées en annexe (certutil urlcache, PowerShell -exec bypass -enc, obfuscation par découpage de chaînes, PsExec avec scripts batch spécifiques). (3) Surveiller les domaines Interactsh (oast[.]site/pro/fun) utilisés pour la vérification d'exploitation OOB. (4) Détecter le dump LSASS via comsvcs.dll (Minidump) en plus de Mimikatz classique. (5) Surveiller les exclusions Windows Defender, particulièrement sur l'ensemble du C: drive. (6) Détecter Rclone renommé (lsp.exe/ngconf.txt) et les transferts via rdpclip.exe. (7) Alerte sur l'installation de Nezha, MeshAgent, Ligolo-ng, Cloudflared, GSocket. (8) Surveiller les modifications de Default Domain Policy (Enabled, Enforced). (9) Détecter l'utilisation de vssadmin pour vol de ntds.dit. (10) Surveiller l'utilisation de CrackMapExec/NetExec. L'advisory recommande d'utiliser l'outil CISA Eviction Strategies Tool (Playbook-NG + COUN7ER) pour l'éviction post-compromission. Les équipes doivent valider leurs contrôles de sécurité contre les techniques ATT&CK documentées.

---

### Implications stratégiques

Medusa représente une menace persistante et opportuniste avec plus de 500 victimes depuis 2021, ciblant particulièrement le secteur santé (HPH). Le recours à des IABs rémunérés jusqu'à 1M USD illustre la professionnalisation de l'écosystème RaaS. La capacité d'exploiter des CVE dans les 24h suivant leur annonce — voire avant la divulgation publique — souligne l'urgence du patch management sur les systèmes exposés à Internet. L'ajout du HHS comme co-auteur reflète l'impact spécifique sur le secteur de la santé, où les incidents ransomware peuvent affecter la sécurité des patients. Les indices de triple-extortion ou de dysfonctionnement opérationnel interne (acteur distinct réclamant un second paiement) suggèrent une cohésion limitée au sein du groupe, ce qui complique les négociations et augmente le risque pour les victimes même après paiement. L'utilisation d'outils RMM légitimes et de techniques LOTL rend la détection difficile pour les organisations ne disposant pas d'une visibilité EDR adéquate. Les secteurs santé, manufacturing et gouvernement doivent prioriser la segmentation réseau, les sauvegardes immuables et le durcissement des politiques Active Directory.

---

### Recommandations

* Patcher en priorité les CVE exploités par Medusa : CVE-2024-1709, CVE-2023-48788, CVE-2025-10035, CVE-2026-1731
* Segmenter le réseau pour limiter le mouvement latéral depuis les machines initialement compromises
* Maintenir des sauvegardes hors ligne, immuables et chiffrées couvrant toute l'infrastructure
* Implémenter une MFA résistante au phishing (FIDO2) pour VPN, webmail et comptes critiques
* Auditer les comptes administrateur et appliquer le principe de moindre privilège
* Surveiller et alerter sur l'installation d'outils RMM non autorisés
* Filtrer le trafic réseau pour empêcher les origines inconnues d'accéder aux services distants internes
* Désactiver les ports inutilisés et restreindre l'exécution de scripts en ligne de commande
* Utiliser l'outil CISA Eviction Strategies Tool pour préparer des plans d'éviction
* Signaler tout incident au FBI/IC3 ou CISA, indépendamment de la décision de payer ou non la rançon

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire à jour des actifs, des comptes privilégiés et des services RMM installés (AnyDesk, Atera, ConnectWise, SimpleHelp, Splashtop, etc.)
* Implémenter une segmentation réseau pour limiter le mouvement latéral depuis les machines initialement compromises
* S'assurer que les sauvegardes sont hors ligne, immuables et chiffrées, couvrant l'ensemble de l'infrastructure
* Appliquer les correctifs sur les CVE exploités par Medusa : CVE-2024-1709 (ScreenConnect), CVE-2023-48788 (Fortinet EMS), CVE-2025-10035 (Fortra GoAnywhere), CVE-2026-1731 (BeyondTrust)
* Déployer des règles de détection Sigma pour les commandes Medusa listées en annexe de l'advisory (certutil, PowerShell obfusqué, PsExec, openrdp.bat, etc.)
* Configurer l'EDR pour alerter sur les exclusions Windows Defender et l'utilisation de certutil pour le transfert de fichiers
* Mettre en place une MFA résistante au phishing (FIDO2) pour VPN, webmail et comptes critiques
* Préparer des playbooks d'isolation réseau et de révocation de sessions pour les comptés compromis

#### Phase 2 — Détection et analyse

* Surveiller les requêtes HTTP vers les domaines Interactsh (oast[.]site, oast[.]pro, oast[.]fun) indiquant une vérification d'exploitation
* Détecter l'exécution de PowerShell avec -exec bypass -enc, -nop -w hidden, ou des chaînes obfusquées par découpage (DownloadFile slicé)
* Surveiller l'utilisation de certutil.exe pour le téléchargement de fichiers (certutil -f urlcache)
* Détecter le dump LSASS via comsvcs.dll (Minidump) ou Mimikatz (mimilib.dll, kiwissp.log)
* Alimenter les SIEM avec les IOCs IP et hashes fournis dans l'advisory (Table 1 et Table 2)
* Surveiller les créations de comptes domaine inattendus et les modifications de Default Domain Policy
* Détecter l'utilisation de Rclone renommé (lsp.exe / ngconf.txt) et les transferts RDP via rdpclip.exe
* Surveiller l'installation de Nezha, MeshAgent, Ligolo-ng, Cloudflared, GSocket sur les hôtes
* Détecter les règles de pare-feu autorisant RDP (port 3389) créées via netsh advfirewall
* Surveiller l'utilisation de CrackMapExec/NetExec pour l'énumération d'hôtes
* Détecter la création de Volume Shadow Copy via vssadmin suivie de la copie de ntds.dit, system et security

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les hôtes compromis du réseau (quarantaine ou mise hors ligne)
* Révoquer et réinitialiser tous les comptes administrateur locaux, comptes de service et comptes admin domaine
* Supprimer les outils C2 : SimpleHelp, Nezha, Cloudflared, Ligolo, MeshAgent et verrouiller l'accès aux outils RMM légitimes
* Patcher la CVE d'accès initial et supprimer toute persistance sur la machine d'entrée (reverse shells, credentials portail web)
* Utiliser l'outil CISA Eviction Strategies Tool (Playbook-NG + COUN7ER) pour élaborer un plan d'éviction systématique
* Désactiver et réactiver Windows Defender de manière contrôlée après élimination des exclusions malveillantes
* Bloquer les adresses IP IOC au niveau des pare-feu et proxies
* Vérifier l'intégrité des contrôleurs de domaine et restaurer les GPO modifiées
* Surveiller le site de fuite Medusa (.onion) pour vérifier si l'organisation apparaît

#### Phase 4 — Activités post-incident

* Conduire une analyse forensique complète pour déterminer le périmètre exact de l'intrusion et la timeline
* Vérifier qu'aucun outil Medusa résiduel ne subsiste (gaze.exe, Rclone, scripts batch, web shells PHP)
* Restaurer les systèmes à partir de sauvegardes hors ligne vérifiées et immuables
* Effectuer un audit complet d'Active Directory : comptes créés, GPO modifiées, délégations Kerberos
* Renforcer les politiques de mots de passe selon les standards NIST (mots de passe longs, pas de rotation fréquente)
* Implémenter le filtrage du trafic réseau pour empêcher les origines inconnues d'accéder aux services distants internes
* Documenter les leçons apprises et mettre à jour les playbooks IR avec les TTPs Medusa observés
* Signaler l'incident au FBI/IC3 et/ou CISA, incluant logs, notes de rançon, communications, wallets Bitcoin
* Tester les contrôles de sécurité contre les techniques ATT&CK documentées dans l'advisory

#### Phase 5 — Threat Hunting (proactif)

* Chercher les traces d'Interactsh (oast[.]site/pro/fun) dans les logs proxy et DNS
* Rechercher les commandes Medusa spécifiques listées en annexe : certutil urlcache, PowerShell obfusqué, PsExec avec openrdp.bat/coba.bat/zam.bat/duooff.bat
* Chasser les exclusions Windows Defender sur l'ensemble du C: drive ou des dossiers spécifiques
* Rechercher les fichiers gaze.exe, gaze.py, lsp.exe, ngconf.txt sur tous les systèmes
* Identifier les sessions RMM non autorisées (SimpleHelp, AnyDesk, Atera, ConnectWise, eHorus, N-able, Splashtop)
* Rechercher les modifications de registre LSA (Security Packages avec mimilib) et les fichiers kiwissp.log
* Chercher les connexions WebSocket/TCP sortantes vers les IPs IOC sur ports 443/4444
* Rechercher l'utilisation de vssadmin pour créer des shadow copies suivie de copies de ntds.dit
* Identifier le trafic exfiltration anormal via Rclone (renommé) ou rdpclip.exe
* Vérifier la présence de web shells PHP (file_save.php) sur les serveurs web

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| IP | `143.244.47[.]89` | High |
| IP | `143.110.243[.]154` | High |
| IP | `167.88.166[.]173` | High |
| IP | `185.238.231[.]16` | High |
| IP | `23.234.89[.]195` | High |
| IP | `146.70.172[.]247` | High |
| IP | `155.2.215[.]71` | High |
| IP | `23.234.106[.]242` | High |
| IP | `37.19.21[.]180` | High |
| IP | `155.2.215[.]69` | High |
| IP | `185.238.231[.]98` | High |
| IP | `37.221.66[.]239` | High |
| IP | `185.135.86[.]185` | High |
| IP | `83.138.53[.]139` | High |
| IP | `185.238.231[.]4` | High |
| IP | `185.238.231[.]77` | High |
| IP | `185.238.231[.]85` | High |
| IP | `85.155.186[.]121` | High |
| IP | `45.61.150[.]9` | High |
| IP | `94.156.67[.]145` | High |
| IP | `23.234.93[.]112` | High |
| DOMAIN | `erp.ranasons[.]com` | High |
| DOMAIN | `oast[.]site` | Medium |
| DOMAIN | `oast[.]pro` | Medium |
| DOMAIN | `oast[.]fun` | Medium |
| DOMAIN | `tcatcher[.]com` | Medium |
| HASH_SHA256 | `2C7F328FEEB94608AAAF99EC70CB0323` | High |
| HASH_SHA256 | `D796259C44BE852327623FD2E40C47F2` | High |
| HASH_SHA256 | `4D0B6E3C9C33550A005E41663A1977CB` | High |
| HASH_SHA256 | `eb05429d25fc57b476428cdb0a134b2f` | High |
| HASH_SHA256 | `44370f5c977e415981febf7dbb87a85c` | High |
| HASH_SHA256 | `8f11d9067da087cb4185fa804caac2df` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing - Méthode principale d'accès initial via vol d'identifiants |
| **T1190** | Exploitation d'applications publiques - Exploitation de CVE non patchées (CVE-2024-1709, CVE-2023-48788, CVE-2025-10035, CVE-2026-1731) |
| **T1059.001** | PowerShell - Énumération réseau, transfert de fichiers, obfuscation |
| **T1059.003** | Windows Command Shell - Énumération système et réseau |
| **T1046** | Network Service Discovery - Énumération réseau via Advanced IP Scanner, SoftPerfect Network Scanner |
| **T1083** | File and Directory Discovery - Énumération du système de fichiers |
| **T1105** | Ingress Tool Transfer - Transfert de fichiers via PowerShell, cmd.exe, certutil |
| **T1047** | WMI - Interrogation d'informations système |
| **T1070.003** | Clear Command History - Suppression de l'historique PowerShell |
| **T1027.013** | Encrypted/Encoded File - Exécution de commandes base64 encodées |
| **T1027** | Obfuscated Files or Information - Obfuscation de chaînes par découpage et concaténation |
| **T1685** | Disable or Modify Tools - Kill/delete EDR via pilotes vulnérables signés |
| **T1564.012** | Hide Artifacts: File/Path Exclusions - Placement d'outils dans dossiers exclus Windows Defender |
| **T1006** | Direct Volume Access - Vol de ntds.dit via Volume Shadow Copy |
| **T1003.001** | LSASS Memory - Dump LSASS via Mimikatz, comsvcs.dll (Minidump) |
| **T1558** | Steal or Forge Kerberos Tickets - Création de tickets Kerberos forgés à partir de ntds.dit volé |
| **T1072** | Software Deployment Tools - Déploiement de l'encrypteur via PDQ Deploy, BigFix |
| **T1021.001** | Remote Desktop Protocol - Mouvement latéral via RDP |
| **T1569.002** | Service Execution - PsExec pour déploiement et exécution distante |
| **T1675** | ESXi Administration Command - Changement de mots de passe root sur machines Linux/ESXi |
| **T1567.002** | Exfiltration to Cloud Storage - Exfiltration via Rclone vers serveurs C2 |
| **T1071.001** | Web Protocols - Communication C2 sur port 443 (reverse/bind shell TLS) |
| **T1219** | Remote Access Tools - Utilisation d'outils RMM légitimes (AnyDesk, Atera, ConnectWise, eHorus, N-able, BeyondTrust, SimpleHelp, Splashtop) |
| **T1136.002** | Create Account: Domain Account - Création de comptes domaine pour persistance |
| **T1484.001** | Group Policy Modification - Modification de la Default Domain Policy pour outrepasser les GPO restrictives |
| **T1486** | Data Encrypted for Impact - Chiffrement AES-256 avec extension .medusa |
| **T1490** | Inhibit System Recovery - Suppression des shadow copies |
| **T1657** | Financial Theft - Extortion financière via ransom en Bitcoin |
| **T1529** | System Shutdown/Reboot - Extinction et chiffrement des machines virtuelles |
| **T1489** | Service Stop - Arrêt des services de backup, sécurité, bases de données, communication |
| **T1016** | System Network Configuration Discovery - ipconfig /all |
| **T1082** | System Information Discovery - systeminfo |
| **T1033** | System Owner/User Discovery - query user |
| **T1049** | System Network Connections Discovery - netstat -a |
| **T1069.002** | Permission Groups Discovery: Domain Groups - net group "domain admins" /domain |
| **T1135** | Network Share Discovery - net share |

---

### Sources

* [https://www.ic3.gov/CSA/2026/260818.pdf](https://www.ic3.gov/CSA/2026/260818.pdf)


---

<div id="mirage2fa-phaas-aitm-ciblant-les-sessions-microsoft-365-avec-plus-de-4-000-victimes-aux-etats-unis"></div>

## Mirage2FA : PhaaS AiTM ciblant les sessions Microsoft 365 avec plus de 4 000 victimes aux États-Unis

### Résumé

ANY.RUN publie une analyse détaillée de Mirage2FA, un toolkit Phishing-as-a-Service (PhaaS) conçu pour voler les identifiants et sessions authentifiées Microsoft 365 via des attaques Adversary-in-the-Middle (AiTM). Le kit est attribué à l'opérateur « LinX Coders » (marqueurs LINX*, channel LinXcoded, bots linxlogsss). L'activité a été observée de septembre 2024 à juillet 2026. Le dataset ANY.RUN recense 9 426 adresses email ciblées, 4 532 potentiellement compromises (taux de ~48%), 3 518 domaines d'organisations distincts touchés, et 9 332 événements de compromission (4 561 vols de cookies de session, 3 044 compromissions mot de passe/2FA, 1 339 logins SSO). 63,7% des victimes identifiées sont aux États-Unis (2 885 victimes), avec une activité dans 94 pays. Les secteurs les plus touchés : Technologies (19,2%), Manufacturing (11,1%), Éducation (9,9%), Conseil (8,3%). La livraison se fait via pièces jointes .htm/.xhtml/.svg, QR codes, et distribution à grande échelle via Amazon SES, avec des leures RH et 401(k). L'attaque se déroule entièrement dans le navigateur : HTML smuggling, récupération d'un loader distant via le pattern /xls/*.js, proxy AiTM sur WebSocket pour relayer l'authentification en temps réel, vol des cookies de session et identifiants. Le C2 principal est 185.174.100[.]224 (AS-Colocrossing). Les domaines C2 incluent *.cheacker[.]store et *.volatilesour[.]store. L'obfuscation évolue du plain-text vers XOR+Base64+eval (clé 0xAD), hex decoders, et obfuscator.io. 33,3% des logins réussis proviennent de mobiles où l'inspection des URLs est plus difficile.

---

### Analyse opérationnelle

Pour les équipes SOC/IT : (1) Mirage2FA contourne la MFA conventionnelle via AiTM — la détection ne peut reposer uniquement sur la validation MFA. (2) Détection comportementale prioritaire : surveiller les requêtes GET /[a-z]{3}/xls/[a-z0-9]+(?:c2v|cpt)?\.js dans les logs proxy, les requêtes DNS avec sous-domaines encodés Base64 (email), et les connexions WebSocket sortantes vers des hôtes inconnus après exécution JS. (3) Bloquer les pièces jointes .htm/.xhtml/.svg au niveau email gateway. (4) Les IOCs statiques (domaines/IPs) tournent rapidement — privilégier la détection comportementale (patterns /xls/*.js, marqueurs LINX*, clé XOR 0xAD, loader a1p2i.js). (5) En cas de compromission confirmée, la réponse doit aller au-delà du reset mot de passe : révoquer toutes les sessions et tokens dans Entra ID, auditer les règles de transfert mail, vérifier les grants OAuth, investiguer l'activité post-compromission. (6) Surveiller particulièrement les utilisateurs mobiles (33,3% des compromissions réussies). (7) Intégrer les domaines de phishing IOC dans les SIEM, firewalls et EDR. (8) L'infrastructure de test de l'opérateur (IPs avec placeholder LINXCODERSEMAIL) peut être utilisée pour l'attribution et le tracking futur.

---

### Implications stratégiques

Mirage2FA illustre l'évolution du phishing vers le vol de sessions plutôt que le simple vol d'identifiants, rendant la MFA conventionnelle (OTP, push) insuffisante. Avec un taux de compromission potentiel de 48% et plus de 4 000 victimes, l'impact business est significatif : accès aux emails corporate, données sensibles, applications SSO connectées, potentiel d'usurpation d'identité et de fraude aux fournisseurs. La concentration sur les États-Unis (63,7%) et les secteurs Technologie/Manufacturing suggère un ciblage délibéré des organisations à forte dépendance M365. L'utilisation d'Amazon SES pour la distribution à grande échelle souligne l'abus de services légitimes pour contourner les filtres email. L'absence de malware binaire (attaque 100% navigateur) complique la détection par les EDR traditionnels. La rotation rapide de l'infrastructure (domaines, IPs) impose une approche de détection comportementale plutôt qu'IOC-statique. Les organisations doivent migrer vers une MFA résistante au phishing (FIDO2/passkeys), réduire la durée de vie des sessions, et implémenter Continuous Access Evaluation dans Entra ID. Le secteur santé (5,4% des victimes) est particulièrement vulnérable compte tenu des implications de confidentialité (HIPAA) en cas d'accès aux emails contenant des PHI.

---

### Recommandations

* Migrer les utilisateurs à haut risque vers FIDO2/WebAuthn ou passkeys (MFA résistante au phishing)
* Bloquer ou mettre en quarantaine les pièces jointes .htm, .xhtml et .svg au niveau de la passerelle email
* Réduire la durée de vie des sessions dans Microsoft Entra ID et activer Continuous Access Evaluation (CAE)
* Déployer des règles de détection pour les patterns /xls/*.js, marqueurs LINX*, et connexions WebSocket suspectes
* En cas de compromission : révoquer toutes les sessions/tokens, pas seulement reset mot de passe
* Surveiller les règles de transfert de courrier et les grants OAuth après un incident de phishing
* Renforcer la sensibilisation sur les QR codes phishing et les emails Amazon SES non sollicités
* Utiliser ANY.RUN Threat Intelligence Lookup pour pivoter depuis un IOC vers l'infrastructure liée
* Surveiller particulièrement les connexions M365 depuis des appareils mobiles
* Intégrer les domaines de phishing IOC dans les SIEM, EDR, firewalls et passerelles email

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Bloquer ou mettre en quarantaine les pièces jointes .htm, .xhtml et .svg au niveau de la passerelle email
* Migrer les utilisateurs à haut risque (administrateurs, dirigeants, finance) vers une MFA résistante au phishing (FIDO2/WebAuthn, passkeys)
* Configurer Microsoft Entra ID pour réduire la durée de vie des sessions et activer Continuous Access Evaluation (CAE)
* Déployer des règles de détection pour les requêtes GET /[a-z]{3}/xls/[a-z0-9]+(?:c2v|cpt)?\.js dans les logs proxy
* Préparer un playbook de réponse aux incidents de vol de session : révocation de sessions, audit des règles de transfert mail, vérification des grants OAuth
* Former les utilisateurs à la détection des QR codes suspects et des emails provenant d'Amazon SES non sollicités
* Mettre en place une surveillance des connexions WebSocket sortantes vers des hôtes inconnus

#### Phase 2 — Détection et analyse

* Surveiller les requêtes DNS où un sous-domaine encodé en Base64 correspond à une adresse email (pattern Mirage2FA)
* Détecter les requêtes HTTP GET vers les patterns /xls/*.js sur les domaines *.cheacker[.]store et *.volatilesour[.]store
* Alimenter les SIEM avec les domaines de phishing IOC fournis dans le rapport
* Détecter les pièces jointes HTML contenant atob(...).map(x => x.charCodeAt(0) ^ 173) suivi de eval() (clé XOR 0xAD)
* Surveiller les connexions WebSocket sortantes vers des hôtes inconnus peu après l'exécution de JavaScript dans le navigateur
* Détecter les documents SVG contenant des éléments <script> inline avec redirection window.location
* Surveiller les tokens LINX* (LINXB64EMAIL, LINXEMAIL, LINXCODERSEMAIL) dans le trafic réseau
* Détecter les connexions M365 provenant d'IPs inhabituelles ou de pays inhabituels après un événement de phishing
* Surveiller les emails transitant par Amazon SES contenant des pièces jointes browser-executable

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement toutes les sessions et tokens actifs de l'utilisateur compromis dans Microsoft Entra ID (pas seulement reset mot de passe)
* Vérifier et supprimer les règles de transfert de courrier malveillantes ajoutées par l'attaquant
* Auditer et révoquer les grants OAuth suspects accordés au compte compromis
* Examiner l'activité effectuée via l'identité compromise : accès email, fichiers SharePoint/OneDrive, applications SSO connectées
* Bloquer les domaines de phishing identifiés au niveau des proxies et passerelles email
* Isoler le poste de l'utilisateur si des artefacts malveillants ont été exécutés localement
* Notifier les contacts internes et externes potentiels d'usurpation d'identité
* Forcer la ré-authentification de tous les services connectés via SSO

#### Phase 4 — Activités post-incident

* Conduire une investigation complète de l'activité post-compromission : emails lus/envoyés, fichiers consultés/téléchargés, modifications de configuration
* Vérifier l'absence de persistance via règles de transport Exchange ou applications Entra ID malveillantes
* Documenter la chaîne d'attaque complète et les IOCs associés pour enrichir la base de threat intelligence
* Mettre à jour les règles de détection email et proxy avec les nouveaux patterns identifiés
* Évaluer l'impact business : données exposées, communications interceptées, potentiel d'usurpation de fournisseurs
* Renforcer la formation anti-phishing avec des exemples Mirage2FA (leures RH, 401(k), QR codes)
* Mettre en place des alertes proactives sur les futures variantes du kit (évolution des marqueurs LINX)

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs proxy les requêtes correspondant au pattern /???/xls/?????*.js$ sur tous les domaines
* Chercher les tokens LINX* dans les logs web, DNS et email (LINXB64EMAIL, LINXEMAIL, LINXCODERSEMAIL, #LINXMASKEMAIL, #LINXRANDSTRING, linxz)
* Identifier les utilisateurs ayant reçu des pièces jointes .htm/.xhtml/.svg et corréler avec les connexions M365 ultérieures
* Rechercher les connexions WebSocket sortantes vers des hôtes non répertoriés dans les logs proxy
* Chercher les domaines DNS où le label de sous-domaine est une chaîne Base64 décodable en adresse email
* Identifier les sessions M365 actives anormales (IP inhabituelle, user-agent inhabituel, géolocalisation impossible)
* Rechercher les règles de transfert de courrier créées récemment par des comptes non administrateurs
* Vérifier les grants OAuth récents pour des applications non reconnues
* Corréler les soumissions de phishing avec les données ANY.RUN Threat Intelligence Lookup pour identifier des campagnes plus larges

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| IP | `185.174.100[.]224` | High |
| IP | `209.205.192[.]6` | Medium |
| IP | `141.95.59[.]233` | Medium |
| IP | `185.174.100[.]20` | Medium |
| IP | `181.214.165[.]173` | Medium |
| IP | `84.239.43[.]155` | Medium |
| IP | `83.147.53[.]130` | Medium |
| IP | `146.70.195[.]104` | Medium |
| IP | `139.28.36[.]38` | Medium |
| IP | `185.174.100[.]76` | Medium |
| IP | `98.144.204[.]109` | Low |
| IP | `98.93.13[.]101` | Low |
| DOMAIN | `user.cheacker[.]store` | High |
| DOMAIN | `hvr.volatilesour[.]store` | High |
| DOMAIN | `ver.bandhiem[.]com` | High |
| DOMAIN | `pynutech[.]store` | High |
| DOMAIN | `adp.pslcertlive[.]site` | High |
| DOMAIN | `ans.rsxbenefits[.]com` | High |
| DOMAIN | `ari.vslbertlive[.]info` | High |
| DOMAIN | `ars.greebys[.]com` | High |
| DOMAIN | `asvbtech[.]store` | High |
| DOMAIN | `avsbtech[.]store` | High |
| DOMAIN | `bezdelz[.]store` | High |
| DOMAIN | `bns.baseasix[.]com` | High |
| DOMAIN | `bsf.allmetreod[.]com` | High |
| DOMAIN | `bverster[.]store` | High |
| DOMAIN | `cureaveritax[.]store` | High |
| DOMAIN | `cvs.pcvgtech[.]online` | High |
| DOMAIN | `dezbelz[.]store` | High |
| DOMAIN | `dverster[.]store` | High |
| DOMAIN | `everster[.]store` | High |
| DOMAIN | `fureaveritax[.]store` | High |
| DOMAIN | `fverster[.]store` | High |
| DOMAIN | `gverster[.]store` | High |
| DOMAIN | `hverster[.]store` | High |
| DOMAIN | `hynutech[.]store` | High |
| DOMAIN | `iverster[.]store` | High |
| DOMAIN | `jverster[.]store` | High |
| DOMAIN | `mettsoll[.]com` | High |
| DOMAIN | `oectech[.]store` | High |
| DOMAIN | `pavetech[.]store` | High |
| DOMAIN | `pectech[.]store` | High |
| DOMAIN | `pezbelz[.]store` | High |
| DOMAIN | `pureaveritax[.]store` | High |
| DOMAIN | `pynutech[.]store` | High |
| DOMAIN | `sopbtech[.]store` | High |
| DOMAIN | `wectech[.]store` | High |
| DOMAIN | `zectech[.]store` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.001** | Spearphishing Attachment - Pièces jointes .htm/.xhtml/.svg malveillantes |
| **T1566.002** | Spearphishing Link - Liens de phishing et QR codes |
| **T1204.002** | User Execution: File - Ouverture de la pièce jointe par la victime |
| **T1027** | Obfuscated Files or Information - Obfuscation JavaScript XOR+Base64+eval, hex decoder, obfuscator.io |
| **T1027.006** | HTML Smuggling - HTML smuggling pour délivrer le stager dans le navigateur |
| **T1105** | Ingress Tool Transfer - Récupération du loader distant via /xls/*.js |
| **T1557** | Adversary-in-the-Middle - Proxy AiTM pour intercepter l'authentification M365 en temps réel |
| **T1539** | Steal Web Session Cookie - Vol des cookies de session authentifiés |
| **T1071.001** | Web Protocols - Communication WebSocket avec le C2 pour le relay AiTM |

---

### Sources

* [https://any.run/cybersecurity-blog/mirage2fa-phishing-targets-us-companies/](https://any.run/cybersecurity-blog/mirage2fa-phishing-targets-us-companies/)


---

<div id="cyberattaque-massive-contre-la-csdd-lettone-vol-des-donnees-personnelles-de-12-million-de-personnes"></div>

## Cyberattaque massive contre la CSDD lettone : vol des données personnelles de 1,2 million de personnes

### Résumé

Dans la nuit du 8 août 2026, une cyberattaque ciblée contre la Direction de la Sécurité Routière de Lettonie (CSDD) a permis à des attaquants d'exploiter une vulnérabilité non corrigée dans un système d'information accessible via Internet. Les attaquants ont exfiltré les données de paiement historiques couvrant 18 ans (depuis 2008), affectant 1,2 million d'individus (soit environ deux tiers de la population lettone d'environ 1,8 million) et 200 000 entités légales. Les données volées comprennent : numéros d'identification personnelle ou d'immatriculation d'entreprise, noms et prénoms, montants et dates de paiement, numéros d'immatriculation de véhicules et adresses enregistrées. Aucune information bancaire ou coordonnée de contact (téléphone, email) n'a été compromise. Le Premier ministre Andris Kulbergs a évoqué la possibilité d'une attaque hybride menée par un État hostile. Le Président Edgars Rinkēvičs a qualifié la fuite de « menace significative pour la sécurité nationale » et demandé le départ de la direction de la CSDD. CERT.LV n'a été notifié que le 10 août, la CSDD n'utilisant pas ses services de supervision. L'enquête a révélé que plusieurs exigences réglementaires n'étaient pas respectées : absence de tests de pénétration et de MFA sur un système de Classe A.

---

### Analyse opérationnelle

L'attaque exploite une vulnérabilité non patchée sur un système exposé à Internet, soulignant l'importance critique de la gestion des vulnérabilités et de la surface d'attaque externe. Le délai de détection (attaque le 8 août, notification CERT.LV le 10 août) démontre une faille dans les processus de détection et de réponse incidentelle, aggravée par l'absence d'intégration de la CSDD aux services de supervision de CERT.LV. L'absence de MFA et de tests de pénétration sur un système de Classe A contrevient aux exigences réglementaires du Cabinet des Ministres. Les données volées (numéro d'identification personnelle, nom, plaque d'immatriculation, adresse, historique de paiements) constituent un matériel idéal pour des campagnes de social engineering hyper-personnalisées. Les équipes SOC doivent s'attendre à une vague de phishing et de fraude ciblant les citoyens lettons, avec des messages frauduleux imitant la CSDD avec un niveau de crédibilité sans précédent. Les organisations lettonnes doivent renforcer la détection des tentatives d'authentification abusant des données volées, notamment dans e-CSDD et les systèmes gouvernementaux associés.

---

### Implications stratégiques

Cette breach représente l'une des plus importantes fuites de données proportionnellement à la population d'un pays membre de l'UE. L'évocation d'une attaque hybride sponsorisée par un État s'inscrit dans le contexte géopolitique tendu des pays baltes face à la Russie. L'incident expose des lacunes structurelles : non-respect des exigences réglementaires de cybersécurité, absence de supervision obligatoire par CERT.LV, et délai de notification public inacceptable (10 jours entre l'attaque et l'information complète du public). Les décisions politiques prises (mandatory CERT.LV integration, centre national cyber 24/7, amendement des réglementations) pourraient servir de modèle pour d'autres pays baltes et européens. Le risque de réputation et de confiance institutionnelle est majeur, avec un impact direct sur la souveraineté numérique lettone. Les assureurs cyber et les régulateurs européens vont probablement durcir leurs exigences vis-à-vis des infrastructures critiques nationales.

---

### Recommandations

* Rendre obligatoire l'intégration de toute l'infrastructure critique aux services de supervision du CERT national
* Imposer des tests de pénétration réguliers et le déploiement de MFA sur tous les systèmes de Classe A
* Réduire le délai de notification publique en cas de breach massive à moins de 72 heures
* Lancer une campagne de sensibilisation nationale sur les risques de phishing personnalisé exploitant les données volées
* Établir un centre national de cybersécurité 24/7 comme annoncé par le Ministère de la Défense

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire complet des systèmes exposés à Internet et de leurs vulnérabilités
* Appliquer les exigences réglementaires : tests de pénétration obligatoires et MFA sur tous les systèmes de Classe A
* Intégrer tous les systèmes d'infrastructure critique aux services de CERT.LV pour supervision continue
* Définir un plan de communication de crise pour notification rapide du public en cas de fuite de données massives

#### Phase 2 — Détection et analyse

* Surveiller les accès anormaux aux bases de données de reçus de paiement et aux systèmes CSDD
* Corréler les logs d'authentification avec les plages horaires inhabituelles (attaque nocturne du week-end)
* Mettre en place des alertes sur les extractions massives de données depuis des systèmes gouvernementaux
* Détecter les tentatives d'authentification suspectes dans e-CSDD utilisant des données personnelles volées

#### Phase 3 — Confinement, éradication et récupération

* Isoler et bloquer les vecteurs d'accès identifiés dans le système d'information CSDD
* Révoquer toutes les sessions actives et forcer la réinitialisation des accès privilégiés
* Appliquer immédiatement les correctifs sur la vulnérabilité exploitée du système accessible via Internet
* Mettre en place une surveillance renforcée des tentatives de fraude utilisant les données volées (numéros d'identification personnels, plaques d'immatriculation, adresses)

#### Phase 4 — Activités post-incident

* Conduire une analyse de cause racine complète sur le délai de notification (attaque le 8 août, notification CERT.LV le 10 août, public informé le 18 août)
* Mettre en conformité les systèmes avec les exigences du Cabinet des Ministres (tests de pénétration, MFA)
* Rendre obligatoire l'intégration à CERT.LV pour toute l'infrastructure critique
* Établir un centre national de cybersécurité 24/7 comme décidé par le Ministère de la Défense
* Notifier l'Inspection des Données de l'État et mener une évaluation complète RGPD

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des indicateurs d'exfiltration de données similaires dans d'autres agences gouvernementales lettones
* Chasser des campagnes de phishing personnalisées exploitant les données volées (nom, numéro d'identification, plaque, adresse)
* Surveiller les tentatives d'authentification dans e-CSDD et autres systèmes gouvernementaux utilisant les données compromises
* Rechercher des connexions avec des acteurs de menace étatiques connus opérant contre les pays baltes

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploit Public-Facing Application |
| **T1078** | Valid Accounts |
| **T1566** | Phishing (risque d'utilisation des données volées pour campagnes de social engineering ultérieures) |

---

### Sources

* [https://mastodon.world/@G4Media/117118226779101503](https://mastodon.world/@G4Media/117118226779101503)
* [https://bnn-news.com/data-of-1-2-million-people-leaked-in-csdd-cyberattack-in-latvia-including-personal-id-numbers-and-addresses-282949](https://bnn-news.com/data-of-1-2-million-people-leaked-in-csdd-cyberattack-in-latvia-including-personal-id-numbers-and-addresses-282949)
* [https://eng.lsm.lv/article/society/crime/18.08.2026-data-of-12-million-people-breached-in-recent-csdd-cyberattack.a659333/](https://eng.lsm.lv/article/society/crime/18.08.2026-data-of-12-million-people-breached-in-recent-csdd-cyberattack.a659333/)


---

<div id="expel-lance-ruxie-ai-classification-automatique-du-phishing-benin-pour-liberer-le-soc"></div>

## Expel lance Ruxie AI : classification automatique du phishing bénin pour libérer le SOC

### Résumé

Expel a annoncé le 18 août 2026 un nouveau module d'IA appelé « Phishing Classification » (PC), intégré à sa plateforme Ruxie. Selon le rapport de threat intelligence d'Expel, les attaques basées sur l'identité (phishing, credential harvesting, social engineering) représentent près de 70% des incidents de sécurité investigués par leur SOC. Cependant, 95% des emails de phishing signalés par les utilisateurs s'avèrent être du bruit bénin (newsletters, alertes système, spam). Le modèle PC fonctionne en complément de l'Automated Marketing Engine (AME) déjà existant, qui avait réduit de 23% le volume de la file d'attente. PC élargit la détection aux emails bénins non marketing (notifications transactionnelles, alertes vendeurs) en utilisant un encodeur sémantique local combiné à des caractéristiques structurelles (résultats d'authentification, mismatches reply-to/return-path, attributs URL/domaine, pixels de tracking, sauts d'en-têtes) et la réputation historique du domaine expéditeur. Ensemble, AME et PC auto-clôturent près de 50% des soumissions utilisateur. Le modèle a été validé en shadow mode avec une précision de 99,85% et zéro menace malveillante manquée. PC s'exécute entièrement dans l'environnement sécurisé d'Expel, sans appel d'API tiers ni LLM génératif par message.

---

### Analyse opérationnelle

Cette annonce illustre une tendance majeure en SecOps : l'automatisation du triage de premier niveau pour réduire la fatigue des analystes et accélérer la réponse aux vraies menaces. Les équipes SOC peuvent s'inspirer de l'approche multi-couches d'Expel : (1) un moteur spécialisé pour les patterns marketing connus (AME), (2) un classifieur ML généraliste pour le bruit bénin restant (PC), (3) des règles de safety post-traitement indépendantes (domaines nouvellement enregistrés, sévérité élevée, simulations de phishing). Les critères structurels exploités (SPF/DKIM/DMARC, mismatches reply-to/return-path, pixels de tracking, sauts d'en-têtes) sont des signaux accessibles à tout SOC via les en-têtes email. L'approche privacy-first (pas d'API tierce, exécution locale) est un modèle pour les organisations soucieuses de la confidentialité des données de triage. Le principe d'explainability (explications lisibles par l'humain pour chaque auto-clôture) est essentiel pour maintenir la confiance des analystes et l'auditabilité.

---

### Implications stratégiques

L'industrialisation du triage phishing par IA reflète une maturation du marché MDR/MDR où la différenciation se fait sur l'efficacité opérationnelle plutôt que sur la couverture de détection seule. Avec 70% des incidents liés à l'identité, le phishing reste le vecteur initial dominant et la gestion de sa file d'attente est un enjeu business direct (coût analyste, time-to-respond, rétention talent). Les organisations qui n'automatisent pas le triage du bruit de fond phishing risquent un turnover SOC élevé et des délais de réponse dégradés sur les vraies menaces. La tendance privacy-first (pas de LLM génératif par message, exécution locale) répond aux inquiétudes réglementaires (RGPD, NIS2) sur l'envoi de données sensibles vers des API tierces. Les fournisseurs MDR qui n'offriront pas ce niveau d'automatisation perdront en compétitivité.

---

### Recommandations

* Évaluer le ratio bruit/menace dans votre file d'attente phishing signalé par les utilisateurs pour quantifier le gain potentiel d'automatisation
* Implémenter une approche multi-couches : règles déterministes pour le marketing connu, ML pour le bruit bénin restant, safety rules pour les signaux de risque élevé
* Prioriser l'explainability : chaque auto-clôture doit inclure une explication des facteurs de décision pour auditabilité
* Exécuter les modèles de classification dans un environnement isolé sans dépendance à des API LLM tierces pour protéger la confidentialité
* Valider tout modèle en shadow mode avec un seuil de précision > 99,8% et zéro menace manquée avant activation en production

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Définir une taxonomie claire des catégories d'emails signalés par les utilisateurs (phishing réel, marketing, transactionnel, spam bénin)
* Évaluer le volume et la composition de la file d'attente phishing pour quantifier le bruit de fond
* Identifier les critères structurels discriminants : résultats d'authentification (SPF/DKIM/DMARC), mismatch reply-to/return-path, attributs URL/domaine, pixels de tracking, sauts d'en-têtes
* Préparer un ensemble de données étiquetées par les analystes pour entraîner et valider un classifieur ML

#### Phase 2 — Détection et analyse

* Déployer le modèle de classification en mode shadow sur le trafic réel et comparer les verdicts avec les décisions des analystes
* Mesurer la précision (objectif > 99,8%), le taux de faux négatifs (zero malicious miss) et le taux d'auto-clôture
* Surveiller les soumissions contenant des domaines nouvellement enregistrés, des sévérités élevées ou des simulations de phishing – ces signaux doivent bypass l'auto-clôture
* Mettre en place des règles de sécurité post-traitement (safety veto) indépendantes du modèle ML

#### Phase 3 — Confinement, éradication et récupération

* Activer l'auto-clôture uniquement après validation en shadow mode et sign-off explicite du SOC
* Garantir que toute soumission auto-clôturée inclut une explication lisible par l'humain listant les facteurs de décision
* Permettre aux analystes de rouvrir en un clic toute soumission auto-clôturée
* Router explicitement les simulations de phishing et les pen-tests vers les analystes humains

#### Phase 4 — Activités post-incident

* Mesurer l'impact : réduction du volume de file d'attente, temps de triage, fatigue analyste, temps de résolution des vraies menaces
* Auditer périodiquement un échantillon d'auto-clôtures pour vérifier la précision continue du modèle
* Ajuster les seuils de confiance et les règles de safety veto en fonction des retours d'expérience
* Communiquer les gains opérationnels aux parties prenantes pour justifier l'investissement AI

#### Phase 5 — Threat Hunting (proactif)

* Analyser les soumissions qui bypassent l'auto-clôture pour identifier de nouvelles campagnes de phishing émergentes
* Corréler les emails signalés avec les indicateurs de compromission connus (domaines, URLs, hashes d'attachments)
* Surveiller l'évolution des tactiques de phishing contournant les classifieurs ML (texte polymorphe, obfuscation sémantique)
* Utiliser les données de classification pour cartographier les vecteurs d'attaque basés sur l'identité (70% des incidents)

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing - vecteur initial dominant (70% des incidents selon Expel) |
| **T1539** | Steal Web Session Cookie - risque associé au credential harvesting via phishing |

---

### Sources

* [https://expel.com/blog/new-ruxie-ai-power-up-phishing-classification/](https://expel.com/blog/new-ruxie-ai-power-up-phishing-classification/)


---

<div id="twinloot-nouveau-malware-python-exploitant-sharepoint-teams-et-edge-pour-vol-de-credentials-et-mouvement-lateral"></div>

## TWINLOOT : nouveau malware Python exploitant SharePoint, Teams et Edge pour vol de credentials et mouvement latéral

### Résumé

Les chercheurs d'Ontinue Cyber Defense Center ont découvert en juillet 2026 un implant Python modulaire et inédit, baptisé TWINLOOT, lors de l'investigation d'une campagne active. TWINLOOT est durci avec PyArmor et pèse 39 MB (bootstrap-fat[.]pyc). Son infrastructure C2 fonctionne entièrement à l'intérieur des services Microsoft de confiance : (1) SharePoint Online sert de dead drop pour le tasking via Microsoft Graph API, avec un polling toutes les 15 secondes ; (2) les serveurs TURN de Microsoft Teams relayent les sessions interactives de l'opérateur via WebRTC DataChannels (première utilisation in-the-wild de cette technique) ; (3) une instance headless du navigateur Edge de la victime envoie les requêtes Graph API via Chrome DevTools Protocol, rendant le trafic indissociable d'une activité Edge légitime. L'implant s'authentifie auprès d'un tenant Azure contrôlé par l'attaquant, pas celui de la victime, ce qui ne génère aucun événement d'audit dans les logs Entra ID de la cible. L'accès initial est obtenu via social engineering sur Microsoft Teams : l'attaquant se fait passer pour le support IT et persuade la victime d'exécuter une commande PowerShell téléchargeant une archive contenant le runtime Python et le payload. TWINLOOT affiche un faux écran de verrouillage Windows 10/11 peuplé des informations réelles du compte de la victime, capture chaque mot de passe saisi sans le valider, affiche un message d'erreur, puis exfiltre les credentials chiffrés vers SharePoint. Ces credentials sont exploités via un tunnel reverse SOCKS5 pour un mouvement latéral (RDP, SMB, WinRM). Une technique de persistance inédite in-the-wild, baptisée « Corrupting the Hive Mind », crée un hive NTUSER.MAN (mandatory profile) hors ligne sans privilèges administrateur ni événement de modification de registre, chargé par Windows au prochain logon en lieu et place du hive utilisateur standard.

---

### Analyse opérationnelle

TWINLOOT représente une évolution significative des techniques d'évasion C2 et de persistance. Pour les équipes SOC, les défis de détection sont multiples : (1) le trafic C2 se termine dans l'espace IP Microsoft, rendant le blocage par IP réputation inefficace ; (2) l'absence d'événements dans les logs Entra ID de la victime (authentification sur un tenant externe) crée un angle mort dans la télémétrie identity ; (3) l'utilisation d'Edge headless via DevTools Protocol fait apparaître le trafic comme un processus signé légitime ; (4) la persistance NTUSER.MAN échappe aux outils de scan de persistance standard qui surveillent les clés de registre. Les détections prioritaires à implémenter : surveillance des connexions SharePoint vers des tenants externes à l'organisation, détection des processus Edge en mode headless avec DevTools Protocol, alerte sur les fichiers NTUSER.MAN dans les profils utilisateurs, corrélation entre appels Teams externes et exécution PowerShell subséquente, surveillance des sessions WebRTC/TURN inhabituelles. La désactivation du mode headless et du remote debugging dans Edge via GPO casse le transport navigateur. La restriction de l'accès externe Teams limite le vecteur d'accès initial. Le déploiement de FIDO2/Passkeys élimine le risque de credential harvesting via fake lock screen.

---

### Implications stratégiques

TWINLOOT illustre l'accélération alarmante du gap entre recherche académique et exploitation malveillante : la technique de persistance NTUSER.MAN (publiée par Praetorian en janvier 2026) a été opérationnalisée en seulement 7 mois, et l'abus de Teams TURN (technique de relay) a atteint trois acteurs distincts en moins d'un an. Cette tendance impose aux organisations de suivre activement la recherche en offensive security et de préemptivement durcir leurs configurations. L'exploitation des services Microsoft de confiance comme infrastructure C2 pose un défi fondamental pour les architectures zero-trust : les défenseurs ne peuvent pas simplement bloquer le trafic vers Microsoft. Les fournisseurs de solutions de sécurité doivent développer des détections comportementales au-delà des signatures. L'absence de visibilité dans les logs Entra ID (tenant attaquant externe) souligne la nécessité d'une télémétrie endpoint complète (EDR) pour combler les angles morts identity. Les organisations très dépendantes de l'écosystème Microsoft 365 sont particulièrement exposées et doivent réévaluer leur posture de sécurité Teams/SharePoint.

---

### Recommandations

* Restreindre l'accès externe Microsoft Teams aux organisations explicitement approuvées
* Désactiver le mode headless et le remote debugging dans Edge via GPO sur tous les endpoints
* Déployer l'authentification FIDO2/Passkeys pour éliminer le risque de credential harvesting par fake lock screen
* Implémenter une détection des connexions SharePoint vers des tenants externes à l'organisation
* Surveiller la création de fichiers NTUSER.MAN dans les répertoires de profils utilisateurs
* Corréler les appels Teams externes avec les exécutions PowerShell subséquentes pour détecter l'accès initial
* Traiter tout runtime Python s'exécutant depuis un chemin user-writable comme suspect
* Révoquer systématiquement credentials et refresh tokens pour tout utilisateur ayant potentiellement rencontré le fake lock screen

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Restreindre l'accès externe Microsoft Teams aux organisations de confiance uniquement
* Désactiver le mode headless et le remote debugging dans Microsoft Edge via GPO
* Surveiller les runtimes Python s'exécutant depuis des chemins accessibles en écriture par l'utilisateur
* Déployer l'authentification phishing-resistant (FIDO2/Passkeys) pour éliminer le risque de credential harvesting via fake lock screen
* Former les utilisateurs à ne jamais exécuter de commandes PowerShell fournies lors d'appels Teams non sollicités

#### Phase 2 — Détection et analyse

* Détecter les endpoints se connectant à des tenants SharePoint en dehors de votre organisation Microsoft 365
* Surveiller le trafic vers Microsoft Graph API provenant de processus Edge headless (Chrome DevTools Protocol attaché)
* Corréler les sessions WebRTC/Teams TURN inhabituelles avec une activité de reverse proxy ou SOCKS5
* Détecter la création de fichiers NTUSER.MAN dans les répertoires de profils utilisateurs (technique de persistance sans admin)
* Surveiller les processus Python s'exécutant depuis des chemins user-writable avec des connexions réseau vers des IP Microsoft
* Alerte sur les affichages de fake lock screen : recherche de processus affichant des interfaces de verrouillage Windows en dehors du processus legitime LogonUI

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement l'endpoint compromis du réseau
* Révoquer tous les credentials et refresh tokens de l'utilisateur compromis (Entra ID, local AD)
* Bloquer le tenant Azure attaquant au niveau des contrôles d'accès Microsoft 365
* Désactiver l'accès externe Teams pour l'organisation si nécessaire
* Réinitialiser les mots de passe de tous les comptes ayant potentiellement saisi des credentials dans le fake lock screen
* Analyser le fichier NTUSER.MAN du profil utilisateur pour identifier les modifications de persistance

#### Phase 4 — Activités post-incident

* Conduire une analyse forensique complète : identifier l'étendue du mouvement latéral via SOCKS5/RDP/SMB/WinRM
* Vérifier les logs SharePoint et Graph API du tenant attaquant pour quantifier les données exfiltrées
* Auditer tous les systèmes accessibles via le tunnel SOCKS5 pour détecter une persistance secondaire
* Documenter la chaîne d'attaque complète pour partage avec la communauté CTI (techniques inédites : NTUSER.MAN, Teams TURN WebRTC DataChannels)
* Mettre à jour les règles de détection EDR et SIEM avec les nouveaux TTP identifiés

#### Phase 5 — Threat Hunting (proactif)

* Chasser les connexions SharePoint vers des tenants externes non approuvés dans toute l'organisation
* Rechercher les processus Edge lancés en mode headless avec DevTools Protocol activé (--remote-debugging-port)
* Identifier les fichiers NTUSER.MAN dans tous les profils utilisateurs (persistance sans admin, indétectable par les outils de scan de persistance standard)
* Corréler les appels Teams entrants d'organisations externes avec des exécutions PowerShell subséquentes
* Surveiller le trafic WebRTC/TURN inhabituel pouvant indiquer des tunnels C2 via Teams relay
* Rechercher des archives contenant un runtime Python embarqué et des fichiers .pyc compilés (pattern bootstrap-fat)

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| HASH_SHA256 | `Non publié (payload PyArmor-hardened, 39 MB, nom de fichier : bootstrap-fat[.]pyc)` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing via Microsoft Teams - impersonation IT support pour initial access |
| **T1059** | Command and Scripting Interpreter - PowerShell pour téléchargement initial du payload |
| **T1105** | Ingress Tool Transfer - téléchargement d'archive contenant runtime Python et payload compilé |
| **T1218** | System Binary Proxy Execution - utilisation headless d'Edge via Chrome DevTools Protocol pour requêtes Graph API |
| **T1110** | Brute Force / Credential Harvesting - fake lock screen capturant les mots de passe sans validation |
| **T1071** | Application Layer Protocol - C2 via SharePoint Online (Graph API) et Teams TURN (WebRTC DataChannels) |
| **T1098** | Account Manipulation - utilisation des credentials volés pour mouvement latéral via SOCKS5 |
| **T1547** | Boot or Logon Autostart Execution - persistance via NTUSER.MAN mandatory profile hive (nouvelle technique, sans privilèges admin) |
| **T1021** | Remote Services - RDP, SMB, WinRM via reverse SOCKS5 tunnel pour mouvement latéral |
| **T1572** | Protocol Tunneling - reverse SOCKS5 tunnel via Teams TURN infrastructure |

---

### Sources

* [https://hackread.com/twinloot-malware-steals-windows-passwords-lock-screen/](https://hackread.com/twinloot-malware-steals-windows-passwords-lock-screen/)
* [https://www.csoonline.com/article/4210973/new-malware-turns-microsoft-cloud-into-its-control-center.html](https://www.csoonline.com/article/4210973/new-malware-turns-microsoft-cloud-into-its-control-center.html)
* [https://thehackernews.com/2026/08/twinloot-abuses-sharepoint-and-teams-to.html](https://thehackernews.com/2026/08/twinloot-abuses-sharepoint-and-teams-to.html)
* [https://expertinsights.com/news/implant-marks-first-use-of-admin-free-windows-persistence](https://expertinsights.com/news/implant-marks-first-use-of-admin-free-windows-persistence)


---

<div id="vulncheck-1-335-cve-suivies-209-critiques-7-non-patchees-xss-path-traversal-et-sqli-dominent"></div>

## VulnCheck : 1 335 CVE suivies, 209 critiques, 7% non patchées – XSS, path traversal et SQLi dominent

### Résumé

Un dossier de sécurité publié sur Valters IT Hub rapporte les statistiques de VulnCheck au 18 août 2026 : 1 335 CVE sont suivies, avec un score CVSS moyen de 7,09. Parmi celles-ci, 209 sont classées critiques et environ 7% restent non patchées. Aucune de ces CVE n'est pour l'instant référencée dans le catalogue CISA KEV (Known Exploited Vulnerabilities), ce qui signifie qu'aucune exploitation active n'a été confirmée à ce jour. Le Trust Score attribué à VulnCheck est de niveau B. Les catégories de vulnérabilités les plus représentées sont les failles XSS (Cross-Site Scripting), les path traversal et les injections SQL (SQLi).

---

### Analyse opérationnelle

Les équipes SOC et IT doivent corréler ces 1 335 CVE avec leur inventaire d'actifs pour identifier les systèmes exposés. Les 209 CVE critiques constituent la priorité de patching immédiate, en particulier pour les systèmes exposés à Internet. Les 7% de CVE non patchées représentent une dette technique à adresser via un plan de remédiation structuré. L'absence actuelle d'exploitation active (non listées dans CISA KEV) offre une fenêtre de remédiation, mais les catégories dominantes (XSS, path traversal, SQLi) sont des vecteurs classiques d'accès initial et d'exfiltration de données. Les équipes doivent s'assurer que les règles WAF couvrent ces patterns d'exploitation et que les logs applicatifs sont monitorés pour détecter des tentatives d'exploitation. Le suivi du passage de ces CVE dans le catalogue CISA KEV doit être automatisé pour réajuster la priorisation en temps réel.

---

### Implications stratégiques

La persistance des catégories XSS, path traversal et SQLi en tête des vulnérabilités indique que les pratiques de développement sécurisé (DevSecOps) n'ont pas encore suffisamment intégré ces contrôles fondamentaux. Le Trust Score B de VulnCheck suggère une source fiable mais perfectible, à croiser avec d'autres sources (NVD, MITRE, éditeurs). Le volume de 1 335 CVE suivies sur un seul fournisseur illustre la pression croissante sur les équipes de gestion des vulnérabilités et justifie l'investissement dans l'automatisation du patching et du virtual patching. L'absence d'exploitation active actuelle ne doit pas créer de faux sentiment de sécurité : le délai moyen entre la publication d'une CVE et son exploitation active se réduit continuellement.

---

### Recommandations

* Corréler les 209 CVE critiques avec l'inventaire d'actifs et prioriser le patching des systèmes exposés à Internet
* Mettre en place un suivi automatisé du catalogue CISA KEV pour détecter l'ajout de ces CVE et réajuster la priorisation
* Renforcer les règles WAF pour les patterns XSS, path traversal et SQLi en attendant le déploiement des correctifs
* Établir un plan de remédiation contraignant pour les 7% de CVE non patchées avec échéances définies
* Intégrer des contrôles SAST/DAST dans le pipeline CI/CD pour réduire l'introduction de vulnérabilités XSS, path traversal et SQLi

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire complet des actifs et de leurs versions logicielles pour corrélation avec les CVE VulnCheck
* S'abonner aux flux VulnCheck et CISA KEV pour prioriser les correctifs
* Définir une matrice de priorisation basée sur le score CVSS, l'exploitabilité et l'exposition Internet

#### Phase 2 — Détection et analyse

* Corréler les 209 CVE critiques avec l'inventaire des actifs pour identifier les systèmes exposés
* Surveiller les tentatives d'exploitation des vulnérabilités XSS, path traversal et SQLi dans les logs WAF et applicatifs
* Mettre en place des alertes sur les 7% de CVE non patchés présents dans l'environnement

#### Phase 3 — Confinement, éradication et récupération

* Appliquer des correctifs virtuels (virtual patching) via WAF pour les CVE critiques non encore patchées
* Isoler ou restreindre l'accès aux systèmes exposés portant des vulnérabilités critiques non corrigées
* Bloquer les patterns d'exploitation XSS, path traversal et SQLi au niveau du WAF

#### Phase 4 — Activités post-incident

* Établir un plan de remédiation pour les 7% de CVE non patchés avec échéances contraignantes
* Mettre à jour la politique de gestion des vulnérabilités pour réduire le délai de patching des CVE critiques
* Conduire un audit des pratiques de développement sécurisé pour les catégories dominantes (XSS, path traversal, SQLi)

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des indicateurs d'exploitation des CVE critiques dans les logs historiques (web, applicatifs, EDR)
* Chasser les tentatives de path traversal et SQLi non bloquées par le WAF
* Surveiller l'apparition des CVE VulnCheck dans le catalogue CISA KEV pour réévaluer la priorisation

---

### Sources

* [https://mastodon.social/@hugovalters/117118097798127618](https://mastodon.social/@hugovalters/117118097798127618)
* [https://www.valtersit.com/vendors/vulncheck/](https://www.valtersit.com/vendors/vulncheck/)


---

<div id="macsync-stealer-rotation-de-linfrastructure-c2-et-analyse-dun-nouveau-loader-zsh"></div>

## MacSync Stealer : rotation de l'infrastructure C2 et analyse d'un nouveau loader zsh

### Résumé

Le 5 mai 2026, le déploiement Jamf Protect d'un client RST Cloud a bloqué un téléchargement depuis jacksonvillemma[.]com sur un endpoint macOS géré. L'analyse a révélé un nouveau sample Stage 2 du stealer MacSync (SHA-256 : 2728a7d444cd65550f652a8c66eaced0fe6d0389161f86393ab73da8f446a362), un infostealer macOS proposé en malware-as-a-service et opéré sous l'alias forum « mentalpositive ». Le certificat TLS du nouveau C2 a été émis 24 heures seulement après la divulgation publique du C2 précédent (glowmedaesthetics[.]com) par le SANS ISC le 1er mai 2026. L'analyse a identifié une clé API statique (5190ef1733183a0dc63fb623357f56d6) partagée across quatre domaines C2 distincts, suggérant une infrastructure parallèle plutôt qu'une rotation séquentielle. Un pivot via any.run TI Lookup sur les patterns URI a permis d'identifier 11 domaines candidats supplémentaires, avec des soumissions s'étalant du 19 février au 8 mai 2026. Le loader exfiltre le mot de passe du compte macOS de la victive en clair via le paramètre &pwd= sur l'URL /dynamic, ce qui sera enregistré dans les logs de proxy web. La chaîne d'infection comprend trois stages : livraison HTTP du loader zsh, décodage base64+gzip et exécution via eval, puis collecte AppleScript dynamique avec exfiltration chunkée (10 MiB) vers /gate.

---

### Analyse opérationnelle

L'infrastructure C2 de MacSync pivote en moins de 24h après disclosure publique, rendant les listes de blocage statiques rapidement obsolètes. La clé API statique (5190ef1733183a0dc63fb623357f56d6) constitue un pivot de détection fiable car elle ne rotate pas entre les builds, contrairement au token hex par-build. Les équipes SOC doivent impérativement : (1) chasser le triplet de protocole C2 (/curl/, /dynamic?txd=, /gate?buildtxd=) sur tous les hostnames dans les logs proxy, pas seulement les domaines connus ; (2) surveiller la création de /tmp/osalogging.zip qui est l'artefact de staging d'exfiltration (éphémère, supprimé après upload réussi) ; (3) détecter les processus zsh combinant base64 -D, gunzip et eval ; (4) alerter sur le User-Agent tronqué Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 qui est une anomalie (macOS Catalina obsolète + absence des tokens Chrome/Safari). Les proxies web qui capturent les URI complètes enregistreront le mot de passe macOS en clair dans le paramètre &pwd= — il faut s'assurer que ces logs sont protégés et purgés appropriément. Les règles YARA communautaires existantes (MAL_OSX_MacSync_Stage2_Wrapper_Dec25, MAL_OBFUSC_Shell_Dropper_Dec25) couvrent ce sample sans modification.

---

### Implications stratégiques

MacSync illustre la maturation de l'écosystème MaaS macOS : le produit a évolué d'un stealer basique (Mac.c, juillet 2025) vers une architecture multi-stage Loader-as-a-Service avec rotation rapide d'infrastructure, suggérant un opérateur sophistiqué et bien financé. Le ciblage de plus de 80 extensions de wallets cryptocurrency et 20 applications desktop wallet indique une focalisation sur les actifs crypto à haute valeur. La rapidité de rotation C2 (24h après disclosure) démontre une veille active de l'opérateur sur la recherche en sécurité. L'existence d'infrastructures C2 parallèles (plusieurs domaines actifs simultanément) suggère soit un opérateur unique gérant plusieurs campagnes, soit plusieurs acheteurs du même MaaS. Les organisations avec des parcs macOS significatifs, particulièrement dans les secteurs technologie et finance, doivent considérer macOS comme une surface d'attaque à part entière et non comme un environnement intrinsèquement sûr.

---

### Recommandations

* Bloquer les domaines C2 confirmés et candidats au niveau DNS/proxy
* Déployer les règles YARA communautaires MAL_OSX_MacSync_Stage2_Wrapper_Dec25 et MAL_OBFUSC_Shell_Dropper_Dec25
* Chasser les patterns URI /dynamic?txd= et /gate?buildtxd= dans les logs proxy rétrospectifs depuis février 2026
* Surveiller la création de /tmp/osalogging.zip sur les endpoints macOS
* Sensibiliser les utilisateurs aux fausses boîtes de dialogue de mot de passe macOS pendant l'installation de logiciels
* Mettre en place une détection pour le User-Agent tronqué AppleWebKit/537.36 sans tokens Chrome/Safari suivants

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer Jamf Protect ou un EDR macOS équivalent sur tous les endpoints gérés
* Mettre en place des règles YARA : MAL_OSX_MacSync_Stage2_Wrapper_Dec25 (Rhys Downing) et MAL_OBFUSC_Shell_Dropper_Dec25 (Nextron Valhalla)
* Configurer la collecte des logs de proxy web avec capture complète des URI (query strings incluses) pour détecter le paramètre &pwd= en clair
* Surveiller la création du fichier /tmp/osalogging.zip via telemetry endpoint
* Préparer des règles de détection pour les processus zsh invoquant base64 -D, gunzip et eval simultanément

#### Phase 2 — Détection et analyse

* Rechercher dans les logs DNS/proxy les domaines C2 confirmés : jacksonvillemma[.]com, focusgroovy[.]com, houstongaragedoorinstallers[.]com, mansfieldpediatrics[.]com, glowmedaesthetics[.]com
* Chasser le triplet de protocole C2 (/curl/<64-hex>, /dynamic?txd=, /gate?buildtxd=) sur tous les hostnames dans les logs proxy
* Détecter le User-Agent tronqué : Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (sans les tokens Chrome/Safari suivants)
* Surveiller les invocations osascript recevant des données piped depuis curl
* Détecter la création de /tmp/osalogging.zip (artefact éphémère, chasse rétrospective sur les événements de création de fichiers)
* Rechercher l'en-tête HTTP api-key: 5190ef1733183a0dc63fb623357f56d6 dans les logs proxy

#### Phase 3 — Confinement, éradication et récupération

* Bloquer immédiatement les domaines C2 confirmés et candidats au niveau DNS/proxy/firewall
* Isoler les endpoints macOS compromis du réseau
* Révoquer les sessions et tokens d'authentification potentiellement compromis (Keychain, navigateurs, wallets crypto)
* Forcer la réinitialisation du mot de passe du compte macOS sur les machines affectées (le mot de passe est exfiltré en clair)
* Analyser le fichier /tmp/osalogging.zip si encore présent pour déterminer l'étendue de l'exfiltration
* Vérifier l'intégrité des wallets cryptocurrency et des credentials Keychain

#### Phase 4 — Activités post-incident

* Réaliser une analyse forensique complète de l'endpoint pour identifier l' vecteur d'entrée initial (malvertising ClickFix, ChatGPT lure, etc.)
* Mettre à jour les règles de détection avec les nouveaux IOCs et patterns identifiés
* Documenter la chaîne d'attaque complète (Stage 1 → Stage 2 → Stage 3) pour enrichir la base de connaissances CTI
* Vérifier que les credentials volés n'ont pas été utilisés pour des accès ultérieurs (VPN, SSO, comptes cloud)
* Renforcer la sensibilisation des utilisateurs sur les fausses boîtes de dialogue de mot de passe macOS

#### Phase 5 — Threat Hunting (proactif)

* Pivoter sur les patterns URI (/dynamic?txd=, /gate?buildtxd=) via any.run TI Lookup ou plateformes similaires pour découvrir de nouveaux domaines C2
* Surveiller l'émission de certificats TLS Let's Encrypt pour des domaines au profil suspect (rotation rapide après disclosure publique)
* Chasser les 11 domaines candidats identifiés (pressureulcerlawyer[.]com, lumenagnet[.]com, etc.) dans les logs rétrospectifs depuis février 2026
* Rechercher des campagnes de malvertising Google imitant Homebrew ou d'autres outils macOS légitimes
* Surveiller les forums criminels pour de nouvelles variantes ou rebranding du MaaS MacSync

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `jacksonvillemma[.]com` | High |
| DOMAIN | `focusgroovy[.]com` | High |
| DOMAIN | `houstongaragedoorinstallers[.]com` | High |
| DOMAIN | `mansfieldpediatrics[.]com` | High |
| DOMAIN | `glowmedaesthetics[.]com` | High |
| DOMAIN | `pressureulcerlawyer[.]com` | Medium |
| DOMAIN | `lumenagnet[.]com` | Medium |
| DOMAIN | `harveylewisinsuranceagency[.]com` | Medium |
| DOMAIN | `blzaeagent[.]com` | Medium |
| DOMAIN | `helxiagent[.]com` | Medium |
| DOMAIN | `nailscanai[.]com` | Medium |
| DOMAIN | `numericagent[.]com` | Medium |
| DOMAIN | `wechatstablecoin[.]com` | Medium |
| DOMAIN | `lalandscapelighting[.]com` | Medium |
| DOMAIN | `tintingsd[.]com` | Medium |
| URL | `hxxp://jacksonvillemma[.]com/curl/7980485fb1e0b1b1d6307a92b5750c7055bc53b662005cbaa662ac634984363d` | High |
| URL | `hxxp://jacksonvillemma[.]com/dynamic?txd=7980485fb1e0b1b1d6307a92b5750c7055bc53b662005cbaa662ac634984363d` | High |
| URL | `hxxp://jacksonvillemma[.]com/gate?buildtxd=7980485fb1e0b1b1d6307a92b5750c7055bc53b662005cbaa662ac634984363d` | High |
| HASH_SHA256 | `2728a7d444cd65550f652a8c66eaced0fe6d0389161f86393ab73da8f446a362` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1140** | Deobfuscate/Decode files or information - base64 -D \| gunzip decoding of embedded payload |
| **T1059.004** | Unix Shell - eval execution of decoded zsh payload |
| **T1071.001** | Web Protocols - HTTP C2 communication via /dynamic and /gate endpoints |
| **T1041** | Exfiltration Over C2 Channel - chunked PUT uploads of /tmp/osalogging.zip to /gate endpoint |
| **T1555** | Credentials from Password Stores - Keychain credential theft via AppleScript collection routine |

---

### Sources

* [https://www.rstcloud.com/macsync-stealer-c2-infrastructure-rotation/](https://www.rstcloud.com/macsync-stealer-c2-infrastructure-rotation/)
* [https://otx.alienvault.com/pulse/6a84aadc256eec05c0dafa57](https://otx.alienvault.com/pulse/6a84aadc256eec05c0dafa57)


---

<div id="medusa-ransomware-advisory-cisafbihhs-mis-a-jour-plus-de-500-victimes-et-nouvelles-tactiques"></div>

## Medusa Ransomware : advisory CISA/FBI/HHS mis à jour — plus de 500 victimes et nouvelles tactiques

### Résumé

Le 18 août 2026, le FBI, la CISA et le HHS ont publié une mise à jour de l'advisory #StopRansomware sur le groupe Medusa, un ransomware-as-a-service (RaaS) identifié depuis juin 2021. Le nombre de victimes est passé de plus de 300 (mars 2025) à plus de 500 (avril 2026), touchant les secteurs de la santé, éducation, juridique, assurance, technologie et manufacture. L'advisory mis à jour révèle que les acteurs Medusa exploitent de nouvelles vulnérabilités : Fortra GoAnywhere CVE-2025-10035 et BeyondTrust CVE-2026-1731, parfois dans les 24h suivant l'annonce publique, et jusqu'à une semaine avant la divulgation publique. Les acteurs utilisent Interactsh (oast[.]site, oast[.]pro, oast[.]fun) pour vérifier le succès de l'exploitation via des requêtes OOB. Medusa recrute des initial access brokers (IABs) sur les forums criminels, avec des paiements de 100$ à 1M$. Le modèle de double-extortion inclut un site .onion avec compte à rebours, et des victimes peuvent payer 10 000$ pour ajouter un jour au timer. L'advisory note également un potentiel schéma de triple-extortion où un second acteur Medusa contacte la victime après paiement pour réclamer une seconde fois.

---

### Analyse opérationnelle

L'advisory met à jour plusieurs éléments critiques pour les équipes SOC : (1) deux nouvelles CVE exploitées (GoAnywhere CVE-2025-10035, BeyondTrust CVE-2026-1731) à ajouter aux règles de détection d'exploitation ; (2) l'utilisation d'Interactsh pour la vérification OOB — les domaines oast[.]site/pro/fun doivent être bloqués et surveillés comme indicateurs d'exploitation active ; (3) la rapidité d'exploitation (24h après annonce CVE, voire avant disclosure publique) signifie que les fenêtres de patching sont extrêmement réduites ; (4) le recours aux IABs implique que la détection doit couvrir non seulement l'exploitation initiale mais aussi l'utilisation de credentials valides ; (5) l'utilisation d'outils légitimes et living-off-the-land rend la détection comportementale essentielle. Les équipes doivent prioriser le patching des produits listés (ScreenConnect, Fortinet EMS, GoAnywhere, BeyondTrust) et surveiller la création de comptes, l'installation de logiciels RMM, et les mouvements latéraux via RDP. Le potentiel triple-extortion doit être anticipé dans la négociation de rançon.

---

### Implications stratégiques

La trajectoire de Medusa (de 300 à 500+ victimes en 13 mois) démontre la rentabilité croissante du modèle RaaS avec recours aux IABs. L'exploitation de N-days dans les 24h suivant l'annonce publique — et potentiellement avant disclosure — suggère un accès à des exploits privés ou une veille CVE extrêmement agressive. Le ciblage récurrent du secteur healthcare (HPH) souligne la vulnérabilité des organisations de santé face aux ransomwares. Le schéma de triple-extortion potentiel indique une possible fragmentation opérationnelle au sein du groupe, créant un risque accru pour les victimes même après paiement. Le département d'État américain offre 10M$ pour des informations liant Medusa à un gouvernement étranger, suggérant des préoccupations géopolitiques sur l'attribution. Les organisations doivent intégrer le risque de triple-extortion dans leurs processus de réponse aux incidents et de décision de paiement de rançon.

---

### Recommandations

* Patcher immédiatement les produits vulnérables listés dans l'advisory (ScreenConnect, Fortinet EMS, GoAnywhere, BeyondTrust)
* Bloquer et surveiller les domaines Interactsh : oast[.]site, oast[.]pro, oast[.]fun
* Surveiller la création de nouveaux comptes utilisateurs et l'installation de logiciels RMM non autorisés
* Mettre en place une détection comportementale pour les techniques living-off-the-land
* Préparer un playbook de réponse incluant le scénario de triple-extortion
* Consulter et implémenter les mitigations détaillées dans l'advisory CISA AA25-071A

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire à jour des actifs exposés à internet et de leur statut de patching
* Surveiller les annonces CVE et prioriser le patching des produits listés dans l'advisory (ScreenConnect, Fortinet EMS, GoAnywhere, BeyondTrust)
* Déployer une détection pour les requêtes vers les domaines Interactsh (oast[.]site, oast[.]pro, oast[.]fun) indiquant une vérification d'exploitation OOB
* Mettre en place une surveillance des comptes utilisateurs nouvellement créés (technique de persistence de Medusa)
* Configurer des alertes sur l'installation de logiciels RMM non autorisés (AnyDesk, TeamViewer, etc.)
* Préparer des playbooks de réponse ransomware avec focus sur le modèle double-extortion

#### Phase 2 — Détection et analyse

* Détecter les requêtes HTTP vers oast[.]site, oast[.]pro, oast[.]fun (Interactsh - vérification d'exploitation par les acteurs Medusa)
* Surveiller les connexions RDP et l'utilisation d'outils RMM pour le mouvement latéral
* Détecter la création de nouveaux comptes utilisateurs par des comptes de service ou des comptes compromis
* Surveiller les accès aux partages de fichiers massifs et l'exfiltration de données (volume inhabituel)
* Alimenter le SIEM avec les IOCs et TTPs de l'advisory CISA/FBI/HHS mis à jour
* Détecter les communications Tox ou accès au site .onion de Medusa depuis le réseau d'entreprise

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les systèmes compromis du réseau
* Désactiver et réinitialiser les comptes compromis ou nouvellement créés par les attaquants
* Bloquer les communications vers les domaines Interactsh et les infrastructures C2 connues
* Couper l'accès externe aux services vulnérables non patchés (ScreenConnect, Fortinet EMS, GoAnywhere, BeyondTrust)
* Préserver les evidences forensiques avant tout nettoyage
* Évaluer l'étendue de l'exfiltration de données pour préparer la réponse à l'extorsion

#### Phase 4 — Activités post-incident

* Réaliser une analyse forensique complète pour déterminer le vecteur d'entrée initial et la chronologie de l'attaque
* Vérifier que tous les systèmes compromis ont été identifiés et nettoyés avant restauration
* Mettre à jour les règles de détection et les IOCs avec les findings de l'incident
* Évaluer les obligations de notification (RGPD, NIS2, sectorielles) en cas d'exfiltration de données
* Documenter l'incident pour partage avec les autorités (CISA, FBI) et les ISAC sectoriels
* Renforcer le programme de patching avec focus sur les N-days exploités par Medusa

#### Phase 5 — Threat Hunting (proactif)

* Chasser les signaux d'exploitation OOB via Interactsh dans les logs réseau rétrospectifs
* Rechercher des comptes créés récemment avec privilèges élevés qui pourraient être des comptes de persistence
* Surveiller les forums criminels pour les offres d'IAB ciblant des organisations similaires
* Identifier les endpoints exposés à internet avec des versions logicielles vulnérables aux CVE exploités par Medusa
* Rechercher des patterns de double/triple-extortion (contact par un second acteur Medusa après paiement)

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `oast[.]site` | High |
| DOMAIN | `oast[.]pro` | High |
| DOMAIN | `oast[.]fun` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing - primary method for stealing victim credentials |
| **T1190** | Exploit Public-Facing Application - exploitation of unpatched CVEs (ScreenConnect CVE-2024-1709, Fortinet CVE-2023-48788, GoAnywhere CVE-2025-10035, BeyondTrust CVE-2026-1731) |
| **T1657** | Financial Theft - double-extortion ransom demands via Tor live chat or Tox |
| **T1078** | Valid Accounts - use of credentials obtained from IABs |
| **T1219** | Remote Access Software - deployment of RMM tools for lateral movement |

---

### Sources

* [https://databreaches.net/2026/08/18/medusa-ransomware-tallies-hundreds-of-new-victims-says-updated-advisory-on-groups-tactics/](https://databreaches.net/2026/08/18/medusa-ransomware-tallies-hundreds-of-new-victims-says-updated-advisory-on-groups-tactics/)
* [https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a)
* [https://cyberscoop.com/medusa-ransomware-tactics-cisa-advisory/](https://cyberscoop.com/medusa-ransomware-tactics-cisa-advisory/)


---

<div id="thehatman-vente-de-donnees-azureentra-id-de-9-entreprises-dont-mcdonalds-vodafone-et-tcs"></div>

## TheHatman : vente de données Azure/Entra ID de 9 entreprises dont McDonald's, Vodafone et TCS

### Résumé

Entre le 31 juillet et le 16 août 2026, un acteur de menace identifié sous le pseudonyme « TheHatman » a publié sur un forum de cybercrime des données prétendument exfiltrées des environnements Microsoft Azure/Entra ID de 9 entreprises : McDonald's (1,7M+ enregistrements), TCS (800K+), Vodafone (425K+), HCLTech (250K+), IHG (185K+), Kyndryl (170K+), Gap (80K+), Hexaware (20K+) et Wyndham (9K+), totalisant environ 3,64 millions d'enregistrements selon les chiffres de l'attaquant. Les données incluent noms, IDs employés, emails professionnels, titres, départements, numéros de téléphone, adresses, comptes de service et comptes administrateur. La société de threat intelligence Hudson Rock a évalué les échantillons comme « d'authenticité élevée » au vu des domaines d'entreprise et des formats de directory Entra ID, sans toutefois confirmer le vecteur d'intrusion ou la période d'extraction. TCS, HCLTech et Gap ont publiquement nié toute compromission de leurs systèmes actuels, indiquant que les données semblent anciennes (plusieurs années). Aucune vulnérabilité zero-day d'Azure ou compromission de l'infrastructure cloud de Microsoft n'a été confirmée. Les hypothèses sur le vecteur initial incluent infostealer, phishing, password spray, MFA fatigue, ou applications tierces avec permissions excessives. Le compte TheHatman a rejoint le forum en mars 2026 avec 9 posts au total, ce qui ne permet pas de déterminer s'il a lui-même accédé aux environnements ou s'il revend des données obtenues par d'autres moyens.

---

### Analyse opérationnelle

Aucun IOC déterminé (IP source, App ID, User-Agent) n'a été publié, ce qui limite la corrélation directe. Les équipes SOC doivent se concentrer sur la détection d'énumération massive via Microsoft Graph API : (1) activer et configurer Microsoft Graph Activity Logs (requiert Entra ID P1/P2) avec transfert vers Log Analytics/Storage/Event Hubs ; (2) rechercher des volumes inhabituels de requêtes sur /users, /groups, /directoryRoles, /applications depuis des IPs, App IDs ou User-Agents anormaux ; (3) vérifier les sign-ins non-interactifs (service principals, managed identities) ; (4) surveiller les nouvelles inscriptions d'applications, consentements OAuth, ajout de credentials, changements de rôles. La conception par défaut d'Entra ID accorde aux membres normaux des permissions de lecture étendues sur le directory (énumération de tous les utilisateurs, contacts, groupes, rôles d'administration) — un seul compte compromis à faible privilège peut donc extraire l'annuaire complet. En cas d'infection infostealer suspectée, le changement de mot de passe seul est insuffisant : les session cookies et tokens volés permettent un accès persistant jusqu'à révocation. Les équipes doivent révoquer toutes les sessions et refresh tokens, isoler les endpoints infectés, et réinitialiser MFA depuis un appareil sûr.

---

### Implications stratégiques

Cet incident illustre le risque d'« attaque par identité » où la compromission d'un seul compte — même à faible privilège — permet l'exfiltration massive de données organisationnelles via les API légitimes de Microsoft Graph. La conception par défaut d'Entra ID, qui autorise une lecture large du directory aux membres normaux, constitue une surface d'attaque souvent sous-estimée. Les données d'annuaire (organigramme, noms, titres, relations hiérarchiques, comptes administrateur) sont directement exploitables pour des attaques BEC, fraude au président, et phishing ciblé. Les dénégations de TCS, HCLTech et Gap (données anciennes, pas de compromission actuelle) soulignent la difficulté d'attribution et la possibilité de revente de données historiques. L'absence de confirmation officielle de McDonald's, Vodafone, IHG, Kyndryl, Hexaware et Wyndham crée une zone d'incertitude. Les organisations doivent adopter une approche de minimisation des données dans Entra ID (ne pas synchroniser d'informations non nécessaires), restreindre les permissions des applications OAuth, et exiger une MFA phishing-resistant (FIDO2) pour les rôles administrateur via PIM.

---

### Recommandations

* Activer Microsoft Graph Activity Logs et surveiller les volumes inhabituels de requêtes d'énumération directory
* Révoquer sessions et refresh tokens pour les comptes suspectés compromis
* Implémenter MFA phishing-resistant (FIDO2/passkeys) pour tous les rôles administrateur via Entra ID PIM
* Inventorier et restreindre les applications OAuth avec permissions Directory.Read.All ou équivalent
* Minimiser les informations stockées dans Entra ID (téléphones, adresses, IDs employés, détails organisationnels)
* Sensibiliser les équipes finance/IT/helpdesk aux tentatives de BEC basées sur des données d'annuaire
* Surveiller les forums criminels pour de nouvelles publications de TheHatman

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Activer et configurer Microsoft Graph Activity Logs avec transfert vers Log Analytics, Storage ou Event Hubs
* Vérifier que les logs Entra ID (sign-in interactifs/non-interactifs, service principals, managed identities, audit logs) sont conservés avec une durée suffisante
* Mettre en place des alertes sur les volumes inhabituels de requêtes Microsoft Graph (users, groups, directory roles)
* Inventorier les applications OAuth avec permissions Directory.Read.All ou similaires
* Activer Entra ID Identity Protection et configurer les policies de risk
* Implémenter l'authentification phishing-resistant (FIDO2/passkeys) pour les rôles Global Administrator via PIM

#### Phase 2 — Détection et analyse

* Rechercher dans Microsoft Graph Activity Logs des volumes inhabituels de requêtes sur /users, /groups, /directoryRoles, /applications, /devices
* Corréler les requêtes Graph avec l'IP source, l'App ID, le User-Agent et le volume de réponses
* Vérifier les sign-ins non-interactifs (service principals, managed identities) pour des patterns anormaux
* Détecter les nouvelles inscriptions d'applications, consentements OAuth, ajout de credentials, changements de rôles d'administration
* Surveiller les modifications de règles de transfert de courrier et de méthodes d'authentification
* Vérifier Identity Protection pour les alertes de leaked credentials, password spray, anonymous IP, unfamiliar locations

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les nouveaux sign-ins pour les comptes suspectés compromis
* Révoquer toutes les sessions et refresh tokens via Entra ID
* Effectuer un changement de mot de passe et une ré-enrôlement MFA depuis un appareil sûr
* Isoler et investiguer les endpoints suspectés d'infection par infostealer
* Révoquer les permissions des applications OAuth suspectes ou excessives
* Désactiver les comptes de service non utilisés ou compromis
* Vérifier et révoquer les accès basés sur session cookies potentiellement volés

#### Phase 4 — Activités post-incident

* Réaliser une analyse forensique des endpoints infectés par infostealer pour identifier les credentials volés
* Mettre à jour les règles de détection avec les patterns d'énumération Graph observés
* Réviser et minimiser les informations stockées dans Entra ID (téléphones, adresses, IDs employés, infos organisationnelles)
* Auditer et nettoyer les comptes inactifs, départ, contacts inutiles
* Renforcer les procédures de vérification d'identité pour les demandes de reset MFA, changement de contact, transferts financiers
* Documenter l'incident pour les notifications réglementaires si applicable

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs Graph rétrospectifs des patterns d'énumération massive de directory depuis des IPs/App IDs inhabituels
* Surveiller les forums criminels pour de nouvelles publications de TheHatman ou ventes de données similaires
* Chasser les infections infostealer sur les endpoints via EDR (cookies de session, credentials browser)
* Identifier les applications avec des secrets long-terms ou des permissions excessives (Directory.Read.All)
* Rechercher des sign-ins depuis des IPs anonymes ou des locations inhabituelles sur les comptes administrateurs

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078** | Valid Accounts - use of compromised credentials to access Azure/Entra ID tenants |
| **T1528** | Steal Application Access Token - potential session cookie theft via infostealer |
| **T1119** | Automated Collection - bulk directory enumeration via Microsoft Graph API |
| **T1087** | Account Discovery - enumeration of users, groups, and admin roles in Entra ID |

---

### Sources

* [https://rocket-boys.co.jp/security-measures-lab/mcdonalds-azure-entra-id-unauthorized-access-data-sale/](https://rocket-boys.co.jp/security-measures-lab/mcdonalds-azure-entra-id-unauthorized-access-data-sale/)


---

<div id="clop-web-shell-java-sur-mesure-deploye-sur-les-serveurs-ptc-windchillflexplm-via-cve-2026-12569-43-organisations-visees-dont-shell-ge-et-philips"></div>

## Clop : web shell Java sur mesure déployé sur les serveurs PTC Windchill/FlexPLM via CVE-2026-12569 — 43 organisations visées dont Shell, GE et Philips

### Résumé

Le groupe d'extorsion Clop a exploité la vulnérabilité critique CVE-2026-12569 (RCE par validation d'entrée incorrecte) affectant les serveurs PTC Windchill et FlexPLM pour déployer un web shell Java sur mesure et exfiltrer des données. ReliaQuest a analysé le web shell et l'a attribué à Clop sur la base d'emails d'extorsion contenant des adresses utilisées sur le site de leak du groupe, d'en-têtes HTTP X-windchill-req précédemment observés, et de TTPs caractéristiques. Le web shell JSP importe directement des classes Windchill spécifiques (MethodContext, WTConnection, WTKeyStoreUtil) pour accéder à la base de données sous l'identité du service applicatif, déchiffrer les credentials stockés (mot de passe LDAP manager via WTKeyStoreUtil.decryptProperty()), énumérer les file vaults (tables ApplicationData, FVITEM, FVMOUNT, MasteredOnReplicaItem), et exfiltrer des fichiers. Le shell est contrôlé via l'en-tête HTTP X-windchill-req (8 caractères : 1 commande + 7 valeur fixe) et supporte 8 commandes : vol de secrets (S), mapping du file vault (L), énumération de répertoires (D), lecture de fichier (G), suppression de fichier (R), exécution de code Java additionnel (J), identification OS (O), et echo (E). Clop a publié 43 organisations sur son site de leak, dont Shell (89GB prétendument volés), GE et Philips. Philips a confirmé une tentative d'intrusion sur des serveurs internes, contenue sans impact client. Shell et GE ont reconnu enquêter sur un « incident potentiel ». PTC a commencé à publier des patches le 17 juin 2026. La CISA a ajouté CVE-2026-12569 au catalogue KEV avec obligation de patching sous 3 jours pour les agences fédérales. Le BSI allemand a émis une alerte urgente de nuit demandant aux clients PTC de patcher immédiatement. PTC indique que ses produits sont utilisés par plus de 30 000 entreprises dans l'aérospatiale, défense, automobile, industrie lourde, retail et technologies médicales.

---

### Analyse opérationnelle

Ce web shell n'est pas un shell générique mais un implant spécifiquement conçu pour Windchill, avec une connaissance détaillée des APIs internes, du schéma de base de données, du keystore et de la structure des file vaults. Les équipes SOC doivent : (1) identifier tous les serveurs Windchill/FlexPLM et vérifier l'application du patch CVE-2026-12569 ; (2) rechercher des fichiers JSP inhabituels dans les répertoires Windchill, particulièrement ceux contenant des références à X-windchill-req ; (3) surveiller les en-têtes HTTP X-windchill-req et X-windchill-prm dans les logs du reverse proxy/WAF ; (4) surveiller les requêtes de base de données sur les tables ApplicationData, FVITEM, FVMOUNT, MasteredOnReplicaItem sous l'identité du service applicatif — l'activité malveillante sera attribuée au service normal, limitant la valeur des alertes basées sur de nouveaux comptes ; (5) détecter la création du fichier flst.txt (output de la commande L) ; (6) surveiller l'utilisation de WTKeyStoreUtil.decryptProperty(). En cas de compromission confirmée, le mot de passe LDAP manager et tous les credentials Windchill doivent être considérés comme compromis et changés. La commande J (chargement de code Java additionnel via ZIP Base64 en mémoire) permet à l'attaquant d'étendre ses capacités sans laisser de fichiers sur disque.

---

### Implications stratégiques

L'attaque marque l'extension du playbook de Clop des produits de transfert de fichiers (Accellion, GoAnywhere, Serv-U, Cleo, MOVEit — 2 770+ organisations affectées) vers les logiciels PLM, cœur de la conception et du développement produit. Les données ciblées (plans, dessins, projets, installations) représentent de la propriété intellectuelle à haute valeur, avec des implications concurrentielles et de sécurité nationale potentielles (secteurs défense/aérospatiale). Le développement d'un web shell spécifique à une application démontre une investissement significatif dans la compréhension de la plateforme cible, suggérant soit une expertise interne au groupe, soit un accès à des outils/consultants spécialisés. L'ajout au catalogue KEV de la CISA et l'intervention nocturne du BSI allemand soulignent l'urgence perçue par les autorités. Le département d'État américain offre 10M$ pour des informations liant Clop à un gouvernement étranger. Avec 30 000+ entreprises utilisant PTC Windchill/FlexPLM, la surface d'attaque potentielle est considérable et d'autres victimes sont probables. Les organisations utilisant des logiciels enterprise exposés à internet doivent anticiper que Clop continuera à étendre ses cibles à de nouvelles catégories de produits.

---

### Recommandations

* Patcher immédiatement tous les serveurs PTC Windchill/FlexPLM contre CVE-2026-12569
* Rechercher des fichiers JSP inhabituels dans les répertoires Windchill, particulièrement ceux contenant X-windchill-req
* Surveiller les en-têtes HTTP X-windchill-req et X-windchill-prm dans les logs proxy/WAF
* En cas de compromission, changer le mot de passe LDAP manager et tous les credentials Windchill
* Isoler les instances Windchill/FlexPLM non patchées de l'exposition internet
* Surveiller les requêtes DB sur les tables ApplicationData, FVITEM, FVMOUNT, MasteredOnReplicaItem
* Consulter les advisories de ReliaQuest et Ransom-ISAC pour les IOCs supplémentaires
* Surveiller le catalogue KEV de CISA pour les produits enterprise utilisés par l'organisation

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Identifier tous les serveurs PTC Windchill et FlexPLM exposés à internet et vérifier l'application du patch CVE-2026-12569 (disponible depuis le 17 juin 2026)
* Surveiller le catalogue KEV de CISA pour les produits utilisés par l'organisation
* Préparer des règles de détection pour les fichiers JSP inhabituels dans les répertoires Windchill
* Mettre en place une surveillance des en-têtes HTTP X-windchill-req et X-windchill-prm dans les logs du reverse proxy/WAF
* Documenter l'emplacement des keystores, configurations LDAP et file vaults Windchill pour faciliter l'investigation
* Préparer des procédures de rotation des credentials LDAP manager et autres credentials Windchill

#### Phase 2 — Détection et analyse

* Rechercher des fichiers JSP inhabituels dans les répertoires Windchill, particulièrement ceux contenant des références à X-windchill-req
* Détecter les en-têtes HTTP X-windchill-req (8 caractères) et X-windchill-prm dans les logs proxy/WAF
* Surveiller les requêtes de base de données Windchill sous l'identité du service applicatif (MethodContext/WTConnection) sur les tables ApplicationData, FVITEM, FVMOUNT, MasteredOnReplicaItem
* Détecter la création de fichiers flst.txt (output de la commande L du web shell)
* Surveiller les accès aux fichiers de configuration LDAP et l'utilisation de WTKeyStoreUtil.decryptProperty()
* Détecter le chargement de code Java additionnel via Base64-encoded ZIP (command J)

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les serveurs Windchill/FlexPLM compromis du réseau
* Supprimer les web shells JSP identifiés
* Changer immédiatement le mot de passe LDAP manager et tous les credentials Windchill (considérés comme compromis)
* Révoquer toutes les sessions et tokens associés aux serveurs compromis
* Bloquer l'accès externe aux instances Windchill/FlexPLM non patchées
* Préserver les logs et evidences forensiques pour l'analyse
* Évaluer l'étendue de l'exfiltration (fichiers, credentials, données de configuration)

#### Phase 4 — Activités post-incident

* Réaliser une analyse forensique complète pour déterminer la chronologie et l'étendue de la compromission
* Vérifier que tous les web shells ont été supprimés et qu'aucun backdoor persistant n'est présent
* Mettre à jour les règles de détection avec les IOCs et patterns identifiés
* Évaluer l'impact sur la propriété intellectuelle (plans, dessins, projets) et les obligations de notification
* Documenter l'incident pour partage avec CISA, BSI et les ISAC sectoriels
* Renforcer le programme de patching avec focus sur les produits enterprise exposés à internet
* Réviser l'architecture pour minimiser l'exposition publique des serveurs Windchill/FlexPLM

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétrospectivement des fichiers JSP inhabituels dans tous les serveurs d'applications enterprise
* Chasser les en-têtes HTTP X-windchill-req dans les logs proxy/WAF depuis juin 2026
* Surveiller les autres produits enterprise (file transfer, ERP, PLM) pour des patterns d'attaque similaires (Clop a un historique : Accellion, GoAnywhere, Serv-U, Cleo, MOVEit)
* Identifier les serveurs Windchill/FlexPLM exposés à internet via des scans d'inventaire externes
* Rechercher des emails d'extorsion Clop dans les boîtes mail des employés (Ransom-ISAC a confirmé l'envoi d'emails d'extorsion à des centaines d'employés)
* Surveiller le site de leak Clop pour de nouvelles victimes potentielles dans l'organisation ou ses partenaires

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploit Public-Facing Application - exploitation of CVE-2026-12569 in PTC Windchill/FlexPLM |
| **T1505.003** | Server Software Component: Web Shell - deployment of custom JSP web shell on Windchill servers |
| **T1552** | Unsecured Credentials - decryption of LDAP manager password via WTKeyStoreUtil.decryptProperty() |
| **T1005** | Data from Local System - enumeration and exfiltration of files from Windchill file vaults |
| **T1213** | Data from Information Repositories - querying ApplicationData, FVITEM, FVMOUNT, MasteredOnReplicaItem tables |
| **T1059** | Command and Scripting Interpreter - execution of additional Java code via Base64-encoded ZIP (command J) |

---

### Sources

* [https://www.bleepingcomputer.com/news/security/clop-created-custom-web-shell-for-windchill-data-theft-attacks/](https://www.bleepingcomputer.com/news/security/clop-created-custom-web-shell-for-windchill-data-theft-attacks/)
* [https://rocket-boys.co.jp/security-measures-lab/clop-ransomware-ptc-vulnerability-cyberattack-organizations/](https://rocket-boys.co.jp/security-measures-lab/clop-ransomware-ptc-vulnerability-cyberattack-organizations/)


---

<div id="wallets-hardware-crypto-risques-accrus-apres-des-vols-de-donnees-personnelles-chez-les-prestataires-de-livraison"></div>

## Wallets hardware crypto : risques accrus après des vols de données personnelles chez les prestataires de livraison

### Résumé

Des violations de données chez deux entreprises de livraison utilisées par les fabricants de wallets hardware Trezor et SafePal ont exposé les données personnelles de milliers de clients (noms, adresses postales, emails, numéros de téléphone). Les wallets eux-mêmes n'ont pas été compromis, mais le vol d'informations de livraison expose les détenteurs de crypto à des attaques physiques (« wrench attacks ») visant à obtenir par la force le seed phrase stocké sur le wallet. CertiK a confirmé des dizaines d'attaques physiques en 2025, en hausse de 75% par rapport à l'année précédente, avec plus de 40M$ volés. Chainalysis estime les pertes 2026 à environ 30M$ à ce jour, via kidnappings et home invasions. Dans un incident séparé début août 2026, des hackers ont volé plus de 130M$ en cryptocurrency en exploitant une vulnérabilité dans le code de génération de seed phrases des wallets Coldcard de Coinkite, permettant de prédire les mots de passe générés hors ligne et de drainer les fonds directement depuis la blockchain. Trezor et SafePal ont averti leurs clients d'être vigilants face au phishing utilisant les données volées.

---

### Analyse opérationnelle

L'incident souligne que la sécurité des wallets hardware ne dépend pas uniquement du dispositif lui-même mais de l'écosystème de fournisseurs ayant accès aux données clients. Les équipes SOC/IT des fabricants de wallets doivent : (1) évaluer la posture de sécurité des prestataires logistiques ; (2) minimiser les données partagées avec les tiers (éviter adresses postales complètes, utiliser des relais) ; (3) surveiller les campagnes de phishing ciblé utilisant les données volées (noms + numéros de téléphone permettent un spear-phishing très personnalisé). Pour le cas Coldcard, la vulnérabilité dans le générateur de seed phrases (une ligne de code datant de 2021) démontre que même des dispositifs hors ligne peuvent être compromis si leur code de génération d'entropie est défectueux. Les équipes doivent auditer les firmwares des wallets hardware et surveiller les transactions blockchain suspectes depuis les wallets des clients affectés. La détection d'attaques physiques échappe au périmètre SOC traditionnel mais nécessite une coordination avec la sécurité physique et les forces de l'ordre.

---

### Implications stratégiques

L'incident révèle une faille structurelle dans l'écosystème crypto : la chaîne logistique physique des wallets hardware crée une base de données d'adresses de détenteurs de crypto à haute valeur nette, exploitable pour des attaques physiques. La hausse de 75% des wrench attacks en 2025 indique une professionnalisation de la criminalité physique ciblant le crypto. Le cas Coldcard (130M$ volés via prédiction de seed phrases) démontre que la sécurité des wallets hardware repose sur la qualité du code de génération d'entropie, et qu'une vulnérabilité logicielle peut compromettre des dispositifs censés être sécurisés par conception. Ces incidents pourraient éroder la confiance dans les wallets hardware comme solution de stockage de référence et pousser vers des solutions alternatives (multi-sig, custodians institutionnels). Les fabricants doivent reconsidérer leur chaîne logistique (anonymisation des adresses de livraison, chiffrement des données clients chez les tiers) et auditer rigoureusement leur code de génération de seed phrases. Les implications réglementaires sont potentiellement significatives (RGPD pour les données personnelles volées, obligations de notification).

---

### Recommandations

* Utiliser des adresses de livraison alternatives (relais, points de retrait) pour les wallets hardware
* Minimiser les données personnelles partagées avec les prestataires logistiques
* Auditer le code de génération de seed phrases des wallets hardware utilisés
* Sensibiliser les détenteurs de crypto aux risques d'attaques physiques et de phishing ciblé
* En cas de vol de données confirmé, transférer les fonds vers un nouveau wallet avec un nouveau seed phrase
* Évaluer la posture de sécurité des fournisseurs tiers ayant accès aux données clients
* Surveiller les transactions blockchain pour détecter des vols liés aux données compromises

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire des fournisseurs tiers ayant accès aux données clients (noms, adresses, emails, téléphones)
* Évaluer la posture de sécurité des partenaires logistiques et de livraison
* Mettre en place des procédures de notification rapide en cas de compromission de tiers
* Sensibiliser les détenteurs de wallets hardware sur les risques d'attaque physique (wrench attacks) et de phishing ciblé
* Recommander l'utilisation d'adresses de livraison alternatives (relais, boîtes postales) pour les wallets hardware
* Vérifier la sécurité du générateur de seed phrases des wallets hardware (audit code, version firmware)

#### Phase 2 — Détection et analyse

* Surveiller les communications de phishing ciblé utilisant des informations personnelles précises (nom, adresse, numéro de téléphone)
* Détecter les tentatives de réinitialisation de compte ou de transfert de crypto utilisant des credentials volés
* Surveiller les transactions blockchain suspectes depuis les wallets des clients affectés
* Identifier les accès anormaux aux systèmes de gestion des commandes et adresses de livraison
* Détecter les tentatives de prédiction de seed phrases via analyse des transactions blockchain (cas Coldcard)

#### Phase 3 — Confinement, éradication et récupération

* Notifier immédiatement les clients dont les données personnelles ont été compromises
* Recommander aux clients affectés de transférer leurs fonds vers un nouveau wallet avec un nouveau seed phrase
* Renforcer la sécurité physique des clients à risque (recommandations de sécurité à domicile)
* Bloquer les campagnes de phishing identifiées utilisant les données volées
* Coordonner avec les forces de l'ordre en cas d'attaque physique signalée
* Isoler les systèmes tiers compromis et révoquer les accès partagés

#### Phase 4 — Activités post-incident

* Réaliser une audit de sécurité des fournisseurs tiers impliqués dans la chaîne logistique
* Mettre à jour les procédures de sélection et d'évaluation des partenaires logistiques
* Documenter l'incident pour les notifications réglementaires (RGPD, etc.)
* Communiquer transparentment avec les clients sur les risques et les mesures prises
* Évaluer le besoin de changer de fournisseur logistique ou de modifier le processus de livraison
* Analyser les leçons apprises pour renforcer la résilience de la supply chain

#### Phase 5 — Threat Hunting (proactif)

* Surveiller les forums et marketplaces criminels pour la vente de données personnelles de détenteurs de wallets
* Rechercher des patterns d'attaques physiques ciblant des détenteurs de crypto dans les rapports de police
* Analyser les transactions blockchain pour identifier des vols potentiellement liés aux données volées
* Surveiller les vulnérabilités dans les générateurs de seed phrases d'autres wallets hardware
* Identifier d'autres fournisseurs de la supply chain crypto exposés à des risques similaires

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing - targeted phishing using stolen personal data (names, emails, phone numbers) to steal crypto |
| **T1591** | Gather Victim Host Information - theft of shipping data to identify physical locations of high-net-worth crypto holders |
| **T1606** | Forge Web Credentials - exploitation of Coldcard seed phrase generation vulnerability to predict passwords |

---

### Sources

* [https://techcrunch.com/2026/08/17/crypto-hardware-wallet-owners-face-fresh-security-risks-after-recent-spate-of-personal-data-thefts/](https://techcrunch.com/2026/08/17/crypto-hardware-wallet-owners-face-fresh-security-risks-after-recent-spate-of-personal-data-thefts/)


---

<div id="chocopoc-cible-les-chercheurs-en-vulnerabilites"></div>

## ChocoPoC cible les chercheurs en vulnérabilités

### Résumé

Une enquête menée conjointement par YesWeHack et Sekoia, publiée le 1er juillet 2026 et relayée le 18 août 2026, révèle une campagne d'attaque par chaîne d'approvisionnement visant les chercheurs en vulnérabilités depuis fin 2025. Des acteurs malveillants diffusent de faux dépôts GitHub proposant des preuves de concept (PoC) pour des vulnérabilités critiques très médiatisées (FortiWeb CVE-2025-64446, React2Shell CVE-2025-55182, MongoBleed CVE-2025-14847, PAN-OS CVE-2026-0257, Ivanti Sentry CVE-2026-10520, Checkpoint VPN CVE-2026-50751, Joomla SP Page Builder CVE-2026-48908). Sept dépôts piégés ont été identifiés, créés sous des comptes GitHub éphémères (lincemorado97, bolubey, ogenich). L'installation via pip install déclenche le téléchargement de dépendances Python malveillantes : en 2025, les paquets 'slogsec' et 'logcrypt.cryptography' étaient utilisés ; en 2026, l'opérateur est passé à 'frint' et 'skytext'. Le paquet skytext, présenté comme une bibliothèque de couleurs terminal, embarque des extensions natives compilées (gradient.so sur Linux, gradient.pyd sur Windows) contenant un dropper obfusqué. Ce dropper utilise le PEB walking, la résolution d'API par hash d'exports, l'anti-debugging (CheckRemoteDebuggerPresent, inspection Dr0-Dr3) et un environmental key gating conditionnant l'exécution à la présence d'un module nommé EXPLOIT_POC.py — rendant les analyses sandbox inefficaces. Lorsque les conditions sont réunies, le malware déchiffre cinq scripts Python, installe une persistance via fichiers .pth et un _distutils_hack trojanisé (avec timestomping), puis lance choco.py, un downloader qui récupère le RAT ChocoPoC depuis un dataset Mapbox utilisé comme dead drop resolver. Le trafic C2 est tunnellisé via DNS-over-HTTPS (dns.alidns[.]com, cloudflare-dns[.]com) et utilise du domain fronting sur api.mapbox[.]com (SNI/Host header forcé) pour se fondre dans un trafic légitime. Pour l'exfiltration lourde, un serveur HTTP dédié est utilisé (91[.]132[.]163[.]78:8001). ChocoPoC est un RAT Python complet : vol de données navigateurs (Chrome, Brave, Edge, Firefox — passwords, cookies, historiques, autofill), collecte de fichiers locaux (.txt, .md, .db), historiques shell, infos réseau, processus actifs, exécution de commandes système, exécution dynamique de code Python, et ajustement de l'intervalle de beaconing. Les commandes utilisent des noms espagnols (hola, cmd, dormir, browserdata). Le paquet skytext a enregistré environ 2 400 téléchargements, avec des pics corrélés aux divulgations de CVE critiques (notamment le 5 mai, correspondant à l'ajout d'une vulnérabilité au catalogue KEV de CISA). Les chercheurs attribuent avec une forte confiance les deux vagues (2025 et 2026) au même acteur, sur la base d'identifiants Mapbox feature identiques, de contrôles environnementaux similaires et de variables anti-récursion communes. Des comptes compromis (identifiants issus de fuites, dont une probablement via infostealer) ont été utilisés pour publier les paquets malveillants (emails : leechuun[@]gmail[.]com, faberhun[@]gmail[.]com, 21104040041[@]student.uin-suka.ac[.]id, 200111085[@]ogrenci.ibu.edu[.]tr).

---

### Analyse opérationnelle

Cette campagne représente une menace directe pour les équipes SOC, les pentesters et les environnements de recherche en vulnérabilités. La détection est particulièrement complexe pour plusieurs raisons : (1) Le code malveillant ne s'exécute que si un fichier nommé 'EXPLOIT_POC.py' est présent dans l'environnement Python — un échantillon isolé en sandbox apparaît inoffensif et génère 0 détection VirusTotal ; (2) La persistance s'établit via des mécanismes Python légitimes (fichiers .pth, _distutils_hack) difficiles à distinguer d'un comportement normal ; (3) Le C2 utilise l'API Mapbox avec domain fronting — le trafic TLS est indiscernable d'une utilisation cartographique légitime ; (4) Le DNS-over-HTTPS contourne les sinkholes DNS et le filtrage UDP/53. Les équipes SOC doivent prioritairement : vérifier la présence des paquets frint/skytext/slogsec/logcrypt.cryptography dans tous les environnements Python ; surveiller les connexions vers api.mapbox[.]com depuis des processus Python ; analyser les fichiers .pth dans site-packages ; détecter les variables d'environnement ZEBUWIAKGPHOQAP006 et JKHWQVEKRASDF12 ; surveiller le port 8001 sur 91[.]132[.]163[.]78. L'impact d'une compromission est élevé : un pentester compromis peut voir ses credentials clients, rapports de pentest confidentiels, données techniques sur des systèmes vulnérables, et clés API exfiltrés. De plus, si le PoC est intégré dans un framework de scan (Nuclei, MDUT), une double supply chain attack peut en résulter, propageant l'infection aux clients du pentester. Les hashes SHA256 des binaires malveillants (gradient.pyd, gradient.so) et des paquets PyPI sont disponibles pour corrélation.

---

### Implications stratégiques

Cette campagne illustre une évolution majeure du renseignement cyber : l'exploitation de l'urgence entourant les nouvelles CVE comme surface d'attaque. Les chercheurs en vulnérabilités, acteurs clés de la défense, deviennent des cibles prioritaires et stratégiques. Les implications sont triples : (1) Risque de cascade : un pentester compromis peut infecter les outils de scan utilisés chez ses clients, créant une double chaîne d'approvisionnement avec un impact potentiellement exponentiel ; (2) Risque de fuite d'informations sensibles : rapports de vulnérabilités non patchées, credentials clients, architecture réseau, données d'engagement — autant d'informations exploitables par des acteurs étatiques ou criminels ; (3) Érosion de confiance dans l'écosystème open-source de la sécurité : les dépôts GitHub PoC et les paquets PyPI deviennent des vecteurs d'attaque crédibles, remettant en question les pratiques d'intégration rapide de code communautaire. L'utilisation de comptes compromis par infostealer pour publier les paquets souligne l'interconnexion des écosystèmes criminels : une infection par infostealer peut alimenter une campagne de supply chain attack mois ou années plus tard. Les organisations doivent revoir leurs politiques d'utilisation de PoC tiers, imposer des revues de dépendances systématiques, envisager l'utilisation d'environnements isolés (conteneurs jetables) pour l'exécution de code non vérifié, et déployer un miroir PyPI privé avec allowlisting. La réutilisation d'infrastructures légitimes (Mapbox, Cloudflare DoH, AliDNS) comme canal C2 pose le défi de la détection sans faux positifs massifs et nécessite une approche comportementale plutôt que signature-based.

---

### Recommandations

* Interdire l'installation de PoC GitHub sans revue préalable du requirements.txt et pyproject.toml (vérification des dépendances transitives)
* Déployer un miroir PyPI privé avec allowlisting des paquets autorisés (devpi, Artifactory)
* Exécuter tout PoC tiers dans un environnement isolé (conteneur Docker jetable, VM dédiée sans accès aux credentials de production)
* Surveiller le trafic réseau des environnements de recherche vers api.mapbox[.]com et 91[.]132[.]163[.]78
* Mettre en place un scan automatique des dépendances Python (pip-audit, safety, semgrep supply-chain) dans les workflows de développement
* Former les équipes aux techniques de supply chain attack via faux PoC et à l'environmental key gating
* Surveiller les nouveaux dépôts GitHub PoC publiés dans les 48h suivant une divulgation de CVE critique (reverse-indexing via nomi-sec/PoC-in-GitHub)
* Déployer des règles EDR pour détecter l'exécution de processus Python avec CREATE_NO_WINDOW (0x08000000) et l'import de modules natifs (.so/.pyd) dans un contexte de recherche
* Mettre en place une veille sur les nouveaux paquets PyPI publiés peu après des divulgations de CVE (pepy.tech, pypistats.org)
* Surveiller les variables d'environnement ZEBUWIAKGPHOQAP006 et JKHWQVEKRASDF12 comme indicateurs de compromission

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre en place un allowlisting des paquets PyPI autorisés via un miroir privé (devpi, Artifactory, Nexus)
* Former les équipes de recherche en vulnérabilités aux risques de supply chain attack via faux PoC GitHub et dépendances transitives
* Déployer des outils de scan de dépendances (pip-audit, safety, semgrep) dans les pipelines CI/CD et les environnements de développement
* Établir une politique de revue systématique des requirements.txt et pyproject.toml avant toute installation de PoC tiers
* Maintenir un inventaire des dépôts GitHub utilisés comme sources de PoC et des comptes PyPI associés
* Déployer des règles EDR pour surveiller l'exécution de processus Python avec flags CREATE_NO_WINDOW (0x08000000)
* Configurer le filtrage DNS pour détecter les requêtes DoH vers dns.alidns[.]com et cloudflare-dns[.]com

#### Phase 2 — Détection et analyse

* Rechercher la présence des paquets PyPI 'frint', 'skytext', 'slogsec', 'logcrypt.cryptography' dans tous les environnements Python (pip list, site-packages)
* Surveiller le trafic réseau vers api.mapbox[.]com depuis des processus Python non liés à un usage cartographique légitime
* Détecter les requêtes DNS-over-HTTPS vers dns.alidns[.]com et cloudflare-dns[.]com depuis des interpréteurs Python
* Rechercher les fichiers .pth modifiés et _distutils_hack trojanisé dans les répertoires Python site-packages
* Surveiller la création de fichiers nommés 'EXPLOIT_POC.py', 'choco.py', 'pozos.py' sur les postes de travail
* Détecter les connexions vers 91[.]132[.]163[.]78 sur le port 8001
* Rechercher les variables d'environnement ZEBUWIAKGPHOQAP006 et JKHWQVEKRASDF12
* Analyser les dépôts GitHub référencés (lincemorado97, bolubey, ogenich) pour identifier d'éventuels clones internes
* Surveiller les imports de modules natifs (.so, .pyd) par des processus Python dans des contextes de recherche en vulnérabilités

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les machines ayant exécuté des PoC provenant des dépôts GitHub identifiés (lincemorado97/*, bolubey/*, ogenich/*)
* Bloquer les paquets PyPI malveillants (frint, skytext, slogsec, logcrypt.cryptography) au niveau du proxy/miroir PyPI
* Couper l'accès réseau des machines compromises vers api.mapbox[.]com et 91[.]132[.]163[.]78
* Révoquer et réinitialiser tous les identifiants stockés dans les navigateurs (Chrome, Brave, Edge, Firefox) des machines affectées
* Supprimer les fichiers .pth malveillants (distutils-precedence.pth) et restaurer _distutils_hack légitime
* Désinstaller les paquets malveillants et nettoyer l'environnement Python (reconstruction du venv)
* Révoquer les tokens API, clés SSH et credentials de services potentiellement exfiltrés
* Capturer une image forensique des machines compromises avant nettoyage pour analyse approfondie

#### Phase 4 — Activités post-incident

* Auditer tous les dépôts GitHub de PoC précédemment utilisés par l'équipe pour identifier d'autres compromissions (reverse-indexing via nomi-sec/PoC-in-GitHub)
* Rotation complète des credentials potentiellement exfiltrés (SSH keys, tokens API, identifiants clients, credentials de rapports de pentest)
* Vérifier l'intégrité des rapports de pentest et données clients potentiellement accessibles depuis les machines compromises
* Documenter l'incident et mettre à jour les procédures de validation des PoC tiers (checklist de revue de dépendances)
* Mettre en place un monitoring continu des nouveaux paquets PyPI associés aux CVE récentes (pepy.tech, pypistats.org)
* Vérifier si des frameworks de scan internes (Nuclei, MDUT) ont intégré des PoC compromis (double supply chain attack)
* Communiquer aux clients concernés si des données d'engagement ont pu être exposées

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs réseau historiques toute connexion vers api.mapbox[.]com depuis des processus Python (au moins 6 mois rétroactifs)
* Analyser les statistiques de téléchargement des paquets malveillants pour corréler avec les activités internes (pics post-CVE)
* Rechercher des patterns similaires : nouveaux paquets PyPI publiés peu après des divulgations de CVE critiques (KEV catalog)
* Surveiller les nouveaux dépôts GitHub PoC créés pour les CVE récentes et analyser systématiquement leurs requirements.txt
* Chasser des variantes utilisant d'autres services légitimes comme dead drop resolver (Pastebin, Discord, Telegram, Cloudflare Workers)
* Rechercher des comptes PyPI créés avec des emails issus de fuites (corrélation avec bases d'infostealers)
* Surveiller les comptes Mapbox nouvellement créés avec des patterns de noms similaires (frankley, mattallahsaed, james09790, rdraa)

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| HASH_SHA256 | `93739477cd379adef95126b22758c0e644282d2028dd297328ce856fa111dd06` | High |
| HASH_SHA256 | `17997e9e0256d0f5d5d21a4852c37f16b338e4bb9c2bec09bdfd822b24aa76b4` | High |
| HASH_SHA256 | `5abd45d6f4a1705dca55d882f017d4768888dce9ad99cea40b3da35c23de5cae` | High |
| HASH_SHA256 | `40569318e89db751ff3886b2617d990d8a343f0d1d8727b7f978a28129ca36bc` | High |
| HASH_SHA256 | `320b29844892e3c59bc6fcb07e701b2b3230a37cb4a13176174e9e294ec6d43e` | High |
| IP | `91[.]132[.]163[.]78` | High |
| DOMAIN | `mapbox[.]com` | High |
| DOMAIN | `alidns[.]com` | Medium |
| DOMAIN | `cloudflare-dns[.]com` | Medium |
| URL | `hxxps://api[.]mapbox[.]com/datasets/v1/frankley/cmor0tcxf008i1mmpd7apt903/features/dm370543acmdopk296nahbtua` | High |
| URL | `hxxps://api[.]mapbox[.]com/datasets/v1/mattallahsaed/cmismaye7000s1mp2v8fkn4lp/features/dm370543acmdopk296nahbtua` | High |
| URL | `hxxp://91[.]132[.]163[.]78:8001/assets/static/bundle[.]ext[.]min[.]de5b2bc9[.]js` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1195.002** | Compromise Software Supply Chain : paquets PyPI malveillants (frint, skytext, slogsec, logcrypt.cryptography) injectés via requirements.txt de faux dépôts PoC GitHub |
| **T1059.006** | Command and Scripting Interpreter: Python — RAT ChocoPoC et downloader choco.py écrits en Python, exécution dynamique via exec() |
| **T1071.001** | Application Layer Protocol: Web Protocols — utilisation de l'API Mapbox comme dead drop resolver et canal C2 covert |
| **T1105** | Ingress Tool Transfer — téléchargement de la charge utile RAT depuis un dataset Mapbox |
| **T1027** | Obfuscated Files or Information — extensions compilées obfusquées, blocs XOR-encryptés compressés Zlib, résolution dynamique d'API par hash d'exports |
| **T1497.001** | System Checks: Virtual Machine/Sandbox Evidence — environmental key gating sur hash du nom de module (EXPLOIT_POC.py), rendant l'analyse sandbox inefficace |
| **T1497.003** | System Checks: Virtual Machine/Sandbox Evidence — anti-debugging via CheckRemoteDebuggerPresent et inspection des registres Dr0-Dr3 (GetThreadContext) |
| **T1547.007** | Boot or Logon Autostart Execution: Re-opened Applications — persistance via fichiers .pth et _distutils_hack trojanisé chargés à chaque démarrage d'interpréteur Python |
| **T1005** | Data from Local System — collecte de fichiers (.txt, .md, .db), historiques shell (.bash_history, .zsh_history), configuration réseau, liste des processus |
| **T1555.003** | Credentials from Password Stores: Credentials from Web Browsers — vol de mots de passe, cookies, historiques et autofill depuis Chrome, Brave, Edge, Firefox |
| **T1572** | Protocol Tunneling — DNS-over-HTTPS via dns.alidns[.]com et cloudflare-dns[.]com pour contourner le filtrage DNS local |
| **T1090.004** | Proxy: Domain Fronting — SNI/Host header forcé à api.mapbox[.]com avec connexion IP directe, trafic TLS indiscernable d'une utilisation Mapbox légitime |
| **T1070.006** | Timestomping — manipulation des horodatages des fichiers .pth et _distutils_hack pour échapper à la forensique |
| **T1036** | Masquerading — paquet skytext présenté comme bibliothèque de couleurs terminal, _distutils_hack trojanisé imitant un paquet setuptools légitime |
| **T1213** | Data from Information Repositories — exfiltration via datasets Mapbox (création de features contenant les données volées) |

---

### Sources

* [https://www.datasecuritybreach.fr/chocopoc-cible-les-chercheurs-en-vulnerabilites/](https://www.datasecuritybreach.fr/chocopoc-cible-les-chercheurs-en-vulnerabilites/)
* [https://www.yeswehack.com/news/chocopocs-vulnerability-researchers-trojanised-exploits](https://www.yeswehack.com/news/chocopocs-vulnerability-researchers-trojanised-exploits)


---

<div id="piratage-du-fisc-proteger-le-pacte-republicain-et-le-consentement-a-limpot"></div>

## Piratage du fisc : protéger le pacte républicain et le consentement à l'impôt

### Résumé

Le 12 août 2026, un acteur malveillant se présentant sous le pseudonyme « ZeroBytes » a revendiqué sur le forum cybercriminel PwnForums des accès illégitimes au système d'information de la Direction générale des Finances publiques (DGFiP). Deux intrusions ont été confirmées par la DGFiP dans un communiqué du 14 août 2026. La première, fin juin 2026, a visé le portail impots.gouv.fr via l'usurpation d'identifiants d'un agent de la DGFiP et d'un tiers habilité (notaire, huissier ou collectivité). ZeroBytes a affirmé avoir récupéré l'accès à un VPN utilisé par les agents du fisc, lui permettant d'accéder à un outil de recherche interne et d'aspirer près de 680 000 lignes de données avant que la connexion ne soit coupée. Les données exfiltrées concernent au moins 678 000 particuliers et professionnels : noms et prénoms, revenu fiscal de référence, quotient familial, taux de prélèvement à la source, et pour les entreprises, raison sociale et numéro SIREN. La seconde intrusion, fin juillet 2026, a ciblé le Serveur Professionnel de Données Cadastrales (SPDC), accessible via apexappliext.dgfip.finances.gouv[.]fr. ZeroBytes a affirmé avoir contourné l'authentification multifacteur (MFA) pour y pénétrer, puis a interrompu lui-même le téléchargement (trop lent selon lui). Il revendique 252 149 enregistrements cadastraux correspondant à plus de 2 millions de titulaires de droits, sur un système pouvant contenir des données sur environ 20 millions de citoyens. La DGFiP évoque 200 000 comptes cadastraux concernés (430 000 selon des sources ultérieures). ZeroBytes se présente comme un duo français motivé par l'argent, avec un historique d'intrusions sur des cibles françaises. Il a affirmé conserver un accès actif au panel SPDC et l'a proposé à la vente alongside la base de données, pour un prix se chiffrant en milliers d'euros. La DGFiP a saisi la CNIL, déposé plainte, coupé préventivement des accès sensibles, et le Premier ministre a demandé un audit approfondi à l'ANSSI ainsi que l'accélération du plan de sécurisation des SI de l'État. L'article du Monde, publié dans la section Idées, analyse les implications politiques et sociales de cette breach, notamment l'atteinte au « pacte républicain » et au consentement à l'impôt. Le secrétaire d'État aux Comptes publics, David Amiel, a présenté ses excuses publiquement le 18 août 2026.

---

### Analyse opérationnelle

L'attaque contre la DGFiP illustre plusieurs défaillances opérationnelles exploitables : (1) Usurpation de credentials d'agents via VPN — l'absence de surveillance comportementale des sessions VPN a permis une extraction de 680 000 lignes sans détection ; (2) Contournement de MFA sur le SPDC — la méthode de contournement n'est pas détaillée mais soulève des questions sur la robustesse de l'implémentation MFA (probablement MFA basée sur SMS/OTP plutôt que FIDO2) ; (3) Délai de détection critique : les intrusions de fin juin et fin juillet n'ont été identifiées qu'après la revendication publique sur PwnForums le 12 août, soit plus d'un mois après la première intrusion — la DGFiP a reconnu que les contrôles d'accès initiaux n'avaient pas détecté le vol de données en raison de la « sophistication de l'attaque » ; (4) Accès tiers : l'élargissement de l'accès à des tiers habilités (notaires, huissiers, collectivités) multiplie la surface d'attaque et le nombre de comptes pouvant être compromis. Les équipes SOC doivent : surveiller activement les sessions VPN pour des comportements anormaux (UEBA) ; implémenter une détection d'exfiltration de données structurées (DLP) ; renforcer les contrôles MFA (migration vers FIDO2/WebAuthn) ; surveiller les forums du darkweb pour détection précoce ; mettre en place des honeytokens dans les bases sensibles. Le risque de phishing ciblé post-breach est très élevé : les données fiscales précises (revenu, quotient familial, taux de prélèvement à la source) permettent des campagnes d'hameçonnage hautement crédibles impersonnant les services fiscaux, avec un potentiel d'extorsion individuelle.

---

### Implications stratégiques

Ce piratage constitue une crise de souveraineté numérique et de confiance institutionnelle majeure pour l'État français. Les enjeux stratégiques sont multiples : (1) Atteinte au pacte républicain : la fuite de données fiscales de 678 000+ contribuables érode la confiance dans l'administration fiscale et le consentement à l'impôt — c'est précisément le sujet de l'article du Monde ; (2) Risque d'exploitation criminelle massive : les données précises (revenu, quotient familial, adresse cadastrale) constituent une mine d'or pour le phishing ciblé, l'extorsion, l'espionnage économique et le social engineering — le risque se matérialisera dans les semaines et mois suivants ; (3) Responsabilité réglementaire : le délai entre l'intrusion (fin juin) et la notification CNIL (mi-août) pose la question de la conformité RGPD (notification dans les 72h après découverte) — le syndicat Solidaires Finances Publiques a dénoncé une communication « tardive » ; (4) Géopolitique et cybercriminalité : ZeroBytes se présentant comme un duo français, l'attaque soulève la question de la cybercriminalité intra-nationale ciblant les infrastructures critiques étatiques, sans nécessiter de sophistication de type APT ; (5) Décisions politiques : le Premier ministre a demandé l'accélération du plan de sécurisation des SI de l'État (annoncé le 30 avril 2026) et un audit ANSSI — cet incident pourrait servir de catalyseur pour imposer des standards de cybersécurité plus stricts (MFA phishing-resistant obligatoire, segmentation réseau, DLP) aux administrations publiques françaises ; (6) Précédent : ZeroBytes ayant un historique d'attaques sur des cibles françaises, l'absence de dissuasion effective pose la question de la réponse pénale et de la capacité d'attribution. L'incident pourrait également avoir des répercussions sur les négociations européennes sur la directive NIS2 et la résilience numérique des administrations.

---

### Recommandations

* Déployer une MFA phishing-resistant (FIDO2/WebAuthn) sur tous les accès VPN et systèmes internes sensibles de l'administration
* Implémenter une surveillance comportementale des sessions VPN (UEBA) avec alertes en temps réel sur volumes de données, horaires et géolocalisation
* Mettre en place des solutions DLP pour détecter l'exfiltration massive de données structurées (requêtes SQL anormales, exports volumineux)
* Surveiller activement les forums cybercriminels (darkweb, PwnForums) pour détection précoce de ventes de données gouvernementales
* Réduire le délai de détection via des tests d'intrusion réguliers et du red teaming sur les systèmes fiscaux
* Renforcer la formation anti-phishing des agents et des tiers habilités (notaires, huissiers, collectivités)
* Segmenter le réseau pour limiter le lateral movement depuis les accès VPN vers les bases de données sensibles
* Mettre en place des honeytokens/canary tokens dans les bases fiscales pour détecter l'exfiltration
* Réviser la politique d'accès tiers : minimiser le nombre de comptes habilités, appliquer le principe du moindre privilège
* Accélérer la mise en œuvre du plan de sécurisation des SI de l'État annoncé le 30 avril 2026
* Préparer des templates de communication de crise et de notification individuelle pour les futurs incidents de ce type

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Renforcer l'authentification multifacteur avec des méthodes phishing-resistant (FIDO2/WebAuthn) sur tous les accès VPN et systèmes internes sensibles
* Mettre en place une surveillance comportementale des sessions VPN (UEBA) : détection d'anomalies de connexion (heures, géolocalisation, volumes de transfert, sessions simultanées)
* Établir un inventaire complet des comptes à privilèges et des accès tiers habilités (notaires, huissiers, collectivités) avec revue périodique
* Déployer des solutions DLP pour détecter l'exfiltration massive de données structurées (requêtes SQL anormales, exports volumineux)
* Définir des procédures de réponse à incident incluant notification CNIL dans les 72 heures et communication publique
* Mettre en place une veille sur les forums cybercriminels (darkweb) pour détection précoce de ventes de données gouvernementales
* Segmenter le réseau pour limiter la latérale movement depuis les accès VPN vers les bases de données sensibles

#### Phase 2 — Détection et analyse

* Surveiller les connexions VPN atypiques : heures inhabituelles, volumes de transfert élevés, géolocalisation anormale, sessions simultanées
* Détecter les accès simultanés depuis plusieurs sessions sur un même compte agent
* Mettre en place des alertes sur les requêtes SQL massives ou exports de données inhabituels depuis les bases fiscales et cadastrales
* Surveiller les tentatives de contournement de MFA sur le SPDC (apexappliext.dgfip.finances.gouv[.]fr) : échecs répétés, tokens suspects, changements de device
* Rechercher l'activité de l'acteur ZeroBytes sur les forums du darkweb (PwnForums) pour détection précoce de revendications
* Mettre en place des honeytokens/canary tokens dans les bases de données fiscales pour détecter l'exfiltration
* Surveiller les accès au SPDC en dehors des heures ouvrées et les téléchargements de données cadastrales volumineux

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement tous les comptes compromis (agent DGFiP et tiers habilité) et tous les accès associés
* Couper préventivement les accès aux systèmes d'information sensibles (comme fait par la DGFiP)
* Bloquer les adresses IP et sessions VPN suspectes identifiées lors des investigations
* Isoler les systèmes ayant fait l'objet d'accès illégitimes (impots.gouv.fr, SPDC)
* Réinitialiser tous les credentials potentiellement compromis (agents et tiers habilités, rotation des certificats VPN)
* Mettre en œuvre des coupures préventives des accès aux systèmes d'information sensibles au-delà des comptes identifiés
* Vérifier l'absence d'accès persistant (ZeroBytes a affirmé être 'still logged into the panel')

#### Phase 4 — Activités post-incident

* Notifier la CNIL dans les 72 heures conformément au RGPD (article 33)
* Informer individuellement chaque personne concernée (678 000 particuliers/professionnels + ~200 000 comptes cadastraux) par courriel et courrier avec détail des données exposées
* Déposer plainte et coopérer avec les autorités judiciaires (parquet de Paris)
* Conduire un audit approfondi confié à l'ANSSI pour établir précisément les circonstances et causes de l'incident
* Accélérer le plan de sécurisation des systèmes d'information de l'État (annoncé le 30 avril 2026)
* Mettre en place des mesures de vigilance pour les usagers : alerte phishing ciblé, canal d'information dédié
* Évaluer le respect du délai de notification RGPD (intrusion fin juin, notification mi-août — possible non-conformité)
* Documenter l'incident pour retour d'expérience et mise à jour des procédures de sécurité

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs historiques (juin-juillet 2026) les patterns d'accès correspondant aux TTP de ZeroBytes : VPN + extraction massive
* Analyser les autres systèmes gouvernementaux français pour des indicateurs de compromission similaires (VPN, MFA bypass, accès tiers)
* Surveiller les forums du darkweb (PwnForums et autres) pour des ventes de données gouvernementales françaises et l'activité de ZeroBytes
* Rechercher des comptes d'agents compromis via infostealer pouvant donner accès aux systèmes DGFiP (corrélation avec bases de fuites)
* Corréler les accès illégitimes avec des campagnes de phishing ciblant les agents de la DGFiP et les tiers habilités (notaires, huissiers)
* Vérifier si ZeroBytes a accédé à d'autres systèmes gouvernementaux avec les mêmes credentials ou techniques
* Analyser les logs d'authentification MFA pour identifier d'autres tentatives de contournement sur les systèmes critiques de l'État

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `impots.gouv[.]fr` | High |
| DOMAIN | `apexappliext.dgfip.finances.gouv[.]fr` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078** | Valid Accounts — usurpation d'identifiants d'un agent de la DGFiP et d'un tiers habilité (notaire, huissier, collectivité locale) |
| **T1133** | External Remote Services — accès via VPN utilisé par les agents du fisc pour connexion distante au système d'information interne |
| **T1556** | Modify Authentication Process — contournement de l'authentification multifacteur (MFA) sur le Serveur Professionnel de Données Cadastrales (SPDC) |
| **T1041** | Exfiltration Over C2 Channel — extraction automatisée de près de 680 000 lignes de données fiscales via l'outil de recherche interne |
| **T1213** | Data from Information Repositories — consultation et extraction de données depuis les bases fiscales (revenu, quotient familial) et cadastrales (SPDC) |
| **T1567.002** | Exfiltration Over Web Service: Exfiltration to Cloud Storage — mise en vente des données sur un forum cybercriminel (PwnForums) sur le darkweb |
| **T1584** | Compromise Infrastructure — ZeroBytes a affirmé conserver un accès actif au panel SPDC et l'a proposé à la vente alongside la base de données |

---

### Sources

* [https://www.lemonde.fr/idees/article/2026/08/18/piratage-du-fisc-proteger-le-pacte-republicain-et-le-consentement-a-l-impot_6748938_3232.html](https://www.lemonde.fr/idees/article/2026/08/18/piratage-du-fisc-proteger-le-pacte-republicain-et-le-consentement-a-l-impot_6748938_3232.html)
* [https://presse.economie.gouv.fr/?p=182374](https://presse.economie.gouv.fr/?p=182374)
* [https://www.bleepingcomputer.com/news/security/french-tax-authority-data-breach-affects-678-000-individuals/](https://www.bleepingcomputer.com/news/security/french-tax-authority-data-breach-affects-678-000-individuals/)
* [https://www.theregister.com/security/2026/08/14/french-tax-authority-admits-data-heist-after-crook-touts-2m-records/5287885](https://www.theregister.com/security/2026/08/14/french-tax-authority-admits-data-heist-after-crook-touts-2m-records/5287885)
* [https://www.france24.com/fr/info-en-continu/20260814-fisc-pirate-ce-que-l-on-sait-des-donnees-derobees](https://www.france24.com/fr/info-en-continu/20260814-fisc-pirate-ce-que-l-on-sait-des-donnees-derobees)
