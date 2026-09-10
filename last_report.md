# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [Scans et force brute ciblant les serveurs Proxmox VE après la publication d'un avis de vulnérabilité](#scans-et-force-brute-ciblant-les-serveurs-proxmox-ve-apres-la-publication-dun-avis-de-vulnerabilite)
  * [Ingénierie sociale sur le thème des passkeys menant à un compromis d'identité et du cloud](#ingenierie-sociale-sur-le-theme-des-passkeys-menant-a-un-compromis-didentite-et-du-cloud)
  * [Rapport Proofpoint 2026 Voice of the CISO : résilience en amélioration, l'IA élargit le mandat des CISO](#rapport-proofpoint-2026-voice-of-the-ciso-resilience-en-amelioration-lia-elargit-le-mandat-des-ciso)
  * [Quatre vecteurs d'exposition des clés SSH via un agent de codage IA, et les contre-mesures réellement efficaces](#quatre-vecteurs-dexposition-des-cles-ssh-via-un-agent-de-codage-ia-et-les-contre-mesures-reellement-efficaces)
  * [TornadoRevC2 : framework open-source de post-exploitation avec 49 plugins publié par un opérateur red team](#tornadorevc2-framework-open-source-de-post-exploitation-avec-49-plugins-publie-par-un-operateur-red-team)
  * [voidsec-proxy : boîte à outils open-source OPSEC en Python (18 modules, 50+ commandes) publiée sur GitHub](#voidsec-proxy-boite-a-outils-open-source-opsec-en-python-18-modules-50-commandes-publiee-sur-github)
  * [Désactivation de Windows Defender via l'enregistrement d'un faux antivirus auprès du Windows Security Center](#desactivation-de-windows-defender-via-lenregistrement-dun-faux-antivirus-aupres-du-windows-security-center)
  * [Exploitation active de vulnérabilités Cisco Secure Firewall Management Center (alerte Talos)](#exploitation-active-de-vulnerabilites-cisco-secure-firewall-management-center-alerte-talos)
  * [Signalement d'une possible page de phishing via un lien de redirection encurtador.dev (analyse urldna)](#signalement-dune-possible-page-de-phishing-via-un-lien-de-redirection-encurtadordev-analyse-urldna)
  * [Bonnes pratiques CI/CD : épingler les dépendances pour réduire le risque de compromission de la chaîne d'approvisionnement](#bonnes-pratiques-cicd-epingler-les-dependances-pour-reduire-le-risque-de-compromission-de-la-chaine-dapprovisionnement)
  * [Balayage massif d'infrastructures crypto mal configurées capté par les honeypots Lurescope](#balayage-massif-dinfrastructures-crypto-mal-configurees-capte-par-les-honeypots-lurescope)
  * [Trezor : campagne de phishing « STM32 Entropy Vulnerability » émise via un prestataire e-mail compromis](#trezor-campagne-de-phishing-stm32-entropy-vulnerability-emise-via-un-prestataire-e-mail-compromis)
  * [Qilin revendique Mitsuwa Trading Co., Ltd sur son site de fuite](#qilin-revendique-mitsuwa-trading-co-ltd-sur-son-site-de-fuite)
  * [Outil public d'écoute via exploitation de carte SIM (mécanisme S@T setup call) publié sur GitHub](#outil-public-decoute-via-exploitation-de-carte-sim-mecanisme-st-setup-call-publie-sur-github)
  * [Extradition vers les États-Unis d'un développeur russe soupçonné de prises de contrôle de comptes bancaires](#extradition-vers-les-etats-unis-dun-developpeur-russe-soupconne-de-prises-de-controle-de-comptes-bancaires)
  * [Chatter : échéance imminente (11 septembre) suggérée en lien avec ShinyHunters](#chatter-echeance-imminente-11-septembre-suggeree-en-lien-avec-shinyhunters)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

Le paysage de la menace du jour est dominé par le volet technique avec 98 vulnérabilités recensées, traduisant une activité soutenue de divulgation et d'exploitation qui exige un triage prioritaire des correctifs. Les 22 fuites de données confirmées témoignent d'une pression persistante sur les données personnelles et corporatives, vraisemblablement en aval de l'exploitation de certaines vulnérabilités récemment publiées. L'absence totale d'acteurs de menace (0) est notable et pourrait refléter un biais de collecte ou une phase de latence dans les campagnes d'attribution, à surveiller afin d'éviter un angle mort. Le volet géopolitique reste marginal (3 publications) mais mérite une veille ciblée compte tenu des tensions actuelles susceptibles d'influencer les opérations cyber étatiques. La couverture réglementaire est quasi inexistante (1 publication), n'indiquant aucun changement normatif majeur à intégrer immédiatement dans la conformité. La production analytique demeure modérée (16 articles), à croiser avec les volumes techniques pour affiner la priorisation. Recommandation : concentrer les efforts sur la gestion des vulnérabilités et la vérification de l'exposition aux fuites de données signalées, tout en réévaluant la couverture de collecte sur les acteurs de menace.

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
| **Asie de l'Est, Europe, Indo-Pacifique** | Diplomatie / Défense / Industries technologiques (semi-conducteurs, énergie, quantique, IA) | Visite d'État du président sud-coréen Lee Jae-myung en France et consolidation du Partenariat Stratégique Global franco-coréen | Le président sud-coréen Lee Jae-myung effectue une visite d'État de quatre jours en France (6-9 septembre 2026) pour marquer le 140e anniversaire des relations diplomatiques entre les deux pays, après la visite d'Emmanuel Macron à Séoul en avril 2026 et la participation sud-coréenne au G7 d'Evian en juin. La relation bilatérale, élevée au rang de « Partenariat Stratégique Global » en début d'année, repose sur de fortes convergences : sécurisation des chaînes de valeur, autonomie stratégique, ambitions technologiques (défense, énergie, quantique, semi-conducteurs) et attachement à un ordre multilatéral face à la rivalité sino-américaine. Toutefois, la relation reste ambiguë : les deux pays coopèrent précisément dans les secteurs où ils se concurrencent le plus (nucléaire civil, défense, semi-conducteurs, automobile, aéronautique, IA), et une asymétrie géopolitique persiste — la France dispose d'une autonomie stratégique (dissuasion, siège permanent au Conseil de sécurité, projection en Indo-Pacifique) tandis que la Corée du Sud reste dépendante de l'alliance américaine face à la menace nord-coréenne. Sans exécution matérielle durable, le partenariat demeure prometteur mais fragile. | [https://www.iris-france.org/visite-detat-de-lee-jae-myung-en-france-ou-en-est-la-cooperation-franco-coreenne/](https://www.iris-france.org/visite-detat-de-lee-jae-myung-en-france-ou-en-est-la-cooperation-franco-coreenne/) |
| **Amérique du Nord, Moyen-Orient, Asie, Afrique** | Sécurité / Renseignement / Défense / Politique étrangère | Bilan rétrospectif de la « guerre mondiale contre le terrorisme » lancée après les attentats du 11 septembre 2001 | Analyse rétrospective d'un ancien diplomate américain sur la « guerre mondiale contre le terrorisme » déclarée après le 11 septembre 2001. Ce qui fut le traumatisme fondateur d'une génération et la priorité absolue de la politique étrangère américaine pendant deux décennies (guerres d'Afghanistan et d'Irak, opérations discrètes au Moyen-Orient, en Asie et en Afrique, mobilisation de l'armée, du renseignement, de la diplomatie et de l'aide extérieure) n'est plus aujourd'hui la grande campagne nationale de Washington. Pour les nouvelles générations et une partie des décideurs actuels, le 11-Septembre appartient désormais à l'histoire ancienne. L'auteur souligne qu'il est difficile de dire si cette « guerre » a été gagnée, voire si elle s'est un jour réellement terminée, la menace djihadiste (al-Qaïda, déjà auteure d'attentats contre des ambassades américaines en Afrique et contre un navire au large du Yémen avant 2001) ayant évolué et s'être diffusée plutôt que disparue. | [https://www.iris-france.org/qui-a-gagne-la-guerre-mondiale-contre-le-terrorisme/](https://www.iris-france.org/qui-a-gagne-la-guerre-mondiale-contre-le-terrorisme/) |
| **Asie du Sud, Eurasie, Asie centrale** | Diplomatie / Géopolitique / Économie des pays émergents | 18e sommet des BRICS élargies à New Delhi (12-13 septembre 2026) sous présidence indienne | Moins de deux semaines après le sommet de l'Organisation de coopération de Shanghai (OSC), les BRICS élargies tiennent leur 18e sommet à New Delhi les 12 et 13 septembre 2026. Quatrième sommet présidé par l'Inde (après 2012, 2016 et 2021), il sera vraisemblablement le dernier indien pour au moins une dizaine d'années compte tenu de l'élargissement décidé en 2023 : le groupe compte désormais onze membres à part entière et dix membres associés. La présidence indienne a préparé un agenda volontairement pratique et inclusif, dans la lignée du G20 de 2023 et du sommet sur l'intelligence artificielle de février. Au-delà de l'ordre du jour officiel, les enjeux réels se joueront dans les plénières et surtout dans les rencontres bilatérales en marge du sommet, dans un contexte de recomposition des équilibres internationaux et de la mondialisation. | [https://www.iris-france.org/le-18e-sommet-des-brics-ce-qui-se-joue-vraiment-a-new-delhi/](https://www.iris-france.org/le-18e-sommet-des-brics-ce-qui-se-joue-vraiment-a-new-delhi/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Règlement européen sur la résilience cyber (CRA) – entrée en vigueur des obligations de notification des vulnérabilités et incidents (11 septembre 2026) | Union européenne (Commission européenne, avec appui d'ENISA et des CSIRTs désignés, via la plateforme unique de signalement – SRP) | 2026-09-09 | Union européenne, avec portée extraterritoriale : tout fabricant ou développeur commercialisant dans l'UE un produit avec éléments numériques (matériel ou logiciel, y compris composants commercialisés séparément et solutions de traitement à distance des données) | Règlement européen sur la résilience cyber (CRA) – entrée en vigueur des obligations de notification des vulnérabilités et incidents (11 septembre 2026) | Le règlement européen sur la résilience cyber (CRA) franchit une étape majeure : à compter du 11 septembre 2026, les obligations de notification des vulnérabilités activement exploitées et des incidents graves deviennent la première composante pleinement contraignante du texte, bien avant l'échéance de conformité globale fixée au 11 décembre 2027. Tout fabricant vendant des produits avec éléments numériques dans l'UE est concerné, quelle que soit sa localisation. Le régime de notification impose des délais stricts via la plateforme unique de signalement (SRP) : alerte précoce sous 24 heures, notification complète sous 72 heures, puis rapport final dans un délai de 14 jours à un mois. La notion d'« exploitation active » est définie comme l'existence de preuves fiables qu'un acteur malveillant a exploité une vulnérabilité dans un système sans l'autorisation du propriétaire de celui-ci, précision importante qui distingue exploitation malveillante et tests autorisés. Le point critique souligné par l'article est que le CRA suppose que les fabricants ont déjà réalisé une évaluation des risques cybersécurité au niveau produit (article 13(2)) : sans cette base de référence, il est impossible de déterminer de manière défendable si un incident est « grave » ou si une exploitation est « active ». Le véritable déficit opérationnel identifié n'est pas réglementaire mais technique et organisationnel : gestion des SBOM, flux de renseignement sur les vulnérabilités adaptés aux produits, surveillance continue et procédures de réponse à incident éprouvées doivent fonctionner de manière intégrée, et non être ajoutés après l'échéance. | `hxxps://www.guidepointsecurity[.]com/blog/eu-cra-reporting-requirements/` |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Transport aérien / Voyage (données gouvernementales de passagers)** | Système APIS (Advance Passenger Information System) lié au Vietnam | Dossiers APIS : identité des voyageurs, données de passeports, informations de vols et itinéraires (environ 220 millions d'enregistrements). | 220000000 | [https://www.bleepingcomputer.com/news/security/220-million-traveler-records-exposed-in-vietnam-linked-apis-leak/](https://www.bleepingcomputer.com/news/security/220-million-traveler-records-exposed-in-vietnam-linked-apis-leak/) |
| **Éducation / EdTech** | Mathspace | Données personnelles d'utilisateurs de la plateforme (plus d'un million de personnes) ; nature exacte non précisée dans la source (probablement identifiants de comptes, coordonnées et données liées au parcours scolaire). | 1000000 | [https://www.bleepingcomputer.com/news/security/mathspace-discloses-data-breach-affecting-over-1-million-people/](https://www.bleepingcomputer.com/news/security/mathspace-discloses-data-breach-affecting-over-1-million-people/) |
| **Éducation (district scolaire public)** | Westfield Public Schools (New Jersey, États-Unis) | Fichiers et serveurs du district (chiffrement revendiqué) ; échantillons de données publiés sur le site de fuite ; systèmes affectés : SIS, portails parents, carnets de notes, téléphonie, Wi-Fi. | Inconnu | [https://databreaches.net/2026/09/09/network-outage-disrupts-westfield-public-schools-in-new-jersey-as-ransomware-group-posts-samples/](https://databreaches.net/2026/09/09/network-outage-disrupts-westfield-public-schools-in-new-jersey-as-ransomware-group-posts-samples/) |
| **Santé / technologies de santé (États-Unis)** | Veradigm | Données patients : informations personnelles et numéros de sécurité sociale (SSN) ; le groupe Gentlemen revendique 3,5 millions de dossiers patients volés. | 3500000 | [https://www.bleepingcomputer.com/news/security/veradigm-discloses-patient-data-breach-after-gentlemen-gang-claims-attack/](https://www.bleepingcomputer.com/news/security/veradigm-discloses-patient-data-breach-after-gentlemen-gang-claims-attack/)<br>[https://cybersecuritynews.com/veradigm-patient-data-breach/](https://cybersecuritynews.com/veradigm-patient-data-breach/)<br>[https://osintsights.com/veradigm-breach-exposes-patient-data-after-ransomware-attack](https://osintsights.com/veradigm-breach-exposes-patient-data-after-ransomware-attack) |
| **Santé (équipement médical et services à domicile)** | AdaptHealth | Noms complets, coordonnées, informations démographiques, informations d'assurance santé et informations de santé. | 4115802 | [https://osintsights.com/adapthealth-breach-exposes-41-million-patients-data?utm_source=mastodon&utm_medium=social](https://osintsights.com/adapthealth-breach-exposes-41-million-patients-data?utm_source=mastodon&utm_medium=social) |
| **Multi-sectoriel (documents d'identité)** | Non identifié (base de données de permis de conduire — 153 millions de documents en vente) | Copies de permis de conduire (153 millions de documents) ; métadonnées associées non précisées dans la source. | 153000000 | [https://osintsights.com/ai-powered-attacks-target-id-databases?utm_source=mastodon&utm_medium=social](https://osintsights.com/ai-powered-attacks-target-id-databases?utm_source=mastodon&utm_medium=social) |
| **Santé (santé comportementale)** | BestCare Treatment Services Inc. | Noms complets, dates de naissance, informations médicales, coordonnées et informations démographiques, autres identifiants patients. | 4216 | [https://beyondmachines.net/event_details/bestcare-treatment-services-data-breach-affects-more-than-4000-individuals-e-r-6-e-s/gD2P6Ple2L](https://beyondmachines.net/event_details/bestcare-treatment-services-data-breach-affects-more-than-4000-individuals-e-r-6-e-s/gD2P6Ple2L) |
| **Santé (groupe médical orthopédique - Californie du Nord)** | Golden State Orthopedics & Spine (GSOS) | Noms complets, adresses postales, dates de naissance, numéros de Sécurité sociale (SSN), informations d'assurance santé, informations de diagnostic médical (PHI) - variables selon les individus. | 150 Go (revendiqués par Brain Cipher) | [https://beyondmachines.net/event_details/golden-state-orthopedics-spine-discloses-data-breach-as-brain-cipher-claims-150-gb-stolen-n-j-t-z-e/gD2P6Ple2L](https://beyondmachines.net/event_details/golden-state-orthopedics-spine-discloses-data-breach-as-brain-cipher-claims-150-gb-stolen-n-j-t-z-e/gD2P6Ple2L) |
| **Santé (cabinet de gestion de la douleur - Caroline du Nord)** | Crystal Coast Pain Management (division d'East Carolina Anesthesia Associates) | Noms complets, dates de naissance, numéros de Sécurité sociale (SSN), informations médicales. | 300 Go (revendiqués par DEVMAN 2.0) | [https://beyondmachines.net/event_details/crystal-coast-pain-management-discloses-data-breach-as-devman-2-0-claims-300-gb-stolen-w-a-0-p-a/gD2P6Ple2L](https://beyondmachines.net/event_details/crystal-coast-pain-management-discloses-data-breach-as-devman-2-0-claims-300-gb-stolen-w-a-0-p-a/gD2P6Ple2L) |
| **Cybercriminalité / écosystème IA (fournisseurs de modèles et plateformes SaaS)** | Comptes utilisateurs de services d'IA (Google, Anthropic, OpenAI, Groq, OpenRouter, Character[.]ai, Poe[.]com, etc.) | Jetons de session et JWT/JWE non expirés (dont 555 liés à des services IA), 24 clés API valides, identifiants, PII en clair présentes dans 17,7 % des JWT. | 7 Go de logs d'infostealer (5 871 machines infectées dans 162 pays) | [https://thehackernews.com/2026/09/infostealer-logs-expose-replayable-ai.html](https://thehackernews.com/2026/09/infostealer-logs-expose-replayable-ai.html) |
| **Santé (soins à domicile / réseau de franchises - Oklahoma)** | Interim HealthCare of Oklahoma City | Selon les acteurs (non confirmé par la victime) : dossiers médicaux et données cliniques, listes de patients et PII, informations financières des franchisés, détails d'audits internes/externes, mémorandums et enregistrements opérationnels. | 1 To (Genesis) + 530 Go (Anubis) revendiqués ; 500 individus listés au portail HHS | [https://beyondmachines.net/event_details/interim-healthcare-of-oklahoma-city-reports-data-breach-amid-separate-genesis-and-anubis-ransomware-claims-b-3-u-e-p/gD2P6Ple2L](https://beyondmachines.net/event_details/interim-healthcare-of-oklahoma-city-reports-data-breach-amid-separate-genesis-and-anubis-ransomware-claims-b-3-u-e-p/gD2P6Ple2L) |
| **Santé (réseau de centres d'urgence - Nutex Health)** | Nutex Health | Informations de patients, employés et prestataires (PII/PHI alléguées), informations commerciales et financières - selon la plainte. | Inconnu | [https://www.netsec.news/nutex-health-data-theft-cyberattack/](https://www.netsec.news/nutex-health-data-theft-cyberattack/) |
| **Transport public (Los Angeles County Metropolitan Transportation Authority)** | Los Angeles County Metropolitan Transportation Authority (LA Metro) | Non confirmé - nature et volume des données alléguées inconnus à ce stade. | Inconnu | [https://beyondmachines.net/event_details/the-gentlemen-claims-la-metro-breach-and-sets-nine-day-deadline-l-2-y-5-f/gD2P6Ple2L](https://beyondmachines.net/event_details/the-gentlemen-claims-la-metro-breach-and-sets-nine-day-deadline-l-2-y-5-f/gD2P6Ple2L) |
| **Événementiel / plateforme en ligne (Brésil)** | ime[.]events (plateforme brésilienne d'événements) | Noms, adresses e-mail, hachages de mots de passe bcrypt, identifiants CPF/CNPJ, numéros de téléphone, dates de naissance, adresses postales. | 502 000 enregistrements | [https://go.darkwebsonar.io/sorb-mastodon](https://go.darkwebsonar.io/sorb-mastodon) |
| **Secteur public / administration des transports (Floride, États-Unis)** | Florida Department of Highway Safety and Motor Vehicles (FLHSMV) - Base DAVID | Numéros de sécurité sociale, nom complet et signature, adresse du domicile, date de naissance, numéro d'identification du conducteur, caractéristiques physiques, numéros de VIN, numéros et descriptions de plaques d'immatriculation, statut de délinquant sexuel. | 200000 | [https://beyondmachines.net/event_details/shinyhunters-claims-to-have-stolen-over-200000-records-from-florida-david-database-l-s-4-m-g/gD2P6Ple2L](https://beyondmachines.net/event_details/shinyhunters-claims-to-have-stolen-over-200000-records-from-florida-david-database-l-s-4-m-g/gD2P6Ple2L) |
| **Secteur public / collectivité territoriale (Aveyron, Occitanie, France)** | Département de l'Aveyron - Site d'offres d'emploi | Données personnelles de plus de 20 000 demandeurs d'emploi inscrites sur le site d'offres d'emploi du département (détail exact des champs non précisé publiquement). | 20000 | [https://france3-regions.franceinfo.fr/occitanie/aveyron/rodez/cyberattaque-sur-un-site-d-offres-d-emploi-du-departement-de-l-aveyron-les-donnees-de-plus-de-20-000-personnes-piratees-3412799.html](https://france3-regions.franceinfo.fr/occitanie/aveyron/rodez/cyberattaque-sur-un-site-d-offres-d-emploi-du-departement-de-l-aveyron-les-donnees-de-plus-de-20-000-personnes-piratees-3412799.html)<br>[https://mastobot.ping.moi/@cyberveille/117240614486955558](https://mastobot.ping.moi/@cyberveille/117240614486955558) |
| **Santé (urgences privées - Texas, États-Unis)** | Longview ER Operations LLC (Hospitality Health ER) | Informations de santé protégées (PHI) ; le périmètre exact des données et des personnes affectées est en cours de détermination. | 501 | [https://beyondmachines.net/event_details/longview-er-operations-discloses-data-breach-following-unauthorized-network-access-c-w-d-s-c/gD2P6Ple2L](https://beyondmachines.net/event_details/longview-er-operations-discloses-data-breach-following-unauthorized-network-access-c-w-d-s-c/gD2P6Ple2L) |
| **Restauration rapide / franchise (Afrique du Sud)** | The Rohloff Group (franchisé KFC - Afrique du Sud) | Données d'employés et données d'entreprise (536 Go revendiqués par INC Ransom ; périmètre exact non confirmé). | Inconnu | [https://mybroadband.co.za/news/security/666413-large-kfc-franchise-operator-in-south-africa-hit-by-536gb-data-breach.html](https://mybroadband.co.za/news/security/666413-large-kfc-franchise-operator-in-south-africa-hit-by-536gb-data-breach.html) |
| **Médias / édition (États-Unis, portefeuille international)** | Condé Nast | 32 815 767 adresses e-mail uniques ; noms et prénoms (31,6 % des enregistrements), adresses postales (22,3 %), genre (17,5 %), dates de naissance (12,6 %), numéros de téléphone (2,9 %). Aucun mot de passe, hachage de mot de passe, identifiant ni donnée de carte de paiement. | 32815767 | [https://securityaffairs.com/198628/data-breach/conde-nast-data-of-32-8-million-users-offered-for-sale-after-wired-leak.html](https://securityaffairs.com/198628/data-breach/conde-nast-data-of-32-8-million-users-offered-for-sale-after-wired-leak.html) |
| **Finance / paiements (Corée du Sud)** | Toss Payments et Coem Payments (passerelles de paiement - Corée du Sud) | Noms des titulaires, numéros de carte, dates d'expiration, deux premiers chiffres des mots de passe de carte, et selon le mode de paiement, informations liées à la date de naissance. Aucun registre de transactions individuelles ni informations complètes de carte. | Inconnu | [https://finance.biggo.com/news/05cae269-1adc-454e-93ce-64ffe8ab1cde](https://finance.biggo.com/news/05cae269-1adc-454e-93ce-64ffe8ab1cde) |
| **Secteur public / Administration gouvernementale (sécurité routière et véhicules)** | Florida Department of Highway Safety and Motor Vehicles (Florida DMV) - Base de données DAVID | Dossiers conducteurs de la base DAVID : noms, adresses, numéros de sécurité sociale, dates de naissance, numéros de permis de conduire, véhicules enregistrés, ainsi que des pages et images des dossiers (photo et signature potentiellement incluses). Plus de 200 000 records revendiqués. | 200000 | [https://www.csoonline.com/article/4220193/shinyhunters-claims-florida-dmv-breach-puts-data-on-the-clock.html](https://www.csoonline.com/article/4220193/shinyhunters-claims-florida-dmv-breach-puts-data-on-the-clock.html) |
| **Santé (soins à domicile et hospice - filiale d'Optum/UnitedHealth Group)** | LHC Group, Inc. (filiale d'Optum / UnitedHealth Group) | PII : noms complets, adresses, dates de naissance, SSN. Données financières : coordonnées bancaires ou autres. PHI : résumés cliniques, codes de diagnostic, plans de traitement, dates de service, informations d'assurance dont numéros Medicare/Medicaid. | 162 578 individus affectés | [https://cyber.netsecops.io/articles/lhc-group-discloses-health-data-breach-affecting-162000-patients/?utm_source=mastodon&utm_medium=social&utm_campaign=daily](https://cyber.netsecops.io/articles/lhc-group-discloses-health-data-breach-affecting-162000-patients/?utm_source=mastodon&utm_medium=social&utm_campaign=daily) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-87911** | 9.6 | N/A | FALSE | Amazon awslabs postgres-mcp-server < 1.1.7 | Injection de commandes OS (CWE-78) par contournement de l'application en lecture seule (CWE-184) | Exécution de commandes OS arbitraires sur l'hôte hébergeant le serveur PostgreSQL, avec les privilèges du service, permettant potentiellement la compromission complète de l'hôte, l'exfiltration des bases de données et un mouvement latéral. | Theoretical | Mettre à jour postgres-mcp-server vers la version 1.1.7 ou ultérieure. Références : bulletin AWS 2026-104 et avis GitHub GHSA-FPH8-PG5W-78FV. | [https://cvefeed.io/vuln/detail/CVE-2026-87911](https://cvefeed.io/vuln/detail/CVE-2026-87911) |
| **CVE-2026-19311** | N/A | N/A | FALSE | OpenSearch Alerting Plugin 2.4.0 à 2.19.5 et 3.0.0 à 3.7.0 ; Amazon OpenSearch Service (moteurs 2.4 à 3.5) | Autorisation manquante (CWE-862) dans l'API Execute Monitor du plugin Alerting | Accès non autorisé en lecture, modification et suppression de données d'index arbitraires sur les clusters OpenSearch, entraînant un risque de fuite, d'altération ou de destruction de données. | None | Mettre à jour vers OpenSearch 2.19.6 / 3.8.0 ou ultérieur ; pour Amazon OpenSearch Service, appliquer la version de service software R20260428-P3 (pas de mise à niveau de moteur requise). En attendant, restreindre le rôle alerting_full_access aux administrateurs de confiance. Référence : GHSA-XXPG-Q3WH-685Q. | [https://aws.amazon.com/security/security-bulletins/rss/2026-078-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-078-aws/) |
| **CVE-2026-18830** | N/A | N/A | FALSE | Amazon Bedrock AgentCore harness - API InvokeHarness antérieure au 31 juillet 2026 | Validation d'entrées insuffisante permettant le contournement de l'invocation du modèle | Exécution d'outils configurés sans passer par l'invocation du modèle et ses contrôles de sécurité, pouvant entraîner des actions non autorisées limitées au périmètre d'outils du harness (un harness sans outil ne pouvait rien exécuter). | None | Aucune action client requise : la mitigation est appliquée automatiquement côté serveur pour toutes les requêtes. Vérifier néanmoins la conformité du service et revoir le périmètre des outils configurés. | [https://aws.amazon.com/security/security-bulletins/rss/2026-073-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-073-aws/) |
| **CVE-2026-85012** | N/A | N/A | FALSE | @amazon-codecatalyst/blueprints.blueprint (npm) versions <= 0.3.155 | Injection de commandes OS (CWE-78) via le champ owner du fichier .ownership-file lors de la resynthèse | Exécution de commandes arbitraires dans l'environnement réalisant la resynthèse, avec les privilèges et credentials disponibles dans cet environnement, pouvant mener à la compromission de la chaîne CI/CD et au vol de secrets. | None | Mettre à jour le package npm vers la version 0.3.156 ou ultérieure (suppression de l'interprétation shell du champ owner et rejet des valeurs hors allowlist) ; c'est la seule mitigation pour les consommateurs directs du package. Aucune action requise pour l'usage du service CodeCatalyst. Référence : GHSA-C7RJ-FR2J-64W7. | [https://aws.amazon.com/security/security-bulletins/rss/2026-095-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-095-aws/) |
| **CVE-2026-77234** | N/A | N/A | FALSE | FreeRTOS-Kernel versions >= 7.0.0 et <= 11.3.0 (ports avec MPU activé, utilisant les timers logiciels) | Validation de commande incomplète dans le chemin des commandes des timers logiciels - exécution de code arbitraire en contexte privilégié | Exécution de code arbitraire en contexte privilégié du noyau et contournement de l'isolation MPU des tâches, compromettant la sécurité de l'ensemble du dispositif embarqué. | None | Mettre à jour FreeRTOS-Kernel vers V11.3.1 ou ultérieure. Aucun risque si les timers logiciels ne sont pas utilisés ; sinon, la mise à jour est la remédiation recommandée. Patcher les forks et code dérivé. | [https://aws.amazon.com/security/security-bulletins/rss/2026-086-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-086-aws/) |
| **CVE-2026-77235** | N/A | N/A | FALSE | FreeRTOS-Kernel versions >= 10.2.0 et <= 11.3.0 (ports ARMv8-M avec TrustZone + MPU) | Validation de privilège manquante dans la gestion des contextes sécurisés ARM TrustZone (ARMv8-M) - use-after-free | Use-after-free de la mémoire Secure-world et corruption du contexte sécurisé, causant des crashes ou un comportement indéfini potentiellement exploitables pour compromettre le monde sécurisé. | None | Mettre à jour FreeRTOS-Kernel vers V11.3.1 ou ultérieure ; aucun contournement complet autre que la mise à jour. Les applications n'utilisant pas de contextes sécurisés TrustZone ne sont pas affectées. Patcher les forks et code dérivé. | [https://aws.amazon.com/security/security-bulletins/rss/2026-086-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-086-aws/) |
| **CVE-2026-77236** | N/A | N/A | FALSE | FreeRTOS-Kernel versions >= 10.2.0 et <= 11.3.0 (ports ARMv8-M avec TrustZone) | Validation de taille manquante dans l'allocation des contextes sécurisés ARM TrustZone (ARMv8-M) - écriture hors limites | Écriture hors limites dans la mémoire Secure-world et corruption des structures de contrôle du tas sécurisé, pouvant mener à des crashes ou à un comportement indéfini exploitable. | None | Mettre à jour FreeRTOS-Kernel vers V11.3.1 ou ultérieure ; aucun contournement complet autre que la mise à jour. Les applications n'utilisant pas de contextes sécurisés TrustZone ne sont pas affectées. Patcher les forks et code dérivé. | [https://aws.amazon.com/security/security-bulletins/rss/2026-086-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-086-aws/) |
| **CVE-2026-77237** | N/A | N/A | FALSE | FreeRTOS-Kernel versions >= 7.4.0 et <= 11.3.0 (ports avec MPU activé et configUSE_QUEUE_SETS=1) | Validation de type manquante dans la fonctionnalité queue-set - lecture hors limites en contexte privilégié | Divulgation du contenu de la mémoire privilégiée du noyau (fuite d'informations), pouvant faciliter des attaques ultérieures contre le dispositif. | None | Mettre à jour FreeRTOS-Kernel vers V11.3.1 ou ultérieure. Les applications compilées sans queue sets ne sont pas affectées. Patcher les forks et code dérivé. | [https://aws.amazon.com/security/security-bulletins/rss/2026-086-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-086-aws/) |
| **CVE-2026-85781** | N/A | N/A | FALSE | Amazon EFS CSI Driver versions <= 3.4.0 (avec l'option --delete-access-point-root-dir=true) | Vérification de propriété des access points absente dans la logique de suppression de volumes | Suppression récursive non autorisée de répertoires sur des file systems Amazon EFS, entraînant une perte de données potentielle sur des systèmes de fichiers hors du périmètre de l'attaquant. | None | Mettre à jour vers EFS CSI Driver v3.4.1 ou ultérieure. En attendant : désactiver --delete-access-point-root-dir, restreindre le RBAC de création de PersistentVolumes aux administrateurs de confiance, limiter le rôle IAM du contrôleur aux file systems qu'il doit gérer et attacher des resource policies EFS explicites. Référence : GHSA-5MRV-3W42-4FHG. | [https://aws.amazon.com/security/security-bulletins/rss/2026-099-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-099-aws/) |
| **CVE-2026-18428** | N/A | N/A | FALSE | OpenSearch SQL Plugin v2.13 à v3.6 (open source) ; Amazon OpenSearch Service v2.13 à v3.5 (géré) | Contournement de validation des requêtes asynchrones (bypass de la deny list de grammaire SQL) | Contournement des restrictions de grammaire SQL permettant l'exécution de requêtes normalement interdites contre des sources de données externes, avec risque d'accès ou de manipulation non autorisée de données. | None | Mettre à jour vers OpenSearch SQL Plugin 3.7 / 2.19.6 ou ultérieur ; pour Amazon OpenSearch Service, appliquer la dernière version du service software (pas de mise à niveau de moteur requise). Les utilisateurs n'utilisant pas le direct query ne sont pas affectés ; sinon restreindre l'accès async query aux utilisateurs de confiance. Référence : GHSA-G4JR-343C-FVJM. | [https://aws.amazon.com/security/security-bulletins/rss/2026-081-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-081-aws/) |
| **CVE-2026-84851** | N/A | N/A | FALSE | Amazon Ion-C (amazon-ion/ion-c) versions < 1.1.6 | Récursion non contrôlée (CWE-674) dans le lecteur Ion - déni de service | Déni de service par crash de l'application embarquant la bibliothèque (épuisement de la pile native), affectant la disponibilité des services traitant des données Ion non fiables. | None | Mettre à jour ion-c vers la version 1.1.6 ou ultérieure et patcher les forks. En attendant, éviter les APIs réécrivant automatiquement les données lues (ion_writer_write_one_value / ion_writer_write_all_values) au profit d'un parcours manuel de l'arbre de valeurs avec limite de profondeur. Référence : GHSA-9GFG-HGJ4-GH44. | [https://aws.amazon.com/security/security-bulletins/rss/2026-094-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-094-aws/) |
| **CVE-2026-19111** | N/A | N/A | FALSE | strands-agents-tools < 0.8.3 (outils mongodb_memory, elasticsearch_memory, mem0_memory) | IDOR (référence directe d'objet non sécurisée) - contournement de l'isolation multi-tenant | Fuite, altération ou suppression de données mémoire inter-tenants ; injection de mémoires falsifiées pouvant influencer le comportement des agents IA ; redirection potentielle de la couche mémoire vers une infrastructure contrôlée par un acteur malveillant. | None | Mettre à jour strands-agents-tools vers la version 0.8.3 ou supérieure. En attendant : ne pas déployer ces outils dans des agents multi-tenants où les utilisateurs finaux partagent un même déploiement, restreindre leur usage à des déploiements mono-tenant avec namespace fixe, et ne pas utiliser les fonctions autonomes mongodb_memory/elasticsearch_memory acceptant des paramètres de connexion. Référence : GHSA-mpxq-953j-42m4. Contact : aws-security[@]amazon[.]com. | [https://aws.amazon.com/security/security-bulletins/rss/2026-077-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-077-aws/) |
| **CVE-2026-85788** | N/A | N/A | FALSE | awslabs.mysql-mcp-server <= 1.0.21 | Contournement du mode lecture seule via commentaires SQL inline (liste d'interdiction incomplète) | Modification ou suppression potentielle de données par des instructions SQL normalement bloquées, dans la limite des privilèges de l'utilisateur MySQL configuré ; aucun impact sur les services AWS. | None | Mettre à jour vers awslabs.mysql-mcp-server 1.0.23 ou supérieure (pip install --upgrade awslabs.mysql-mcp-server). En défense en profondeur, accorder à l'utilisateur de base de données du serveur MCP uniquement les privilèges minimaux requis et ne pas lui attribuer le privilège FILE sauf nécessité explicite. Aucun contournement disponible. Référence : GHSA-x25m-ph3m-3r9q. | [https://aws.amazon.com/security/security-bulletins/rss/2026-103-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-103-aws/) |
| **CVE-2026-18952** | N/A | N/A | FALSE | OpenSearch Security Analytics Plugin >= 2.15.0 (corrigé >= 3.7.0) ; Amazon OpenSearch Service moteurs >= 2.15.0 | SSRF et lecture de fichiers locaux (validation d'entrée manquante) dans le parseur de flux threat intelligence | Accès à des ressources internes depuis les nœuds OpenSearch (localhost, endpoints de métadonnées cloud) et lecture de fichiers locaux potentiellement sensibles, pouvant mener à une compromission de l'environnement. | None | Auto-géré : mettre à jour le plugin vers >= 3.7.0. Amazon OpenSearch Service : appliquer la mise à jour du logiciel de service (moteur 3.7), automatique pour les domaines avec mises à jour activées. En attendant : restreindre le rôle security_analytics_full_access aux utilisateurs de confiance et bloquer via politiques réseau/proxy les requêtes sortantes des nœuds vers localhost et les endpoints de métadonnées internes. | [https://aws.amazon.com/security/security-bulletins/rss/2026-079-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-079-aws/) |
| **CVE-2026-81838** | N/A | N/A | FALSE | awsdac (diagram-as-code) versions 0.10 à 0.23 incluses | Zip Slip (traversée de chemin) lors de l'extraction d'archives zip | Écriture arbitraire de fichiers et exécution potentielle de code arbitraire sur la machine exécutant awsdac, notamment les runners CI/CD ; aucun impact sur les services AWS, les comptes AWS ou les données clients. | None | Mettre à jour awsdac vers la version 0.24 ou supérieure. En attendant : ne traiter que des fichiers de définition (y compris locaux) provenant de sources fiables, ne pas exécuter awsdac avec --allow-untrusted-definitions, et épingler en CI/CD les définitions consommées à du contenu revu et approuvé. Référence : GHSA-hhpv-ppg2-jfj5. | [https://aws.amazon.com/security/security-bulletins/rss/2026-090-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-090-aws/) |
| **CVE-2026-81849** | N/A | N/A | FALSE | amazon-ssm-agent de 2.0.767.0 à 3.3.4364.0 | Traversée de chemin (limitation incorrecte d'un pathname à un répertoire restreint) dans le plugin aws:downloadContent | Écriture arbitraire de fichiers avec privilèges root sur les instances et serveurs gérés ; possibilité d'exécution de code arbitraire en tant que root si des fichiers système sensibles sont écrasés. | None | Mettre à jour amazon-ssm-agent vers la version 3.3.4515.0 ou supérieure. Aucun contournement disponible : appliquer le correctif en priorité et restreindre strictement les permissions ssm:SendCommand. Référence : GHSA-mqvm-jv87-w7rx. | [https://aws.amazon.com/security/security-bulletins/rss/2026-091-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-091-aws/) |
| **CVE-2026-85787** | N/A | N/A | FALSE | awslabs.postgres-mcp-server < 1.1.7 (paquets PyPI) | Liste d'entrées interdites incomplète dans le composant de validation SQL - contournement du périmètre lecture seule | Modification de données (écritures SQL) au-delà du périmètre lecture seule via injection dans le contenu soumis par un utilisateur authentifié, dans la limite des privilèges du rôle Postgres configuré. | None | Mettre à jour vers la version 1.1.7 ou supérieure. En défense en profondeur : connecter le serveur MCP avec un rôle Postgres à privilèges minimaux (ne pas utiliser superuser, rds_superuser ou l'utilisateur maître du cluster, qui contournent la row-level security et peuvent lire pg_authid/pg_user_mappings) ; pour la lecture seule, n'accorder que CONNECT + USAGE + SELECT et forcer les transactions read-only au niveau du rôle ; pour la lecture/écriture, n'accorder que les privilèges INSERT/UPDATE/DELETE strictement nécessaires, ciblés sur les schémas et tables requis. Référence : GHSA-pwr4-hmph-gqgc. | [https://aws.amazon.com/security/security-bulletins/rss/2026-101-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-101-aws/) |
| **CVE-2026-85028** | N/A | N/A | FALSE | AWS FPGA Development Kit (aws-fpga) < 2.3.4 | Création de fichier temporaire dans un répertoire aux permissions non sécurisées - élévation de privilèges locale | Exécution de code arbitraire avec privilèges root par un utilisateur local sur la machine où s'effectue l'installation du kit. | None | Mettre à jour vers AWS FPGA Developer Kit 2.3.4 ou supérieure (le code écrivant dans /tmp/sdk_root_env.exp a été supprimé, les outils sourcent désormais directement shared/bin/set_common_functions.sh). En attendant : supprimer ou commenter les lignes référençant /tmp/sdk_root_env.exp dans sdk_setup.sh et install_fpga_mgmt_tools.sh. Référence : GHSA-g4hc-wrmm-2x74. | [https://aws.amazon.com/security/security-bulletins/rss/2026-096-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-096-aws/) |
| **CVE-2026-75935** | N/A | N/A | FALSE | Amazon ion-java < 1.12.0 | Déni de service par amplification mémoire via préallocation à longueur déclarée | Déni de service par épuisement mémoire des applications parsant des données Ion non fiables (API, files d'attente, pipelines de données), pouvant entraîner des OOM kills et des interruptions de service. | None | Mettre à jour ion-java vers la version 1.12.0 ou supérieure et corriger les forks dérivés. Configurer une taille de buffer maximale limitée via IonBufferConfiguration.withMaximumBufferSize (effectif pour toutes les combinaisons sauf le Ion texte encodé GZIP) et désactiver manuellement la décompression GZIP automatique via IonReaderBuilder.withGzipDecompressionEnabled(false) pour les entrées non fiables. Référence : GHSA-822f-6gg9-whr5. | [https://aws.amazon.com/security/security-bulletins/rss/2026-083-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-083-aws/) |
| **CVE-2026-75936** | N/A | N/A | FALSE | Amazon ion-java < 1.12.0 | Déni de service par amplification mémoire via expansion de données fortement compressées | Déni de service par épuisement mémoire des applications parsant des données Ion compressées non fiables, pouvant entraîner des OOM kills et des interruptions de service. | None | Mettre à jour ion-java vers la version 1.12.0 ou supérieure et corriger les forks dérivés. Configurer une taille de buffer maximale limitée via IonBufferConfiguration.withMaximumBufferSize et désactiver manuellement la décompression GZIP automatique via IonReaderBuilder.withGzipDecompressionEnabled(false) pour les entrées non fiables. Avant 1.12.0, aucun contournement n'est efficace pour toutes les combinaisons d'encodage ([texte, binaire] x [GZIP, non compressé]). Référence : GHSA-wj53-jv76-65mc. | [https://aws.amazon.com/security/security-bulletins/rss/2026-083-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-083-aws/) |
| **CVE-2026-77810** | N/A | N/A | FALSE | Amazon Athena Federated Query - connecteur Neptune, versions >= v2024.15.1 et <= v2026.28.1 | Accès non autorisé aux propriétés de la fonction Lambda du connecteur (exposition d'informations potentiellement sensibles) | Un acteur disposant d'un accès légitime à Neptune via Athena peut récupérer des propriétés de la Lambda du connecteur, susceptibles de contenir des secrets ou identifiants, ouvrant la voie à une escalade de privilèges ou à un mouvement latéral dans l'environnement AWS. | None | Mettre à jour Athena Federated Query vers la version v2026.30.1 ou ultérieure et corriger tout fork ou code dérivé. Mesures alternatives : désactiver le query passthrough sur le connecteur, restreindre l'action athena:StartQueryExecution sur le catalogue Neptune, ou garantir que les requêtes passthrough ne contiennent que du Gremlin, openCypher ou SPARQL. | [https://aws.amazon.com/security/security-bulletins/rss/2026-087-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-087-aws/)<br>[https://infosec.exchange/@securityfeed/117243384290139523](https://infosec.exchange/@securityfeed/117243384290139523) |
| **CVE-2026-75897** | N/A | N/A | FALSE | OpenSearch Dashboards (open-source auto-géré) versions 1.3.0 à 3.7.0 incluses (dont 2.x jusqu'à 2.19.6) ; Kibana 7.7.1 à 7.10.2 ; Amazon OpenSearch Service (moteurs 1.3, 2.11, 2.13, 2.15, 2.17, 2.19, 3.1, 3.3, 3.5 et compatibilité Elasticsearch/Kibana 7.9-7.10). Amazon OpenSearch Serverless non affecté. | Consommation non contrôlée de ressources (déni de service) - validation d'entrée insuffisante sur la route capabilities | Déni de service à distance d'OpenSearch Dashboards (épuisement des ressources), perturbant l'accès aux fonctions de visualisation et de gestion des clusters OpenSearch. | None | Open-source : migrer vers OpenSearch Dashboards 3.8.0 ou ultérieur. Amazon OpenSearch Service : appliquer la dernière mise à jour logicielle de service disponible pour chaque version affectée. Serverless : aucune action. Contournements : placer une couche d'authentification (reverse proxy, load balancer, SAML/OIDC/Cognito/basic-auth) devant Dashboards - la route n'étant alors atteignable qu'après authentification - et restreindre l'accès réseau au point de terminaison Dashboards. | [https://aws.amazon.com/security/security-bulletins/rss/2026-082-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-082-aws/)<br>[https://infosec.exchange/@securityfeed/117243384290139523](https://infosec.exchange/@securityfeed/117243384290139523) |
| **CVE-2026-18656** | N/A | N/A | FALSE | Kiro IDE pour Windows, versions 1.0.0 à 1.0.212 (bulletin commun avec CVE-2026-18657 concernant Kiro CLI) | Élément de chemin de recherche non contrôlé (uncontrolled search path) menant à l'exécution de code arbitraire | Exécution de code arbitraire sur le poste Windows de l'utilisateur, avec ses privilèges, à la simple ouverture d'un répertoire de projet piégé - risque de compromission de poste de développeur et de vol d'identifiants (tokens, clés). | None | Mettre à jour Kiro IDE vers la version 1.0.228 ou ultérieure (et Kiro CLI vers v2.10.0 ou ultérieure pour l'autre CVE du même bulletin). Aucun contournement disponible : appliquer le correctif en priorité et éviter d'ouvrir des répertoires de projet de provenance non fiable. | [https://aws.amazon.com/security/security-bulletins/rss/2026-074-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-074-aws/)<br>[https://infosec.exchange/@securityfeed/117243384290139523](https://infosec.exchange/@securityfeed/117243384290139523) |
| **CVE-2026-18657** | N/A | N/A | FALSE | Kiro CLI pour Windows, versions antérieures à v2.10.0 (bulletin commun avec CVE-2026-18656 concernant Kiro IDE) | Élément de chemin de recherche non contrôlé (uncontrolled search path) menant à l'exécution de code arbitraire | Exécution de code arbitraire sur le poste Windows de l'utilisateur, avec ses privilèges, à l'ouverture d'un répertoire de projet piégé - compromission potentielle du poste de développeur et des identifiants qu'il contient. | None | Mettre à jour Kiro CLI vers la version v2.10.0 ou ultérieure (et Kiro IDE vers 1.0.228 ou ultérieure pour l'autre CVE du même bulletin). Aucun contournement disponible : appliquer le correctif en priorité et éviter d'ouvrir des répertoires de projet de provenance non fiable. | [https://aws.amazon.com/security/security-bulletins/rss/2026-074-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-074-aws/)<br>[https://infosec.exchange/@securityfeed/117243384290139523](https://infosec.exchange/@securityfeed/117243384290139523) |
| **CVE-2026-84942** | N/A | N/A | FALSE | OpenSearch Dashboards (open-source auto-géré) v2.0.0 à v3.5.0 (corrigé en v2.19.5 et v3.6.0) ; Amazon OpenSearch Service managé versions v2.3.0 à v3.5.0 (mise à jour logicielle de service disponible pour toutes les versions affectées). Amazon OpenSearch Serverless non affecté. | Cross-Site Scripting stocké (XSS) via contournement de la validation des fonctions d'expression Vega | Exécution de JavaScript dans le navigateur des autres utilisateurs : vol de cookies de session, actions effectuées au nom des victimes, compromission possible de comptes à privilèges d'administration de Dashboards. | None | Open-source : mettre à jour vers OpenSearch Dashboards 2.19.5 ou 3.6.0 ou ultérieur (durcissement de la validation des expressions Vega). Amazon OpenSearch Service : appliquer la dernière version logicielle de service (pas de changement de moteur requis ; mise à jour automatique possible hors pic). Contournements : restreindre l'accès en écriture aux API visualization/saved-objects aux utilisateurs de confiance et, optionnellement, désactiver le type de visualisation Vega. | [https://aws.amazon.com/security/security-bulletins/rss/2026-102-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-102-aws/)<br>[https://infosec.exchange/@securityfeed/117243384290139523](https://infosec.exchange/@securityfeed/117243384290139523) |
| **CVE-2026-78379** | N/A | N/A | FALSE | strands-agents-tools (outil python_repl de Strands Agents Tools), versions antérieures à 0.8.5 | Contournement de consentement (neutralisation d'entrée insuffisante pour le prompt LLM) menant à l'exécution de code arbitraire | Exécution de code Python arbitraire sur l'hôte de l'agent IA sans validation humaine, avec les privilèges de l'agent : compromission de l'hôte, exfiltration de données et pivot vers les systèmes accessibles. | None | Mettre à jour strands-agents-tools vers la version 0.8.5 ou ultérieure. Contournements : retirer batch ou python_repl de la liste d'outils de l'agent (le contournement exige que les deux soient enregistrés sur le même agent), ne pas rendre python_repl accessible à un agent traitant du contenu non fiable, et exécuter tout agent utilisant python_repl dans un environnement isolé à moindre privilège. | [https://aws.amazon.com/security/security-bulletins/rss/2026-089-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-089-aws/)<br>[https://infosec.exchange/@securityfeed/117243384290139523](https://infosec.exchange/@securityfeed/117243384290139523) |
| **CVE-2026-87491** | 8.8 | N/A | FALSE | Google Chrome versions antérieures à 153.0.8010.36 (Linux et Windows) et antérieures à 153.0.8010.37 (Mac) | Écriture hors limites (CWE-787) dans le moteur JavaScript/WebAssembly V8 - exécution de code arbitraire dans le sandbox du navigateur | Exécution de code arbitraire à distance dans le sandbox du navigateur : compromission du processus renderer, exposition potentielle de données du processus, et tremplin vers une compromission complète de l'endpoint si la faille est chaînée avec une évasion de sandbox ou une élévation de privilèges. | Active | Mettre à jour Chrome vers 153.0.8010.36/.37 ou supérieur, ainsi que les navigateurs basés sur Chromium après propagation du correctif amont ; déployer les mises à jour par GPO/MDM en priorité ; sensibiliser aux liens web malveillants ; surveiller les crashes de renderer et les processus enfants anormaux des navigateurs. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1139/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1139/)<br>[https://chromereleases.googleblog.com/2026/09/stable-channel-update-for-desktop_0808145027.html](https://chromereleases.googleblog.com/2026/09/stable-channel-update-for-desktop_0808145027.html)<br>[https://thehackernews.com/2026/09/chrome-v8-zero-day-exploited-in-wild.html](https://thehackernews.com/2026/09/chrome-v8-zero-day-exploited-in-wild.html)<br>[https://www.security.nl/posting/952293/Google+patcht+ruim+200+kwetsbaarheden+in+Chrome%2C+waaronder+misbruikt+lek?channel=rss](https://www.security.nl/posting/952293/Google+patcht+ruim+200+kwetsbaarheden+in+Chrome%2C+waaronder+misbruikt+lek?channel=rss)<br>[https://securityaffairs.com/198757/security/google-fixes-the-seventh-actively-exploited-chrome-zero-day-of-2026.html](https://securityaffairs.com/198757/security/google-fixes-the-seventh-actively-exploited-chrome-zero-day-of-2026.html)<br>[https://socprime.com/blog/cve-2026-87491-chrome-v8-zero-day-exploited/](https://socprime.com/blog/cve-2026-87491-chrome-v8-zero-day-exploited/)<br>[https://theperimetersite.com/report/243](https://theperimetersite.com/report/243) |
| **CVE-2026-58649** | N/A | N/A | FALSE | .NET 8.0/9.0/10.0/11.0, ASP.NET Core 8.0/9.0/10.0/11.0 et .NET Framework 3.5/4.6.2-4.8.1 installés sur Linux, macOS et Windows (versions antérieures aux correctifs de septembre 2026) | Multiples vulnérabilités (exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, atteinte à la confidentialité des données) | Selon la CVE exploitée : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance ou divulgation de données confidentielles sur les systèmes exécutant des versions non corrigées de .NET, ASP.NET Core ou .NET Framework. | None | Appliquer les mises à jour de sécurité Microsoft de septembre 2026 : .NET 8.0.130/8.0.424, 9.0.120/9.0.317, 10.0.111/10.0.400, .NET 11 RC1, ASP.NET Core 8.0.31, 9.0.20, 10.0.12 et 11.0 RC1, ainsi que les builds .NET Framework 4.7.4145.0, 4.8.4806.0 et 4.8.9347.0 (se référer aux bulletins MSRC de chaque CVE). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1146/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1146/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58649](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58649) |
| **CVE-2026-85880** | 7.8 | N/A | TRUE | Windows 10 (versions 1607, 1809, 21H2, 22H2), Windows Server 2012, 2012 R2, 2016, 2019 et 2022 (installations Server Core incluses) ; Windows 11 et Windows Server 2025 ne figurent pas dans le périmètre déclaré | Dépassement de tampon basé sur le tas (heap-based buffer overflow) dans le noyau Windows menant à une élévation de privilèges locaux (LPE) | Élévation de privilèges au niveau SYSTEM, permettant à un attaquant ayant obtenu une exécution de code dans le navigateur de prendre le contrôle complet du poste, d'y déployer des charges utiles (loaders, extensions de navigateur malveillantes) et de poursuivre des opérations d'espionnage. | Active | Appliquer en priorité les mises à jour de sécurité Microsoft de septembre 2026 ; maintenir Chrome et les navigateurs basés sur Chromium à jour ; renforcer la protection anti-phishing (filtrage des liens, sensibilisation) ; déployer des détections EDR sur les injections de DLL et les élévations de privilèges anormales ; appliquer le moindre privilège sur les postes de travail. | [https://thehackernews.com/2026/09/four-spy-groups-used-same-chrome-and.html](https://thehackernews.com/2026/09/four-spy-groups-used-same-chrome-and.html)<br>[https://www.proofpoint.com/us/blog/threat-insight/once-bluemoon-multiple-state-aligned-threat-actors-rapidly-adopt-novel-exploit](https://www.proofpoint.com/us/blog/threat-insight/once-bluemoon-multiple-state-aligned-threat-actors-rapidly-adopt-novel-exploit)<br>[https://www.security.nl/posting/952290/Microsoft+dicht+bijna+duizend+beveiligingslekken+tijdens+patchdinsdag+september?channel=rss](https://www.security.nl/posting/952290/Microsoft+dicht+bijna+duizend+beveiligingslekken+tijdens+patchdinsdag+september?channel=rss)<br>[https://thehackernews.com/2026/09/microsoft-patches-record-974-flaws.html](https://thehackernews.com/2026/09/microsoft-patches-record-974-flaws.html)<br>[https://securityaffairs.com/198705/security/microsofts-biggest-patch-tuesday-974-cves-2-zero-days-and-20-wormable-bugs.html](https://securityaffairs.com/198705/security/microsofts-biggest-patch-tuesday-974-cves-2-zero-days-and-20-wormable-bugs.html)<br>[https://socprime.com/blog/cve-2026-85880-and-cve-2026-81963-analysis/](https://socprime.com/blog/cve-2026-85880-and-cve-2026-81963-analysis/)<br>[https://arstechnica.com/information-technology/2026/09/4-groups-caught-using-the-same-chrome-and-windows-exploit-kit/](https://arstechnica.com/information-technology/2026/09/4-groups-caught-using-the-same-chrome-and-windows-exploit-kit/)<br>[https://theperimetersite.com/report/243](https://theperimetersite.com/report/243) |
| **CVE-2026-85046** | 8.8 | N/A | FALSE | Google Chrome et navigateurs basés sur Chromium (faille corrigée en amont dans le code source Chromium avant propagation vers les versions stables - situation de patch gap) | Confusion de types (type confusion) dans le moteur V8 – exécution de code à distance dans le sandbox | Exécution de code arbitraire dans le sandbox du navigateur à la simple consultation d'une page HTML piégée ; combinée à l'échappement de sandbox et à la LPE Windows, elle conduit à une compromission complète du poste de travail et au déploiement de charges utiles d'espionnage. | Active | Appliquer sans délai les mises à jour stables de Chrome/Chromium et d'Edge pour réduire la fenêtre de patch gap ; corriger Windows contre CVE-2026-85880 pour briser la chaîne d'exploitation ; surveiller les indicateurs liés aux quatre groupes identifiés ; renforcer la détection des chaînes navigateur vers LPE. | [https://thehackernews.com/2026/09/four-spy-groups-used-same-chrome-and.html](https://thehackernews.com/2026/09/four-spy-groups-used-same-chrome-and.html)<br>[https://www.proofpoint.com/us/blog/threat-insight/once-bluemoon-multiple-state-aligned-threat-actors-rapidly-adopt-novel-exploit](https://www.proofpoint.com/us/blog/threat-insight/once-bluemoon-multiple-state-aligned-threat-actors-rapidly-adopt-novel-exploit)<br>[https://thehackernews.com/2026/09/chrome-v8-zero-day-exploited-in-wild.html](https://thehackernews.com/2026/09/chrome-v8-zero-day-exploited-in-wild.html)<br>[https://securityaffairs.com/198757/security/google-fixes-the-seventh-actively-exploited-chrome-zero-day-of-2026.html](https://securityaffairs.com/198757/security/google-fixes-the-seventh-actively-exploited-chrome-zero-day-of-2026.html)<br>[https://arstechnica.com/information-technology/2026/09/4-groups-caught-using-the-same-chrome-and-windows-exploit-kit/](https://arstechnica.com/information-technology/2026/09/4-groups-caught-using-the-same-chrome-and-windows-exploit-kit/) |
| **CVE-2026-81963** | 7.8 | N/A | TRUE | Windows 11 (versions 23H2, 24H2, 25H2, 26H1) et Windows Server 2025 (Server Core inclus) ; le correctif est déployé pour toutes les versions prises en charge de Windows | Résolution de liens incorrecte avant accès aux fichiers (CWE-59) couplée à un contrôle d'accès incorrect (CWE-284) dans la pile Windows Update - élévation de privilèges locale | Élévation de privilèges locale vers SYSTEM à partir d'un premier accès, permettant le contrôle complet du système et l'enchaînement avec des techniques de post-exploitation (persistance, vol de credentials, mouvement latéral). | Active | Appliquer les mises à jour de septembre 2026 sur toutes les versions prises en charge de Windows ; prioriser selon le catalogue KEV (échéance 22/09/2026) ; surveiller les processus Windows Update et les écritures anormales de fichiers système ; déployer les détections d'élévation de privilèges et de modifications de composants système. | [https://www.security.nl/posting/952290/Microsoft+dicht+bijna+duizend+beveiligingslekken+tijdens+patchdinsdag+september?channel=rss](https://www.security.nl/posting/952290/Microsoft+dicht+bijna+duizend+beveiligingslekken+tijdens+patchdinsdag+september?channel=rss)<br>[https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-september-2026/](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-september-2026/)<br>[https://thehackernews.com/2026/09/microsoft-patches-record-974-flaws.html](https://thehackernews.com/2026/09/microsoft-patches-record-974-flaws.html)<br>[https://securityaffairs.com/198705/security/microsofts-biggest-patch-tuesday-974-cves-2-zero-days-and-20-wormable-bugs.html](https://securityaffairs.com/198705/security/microsofts-biggest-patch-tuesday-974-cves-2-zero-days-and-20-wormable-bugs.html)<br>[https://socprime.com/blog/cve-2026-85880-and-cve-2026-81963-analysis/](https://socprime.com/blog/cve-2026-85880-and-cve-2026-81963-analysis/)<br>[https://theperimetersite.com/report/243](https://theperimetersite.com/report/243) |
| **CVE-2026-55007** | 8.1 | N/A | FALSE | Microsoft Exchange Server | Exécution de code à distance (RCE) pré-authentification via l'envoi d'un e-mail avec pièce jointe Visio | Compromission des serveurs Exchange (RCE sans authentification ni interaction utilisateur), avec risques d'exfiltration des messageries, de déploiement de webshells, de pivot vers l'Active Directory et de mouvement latéral. | None | Appliquer les mises à jour de septembre 2026 en priorité sur tous les serveurs Exchange ; ne pas exposer Exchange directement à Internet (publication via reverse proxy/VPN) ; restreindre les types de pièces jointes en amont ; journaliser et surveiller les processus enfants anormaux (w3wp.exe) et les requêtes suspectes ; déployer un EDR sur les serveurs de messagerie. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1149/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1149/)<br>[https://www.security.nl/posting/952290/Microsoft+dicht+bijna+duizend+beveiligingslekken+tijdens+patchdinsdag+september?channel=rss](https://www.security.nl/posting/952290/Microsoft+dicht+bijna+duizend+beveiligingslekken+tijdens+patchdinsdag+september?channel=rss)<br>[https://thehackernews.com/2026/09/microsoft-patches-record-974-flaws.html](https://thehackernews.com/2026/09/microsoft-patches-record-974-flaws.html) |
| **CVE-2026-69414** | 7.8 | N/A | FALSE | Moteur de protection contre les programmes malveillants Microsoft (Malware Protection Engine) / Microsoft Defender - toutes versions prises en charge de Windows | Élévation de privilèges dans le moteur antimalware - lecture arbitraire de fichiers avec privilèges SYSTEM (selon le PoC publié) | Lecture de fichiers arbitraires avec les privilèges SYSTEM (ruche SAM, secrets, clés privées, fichiers de configuration), sans interaction utilisateur ; contournement potentiel de mécanismes de protection ; risque d'abus par des acteurs cherchant à affaiblir les défenses endpoint. | Theoretical | Vérifier que le moteur Malware Protection est en version ≥ 1.1.26080.3 et que les mises à jour automatiques des définitions sont actives ; surveiller les correctifs Microsoft à venir pour le contournement ShieldCrash ; restreindre les ACL sur les fichiers sensibles (SAM, secrets, clés) ; surveiller les comportements anormaux de MsMpEng ; suivre les publications du chercheur et les avis des éditeurs concernés. | [https://thehackernews.com/2026/09/researcher-drops-new-microsoft-defender.html](https://thehackernews.com/2026/09/researcher-drops-new-microsoft-defender.html)<br>[https://securityaffairs.com/198726/security/chaotic-eclipse-released-shieldcrash-a-poc-for-microsoft-defender-zero-day.html](https://securityaffairs.com/198726/security/chaotic-eclipse-released-shieldcrash-a-poc-for-microsoft-defender-zero-day.html) |
| **CVE-2026-71114** | 6.1 | N/A | FALSE | Oracle VirtualBox (périphérique virtuel VirtioSCSI) | Lecture hors limites (out-of-bounds read) — divulgation d'informations | Divulgation d'informations sensibles dans le contexte de l'hyperviseur depuis une VM compromise disposant de code à privilèges élevés ; risque de fuite de secrets résidant en mémoire de l'hyperviseur et étape préalable potentielle à une évasion de machine virtuelle. | None | Appliquer les correctifs du CPU Oracle d'août 2026 (hxxps://www[.]oracle.com/security-alerts/cspuaug2026[.]html) ; limiter l'exécution de code privilégié dans les invités ; surveiller les accès aux périphériques virtuels ; segmenter les environnements de virtualisation sensibles. | [http://www.zerodayinitiative.com/advisories/ZDI-26-641/](http://www.zerodayinitiative.com/advisories/ZDI-26-641/) |
| **CVE-2026-71132** | 5.3 | N/A | FALSE | Oracle VirtualBox (périphérique virtuel VirtioSCSI) | Utilisation de mémoire non initialisée — divulgation d'informations | Divulgation d'informations sensibles dans le contexte de l'hyperviseur depuis une VM compromise avec code à privilèges élevés ; exposition potentielle de données résiduelles en mémoire (secrets, credentials) et vecteur préalable à une évasion de VM. | None | Appliquer les correctifs du CPU Oracle d'août 2026 (hxxps://www[.]oracle.com/security-alerts/cspuaug2026[.]html) ; restreindre les privilèges dans les invités ; surveiller les périphériques virtuels ; segmenter les environnements de virtualisation. | [http://www.zerodayinitiative.com/advisories/ZDI-26-640/](http://www.zerodayinitiative.com/advisories/ZDI-26-640/) |
| **CVE-2026-71116** | 7.5 | N/A | FALSE | Oracle VirtualBox (périphérique graphique VMSVGA) | Débordement de tampon basé sur le tas (heap-based buffer overflow) — élévation de privilèges locale | Élévation de privilèges et exécution de code arbitraire dans le contexte de l'hyperviseur depuis un invité compromis : compromission potentielle de l'hôte de virtualisation et de l'ensemble des VM hébergées (évasion de VM). | None | Appliquer les correctifs du CPU Oracle d'août 2026 (hxxps://www[.]oracle.com/security-alerts/cspuaug2026[.]html) ; désactiver l'accélération 3D si non nécessaire ; restreindre le code privilégié dans les invités ; surveiller les processus hyperviseur. | [http://www.zerodayinitiative.com/advisories/ZDI-26-639/](http://www.zerodayinitiative.com/advisories/ZDI-26-639/) |
| **CVE-2026-60414** | 7.8 | N/A | FALSE | Oracle Outside In Technology (analyse de fichiers WPS) | Corruption mémoire lors de l'analyse de fichiers — exécution de code à distance | Exécution de code arbitraire dans le contexte du processus courant sur les systèmes traitant des fichiers WPS ; compromission possible des serveurs de prévisualisation/conversion de documents et pivot vers le réseau interne. | None | Appliquer les correctifs du CPU Oracle d'août 2026 (hxxps://www[.]oracle.com/security-alerts/cspuaug2026[.]html) ; filtrer les types de fichiers entrants ; sandboxer le traitement de documents ; sensibiliser aux fichiers provenant de sources non fiables. | [http://www.zerodayinitiative.com/advisories/ZDI-26-638/](http://www.zerodayinitiative.com/advisories/ZDI-26-638/) |
| **CVE-2026-60413** | 7.8 | N/A | FALSE | Oracle Outside In Technology (analyse de fichiers GEM) | Dépassement d'entier (integer overflow) lors de l'analyse de fichiers — exécution de code à distance | Exécution de code arbitraire dans le contexte du processus courant sur les systèmes traitant des fichiers GEM ; compromission possible des serveurs de traitement documentaire et rebond vers le réseau interne. | None | Appliquer les correctifs du CPU Oracle d'août 2026 (hxxps://www[.]oracle.com/security-alerts/cspuaug2026[.]html) ; filtrer les types de fichiers entrants ; sandboxer le traitement de documents ; sensibiliser aux fichiers de sources non fiables. | [http://www.zerodayinitiative.com/advisories/ZDI-26-637/](http://www.zerodayinitiative.com/advisories/ZDI-26-637/) |
| **CVE-2026-60412** | 7.8 | N/A | FALSE | Oracle Outside In Technology (analyse de fichiers PostScript) | Débordement de tampon basé sur le tas (heap-based buffer overflow) lors de l'analyse de fichiers — exécution de code à distance | Exécution de code arbitraire dans le contexte du processus courant sur les systèmes traitant des fichiers PostScript ; compromission possible des serveurs de traitement documentaire et rebond vers le réseau interne. | None | Appliquer les correctifs du CPU Oracle d'août 2026 (hxxps://www[.]oracle.com/security-alerts/cspuaug2026[.]html) ; filtrer les fichiers PostScript entrants ; sandboxer le traitement de documents ; sensibiliser aux fichiers de sources non fiables. | [http://www.zerodayinitiative.com/advisories/ZDI-26-636/](http://www.zerodayinitiative.com/advisories/ZDI-26-636/) |
| **CVE-2026-60392** | 7.8 | N/A | FALSE | Oracle Outside In Technology (analyse de fichiers PDF) | Dépassement d'entier (integer overflow) lors de l'analyse de fichiers — exécution de code à distance | Exécution de code arbitraire dans le contexte du processus courant sur les systèmes traitant des PDF ; compromission possible des serveurs de prévisualisation/conversion de documents et rebond vers le réseau interne. | None | Appliquer les correctifs du CPU Oracle d'août 2026 (hxxps://www[.]oracle.com/security-alerts/cspuaug2026[.]html) ; filtrer et sandboxer les PDF entrants ; exécuter le parsing à faibles privilèges ; sensibiliser aux PDF de sources non fiables. | [http://www.zerodayinitiative.com/advisories/ZDI-26-635/](http://www.zerodayinitiative.com/advisories/ZDI-26-635/) |
| **CVE-2026-20293** | N/A | N/A | FALSE | Cisco Intersight Server Firmware (versions antérieures à 5.4(0.260042) / 5.4(0.260050)1), Cisco UCS Server Software (branches 1.2, 2.0, 4.0, 4.2, 4.3, 6.0 antérieures aux correctifs listés), Cisco NFVIS (antérieur à 4.15.7), UCS XE-Series Server Firmware (antérieur à 6.0(2.260143)), UCSE BIOS (antérieur à 4.041), UCSE Software (antérieur à 4.15.4-b1) | Contournement de la politique de sécurité (bypass de Secure Boot UEFI) | Contournement de la politique de sécurité au démarrage (Secure Boot UEFI) : possibilité pour un attaquant ayant un accès approprié d'exécuter du code non signé au démarrage, de compromettre l'intégrité du firmware et de établir une persistance pré-OS sur les serveurs affectés. | None | Se référer au bulletin Cisco cisco-sa-ucs-uefi-sb-bypass-eb6xC5GW pour l'obtention des correctifs et mettre à jour les firmwares concernés (Intersight Server Firmware, UCS Server Software, NFVIS, UCSE) ; vérifier l'activation de Secure Boot ; restreindre les accès physiques et au plan de management. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1138/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1138/)<br>[https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucs-uefi-sb-bypass-eb6xC5GW](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucs-uefi-sb-bypass-eb6xC5GW) |
| **CVE-2026-44756** | 10.0 | N/A | FALSE | SAP Kernel / Extended Passport (EPP) Processing : KRNL64NUC 7.22, 7.22EXT ; KRNL64UC 7.22, 7.22EXT, 7.53, 8.04 ; KERNEL 7.22, 7.53, 7.54, 7.77, 7.89, 7.93, 8.04, 9.16, 9.18, 9.19, 9.20 ; WEBDISP 9.16, 9.18, 9.19, 9.20. Impacte les produits s'appuyant sur le noyau vulnérable : S/4HANA, ERP/Business Suite (ECC), NetWeaver, Web Dispatcher, BW/4HANA, Enterprise Portal, PI/PO, Solution Manager. | Corruption mémoire (validation de bornes manquante lors de la désérialisation des données EPP) permettant une exécution de code à distance non authentifiée | Exécution de commandes OS arbitraires avec privilèges d'administration SAP sur l'hôte, conduisant à la compromission totale des données et processus métier : lecture du secure store (identifiants de base de données, hachages de mots de passe), lecture des sessions actives des utilisateurs connectés, extraction d'identifiants stockés pour mouvement latéral vers les autres systèmes SAP, et modification des données applicatives, de la configuration et des binaires SAP. | None | Appliquer immédiatement la SAP Security Note 3747649 (correctifs des noyaux ABAP et Java et versions supportées du Web Dispatcher) après inventaire complet du paysage SAP. Ne pas compter sur un seul contrôle réseau car la faille est joignable via plusieurs protocoles sans identifiants : restreindre l'exposition Internet, segmenter, surveiller les requêtes vers les services SAP exposés, les comportements anormaux des serveurs applicatifs et les exécutions de processus inattendues sous les comptes OS SAP. | [https://cert.europa.eu/publications/security-advisories/2026-011/](https://cert.europa.eu/publications/security-advisories/2026-011/)<br>[https://thehackernews.com/2026/09/sap-patches-cvss-100-kernel-flaw.html](https://thehackernews.com/2026/09/sap-patches-cvss-100-kernel-flaw.html)<br>[https://www.cisecurity.org/advisory/a-vulnerability-in-sap-extended-passport-epp-processing-could-allow-for-remote-code-execution_2026-092](https://www.cisecurity.org/advisory/a-vulnerability-in-sap-extended-passport-epp-processing-could-allow-for-remote-code-execution_2026-092)<br>[https://socprime.com/blog/cve-2026-44756-sap-kernel-rce-vulnerability/](https://socprime.com/blog/cve-2026-44756-sap-kernel-rce-vulnerability/) |
| **CVE-2026-58240** | 9.8 | N/A | FALSE | SAP NetWeaver Message Server (composant BC-CST-MS) : KERNEL 9.16, 9.18, 9.19, 9.20 — lignes de noyau 9.x sur lesquelles tournent SAP S/4HANA et SAP S/4HANA Cloud Private Edition, et potentiellement d'autres produits basés ABAP. | Vérification d'authentification manquante (défaut logique) dans le Message Server permettant l'enregistrement de composants non autorisés et l'exécution de code à distance | Un attaquant non authentifié, sans identifiants, certificat ni mauvaise configuration préexistante, obtient une exécution de code à distance complète sous le compte OS <sid>adm (utilisateur exécutant SAP) sur chaque serveur applicatif du cluster, avec un impact élevé sur la confidentialité, l'intégrité et la disponibilité du système et des données métier. | None | Appliquer la SAP Security Note 3759472 dès que possible pour mettre à jour les versions KERNEL 9.x affectées. En complément, surveiller les enregistrements de composants auprès du Message Server, restreindre au maximum l'accès réseau au port du Message Server dans les limites des besoins de logon SAP GUI, et préparer la rotation des identifiants <sid>adm en cas de suspicion de compromission. | [https://cert.europa.eu/publications/security-advisories/2026-011/](https://cert.europa.eu/publications/security-advisories/2026-011/)<br>[https://thehackernews.com/2026/09/sap-patches-cvss-100-kernel-flaw.html](https://thehackernews.com/2026/09/sap-patches-cvss-100-kernel-flaw.html) |
| **CVE-2026-76969** | 9.4 | N/A | FALSE | Applications multi-locataires utilisant SAP Cloud Application Programming Model (CAP). | Divulgation d'identifiants (credential disclosure) permettant à un attaquant non authentifié d'obtenir des informations sensibles | Exposition d'identifiants sensibles à un attaquant non authentifié, réutilisables pour remplacer ou supprimer des données dans les applications multi-locataires affectées, avec un impact élevé sur la confidentialité et l'intégrité. | None | Appliquer les correctifs SAP publiés dans le cadre du Patch Day de septembre 2026 pour les applications CAP affectées, et rotater les identifiants potentiellement exposés. | [https://thehackernews.com/2026/09/sap-patches-cvss-100-kernel-flaw.html](https://thehackernews.com/2026/09/sap-patches-cvss-100-kernel-flaw.html) |
| **CVE-2026-87930** | 9.2 | N/A | FALSE | MaxSite CMS jusqu'à la version 109.6 incluse (éditeur : Maxsite, produit : cms). | Injection d'objets PHP (PHP Object Injection, CWE-502) via désérialisation de données non fiables (cookie ci_session passé à unserialize() sans restriction de classes) | Un attaquant non authentifié peut injecter des objets PHP via un cookie forgé, corrompre l'état de l'application et potentiellement exécuter du code si des classes gadget sont présentes, avec un impact élevé sur la confidentialité et l'intégrité du système. | Theoretical | Mettre à jour MaxSite CMS vers une version restreignant l'usage de unserialize() et protégeant les cookies de session ; passer à la dernière version ; revoir et sécuriser les clés de chiffrement des cookies de session ; supprimer ou restreindre les classes gadget ; assainir toutes les entrées utilisateur. | [https://cvefeed.io/vuln/detail/CVE-2026-87930](https://cvefeed.io/vuln/detail/CVE-2026-87930) |
| **CVE-2026-87929** | 9.8 | N/A | FALSE | MaxSite CMS jusqu'à la version 109.6 incluse (éditeur : Maxsite, produit : cms). | Contournement d'authentification via clé cryptographique codée en dur (CWE-321 : Use of Hard-coded Cryptographic Key) | Un attaquant non authentifié peut forger des cookies de session avec privilèges administrateur, contourner entièrement l'authentification et prendre le contrôle de l'application (modification de contenu, de configuration, potentiellement pivot vers d'autres attaques). | Theoretical | Mettre à jour MaxSite CMS vers une version imposant le changement de la clé de chiffrement de session ; passer à la dernière version ; changer la clé de chiffrement de session codée en dur dans la configuration ; déployer l'application mise à jour en production. | [https://cvefeed.io/vuln/detail/CVE-2026-87929](https://cvefeed.io/vuln/detail/CVE-2026-87929) |
| **CVE-2026-87927** | 8.8 | N/A | FALSE | MaxSite CMS jusqu'à la version 109.6 incluse (éditeur : Maxsite, produit : cms). | Inclusion locale de fichiers (LFI, CWE-98 : contrôle improper du nom de fichier pour les instructions include/require) via les dispatchers ajax et require-maxsite | Un attaquant non authentifié peut exécuter des fichiers de handlers privilégiés sans authentification en contournant la validation de chemin, accédant à des fonctionnalités sensibles de l'application (impact élevé sur l'intégrité et la confidentialité). | Theoretical | Mettre à jour MaxSite CMS vers une version postérieure à 109.6 corrigeant l'inclusion locale de fichiers et la traversée de chemin ; supprimer ou désactiver les fonctionnalités de dispatcher non nécessaires ; assainir toutes les entrées utilisateur contre la traversée de chemin. | [https://cvefeed.io/vuln/detail/CVE-2026-87927](https://cvefeed.io/vuln/detail/CVE-2026-87927) |
| **CVE-2026-18851** | N/A | N/A | FALSE | Ivanti Endpoint Manager Mobile (EPMM) : versions 12.9.x antérieures à 12.9.0.2 et versions antérieures à 12.8.0.4. | Vulnérabilité dans Ivanti EPMM (le type précis n'est pas détaillé dans l'avis CERT-FR ; l'avis global couvre des risques d'exécution de code arbitraire à distance, d'élévation de privilèges et de contournement de la politique de sécurité) | Dans le cadre de l'avis CERT-FR, certaines des vulnérabilités couvertes permettent à un attaquant de provoquer une exécution de code arbitraire à distance, une élévation de privilèges et un contournement de la politique de sécurité ; la compromission d'EPMM expose la gestion de l'ensemble du parc mobile (politiques, appareils, données). | None | Se référer au bulletin de sécurité Ivanti (Security Advisory - Ivanti Endpoint Manager Mobile CVE-2026-18851 du 8 septembre 2026) pour obtenir les correctifs et mettre à niveau EPMM vers 12.9.0.2, 12.8.0.4 ou versions ultérieures. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1135/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1135/) |
| **CVE-2026-83527** | N/A | N/A | FALSE | Ivanti Sentry : versions antérieures à R10.6.4, versions R10.7.x antérieures à R10.7.3, versions R10.8.x antérieures à R10.8.2. | Vulnérabilité dans Ivanti Sentry (le type précis n'est pas détaillé dans l'avis CERT-FR ; l'avis global couvre des risques d'exécution de code arbitraire à distance, d'élévation de privilèges et de contournement de la politique de sécurité) | Dans le cadre de l'avis CERT-FR, certaines des vulnérabilités couvertes permettent à un attaquant de provoquer une exécution de code arbitraire à distance, une élévation de privilèges et un contournement de la politique de sécurité ; la compromission de Sentry, passerelle de sécurisation des communications (Active Sync, Kerberos, LDAP), peut affecter les services d'authentification intégrés. | None | Se référer au bulletin de sécurité Ivanti (Security Advisory - Ivanti Sentry CVE-2026-83527 du 8 septembre 2026) pour obtenir les correctifs et mettre à niveau Sentry vers R10.6.4, R10.7.3, R10.8.2 ou versions ultérieures. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1135/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1135/) |
| **CVE-2026-82563** | 8.4 | N/A | FALSE | Softish C6 Ear Camera et application Android EarVision | Contournement d'authentification par usurpation (CWE-290 - Authentication Bypass by Spoofing) | Manipulation des réponses d'état du périphérique, observation des requêtes de l'application et déclenchement potentiel d'un comportement de mise à jour du firmware, ouvrant la voie à une exploitation en chaîne (notamment avec CVE-2026-77974 pour pousser un firmware via un canal non authentifié). | None | Mettre en œuvre une authentification mutuelle pour toutes les communications du périphérique, valider rigoureusement les certificats et l'identité du périphérique, chiffrer tous les canaux de communication sensibles et auditer régulièrement les journaux d'accès du périphérique. Référence : avis CISA CSAF va-26-251-01. | [https://cvefeed.io/vuln/detail/CVE-2026-82563](https://cvefeed.io/vuln/detail/CVE-2026-82563)<br>[https://raw.githubusercontent.com/cisagov/CSAF/refs/heads/develop/csaf_files/VA/white/2026/va-26-251-01.json](https://raw.githubusercontent.com/cisagov/CSAF/refs/heads/develop/csaf_files/VA/white/2026/va-26-251-01.json) |
| **CVE-2026-81640** | 8.8 | N/A | FALSE | Softish C6 Ear Camera et application Android EarVision | Utilisation d'identifiants codés en dur (CWE-798 - Use of Hard-coded Credentials) | Affaiblissement ou annulation de la valeur de sécurité du mot de passe du point d'accès, avec exposition potentielle du flux vidéo en direct, des services du périphérique, des interfaces de statut et de la fonctionnalité de mise à jour du firmware. | None | Changer le mot de passe Wi-Fi par défaut, mettre en œuvre une authentification forte pour l'accès au périphérique, sécuriser la configuration du réseau sans fil et mettre à jour le firmware vers la dernière version. Référence : avis CISA CSAF va-26-251-01. | [https://cvefeed.io/vuln/detail/CVE-2026-81640](https://cvefeed.io/vuln/detail/CVE-2026-81640)<br>[https://raw.githubusercontent.com/cisagov/CSAF/refs/heads/develop/csaf_files/VA/white/2026/va-26-251-01.json](https://raw.githubusercontent.com/cisagov/CSAF/refs/heads/develop/csaf_files/VA/white/2026/va-26-251-01.json) |
| **CVE-2026-77974** | 8.5 | N/A | FALSE | Softish C6 Ear Camera et application Android EarVision | Absence d'authentification pour une fonction critique (CWE-306 - Missing Authentication for Critical Function) | Possibilité de faire transmettre un firmware arbitraire vers le périphérique via un canal non authentifié et non signé, conduisant à un compromission complète du périphérique (exécution de firmware malveillant). | None | Mettre en œuvre des mécanismes robustes d'authentification du périphérique, imposer des mises à jour firmware signées, valider l'intégrité du canal de mise à jour et restreindre les permissions de mise à jour. Référence : avis CISA CSAF va-26-251-01. | [https://cvefeed.io/vuln/detail/CVE-2026-77974](https://cvefeed.io/vuln/detail/CVE-2026-77974)<br>[https://raw.githubusercontent.com/cisagov/CSAF/refs/heads/develop/csaf_files/VA/white/2026/va-26-251-01.json](https://raw.githubusercontent.com/cisagov/CSAF/refs/heads/develop/csaf_files/VA/white/2026/va-26-251-01.json) |
| **CVE-2026-60155** | 7.5 | N/A | FALSE | Oracle VirtualBox (composant VMSVGA) | Condition de course (race condition) menant à une élévation de privilèges locale | Élévation de privilèges et exécution de code arbitraire dans le contexte de l'hyperviseur, soit une évasion de machine virtuelle depuis un invité compromis vers l'hôte. | None | Appliquer la mise à jour Oracle publiée dans le Critical Patch Update de juillet 2026 (hxxps://www[.]oracle[.]com/security-alerts/cpujul2026[.]html). Limiter les privilèges administrateur dans les invités et restreindre l'accès local aux hôtes de virtualisation. | [http://www.zerodayinitiative.com/advisories/ZDI-26-644/](http://www.zerodayinitiative.com/advisories/ZDI-26-644/)<br>[https://www.oracle.com/security-alerts/cpujul2026.html](https://www.oracle.com/security-alerts/cpujul2026.html) |
| **CVE-2026-60162** | 6.1 | N/A | FALSE | Oracle VirtualBox (composant VMSVGA) | Lecture hors limites (out-of-bounds read) menant à une divulgation d'informations | Divulgation d'informations sensibles depuis le contexte de l'hyperviseur ; la fuite peut être exploitée en combinaison avec d'autres vulnérabilités pour escalader les privilèges et exécuter du code arbitraire dans le contexte de l'hyperviseur. | None | Appliquer la mise à jour Oracle publiée dans le Critical Patch Update de juillet 2026 (hxxps://www[.]oracle[.]com/security-alerts/cpujul2026[.]html). Limiter les privilèges administrateur dans les invités. | [http://www.zerodayinitiative.com/advisories/ZDI-26-643/](http://www.zerodayinitiative.com/advisories/ZDI-26-643/)<br>[https://www.oracle.com/security-alerts/cpujul2026.html](https://www.oracle.com/security-alerts/cpujul2026.html) |
| **CVE-2026-60159** | 7.5 | N/A | FALSE | Oracle VirtualBox (composant IDisplay) | Lecture hors limites (out-of-bounds read) menant à une élévation de privilèges locale | Élévation de privilèges et exécution de code arbitraire dans le contexte de l'hyperviseur, soit une évasion de machine virtuelle depuis un invité compromis vers l'hôte. | None | Appliquer la mise à jour Oracle publiée dans le Critical Patch Update de juillet 2026 (hxxps://www[.]oracle[.]com/security-alerts/cpujul2026[.]html). Limiter les privilèges administrateur dans les invités et restreindre l'accès local aux hôtes de virtualisation. | [http://www.zerodayinitiative.com/advisories/ZDI-26-642/](http://www.zerodayinitiative.com/advisories/ZDI-26-642/)<br>[https://www.oracle.com/security-alerts/cpujul2026.html](https://www.oracle.com/security-alerts/cpujul2026.html) |
| **CVE-2026-87995** | 8.7 | N/A | FALSE | Open WebUI versions 0.8.11 à 0.11.0 (exclue) | XSS same-origin menant à une prise de contrôle de compte (CWE-79, CWE-1021) via iframe de preview de port terminal avec allow-same-origin codé en dur | Prise de contrôle du compte de la victime (account takeover) lors de l'ouverture d'une preview de port, avec accès aux fonctionnalités et données de la plateforme AI auto-hébergée sous l'identité de la victime. | None | Mettre à jour Open WebUI vers la version 0.11.1 ou ultérieure et revoir les configurations de sécurité associées (références : hxxps://github[.]com/open-webui/open-webui/security/advisories/GHSA-jmc6-2wr8-h3wj et hxxps://github[.]com/open-webui/open-webui/releases/tag/v0.11.1). | [https://cvefeed.io/vuln/detail/CVE-2026-87995](https://cvefeed.io/vuln/detail/CVE-2026-87995)<br>[https://github.com/open-webui/open-webui/security/advisories/GHSA-jmc6-2wr8-h3wj](https://github.com/open-webui/open-webui/security/advisories/GHSA-jmc6-2wr8-h3wj)<br>[https://github.com/open-webui/open-webui/releases/tag/v0.11.1](https://github.com/open-webui/open-webui/releases/tag/v0.11.1) |
| **CVE-2026-87016** | 8.1 | N/A | FALSE | Open WebUI versions 0.6.41 à 0.11.0 (exclue) avec backend SQLite | Authentification défaillante (CWE-287) et neutralisation incorrecte des caractères génériques (CWE-155) : connexion en tant qu'un autre utilisateur via le claim subject OAuth | Prise de contrôle de comptes, y compris des comptes administrateur, via l'émission de la session d'un autre utilisateur, compromettant l'intégralité de l'instance Open WebUI. | None | Mettre à jour Open WebUI vers la version 0.11.1, revoir les configurations OAuth pour détecter les caractères génériques et surveiller les journaux d'accès utilisateur pour toute activité suspecte (références : hxxps://github[.]com/open-webui/open-webui/security/advisories/GHSA-wpmr-8h3q-fwj7 et hxxps://github[.]com/open-webui/open-webui/releases/tag/v0.11.1). | [https://cvefeed.io/vuln/detail/CVE-2026-87016](https://cvefeed.io/vuln/detail/CVE-2026-87016)<br>[https://github.com/open-webui/open-webui/security/advisories/GHSA-wpmr-8h3q-fwj7](https://github.com/open-webui/open-webui/security/advisories/GHSA-wpmr-8h3q-fwj7)<br>[https://github.com/open-webui/open-webui/releases/tag/v0.11.1](https://github.com/open-webui/open-webui/releases/tag/v0.11.1) |
| **CVE-2026-8044** | 8.6 | N/A | FALSE | Produits Schneider Electric concernés par l'avis SEVD-2026-251-01 (versions exactes non encore recensées) | Injection d'arguments (CWE-88) menant à une exécution de code à distance | Exécution de code à distance par un attaquant disposant d'un compte privilégié, via des arguments malveillants injectés dans les paramètres de configuration de sauvegarde. | None | Valider et neutraliser toutes les entrées utilisateur utilisées dans les commandes ; éviter d'exécuter des commandes externes avec des arguments fournis par l'utilisateur ; implémenter des contrôles d'accès stricts pour les comptes privilégiés ; appliquer les correctifs de l'éditeur dès leur disponibilité (avis SEVD-2026-251-01). | [https://cvefeed.io/vuln/detail/CVE-2026-8044](https://cvefeed.io/vuln/detail/CVE-2026-8044) |
| **CVE-2026-19233** | 8.6 | N/A | FALSE | Serveur web des produits Schneider Electric concernés par l'avis SEVD-2026-251-01 (versions exactes non encore recensées) | Server-Side Request Forgery (SSRF, CWE-918) | Exécution de commandes non autorisée et divulgation de données du serveur ; possibilité de rebond vers des services internes via des requêtes forgées côté serveur. | None | Valider et neutraliser tous les paramètres côté serveur ; implémenter une validation stricte des paramètres des points de terminaison ; restreindre l'accès réseau sortant du serveur ; appliquer les correctifs ou mises à jour de l'éditeur (avis SEVD-2026-251-01). | [https://cvefeed.io/vuln/detail/CVE-2026-19233](https://cvefeed.io/vuln/detail/CVE-2026-19233) |
| **CVE-2025-53521** | 9.8 | N/A | TRUE | F5 BIG-IP Access Policy Manager (APM) : versions 17.5.0–17.5.1, 17.1.0–17.1.2, 16.1.0–16.1.6, 15.1.0–15.1.10, lorsqu'une politique d'accès APM est configurée sur un serveur virtuel | RCE non authentifiée (CVE-2025-53521, initialement classée déni de service puis reclassée RCE) exploitée pour déployer le rootkit fileless PoisonedRefresh injectant un web shell PHP en mémoire | Web shell en mémoire permettant l'exécution de commandes via des requêtes web ordinaires, indétectable par scan disque ; persistance via httpd infecté, rc.local et images d'upgrade ; contournement de SELinux ; compromission furtive et durable des appliances, y compris propagation via les supports d'installation. | Active | Appliquer les versions corrigées : 17.5.1.3, 17.1.3, 16.1.6.1, 15.1.10.8 (le correctif d'octobre 2025 reste valide et protège contre l'exploitation) ; suivre les guides F5 de remédiation et d'évaluation de compromission avant tout durcissement générique Apache/PHP ; reconstruire les appliances depuis des images saines vérifiées ; surveiller les IOCs F5 (scripts apm_css.php3, full_wt.php3, webtop_popup_css.php3 — leur présence seule ne constitue pas une preuve de compromission). | [https://thehackernews.com/2026/09/f5-big-ip-apm-malware-injects-php-web.html](https://thehackernews.com/2026/09/f5-big-ip-apm-malware-injects-php-web.html)<br>[https://securityaffairs.com/198746/malware/poisonedrefresh-a-fileless-linux-rootkit-that-injects-php-web-shells-into-f5-big-ip-apm-server-memory.html](https://securityaffairs.com/198746/malware/poisonedrefresh-a-fileless-linux-rootkit-that-injects-php-web-shells-into-f5-big-ip-apm-server-memory.html) |
| **CVE-2026-62437** | N/A | N/A | FALSE | Xen - toutes versions dépourvues du dernier correctif de sécurité (correctifs XSA-509 à XSA-513) | Multiples vulnérabilités : exécution de code arbitraire, déni de service à distance et contournement de la politique de sécurité | Sur un hôte de virtualisation, l'exploitation peut permettre l'exécution de code arbitraire dans le contexte de l'hyperviseur, un déni de service à distance de l'hôte ou le contournement de la politique de sécurité, avec un risque d'évasion de machine virtuelle et de compromission de l'ensemble des VM hébergées (cloud privé, IaaS, infrastructures mutualisées). | None | Appliquer sans délai les correctifs Xen correspondant aux XSA-509 à XSA-513 ; mettre à jour l'hyperviseur puis redémarrer les hôtes selon les recommandations de l'éditeur ; restreindre l'accès aux interfaces d'administration et aux périphériques virtuels exposés ; surveiller les avis CERT-FR et les futures XSA. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1136/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1136/)<br>[https://xenbits.xen.org/xsa/advisory-509.html](https://xenbits.xen.org/xsa/advisory-509.html)<br>[https://xenbits.xen.org/xsa/advisory-510.html](https://xenbits.xen.org/xsa/advisory-510.html)<br>[https://xenbits.xen.org/xsa/advisory-511.html](https://xenbits.xen.org/xsa/advisory-511.html)<br>[https://xenbits.xen.org/xsa/advisory-512.html](https://xenbits.xen.org/xsa/advisory-512.html)<br>[https://xenbits.xen.org/xsa/advisory-513.html](https://xenbits.xen.org/xsa/advisory-513.html) |
| **CVE-2026-78546** | N/A | N/A | FALSE | Citrix Workspace app pour Windows : versions antérieures à 2507.1 LTSR CU3, versions antérieures à 2603.11 et versions antérieures à 2607 LTSR | Multiples vulnérabilités - problème de sécurité non spécifié par l'éditeur | Non détaillé par l'éditeur ; en tant que client d'accès aux bureaux et applications virtuels, un Workspace app compromis peut servir de vecteur d'attaque contre les postes de travail et les environnements VDI/Citrix (accès aux ressources publiées, vol d'identifiants de session, pivot vers l'infrastructure d'accès distant). | None | Mettre à jour Citrix Workspace app pour Windows vers 2507.1 LTSR CU3, 2603.11 ou 2607 LTSR (ou versions ultérieures) en se référant au bulletin CTX697034 ; déployer les mises à jour via l'outil de gestion de parc ; sensibiliser les utilisateurs aux fichiers .ica non sollicités. | [https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697034&articleURL=Citrix_Workspace_app_for_Windows_Security_Bulletin_CVE_2026_78546_and_CVE_2026_78547](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697034&articleURL=Citrix_Workspace_app_for_Windows_Security_Bulletin_CVE_2026_78546_and_CVE_2026_78547) |
| **CVE-2026-21269** | N/A | N/A | FALSE | Adobe Acrobat 2024 versions antérieures à 24.001.30429, Adobe Acrobat et Acrobat Reader versions antérieures à 26.002.21901 (Windows/macOS) ; ColdFusion 2023 antérieur à 2023.0.24 et ColdFusion 2025 antérieur à 2025.0.13 ; Adobe Commerce versions 2.4.5-x à 2.4.9-x antérieures aux builds 2026-sep ; Adobe Commerce B2B versions 1.3.x à 1.5.3-x antérieures aux builds 2026-sep ; Magento Open Source versions antérieures à 2.4.7-2026-sep, 2.4.8-2026-sep et 2.4.9-2026-sep | Multiples vulnérabilités : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, injection de code indirecte (XSS), injection SQL (SQLi), contournement de la politique de sécurité, atteinte à la confidentialité des données | Compromission possible de serveurs ColdFusion et de plateformes e-commerce (exécution de code à distance, injection SQL, accès aux données clients), élévation de privilèges, atteinte à la confidentialité des données, déni de service, et exploitation de documents PDF malveillants contre les postes de travail via Acrobat/Reader (RCE côté client). | None | Appliquer les mises à jour APSB26-119 (ColdFusion 2023 >= 2023.0.24, ColdFusion 2025 >= 2025.0.13), APSB26-138 (Adobe Commerce, Adobe Commerce B2B et Magento Open Source en builds 2026-sep) et APSB26-141 (Acrobat >= 24.001.30429 / 26.002.21901) ; restreindre l'exposition des consoles d'administration ; surveiller les bulletins de sécurité Adobe. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1140/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1140/)<br>[https://helpx.adobe.com/security/products/coldfusion/apsb26-119.html](https://helpx.adobe.com/security/products/coldfusion/apsb26-119.html)<br>[https://helpx.adobe.com/security/products/magento/apsb26-138.html](https://helpx.adobe.com/security/products/magento/apsb26-138.html)<br>[https://helpx.adobe.com/security/products/acrobat/apsb26-141.html](https://helpx.adobe.com/security/products/acrobat/apsb26-141.html) |
| **CVE-2026-86853** | N/A | N/A | FALSE | Mozilla Firefox pour iOS, versions antérieures à 155.1 | Déni de service à distance | Un attaquant peut rendre le navigateur indisponible ou le faire planter à distance (déni de service), perturbant l'accès des utilisateurs aux ressources web sur les terminaux iOS non corrigés. Aucun impact direct sur la confidentialité ou l'intégrité des données n'est signalé. | None | Mettre à jour Firefox pour iOS vers la version 155.1 ou supérieure (App Store / MDM) en se référant au bulletin mfsa2026-89 ; vérifier ensuite la conformité du parc mobile. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1142/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1142/)<br>[https://www.mozilla.org/en-US/security/advisories/mfsa2026-89/](https://www.mozilla.org/en-US/security/advisories/mfsa2026-89/) |
| **CVE-2026-12858** | N/A | N/A | FALSE | ESET AV Remover, versions antérieures à 1.6.17.0 | Élévation de privilèges | Un attaquant disposant d'un accès initial limité (compte standard ou code exécuté localement) peut élever ses privilèges via AV Remover, facilitant la persistance, le contournement des contrôles de sécurité et le mouvement latéral. | None | Mettre à jour ESET AV Remover vers la version 1.6.17.0 ou supérieure (bulletin ca9000) ; restreindre l'exécution de l'outil aux administrateurs et aux fenêtres de maintenance. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1143/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1143/)<br>[https://support-feed.eset.com/link/15370/17443273/ca9000](https://support-feed.eset.com/link/15370/17443273/ca9000) |
| **CVE-2026-70341** | N/A | N/A | FALSE | Microsoft Edge pour Android, iOS, Linux, macOS et Windows, versions antérieures à 152.0.4191.52 | Exécution de code arbitraire à distance | Compromission du poste de travail : un attaquant peut exécuter du code arbitraire dans le contexte de l'utilisateur (par exemple via une page web malveillante), accéder aux données locales, déployer des charges utiles et pivoter vers le réseau interne. | None | Mettre à jour Microsoft Edge vers la version 152.0.4191.52 ou supérieure (WSUS, Intune, mise à jour automatique) et vérifier la version via edge://version ; sensibiliser les utilisateurs aux liens malveillants. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1144/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1144/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-70341](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-70341) |
| **CVE-2026-62804, CVE-2026-64918, CVE-2026-69285, CVE-2026-69442, CVE-2026-69477, CVE-2026-69529, CVE-2026-69556, CVE-2026-69614, CVE-2026-69626, CVE-2026-69629, CVE-2026-69632, CVE-2026-69671, CVE-2026-69678, CVE-2026-69686, CVE-2026-69719, CVE-2026-69722, CVE-2026-69734, CVE-2026-69739, CVE-2026-69742, CVE-2026-69759, CVE-2026-69764, CVE-2026-69767, CVE-2026-69778, CVE-2026-69797, CVE-2026-72938, CVE-2026-72956, CVE-2026-72972, CVE-2026-72973, CVE-2026-72974, CVE-2026-72975, CVE-2026-72976, CVE-2026-72977, CVE-2026-77898, CVE-2026-77901, CVE-2026-77911, CVE-2026-78439, CVE-2026-78502, CVE-2026-78503, CVE-2026-78504, CVE-2026-78505, CVE-2026-78506, CVE-2026-78507, CVE-2026-78509, CVE-2026-78510, CVE-2026-78511, CVE-2026-78512, CVE-2026-78513, CVE-2026-78514** | N/A | N/A | FALSE | Microsoft Office et ses composants (48 CVE corrigées — liste complète dans l'avis CERT-FR CERTFR-2026-AVI-1145) | Multiples vulnérabilités (exécution de code à distance, élévation de privilèges, divulgation d'informations, déni de service) | Selon la CVE exploitée : exécution de code arbitraire à distance (ouverture d'un document piégé), élévation de privilèges sur le poste, atteinte à la confidentialité des données ou déni de service. Surface d'attaque très large compte tenu de l'omniprésence d'Office en environnement professionnel. | None | Appliquer en priorité les mises à jour de sécurité Microsoft du 08/09/2026 pour l'ensemble des composants Office ; consulter le guide MSRC pour chaque CVE et prioriser les vulnérabilités de type RCE ; bloquer les macros et fichiers à risque en attendant la conformité du parc. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1145/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1145/) |
| **CVE-2026-62895, CVE-2026-69854, CVE-2026-77909, CVE-2026-81349, CVE-2026-83948** | N/A | N/A | FALSE | Azure Arc SQL Server Extension < 1.1.3518.465 ; Azure CycleCloud < 8.9.2 ; Azure HDInsight < 2606012120 ; Microsoft Azure CLI < 2.2.1 ; Spring Cloud Azure < 7.4.0 | Multiples vulnérabilités (exécution de code arbitraire à distance, élévation de privilèges, atteinte à la confidentialité des données) | Compromission de ressources cloud : exécution de code sur des services Azure, élévation de privilèges dans l'environnement (RBAC, identités managées) et exposition/exfiltration potentielle de données sensibles hébergées. | None | Mettre à jour chaque composant : Azure Arc SQL Server Extension ≥ 1.1.3518.465, Azure CycleCloud ≥ 8.9.2, Azure HDInsight ≥ 2606012120, Azure CLI ≥ 2.2.1, Spring Cloud Azure ≥ 7.4.0 ; revoir les rôles RBAC et auditer les journaux d'activité Azure. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1148/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1148/)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62895](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62895)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69854](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69854)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-77909](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-77909)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-81349](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-81349)<br>[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-83948](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-83948) |
| **CVE-2026-88069** | 9.3 | N/A | FALSE | Pandora (pandora-analysis) — worker d'extraction d'archives, versions non précisées | Path traversal (CWE-22) — écriture de fichiers arbitraire hors du répertoire d'extraction | Écrasement de fichiers applicatifs ou système accessibles au processus Pandora, déni de service du service d'analyse et compromission potentielle du serveur (jusqu'à l'exécution de code) selon les permissions du worker et les fichiers écrasables. | Theoretical | Appliquer le correctif officiel (hxxps://github[.]com/pandora-analysis/pandora/commit/d86ac5b260fb9a41e07f1da1bbd326cdcfc188a7) : résolution et validation des chemins d'extraction, rejet des traversées de répertoires ; exécuter le worker avec des permissions minimales dans un environnement confiné (conteneur, chroot, montage en lecture seule). | [https://cvefeed.io/vuln/detail/CVE-2026-88069](https://cvefeed.io/vuln/detail/CVE-2026-88069)<br>[https://github.com/pandora-analysis/pandora/commit/d86ac5b260fb9a41e07f1da1bbd326cdcfc188a7](https://github.com/pandora-analysis/pandora/commit/d86ac5b260fb9a41e07f1da1bbd326cdcfc188a7) |
| **CVE-2026-79322** | 8.6 | N/A | FALSE | Mageplaza Blog extension pour Magento 2 (mageplaza/magento-2-blog-extension), versions ≤ 4.3.2 | Injection SQL (CWE-89), exploitable à distance sans authentification | Lecture arbitraire du contenu de la base Magento : données clients (PII), hachages de mots de passe, commandes, jetons ; risque d'exfiltration massive, de manipulation des données et, selon la configuration du SGBD, de compromission plus étendue du serveur. | Theoretical | Mettre à jour l'extension Mageplaza Blog vers la dernière version corrigée ; à défaut, désactiver le module ; imposer des requêtes paramétrées et la validation/neutralisation des entrées côté code ; déployer des règles WAF bloquant les motifs d'injection SQL sur /mpblog/post/view. | [https://cvefeed.io/vuln/detail/CVE-2026-79322](https://cvefeed.io/vuln/detail/CVE-2026-79322)<br>[https://gist.github.com/mrtantoine/417ee9b774f022bd747211b9eadc0069](https://gist.github.com/mrtantoine/417ee9b774f022bd747211b9eadc0069) |
| **CVE-2026-54694** | N/A | N/A | FALSE | skills-service (NationalSecurityAgency) | XSS stockée (Stored XSS) via l'enregistrement utilisateur | Prise de contrôle de comptes privilégiés, exécution d'actions administratives non autorisées, compromission de l'ensemble de la plateforme et vol potentiel de données de session. | Theoretical | Appliquer le correctif éditeur dès sa publication, assainir toutes les entrées utilisateur, implémenter des politiques CSP, restreindre l'auto-enregistrement et sensibiliser aux liens malveillants. | [https://cvefeed.io/vuln/detail/CVE-2026-54694](https://cvefeed.io/vuln/detail/CVE-2026-54694) |
| **CVE-2026-87874** | 8.1 | N/A | FALSE | Collection Ansible community.general (plugin de cache memcached) - Red Hat Ceph Storage et Red Hat OpenStack Platform concernés | Désérialisation de données non fiables (CWE-502) menant à un RCE par empoisonnement de cache | Exécution de code à distance sur le contrôleur Ansible avec ses privilèges, compromission des secrets (Vault, clés SSH) et pivot possible vers l'ensemble de l'infrastructure gérée par Ansible. Exploitation à distance possible (CVSS 3.1 : 8.1 HIGH). | Theoretical | Mettre à jour la collection community.general, désactiver la sérialisation pickle pour memcached, limiter l'accès réseau à memcached, activer l'authentification SASL/TLS et protéger le contrôleur Ansible. | [https://cvefeed.io/vuln/detail/CVE-2026-87874](https://cvefeed.io/vuln/detail/CVE-2026-87874)<br>[https://access.redhat.com/security/cve/CVE-2026-87874](https://access.redhat.com/security/cve/CVE-2026-87874)<br>[https://bugzilla.redhat.com/show_bug.cgi?id=2530995](https://bugzilla.redhat.com/show_bug.cgi?id=2530995) |
| **CVE-2026-77120** | 8.7 | N/A | FALSE | Console du système d'exploitation (produits Schneider Electric, avis SEVD-2026-251-02) | Injection de commande OS (CWE-78) avec escalade de privilèges | Escalade de privilèges au niveau root, exécution non autorisée de fonctions administratives et compromission totale de l'équipement concerné, avec un risque élevé en environnement OT/ICS. | Theoretical | Assainir et valider les entrées de commandes OS, appliquer le correctif du SEVD-2026-251-02, désactiver SSH si non requis et restreindre l'accès à la console. | [https://cvefeed.io/vuln/detail/CVE-2026-77120](https://cvefeed.io/vuln/detail/CVE-2026-77120)<br>[https://download.se.com/files?p_Doc_Ref=SEVD-2026-251-02&p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2026-251-02.pdf](https://download.se.com/files?p_Doc_Ref=SEVD-2026-251-02&p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2026-251-02.pdf) |
| **CVE-2026-47156** | 9.3 | N/A | FALSE | MantisBT versions 2.28.3 et antérieures (API SOAP) | Contournement d'authentification (CWE-287, CWE-639) avec escalade de privilèges vers administrateur | Prise de contrôle du compte administrateur, accès à l'ensemble des bugs et pièces jointes, exécution d'actions administratives, dépôt potentiel de web shell (CAPEC-650). Exploitable à distance sans accès préalable sur les installations par défaut. | Theoretical | Mettre à jour vers MantisBT 2.28.4 (aucun contournement disponible), désactiver l'auto-enregistrement si non nécessaire et restreindre l'exposition réseau de l'API SOAP. | [https://cvefeed.io/vuln/detail/CVE-2026-47156](https://cvefeed.io/vuln/detail/CVE-2026-47156)<br>[https://github.com/mantisbt/mantisbt/security/advisories/GHSA-c2xg-qjqw-2v98](https://github.com/mantisbt/mantisbt/security/advisories/GHSA-c2xg-qjqw-2v98)<br>[https://github.com/mantisbt/mantisbt/commit/e3571c319b1721b41b0dc4b5b5203cbdcbe0c2ee](https://github.com/mantisbt/mantisbt/commit/e3571c319b1721b41b0dc4b5b5203cbdcbe0c2ee)<br>[https://mantisbt.org/bugs/view.php?id=37121](https://mantisbt.org/bugs/view.php?id=37121) |
| **CVE-2026-18147** | 8.1 | N/A | FALSE | FreeIPA / IdM Web UI (page de réinitialisation de mot de passe) - Red Hat Enterprise Linux | Cross-Site Scripting DOM (CWE-79) | Exécution d'actions dans la session de la victime, pouvant mener à un contrôle administratif complet de l'infrastructure IdM si un administrateur est ciblé (compromission Kerberos/LDAP, création de comptes, vol de secrets). CVSS 3.1 : 8.1 HIGH, exploitable à distance. | Theoretical | Appliquer les dernières mises à jour de sécurité FreeIPA, assainir toutes les entrées utilisateur, éviter le rendu direct des données fournies par l'utilisateur et déployer des en-têtes CSP. | [https://cvefeed.io/vuln/detail/CVE-2026-18147](https://cvefeed.io/vuln/detail/CVE-2026-18147)<br>[https://access.redhat.com/security/cve/CVE-2026-18147](https://access.redhat.com/security/cve/CVE-2026-18147)<br>[https://bugzilla.redhat.com/show_bug.cgi?id=2508181](https://bugzilla.redhat.com/show_bug.cgi?id=2508181) |
| **CVE-2026-79689** | 9.8 | N/A | FALSE | Dell Secure Connect Gateway (SCG) 5.0 Appliance versions < 5.36.00.16 et SCG 5.0 Application versions < 5.36.00.00 | Injection de commande OS (CWE-78) en pré-authentification | Exécution de commandes/scripts à distance sans authentification sur la passerelle, compromission de l'appliance et pivot potentiel vers l'infrastructure supervisée via la connectivité support Dell. | Theoretical | Mettre à jour l'appliance SCG vers 5.36.00.16 ou supérieur et l'application vers 5.36.00.00 ou supérieur (DSA-2026-382), et restreindre l'exposition réseau des interfaces SCG. | [https://cvefeed.io/vuln/detail/CVE-2026-79689](https://cvefeed.io/vuln/detail/CVE-2026-79689)<br>[https://www.dell.com/support/kbdoc/en-in/000503426/dsa-2026-382-security-update-for-dell-secure-connect-gateway-virtual-edition-multiple-vulnerabilities](https://www.dell.com/support/kbdoc/en-in/000503426/dsa-2026-382-security-update-for-dell-secure-connect-gateway-virtual-edition-multiple-vulnerabilities) |
| **CVE-2026-68484** | 9.0 | N/A | FALSE | Sage Cash Collect (API Sage AR Automation) | Défaut d'autorisation (CWE-862 - Missing Authorization) | Élévation de privilèges vers administrateur, création de comptes non autorisés, accès et manipulation potentielle des données de recouvrement et des comptes clients. | Theoretical | Appliquer les correctifs du vendor (June R2 Release 2026), vérifier que tous les appels API administratifs valident les privilèges utilisateur et supprimer tout compte administrateur non autorisé créé. | [https://cvefeed.io/vuln/detail/CVE-2026-68484](https://cvefeed.io/vuln/detail/CVE-2026-68484)<br>[https://helpcenter.sara.sage.com/hc/en-us/articles/52106283946651-June-R2-Release-2026](https://helpcenter.sara.sage.com/hc/en-us/articles/52106283946651-June-R2-Release-2026) |
| **CVE-2026-82533** | 9.4 | N/A | FALSE | DeepSeek Harness (outil open source d'exécution d'agents de codage IA), versions 0.1.1-rc.2 et antérieures | Évasion de sandbox par appel à l'interface web locale non authentifiée (contrôle basé uniquement sur l'en-tête Host fourni par le client) | Exécution de commandes hors du sandbox sans approbation sur la machine du développeur, écritures hors workspace et récupération de l'intégralité des conversations stockées sans clé d'authentification ; risque de compromission de la machine de développement, des dépôts et des secrets. | Theoretical | Mettre à jour vers 0.1.2-alpha.2 ou ultérieur (0.1.2-rc.1 recommandé) ; ne pas exposer ni rediriger le port de l'interface locale ; exécuter les agents dans des environnements isolés avec moindre privilège ; traiter avec méfiance le contenu non fiable lu par les agents. | [https://thehackernews.com/2026/09/deepseek-harness-flaw-let-ai-agents.html](https://thehackernews.com/2026/09/deepseek-harness-flaw-let-ai-agents.html) |
| **CVE-2026-67401** | N/A | N/A | FALSE | cPanel & WHM — toutes les versions supportées (lignes 11.110, 11.134, 11.136, 11.138 et WP Squared) | Injection SQL dans EmailTrack permettant la création de fichiers arbitraires puis l'exécution de code en tant que root | Prise de contrôle totale du serveur : lecture de tous les comptes d'hébergement, modification des fichiers et bases de données, création de comptes cachés, installation de malware, vol d'identifiants et pivot vers les réseaux clients. | None | Mettre à jour vers les builds corrigés (11.110.0.143, 11.134.0.55, 11.136.0.39, 11.138.0.4, WP Squared 11.138.1.9) via WHM (Home / cPanel / Upgrade to Latest Version) ou en ligne de commande (/usr/local/cpanel/scripts/upcp --force) ; à défaut, restreindre les privilèges mail/EmailTrack ; auditer les serveurs pour détecter une compromission antérieure à la mise à jour. | [https://thehackernews.com/2026/09/new-cpanel-flaw-lets-hosting-account.html](https://thehackernews.com/2026/09/new-cpanel-flaw-lets-hosting-account.html) |
| **CVE-2026-86218** | 10.0 | N/A | TRUE | N-able N-central (corrigé dans N-central 2026.3 Hotfix 4, publié le 5 septembre 2026) | Injection de code statique (static code injection) permettant une exécution de code à distance sans authentification (pre-auth RCE) | Compromission totale du serveur N-central et, par propagation, de l'ensemble des systèmes clients et environnements d'entreprise gérés ; risque élevé de déploiement de ransomware à grande échelle via le canal MSP. | Active | Appliquer immédiatement N-central 2026.3 Hotfix 4 ; ne pas exposer N-central sur Internet ; auditer l'environnement pour des IOCs et activités anormales antérieures au patch (le patching seul ne suffit pas) ; renforcer la journalisation externe ; considérer le chaînage CVE-2026-86206/CVE-2026-86207 comme vecteur alternatif (Hotfix 3). | [https://thehackernews.com/2026/09/n-able-n-central-pre-auth-rce-flaw.html](https://thehackernews.com/2026/09/n-able-n-central-pre-auth-rce-flaw.html) |
| **CVE-2026-86206** | N/A | N/A | FALSE | N-able N-central (corrigé dans N-central 2026.3 Hotfix 3, publié le 5 septembre 2026) | Vulnérabilité d'authentification chaînable avec CVE-2026-86207 pour un contournement d'authentification complet à distance sans identifiants | Création d'un compte System Administrator contrôlé par l'attaquant, donnant un contrôle complet du serveur N-central et, par propagation, des systèmes clients gérés par l'outil. | Theoretical | Appliquer N-central 2026.3 Hotfix 3 ou ultérieur ; surveiller les créations de comptes administrateur ; restreindre l'exposition réseau de N-central ; auditer les comptes existants pour détecter des comptes frauduleux préexistants. | [https://thehackernews.com/2026/09/n-able-n-central-pre-auth-rce-flaw.html](https://thehackernews.com/2026/09/n-able-n-central-pre-auth-rce-flaw.html) |
| **CVE-2026-86207** | N/A | N/A | FALSE | N-able N-central (corrigé dans N-central 2026.3 Hotfix 3, publié le 5 septembre 2026) | Vulnérabilité d'authentification chaînable avec CVE-2026-86206 pour un contournement d'authentification complet à distance sans identifiants | Création d'un compte System Administrator contrôlé par l'attaquant, donnant un contrôle complet du serveur N-central et, par propagation, des systèmes clients gérés par l'outil. | Theoretical | Appliquer N-central 2026.3 Hotfix 3 ou ultérieur ; surveiller les créations de comptes administrateur ; restreindre l'exposition réseau de N-central ; auditer les comptes existants pour détecter des comptes frauduleux préexistants. | [https://thehackernews.com/2026/09/n-able-n-central-pre-auth-rce-flaw.html](https://thehackernews.com/2026/09/n-able-n-central-pre-auth-rce-flaw.html) |
| **CVE-2026-59346** | 7.5 | N/A | FALSE | VMware Workstation (périphérique virtuel VMXNET3) | Dépassement d'entier (integer overflow) lors de la segmentation TSO de VMXNET3, menant à une escalade de privilèges locale | Escalade de privilèges depuis un invité compromis jusqu'à l'exécution de code dans le contexte de l'hyperviseur, avec possibilité d'accéder aux autres machines virtuelles et à l'hôte (scénario d'évasion de VM). | None | Appliquer la mise à jour VMware Workstation publiée par Broadcom (avis de sécurité) ; limiter l'exécution de code à haut privilège dans les invités ; surveiller les anomalies des périphériques virtuels ; isoler les charges de travail sensibles. | [http://www.zerodayinitiative.com/advisories/ZDI-26-647/](http://www.zerodayinitiative.com/advisories/ZDI-26-647/)<br>[https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38288](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38288) |
| **CVE-2026-8037** | 7.2 | N/A | FALSE | Progress Software Kemp LoadMaster | Exécution de code à distance par utilisation de mémoire non initialisée dans la fonction escape_quotes (authentification requise) | Exécution de code en contexte root sur une appliance de répartiteur de charge en position stratégique : interception ou manipulation du trafic, vol de secrets et de sessions, pivot vers les serveurs backend. | None | Appliquer le correctif Progress (bulletin critique juin 2026) ; restreindre l'accès d'administration aux réseaux de gestion ; surveiller les sessions d'administration et les exécutions de commandes ; auditer la configuration des appliances après mise à jour. | [http://www.zerodayinitiative.com/advisories/ZDI-26-646/](http://www.zerodayinitiative.com/advisories/ZDI-26-646/)<br>[https://community.progress.com/s/article/LoadMaster-Critical-Security-Bulletin-June-2026-CVE-2026-8037-CVE-2026-33691](https://community.progress.com/s/article/LoadMaster-Critical-Security-Bulletin-June-2026-CVE-2026-8037-CVE-2026-33691) |
| **CVE-2026-84387** | 7.2 | N/A | FALSE | Fortinet FortiSandbox | Injection de commande via le paramètre cronValue de l'endpoint write_remote_backup_to_crontab (validation insuffisante avant appel système, authentification requise) | Exécution de code en contexte root sur une appliance de sandbox d'analyse de fichiers : compromission de l'appliance, persistance via crontab, accès aux échantillons et résultats d'analyse, pivot potentiel dans le réseau de sécurité. | None | Appliquer le correctif Fortinet (FG-IR-26-167) ; restreindre l'accès d'administration aux réseaux de gestion ; surveiller les modifications de crontab et les sessions d'administration ; auditer les appliances après mise à jour. | [http://www.zerodayinitiative.com/advisories/ZDI-26-645/](http://www.zerodayinitiative.com/advisories/ZDI-26-645/)<br>[https://fortiguard.fortinet.com/psirt/FG-IR-26-167](https://fortiguard.fortinet.com/psirt/FG-IR-26-167) |
| **CVE-2026-70477** | 9.8 | N/A | FALSE | Flowise (fonctionnalité CSV Agent) | Injection de prompt conduisant à l'exécution de code à distance (RCE) — assainissement insuffisant des entrées | Exécution de code à distance non authentifiée sur les instances Flowise exposées, compromission du compte de service, pivot possible vers l'infrastructure et les données accessibles depuis l'hôte. | Theoretical | Appliquer la mise à jour Flowise (commit f4e2794f6a576b94578f2fdafbf49c2fb304626c publié sur hxxps://github[.]com/FlowiseAI/Flowise). En attendant, restreindre l'exposition réseau, imposer une authentification frontale et ne soumettre aux agents CSV que des données de confiance. | [http://www.zerodayinitiative.com/advisories/ZDI-26-634/](http://www.zerodayinitiative.com/advisories/ZDI-26-634/) |
| **CVE-2026-4153** | 7.8 | N/A | FALSE | GIMP (parsing de fichiers PSP / Paint Shop Pro) | Débordement d'entier (integer overflow) avant allocation de buffer lors du parsing de fichiers PSP — exécution de code à distance | Exécution de code arbitraire sur le poste de la victime à l'ouverture d'un fichier PSP piégé, avec les privilèges de l'utilisateur, pouvant mener à une compromission complète du poste. | Theoretical | Mettre à jour GIMP avec le correctif officiel (commit 98cb1371fd4e22cca75017ea3252dc32fc218712 sur hxxps://gitlab[.]gnome[.]org/GNOME/gimp). Ne pas ouvrir de fichiers PSP de provenance inconnue et filtrer ce format en passerelle. | [http://www.zerodayinitiative.com/advisories/ZDI-26-633/](http://www.zerodayinitiative.com/advisories/ZDI-26-633/) |
| **CVE-2026-13086** | 8.8 | N/A | FALSE | WatchGuard FireWare OS (service Endpoint Protection Manager / epm connect) | Débordement de buffer basé sur la pile (stack-based buffer overflow) — exécution de code à distance | Exécution de code en tant que root sur le pare-feu, compromission totale de l'appliance : interception du trafic, modification de règles, pivot vers le réseau interne, persistance au niveau du périphérique de sécurité. | Theoretical | Appliquer la mise à jour WatchGuard (référence hxxps://psirt[.]watchguard[.]com/CVE-2026-13086). Restreindre l'accès au service EPM et aux interfaces d'administration, segmenter le réseau de management et surveiller les requêtes anormales. | [http://www.zerodayinitiative.com/advisories/ZDI-26-632/](http://www.zerodayinitiative.com/advisories/ZDI-26-632/) |
| **CVE-2026-18444** | 3.3 | N/A | FALSE | NI LabVIEW (parsing de fichiers VI) | Lecture hors bornes (out-of-bounds read) lors du parsing de fichiers VI — divulgation d'informations | Fuite d'informations sensibles présentes en mémoire du processus LabVIEW (fragments de données, secrets éventuels) à l'ouverture d'un fichier VI piégé. Impact limité (confidentialité partielle) mais exploitable en reconnaissance préalable. | Theoretical | Appliquer la mise à jour NI (hxxps://www[.]ni[.]com/en/support/security/available-critical-and-security-updates-for-ni-software/2026/integer-conversion-vulnerability-resulting-in-an-out-of-bounds-read-in-ni-labview[.]html). Ne pas ouvrir de fichiers VI non fiables. | [http://www.zerodayinitiative.com/advisories/ZDI-26-631/](http://www.zerodayinitiative.com/advisories/ZDI-26-631/) |
| **CVE-2026-18445** | 3.3 | N/A | FALSE | NI LabVIEW (parsing de fichiers VI) | Débordement d'entier (integer overflow) avant lecture mémoire lors du parsing de fichiers VI — divulgation d'informations | Fuite d'informations sensibles présentes en mémoire du processus LabVIEW à l'ouverture d'un fichier VI piégé. Impact limité mais cumulable avec d'autres failles en reconnaissance préalable. | Theoretical | Appliquer la mise à jour NI (hxxps://www[.]ni[.]com/en/support/security/available-critical-and-security-updates-for-ni-software/2026/integer-overflow-vulnerability-resulting-in-an-out-of-bounds-write-in-ni-labview[.]html). Ne pas ouvrir de fichiers VI non fiables. | [http://www.zerodayinitiative.com/advisories/ZDI-26-630/](http://www.zerodayinitiative.com/advisories/ZDI-26-630/) |
| **CVE-2026-19820** | 6.1 | N/A | FALSE | Backblaze Personal Computer Backup (service Backblaze, composant bzreports) — Windows | Suivi de lien (link following) — écrasement de fichiers arbitraires conduisant à un déni de service | Déni de service local : écrasement de fichiers arbitraires pouvant dégrader le système, corrompre des données ou empêcher le fonctionnement de la solution de sauvegarde (ce qui peut être exploité par des attaquants pour affaiblir les capacités de restauration). | Theoretical | Mettre à jour le client Backblaze vers la version 10.0.1.1069 (notes de version : hxxps://www[.]backblaze[.]com/computer-backup/docs/backup-client-release-notes-windows). Limiter les privilèges locaux et surveiller la création de liens symboliques. | [http://www.zerodayinitiative.com/advisories/ZDI-26-628/](http://www.zerodayinitiative.com/advisories/ZDI-26-628/) |
| **CVE-2025-25249** | 9.2 | N/A | TRUE | Fortinet FortiGate exécutant FortiOS (interface SSL-VPN) | Absence d'authentification pour une fonction critique (CWE-306) permettant l'exécution de code arbitraire à distance non authentifiée | Exécution de code arbitraire non authentifiée sur le pare-feu de périmètre, installation d'un RAT (PivotC2), pivot vers le réseau interne, risque d'espionnage, de vol de données et de compromission étendue de l'infrastructure. | Active | Appliquer le correctif Fortinet sur tous les FortiGate/FortiOS, vérifier l'intégrité des équipements (réinstallation du firmware si compromission suspectée), restreindre l'exposition du portail SSL-VPN (filtrage IP, MFA), surveiller les communications C2 et réinitialiser identifiants et certificats en cas d'incident avéré. | [https://insomnisec.com/posts/2026-09-09-cve-2025-25249-pivotc2-fortigate_v2/](https://insomnisec.com/posts/2026-09-09-cve-2025-25249-pivotc2-fortigate_v2/) |
| **CVE-2026-43603** | N/A | N/A | FALSE | Pilote de noyau GPU AMD pour Linux (processeurs/cartes EPYC, Athlon, Ryzen, Radeon, Instinct ; correctifs EPYC Embedded et Ryzen Embedded prévus en octobre) | Déréférencement de pointeur NULL (NULL pointer dereference) dans le pilote GPU du noyau Linux | Plantage du système et déni de service (DoS) ; aucune exécution de code ni élévation de privilèges décrites. | None | Appliquer les correctifs AMD publiés en juillet 2026 pour les plateformes concernées, planifier la mise à jour des variantes Embedded pour octobre, maintenir les pilotes GPU à jour et surveiller les crashs noyau. | [https://www.securityweek.com/chipmaker-patch-tuesday-nvidia-amd-arm-issue-security-advisories/](https://www.securityweek.com/chipmaker-patch-tuesday-nvidia-amd-arm-issue-security-advisories/) |
| **CVE-2026-28662** | N/A | N/A | FALSE | Composant System d'Android (faille liée au Wi-Fi) - niveau de patch de sécurité 2026-09-05 | Corruption mémoire liée au Wi-Fi pouvant conduire à une exécution de code à distance (RCE) et à une élévation de privilèges | Exécution de code à distance sans interaction utilisateur via le Wi-Fi, élévation de privilèges potentielle et compromission complète de l'appareil ; le composant System, cœur fonctionnel du téléphone, concentre l'essentiel des failles critiques. | None | Déployer au plus vite le niveau de patch de sécurité 2026-09-05 (ou ultérieur) sur l'ensemble du parc Android ; les mises à jour Wear OS, Android XR et Android Automotive OS intègrent également ces correctifs ; en attendant la mise à jour, restreindre l'usage du Wi-Fi sur les appareils non patchés. | [https://www.securityweek.com/androids-september-2026-updates-patch-180-vulnerabilities/](https://www.securityweek.com/androids-september-2026-updates-patch-180-vulnerabilities/) |
| **** | N/A | N/A | FALSE | Postfix : versions antérieures à 3.5.28 (branche 3.5), 3.6.21 (branche 3.6), 3.7.23 (branche 3.7), 3.8.21 (branche 3.8), 3.9.15 (branche 3.9), 3.10.14 (branche 3.10) et 3.11.7 (branche 3.11) | Multiples vulnérabilités : déni de service à distance et contournement de la politique de sécurité | Un attaquant distant peut provoquer un déni de service du service de messagerie (interruption du flux SMTP, saturation des ressources) et contourner la politique de sécurité (restrictions de relais/accès), impactant la disponibilité du courriel et potentiellement le routage des messages de l'organisation. | None | Mettre à jour Postfix vers la version corrigée de la branche utilisée (3.5.28, 3.6.21, 3.7.23, 3.8.21, 3.9.15, 3.10.14 ou 3.11.7) ; redémarrer le service après mise à jour ; appliquer les recommandations de durcissement de l'éditeur ; surveiller les avis CERT-FR et les annonces Postfix. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1141/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1141/)<br>[http://www.postfix.org/announcements/postfix-3.11.7.html](http://www.postfix.org/announcements/postfix-3.11.7.html) |
| **** | N/A | N/A | FALSE | Microsoft Windows (versions et composants non précisés dans la source) | Multiples vulnérabilités (détails non disponibles dans le flux) | Non évaluable faute de détails ; les vulnérabilités Windows corrigées lors d'un Patch Tuesday incluent classiquement des exécutions de code à distance, des élévations de privilèges et des divulgations d'informations. | None | Appliquer les mises à jour de sécurité Microsoft de septembre 2026 sur l'ensemble des systèmes Windows (serveurs et postes) et vérifier la conformité par scan de vulnérabilités. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1147/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1147/) |
| **** | 5.8 | N/A | FALSE | Microsoft Azure Entra ID (endpoint OAuth Device Code Grant) | Divulgation d'informations via des messages d'erreur contenant des données sensibles | Fuite d'informations organisationnelles internes sur des tenants Entra ID arbitraires, exploitable en phase de reconnaissance (OSINT/CTI) pour préparer des attaques de phishing, de device code phishing ou d'accès initial. | Theoretical | S'assurer du déploiement de la version corrigée (2.1.24394.0). Restreindre le flux device code via l'accès conditionnel, surveiller les tentatives de reconnaissance et sensibiliser aux arnaques par device code. | [http://www.zerodayinitiative.com/advisories/ZDI-26-629/](http://www.zerodayinitiative.com/advisories/ZDI-26-629/) |
| **** | N/A | N/A | FALSE | ScreenConnect (Remote Access Support et Access, déploiements cloud et on-premises) — fonctionnalité de transfert de fichiers | Problème de sécurité affectant le comportement de transfert de fichiers (CVE en cours d'attribution) ; propagation observée de charges malveillantes via les sessions ScreenConnect | Propagation automatisée (type ver) de charges malveillantes via une infrastructure RMM de confiance, persistance, déploiement d'outils d'accès à distance supplémentaires, risque élevé de passage à l'action (déploiement de ransomware, exfiltration) sur l'ensemble des endpoints gérés. | Active | Appliquer les mesures d'atténuation ConnectWise : désactiver temporairement les permissions de transfert de fichiers dans ScreenConnect (cloud et on-premises) jusqu'à la publication du correctif ; auditer les clients ScreenConnect installés (légitimes vs pirates) ; surveiller wscript.exe, la chaîne 1.vbs–4.vbs et la clé Run WindowsServiceHost ; bloquer les outils RMM non autorisés ; sensibiliser aux arnaques au support technique. | [https://fieldeffect.com/blog/screenconnect-vulnerability-worm-like-malware-campaign](https://fieldeffect.com/blog/screenconnect-vulnerability-worm-like-malware-campaign) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="scans-et-force-brute-ciblant-les-serveurs-proxmox-ve-apres-la-publication-dun-avis-de-vulnerabilite"></div>

## Scans et force brute ciblant les serveurs Proxmox VE après la publication d'un avis de vulnérabilité

### Résumé

Le 9 septembre 2026, le SANS Internet Storm Center rapporte une hausse des scans et tentatives de force brute ciblant les serveurs Proxmox VE, environ une semaine après la publication par Proxmox d'un avis révélant une vulnérabilité affectant les anciennes versions de son produit Proxmox Virtual Environment, uniquement la version 7, non supportée depuis environ deux ans. Les observations incluent une augmentation des scans sur le port 8006 et du trafic de force brute contre l'endpoint /api2/json/access/ticket : requêtes POST avec l'utilisateur root@pam et un User-Agent Go-http-client/1.1 (exemple d'IP source : 62.60.130[.]193). Les échecs d'authentification apparaissent en code 401 dans les logs du proxy PVE ; un code 308 apparaît lorsque la première tentative est envoyée sans TLS. Sont également observés un fingerprinting via /pve2/images/logo-128.png et des requêtes POST vers /api2/extjs/access/ticket, endpoint qui retourne toujours 200, une charge utile d'environ 77 octets indiquant un échec de connexion.

---

### Analyse opérationnelle

Surveiller le port 8006 et alerter sur les rafales de codes 401/308 sur /api2/json/access/ticket ; sur l'endpoint /api2/extjs/access/ticket, analyser la taille de la réponse (environ 77 octets = échec) car le log du proxy ne reflète pas l'issue de l'authentification. Détecter le fingerprinting /pve2/images/logo-128.png et l'User-Agent Go-http-client/1.1. Restreindre l'exposition du port 8006 à Internet (VPN/bastion, listes blanches), migrer les instances Proxmox VE 7 (EOL) vers une version supportée, imposer des identifiants forts/MFA sur root@pam et centraliser les logs du proxy PVE.

---

### Implications stratégiques

Les infrastructures de virtualisation en fin de vie exposées constituent une porte d'entrée privilégiée pour des opérations de ransomware ciblant les hyperviseurs. L'attention croissante portée à Proxmox, alternative largement déployée aux solutions historiques de virtualisation, suggère une extension de la surface d'attaque des environnements de virtualisation ; les organisations exploitant des versions non supportées doivent traiter leur mise à niveau comme un risque prioritaire.

---

### Recommandations

* Mettre à niveau Proxmox VE 7 (non supporté) vers une version supportée
* Restreindre l'accès au port 8006 (VPN, bastion, allowlist IP)
* Activer l'authentification forte (MFA) sur root@pam et éliminer les identifiants faibles
* Centraliser et surveiller les logs du proxy PVE (401/308, endpoint extjs, taille de réponse)
* Bloquer les IP sources de force brute observées, ex. 62.60.130[.]193

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les instances Proxmox VE et leurs versions ; prioriser la migration des versions 7 non supportées
* Restreindre l'exposition du port 8006 (VPN, bastion, allowlist IP)
* Activer MFA/mots de passe forts sur root@pam et revoir les comptes à privilèges
* Centraliser les logs du proxy PVE et définir des seuils d'alerte sur les échecs d'authentification

#### Phase 2 — Détection et analyse

* Alerter sur les rafales de codes 401/308 sur /api2/json/access/ticket depuis une même source
* Sur /api2/extjs/access/ticket, analyser la taille de réponse (environ 77 octets = échec) car le code HTTP reste 200
* Détecter les scans du port 8006 et le fingerprinting via /pve2/images/logo-128.png
* Signaler l'User-Agent Go-http-client/1.1 sur les endpoints d'authentification

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les IP sources de force brute au pare-feu
* Révoquer les tickets/sessions actifs et rotationner les identifiants root@pam en cas de suspicion de succès
* Isoler tout nœud compromis du cluster et des réseaux de production
* Restreindre temporairement l'interface de gestion aux sources légitimes

#### Phase 4 — Activités post-incident

* Vérifier dans les logs toute authentification réussie suivant les rafales d'échecs
* Contrôler l'intégrité des VM/conteneurs et rechercher tâches planifiées ou comptes inconnus
* Mettre à niveau la version de Proxmox VE et appliquer l'avis de sécurité
* Mettre à jour les procédures de durcissement et de supervision

#### Phase 5 — Threat Hunting (proactif)

* Rechercher historiquement les patterns 401/308 sur le port 8006
* Chasser les POST vers /api2/extjs/access/ticket avec réponses d'environ 77 octets
* Identifier les instances Proxmox exposées sur Internet (surface externe)
* Rechercher les requêtes de fingerprinting logo-128.png dans les logs du proxy

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| IP | `62.60.130[.]193` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1110.001** | Password Guessing : force brute sur l'endpoint d'authentification Proxmox (/api2/json/access/ticket) avec l'utilisateur root@pam |
| **T1595.002** | Vulnerability Scanning : hausse des scans du port 8006 suite à la publication d'un avis de vulnérabilité Proxmox VE |

---

### Sources

* [https://isc.sans.edu/diary/rss/33324](https://isc.sans.edu/diary/rss/33324)


---

<div id="ingenierie-sociale-sur-le-theme-des-passkeys-menant-a-un-compromis-didentite-et-du-cloud"></div>

## Ingénierie sociale sur le thème des passkeys menant à un compromis d'identité et du cloud

### Résumé

Le 9 septembre 2026, Microsoft publie un article décrivant une campagne d'ingénierie sociale exploitant le thème des passkeys (clés d'authentification) et conduisant à un compromis d'identité et d'environnement cloud. La page référence également le « Cloud Web Applications Threat Matrix », un cadre aligné sur MITRE ATT&CK destiné à aider les défenseurs à comprendre, prioriser et atténuer les menaces pesant sur les applications web hébergées dans le cloud et les plateformes serverless.

---

### Analyse opérationnelle

Les équipes doivent surveiller les inscriptions de nouvelles méthodes d'authentification (passkeys), les changements de méthodes MFA, les connexions anormales et les consentements OAuth inhabituels sur les identités cloud. Les leurres thématiques « passkey » visant l'enrôlement ou la réinitialisation de méthodes d'authentification doivent être intégrés aux règles de détection (accès conditionnel, détection AiTM, journaux d'authentification) et aux campagnes de sensibilisation des utilisateurs.

---

### Implications stratégiques

L'évolution des leurres de phishing vers les thèmes d'authentification (passkeys) illustre l'adaptation des acteurs de menace à l'adoption généralisée du MFA : l'identité devient le périmètre principal à défendre, et son compromis ouvre un accès direct aux environnements cloud et aux données d'entreprise.

---

### Recommandations

* Déployer des méthodes d'authentification résistantes au phishing
* Surveiller et alerter sur les enrôlements de nouvelles méthodes d'authentification et les changements MFA
* Appliquer l'accès conditionnel et la détection de sessions anormales (AiTM, rejeu de tokens)
* Sensibiliser les utilisateurs aux leurres exploitant le thème des passkeys

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer des méthodes d'authentification résistantes au phishing (passkeys matérielles, FIDO2) et l'accès conditionnel
* Journaliser et centraliser les événements d'authentification et d'enrôlement des méthodes MFA/passkeys
* Sensibiliser les utilisateurs aux leurres exploitant les thèmes d'authentification (passkeys, réinitialisation MFA)
* Définir des procédures de révocation de sessions et de tokens pour les identités compromises

#### Phase 2 — Détection et analyse

* Alerter sur les enrôlements de nouvelles méthodes d'authentification et les modifications MFA inhabituelles
* Détecter les connexions anormales (impossible travel, appareils non conformes, authentification legacy)
* Surveiller les consentements OAuth et ajouts d'applications tierces suspects
* Détecter les infrastructures AiTM (proxy d'interception) ciblant les flux d'authentification

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement les sessions, tokens de rafraîchissement et consentements du compte compromis
* Réinitialiser les méthodes d'authentification et les identifiants de l'utilisateur impacté
* Bloquer les domaines et infrastructures de phishing identifiés
* Isoler les appareils concernés et vérifier leur intégrité

#### Phase 4 — Activités post-incident

* Déterminer le vecteur initial (leurre passkey) et le périmètre d'accès obtenu dans le cloud
* Auditer les boîtes mail, fichiers et applications cloud consultés ou exfiltrés
* Révoquer les applications OAuth malveillantes et élargir la recherche aux comptes similaires
* Documenter le retour d'expérience et renforcer les règles d'accès conditionnel

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les enrôlements de passkeys/MFA atypiques (heure, localisation, appareil)
* Chasser les rejeux de tokens et les connexions avec cookies de session volés
* Identifier les usages d'authentification legacy contournant le MFA
* Rechercher les consentements OAuth à large périmètre accordés à des applications inconnues

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566** | Phishing : campagne d'ingénierie sociale exploitant le thème des passkeys |
| **T1078** | Valid Accounts : compromis d'identité menant à l'accès à l'environnement cloud |

---

### Sources

* [https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/)


---

<div id="rapport-proofpoint-2026-voice-of-the-ciso-resilience-en-amelioration-lia-elargit-le-mandat-des-ciso"></div>

## Rapport Proofpoint 2026 Voice of the CISO : résilience en amélioration, l'IA élargit le mandat des CISO

### Résumé

Le 9 septembre 2026, Proofpoint publie son rapport 2026 Voice of the CISO, fondé sur une étude mondiale auprès de 1 600 CISO dans 16 pays. La part de CISO estimant leur organisation exposée à une cyberattaque majeure dans les 12 mois recule à 61 % (contre 76 % en 2025) et les pertes de données matérielles déclarées passent de 66 % à 53 %. Le risque humain est identifié comme première vulnérabilité par 79 % des CISO (contre 66 % en 2025). Les préoccupations liées à la sécurité de la GenAI progressent de 18 points à 78 % ; 85 % citent l'activation sûre de l'IA (assistants, copilotes, automatisation) comme priorité sur deux ans, tandis que 79 % doivent gérer les risques liés à l'IA sans augmentation proportionnelle des ressources. 56 % se déclarent non préparés à une attaque ciblée. Parmi les organisations ayant subi une perte de données matérielle : insiders malveillants ou criminels en tête (46 %), insiders négligents et compromis (38 % chacun), et 93 % des CISO concernés impliquent des employés partants. Les préoccupations se concentrent sur les plateformes de collaboration (34 %), les assistants/copilotes/agents IA (33 %), les applications SaaS et intégrations tierces (33 %), les outils GenAI publics (31 %) et le stockage/partage de fichiers cloud (30 %).

---

### Analyse opérationnelle

Traduire les constats en priorités opérationnelles : renforcer les programmes de risque interne (insider risk), encadrer les processus de départ des employés (93 % des pertes matérielles impliquent des employés partants), étendre la DLP aux plateformes de collaboration, au stockage cloud et aux outils GenAI, et évaluer le risque des intégrations SaaS tierces. Mettre en place la supervision des usages d'assistants IA et copilotes avec contrôles d'accès aux données sensibles.

---

### Implications stratégiques

La baisse perçue du risque d'attaque majeure (61 % contre 76 %) contraste avec un risque concentré sur le facteur humain (79 %) et l'IA : les CISO doivent à la fois protéger l'organisation et permettre l'adoption de l'IA (78 % de préoccupation GenAI, +18 points), souvent sans ressources proportionnelles (79 %). Ce double mandat devient un enjeu de gouvernance et de budget, d'autant que 56 % des organisations se jugent non préparées à une attaque ciblée ; les décisions d'investissement doivent arbitrer entre réduction du risque humain et gouvernance de l'IA.

---

### Recommandations

* Structurer un programme de risque interne couvrant insiders malveillants, négligents et compromis
* Renforcer les contrôles de départ des employés (révocation d'accès, surveillance des téléchargements)
* Étendre la DLP aux plateformes de collaboration, SaaS, stockage cloud et outils GenAI
* Définir une gouvernance d'usage de l'IA (assistants, copilotes, agents) avec contrôles d'accès aux données
* Réévaluer la préparation aux attaques ciblées (56 % des organisations se jugent non préparées)

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Définir une politique de classification des données et un contrôle DLP couvrant collaboration, SaaS, stockage cloud et outils GenAI
* Formaliser un processus de offboarding avec révocation immédiate des accès et revue des droits
* Déployer une gestion des accès privilégiés et une journalisation centralisée des téléchargements et exports
* Sensibiliser aux risques internes et mettre en place un canal de signalement

#### Phase 2 — Détection et analyse

* Alerter sur les téléchargements massifs ou exports anormaux, notamment par des employés en départ
* Surveiller l'usage d'outils GenAI publics avec des données sensibles
* Détecter les comptes internes compromis (connexions anormales, modifications MFA)
* Suivre les consentements OAuth et les intégrations SaaS tierces à risque

#### Phase 3 — Confinement, éradication et récupération

* Suspendre immédiatement les accès et sessions du compte impliqué
* Révoquer les tokens et clés d'API associés
* Isoler le poste de travail et préserver les preuves (forensique)
* Coordonner avec RH/juridique pour les mesures à l'égard de l'insider

#### Phase 4 — Activités post-incident

* Déterminer le périmètre exact des données exfiltrées et les impacts réglementaires (notification)
* Analyser les vecteurs utilisés (mail, cloud personnel, GenAI, périphériques)
* Renforcer les contrôles défaillants et mettre à jour les procédures de offboarding
* Documenter le retour d'expérience et ajuster les politiques DLP

#### Phase 5 — Threat Hunting (proactif)

* Rechercher historiquement les téléchargements massifs précédant des départs d'employés
* Chasser les uploads vers des services de stockage personnels ou non approuvés
* Identifier les données sensibles soumises à des outils GenAI publics
* Auditer les intégrations SaaS et OAuth disposant d'un large périmètre d'accès

---

### Sources

* [https://www.proofpoint.com/us/newsroom/press-releases/proofpoint-2026-voice-ciso-report-finds-cyber-resilience-improving-while-ai](https://www.proofpoint.com/us/newsroom/press-releases/proofpoint-2026-voice-ciso-report-finds-cyber-resilience-improving-while-ai)


---

<div id="quatre-vecteurs-dexposition-des-cles-ssh-via-un-agent-de-codage-ia-et-les-contre-mesures-reellement-efficaces"></div>

## Quatre vecteurs d'exposition des clés SSH via un agent de codage IA, et les contre-mesures réellement efficaces

### Résumé

Un document technique publié le 9 septembre 2026 décrit quatre vecteurs par lesquels un agent de codage IA (assistant de développement piloté par IA) peut accéder à des clés SSH présentes sur le poste de travail du développeur et les exposer, puis évalue les mesures de protection qui contrent effectivement chacun de ces vecteurs.

---

### Analyse opérationnelle

Inventorier les clés SSH et les agents de codage IA déployés sur les postes de développement ; restreindre les permissions et l'exécution des agents (sandboxing, contrôle des accès fichiers à ~/.ssh) ; surveiller les processus accédant aux fichiers de clés privées et les connexions SSH sortantes anormales ; imposer des phrases secrètes fortes ou des clés matérielles (FIDO2) ; intégrer la détection de secrets dans les dépôts et l'historique Git.

---

### Implications stratégiques

L'adoption d'agents de codage IA élargit la surface d'attaque des postes de développement : les clés SSH deviennent une cible directe permettant un mouvement latéral vers les serveurs et un risque pour la chaîne d'approvisionnement logicielle. Les organisations doivent intégrer la gouvernance des outils IA dans le cycle de développement et traiter les postes développeurs comme des actifs à haut risque.

---

### Recommandations

* Sandboxer et restreindre les permissions des agents de codage IA (accès fichiers, réseau)
* Protéger les clés SSH par phrase secrète ou clés matérielles (FIDO2) et limiter leur périmètre
* Surveiller les accès aux fichiers ~/.ssh et alerter sur les connexions SSH anormales
* Rotationner immédiatement les clés exposées et purger les authorized_keys compromises
* Scanner les dépôts et historiques Git pour détecter les secrets exposés

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les clés SSH, agents SSH et postes de développement utilisant des assistants de codage IA
* Définir une politique d'usage des agents de codage IA (permissions, sandboxing, réseau autorisé)
* Imposer des phrases secrètes fortes ou des clés matérielles (FIDO2) et une rotation régulière des clés SSH
* Déployer la détection de secrets et la journalisation des accès fichiers sur les postes développeurs

#### Phase 2 — Détection et analyse

* Alerter sur tout processus non autorisé accédant à ~/.ssh ou aux fichiers de clés privées
* Surveiller les connexions SSH depuis des IP ou à des horaires anormaux
* Détecter les modifications de configuration des agents IA et les transferts réseau de matériel cryptographique
* Surveiller les ajouts suspects dans les fichiers authorized_keys

#### Phase 3 — Confinement, éradication et récupération

* Révoquer et rotationner immédiatement les clés SSH exposées
* Isoler le poste de travail concerné et suspendre l'agent IA
* Purger les clés compromises des fichiers authorized_keys des serveurs
* Bloquer les destinations d'exfiltration identifiées

#### Phase 4 — Activités post-incident

* Déterminer les clés exposées, les hôtes accessibles et les connexions réalisées
* Analyser les logs d'authentification des serveurs SSH pour détecter un usage abusif
* Renforcer le cloisonnement des agents IA et corriger les écarts de configuration
* Capitaliser les enseignements dans la politique de développement et d'usage de l'IA

#### Phase 5 — Threat Hunting (proactif)

* Chasser les connexions SSH réussies avec des clés de développeurs depuis des sources inhabituelles
* Rechercher les lectures de fichiers de clés privées par des processus d'agents IA
* Scanner l'historique Git et les artefacts de build pour des clés exposées
* Auditer les hôtes disposant de clés autorisées obsolètes ou orphelines

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1552.004** | Unsecured Credentials: Private Keys : accès et exfiltration de clés SSH privées par un agent de codage IA |

---

### Sources

* [https://github.com/Adarsh14734/Aegis/blob/main/docs/ssh-key-exposure.md](https://github.com/Adarsh14734/Aegis/blob/main/docs/ssh-key-exposure.md)


---

<div id="tornadorevc2-framework-open-source-de-post-exploitation-avec-49-plugins-publie-par-un-operateur-red-team"></div>

## TornadoRevC2 : framework open-source de post-exploitation avec 49 plugins publié par un opérateur red team

### Résumé

Un développeur se présentant comme opérateur red team (u/kamalx06) a publié sur Reddit r/redteamsec le framework TornadoRevC2, disponible sur GitHub. Initialement simple gestionnaire de sessions reverse-shell TCP/TLS, l'outil est devenu un framework de post-exploitation modulaire avec 49 plugins couvrant énumération, exécution, persistance, pivoting et destruction. Il fonctionne comme un gestionnaire de sessions interactives (PTY/TTY) et non comme un C2 à beacons. Les plugins d'énumération utilisent exclusivement des commandes natives (netsh, ss, iptables, cmdlets PowerShell) sans déposer de binaires ni de fichiers temporaires. Capacités notables : exécution en mémoire (ELF Linux via memfd_create avec repli /dev/shm, RunPE Windows en développement), création de sessions C2 distantes via SSH, WinRM, SMB, RDP, WMI ou MSSQL avec mot de passe, hash NTLM ou clé SSH (intégration netexec), persistance par cronjob chiffré TLS (Linux) ou clé Run (Windows), exécution de commandes en tant qu'autre utilisateur (runas), déploiement d'agents de tunneling Ligolo-ng, pivoting SOCKS5, chiffrement de fichiers (AES-GCM + clé RSA), effacement de l'historique shell et des journaux d'événements Windows, transferts de fichiers par chunks avec vérification SHA-256, journalisation par session et auto-mise-à-jour depuis Git.

---

### Analyse opérationnelle

La faible empreinte d'artefacts (pas de dépôt binaire pour la reconnaissance, commandes natives uniquement) réduit l'efficacité des détections basées sur les fichiers : la détection doit s'appuyer sur la journalisation des lignes de commande (Sysmon EID 1, PowerShell 4104, auditd), les corrélations de rafales d'énumération et l'analyse réseau (sessions TLS sortantes interactives de longue durée vers destinations inconnues). Surveiller spécifiquement : exécution via memfd_create ou depuis /dev/shm, écritures dans cron et clés Run, purges d'historique shell et Event ID 1102, authentifications successives multi-protocoles (SSH/WinRM/SMB/RDP/WMI) avec hash NTLM typiques de netexec. Restreindre les protocoles d'administration sortants, monter /dev/shm en noexec et durcir les accès aux protocoles d'administration distants.

---

### Implications stratégiques

La publication publique d'un framework post-exploitation complet et modulaire abaisse la barrière d'entrée pour des acteurs malveillants : un outil conçu pour le red team est immédiatement réutilisable par des acteurs criminels ou étatiques. L'approche living-off-the-land sans dépôt de fichiers complique l'attribution et la détection EDR, incitant à rééquilibrer les investissements vers la télémétrie de processus et réseau. Le suivi des outils offensifs open-source (tool tracking) devient nécessaire pour maintenir les capacités de détection à jour.

---

### Recommandations

* Journaliser les lignes de commande et l'exécution en mémoire (Sysmon, auditd, PowerShell Script Block Logging).
* Alerter sur memfd_create, l'exécution depuis /dev/shm, les modifications cron et les écritures dans les clés Run.
* Restreindre SSH/WinRM/SMB/RDP/WMI sortants et surveiller les sessions TLS interactives anormales.
* Suivre le dépôt GitHub de l'outil pour anticiper son évolution et créer des détections dédiées.
* Bloquer les purges d'historique et alerter sur l'Event ID 1102 (effacement du journal de sécurité).

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Activer la journalisation détaillée des lignes de commande (Sysmon Event ID 1, PowerShell Script Block Logging 4104, auditd).
* Déployer des règles EDR sur l'exécution via memfd_create et depuis /dev/shm (montage noexec).
* Restreindre les protocoles d'administration sortants (SSH, WinRM, SMB, RDP, WMI, MSSQL) vers l'extérieur.
* Journaliser et alerter sur les modifications de cron et des clés de registre Run/RunOnce.
* Sensibiliser les équipes SOC à l'existence du framework et de ses capacités anti-forensiques.

#### Phase 2 — Détection et analyse

* Alerter sur les sessions TLS sortantes interactives de longue durée vers des destinations inconnues.
* Détecter les rafales de commandes natives d'énumération (netsh, ss, iptables, cmdlets PowerShell) sans dépôt de fichier associé.
* Surveiller les exécutions de binaires via memfd_create ou depuis /dev/shm.
* Détecter les authentifications successives multi-protocoles (SSH/WinRM/SMB/RDP/WMI) avec hash NTLM, typiques de netexec.
* Alerter sur les purges d'historique shell et les événements de effacement de journaux Windows (Event ID 1102).

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement l'hôte compromis du réseau.
* Bloquer les indicateurs de l'infrastructure C2 identifiés (IP/domaines) au niveau du pare-feu et du proxy.
* Révoquer et renouveler les credentials exposés (mots de passe, hashes NTLM, clés SSH).
* Supprimer les mécanismes de persistance (cronjobs, clés Run) avant remédiation complète.

#### Phase 4 — Activités post-incident

* Analyser l'historique shell, les journaux d'événements et les cronjobs pour reconstituer les actions de l'opérateur.
* Rechercher les agents de tunneling Ligolo-ng et les proxys SOCKS5 résiduels.
* Vérifier l'intégrité des fichiers sensibles (transferts opérateur par chunks avec SHA-256, chiffrement AES-GCM + effacement sécurisé possibles).
* Documenter la chronologie de l'intrusion et produire un rapport avec les leçons apprises.

#### Phase 5 — Threat Hunting (proactif)

* Chasser les processus lancés depuis /dev/shm ou via memfd_create sur les endpoints Linux.
* Rechercher les tâches cron de redémarrage exécutant des shells inversés chiffrés TLS.
* Rechercher les écritures récentes dans les clés Run/RunOnce sans installation logicielle associée.
* Corréler les connexions TLS sortantes de longue durée avec des sessions interactives (PTY/TTY) et des purges de journaux.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxps://github[.]com/kamalx06/TornadoRevC2[.]git` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1059.004** | Unix Shell - exécution de commandes et shells inversés via commandes natives (netsh, ss, iptables) |
| **T1059.001** | PowerShell - énumération Windows via cmdlets natifs sans dépôt de fichiers |
| **T1053.003** | Cron - persistance par cronjob de reverse shell chiffré TLS sur Linux/Unix |
| **T1547.001** | Registry Run Keys - persistance Windows via clé Run |
| **T1078** | Valid Accounts - création de sessions C2 distantes via SSH, WinRM, SMB, RDP, WMI, MSSQL avec mot de passe, hash NTLM ou clé SSH |
| **T1090** | Proxy - pivoting SOCKS5 et déploiement d'agents de tunneling Ligolo-ng via hôtes compromis |
| **T1055** | Process Injection - exécution de payloads en mémoire (memfd_create, RunPE) |
| **T1070.003** | Clear Command History - effacement de l'historique shell (plugin historydel) |
| **T1070.001** | Clear Windows Event Logs - purge des journaux d'événements Windows (plugin eventlogdel) |
| **T1105** | Ingress Tool Transfer - transferts de fichiers par chunks avec vérification SHA-256 |

---

### Sources

* [https://www.reddit.com/r/redteamsec/comments/1wboyjm/tornadorevc2_a_postex_framework_i_built_for_red/](https://www.reddit.com/r/redteamsec/comments/1wboyjm/tornadorevc2_a_postex_framework_i_built_for_red/)


---

<div id="voidsec-proxy-boite-a-outils-open-source-opsec-en-python-18-modules-50-commandes-publiee-sur-github"></div>

## voidsec-proxy : boîte à outils open-source OPSEC en Python (18 modules, 50+ commandes) publiée sur GitHub

### Résumé

Le projet voidsec-proxy (VoidSecSoftwares), publié sur GitHub en version 3.0.0, est une boîte à outils Python sans dépendances obligatoires regroupant 18 modules et plus de 50 commandes : chaîne de proxys SOCKS5 avec rotation automatique, scanner de ports TCP multithread avec banner grabbing, toolkit DNS (résolution, reverse DNS, énumération de sous-domaines), cracking de hashes (MD5, SHA1, SHA256, SHA512) avec wordlists, générateur/auditeur de mots de passe, mutateur de wordlists, reconnaissance réseau, fingerprinting web, canaux d'exfiltration covert et encodage, chiffrement de fichiers AES-GCM, suppression sécurisée de fichiers, stéganographie, générateur de reverse shell, analyse forensique de fichiers, anonymisation et gestion de plugins. L'outil est distribué publiquement via GitHub avec support optionnel de cryptographie (AES-GCM, ChaCha20, stéganographie).

---

### Analyse opérationnelle

Cet outil consolide en un seul binaire des capacités de reconnaissance, de pivoting et d'exfiltration directement réutilisables par des attaquants : détecter les scans TCP internes massifs, les connexions locales vers des proxys SOCKS5 (ports types 1080/9050), les énumérations DNS de sous-domaines en volume, l'usage de wordlists de cracking et les fichiers chiffrés AES-GCM créés avant exfiltration. Surveiller l'exécution de scripts Python non signés sur les postes sensibles et journaliser les flux sortants des hôtes exécutant des chaînes de proxys.

---

### Implications stratégiques

La consolidation d'outils OPSEC (proxy, stéganographie, exfiltration covert, effacement sécurisé) dans un toolkit unique et sans dépendances facilite les opérations furtives d'acteurs à moyens limités. Cela renforce la tendance des intrusions s'appuyant sur des outils open-source légitimes, compliquant la distinction entre tests d'intrusion et intrusions réelles et exigeant une surveillance continue des dépôts GitHub offensifs.

---

### Recommandations

* Détecter les scans de ports internes et les proxys SOCKS5 locaux (1080/9050).
* Journaliser et alerter sur les énumérations DNS massives et le cracking de hashes.
* Surveiller l'exécution de Python non signé sur les postes sensibles.
* Suivre le dépôt GitHub pour anticiper les usages malveillants.
* Contrôler les fichiers chiffrés et les suppressions sécurisées sur les actifs critiques.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Journaliser les connexions sortantes vers des proxys SOCKS5 et les résolutions DNS anormales.
* Activer la détection des scans de ports internes (volume anormal de connexions SYN).
* Surveiller l'exécution de scripts Python non signés sur les postes sensibles.
* Journaliser les requêtes DNS inhabituelles (TXT, énumération de sous-domaines en volume).

#### Phase 2 — Détection et analyse

* Détecter les scans TCP multi-ports internes avec banner grabbing.
* Alerter sur les chaînes de proxys SOCKS5 locales (écoute sur ports types 1080/9050).
* Surveiller les tentatives locales de cracking de hashes avec wordlists volumineuses.
* Détecter les encodages inhabituels, canaux covert et fichiers stéganographiés en sortie.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les proxys et domaines utilisés pour la rotation.
* Isoler les hôtes exécutant l'outil et saisir les artefacts (wordlists, fichiers chiffrés, résultats de scan).
* Réinitialiser les credentials dont les hashes auraient pu être crackés.

#### Phase 4 — Activités post-incident

* Tenter la récupération des fichiers effacés de manière sécurisée (shred) et exploiter les journaux résiduels.
* Reconstituer les cibles reconnues à partir des exports de scan (JSON/CSV) et des requêtes DNS.
* Évaluer les données exfiltrables via canaux covert et auditer les flux sortants correspondants.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les processus Python écoutant sur les ports 1080/9050 avec rotation de proxys.
* Chasser les énumérations DNS de sous-domaines massives depuis un même hôte.
* Rechercher les fichiers chiffrés AES-GCM créés juste avant des transferts sortants.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxps://github[.]com/VoidSecSoftwares/voidsec-proxy[.]git` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1090** | Proxy - chaîne de proxys SOCKS5 avec rotation automatique |
| **T1046** | Network Service Discovery - scanner de ports TCP multithread avec banner grabbing |
| **T1110.002** | Password Cracking - cracking de hashes MD5/SHA1/SHA256/SHA512 avec wordlists |
| **T1048** | Exfiltration Over Alternative Protocol - canaux covert et encodage |
| **T1027** | Obfuscated Files or Information - stéganographie et encodage de données |

---

### Sources

* [https://github.com/VoidSecSoftwares/voidsec-proxy](https://github.com/VoidSecSoftwares/voidsec-proxy)


---

<div id="desactivation-de-windows-defender-via-lenregistrement-dun-faux-antivirus-aupres-du-windows-security-center"></div>

## Désactivation de Windows Defender via l'enregistrement d'un faux antivirus auprès du Windows Security Center

### Résumé

L'article d'ipurple.team (9 septembre 2026) décrit une technique permettant à des acteurs de menace de désactiver Windows Defender en abusant l'API du Windows Security Center (WSC) pour simuler l'enregistrement d'un produit antivirus tiers. Lorsqu'un antivirus tiers est enregistré, Defender bascule en mode passif pour éviter les collisions de scan ; la technique exploite ce mécanisme pour dégrader les protections sans générer les indicateurs de manipulation habituels ni introduire de pilote. La technique ne concerne que les endpoints Windows, pas les serveurs. Une preuve de concept publique nommée defendnot, publiée par es3n1n, abuse de l'interface COM IWscAVStatus (via wscapi.dll) : la fonction Register() soumet un chemin d'exécutable signé et un nom d'affichage pour identifier le faux antivirus, et UpdateStatus() met à jour l'état rapporté (activé, désactivé, expiré ou défaillant).

---

### Analyse opérationnelle

Détecter les transitions anormales de Defender : passage en mode passif ou désactivation de la protection temps réel sans antivirus tiers correspondant dans l'inventaire (Event IDs 5000/5001/5007, états WSC). Alerter sur l'enregistrement de nouveaux produits de sécurité dans le Centre de sécurité et sur l'usage de wscapi.dll / de l'interface IWscAVStatus par des processus non liés à un éditeur AV légitime. Maintenir la Tamper Protection active, réconcilier en continu l'inventaire AV avec les états rapportés par WSC, et traiter toute désactivation de Defender comme un incident d'évasion défensive (T1562.001).

---

### Implications stratégiques

Cette technique illustre l'évolution de l'évasion défensive vers l'abus d'API légitimes de Windows, sans pilote (évitant les détections BYOVD) et sans indicateurs de manipulation classiques, réduisant la visibilité EDR de manière quasi silencieuse sur les endpoints. La fenêtre sans protection temps réel expose les organisations aux déploiements de charges utiles secondaires. Les éditeurs EDR et les équipes de détection doivent intégrer l'état WSC comme source de télémétrie de premier plan.

---

### Recommandations

* Activer et surveiller la Tamper Protection sur tous les endpoints.
* Alerter sur les passages en mode passif ou désactivations de Defender sans AV tiers inventorié.
* Surveiller les enregistrements de nouveaux produits AV auprès de WSC et l'usage d'IWscAVStatus.
* Traiter toute désactivation de Defender comme un incident T1562.001.
* Réconcilier automatiquement l'inventaire AV avec les états rapportés par le Centre de sécurité.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Vérifier que la protection contre les manipulations (Tamper Protection) est activée sur tous les endpoints.
* Inventorier les solutions antivirus tierces légitimes pour établir une baseline des états attendus.
* Journaliser les changements d'état de Windows Defender et du service wscsvc.
* Configurer des alertes EDR sur l'usage des API WSC (wscapi.dll) par des processus non liés à un éditeur AV légitime.

#### Phase 2 — Détection et analyse

* Alerter sur les événements Defender indiquant un passage en mode passif ou une désactivation de la protection temps réel sans antivirus tiers connu (Event IDs 5000/5001/5007).
* Surveiller l'enregistrement de nouveaux produits antivirus dans le Centre de sécurité Windows.
* Corréler l'exécution de processus invoquant l'interface COM IWscAVStatus ou wscapi.dll.
* Réconcilier en continu les états rapportés par WSC avec l'inventaire AV tiers.

#### Phase 3 — Confinement, éradication et récupération

* Réactiver Windows Defender et forcer une analyse complète de l'hôte.
* Supprimer l'enregistrement du faux produit antivirus et l'artefact associé.
* Isoler l'hôte le temps de vérifier l'absence d'autres actions de l'attaquant pendant la fenêtre sans protection.

#### Phase 4 — Activités post-incident

* Déterminer le vecteur d'entrée initial ayant permis l'exécution de l'outil (ex. defendnot).
* Vérifier l'absence de persistance complémentaire et de credentials exposés durant la fenêtre sans protection temps réel.
* Renforcer la politique de sécurité endpoint (règles ASR, intégrité mémoire) et mettre à jour la baseline AV.

#### Phase 5 — Threat Hunting (proactif)

* Chasser les endpoints où Defender est désactivé ou passif sans correspondance dans l'inventaire AV tiers.
* Rechercher les produits de sécurité enregistrés auprès de WSC dont l'exécutable n'appartient à aucun éditeur AV connu.
* Rechercher les usages de wscapi.dll / IWscAVStatus hors processus légitimes d'éditeurs AV.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1562.001** | Impair Defenses: Disable or Modify Tools - désactivation de Windows Defender via fausse enregistrement d'un antivirus auprès du Windows Security Center (interface COM IWscAVStatus) |

---

### Sources

* [https://ipurple.team/2026/09/09/windows-security-center/](https://ipurple.team/2026/09/09/windows-security-center/)


---

<div id="exploitation-active-de-vulnerabilites-cisco-secure-firewall-management-center-alerte-talos"></div>

## Exploitation active de vulnérabilités Cisco Secure Firewall Management Center (alerte Talos)

### Résumé

Cisco Talos signale sur son blog une exploitation active et en cours de vulnérabilités affectant Cisco Secure Firewall Management Center (FMC). Le contenu détaillé de l'article (CVE concernées, versions affectées, indicateurs) n'est pas disponible dans la source analysée ; le titre confirme toutefois l'exploitation active et continue de ces vulnérabilités.

---

### Analyse opérationnelle

Traiter l'alerte comme prioritaire : inventorier les versions de FMC et des dispositifs gérés, consulter les advisories Cisco PSIRT/Talos pour identifier les CVE et correctifs, appliquer les correctifs dès publication, retirer toute exposition Internet des interfaces de gestion FMC et restreindre leur accès à des jump hosts dédiés. Examiner les journaux FMC (authentifications anormales, modifications de configuration, création de comptes ou de règles inattendues) et corréler avec les indicateurs publiés par Talos.

---

### Implications stratégiques

Le Firewall Management Center constitue un point de contrôle centralisé : sa compromission permet de manipuler les politiques de pare-feu de l'ensemble du périmètre, de créer des règles d'exfiltration ou de pivot. L'exploitation active par des acteurs inconnus accroît le risque pour les organisations exposées et s'inscrit dans la tendance des intrusions ciblant les équipements de sécurité réseau et de périphérie comme point d'entrée privilégié.

---

### Recommandations

* Inventorier et corriger en urgence les instances FMC selon les advisories Cisco.
* Retirer l'exposition Internet des interfaces de gestion et restreindre l'accès administratif.
* Auditer comptes, règles et configurations FMC pour détecter des modifications malveillantes.
* Surveiller les publications Talos pour récupérer les indicateurs de compromission.
* Sauvegarder les configurations pour comparaison et restauration.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les versions de Cisco Secure Firewall Management Center (FMC) et des dispositifs gérés.
* Restreindre l'accès aux interfaces de gestion (VPN d'administration, jump hosts, listes blanches IP).
* S'abonner aux advisories Cisco PSIRT et Talos pour suivre les CVE, correctifs et indicateurs.
* Sauvegarder les configurations FMC pour comparaison et restauration rapide.

#### Phase 2 — Détection et analyse

* Surveiller les journaux FMC pour des tentatives d'exploitation, authentifications anormales et changements de configuration inattendus.
* Alerter sur la création de comptes administrateurs ou de règles de pare-feu non planifiées.
* Corréler les flux entrants vers les interfaces de gestion exposées avec les indicateurs publiés par Talos.

#### Phase 3 — Confinement, éradication et récupération

* Appliquer immédiatement les correctifs Cisco dès leur disponibilité.
* Retirer toute exposition Internet des interfaces de gestion FMC.
* En cas de compromission suspectée, isoler le FMC et auditer les configurations déployées vers les firewalls gérés.

#### Phase 4 — Activités post-incident

* Auditer les comptes, règles et objets créés ou modifiés pendant la fenêtre d'exposition.
* Effectuer la rotation des credentials d'administration FMC et des clés API.
* Vérifier l'absence de persistance (tâches planifiées, modifications de politiques) sur le FMC et les dispositifs gérés.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux historiques les patterns d'exploitation correspondant aux vulnérabilités visées.
* Chasser les déploiements de politiques incohérents ou les exports de données depuis le FMC.
* Comparer les configurations actuelles aux sauvegardes pour détecter des modifications malveillantes.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploit Public-Facing Application - exploitation active de vulnérabilités affectant Cisco Secure Firewall Management Center |

---

### Sources

* [https://blog.talosintelligence.com/fmc-ongoing-exploitation/](https://blog.talosintelligence.com/fmc-ongoing-exploitation/)


---

<div id="signalement-dune-possible-page-de-phishing-via-un-lien-de-redirection-encurtadordev-analyse-urldna"></div>

## Signalement d'une possible page de phishing via un lien de redirection encurtador.dev (analyse urldna)

### Résumé

Un signalement communautaire daté du 9 septembre 2026 identifie une URL de redirection suspectée de phishing : hxxps://www[.]encurtador[.]dev/redirecionamento/sella-app. Une analyse de l'URL est publiée sur urldna.io. Le contenu de la page cible et l'ampleur de la campagne ne sont pas détaillés dans la source ; le signalement porte sur un lien de redirection (service de réduction de liens) pointant vers une ressource nommée sella-app.

---

### Analyse opérationnelle

Bloquer proactivement le domaine encurtador[.]dev et l'URL complète au niveau DNS, proxy et passerelle mail, en évaluant le risque de faux positif (service de redirection légitime détourné). Rechercher dans les journaux proxy/DNS et mail tout accès ou diffusion du lien, analyser la destination via sandbox/urldna pour identifier la marque usurpée et l'infrastructure d'hébergement, et réinitialiser les identifiants des utilisateurs ayant interagi avec la page.

---

### Implications stratégiques

L'usage de services de réduction/redirection de liens (ici encurtador.dev) reste un vecteur privilégié pour contourner les filtrages de réputation d'URL et les passerelles mail. Les campagnes usurpant des marques d'applications (pattern sella-app, possiblement à connotation bancaire) exposent les organisations du secteur financier et leurs clients au vol d'identifiants, avec un risque direct de fraude et d'atteinte réputationnelle.

---

### Recommandations

* Bloquer le domaine encurtador[.]dev et l'URL signalée (DNS, proxy, mail).
* Analyser la destination via sandbox pour confirmer le phishing et identifier la marque usurpée.
* Rechercher dans les logs proxy/mail les accès et diffusions du lien.
* Réinitialiser les credentials des utilisateurs ayant soumis des identifiants.
* Signaler l'URL aux services de blocage et au CERT compétent.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir des listes de blocage DNS/proxy et un processus de signalement utilisateur.
* Configurer la passerelle mail pour analyser et réécrire les liens de redirection (shorteners).

#### Phase 2 — Détection et analyse

* Surveiller les accès proxy/DNS vers encurtador[.]dev et l'URL de redirection identifiée.
* Rechercher dans les journaux mail la diffusion du lien aux utilisateurs.
* Alerter sur les soumissions de credentials vers les domaines cibles potentiels.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer le domaine et l'URL au niveau DNS, proxy et passerelle mail.
* Purger les messages contenant le lien des boîtes utilisateurs.
* Réinitialiser les credentials des utilisateurs ayant interagi avec la page.

#### Phase 4 — Activités post-incident

* Analyser la page (via urldna ou sandbox) pour identifier la marque usurpée et l'infrastructure d'hébergement.
* Signaler l'URL aux services de blocage et au CERT approprié.
* Communiquer aux utilisateurs et renforcer la sensibilisation au phishing via shorteners.

#### Phase 5 — Threat Hunting (proactif)

* Chasser les accès historiques à encurtador[.]dev et aux chemins de redirection similaires.
* Rechercher d'autres URLs du même opérateur (patterns de redirection, chaîne sella-app).
* Vérifier les sessions anormales suite à d'éventuelles soumissions d'identifiants.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxps://www[.]encurtador[.]dev/redirecionamento/sella-app` | Medium |
| DOMAIN | `encurtador[.]dev` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Phishing: Spearphishing Link - lien de redirection (service de réduction d'URL) pointant vers une page de phishing suspectée |

---

### Sources

* [https://urldna.io/scan/6aa119e03b77500007f164ed](https://urldna.io/scan/6aa119e03b77500007f164ed)


---

<div id="bonnes-pratiques-cicd-epingler-les-dependances-pour-reduire-le-risque-de-compromission-de-la-chaine-dapprovisionnement"></div>

## Bonnes pratiques CI/CD : épingler les dépendances pour réduire le risque de compromission de la chaîne d'approvisionnement

### Résumé

Un conseil sécurité publié le 9 septembre 2026 recommande d'épingler les dépendances logicielles pour sécuriser les pipelines CI/CD : s'appuyer sur des versions latest ou des plages sémantiques larges produit des builds non déterministes et expose aux compromissions amont (upstream). L'usage de lockfiles (package-lock.json, poetry.lock) garantit que chaque déploiement utilise exactement le même code et atténue le risque de compromission soudaine d'une dépendance. La source renvoie vers une base de données CVE pour surveiller les risques liés aux dépendances.

---

### Analyse opérationnelle

Imposer les lockfiles et l'épinglage exact (voire par hash) dans les politiques de build, bloquer en CI toute modification de dépendance hors lockfile ou usage de latest, utiliser un registre privé/proxy avec vérification de checksums, générer un SBOM par build et surveiller les CVE des dépendances pour prioriser des mises à jour contrôlées plutôt que des mises à jour automatiques non vérifiées.

---

### Implications stratégiques

Les attaques par la chaîne d'approvisionnement logicielle (compromission de paquets amont, publications malveillantes) constituent un vecteur à fort impact et faible coût pour les attaquants. La gouvernance des dépendances (épinglage, SBOM, revue des mises à jour) devient un enjeu de conformité et de résilience, notamment pour les organisations soumises à des exigences réglementaires sur la sécurité logicielle.

---

### Recommandations

* Imposer lockfiles et épinglage exact des versions dans tous les pipelines.
* Vérifier les checksums/hashes des dépendances via un registre privé.
* Alerter en CI sur l'usage de latest ou de plages semver larges.
* Générer un SBOM et surveiller les CVE des dépendances.
* Revoir les nouvelles dépendances et changements de mainteneurs avant adoption.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Imposer l'usage de lockfiles (package-lock.json, poetry.lock) et l'épinglage exact des versions.
* Utiliser un registre privé/proxy avec vérification des checksums/hashes des dépendances.
* Générer un SBOM par build et surveiller les CVE des dépendances.

#### Phase 2 — Détection et analyse

* Alerter en CI sur toute modification de dépendance hors lockfile ou usage de latest/plages semver larges.
* Surveiller les publications amont (nouvelles versions inattendues, changements de mainteneurs).
* Vérifier l'intégrité des artefacts téléchargés (hashs attendus).

#### Phase 3 — Confinement, éradication et récupération

* Geler les builds et épingler la dernière version saine connue de la dépendance compromise.
* Purger les caches de dépendances et reconstruire depuis des sources vérifiées.
* Révoquer les secrets/tokens exposés aux pipelines CI/CD affectés.

#### Phase 4 — Activités post-incident

* Auditer les artefacts déployés pendant la fenêtre de compromission et retirer les versions affectées.
* Analyser le code de la dépendance compromise pour identifier les comportements malveillants (exfiltration, backdoor).
* Mettre à jour la politique de gestion des dépendances et la revue des mises à jour amont.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les builds utilisant latest ou des plages de versions larges.
* Chasser les dépendances introduites récemment sans revue ou avec des mainteneurs nouveaux.
* Corréler les flux sortants des runners CI vers des domaines inconnus.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1195** | Supply Chain Compromise - risque de compromission amont des dépendances logicielles, atténué par l'épinglage des versions et les lockfiles |

---

### Sources

* [https://cvedatabase.com](https://cvedatabase.com)


---

<div id="balayage-massif-dinfrastructures-crypto-mal-configurees-capte-par-les-honeypots-lurescope"></div>

## Balayage massif d'infrastructures crypto mal configurées capté par les honeypots Lurescope

### Résumé

Selon la télémétrie first-party des honeypots Lurescope, 791 000 événements ont été collectés en une semaine, provenant de 13 600 adresses IP réparties dans 157 pays. Un seul serveur situé au Pérou a généré 65 259 sollicitations, dont 21 752 intrusions complètes. Le nom d'utilisateur « wallet » est devenu le deuxième plus sondé, systématiquement associé à un mot de passe vide, ce qui indique un balayage actif à la recherche de coffres crypto mal configurés. Des statistiques en direct et une blocklist hebdomadaire sont publiées sur lurescope[.]com.

---

### Analyse opérationnelle

Les équipes SOC doivent surveiller les tentatives d'authentification utilisant le couple « wallet »/mot de passe vide sur l'ensemble des services exposés (SSH, RDP, API, interfaces d'administration de nœuds crypto). La blocklist hebdomadaire peut être intégrée aux contrôles de filtrage. Mesures prioritaires : désactivation de l'authentification par mot de passe au profit de clés/MFA, verrouillage de compte, rate-limiting, restriction d'exposition des nœuds crypto et interfaces d'administration (VPN/bastion, allowlist IP). Corréler les 13 600 IP sources avec les journaux internes pour identifier d'éventuelles connexions réussies passées inaperçues.

---

### Implications stratégiques

Le volume et l'ampleur géographique du scan (157 pays) confirment l'industrialisation du balayage des infrastructures crypto mal configurées. Le taux d'intrusion complète observé sur un seul hôte (environ un tiers des sollicitations) montre que les configurations par défaut restent insuffisantes. Les organisations détenant des actifs numériques ou hébergeant des nœuds crypto sont des cibles prioritaires avec un risque financier direct. L'exploitation de télémétrie honeypot et de blocklists communautaires devient un levier défensif à intégrer dans la stratégie de durcissement.

---

### Recommandations

* Interdire tout compte exposé sans mot de passe et imposer MFA/clés sur les services d'authentification
* Intégrer la blocklist hebdomadaire de lurescope[.]com dans les pare-feux et proxys
* Restreindre l'accès réseau aux nœuds crypto et interfaces d'administration (bastion, allowlist IP)
* Alerter sur les authentifications avec le nom d'utilisateur « wallet » ou mot de passe vide
* Corréler les IP de la télémétrie avec les journaux d'authentification internes sur les 90 derniers jours

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier tous les services exposés (SSH, RDP, API, interfaces d'administration, nœuds crypto) et leur mode d'authentification
* Interdire les comptes sans mot de passe et les authentifications anonymes sur toute infrastructure exposée
* Imposer l'authentification par clés/MFA et désactiver l'authentification par mot de passe lorsque possible
* Déployer des honeypots ou canaux leurres pour détecter les campagnes de balayage en amont
* Intégrer les blocklists communautaires hebdomadaires (type lurescope[.]com) dans les pare-feux et EDR
* Centraliser la journalisation des tentatives d'authentification (échecs et succès) dans un SIEM

#### Phase 2 — Détection et analyse

* Alerter sur toute tentative d'authentification avec le nom d'utilisateur « wallet » ou un mot de passe vide
* Détecter les échecs d'authentification répétés depuis un grand nombre d'IP distinctes (comportement distribué)
* Corréler les IP sources internes avec la blocklist hebdomadaire et la télémétrie honeypot (13,6K IP / 157 pays)
* Surveiller les connexions réussies anormales sur les interfaces d'administration et les nœuds crypto
* Alerter sur tout trafic entrant anormalement élevé depuis un même hôte (ex. 65 259 sollicitations/semaine)

#### Phase 3 — Confinement, éradication et récupération

* Bloquer immédiatement les IP sources identifiées comme actives dans les intrusions
* Désactiver ou verrouiller les comptes compromis et révoquer les sessions actives
* Isoler les hôtes ayant subi une intrusion complète (quarantaine réseau)
* Restreindre l'accès aux interfaces d'administration via VPN/bastion et allowlist IP
* Rotation de l'ensemble des credentials potentiellement exposés

#### Phase 4 — Activités post-incident

* Mener une analyse forensique des hôtes intrus pour déterminer le vecteur (identifiants faibles/absents) et l'étendue
* Vérifier l'exfiltration potentielle de clés, seeds ou données de portefeuilles
* Revoir les règles de détection et les politiques d'authentification à la lumière de l'incident
* Documenter l'incident et partager les IOC observés avec la communauté/CTI interne
* Mettre à jour la blocklist interne et les règles de blocage périmétrique

#### Phase 5 — Threat Hunting (proactif)

* Chasser dans les logs historiques les connexions réussies avec des noms d'utilisateur inhabituels ou des mots de passe vides
* Rechercher les IP de la télémétrie (13,6K IP, 157 pays) dans les journaux d'authentification des 30-90 derniers jours
* Identifier les nœuds crypto, wallets ou interfaces d'administration exposés publiquement sur le périmètre
* Rechercher des créations de comptes ou modifications de configuration postérieures à des pics de tentatives d'authentification

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1110.001** | Password Guessing : sondage massif du nom d'utilisateur « wallet » systématiquement associé à un mot de passe vide |
| **T1190** | Exploit Public-Facing Application : 21 752 intrusions complètes observées contre des services exposés, dont des coffres crypto mal configurés |

---

### Sources

* [https://infosec.exchange/@lurescope/117243312274890455](https://infosec.exchange/@lurescope/117243312274890455)


---

<div id="trezor-campagne-de-phishing-stm32-entropy-vulnerability-emise-via-un-prestataire-e-mail-compromis"></div>

## Trezor : campagne de phishing « STM32 Entropy Vulnerability » émise via un prestataire e-mail compromis

### Résumé

Trezor a confirmé la compromission de l'un de ses prestataires e-mail, ayant permis l'envoi d'une campagne de phishing intitulée « Critical Security Alert: STM32 Entropy Vulnerability » via son infrastructure d'envoi légitime. Les messages proviennent de mailing[.]trezor[.]io (IP 172[.]246[.]19[.]223), avec un DKIM valide d=trezor[.]io, un envoi via Sendinblue/Brevo et des liens de tracking en r[.]mailing[.]trezor[.]io. La même IP avait déjà été observée lors de l'incident Trezor de 2024. Le lien frauduleux est masqué derrière le redirecteur légitime avant de rediriger la victime vers un faux outil de vérification. Il ne s'agit donc pas d'un simple spoofing, ce qui explique la validation DKIM/SPF/DMARC et le passage de certains filtres anti-spam.

---

### Analyse opérationnelle

Les contrôles DKIM/SPF/DMARC ne suffisent pas : un message peut être signé légitimement via un canal compromis. Les équipes doivent rechercher dans les passerelles mail les messages avec l'objet « Critical Security Alert: STM32 Entropy Vulnerability », corréler l'IP d'envoi 172[.]246[.]19[.]223 et analyser en sandbox les URL finales cachées derrière le redirecteur r[.]mailing[.]trezor[.]io. Actions : blocage de l'IP et des domaines de destination, purge des messages, sensibilisation ciblée des détenteurs de portefeuilles matériels (ne jamais saisir de seed suite à un e-mail), surveillance des clics via les liens de tracking.

---

### Implications stratégiques

La réutilisation de la même IP que lors de l'incident de 2024 suggère un acteur persistant ciblant l'écosystème Trezor ou une faiblesse récurrente de la chaîne d'approvisionnement e-mail. L'abus de canaux d'envoi légitimes (ESP compromis) érode la confiance dans l'authentification e-mail et expose directement les détenteurs de crypto-actifs à un risque financier élevé. Les organisations doivent étendre la gestion des risques tiers aux prestataires de communication et anticiper des campagnes exploitant des marques de confiance avec une authentification e-mail valide.

---

### Recommandations

* Ne pas considérer DKIM/SPF/DMARC valides comme preuve de légitimité ; inspecter le contenu et la destination finale des liens
* Bloquer l'IP 172[.]246[.]19[.]223 et surveiller les domaines mailing[.]trezor[.]io et r[.]mailing[.]trezor[.]io
* Rappeler aux utilisateurs de ne jamais saisir de phrase de récupération (seed) via un lien reçu par e-mail
* Résoudre les chaînes de redirection en sandbox pour extraire les URL de phishing réelles
* Renforcer les contrôles d'accès et la surveillance des comptes chez les prestataires d'envoi d'e-mails

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser les utilisateurs détenant des portefeuilles matériels : ne jamais saisir de phrase de récupération (seed) à la suite d'un e-mail
* Définir une procédure de vérification hors bande des alertes de sécurité prétendument émises par des fournisseurs
* Étendre l'évaluation des risques tiers aux prestataires d'envoi d'e-mails (ESP) et exiger des contrôles d'accès renforcés
* Configurer DMARC en mode rejet et surveiller les rapports d'authentification des domaines de marque
* Déployer un sandbox d'analyse d'URL pour résoudre les chaînes de redirection

#### Phase 2 — Détection et analyse

* Rechercher dans la passerelle mail les messages portant l'objet « Critical Security Alert: STM32 Entropy Vulnerability »
* Alerter sur les messages envoyés via mailing[.]trezor[.]io depuis l'IP 172[.]246[.]19[.]223
* Surveiller les clics sur les liens de tracking r[.]mailing[.]trezor[.]io dans les journaux proxy/DNS
* Détecter les accès à de faux outils ou portails de vérification Trezor (résolution finale des redirections)
* Ne pas traiter la validation DKIM/SPF/DMARC comme un signal de légitimité suffisant : corréler avec le contenu et la destination finale

#### Phase 3 — Confinement, éradication et récupération

* Purger les messages de phishing de toutes les boîtes (recherche et destruction)
* Bloquer l'IP d'envoi 172[.]246[.]19[.]223 et les domaines/URL finaux du faux outil de vérification
* Réinitialiser les credentials des utilisateurs ayant cliqué ou saisi des informations
* Notifier les destinataires ayant interagi avec le message et leur demander de vérifier leurs portefeuilles
* Signaler l'abus au prestataire e-mail (Sendinblue/Brevo) et à Trezor

#### Phase 4 — Activités post-incident

* Déterminer si des phrases de récupération ou credentials ont été saisis sur le faux outil et vérifier tout mouvement d'actifs associé
* Analyser la chaîne de compromission du prestataire e-mail avec le fournisseur (compte compromis, vol d'identifiants API)
* Revoir les contrôles anti-phishing à la lumière du contournement des filtres via un canal signé légitime
* Partager les IOC (IP, domaines, objets de messages) avec les équipes CTI et la communauté
* Documenter l'incident comme un cas de compromission de chaîne d'approvisionnement e-mail récurrente (2024 et 2026)

#### Phase 5 — Threat Hunting (proactif)

* Rechercher historiquement l'objet « STM32 Entropy Vulnerability », l'IP 172[.]246[.]19[.]223 et les domaines mailing[.]trezor[.]io / r[.]mailing[.]trezor[.]io dans les passerelles et proxies
* Identifier les utilisateurs ayant cliqué sur les liens de tracking ou accédé au faux outil de vérification
* Rechercher via DLP toute saisie ou transmission de seed phrase / phrase de récupération
* Corréler avec l'incident Trezor de 2024 pour identifier un schéma de réutilisation d'infrastructure par le même acteur

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| IP | `172[.]246[.]19[.]223` | High |
| DOMAIN | `mailing[.]trezor[.]io` | Medium |
| DOMAIN | `r[.]mailing[.]trezor[.]io` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Spearphishing Link : campagne « Critical Security Alert: STM32 Entropy Vulnerability » redirigeant vers un faux outil de vérification |
| **T1584.006** | Compromise Infrastructure: Web Services : abus du prestataire e-mail (Sendinblue/Brevo) et du canal d'envoi légitime de Trezor |
| **T1036.005** | Masquerading: Match Legitimate Name or Location : lien frauduleux masqué derrière le redirecteur légitime r[.]mailing[.]trezor[.]io |

---

### Sources

* [https://infosec.exchange/@decio/117243195099453609](https://infosec.exchange/@decio/117243195099453609)


---

<div id="qilin-revendique-mitsuwa-trading-co-ltd-sur-son-site-de-fuite"></div>

## Qilin revendique Mitsuwa Trading Co., Ltd sur son site de fuite

### Résumé

Le groupe ransomware Qilin a ajouté Mitsuwa Trading Co., Ltd à la liste des victimes publiée sur son site de fuite de données, selon la surveillance RansomLook du 9 septembre. L'entrée indique une opération de type RaaS (Ransomware-as-a-Service) ; l'état du site de fuite est signalé comme dégradé. Aucun détail technique, montant de rançon ni preuve d'exfiltration n'est fourni dans la publication.

---

### Analyse opérationnelle

Vérifier si Mitsuwa Trading est un fournisseur, partenaire ou client de l'organisation (risque de contamination ou d'exposition via la supply chain). Surveiller le site de fuite de Qilin pour d'éventuelles publications de données dans les 48-72 heures. Si l'entité est interne, déclencher le processus de réponse à incident ransomware : isolation des systèmes, vérification de l'intégrité des sauvegardes, recherche des TTP et IOCs Qilin connus (chiffrement, suppression des copies d'ombre, outils d'exfiltration).

---

### Implications stratégiques

Qilin demeure un RaaS actif ciblant des entreprises de taille intermédiaire internationales, avec une récurrence observée sur des entités japonaises du commerce et de l'industrie. Une revendication non accompagnée de preuves peut servir de levier de pression psychologique. Le modèle de double extorsion expose la victime à des risques réglementaires (notification de fuite) et réputationnels au-delà du seul chiffrement.

---

### Recommandations

* Surveiller le site de fuite Qilin et les flux CTI pour toute publication de données concernant Mitsuwa Trading
* Évaluer les liens contractuels et les flux de données avec Mitsuwa Trading (risque supply chain)
* Vérifier l'intégrité des sauvegardes et tester une restauration hors ligne
* Rappeler aux équipes les procédures de signalement d'anomalies de chiffrement ou d'exfiltration

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir des sauvegardes hors ligne testées (règle 3-2-1) et des procédures de restauration documentées
* Segmenter le réseau et imposer un MFA sur les comptes à privilèges et les accès distants (VPN)
* Exploiter une veille continue des sites de fuite (type RansomLook) pour détecter les revendications touchant l'organisation, ses partenaires ou fournisseurs
* Sensibiliser les utilisateurs au phishing, vecteur d'accès initial privilégié par les affiliés Qilin

#### Phase 2 — Détection et analyse

* Surveiller les signes de chiffrement massif : extensions de fichiers modifiées, dépôts de notes de rançon, processus suspects
* Alerter sur les suppressions de Volume Shadow Copies (vssadmin delete shadows), l'arrêt des services de sécurité et de sauvegarde
* Détecter les exfiltrations massives vers des services de stockage cloud ou Tor (rclone, Mega)
* Surveiller les publications du site de fuite Qilin mentionnant l'entreprise ou des partenaires de la supply chain

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les systèmes compromis et désactiver les comptes compromis
* Préserver les preuves (images mémoire et disque, journaux) avant toute restauration
* Bloquer les domaines et IP de C2 ainsi que les canaux de communication de l'attaquant
* Informer direction, juridique et préparer les notifications réglementaires (RGPD/ANSSI)

#### Phase 4 — Activités post-incident

* Restaurer depuis des sauvegardes vérifiées saines après remédiation complète du périmètre
* Identifier le chemin d'accès initial (vulnérabilité, identifiants volés, accès distant) et le corriger
* Réinitialiser l'ensemble des identifiants et révoquer tokens et sessions actives
* Réaliser un retour d'expérience et mettre à jour les règles de détection et le plan de crise

#### Phase 5 — Threat Hunting (proactif)

* Chasser les outils connus des affiliés Qilin (AnyDesk, Atera, Mimikatz, Rclone, Process Hacker) dans les télémétries EDR
* Rechercher les créations de comptes locaux/admin inexpliquées et l'usage anormal de RDP/VPN
* Vérifier les connexions sortantes vers Tor et les services de partage de fichiers
* Comparer les TTP et indicateurs publiés dans les advisories CTI sur Qilin avec les journaux des 90 derniers jours

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact : revendication typique d'une opération de chiffrement par un groupe ransomware |
| **T1567** | Exfiltration Over Web Service : modèle de double extorsion avec publication des données sur un site de fuite |

---

### Sources

* [https://www.ransomlook.io//group/qilin](https://www.ransomlook.io//group/qilin)


---

<div id="outil-public-decoute-via-exploitation-de-carte-sim-mecanisme-st-setup-call-publie-sur-github"></div>

## Outil public d'écoute via exploitation de carte SIM (mécanisme S@T setup call) publié sur GitHub

### Résumé

Un dépôt GitHub nommé « Exploit-Mobile-Phone-SIM-Card-for-Eavesdropping » décrit une attaque consistant à envoyer un SMS binaire contenant un payload exécuté par le système de la carte SIM (mécanisme « S@t setup call ») pour déclencher un appel sortant vers un numéro contrôlé par l'attaquant, permettant ensuite d'écouter l'environnement de la victime, généralement sans interaction de sa part (signe extérieur : bref allumage du rétroéclairage). L'auteur explique contourner le filtrage des opérateurs en injectant le SMS via un émulateur de station de base (BTS) qui capte brièvement le téléphone. L'attaque n'est pas fiable à 100 % : certains téléphones affichent une demande de confirmation. L'auteur liste d'autres abus possibles (DoS téléphonique, épuisement du crédit, appels vers numéros surtaxés) et rappelle le caractère illégal et non éthique de l'écoute à l'insu d'autrui.

---

### Analyse opérationnelle

Pour les équipes sécurité mobile : détecter les SMS binaires (classe 2 / SIM Toolkit, ports S@T) dans les journaux MDM/EMM et passerelles SMS d'entreprise ; surveiller les appels sortants inexpliqués et les activations d'écran sans interaction. Mesures techniques : désactiver ou verrouiller le SIM Toolkit et les services S@T via MDM, imposer des SIM récentes avec correctifs Java Card, restreindre l'itinérance automatique, signaler les BTS pirates aux opérateurs. Les SOC télécoms peuvent déployer la détection d'anomalies radio (IMSI catchers) et filtrer les SMS OTA provenant de réseaux non homologués.

---

### Implications stratégiques

La disponibilité publique d'outils d'écoute téléphonique abaisse la barrière technique pour l'espionnage d'entreprise, le harcèlement et la surveillance de personnalités. Les secteurs sensibles (gouvernement, défense, juridique, journalisme) sont particulièrement exposés à un risque de surveillance physique. Cela renforce la nécessité d'intégrer le canal mobile (voix/SMS) dans les évaluations de risque et de négocier avec les opérateurs le filtrage des SMS OTA S@T, mécanisme largement obsolète mais encore actif sur de nombreux parcs.

---

### Recommandations

* Désactiver le SIM Toolkit / les services S@T sur les parcs mobiles d'entreprise via MDM
* Sensibiliser aux signaux d'une écoute potentielle (rétroéclairage bref sans interaction, appel sortant inconnu)
* Exiger des opérateurs le filtrage des SMS binaires OTA et la notification des anomalies radio
* Remplacer les SIM anciennes et appliquer les mises à jour des cartes (correctifs Java Card)

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les terminaux mobiles, versions de SIM et d'OS via MDM/EMM
* Désactiver par politique le SIM Toolkit et les services S@T/OTA non nécessaires
* Contractualiser avec les opérateurs le filtrage des SMS binaires et la détection de stations de base non autorisées
* Former les utilisateurs aux signaux d'une écoute potentielle (appel sortant inconnu, rétroéclairage spontané)

#### Phase 2 — Détection et analyse

* Corréler dans les journaux CDR les appels sortants automatiques vers des numéros inconnus
* Surveiller via MDM la réception de SMS de classe 2 / messages OTA destinés à la SIM
* Alerter sur les bascules réseau anormales (attachement à une BTS inconnue puis retour au réseau public)
* Détecter les activations d'écran sans interaction utilisateur

#### Phase 3 — Confinement, éradication et récupération

* Passer le terminal suspect en mode avion ou l'éteindre si une écoute est suspectée
* Retirer ou remplacer la carte SIM et réinitialiser les paramètres réseau
* Signaler l'incident à l'opérateur (recherche de BTS pirate, blocage des SMS OTA)
* Préserver les preuves (journaux MDM, CDR) avant toute manipulation du terminal

#### Phase 4 — Activités post-incident

* Analyser avec l'opérateur les CDR pour identifier le numéro de l'attaquant et la durée des sessions
* Remplacer la SIM et vérifier l'absence d'applications SIM malveillantes
* Documenter l'incident et durcir les politiques MDM (désactivation définitive de S@T)
* Évaluer la confidentialité des informations exposées pendant l'écoute

#### Phase 5 — Threat Hunting (proactif)

* Rechercher historiquement les SMS binaires/OTA dans les journaux des passerelles SMS
* Chasser les appels sortants de courte durée répétés vers un même numéro
* Vérifier les enregistrements d'attachement radio pour des BTS non répertoriées
* Auditer les terminaux dont le SIM Toolkit reste actif malgré les politiques de sécurité

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxps://github[.]com/X-3306/Exploit-Mobile-Phone-SIM-Card-for-Eavesdropping` | Low |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1478** | Exploit SS7 (analogue) : abus des mécanismes de signalisation télécom — SMS binaire S@T injecté via un émulateur de station de base pour déclencher un appel sortant et écouter l'environnement de la cible |

---

### Sources

* [https://github.com/X-3306/Exploit-Mobile-Phone-SIM-Card-for-Eavesdropping](https://github.com/X-3306/Exploit-Mobile-Phone-SIM-Card-for-Eavesdropping)


---

<div id="extradition-vers-les-etats-unis-dun-developpeur-russe-soupconne-de-prises-de-controle-de-comptes-bancaires"></div>

## Extradition vers les États-Unis d'un développeur russe soupçonné de prises de contrôle de comptes bancaires

### Résumé

Sergei Anatolyevich Filimonov, 36 ans, développeur web russe, a été extradé de la République de Géorgie vers les États-Unis et a comparu le 4 septembre devant un tribunal fédéral d'Atlanta, plaidant non coupable de fraude et de vol d'identité. Selon le FBI d'Atlanta, il aurait utilisé des domaines usurpés et des pages de connexion frauduleuses pour cibler des clients de banque en ligne et dérober des millions de dollars. L'affaire est liée à la saisie fédérale en décembre 2025 du domaine web3adspanels[.]org. Filimonov reste en détention.

---

### Analyse opérationnelle

Indicateur à bloquer et surveiller : le domaine web3adspanels[.]org (saisi) et tout domaine apparenté de phishing bancaire. Renforcer la détection des pages de connexion frauduleuses (typosquatting, homoglyphes) via filtrage DNS et passerelles web ; déployer un MFA résistant au phishing (FIDO2) sur les accès bancaires ; surveiller la réutilisation éventuelle des infrastructures liées à l'affaire. Les équipes anti-fraude doivent corréler les signalements d'ATO avec des campagnes de faux portails bancaires et surveiller les modifications de coordonnées de paiement.

---

### Implications stratégiques

L'extradition depuis la Géorgie illustre l'élargissement de la coopération judiciaire internationale contre la cybercriminalité d'Europe de l'Est, y compris vis-à-vis d'acteurs intermédiaires comme des développeurs. Les pertes de plusieurs millions de dollars confirment la rentabilité des schémas d'ATO par phishing bancaire. Les organisations financières doivent anticiper la poursuite de ces campagnes malgré les arrestations, les infrastructures de phishing étant facilement recréées.

---

### Recommandations

* Bloquer et surveiller le domaine web3adspanels[.]org et les domaines apparentés
* Déployer un MFA résistant au phishing (FIDO2/passkeys) sur les accès bancaires et sensibles
* Mettre en place la détection de domaines usurpés (monitoring de marque, typosquatting)
* Sensibiliser les utilisateurs aux fausses pages de connexion bancaires

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer un MFA résistant au phishing (FIDO2/passkeys) sur les accès bancaires et comptes à privilèges
* Mettre en place un monitoring de marque pour détecter les domaines usurpés et typosquats
* Configurer le filtrage DNS/web avec réputation des domaines de phishing
* Définir une procédure de prise de contrôle de compte (ATO) avec le service anti-fraude

#### Phase 2 — Détection et analyse

* Alerter sur les connexions depuis des domaines/IP de phishing connus et les soumissions de formulaires de connexion anormales
* Détecter les modifications de coordonnées bancaires ou de paramètres de compte suivies de virements
* Surveiller les connexions atypiques (géolocalisation, empreinte de périphérique)
* Intégrer les flux CTI mentionnant web3adspanels[.]org et les infrastructures liées à l'affaire

#### Phase 3 — Confinement, éradication et récupération

* Geler ou bloquer les comptes compromis et révoquer sessions et tokens
* Bloquer les domaines de phishing au niveau DNS/proxy et demander un takedown (registrar/CERT)
* Faire rappeler ou annuler les transactions frauduleuses en coordination avec la banque
* Réinitialiser les identifiants des victimes et vérifier les règles de transfert

#### Phase 4 — Activités post-incident

* Analyser le vecteur (email, SMS, publicité) et l'étendue des victimes potentielles
* Notifier les clients concernés et les autorités (plainte, IC3, régulateur si données personnelles)
* Renforcer les contrôles anti-fraude (step-up d'authentification sur les opérations sensibles)
* Partager les IOC avec la communauté et l'ISAC sectoriel

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux proxy/DNS les accès à web3adspanels[.]org et aux domaines similaires
* Chasser les identifiants bancaires exposés dans des fuites publiques (risque de credential stuffing)
* Corréler les campagnes de phishing passées avec les infrastructures de l'affaire (IP, certificats, trackers)
* Auditer les comptes ayant modifié leurs paramètres de sécurité au cours des 90 derniers jours

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `web3adspanels[.]org` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Spearphishing Link : diffusion de pages de connexion frauduleuses pour récolter les identifiants bancaires des victimes |
| **T1583.001** | Acquire Infrastructure: Domains : enregistrement de domaines usurpés imitant des portails bancaires légitimes |
| **T1656** | Impersonation : usurpation de l'identité visuelle de sites bancaires pour tromper les clients |

---

### Sources

* [https://databreaches.net/2026/09/09/russian-suspect-in-bank-account-takeovers-is-extradited-to-us/](https://databreaches.net/2026/09/09/russian-suspect-in-bank-account-takeovers-is-extradited-to-us/)


---

<div id="chatter-echeance-imminente-11-septembre-suggeree-en-lien-avec-shinyhunters"></div>

## Chatter : échéance imminente (11 septembre) suggérée en lien avec ShinyHunters

### Résumé

Un message publié sur Mastodon (infosec.exchange) par le compte security_crawler_carl évoque une « Ticking Clock Debuff » de durée inconnue expirant le 11 septembre, accompagné des hashtags #Ransomware, #DataBreach, #CyberSecurity, #GovernmentSecurity et #ShinyHunters. La publication, fragmentaire (troisième volet d'une série), suggère une échéance imminente liée à une fuite de données ou à une extorsion associée à ShinyHunters, sans préciser la victime ni la nature exacte des données.

---

### Analyse opérationnelle

Surveiller les canaux de fuite et les comptes affiliés à ShinyHunters jusqu'au 11 septembre et au-delà ; vérifier si l'organisation ou ses partenaires figurent parmi les cibles potentielles ; préparer les critères de déclenchement du plan de réponse à incident et de notification réglementaire en cas de publication de données. Corréler avec les campagnes récentes d'extorsion visant le secteur public et les plateformes SaaS (vishing, ingénierie sociale).

---

### Implications stratégiques

L'usage d'un compte à rebours est une tactique de pression psychologique classique de l'extorsion visant à accélérer la décision de paiement des victimes. La mention #GovernmentSecurity suggère un ciblage du secteur public, avec des enjeux de continuité de service et de confiance citoyenne. La médiatisation croissante de ShinyHunters accroît le risque réputationnel pour toute organisation citée, même sans confirmation technique de compromission.

---

### Recommandations

* Surveiller les sites de fuite et canaux Telegram/X/Mastodon liés à ShinyHunters jusqu'à l'échéance
* Vérifier l'exposition potentielle de l'organisation (journaux d'accès, alertes CTI, dark web)
* Préparer la cellule de communication de crise et les procédures de notification (CNIL/RGPD)
* Renforcer l'authentification (MFA résistant au phishing) sur les données clients et les plateformes CRM/SaaS

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir une veille CTI sur les acteurs d'extorsion (ShinyHunters) et leurs canaux de publication
* Documenter les procédures de notification en cas de fuite de données (RGPD/CNIL, clients, partenaires)
* Préparer une cellule de crise communication/juridique avec scénarios de fuite de données
* Cartographier les données sensibles et leurs accès (CRM, bases clients, environnements SaaS)

#### Phase 2 — Détection et analyse

* Surveiller les sites de fuite, Telegram et réseaux sociaux pour les publications liées à l'échéance du 11 septembre
* Alerter sur toute mention du nom de l'organisation, de ses marques ou de ses partenaires
* Détecter les accès anormaux aux bases de données clients et entrepôts de données (CRM, SaaS)
* Corréler les tentatives de vishing/ingénierie sociale récentes avec les TTP connus de ShinyHunters

#### Phase 3 — Confinement, éradication et récupération

* Si une compromission est confirmée, révoquer les accès et tokens compromis (OAuth, intégrations SaaS)
* Isoler les systèmes concernés et préserver les preuves (journaux, snapshots)
* Bloquer les comptes et canaux utilisés par l'attaquant
* Coordonner avec le juridique avant tout contact avec l'acteur de menace

#### Phase 4 — Activités post-incident

* Qualifier précisément les données exposées et notifier les personnes et régulateurs concernés
* Communiquer de manière transparente avec les clients et parties prenantes
* Remédier au vecteur d'accès initial et renforcer les contrôles (MFA, moindre privilège)
* Mettre à jour le plan de crise sur la base du retour d'expérience

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les exfiltrations massives récentes (volumes anormaux, exports CRM, usage de rclone)
* Chasser les connexions atypiques aux applications SaaS (nouveaux périphériques, IP Tor ou résidentielles)
* Vérifier la présence d'identifiants de l'organisation dans les fuites publiques (credential monitoring)
* Auditer les intégrations OAuth et applications tierces connectées aux données clients

---

### Sources

* [https://infosec.exchange/@security_crawler_carl/117241502967296700](https://infosec.exchange/@security_crawler_carl/117241502967296700)
