# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [Chaîne d'approvisionnement d'inférence auto-expansive : un agent IA récolte, valide et re-sert des accès LLM volés](#chaine-dapprovisionnement-dinference-auto-expansive-un-agent-ia-recolte-valide-et-re-sert-des-acces-llm-voles)
  * [BTR_CLI : attaque BYOVD contre Windows Defender via un pilote signé vulnérable](#btrcli-attaque-byovd-contre-windows-defender-via-un-pilote-signe-vulnerable)
  * [Avis de sécurité GitLab AV26-917 : les plateformes CI/CD, cibles de choix](#avis-de-securite-gitlab-av26-917-les-plateformes-cicd-cibles-de-choix)
  * [Direwolf : le groupe de ransomware à double extorsion publie la victime Port of Tanjung Pelepas sur son site de fuite](#direwolf-le-groupe-de-ransomware-a-double-extorsion-publie-la-victime-port-of-tanjung-pelepas-sur-son-site-de-fuite)
  * [VX-Pack : kit de phishing AiTM « as-a-service » d'origine brésilienne ciblant les banques au Brésil et au Portugal](#vx-pack-kit-de-phishing-aitm-as-a-service-dorigine-bresilienne-ciblant-les-banques-au-bresil-et-au-portugal)
  * [Phishing possible détecté sur le domaine ceihmedicalcenter[.]com[.]br (page imitant Adobe)](#phishing-possible-detecte-sur-le-domaine-ceihmedicalcentercombr-page-imitant-adobe)
  * [Un ressortissant ukrainien condamné à quatre ans de prison pour conspiration de fraude électronique liée au ransomware Conti](#un-ressortissant-ukrainien-condamne-a-quatre-ans-de-prison-pour-conspiration-de-fraude-electronique-liee-au-ransomware-conti)
  * [Fuite MyDr en Pologne : environ 18,8 millions de personnes et plus de 12 000 établissements médicaux concernés](#fuite-mydr-en-pologne-environ-188-millions-de-personnes-et-plus-de-12-000-etablissements-medicaux-concernes)
* [Signaux faibles](#signaux-faibles)
  * [Des pirates ont abusé de Claude pour extraire des secrets de 1,8 million d'applications Android](#des-pirates-ont-abuse-de-claude-pour-extraire-des-secrets-de-18-million-dapplications-android)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

La veille du jour est dominée par la publication de 67 vulnérabilités, un volume qui impose de prioriser le tri sur les failles exploitables et les actifs exposés. Les 24 incidents de fuite de données signalés confirment une pression soutenue sur les données personnelles et corporatives, suggérant l'exploitation de compromissions antérieures ou d'expositions via des tiers. L'absence totale de rapports sur des acteurs de la menace (0) est atypique et pourrait refléter un creux de publication ou une lacune de collecte à vérifier auprès des sources. L'activité géopolitique (4 signalements) reste modérée mais mérite un suivi pour anticiper les tensions susceptibles d'alimenter des campagnes ciblées. Le volet réglementaire est faible (1), sans évolution normative majeure à intégrer immédiatement. Les 9 articles d'analyse fournissent un contexte utile mais secondaire face à l'urgence opérationnelle des vulnérabilités. Recommandation : concentrer les efforts du SOC sur la priorisation des correctifs et l'enquête sur les fuites potentiellement liées à notre périmètre.

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
| **Monde, Russie, Chine, États-Unis** | Technologie / Intelligence artificielle / Applications mobiles | Instrumentalisation de l'IA générative par des groupes d'espionnage liés à des États | Des acteurs de menaces à motivation financière et des groupes d'espionnage liés à la Russie et à la Chine ont détourné le modèle de langage Claude d'Anthropic afin d'extraire des secrets (clés d'API, jetons d'authentification) présents dans environ 1,8 million d'applications Android. Au-delà de la dimension cyber, cette affaire illustre la géopolitique de l'IA : les modèles commerciaux occidentaux deviennent un levier de collecte de renseignement pour des États adverses, exposant la chaîne de valeur technologique et la propriété intellectuelle. Elle confirme la tendance à l'industrialisation de l'espionnage via l'IA générative et interroge les politiques de contrôle des usages et de sécurisation des secrets dans les applications mobiles. | [https://www.bleepingcomputer.com/news/security/hackers-abused-claude-to-extract-secrets-from-18m-android-apps/](https://www.bleepingcomputer.com/news/security/hackers-abused-claude-to-extract-secrets-from-18m-android-apps/)<br>[https://infosec.exchange/@cloud/117254968634820247](https://infosec.exchange/@cloud/117254968634820247) |
| **France, Europe** | Intelligence économique / Stratégie d'entreprise | L'intelligence économique comme impératif stratégique face au retour des rapports de puissance | La note de synthèse de l'EPGE restitue l'intervention de Christian Harbulot (podcast KPMG du 27 janvier 2026) : les entreprises ne peuvent plus lire l'économie mondiale uniquement à l'aune du marché et de la concurrence, mais doivent intégrer des systèmes de puissance où dépendances, technologies, information et action collective déterminent les positions. L'interdépendance produit de la vulnérabilité lorsqu'un acteur maîtrise un maillon critique d'une chaîne de valeur ou utilise sa position économique comme levier. L'intelligence économique y est redéfinie comme « usage offensif de l'information » : orienter la recherche d'information selon des objectifs stratégiques, analyser les signaux utiles, transformer l'information en avantage. La note plaide pour élever l'IE au rang de compétence de direction générale et de conseil d'administration, dans un contexte de tensions géopolitiques, de ruptures d'approvisionnement, de cyberattaques et d'affrontements informationnels. | [https://www.epge.fr/note-de-synthese-lintelligence-economique-un-imperatif-strategique-face-aux-nouvelles-menaces/](https://www.epge.fr/note-de-synthese-lintelligence-economique-un-imperatif-strategique-face-aux-nouvelles-menaces/) |
| **États-Unis, Moyen-Orient, Chine, Monde** | Géopolitique / Relations internationales | 25 ans du 11-Septembre : relecture des bouleversements géopolitiques | À l'occasion du 25e anniversaire des attentats du 11 septembre 2001 (environ 3 000 morts, perpétrés par Al-Qaïda contre le World Trade Center et le Pentagone), Pascal Boniface (IRIS) nuance l'idée d'une rupture totale de l'ordre mondial : les attentats ont amplifié et accéléré des dynamiques préexistantes, notamment la multiplication des interventions extérieures américaines dans le cadre de la « guerre contre le terrorisme », sans bouleverser fondamentalement les rapports de force ni les grandes tendances géopolitiques. Il souligne qu'un choc structurel moins médiatisé de l'année 2001 est l'adhésion de la Chine à l'OMC, matrice de la redistribution de la puissance économique mondiale observable aujourd'hui. | [https://www.iris-france.org/le-11-septembre-a-t-il-change-le-monde/](https://www.iris-france.org/le-11-septembre-a-t-il-change-le-monde/) |
| **Israël, Territoires palestiniens, Émirats arabes unis, France, Royaume-Uni, Canada** | Géopolitique / Diplomatie | Crise politique israélienne et tensions diplomatiques autour du conflit israélo-palestinien | Le journal israélien Haaretz a révélé le 8 septembre que Benyamin Netanyahou aurait eu connaissance, via le leader émirati Mohammed Ben Zayed, dix jours avant le 7 octobre, de la préparation d'une opération majeure du Hamas sur le territoire israélien ; des révélations réfutées mais qui fragilisent le Premier ministre à l'approche des élections législatives d'octobre. Cette publication intervient au lendemain de l'annonce de sanctions par la France, le Royaume-Uni et le Canada contre les produits issus des colonies israéliennes en Cisjordanie, constituant un véritable revers diplomatique et politique pour Netanyahou. La conjonction de ces éléments ouvre une période d'incertitude sur la stabilité politique israélienne, sur la pérennité de l'ère Netanyahou et sur les équilibres régionaux, notamment le rôle des Émirats arabes unis. | [https://www.iris-france.org/clap-de-fin-pour-netanyahou/](https://www.iris-france.org/clap-de-fin-pour-netanyahou/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| Règlement européen sur la résilience cyber (CRA) – Échéance du 11 septembre 2026 pour les obligations de signalement des fabricants | Union européenne (ENISA et CSIRT de coordination, via la plateforme unique de signalement – SRP) | 2026-09-11 | Union européenne | Règlement européen sur la résilience cyber (CRA) – Échéance du 11 septembre 2026 pour les obligations de signalement des fabricants | À compter du 11 septembre 2026, les fabricants de produits avec éléments numériques soumis au Cyber Resilience Act (CRA) doivent signaler les vulnérabilités activement exploitées (AEV) et les incidents graves affectant la sécurité de leurs produits via la plateforme unique de signalement (SRP) : alerte précoce sous 24 heures, notification complète sous 72 heures, puis rapport final au plus tard 14 jours après la disponibilité d'une mesure corrective ou atténuante pour une AEV, et dans le mois suivant la notification de 72 heures pour un incident grave. Le signalement volontaire prévu à l'article 15 (vulnérabilités, cybermenaces, incidents, quasi-incidents auprès d'un CSIRT ou de l'ENISA) ne sera pas disponible au lancement de la SRP et sera ajouté ultérieurement. Les obligations des Stewards (notamment la communauté open source) n'entrent en vigueur que le 11 décembre 2027 : l'échéance du 11 septembre 2026 concerne donc uniquement les fabricants. En pratique, lorsqu'un fabricant identifie une vulnérabilité activement exploitée dans un composant open source tiers, il reste responsable mais pourra solliciter le projet, ses mainteneurs ou son steward pour obtenir informations, support et collaboration, notamment dans le cadre de l'article 13(6) du CRA. L'OpenSSF a publié un guide de préparation à l'attention des fabricants ainsi qu'un résumé d'une page pour les projets open source hébergés par la Linux Foundation (hxxps://cra-lf-readiness[.]openssf[.]org). | `hxxps://openssf[.]org/blog/2026/09/11/a-community-guide-to-the-eu-cra-september-11-deadline-for-manufacturers/` |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Éducation (district scolaire public, Texas, États-Unis)** | Lamesa Independent School District (Lamesa ISD) | Aucune compromission de données du district confirmée : les données étudiants, personnel et de sécurité ne sont pas concernées selon le district. | Inconnu | [https://databreaches.net/2026/09/11/tx-two-lamesa-isd-employees-arrested-over-security-breach/](https://databreaches.net/2026/09/11/tx-two-lamesa-isd-employees-arrested-over-security-breach/) |
| **Secteur public / administration (transport et sécurité routière, Floride, États-Unis)** | Florida Department of Highway Safety and Motor Vehicles (FLHSMV) – base de données DAVID | Dossiers de conducteurs de la base DAVID : données personnelles sensibles et informations relatives aux véhicules. Nombre exact non confirmé (plus de 200 000 dossiers revendiqués par ShinyHunters). | 200000 | [https://osintsights.com/florida-dmv-breach-exposed-via-stolen-police-credentials?utm_source=mastodon&utm_medium=social](https://osintsights.com/florida-dmv-breach-exposed-via-stolen-police-credentials?utm_source=mastodon&utm_medium=social) |
| **Santé (fournisseur de soins à domicile et d'équipements médicaux, États-Unis)** | AdaptHealth | Données personnelles et potentiellement de santé (PII/PHI) d'environ 4,1 millions de personnes. | 4100000 | [https://www.securitymagazine.com/articles/102573-41m-impacted-by-adapthealth-data-breach](https://www.securitymagazine.com/articles/102573-41m-impacted-by-adapthealth-data-breach) |
| **Santé (soins à domicile et staffing médical, États-Unis)** | Interim HealthCare | Dossiers médicaux et informations cliniques de patients (PHI), données financières d'entreprise, détails des franchisés, audits internes et communications professionnelles (plus de 1,5 To revendiqués au total). | 1530 | [https://cyber.netsecops.io/articles/two-ransomware-gangs-genesis-anubis-claim-interim-healthcare-breach/?utm_source=mastodon&utm_medium=social&utm_campaign=daily](https://cyber.netsecops.io/articles/two-ransomware-gangs-genesis-anubis-claim-interim-healthcare-breach/?utm_source=mastodon&utm_medium=social&utm_campaign=daily) |
| **Santé / dispositifs médicaux (fabricant, Deerfield, Illinois, États-Unis)** | Baxter International | 7,1 millions d'enregistrements Salesforce revendiqués, dont certains contiendraient des données personnelles identifiables (PII) ; nature et volume exacts non confirmés par Baxter. | 7100000 | [https://www.defensorum.com/shinyhunters-baxter-international-records/](https://www.defensorum.com/shinyhunters-baxter-international-records/) |
| **Santé (réseau de cabinets d'ophtalmologie, États-Unis)** | American Vision Partners | Données personnelles et de santé de plus de 2,2 millions de personnes (chiffre final réévalué) ; environ 258 000 personnes incluses dans la sous-classe des dommages. | 2200000 | [https://www.netsec.news/american-vision-partners-data-breach-litigation/](https://www.netsec.news/american-vision-partners-data-breach-litigation/) |
| **Télécommunications (opérateur mobile, Suisse)** | Salt Mobile SA (Suisse) | Données clients potentiellement compromises ; nature et volume en cours de vérification par Salt. | Inconnu | [https://www.watson.ch/fr/suisse/cybercrime/467949601-salt-alerte-sur-un-vol-de-donnees-en-suisse-ce-qui-aurait-fuite](https://www.watson.ch/fr/suisse/cybercrime/467949601-salt-alerte-sur-un-vol-de-donnees-en-suisse-ce-qui-aurait-fuite)<br>[https://mastobot.ping.moi/@cyberveille/117252882822844446](https://mastobot.ping.moi/@cyberveille/117252882822844446) |
| **Santé - solutions logicielles médicales (EHR/CHI)** | Veradigm (ex-Allscripts) | Données patients (nature et volume exacts non précisés dans les sources ; en attente de la notification officielle de Veradigm). | Inconnu | [https://www.bleepingcomputer.com/news/security/veradigm-discloses-patient-data-breach-after-gentlemen-gang-claims-attack/](https://www.bleepingcomputer.com/news/security/veradigm-discloses-patient-data-breach-after-gentlemen-gang-claims-attack/) |
| **Vérification d'identité / KYC (clients : casinos, dispensaires, hôtels, locations de véhicules)** | IDScan.net | Noms complets, numéros de permis de conduire et de pièces d'identité gouvernementales, dates de naissance, photos et scans numériques haute résolution de permis de conduire américains et canadiens (153M+ permis revendiqués, 170M+ documents exposés). | 153000000 | [https://thecybersecguru.com/news/idscan-data-breach-153-million-drivers-licenses/](https://thecybersecguru.com/news/idscan-data-breach-153-million-drivers-licenses/)<br>[https://lifehacker.com/tech/over-150-million-drivers-license-leaked?utm_medium=RSS](https://lifehacker.com/tech/over-150-million-drivers-license-leaked?utm_medium=RSS)<br>[https://www.bleepingcomputer.com/news/security/idscan-confirms-breach-tied-to-153-million-stolen-drivers-licenses/](https://www.bleepingcomputer.com/news/security/idscan-confirms-breach-tied-to-153-million-stolen-drivers-licenses/) |
| **Retail - mobilier (Australie)** | Nick Scali | Noms, adresses e-mail, adresses de livraison et numéros de téléphone de clients (nombre d'individus non divulgué ; aucune donnée de carte de paiement compromise). | Inconnu | [https://beyondmachines.net/event_details/nick-scali-discloses-cyberattack-affecting-operations-and-customer-information-v-c-u-m-h/gD2P6Ple2L](https://beyondmachines.net/event_details/nick-scali-discloses-cyberattack-affecting-operations-and-customer-information-v-c-u-m-h/gD2P6Ple2L) |
| **VPN / Cybersécurité** | Surfshark | Secrets internes exposés via un serveur de test mal configuré ; aucune donnée client confirmée comme compromise. | Inconnu | [https://securityonline.info/surfshark-test-server-breach/?utm_source=mastodon&utm_medium=jetpack_social](https://securityonline.info/surfshark-test-server-breach/?utm_source=mastodon&utm_medium=jetpack_social) |
| **Éducation - enseignement supérieur public (Bolivie)** | Universidad Autónoma Tomás Frías | Numéros de cartes d'identité nationale, noms complets, filières d'études et identifiants étudiants (enregistrements d'étudiants et candidats de 2004 à 2025). | Inconnu | [https://go.darkwebsonar.io/dbhunter-mastodon](https://go.darkwebsonar.io/dbhunter-mastodon) |
| **Courtage de données / information** | National Public Data | Numéros de sécurité sociale (SSN) et enregistrements personnels (noms, coordonnées et autres données d'identité) | 272000000 | [https://infosec.exchange/@indigoprivacy/117250342212656536](https://infosec.exchange/@indigoprivacy/117250342212656536) |
| **Éducation / EdTech** | Mathspace | Noms complets, noms d'utilisateur, adresses e-mail et détails de compte. Les dossiers académiques, mots de passe, jetons d'authentification et identifiants SSO ne sont pas compromis ; aucune publication ou vente des données n'est constatée à ce jour | 1079819 | [https://astig.ph/mathspace-data-breach-metabase-vulnerability-2026/](https://astig.ph/mathspace-data-breach-metabase-vulnerability-2026/) |
| **Secteur public / forces de l'ordre (État de Floride)** | Florida FLHSMV (base de données DAVID) | Données du registre des conducteurs et véhicules (DAVID) consultées via un compte policier compromis ; périmètre exact en cours d'évaluation | Inconnu | [https://www.bleepingcomputer.com/news/security/florida-confirms-dmv-database-breached-via-stolen-police-account/](https://www.bleepingcomputer.com/news/security/florida-confirms-dmv-database-breached-via-stolen-police-account/) |
| **Éducation supérieure (université privée)** | University of San Francisco (USF) | Non confirmé - aucune donnée personnelle, identifiant ni échantillon publié ; seules des informations institutionnelles issues de sources publiques sont citées | Inconnu | [https://www.yazoul.net/intel/claim/2026-09-11-university-of-san-francisco-ransomware-claim-by-thegentlemen-sep-2026](https://www.yazoul.net/intel/claim/2026-09-11-university-of-san-francisco-ransomware-claim-by-thegentlemen-sep-2026) |
| **Santé / logistique pharmaceutique** | McKesson | 284 millions de dossiers de patients (données personnelles de santé) | 284000000 | [https://theperimetersite.com/report/249](https://theperimetersite.com/report/249) |
| **Multi-sectoriel (entreprises utilisant Microsoft 365)** | Organisations utilisant Microsoft 365 (cibles de campagne) | Identifiants, jetons de session et données organisationnelles sensibles issues des tenants Microsoft 365 (courriels, fichiers) | Inconnu | [https://www.bleepingcomputer.com/news/security/passkey-themed-phishing-attacks-lead-to-microsoft-365-data-theft/](https://www.bleepingcomputer.com/news/security/passkey-themed-phishing-attacks-lead-to-microsoft-365-data-theft/) |
| **Secteur public / administration numérique (Japon)** | Agence numérique du Japon (Government Solution Service - GSS) | Données personnelles de travailleurs et sous-traitants (exposition potentielle) ; identifiants My Number et données financières non compromis | 246000 | [https://www.gadgets360.com/cryptocurrency/news/japan-digital-agency-reports-potential-leak-of-246000-records-after-cyberattack-crypto-scams-hacks-data-breach-12034550](https://www.gadgets360.com/cryptocurrency/news/japan-digital-agency-reports-potential-leak-of-246000-records-after-cyberattack-crypto-scams-hacks-data-breach-12034550) |
| **Technologie / plateforme de contenus (musique et vidéo libres de droits)** | MuPot | Noms, adresses e-mail et numéros de téléphone mobile (périmètre variable selon les utilisateurs ; ampleur exacte non confirmée) | Inconnu | [https://biz.chosun.com/en/en-it/2026/09/11/LGDPJ3JHORBJVELRETSAIBMFRE/](https://biz.chosun.com/en/en-it/2026/09/11/LGDPJ3JHORBJVELRETSAIBMFRE/) |
| **Vérification d'identité / KYC / Technologies** | IDScan (société de vérification d'identité) | Scans de permis de conduire (153 millions), numéros d'identification, informations personnelles et enregistrements clients | 153000000 | [https://therecord.media/idscan-data-breach-notice-drivers-licenses](https://therecord.media/idscan-data-breach-notice-drivers-licenses) |
| **Politique / Organisations et partis politiques** | Organisations d'extrême droite françaises (dont un parti politique) | Non détaillé dans la source accessible ; données internes et informations sur les adhérents des organisations piratées présumées affectées | Inconnu | [https://www.lemonde.fr/politique/article/2026/09/11/anthropic-revele-que-plusieurs-organisations-d-extreme-droite-francaises-dont-un-parti-politique-ont-ete-piratees-a-l-aide-de-son-ia-claude_6770595_823448.html](https://www.lemonde.fr/politique/article/2026/09/11/anthropic-revele-que-plusieurs-organisations-d-extreme-droite-francaises-dont-un-parti-politique-ont-ete-piratees-a-l-aide-de-son-ia-claude_6770595_823448.html) |
| **Administration publique / Fiscalité** | Direction générale des Finances publiques (site des impôts - fisc français) | Données fiscales et personnelles de contribuables (volume massif, périmètre exact non précisé), volées durant l'été 2026 | Inconnu | [https://www.lemonde.fr/pixels/article/2026/09/11/piratage-du-site-des-impots-la-cnil-va-controler-le-fisc-apres-le-vol-de-donnees-massif-survenu-durant-l-ete_6770181_4408996.html](https://www.lemonde.fr/pixels/article/2026/09/11/piratage-du-site-des-impots-la-cnil-va-controler-le-fisc-apres-le-vol-de-donnees-massif-survenu-durant-l-ete_6770181_4408996.html) |
| **Pharmaceutique / Santé** | Novo Nordisk | Données expérimentales sur des médicaments, enregistrements clients, écosystème IA/ML, secrets techniques (tokens API, identifiants de bases de données, mots de passe de comptes de service) ; plus de 1 To de données publiées après refus de paiement | Inconnu | [https://www.bankinfosecurity.com/novo-nordisk-data-breach-tied-to-stolen-github-access-tokens-a-32802](https://www.bankinfosecurity.com/novo-nordisk-data-breach-tied-to-stolen-github-access-tokens-a-32802) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-85706** | 10.0 | N/A | TRUE | GitLab Community Edition (CE) et Enterprise Edition (EE) auto-gérées : toutes versions à partir de 18.7 antérieures à 19.1.8, versions 19.2 antérieures à 19.2.6 et versions 19.3 antérieures à 19.3.2 | Path traversal (traversée de chemin) dans l'API de consultation des commits de dépôt — lecture arbitraire de fichiers sans authentification (CVSS 10.0) | Divulgation de secrets et d'identifiants (tokens, clés SSH, credentials cloud/base de données), compromission potentielle des pipelines CI/CD et des systèmes connectés, empoisonnement de la chaîne d'approvisionnement logicielle, pivot vers les environnements de développement, staging et production. | Active | Mettre à jour vers GitLab 19.1.8, 19.2.6 ou 19.3.2 ; ne pas exposer les instances auto-gérées à Internet sans nécessité ; inspecter les journaux pour des POST vers /api/v4/projects/{id}/repository/commits/ avec paramètre file.path ; faire pivoter les secrets potentiellement exposés. Référence éditeur : bulletin GitLab du 10/09/2026 (patch release 19.3.2). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/)<br>[https://thehackernews.com/2026/09/gitlab-cvss-10-file-read-flaw-draws-in.html](https://thehackernews.com/2026/09/gitlab-cvss-10-file-read-flaw-draws-in.html)<br>[https://fieldeffect.com/blog/gitlab-fixes-critical-vulnerability-probing-begins](https://fieldeffect.com/blog/gitlab-fixes-critical-vulnerability-probing-begins)<br>[https://cyberscoop.com/gitlab-critical-flaws-path-traversal-scans/](https://cyberscoop.com/gitlab-critical-flaws-path-traversal-scans/) |
| **CVE-2026-87719** | 9.9 | N/A | TRUE | GitLab Enterprise Edition (EE) auto-gérée, versions à partir de 18.3 ; corrigé en 19.1.8, 19.2.6 et 19.3.2 | Désérialisation non sécurisée (insecure deserialization) permettant une divulgation d'informations (CVSS 9.9) | Exposition de configurations d'instance et d'identifiants sensibles (moteur de recherche avancé), réutilisables pour élever des privilèges ou pivoter vers d'autres systèmes et intégrations connectées à GitLab. | Active | Mettre à jour vers 19.1.8 / 19.2.6 / 19.3.2 ; restreindre l'accès à Duo Chat ; faire pivoter les identifiants potentiellement exposés ; surveiller les abonnements GraphQL et les accès aux configurations Advanced Search. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/)<br>[https://thehackernews.com/2026/09/gitlab-cvss-10-file-read-flaw-draws-in.html](https://thehackernews.com/2026/09/gitlab-cvss-10-file-read-flaw-draws-in.html)<br>[https://cyberscoop.com/gitlab-critical-flaws-path-traversal-scans/](https://cyberscoop.com/gitlab-critical-flaws-path-traversal-scans/) |
| **CVE-2026-19478** | N/A | N/A | FALSE | GitLab CE/EE (versions concernées non précisées dans la source ; faille corrigée avant la vague de correctifs du 10/09/2026) | Injection de code via GraphQL | Exécution de code côté serveur sur les instances GitLab vulnérables, avec les risques associés à la compromission d'une plateforme DevSecOps (code source, secrets CI/CD, pipelines). | Active | Vérifier que les instances exécutent une version intégrant le correctif de CVE-2026-19478 et appliquer la dernière release de maintenance (19.3.2 / 19.2.6 / 19.1.8) ; suivre les bulletins GitLab. | [https://thehackernews.com/2026/09/gitlab-cvss-10-file-read-flaw-draws-in.html](https://thehackernews.com/2026/09/gitlab-cvss-10-file-read-flaw-draws-in.html) |
| **CVE-2026-81578** | N/A | N/A | FALSE | PaperCut NG/MF (applications web Java auto-hébergées, s'exécutant par défaut avec les privilèges SYSTEM sur Windows et généralement intégrées à l'Active Directory) ; corrigé dans les maintenance releases 26.0.5, 25.0.13 et 24.1.10 | Contournement d'authentification et exécution de code arbitraire (exploitée activement conjointement avec CVE-2026-82078) | Compromission de serveurs d'impression avec privilèges SYSTEM, intégrés au domaine : pivot vers l'Active Directory, vol de données, perturbation de la continuité d'activité et risque de déploiement de ransomware par des acteurs tiers (access brokering). | Active | Migrer vers PaperCut 26.0.5 / 25.0.13 / 24.1.10 (remplace les correctifs d'urgence) ; ne pas exposer les serveurs PaperCut à Internet ; bloquer 45.142.193[.]132 ; réinitialiser les identifiants du service PaperCut ; appliquer les recommandations du NCSC. | [https://www.security.nl/posting/952677/%27Vierhonderd+organisaties+wereldwijd+gehackt+via+PaperCut-kwetsbaarheden%27?channel=rss](https://www.security.nl/posting/952677/%27Vierhonderd+organisaties+wereldwijd+gehackt+via+PaperCut-kwetsbaarheden%27?channel=rss)<br>[https://thehackernews.com/2026/09/papercut-replaces-emergency-patches.html](https://thehackernews.com/2026/09/papercut-replaces-emergency-patches.html) |
| **CVE-2026-82078** | N/A | N/A | FALSE | PaperCut NG/MF (applications web Java auto-hébergées, s'exécutant par défaut avec les privilèges SYSTEM sur Windows et généralement intégrées à l'Active Directory) ; corrigé dans les maintenance releases 26.0.5, 25.0.13 et 24.1.10 | Exécution de code arbitraire après contournement d'authentification (exploitée activement conjointement avec CVE-2026-81578) | Exécution de code en tant que SYSTEM sur des serveurs domain-joined : prise de contrôle de l'environnement d'impression, accès à d'autres systèmes du réseau, vol de données, perturbation d'activité et risque de ransomware via revente d'accès. | Active | Appliquer PaperCut 26.0.5 / 25.0.13 / 24.1.10 ; retirer de l'exposition Internet les serveurs non corrigés ; bloquer 45.142.193[.]132 ; surveiller l'AD et réinitialiser les identifiants potentiellement compromis. | [https://www.security.nl/posting/952677/%27Vierhonderd+organisaties+wereldwijd+gehackt+via+PaperCut-kwetsbaarheden%27?channel=rss](https://www.security.nl/posting/952677/%27Vierhonderd+organisaties+wereldwijd+gehackt+via+PaperCut-kwetsbaarheden%27?channel=rss)<br>[https://thehackernews.com/2026/09/papercut-replaces-emergency-patches.html](https://thehackernews.com/2026/09/papercut-replaces-emergency-patches.html) |
| **CVE-2026-20079** | 10.0 | N/A | TRUE | Cisco Secure Firewall Management Center (FMC) — versions couvertes par les hotfixes publiées par Cisco | Contournement d'authentification dans l'interface web de FMC permettant l'exécution de fichiers de script et l'obtention d'un accès root (CVSS 10.0) | Accès root sur le centre de gestion des pare-feu, vol d'identifiants et de configurations de périphériques réseau, persistance (web shells, implant Cyclops Blink), perte de visibilité/contrôle du périmètre et préparation de mouvements latéraux. | Active | Appliquer les hotfixes Cisco pour CVE-2026-20079 et CVE-2026-20316 ; ne pas exposer l'interface web FMC ; inspecter les webroots Tomcat (web shells JSP) ; faire pivoter les identifiants ; appliquer la prochaine release de durcissement Cisco. | [https://thehackernews.com/2026/09/cisco-fmc-flaws-exploited-to-steal.html](https://thehackernews.com/2026/09/cisco-fmc-flaws-exploited-to-steal.html)<br>[https://securityaffairs.com/198884/cyber-crime/attackers-exploit-critical-cisco-fmc-flaw-to-deploy-qilin-ransomware.html](https://securityaffairs.com/198884/cyber-crime/attackers-exploit-critical-cisco-fmc-flaw-to-deploy-qilin-ransomware.html) |
| **CVE-2026-20316** | 5.3 | N/A | TRUE | Cisco Secure Firewall Management Center (FMC) — versions couvertes par les hotfixes publiées par Cisco | Divulgation d'informations : connexion avec un compte à faibles privilèges pour accéder à des données sensibles ; chaînable avec d'autres failles FMC pour élever les privilèges (CVSS 5.3) | Accès à des données sensibles, escalade de privilèges en chaîne, compromission de l'infrastructure FMC et des périphériques gérés, maintien d'accès par tunneling et déploiement du ransomware Qilin sur les terminaux ciblés. | Active | Appliquer les hotfixes Cisco pour CVE-2026-20316 et CVE-2026-20079 ; surveiller l'usage anormal des outils natifs FMC et les tunnels sortants ; restreindre les comptes à faibles privilèges ; correctif requis au titre du catalogue KEV. | [https://thehackernews.com/2026/09/cisco-fmc-flaws-exploited-to-steal.html](https://thehackernews.com/2026/09/cisco-fmc-flaws-exploited-to-steal.html)<br>[https://securityaffairs.com/198884/cyber-crime/attackers-exploit-critical-cisco-fmc-flaw-to-deploy-qilin-ransomware.html](https://securityaffairs.com/198884/cyber-crime/attackers-exploit-critical-cisco-fmc-flaw-to-deploy-qilin-ransomware.html) |
| **CVE-2024-11222** | N/A | N/A | FALSE | GitLab Community Edition (CE) et Enterprise Edition (EE) : versions antérieures à 19.1.8, versions 19.2.x antérieures à 19.2.6, versions 19.3.x antérieures à 19.3.2 | Non détaillée dans la source (parmi les risques annoncés : exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité des données, contournement de la politique de sécurité, XSS) | Potentiel : exécution de code arbitraire à distance, déni de service à distance et/ou atteinte à la confidentialité des données selon la vulnérabilité. | None | Mettre à jour GitLab CE/EE vers 19.1.8, 19.2.6 ou 19.3.2 selon la branche (bulletin GitLab du 10/09/2026). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/) |
| **CVE-2025-14871** | N/A | N/A | FALSE | GitLab Community Edition (CE) et Enterprise Edition (EE) : versions antérieures à 19.1.8, versions 19.2.x antérieures à 19.2.6, versions 19.3.x antérieures à 19.3.2 | Non détaillée dans la source (parmi les risques annoncés : exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité des données, contournement de la politique de sécurité, XSS) | Potentiel : exécution de code arbitraire à distance, déni de service à distance et/ou atteinte à la confidentialité des données selon la vulnérabilité. | None | Mettre à jour GitLab CE/EE vers 19.1.8, 19.2.6 ou 19.3.2 selon la branche (bulletin GitLab du 10/09/2026). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/) |
| **CVE-2026-1168** | N/A | N/A | FALSE | GitLab Community Edition (CE) et Enterprise Edition (EE) : versions antérieures à 19.1.8, versions 19.2.x antérieures à 19.2.6, versions 19.3.x antérieures à 19.3.2 | Non détaillée dans la source (parmi les risques annoncés : exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité des données, contournement de la politique de sécurité, XSS) | Potentiel : exécution de code arbitraire à distance, déni de service à distance et/ou atteinte à la confidentialité des données selon la vulnérabilité. | None | Mettre à jour GitLab CE/EE vers 19.1.8, 19.2.6 ou 19.3.2 selon la branche (bulletin GitLab du 10/09/2026). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/) |
| **CVE-2026-12910** | N/A | N/A | FALSE | GitLab Community Edition (CE) et Enterprise Edition (EE) : versions antérieures à 19.1.8, versions 19.2.x antérieures à 19.2.6, versions 19.3.x antérieures à 19.3.2 | Non détaillée dans la source (parmi les risques annoncés : exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité des données, contournement de la politique de sécurité, XSS) | Potentiel : exécution de code arbitraire à distance, déni de service à distance et/ou atteinte à la confidentialité des données selon la vulnérabilité. | None | Mettre à jour GitLab CE/EE vers 19.1.8, 19.2.6 ou 19.3.2 selon la branche (bulletin GitLab du 10/09/2026). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/) |
| **CVE-2026-13210** | N/A | N/A | FALSE | GitLab Community Edition (CE) et Enterprise Edition (EE) : versions antérieures à 19.1.8, versions 19.2.x antérieures à 19.2.6, versions 19.3.x antérieures à 19.3.2 | Non détaillée dans la source (parmi les risques annoncés : exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité des données, contournement de la politique de sécurité, XSS) | Potentiel : exécution de code arbitraire à distance, déni de service à distance et/ou atteinte à la confidentialité des données selon la vulnérabilité. | None | Mettre à jour GitLab CE/EE vers 19.1.8, 19.2.6 ou 19.3.2 selon la branche (bulletin GitLab du 10/09/2026). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/) |
| **CVE-2026-16794** | N/A | N/A | FALSE | GitLab Community Edition (CE) et Enterprise Edition (EE) : versions antérieures à 19.1.8, versions 19.2.x antérieures à 19.2.6, versions 19.3.x antérieures à 19.3.2 | Non détaillée dans la source (parmi les risques annoncés : exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité des données, contournement de la politique de sécurité, XSS) | Potentiel : exécution de code arbitraire à distance, déni de service à distance et/ou atteinte à la confidentialité des données selon la vulnérabilité. | None | Mettre à jour GitLab CE/EE vers 19.1.8, 19.2.6 ou 19.3.2 selon la branche (bulletin GitLab du 10/09/2026). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/) |
| **CVE-2026-19619** | N/A | N/A | FALSE | GitLab Community Edition (CE) et Enterprise Edition (EE) : versions antérieures à 19.1.8, versions 19.2.x antérieures à 19.2.6, versions 19.3.x antérieures à 19.3.2 | Non détaillée dans la source (parmi les risques annoncés : exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité des données, contournement de la politique de sécurité, XSS) | Potentiel : exécution de code arbitraire à distance, déni de service à distance et/ou atteinte à la confidentialité des données selon la vulnérabilité. | None | Mettre à jour GitLab CE/EE vers 19.1.8, 19.2.6 ou 19.3.2 selon la branche (bulletin GitLab du 10/09/2026). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/) |
| **CVE-2026-3855** | N/A | N/A | FALSE | GitLab Community Edition (CE) et Enterprise Edition (EE) : versions antérieures à 19.1.8, versions 19.2.x antérieures à 19.2.6, versions 19.3.x antérieures à 19.3.2 | Non détaillée dans la source (parmi les risques annoncés : exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité des données, contournement de la politique de sécurité, XSS) | Potentiel : exécution de code arbitraire à distance, déni de service à distance et/ou atteinte à la confidentialité des données selon la vulnérabilité. | None | Mettre à jour GitLab CE/EE vers 19.1.8, 19.2.6 ou 19.3.2 selon la branche (bulletin GitLab du 10/09/2026). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/) |
| **CVE-2026-7514** | N/A | N/A | FALSE | GitLab Community Edition (CE) et Enterprise Edition (EE) : versions antérieures à 19.1.8, versions 19.2.x antérieures à 19.2.6, versions 19.3.x antérieures à 19.3.2 | Non détaillée dans la source (parmi les risques annoncés : exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité des données, contournement de la politique de sécurité, XSS) | Potentiel : exécution de code arbitraire à distance, déni de service à distance et/ou atteinte à la confidentialité des données selon la vulnérabilité. | None | Mettre à jour GitLab CE/EE vers 19.1.8, 19.2.6 ou 19.3.2 selon la branche (bulletin GitLab du 10/09/2026). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/) |
| **CVE-2026-78252** | N/A | N/A | FALSE | GitLab Community Edition (CE) et Enterprise Edition (EE) : versions antérieures à 19.1.8, versions 19.2.x antérieures à 19.2.6, versions 19.3.x antérieures à 19.3.2 | Non détaillée dans la source (parmi les risques annoncés : exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité des données, contournement de la politique de sécurité, XSS) | Potentiel : exécution de code arbitraire à distance, déni de service à distance et/ou atteinte à la confidentialité des données selon la vulnérabilité. | None | Mettre à jour GitLab CE/EE vers 19.1.8, 19.2.6 ou 19.3.2 selon la branche (bulletin GitLab du 10/09/2026). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/) |
| **CVE-2026-79708** | N/A | N/A | FALSE | GitLab Community Edition (CE) et Enterprise Edition (EE) : versions antérieures à 19.1.8, versions 19.2.x antérieures à 19.2.6, versions 19.3.x antérieures à 19.3.2 | Non détaillée dans la source (parmi les risques annoncés : exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité des données, contournement de la politique de sécurité, XSS) | Potentiel : exécution de code arbitraire à distance, déni de service à distance et/ou atteinte à la confidentialité des données selon la vulnérabilité. | None | Mettre à jour GitLab CE/EE vers 19.1.8, 19.2.6 ou 19.3.2 selon la branche (bulletin GitLab du 10/09/2026). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/) |
| **CVE-2026-8030** | N/A | N/A | FALSE | GitLab Community Edition (CE) et Enterprise Edition (EE) : versions antérieures à 19.1.8, versions 19.2.x antérieures à 19.2.6, versions 19.3.x antérieures à 19.3.2 | Non détaillée dans la source (parmi les risques annoncés : exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité des données, contournement de la politique de sécurité, XSS) | Potentiel : exécution de code arbitraire à distance, déni de service à distance et/ou atteinte à la confidentialité des données selon la vulnérabilité. | None | Mettre à jour GitLab CE/EE vers 19.1.8, 19.2.6 ou 19.3.2 selon la branche (bulletin GitLab du 10/09/2026). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/) |
| **CVE-2026-82837** | N/A | N/A | FALSE | GitLab Community Edition (CE) et Enterprise Edition (EE) : versions antérieures à 19.1.8, versions 19.2.x antérieures à 19.2.6, versions 19.3.x antérieures à 19.3.2 | Non détaillée dans la source (parmi les risques annoncés : exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité des données, contournement de la politique de sécurité, XSS) | Potentiel : exécution de code arbitraire à distance, déni de service à distance et/ou atteinte à la confidentialité des données selon la vulnérabilité. | None | Mettre à jour GitLab CE/EE vers 19.1.8, 19.2.6 ou 19.3.2 selon la branche (bulletin GitLab du 10/09/2026). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/) |
| **CVE-2026-86340** | N/A | N/A | FALSE | GitLab Community Edition (CE) et Enterprise Edition (EE) : versions antérieures à 19.1.8, versions 19.2.x antérieures à 19.2.6, versions 19.3.x antérieures à 19.3.2 | Non détaillée dans la source (parmi les risques annoncés : exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité des données, contournement de la politique de sécurité, XSS) | Potentiel : exécution de code arbitraire à distance, déni de service à distance et/ou atteinte à la confidentialité des données selon la vulnérabilité. | None | Mettre à jour GitLab CE/EE vers 19.1.8, 19.2.6 ou 19.3.2 selon la branche (bulletin GitLab du 10/09/2026). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/) |
| **CVE-2026-86341** | N/A | N/A | FALSE | GitLab Community Edition (CE) et Enterprise Edition (EE) : versions antérieures à 19.1.8, versions 19.2.x antérieures à 19.2.6, versions 19.3.x antérieures à 19.3.2 | Non détaillée dans la source (parmi les risques annoncés : exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité des données, contournement de la politique de sécurité, XSS) | Potentiel : exécution de code arbitraire à distance, déni de service à distance et/ou atteinte à la confidentialité des données selon la vulnérabilité. | None | Mettre à jour GitLab CE/EE vers 19.1.8, 19.2.6 ou 19.3.2 selon la branche (bulletin GitLab du 10/09/2026). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/) |
| **CVE-2026-88765** | N/A | N/A | FALSE | GitLab Community Edition (CE) et Enterprise Edition (EE) : versions antérieures à 19.1.8, versions 19.2.x antérieures à 19.2.6, versions 19.3.x antérieures à 19.3.2 | Non détaillée dans la source (parmi les risques annoncés : exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité des données, contournement de la politique de sécurité, XSS) | Potentiel : exécution de code arbitraire à distance, déni de service à distance et/ou atteinte à la confidentialité des données selon la vulnérabilité. | None | Mettre à jour GitLab CE/EE vers 19.1.8, 19.2.6 ou 19.3.2 selon la branche (bulletin GitLab du 10/09/2026). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/) |
| **CVE-2026-90456** | 9.2 | N/A | FALSE | Composant de gestion d'inventaire embarqué (produits affectés exacts non encore recensés par le CVE) | Utilisation d'identifiants administratifs par défaut (CWE-1392) | Prise de contrôle totale de l'interface d'administration du composant (confidentialité, intégrité et disponibilité élevées), lecture et modification des données d'inventaire, risque de pivot au sein d'un environnement industriel (OT/ICS). | None | Régénérer les identifiants par défaut à chaque déploiement, ne jamais utiliser les fichiers d'exemple comme configuration active, supprimer ou sécuriser ces fichiers d'exemple, revoir toutes les configurations déployées et appliquer les mises à jour de sécurité fournies par l'éditeur. | [https://cvefeed.io/vuln/detail/CVE-2026-90456](https://cvefeed.io/vuln/detail/CVE-2026-90456)<br>[https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-254-01.json](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-254-01.json) |
| **CVE-2026-90451** | 8.2 | N/A | FALSE | Composant d'analyse de paquets (packet-analysis) embarqué (produits affectés exacts non encore recensés par le CVE) | Falsification de cookies d'authentification via un secret codé en dur (CWE-1392 - Use of Default Credentials) | Contournement complet de l'authentification du composant (intégrité élevée), usurpation d'identité d'utilisateurs légitimes, accès non autorisé à la fonction d'analyse de paquets et aux données capturées. | None | Régénérer le secret de signature avec une valeur unique, ne pas déployer les fichiers de configuration d'exemple, revoir toutes les configurations déployées, implémenter des routines de setup générant des secrets aléatoires et appliquer les correctifs de l'éditeur. | [https://cvefeed.io/vuln/detail/CVE-2026-90451](https://cvefeed.io/vuln/detail/CVE-2026-90451)<br>[https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-254-01.json](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-254-01.json) |
| **CVE-2026-90444** | 8.7 | N/A | FALSE | Interface de transfert de fichiers avec traitement automatisé des fichiers téléversés (produits affectés exacts non encore recensés par le CVE) | Injection de commandes OS via contournement de validation de nom de fichier (CWE-78) | Exécution de commandes arbitraires avec les privilèges du processus d'ingestion, lecture et modification des données de journaux ingérées, possible point d'ancrage (foothold) pour un mouvement latéral dans le réseau interne. | None | Sanitiser tous les noms de fichiers vis-à-vis des métacaractères shell, ne pas construire de commandes système à partir de noms de fichiers, valider et restreindre les données d'entrée, appliquer le moindre privilège aux processus et appliquer les mises à jour de sécurité de l'éditeur. | [https://cvefeed.io/vuln/detail/CVE-2026-90444](https://cvefeed.io/vuln/detail/CVE-2026-90444)<br>[https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-254-01.json](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-254-01.json) |
| **CVE-2026-72710** | 9.8 | N/A | FALSE | SPIP en versions antérieures à 4.4.18 | Exécution de code à distance (RCE) via injection dans la file de tâches de l'action editer_objet.php (CWE-915 - modification non contrôlée d'attributs d'objets déterminés dynamiquement) | Exécution de code arbitraire côté serveur sur les instances SPIP non corrigées, compromission totale du CMS et de l'hôte (impact technique total selon SSVC), attaque automatisable une fois le nonce obtenu, risque de compromission en chaîne avec les CVE-2026-72708 et CVE-2026-72709. | Theoretical | Mettre à jour SPIP vers la version 4.4.18 ou supérieure (hxxps://blog[.]spip[.]net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-4-18[.]html), purger la table spip_jobs, régénérer les secrets de nonces, vérifier la résolution des noms de tables du paramètre arg, imposer la liste blanche des colonnes éditables et sanitiser les valeurs fonction/args avant toute désérialisation. | [https://cvefeed.io/vuln/detail/CVE-2026-72710](https://cvefeed.io/vuln/detail/CVE-2026-72710)<br>[https://www.vulncheck.com/advisories/spip-remote-code-execution-via-editer-objet-php-job-queue-injection](https://www.vulncheck.com/advisories/spip-remote-code-execution-via-editer-objet-php-job-queue-injection)<br>[https://blog.lexfo.fr/casse-spip-sqli-to-rce.html](https://blog.lexfo.fr/casse-spip-sqli-to-rce.html)<br>[https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-4-18.html](https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-4-18.html) |
| **CVE-2026-72709** | 9.8 | N/A | FALSE | SPIP en versions antérieures à 4.4.18 | Absence de vérification d'autorisation (CWE-862 - Missing Authorization) sur les endpoints d'administration ecrire/action/ | Prise de contrôle de comptes arbitraires dont le compte administrateur, contournement total de l'authentification, modification de comptes et d'auteurs, étape pivot permettant d'obtenir un nonce valide exploitable pour la RCE (CVE-2026-72710). | Theoretical | Mettre à jour SPIP vers la version 4.4.18 ou supérieure, imposer des vérifications de permissions serveur (autoriser()) avant toute opération privilégiée, mettre en place des contrôles d'accès stricts sur les actions d'administration et réinitialiser les mots de passe des comptes sensibles après application du correctif. | [https://cvefeed.io/vuln/detail/CVE-2026-72709](https://cvefeed.io/vuln/detail/CVE-2026-72709)<br>[https://www.vulncheck.com/advisories/spip-missing-authorization-via-ecrire-action-editer-auteur](https://www.vulncheck.com/advisories/spip-missing-authorization-via-ecrire-action-editer-auteur)<br>[https://blog.lexfo.fr/casse-spip-sqli-to-rce.html](https://blog.lexfo.fr/casse-spip-sqli-to-rce.html)<br>[https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-4-18.html](https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-4-18.html) |
| **CVE-2026-72708** | 8.7 | N/A | FALSE | SPIP en versions antérieures à 4.4.18 | Injection SQL aveugle non authentifiée (CWE-89) via le paramètre annee du sitemap public | Exfiltration de contenu arbitraire de la base de données sans authentification, dont le secret alea_ephemere, permettant la falsification des nonces d'action (CVE-2026-72709) puis l'exécution de code à distance (CVE-2026-72710) ; atteinte à la confidentialité de l'ensemble des données SPIP. | Theoretical | Mettre à jour SPIP vers la version 4.4.18 ou supérieure, appliquer les correctifs de l'éditeur sur l'échappement SQL, surveiller et filtrer les requêtes anormales vers sitemap.xml.html et régénérer alea_ephemere en cas de suspicion d'extraction. | [https://cvefeed.io/vuln/detail/CVE-2026-72708](https://cvefeed.io/vuln/detail/CVE-2026-72708)<br>[https://www.vulncheck.com/advisories/spip-unauthenticated-sql-injection-via-sitemap-annee-parameter](https://www.vulncheck.com/advisories/spip-unauthenticated-sql-injection-via-sitemap-annee-parameter)<br>[https://blog.lexfo.fr/casse-spip-sqli-to-rce.html](https://blog.lexfo.fr/casse-spip-sqli-to-rce.html)<br>[https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-4-18.html](https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-4-18.html) |
| **CVE-2026-62103** | 9.8 | N/A | FALSE | Plugin WordPress Everest Forms en versions <= 3.6.0 (éditeur WPEverest) | Injection d'objets PHP non authentifiée (CWE-502 - Désérialisation de données non fiables) | Injection d'objets PHP pouvant mener, selon les gadget chains disponibles dans l'installation WordPress (plugins/thèmes), à l'exécution de code arbitraire, à l'extraction de données sensibles de la base, à l'injection SQL ou à un déni de service ; exploitabilité à distance sans aucune authentification, avec un impact maximal sur la confidentialité, l'intégrité et la disponibilité. | None | Mettre à jour le plugin Everest Forms vers la version 3.6.1 ou supérieure, appliquer promptement les correctifs de l'éditeur, revoir la configuration de sécurité du plugin, durcir l'environnement PHP (restrictions de désérialisation et de fonctions dangereuses) et surveiller les tentatives d'exploitation via WAF. | [https://cvefeed.io/vuln/detail/CVE-2026-62103](https://cvefeed.io/vuln/detail/CVE-2026-62103)<br>[https://patchstack.com/database/wordpress/plugin/everest-forms/vulnerability/wordpress-everest-forms-plugin-3-6-0-php-object-injection-vulnerability?_s_id=cve](https://patchstack.com/database/wordpress/plugin/everest-forms/vulnerability/wordpress-everest-forms-plugin-3-6-0-php-object-injection-vulnerability?_s_id=cve)<br>[https://stemshop.top/cve/CVE-2026-62103](https://stemshop.top/cve/CVE-2026-62103) |
| **CVE-2026-89090** | 8.2 | N/A | FALSE | AWS SDK for Go v2, toutes versions antérieures à release-2026-03-23 | Déni de service - panic non récupérée dans le décodeur d'en-têtes EventStream (CWE-248 : Uncaught Exception) | Interruption de service (déni de service) des applications Go consommant des flux EventStream, avec terminaison du processus hôte. Aucun impact sur la confidentialité ou l'intégrité des données n'est signalé ; le risque principal est la disponibilité. | None | Mettre à jour AWS SDK for Go v2 vers la version release-2026-03-23 ou supérieure, et corriger tout code forké ou dérivé du SDK pour y intégrer le correctif. Aucune solution de contournement n'est applicable selon AWS. Contact de sécurité de l'éditeur : aws-security[@]amazon[.]com. | [https://cvefeed.io/vuln/detail/CVE-2026-89090](https://cvefeed.io/vuln/detail/CVE-2026-89090)<br>[https://aws.amazon.com/security/security-bulletins/rss/2026-110-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-110-aws/) |
| **CVE-2026-15409** | 10.0 | N/A | TRUE | SonicWall SMA1000 : SMA6210, SMA7210, SMA8200v en firmware 12.4.3-03245 (firmware correctif à partir de 12.4.3-03453) | SSRF non authentifié de sévérité maximale (CVSS 10.0) dans le proxy WebSocket du portail WorkPlace, chaînable en exécution de commandes OS | Compromission totale des appliances exposées, exécution de commandes à distance, vol massif de credentials LDAP et Active Directory, réplication complète de la base NTDS (DCSync), pivot vers les réseaux internes et usage documenté dans des campagnes de ransomware. La compromission des credentials rend une simple reconstruction de l'appliance insuffisante. | Active | Mettre à jour le firmware vers 12.4.3-03453 ou supérieur ; restreindre l'exposition du portail WorkPlace ; appliquer les mitigations CISA (BOD 26-04, exigences de tri forensique) ou suspendre l'usage du produit si aucune mitigation n'est possible ; réinitialiser les credentials LDAP/AD potentiellement compromis (double reset krbtgt en cas de DCSync) ; bloquer l'infrastructure attaquante (95.181.173[.]36) ; mener une chasse aux compromissions sur les appliances et les contrôleurs de domaine. | [https://securityaffairs.com/198864/hacking/uk-council-attack-linked-to-mass-exploitation-of-sonicwall-flaw.html](https://securityaffairs.com/198864/hacking/uk-council-attack-linked-to-mass-exploitation-of-sonicwall-flaw.html)<br>[https://cyberworldops.eu/en/uk-council-cyberattack-tied-to-mass-exploitation-of-critical-sonicwall](https://cyberworldops.eu/en/uk-council-cyberattack-tied-to-mass-exploitation-of-critical-sonicwall)<br>[https://infosec.exchange/@cyberworldops/117254298054846801](https://infosec.exchange/@cyberworldops/117254298054846801) |
| **CVE-2026-89266** | 8.8 | N/A | FALSE | stb_vorbis jusqu'à la version 1.22 incluse (bibliothèque C de décodage Ogg Vorbis) et toutes les applications l'embarquant | Dépassement de tampon dans le tas (heap buffer overflow) — troncature de la taille d'allocation des multiplicands de codebook de size_t vers int dans la fonction start_decoder() | Crash du processus victime ou corruption du tas, pouvant mener à un déni de service et potentiellement à l'exécution de code arbitraire dans le contexte de l'application traitant le fichier malveillant. | Theoretical | Mettre à jour stb_vorbis vers une version corrigeant le dépassement de tampon ; reconstruire les applications embarquant la bibliothèque ; en mesure compensatoire, éviter de traiter des fichiers Ogg Vorbis non fiables et durcir les applications (fuzzing, sandboxing). | [https://cvefeed.io/vuln/detail/CVE-2026-89266](https://cvefeed.io/vuln/detail/CVE-2026-89266) |
| **CVE-2026-44715** | 8.7 | N/A | FALSE | OpenMRS (openmrs-core) versions antérieures à 1.23.0 et antérieures à 2.10.0 | Contrôle d'accès défaillant (CWE-285, Broken Access Control) — services DWR d'administration accessibles à un utilisateur authentifié non privilégié | Un utilisateur authentifié non privilégié peut déclencher des opérations d'administration sensibles telles que la migration d'archive HL7, avec un risque d'atteinte à l'intégrité et à la disponibilité des données médicales et de perturbation des processus cliniques. | Theoretical | Mettre à jour OpenMRS vers la version 1.23.0 ou 2.10.0 qui corrige la restriction des services DWR administratifs ; en attendant, restreindre l'accès aux endpoints DWR et revoir les autorisations des comptes. | [https://cvefeed.io/vuln/detail/CVE-2026-44715](https://cvefeed.io/vuln/detail/CVE-2026-44715) |
| **CVE-2026-54174** | 8.3 | N/A | FALSE | apko versions antérieures à 1.2.9 et melange versions antérieures à 0.50.4 (Chainguard) | Vérification d'intégrité des paquets incomplète (CWE-345, CWE-354) — le hachage de la section de contrôle (.PKGINFO) est vérifié mais jamais celui de la section de données (fichiers réellement installés) | Installation de fichiers arbitraires (paquets trojanisés) lors des constructions d'images et déploiements, entraînant un risque de compromission de la chaîne d'approvisionnement logicielle, d'exécution de code et de persistance dans les environnements cibles. | Theoretical | Mettre à jour apko vers la version 1.2.9 ou ultérieure et melange vers la version 0.50.4 ou ultérieure ; reconstruire et re-signer les paquets avec les outils corrigés ; sécuriser les miroirs et canaux de téléchargement (TLS, épinglage). | [https://cvefeed.io/vuln/detail/CVE-2026-54174](https://cvefeed.io/vuln/detail/CVE-2026-54174) |
| **CVE-2026-49464** | 8.1 | N/A | FALSE | Paquet nl.nl-portal:taak (NL Portal Backend Libraries) versions 1.5.0 à 3.0.0 | IDOR — contournement d'autorisation par clé contrôlée par l'utilisateur (CWE-639) sur la mutation GraphQL submitTaakV2 | Atteinte à la confidentialité (lecture des données de formulaire d'autrui) et à l'intégrité (écrasement de données, complétion frauduleuse de tâches) sur des portails gouvernementaux traitant des demandes de résidents, avec un risque de perturbation de services publics et d'exposition de données personnelles. | Theoretical | Mettre à jour le paquet nl.nl-portal:taak vers la version 3.0.1 ; en attendant, bloquer la mutation submitTaakV2 au niveau de la passerelle API ou restreindre l'accès à l'endpoint /graphql aux réseaux de confiance. | [https://cvefeed.io/vuln/detail/CVE-2026-49464](https://cvefeed.io/vuln/detail/CVE-2026-49464) |
| **CVE-2026-53952** | N/A | N/A | FALSE | GetSimple CMS et GetSimpleCMS-CE (versions affectées non précisées dans la source disponible) | Création de compte administrateur non authentifiée via un défaut logique dans la procédure d'installation (setup logic flaw) | Prise de contrôle totale du CMS par création d'un compte administrateur non autorisé : défiguration, dépôt de webshell, exfiltration de contenu, utilisation du serveur comme pivot pour des attaques ultérieures. | Theoretical | Consulter les advisories officiels GetSimple CMS/CE pour identifier les versions corrigées ; s'assurer que la procédure d'installation est verrouillée ou supprimée après déploiement ; restreindre l'accès aux répertoires d'administration et de setup ; surveiller toute création de compte administrateur. | [https://cvefeed.io/vuln/detail/CVE-2026-53952](https://cvefeed.io/vuln/detail/CVE-2026-53952) |
| **CVE-2026-79395** | 9.8 | N/A | FALSE | Caméras IP Xiongmai, firmware XM530 HMT.CM2005-v220608.1837 et versions antérieures (démon Sofia IPC) | Authentification défaillante (CWE-287) — contournement de la routine de vérification WS-Security (wsse:UsernameToken) dans le démon Sofia IPC | Accès non authentifié aux fonctions privilégiées des caméras : espionnage via récupération des flux vidéo, manipulation physique de la caméra (PTZ), déni de service par redémarrage, et risque de pivot au sein du réseau où sont déployées ces caméras. | Theoretical | Mettre à jour le firmware vers une version postérieure à HMT.CM2005-v220608.1837 (dernière version corrigée publiée par le fabricant) ; s'assurer que tous les comptes disposent de mots de passe forts et non vides ; désactiver ou restreindre l'accès distant si non nécessaire ; segmenter le réseau de vidéosurveillance. | [https://cvefeed.io/vuln/detail/CVE-2026-79395](https://cvefeed.io/vuln/detail/CVE-2026-79395) |
| **CVE-2026-62107** | 8.8 | N/A | FALSE | Plugin WordPress Masteriyo - LMS (learning-management-system), versions <= 3.4.0 | Injection d'objets PHP non authentifiée (désérialisation de données non fiables - CWE-502, CAPEC-586) | Compromission potentielle du site WordPress : exécution de code à distance via chaîne de désérialisation, manipulation de contenu, accès à la base de données et pivot possible vers l'infrastructure d'hébergement. Impact élevé sur la confidentialité, l'intégrité et la disponibilité. | None | Mettre à jour Masteriyo LMS vers la version 3.4.1 ou supérieure, appliquer les correctifs de l'éditeur et, en attendant, désactiver le plugin. Surveiller les tentatives d'exploitation dans les journaux web et revoir les contrôles d'accès. | [https://cvefeed.io/vuln/detail/CVE-2026-62107](https://cvefeed.io/vuln/detail/CVE-2026-62107)<br>[https://patchstack.com/database/wordpress/plugin/learning-management-system/vulnerability/wordpress-masteriyo-lms-plugin-3-4-0-php-object-injection-vulnerability?_s_id=cve](https://patchstack.com/database/wordpress/plugin/learning-management-system/vulnerability/wordpress-masteriyo-lms-plugin-3-4-0-php-object-injection-vulnerability?_s_id=cve) |
| **CVE-2026-62106** | 8.8 | N/A | FALSE | Plugin WordPress SMS Alert Order Notifications (slug sms-alert), versions <= 3.9.9 | Élévation de privilèges d'abonné (attribution incorrecte de privilèges - CWE-266) | Un compte faiblement privilégié peut obtenir des droits administrateur, prendre le contrôle du site WordPress, installer des mécanismes de persistance (plugins, webshells) et accéder aux données des commandes/utilisateurs, avec un impact élevé sur la confidentialité, l'intégrité et la disponibilité. | None | Mettre à jour SMS Alert Order Notifications vers une version postérieure à 3.9.9, appliquer les correctifs de l'éditeur, revoir les contrôles d'accès et les privilèges des utilisateurs, et surveiller les changements de rôles. | [https://cvefeed.io/vuln/detail/CVE-2026-62106](https://cvefeed.io/vuln/detail/CVE-2026-62106)<br>[https://patchstack.com/database/wordpress/plugin/sms-alert/vulnerability/wordpress-sms-alert-order-notifications-plugin-3-9-9-privilege-escalation-vulnerability?_s_id=cve](https://patchstack.com/database/wordpress/plugin/sms-alert/vulnerability/wordpress-sms-alert-order-notifications-plugin-3-9-9-privilege-escalation-vulnerability?_s_id=cve) |
| **CVE-2026-62105** | 9.8 | N/A | FALSE | Plugin WordPress ThemeREX Addons (slug trx_addons), versions < 2.45.0 | Injection d'objets PHP non authentifiée (désérialisation de données non fiables - CWE-502, CAPEC-586) | Exécution de code potentielle via chaîne POP, compromission à grande échelle des sites utilisant les thèmes ThemeREX, manipulation de contenu, exfiltration de données et pivot vers l'hébergement. Criticité maximale compte tenu de l'absence d'authentification requise. | None | Mettre à jour ThemeREX Addons vers la version 2.45.0 ou supérieure, vérifier la version installée après mise à jour et, en attendant, désactiver le plugin. Renforcer la détection sur les endpoints du plugin. | [https://cvefeed.io/vuln/detail/CVE-2026-62105](https://cvefeed.io/vuln/detail/CVE-2026-62105)<br>[https://patchstack.com/database/wordpress/plugin/trx_addons/vulnerability/wordpress-themerex-addons-plugin-2-45-0-php-object-injection-vulnerability?_s_id=cve](https://patchstack.com/database/wordpress/plugin/trx_addons/vulnerability/wordpress-themerex-addons-plugin-2-45-0-php-object-injection-vulnerability?_s_id=cve) |
| **CVE-2026-62102** | 8.8 | N/A | FALSE | Plugin WordPress Gato GraphQL (slug gatographql), versions <= 19.2.3 | Élévation de privilèges d'abonné (attribution incorrecte de privilèges - CWE-266) | Un compte faiblement privilégié peut obtenir des droits administrateur, prendre le contrôle du site, installer des persistances et accéder aux données, avec un impact élevé sur la confidentialité, l'intégrité et la disponibilité. | None | Mettre à jour Gato GraphQL vers une version corrigée, appliquer les correctifs de l'éditeur pour les anciennes versions, revoir les contrôles d'accès et les privilèges, et surveiller les changements de rôles. | [https://cvefeed.io/vuln/detail/CVE-2026-62102](https://cvefeed.io/vuln/detail/CVE-2026-62102)<br>[https://patchstack.com/database/wordpress/plugin/gatographql/vulnerability/wordpress-gato-graphql-plugin-19-2-3-privilege-escalation-vulnerability?_s_id=cve](https://patchstack.com/database/wordpress/plugin/gatographql/vulnerability/wordpress-gato-graphql-plugin-19-2-3-privilege-escalation-vulnerability?_s_id=cve) |
| **CVE-2026-54072** | 9.3 | N/A | FALSE | Authorizer (serveur d'authentification/autorisation open source auto-hébergeable), versions antérieures à 2.2.1 | Redirection non validée (open redirect - CWE-601) sur le endpoint /authorize entraînant une fuite de jetons OAuth2 vers une URL contrôlée par l'attaquant | Vol de jetons d'accès, d'identité et de rafraîchissement permettant l'usurpation d'identité des utilisateurs et l'accès non autorisé aux applications protégées par Authorizer, avec contournement potentiel de l'authentification multifacteur selon les flux. | Theoretical | Mettre à jour Authorizer vers la version 2.2.1 ou supérieure, vérifier que la validation des redirect_uri est bien appliquée, révoquer et renouveler les jetons émis avant correctif, et rotater les secrets clients OAuth. | [https://cvefeed.io/vuln/detail/CVE-2026-54072](https://cvefeed.io/vuln/detail/CVE-2026-54072)<br>[https://github.com/authorizerdev/authorizer/security/advisories/GHSA-h29v-hj44-q8cv](https://github.com/authorizerdev/authorizer/security/advisories/GHSA-h29v-hj44-q8cv) |
| **CVE-2026-82617** | 10.0 | N/A | FALSE | Apache OpenNLP, versions 2.0.0 à 2.5.11 et 3.0.0-M1 à 3.0.0-M5 | ReDoS / épuisement de pile (complexité d'expression régulière inefficace - CWE-1333) dans les motifs intégrés EMAIL et URL de RegexNameFinderFactory | Déni de service : une seule requête peut figer le CPU de quelques secondes à plusieurs minutes ou provoquer la mort abrupte du thread appelant, privant de service l'application hôte (API NLP, pipelines de traitement de texte). | Theoretical | Mettre à niveau vers OpenNLP 2.5.12 ou 3.0.0-M6, éviter les finders regex affectés, assainir et limiter la taille des entrées utilisateur, et renforcer la résilience (timeouts, rate limiting, dimensionnement des piles de threads). | [https://cvefeed.io/vuln/detail/CVE-2026-82617](https://cvefeed.io/vuln/detail/CVE-2026-82617)<br>[https://lists.apache.org/thread/spzhcxxszqdpppg70m1zz2l3mv29mhl3](https://lists.apache.org/thread/spzhcxxszqdpppg70m1zz2l3mv29mhl3)<br>[http://www.openwall.com/lists/oss-security/2026/09/11/10](http://www.openwall.com/lists/oss-security/2026/09/11/10) |
| **CVE-2026-84869** | 9.9 | N/A | FALSE | ConnectWise ScreenConnect (déploiements cloud et on-premises), versions antérieures au correctif de septembre 2026 | Exécution de code non autorisée sur les clients via le transfert de fichiers dans les sessions distantes (absence d'autorisation / de confirmation de l'hôte) | Exécution de code sur l'ensemble des postes clients gérés via l'outil RMM : vecteur idéal de déploiement de ransomware, de mouvement latéral massif et de compromission de la chaîne de gestion MSP vers les environnements clients. | Theoretical | Appliquer immédiatement le correctif ConnectWise sur les installations on-premises, vérifier que le cloud est à jour, appliquer les mitigations temporaires de l'éditeur, restreindre l'accès aux instances ScreenConnect et surveiller les transferts de fichiers en session. | [https://www.security.nl/posting/952702/Kritiek+ScreenConnect-lek+laat+aanvaller+code+op+clients+uitvoeren?channel=rss](https://www.security.nl/posting/952702/Kritiek+ScreenConnect-lek+laat+aanvaller+code+op+clients+uitvoeren?channel=rss) |
| **CVE-2026-42018** | N/A | N/A | FALSE | JFrog Artifactory auto-hébergé (branches 7.146 corrigée le 28/04/2026 et 7.133 corrigée le 12/08/2026) | Fuite de jeton : remise du jeton de l'utilisateur anonyme interne à un appelant non authentifié, même lorsque l'accès anonyme est désactivé | Contrôle administrateur du dépôt d'artefacts : empoisonnement possible de la chaîne d'approvisionnement logicielle (backdoors dans les builds consommés en aval), persistance via plugins Groovy, exfiltration et installation de backdoors avec canal C2. | Active | Appliquer les correctifs JFrog (branche 7.146 depuis le 28/04 et branche 7.133 depuis le 12/08/2026), corriger au minimum l'une des deux failles de la chaîne, auditer et supprimer comptes admin et plugins Groovy inconnus, révoquer les jetons et rechercher les actions sous token:anonymous. | [https://thehackernews.com/2026/09/attackers-chain-jfrog-artifactory-flaws.html](https://thehackernews.com/2026/09/attackers-chain-jfrog-artifactory-flaws.html) |
| **CVE-2026-42016** | N/A | N/A | FALSE | JFrog Artifactory auto-hébergé, versions jusqu'à 7.133.11 pour cette faille (branches 7.146 et 7.161 hors de la gamme affectée publiée) | Élévation de portée de jeton : échange d'un jeton à faible privilège contre un jeton à portée administrateur (vérification de la signature et de l'émetteur sans contrôle des scopes) | Obtention furtive de privilèges administrateur sur le dépôt d'artefacts : prise de contrôle persistante, exécution de code via plugins, risque d'empoisonnement de la chaîne d'approvisionnement logicielle et déploiement de backdoors. | Active | Appliquer les correctifs JFrog, révoquer les jetons compromis (surtout ceux à portée admin sous identité anonymous), auditer et purger comptes admin et plugins Groovy inconnus, et surveiller les actions administrateur dans les journaux d'audit. | [https://thehackernews.com/2026/09/attackers-chain-jfrog-artifactory-flaws.html](https://thehackernews.com/2026/09/attackers-chain-jfrog-artifactory-flaws.html) |
| **CVE-2026-82329** | 9.8 | N/A | TRUE | JFrog Artifactory auto-hébergé, six branches de release affectées jusqu'à 7.161 (configuration par défaut) | Contournement d'authentification critique (auth bypass) permettant d'obtenir des privilèges administrateur sans aucune autre faille | Prise de contrôle administrateur totale du dépôt d'artefacts sans authentification, lecture de la configuration et vol de la clé de jointure de cluster (risque de compromission du cluster), avec un risque majeur d'empoisonnement de la chaîne d'approvisionnement logicielle. | Active | Appliquer immédiatement les correctifs JFrog sur toutes les branches affectées, rotater la clé de jointure de cluster et les secrets, révoquer les jetons/comptes admin illicites, restreindre l'exposition réseau et surveiller les actions administrateur non authentifiées. | [https://thehackernews.com/2026/09/attackers-chain-jfrog-artifactory-flaws.html](https://thehackernews.com/2026/09/attackers-chain-jfrog-artifactory-flaws.html) |
| **CVE-2026-89332** | N/A | N/A | FALSE | Kiro IDE < 0.8.135 | Exfiltration de données sensibles du workspace via modification par l'agent du fichier de configuration du workspace (redirection de l'URL du registre Kiro Powers vers un endpoint externe) | Envoi de données sensibles du workspace (code, configuration, secrets de projet) vers un endpoint contrôlé par l'attaquant, quasi à l'insu du développeur. | Theoretical | Mettre à jour Kiro IDE vers 0.8.135 ou supérieur ; faire tourner les identifiants présents dans tout projet ouvert sur une version antérieure ; aucune solution de contournement. | [https://aws.amazon.com/security/security-bulletins/rss/2026-111-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-111-aws/) |
| **CVE-2026-18061** | N/A | N/A | FALSE | AWS Advanced JDBC Wrapper, versions >= 3.3.0 et <= 4.2.0 (plugin optionnel RemoteQueryCachePlugin) | XXE - restriction incorrecte des références d'entités externes XML dans le plugin optionnel RemoteQueryCachePlugin | Lecture de fichiers sensibles côté application (credentials de base de données, identifiants de rôles IAM) via un cache partagé empoisonné. | Theoretical | Mettre à jour vers 4.3.0 (et patcher les forks) ; à défaut, ne pas activer le RemoteQueryCachePlugin ou restreindre l'écriture du cache partagé aux principaux de confiance. | [https://aws.amazon.com/security/security-bulletins/rss/2026-109-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-109-aws/) |
| **CVE-2026-89065** | N/A | N/A | FALSE | projen < 0.101.37 (composant de nettoyage du manifeste des fichiers générés) | Traversée de chemin relative (path traversal) permettant la suppression récursive de fichiers hors du répertoire projet | Suppression récursive de fichiers et répertoires hors du projet sur le poste développeur ou le runner CI (perte de données, sabotage de l'environnement de build). | Theoretical | Mettre à jour vers 0.101.37 ou supérieur ; en attendant, auditer l'historique de contrôle de version de .projen/files.json et retirer les entrées s'échappant du répertoire projet avant d'exécuter projen. | [https://aws.amazon.com/security/security-bulletins/rss/2026-108-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-108-aws/) |
| **CVE-2026-89066** | N/A | N/A | FALSE | projen < 0.103.0 (composant de synthèse des tâches) | Injection de commande OS via métacaractères shell dans les valeurs de configuration projet et les noms de fichiers interpolés dans .projen/tasks.json | Exécution de commandes arbitraires sur un poste développeur ou un runner CI : compromission de la chaîne d'approvisionnement logicielle, vol de secrets CI/Cloud, modification de dépôts. | Theoretical | Mettre à jour vers 0.103.0 ou supérieur puis re-synthétiser les projets ; en attendant, auditer les valeurs de configuration listées dans l'avis pour détecter et retirer/échapper les métacaractères shell avant d'exécuter projen. | [https://aws.amazon.com/security/security-bulletins/rss/2026-108-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-108-aws/) |
| **CVE-2026-85102** | 9.8 | N/A | FALSE | Check Point Quantum Security Gateway, Security Management Server, Spark Firewall (fonctionnalité de traitement des certificats VPN) | Validation de confiance de certificat incorrecte (improper certificate trust-validation) lors de la négociation VPN - exécution de code possible par un acteur distant non authentifié sous conditions spécifiques | Exécution de code sur une Security Gateway exposée au périmètre ; en environnement où le serveur de gestion est affecté, contrôle administratif potentiel de multiples équipements gérés. | Theoretical | Appliquer les Live Patch / Jumbo Hotfix Check Point ; vérifier les versions déployées ; limiter l'exposition des interfaces VPN ; vérifier l'application des correctifs des CVE précédemment exploitées (CVE-2026-50751, CVE-2026-16232). | [https://fieldeffect.com/blog/check-point-patches-two-critical-vpn-certificate-processing-vulnerabilities](https://fieldeffect.com/blog/check-point-patches-two-critical-vpn-certificate-processing-vulnerabilities) |
| **CVE-2026-85103** | 9.8 | N/A | FALSE | Check Point Quantum Security Gateway, Security Management Server, Spark Firewall (fonctionnalité de traitement des certificats VPN) | Débordement de tampon basé sur le tas (heap-based buffer overflow) lors du décodage ASN.1 des certificats VPN - corruption mémoire et exécution de code possibles sous conditions spécifiques | Exécution de code sur des équipements périmétriques exposés à du trafic non fiable ; risque étendu en cas de compromission du serveur de gestion (contrôle administratif de multiples déploiements). | Theoretical | Appliquer les Live Patch / Jumbo Hotfix ; restreindre l'exposition des services VPN ; surveiller les crashs et erreurs de décodage de certificats. | [https://fieldeffect.com/blog/check-point-patches-two-critical-vpn-certificate-processing-vulnerabilities](https://fieldeffect.com/blog/check-point-patches-two-critical-vpn-certificate-processing-vulnerabilities) |
| **CVE-2026-39987** | N/A | N/A | FALSE | marimo (serveur/notebook Python - terminal WebSocket accessible sans authentification) | Exécution de code à distance (RCE) pré-authentification via WebSocket | Compromission totale des instances marimo exposées, vol de secrets cloud (AWS Secrets Manager, backend Redis), pivot vers les bastions via SSH, déploiement potentiel de RAT. | Active | Appliquer le correctif marimo ; ne pas exposer marimo publiquement ; restreindre les rôles IAM des instances ; faire tourner les secrets ; surveiller CloudTrail (GetCallerIdentity, Secrets Manager) et les accès SSH aux bastions. | [https://webflow.sysdig.com/blog/machine-speed-hold-the-ai-hand-rolled-marimo-cve-2026-39987-exploit](https://webflow.sysdig.com/blog/machine-speed-hold-the-ai-hand-rolled-marimo-cve-2026-39987-exploit) |
| **CVE-2026-75162** | N/A | N/A | FALSE | MBS-Solutions X-Serie Gateway (passerelle de bord industrielle), firmware V6_00_05 | Divulgation d'informations - stockage en clair d'informations sensibles (CWE-312) : identifiants OPC-UA exposés via /cgi-bin/wwwugw.cgi (méthode opcua-configuration) | Récupération d'identifiants OPC-UA en clair par un utilisateur à moindre privilège : usurpation de clients/serveurs OPC-UA, mouvement latéral vers les réseaux OT, manipulation potentielle de variables de processus, perturbation de production ou conditions dangereuses à l'usine. | None | Aucun patch disponible : restreindre urgemment l'accès réseau à l'interface web de la passerelle, segmenter IT/OT, appliquer le moindre privilège, surveiller les accès à wwwugw.cgi et faire tourner les identifiants OPC-UA ; surveiller la publication d'un correctif éditeur. | [https://www.valtersit.com/cve/CVE-2026-75162/](https://www.valtersit.com/cve/CVE-2026-75162/) |
| **CVE-2026-61608** | 6.8 | N/A | FALSE | SolidInvoice (versions antérieures à 3.0.1) | Défaut d'expiration des liens d'invitation utilisateur (insuffisance de contrôle d'accès / gestion de session) | Création non autorisée de comptes utilisateurs, accès aux données de facturation et aux données clients, manipulation potentielle des factures et des coordonnées de paiement. | Theoretical | Mettre à jour vers SolidInvoice v3.0.1, révoquer les invitations en attente, surveiller les créations de comptes anormales et imposer une expiration systématique des liens d'invitation. | [https://www.valtersit.com/cve/CVE-2026-61608/](https://www.valtersit.com/cve/CVE-2026-61608/) |
| **** | N/A | N/A | FALSE | Noyau Linux de Red Hat Enterprise Linux (multiples variantes et versions : RHEL 8, 9.4, 10.0, CodeReady Linux Builder, Real Time, SAP Solutions, architectures x86_64, aarch64, s390x, ppc64le) | Multiples vulnérabilités dans le noyau Linux (élévation de privilèges, exécution de code arbitraire, déni de service à distance, atteintes à la confidentialité/intégrité, contournement de politique de sécurité) | Selon les vulnérabilités : élévation de privilèges locale, exécution de code arbitraire, déni de service à distance, fuite ou altération de données et contournement de la politique de sécurité sur les systèmes RHEL concernés. | None | Appliquer les mises à jour du noyau via les bulletins RHSA listés (du 04/09/2026 au 10/09/2026) et redémarrer les systèmes pour charger le noyau corrigé ; suivre les recommandations du CERT-FR (CERTFR-2026-AVI-1161). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1161/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1161/) |
| **** | N/A | N/A | FALSE | Noyau Linux d'Ubuntu (multiples versions et variantes) | Multiples vulnérabilités dans le noyau Linux | Risques typiques des vulnérabilités noyau : élévation de privilèges, déni de service, atteintes à la confidentialité et à l'intégrité selon les CVE agrégées. | None | Appliquer les mises à jour du noyau via les bulletins USN listés et redémarrer les systèmes ; suivre les recommandations du CERT-FR (CERTFR-2026-AVI-1162). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1162/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1162/) |
| **** | N/A | N/A | FALSE | Noyau Linux de Debian (Long Term Support) | Multiples vulnérabilités dans le noyau Linux | Risques typiques des vulnérabilités noyau : élévation de privilèges, déni de service, atteintes à la confidentialité et à l'intégrité selon les CVE agrégées. | None | Appliquer les mises à jour du noyau Debian LTS dès leur publication et redémarrer les systèmes ; suivre les recommandations du CERT-FR (CERTFR-2026-AVI-1163). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1163/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1163/) |
| **** | N/A | N/A | FALSE | Noyau Linux de SUSE (multiples versions et variantes) | Multiples vulnérabilités dans le noyau Linux | Risques typiques des vulnérabilités noyau : élévation de privilèges, déni de service, atteintes à la confidentialité et à l'intégrité selon les CVE agrégées. | None | Appliquer les mises à jour du noyau via les bulletins SUSE-SU listés et redémarrer les systèmes ; suivre les recommandations du CERT-FR (CERTFR-2026-AVI-1164). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1164/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1164/) |
| **** | N/A | N/A | FALSE | Produits IBM (multiples) — cf. bulletins de sécurité IBM 7286515 à 7287136 (07 au 11 septembre 2026) | Multiples vulnérabilités (détails et CVE non spécifiés dans l'avis disponible) | Non détaillé dans l'avis disponible ; à évaluer bulletin par bulletin auprès de l'éditeur (risques potentiels classiques : exécution de code, élévation de privilèges, déni de service, atteinte à la confidentialité). | None | Se référer aux bulletins de sécurité IBM listés dans la documentation de l'avis (7286515 à 7287136) pour l'obtention et l'application des correctifs correspondant aux produits et versions déployés. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1165/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1165/) |
| **** | N/A | N/A | FALSE | FortiAnalyzer 7.6.x < 7.6.7 ; FortiClientWindows < 7.4.7 ; FortiManager et FortiManager Cloud 7.6.x < 7.6.5 et < 7.4.11 ; FortiMonitorOnSight 7.2.x < 7.2.8 ; FortiOS 7.6.x < 7.6.7 ; FortiPAM < 1.9.1 et FortiPAM Chrome Extension < 8.0.1.123 ; FortiProxy 7.6.x < 7.6.7 ; FortiSandbox 4.4.x < 4.4.10, 5.0.x < 5.0.6/5.0.7, 5.2.x < 5.2.1, FortiSandbox Cloud et PaaS 5.0.x < 5.0.6 ; FortiSIEM < 7.5.2 ; FortiSOAR on-premise et PaaS 7.6.x < 7.6.7 et < 7.5.4 | Multiples vulnérabilités : exécution de code arbitraire à distance, élévation de privilèges, déni de service à distance, contournement de la politique de sécurité, atteintes à la confidentialité et à l'intégrité des données | Un attaquant pourrait obtenir une exécution de code arbitraire à distance, élever ses privilèges, provoquer un déni de service à distance, contourner la politique de sécurité et compromettre la confidentialité et l'intégrité des données traitées par les équipements Fortinet, avec un risque de compromission de l'ensemble de l'architecture de sécurité périmétrique. | None | Appliquer les correctifs publiés par Fortinet dans les bulletins FG-IR-26-164 à FG-IR-26-174 (hxxps://www[.]fortiguard[.]com/psirt) : mettre à jour FortiOS, FortiProxy et FortiAnalyzer vers 7.6.7, FortiManager vers 7.6.5 ou 7.4.11, FortiSandbox vers 4.4.10 / 5.0.7 / 5.2.1, FortiSIEM vers 7.5.2, FortiSOAR vers 7.6.7 ou 7.5.4, FortiPAM vers 1.9.1, FortiClientWindows vers 7.4.7 et FortiMonitorOnSight vers 7.2.8. En attendant, restreindre l'exposition des interfaces d'administration. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1166/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1166/) |
| **** | N/A | N/A | FALSE | Sogou Input Method pour Windows (composants sgbiz:, biz_helper.exe, SGMyInput.exe, navigateur embarqué basé sur Chromium 80) | Chaîne d'exploitation client : gestionnaire de schéma d'URI sgbiz: sans filtrage des arguments de ligne de commande, ouverture d'URL arbitraire dans la boutique de skins, navigateur embarqué Chromium 80 avec sandbox et same-origin policy désactivées | Exécution de code avec les privilèges de l'utilisateur et installation d'un backdoor (shell distant, exfiltration, chargement de modules), avec un risque massif compte tenu de la base d'utilisateurs (>455 millions/mois) et du ciblage de secteurs sensibles en Asie. | Active | Appliquer le correctif Tencent (avril 2026) ; ne pas cliquer sur des liens sgbiz: non sollicités ; surveiller l'exécution de biz_helper.exe/SGMyInput.exe ; compte tenu du risque résiduel (navigateur embarqué obsolète, sandbox désactivée), évaluer le retrait de l'application sur les postes sensibles. | [https://thehackernews.com/2026/09/china-linked-unc3569-exploited-sogou.html](https://thehackernews.com/2026/09/china-linked-unc3569-exploited-sogou.html) |
| **** | N/A | N/A | FALSE | Noyau Linux (multiples sous-systèmes : ESP, RxRPC, helpers de fragments de socket buffer, traffic control pedit, systèmes de fichiers) - 13 LPE suivies en 2026 | Élévations de privilèges locales (LPE) - classe de bugs copy-on-write / zero-copy écrivant dans des données censées être copiées d'abord | Passage d'un accès non privilégié au contrôle root complet de l'hôte, étape clé transformant un foothold en contrôle total de la machine. | Theoretical | Appliquer rapidement les correctifs noyau ; installer les règles Elastic préconstruites (OS: Linux, Tactic: Privilege Escalation) ; déployer Elastic Defend ; activer l'intégration Auditd Manager ; restreindre user namespaces et capacités. | [https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework](https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework) |
| **** | N/A | N/A | FALSE | PaperCut NG/MF (instances exposées) | Exploitation massive et automatisée par agents IA (campagne d'intrusion autonome) ; aucun CVE PaperCut clairement identifié dans la source | Compromission de serveurs d'impression utilisés comme pivot pour un mouvement latéral autonome vers les contrôleurs de domaine et les données critiques ; fenêtres de détection effondrées du fait de la vitesse d'exécution des agents. | Active | Corriger et durcir les instances PaperCut, restreindre les privilèges des serveurs d'impression, segmenter le réseau, détecter les mouvements latéraux automatisés et revoir les délais de réponse des playbooks face à une exploitation sans intervention humaine. | [https://theperimetersite.com/report/247](https://theperimetersite.com/report/247) |
| **** | N/A | N/A | FALSE | Endpoints IA auto-hébergés exposés : Open WebUI (18 529 instances joignables), vLLM (4 880 endpoints), plateformes d'agents et bases vectorielles | Exposition publique de services IA sans authentification (mauvaise configuration / absence de contrôle d'accès réseau) ; aucun CVE identifié | Accès non authentifié potentiel aux modèles, prompts, documents et credentials ; détournement de compute d'inférence ; fuite de propriété intellectuelle et de données clients ; point d'entrée possible dans le SI via des services souvent privilégiés. | Theoretical | Ne jamais exposer ces services directement à Internet ; imposer une authentification (reverse proxy SSO/MFA), segmenter le réseau, surveiller en continu l'exposition externe des actifs IA et auditer les accès aux endpoints. | [https://securityaffairs.com/198898/ai/the-ai-supply-chain-has-a-security-problem-and-much-of-it-is-sitting-on-the-open-internet.html](https://securityaffairs.com/198898/ai/the-ai-supply-chain-has-a-security-problem-and-much-of-it-is-sitting-on-the-open-internet.html) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="chaine-dapprovisionnement-dinference-auto-expansive-un-agent-ia-recolte-valide-et-re-sert-des-acces-llm-voles"></div>

## Chaîne d'approvisionnement d'inférence auto-expansive : un agent IA récolte, valide et re-sert des accès LLM volés

### Résumé

Un analyste du SANS Internet Storm Center a observé, via un honeypot simulant un endpoint d'inférence compatible OpenAI, un opérateur utilisant un agent de codage semi-autonome pour mener une opération offensive : identification de passerelles de revente LLM mal sécurisées via des requêtes FOFA (title="V2Board", header="subscription-userinfo"), acquisition d'accès API par failles web ordinaires et farming de comptes (inscriptions ouvertes avec soldes gratuits, identifiants par défaut, faiblesses d'autorisation sur group_id, endpoint exposé /api/auth-files, création automatisée de comptes d'essai via e-mails temporaires et services de résolution de CAPTCHA), validation de la capacité d'inférence (test de calcul d'une factorielle pour distinguer une inférence réelle de réponses pré-enregistrées), puis agrégation d'environ 379 endpoints amont derrière une passerelle New-API auto-hébergée. Le client de l'agent embarquant ses instructions et son contexte dans les requêtes, le honeypot a reçu environ 43 Ko de données : un AGENTS.md, un playbook offensif, des notes d'infrastructure, des scripts de reconnaissance, des clés API collectées et une partie de l'historique de travail de l'agent. Une instruction demandant à l'agent de vérifier son proxy avant d'attaquer a exposé l'IP de sortie directe (non proxifiée) de l'opérateur, contenue dans le playbook comme valeur de référence. L'auteur décrit un mécanisme en boucle : la capacité d'inférence acquise est validée, consolidée puis re-servie via une API unifiée pour soutenir les opérations suivantes, formant une chaîne d'approvisionnement d'inférence partiellement auto-expansive.

---

### Analyse opérationnelle

Pour les équipes SOC/IT : inventorier et durcir toute passerelle LLM exposée (V2Board, New-API, one-api et dérivés) - désactiver l'inscription ouverte, imposer une vérification e-mail robuste et anti-CAPTCHA, corriger les contrôles d'autorisation sur group_id, restreindre les limites de facturation par défaut, exiger une authentification sur tous les endpoints d'administration et de catalogue. Détecter les précurseurs : sondes d'indexation FOFA/Shodan contre ces portails, accès à /api/auth-files, création massive de comptes, consommation anormale de tokens, tests logiques de type « calcule une factorielle » dans les prompts. Journaliser le contenu des requêtes vers les endpoints d'inférence : la fuite du « plan de contrôle » de l'agent (43 Ko d'instructions, clés API, historique) démontre que les agents IA divulguent leur contexte aux endpoints qu'ils contactent - traiter tout endpoint tiers comme exposé et filtrer la télémétrie sensible. Surveiller les clés API : rotation, détection de réutilisation sur des revendeurs, alertes de facturation.

---

### Implications stratégiques

L'émergence d'une économie criminelle de la capacité d'inférence : les accès LLM volés sont récoltés, validés et re-revendus via des passerelles unifiées, abaissant le coût d'accès à des modèles premium pour d'autres opérations malveillantes. L'automatisation agentique crée une boucle auto-expansive où l'outil offenseur étend sa propre infrastructure, signe d'une industrialisation de la cybercriminalité assistée par IA. Pour les fournisseurs et revendeurs d'IA, cela impose une gouvernance stricte des inscriptions, de la facturation et des quotas ; pour les organisations utilisant des agents de codage, cela révèle un risque de fuite d'informations sensibles (instructions internes, clés, historique) vers des endpoints non maîtrisés. Décisionnel : classer les infrastructures IA comme actifs critiques et intégrer la sécurité des passerelles LLM dans les programmes de gestion des risques.

---

### Recommandations

* Inventorier toutes les passerelles LLM (V2Board, New-API, one-api et dérivés) exposées et désactiver l'inscription ouverte
* Corriger les contrôles d'autorisation (group_id) et exiger une authentification sur tous les endpoints d'administration et de catalogue
* Imposer des limites de facturation et des quotas par défaut stricts ; alerter sur les consommations anormales
* Journaliser et inspecter les requêtes envoyées aux endpoints d'inférence pour détecter les tests logiques (factorielle) et les fuites de contexte d'agents
* Rotater les clés API et détecter leur réutilisation sur des services de revente
* Déployer des honeypots d'inférence pour détecter ce type d'activité sur son périmètre

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les endpoints d'inférence et passerelles LLM (compatibles OpenAI, V2Board, New-API, one-api) et cartographier leur exposition
* Durcir les configurations : inscription fermée ou vérifiée, MFA, quotas et limites de facturation par défaut stricts, autorisations granulaires sur group_id
* Définir la journalisation des requêtes d'inférence (prompts, métadonnées, clés utilisées) avec rétention adaptée
* Sensibiliser les équipes utilisant des agents de codage IA au risque de fuite de contexte et de clés vers des endpoints tiers
* Déployer des honeypots d'API d'inférence et s'abonner aux flux de renseignement sur l'abus de services IA

#### Phase 2 — Détection et analyse

* Alerter sur les accès aux endpoints sensibles (/api/auth-files, catalogues de modèles exposés sans authentification)
* Détecter les créations de comptes en masse (e-mails temporaires, résolution automatisée de CAPTCHA)
* Surveiller les consommations de tokens anormales, l'exploitation de limites de facturation élevées et les clés utilisées depuis des IP de datacenter
* Inspecter les prompts pour des motifs de validation d'inférence (calcul de factorielle, édition de fichiers) et les fuites de contexte d'agents (AGENTS.md, instructions embarquées)
* Corréler les scans FOFA/Shodan ciblant les portails LLM avec les tentatives de connexion ultérieures

#### Phase 3 — Confinement, éradication et récupération

* Révoquer/rotater immédiatement les clés API compromises et désactiver les comptes frauduleux
* Fermer l'inscription ouverte et bloquer les plages IP de l'attaquant (IP de sortie directe si identifiée)
* Isoler ou mettre hors ligne la passerelle compromise et purger ses canaux amont
* Appliquer des rate limits et un challenge anti-automatisation sur les endpoints d'authentification

#### Phase 4 — Activités post-incident

* Analyser les journaux pour déterminer l'étendue des accès (endpoints, modèles consommés, données transitées dans les prompts)
* Évaluer la fuite d'informations sensibles via les requêtes d'agents (instructions internes, clés API, historique de travail)
* Réconcilier la facturation et quantifier l'abus de capacité d'inférence
* Produire un retour d'expérience et corriger les faiblesses d'autorisation et de configuration exploitées

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les instances V2Board/New-API/one-api exposées sur son périmètre et ses surfaces externes
* Chasser les clés API réutilisées sur des revendeurs tiers ou des passerelles d'agrégation inconnues
* Rechercher dans les journaux les motifs de prompts de validation (factorielle) et les charges utiles volumineuses (~43 Ko) contenant des instructions d'agents
* Identifier dans l'historique d'authentification les connexions avec identifiants par défaut ou manipulations de group_id

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1596.005** | Search Open Technical Databases: Scan Databases - utilisation de requêtes FOFA (title="V2Board", header="subscription-userinfo") pour localiser des passerelles LLM exposées |
| **T1552** | Unsecured Credentials - exploitation d'inscriptions ouvertes, d'identifiants par défaut, de faiblesses d'autorisation sur group_id et d'endpoints exposés (/api/auth-files) pour obtenir des clés API |
| **T1585.002** | Establish Accounts: Email Accounts - création automatisée de comptes d'essai via e-mails temporaires et services de résolution de CAPTCHA |
| **T1078** | Valid Accounts - utilisation et validation des clés API compromises contre des services de revente d'inférence |
| **T1583** | Acquire Infrastructure - déploiement d'une passerelle New-API auto-hébergée agrégrant environ 379 endpoints amont pour re-servir la capacité d'inférence volée |

---

### Sources

* `hxxps://isc.sans.edu/diary/rss/33332`


---

<div id="btrcli-attaque-byovd-contre-windows-defender-via-un-pilote-signe-vulnerable"></div>

## BTR_CLI : attaque BYOVD contre Windows Defender via un pilote signé vulnérable

### Résumé

Un nouvel épisode de « Weekly Purple Team » présente une attaque BYOVD (Bring Your Own Vulnerable Driver) menée avec l'outil BTR_CLI, qui abuse d'un pilote signé vulnérable pour contourner la protection anti-modification (tamper protection) de Windows Defender au niveau du noyau. La démonstration montre l'obtention d'un accès kernel, la suppression de fichiers, la réécriture de clés de registre et la suppression complète de Defender de l'hôte. Côté défense, l'épisode couvre la détection : événements de chargement de pilotes, télémétrie du processus BTR_CLI, alertes de tamper protection et surveillance du registre. Les techniques MITRE ATT&CK couvertes sont T1562.001, T1068 et T1112, au format red vs. blue.

---

### Analyse opérationnelle

Activer la blocklist Microsoft des pilotes vulnérables et, si possible, HVCI/VBS pour empêcher le chargement du pilote abusé. Déployer des détections sur : événements de chargement de pilotes (Sysmon EID 6), processus BTR_CLI et leurs lignes de commande, alertes de tamper protection Defender, et modifications du registre des clés de stratégie Defender (désactivations, exclusions). Surveiller les suppressions de fichiers liées à Defender et toute élévation de privilèges via pilote. Restreindre les privilèges administrateur locaux (les attaques BYOVD nécessitent généralement un accès administrateur) et journaliser les installations de services de pilotes.

---

### Implications stratégiques

Le tooling BYOVD prêt à l'emploi (BTR_CLI) démocratise une évasion kernel capable de neutraliser les EDR, y compris leurs protections anti-modification. Cela démontre que la protection endpoint seule est contournable et justifie une défense en profondeur : contrôle des pilotes, VBS/HVCI, télémétrie noyau et détections Windows natives en complément de l'EDR. Tendance persistante : les acteurs de menace, y compris ceux opérant des ransomwares, exploitent massivement des pilotes signés vulnérables ; la gestion du risque « pilotes » doit être intégrée aux programmes de supply chain et de durcissement.

---

### Recommandations

* Activer la liste de blocage des pilotes vulnérables Microsoft et HVCI (intégrité de mémoire virtuelle)
* Alerter sur tout chargement de pilote non Microsoft signé et sur le processus BTR_CLI
* Surveiller les clés de registre Defender (politiques, exclusions) et les alertes de tamper protection
* Restreindre les droits administrateur locaux et journaliser la création de services de pilotes
* Valider ces détections en exercice purple team (T1562.001, T1068, T1112)

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Activer la blocklist Microsoft des pilotes vulnérables et HVCI/VBS (intégrité de mémoire) sur les endpoints
* Inventorier les pilotes tiers signés présents sur le parc et les vérifier contre les listes de pilotes vulnérables (ex. LOLDrivers)
* Configurer la journalisation Sysmon (EID 6 driver load, EID 1 process creation, EID 13 registry) et centraliser les journaux Defender
* Restreindre les privilèges administrateur locaux nécessaires au chargement de pilotes

#### Phase 2 — Détection et analyse

* Alerter sur tout chargement de pilote non Microsoft signé, en particulier ceux listés comme vulnérables
* Détecter le processus BTR_CLI et ses lignes de commande (télémétrie process)
* Surveiller les alertes de tamper protection Defender et les modifications de clés de registre Defender (T1112)
* Détecter les tentatives d'élévation de privilèges via pilote (T1068) et les suppressions de fichiers liées à Defender

#### Phase 3 — Confinement, éradication et récupération

* Isoler l'hôte du réseau pour empêcher tout chargement supplémentaire de pilote ou déploiement d'outils
* Bloquer/supprimer le pilote vulnérable et le service associé ; restaurer les clés de registre Defender et réactiver Defender
* Réinitialiser les identifiants locaux compromis et vérifier l'absence de persistance additionnelle

#### Phase 4 — Activités post-incident

* Analyser ce que l'attaquant a fait avec l'accès kernel (fichiers supprimés, outils déployés, autres défenses désactivées)
* Vérifier l'intégrité du système ; envisager une reconstruction en cas de compromission kernel confirmée
* Collecter les artefacts (pilote, hashes, registre, journaux) et enrichir les règles de détection
* Réaliser un retour d'expérience et corriger les écarts de durcissement (blocklist, HVCI, privilèges)

#### Phase 5 — Threat Hunting (proactif)

* Chasser l'historique des chargements de pilotes contre les listes de pilotes vulnérables (hashes, noms)
* Rechercher les modifications de registre sur les politiques Defender et les exclusions ajoutées
* Rechercher les services de pilotes créés récemment et les arrêts/désactivations du service WinDefend
* Corréler les alertes de tamper protection avec des processus administrateurs inhabituels

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1562.001** | Impair Defenses: Disable or Modify Tools - suppression complète de Windows Defender de l'hôte via contournement de la tamper protection |
| **T1068** | Exploitation for Privilege Escalation - abus d'un pilote signé vulnérable (BYOVD) pour obtenir un accès kernel |
| **T1112** | Modify Registry - réécriture de clés de registre liées à Defender pour désactiver les défenses |

---

### Sources

* `hxxps://youtu.be/iB_OFmrBIBM`


---

<div id="avis-de-securite-gitlab-av26-917-les-plateformes-cicd-cibles-de-choix"></div>

## Avis de sécurité GitLab AV26-917 : les plateformes CI/CD, cibles de choix

### Résumé

GitLab a publié un avis de sécurité référencé AV26-917. Le post souligne que les plateformes de CI/CD restent des cibles de choix car elles centralisent identifiants (credentials), pipelines et accès aux dépôts, et recommande de vérifier sa version de GitLab et ses configurations d'accès. Aucun détail technique (CVE, score CVSS, vecteur d'exploitation) n'est fourni dans la source.

---

### Analyse opérationnelle

Vérifier immédiatement les versions des instances GitLab du parc et les comparer à l'avis AV26-917 ; planifier la mise à jour vers les versions corrigées. Revoir les configurations d'accès : exposition Internet, authentification (2FA), tokens d'accès et secrets stockés dans les variables CI/CD, permissions des groupes et projets. Surveiller les canaux officiels GitLab pour obtenir les détails CVE et les indicateurs d'exploitation dès publication.

---

### Implications stratégiques

Les plateformes CI/CD constituent un point de convergence critique de la supply chain logicielle : leur compromission expose le code source et les secrets, et permet l'empoisonnement de pipelines (déploiement de code malveillant chez les clients). Un avis GitLab doit être traité avec la même priorité qu'une vulnérabilité sur un service exposé. Décisionnel : intégrer les plateformes CI/CD dans la gestion des vulnérabilités à cycle court et auditer régulièrement leurs configurations d'accès.

---

### Recommandations

* Vérifier la version de toutes les instances GitLab et appliquer les correctifs de l'avis AV26-917
* Restreindre l'exposition Internet et imposer la 2FA sur les comptes GitLab
* Rotater les secrets et tokens stockés dans les variables CI/CD après mise à jour
* Auditer les configurations d'accès (permissions projets/groupes, runners partagés)
* S'abonner aux avis de sécurité GitLab et aux flux CISA pour le suivi des CVE

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les instances GitLab (versions, éditions, exposition Internet) et leurs runners
* S'abonner aux avis de sécurité GitLab et aux alertes CISA pour un suivi proactif
* Documenter les secrets stockés dans les variables CI/CD et leurs propriétaires
* Définir une procédure de patching à cycle court pour les plateformes CI/CD

#### Phase 2 — Détection et analyse

* Surveiller la publication de l'avis AV26-917 et des CVE associées dès leur divulgation
* Scanner le parc pour identifier les instances concernées par les versions vulnérables
* Surveiller les journaux GitLab : connexions anormales, création de tokens, pipelines inhabituels, accès administrateur

#### Phase 3 — Confinement, éradication et récupération

* Appliquer les mises à jour de sécurité vers les versions corrigées
* Si le patch est différé, restreindre l'exposition (WAF/VPN), désactiver les fonctionnalités affectées et renforcer l'authentification
* Révoquer et rotater les tokens d'accès et secrets potentiellement exposés

#### Phase 4 — Activités post-incident

* Analyser les journaux d'audit GitLab pour détecter toute exploitation antérieure (accès aux dépôts, exfiltration, modifications de pipelines)
* Évaluer la compromission des secrets et du code source ; rotater l'ensemble des identifiants concernés
* Vérifier l'intégrité des artefacts publiés (images, paquets) construits par les pipelines

#### Phase 5 — Threat Hunting (proactif)

* Chasser dans les journaux les requêtes d'exploitation liées aux CVE de l'avis (dès publication de PoC)
* Rechercher les pipelines déclenchés hors horaires, par des comptes inattendus ou produisant des artefacts non signés
* Identifier les comptes disposant de tokens à portée étendue (admin, API) et détecter leur usage anormal

---

### Sources

* `hxxps://malware.news/t/gitlab-security-advisory-av26-917/125543`


---

<div id="direwolf-le-groupe-de-ransomware-a-double-extorsion-publie-la-victime-port-of-tanjung-pelepas-sur-son-site-de-fuite"></div>

## Direwolf : le groupe de ransomware à double extorsion publie la victime Port of Tanjung Pelepas sur son site de fuite

### Résumé

Le service de surveillance RansomLook recense une nouvelle victime publiée le 2026-09-11 sur le site de fuite du groupe Direwolf : Port of Tanjung Pelepas. Direwolf est un groupe de ransomware à double extorsion apparu vers mai 2025, combinant chiffrement de fichiers (extension .direwolf) et revente de données. Le chiffreur est écrit en Go, livré sous forme de binaire packé UPX et utilise Curve25519 et ChaCha20 ; il supprime les sauvegardes, désactive la journalisation et arrête des services clés pour empêcher toute récupération. Les notes de rançon sont hautement personnalisées (identifiants de chat en direct, portails dédiés par victime). Le groupe affiche 135 publications depuis sa création, dont 49 sur les 30 derniers jours et 11 sur les 7 derniers jours. Ses cibles couvrent l'industrie manufacturière, la technologie, la santé, l'éducation et la finance, notamment aux États-Unis, en Thaïlande, à Taïwan, à Singapour et en Turquie ; les victimes récentes incluent Wolfram Research, PTT Oil and Retail Business, THQ Nordic, Arizona State University, Statista GmbH ou encore Quironsalud. L'infrastructure de fuite .onion est en ligne (uptime d'environ 77 % sur 30 jours), un serveur de fichiers associé est hors ligne et le serveur de chat est opérationnel.

---

### Analyse opérationnelle

Artefacts de détection prioritaires : extension de fichiers .direwolf, note de rançon HowToRecoveryFiles.txt, binaires Go packés UPX, suppressions massives de sauvegardes, désactivation de la journalisation et arrêts de services critiques. Les équipes SOC doivent déployer des règles EDR/SIEM sur ces comportements (T1486, T1490, T1562.001, T1489) et surveiller les flux sortants anormaux signalant une exfiltration préalable au chiffrement. Les URL .onion du groupe (site de fuite, serveur de fichiers, serveur de chat) peuvent être bloquées en sortie et servent de pivots de monitoring. La personnalisation des notes de rançon et des portails par victime indique une opération structurée : toute négociation ou analyse de note récupérée doit être conservée comme preuve. La surface d'attaque typique reste les accès distants et comptes privilégiés : vérifier MFA, segmentation et protection des sauvegardes.

---

### Implications stratégiques

La cadence de publication (49 victimes en 30 jours) fait de Direwolf un acteur à forte activité malgré son apparition récente, avec une portée multi-sectorielle incluant santé, éducation et finance. La compromission revendiquée d'un port maritime (Port of Tanjung Pelepas) illustre le risque pour les infrastructures logistiques critiques et les effets en cascade sur les chaînes d'approvisionnement régionales (Asie du Sud-Est). Le modèle de double extorsion expose les organisations à un double impact : interruption d'activité et fuite de données avec risque réglementaire (RGPD et équivalents) et réputationnel. Les directions doivent intégrer Direwolf dans leurs évaluations de risque tiers/filiales en Asie, Amérique latine et Europe, et arbitrer des investissements sur l'immutabilité des sauvegardes, la détection comportementale et les plans de continuité.

---

### Recommandations

* Vérifier la présence des indicateurs (extension .direwolf, HowToRecoveryFiles.txt, binaires UPX/Go suspects) sur le parc et dans le SIEM
* Bloquer en sortie les URL .onion listées et surveiller les publications du groupe sur les plateformes de suivi de leak sites
* Renforcer l'immutabilité et l'isolation des sauvegardes, et tester une restauration complète
* Activer les détections comportementales sur suppression de sauvegardes, arrêt de services et désactivation de logs
* Sensibiliser les équipes IT aux TTP du groupe et intégrer Direwolf à la veille menace du secteur (manufacturing, logistique, santé)

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir des sauvegardes 3-2-1 avec au moins une copie hors ligne et immuable, et tester régulièrement les restaurations
* Activer la protection anti-altération (tamper protection) des EDR/EPP et centraliser les journaux vers un SIEM hors du périmètre chiffrable
* Durcir les accès distants : MFA sur VPN et services exposés, revue des comptes privilégiés
* Segmenter le réseau et restreindre les partages SMB et les droits d'écriture sur les sauvegardes
* Formaliser un plan de réponse ransomware (rôles, arbitrages, contacts juridiques/RGPD/assureur) et le tester par exercice

#### Phase 2 — Détection et analyse

* Alerter sur la création de fichiers avec extension .direwolf ou sur la présence d'une note de rançon HowToRecoveryFiles.txt
* Détecter les suppressions massives de sauvegardes, snapshots ou shadow copies (vssadmin, wbadmin) et les arrêts anormaux de services (bases de données, agents de sauvegarde, antivirus)
* Surveiller la désactivation de la journalisation ou des outils de défense
* Détecter les binaires Go packés UPX exécutés depuis des répertoires inhabituels
* Surveiller les flux sortants volumineux anormaux (exfiltration préalable à l'extorsion) et les connexions vers l'infrastructure .onion listée

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les machines concernées du réseau (déconnexion réseau, mise en quarantaine EDR)
* Couper les partages réseau et suspendre les réplications de sauvegarde pour éviter leur chiffrement
* Bloquer les IOC (URL .onion, binaires identifiés) au niveau proxy/DNS/EDR
* Désactiver les comptes compromis et révoquer les sessions et jetons d'authentification
* Préserver les preuves : images mémoire et disque avant toute restauration

#### Phase 4 — Activités post-incident

* Restaurer depuis des sauvegardes vérifiées saines après reformatage des systèmes compromis
* Mener l'analyse forensique pour identifier le vecteur initial, la durée de présence et l'étendue de l'exfiltration
* Renouveler l'ensemble des secrets (mots de passe, clés, certificats, comptes de service)
* Si exfiltration de données personnelles, effectuer les notifications réglementaires requises (RGPD/CNIL, ANSSI) et informer les parties prenantes
* Surveiller le site de fuite du groupe pour détecter une publication de données et documenter l'incident (retour d'expérience)

#### Phase 5 — Threat Hunting (proactif)

* Rechercher sur l'ensemble du parc les fichiers *.direwolf et HowToRecoveryFiles.txt
* Chasser les processus packés UPX / binaires Go inconnus et les exécutions depuis %TEMP% ou des partages
* Corréler les événements de suppression de journaux, d'arrêts de services et de suppressions de sauvegardes sur les 30 derniers jours
* Rechercher des connexions sortantes inhabituelles vers des résolveurs/TOR ou des volumes de transfert sortants anormaux
* Vérifier l'intégrité des sauvegardes existantes et l'absence de comptes dormants créés par l'attaquant

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxp://direwolfcdkv5whaz2spehizdg22jsuf5aeje4asmetpbt6ri4jnd4qd[.]onion/` | High |
| URL | `hxxp://direwolfgpyqohwxwoetsz7a6p72diu32c3wfysqdx4ei6bwft7zh3yd[.]onion/` | High |
| URL | `hxxp://direwolf66s5zealav7azcyqeipiswecvvnapyuby3dek473kyqfucad[.]onion` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact : chiffrement des fichiers avec extension .direwolf (Curve25519/ChaCha20) |
| **T1490** | Inhibit System Recovery : suppression des sauvegardes pour bloquer la restauration |
| **T1562.001** | Impair Defenses : désactivation de la journalisation |
| **T1489** | Service Stop : arrêt de services clés pour empêcher la récupération |

---

### Sources

* [https://www.ransomlook.io//group/direwolf](https://www.ransomlook.io//group/direwolf)


---

<div id="vx-pack-kit-de-phishing-aitm-as-a-service-dorigine-bresilienne-ciblant-les-banques-au-bresil-et-au-portugal"></div>

## VX-Pack : kit de phishing AiTM « as-a-service » d'origine brésilienne ciblant les banques au Brésil et au Portugal

### Résumé

Infoblox Threat Intel décrit VX-Pack, un kit de phishing-as-a-service d'origine brésilienne ciblant des banques au Brésil et au Portugal, actif depuis au moins janvier 2025 et vendu par un développeur unique à plusieurs acheteurs opérant leurs propres campagnes. Contrairement aux kits AiTM classiques à proxy inverse (Evilginx, Tycoon 2FA, EvilProxy) qui relaient le trafic et volent le cookie de session, VX-Pack utilise un site réplique : l'opérateur observe la victime remplir chaque champ via une connexion WebSocket, rejoue lui-même les identifiants contre la vraie banque, et redemande un OTP à la victime si le token expire (« token inválido »). Il n'y a ni vol de cookie de session ni empreinte de relay côté banque : les contrôles anti-proxy de la banque voient le trafic de la machine de l'opérateur lui-même. Le kit usurpe Banco Santander et plus de dix autres institutions financières et plateformes de paiement. Neuf domaines de phishing sont listés, dont pactualapp[.]com, pactualpj[.]com, pactual[.]live, ativarbia[.]net, ativarbia[.]com, pactualapp[.]live, centraldecancelamentos[.]pt, verificador-cliente[.]live et ativador-login[.]click.

---

### Analyse opérationnelle

Détection : bloquer et surveiller les neuf domaines listés en DNS/proxy/passerelle mail, et chasser les motifs de nommage proches (pactual*, ativarbia*, TLD .live/.click/.pt). Point clé pour les équipes anti-fraude bancaires : l'absence de proxy inverse signifie que les contrôles anti-AiTM basés sur l'empreinte du relay ne se déclenchent pas ; les connexions frauduleuses semblent provenir d'une machine « normale » (celle de l'opérateur). Les signaux exploitables côté victime sont la sollicitation répétée d'OTP et la séquence mot de passe puis token sur un domaine non officiel. Mesures : MFA résistant au phishing (FIDO2/passkeys), filtrage des domaines nouvellement enregistrés, corrélation des demandes OTP multiples avec des connexions atypiques, et signalement des domaines pour takedown.

---

### Implications stratégiques

VX-Pack illustre l'évolution du modèle PhaaS : le passage du proxy inverse à la réplique pilotée en direct par un opérateur contourne les contrôles anti-AiTM des banques et fragilise la confiance placée dans la détection anti-fraude (« le trafic a passé la détection » n'est plus un gage de légitimité). Le modèle as-a-service multiplie le nombre d'acteurs capables de mener des attaques 2FA bypass avec peu de compétences, abaissant la barrière d'entrée contre le secteur financier. La cible Brésil/Portugal suggère une expansion possible vers d'autres marchés lusophones et européens, y compris la France. Les banques et fintechs doivent réévaluer leurs contrôles d'authentification (passkeys, liaison du canal de transaction, détection comportementale) et renforcer le partage de renseignements sectoriel pour suivre des infrastructures rotatives.

---

### Recommandations

* Ajouter les neuf domaines listés aux listes de blocage DNS/proxy/mail et aux règles SIEM
* Surveiller les enregistrements de domaines similaires (certificat transparency, flux NRD) pour anticiper les rotations d'infrastructure
* Déployer des méthodes d'authentification résistantes au phishing pour les accès financiers
* Ajuster les modèles anti-fraude : ne pas traiter l'absence d'empreinte proxy comme un signal de légitimité
* Sensibiliser les clients/utilisateurs au schéma de redemande d'OTP (« token inválido ») et au contrôle du domaine dans la barre d'adresse

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer une authentification résistante au phishing (FIDO2/passkeys) en priorité sur les accès bancaires et sensibles
* Configurer un filtrage DNS/proxy avec blocage des catégories phishing et des domaines nouvellement enregistrés (NRD)
* Mettre en place DMARC/DKIM/SPF en mode strict et surveiller les domaines typosquatting proches des marques utilisées
* Sensibiliser les utilisateurs au schéma spécifique : page réplique demandant mot de passe puis OTP, avec relance en cas de « token inválido »
* Coordonner avec les équipes anti-fraude bancaires le partage d'indicateurs (FS-ISAC, CERT sectoriel)

#### Phase 2 — Détection et analyse

* Alerter sur toute résolution DNS ou connexion proxy vers les domaines listés (pactualapp[.]com, ativarbia[.]com, verificador-cliente[.]live, etc.)
* Détecter les séquences anormales de demandes OTP rapprochées ou d'échecs de validation de token suivis de connexions réussies
* Corréler les connexions réussies depuis des IP/réseaux atypiques (machine de l'opérateur) avec des connexions victimes récentes
* Surveiller les signalements utilisateurs de pages de login suspectes et analyser les URLs via sandbox/analyse d'URL

#### Phase 3 — Confinement, éradication et récupération

* Bloquer immédiatement les neuf domaines en DNS, proxy et passerelle de messagerie
* Réinitialiser les identifiants et révoquer sessions/jetons des utilisateurs ayant interagi avec ces domaines
* Purger les e-mails contenant les liens encore présents dans les boîtes
* Signaler les domaines aux registrars/hébergeurs et aux autorités (CERT/Phishing Initiative) pour takedown
* Informer l'institution financière usurpée afin de bloquer les transactions frauduleuses en cours

#### Phase 4 — Activités post-incident

* Analyser les accès frauduleux réalisés avec les identifiants volés (mouvements, virements, changements de coordonnées)
* Documenter le scénario d'attaque et ajuster les règles de détection anti-fraude : le trafic vers la banque provient de la machine de l'opérateur, sans empreinte de proxy inverse
* Partager les IOC et le TTP avec la communauté (ISAC, CERT, fournisseurs DNS) pour enrichir les blocages globaux
* Vérifier l'absence de persistance secondaire sur les postes des victimes (le kit opère côté navigateur, mais écarter une infection complémentaire)

#### Phase 5 — Threat Hunting (proactif)

* Chasser dans les logs DNS/proxy les requêtes vers pactual*, ativarbia*, *.live, *.click récemment enregistrés et les motifs similaires
* Rechercher les certificats TLS émis pour ces domaines et dérivés (certificat transparency) pour anticiper les nouvelles infrastructures
* Corréler les tentatives OTP multiples et les connexions géographiquement incohérentes sur les comptes à risque
* Identifier les utilisateurs ayant soumis des identifiants sur des domaines externes inconnus et leur appliquer une remédiation proactive

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `pactualapp[.]com` | High |
| DOMAIN | `pactualpj[.]com` | High |
| DOMAIN | `pactual[.]live` | High |
| DOMAIN | `ativarbia[.]net` | High |
| DOMAIN | `ativarbia[.]com` | High |
| DOMAIN | `pactualapp[.]live` | High |
| DOMAIN | `centraldecancelamentos[.]pt` | High |
| DOMAIN | `verificador-cliente[.]live` | High |
| DOMAIN | `ativador-login[.]click` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Spearphishing Link : distribution de liens vers des répliques de portails bancaires |
| **T1111** | Two-Factor Authentication Interception : collecte en direct du mot de passe et du OTP, rejoués par l'opérateur contre la banque réelle |
| **T1656** | Impersonation : usurpation de Banco Santander et de plus de dix institutions financières et plateformes de paiement |

---

### Sources

* [https://infosec.exchange/@InfobloxThreatIntel/117254583025085061](https://infosec.exchange/@InfobloxThreatIntel/117254583025085061)


---

<div id="phishing-possible-detecte-sur-le-domaine-ceihmedicalcentercombr-page-imitant-adobe"></div>

## Phishing possible détecté sur le domaine ceihmedicalcenter[.]com[.]br (page imitant Adobe)

### Résumé

Un signalement de phishing possible a été publié le 11 septembre 2026 via urlDNA, concernant l'URL hxxps://ceihmedicalcenter[.]com[.]br/adobe/Windows/checking[.]php. Le chemin de l'URL (/adobe/Windows/checking.php) suggère une page d'hameçonnage imitant Adobe, hébergée sur un domaine appartenant apparemment à un centre médical brésilien, possiblement compromis pour servir d'infrastructure d'hébergement. Une analyse complète de l'URL est disponible sur urlDNA (scan 6aa449693b7750000609629e). Aucun détail supplémentaire (vecteur de distribution, volume de destinataires, victimes ou données collectées) n'est fourni dans la publication.

---

### Analyse opérationnelle

Actions immédiates : bloquer le domaine ceihmedicalcenter[.]com[.]br et l'URL complète en DNS, proxy et passerelle de messagerie ; purger les messages contenant ce lien ; vérifier dans les logs proxy/DNS qu'aucun utilisateur n'y a accédé récemment et identifier ceux qui ont cliqué pour appliquer une remédiation (réinitialisation d'identifiants, analyse du poste). L'hébergement sur un domaine légitime de secteur médical (.com[.]br) augmente la probabilité de contourner les réputations de domaine : les contrôles ne doivent pas se limiter aux listes noires de domaines « suspects ». Si ce domaine appartient à votre organisation, traiter l'incident comme une compromission de site web (répertoire /adobe/Windows/ injecté, probablement via CMS ou identifiants volés) et investiguer le serveur d'hébergement.

---

### Implications stratégiques

Ce cas illustre la tendance à l'abus de sites légitimes compromis (ici un centre médical) comme infrastructure d'hébergement de phishing, ce qui améliore la crédibilité de l'hameçonneur et complique le blocage basé sur la réputation. Le secteur santé, souvent doté de budgets de cybersécurité limités, sert régulièrement de relais pour ce type d'infrastructure, exposant ses propres patients à la confusion. Pour les organisations, l'enjeu est double : se prémunir contre les pages hébergées sur des domaines de confiance compromis (analyse comportementale des URLs, filtrage des nouveaux chemins) et protéger son propre domaine pour ne pas devenir un relais d'attaque, avec le risque réputationnel et juridique associé.

---

### Recommandations

* Bloquer le domaine et l'URL listés sur DNS, proxy et passerelle mail
* Vérifier dans les logs les accès à ce domaine et réinitialiser les identifiants des utilisateurs exposés
* Signaler l'URL à urlDNA, aux services de blocage et au registrar pour takedown
* Si le domaine est sous votre contrôle, auditer immédiatement le serveur web (répertoires injectés, CMS, identifiants) et nettoyer
* Étendre la détection au-delà de la réputation de domaine : analyse des chemins et du contenu des pages pour les sites légitimes compromis

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un filtrage DNS/web avec blocage des catégories phishing et analyse réputationnelle des URLs
* Activer l'inspection des liens dans les passerelles de messagerie (rewriting et détonation en sandbox)
* Sensibiliser les utilisateurs au contrôle du domaine exact avant toute saisie d'identifiants
* Si le domaine appartient à votre organisation, durcir le CMS/hébergement (MFA sur l'administration, mises à jour, WAF)

#### Phase 2 — Détection et analyse

* Alerter sur toute résolution DNS ou connexion proxy vers ceihmedicalcenter[.]com[.]br et l'URL hxxps://ceihmedicalcenter[.]com[.]br/adobe/Windows/checking[.]php
* Surveiller les e-mails contenant ce domaine ou des liens vers des chemins /adobe/Windows/*.php
* Analyser l'URL via urlDNA ou équivalent pour identifier la page réelle, les payloads et les redirections

#### Phase 3 — Confinement, éradication et récupération

* Bloquer le domaine et l'URL en DNS, proxy et passerelle mail
* Purger les messages contenant le lien encore présents dans les boîtes
* Isoler et examiner les postes des utilisateurs ayant accédé à l'URL ou saisi des identifiants
* Si le domaine est interne à l'organisation, mettre hors ligne le répertoire compromis et préserver les journaux du serveur web

#### Phase 4 — Activités post-incident

* Réinitialiser les identifiants de tout utilisateur ayant soumis des données sur la page
* Si le site est votre propriété : identifier la compromission (CMS, identifiants FTP, injection), nettoyer, revoir les accès et surveiller une réinfection
* Signaler l'URL aux services de blocage (Safe Browsing, CERT, registrar) pour accélérer le takedown
* Documenter l'incident et le vecteur de distribution (e-mail, SMS, QR code) pour ajuster la prévention

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les logs proxy/DNS tout accès historique à ceihmedicalcenter[.]com[.]br et à des chemins similaires (/adobe/, /Windows/, checking.php)
* Chasser d'autres pages hébergées sur le même domaine (scan de répertoires, certificat transparency, historique de résolution)
* Identifier les utilisateurs ayant cliqué sur des liens vers des domaines .com[.]br récemment enregistrés ou compromis
* Corréler avec d'autres campagnes de phishing usurpant Adobe pour détecter une infrastructure partagée

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `ceihmedicalcenter[.]com[.]br` | Medium |
| URL | `hxxps://ceihmedicalcenter[.]com[.]br/adobe/Windows/checking[.]php` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Spearphishing Link : page de phishing possible hébergée sur un domaine légitime potentiellement compromis |

---

### Sources

* [https://urldna.io/scan/6aa449693b7750000609629e](https://urldna.io/scan/6aa449693b7750000609629e)


---

<div id="un-ressortissant-ukrainien-condamne-a-quatre-ans-de-prison-pour-conspiration-de-fraude-electronique-liee-au-ransomware-conti"></div>

## Un ressortissant ukrainien condamné à quatre ans de prison pour conspiration de fraude électronique liée au ransomware Conti

### Résumé

DataBreaches.net rapporte la condamnation d'un ressortissant ukrainien à quatre ans de prison pour conspiration en vue de commettre une fraude électronique (wire fraud), en lien avec ses activités pour le compte du groupe de ransomware Conti. Le texte intégral de l'article n'était pas accessible au moment de la collecte (page bloquée) ; les faits proviennent du titre publié.

---

### Analyse opérationnelle

Cette condamnation confirme la dimension financière (fraude électronique) de certaines activités des affiliés Conti. Les équipes peuvent enrichir leurs profils d'acteurs et leurs règles de détection avec les indicateurs historiques du groupe Conti (infrastructures, tooling, techniques), toujours pertinents pour la chasse aux résidus d'activité et aux affiliés récidivistes opérant sous d'autres marques.

---

### Implications stratégiques

La poursuite des condamnations pénales illustre la pression judiciaire internationale maintenue sur l'écosystème Conti, officiellement dissous mais dont les affiliés ont rejoint d'autres programmes de ransomware. Pour les organisations, le risque ne disparaît pas avec le démantèlement d'une marque : les opérateurs réapparaissent sous d'autres bannières, ce qui justifie une veille continue sur les mouvements d'affiliés entre groupes.

---

### Recommandations

* Maintenir actives les détections sur les TTP et IOC historiques de Conti
* Surveiller les mouvements d'affiliés vers d'autres programmes de ransomware
* Intégrer les enseignements des dossiers judiciaires publics dans les profils de menace internes

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sauvegardes hors ligne testées régulièrement (règle 3-2-1)
* Segmentation réseau et restriction des partages SMB/RDP exposés
* Plan de réponse ransomware testé par exercices table-top
* Journalisation centralisée (EDR, Active Directory, VPN) avec rétention suffisante
* Veille sur les affiliés et infrastructures des groupes ransomware

#### Phase 2 — Détection et analyse

* Alertes sur chiffrement en masse et suppression des shadow copies (vssadmin, wbadmin)
* Détection de l'exfiltration de données pré-chiffrement (double extorsion)
* Surveillance des comptes privilégiés et créations anormales de comptes
* Alertes sur les TTP et IOC historiques de Conti et des groupes dérivés

#### Phase 3 — Confinement, éradication et récupération

* Isolation immédiate des machines chiffrées ou suspectes
* Coupure des accès VPN et comptes compromis
* Blocage des domaines et IP C2 identifiés
* Préservation des preuves avant toute remédiation destructive

#### Phase 4 — Activités post-incident

* Évaluation de l'étendue du chiffrement et de l'exfiltration éventuelle
* Restauration depuis des sauvegardes vérifiées saines
* Notifications réglementaires si des données personnelles sont concernées
* Renforcement post-incident : MFA, patching, revue des accès

#### Phase 5 — Threat Hunting (proactif)

* Chasse sur les TTP Conti historiques (tooling de type Cobalt Strike, techniques de latéralisation)
* Recherche de comptes dormants ou créés pendant la période suspecte
* Analyse rétroactive des journaux avec les IOC récents du groupe
* Vérification de l'absence de résidus (webshells, tâches planifiées, services malveillants)

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1657** | Financial Theft - fraude électronique (wire fraud) commise dans le cadre des activités du groupe Conti |
| **T1486** | Data Encrypted for Impact - chiffrement de données à des fins d'extorsion, activité historique du groupe Conti |

---

### Sources

* [https://databreaches.net/2026/09/11/ukrainian-national-sentenced-to-four-years-in-prison-for-wire-fraud-conspiracy-in-connection-with-conti-ransomware/](https://databreaches.net/2026/09/11/ukrainian-national-sentenced-to-four-years-in-prison-for-wire-fraud-conspiracy-in-connection-with-conti-ransomware/)


---

<div id="fuite-mydr-en-pologne-environ-188-millions-de-personnes-et-plus-de-12-000-etablissements-medicaux-concernes"></div>

## Fuite MyDr en Pologne : environ 18,8 millions de personnes et plus de 12 000 établissements médicaux concernés

### Résumé

Selon un article de Prawo.pl relayé sur les réseaux, l'incident de sécurité touchant le logiciel MyDr (documentation médicale électronique, EDM) concerne environ 18,8 millions de personnes et plus de 12 000 établissements médicaux utilisateurs de la solution. Les données incluraient le PESEL (identifiant national polonais). Les procédures menées par les services compétents sont en cours et la société communique de manière lacunaire, entretenant un fort niveau d'incertitude. L'article pose également la question de savoir si un établissement peut conditionner la remise de données à la réalisation d'une visite après la fuite.

---

### Analyse opérationnelle

L'exposition massive de PESEL et de données médicales alimente mécaniquement le phishing, la fraude documentaire et l'usurpation d'identité en Pologne. Les établissements utilisant MyDr doivent appliquer les recommandations de l'éditeur, auditer leurs accès au logiciel, informer leurs patients et renforcer la vérification d'identité (la fuite du PESEL rend les contrôles basés sur ce seul identifiant obsolètes). Les DPO doivent préparer les obligations de notification RODO.

---

### Implications stratégiques

Il s'agit de l'une des plus grandes fuites de données de santé polonaises, avec un effet de type chaîne d'approvisionnement : un seul éditeur expose les données de milliers d'établissements. Les conséquences attendues incluent des sanctions RODO, une perte de confiance dans la numérisation du secteur médical et une pression réglementaire accrue sur les éditeurs de logiciels de santé. La question juridique soulevée (conditionner l'accès aux données à une visite) illustre les tensions opérationnelles post-fuite pour les praticiens.

---

### Recommandations

* Si utilisateur de MyDr : appliquer les correctifs et consignes de l'éditeur et auditer les accès
* Renforcer la vérification d'identité au-delà du PESEL (risque d'usurpation)
* Préparer les notifications RODO et la communication vers les patients
* Surveiller les campagnes de phishing exploitant la fuite

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les données patients traitées via les logiciels de documentation médicale électronique (EDM) tiers
* Définir les procédures RODO de notification en cas de violation
* Sensibiliser le personnel soignant au phishing et à l'usurpation d'identité post-fuite
* Vérifier les clauses de sécurité des contrats avec les éditeurs de logiciels médicaux

#### Phase 2 — Détection et analyse

* Surveiller les annonces de l'éditeur et les dépôts de données fuitées
* Détecter les campagnes de phishing exploitant la fuite MyDr (usurpation d'établissements, d'assureurs, du NFZ)
* Alerter sur les tentatives d'accès anormales aux systèmes EDM

#### Phase 3 — Confinement, éradication et récupération

* Appliquer les mesures correctives de l'éditeur (mots de passe, accès)
* Restreindre l'accès au logiciel aux seuls personnels autorisés
* Bloquer les domaines de phishing identifiés

#### Phase 4 — Activités post-incident

* Informer les patients conformément aux obligations RODO
* Documenter l'incident pour les autorités (UODO) et le NFZ le cas échéant
* Réviser les dépendances à l'éditeur et les exigences contractuelles

#### Phase 5 — Threat Hunting (proactif)

* Chasser les accès anormaux aux dossiers patients dans les journaux EDM
* Rechercher les courriels de phishing référençant MyDr ou la fuite
* Surveiller les fuites publiques pour des données propres à l'établissement

---

### Sources

* [https://fedihood.social/notes/suumngzxlyji5dvvvdxxfi9k](https://fedihood.social/notes/suumngzxlyji5dvvvdxxfi9k)
* [https://www.prawo.pl/zdrowie/czy-przychodnia-moze-uzaleznic-uzyskanie-danych-od-wizyty-w-placowce-po-wycieku-mydr,1552520.html](https://www.prawo.pl/zdrowie/czy-przychodnia-moze-uzaleznic-uzyskanie-danych-od-wizyty-w-placowce-po-wycieku-mydr,1552520.html)


---

<div id="signaux-faibles"></div>

# SIGNAUX FAIBLES

Sujets rapportés par une source unique — un post social sans lien vers un article externe — qu'aucune autre source du corpus ne corrobore. À traiter comme des pistes, non comme des faits établis.

---

<div id="des-pirates-ont-abuse-de-claude-pour-extraire-des-secrets-de-18-million-dapplications-android"></div>

## Des pirates ont abusé de Claude pour extraire des secrets de 1,8 million d'applications Android

### Résumé

Selon le rapport de threat intelligence publié par Anthropic en septembre 2026, des acteurs malveillants ont détourné l'usage du modèle de langage Claude afin d'extraire des secrets (identifiants, clés d'API) présents dans environ 1,8 million d'applications Android. Les indicateurs associés ont été extraits de rapports publics et diffusés via un pulse Open Threat Exchange (OTX) ; l'auteur du pulse signale que ces données sont non vérifiées et préliminaires.

---

### Analyse opérationnelle

Les équipes SOC/IT doivent traiter cette campagne comme un risque de fuite de secrets à très grande échelle : inventorier les applications mobiles internes et tierces, scanner dépôts Git, pipelines CI/CD et APK à la recherche de secrets en dur (clés d'API, jetons, identifiants), révoquer et faire pivoter tout secret exposé, et surveiller les usages anormaux des clés d'API (volumes, géolocalisations, horaires). Les indicateurs du pulse OTX doivent être vérifiés avant tout déploiement en production. Surveiller également les appels automatisés massifs aux API LLM depuis le SI.

---

### Implications stratégiques

Cette campagne illustre la weaponisation de l'IA commerciale : les modèles de langage réduisent drastiquement le coût et la durée d'opérations de reconnaissance à très grande échelle (balayage de millions d'applications). Pour les directions, cela impose une gouvernance stricte de l'usage des LLM (politiques, journalisation, contrôle des sorties) et une hygiène des secrets renforcée dans le SDLC. La tendance à l'abus d'outils IA légitimes par des acteurs malveillants devrait s'accentuer, brouillant la frontière entre usage légitime et malveillant et posant la question de la responsabilité des fournisseurs d'IA.

---

### Recommandations

* Scanner dépôts, artefacts de build et APK pour détecter les secrets en dur et les révoquer immédiatement
* Mettre en place un coffre-fort de secrets et interdire les identifiants codés en dur dans le SDLC
* Journaliser et surveiller les appels aux API de modèles de langage depuis le SI
* Vérifier puis intégrer les indicateurs du pulse OTX associé dans les outils de détection
* Sensibiliser les équipes de développement au risque d'extraction de secrets assistée par IA

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Établir un inventaire des applications mobiles internes, tierces et B2B manipulant des données sensibles
* Déployer des outils de détection de secrets (gitleaks, trufflehog) dans les dépôts de code et pipelines CI/CD
* Définir une politique de gestion des secrets : coffre-fort, rotation automatique, interdiction des secrets en dur
* Formaliser une politique d'usage des services d'IA générative en entreprise avec journalisation des appels
* Sensibiliser les équipes de développement au risque d'exposition de secrets dans les applications mobiles

#### Phase 2 — Détection et analyse

* Alerter sur les requêtes automatisées massives vers les API de modèles de langage depuis le SI
* Surveiller les dépôts et artefacts de build pour tout nouveau secret en dur détecté
* Corréler les usages anormaux de clés d'API (volumes, géolocalisations, horaires atypiques)
* Vérifier puis intégrer les indicateurs du pulse OTX associé dans les outils de détection
* Suivre les publications de threat intelligence concernant l'abus de modèles d'IA commerciaux

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement les secrets et clés d'API identifiés comme exposés
* Faire pivoter les identifiants des comptes de service concernés
* Bloquer ou restreindre l'accès aux services d'IA depuis les segments concernés
* Retirer ou mettre à jour les applications contenant des secrets exposés

#### Phase 4 — Activités post-incident

* Analyser les journaux d'utilisation des clés compromises pour identifier d'éventuels accès frauduleux
* Évaluer l'impact sur les données et systèmes accessibles via les secrets exposés
* Réaliser un retour d'expérience et mettre à jour les politiques SDLC et de gestion des secrets
* Documenter l'incident et partager les enseignements avec les équipes de développement

#### Phase 5 — Threat Hunting (proactif)

* Chasser les secrets en dur dans l'ensemble des dépôts de code, APK et artefacts de build
* Rechercher des connexions ou appels API inhabituels liés aux clés exposées
* Détecter les usages détournés de comptes de services d'IA (facturation anormale, requêtes en masse)
* Corréler les IOC vérifiés du pulse avec les journaux proxy, DNS et EDR historiques

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1552.001** | Unsecured Credentials: Credentials In Files - extraction de secrets (clés d'API, identifiants) stockés dans les fichiers d'applications Android, assistée par un modèle de langage |

---

### Sources

* [https://social.raytec.co/@techbot/117254425946053857](https://social.raytec.co/@techbot/117254425946053857)
* [https://www.anthropic.com/threat-intelligence-report-september-2026](https://www.anthropic.com/threat-intelligence-report-september-2026)
* [https://otx.alienvault.com/pulse/6aa46acb2b6819c462e4fdf7](https://otx.alienvault.com/pulse/6aa46acb2b6819c462e4fdf7)
