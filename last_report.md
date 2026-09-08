# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [Roundup sécurité Linux : plus de 100 CVEs noyau corrigées d'un coup pour Ubuntu, évasion de sandbox Minetest et integer underflow MiniUPnPd](#roundup-securite-linux-plus-de-100-cves-noyau-corrigees-dun-coup-pour-ubuntu-evasion-de-sandbox-minetest-et-integer-underflow-miniupnpd)
  * [Tendances CVE et conseil SBOM : panorama des vulnérabilités les plus consultées (CVEDatabase)](#tendances-cve-et-conseil-sbom-panorama-des-vulnerabilites-les-plus-consultees-cvedatabase)
  * [Exploitation active de deux failles MikroTik RouterOS récemment divulguées : détournement de routeurs via SSH exposé](#exploitation-active-de-deux-failles-mikrotik-routeros-recemment-divulguees-detournement-de-routeurs-via-ssh-expose)
  * [Liquid Network : environ 4 000 BTC retirés du portefeuille de fédération, 3 400 BTC restitués après correctif des bridge nodes](#liquid-network-environ-4-000-btc-retires-du-portefeuille-de-federation-3-400-btc-restitues-apres-correctif-des-bridge-nodes)
  * [Chameleon Ultra : guide de lecture, émulation et test de badges RFID/NFC — risque pour les contrôles d'accès physique](#chameleon-ultra-guide-de-lecture-emulation-et-test-de-badges-rfidnfc-risque-pour-les-controles-dacces-physique)
  * [LockBit5 revendique le cabinet d'avocats sud-africain vsbattorneys.co.za](#lockbit5-revendique-le-cabinet-davocats-sud-africain-vsbattorneyscoza)
  * [Qilin revendique Partners Group SK sur son site de fuite](#qilin-revendique-partners-group-sk-sur-son-site-de-fuite)
  * [BigBear 2.0 : le service de phishing-as-a-service contourne le MFA de 258 organisations et vole plus de 5 000 identifiants Microsoft 365](#bigbear-20-le-service-de-phishing-as-a-service-contourne-le-mfa-de-258-organisations-et-vole-plus-de-5-000-identifiants-microsoft-365)
  * [320 M$ en bitcoins drainés du Liquid Network ; les auteurs se revendiquent « les gentils »](#320-m-en-bitcoins-draines-du-liquid-network-les-auteurs-se-revendiquent-les-gentils)
  * [ShinyHunters : offre d'achat des données « Nexus DL » et menaces de publication visant le DMV de Floride](#shinyhunters-offre-dachat-des-donnees-nexus-dl-et-menaces-de-publication-visant-le-dmv-de-floride)
  * [La police ukrainienne démantèle un vaste réseau de fraude aux cryptomonnaies à Kyiv](#la-police-ukrainienne-demantele-un-vaste-reseau-de-fraude-aux-cryptomonnaies-a-kyiv)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

La veille du jour est dominée par le volume de vulnérabilités (46), traduisant une publication et une exploitation soutenues qui exigent une priorisation rigoureuse des correctifs selon le risque d'exploitation et la criticité des actifs. Les 17 fuites de données recensées confirment une pression persistante sur les données personnelles et corporatives, avec un risque élevé de réutilisation dans des campagnes d'hameçonnage ciblé et de fraude. L'activité attribuée aux acteurs de menace reste faible (1 publication), mais cette visibilité limitée ne préjuge pas d'une absence d'opérations, notamment dans un contexte géopolitique animé (2 publications) susceptible d'alimenter des campagnes à motivation étatique. Le volet réglementaire (3 publications) mérite une attention particulière, l'évolution des obligations (NIS2, DORA, RGPD) influençant directement les priorités de conformité et de remédiation. Les 11 articles analytiques fournissent un contexte d'interprétation utile pour anticiper les tendances à moyen terme. Recommandation : concentrer les efforts sur le triage des vulnérabilités à fort impact, le suivi des données exposées et l'ajustement des règles de détection en conséquence.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **ShinyHunters** |  |  | T1567, T1657 | [https://infosec.exchange/@AmmarSpaces/117232348269302471](https://infosec.exchange/@AmmarSpaces/117232348269302471)<br>[https://infosec.exchange/@PogoWasRight/117231818213330103](https://infosec.exchange/@PogoWasRight/117231818213330103) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Japon, Asie de l'Est** | Santé | Renforcement étatique de la cybersécurité hospitalière | Le ministère japonais de la Santé a annoncé le renforcement des mesures de cybersécurité dans les hôpitaux. Le contenu détaillé de l'article est inaccessible (page bloquée par Cloudflare), seule l'information du titre est exploitable. Cette initiative s'inscrit dans un contexte de menace accrue pesant sur le secteur de la santé, cible récurrente d'attaques (rançongiciels, compromissions de systèmes d'information hospitaliers) susceptibles d'affecter la continuité des soins et la protection des données patients. | [https://databreaches.net/2026/09/07/japans-health-ministry-to-strengthen-cybersecurity-measures-at-hospitals/](https://databreaches.net/2026/09/07/japans-health-ministry-to-strengthen-cybersecurity-measures-at-hospitals/) |
| **Monde, Moyen-Orient, Europe** | Énergie | Sécurité énergétique, polycrise et transition bas-carbone | L'IRIS publie, dans le cadre de l'Observatoire de la sécurité des flux et des matières énergétiques (OSFME, consortium IRIS-Cassini sous contrat avec la DGRIS du ministère des Armées), un rapport sur la sécurité énergétique. Il souligne que la guerre en Ukraine a favorisé une large restructuration des flux énergétiques mondiaux, notamment au profit des États-Unis, et que l'année 2026 constitue une rupture majeure avec le déclenchement de la guerre en Iran par les États-Unis et Israël. Le rapport analyse (1) l'évolution du concept de sécurité énergétique depuis les années 1970, incluant la question d'une gouvernance mondiale des marchés de l'énergie, (2) les réalités infrastructurelles et superstructurelles sous-jacentes (infrastructures, marchés, normes) et (3) les conséquences de la double dynamique transition bas-carbone / instabilité géopolitique croissante (polycrise) sur les systèmes énergétiques. | [https://www.iris-france.org/comprendre-la-securite-energetique-concepts-realites-physiques-transition-energetique-et-polycrise/](https://www.iris-france.org/comprendre-la-securite-energetique-concepts-realites-physiques-transition-energetique-et-polycrise/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| EDRi – « Why the EU age-verification tool does not solve privacy concerns » | Commission européenne (projet législatif) / EDRi (analyse critique de la société civile) | 2026-09-07 | Union européenne | EDRi – « Why the EU age-verification tool does not solve privacy concerns » | La Commission européenne annoncera, à l'occasion du discours sur l'état de l'Union (SOTEU), une proposition législative visant à interdire les réseaux sociaux aux mineurs, en s'appuyant sur l'application européenne de vérification d'âge présentée quelques mois plus tôt comme « techniquement prête ». En réalité, la Commission n'a publié qu'un « blueprint » (modèle de conception) surnommé « mini-wallet », dérivé du portefeuille d'identité numérique eID Wallet que chaque État membre doit fournir d'ici fin 2026, accompagné d'une application de démonstration. EDRi souligne plusieurs faiblesses structurelles : (1) la non-chaçabilité (unlinkability) n'est pas garantie — la Commission affaiblirait l'exigence légale de « garantir » la non-chaçabilité en la remplaçant par simple « entrave » ; (2) l'anonymat n'est pas assuré car la vérification d'âge repose sur un « trust anchor » (document d'identité étatique couplé au wallet via vérification biométrique faciale), excluant de fait les personnes sans papiers, sans smartphone compatible ou refusant la reconnaissance faciale, alors que des mécanismes cryptographiques de Zero Knowledge Proofs (ZKP) permettraient de prouver la majorité sans révéler d'identité ; (3) les spécifications techniques rendent les ZKP optionnelles (« SHOULD ») pour les applications de vérification et les fournisseurs de services, tandis que l'émission en lot d'attestations de preuve d'âge est obligatoire (« SHALL ») mais avec un horodatage ne « limitant » que partiellement la chaçabilité. Le dispositif n'impose donc pas les technologies les plus protectrices de la vie privée, alors que son déploiement s'accélère. | [https://edri.org/our-work/eu-age-verification-tool-does-not-solve-privacy-concerns/](https://edri.org/our-work/eu-age-verification-tool-does-not-solve-privacy-concerns/) |
| Commission européenne – Apply AI Summit (17 novembre 2026, Bruxelles et en ligne) | Commission européenne (DG Connect) – Vice-présidente exécutive Henna Virkkunen | 2026-09-07 | Union européenne | Commission européenne – Apply AI Summit (17 novembre 2026, Bruxelles et en ligne) | La Commission européenne organise l'Apply AI Summit le 17 novembre 2026 à Bruxelles (EGG) et en ligne, marquant le premier anniversaire de l'adoption de l'Apply AI Strategy, stratégie sectorielle transversale de l'UE pour l'intelligence artificielle, et concluant le premier Mois européen de l'innovation IA. L'événement réunira environ 900 parties prenantes sur site et jusqu'à 2 500 participants sur la plateforme virtuelle, autour de sessions thématiques sectorielles (santé, mobilité, énergie, administration publique, agroalimentaire, médias, défense, communications électroniques, industrie) et transversales (IA frontière, cybersécurité, sûreté de l'IA, souveraineté technologique, main-d'œuvre). Une session est spécifiquement consacrée à l'articulation entre l'AI Act et l'innovation, indiquant que la mise en œuvre réglementaire du règlement européen sur l'IA restera un axe central de la stratégie. La première édition de l'Apply AI Startup Award récompensera des startups européennes. Les inscriptions sont ouvertes jusqu'au 13 novembre 2026. Cet événement, bien que non normatif en soi, est un signal fort de la trajectoire réglementaire et industrielle européenne en matière d'IA de confiance et d'« IA Continent ». | [https://digital-strategy.ec.europa.eu/en/events/apply-ai-summit](https://digital-strategy.ec.europa.eu/en/events/apply-ai-summit) |
| Grindr — règlement de 26 M£ dans le cadre d'une action collective britannique (cabinet Austen Hays, High Court of England and Wales) | High Court of England and Wales (Haute Cour d'Angleterre et du Pays de Galles) ; contexte : autorité norvégienne de protection des données (Datatilsynet) et panel américain de sécurité nationale (CFIUS) | 2026-09-07 | Royaume-Uni (Angleterre et Pays de Galles) | Grindr — règlement de 26 M£ dans le cadre d'une action collective britannique (cabinet Austen Hays, High Court of England and Wales) | Grindr, application de rencontres américaine, versera 26 millions de livres sterling pour mettre fin à une action collective déposée en avril 2024 devant la High Court par le cabinet londonien Austen Hays au nom d'environ 12 000 utilisateurs britanniques. Les plaignants alléguaient que l'application avait partagé des données personnelles hautement sensibles — dont, dans certains cas, le statut VIH — avec des régies publicitaires, en violation de la législation britannique sur la protection des données, sur une période allant jusqu'à début 2020, alors que Grindr était détenue par le groupe chinois Beijing Kunlun Tech. Si le montant est réparti équitablement, chaque requérant percevra environ 2 167 £. Le règlement, qui ne comporte aucune reconnaissance de responsabilité, prévoit un paiement de 13 M£ d'ici fin 2026 et 13 M£ supplémentaires d'ici fin mars 2027. Cette décision s'inscrit dans une série d'épisodes réglementaires : révélation en 2018 du partage du statut VIH avec des tiers suite aux travaux de chercheurs norvégiens, amende de 4,8 M£ (65 M NOK, 10 % du chiffre d'affaires mondial) infligée par la Norvège en 2021 et confirmée en appel en octobre 2025, et cession forcée de Grindr en 2020 après des inquiétudes d'un panel américain de sécurité nationale concernant l'accès possible du gouvernement chinois aux données des utilisateurs américains. L'affaire illustre le risque juridique et financier majeur lié au traitement des catégories particulières de données (santé, orientation sexuelle) et la montée des actions collectives en matière de vie privée au Royaume-Uni. | [https://www.theguardian.com/business/2026/sep/07/grindr-settle-uk-lawsuit-dating-app-ad](https://www.theguardian.com/business/2026/sep/07/grindr-settle-uk-lawsuit-dating-app-ad)<br>[https://mstdn.moimeme.ca/@EdwinG/117231701556085855](https://mstdn.moimeme.ca/@EdwinG/117231701556085855) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Médias / Presse et édition** | Condé Nast | 32 815 767 adresses e-mail uniques ; pour des portions de la population : noms et prénoms (31,6 % des enregistrements), adresses postales (22,3 %), genre (17,5 %), dates de naissance (12,6 %) et numéros de téléphone (2,9 %). Aucun mot de passe, hash de mot de passe, identifiant ni donnée de carte de paiement n'est inclus. | 32815767 | [https://securityaffairs.com/198628/data-breach/conde-nast-data-of-32-8-million-users-offered-for-sale-after-wired-leak.html](https://securityaffairs.com/198628/data-breach/conde-nast-data-of-32-8-million-users-offered-for-sale-after-wired-leak.html) |
| **Secteur public / Administration gouvernementale (ville-État de Berlin)** | Administration de la ville-État de Berlin (Allemagne) | Données personnelles (12 076 personnes, 16 389 e-mails, 11 963 numéros de téléphone, 148 IBAN) ; plus de 5 000 dossiers de personnel et plus de 5 000 dossiers d'infractions administratives ; données de paie et informations sur l'encadrement ; mots de passe en clair et identifiants (GebäudAtlas, ePayment PAYONE, comptes Z_ADMIN) ; procédures disciplinaires, affaires judiciaires, documents de tutelle, accords de confidentialité (NDA) et protocoles de commissions du Bundesrat ; données relatives à la manipulation d'informations classifiées et documents contenant présumément des secrets d'État ; analyses de vulnérabilités de l'approvisionnement en eau de Berlin ; passeports et cartes d'identité issus des dossiers de personnel ; contrats, documents financiers, dossiers RH, données de santé, coffres-forts de mots de passe et archives SQL/PST. | 5,79 To (~1,44 million de fichiers) | [https://securityaffairs.com/198545/cyber-crime/berlin-ransomware-leak-exposes-state-secrets.html](https://securityaffairs.com/198545/cyber-crime/berlin-ransomware-leak-exposes-state-secrets.html) |
| **Secteur public / Transport et immatriculation (permis de conduire)** | Florida Department of Motor Vehicles (DMV de Floride, États-Unis) | Dossiers de permis de conduire et enregistrements associés du DMV de Floride, dont le permis de conduire et les dossiers de Jeffrey Epstein publiés comme preuve de compromission. Périmètre complet non confirmé. | Inconnu | [https://infosec.exchange/@AmmarSpaces/117232348269302471](https://infosec.exchange/@AmmarSpaces/117232348269302471) |
| **Architecture / Services professionnels (BTP et construction)** | MEI Architects (avec autres victimes revendiquées par le même groupe : Alurwalls, Master Manufacturing Co., Pump Engineering Company, Furnished Quarters, Design-Aire Engineering, Jones Little & Co. CPAs, cabinet dentaire de New Britain CT) | Numéros de sécurité sociale, passeports, green cards, factures, documents RH et plans architecturaux (projets passés, en cours et en construction) pour MEI Architects. Pour les autres victimes revendiquées : bases de données SQL avec données personnelles, plans techniques et schémas de pièces métalliques (Master Manufacturing), documents bancaires et financiers, plans de bâtiments clients, dossiers clients, assurances, dossiers comptables et données personnelles d'employés. | 340 Go (~130 000 fichiers) | [https://www.ransomlook.io//group/dark%20project](https://www.ransomlook.io//group/dark%20project) |
| **Éducation (enseignement public K-12, Massachusetts, États-Unis)** | Springfield Public Schools (Massachusetts, États-Unis) | Non déterminé à ce stade - l'étendue de la compromission est en cours d'évaluation par des enquêteurs. Données potentiellement à risque : dossiers des élèves et du personnel (données protégées par FERPA). | Inconnu | [https://databreaches.net/2026/09/07/ma-springfield-public-schools-will-be-closed-tuesday-after-a-cyber-incident/](https://databreaches.net/2026/09/07/ma-springfield-public-schools-will-be-closed-tuesday-after-a-cyber-incident/)<br>[https://www.wwlp.com/news/local-news/hampden-county/cyber-breach-investigation-closes-springfield-schools-tuesday/](https://www.wwlp.com/news/local-news/hampden-county/cyber-breach-investigation-closes-springfield-schools-tuesday/) |
| **Éducation / EdTech** | Mathspace | Données téléchargées : identifiant utilisateur et nom d'utilisateur, prénom et nom, adresse e-mail, pays et fuseau horaire, type d'utilisateur, statut de confirmation de l'e-mail, date de dernière activité, date de dernière connexion, date de création du compte. Non affectés : mots de passe, identifiants de connexion, dossiers académiques, activités d'apprentissage, notes et évaluations. Les fichiers téléchargés ne contenaient pas de lien entre les comptes et les écoles, mais certains e-mails contenant des noms d'écoles et des informations associées auraient pu être interceptés. | 1079819 | [https://databreaches.net/2026/09/07/mathspace-breach-impacts-more-than-1-million-users-in-australia-nz/](https://databreaches.net/2026/09/07/mathspace-breach-impacts-more-than-1-million-users-in-australia-nz/)<br>[https://en.hacks.gr/perissoteroi-apo-ena-ekatommyrio-christes-tis-mathspace-epireastikan-apo-mi-exoysiodotimeni-prosvasi/](https://en.hacks.gr/perissoteroi-apo-ena-ekatommyrio-christes-tis-mathspace-epireastikan-apo-mi-exoysiodotimeni-prosvasi/)<br>[https://www.bleepingcomputer.com/news/security/mathspace-discloses-data-breach-affecting-over-1-million-people/](https://www.bleepingcomputer.com/news/security/mathspace-discloses-data-breach-affecting-over-1-million-people/)<br>`hxxps://osintsights[.]com/mathspace-breach-exposes-data-of-1-million-people`<br>`hxxps://beyondmachines[.]net/event_details/mathspace-data-breach-impacts-over-1-million-users-in-australia-and-new-zealand-y-1-w-d-f/gD2P6Ple2L` |
| **Santé / Esthétique (plateforme de mise en relation avec des cliniques de chirurgie esthétique, Corée du Sud)** | Gangnam Unni | Données personnelles d'environ 220 000 utilisateurs nationaux et internationaux (détail des champs non précisé dans la source accessible) ; exposition potentielle de données sensibles liées à la santé/esthétique à confirmer. | 220000 | [https://databreaches.net/2026/09/07/personal-data-of-approximately-220000-domestic-and-international-gangnam-unni-users-leaked/](https://databreaches.net/2026/09/07/personal-data-of-approximately-220000-domestic-and-international-gangnam-unni-users-leaked/) |
| **Divertissement / Plateforme de fans K-Pop** | Weverse (HYBE) | Données de plus de 422 000 comptes de fans K-Pop (détail des champs non précisé dans la source accessible). | 422000 | [https://databreaches.net/2026/09/07/weverse-data-leak-affects-more-than-422000-k-pop-fan-accounts/](https://databreaches.net/2026/09/07/weverse-data-leak-affects-more-than-422000-k-pop-fan-accounts/) |
| **Gouvernement / État civil (Indonésie)** | DUKCAPIL (Direktorat Jenderal Kependudukan dan Pencatatan Sipil, Indonésie) | Base de données revendiquée de 1,5 Go liée au système d'état civil et d'enregistrement de la population indonésien (DUKCAPIL) ; contenu exact et authenticité non vérifiés à ce stade. | Inconnu | [https://go.darkwebsonar.io/divaccx-mastodon](https://go.darkwebsonar.io/divaccx-mastodon) |
| **Crypto-monnaies / Matériel (hardware wallet) / Logistique tierce** | Trezor | Exposition complète pour 11 742 clients : nom complet, adresse e-mail, numéro de téléphone, adresse d'expédition, numéro de commande. Exposition partielle pour 1 947 clients : nom, ville, adresse e-mail. Données de commandes antérieures (novembre 2019 - août 2021) d'environ 67 000 clients américains supplémentaires : nom, e-mail, téléphone, adresse d'expédition, numéro de commande. Aucune donnée liée aux dispositifs ou wallets (seed phrases) n'est affectée. | 81000 | [https://trezor.io/blog/news/recent-customer-data-exposed-in-shipping-provider-incident](https://trezor.io/blog/news/recent-customer-data-exposed-in-shipping-provider-incident)<br>`hxxps://osintsights[.]com/trezor-breach-expands-to-81000-customers-after-data-leak` |
| **Multisectoriel (analyse transverse sur des entreprises victimes de fuites)** | 516 entreprises victimes de fuites de données (analyse agrégée XposedOrNot) | Mots de passe issus de 516 fuites de données : 83 en clair, 206 fissurables en quelques heures, 153 stockés selon des pratiques robustes. | Inconnu | `hxxps://blog[.]xposedornot[.]com/password-storage-analysis-2026/` |
| **Santé / esthétique médicale (plateforme e-health sud-coréenne)** | Healing Paper (plateforme Gangnam Unni) | Noms complets, numéros de téléphone, adresses e-mail, dates de naissance, genre, pays ou région de résidence, identifiants de connexion aux réseaux sociaux, adresses IP et informations sur les appareils, photos et détails de consultation, informations de traitement et dates de procédures, informations sur les cliniques et praticiens, informations liées aux paiements. | 219665 | `hxxps://beyondmachines[.]net/event_details/healing-paper-data-breach-exposes-medical-data-of-220000-gangnam-unni-users-n-o-w-b-2/gD2P6Ple2L` |
| **Vérification d'identité / KYC (identité numérique)** | IDScan | Données de permis de conduire (documents et informations d'identité) - plus de 153 millions selon les plaignants, proposées à la vente par des hackers. | 153000000 | `hxxps://www[.]bleepingcomputer[.]com/news/security/idscan-sued-over-alleged-data-breach-affecting-153-million-drivers/` |
| **Secteur public / environnement (organisme gouvernemental gallois)** | Natural Resources Wales (NRW) | Données de diversité sensibles des employés (données RH protégées). | Inconnu | `hxxps://gbhackers[.]com/natural-resources-wales-data-breach/` |
| **Multisectoriel, avec prédominance du secteur public (56 % des enregistrements exposés)** | Multiples organisations (164 fuites de bases de données suivies par F6) | Bases de données variées totalisant plus de 600 millions d'enregistrements, dont 56 % de données gouvernementales, diffusées sur des forums underground et Telegram. | 600000000 | `hxxps://hackread[.]com/f6-threat-report-records-database-leaks/` |
| **Santé / Assurance maladie (Medi-Cal, Californie du Nord)** | Partnership HealthPlan of California (PHC) | Noms complets, dates de naissance et numéros d'identification membre. Aucun numéro de sécurité sociale, numéro de permis de conduire, information bancaire ni dossier médical (traitements, diagnostics) n'a été exposé. | 1526 | [https://beyondmachines.net/event_details/partnership-healthplan-of-california-reports-data-breach-affecting-1500-members-i-9-l-p-o/gD2P6Ple2L](https://beyondmachines.net/event_details/partnership-healthplan-of-california-reports-data-breach-affecting-1500-members-i-9-l-p-o/gD2P6Ple2L) |
| **Secteur public / Administration fiscale (France)** | Direction générale des Finances publiques (DGFiP) | Données fiscales, coordonnées et certains renseignements cadastraux concernant 678 000 particuliers et professionnels. Les espaces personnels des contribuables n'ont pas été compromis. | 678000 | [https://www.datasecuritybreach.fr/pentest-audit-de-securite-soc-quels-controles-auraient-pu-detecter-une-attaque-comme-celle-de-la-dgfip/](https://www.datasecuritybreach.fr/pentest-audit-de-securite-soc-quels-controles-auraient-pu-detecter-une-attaque-comme-celle-de-la-dgfip/) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-86544** | 8.1 | N/A | FALSE | knowns (projet knowns-dev) versions antérieures à 0.30.0 | Contournement d'autorisation (CWE-863 : Incorrect Authorization) | Escalade de privilèges sur l'instance knowns : un utilisateur à privilèges restreints peut modifier la politique de permissions et obtenir des capacités d'écriture/modification de code non autorisées lors des appels ultérieurs. | Theoretical | Mettre à jour knowns vers la version 0.30.0 ou ultérieure ; revoir et restreindre les actions de modification de code ; surveiller les escalades de privilèges non autorisées ; appliquer les correctifs éditeur pour les versions affectées. | [https://cvefeed.io/vuln/detail/CVE-2026-86544](https://cvefeed.io/vuln/detail/CVE-2026-86544)<br>[https://www.vulncheck.com/advisories/knowns-before-0.30.0-authorization-bypass-via-misclassified-code-actions](https://www.vulncheck.com/advisories/knowns-before-0.30.0-authorization-bypass-via-misclassified-code-actions)<br>[https://github.com/knowns-dev/knowns/security/advisories/GHSA-w323-3wpx-f7g5](https://github.com/knowns-dev/knowns/security/advisories/GHSA-w323-3wpx-f7g5) |
| **CVE-2026-86543** | 9.8 | N/A | FALSE | knowns (projet knowns-dev) versions antérieures à 0.30.0 | Exposition d'API de gestion sans authentification (CWE-306 : Missing Authentication for Critical Function) | Prise de contrôle potentielle de l'instance : exposition complète de l'API de gestion, création de tunnels publics exposant l'API à Internet et permettant des manipulations ultérieures (CAPEC-12, CAPEC-36, CAPEC-62, CAPEC-166, CAPEC-216). | Theoretical | Mettre à jour vers la version 0.30.0 ou ultérieure ; imposer l'authentification sur l'API de gestion ; restreindre l'accès réseau aux interfaces essentielles uniquement ; revoir les paramètres d'installation par défaut. | [https://cvefeed.io/vuln/detail/CVE-2026-86543](https://cvefeed.io/vuln/detail/CVE-2026-86543)<br>[https://www.vulncheck.com/advisories/knowns-before-0.30.0-unauthenticated-management-api-exposure](https://www.vulncheck.com/advisories/knowns-before-0.30.0-unauthenticated-management-api-exposure)<br>[https://github.com/knowns-dev/knowns/security/advisories/GHSA-fc85-99vc-9c75](https://github.com/knowns-dev/knowns/security/advisories/GHSA-fc85-99vc-9c75) |
| **CVE-2026-86542** | 9.1 | N/A | FALSE | knowns (projet knowns-dev) versions antérieures à 0.30.0 | Traversée de répertoires (CWE-22 : Path Traversal) avec écriture arbitraire de fichiers | Écrasement de fichiers arbitraires pouvant conduire à une exécution de code, une persistance ou un déni de service selon les fichiers ciblés (CAPEC-64, CAPEC-76, CAPEC-78, CAPEC-79, CAPEC-126). | Theoretical | Mettre à jour vers la version 0.30.0 ou ultérieure ; valider tous les noms d'import ; restreindre l'accès en écriture aux fichiers critiques ; surveiller le système de fichiers pour détecter les modifications suspectes. | [https://cvefeed.io/vuln/detail/CVE-2026-86542](https://cvefeed.io/vuln/detail/CVE-2026-86542)<br>[https://www.vulncheck.com/advisories/knowns-before-0.30.0-path-traversal-via-import-name](https://www.vulncheck.com/advisories/knowns-before-0.30.0-path-traversal-via-import-name)<br>[https://github.com/knowns-dev/knowns/security/advisories/GHSA-wh3c-v55g-qfg8](https://github.com/knowns-dev/knowns/security/advisories/GHSA-wh3c-v55g-qfg8) |
| **CVE-2026-86541** | 8.3 | N/A | FALSE | knowns (projet knowns-dev) versions antérieures à 0.30.0 | Traversée de répertoires (CWE-22 : Path Traversal) via l'action MCP code.replace | Écrasement de fichiers arbitraires permettant potentiellement l'exécution de code à la prochaine ouverture de session shell, la persistance ou la compromission de l'accès SSH (CAPEC-64, CAPEC-76, CAPEC-78, CAPEC-79, CAPEC-126). | Theoretical | Mettre à jour vers la version 0.30.0 ou ultérieure ; valider les permissions et la propriété des fichiers ; revoir les fichiers écrasés pour détecter un contenu malveillant ; implémenter une validation des chemins de fichiers. | [https://cvefeed.io/vuln/detail/CVE-2026-86541](https://cvefeed.io/vuln/detail/CVE-2026-86541)<br>[https://www.vulncheck.com/advisories/knowns-before-0.30.0-path-traversal-via-code-replace-mcp-action](https://www.vulncheck.com/advisories/knowns-before-0.30.0-path-traversal-via-code-replace-mcp-action)<br>[https://github.com/knowns-dev/knowns/security/advisories/GHSA-f539-xgc6-xw7q](https://github.com/knowns-dev/knowns/security/advisories/GHSA-f539-xgc6-xw7q) |
| **CVE-2026-86540** | 8.5 | N/A | FALSE | knowns (projet knowns-dev) versions antérieures à 0.30.0 | Exécution de code arbitraire (CWE-78 : OS Command Injection) via le champ binaire LSP non validé | Exécution de code arbitraire sous le compte de l'utilisateur à l'ouverture d'un dépôt malveillant, pouvant mener à une compromission complète du poste de travail (CAPEC-6, CAPEC-15, CAPEC-43, CAPEC-88). | Theoretical | Mettre à jour vers la version 0.30.0 ou ultérieure ; valider tous les fichiers de configuration de projet ; revoir les chemins d'exécution des binaires ; supprimer les fichiers de configuration malveillants. | [https://cvefeed.io/vuln/detail/CVE-2026-86540](https://cvefeed.io/vuln/detail/CVE-2026-86540)<br>[https://www.vulncheck.com/advisories/knowns-before-0.30.0-arbitrary-code-execution-via-lsp-binary](https://www.vulncheck.com/advisories/knowns-before-0.30.0-arbitrary-code-execution-via-lsp-binary)<br>[https://github.com/knowns-dev/knowns/security/advisories/GHSA-mc52-mwq4-vfx3](https://github.com/knowns-dev/knowns/security/advisories/GHSA-mc52-mwq4-vfx3) |
| **CVE-2026-86538** | 8.7 | N/A | FALSE | knowns (projet knowns-dev) versions antérieures à 0.30.0 | Traversée de répertoires (CWE-22 : Path Traversal) avec lecture arbitraire de fichiers | Divulgation d'informations sensibles : lecture de fichiers d'identifiants, de clés et de configurations accessibles par le processus serveur (CAPEC-64, CAPEC-76, CAPEC-78, CAPEC-79, CAPEC-126). | Theoretical | Mettre à jour vers la version 0.30.0 ou ultérieure ; restreindre l'accès à l'endpoint /api/templates/preview ; valider toutes les entrées utilisateur pour les composants de chemin ; appliquer immédiatement les correctifs éditeur. | [https://cvefeed.io/vuln/detail/CVE-2026-86538](https://cvefeed.io/vuln/detail/CVE-2026-86538)<br>[https://www.vulncheck.com/advisories/knowns-before-0.30.0-path-traversal-via-templatefile-parameter](https://www.vulncheck.com/advisories/knowns-before-0.30.0-path-traversal-via-templatefile-parameter)<br>[https://github.com/knowns-dev/knowns/security/advisories/GHSA-fpxv-c555-rhm3](https://github.com/knowns-dev/knowns/security/advisories/GHSA-fpxv-c555-rhm3) |
| **CVE-2026-86439** | 8.8 | N/A | FALSE | knowns (projet knowns-dev) versions antérieures à 0.30.0 | Traversée de répertoires (CWE-22 : Path Traversal) via les outils MCP doc et memory | Compromission de l'intégrité et de la confidentialité des données : lecture, altération et suppression de fichiers arbitraires accessibles par le serveur (CAPEC-64, CAPEC-76, CAPEC-78, CAPEC-79, CAPEC-126). | Theoretical | Mettre à jour l'outil MCP vers la version 0.30.0 ou ultérieure ; valider toutes les entrées de chemin de fichiers ; restreindre l'accès aux fichiers sensibles ; appliquer immédiatement les correctifs éditeur. | [https://cvefeed.io/vuln/detail/CVE-2026-86439](https://cvefeed.io/vuln/detail/CVE-2026-86439)<br>[https://www.vulncheck.com/advisories/knowns-before-0.30.0-path-traversal-via-mcp-doc-and-memory-tools](https://www.vulncheck.com/advisories/knowns-before-0.30.0-path-traversal-via-mcp-doc-and-memory-tools)<br>[https://github.com/knowns-dev/knowns/security/advisories/GHSA-9gfj-28hw-jchp](https://github.com/knowns-dev/knowns/security/advisories/GHSA-9gfj-28hw-jchp) |
| **CVE-2026-86502** | 8.4 | N/A | FALSE | JetBrains IntelliJ IDEA (toutes versions antérieures à 2026.2.2) | Exécution de code locale à distance de développement - absence d'authentification pour une fonction critique (CWE-306) | Exécution de code arbitraire sur les hôtes de développement à distance, avec impact élevé sur la confidentialité, l'intégrité et la disponibilité. Compromission potentielle du code source et des environnements de développement. | None | Mettre à jour IntelliJ IDEA vers la version 2026.2.2 ou ultérieure (consultez hxxps://www.jetbrains[.]com/privacy-security/issues-fixed/), activer TLS sur le serveur gRPC IJent et configurer une authentification forte. | [https://cvefeed.io/vuln/detail/CVE-2026-86502](https://cvefeed.io/vuln/detail/CVE-2026-86502) |
| **CVE-2026-86492** | 8.5 | N/A | FALSE | JetBrains YouTrack (toutes versions antérieures à 2026.2.18634) | Fuite de tokens inter-tenants - exposition d'un élément de données à la mauvaise session (CWE-488) | Vol de tokens d'installation GitHub App entre tenants, permettant un accès non autorisé aux dépôts et ressources GitHub des organisations clientes, avec risque de compromission en chaîne de l'écosystème GitHub. | None | Mettre à jour YouTrack vers la version 2026.2.18634 ou ultérieure, revoir la configuration du cache de tokens, invalider et régénérer les tokens GitHub App affectés. | [https://cvefeed.io/vuln/detail/CVE-2026-86492](https://cvefeed.io/vuln/detail/CVE-2026-86492) |
| **CVE-2026-86482** | 8.8 | N/A | FALSE | JetBrains YouTrack (toutes versions antérieures à 2026.2.18634) | Élévation de privilèges via modification de l'appartenance aux groupes - attribution de privilèges incorrecte (CWE-266) | Élévation de privilèges au sein de YouTrack permettant à un utilisateur malveillant d'obtenir des droits administratifs, de manipuler les projets, les utilisateurs et les données du système de suivi. | None | Mettre à jour YouTrack vers la version 2026.2.18634 ou ultérieure et vérifier que les modifications d'appartenance aux groupes sont correctement autorisées et journalisées. | [https://cvefeed.io/vuln/detail/CVE-2026-86482](https://cvefeed.io/vuln/detail/CVE-2026-86482) |
| **CVE-2026-86480** | 9.8 | N/A | FALSE | JetBrains Hub (toutes versions antérieures à 2026.2.52442) | Autorisation incorrecte - absence d'authentification pour une fonction critique (CWE-306) | Prise de contrôle totale de l'instance Hub par un attaquant non authentifié : obtention de privilèges superuser, accès à l'ensemble des utilisateurs, services et intégrations gérés par Hub, avec risque de compromission en chaîne des produits JetBrains connectés. | None | Mettre à jour JetBrains Hub vers la version 2026.2.52442 ou ultérieure et vérifier le processus d'enregistrement des services (restreindre l'accès réseau et auditer les services de confiance existants). | [https://cvefeed.io/vuln/detail/CVE-2026-86480](https://cvefeed.io/vuln/detail/CVE-2026-86480) |
| **CVE-2026-86479** | 8.1 | N/A | FALSE | JetBrains YouTrack (versions antérieures à 2026.2.18788, 2026.1.14055 et 2025.3.161254) | Référence directe d'objet non sécurisée (IDOR) - absence d'autorisation (CWE-862) | Accès non autorisé à des ressources et données restreintes de YouTrack via l'API REST, avec impact élevé sur la confidentialité et l'intégrité (modification potentielle d'objets accessibles). | None | Mettre à jour YouTrack vers la version 2026.2.18788 ou ultérieure, ou appliquer les versions 2026.1.14055 / 2025.3.161254 pour les branches concernées. | [https://cvefeed.io/vuln/detail/CVE-2026-86479](https://cvefeed.io/vuln/detail/CVE-2026-86479) |
| **CVE-2026-86478** | 9.8 | N/A | FALSE | JetBrains YouTrack Helpdesk (versions antérieures à 2025.3.161254 et 2026.1.14042) | Prise de contrôle de compte non authentifiée - contournement d'authentification par usurpation (CWE-290) | Prise de contrôle de comptes YouTrack Helpdesk par des acteurs non authentifiés, donnant accès aux tickets, données clients et potentiellement à des fonctionnalités sensibles selon le rôle du compte compromis. | None | Mettre à jour YouTrack vers la version 2025.3.161254 ou 2026.1.14042 ou ultérieure, imposer la vérification des emails et réinitialiser les identifiants des comptes potentiellement affectés. | [https://cvefeed.io/vuln/detail/CVE-2026-86478](https://cvefeed.io/vuln/detail/CVE-2026-86478) |
| **CVE-2026-86438** | 8.6 | N/A | FALSE | Lara Dashboard (toutes versions antérieures à 1.3.2) | Absence d'autorisation sur l'action Livewire d'installation de modules - conduisant à une exécution de code à distance (CWE-862) | Exécution de code à distance sur le serveur hébergeant Lara Dashboard par un administrateur à privilèges intermédiaires, avec accès aux secrets d'environnement et aux identifiants de base de données, risque de compromission complète du serveur. | None | Mettre à jour Lara Dashboard vers la version 1.3.2 ou ultérieure, vérifier les rôles et permissions des administrateurs, restreindre l'installation de modules aux sources de confiance. | [https://cvefeed.io/vuln/detail/CVE-2026-86438](https://cvefeed.io/vuln/detail/CVE-2026-86438) |
| **CVE-2026-86437** | 8.6 | N/A | FALSE | Lara Dashboard (toutes versions antérieures à 1.3.2) | Autorisation incorrecte sur l'upload d'archive de mise à niveau du core - conduisant à une exécution de code à distance (CWE-863) | Exécution de code à distance avec les privilèges de l'utilisateur du serveur web, exposition des secrets d'environnement et des identifiants de base de données, compromission complète de l'application et potentiellement du serveur hôte. | None | Mettre à jour Lara Dashboard vers la version 1.3.2 ou ultérieure, vérifier que seuls les Superadmins peuvent accéder à l'endpoint d'upload, restreindre l'accès aux fonctions d'administration sensibles. | [https://cvefeed.io/vuln/detail/CVE-2026-86437](https://cvefeed.io/vuln/detail/CVE-2026-86437) |
| **CVE-2026-86218** | 10.0 | N/A | FALSE | N-able N-central (plateforme RMM), toutes les builds on-premises antérieures à 2026.3.1.14 (Hotfix 4) ; les instances hébergées NCOD sont déjà corrigées | Exécution de code à distance pré-authentification (injection de code statique, CWE-96) | Compromission totale du serveur RMM sans aucune authentification, offrant un point de pivot vers l'ensemble des systèmes clients gérés par les MSP ; risque d'attaques en chaîne à grande échelle (déploiement de ransomware, vol de credentials, persistance). N-central est une cible récurrente : CISA recense quatre autres vulnérabilités du produit déjà utilisées lors d'attaques. | Active | Mettre à jour immédiatement vers 2026.3.1.14 (Hotfix 4) ; les agents n'ont pas besoin d'être mis à jour. Restreindre l'accès entrant à la console (allowlist IP ou VPN) et envisager de déconnecter d'Internet les serveurs encore exposés jusqu'à application du correctif. Auditer les comptes utilisateurs N-central à la recherche d'utilisateurs inattendus. Aucun IOC ni mitigation intermédiaire n'a été publié par l'éditeur à ce stade. | [https://thehackernews.com/2026/09/weekly-recap-chrome-0-day-router.html](https://thehackernews.com/2026/09/weekly-recap-chrome-0-day-router.html)<br>[https://www.security.nl/posting/951967/N-able+waarschuwt+voor+misbruik+van+kritiek+lek+in+N-central+RMM-servers?channel=rss](https://www.security.nl/posting/951967/N-able+waarschuwt+voor+misbruik+van+kritiek+lek+in+N-central+RMM-servers?channel=rss)<br>[https://thehackernews.com/2026/09/n-able-issues-fourth-n-central-hotfix.html](https://thehackernews.com/2026/09/n-able-issues-fourth-n-central-hotfix.html) |
| **CVE-2026-86206** | N/A | N/A | FALSE | N-able N-central (plateforme RMM), builds antérieures au hotfix 3 (2026.3.1.13) publié le 5 septembre 2026 | Contournement des contrôles d'authentification (authentication bypass) | Accès non autorisé complet à la console N-central : un attaquant peut administrer à distance l'ensemble des systèmes clients gérés par les MSP, déployer des agents malveillants, exécuter des commandes et voler des credentials à grande échelle. | Active | Appliquer immédiatement le hotfix N-able (build 2026.3.1.13 ou supérieure), restreindre l'accès entrant à la console (allowlist IP ou VPN), auditer les comptes utilisateurs et les journaux pour détecter tout usage abusif, et vérifier les actions exécutées via le RMM sur les machines clientes. | [https://thehackernews.com/2026/09/weekly-recap-chrome-0-day-router.html](https://thehackernews.com/2026/09/weekly-recap-chrome-0-day-router.html)<br>[https://www.security.nl/posting/951967/N-able+waarschuwt+voor+misbruik+van+kritiek+lek+in+N-central+RMM-servers?channel=rss](https://www.security.nl/posting/951967/N-able+waarschuwt+voor+misbruik+van+kritiek+lek+in+N-central+RMM-servers?channel=rss) |
| **CVE-2026-86207** | N/A | N/A | FALSE | N-able N-central (plateforme RMM), builds antérieures au hotfix 3 (2026.3.1.13) publié le 5 septembre 2026 | Contournement des contrôles d'authentification (authentication bypass) | Accès non autorisé complet à la console N-central : compromission possible de l'ensemble des systèmes clients gérés par les MSP, avec exécution de commandes à distance, déploiement d'agents malveillants et vol de credentials à grande échelle. | Active | Appliquer immédiatement le hotfix N-able (build 2026.3.1.13 ou supérieure), restreindre l'accès entrant à la console (allowlist IP ou VPN), auditer les comptes utilisateurs et les journaux pour détecter tout usage abusif, et vérifier les actions exécutées via le RMM sur les machines clientes. | [https://thehackernews.com/2026/09/weekly-recap-chrome-0-day-router.html](https://thehackernews.com/2026/09/weekly-recap-chrome-0-day-router.html)<br>[https://www.security.nl/posting/951967/N-able+waarschuwt+voor+misbruik+van+kritiek+lek+in+N-central+RMM-servers?channel=rss](https://www.security.nl/posting/951967/N-able+waarschuwt+voor+misbruik+van+kritiek+lek+in+N-central+RMM-servers?channel=rss) |
| **CVE-2026-85046** | 8.8 | N/A | FALSE | Google Chrome (moteur JavaScript/WebAssembly V8) ; les navigateurs basés sur Chromium (Microsoft Edge, Brave, Opera) sont potentiellement concernés | Confusion de types (type confusion) dans le moteur V8, conduisant à une exécution de code à distance | Exécution de code à distance sur le poste de travail par la simple visite d'une page web malveillante : compromission de l'endpoint, vol de credentials et de sessions, pivot vers le réseau interne. | Active | Déployer immédiatement la mise à jour Chrome sur tous les endpoints, en priorisant les utilisateurs à haut risque et les systèmes exposés ; forcer le redémarrage des navigateurs ; surveiller les exécutions de processus et les connexions réseau suspectes provenant des processus de navigateur. | [https://thehackernews.com/2026/09/weekly-recap-chrome-0-day-router.html](https://thehackernews.com/2026/09/weekly-recap-chrome-0-day-router.html)<br>[https://threatnoir.com/focus](https://threatnoir.com/focus) |
| **CVE-2026-14894** | N/A | N/A | FALSE | Plugin WordPress Super Forms (installations non corrigées) | Exécution de code à distance critique par téléversement de fichiers arbitraires non authentifié (dépôt de webshells PHP) | Prise de contrôle complète du site WordPress, persistance via webshell PHP, vol ou altération de données, envoi de spam/phishing depuis l'infrastructure compromise et rebond possible vers l'hébergeur. | Active | Scanner immédiatement toutes les instances WordPress pour détecter la présence de Super Forms ; mettre à jour le plugin vers la dernière version ou le désactiver s'il n'est pas critique ; chasser les webshells dans wp-content et wp-uploads ; bloquer les motifs d'exploitation au niveau WAF/IPS. | [https://threatnoir.com/focus](https://threatnoir.com/focus) |
| **CVE-2026-32475** | N/A | N/A | FALSE | Plugin WordPress Elementor Pro (installations non corrigées) | Exécution de code à distance critique par téléversement de fichiers arbitraires non authentifié (dépôt de webshells PHP) | Prise de contrôle complète du site WordPress, persistance via webshell PHP, vol ou altération de données, utilisation de l'infrastructure pour du phishing/spam et rebond possible vers l'hébergeur. | Active | Scanner immédiatement toutes les instances WordPress pour détecter la présence d'Elementor Pro ; mettre à jour le plugin vers la dernière version ou le désactiver s'il n'est pas critique ; chasser les webshells dans wp-content et wp-uploads ; bloquer les motifs d'exploitation au niveau WAF/IPS. | [https://threatnoir.com/focus](https://threatnoir.com/focus) |
| **CVE-2026-75650** | 10.0 | N/A | FALSE | Adobe Commerce, Magento Open Source, Adobe Commerce B2B | Neutralisation incorrecte des éléments spéciaux utilisés dans un moteur de template (CWE-1336) - injection de template (SSTI) menant à l'exécution de code arbitraire | Compromission totale potentielle du serveur e-commerce : exécution de code arbitraire avec les privilèges de l'utilisateur courant, impact maximal sur la confidentialité, l'intégrité et la disponibilité. Risques associés : vol de données clients et de credentials de paiement, déploiement de webshells, pivot vers l'infrastructure interne et interruption de l'activité de vente en ligne. | None | Mettre à jour Adobe Commerce vers la dernière version et appliquer l'ensemble des correctifs de sécurité Adobe (bulletin APSB26-146) ; revoir et sécuriser les configurations du moteur de template ; surveiller toute exécution de code non autorisée ; restreindre l'accès aux interfaces d'administration et durcir l'exposition Internet des instances. | [https://cvefeed.io/vuln/detail/CVE-2026-75650](https://cvefeed.io/vuln/detail/CVE-2026-75650)<br>[https://radar.offseq.com/threat/cve-2026-75650-improper-neutralization-of-special-elements-used-in-a-template-engine-cwe-1336-in-adobe-1ba4ab0d2a763031](https://radar.offseq.com/threat/cve-2026-75650-improper-neutralization-of-special-elements-used-in-a-template-engine-cwe-1336-in-adobe-1ba4ab0d2a763031)<br>[https://infosec.exchange/@offseq/117231650321650010](https://infosec.exchange/@offseq/117231650321650010)<br>[https://helpx.adobe.com/security/products/magento/apsb26-146.html](https://helpx.adobe.com/security/products/magento/apsb26-146.html) |
| **CVE-2026-67276** | 9.2 | N/A | FALSE | MikroTik RouterOS 7.24 à versions antérieures à 7.24.2, 7.0.0 à versions antérieures à 7.23.4, 6.0.0 à versions antérieures à 6.49.21 | Vérification incorrecte de signature cryptographique (CWE-347) - contournement de l'authentification SSH par validation incomplète de la clé publique RSA | Prise de contrôle administrative totale et non authentifiée des routeurs dont le service SSH est exposé : création de comptes à privilèges élevés, modification de la configuration, persistance pouvant survivre jusqu'à une investigation et une reconstruction active. Un routeur compromis peut servir de relais (proxy/VPN), de point d'interception du trafic, de pivot vers le réseau interne ou être intégré à des botnets. | Active | Mettre à jour RouterOS vers les versions corrigées (7.24.2+, 7.23.4+ ou 6.49.21+) ; ne pas exposer SSH directement depuis Internet (ACL, désactivation du service, VPN d'administration) ; vérifier les logs 'Flagged status' après mise à jour ; régénérer les clés SSH et auditer les comptes et la configuration des équipements. | [https://www.security.nl/posting/951949/MikroTik-routers+via+kritieke+SSH-kwetsbaarheden+op+afstand+overgenomen?channel=rss](https://www.security.nl/posting/951949/MikroTik-routers+via+kritieke+SSH-kwetsbaarheden+op+afstand+overgenomen?channel=rss)<br>[https://socprime.com/blog/cve-2026-67276-mikrotik-routeros-ssh-zero-day/](https://socprime.com/blog/cve-2026-67276-mikrotik-routeros-ssh-zero-day/) |
| **CVE-2026-86060** | N/A | N/A | FALSE | MikroTik RouterOS (versions corrigées : 7.24.2+, 7.23.4+, 6.49.21+) | Élévation de privilèges SSH via une gestion incorrecte des noms d'utilisateur commençant par un caractère non autorisé par le login SSH | Élévation aux droits d'administration complète du routeur lorsqu'elle est combinée à CVE-2026-67276, aboutissant à une prise de contrôle totale et non authentifiée de l'équipement : création de comptes privilégiés, modification de configuration, mise en place de persistance et utilisation du routeur comme relais ou point d'interception. | Active | Appliquer les mises à jour RouterOS publiées le 3 septembre 2026 ; restreindre l'exposition SSH (ACL, désactivation du service depuis Internet) ; surveiller les tentatives d'authentification avec des noms d'utilisateur anormaux et les alertes 'Flagged status' ; auditer et régénérer les comptes et credentials après suspicion de compromission. | [https://www.security.nl/posting/951949/MikroTik-routers+via+kritieke+SSH-kwetsbaarheden+op+afstand+overgenomen?channel=rss](https://www.security.nl/posting/951949/MikroTik-routers+via+kritieke+SSH-kwetsbaarheden+op+afstand+overgenomen?channel=rss)<br>[https://socprime.com/blog/cve-2026-67276-mikrotik-routeros-ssh-zero-day/](https://socprime.com/blog/cve-2026-67276-mikrotik-routeros-ssh-zero-day/) |
| **CVE-2026-84962, CVE-2026-84963, CVE-2026-84964, CVE-2026-84965, CVE-2026-84966, CVE-2026-84967, CVE-2026-84968, CVE-2026-84969, CVE-2026-84970, CVE-2026-84971** | N/A | N/A | FALSE | MongoDB C Driver (2.x < 2.5.2 et < 1.30.9), MongoDB C++ Driver (< 4.5.2), libmongocrypt (< 1.20.4), MongoDB pour VS Code (< 1.17.1), MongoDB PHP Driver (2.1.x < 2.1.9, 2.2.x < 2.5.1, < 1.21.8) | Multiples vulnérabilités : atteinte à la confidentialité des données, atteinte à l'intégrité des données, injection de requêtes illégitimes par rebond (CSRF), contournement de la politique de sécurité et déni de service | Un attaquant peut provoquer une atteinte à la confidentialité et à l'intégrité des données manipulées via les drivers affectés, réaliser des injections de requêtes par rebond (CSRF), contourner la politique de sécurité et causer un déni de service. Les applications utilisant ces drivers comme composants de connexion constituent la surface d'attaque principale. | None | Mettre à jour l'ensemble des composants vers les versions corrigées : C Driver 2.5.2 / 1.30.9, C++ Driver 4.5.2, libmongocrypt 1.20.4, MongoDB pour VS Code 1.17.1, PHP Driver 2.1.9 / 2.5.1 / 1.21.8 selon la branche. Se référer aux bulletins de sécurité MongoDB listés dans l'avis CERT-FR. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1123/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1123/) |
| **CVE-2013-5211, CVE-2016-9042, CVE-2016-9310, CVE-2017-6451, CVE-2017-6452, CVE-2017-6455, CVE-2017-6458, CVE-2017-6459, CVE-2017-6460, CVE-2017-6462, CVE-2017-6463, CVE-2017-6464** | N/A | N/A | FALSE | Junos OS Evolved (< 20.1R1-EVO) et Junos OS branches 12.3R12-x, 12.3X48-x, 15.1R7-x, 15.1X49-x, 16.1R7-x, 17.1R2-x, 17.2R1-x, 17.2R2-x, 17.2R3-x, 17.3R2-x, 17.3R3-x, 17.4R2-x, 18.1R3-x, 18.2R2-x, 18.2R3-x, 18.3R1-x, 18.3R2-x, 18.4R1-x, 18.4R2-x, 19.1R1-x (versions antérieures aux correctifs listés) | Multiples vulnérabilités liées à NTP : exécution de code arbitraire, élévation de privilèges, déni de service à distance | Un attaquant peut provoquer une exécution de code arbitraire, une élévation de privilèges sur les équipements réseau ou un déni de service à distance. L'abus des fonctionnalités NTP vulnérables peut également transformer les équipements en amplificateurs d'attaques DDoS contre des tiers. | None | Mettre à jour Junos OS et Junos OS Evolved vers les versions corrigées du bulletin JSA11171. Restreindre le service NTP aux sources de confiance, désactiver monlist/mode 7 et filtrer UDP/123 en ingress depuis Internet. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1124/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1124/) |
| **CVE-2024-11053, CVE-2024-31227, CVE-2024-31228, CVE-2024-31449, CVE-2024-46981, CVE-2024-51741, CVE-2024-7264, CVE-2024-9681, CVE-2025-13034, CVE-2025-14017, CVE-2025-14524, CVE-2025-15079, CVE-2025-15224, CVE-2025-21605, CVE-2025-27151, CVE-2025-32023, CVE-2025-48367, CVE-2025-6170** | N/A | N/A | FALSE | Open Source RabbitMQ (< 3.13.19, 4.0.x < 4.0.24, 4.1.x < 4.1.15, 4.2.x < 4.2.10, 4.3.x < 4.3.5) et Tanzu for Valkey sur Kubernetes (< 13.5.0) | Multiples vulnérabilités (impact non spécifié par l'éditeur) | Non spécifié par l'éditeur. Compte tenu de la nature des composants (brokers de messages et bases clé-valeur souvent critiques pour les applications), une exploitation pourrait affecter la confidentialité, l'intégrité ou la disponibilité des flux de messages et des données. | None | Mettre à jour RabbitMQ vers les versions 3.13.19 / 4.0.24 / 4.1.15 / 4.2.10 / 4.3.5 selon la branche et Tanzu for Valkey sur Kubernetes vers la version 13.5.0 ou supérieure, en se référant aux bulletins Broadcom listés dans l'avis CERT-FR. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1125/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1125/) |
| **CVE-2026-82753** | 8.2 | N/A | FALSE | ash_authentication_oauth2_server versions 0.3.0 à 0.3.1 (exclusive) | Allocation de ressources sans limites ni contrôle (CWE-770) permettant un déni de service par épuisement du stockage et de la mémoire | Épuisement non borné du stockage de la base de données et de la mémoire de l'application (lignes clients permanentes et entrées de cache volumineuses), conduisant à un déni de service du serveur d'authentification OAuth2 et potentiellement des services dépendants. | Theoretical | Mettre à jour ash_authentication_oauth2_server vers la version 0.3.1 ou ultérieure. En complément : imposer des limites de ressources sur les requêtes clients, valider les données client avant toute mise en cache et mettre en place un garbage collection du cache et des lignes clients. | [https://cvefeed.io/vuln/detail/CVE-2026-82753](https://cvefeed.io/vuln/detail/CVE-2026-82753)<br>[https://cna.erlef.org/cves/CVE-2026-82753.html](https://cna.erlef.org/cves/CVE-2026-82753.html)<br>[https://github.com/ash-project/ash_authentication_oauth2_server/security/advisories/GHSA-9pv3-wxjm-f846](https://github.com/ash-project/ash_authentication_oauth2_server/security/advisories/GHSA-9pv3-wxjm-f846) |
| **CVE-2026-82586** | 8.2 | N/A | FALSE | ash_lua versions 0.1.0 à 0.2.1 (exclusive) | Protection inadéquate d'un chemin alternatif (CWE-424) permettant à un script Lua de lire des attributs privés hors allow-list | Fuite d'attributs privés et sensibles, notamment les hachages de mots de passe (hashed_password) et toute donnée marquée sensitive?: true, pour l'ensemble des enregistrements accessibles à l'acteur. Risque d'exploitation hors ligne des hachages et de violation de la confidentialité des données. | Theoretical | Mettre à jour ash_lua vers la version 0.2.1 ou ultérieure et s'assurer que tout accès aux champs respecte la allow-list des champs exposés, y compris pour les chemins d'agrégats. Restreindre la possibilité de soumettre des scripts Lua. | [https://cvefeed.io/vuln/detail/CVE-2026-82586](https://cvefeed.io/vuln/detail/CVE-2026-82586)<br>[https://cna.erlef.org/cves/CVE-2026-82586.html](https://cna.erlef.org/cves/CVE-2026-82586.html)<br>[https://github.com/ash-project/ash_lua/security/advisories/GHSA-37jv-wc37-fhcw](https://github.com/ash-project/ash_lua/security/advisories/GHSA-37jv-wc37-fhcw) |
| **CVE-2026-7861** | 9.8 | N/A | FALSE | Next4Biz CSM (Customer Service Management), toutes versions jusqu'au build 07092026 inclus | Désérialisation de données non fiables (CWE-502) permettant une injection de code | Injection de code à distance non authentifiée sur une plateforme de gestion de la relation client : compromission totale potentielle du serveur (confidentialité, intégrité, disponibilité maximales), accès aux données clients et pivot vers le réseau interne. | Theoretical | Aucun correctif éditeur disponible à ce stade (vendor non répondant). Appliquer des contrôles compensatoires : restreindre l'exposition Internet de Next4Biz CSM, filtrer via WAF les charges utiles de désérialisation, surveiller les avis USOM/éditeur pour l'apparition d'un patch et envisager la mise en quarantaine ou le remplacement du produit si le risque est inacceptable. | [https://cvefeed.io/vuln/detail/CVE-2026-7861](https://cvefeed.io/vuln/detail/CVE-2026-7861)<br>[https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-1027](https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-1027) |
| **CVE-2026-79645** | 8.2 | N/A | FALSE | Dell Secure Connect Gateway (SCG) 5.0 Appliance versions antérieures à 5.36.00.16 et Dell SCG 5.0 Application versions antérieures à 5.36.00.00 | Absence d'authentification pour une fonction critique (CWE-306) | Accès non autorisé à la passerelle SCG, qui constitue un point de gestion central : un attaquant pourrait pivoter vers les infrastructures supervisées (serveurs, hyperviseurs), accéder à des informations de configuration sensibles ou manipuler les fonctions de gestion à distance. | None | Mettre à jour Dell SCG Appliance vers la version 5.36.00.16 ou supérieure et Dell SCG Application vers la version 5.36.00.00 ou supérieure (avis DSA-2026-382). En attendant la mise à jour, restreindre l'exposition réseau de l'interface SCG (ACL, VPN, segmentation) et surveiller les tentatives d'accès non authentifiées. | [https://cvefeed.io/vuln/detail/CVE-2026-79645](https://cvefeed.io/vuln/detail/CVE-2026-79645)<br>[https://www.dell.com/support/kbdoc/en-in/000503426/dsa-2026-382-security-update-for-dell-secure-connect-gateway-virtual-edition-multiple-vulnerabilities](https://www.dell.com/support/kbdoc/en-in/000503426/dsa-2026-382-security-update-for-dell-secure-connect-gateway-virtual-edition-multiple-vulnerabilities) |
| **CVE-2026-13181** | 8.1 | N/A | FALSE | Telerik UI for ASP.NET AJAX (contrôle RadAsyncUpload), versions 2010.1.309 à 2026.2.519 | Résolution de type .NET non contrôlée (unguarded type resolution) permettant une exécution de code à distance non authentifiée via désérialisation de gadget | Exécution de code à distance non authentifiée sur le serveur IIS avec les privilèges du pool d'applications : webshell persistant ou exécution furtive en mémoire, mouvement latéral, compromission complète de l'application hébergée et des données associées. | Theoretical | Mettre à jour Telerik UI for ASP.NET AJAX vers la version 2026.2.708 ou supérieure ; identifier les applications utilisant RadAsyncUpload avec une clé de chiffrement explicite (configuration à risque) ; restreindre l'accès aux handlers Telerik ; surveiller les volumes anormaux de requêtes oracle (environ 127 000 requêtes observées en laboratoire, soit environ une heure contre une cible de test). | [https://thehackernews.com/2026/09/telerik-ui-padding-oracle-bug-chained.html](https://thehackernews.com/2026/09/telerik-ui-padding-oracle-bug-chained.html) |
| **CVE-2026-13182** | N/A | N/A | FALSE | Telerik UI for ASP.NET AJAX (contrôle RadAsyncUpload), versions 2010.1.309 à 2026.2.519 | Padding oracle AES-CBC (état client chiffré sans contrôle d'intégrité) - maillon d'entrée de la chaîne d'exploitation | Déchiffrement et falsification de la configuration de téléversement chiffrée sans connaissance de la clé, constituant le prérequis de la chaîne complète menant à l'exécution de code à distance avec les privilèges du pool d'applications IIS. | Theoretical | Mettre à jour vers la version 2026.2.708 ou supérieure ; surveiller et limiter le débit (rate limiting) sur les endpoints RadAsyncUpload ; revoir les configurations avec clé de chiffrement explicite ; uniformiser les réponses serveur pour réduire la surface d'oracle. | [https://thehackernews.com/2026/09/telerik-ui-padding-oracle-bug-chained.html](https://thehackernews.com/2026/09/telerik-ui-padding-oracle-bug-chained.html) |
| **CVE-2026-13183** | N/A | N/A | FALSE | Telerik UI for ASP.NET AJAX (contrôle RadAsyncUpload), versions 2010.1.309 à 2026.2.519 | Variante du padding oracle par analyse temporelle des réponses (timing side-channel) | Contournement des protections par masquage des messages d'erreur, rendant la chaîne d'exploitation applicable à un périmètre plus large d'applications et aboutissant, en combinaison avec les autres maillons, à une exécution de code à distance avec les privilèges du pool d'applications IIS. | Theoretical | Mettre à jour vers la version 2026.2.708 ou supérieure ; appliquer un rate limiting sur les endpoints de téléversement Telerik ; surveiller les latences anormales et les volumes de requêtes sur les handlers ; revoir les configurations avec clé de chiffrement explicite. | [https://thehackernews.com/2026/09/telerik-ui-padding-oracle-bug-chained.html](https://thehackernews.com/2026/09/telerik-ui-padding-oracle-bug-chained.html) |
| **CVE-2026-19490** | N/A | N/A | FALSE | Citrix NetScaler ADC / NetScaler Gateway lorsque configuré en Gateway (serveur virtuel VPN, ICA Proxy, CVPN, RDP Proxy), serveur virtuel AAA ou SAML Identity Provider | Contournement d'authentification (authentication bypass) pré-authentification | Accès non authentifié à des passerelles d'accès distant massivement déployées pour le télétravail : compromission du périmètre réseau, vol d'identifiants et de sessions, pivot vers l'infrastructure interne, risque de déploiement de ransomware. La compromission d'un NetScaler peut avoir un impact majeur car l'équipement est positionné entre les serveurs internes et Internet. | Active | Appliquer immédiatement la mise à jour Citrix publiée le 19/08/2026 ; auditer les configurations Gateway/AAA/SAML ; restreindre l'exposition Internet des interfaces d'administration et d'accès distant ; surveiller les authentifications anormales ; suivre les alertes CCB et Previdian ; bloquer les IP d'attaque signalées. | [https://www.security.nl/posting/951941/Kritiek+beveiligingslek+in+Citrix+NetScaler+actief+misbruikt+bij+aanvallen?channel=rss](https://www.security.nl/posting/951941/Kritiek+beveiligingslek+in+Citrix+NetScaler+actief+misbruikt+bij+aanvallen?channel=rss) |
| **CVE-2026-83548** | 10.0 | N/A | FALSE | SonicWall SMA 1000 Series (appliances SMA 6210, 7210 et 8200v) | SSRF (Server-Side Request Forgery) pré-authentification | Un attaquant non authentifié peut manipuler la passerelle pour accéder à des ressources internes, récupérer des secrets (tokens cloud, identifiants) et préparer une compromission plus large de l'environnement. Exploitation zero-day confirmée : les systèmes non patchés exposés sur Internet sont considérés comme compromis potentiels. | Active | Appliquer sans délai le correctif SonicWall pour SMA 1000 ; restreindre l'exposition Internet des appliances ; surveiller les requêtes sortantes anormales émises par les passerelles ; révoquer les sessions et secrets potentiellement exposés. | [https://research.checkpoint.com/2026/7th-september-threat-intelligence-report/](https://research.checkpoint.com/2026/7th-september-threat-intelligence-report/) |
| **CVE-2026-83549** | N/A | N/A | FALSE | SonicWall SMA 1000 Series (appliances SMA 6210, 7210 et 8200v) | Exécution de code à distance (RCE) post-authentification | Un attaquant disposant d'un accès authentifié (légitime ou obtenu via une autre faille) peut exécuter du code arbitraire sur la passerelle, compromettre l'appliance, intercepter les flux d'accès distant et pivoter vers le réseau interne. Exploitation zero-day confirmée. | Active | Appliquer le correctif SonicWall sans délai ; imposer un MFA sur les accès d'administration ; révoquer les sessions et renouveler les identifiants ; surveiller les exécutions de commandes et modifications de configuration anormales. | [https://research.checkpoint.com/2026/7th-september-threat-intelligence-report/](https://research.checkpoint.com/2026/7th-september-threat-intelligence-report/) |
| **CVE-2026-82329** | 9.8 | N/A | FALSE | JFrog Artifactory (déploiements auto-hébergés / self-hosted) | Contournement d'authentification (authentication bypass) pré-authentification | Prise de contrôle totale des dépôts d'artefacts par un attaquant non authentifié : vol de code et de secrets, empoisonnement de la chaîne logicielle (distribution de paquets malveillants aux clients et pipelines CI/CD), mouvement latéral via les identifiants stockés. Exploitation active observée contre les systèmes exposés. | Active | Appliquer le correctif JFrog immédiatement ; révoquer et régénérer tous les tokens d'accès ; restreindre l'exposition Internet des instances auto-hébergées ; activer les protections IPS dédiées ; auditer l'intégrité des artefacts et des dépôts. | [https://research.checkpoint.com/2026/7th-september-threat-intelligence-report/](https://research.checkpoint.com/2026/7th-september-threat-intelligence-report/) |
| **CVE-2017-18737** | 8.8 | 1.84% | FALSE | Équipements réseau Netgear (routeurs) – produit exact non précisé dans la source | Vulnérabilité non corrigée (statut de patch inconnu / unpatched) | Les routeurs Netgear non corrigés exposent les réseaux domestiques et de télétravail à des compromissions (détournement de trafic, injection DNS, pivot vers les équipements internes). L'absence de correctif maintient une fenêtre d'exposition permanente, particulièrement pour les modèles EOL. | None | Vérifier et mettre à jour le firmware des routeurs Netgear ; remplacer les modèles sans support ; désactiver l'administration distante ; surveiller les avis Netgear et les sources NVD/EPSS pour toute évolution du statut d'exploitation. | [https://www.valtersit.com/vendors/netgear/](https://www.valtersit.com/vendors/netgear/) |
| **CVE-2022-41545** | N/A | 0.29% | FALSE | Équipements réseau Netgear (routeurs) – produit exact non précisé dans la source | Vulnérabilité non corrigée (statut de patch inconnu / unpatched) | Maintien d'une surface d'attaque persistante sur les routeurs Netgear non corrigés, avec un risque de compromission des réseaux domestiques et de télétravail (détournement de trafic, pivot interne), aggravé par l'absence de correctif éditeur. | None | Vérifier la disponibilité d'un firmware corrigé ; remplacer les équipements non supportés ; durcir la configuration (désactivation de l'administration distante, identifiants forts) ; suivre l'évolution de l'EPSS et des avis de sécurité. | [https://www.valtersit.com/vendors/netgear/](https://www.valtersit.com/vendors/netgear/) |
| **CVE-2026-72898** | 10.0 | N/A | FALSE | Metabase (plateforme de business intelligence open source), exploitée via l'infrastructure du prestataire logistique ShipMonk | Injection SQL zero-day (CVSS 10.0 CRITIQUE) | Exposition de données personnelles de 81 000 clients : noms, adresses email, numéros de téléphone, adresses postales de livraison et numéros de commande. Ces informations sont directement exploitables pour des campagnes de phishing ciblées, de l'ingénierie sociale (usurpation du support Trezor pour vol de seed phrases) et des risques physiques (ciblage de détenteurs de crypto-actifs à domicile). L'incident illustre également un échec majeur de gouvernance des données chez un tiers : 67 000 enregistrements censés être supprimés depuis des années ont été conservés et exposés. | Active | Appliquer immédiatement les correctifs Metabase publiés pour CVE-2026-72898 et vérifier la version de toutes les instances déployées, y compris chez les prestataires. Restreindre l'exposition des instances Metabase (authentification forte, segmentation réseau, WAF avec règles anti-injection SQL). Auditer les engagements contractuels de suppression des données chez les tiers et mettre en place des vérifications techniques de purge effective. Surveiller les indicateurs d'exploitation dans les logs et renforcer la vigilance face aux tentatives de phishing se réclamant de Trezor ou de son support client. | `hxxps://deafnews[.]it/en/article/trezor-81000-customers-exposed-shipmonk-violated-data-deletion-contract` |
| **** | N/A | N/A | FALSE | Roundcube Webmail versions 1.6.x antérieures à 1.6.19 et versions 1.7.x antérieures à 1.7.4 | Multiples vulnérabilités : falsification de requêtes côté serveur (SSRF), injection de code indirecte à distance (XSS), contournement de la politique de sécurité | Le SSRF permet des requêtes arbitraires émises depuis le serveur webmail (pivot réseau interne), le XSS permet le vol de sessions et l'exécution d'actions au nom de l'utilisateur, et le contournement de la politique de sécurité affaiblit les protections du webmail. | None | Se référer au bulletin de sécurité de l'éditeur et appliquer les correctifs : mettre à niveau Roundcube Webmail vers les versions 1.6.19 (branche 1.6.x) ou 1.7.4 (branche 1.7.x). | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1122/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1122/)<br>[https://roundcube.net/news/2026/09/06/security-updates-1.6.19-and-1.7.4](https://roundcube.net/news/2026/09/06/security-updates-1.6.19-and-1.7.4) |
| **** | N/A | N/A | FALSE | Belden HiOS Switch Platform : branches 07.x < 07.1.12, 08.x < 08.7.10, 09.0.x < 09.0.13, 09.3.x < 09.3.03, 10.3.x < 10.3.08, 10.5.x < 10.5.00 | Vulnérabilité liée au service HTTPS permettant un déni de service à distance (aucun identifiant CVE cité dans la source) | Un attaquant ayant accès au service HTTPS des commutateurs peut provoquer un déni de service à distance, avec perte potentielle de l'administration des équipements et perturbation du réseau industriel supporté. | None | Mettre à jour le firmware HiOS vers les versions corrigées (07.1.12, 08.7.10, 09.0.13, 09.3.03, 10.3.08, 10.5.00 selon la branche) en se référant au bulletin Belden PSIRT-6, et restreindre l'accès de management des commutateurs. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1126/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1126/) |
| **** | N/A | N/A | FALSE | Traefik versions antérieures à v2.11.57 et Traefik v3.x antérieures à v3.7.13 | Multiples vulnérabilités : atteinte à la confidentialité des données et contournement de la politique de sécurité (identifiées par cinq avis GHSA ; aucun identifiant CVE cité dans la source) | Un attaquant peut contourner les politiques de sécurité du proxy (routage, middlewares, contrôle d'accès) et accéder à des données confidentielles transitant par ou derrière Traefik, notamment vers des services internes normalement protégés. | None | Mettre à jour Traefik vers v2.11.57 ou v3.7.13 selon la branche en se référant aux avis GHSA de l'éditeur, et restreindre l'exposition du dashboard et de l'API de Traefik. | [https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1127/](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1127/) |
| **** | N/A | N/A | FALSE | Boutiques en ligne sous Adobe Magento (versions non précisées ; zero-day non corrigé au moment de la publication) | Exploitation active d'un zero-day non corrigé avec installation de backdoors (détails techniques non confirmés) | Compromission de serveurs e-commerce, installation de portes dérobées persistantes, risque de vol de données clients et de cartes de paiement (skimming), détournement de commandes, atteinte à la réputation et non-conformité PCI DSS. | Active | Surveiller les avis de sécurité Adobe/Magento et appliquer les correctifs dès leur publication ; renforcer le WAF ; restreindre les droits du compte d'exécution web ; auditer l'intégrité des fichiers (modules, thèmes, cron) ; rechercher proactivement des webshells et des comptes administrateurs frauduleux ; maintenir des sauvegardes hors ligne testées. | [https://thecyberexpress.com/attackers-exploit-unpatched-magento-zero-day/](https://thecyberexpress.com/attackers-exploit-unpatched-magento-zero-day/) |
| **** | N/A | N/A | FALSE | Routeurs MikroTik sous RouterOS (versions et identifiants CVE non précisés dans la source) | Vulnérabilités RouterOS exploitées avant la publication des correctifs (exploitation pré-patch) | Compromission de routeurs exposés : persistance via scripts planifiés, création de proxys SOCKS, interception ou redirection de trafic, intégration à des botnets, pivot vers le réseau interne. | Active | Appliquer immédiatement les dernières mises à jour RouterOS ; désactiver les services d'administration exposés (Winbox/API/Web) ou les restreindre par ACL ; imposer des mots de passe forts et l'authentification par clés ; auditer les configurations (scheduler, files, NAT, proxys) ; surveiller le trafic sortant anormal. | [https://thecyberexpress.com/mikrotik-routeros-exploited-before-patch/](https://thecyberexpress.com/mikrotik-routeros-exploited-before-patch/) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="roundup-securite-linux-plus-de-100-cves-noyau-corrigees-dun-coup-pour-ubuntu-evasion-de-sandbox-minetest-et-integer-underflow-miniupnpd"></div>

## Roundup sécurité Linux : plus de 100 CVEs noyau corrigées d'un coup pour Ubuntu, évasion de sandbox Minetest et integer underflow MiniUPnPd

### Résumé

Le site LinuxCompatible.org publie une revue de sécurité Linux (SUSE, Ubuntu, Debian) indiquant qu'Ubuntu a corrigé en une seule vague plus d'une centaine de CVEs affectant le noyau. La publication mentionne également une évasion de sandbox Lua dans Minetest et un integer underflow dans MiniUPnPd, et recommande de patcher sans délai, en particulier pour les serveurs de jeux auto-hébergés et les services UPnP exposés.

---

### Analyse opérationnelle

Prioriser le déploiement des mises à jour noyau Ubuntu (redémarrage requis) sur l'ensemble des parcs serveurs. Identifier les hôtes exécutant Minetest (serveurs de jeux) et MiniUPnPd (passerelle UPnP) et vérifier leur exposition Internet. Contrôler les règles de pare-feu bloquant l'UPnP entrant depuis l'extérieur, planifier les fenêtres de maintenance avec reboot et suivre les bulletins SUSE/Debian correspondants pour les autres distributions.

---

### Implications stratégiques

La concentration de correctifs noyau en une seule publication accroît la charge opérationnelle des équipes IT et le risque d'écart de patch entre serveurs. Les composants UPnP exposés restent une surface d'attaque récurrente pour l'accès initial sur les réseaux de petite taille et les infrastructures auto-hébergées, justifiant une politique d'exposition externe stricte.

---

### Recommandations

* Appliquer immédiatement les mises à jour noyau Ubuntu et redémarrer les hôtes concernés
* Restreindre ou désactiver tout service UPnP (MiniUPnPd) exposé à Internet
* Corriger Minetest si des serveurs de jeux sont auto-hébergés
* Vérifier l'inventaire des noyaux en fin de support et les redémarrages en attente

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire à jour des hôtes Linux, versions de noyau et paquets sensibles (Minetest, MiniUPnPd)
* S'abonner aux bulletins de sécurité Ubuntu, SUSE et Debian ainsi qu'aux flux CVE
* Définir des fenêtres de maintenance et des procédures de redémarrage pour les serveurs (les correctifs noyau exigent un reboot)
* Tester les correctifs en environnement de recette avant déploiement en production

#### Phase 2 — Détection et analyse

* Croiser les annonces de correctifs avec l'inventaire pour identifier les hôtes vulnérables
* Détecter les services UPnP (ports 1900/5000) et serveurs de jeux exposés à Internet via scans externes et télémétrie réseau
* Surveiller les journaux système pour des signes d'exploitation (crashs MiniUPnPd, processus Lua inattendus, redémarrages anormaux)

#### Phase 3 — Confinement, éradication et récupération

* Supprimer l'exposition Internet des services UPnP et serveurs de jeux non corrigés (règles de pare-feu, ACL)
* Appliquer les correctifs en priorité sur les systèmes exposés puis redémarrer les hôtes
* En cas de suspicion de compromission, isoler l'hôte et préserver les journaux

#### Phase 4 — Activités post-incident

* Vérifier les versions de noyau et de paquets après patch et confirmer la levée des expositions
* Analyser les journaux antérieurs au patch pour détecter toute exploitation passée inaperçue
* Documenter les délais de correction, les écarts constatés et mettre à jour les procédures de patch

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des connexions entrantes anormales vers les ports UPnP et de jeux avant la période de patch
* Chercher des processus enfants inattendus issus de MiniUPnPd ou du serveur Minetest
* Corréler les tentatives d'exploitation UPnP avec des campagnes de scan de masse connues

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploitation potentielle d'applications exposées publiquement (serveurs UPnP/MiniUPnPd et serveurs de jeux Minetest accessibles depuis Internet) |

---

### Sources

* [https://www.linuxcompatible.org/story/linux-security-roundup-suse-ubuntu-and-debian-ship-major-cve-patches](https://www.linuxcompatible.org/story/linux-security-roundup-suse-ubuntu-and-debian-ship-major-cve-patches)


---

<div id="tendances-cve-et-conseil-sbom-panorama-des-vulnerabilites-les-plus-consultees-cvedatabase"></div>

## Tendances CVE et conseil SBOM : panorama des vulnérabilités les plus consultées (CVEDatabase)

### Résumé

La plateforme CVEDatabase publie un instantané des CVEs en tendance, incluant notamment CVE-2026-20127 (authentification de peering Cisco Catalyst SD-WAN Controller/Manager, critique, CVSS 10.0), CVE-2026-21858 (n8n versions 1.65.0 à 1.121.0, accès aux fichiers du système sous-jacent, critique, CVSS 10.0), CVE-2026-26216 (Crawl4AI antérieur à 0.8.0, RCE via le déploiement Docker API, critique, CVSS 10.0), CVE-2026-1340 (Ivanti Endpoint Manager Mobile, injection de code permettant un RCE non authentifié, critique, CVSS 9.8), CVE-2026-21643 (Fortinet FortiClientEMS 7.4.4, injection SQL, critique, CVSS 9.8) et CVE-2026-22769 (Dell RecoverPoint for Virtual Machines antérieur à 6.0.3.1 HF1, identifiant codé en dur, critique, CVSS 10.0). Figurent aussi des CVEs Cisco SD-WAN Manager (CVE-2026-20122, CVE-2026-20133, CVE-2026-20128), CVE-2026-20805 (Desktop Windows Manager), CVE-2026-20045 (Cisco Unified CM), CVE-2025-53521 (F5 BIG-IP APM), CVE-2026-5281 (use-after-free Dawn dans Google Chrome) et des vulnérabilités historiques toujours très consultées (Log4Shell CVE-2021-44228, Heartbleed CVE-2014-0160, PaperCut CVE-2023-27351, TeamCity CVE-2024-27199). Le site rappelle l'intérêt de maintenir un SBOM pour répondre rapidement aux nouvelles vulnérabilités.

---

### Analyse opérationnelle

Croiser ces CVEs avec l'inventaire (SBOM/CMDB) pour identifier les produits présents : Cisco SD-WAN, n8n, Crawl4AI, Ivanti EPMM, FortiClientEMS, Dell RecoverPoint, F5 BIG-IP. Prioriser les vulnérabilités critiques exploitables à distance sans authentification (CVE-2026-20127, CVE-2026-1340, CVE-2026-26216, CVE-2026-21643). Vérifier les versions n8n (1.65.0 à 1.121.0) et Crawl4AI (antérieures à 0.8.0) exposées, et suivre l'ajout éventuel de ces CVEs à CISA KEV ainsi que les scores EPSS pour affiner la priorisation.

---

### Implications stratégiques

La récurrence de RCE non authentifiés sur des produits d'entreprise (Ivanti, Fortinet, Cisco) confirme la pression des acteurs de menace sur les appliances de bordure et les plateformes d'automatisation. Sans SBOM ni inventaire fiable, le délai d'identification des actifs touchés s'allonge et la fenêtre d'exposition s'accroît, avec un risque de compromission en masse avant correctif.

---

### Recommandations

* Maintenir un SBOM à jour pour cartographier les dépendances et réagir rapidement aux nouvelles CVEs
* Prioriser le patch des CVEs critiques exploitables à distance (CVSS 9.8 à 10.0) listées
* Restreindre l'exposition Internet des interfaces d'administration (SD-WAN Manager, EPMM, FortiClientEMS, n8n)
* S'abonner aux alertes CVE et suivre CISA KEV/EPSS pour la priorisation

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Constituer et maintenir un SBOM et un inventaire CMDB couvrant les produits concernés (Cisco SD-WAN, Ivanti EPMM, FortiClientEMS, n8n, Crawl4AI, Dell RecoverPoint, F5 BIG-IP)
* S'abonner aux flux NVD, CISA KEV, EPSS et aux alertes éditeurs
* Définir des SLA de patch par criticité (ex. 48-72h pour les RCE non authentifiés)
* Documenter les procédures de mise à jour et de rollback par produit

#### Phase 2 — Détection et analyse

* Corréler chaque nouvelle CVE avec l'inventaire pour détecter les actifs concernés
* Surveiller les journaux des produits exposés (tentatives d'injection SQL sur FortiClientEMS, requêtes anormales sur l'endpoint /crawl de Crawl4AI, accès fichiers inhabituels sur n8n)
* Détecter les interfaces d'administration exposées à Internet via scans externes réguliers

#### Phase 3 — Confinement, éradication et récupération

* Restreindre l'accès aux systèmes vulnérables (ACL, VPN, désactivation temporaire des fonctionnalités concernées)
* Appliquer les correctifs éditeurs ou des mesures compensatoires (règles WAF, durcissement)
* Isoler tout système suspecté d'être compromis et préserver les preuves

#### Phase 4 — Activités post-incident

* Vérifier les versions déployées et la clôture effective des vulnérabilités
* Rechercher des traces d'exploitation antérieure (comptes créés, fichiers modifiés, exécutions de commandes)
* Mettre à jour le SBOM, les runbooks et les règles de détection à partir des enseignements

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des requêtes POST anormales vers les API des produits concernés (peering SD-WAN, endpoint /crawl de Crawl4AI)
* Chercher des connexions sortantes inattendues depuis les hôtes n8n ou Crawl4AI (signe de RCE)
* Identifier dans les journaux d'authentification tout usage d'identifiants codés en dur (Dell RecoverPoint)

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploitation d'applications exposées publiquement : plusieurs CVEs en tendance sont des RCE ou injections exploitables à distance sans authentification (Ivanti EPMM, Crawl4AI, FortiClientEMS, Cisco SD-WAN) |

---

### Sources

* [https://cvedatabase.com](https://cvedatabase.com)


---

<div id="exploitation-active-de-deux-failles-mikrotik-routeros-recemment-divulguees-detournement-de-routeurs-via-ssh-expose"></div>

## Exploitation active de deux failles MikroTik RouterOS récemment divulguées : détournement de routeurs via SSH exposé

### Résumé

Selon BleepingComputer, des attaquants exploitent deux vulnérabilités récemment divulguées de MikroTik RouterOS pour prendre le contrôle de routeurs dont le service SSH est exposé à Internet. L'enchaînement des deux failles conférerait un contrôle complet du périphérique. Aucun identifiant CVE ni détail technique approfondi n'est fourni dans la source consultée.

---

### Analyse opérationnelle

Identifier tous les routeurs MikroTik du parc et vérifier les versions de RouterOS ; appliquer les correctifs publiés par MikroTik ; restreindre l'exposition du service SSH (ACL, accès via VPN uniquement, désactivation depuis Internet) ; auditer les configurations des routeurs exposés (comptes créés, règles NAT inattendues, scripts planifiés, fichiers) ; surveiller les connexions SSH entrantes anormales et les modifications de configuration.

---

### Implications stratégiques

Les routeurs compromis sont systématiquement réutilisés comme relais (proxys, botnets, infrastructures de phishing), exposant l'organisation à un risque de pivot réseau, de interception de trafic et à l'usage de son infrastructure dans des attaques visant des tiers, avec des conséquences réputationnelles et des blocages par les fournisseurs.

---

### Recommandations

* Patcher immédiatement RouterOS sur tous les équipements MikroTik
* Désactiver ou restreindre SSH/Winbox exposés à Internet (ACL, liste blanche, VPN)
* Auditer comptes, scripts scheduler, règles NAT et fichiers sur les routeurs exposés
* Surveiller les connexions SSH entrantes et les modifications de configuration

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les routeurs MikroTik (modèles, versions RouterOS, exposition Internet)
* Définir une configuration de référence durcie : SSH désactivé ou restreint par ACL, comptes nominatifs, services inutiles désactivés
* Centraliser les journaux RouterOS (syslog) et alerter sur les connexions SSH et les changements de configuration
* Suivre les avis de sécurité MikroTik et les flux CVE

#### Phase 2 — Détection et analyse

* Alerter sur les connexions SSH réussies depuis des adresses IP externes inconnues
* Détecter les modifications de configuration : nouveaux comptes, règles NAT/port-forwarding, scripts scheduler, fichiers ajoutés
* Surveiller les flux sortants anormaux depuis les routeurs (usage en proxy ou C2)

#### Phase 3 — Confinement, éradication et récupération

* Restreindre immédiatement l'accès SSH/Winbox depuis Internet (ACL, désactivation du service)
* Changer les identifiants d'administration et révoquer les clés SSH inconnues
* Isoler ou remplacer les routeurs suspectés d'être compromis et restaurer une configuration saine

#### Phase 4 — Activités post-incident

* Réinstaller RouterOS depuis une image officielle et recharger une configuration validée
* Analyser les journaux pour déterminer la date d'intrusion et les actions de l'attaquant
* Vérifier l'absence de persistance (scripts, tâches planifiées, comptes) après restauration

#### Phase 5 — Threat Hunting (proactif)

* Rechercher sur toute la flotte les comptes utilisateurs inconnus et les clés SSH non référencées
* Chercher des règles de redirection de ports ou de proxy (SOCKS) non autorisées
* Corréler les adresses IP sources des connexions SSH avec les campagnes connues d'exploitation MikroTik

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploitation de deux vulnérabilités RouterOS récemment divulguées sur des routeurs dont le service SSH est exposé à Internet, aboutissant à un contrôle complet du périphérique |

---

### Sources

* [https://www.bleepingcomputer.com/news/security/hackers-exploit-new-mikrotik-routeros-flaws-to-hijack-routers/](https://www.bleepingcomputer.com/news/security/hackers-exploit-new-mikrotik-routeros-flaws-to-hijack-routers/)


---

<div id="liquid-network-environ-4-000-btc-retires-du-portefeuille-de-federation-3-400-btc-restitues-apres-correctif-des-bridge-nodes"></div>

## Liquid Network : environ 4 000 BTC retirés du portefeuille de fédération, 3 400 BTC restitués après correctif des bridge nodes

### Résumé

D'après Techmeme (compilation de sources dont CoinDesk, The Block et le Wall Street Journal), un attaquant a retiré environ 4 000 BTC sur les 4 200 détenus dans le portefeuille de fédération de la Liquid Network (Blockstream), réseau de règlement utilisé par des plateformes d'échange. Blockstream a interrompu les nouvelles transactions sur le réseau et indiqué que ses bridge nodes avaient été corrigés ; l'attaquant, présenté comme un possible « white-hat », a restitué 3 400 BTC. Le mécanisme de fédération multi-signatures, censé servir de garde-fou, a cédé sans que le point de défaillance précis soit détaillé dans les sources consultées.

---

### Analyse opérationnelle

Pour les organisations opérant des nœuds ou des services adossés à Liquid : suspendre ou valider les interactions avec le réseau jusqu'à confirmation du déploiement des correctifs, mettre à jour les bridge nodes, auditer la logique multi-signatures et les autorisations, surveiller les transactions anormales sur les adresses de fédération et vérifier l'intégrité de ses propres avoirs et procédures de custody.

---

### Implications stratégiques

L'incident illustre la fragilité des ponts et fédérations crypto même en présence d'un mécanisme multi-signatures, avec un impact financier direct (environ 600 BTC non restitués à ce stade) et une perte de confiance potentielle pour les exchanges utilisant le réseau. La restitution partielle suggère un acteur se réclamant du white-hat, mais le risque de récurrence ou d'imitation malveillante demeure élevé.

---

### Recommandations

* Appliquer les correctifs publiés par Blockstream sur les bridge nodes avant toute reprise des opérations
* Auditer les mécanismes multi-signatures et les procédures de garde (clés, quorum, supervision)
* Surveiller les mouvements on-chain des adresses de fédération et des fonds restitués
* Revoir les plans de continuité (gel des transactions, communication) pour les services adossés à Liquid

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les dépendances aux réseaux de fédération et ponts crypto (Liquid, bridges) et les avoirs exposés
* Documenter les procédures de suspension des transactions et de communication de crise
* Mettre en place une supervision on-chain des adresses de fédération avec alertes sur mouvements importants
* Revoir l'architecture de garde multi-signatures (quorum, diversification des opérateurs de clés)

#### Phase 2 — Détection et analyse

* Alerter sur tout retrait anormal depuis les portefeuilles de fédération (montant, fréquence, destination)
* Surveiller les anomalies sur les bridge nodes (erreurs, comportements inattendus, tentatives d'exploitation)
* Suivre les annonces de sécurité Blockstream et les discussions publiques (X, forums spécialisés)

#### Phase 3 — Confinement, éradication et récupération

* Suspendre les nouvelles transactions sur le réseau ou le service concerné
* Appliquer les correctifs sur les bridge nodes et vérifier leur intégrité avant reprise
* Coordonner avec les opérateurs de fédération et les contreparties (exchanges) le gel des mouvements suspects

#### Phase 4 — Activités post-incident

* Analyser la logique défaillante (revue de code, audit externe) et documenter précisément le point de défaillance
* Suivre la restitution des fonds et les interactions avec l'attaquant
* Publier une communication transparente et mettre à jour les procédures de garde et de supervision

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des transactions historiques anormales sur les adresses de fédération
* Identifier d'éventuelles tentatives d'exploitation antérieures sur les bridge nodes (journaux, télémétrie)
* Surveiller les adresses de l'attaquant pour détecter tout mouvement des fonds restants

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploitation présumée des bridge nodes de la fédération Liquid, corrigés par Blockstream après l'incident |
| **T1657** | Vol de crypto-monnaies : retrait d'environ 4 000 BTC depuis le portefeuille de fédération de la Liquid Network |

---

### Sources

* [https://www.techmeme.com/260907/p18#a260907p18](https://www.techmeme.com/260907/p18#a260907p18)


---

<div id="chameleon-ultra-guide-de-lecture-emulation-et-test-de-badges-rfidnfc-risque-pour-les-controles-dacces-physique"></div>

## Chameleon Ultra : guide de lecture, émulation et test de badges RFID/NFC — risque pour les contrôles d'accès physique

### Résumé

Mobile-Hacker publie un guide sur le Chameleon Ultra, dispositif open source de recherche RFID/NFC capable d'identifier et lire des badges sans contact (technologies 125 kHz basse fréquence et 13,56 MHz haute fréquence/NFC), de sauvegarder jusqu'à huit profils d'identifiants, d'émuler des cartes auprès de lecteurs compatibles et, dans certains cas, d'écrire sur des supports vierges, avec connexion USB-C ou Bluetooth LE. L'article distingue les opérations de lecture, sauvegarde, émulation, écriture et clonage, souligne les usages légitimes (recherche, tests autorisés, apprentissage) et rappelle que tout usage non autorisé (copie de badge d'autrui, intrusion, contournement de systèmes de paiement ou de transport) est illégal.

---

### Analyse opérationnelle

Évaluer les technologies d'identifiants en place : les badges 125 kHz basse fréquence sont souvent facilement reproductibles, contrairement aux cartes 13,56 MHz à cryptographie forte. Tester lecteurs et badges dans le cadre d'audits autorisés, détecter les appareils Bluetooth inconnus à proximité des lecteurs, surveiller les anomalies d'accès (badges présentés depuis des localisations incohérentes, tentatives refusées répétées) et activer les fonctions anti-clonage/anti-rejeu des contrôleurs modernes.

---

### Implications stratégiques

La démocratisation d'outils d'émulation RFID à faible coût étend la surface d'attaque au physique : un badge cloné contourne l'ensemble des contrôles logiques en amont et peut servir de point d'entrée discret vers les systèmes critiques. Les organisations doivent intégrer le contrôle d'accès physique dans leur gestion du risque (tests d'intrusion physique, chiffrement des identifiants, segmentation entre zones physiques et actifs informationnels).

---

### Recommandations

* Migrer les badges 125 kHz vers des technologies à cryptographie forte (ex. DESFire EV2/EV3)
* Activer la détection de clonage et de rejeu sur les contrôleurs d'accès et surveiller les anomalies
* Inclure des tests d'intrusion physique (badges) dans les exercices red team autorisés
* Sensibiliser les employés au prêt de badges et aux identifiants non protégés

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les technologies de badges et lecteurs en place (fréquence 125 kHz vs 13,56 MHz, chiffrement) et les zones sensibles
* Définir un périmètre et une autorisation formelle pour les tests d'accès physique (red team)
* Centraliser les journaux des contrôleurs d'accès et alerter sur les anomalies (horaires, localisations, tentatives refusées répétées)

#### Phase 2 — Détection et analyse

* Détecter les appareils Bluetooth inconnus à proximité des lecteurs (le Chameleon Ultra communique via BLE et USB-C)
* Surveiller les présentations de badge incohérentes (même badge sur deux sites éloignés en peu de temps, usage hors horaires)
* Alerter sur les tentatives d'accès refusées répétées aux portes sensibles

#### Phase 3 — Confinement, éradication et récupération

* Révoquer ou bloquer immédiatement tout identifiant suspecté d'être cloné
* Renforcer temporairement les contrôles (agents de sécurité, vérification visuelle, verrouillage des zones sensibles)
* Préserver les journaux d'accès comme éléments de preuve

#### Phase 4 — Activités post-incident

* Analyser le chemin d'accès emprunté et les systèmes exposés à la suite de l'intrusion physique
* Recycler ou remplacer les identifiants compromis et réévaluer la technologie de badges
* Documenter l'incident et mettre à jour les procédures de contrôle d'accès

#### Phase 5 — Threat Hunting (proactif)

* Corréler les accès physiques avec les journaux d'accès logique (postes utilisés après entrée)
* Rechercher les badges utilisés depuis des lecteurs géographiquement incohérents
* Auditer les zones où des badges basse fréquence (125 kHz) clonables restent en usage

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1200** | Hardware Additions : usage d'un matériel dédié (Chameleon Ultra) pour lire, sauvegarder et émuler des identifiants RFID/NFC afin d'obtenir un accès physique aux locaux |

---

### Sources

* [https://www.mobile-hacker.com/2026/09/07/chameleon-ultra-guide-to-rfid-reading-emulation-and-testing/](https://www.mobile-hacker.com/2026/09/07/chameleon-ultra-guide-to-rfid-reading-emulation-and-testing/)


---

<div id="lockbit5-revendique-le-cabinet-davocats-sud-africain-vsbattorneyscoza"></div>

## LockBit5 revendique le cabinet d'avocats sud-africain vsbattorneys.co.za

### Résumé

Le 7 septembre 2026, le groupe ransomware LockBit5 a publié vsbattorneys[.]co[.]za, un cabinet d'avocats sud-africain, sur son site de fuite. Les métadonnées de la source (RansomLook) caractérisent LockBit5 comme une opération RaaS (Ransomware-as-a-Service) et affichent un compteur de victimes dégradé (2/6), cohérent avec une activité de publication récente ou partielle du groupe.

---

### Analyse opérationnelle

Intégrer LockBit5 aux flux de veille (IoC, TTP) et surveiller les sites de fuite pour détecter toute mention d'entités de son écosystème (clients, partenaires, sous-traitants) ; vérifier si des données échangées avec ce cabinet sont exposées. Défense ransomware standard : EDR sur serveurs et postes, sauvegardes hors-ligne immuables testées, segmentation, MFA sur les accès distants, durcissement des services exposés. Détection : alertes sur suppression des copies d'ombre, modifications massives de fichiers, création de services suspects, flux Tor sortants anormaux depuis le SI.

---

### Implications stratégiques

La réapparition d'une marque LockBit (LockBit5) après le démantèlement de 2024 illustre la résilience du modèle d'affaires criminel et sa fragmentation en franchises successives. Le secteur juridique est une cible privilégiée : données clients sensibles, secret professionnel, forte pression à payer. Toute organisation en relation avec ce cabinet expose un risque de fuite de données contractuelles ou confidentielles via la double extorsion.

---

### Recommandations

* Vérifier si l'organisation entretient des échanges avec vsbattorneys[.]co[.]za et évaluer l'exposition des données partagées
* Renforcer les sauvegardes 3-2-1 avec copies immuables hors-ligne et tester la restauration
* Affiner les règles EDR contre le chiffrement de masse et la suppression de sauvegardes
* Imposer un MFA résistant au phishing sur tous les accès distants et privilégiés
* Surveiller le site de fuite LockBit5 et les canaux de revente de données pour détecter des données de l'écosystème

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sauvegardes 3-2-1 avec copies immuables/hors-ligne et restaurations testées régulièrement
* EDR déployé sur serveurs et postes avec télémétrie centralisée dans le SIEM
* Segmentation réseau et restriction des mouvements latéraux (RDP, SMB, outils d'administration à distance)
* MFA sur VPN, messagerie et comptes à privilèges ; gestion des accès privilégiés (PAM)
* Plan de réponse ransomware documenté avec contacts juridiques, assureur cyber et autorités
* Correctifs à jour sur les surfaces exposées (passerelles VPN, pare-feux, serveurs web)

#### Phase 2 — Détection et analyse

* Alertes sur suppression des instantanés et sauvegardes (vssadmin delete shadows, wbadmin)
* Détection de chiffrement de masse (modifications anormales de fichiers, extensions aléatoires)
* Créations suspectes de comptes, services ou tâches planifiées ; exécution d'outils de tunneling (beacons, chisel)
* Volumes de sortie réseau inhabituels évoquant une exfiltration pré-chiffrement
* Connexions RDP/VPN anormales (horaires, géolocalisation, échecs répétés suivis d'un succès)

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les hôtes chiffrés ou suspects du réseau
* Désactiver les comptes compromis et révoquer sessions, tokens et tickets Kerberos
* Bloquer les IoC (IP/domaines C2) au pare-feu et au proxy ; restreindre les accès distants non essentiels
* Préserver les preuves (images mémoire et disques, journaux) avant toute réinitialisation
* Éviter toute extinction non contrôlée des systèmes afin de protéger la mémoire forensique

#### Phase 4 — Activités post-incident

* Reconstruction depuis des images et sauvegardes saines après validation de l'absence de persistance
* Rotation complète des identifiants, clés, secrets et certificats
* Analyse de cause racine : vecteur initial, durée de présence, périmètre des données exfiltrées
* Notifications réglementaires et légales (clients, autorité de protection des données, assureur)
* Renforcement des contrôles défaillants identifiés et retour d'expérience formalisé

#### Phase 5 — Threat Hunting (proactif)

* Recherche de notes de rançon, noms de fichiers et artefacts propres aux souches LockBit et variantes
* Chasse aux mouvements latéraux récents (RDP, PsExec, WMI, comptes locaux inusités)
* Recherche de mécanismes de persistance (services, tâches planifiées, run keys, comptes créés) sur les serveurs critiques
* Analyse des journaux VPN/pare-feu pour des accès antérieurs non détectés
* Surveillance continue du site de fuite LockBit5 pour toute mention de l'organisation ou de ses partenaires

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `vsbattorneys[.]co[.]za` | Low |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Chiffrement des données pour impact (extorsion par rançongiciel) |
| **T1490** | Inhibition de la récupération système (suppression des sauvegardes et instantanés) |
| **T1567** | Exfiltration de données vers un service web (site de fuite, double extorsion) |

---

### Sources

* [https://www.ransomlook.io//group/lockbit5](https://www.ransomlook.io//group/lockbit5)


---

<div id="qilin-revendique-partners-group-sk-sur-son-site-de-fuite"></div>

## Qilin revendique Partners Group SK sur son site de fuite

### Résumé

Le 7 septembre 2026, le groupe ransomware Qilin a listé « Partners Group SK » comme victime sur son site de fuite (relais via RansomLook). Les métadonnées de la source indiquent que Qilin opère sous modèle RaaS et recense un volume très important de victimes publiées (compteur dégradé 1/640), signe d'une campagne active et industrialisée. Le secteur et le pays de la victime ne sont pas précisés dans la source.

---

### Analyse opérationnelle

Intégrer Qilin aux flux de veille (IoC, TTP) : le groupe est connu pour l'exploitation d'accès distants non patchés et la double extorsion. Contrôles prioritaires : correctifs des passerelles VPN/edge, MFA systématique, suppression des comptes par défaut, sauvegardes immuables. Détection : comportements de chiffrement de masse, exfiltration massive (Rclone), outils living-off-the-land (PowerShell). Vérifier si l'organisation entretient des relations commerciales avec l'entité visée afin d'évaluer une exposition indirecte.

---

### Implications stratégiques

Le volume de victimes affiché par Qilin confirme la pression continue du ransomware RaaS sur des organisations de toutes tailles, y compris en Europe. La revendication publique crée un risque réputationnel et contractuel immédiat pour la victime et ses partenaires. Les directions doivent anticiper les scénarios de fuite de données (notification clients, conformité RGPD) et cadrer en amont leur politique de négociation ou de refus de paiement.

---

### Recommandations

* Surveiller le site de fuite Qilin et les relais type RansomLook pour détecter des entités liées à l'écosystème
* Prioriser le patching et le durcissement des passerelles VPN et équipements exposés
* Vérifier l'absence de comptes à privilèges sans MFA et l'absence de mots de passe par défaut
* Tester les restaurations depuis les sauvegardes immuables
* Préparer la matrice de décision négociation/refus et le plan de notification en cas de fuite confirmée

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sauvegardes immuables/hors-ligne avec tests de restauration réguliers
* EDR avec télémétrie centralisée et règles de blocage des comportements de chiffrement
* Durcissement et correctifs des passerelles d'accès distant (VPN, pare-feux) — vecteur historique du groupe
* MFA sur tous les accès externes et comptes privilégiés
* Plan de crise ransomware : rôles, chaîne de décision, contacts juridiques et assureur

#### Phase 2 — Détection et analyse

* Alertes sur suppression des sauvegardes et instantanés de volume
* Détection de chiffrement massif et de renommage de fichiers anormal
* Usage suspect d'outils d'exfiltration (Rclone, curl, PowerShell Invoke-WebRequest) et pics de trafic sortant
* Connexions VPN anormales (comptes désactivés, géographies inusitées, MFA contourné)
* Création de comptes locaux/domaine et élévation de privilèges inexpliquées

#### Phase 3 — Confinement, éradication et récupération

* Isolation réseau des hôtes compromis et des segments touchés
* Désactivation des comptes compromis et révocation des sessions/tokens
* Blocage des IoC C2 et des infrastructures de l'acteur au périmètre
* Coupure préventive des accès VPN/administration à distance non essentiels
* Préservation des journaux et images disques pour l'investigation

#### Phase 4 — Activités post-incident

* Reconstruction depuis des sauvegardes saines après vérification de l'absence de persistance
* Rotation des secrets, mots de passe, clés VPN et certificats
* Analyse du vecteur initial (souvent accès VPN/edge non patché) et de la chronologie de l'intrusion
* Notifications réglementaires (RGPD/autorités nationales) et communication aux parties prenantes
* Renforcement des contrôles d'accès distant et exercice de retour d'expérience

#### Phase 5 — Threat Hunting (proactif)

* Recherche d'exploitations historiques de passerelles edge (Fortinet, VPN) dans les journaux
* Chasse aux usages de Rclone et outils de transfert de fichiers vers des domaines de stockage inconnus
* Recherche de comptes créés ou modifiés pendant la fenêtre de compromission
* Analyse des tâches planifiées et services Windows suspects sur les serveurs fichiers
* Surveillance du site de fuite Qilin pour toute mention de l'organisation, de ses filiales ou partenaires

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Chiffrement des données pour impact (extorsion par rançongiciel) |
| **T1490** | Inhibition de la récupération système (suppression des sauvegardes et instantanés) |
| **T1567** | Exfiltration de données vers un service web (site de fuite, double extorsion) |

---

### Sources

* [https://www.ransomlook.io//group/qilin](https://www.ransomlook.io//group/qilin)


---

<div id="bigbear-20-le-service-de-phishing-as-a-service-contourne-le-mfa-de-258-organisations-et-vole-plus-de-5-000-identifiants-microsoft-365"></div>

## BigBear 2.0 : le service de phishing-as-a-service contourne le MFA de 258 organisations et vole plus de 5 000 identifiants Microsoft 365

### Résumé

Le service de phishing-as-a-service (PhaaS) « BigBear 2.0 » a permis de contourner l'authentification multifacteur (MFA) de 258 organisations et de dérober plus de 5 000 identifiants Microsoft 365. Les attaques reposent sur des techniques adversary-in-the-middle (AiTM) avec vol de jetons de session. Selon l'article, les kits PhaaS actuels sont désormais capables de contourner à grande échelle les stratégies d'accès conditionnel et les invites MFA.

---

### Analyse opérationnelle

Impact opérationnel direct : le MFA par OTP/push ne constitue plus un contrôle suffisant face aux kits AiTM. Mesures techniques prioritaires : migrer vers une authentification résistante au hameçonnage (FIDO2/passkeys), exiger des appareils conformes dans l'accès conditionnel, activer la détection de vol de jetons (connexions sans événement MFA correspondant, impossible travel, incohérences d'agent utilisateur), révoquer systématiquement les sessions en cas de suspicion, et surveiller les règles de boîte aux lettres et consentements OAuth créés après compromission. Bloquer l'infrastructure PhaaS connue via les flux de threat intelligence et les journaux proxy/DNS.

---

### Implications stratégiques

La montée en puissance du modèle PhaaS démontre l'industrialisation du hameçonnage : des capacités autrefois réservées à des acteurs étatiques (contournement du MFA par AiTM) sont désormais louées à grande échelle à des acteurs criminels de tous niveaux. Les organisations doivent réviser leurs hypothèses de risque : la conformité MFA seule ne protège plus contre la compromission de compte. Cela a des conséquences sur les exigences des assureurs cyber, les cadres de conformité (NIS2, contrôles d'authentification) et les budgets sécurité, avec un déplacement nécessaire vers les passkeys, la liaison de jetons et la détection comportementale des sessions.

---

### Recommandations

* Déployer des méthodes d'authentification résistantes au hameçonnage (FIDO2, passkeys) en priorité pour les comptes à privilèges et les exécutifs
* Renforcer l'accès conditionnel : appareils conformes, évaluation du risque de connexion, restrictions de localisation
* Révoquer les sessions et réenregistrer le MFA immédiatement en cas de suspicion de vol de jeton
* Détecter les connexions sans événement MFA correspondant et les règles de boîte aux lettres frauduleuses
* Bloquer l'infrastructure PhaaS connue et intégrer les indicateurs BigBear 2.0 aux contrôles de passerelle

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer une authentification multifacteur résistante au hameçonnage (clés FIDO2, passkeys, Windows Hello for Business)
* Renforcer les stratégies d'accès conditionnel : exigence d'appareils conformes/enregistrés, restrictions par localisation et par risque
* Activer la journalisation avancée (sign-in logs, audit logs, Unified Audit Log) et centraliser dans le SIEM
* Déployer DMARC/DKIM/SPF en mode strict et des simulations de hameçonnage régulières axées sur le vol de jetons
* Sensibiliser les utilisateurs aux pages de connexion intermédiaires et aux proxys de hameçonnage AiTM

#### Phase 2 — Détection et analyse

* Alerter sur les connexions présentant une incohérence entre l'agent utilisateur et l'appareil déclaré, ou un changement brutal de localisation (impossible travel)
* Détecter les sessions authentifiées sans événement MFA correspondant (signature typique du vol de jeton)
* Surveiller les enregistrements MFA inhabituels, les ajouts de méthodes d'authentification et les consentements d'applications OAuth récents
* Détecter les règles de boîte aux lettres créées post-connexion (redirections, transferts) et les recherches massives dans les courriels
* Corréler les indicateurs d'infrastructure PhaaS connus (domaines, certificats, empreintes de kits) avec les journaux proxy et DNS

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement toutes les sessions et jetons de rafraîchissement des comptes compromis (Revoke Sessions dans Entra ID)
* Réinitialiser les mots de passe et réenregistrer les méthodes MFA des comptes affectés
* Bloquer les adresses IP, domaines et URLs de l'infrastructure AiTM identifiée (proxy, DNS, pare-feu, passerelle mail)
* Mettre en quarantaine les messages de hameçonnage et purger les copies distribuées
* Appliquer temporairement des stratégies d'accès conditionnel restrictives (blocage géographique, exigence d'appareil conforme)

#### Phase 4 — Activités post-incident

* Analyser l'activité post-compromission : accès aux courriels, exfiltration de données, règles de redirection, applications OAuth consenties
* Identifier les données consultées ou exfiltrées et notifier les parties prenantes conformément aux obligations légales
* Vérifier l'absence de persistance (règles de boîte, délégations, comptes secondaires, enregistrements d'appareils malveillants)
* Documenter la chronologie de l'intrusion et mettre à jour les règles de détection et les stratégies d'accès conditionnel

#### Phase 5 — Threat Hunting (proactif)

* Chasser les sessions Microsoft 365 authentifiées depuis des AS/IP jamais observés pour l'utilisateur, notamment des hébergeurs résidentiels ou VPN
* Rechercher les connexions réussies sans correspondance MFA dans les journaux de connexion
* Identifier les boîtes aux lettres avec règles de redirection cachées (marquées IsInboxRule) ou délégations inhabituelles
* Rechercher les consentements OAuth à des applications tierces suspectes accordés après une connexion à risque
* Croiser les journaux historiques avec les indicateurs d'infrastructure BigBear 2.0 publiés par les sources de threat intelligence

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Phishing: Spearphishing Link |
| **T1557** | Adversary-in-the-Middle |
| **T1539** |  |
| **T1078** | Valid Accounts |

---

### Sources

* [https://databreaches.net/2026/09/07/bigbear-microsoft-365-phishing-service-bypassed-mfa-at-258-organizations/](https://databreaches.net/2026/09/07/bigbear-microsoft-365-phishing-service-bypassed-mfa-at-258-organizations/)
* [https://www.bleepingcomputer.com/news/security/bigbear-microsoft-365-phishing-service-bypassed-mfa-at-258-organizations/](https://www.bleepingcomputer.com/news/security/bigbear-microsoft-365-phishing-service-bypassed-mfa-at-258-organizations/)


---

<div id="320-m-en-bitcoins-draines-du-liquid-network-les-auteurs-se-revendiquent-les-gentils"></div>

## 320 M$ en bitcoins drainés du Liquid Network ; les auteurs se revendiquent « les gentils »

### Résumé

Le 7 septembre 2026, DataBreaches.net rapporte que des pirates ont drainé environ 320 millions de dollars en bitcoins du Liquid Network (sidechain de Bitcoin). Les auteurs ont revendiqué publiquement l'opération en se présentant comme « the good guys », un cadrage auto-proclamé non vérifié à ce stade. Le vecteur d'intrusion exact n'est pas détaillé dans la source.

---

### Analyse opérationnelle

Pour les entités opérant des infrastructures d'actifs numériques : revue de la gestion des clés (HSM, multisig, seuils de signature), journalisation des accès privilégiés, surveillance on-chain des flux et alertes sur les retraits massifs. En cas d'incident : coordination avec les plateformes d'échange pour le gel des fonds, recours à des firmes d'analyse de chaîne, préservation des journaux d'infrastructure pour identifier l'accès initial et le périmètre compromis.

---

### Implications stratégiques

Un vol de cette ampleur alimente l'économie du blanchiment en crypto-actifs et accroît le risque systémique pour les infrastructures d'actifs numériques (fédérations, sidechains, custodians). La revendication « good guys » peut signaler une tentative de légitimation, une extorsion déguisée ou une dynamique de restitution partielle — scénarios à intégrer dans la gestion de crise. Le secteur s'expose à un renforcement réglementaire et à une défiance accrue des investisseurs et partenaires institutionnels.

---

### Recommandations

* Revoir l'architecture de custody (multisig, HSM, séparation des duties) des infrastructures d'actifs numériques
* Déployer la surveillance on-chain avec alertes sur les flux massifs et adresses à risque
* Préparer les contacts de gel d'urgence avec plateformes d'échange et firmes d'analyse de chaîne
* Journaliser et corréler les accès privilégiés aux systèmes de signature dans un SIEM
* Documenter un plan de communication de crise spécifique aux incidents crypto

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Custody des clés en HSM/multisig avec seuils de signature et séparation des duties
* Journalisation et alerting des accès privilégiés aux systèmes de signature et d'orchestration
* Surveillance on-chain continue avec listes de surveillance (mixers, bridges, adresses sanctionnées)
* Plan de réponse incident crypto : contacts plateformes d'échange, firmes d'analyse de chaîne, autorités (IC3)
* Exercices de rotation de clés et procédures de gel d'urgence documentées

#### Phase 2 — Détection et analyse

* Alertes sur retraits massifs ou séries de transactions anormales depuis les portefeuilles chauds
* Usage anormal des clés de fédération ou signatures hors fenêtres/processus attendus
* Anomalies d'accès privilégié aux infrastructures de signature (heures, IP, comptes)
* Surveillance mempool et flux on-chain pour détecter des mouvements inhabituels
* Alertes sur modifications de configuration des nœuds et services de signature

#### Phase 3 — Confinement, éradication et récupération

* Coordination immédiate avec les plateformes d'échange et firmes d'analyse de chaîne pour tracer/geler les fonds
* Isolation des systèmes compromis et suspension des flux de retrait automatiques
* Rotation d'urgence des clés et reconfiguration multisig
* Préservation des journaux d'infrastructure pour identifier l'accès initial
* Communication de crise interne et vers les contreparties concernées

#### Phase 4 — Activités post-incident

* Signalement aux autorités compétentes (IC3, juridictions locales) et dépôt de dossier d'analyse de chaîne
* Analyse de cause racine : vecteur d'intrusion, compromission de clés ou de processus de signature
* Divulgation maîtrisée aux clients/utilisateurs et décisions de compensation
* Renforcement de l'architecture de custody et des contrôles de signature
* Retour d'expérience partagé avec l'écosystème (fédérations, custodians)

#### Phase 5 — Threat Hunting (proactif)

* Suivi des fonds à travers mixers, bridges et sauts de chaîne avec outils d'analyse on-chain
* Recherche dans les journaux d'infrastructure d'un accès initial antérieur non détecté
* Chasse aux artefacts de compromission sur les systèmes de signature (webshells, outils de tunneling)
* Surveillance des canaux criminels et forums pour détecter des mouvements de fonds ou des revendications complémentaires
* Corrélation des adresses de réception avec les bases d'IoC et listes de sanctions

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1657** | Vol financier (drainage de fonds en crypto-actifs) |

---

### Sources

* [https://databreaches.net/2026/09/07/hackers-drain-320m-in-bitcoin-from-liquid-network-claim-theyre-the-good-guys/](https://databreaches.net/2026/09/07/hackers-drain-320m-in-bitcoin-from-liquid-network-claim-theyre-the-good-guys/)


---

<div id="shinyhunters-offre-dachat-des-donnees-nexus-dl-et-menaces-de-publication-visant-le-dmv-de-floride"></div>

## ShinyHunters : offre d'achat des données « Nexus DL » et menaces de publication visant le DMV de Floride

### Résumé

Le 4 septembre 2026, ShinyHunters a publié un message adressé à DataBroker1 (acteur ayant listé les données « Nexus DL », des permis de conduire), proposant un paiement « équivalent à une rançon » pour obtenir ces données, avec le contact shinygroup[@]onionmail[.]com. Le 7 septembre 2026, ShinyHunters a publiquement sommé le DMV de l'État de Floride de le contacter sous peine de publication des fichiers, avec échantillons en preuve et échéance fixée au 11 septembre 2026. La chronologie suggère une tentative d'acquisition ou de contrôle du jeu de données et une campagne d'extorsion en cours contre l'État de Floride.

---

### Analyse opérationnelle

Ajouter shinygroup[@]onionmail[.]com aux indicateurs de contact de l'acteur et surveiller ses canaux de publication (forums, réseaux infosec). Toute organisation détenant des données de permis de conduire (DMV, assureurs, fintechs, processus KYC) doit vérifier si ses données figurent dans le jeu « Nexus DL », préparer la détection de fraude documentaire et anticiper une publication. Suivre l'échéance du 11/09/2026 pour corréler une éventuelle fuite avec les échantillons déjà diffusés.

---

### Implications stratégiques

Cette séquence illustre l'émergence d'un marché secondaire d'extorsion où des acteurs rachètent des jeux de données à des courtiers (data brokers) pour relancer eux-mêmes la pression sur les victimes. Les données de permis de conduire alimentent la fraude à l'identité, l'ouverture de comptes et le contournement KYC. Cibler un DMV d'État américain maximise la visibilité médiatique et le risque réglementaire ; les entités détenant des PII similaires doivent revoir leur posture de notification et de prévention de la fraude.

---

### Recommandations

* Surveiller les publications de ShinyHunters et les listings de DataBroker1 (forums, canaux spécialisés)
* Vérifier si des données de l'organisation ou de ses clients apparaissent dans les échantillons « Nexus DL »
* Renforcer la détection de fraude documentaire et les contrôles KYC (vérification des permis)
* Bloquer/signaler l'adresse de contact de l'acteur et documenter toute sollicitation pour les autorités
* Préparer un plan de notification en cas de confirmation de fuite de PII

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les détentions de données de permis de conduire et autres PII sensibles (DMV, KYC, assureurs)
* Mettre en place une veille des forums de fuite, canaux de l'acteur et marketplaces de données
* Définir une chaîne d'escalade extorsion (juridique, communication, direction, autorités)
* Établir des contacts préalables avec les autorités (FBI/IC3) et les services de monitoring de fuites
* Documenter la politique de réponse à l'extorsion (refus de paiement, notification, prévention de la fraude)

#### Phase 2 — Détection et analyse

* Surveiller les publications de ShinyHunters et les listings de DataBroker1 (forums, réseaux sociaux, canaux spécialisés)
* Activer le monitoring de fuites pour les PII de l'organisation et de ses clients (permis, identifiants)
* Suivre l'échéance annoncée (11/09/2026) et corréler toute publication avec les échantillons diffusés
* Détecter les sollicitations d'extorsion entrantes (messagerie, formulaires, réseaux sociaux) et les documenter
* Surveiller les signaux de fraude documentaire (tentatives d'ouverture de comptes avec permis compromis)

#### Phase 3 — Confinement, éradication et récupération

* En cas de confirmation de fuite : activer la cellule de crise juridique/communication et alerter les autorités
* Ne pas engager de paiement ; documenter toutes les interactions avec l'acteur comme preuves
* Demander des retraits (takedowns) auprès des plateformes hébergeant les données
* Bloquer/signaler l'adresse de contact de l'acteur et préserver les messages reçus
* Renforcer temporairement les contrôles KYC et de vérification d'identité

#### Phase 4 — Activités post-incident

* Notifier les personnes concernées conformément aux obligations légales et proposer un suivi (surveillance d'identité)
* Déterminer l'origine de la compromission (source du jeu de données Nexus DL) et corriger le point d'entrée
* Coordonner avec les régulateurs et les autorités d'État compétentes
* Renforcer la protection des référentiels de PII (chiffrement, minimisation, contrôles d'accès)
* Bilan d'extorsion : impact réputationnel, coûts, efficacité de la réponse

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des échantillons « Nexus DL » dans les bases internes et les jeux de données exposés historiquement
* Analyser les accès massifs ou anormaux aux référentiels de PII (journaux d'accès base de données)
* Surveiller les marketplaces et canaux de revente pour détecter des PII de l'organisation ou de ses clients
* Corréler l'adresse de contact de l'acteur et ses pseudonymes avec les incidents d'extorsion antérieurs
* Suivre les infrastructures de l'acteur (comptes forums, adresses de contact) pour anticiper les prochaines campagnes

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1657** | Vol financier / extorsion : menace de publication de données contre paiement |

---

### Sources

* [https://infosec.exchange/@PogoWasRight/117231818213330103](https://infosec.exchange/@PogoWasRight/117231818213330103)


---

<div id="la-police-ukrainienne-demantele-un-vaste-reseau-de-fraude-aux-cryptomonnaies-a-kyiv"></div>

## La police ukrainienne démantèle un vaste réseau de fraude aux cryptomonnaies à Kyiv

### Résumé

La police ukrainienne a démantelé à Kyiv un vaste réseau criminel spécialisé dans la fraude aux cryptomonnaies. Selon l'article, ce syndicat illicite a dérobé des millions de dollars à des investisseurs internationaux. Aucun détail supplémentaire sur les modes opératoires précis, le nombre d'arrestations ou les infrastructures saisies n'est fourni dans la source.

---

### Analyse opérationnelle

Pour les équipes SOC et de prévention de la fraude : ce type de réseau repose typiquement sur de fausses plateformes d'investissement, du social engineering à grande échelle et des infrastructures de collecte de fonds en cryptomonnaies. Il convient de déployer des règles de détection sur les passerelles mail (sollicitations d'investissement, domaines récemment enregistrés imitant des plateformes d'échange), de surveiller les transactions sortantes atypiques et de bloquer les domaines frauduleux identifiés. Les organisations exposées à des clients investisseurs doivent renforcer les alertes sur les virements vers des plateformes d'échange inconnues.

---

### Implications stratégiques

Cette opération confirme le rôle de l'Ukraine comme théâtre actif de la cybercriminalité financière et la capacité de ses forces de l'ordre à mener des démantèlements de grande ampleur malgré le contexte de conflit. La fraude aux cryptomonnaies visant des investisseurs internationaux reste une menace rentable et peu risquée pour les acteurs criminels. Pour les entreprises du secteur financier et les investisseurs, cela impose une due diligence renforcée sur les plateformes d'investissement et une coopération internationale accrue avec les autorités.

---

### Recommandations

* Sensibiliser les employés et clients aux schémas de fraude à l'investissement en cryptomonnaies
* Bloquer proactivement les domaines de fausses plateformes d'échange via les flux de threat intelligence
* Signaler toute sollicitation frauduleuse aux autorités compétentes (police, IC3, régulateurs)
* Renforcer les contrôles KYC/AML sur les transactions en actifs numériques

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser les employés et clients aux schémas de fraude à l'investissement en cryptomonnaies (fausses plateformes d'échange, promesses de rendements garantis)
* Établir des procédures de signalement interne des tentatives de fraude et des sollicitations d'investissement suspectes
* Mettre en place une veille sur les infrastructures de fraude (domaines frauduleux, faux sites d'échange) en lien avec des flux de threat intelligence
* Pour les organisations financières : renforcer les contrôles KYC/AML et la surveillance des transactions en actifs numériques
* Identifier les contacts des autorités compétentes (police, régulateurs financiers, plateformes d'échange) pour les signalements

#### Phase 2 — Détection et analyse

* Surveiller les passerelles de messagerie pour détecter les sollicitations d'investissement frauduleuses et les liens vers de fausses plateformes
* Analyser les transactions financières sortantes atypiques et les demandes de virement vers des plateformes d'échange inconnues
* Contrôler le trafic web sortant vers des domaines récemment enregistrés imitant des plateformes d'échange légitimes
* Corréler les alertes DLP et les accès à des portefeuilles numériques depuis le réseau de l'entreprise

#### Phase 3 — Confinement, éradication et récupération

* Bloquer immédiatement les domaines, URLs et adresses de portefeuilles identifiés comme frauduleux (proxy, DNS, passerelle mail)
* Geler ou suspendre les transactions suspectes en coordination avec les plateformes d'échange concernées
* Isoler et réinitialiser les comptes internes ayant interagi avec l'infrastructure frauduleuse
* Préserver les preuves (journaux, courriels, captures des faux sites) avant toute remédiation destructive

#### Phase 4 — Activités post-incident

* Signaler l'incident aux autorités (police nationale, IC3, régulateur financier) et coopérer avec les enquêtes en cours
* Notifier les victimes internes ou clientes et documenter les pertes financières
* Réaliser une analyse forensique des flux financiers et des communications avec le réseau frauduleux
* Mettre à jour les procédures de sensibilisation et les règles de détection sur la base des enseignements

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux proxy/DNS toute interaction historique avec les domaines et serveurs du réseau démantelé
* Chasser les courriels antérieurs liés à la campagne de fraude dans les boîtes aux lettres (recherche par mots-clés et expéditeurs)
* Vérifier les adresses de portefeuilles connues du réseau dans les journaux de transactions et de communications
* Effectuer une veille OSINT sur les infrastructures résiduelles et les relances possibles du réseau sous d'autres marques

---

### Sources

* [https://meterpreter.org/ukraine-cryptocurrency-fraud-network/](https://meterpreter.org/ukraine-cryptocurrency-fraud-network/)
