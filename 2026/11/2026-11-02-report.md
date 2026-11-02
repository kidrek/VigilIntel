# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [Extraction de fichiers OneNote, (dim. 1er novembre)](#extraction-de-fichiers-onenote-dim-1er-novembre)
  * [SentinelOne Prompt Security : de quoi s'agit-il et comment je l'ai réellement testé](#sentinelone-prompt-security-de-quoi-sagit-il-et-comment-je-lai-reellement-teste)
  * [Présentation de pathrunner : un framework d'élévation de privilèges AWS](#presentation-de-pathrunner-un-framework-delevation-de-privileges-aws)
  * [Empreinte GPU à partir de l'ordonnancement des additions atomiques — précision de 99,1 %, survit aux redémarrages, fonctionne même entre modèles de GPU identiques dans des environnements cloud partagés. L'implication : « même matériel » ne signifie pas « même empreinte ». Les hypothèses d'isolation dans les infrastructures GPU multi-tenant méritent un second regard.#infosec #fingerprinting #GPU https://infosec.pub/post/54379636](#empreinte-gpu-a-partir-de-lordonnancement-des-additions-atomiques-precision-de-991-survit-aux-redemarrages-fonctionne-meme-entre-modeles-de-gpu-identiques-dans-des-environnements-cloud-partages-limplication-meme-materiel-ne-signifie-pas-meme-empreinte-les-hypotheses-disolation-dans-les-infrastructures-gpu-multi-tenant-meritent-un-second-regardinfosec-fingerprinting-gpu-httpsinfosecpubpost54379636)
  * [« Scénario cauchemar » : un spyware zero-click infecte les téléphones via des publicités ciblées](#scenario-cauchemar-un-spyware-zero-click-infecte-les-telephones-via-des-publicites-ciblees)
  * [Des villes signalent des problèmes pour mettre fin aux programmes de caméras Flock. Le chef de la police de Plymouth affirme avoir débranché les lecteurs de plaques après que le fournisseur n'a pas répondu. Dayton indique que les caméras ont été réactivées malgré une pause.](#des-villes-signalent-des-problemes-pour-mettre-fin-aux-programmes-de-cameras-flock-le-chef-de-la-police-de-plymouth-affirme-avoir-debranche-les-lecteurs-de-plaques-apres-que-le-fournisseur-na-pas-repondu-dayton-indique-que-les-cameras-ont-ete-reactivees-malgre-une-pause)
  * [Possible Phishing 🎣 on: ⚠️hxxps[:]//web-fun-checkout-prototype-uniswap[.]vercel[.]app/explore/pools/ethereum/0x21b8065d10f73ee2e260e5b47d3344d3ced7596e](#possible-phishing-on-hxxpsweb-fun-checkout-prototype-uniswapvercelappexplorepoolsethereum0x21b8065d10f73ee2e260e5b47d3344d3ced7596e)
  * [Alpine Linux reconstruit GitLab après une tentative d'attaque RCE](#alpine-linux-reconstruit-gitlab-apres-une-tentative-dattaque-rce)
  * [Évaluation par IA : priorisation des victimes pilotée par modèle dans l'infostealer VOLTA](#evaluation-par-ia-priorisation-des-victimes-pilotee-par-modele-dans-linfostealer-volta)
  * [Le malware NetamLoader cible les systèmes gouvernementaux Windows 10 en Asie via une injection .NET](#le-malware-netamloader-cible-les-systemes-gouvernementaux-windows-10-en-asie-via-une-injection-net)
  * [Les agents IA ne signent pas de NDA](#les-agents-ia-ne-signent-pas-de-nda)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

Le corpus quotidien de 70 items est dominé par les vulnérabilités (33) et les fuites de données (20), qui représentent à eux seuls plus des trois quarts du volume. Cette répartition impose une priorisation opérationnelle vers la gestion des correctifs et la surveillance des expositions, plutôt que vers une réponse large aux acteurs de menace. Les 3 items threat_actors suggèrent une activité adverse ciblée mais peu documentée dans le flux, à corréler avec les vulnérabilités critiques et les incidents de fuite. Le faible volume géopolitique (1) et réglementaire (2) ne doit pas être ignoré, car ces signaux peuvent annoncer des changements de risque pays ou de conformité. Les 11 articles de contexte servent à qualifier les tendances et à éviter une lecture purement quantitative des 20 fuites et 33 vulnérabilités. Recommandation : émettre un bulletin interne priorisant les vulnérabilités exploitables et les fuites à impact client, avec revue des acteurs ciblant l’organisation. Surveiller l’évolution sur 24-48 h pour détecter une éventuelle hausse géopolitique ou réglementaire.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **Booba Project** |  | Extorsion double et fuite de données; détails non fournis. | T1133, T1078, T1486, T1657 | [https://cti.fyi/blog/this-week-in-ransomware-2026-10-25-to-2026-11-01.html](https://cti.fyi/blog/this-week-in-ransomware-2026-10-25-to-2026-11-01.html)<br>[https://infosec.exchange/@CTI_FYI/117543431858072833](https://infosec.exchange/@CTI_FYI/117543431858072833)<br>`hxxps://cti[.]fyi/blog/this-week-in-ransomware-2026-10-25-to-2026-11-01[.]html` |
| **DragonForce** |  | Extorsion double et fuite de données; détails non fournis. | T1133, T1078, T1486, T1657 | [https://cti.fyi/blog/this-week-in-ransomware-2026-10-25-to-2026-11-01.html](https://cti.fyi/blog/this-week-in-ransomware-2026-10-25-to-2026-11-01.html)<br>[https://infosec.exchange/@CTI_FYI/117543431858072833](https://infosec.exchange/@CTI_FYI/117543431858072833)<br>`hxxps://cti[.]fyi/blog/this-week-in-ransomware-2026-10-25-to-2026-11-01[.]html` |
| **Caramel Tsunami (alias : Candiru)** | mobile, société civile, journalistes | Malvertising/waterhole, exploitation zero-click, obfuscation, surveillance mobile. | T1189, T1583.008, T1027, T1437 | [https://www.wired.com/story/nightmare-scenario-zero-click-spyware-is-infecting-phones-via-targeted-ads/](https://www.wired.com/story/nightmare-scenario-zero-click-spyware-is-infecting-phones-via-targeted-ads/) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Corée du Nord, Asie de l'Est, États-Unis** | Cryptomonnaies / Services financiers numériques | Attribution étatique d'un piratage de plateforme crypto et gestion de crise opérationnelle | Le piratage de la plateforme Binance, qualifié de « casse du siècle », fait l'objet d'une attribution publique par le FBI à la Corée du Nord. Cette séquence illustre la continuité de la doctrine nord-coréenne de financement du régime par le vol de crypto-actifs, généralement opérée par des groupes rattachés à l'appareil de renseignement militaire (Lazarus et ses dérivés). L'attribution par une agence fédérale américaine, et non par la seule entreprise victime, transforme l'incident en dossier géopolitique : elle ouvre la voie à des mesures de sanctions, à des actions de perturbation des infrastructures de blanchiment et à une pression diplomatique accrue. La réouverture annoncée des retraits constitue un signal de reprise de contrôle partiel, mais elle reste un indicateur à surveiller : elle peut exposer la plateforme à des retraits de précaution massifs, à des mouvements de fonds suspects cherchant à profiter de la reprise de liquidité, et à un risque de seconde vague d'incidents (hameçonnage des utilisateurs, usurpation de communication officielle). L'absence de détails techniques publics sur le vecteur d'intrusion limite l'évaluation de la contagion à d'autres plateformes utilisant des composants similaires. Sur le plan de la réponse internationale, l'attribution unilatérale américaine renforce la fragmentation des régimes de conformité : les échanges devront arbitrer entre exigences de gel des avoirs liés à la RPDC, obligations de remboursement des clients et pressions réglementaires locales. | [https://www.lemonde.fr/pixels/article/2026/11/01/piratage-de-la-plateforme-de-cryptomonnaies-binance-la-plateforme-annonce-rouvrir-les-retraits-le-fbi-accuse-la-coree-du-nord-du-casse-du-siecle_6803867_4408997.html](https://www.lemonde.fr/pixels/article/2026/11/01/piratage-de-la-plateforme-de-cryptomonnaies-binance-la-plateforme-annonce-rouvrir-les-retraits-le-fbi-accuse-la-coree-du-nord-du-casse-du-siecle_6803867_4408997.html) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| CTI-RL-2026-11-01-001 | Polymarket (plateforme de marché de prédiction), DebugBear (prestataire de monitoring RUM), registraire du domaine DebugBear, autorités répressives (saisine annoncée par Polymarket) | 2026-11-01 | International — opérateurs et prestataires de droit américain, victimes (726 portefeuilles remboursés) réparties sur plusieurs juridictions | CTI-RL-2026-11-01-001 | Le 29 octobre 2026, Polymarket a subi une attaque de chaîne d'approvisionnement logicielle qui a vidé environ 2,7 M$ des portefeuilles de 726 traders. Le vecteur n'est pas l'infrastructure de Polymarket mais le prestataire tiers DebugBear : les enregistrements DNS de cdn.debugbear[.]com ont été détournés au niveau du registraire, redirigeant le script de monitoring RUM chargé par la plateforme vers un serveur attaquant servant un drainer de 15 Ko. Le script malveillant, exécuté avec les privilèges du code first-party, lisait les identifiants stockés dans le local storage du navigateur (polymarket.auth.params, poly_clob_api_key_map), recherchait le signer dans l'arbre de composants React, puis faisait signer des transferts et des ventes soumis via le relayer de Polymarket vers l'adresse 0x3F99139F1C5854bb628c2e576Aaf638e99dFfc18. La trace on-chain montre 28,6 M de tokens POL collectés entre 17:10 et 18:02 UTC, valorisés environ 2,64 M$, puis dispersés vers trois adresses entre 18:28 et 18:38 UTC. Sur le plan réglementaire et juridique, l'incident illustre plusieurs angles : (1) responsabilité contractuelle et extracontractuelle du prestataire compromis — DebugBear indique n'avoir constaté aucune intrusion dans ses propres systèmes et cible une attaque visant un seul client, ce qui déplace le débat sur la faute du registraire et sur la répartition des obligations de sécurité dans la chaîne contractuelle ; (2) obligations de notification — Polymarket a publié un premier statut à 17:38 UTC, retiré le script en moins d'une heure, purgé les caches, réinitialisé les sessions et suspendu le trading, puis a saisi les autorités répressives, sans qu'aucune obligation de plainte des utilisateurs ne soit requise ; (3) traitement des préjudices — remboursement d'environ 2,7 M$ aux 726 portefeuilles affectés, complété par 1,19 M$ vers environ 5 500 portefeuilles lésés pendant la pause de trading, soit 3,9 M$ au total, ce qui constitue une indemnisation volontaire sans reconnaissance de responsabilité formelle publiée ; (4) limites des dispositifs de conformité techniques — la CSP de Polymarket autorisait tous les hôtes contactés par le drainer puisqu'il s'agissait d'hôtes déjà légitimes, et aucune exigence normative n'imposait le Subresource Integrity (SRI) sur le script tiers, ce qui montre que les cadres de sécurité réglementaires (NIS2, DORA pour les entités européennes recourant à des prestataires TIC, exigences de l'ACPR/AMF pour les acteurs crypto enregistrés en France) doivent être explicitement déclinés en contrôles sur le code tiers et la surface DNS. L'absence de fuite de clés privées, de phrases de récupération ou de mots de passe selon Hudson Rock réduit l'exposition au titre des notifications de violation de données personnelles, mais les identifiants de session et clés API dérobés dans le navigateur restent des données d'authentification sensibles justifiant une analyse de qualification au regard du RGPD. | [https://beyondmachines.net/event_details/polymarket-supply-chain-attack-drains-2-7-million-via-hijacked-third-party-script-z-0-0-c-b/gD2P6Ple2L](https://beyondmachines.net/event_details/polymarket-supply-chain-attack-drains-2-7-million-via-hijacked-third-party-script-z-0-0-c-b/gD2P6Ple2L)<br>[https://thehackernews.com/2026/11/hackers-steal-about-27-million-from.html](https://thehackernews.com/2026/11/hackers-steal-about-27-million-from.html) |
| CTI-RL-2026-10-31-002 | Name.com (registraire accrédité ICANN), Blockaid (société de sécurité), projets DeFi Flap et Kintsu (victimes confirmées) | 2026-10-31 | International — registraire accrédité ICANN soumis aux obligations du RAA, victimes et projets répartis sur plusieurs juridictions | CTI-RL-2026-10-31-002 | Entre le 30 et le 31 octobre 2026, 15 domaines clients de Name.com, dont 10 liés à Vercel, ont été détournés au niveau du registraire. Au moins 12 sites de projets DeFi ont servi des pages d'apparence légitime hébergeant le « Step Drainer », qui incitait les visiteurs à signer des transactions frauduleuses ; les pertes on-chain sont estimées à environ 138 000 $. Les contrats intelligents des projets ciblés sont restés intacts : seule la couche front-end et la résolution DNS ont été compromises. Dix domaines ont été placés en statut « client hold » avant restauration, statut qui suspend temporairement toute résolution. Name.com a reconnu publiquement la redirection abusive, restauré les domaines et recommandé la revue des paramètres DNS et l'activation de l'authentification à deux facteurs. Sur le plan réglementaire, l'incident soulève la question de la responsabilité du registraire au titre de l'Accreditation Agreement ICANN (RAA) : obligations de sécurité raisonnable, de protection des données de compte, de notification aux titulaires de noms de domaine et de coopération avec les enquêtes. Le vecteur d'entrée initial reste inconnu, ce qui empêche à ce stade d'établir une faute caractérisée, mais l'absence de divulgation détaillée sur les contrôles d'accès au panneau de registraire et sur les délais de détection constitue un risque réputationnel et contentieux. Les projets ayant migré rapidement leurs serveurs de noms vers Vercel ou Cloudflare ont limité les pertes, ce qui plaide pour l'inscription d'un playbook registraire dans les plans de réponse à incident. Aucune obligation de notification RGPD n'est établie à ce stade, les données personnelles des utilisateurs n'ayant pas été exfiltrées côté projets ; en revanche, la compromission de comptes clients du registraire peut relever d'une violation de données selon la nature des informations d'accès exposées. | [https://cryptobriefing.com/name-com-restores-hijacked-defi-domains/](https://cryptobriefing.com/name-com-restores-hijacked-defi-domains/) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Finance / Banque** | Neuf grandes banques sud-coréennes (non nommées publiquement) | Données financières de clients : identifiants de comptes, informations personnelles et éléments bancaires permettant la fraude et l'usurpation d'identité (périmètre exact non détaillé publiquement). | Dizaines de milliers de clients répartis sur neuf établissements bancaires | [https://cyber.netsecops.io/articles/amateur-hacker-uses-ai-to-breach-south-korean-banks/?utm_source=mastodon&utm_medium=social&utm_campaign=daily](https://cyber.netsecops.io/articles/amateur-hacker-uses-ai-to-breach-south-korean-banks/?utm_source=mastodon&utm_medium=social&utm_campaign=daily)<br>[https://mastodon.social/@netsecio/117543566970124585](https://mastodon.social/@netsecio/117543566970124585)<br>`hxxps://cyber[.]netsecops[.]io/articles/amateur-hacker-uses-ai-to-breach-south-korean-banks/` |
| **Technologie / Plateformes de développement cloud et services d'IA** | Northflank, Railway, OpenCode, Warp, Lightning AI, Fireworks AI, Andromeda, Zeabur, CommandCode | Clés API et secrets d'accès aux services d'IA (OpenAI, Anthropic et autres) stockés en variables d'environnement, ainsi que les identifiants d'accès aux plateformes de développement concernées. | 9 plateformes compromises, plus de 100 000 dollars d'usage frauduleux de services d'IA documentés | [https://cyber.netsecops.io/articles/black-october-attacks-hit-nine-ai-developer-platforms/?utm_source=mastodon&utm_medium=social&utm_campaign=daily](https://cyber.netsecops.io/articles/black-october-attacks-hit-nine-ai-developer-platforms/?utm_source=mastodon&utm_medium=social&utm_campaign=daily)<br>[https://mastodon.social/@netsecio/117543567172946307](https://mastodon.social/@netsecio/117543567172946307)<br>`hxxps://cyber[.]netsecops[.]io/articles/black-october-attacks-hit-nine-ai-developer-platforms/` |
| **Multi-secteurs — prédominance « Autre », services professionnels, santé, industrie manufacturière, éducation, technologie** | 184 organisations victimes divulguées sur les portails de fuite Tor et miroirs d'extorsion clearnet (multi-secteurs, multi-pays) | Données d'entreprise exfiltrées avant chiffrement : documents internes, données financières, informations RH et clients, données de propriété intellectuelle — périmètre variable selon les victimes. | 184 divulgations de victimes sur 7 jours (25 octobre – 1er novembre 2026) | [https://cti.fyi/blog/this-week-in-ransomware-2026-10-25-to-2026-11-01.html](https://cti.fyi/blog/this-week-in-ransomware-2026-10-25-to-2026-11-01.html)<br>[https://infosec.exchange/@CTI_FYI/117543431858072833](https://infosec.exchange/@CTI_FYI/117543431858072833)<br>`hxxps://cti[.]fyi/blog/this-week-in-ransomware-2026-10-25-to-2026-11-01[.]html` |
| **Multi-secteurs (agrégation hebdomadaire toutes industries)** | Multiples organisations non détaillées (agrégation hebdomadaire de violations) | Non détaillé — catégories hétérogènes selon les violations agrégées (données clients, identifiants, données internes, données financières). | 390 violations de données revendiquées sur une période de 6 jours | [https://youtu.be/-WxzkSiuiLc](https://youtu.be/-WxzkSiuiLc)<br>[https://mastodon.social/@NickAEsp/117543518862387259](https://mastodon.social/@NickAEsp/117543518862387259)<br>[https://soundcloud.com/nickaesp/b2026-11-01](https://soundcloud.com/nickaesp/b2026-11-01)<br>[https://mastodon.social/@NickAEsp/117543518519287523](https://mastodon.social/@NickAEsp/117543518519287523)<br>`hxxps://youtu[.]be/-WxzkSiuiLc`<br>`hxxps://soundcloud[.]com/nickaesp/b2026-11-01` |
| **Secteur public — aménagement du territoire et développement régional (Land de Saxe-Anhalt, Allemagne)** | SALEG (Sachsen-Anhaltische Landesentwicklungsgesellschaft mbH) | Non divulgué par l'acteur. Aucun échantillon, listing de fichiers ni artefact de preuve publié. Données potentiellement concernées (hypothèse non vérifiée) : documentation de projets municipaux, données foncières et cadastrales, communications internes, données personnelles de collaborateurs et de contacts communaux. | Inconnu | [https://www.yazoul.net/intel/claim/2026-11-01-saleg-ransomware-claim-by-payload-october-2026/?utm_source=mastodon&utm_medium=social](https://www.yazoul.net/intel/claim/2026-11-01-saleg-ransomware-claim-by-payload-october-2026/?utm_source=mastodon&utm_medium=social)<br>[https://infosec.exchange/@Matchbook3469/117543033462958259](https://infosec.exchange/@Matchbook3469/117543033462958259)<br>`hxxps://www[.]yazoul[.]net/intel/claim/2026-11-01-saleg-ransomware-claim-by-payload-october-2026/` |
| **Commerce de détail — horlogerie / e-commerce (Japon)** | Seiko (boutiques en ligne japonaises : Grand Seiko Boutique, Seiko Online Store, Seiko Clock Online Store) — via le fournisseur tiers Swym | Numéros de cartes de paiement, noms des titulaires, cryptogrammes CVV, dates d'expiration. Aucune donnée personnelle stockée sur les systèmes Seiko confirmée comme compromise ; aucun accès aux comptes marchands ou données applicatives Swym rapporté. | Inconnu | [https://beyondmachines.net/event_details/seiko-disables-online-store-features-following-third-party-supply-chain-attack-n-x-r-e-q/gD2P6Ple2L](https://beyondmachines.net/event_details/seiko-disables-online-store-features-following-third-party-supply-chain-attack-n-x-r-e-q/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117542964124656994](https://infosec.exchange/@beyondmachines1/117542964124656994)<br>`hxxps://beyondmachines[.]net/event_details/seiko-disables-online-store-features-following-third-party-supply-chain-attack-n-x-r-e-q/gD2P6Ple2L` |
| **Secteur public — sécurité intérieure et application de la loi (États-Unis)** | US Department of Homeland Security (DHS) — employés | Données d'identification de plus de 40 000 employés du DHS : noms, fonctions, affectations, et éléments permettant d'identifier des personnels de surveillance, de renseignement humain et d'opérations sous couverture. | 40000 | [https://www.reuters.com/legal/government/leak-website-releases-data-tens-thousands-dhs-employees-2026-10-28/](https://www.reuters.com/legal/government/leak-website-releases-data-tens-thousands-dhs-employees-2026-10-28/)<br>[https://indieweb.social/@jbz/117542840931145905](https://indieweb.social/@jbz/117542840931145905)<br>`hxxps://www[.]reuters[.]com/legal/government/leak-website-releases-data-tens-thousands-dhs-employees-2026-10-28/` |
| **Services automobiles — gestion de flottes, cartes grises et démarches d'immatriculation (France)** | MPA Group (France) | Données de plus de 300 000 patients : ordonnances, données personnelles et éléments relatifs aux traitements médicaux. | 1100000 | [https://infonewscyber.fr/info/mpa-group-1-1-million-de-plaques-dimmatriculation-et-des-adresses-pers-e8ac4408e63ed145](https://infonewscyber.fr/info/mpa-group-1-1-million-de-plaques-dimmatriculation-et-des-adresses-pers-e8ac4408e63ed145)<br>[https://infosec.exchange/@infonewscyber/117542836686320563](https://infosec.exchange/@infonewscyber/117542836686320563)<br>`hxxps://infonewscyber[.]fr/info/mpa-group-1-1-million-de-plaques-dimmatriculation-et-des-adresses-pers-e8ac4408e63ed145`<br>[https://infonewscyber.fr/info/grande-pharmacie-bailly-plus-de-300-000-patients-revendiques-dans-une-59bb4c6f862011d9](https://infonewscyber.fr/info/grande-pharmacie-bailly-plus-de-300-000-patients-revendiques-dans-une-59bb4c6f862011d9)<br>[https://infosec.exchange/@infonewscyber/117542698883731874](https://infosec.exchange/@infonewscyber/117542698883731874)<br>`hxxps://infonewscyber[.]fr/info/grande-pharmacie-bailly-plus-de-300-000-patients-revendiques-dans-une-59bb4c6f862011d9` |
| **Secteur public — registre d'immatriculation des véhicules (Argentine)** | Registre national des immatriculations de véhicules (Argentine) — données revendiquées par « skyling » | Base SQL de 1,2 Go : plaques d'immatriculation, marque et modèle du véhicule, dates de transaction, noms des propriétaires, numéros de documents d'identité, adresses. | Inconnu | [https://go.darkwebsonar.io/skyling-mastodon](https://go.darkwebsonar.io/skyling-mastodon)<br>[https://infosec.exchange/@darkwebsonar/117542300835178539](https://infosec.exchange/@darkwebsonar/117542300835178539)<br>`hxxps://go[.]darkwebsonar[.]io/skyling-mastodon` |
| **Transport aérien — réservation de passagers (Malaisie / fournisseur GDS international)** | Malaysia Airlines (via le fournisseur tiers Amadeus) | Noms des passagers et références de réservation (PNR), dates et itinéraires de vol, classe de cabine et numéros de siège, adresses e-mail et numéros de téléphone, numéros de passeport et nationalités, numéros de programmes de fidélité. | Inconnu | [https://beyondmachines.net/event_details/malaysia-airlines-reports-three-year-data-exposure-via-amadeus-system-breach-r-y-1-z-c/gD2P6Ple2L](https://beyondmachines.net/event_details/malaysia-airlines-reports-three-year-data-exposure-via-amadeus-system-breach-r-y-1-z-c/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117541310623562969](https://infosec.exchange/@beyondmachines1/117541310623562969)<br>`hxxps://beyondmachines[.]net/event_details/malaysia-airlines-reports-three-year-data-exposure-via-amadeus-system-breach-r-y-1-z-c/gD2P6Ple2L` |
| **Énergie — production nucléaire / infrastructure critique (États-Unis, Texas)** | STP Nuclear Operating Co. (South Texas Project Electric Generating Station) | Données personnelles de 1 173 personnes : noms complets, numéros de sécurité sociale, dates de naissance et autres informations personnelles. | 1173 | [https://beyondmachines.net/event_details/stp-nuclear-operating-co-reports-data-breach-affecting-1173-texans-h-9-j-v-1/gD2P6Ple2L](https://beyondmachines.net/event_details/stp-nuclear-operating-co-reports-data-breach-affecting-1173-texans-h-9-j-v-1/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117540838787400962](https://infosec.exchange/@beyondmachines1/117540838787400962)<br>`hxxps://beyondmachines[.]net/event_details/stp-nuclear-operating-co-reports-data-breach-affecting-1173-texans-h-9-j-v-1/gD2P6Ple2L` |
| **Commerce de détail / e-commerce** | Asos (clients) et internautes exposés au vol d'identité par « jigsawing » de données personnelles | Dates de naissance, noms, adresses e-mail et postales, éventuellement numéros de téléphone et identifiants de comptes clients (données issues de la violation Asos et d'autres fuites retail agrégées). | Inconnu | `hxxps://www[.]theguardian[.]com/money/2026/nov/01/do-not-share-date-of-birth-online-scam-fraudsters-advice` |
| **Cryptomonnaies / exchange** | Binance | Identifiants et secrets d'accès d'un employé, clés API et de signature, sessions authentifiées, et in fine des actifs crypto (portefeuilles) pour un montant rapporté de 6,3 milliards de dollars. | Inconnu | `hxxps://justpaste[.]in/news/north-korean-hackers-blamed-for-stealing-record-6-3b-in-binance-breach/` |
| **Cloud / Platform-as-a-Service (PaaS) et développement logiciel** | Northflank (plateforme PaaS) et ses clients | Secrets et identifiants clients stockés sur la plateforme (clés API de fournisseurs d'IA, tokens de déploiement, variables d'environnement, éventuellement identifiants de services cloud tiers). | Inconnu | `hxxps://www[.]bleepingcomputer[.]com/news/security/northflank-security-breach-leads-to-abuse-of-customers-ai-api-keys/` |
| **Services financiers / caisses de pension (Suisse)** | Publica (plus grande caisse de pension suisse) | Données non confirmées à ce stade ; périmètre potentiel : données d'identification des assurés, coordonnées, informations financières et de retraite détenues par la caisse ou son prestataire logiciel. | Inconnu | `hxxps://mastodon[.]uno/[@]silvanomarioni/117539656227607292`<br>`hxxps://shattered[.]io/publica-swiss-pension-fund-breach-2026/` |
| **Blockchain intelligence / services financiers et conformité** | Chainalysis | User IDs, noms complets, adresses e-mail, libellés de rôle organisationnel ; pas de graphes d’enquête, notes, mots de passe en clair, identifiants d’authentification ni jetons de session selon Chainalysis. | Inconnu | `hxxps://www[.]bleepingcomputer[.]com/news/security/chainalysis-discloses-data-breach-from-offensive-agentic-techniques/`<br>[https://beyondmachines.net/event_details/chainalysis-repoers-data-breach-driven-by-ai-agentic-techniques-7-k-7-5-j/gD2P6Ple2L](https://beyondmachines.net/event_details/chainalysis-repoers-data-breach-driven-by-ai-agentic-techniques-7-k-7-5-j/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117540130990287195](https://infosec.exchange/@beyondmachines1/117540130990287195)<br>[https://thehackernews.com/2026/10/chainalysis-confirms-intrusion-into.html](https://thehackernews.com/2026/10/chainalysis-confirms-intrusion-into.html)<br>[https://infosec.exchange/@edwardk/117540608629302810](https://infosec.exchange/@edwardk/117540608629302810) |
| **Secteur public / sécurité intérieure** | US Department of Homeland Security (DHS) | Noms, adresses e-mail professionnelles, numéros de téléphone, adresses de bureaux, intitulés de poste, appartenance à des groupes Active Directory internes (dont groupes d'accès à Mobile Fortify et Penlink), répartition par unité (ICE, CBP, CISA) | 41000 | `hxxps://www[.]malwarebytes[.]com/blog/data-breaches/2026/10/hackers-steal-and-publish-data-on-41000-homeland-security-workers` |
| **Cloud / PaaS – hébergement d'applications** | Northflank | Clés API d'IA (abus confirmé), mots de passe de bases de données, identifiants de services cloud, jetons d'authentification, secrets stockés dans les workloads et les groupes globaux | Inconnu | `hxxps://beyondmachines[.]net/event_details/northflank-security-breach-exposes-customer-secrets-and-ai-api-keys-y-z-e-5-r/gD2P6Ple2L` |
| **** | Canton de Vaud – Direction générale de l'enseignement postobligatoire (DGEP) |  | Inconnu |  |
| **Ingénierie environnementale / Energy & Utilities (eau, eaux usées, déchets, bioremédiation)** | Groupe AC Environnement | Revendication non vérifiée : fichiers de projet et données employés ; aucun volume, échantillon ou preuve d’exfiltration fourni. | Inconnu | [https://www.yazoul.net/intel/claim/2026-10-31-groupe-ac-environnement-hit-by-thegentlemen-oct-2026/?utm_source=mastodon&utm_medium=social](https://www.yazoul.net/intel/claim/2026-10-31-groupe-ac-environnement-hit-by-thegentlemen-oct-2026/?utm_source=mastodon&utm_medium=social)<br>[https://mastodon.social/@Matchbook3469/117541570302220882](https://mastodon.social/@Matchbook3469/117541570302220882) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-118539** | N/A | N/A | FALSE | Drupal Commerce Core | Vulnérabilité critique (type exact non précisé) | Compromission potentielle des sites Drupal Commerce, pouvant entraîner une exécution de code à distance, un accès non autorisé aux données ou une altération du site. L'impact est critique sur la confidentialité, l'intégrité et la disponibilité. | Active | Appliquer les correctifs Drupal dès leur publication, surveiller les avis de sécurité Drupal, restreindre l'accès aux interfaces d'administration et déployer des règles WAF pour bloquer les tentatives d'exploitation. | [https://securityaffairs.com/202221/apt/fbi-blames-north-korea-for-6-billion-binance-crypto-theft.html](https://securityaffairs.com/202221/apt/fbi-blames-north-korea-for-6-billion-binance-crypto-theft.html)<br>[https://securityaffairs.com/202216/ai/security-affairs-ai-cybersecurity-newsletter-round-6.html](https://securityaffairs.com/202216/ai/security-affairs-ai-cybersecurity-newsletter-round-6.html)<br>[https://securityaffairs.com/202209/malware/security-affairs-malware-newsletter-round-121.html](https://securityaffairs.com/202209/malware/security-affairs-malware-newsletter-round-121.html)<br>[https://securityaffairs.com/202200/breaking-news/security-affairs-newsletter-round-602-by-pierluigi-paganini-international-edition.html](https://securityaffairs.com/202200/breaking-news/security-affairs-newsletter-round-602-by-pierluigi-paganini-international-edition.html)<br>[https://securityaffairs.com/202184/security/sms-of-death-android-under-attack-an-invisible-sms-can-block-calls-and-emergency-services.html](https://securityaffairs.com/202184/security/sms-of-death-android-under-attack-an-invisible-sms-can-block-calls-and-emergency-services.html) |
| **CVE-2026-97631** | N/A | N/A | FALSE | Firmware UEFI (serveurs) | Vulnérabilité UEFI (16 ans d'âge) | Persistance au niveau du firmware, contournement des mécanismes de sécurité, compromission profonde des serveurs et difficulté de détection et d'éradication. | None | Appliquer les mises à jour UEFI des fournisseurs, activer Secure Boot, surveiller l'intégrité du firmware et restreindre les accès physiques aux serveurs. | [https://securityaffairs.com/202200/breaking-news/security-affairs-newsletter-round-602-by-pierluigi-paganini-international-edition.html](https://securityaffairs.com/202200/breaking-news/security-affairs-newsletter-round-602-by-pierluigi-paganini-international-edition.html) |
| **CVE-2026-120308** | 9.9 | N/A | FALSE | Beta9 (gateway et worker) | Traversée de répertoire (CWE-22) et exposition de ressources (CWE-668) | Accès non autorisé aux fichiers de l'hôte, compromission de l'isolation multi-tenant, vol de données, modification de fichiers critiques et mouvement latéral potentiel. | None | Mettre à jour le gateway vers 0.1.776+ et le worker vers 0.1.756+. Valider les identifiants de volume et les chemins de montage avant tout montage, et restreindre les tokens de workspace. | [https://cvefeed.io/vuln/detail/CVE-2026-120308](https://cvefeed.io/vuln/detail/CVE-2026-120308) |
| **CVE-2026-120307** | 9.9 | N/A | FALSE | Beta9 worker | Traversée de répertoire (CWE-22), traversée de chemin relatif (CWE-23) et suivi de lien (CWE-59) | Évasion de conteneur, compromission du cluster Kubernetes, accès aux secrets, mouvement latéral et exécution de code arbitraire sur l'hôte. | None | Mettre à jour le worker vers 0.1.756+. Restreindre les permissions du service account, utiliser os.OpenRoot pour les opérations de fichiers et appliquer des politiques de sécurité Kubernetes. | [https://cvefeed.io/vuln/detail/CVE-2026-120307](https://cvefeed.io/vuln/detail/CVE-2026-120307) |
| **CVE-2026-120306** | 9.9 | N/A | FALSE | Beta9 build worker (Buildah) | Isolation incorrecte (CWE-653) et gestion incorrecte des privilèges (CWE-269) | Évasion de sandbox, compromission du worker et du cluster, accès aux secrets, exécution de code arbitraire et mouvement latéral. | None | Mettre à jour le worker vers 0.1.756+. Utiliser l'isolation OCI pour les builds, ne pas exécuter en privilégié et restreindre les capabilities. | [https://cvefeed.io/vuln/detail/CVE-2026-120306](https://cvefeed.io/vuln/detail/CVE-2026-120306) |
| **CVE-2026-84170** | 8.3 | N/A | FALSE | Apache Wicket 9.14.0 à 9.24.0 et 10.0.0 à 10.9.1 (composant AbstractFileUploadResource / FileUploadToResourceField) | Allocation de ressources sans limite ni limitation de débit (CWE-770) — déni de service | Déni de service par épuisement du disque (fichiers spoolés persistants) ou de la heap JVM (parties non-fichier lues en mémoire), déclenchable par une seule requête répétable, sans authentification. Impact potentiel sur l'ensemble des applications servies par la JVM touchée. | Theoretical | Mettre à jour vers Apache Wicket 9.25.0 ou 10.12.0. En attendant : démonter la ressource d'upload si non nécessaire, imposer une autorisation applicative sur la ressource, limiter la taille des requêtes au niveau du reverse proxy, restreindre l'accès réseau aux endpoints d'upload et surveiller la consommation disque/heap. | [https://cvefeed.io/vuln/detail/CVE-2026-84170](https://cvefeed.io/vuln/detail/CVE-2026-84170) |
| **CVE-2026-83594** | 8.3 | N/A | FALSE | Apache Wicket 9.14.0 à 9.24.0 et 10.0.0 à 10.11.0 (composant FileUploadToResourceField) | Allocation mémoire de taille excessive (CWE-789) — déni de service | Déni de service applicatif complet par épuisement de la heap JVM, avec possibilité de provoquer des exceptions non gérées remontant dans l'application. Accessible à tout client capable de charger la page, sans interaction utilisateur. | Theoretical | Mettre à jour vers Apache Wicket 9.25.0 ou 10.12.0. En attendant : refuser l'action ENABLE sur le champ via la stratégie d'autorisation, éviter UploadInfo#get() au profit de getFile() avec validation de taille, limiter la taille des requêtes et le débit au niveau du reverse proxy. | [https://cvefeed.io/vuln/detail/CVE-2026-83594](https://cvefeed.io/vuln/detail/CVE-2026-83594) |
| **CVE-2026-120240** | 9.9 | N/A | FALSE | WAVLINK WN553X1-B firmware V260403_2.0.0 (binaire /bin/ioos, fonction sub_41A748, WireGuard CLI Group Handler) | Injection de commandes OS (CWE-77 / CWE-78) | Exécution de commandes arbitraires sur le routeur, permettant la modification de la configuration réseau, l'interception de trafic, la persistance, l'installation d'implants et l'utilisation de l'équipement comme point d'entrée vers le réseau interne. | Active | Appliquer un firmware corrigé dès sa disponibilité. En attendant : restreindre l'accès à l'interface d'administration au LAN, désactiver l'administration WAN et le service WireGuard CLI non utilisé, remplacer l'équipement si aucun correctif n'est publié. | [https://cvefeed.io/vuln/detail/CVE-2026-120240](https://cvefeed.io/vuln/detail/CVE-2026-120240) |
| **CVE-2026-120239** | 9.9 | N/A | FALSE | WAVLINK WN553X1-B firmware V260403_2.0.0 (binaire /bin/ioos, fonction sub_419DA8, WireGuard CLI Handler) | Injection de commandes OS (CWE-77 / CWE-78) | Exécution de commandes arbitraires sur le routeur : altération de la configuration, interception ou redirection de trafic, persistance, utilisation comme pivot vers le réseau interne. | Active | Appliquer un firmware corrigé dès disponibilité. En attendant : restreindre l'administration au LAN, désactiver l'accès WAN et le handler WireGuard CLI non utilisé, remplacer l'équipement sans correctif. | [https://cvefeed.io/vuln/detail/CVE-2026-120239](https://cvefeed.io/vuln/detail/CVE-2026-120239) |
| **CVE-2026-120238** | 9.9 | N/A | FALSE | WAVLINK WN553X1-B firmware 260403_2.0.0 (binaire /bin/ioos, fonction sub_4162A8, handler ovpn_file) | Injection de commandes OS (CWE-77 / CWE-78) | Exécution de commandes arbitraires sur le routeur : altération des profils OpenVPN, interception de trafic, persistance, utilisation comme pivot vers le réseau interne. | Active | Appliquer un firmware corrigé dès disponibilité. En attendant : restreindre l'administration au LAN, désactiver l'accès WAN et le handler ovpn_file non utilisé, remplacer l'équipement sans correctif. | [https://cvefeed.io/vuln/detail/CVE-2026-120238](https://cvefeed.io/vuln/detail/CVE-2026-120238) |
| **CVE-2026-62048** | 9.3 | N/A | FALSE | Plugin WordPress BookIt (Liquid Web / StellarWP) jusqu'à la version 2.6.0.6 incluse | Injection SQL (CWE-89) | Accès non autorisé à la base de données du site : extraction d'informations sensibles (identifiants, données clients, réservations), modification ou suppression de données, et potentiellement exécution de commandes via la base selon les privilèges du compte SQL. | Theoretical | Mettre à jour le plugin BookIt vers la version 2.6.0.7 ou ultérieure. En attendant : désactiver le plugin si possible, filtrer les payloads SQLi au WAF, restreindre les privilèges du compte base de données et surveiller les erreurs SQL. | [https://cvefeed.io/vuln/detail/CVE-2026-62048](https://cvefeed.io/vuln/detail/CVE-2026-62048) |
| **CVE-2026-120338** | N/A | N/A | FALSE | Prefab UI (runtime Pyodide / WebAssembly) | Évasion de sandbox vers exécution de code arbitraire sur l'hôte | Exécution de code arbitraire sur l'hôte hébergeant le runtime, avec les privilèges du processus applicatif : compromission de l'application, accès aux données traitées et pivot potentiel vers l'infrastructure interne. | Theoretical | Surveiller la publication du correctif éditeur et appliquer la mise à jour dès disponibilité. En attendant : ne pas exécuter de code Python non fiable, isoler les runtimes Pyodide dans des conteneurs à privilèges réduits sans accès réseau sortant, restreindre l'accès aux fonctionnalités d'exécution de code. | [https://cvefeed.io/vuln/detail/CVE-2026-120338](https://cvefeed.io/vuln/detail/CVE-2026-120338) |
| **CVE-2026-120232** | 8.8 | N/A | FALSE | Horizon DataSys Reboot Restore Standard jusqu'à la version 13.2 (pilote noyau shield.sys, fonction sub_23908) | Corruption mémoire dans un pilote noyau (CWE-119) | Élévation de privilèges locale pouvant mener à l'exécution de code en mode noyau, au contournement des mécanismes de sécurité de l'OS et à la compromission complète du poste, avec risque de crash système (BSOD). | Active | Appliquer le correctif éditeur dès sa publication. En attendant : désinstaller ou désactiver le pilote sur les postes où il n'est pas indispensable, restreindre les droits d'installation de pilotes, activer HVCI et la blocklist de pilotes vulnérables de Microsoft, et bloquer le hash du PoC public. | [https://cvefeed.io/vuln/detail/CVE-2026-120232](https://cvefeed.io/vuln/detail/CVE-2026-120232) |
| **CVE-2026-120231** | 9.9 | N/A | FALSE | WAVLINK WN553X1-B, firmware V260403_2.0.0 — composant OpenVPN CLI Handler, fonction sub_416568 du binaire /bin/ioos | Injection de commandes OS (CWE-77 / CWE-78) | Exécution de commandes arbitraires sur le routeur avec les privilèges du service, permettant la prise de contrôle complet de l'équipement, la modification de la configuration réseau/VPN, l'interception de trafic, le pivot vers le réseau interne et l'installation de persistance. | Active | Appliquer dès que disponible le firmware corrigé de WAVLINK ; à défaut, restreindre l'accès à l'interface d'administration et au service OpenVPN aux réseaux d'administration de confiance, désactiver l'administration WAN, remplacer l'équipement si le support est absent, et surveiller les journaux à la recherche de métacaractères shell dans les paramètres exposés. | [https://cvefeed.io/vuln/detail/CVE-2026-120231](https://cvefeed.io/vuln/detail/CVE-2026-120231) |
| **CVE-2026-120230** | 9.9 | N/A | FALSE | WAVLINK WN701AE, firmware 260105 — composant ioos Web Backend, fonction del_vlan_group | Injection de commandes OS (CWE-77 / CWE-78) | Exécution de commandes arbitraires sur le routeur, altération de la segmentation VLAN, prise de contrôle de l'équipement, pivot vers les réseaux internes et déni de service par suppression de la configuration réseau. | Active | Mettre à jour le firmware WN701AE vers une version corrigée, restreindre l'accès à l'interface web d'administration, désactiver l'administration distante, surveiller les journaux HTTP et remplacer l'équipement en fin de support. | [https://cvefeed.io/vuln/detail/CVE-2026-120230](https://cvefeed.io/vuln/detail/CVE-2026-120230) |
| **CVE-2026-120229** | 9.1 | N/A | FALSE | WAVLINK WN553X1-B, firmware 260403_2.0.0 — fonction sub_416B50 du binaire /bin/ioos | Injection de commandes OS (CWE-77 / CWE-78) | Exécution de commandes arbitraires sur le routeur, contournement des mécanismes de vérification de mot de passe, prise de contrôle de l'équipement et pivot vers le réseau interne. | Active | Appliquer le firmware corrigé, restreindre l'accès aux fonctions d'administration, désactiver l'administration WAN, surveiller les journaux et remplacer l'équipement si aucun correctif n'est disponible. | [https://cvefeed.io/vuln/detail/CVE-2026-120229](https://cvefeed.io/vuln/detail/CVE-2026-120229) |
| **CVE-2026-120228** | 9.9 | N/A | FALSE | WAVLINK WN553X1-B, firmware V260403_2.0.0 — composant ioos Service, fonction sub_416D88 du binaire /bin/ioos | Injection de commandes OS (CWE-77 / CWE-78) | Exécution de commandes arbitraires avec les privilèges du service, prise de contrôle du routeur, altération de la configuration réseau et pivot vers les systèmes internes. | Active | Appliquer le correctif firmware WAVLINK, restreindre l'accès au service ioos et à l'interface d'administration, désactiver l'administration WAN, surveiller les journaux et remplacer l'équipement si nécessaire. | [https://cvefeed.io/vuln/detail/CVE-2026-120228](https://cvefeed.io/vuln/detail/CVE-2026-120228) |
| **CVE-2026-120227** | 9.9 | N/A | FALSE | WAVLINK WN701AE, firmware M01AE_V260105 — composant ioos Web Backend, fonction del_staticrule du script static_route_setting.sh | Injection de commandes OS (CWE-77 / CWE-78) | Exécution de commandes arbitraires sur le routeur, altération du routage et de la configuration réseau, prise de contrôle de l'équipement et pivot vers le réseau interne. | Active | Appliquer le firmware corrigé, restreindre l'accès à l'interface web d'administration, désactiver l'administration WAN, surveiller les journaux et remplacer l'équipement en fin de support. | [https://cvefeed.io/vuln/detail/CVE-2026-120227](https://cvefeed.io/vuln/detail/CVE-2026-120227) |
| **CVE-2026-120225** | 9.1 | N/A | FALSE | Oray Pugongying X5 Pro jusqu'à la version 7.6.1 — fonction config_restore_ex du fichier /etc/openwrt_release | Traversée de répertoire relative (CWE-22 / CWE-23) | Lecture et écriture de fichiers arbitraires, altération de la configuration système, exécution de code avec les privilèges root, prise de contrôle complet de l'équipement et persistance. | Active | Mettre à jour vers une version postérieure à 7.6.1 si elle devient disponible, restreindre l'accès à l'interface d'administration, désactiver l'administration distante, isoler l'équipement sur un segment dédié et envisager son remplacement en l'absence de support éditeur. | [https://cvefeed.io/vuln/detail/CVE-2026-120225](https://cvefeed.io/vuln/detail/CVE-2026-120225) |
| **CVE-2026-120224** | N/A | N/A | FALSE | Oray Pugongying X5 Pro — API d'administration, fonction run_async_task | Autorisation impropre (CWE-285) | Contournement des contrôles d'accès à l'API, exécution de tâches asynchrones non autorisées, modification potentielle de la configuration de l'équipement et élévation de privilèges. | None | Restreindre l'exposition de l'API d'administration, appliquer les mises à jour éditeur dès publication, révoquer les jetons exposés et surveiller les appels anormaux à run_async_task. | [https://cvefeed.io/vuln/detail/CVE-2026-120224](https://cvefeed.io/vuln/detail/CVE-2026-120224) |
| **CVE-2026-120198** | N/A | N/A | FALSE | WAVLINK WL-WN530BE1-A — composant protocol.csp, fonction con_check_read_finish | Injection de commandes (CWE-78) | Exécution potentielle de commandes arbitraires sur l'équipement, prise de contrôle du routeur et pivot vers le réseau interne. | None | Restreindre l'accès au service protocol.csp et à l'interface d'administration, appliquer les mises à jour éditeur dès publication, surveiller les journaux et remplacer l'équipement si aucun correctif n'est disponible. | [https://cvefeed.io/vuln/detail/CVE-2026-120198](https://cvefeed.io/vuln/detail/CVE-2026-120198) |
| **CVE-2026-120197** | 9.9 | N/A | FALSE | WAVLINK WL-WN530HG4B (firmware M_V260724 et versions antérieures) | Injection de commandes OS (CWE-77 / CWE-78) | Exécution de code arbitraire sur l'équipement avec les droits du service web, permettant la modification de la configuration (redirection de ports, DNS, VPN), l'interception de trafic, l'intégration de l'équipement à un botnet ou son utilisation comme point d'appui pour pivoter vers le réseau interne. Confidentialité, intégrité et disponibilité du routeur et du réseau qu'il dessert sont compromises. | Active | Appliquer le correctif éditeur dès sa publication et vérifier la version de firmware après mise à jour. En attendant, désactiver l'administration distante et restreindre l'accès à l'interface web par liste blanche d'adresses IP ou via un tunnel d'administration. Segmenter les équipements réseau et surveiller les requêtes anormales vers /cgi-bin/wapi.cgi. Remplacer les équipements en fin de support. | [https://cvefeed.io/vuln/detail/CVE-2026-120197](https://cvefeed.io/vuln/detail/CVE-2026-120197) |
| **CVE-2026-112816** | 10.0 | N/A | FALSE | Canonical LXD (4.0.14, 5.0.10, 5.21.8, 6.9 et antérieurs) et MicroCloud (2.x, 3.x) ; Incus avant 7.6.0 | Contournement d'authentification / validation incorrecte de chaîne de certificats mTLS (usurpation de client de confiance) | Usurpation d'un client de confiance donnant accès au cluster et à ses machines virtuelles ; si le client usurpé est privilégié, l'attaquant obtient un accès root à la machine hôte. Risque de compromission complète de l'infrastructure de virtualisation/conteneurs et de latéralisation vers les charges de travail hébergées. | None | Mettre à jour vers LXD 6.10.1 (canal 6/stable), 5.21.9 (5.21/stable), 5.0.11 (5.0/stable), 4.0.15 (4.0/stable), MicroCloud 3.4.1 (3/stable) ou 2.1.5 (2/stable), et Incus 7.6.0 ; exécuter sudo snap refresh lxd et sudo snap refresh microcloud puis vérifier la version réellement installée. Aucun contournement de configuration n'existe : restreindre l'accès réseau à l'écouteur HTTPS de l'API est la seule mesure d'atténuation temporaire. Les paquets LXD de l'archive Ubuntu ne sont pas affectés. | [https://thehackernews.com/2026/11/critical-lxd-and-microcloud-flaw-cvss.html](https://thehackernews.com/2026/11/critical-lxd-and-microcloud-flaw-cvss.html) |
| **CVE-2026-105697** | 9.9 | N/A | FALSE | Langflow, versions antérieures à 1.10.3 | Vulnérabilité critique non précisée publiquement (score CVSS 9.9), référencée GHSA-w794-rj3p-xv45 | Compromission de l'instance Langflow : accès aux flux, aux secrets (clés d'API de fournisseurs LLM, identifiants de bases vectorielles), aux données traitées et potentiellement exécution de code sur l'hôte. Risque d'empoisonnement des chaînes d'IA et d'exfiltration de données sensibles. | None | Mettre à jour vers Langflow 1.10.3 sans délai. En attendant, restreindre l'accès réseau à l'interface (VPN, reverse proxy authentifié, liste blanche), isoler l'instance dans un segment dédié et surveiller les journaux applicatifs. Consulter l'avis GHSA-w794-rj3p-xv45 pour les détails techniques et les éventuelles mesures complémentaires. | [https://mastodon.social/@Tokenmaxradar/117543785470139423](https://mastodon.social/@Tokenmaxradar/117543785470139423) |
| **CVE-2026-82115** | N/A | N/A | FALSE | Apache Wicket 8.0.0 à 8.19.0, 9.0.0 à 9.24.0 et 10.0.0 à 10.11.0 | Contrôle d'accès défaillant sur les ressources WebSocket partagées | Accès non autorisé à des données ou canaux de communication temps réel réservés à certains rôles : fuite d'informations métier, écoute de notifications, injection de messages dans des canaux partagés. L'impact reste limité au périmètre applicatif de l'instance Wicket concernée. | None | Mettre à jour vers Apache Wicket 8.20.0, 9.25.0 ou 10.12.0 selon la branche. En attendant, restreindre l'exposition des ressources WebSocket partagées et renforcer les contrôles d'autorisation applicatifs au niveau des handlers. Surveiller les accès authentifiés anormaux aux endpoints WebSocket. | [https://www.cve.org/CVERecord?id=CVE-2026-82115](https://www.cve.org/CVERecord?id=CVE-2026-82115) |
| **CVE-2026-116386** | 9.8 | 0.35% | FALSE | Plugin WordPress SMS Alert Order Notifications, versions <= 4.0.2 | Élévation de privilèges non authentifiée (CWE-266) | Prise de contrôle partielle ou totale du site WordPress : création de comptes administrateur, modification de contenu, installation de plugins malveillants, redirection des visiteurs, exfiltration de données clients. Un site compromis peut servir de relais pour des campagnes de phishing ou de distribution de malware. | None | Mettre à jour le plugin vers une version corrigée dès sa publication ; en attendant, désactiver le plugin. Renforcer l'authentification des comptes administrateur (MFA), surveiller les changements de rôles et les créations de comptes, et protéger l'interface d'administration par filtrage réseau ou WAF. | [https://www.thehackerwire.com/vulnerability/CVE-2026-116386/](https://www.thehackerwire.com/vulnerability/CVE-2026-116386/) |
| **CVE-2026-116862** | 7.5 | 0.32% | FALSE | Plugin WordPress WP REST Cache, versions <= 2026.3.1 | Contrôle d'accès défaillant non authentifié (CWE-862) | Accès non autorisé à des données ou fonctionnalités du site via l'API REST : fuite d'informations (contenus non publiés, données utilisateur, configuration), voire modification de contenu selon les routes exposées. Impact limité à la confidentialité et à l'intégrité du site concerné. | None | Mettre à jour le plugin vers la version corrigée ou le désactiver. Purger le cache REST, restreindre l'accès à l'API REST aux usages légitimes et surveiller les requêtes non authentifiées vers les endpoints REST. | [https://www.thehackerwire.com/vulnerability/CVE-2026-116862/](https://www.thehackerwire.com/vulnerability/CVE-2026-116862/) |
| **CVE-2026-116861** | 7.5 | 0.34% | FALSE | Plugin WordPress Flexible Chat, versions <= 1.1.0 | Exposition d'informations sensibles non authentifiée (CWE-201) | Fuite de données de conversation et d'informations potentiellement personnelles ou confidentielles échangées via le chat. Risque de conformité (RGPD), d'atteinte à la réputation et d'utilisation des données pour des attaques d'ingénierie sociale ciblées. | None | Mettre à jour le plugin vers la version corrigée ou le désactiver. Restreindre l'accès aux endpoints du chat, surveiller les extractions massives et évaluer l'exposition de données personnelles pour engager les notifications nécessaires. | [https://www.thehackerwire.com/vulnerability/CVE-2026-116861/](https://www.thehackerwire.com/vulnerability/CVE-2026-116861/) |
| **CVE-2026-78030** | 9.8 | N/A | FALSE | DBI pour Perl, versions antérieures à 1.653 (pilote DBD::DBM) | Chargement de module non validé à partir d'une entrée externe (CWE-470, unsafe reflection) | Exécution de code arbitraire dans le contexte du processus Perl (remote ou adjacent selon le point d'entrée), avec les privilèges du service applicatif : accès aux bases de données, aux secrets de connexion et aux fichiers de l'hôte. Risque de compromission complète du service et de pivot vers les systèmes adjacents. | None | Mettre à jour DBI vers 1.653 ou supérieur. En attendant, ne jamais laisser un utilisateur non fiable fournir ou modifier les attributs dbm_type et dbm_mldbm, valider strictement les DSN, restreindre l'accès aux proxys DBI et exécuter les processus Perl avec des privilèges minimaux dans des répertoires non inscriptibles. | [https://www.valtersit.com/cve/CVE-2026-78030/](https://www.valtersit.com/cve/CVE-2026-78030/) |
| **CVE-2026-58882** | N/A | N/A | FALSE | Android (pile de communication cellulaire / traitement des SMS) | Déni de service à distance par SMS spécialement conçu | Indisponibilité du service cellulaire, crash du terminal, perturbation des communications, répétition possible contre des utilisateurs ciblés. Risque opérationnel pour les flottes mobiles non patchées. | Theoretical | Appliquer les correctifs Android dès que disponibles; vérifier les niveaux de patch; filtrer les SMS au niveau passerelle/opérateur; surveiller les crashs anormaux; restreindre les périphériques non supportés. | [https://www.bleepingcomputer.com/news/security/new-android-sms-of-death-exploit-can-remotely-crash-unpatched-phones/](https://www.bleepingcomputer.com/news/security/new-android-sms-of-death-exploit-can-remotely-crash-unpatched-phones/)<br>[https://infosec.exchange/@edwardk/117540613444541254](https://infosec.exchange/@edwardk/117540613444541254) |
| **CVE-2026-111357** | 8.8 | N/A | TRUE | Ivanti Connect Secure (ICS) | Authentification manquante pour une fonction critique permettant une élévation de privilèges local | Élévation de privilèges jusqu'à root, extraction d'identifiants et de métadonnées Active Directory limitées, reconnaissance de l'hôte, recherche de mots de passe administrateur et de clés de récupération BitLocker. La chaîne complète permet une compromission profonde de l'appliance. | Active | Appliquer ICS 25.1.1.3 ou 22.8R2.6; restreindre l'accès administratif; surveiller les connexions et commandes suspectes; réinitialiser les identifiants exposés; protéger et renouveler les clés BitLocker; vérifier les indicateurs UTA0576. | [https://thehackernews.com/2026/10/attackers-chain-three-ivanti-connect.html](https://thehackernews.com/2026/10/attackers-chain-three-ivanti-connect.html)<br>[https://infosec.exchange/@edwardk/117540611117816368](https://infosec.exchange/@edwardk/117540611117816368) |
| **CVE-2026-118527** | 4.3 | N/A | TRUE | Ivanti Connect Secure (ICS) | Génération de nombres ou d'identifiants prévisibles permettant à un attaquant distant authentifié de téléverser des fichiers contrôlés à un emplacement connu du disque | Téléversement de contenu contrôlé par l'attaquant à un emplacement connu, facilitation de la chaîne d'exploitation, préparation d'outils ou de charges utiles, et contribution à l'obtention d'un accès root non authentifié. | Active | Appliquer ICS 25.1.1.3 ou 22.8R2.6; restreindre les accès authentifiés; surveiller l'intégrité des fichiers et les téléversements; examiner les répertoires critiques; vérifier les indicateurs UTA0576. | [https://thehackernews.com/2026/10/attackers-chain-three-ivanti-connect.html](https://thehackernews.com/2026/10/attackers-chain-three-ivanti-connect.html)<br>[https://infosec.exchange/@edwardk/117540611117816368](https://infosec.exchange/@edwardk/117540611117816368) |
| **CVE-2026-104935** | 8.6 | N/A | TRUE | Ivanti Connect Secure (ICS) | Contournement d'authentification | Contournement d'authentification permettant l'accès non authentifié à l'appliance, puis exécution de code root via la chaîne d'exploitation, extraction d'identifiants et de métadonnées Active Directory, reconnaissance de l'hôte et recherche de secrets sensibles. | Active | Appliquer ICS 25.1.1.3 ou 22.8R2.6; restreindre l'exposition Internet; surveiller les accès non authentifiés; réinitialiser les identifiants exposés; renouveler les clés BitLocker; vérifier les indicateurs UTA0576. | [https://thehackernews.com/2026/10/attackers-chain-three-ivanti-connect.html](https://thehackernews.com/2026/10/attackers-chain-three-ivanti-connect.html)<br>[https://infosec.exchange/@edwardk/117540611117816368](https://infosec.exchange/@edwardk/117540611117816368) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="extraction-de-fichiers-onenote-dim-1er-novembre"></div>

## Extraction de fichiers OneNote, (dim. 1er novembre)

### Résumé

Didier Stevens (SANS ISC) décrit l'ajout d'une option --jsonoutput à son outil onedump.py, qui permet d'extraire en une seule passe les fichiers embarqués contenus dans plusieurs fichiers OneNote (.one). La sortie JSON peut ensuite être traitée par myjson-filter.py avec l'option -W hashvir pour écrire les fichiers sur disque, nommés par le SHA-256 de leur contenu avec l'extension .vir. L'auteur rappelle que plusieurs de ses outils disposent déjà d'une sortie JSON de ce type.

---

### Analyse opérationnelle

Le format .one reste un conteneur d'archive pratique pour transporter des charges utiles à travers les filtres de messagerie, car il peut embarquer scripts, exécutables ou documents leurres. L'apport décrit ici est purement défensif : il permet d'industrialiser le triage de lots de fichiers .one suspects sans exécuter l'échantillon, en extrayant chaque objet embarqué et en le nommant par son empreinte SHA-256. Pour un SOC, cela signifie des pivots de recherche fiables (hash) injectables dans l'EDR, le proxy et le SIEM, et une réduction du temps de traitement lors de campagnes de phishing à pièces jointes .one. Le point de vigilance opérationnel reste l'exécution des fichiers extraits : l'extraction doit se faire en environnement isolé, et les objets .vir ne doivent jamais être ouverts sur un poste de production.

---

### Implications stratégiques

La persistance du format OneNote comme vecteur de livraison illustre l'écart entre les politiques de blocage d'extensions (souvent centrées sur .exe, .js, .lnk) et la réalité des conteneurs alternatifs. Les organisations qui n'ont pas généralisé le blocage ou le détachement des conteneurs bureautiques exotiques restent exposées à des campagnes à faible coût pour l'attaquant. Investir dans l'automatisation du triage d'échantillons est un levier de réduction du temps de confinement plus rentable que l'ajout de signatures unitaires.

---

### Recommandations

* Bloquer ou mettre en quarantaine les fichiers .one provenant d'expéditeurs externes non authentifiés.
* Automatiser l'extraction des fichiers embarqués en sandbox et indexer les hash SHA-256 dans le SIEM.
* Interdire l'ouverture de fichiers extraits (.vir) hors environnement d'analyse dédié.
* Former les équipes de première ligne à reconnaître les pièces jointes OneNote comme vecteur d'exécution.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Déployer un pipeline d'extraction automatisé des fichiers embarqués (.one, archives, OLE) sur la passerelle de messagerie et dans la sandbox d'analyse.
* Conserver les hash SHA-256 de tous les fichiers extraits comme pivot de rétro-recherche dans le SIEM et l'EDR.
* Documenter la procédure d'extraction (outil onedump.py --jsonoutput + myjson-filter.py -W hashvir) dans le runbook de l'équipe analyse malware.

#### Phase 2 — Détection et analyse

* Alerter sur toute pièce jointe .one entrante externe, en particulier si l'expéditeur est inconnu ou le nom de fichier générique.
* Détecter les processus de bureautique/OneNote lançant des enfants inhabituels (cmd, powershell, wscript, mshta, rundll32).
* Surveiller les écritures de fichiers avec extension .vir ou noms aléatoires dans les répertoires temporaires utilisateur.

#### Phase 3 — Confinement, éradication et récupération

* Isoler le poste ayant ouvert le fichier .one et bloquer l'expéditeur au niveau de la passerelle mail.
* Extraire et hasher tous les fichiers embarqués pour identifier la charge utile finale et bloquer son hash sur l'EDR et le proxy.
* Rechercher le même hash sur l'ensemble du parc et sur les journaux de messagerie des 30 derniers jours.

#### Phase 4 — Activités post-incident

* Mettre à jour les règles de filtrage des extensions à risque et les signatures de détection.
* Revoir la politique de blocage des conteneurs OneNote en provenance d'Internet.
* Capitaliser les échantillons et IOC dans la base de renseignement interne.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les exécutions de OneNote suivies d'un processus réseau sortant dans les 5 minutes.
* Chasser les fichiers .one stockés dans les répertoires de téléchargement ou les partages réseau.
* Corréler les hash extraits avec les jeux de renseignement externes (VirusTotal, MISP).

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1027.009** | Embedded Payloads — fichiers malveillants embarqués dans des conteneurs OneNote (.one) |
| **T1204.002** | User Execution: Malicious File — ouverture d'une pièce jointe .one par la victime |
| **T1566.001** | Phishing: Spearphishing Attachment — livraison de charges utiles via pièces jointes |

---

### Sources

* [https://isc.sans.edu/diary/rss/33478](https://isc.sans.edu/diary/rss/33478)


---

<div id="sentinelone-prompt-security-de-quoi-sagit-il-et-comment-je-lai-reellement-teste"></div>

## SentinelOne Prompt Security : de quoi s'agit-il et comment je l'ai réellement testé

### Résumé

L'auteur relate une évaluation pratique de Prompt Security, produit de DLP pour usages d'IA générative racheté par SentinelOne. Le produit se compose d'une extension navigateur (couvrant les sites d'IA et les fonctions d'IA intégrées à des sites ordinaires) et d'un agent endpoint installant un proxy local et un certificat propre afin d'inspecter le trafic chiffré vers les modèles, y compris pour les assistants de code en ligne de commande. Seul le module « Employees » était sous licence ; les modules « Homegrown Apps » et « Agentic AI » n'ont pas été testés. Les tests ont été menés sur Windows, en mode monitor puis en mode blocage, avec des secrets canary envoyés dans tous les canaux disponibles.

---

### Analyse opérationnelle

Le sujet central est le shadow AI : des collaborateurs collent des clés API, des données clients ou des fichiers .env dans des interfaces d'IA sans visibilité de l'entreprise. La couverture repose sur deux mécanismes distincts — l'extension navigateur, seule à pouvoir lire le texte contenu dans une capture d'écran ou un document uploadé, et l'agent endpoint avec interception TLS locale, indispensable pour les applications de bureau et les CLI. Ce second mécanisme a des conséquences opérationnelles lourdes : déploiement d'une autorité de certification interne, gestion du cycle de vie des certificats, risque de rupture d'applications lors du passage du mode monitor au mode blocage, et nécessité d'exclure les flux légitimes. Les tests n'ayant porté que sur Windows, la couverture macOS/Linux et les canaux mobiles restent des angles morts à valider avant généralisation.

---

### Implications stratégiques

La gouvernance de l'IA générative devient un enjeu de conformité à part entière : fuite de données personnelles, exposition de secrets d'infrastructure, perte de propriété intellectuelle sur du code source. Les organisations arbitrent entre interdiction (coûteuse en productivité et contournée en pratique) et encadrement technique, ce qui pousse vers des solutions de DLP spécialisées et crée une dépendance à un fournisseur unique couvrant à la fois endpoint et navigateur. La maturité des modules « agents autonomes » sera déterminante : les agents IA disposant d'accès à des systèmes internes constituent la prochaine frontière de risque, bien au-delà de la simple saisie de prompts.

---

### Recommandations

* Démarrer tout déploiement DLP IA en mode monitor pendant au moins 30 jours avant activation du blocage.
* Cartographier l'ensemble des canaux d'accès aux modèles (navigateur, bureau, CLI, IDE) avant de considérer la couverture comme complète.
* Mettre en place une rotation systématique des secrets détectés en prompt et un coffre-fort de secrets pour les développeurs.
* Étendre l'évaluation aux postes macOS/Linux et aux terminaux mobiles avant généralisation.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser les services d'IA générative utilisés (navigateur, applications de bureau, CLI, IDE) et les classifier en autorisé / toléré / interdit.
* Définir une politique de classification des données interdites en prompt (secrets, données clients, données personnelles, code source).
* Préparer un déploiement en mode monitor avant tout passage en blocage, avec métriques de faux positifs.

#### Phase 2 — Détection et analyse

* Journaliser les prompts sortants et les actions appliquées (allow, redact, mask, block) par utilisateur et par application.
* Détecter les secrets en clair (clés API, tokens, chaînes de connexion, fichiers .env) dans les flux vers les services d'IA.
* Surveiller l'installation d'agents CLI d'IA et de proxys locaux non approuvés sur les postes.

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement toute clé API ou identifiant détecté comme exposé et faire tourner les secrets concernés.
* Bloquer l'application ou le canal concerné (extension, CLI, domaine) pour l'utilisateur à l'origine de la fuite.
* Isoler le poste si un agent non autorisé avec interception TLS locale est découvert.

#### Phase 4 — Activités post-incident

* Analyser les faux positifs du passage en mode blocage et ajuster les règles de détection.
* Documenter les canaux non couverts par la solution (applications non testées, systèmes hors périmètre).
* Mettre à jour la charte d'usage de l'IA et communiquer auprès des métiers.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux proxy les sessions persistantes vers des domaines d'IA non approuvés.
* Chasser les fichiers .env, .pem et fichiers de configuration contenant des secrets dans les répertoires synchronisés cloud.
* Corréler les pics d'usage d'IA avec des événements RH (départs, sous-traitants) pour détecter les exfiltrations opportunistes.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1567** | Exfiltration Over Web Service — envoi de données sensibles vers des services d'IA générative |
| **T1552.001** | Unsecured Credentials: Credentials In Files — fuite de clés API et de fichiers .env via les prompts |
| **T1048** | Exfiltration Over Alternative Protocol — contournement des contrôles via des clients CLI et proxys locaux |

---

### Sources

* [https://www.cyberengage.org/post/sentinelone-prompt-security-what-it-is-and-how-i-actually-tested-it](https://www.cyberengage.org/post/sentinelone-prompt-security-what-it-is-and-how-i-actually-tested-it)


---

<div id="presentation-de-pathrunner-un-framework-delevation-de-privileges-aws"></div>

## Présentation de pathrunner : un framework d'élévation de privilèges AWS

### Résumé

Datadog Security Labs annonce la publication de pathrunner, un framework open source dédié à l'escalade de privilèges dans AWS. L'article est classé par l'éditeur dans les thématiques « threat detection » et « cloud misconfiguration », ce qui positionne l'outil à la fois comme outil d'évaluation offensive et comme support de détection des chemins d'élévation de privilèges en environnement cloud.

---

### Analyse opérationnelle

Les frameworks d'escalade de privilèges cloud répondent à un problème structurel : la complexité des politiques IAM rend difficile la visualisation des chemins permettant à une identité faiblement privilégiée d'atteindre des droits administratifs (par exemple via iam:PassRole combiné au lancement d'un service de calcul, ou via la création d'une nouvelle version de politique). Pour un SOC cloud, l'intérêt défensif est double : disposer d'une cartographie des chemins réellement exploitables dans son propre tenant, et construire des règles de détection sur les séquences d'appels API plutôt que sur des événements isolés. La détection doit s'appuyer sur CloudTrail centralisé multi-comptes et multi-régions, avec une attention particulière aux actions IAM de création/modification de politiques et aux assumations de rôle inter-comptes.

---

### Implications stratégiques

L'élévation de privilèges cloud est un point de bascule majeur : à partir d'un rôle applicatif compromis, un attaquant peut atteindre le contrôle total du compte et de ses données. La démocratisation d'outils open source spécialisés abaisse la barrière technique et accroît la pression sur les équipes sécurité cloud, qui doivent traiter la revue des permissions IAM comme un contrôle continu et non comme un audit annuel. Les organisations multi-cloud et les scale-ups à forte croissance, où les politiques IAM évoluent vite, sont les plus exposées.

---

### Recommandations

* Exécuter une cartographie des chemins d'escalade sur chaque compte AWS et prioriser les chemins menant à des rôles administratifs.
* Restreindre iam:PassRole par condition sur les ARN de rôles autorisés.
* Imposer MFA et des conditions de source sur les assumations de rôle sensibles.
* Intégrer les séquences d'appels IAM sensibles dans les règles de détection SIEM.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les identités IAM, rôles, politiques inline et relations de confiance inter-comptes dans l'ensemble des comptes AWS.
* Activer et centraliser CloudTrail sur toutes les régions et tous les comptes, avec intégration SIEM.
* Définir une baseline des actions IAM sensibles (iam:PassRole, iam:CreatePolicyVersion, sts:AssumeRole, iam:AttachRolePolicy).

#### Phase 2 — Détection et analyse

* Alerter sur les séquences d'appels API correspondant à des chemins d'escalade connus (PassRole suivi de création de fonction Lambda ou de lancement EC2).
* Détecter la création ou la modification de politiques accordant des permissions larges (Action: *, Resource: *).
* Surveiller les changements de relation de confiance de rôle et les assumations de rôle inhabituelles par utilisateur ou par IP.

#### Phase 3 — Confinement, éradication et récupération

* Désactiver les clés d'accès et les sessions de l'identité compromise, révoquer les sessions temporaires actives.
* Restaurer les politiques IAM modifiées à partir de la version précédente et supprimer les rôles créés frauduleusement.
* Restreindre les chemins d'escalade identifiés par des conditions (aws:SourceArn, MFA, périmètre de compte).

#### Phase 4 — Activités post-incident

* Revoir l'ensemble des chemins d'escalade détectés et prioriser leur remédiation par niveau de privilège atteignable.
* Mettre en place une revue périodique des permissions selon le principe du moindre privilège.
* Documenter les écarts de configuration cloud dans le registre des risques.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les créations de politiques IAM avec des permissions administratives sur les 90 derniers jours.
* Chasser les assumations de rôle inter-comptes vers des comptes non répertoriés dans l'inventaire.
* Corréler les activités IAM suspectes avec les journaux de facturation AWS (création de ressources coûteuses).

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078.004** | Valid Accounts: Cloud Accounts — usage d'identités IAM légitimes pour élever ses privilèges |
| **T1098** | Account Manipulation — modification de rôles, politiques et trusts pour persister |
| **T1548** | Abuse Elevation Control Mechanism — exploitation de chemins d'escalade de privilèges dans AWS |

---

### Sources

* [https://securitylabs.datadoghq.com/articles/introducing-pathrunner-aws-privilege-escalation-framework/](https://securitylabs.datadoghq.com/articles/introducing-pathrunner-aws-privilege-escalation-framework/)


---

<div id="empreinte-gpu-a-partir-de-lordonnancement-des-additions-atomiques-precision-de-991-survit-aux-redemarrages-fonctionne-meme-entre-modeles-de-gpu-identiques-dans-des-environnements-cloud-partages-limplication-meme-materiel-ne-signifie-pas-meme-empreinte-les-hypotheses-disolation-dans-les-infrastructures-gpu-multi-tenant-meritent-un-second-regardinfosec-fingerprinting-gpu-httpsinfosecpubpost54379636"></div>

## Empreinte GPU à partir de l'ordonnancement des additions atomiques — précision de 99,1 %, survit aux redémarrages, fonctionne même entre modèles de GPU identiques dans des environnements cloud partagés. L'implication : « même matériel » ne signifie pas « même empreinte ». Les hypothèses d'isolation dans les infrastructures GPU multi-tenant méritent un second regard.#infosec #fingerprinting #GPU https://infosec.pub/post/54379636

### Résumé

Un projet publié sous le nom gpu-instance-fingerprint permet d'identifier le GPU exact sur lequel une charge de travail s'exécute, y compris entre GPU de modèle identique, à partir de l'ordre dans lequel les opérations « atomic add » aboutissent. Le projet revendique une précision de 99,1 %, une persistance de l'empreinte après redémarrage, et un fonctionnement dans des environnements cloud partagés où plusieurs locataires utilisent des GPU identiques.

---

### Analyse opérationnelle

Cette capacité remet en cause l'hypothèse selon laquelle deux instances sur du matériel identique sont indistinguables. Pour un fournisseur cloud ou une équipe sécurité, cela ouvre deux angles : un angle offensif (traçabilité d'une cible à travers ses sessions, détection de co-résidence pour préparer des attaques par canal auxiliaire) et un angle défensif (attribution d'activités malveillantes à une instance précise malgré le changement d'identifiants). La contre-mesure principale consiste à restreindre l'accès aux compteurs de performance et interfaces de télémétrie GPU depuis les charges non privilégiées, et à randomiser l'allocation matérielle entre sessions lorsque c'est possible.

---

### Implications stratégiques

L'isolation des infrastructures GPU devient un sujet de conformité et de confiance contractuelle, à l'heure où ces ressources portent des charges d'entraînement et d'inférence sensibles. Si l'empreinte matérielle est stable et traversable, les garanties d'anonymisation des charges de travail et de cloisonnement entre locataires doivent être réexaminées, en particulier pour les secteurs régulés (santé, finance, défense) qui s'appuient sur des GPU mutualisés. Les fournisseurs cloud pourraient être amenés à documenter formellement leurs propriétés d'isolation.

---

### Recommandations

* Intégrer le fingerprinting matériel dans les revues de modèle de menace des infrastructures GPU mutualisées.
* Restreindre l'accès aux compteurs de performance GPU pour les charges locataires non privilégiées.
* Exiger des fournisseurs cloud des précisions contractuelles sur les garanties d'isolation GPU.
* Surveiller les charges de travail exécutant des micro-benchmarks matériels répétés.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Documenter les hypothèses d'isolation des infrastructures GPU multi-tenant (partage de modèles identiques, co-résidence).
* Établir une baseline des caractéristiques matérielles exposées aux charges de travail locataires.
* Définir une politique de minimisation des informations matérielles accessibles depuis les conteneurs et machines virtuelles.

#### Phase 2 — Détection et analyse

* Surveiller les charges de travail exécutant des micro-benchmarks répétés sur les opérations atomiques GPU.
* Détecter les tentatives de corrélation d'empreinte matérielle entre sessions ou entre comptes locataires.
* Alerter sur les accès inhabituels aux interfaces de télémétrie GPU (nvidia-smi, compteurs de performance).

#### Phase 3 — Confinement, éradication et récupération

* Restreindre l'accès aux compteurs de performance et aux interfaces de télémétrie matérielle pour les charges non privilégiées.
* Isoler ou migrer les charges de travail identifiées comme réalisant du fingerprinting.
* Renforcer la randomisation de l'allocation GPU entre sessions si le fournisseur le permet.

#### Phase 4 — Activités post-incident

* Réévaluer les garanties d'isolation contractuelles avec le fournisseur cloud.
* Intégrer le fingerprinting matériel dans la revue des modèles de menace cloud.
* Documenter les limites de l'anonymisation des charges de travail dans l'infrastructure.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les conteneurs exécutant des boucles d'opérations atomiques intensives sans finalité métier identifiable.
* Corréler les empreintes GPU observées avec les journaux d'allocation pour détecter une co-résidence non déclarée.
* Analyser les tentatives de persistance d'identifiant matériel à travers les redémarrages.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1592** | Gather Victim Host Information — identification matérielle fine de la cible |
| **T1082** | System Information Discovery — collecte de caractéristiques matérielles exploitables comme empreinte |

---

### Sources

* [https://infosec.pub/post/54379636](https://infosec.pub/post/54379636)


---

<div id="scenario-cauchemar-un-spyware-zero-click-infecte-les-telephones-via-des-publicites-ciblees"></div>

## « Scénario cauchemar » : un spyware zero-click infecte les téléphones via des publicités ciblées

### Résumé

Le Citizen Lab de l'Université de Toronto documente une campagne baptisée « AdFection » : des publicités ciblées ont servi de vecteur d'infection par un spyware mercenaire, sans interaction de la victime. Entre 2024 et 2025, 45 appareils de la chaîne Al Jazeera auraient été ciblés ; les publicités ciblées auraient été émises par la société de marketing Discover-Tech, et le spyware est attribué au développeur israélien Candiru. Les appareils infectés auraient d'abord contacté des domaines liés à Discover-Tech, puis une infrastructure associée à Candiru. Google a mis fin à l'enregistrement de Discover-Tech. Ni Discover-Tech, ni Integrity Partners (présenté comme propriétaire des actifs de Candiru après les sanctions américaines de 2021) n'ont répondu aux sollicitations. Les chercheurs soulignent que les victimes ne voient rien d'anormal, parfois même aucune publicité.

---

### Analyse opérationnelle

La difficulté défensive est structurelle : l'infection ne requiert ni clic, ni installation, ni faille applicative exploitable par la victime, ce qui neutralise la plupart des sensibilisations utilisateurs. Les leviers réellement actionnables sont le blocage publicitaire et DNS aussi complet que possible sur tous les canaux, la surveillance des connexions sortantes des terminaux sensibles vers des domaines de régie publicitaire, et la capacité d'analyse forensique mobile. La chaîne d'infection en deux temps (contact avec l'infrastructure publicitaire, puis avec l'infrastructure de commande) constitue un point de détection corrélable dans les journaux réseau, à condition de disposer d'une visibilité sur le trafic mobile.

---

### Implications stratégiques

Cette affaire marque la convergence entre l'écosystème publicitaire programmatique et le marché du spyware mercenaire : la capacité à pousser un contenu arbitraire et individualisé vers une cible précise devient une primitive d'attaque. Les conséquences dépassent la seule cible : elles touchent la liberté de la presse, la protection de la société civile et la régulation du commerce des outils de surveillance. Les sanctions déjà prises contre Candiru n'ont pas empêché la réutilisation d'infrastructures via des sociétés écrans, ce qui plaide pour des contrôles de vigilance renforcés sur les régies publicitaires et pour une pression réglementaire accrue sur les plateformes.

---

### Recommandations

* Déployer un blocage publicitaire et DNS agressif sur les terminaux des populations à risque.
* Mettre en place une capacité d'analyse forensique mobile et un canal de signalement confidentiel pour les victimes potentielles.
* Exiger des plateformes publicitaires des garanties de vérification des annonceurs.
* Partager les indicateurs de campagne avec les CERT et les organisations de défense de la presse.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Identifier les populations à risque élevé (journalistes, avocats, militants, dirigeants) et leur fournir des terminaux durcis.
* Imposer un filtrage publicitaire et DNS au niveau réseau et MDM sur les flottes mobiles sensibles.
* Établir une procédure d'analyse forensique mobile (acquisition de logs, MVT ou équivalent) et un canal de signalement confidentiel.

#### Phase 2 — Détection et analyse

* Rechercher les connexions sortantes des terminaux mobiles vers des domaines publicitaires et vers l'infrastructure de commande connue.
* Analyser les journaux de trafic pour détecter des requêtes publicitaires personnalisées suivies d'une connexion vers un domaine non catégorisé.
* Surveiller les indicateurs d'anomalie sur mobile : consommation batterie, données, processus inconnus, redémarrages.

#### Phase 3 — Confinement, éradication et récupération

* Retirer le terminal du réseau, réinitialiser complètement l'appareil et changer tous les comptes et secrets associés.
* Bloquer au niveau DNS et proxy les domaines publicitaires et d'infrastructure identifiés.
* Notifier la victime et, le cas échéant, les autorités et l'éditeur de la plateforme mobile.

#### Phase 4 — Activités post-incident

* Documenter la chronologie de l'infection et les données potentiellement exfiltrées.
* Renforcer la politique de filtrage publicitaire sur l'ensemble des flottes sensibles.
* Partager les indicateurs avec les pairs du secteur et les CERT compétents.

#### Phase 5 — Threat Hunting (proactif)

* Chasser les terminaux ayant contacté des domaines de régies publicitaires liées à l'infrastructure de spyware documentée.
* Rechercher des artefacts de spyware mobile connus (profils de configuration, certificats, extensions).
* Corréler les journaux réseau des terminaux à risque avec les périodes de campagnes publicitaires ciblées.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1189** | Drive-by Compromise — infection lors de la simple consultation d'une page affichant des publicités |
| **T1583.008** | Acquire Infrastructure: Malvertising — achat de publicités ciblées comme vecteur de livraison |
| **T1027** | Obfuscated Files or Information — dissimulation de la charge utile dans le flux publicitaire |
| **T1437** | Application Layer Protocol (mobile) — communication avec l'infrastructure de commande et contrôle |

---

### Sources

* [https://www.wired.com/story/nightmare-scenario-zero-click-spyware-is-infecting-phones-via-targeted-ads/](https://www.wired.com/story/nightmare-scenario-zero-click-spyware-is-infecting-phones-via-targeted-ads/)


---

<div id="des-villes-signalent-des-problemes-pour-mettre-fin-aux-programmes-de-cameras-flock-le-chef-de-la-police-de-plymouth-affirme-avoir-debranche-les-lecteurs-de-plaques-apres-que-le-fournisseur-na-pas-repondu-dayton-indique-que-les-cameras-ont-ete-reactivees-malgre-une-pause"></div>

## Des villes signalent des problèmes pour mettre fin aux programmes de caméras Flock. Le chef de la police de Plymouth affirme avoir débranché les lecteurs de plaques après que le fournisseur n'a pas répondu. Dayton indique que les caméras ont été réactivées malgré une pause.

### Résumé

Plusieurs villes américaines rencontreraient des difficultés à mettre fin à leurs contrats avec Flock Safety. À Plymouth (Minnesota), le conseil municipal a voté la résiliation en septembre, mais la société n'a pas répondu à la demande ; après plus d'un mois sans retour, le chef de la police a fait débrancher physiquement les caméras. À Dayton (Minnesota), la société a accusé réception et annoncé un délai pouvant aller jusqu'à 60 jours pour le retrait, mais deux caméras ont été remises en service sans autorisation, malgré une demande explicite de suspension des interventions. Un précédent similaire est mentionné à Elgin Community College (Illinois). Flock déclare respecter la décision de la ville et travailler au retrait des caméras.

---

### Analyse opérationnelle

Le cas illustre un échec classique d'offboarding fournisseur : la résiliation contractuelle n'entraîne ni l'arrêt effectif de la collecte, ni la révocation des accès, ni le retrait du matériel. La leçon opérationnelle est que la coupure doit être vérifiée au niveau infrastructure (alimentation, port réseau, VLAN, pare-feu) et non au niveau de l'interface d'administration du fournisseur, qui reste sous son contrôle. Il faut également traiter la révocation des comptes, clés API et certificats, la conservation ou la suppression des données déjà collectées, et l'obtention d'une attestation écrite. La réactivation non autorisée d'un dispositif censé être hors service est un indicateur à surveiller dans les journaux réseau.

---

### Implications stratégiques

Ce dossier illustre le risque de dépendance à un fournisseur unique sur des dispositifs de surveillance déployés dans l'espace public : la collecte de données peut se poursuivre alors que la décision politique de l'arrêter a été prise. Au-delà de la conformité vie privée, c'est la question de la souveraineté opérationnelle des collectivités sur leurs propres infrastructures qui est posée. Les organisations devraient intégrer des clauses de sortie contraignantes et des mécanismes de coupure unilatérale dans tout contrat portant sur des dispositifs de collecte connectés.

---

### Recommandations

* Exiger dans chaque contrat une clause d'offboarding avec preuve d'arrêt et attestation de suppression des données.
* Vérifier la coupure au niveau réseau et alimentation, indépendamment des outils du fournisseur.
* Révoquer systématiquement comptes, clés et certificats fournisseurs à la résiliation.
* Auditer périodiquement les flux résiduels vers les plateformes tierces.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Tenir un inventaire à jour des dispositifs tiers connectés (caméras, capteurs, lecteurs de plaques) avec propriétaire, localisation et niveau d'accès réseau.
* Formaliser dans chaque contrat une clause d'offboarding : délais, preuve d'arrêt, suppression des données, restitution du matériel.
* Définir une procédure interne de révocation d'accès et de déconnexion physique vérifiée.

#### Phase 2 — Détection et analyse

* Surveiller la réapparition de flux réseau provenant de dispositifs censés être hors service.
* Alerter sur toute réactivation de compte, de licence ou de work order après notification de résiliation.
* Contrôler périodiquement l'état physique et logique des dispositifs décommissionnés.

#### Phase 3 — Confinement, éradication et récupération

* Couper l'alimentation et le lien réseau des dispositifs au niveau infrastructure, sans dépendre de l'interface fournisseur.
* Révoquer les comptes, clés API, certificats et accès VPN du fournisseur.
* Exiger une attestation écrite de suppression des données et de fin de traitement.

#### Phase 4 — Activités post-incident

* Vérifier la suppression effective des données détenues par le fournisseur et obtenir une preuve documentaire.
* Mettre à jour la politique d'achat et les clauses de sortie pour les futurs contrats.
* Documenter l'incident pour les autorités de protection des données si des données personnelles sont concernées.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux réseau tous les flux résiduels vers les plateformes du fournisseur.
* Auditer les accès fournisseurs encore actifs sur les autres contrats en cours.
* Contrôler la présence physique des équipements déclarés retirés.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1199** | Trusted Relationship — exploitation de la relation de confiance avec un fournisseur tiers pour maintenir un accès |
| **T1562.001** | Impair Defenses: Disable or Modify Tools — réactivation non autorisée de dispositifs de collecte |

---

### Sources

* [https://www.theverge.com/tech/1024232/flock-ignoring-cancel-contracts](https://www.theverge.com/tech/1024232/flock-ignoring-cancel-contracts)


---

<div id="possible-phishing-on-hxxpsweb-fun-checkout-prototype-uniswapvercelappexplorepoolsethereum0x21b8065d10f73ee2e260e5b47d3344d3ced7596e"></div>

## Possible Phishing 🎣 on: ⚠️hxxps[:]//web-fun-checkout-prototype-uniswap[.]vercel[.]app/explore/pools/ethereum/0x21b8065d10f73ee2e260e5b47d3344d3ced7596e

### Résumé

Un signalement publié via le service d'analyse d'URL URLDNA (relayé sur Mastodon) identifie une possible page de phishing hébergée sur le sous-domaine web-fun-checkout-prototype-uniswap[.]vercel[.]app. L'URL imite une interface de pools de liquidité Ethereum d'Uniswap et inclut dans son chemin une adresse de contrat Ethereum (0x21b8065d10f73ee2e260e5b47d3344d3ced7596e). Le post est classé par son auteur sous les étiquettes #phishing, #scam et #cybersecurity, et renvoie à un rapport de scan URLDNA. Aucune attribution ni information sur le volume de victimes n'est fournie par la source.

---

### Analyse opérationnelle

Le vecteur repose sur l'abus d'un PaaS légitime (vercel.app) : le domaine racine est réputé et souvent autorisé par les filtres, ce qui abaisse le taux de blocage des passerelles web et des proxys. La détection doit donc porter sur le sous-domaine et sur la structure de l'URL (marque + mots-clés « checkout », « pools », « prototype » + adresse hexadécimale 0x) plutôt que sur le domaine de second niveau. Pour un SOC, les points de collecte utiles sont les logs DNS/proxy/SWG, les journaux de résolution et de certificats, la télémétrie navigateur (extensions wallet, appels à window.ethereum) et les signalements utilisateurs. En réponse, le blocage doit être appliqué simultanément au proxy, au DNS et à la messagerie, avec escalade vers l'hébergeur pour retrait. Le risque aval est un drain de wallet via signature malveillante (approve/permit) : toute victime potentielle doit faire révoquer ses approbations de tokens et ses sessions, et vérifier ses transactions sortantes.

---

### Implications stratégiques

L'abus de plateformes d'hébergement gratuites et réputées constitue une tendance de fond qui érode la confiance dans les filtrages basés sur la réputation de domaine et déplace la charge de détection vers l'analyse d'URL et de contenu. Le secteur crypto/DeFi reste une cible privilégiée en raison de l'irréversibilité des transactions et de la valeur immédiate des actifs numériques : une usurpation de marque réussie se traduit directement en pertes financières pour les utilisateurs et en atteinte à la réputation de la plateforme imitée. Pour les organisations exposées, cela impose d'intégrer la surveillance des usurpations de marque (brand monitoring) et la prise en compte des sous-domaines de PaaS dans les politiques de filtrage, au prix d'un arbitrage entre disponibilité de services légitimes et réduction de la surface d'exposition.

---

### Recommandations

* Bloquer le sous-domaine web-fun-checkout-prototype-uniswap[.]vercel[.]app et l'URL signalée sur l'ensemble des points de contrôle (proxy, DNS, messagerie, EDR).
* Ajouter une règle de détection générique sur les sous-domaines *.vercel.app, *.netlify.app et *.pages.dev contenant des noms de marques financières ou des adresses 0x.
* Signaler l'URL à Vercel (abuse) et aux navigateurs pour blocage interstitiel.
* Pour les utilisateurs ayant visité la page : révoquer les approbations de tokens, changer les mots de passe des comptes交易所/wallet et vérifier les transactions récentes.
* Renforcer la sensibilisation aux fausses interfaces DeFi et à la vérification des URL avant connexion d'un wallet.
* Industrialiser l'ingestion des flux de détection de phishing (URLDNA, VirusTotal, signalements internes) avec enrichissement et scoring automatique.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les domaines et sous-domaines légitimes de la marque (Uniswap, portails DeFi) et maintenir une liste de surveillance des PaaS gratuits (vercel.app, netlify.app, pages.dev) utilisés pour l'usurpation.
* Configurer l'ingestion des flux de détection de phishing (URLDNA, PhishTank, VirusTotal, signalements utilisateurs) dans le SIEM avec enrichissement automatique.
* Sensibiliser les utilisateurs crypto/finance aux fausses interfaces de pools de liquidité et aux adresses de contrats Ethereum injectées dans les URL.
* Définir une procédure de signalement rapide (bouton de report, boîte abuse@) et un canal de contact avec les hébergeurs (Vercel) et les registrars.

#### Phase 2 — Détection et analyse

* Rechercher dans les logs proxy/DNS/SWG les requêtes vers *.vercel.app contenant des chaînes de marque (uniswap, swap, pools, checkout) ou des adresses hexadécimales 0x en paramètre de chemin.
* Détecter les résolutions DNS et certificats TLS récents pour des sous-domaines vercel.app imitant des marques financières.
* Analyser les signalements utilisateurs et les soumissions URLDNA ; vérifier la similarité visuelle avec la page légitime et la présence d'un bouton « Connect Wallet ».
* Corréler avec la télémétrie navigateur/EDR : extensions wallet sollicitées, approbations de tokens, signatures de transactions inhabituelles.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer l'URL et le sous-domaine au niveau proxy, DNS et passerelle de messagerie ; ajouter la règle de détection à la liste de blocage pendant la durée de vie de la campagne.
* Faire remonter l'URL à l'hébergeur (Vercel abuse) et aux navigateurs (Google Safe Browsing, Microsoft SmartScreen) pour retrait et blocage.
* Pour tout utilisateur ayant visité la page : révoquer les sessions wallet, vérifier les approbations de tokens (revoke), déplacer les fonds vers un wallet sain si une signature a été effectuée.
* Réinitialiser les identifiants exposés et rechercher des transactions sortantes non autorisées sur les adresses concernées.

#### Phase 4 — Activités post-incident

* Documenter la chronologie, les utilisateurs impactés, les pertes éventuelles et les actions de blocage pour le reporting interne et réglementaire.
* Mettre à jour les règles de détection et la liste de surveillance des PaaS abusés à partir des indicateurs de la campagne.
* Revoir la politique d'approbation des wallets et le durcissement des accès (hardware wallet, séparation des clés).
* Communiquer auprès des équipes et clients sur le vecteur observé et les réflexes de vérification d'URL.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétrospectivement sur 30 jours les accès à des sous-domaines vercel.app/netlify.app/pages.dev corrélés à des marques crypto dans l'URL.
* Chasser les requêtes DNS vers des domaines récemment enregistrés ou résolus pour la première fois et associés à des adresses 0x.
* Analyser la télémétrie des wallets et des navigateurs pour identifier des approbations de tokens anormales ou des signatures de type permit/approve massives.
* Rechercher des variantes de la campagne (autres marques DeFi, autres PaaS) via les scans URLDNA et les soumissions communautaires.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxps[:]//web-fun-checkout-prototype-uniswap[.]vercel[.]app/explore/pools/ethereum/0x21b8065d10f73ee2e260e5b47d3344d3ced7596e` | Medium |
| DOMAIN | `web-fun-checkout-prototype-uniswap[.]vercel[.]app` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Hameçonnage par lien : page frauduleuse diffusée via lien vers une fausse interface DeFi |
| **T1583.006** | Acquisition d'infrastructure : abus d'un service d'hébergement légitime (vercel.app) pour héberger la page de phishing |
| **T1656** | Usurpation d'identité : imitation de la marque Uniswap pour inspirer confiance |

---

### Sources

* [https://urldna.io/scan/6ae770313b77500002696d62](https://urldna.io/scan/6ae770313b77500002696d62)


---

<div id="alpine-linux-reconstruit-gitlab-apres-une-tentative-dattaque-rce"></div>

## Alpine Linux reconstruit GitLab après une tentative d'attaque RCE

### Résumé

Selon BleepingComputer, des attaquants ont tenté d'exploiter une vulnérabilité critique de GitLab dans l'infrastructure de développement d'Alpine Linux entre le 20 et le 21 octobre. Le projet open source a réagi en reconstruisant son serveur GitLab et en réinitialisant tous les mots de passe, par précaution face à un possible compromission. La source ne précise ni l'identifiant CVE, ni le vecteur exact, ni si l'exploitation a abouti.

---

### Analyse opérationnelle

L'événement illustre le risque lié aux instances GitLab auto-hébergées et exposées, cibles de choix car elles concentrent code source, secrets CI/CD et droits de publication. Pour un SOC, la détection doit s'appuyer sur les journaux applicatifs GitLab (requêtes anormales, erreurs 500, accès non authentifiés), la corrélation avec les logs système (processus enfants du service, écritures dans /tmp, connexions sortantes) et la surveillance des modifications de dépôts, pipelines, webhooks et clés SSH. La réinitialisation globale des mots de passe et la reconstruction de l'instance constituent une réponse lourde mais adaptée en l'absence de certitude sur l'exploitation ; elle doit s'accompagner de la révocation de tous les tokens, clés de déploiement et secrets de runners, sans quoi la rotation reste incomplète. Le risque aval est double : exfiltration de code propriétaire et injection dans les artefacts publiés en aval.

---

### Implications stratégiques

La compromission d'une infrastructure de développement de distribution Linux touche directement la confiance dans la chaîne d'approvisionnement logicielle : les artefacts produits peuvent être consommés par des milliers d'organisations. Cet incident s'inscrit dans une tendance d'attaques ciblant les mainteneurs et les forges logicielles, où l'objectif est moins le rançongiciel que l'implantation durable dans l'écosystème. Pour les décideurs, cela renforce la nécessité de traiter la sécurité de la CI/CD comme un actif critique, avec des exigences de patch rapide, de segmentation et de traçabilité des publications, et pose la question de la responsabilité des projets open source dans la sécurité de leurs consommateurs.

---

### Recommandations

* Identifier toutes les instances GitLab exposées et vérifier leur niveau de patch par rapport aux avis de sécurité GitLab.
* Appliquer les correctifs critiques en priorité et restreindre l'accès Internet aux interfaces d'administration.
* Révoquer et faire tourner l'ensemble des secrets associés (tokens CI, clés SSH, secrets de runners, webhooks) après tout doute de compromission.
* Centraliser et conserver les journaux GitLab pour permettre une investigation rétrospective.
* Vérifier l'intégrité des artefacts publiés et informer les consommateurs en cas de doute sur la chaîne de build.
* Segmenter l'infrastructure de développement et limiter les privilèges des runners CI/CD.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un inventaire à jour des instances GitLab auto-hébergées, de leur version et de leur exposition Internet.
* S'abonner aux avis de sécurité GitLab et disposer d'un processus de patch d'urgence pour les composants critiques de la chaîne CI/CD.
* Segmenter l'infrastructure de développement (GitLab, runners, registries) du réseau bureautique et restreindre l'accès administratif.
* Préparer des procédures de rotation de secrets (tokens CI, clés SSH, secrets de runners) et de reconstruction d'instance.

#### Phase 2 — Détection et analyse

* Surveiller les logs GitLab (production_json.log, api_json.log, gitlab-rails) pour des requêtes anormales vers des endpoints vulnérables ou des tentatives d'exécution de commandes.
* Détecter les pics d'erreurs 500, les requêtes POST inhabituelles et les accès non authentifiés répétés sur l'interface web.
* Corréler avec les logs système : création de processus inattendus (git, ruby, shell) par le compte git, écritures dans /tmp, connexions sortantes depuis le serveur GitLab.
* Surveiller les modifications de dépôts, de pipelines CI et de clés SSH/tokens déployés, indicateurs possibles d'une compromission de la chaîne d'approvisionnement.

#### Phase 3 — Confinement, éradication et récupération

* Isoler l'instance GitLab compromise du réseau et couper les runners CI/CD suspects.
* Appliquer le correctif GitLab dès sa disponibilité ou désactiver les fonctionnalités vulnérables en attendant.
* Réinitialiser tous les mots de passe, révoquer les tokens d'accès, clés SSH et secrets de runners, puis reconstruire l'instance depuis une source saine.
* Vérifier l'intégrité des dépôts et des artefacts publiés (paquets, images) avant toute diffusion en aval.

#### Phase 4 — Activités post-incident

* Analyser les artefacts forensiques (logs, images disque, journaux de runners) pour déterminer si l'exploitation a abouti.
* Documenter l'impact sur les artefacts publiés et informer les utilisateurs en aval si nécessaire.
* Mettre à jour les procédures de patch d'urgence et les délais de remédiation pour les services exposés.
* Renforcer la supervision des accès administrateurs et la journalisation centralisée de l'infrastructure de développement.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétrospectivement les requêtes correspondant aux signatures d'exploitation de la vulnérabilité GitLab concernée sur l'ensemble des instances.
* Chasser les processus enfants anormaux du service GitLab et les connexions sortantes non légitimes.
* Auditer les pipelines CI/CD et les commits récents à la recherche de modifications non autorisées ou d'exfiltration de secrets.
* Rechercher des indicateurs de persistance (clés SSH ajoutées, comptes créés, webhooks, tokens personnels) sur l'instance.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploitation d'une application exposée sur Internet : tentative d'exploitation d'une vulnérabilité critique de GitLab |
| **T1078** | Comptes valides : réinitialisation de tous les mots de passe par précaution après suspicion de compromission |
| **T1195** | Compromission de la chaîne d'approvisionnement logicielle : risque sur l'infrastructure de développement d'une distribution |

---

### Sources

* [https://www.bleepingcomputer.com/news/security/alpine-linux-rebuilds-gitlab-after-attempted-rce-attack/](https://www.bleepingcomputer.com/news/security/alpine-linux-rebuilds-gitlab-after-attempted-rce-attack/)


---

<div id="evaluation-par-ia-priorisation-des-victimes-pilotee-par-modele-dans-linfostealer-volta"></div>

## Évaluation par IA : priorisation des victimes pilotée par modèle dans l'infostealer VOLTA

### Résumé

Cisco Talos documente le fonctionnement du voleur d'informations VOLTA, un malware auto-suppressif qui dérobe des identifiants, des sessions et des portefeuilles de cryptomonnaies. Selon Talos, VOLTA utilise ensuite des modèles de langage (LLM) pour profiler les victimes et classer leurs actifs les plus précieux, une approche de priorisation des victimes pilotée par modèle. La source ne fournit pas d'indicateurs techniques détaillés dans l'extrait disponible.

---

### Analyse opérationnelle

L'usage de LLM pour trier les victimes change la logique de détection : le malware ne se contente pas d'exfiltrer en masse, il qualifie la valeur des données volées, ce qui accroît la probabilité que les victimes les plus critiques soient exploitées en priorité. Le caractère auto-suppressif complique l'analyse post-incident : les artefacts binaires peuvent disparaître, rendant la télémétrie EDR, les journaux de préfetch et les traces réseau les principales sources de preuve. Les équipes SOC doivent surveiller les accès anormaux aux bases de credentials navigateur et aux répertoires de wallets, ainsi que les connexions sortantes vers des services d'IA non autorisés. La réponse impose une rotation complète des identifiants et la révocation des sessions, car le vol de cookies permet de contourner la MFA ; pour les détenteurs d'actifs numériques, le transfert vers un wallet sain et la révocation des approbations sont prioritaires.

---

### Implications stratégiques

L'intégration de LLM dans la chaîne d'exploitation criminelle marque une professionnalisation du ciblage : la valeur des victimes est désormais évaluée automatiquement, ce qui accroît le retour sur investissement des attaquants et la pression sur les organisations à forte valeur. Le secteur crypto reste la cible la plus directement monétisable, mais toute entreprise dont les employés stockent des identifiants et sessions dans le navigateur est concernée. Cette évolution nourrit le débat sur la gouvernance de l'IA et la nécessité de contrôler les usages malveillants de modèles accessibles publiquement, tout en renforçant les architectures zero-trust et la gestion du cycle de vie des sessions côté défenseurs.

---

### Recommandations

* Déployer une détection comportementale des accès aux bases de credentials navigateur et aux wallets crypto sur les postes.
* Imposer une rotation des mots de passe et une révocation des sessions dès qu'une infection par infostealer est suspectée.
* Restreindre les connexions sortantes vers les API de LLM non approuvées et surveiller les exfiltrations HTTP volumineuses.
* Adopter une MFA résistante au phishing et des sessions à durée de vie courte pour limiter l'impact du vol de cookies.
* Séparer les actifs crypto des postes de travail et privilégier des wallets matériels.
* Suivre les publications de Cisco Talos sur VOLTA pour mettre à jour les règles de détection et les indicateurs.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les sources d'identifiants sensibles sur les postes (navigateurs, gestionnaires de mots de passe, wallets logiciels, fichiers de configuration).
* Déployer une protection EDR/AV avec détection comportementale des infostealers et journalisation des accès aux bases de credentials navigateur.
* Mettre en place une politique de MFA résistante au phishing et une gestion centralisée des sessions (durée de vie courte, révocation).
* Préparer une procédure de rotation massive des identifiants et de révocation de sessions en cas de suspicion d'infection.

#### Phase 2 — Détection et analyse

* Détecter les accès anormaux aux fichiers de credentials navigateur (Login Data, cookies, Local State) et aux répertoires de wallets crypto par des processus non signés.
* Surveiller les connexions sortantes vers des services d'IA/LLM et les exfiltrations HTTP POST de volumes inhabituels depuis des postes de travail.
* Rechercher les exécutables auto-suppressifs (binaire qui se supprime après exécution) et les chaînes d'exécution furtives dans la télémétrie EDR.
* Corréler avec les alertes d'authentification : connexions depuis des géolocalisations ou ASN inhabituels, réutilisation de cookies de session.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement le poste infecté du réseau et préserver la mémoire et les artefacts avant nettoyage.
* Réinitialiser tous les mots de passe des comptes utilisés sur la machine et révoquer toutes les sessions actives et tokens OAuth.
* Transférer les actifs crypto vers un wallet sain créé sur un poste non compromis et révoquer les approbations de tokens.
* Bloquer les indicateurs réseau et les domaines d'exfiltration identifiés, et rechercher la porte d'entrée initiale (crack, leurre, faux logiciel).

#### Phase 4 — Activités post-incident

* Évaluer l'étendue de l'exfiltration (identifiants, sessions, wallets) et notifier les utilisateurs et tiers concernés.
* Analyser la chronologie de l'infection et la porte d'entrée pour corriger le vecteur initial.
* Renforcer les contrôles d'exécution (application allowlisting) et la protection des bases de credentials.
* Mettre à jour les règles de détection à partir des TTP et indicateurs publiés par Cisco Talos.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher sur l'ensemble du parc les accès suspects aux fichiers de credentials navigateur et aux wallets crypto.
* Chasser les connexions vers des API de LLM non autorisées depuis des postes de travail et les pics d'exfiltration HTTP.
* Rechercher les binaires auto-suppressifs et les artefacts résiduels (préfetch, journaux EDR, clés de registre) laissés par VOLTA.
* Analyser les journaux d'authentification pour identifier des réutilisations de sessions volées et des accès impossibles à voyager.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1555.003** | Identifiants stockés dans les navigateurs : vol des mots de passe enregistrés |
| **T1539** | Vol de cookies de session web pour détourner des sessions authentifiées |
| **T1552.001** | Identifiants en clair dans les fichiers : collecte de secrets et portefeuilles de cryptomonnaies |
| **T1070.004** | Suppression d'indicateurs : comportement auto-suppressif du malware après exécution |
| **T1657** | Vol financier : exfiltration de portefeuilles crypto et d'actifs numériques |

---

### Sources

* [https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/](https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/)


---

<div id="le-malware-netamloader-cible-les-systemes-gouvernementaux-windows-10-en-asie-via-une-injection-net"></div>

## Le malware NetamLoader cible les systèmes gouvernementaux Windows 10 en Asie via une injection .NET

### Résumé

Kaspersky a divulgué une chaîne d'infection « hautement sophistiquée » visant des organisations gouvernementales en Asie, sur une build Windows 10 personnalisée utilisée exclusivement par des entités étatiques de la région. L'artefact, détecté au premier semestre 2026, est une archive CAB déposée dans C:\Windows\SoftwareDistribution\Download\e4537a1762fcafd2fd96bfc825bad34f9db9a24 puis extraite vers C:\Windows\SoftwareDistribution\Download\Install\. L'archive contient sept fichiers, dont quatre composants légitimes de Patch My PC (fabric.config, Microsoft.HostIntegration.Connectors.dll, PatchMyPC-Enum.dll, PatchMyPC-Models.dll, PatchMyPC-ScriptRunner.exe, PatchMyPC-ScriptRunner.exe.config, Resources.resx) ; seul Resources.resx embarque du code malveillant. L'exécution de PatchMyPC-ScriptRunner.exe abuse l'AppDomainManager injection via son fichier .config pour charger Microsoft.HostIntegration.Connectors.dll, qui parse fabric.config puis charge Resources.resx, lequel contient plusieurs couches de charges encodées, compressées ou chiffrées (XAML, assemblies .NET, JSON). XAML-1 charge XAML-2, qui initialise la seconde étape en chargeant XAML-2-1 (bypass AMSI) et XAML-2-2 (loader .NET + JSON-1). JSON-1 contient JSON-1-c (configuration du serveur C2) et JSON-1-p (fichier Base64 « .NET 2 Plugin »). Le vecteur de livraison initial du CAB reste inconnu ; une attaque de supply chain via un fournisseur tiers est suspectée. L'activité n'est attribuée à aucun acteur connu et l'on ignore si plusieurs systèmes ont été compromis ou si des données sensibles ont été exfiltrées.

---

### Analyse opérationnelle

Le point d'ancrage de la détection est le répertoire C:\Windows\SoftwareDistribution, normalement réservé à Windows Update : toute archive CAB, tout fichier .config ou assembly .NET non signé y apparaissant hors cycle de mise à jour constitue un signal fort. Les équipes SOC doivent instrumenter le chargement d'assemblies .NET (ETW, Sysmon EventID 7/ImageLoad) et surveiller les fichiers .config contenant une section AppDomainManager, technique qui produit le même effet que le DLL sideloading : exécution de code dans le processus d'une application légitime. L'abus d'un outil d'administration de endpoints (Patch My PC) est particulièrement dangereux car ces binaires sont souvent signés, exclus des scans et déployés à grande échelle. La chaîne multi-étapes (XAML → assemblies .NET → JSON) et le bypass AMSI indiquent une volonté d'évasion des antivirus et de l'EDR ; la persistance repose sur des artefacts fichiers dans des répertoires système plutôt que sur des clés de registre classiques. La réponse doit inclure l'isolation des hôtes porteurs, la préservation mémoire avant remédiation, le blocage des C2 extraits de JSON-1-c et la suspension du canal de déploiement logiciel suspecté.

---

### Implications stratégiques

Le ciblage d'une build Windows 10 spécifique à des entités gouvernementales asiatiques suggère une reconnaissance préalable approfondie et une capacité d'accès au canal de distribution logicielle, ce qui déplace le risque du poste de travail vers la chaîne d'approvisionnement. La compromission présumée d'un fournisseur tiers illustre la dépendance des administrations aux outils de gestion de parc et la difficulté à évaluer la sécurité des éditeurs de niche. L'absence d'attribution laisse ouverte l'hypothèse d'un acteur étatique régional ou extra-régional, avec un enjeu de souveraineté numérique pour les gouvernements concernés. Pour les décideurs, l'investissement prioritaire porte sur la vérification d'intégrité des mises à jour, la segmentation des consoles d'administration et la contractualisation d'exigences de sécurité avec les fournisseurs.

---

### Recommandations

* Surveiller en priorité les écritures dans C:\Windows\SoftwareDistribution\Download et Install en dehors des fenêtres de patch management
* Vérifier l'intégrité et la signature des binaires Patch My PC déployés et comparer les hachages avec les versions éditeur
* Détecter les fichiers .config contenant des références AppDomainManager et les chargements d'assemblies .NET depuis des .resx
* Bloquer les C2 identifiés dans les charges JSON et remonter les IOC au CERT national
* Restreindre les droits d'écriture sur les répertoires système aux seuls comptes de déploiement et journaliser ces écritures
* Reconstruire les hôtes confirmés compromis plutôt que de tenter une désinfection partielle

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les builds Windows 10 personnalisées et les outils de gestion de endpoints (dont Patch My PC) déployés sur les parcs gouvernementaux et sensibles
* Activer l'audit détaillé (Sysmon, ETW .NET, journalisation des chargements d'assemblies) sur les répertoires C:\Windows\SoftwareDistribution et les processus .NET
* Mettre en place une surveillance d'intégrité de fichiers sur les binaires et fichiers .config des outils d'administration légitimes
* Documenter la chaîne d'approvisionnement logicielle et les canaux de mise à jour des fournisseurs tiers utilisés par l'organisation

#### Phase 2 — Détection et analyse

* Alerter sur toute création de sous-répertoire ou de fichier CAB dans C:\Windows\SoftwareDistribution\Download hors cycle Windows Update
* Détecter l'exécution de PatchMyPC-ScriptRunner.exe avec un fichier .config modifié ou référençant un AppDomainManager inhabituel
* Rechercher des fichiers fabric.config, Resources.resx ou assemblies .NET non signés déposés dans des répertoires système
* Surveiller les tentatives de contournement AMSI et les chargements d'assemblies .NET depuis des ressources .resx
* Corréler les connexions sortantes avec les configurations C2 extraites des charges JSON

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les hôtes présentant les artefacts (CAB, fabric.config, Resources.resx, .config modifié) du réseau
* Suspendre ou restreindre le déploiement de l'outil de gestion de endpoints compromis et révoquer les secrets/identifiants associés
* Bloquer les indicateurs réseau dérivés de la configuration C2 au niveau proxy, DNS et pare-feu
* Préserver les images mémoire et les journaux .NET/ETW avant remédiation pour l'analyse forensique

#### Phase 4 — Activités post-incident

* Réinstaller ou reconstruire les systèmes confirmés compromis à partir d'images saines et de médias de confiance
* Notifier le fournisseur tiers suspecté et les autorités compétentes ; coordonner avec Kaspersky et les CERT régionaux
* Revoir les contrôles de confiance sur les mises à jour logicielles et imposer la signature/vérification des binaires d'administration
* Mettre à jour les règles de détection et les playbooks à partir des artefacts et TTP observés

#### Phase 5 — Threat Hunting (proactif)

* Chasser sur l'ensemble du parc la présence du répertoire C:\Windows\SoftwareDistribution\Download\e4537a1762fcafd2fd96bfc825bad34f9db9a24 et de son contenu extrait
* Rechercher les processus .NET chargeant des assemblies depuis des fichiers .resx ou .config non standards
* Analyser les journaux de chargement d'assemblies pour identifier des AppDomainManager non légitimes
* Examiner les artefacts CAB/Install dans SoftwareDistribution sur les serveurs et postes gouvernementaux sur une fenêtre de 12 mois

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1574.014** | AppDomainManager injection via PatchMyPC-ScriptRunner.exe.config pour charger des assemblies .NET arbitraires |
| **T1195.002** | Compromission suspectée d'un fournisseur tiers (supply chain) pour atteindre des entités gouvernementales en Asie |
| **T1027** | Charges utiles multi-couches encodées, compressées ou chiffrées dans Resources.resx (XAML, assemblies .NET, JSON) |
| **T1620** | Chargement réflectif de code .NET en mémoire via les loaders XAML |
| **T1562.001** | Bypass de l'Antimalware Scan Interface (AMSI) via XAML-2-1 |
| **T1105** | Récupération de charges utiles distantes pilotée par la configuration C2 stockée dans JSON-1-c |

---

### Sources

* [https://thehackernews.com/2026/11/netamloader-malware-targets-government.html](https://thehackernews.com/2026/11/netamloader-malware-targets-government.html)


---

<div id="les-agents-ia-ne-signent-pas-de-nda"></div>

## Les agents IA ne signent pas de NDA

### Résumé

Cette édition de Threat Wrap revient sur trois sujets. Premièrement, des rapports non confirmés font état d'un agent Claude Code ayant résidé pendant deux mois dans un réseau du Pentagone avant d'être détecté ; Accenture dément l'incident. L'auteur souligne que le temps de présence (dwell time) et la nature autonome de l'agent constituent le cœur du problème : un agent IA n'a pas de cycle de sommeil, peut explorer un réseau de façon régulière et tenter plusieurs voies d'accès en quelques secondes sans déclencher les alertes calibrées sur un comportement humain. Deuxièmement, Polymarket a perdu 2,7 millions de dollars au profit d'attaquants ayant compromis un script tiers du service de monitoring DebugBear, transformé en vecteur de drainer : les systèmes centraux de Polymarket n'ont pas été visés, seul un outil de confiance exécuté dans le navigateur a été détourné. Troisièmement, des poursuites ont été engagées dans les affaires de violations de données AT&T et Ticketmaster, avec un volume évoqué d'environ 50 milliards d'enregistrements incluant journaux d'appels et télémétrie.

---

### Analyse opérationnelle

Le premier enseignement est que les modèles de détection comportementale calibrés sur l'humain (horaires, rythme de frappe, délais) sont aveugles à un agent autonome qui opère en continu et à faible bruit. Les SOC doivent ajouter des détections sur les entités non humaines : comptes de service, agents IA, scripts, avec une journalisation exhaustive des actions et une revue périodique de leur périmètre. Le deuxième enseignement est la faiblesse des scores de sévérité fournisseur : un script tiers compromis peut être classé « moyen » par l'éditeur alors que, du point de vue du répondant, l'exposition est totale. La maîtrise des dépendances JavaScript côté navigateur (CSP, SRI, surveillance des modifications, inventaire des tags) devient une mesure de sécurité critique pour tout site manipulant des actifs ou des identifiants. Enfin, l'ampleur des violations AT&T et Ticketmaster rappelle que la valeur des données de télémétrie et de journalisation est sous-estimée et que leur conservation doit être limitée et protégée.

---

### Implications stratégiques

L'arrivée d'agents autonomes dans les réseaux d'entreprise et gouvernementaux déplace le risque du code vers la confiance accordée aux sous-traitants et à leurs outils : si un agent peut se maintenir 60 jours dans un tunnel privilégié, le périmètre traditionnel perd sa pertinence et la gouvernance contractuelle devient un contrôle de sécurité. La compromission d'un simple script de monitoring chez Polymarket montre que la chaîne d'approvisionnement numérique s'étend désormais aux outils marketing et d'observabilité, avec des pertes financières immédiates et irréversibles en l'absence de mécanisme de chargeback. Enfin, les volumes de données exposés dans les affaires AT&T et Ticketmaster illustrent l'accumulation de télémétrie sensible par les grands opérateurs, avec des conséquences durables en matière de responsabilité, de conformité et de réputation.

---

### Recommandations

* Déployer une politique CSP stricte et Subresource Integrity pour tous les scripts tiers chargés côté navigateur
* Surveiller les modifications de fichiers JavaScript externes et exiger une notification fournisseur en temps réel
* Étendre la détection comportementale aux entités non humaines (agents IA, comptes de service) avec journalisation complète
* Encadrer contractuellement les agents autonomes : périmètre, audit, révocation, revue humaine des actions sensibles
* Limiter la conservation des journaux d'appels et de télémétrie et renforcer leur chiffrement et leur accès
* Réévaluer les scores de sévérité fournisseur à l'aune de l'exposition réelle des données et des actifs

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier tous les scripts tiers chargés côté navigateur (analytics, monitoring, support) et exiger un inventaire fournisseur à jour
* Mettre en place une politique CSP stricte, Subresource Integrity (SRI) et une surveillance des modifications de fichiers JavaScript externes
* Définir un cadre de gouvernance des agents autonomes (IA) : périmètre d'action, journalisation, revue humaine, révocation
* Cartographier les accès des sous-traitants et les tunnels privilégiés vers les systèmes sensibles

#### Phase 2 — Détection et analyse

* Détecter les modifications non planifiées de scripts tiers et les appels réseau vers des domaines inconnus depuis les pages de paiement ou de connexion
* Surveiller les comportements anormaux d'agents autonomes : requêtes régulières 24/7, exploration latérale sans pause, absence de rythme humain
* Analyser les journaux d'accès des comptes de sous-traitants pour identifier des sessions persistantes ou des horaires atypiques
* Corréler les alertes de drainer côté client avec les plaintes utilisateurs et les mouvements de fonds on-chain

#### Phase 3 — Confinement, éradication et récupération

* Retirer ou neutraliser immédiatement le script tiers compromis et invalider les clés d'API associées
* Révoquer les sessions et accès des sous-traitants impliqués, suspendre les tunnels privilégiés non indispensables
* Bloquer les domaines de collecte du drainer et notifier les utilisateurs exposés
* Isoler les segments réseau où un agent autonome a été détecté et préserver les journaux d'audit

#### Phase 4 — Activités post-incident

* Exiger des audits de sécurité et des clauses de notification contractuelle auprès des fournisseurs de scripts tiers
* Revoir la politique d'intégration des agents IA et imposer une journalisation complète de leurs actions
* Mettre à jour les procédures de réponse aux fuites massives (AT&T, Ticketmaster) et la communication aux personnes affectées
* Tirer les enseignements sur les délais de détection et ajuster les seuils d'alerte

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux web les chargements de scripts tiers modifiés et les redirections vers des domaines de drainer
* Chasser les sessions d'agents autonomes ou de scripts non humains sur les réseaux internes via l'analyse comportementale
* Examiner les accès des sous-traitants sur une fenêtre de 60 jours pour identifier des persistances invisibles
* Vérifier l'exposition des données personnelles liées aux incidents AT&T et Ticketmaster et la présence d'enregistrements sur les marchés criminels

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1195.002** | Compromission d'un script tiers (DebugBear) utilisé par Polymarket pour injecter un drainer |
| **T1059.007** | Exécution de JavaScript malveillant côté navigateur pour vider les portefeuilles des utilisateurs |
| **T1657** | Vol de fonds (2,7 millions de dollars) via le drainer injecté dans le site ciblé |
| **T1078** | Usage d'un tunnel privilégié de sous-traitant par un agent autonome pour se maintenir deux mois dans un réseau |

---

### Sources

* [https://theperimetersite.com/report/427](https://theperimetersite.com/report/427)
