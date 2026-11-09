# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [SentinelOne Prompt Security : l'agent endpoint](#sentinelone-prompt-security-lagent-endpoint)
  * [🚨New ransom group blog post!🚨Group name: anubis Post title: Kahler Automation Location: 🇩🇪 DE Sector: Agriculture & Food](#new-ransom-group-blog-postgroup-name-anubis-post-title-kahler-automation-location-de-sector-agriculture-food)
  * [Phishing possible 🎣 sur : ⚠️hxxps[:]//netflixtoto[.]xyz](#phishing-possible-sur-hxxpsnetflixtotoxyz)
  * [Ainsi, #OpenSSH sur #Alpine est trivialement facile à pirater pour obtenir root. Dans la #infosec, cela est connu comme « mauvais ». Alpine confirme que l'exploitation nécessite une connexion, un port #SSH joignable et un nom de compte connu lorsque les conditions requises existent. La faille peut permettre à des attaquants distants de contourner l'authentification par mot de passe sur les serveurs Alpine #Linux affectés, y compris les comptes destinés à un accès par clé uniquement. OpenSSH a publié Portable 10.6p2 le 5 novembre 2026 pour bloquer le problème, qui affecte les systèmes Linux utilisant #musl #libc sans authentification #PAM. Si c'est votre configuration, allez la corriger MAINTENANT. Voici un lien vers le site du chercheur ozgun #kultekin, où il explique l'historique, et un dessin tldr, également d'Orzgun.https://sshhole.com/](#ainsi-openssh-sur-alpine-est-trivialement-facile-a-pirater-pour-obtenir-root-dans-la-infosec-cela-est-connu-comme-mauvais-alpine-confirme-que-lexploitation-necessite-une-connexion-un-port-ssh-joignable-et-un-nom-de-compte-connu-lorsque-les-conditions-requises-existent-la-faille-peut-permettre-a-des-attaquants-distants-de-contourner-lauthentification-par-mot-de-passe-sur-les-serveurs-alpine-linux-affectes-y-compris-les-comptes-destines-a-un-acces-par-cle-uniquement-openssh-a-publie-portable-106p2-le-5-novembre-2026-pour-bloquer-le-probleme-qui-affecte-les-systemes-linux-utilisant-musl-libc-sans-authentification-pam-si-cest-votre-configuration-allez-la-corriger-maintenant-voici-un-lien-vers-le-site-du-chercheur-ozgun-kultekin-ou-il-explique-lhistorique-et-un-dessin-tldr-egalement-dorzgunhttpssshholecom)
  * [Dissecting WerFault](#dissecting-werfault)
  * [Cela aurait pu être une mauvaise journée pour DHS.gov, surtout dans ce climat](#cela-aurait-pu-etre-une-mauvaise-journee-pour-dhsgov-surtout-dans-ce-climat)
  * [Outil open source qui classe les correctifs AD selon le nombre d'utilisateurs qu'ils coupent de Domain Admin, et signale d'abord les plus faciles (retours souhaités)](#outil-open-source-qui-classe-les-correctifs-ad-selon-le-nombre-dutilisateurs-quils-coupent-de-domain-admin-et-signale-dabord-les-plus-faciles-retours-souhaites)
  * [Fantôme dans le script : risques cachés](#fantome-dans-le-script-risques-caches)
  * [Nous évaluons avec une haute confiance que l'échantillon est Arid Gopher, et donc une activité d'Arid Viper. Les deux campagnes partagent la victimologie et les habitudes de nommage.](#nous-evaluons-avec-une-haute-confiance-que-lechantillon-est-arid-gopher-et-donc-une-activite-darid-viper-les-deux-campagnes-partagent-la-victimologie-et-les-habitudes-de-nommage)
  * [RT: @fuitesinfos 🚨 FUITES INFOS | SGS — ~ 22,7 millions de personnes et 4000 centres. #controletechnique](#rt-fuitesinfos-fuites-infos-sgs-227-millions-de-personnes-et-4000-centres-controletechnique)
  * [Comté de Sussex, New Jersey : avis d'incident de confidentialité des données](#comte-de-sussex-new-jersey-avis-dincident-de-confidentialite-des-donnees)
  * [CTM360 expose des arnaques aux fausses cartes cadeaux exploitant des marques de confiance](#ctm360-expose-des-arnaques-aux-fausses-cartes-cadeaux-exploitant-des-marques-de-confiance)
  * [1,4 million d'e-mails de phishing envoyés via le système d'alerte aux catastrophes du Japon](#14-million-de-mails-de-phishing-envoyes-via-le-systeme-dalerte-aux-catastrophes-du-japon)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

La CTI du jour est dominée par 24 vulnérabilités et 22 violations de données, qui concentrent l’essentiel du volume et doivent structurer les priorités opérationnelles. La priorité immédiate est de qualifier les vulnérabilités exploitables et exposées, puis d’accélérer les correctifs sur les actifs critiques. Les 22 violations de données imposent une surveillance renforcée des fuites, une évaluation de l’exposition des identifiants et une coordination avec les équipes juridiques et communication. Les 4 items réglementaires appellent une vérification de conformité et de notification, sans toutefois détourner les ressources de la remédiation technique. Les 2 acteurs de menace et 2 signaux géopolitiques restent limités en volume mais doivent être contextualisés pour détecter d’éventuelles campagnes ciblées ou changements d’intérêt. Les 13 articles fournissent un socle de contexte utile pour trianguler les signaux, mais ne doivent pas diluer la priorisation face aux risques techniques et aux fuites de données. En synthèse, la journée doit être pilotée autour de la réduction de l’exposition aux vulnérabilités et de la maîtrise des violations de données, avec une veille réglementaire et géopolitique en soutien.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **Storm-1567 (alias : Akira)** | commerce de détail | Double extorsion, accès initial via VPN ou identifiants, revendication non vérifiée. | T1133, T1486, T1567, T1657 | [https://www.yazoul.net/intel/claim/2026-11-07-ligne-roset-ransomware-claim-by-akira-nov-2026/?utm_source=mastodon&utm_medium=social](https://www.yazoul.net/intel/claim/2026-11-07-ligne-roset-ransomware-claim-by-akira-nov-2026/?utm_source=mastodon&utm_medium=social)<br>[https://infosec.exchange/@Matchbook3469/117581208576693618](https://infosec.exchange/@Matchbook3469/117581208576693618) |
| **DataSuckers** |  | Compromission d'identifiants, fuite de données et site de fuite; arrestations. | T1552, T1078, T1213, T1567, T1657 | [https://www.zataz.com/datasuckers-trois-suspects-arretes-apres-une-fuite/](https://www.zataz.com/datasuckers-trois-suspects-arretes-apres-une-fuite/)<br>[https://infosec.exchange/@cloud/117581342037352265](https://infosec.exchange/@cloud/117581342037352265) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Union européenne, Russie, Ukraine** | Finance et cryptomonnaies | Contournement de sanctions par crypto-actifs | L’UE met en place une task force de 12 mois pour contrer l’usage des cryptomonnaies afin de contourner les sanctions imposées à la Russie. La priorité porte sur les réseaux liés au stablecoin A7A5 et, plus largement, sur les canaux financiers non traditionnels. Cette approche traduit un basculement vers l’application financière des sanctions plutôt que vers l’escalade militaire. Les marchés interprètent ce durcissement comme une baisse de probabilité d’un cessez-le-feu Russie-Ukraine d’ici fin 2026, mais l’impact réel dépendra de la capacité de la task force à perturber les flux, à coordonner les contrôles et à cibler les intermédiaires crypto. | [https://cryptobriefing.com/eu-launches-task-force-to-stop-crypto-sanctions-evasion-by-russia/](https://cryptobriefing.com/eu-launches-task-force-to-stop-crypto-sanctions-evasion-by-russia/)<br>[https://infosec.exchange/@edwardk/117580254955899781](https://infosec.exchange/@edwardk/117580254955899781) |
| **Estonie, Royaume-Uni, Russie** | Défense et opérations militaires | OPSEC, sécurité mobile et chantage | Un soldat britannique déployé en Estonie pour l’exercice Eastern Warrior a ignoré l’ordre de retirer sa carte SIM et de désactiver la localisation avant son déploiement. Son téléphone a été compromis, des photos intimes volées et utilisées pour un chantage. L’affaire illustre le risque opérationnel des appareils personnels en zone proche de la Russie, la nécessité d’appliquer strictement les mesures OPSEC et la rapidité avec laquelle une compromission personnelle peut devenir une vulnérabilité de sécurité. La condamnation en cour martiale souligne la gravité disciplinaire de l’écart aux procédures. | [https://arstechnica.com/security/2026/11/british-soldier-ignored-order-to-pull-his-sim-card-then-got-blackmailed/](https://arstechnica.com/security/2026/11/british-soldier-ignored-order-to-pull-his-sim-card-then-got-blackmailed/)<br>[https://infosec.exchange/@edwardk/117580250035841801](https://infosec.exchange/@edwardk/117580250035841801) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| United States v. Soall, Hazan & Sheetrit — acte d'accusation rendu public par le SDNY le 5 novembre 2026 | U.S. Attorney's Office for the Southern District of New York (SDNY) et FBI, New York Field Office | 2026-11-05 | États-Unis (ressort du SDNY) ; arrestations en Espagne (17/06/2026 et 05/08/2026) et au Royaume-Uni (07/09/2026) ; demandes d'extradition en cours | United States v. Soall, Hazan & Sheetrit — acte d'accusation rendu public par le SDNY le 5 novembre 2026 | Le parquet fédéral de Manhattan a rendu public un acte d'accusation visant trois ressortissants étrangers — Jacob Soall (alias « Seba Clarke », « Rocky Balboa »), Sharon Hazan (alias « Superman Cash », « Impossible Mission », « Fat Boy », « Ron ») et Guy Sheetrit — pour une campagne de fraude au virement assistée par « super intelligence » (SI), c'est-à-dire, dans les faits, par clonage vocal et génération d'images de synthèse. Les faits courent de 2024 à 2026 et portent sur plus de 129 millions de dollars, dont 4,8 M$ prélevés à un groupe hospitalier du Missouri, 2,7 M$ à une banque du Rhode Island et 3,0 M$ à un groupe hospitalier de Californie. Le mode opératoire est un BEC de nouvelle génération, en trois temps : (1) prise de contact avec un employé en se faisant passer pour le PDG de sa propre entreprise et invocation d'une opération financière confidentielle ; (2) relais vers de prétendus avocats de grands cabinets internationaux, eux aussi usurpés vocalement et visuellement pour donner de la crédibilité à l'opération ; (3) instruction de virement vers un compte bancaire contrôlé par la conspiration. L'élément notable pour la CTI est la rupture d'un postulat de sécurité longtemps admis en entreprise : la voix et l'image d'un dirigeant ne constituent plus un facteur d'authentification. Le communiqué du FBI comme celui du procureur insistent explicitement sur la nécessité pour le secteur privé d'adapter ses contrôles. Aucun indicateur technique (domaine, IP, hash) n'est publié à ce stade : l'affaire est décrite au niveau des TTP et des préjudices, ce qui limite l'exploitation directe en détection et impose un travail de chasse sur les comportements (procédures de paiement, canaux de vérification). | [https://www.justice.gov/usao-sdny/pr/three-foreign-nationals-arrested-and-charged-scheme-use-super-intelligence-defraud](https://www.justice.gov/usao-sdny/pr/three-foreign-nationals-arrested-and-charged-scheme-use-super-intelligence-defraud)<br>[https://www.reddit.com/r/blueteamsec/comments/1xquu7b/three_foreign_nationals_arrested_and_charged_with/](https://www.reddit.com/r/blueteamsec/comments/1xquu7b/three_foreign_nationals_arrested_and_charged_with/) |
| Avis éditeur « Manual Security Check Instructions for the PC Launcher » — Proxima Beta Pte. Ltd. / SHIFT UP CORP. | Proxima Beta Pte. Ltd. et SHIFT UP CORP. (éditeurs du jeu), via un avis publié sur le site officiel | 2026-11-04 | International — éditeurs établis à Singapour et en Corée du Sud ; base d'utilisateurs mondiale, dont l'Union européenne (le site mentionne le Digital Services Act) | Avis éditeur « Manual Security Check Instructions for the PC Launcher » — Proxima Beta Pte. Ltd. / SHIFT UP CORP. | L'éditeur de GODDESS OF VICTORY: NIKKE publie le 4 novembre 2026 un avis intitulé « Manual Security Check Instructions for the PC Launcher » demandant à tout utilisateur ayant lancé le launcher Windows au moins une fois depuis le 27 septembre 2026 à 15 h 41 (UTC+9) d'effectuer une vérification de sécurité et de prendre « les mesures nécessaires ». L'avis est extrêmement pauvre en informations : aucune nature d'incident n'est précisée (compromission du canal de mise à jour, binaire malveillant, vol d'identifiants, atteinte à la chaîne de distribution logicielle), aucun indicateur technique n'est fourni (hash, nom de fichier, domaine, version affectée), aucune CVE ni avis de sécurité détaillé n'est référencé, et la fenêtre d'exposition est exprimée par une simple date de lancement. Cette opacité est en soi un signal : elle empêche les utilisateurs comme les équipes de sécurité de vérifier l'état de leurs postes et de corréler l'événement avec leurs propres télémétries. Sur le plan réglementaire, l'épisode touche à plusieurs obligations : transparence et information des consommateurs, notification d'incident en cas d'atteinte à des données personnelles (RGPD, autorités de protection des données), obligations sectorielles de notification pour les entités essentielles ou importantes (NIS2) si l'éditeur ou ses prestataires relèvent du champ, et devoir de diligence des plateformes en ligne au titre du Digital Services Act. Le fait que l'éditeur s'en remette à une « vérification manuelle » par l'utilisateur, sans mesure automatisée ni correctif identifié, déplace la charge de la preuve et du risque vers la base installée. | [https://nikke-en.com/newsdetail.html?content_id=ecdccd40a55a5a46aaa9abda64d436082db7](https://nikke-en.com/newsdetail.html?content_id=ecdccd40a55a5a46aaa9abda64d436082db7)<br>[https://www.reddit.com/r/blueteamsec/comments/1xqus6j/goddess_of_victory_nikke_if_you_have_launched_the/](https://www.reddit.com/r/blueteamsec/comments/1xqus6j/goddess_of_victory_nikke_if_you_have_launched_the/) |
| Article de presse — Data Security Breach (rubrique réglementaire/juridique) | Article de presse rapportant les référentiels ISO/IEC 27001, les dispositifs de qualification de l'ANSSI (dont PASSI) et les activités d'évaluation d'organismes comme LSTI | 2026-11-09 | France et Union européenne (RGPD, NIS2, DORA) | Article de presse — Data Security Breach (rubrique réglementaire/juridique) | L'article analyse la montée en puissance de la certification comme instrument de confiance commerciale et de gouvernance du risque, dans un contexte où la sécurité ne se démontre plus par la seule déclaration. Trois familles de dispositifs sont distinguées, souvent confondues par les acheteurs : la certification de système de management (ISO/IEC 27001, qui atteste d'un SMSI — identification des risques, traitement, responsabilités, amélioration continue — sur un périmètre défini, après audit indépendant) ; la certification de compétences professionnelles, qui porte sur des personnes ; et la qualification ANSSI, qui porte sur des produits ou des prestations, avec des référentiels comme PASSI pour les prestataires d'audit. Le point juridique central est explicitement rappelé : être certifié ISO 27001 ne vaut pas conformité automatique au RGPD, à NIS2 ou à DORA, chaque texte imposant ses propres exigences, ses propres seuils et ses propres modalités de preuve. Pour une fonction CTI, l'article a une valeur opérationnelle : il fournit une grille de lecture pour évaluer les tiers (fournisseurs, prestataires d'audit, hébergeurs, sous-traitants) et pour éviter l'écueil du « certification-washing », c'est-à-dire l'invocation d'un certificat hors périmètre, expiré ou non accrédité. La complexification des chaînes de sous-traitance numériques y est présentée comme le moteur de cette exigence de preuves vérifiables et de vigilance continue. | [https://www.datasecuritybreach.fr/cybersecurite-la-certification-un-enjeu-strategique/](https://www.datasecuritybreach.fr/cybersecurite-la-certification-un-enjeu-strategique/) |
| Tribunal judiciaire de Paris, jugement du 6 novembre 2026 (affaire Vitaliy K. et deux coaccusés) | Tribunal judiciaire de Paris (juridiction pénale française) | 2026-11-07 | France — fondation Holograph immatriculée aux îles Caïmans, actifs émis sur la blockchain Mantle | Tribunal judiciaire de Paris, jugement du 6 novembre 2026 (affaire Vitaliy K. et deux coaccusés) | Le tribunal judiciaire de Paris a condamné le 6 novembre 2026 un ancien employé de la Holograph Foundation, identifié comme Vitaliy K., à cinq ans d'emprisonnement dont deux fermes, assortis d'une amende de 600 000 euros. Les qualifications retenues sont classiques mais appliquées à un objet crypto : accès non autorisé à un système de traitement automatisé de données, escroquerie en bande organisée, blanchiment et participation à une association de malfaiteurs. Les faits, commis entre mai et août 2024, consistent en la modification illégale des règles de minting des jetons HLG, permettant la création puis le vol d'un milliard de jetons, valorisés à l'époque environ 12,5 millions d'euros (≈14 M$). Deux complices ont été condamnés à des peines plus légères (deux ans, dont 14 mois avec sursis et 80 000 € d'amende pour l'un ; deux ans avec sursis et 40 000 € d'amende pour l'autre). La fondation a été déboutée de sa demande d'indemnisation au titre de la chute du cours du HLG, le tribunal ayant retenu l'absence de lien de causalité direct, le token ayant déjà fortement chuté avant les faits (≈0,03 $ en mai 2024, ≈0,001 $ fin décembre 2024). L'incident recoupe le post-mortem publié en juillet 2024 par Holograph et Halborn sur l'exploit d'un milliard de HLG sur la chaîne Mantle, attribué à un ancien prestataire mécontent ; une arrestation avait eu lieu en Italie en septembre 2024. La fondation a suspendu ses activités et prépare sa liquidation. L'enseignement de sécurité est majeur : l'audit de smart contract vérifie que le code fait ce qu'il dit, mais ne protège pas contre un acteur disposant légitimement des clés et des droits de gouvernance qui réécrit discrètement les règles. La menace est ici interne et privilégiée, non externe. | [https://cryptobriefing.com/holograph-employee-sentenced-hlg-token-mint/](https://cryptobriefing.com/holograph-employee-sentenced-hlg-token-mint/)<br>[https://infosec.exchange/@edwardk/117580252213344598](https://infosec.exchange/@edwardk/117580252213344598) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Logiciels / Gestion de mots de passe (SaaS grand public et entreprise)** | mSeven Software (mSecure) | Base de données clients chiffrée (coffres AES-256), métadonnées de comptes, adresses e-mail, secrets TOTP/2FA potentiellement exposés, passkeys enregistrées, données de facturation/abonnement non confirmées. | Inconnu | [https://aviatrix.ai/threat-research-center/msecure-password-manager-hack-prompts-password-reset-warnings](https://aviatrix.ai/threat-research-center/msecure-password-manager-hack-prompts-password-reset-warnings)<br>[https://infosec.exchange/@security_crawler_carl/117583410401856854](https://infosec.exchange/@security_crawler_carl/117583410401856854) |
| **Fintech / Crypto (cartes de débit adossées à des stablecoins)** | Gnosis Pay | Noms complets des clients, adresses email, numéros de téléphone, historique de transactions et détails d'achats, métadonnées de compte, identifiants personnels utilisés lors de l'enregistrement de la carte. Aucune clé privée, phrase de récupération ni fonds exposés. | Inconnu | [https://newisty.com/blog/gnosis-pay-data-breach-exposes-customer-names-and-home-addresses?utm_source=social&utm_campaign=crypto_news](https://newisty.com/blog/gnosis-pay-data-breach-exposes-customer-names-and-home-addresses?utm_source=social&utm_campaign=crypto_news)<br>[https://mastodon.social/@newisty/117579790262396670](https://mastodon.social/@newisty/117579790262396670)<br>[https://newisty.com/blog/gnosis-pay-data-breach-exposes-customer-names-and-home-addresses](https://newisty.com/blog/gnosis-pay-data-breach-exposes-customer-names-and-home-addresses)<br>[https://beyondmachines.net/event_details/gnosis-pay-discloses-data-breach-affecting-consumer-card-platform-e-m-s-6-b/gD2P6Ple2L](https://beyondmachines.net/event_details/gnosis-pay-discloses-data-breach-affecting-consumer-card-platform-e-m-s-6-b/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117580477680225793](https://infosec.exchange/@beyondmachines1/117580477680225793) |
| **SaaS / Infrastructure d'authentification et d'identité pour développeurs** | WorkOS | Périmètre non confirmé publiquement. Risque potentiel : données clients et métadonnées d'utilisateurs, secrets d'intégration et clés API, configurations d'authentification (SSO/SCIM), journaux d'audit. | Inconnu | [https://www.bleepingcomputer.com/news/security/runaway-ai-hacking-agent-behind-workos-breach-after-escaping-sandbox/](https://www.bleepingcomputer.com/news/security/runaway-ai-hacking-agent-behind-workos-breach-after-escaping-sandbox/)<br>[https://mastodon.thenewoil.org/@thenewoil/117582830326163942](https://mastodon.thenewoil.org/@thenewoil/117582830326163942) |
| **Infrastructure de confiance numérique / autorité de certification (PKI)** | DigiCert | Coordonnées professionnelles des clients (contacts d'entreprise) ; pour une minorité de comptes, copies de passeports ou de permis de conduire. Aucun certificat émis ou révoqué de manière frauduleuse identifié. Nombre de clients non publié. | Inconnu | [https://www.bleepingcomputer.com/news/security/digicert-data-breach-exposes-customer-information-identity-documents/](https://www.bleepingcomputer.com/news/security/digicert-data-breach-exposes-customer-information-identity-documents/)<br>[https://mastodon.thenewoil.org/@thenewoil/117582594372093882](https://mastodon.thenewoil.org/@thenewoil/117582594372093882)<br>[https://therecord.media/digicert-certificate-authority-reports-data-breach](https://therecord.media/digicert-certificate-authority-reports-data-breach)<br>[https://infosec.exchange/@adrianhollister/117581620881664940](https://infosec.exchange/@adrianhollister/117581620881664940) |
| **Infrastructure de transport / Grand projet de construction (tunnel ferroviaire Italie-Autriche)** | Brenner Base Tunnel SE | Données non précisément caractérisées à ce stade : documents de projet (plans, relevés, procédures de site), informations relatives aux fournisseurs et sous-traitants, données internes de la société de projet. Volume de 812 Go revendiqué mais non confirmé. | 812000000 | [https://www.scworld.com/brief/brenner-base-tunnel-se-confirms-data-breach-as-everest-group-claims-theft](https://www.scworld.com/brief/brenner-base-tunnel-se-confirms-data-breach-as-everest-group-claims-theft)<br>[https://mastobot.ping.moi/@Bobe_bot/117583303552359326](https://mastobot.ping.moi/@Bobe_bot/117583303552359326)<br>[https://cyberworldops.eu/en/brenner-base-tunnel-confirms-breach-everest-claims-812-gb](https://cyberworldops.eu/en/brenner-base-tunnel-confirms-breach-everest-claims-812-gb)<br>[https://infosec.exchange/@cyberworldops/117582147273907465](https://infosec.exchange/@cyberworldops/117582147273907465) |
| **Réseaux sociaux / Technologie** | Twitter (X) — revendication non vérifiée | Aucune donnée confirmée. Aucun artefact de preuve (échantillon, volume, arborescence) n'a été publié à ce stade. | Inconnu | [https://www.yazoul.net/intel/claim/2026-11-08-twitter-ransomware-claim-by-byod-nov-2026/?utm_source=mastodon&utm_medium=social](https://www.yazoul.net/intel/claim/2026-11-08-twitter-ransomware-claim-by-byod-nov-2026/?utm_source=mastodon&utm_medium=social)<br>[https://infosec.exchange/@Matchbook3469/117582656391454889](https://infosec.exchange/@Matchbook3469/117582656391454889)<br>[https://www.yazoul.net/intel/claim/2026-11-08-twitter-ransomware-claim-by-byod-nov-2026/](https://www.yazoul.net/intel/claim/2026-11-08-twitter-ransomware-claim-by-byod-nov-2026/) |
| **Développement logiciel / Applications web (runtime PHP)** | Écosystème PHP (recherche sur la vulnérabilité PHP2Shell) | Aucune donnée compromise dans le cadre de cette publication. Le risque concerne les applications PHP vulnérables, exposées à une exécution de code arbitraire et donc à une compromission complète du serveur et des données qu'il héberge. | Inconnu | [https://djad04.github.io/php2shell-deep-dive/](https://djad04.github.io/php2shell-deep-dive/)<br>[https://www.reddit.com/r/redteamsec/comments/1xqm9jb/i_spent_countless_nights_digging_into_php2shell/](https://www.reddit.com/r/redteamsec/comments/1xqm9jb/i_spent_countless_nights_digging_into_php2shell/) |
| **Multi-secteur (santé, banque, services financiers)** | Hôpitaux, banques et institutions financières (États-Unis et Royaume-Uni) | Aucune donnée personnelle exfiltrée au sens d'une violation de base de données. Le préjudice est financier (129 millions de dollars détournés) et repose sur l'usurpation d'identité de dirigeants et d'avocats. | Inconnu | [https://www.scworld.com/brief/three-charged-in-129-million-deepfake-fraud-scheme](https://www.scworld.com/brief/three-charged-in-129-million-deepfake-fraud-scheme)<br>[https://mastobot.ping.moi/@Bobe_bot/117583303026127115](https://mastobot.ping.moi/@Bobe_bot/117583303026127115) |
| **Cybersécurité / Analyse blockchain (SaaS B2B, clients entreprises et agences gouvernementales)** | Chainalysis | Noms et noms d'utilisateur, hachages de mots de passe, mots de passe en clair pour certains comptes, jetons d'authentification/session valides, clés API (rotation imposée). | Inconnu | [https://www.tokenpost.com/news/technology/51173](https://www.tokenpost.com/news/technology/51173)<br>[https://infosec.exchange/@cloud/117582310554068687](https://infosec.exchange/@cloud/117582310554068687) |
| **Secteur public / Registre national d'identification et d'état civil (Pérou)** | RENIEC (Registro Nacional de Identificación y Estado Civil, Pérou) | Données revendiquées : base de données nationale de citoyens (identité, données d'état civil et d'identification) — environ 31 millions d'enregistrements. Contenu exact non confirmé. | Environ 31 millions d'enregistrements revendiqués (non vérifié) | [https://go.darkwebsonar.io/jayko28-mastodon](https://go.darkwebsonar.io/jayko28-mastodon)<br>[https://infosec.exchange/@darkwebsonar/117581936159232255](https://infosec.exchange/@darkwebsonar/117581936159232255) |
| **Commerce de détail / E-commerce de biens de consommation (Japon)** | Iris Ohyama (Iris Plaza / SIMPLE STYLE, Japon) | Noms complets, adresses postales, numéros de téléphone, adresses email, genre, dates de naissance, mots de passe de compte (chiffrés pour les membres actifs, absents pour les anciens membres). Données de carte bancaire non concernées selon l'entreprise. | Environ 7,7 millions de personnes (jusqu'à 5,8 millions de membres actuels et anciens + 1,9 million de non-membres) | [https://www.bleepingcomputer.com/news/security/iris-ohyama-data-cloud-breach-exposes-info-of-77-million-customers/](https://www.bleepingcomputer.com/news/security/iris-ohyama-data-cloud-breach-exposes-info-of-77-million-customers/)<br>[https://infosec.exchange/@cloud/117581823549367013](https://infosec.exchange/@cloud/117581823549367013)<br>[https://osintsights.com/iris-ohyama-breach-exposes-77-million-customer-records?utm_source=mastodon&utm_medium=social](https://osintsights.com/iris-ohyama-breach-exposes-77-million-customer-records?utm_source=mastodon&utm_medium=social)<br>[https://infosec.exchange/@security_crawler_carl/117581786493499199](https://infosec.exchange/@security_crawler_carl/117581786493499199)<br>[https://cyberworldops.eu/en/iris-ohyama-reports-cloud-intrusion-77-million-may-be-affected](https://cyberworldops.eu/en/iris-ohyama-reports-cloud-intrusion-77-million-may-be-affected)<br>[https://infosec.exchange/@cyberworldops/117581668110937136](https://infosec.exchange/@cyberworldops/117581668110937136)<br>[https://osintsights.com/iris-ohyama-breach-exposes-77-million-customer-records](https://osintsights.com/iris-ohyama-breach-exposes-77-million-customer-records) |
| **Secteur public / Justice (parquet de comté, New Jersey, États-Unis)** | Sussex County Prosecutor's Office (SCPO), New Jersey, États-Unis | Noms complets, numéros de sécurité sociale, numéros de permis de conduire, numéros de cartes d'identité délivrées par l'État. Nombre de personnes affectées non communiqué. | Inconnu | [https://beyondmachines.net/event_details/sussex-county-prosecutor-s-office-discloses-network-intrusion-and-potential-data-theft-k-q-l-d-x/gD2P6Ple2L](https://beyondmachines.net/event_details/sussex-county-prosecutor-s-office-discloses-network-intrusion-and-potential-data-theft-k-q-l-d-x/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117580949504733593](https://infosec.exchange/@beyondmachines1/117580949504733593) |
| **E-commerce / Biens de consommation (papier toilette écologique) — Australie, Royaume-Uni, États-Unis** | Who Gives A Crap (WGAC) | Noms complets (prénom et nom), adresses email, numéros de téléphone, adresses postales, montants de dépense cumulés. Données de paiement, mots de passe et historique détaillé des commandes non exposés selon l'entreprise. | Inconnu | [https://beyondmachines.net/event_details/who-gives-a-crap-customer-data-exposed-via-third-party-marketing-software-breach-6-k-x-8-k/gD2P6Ple2L](https://beyondmachines.net/event_details/who-gives-a-crap-customer-data-exposed-via-third-party-marketing-software-breach-6-k-x-8-k/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117580713582347630](https://infosec.exchange/@beyondmachines1/117580713582347630) |
| **Banque / services financiers (Japon)** | SMBC Consumer Finance et Sumitomo Mitsui Banking Corporation (SMBC) | SMBC Consumer Finance : noms complets, sexe, dates de naissance, adresses postales, emails, numéros de téléphone mobile, numéros de permis de conduire, noms d'employeur et téléphones professionnels, revenus annuels et montants de prêts garantis, codes d'établissement financier et numéros de compte client, dates de début de contrat. SMBC Bank : 227 216 adresses email de clients entreprises et indépendants. | 547334 | [https://beyondmachines.net/event_details/smbc-consumer-finance-and-smbc-bank-suffer-major-data-breaches-5-u-i-x-n/gD2P6Ple2L](https://beyondmachines.net/event_details/smbc-consumer-finance-and-smbc-bank-suffer-major-data-breaches-5-u-i-x-n/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117580241716591351](https://infosec.exchange/@beyondmachines1/117580241716591351) |
| **Commerce de détail / programme de cartes de crédit (Japon)** | Ryohin Keikaku Co., Ltd. (MUJI Card) | Numéros de carte de crédit complets (environ 345 000 actifs et valides), dates de naissance, numéros de carte partiels, noms des clients. Noms de titulaires et codes de sécurité (CVV) non inclus dans la fuite. 120 enregistrements supplémentaires issus de l'application Muji et de la boutique en ligne. | 1090120 | [https://beyondmachines.net/event_details/ryohin-keikaku-discloses-major-data-breach-affecting-1-09-million-muji-card-members-0-e-0-t-m/gD2P6Ple2L](https://beyondmachines.net/event_details/ryohin-keikaku-discloses-major-data-breach-affecting-1-09-million-muji-card-members-0-e-0-t-m/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117580005808942470](https://infosec.exchange/@beyondmachines1/117580005808942470) |
| **Hébergement web / services Internet** | DreamHost | Identifiants FTP et identifiants de messagerie des comptes clients ; contenu des boîtes mail potentiellement consultable par les attaquants. Volume exact non communiqué. | Inconnu | [https://gbhackers.com/dreamhost-confirms-data-breach/?utm_source=mastodon&utm_medium=social&utm_campaign=fedica-Calendario-Editoriale](https://gbhackers.com/dreamhost-confirms-data-breach/?utm_source=mastodon&utm_medium=social&utm_campaign=fedica-Calendario-Editoriale)<br>[https://poliversity.it/@ransomnews/117579908432584716](https://poliversity.it/@ransomnews/117579908432584716) |
| **Transverse / tous secteurs** | Multiples organisations (synthèse hebdomadaire) | Non applicable : synthèse agrégée sans victime ni jeu de données spécifique identifié. | Inconnu | [https://soundcloud.com/nickaesp/b2026-11-08](https://soundcloud.com/nickaesp/b2026-11-08)<br>[https://mastodon.social/@NickAEsp/117583002920286869](https://mastodon.social/@NickAEsp/117583002920286869) |
| **Services financiers / courtage (Corée du Sud)** | Mirae Asset Securities | Noms et numéros d'identification des employés, numéros de compte client, mots de passe chiffrés, adresses email, numéros de téléphone mobile. Numéros d'enregistrement de résidence et numéros de permis de conduire non compromis. | 39000 | [https://beyondmachines.net/event_details/mirae-asset-securities-reports-data-breach-affecting-customers-and-employees-6-t-b-n-v/gD2P6Ple2L](https://beyondmachines.net/event_details/mirae-asset-securities-reports-data-breach-affecting-customers-and-employees-6-t-b-n-v/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117581893190478327](https://infosec.exchange/@beyondmachines1/117581893190478327) |
| **Transverse / cybercriminalité (victimes revendiquées : restauration, tourisme)** | Dodo Pizza, Tez Tour et autres victimes revendiquées par DataSuckers | Données non détaillées dans la source. Les victimes revendiquées (Dodo Pizza, Tez Tour) suggèrent des bases clients (identités, coordonnées, données de réservation/commande). Volume non communiqué. | Inconnu | [https://www.zataz.com/datasuckers-trois-suspects-arretes-apres-une-fuite/](https://www.zataz.com/datasuckers-trois-suspects-arretes-apres-une-fuite/)<br>[https://infosec.exchange/@cloud/117581342037352265](https://infosec.exchange/@cloud/117581342037352265) |
| **Santé — hôpital public (Royaume-Uni)** | Royal Cornwall Hospitals NHS Trust (NHS) | Données de santé et d'absence pour maladie de salariés (enregistrements de sickness absence), identités et coordonnées professionnelles de salariés actuels et anciens du trust ainsi que de travailleurs non rattachés au trust ; volume annoncé : 8 003 personnes concernées. | 8003 | [https://www.theregister.com/security/2026/11/07/nhs-breach-helpline-left-staff-carrying-a-significant-emotional-burden/5308201](https://www.theregister.com/security/2026/11/07/nhs-breach-helpline-left-staff-carrying-a-significant-emotional-burden/5308201)<br>[https://infosec.exchange/@edwardk/117580248317134095](https://infosec.exchange/@edwardk/117580248317134095) |
| **Services juridiques — cabinet d'avocats (États-Unis)** | Cuomo LLC | Nature et volume non précisés par la source. Compte tenu du profil de la victime (cabinet d'avocats), les catégories à considérer comme à risque sont : dossiers et pièces de procédure clients, données personnelles de justiciables, informations financières, contrats et documents internes confidentiels. | Inconnu | [https://www.ransomlook.io//group/anubis](https://www.ransomlook.io//group/anubis) |
| **Commerce de détail — mobilier et décoration d'intérieur (France)** | Ligne Roset | Données alléguées, non vérifiées : informations personnelles de salariés incluant passeports et permis de conduire, contrats et accords, documents financiers, fichiers confidentiels et accords de non-divulgation ; volume revendiqué d'environ 150 Go. | 150 Go (volume allégué par l'acteur, non vérifié) | [https://www.yazoul.net/intel/claim/2026-11-07-ligne-roset-ransomware-claim-by-akira-nov-2026/?utm_source=mastodon&utm_medium=social](https://www.yazoul.net/intel/claim/2026-11-07-ligne-roset-ransomware-claim-by-akira-nov-2026/?utm_source=mastodon&utm_medium=social)<br>[https://infosec.exchange/@Matchbook3469/117581208576693618](https://infosec.exchange/@Matchbook3469/117581208576693618) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-123158** | N/A | N/A | FALSE | OpenSSH s'exécutant sur des systèmes Linux utilisant musl libc (Alpine Linux en priorité, ainsi qu'OpenWRT lorsque OpenSSH est installé, Buildroot, Yocto et Void Linux). | Contournement d'authentification (CWE-287 / CWE-305) par mot de passe surdimensionné (>256 caractères) résultant d'une combinaison de défauts entre la fonction crypt() de musl libc et la vérification du hash de mot de passe par OpenSSH. | Un attaquant peut obtenir un accès SSH non authentifié en tant qu'utilisateur valide sur les systèmes vulnérables, y compris depuis l'intérieur d'un réseau d'entreprise, d'un cloud privé ou d'un VPN, sans nécessiter d'identifiants préalables. Cela permet le déploiement de botnets et de backdoors (téléchargement de bot[.]x86_64), le vol de données, le mouvement latéral vers d'autres systèmes, l'installation de persistance (clés authorized_keys, cron, services) et, à terme, la compromission de chaînes de build et d'images conteneurs. L'exposition est d'autant plus grave que la faille est triviale à scanner et à exploiter et que des exploits publics circulent. | Active | Appliquer en urgence les correctifs publiés par OpenSSH et par l'auteur de musl libc (Rich Felker), en priorité sur Alpine Linux et les images de base conteneurisées. Mesure d'atténuation immédiate : positionner 'PasswordAuthentication no' dans la configuration OpenSSH et redémarrer le service ; activer 'UsePAM yes' lorsque c'est possible. Restreindre l'exposition d'sshd à Internet, filtrer les accès par adresse source, imposer un bastion et l'authentification par clé ou certificat avec MFA. Auditer les comptes à hash '*' dans /etc/shadow et supprimer les comptes inutilisés. Surveiller les logs d'authentification pour les mots de passe de plus de 256 caractères et bloquer les IOC connus (156[.]238[.]252[.]37, hxxp://156[.]238[.]252[.]37:8000/bot[.]x86_64). Reconstruire les images et conteneurs compromis à partir de sources saines et intégrer la vérification de version OpenSSH/musl dans les pipelines CI/CD. | [https://isc.sans.edu/diary/rss/33498](https://isc.sans.edu/diary/rss/33498)<br>[https://sshole.events.greynoise.io/](https://sshole.events.greynoise.io/) |
| **CVE-2026-6715** | 9.8 | N/A | FALSE | IBM Concert 1.0 à 3.0.1.1 | Injection de commandes OS (CWE-78) | Exécution arbitraire de commandes sur le système d'exploitation sous-jacent avec les privilèges du service IBM Concert : compromission de la confidentialité, de l'intégrité et de la disponibilité de l'hôte, pivot potentiel vers les systèmes adjacents et les données gérées par la plateforme. | None | Appliquer la mise à jour fournie par IBM (bulletin node/7294607). En attendant, restreindre l'exposition réseau des interfaces IBM Concert, valider et assainir toutes les entrées utilisateur, exécuter le service avec un compte à privilèges minimaux et surveiller les processus enfants anormaux. | [https://cvefeed.io/vuln/detail/CVE-2026-6715](https://cvefeed.io/vuln/detail/CVE-2026-6715) |
| **CVE-2026-15266** | 9.8 | N/A | FALSE | IBM Concert 1.0 à 3.0.1.1 | Exécution de commandes non sécurisée (CWE-78) | Exécution arbitraire de commandes sur le serveur hébergeant IBM Concert, avec risque de compromission totale de l'hôte, de vol de données applicatives et de mouvement latéral dans le réseau. | None | Mettre à jour IBM Concert vers une version corrigée (bulletin node/7294607), appliquer les correctifs éditeur, désactiver les composants affectés lorsque c'est possible, restreindre l'accès réseau au système et surveiller les exécutions de processus anormales. | [https://cvefeed.io/vuln/detail/CVE-2026-15266](https://cvefeed.io/vuln/detail/CVE-2026-15266) |
| **CVE-2026-118904** | 8.1 | N/A | FALSE | IBM webMethods Integration Server 12.1 | Authentification impropre / contournement de la validation des codes de secours 2FA (CWE-287) | Contournement de la 2FA et accès non autorisé aux fonctions d'administration et d'intégration, avec risque de modification des flux métier, d'exfiltration de données traitées par l'ESB et de pivot vers les systèmes connectés. | None | Appliquer les correctifs IBM (bulletin node/7295306), revoir les configurations d'authentification, régénérer les codes de secours, renforcer les contrôles d'accès et restreindre l'exposition des interfaces d'administration. | [https://cvefeed.io/vuln/detail/CVE-2026-118904](https://cvefeed.io/vuln/detail/CVE-2026-118904) |
| **CVE-2026-9764** | 8.8 | N/A | FALSE | IBM Bob 1.0.4 à 2.0.1 | Injection de code / contrôle impropre de l'exécution de serveurs MCP définis par le workspace (CWE-94) | Exécution de code arbitraire sur le poste de l'utilisateur ou le serveur hébergeant IBM Bob, avec vol potentiel de secrets de développement, de jetons d'accès aux dépôts et de code source, ainsi qu'un point d'ancrage pour du mouvement latéral. | None | Mettre à jour IBM Bob vers une version corrigée (bulletin node/7291535), valider et assainir les entrées, restreindre l'exécution des serveurs MCP aux configurations approuvées et sensibiliser les utilisateurs à l'ouverture de workspaces externes. | [https://cvefeed.io/vuln/detail/CVE-2026-9764](https://cvefeed.io/vuln/detail/CVE-2026-9764) |
| **CVE-2026-97677** | 8.1 | N/A | FALSE | IBM Langflow OSS 1.0.0 à 1.12.2 | Traversée de répertoire (CWE-22) permettant écriture et lecture arbitraires de fichiers | Divulgation de secrets et de données sensibles stockées dans le répertoire applicatif, altération de fichiers de configuration et possibilité d'écrasement de fichiers critiques, pouvant conduire à une compromission plus large de la plateforme d'orchestration. | None | Mettre à jour IBM Langflow OSS vers une version corrigée (bulletin node/7290694), restreindre les permissions d'écriture et de lecture du compte de service, limiter la création de flows aux utilisateurs de confiance et isoler les secrets du répertoire de données. | [https://cvefeed.io/vuln/detail/CVE-2026-97677](https://cvefeed.io/vuln/detail/CVE-2026-97677) |
| **CVE-2026-8639** | 8.8 | N/A | FALSE | IBM Security Verify Directory 10.0.0 à 10.0.4 et IBM Verify Directory 11.0.0 | Fixation de session (CWE-384) | Prise de contrôle de la console de gestion de l'annuaire avec les privilèges de la victime : modification d'objets d'annuaire, création de comptes, altération de politiques d'accès et compromission de la chaîne d'authentification de l'entreprise. | None | Mettre à jour vers une version corrigée (bulletin node/7293828), sécuriser la configuration de gestion des sessions (régénération d'identifiant après authentification, cookies HttpOnly/Secure/SameSite), restreindre l'accès à la console et surveiller les réutilisations de session. | [https://cvefeed.io/vuln/detail/CVE-2026-8639](https://cvefeed.io/vuln/detail/CVE-2026-8639) |
| **CVE-2026-19133** | 8.1 | N/A | FALSE | IBM Storage TS4500 Library 1.1.1.6 à 1.12.0.3 | Autorisation impropre (CWE-285) permettant une prise de contrôle de compte | Prise de contrôle de comptes d'administration de la bibliothèque de bandes, avec risque de modification des politiques de sauvegarde, de suppression ou d'exfiltration de données archivées et de perturbation des opérations de restauration. | None | Appliquer les mises à jour éditeur (bulletin node/7292609), vérifier que le système exécute la dernière version, revoir les configurations de contrôle d'accès et restreindre l'exposition de l'interface de gestion. | [https://cvefeed.io/vuln/detail/CVE-2026-19133](https://cvefeed.io/vuln/detail/CVE-2026-19133) |
| **CVE-2026-17466** | 9.1 | N/A | FALSE | IBM Optim Test Data Management 1.0.0, 1.1.0 et 1.2.0 | Traversée de répertoire (CWE-22) entraînant une divulgation d'informations sensibles | Accès non autorisé à des fichiers et données hors du périmètre applicatif, incluant potentiellement des jeux de données de test contenant des données personnelles ou de production, avec risque de violation de données et de non-conformité réglementaire. | None | Mettre à jour IBM Optim vers une version corrigée (bulletin node/7289719), restreindre l'accès aux fichiers sensibles, appliquer les correctifs éditeur sans délai et renforcer les contrôles d'accès et la validation des chemins. | [https://cvefeed.io/vuln/detail/CVE-2026-17466](https://cvefeed.io/vuln/detail/CVE-2026-17466) |
| **CVE-2026-117545** | 8.8 | N/A | FALSE | IBM webMethods Integration Server 12.1 | Contournement d'authentification (CWE-287) | Un attaquant pourrait obtenir un accès non autorisé à des fonctionnalités protégées, usurper l'identité d'un utilisateur ou élever ses privilèges, avec un impact élevé sur la confidentialité, l'intégrité et la disponibilité. | None | Appliquer le correctif IBM référencé pour webMethods Integration Server, mettre à jour vers la dernière version corrigée, renforcer la configuration MFA/2FA, restreindre l'exposition des interfaces d'administration et surveiller les journaux d'authentification. | [https://cvefeed.io/vuln/detail/CVE-2026-117545](https://cvefeed.io/vuln/detail/CVE-2026-117545) |
| **CVE-2026-116501** | 8.4 | N/A | FALSE | IBM Qiskit SDK 2.4.0 à 2.6.1 | Écriture hors limites (CWE-787) | Exécution de code arbitraire sur la machine locale de l'utilisateur ou dans l'environnement de développement, avec un impact élevé sur la confidentialité, l'intégrité et la disponibilité. | None | Mettre à jour IBM Qiskit SDK vers une version corrigée, valider l'intégrité des matrices unitaires et des circuits importés, éviter le traitement de données non fiables et renforcer les contrôles d'accès sur les environnements de développement. | [https://cvefeed.io/vuln/detail/CVE-2026-116501](https://cvefeed.io/vuln/detail/CVE-2026-116501) |
| **CVE-2026-116499** | 8.4 | N/A | FALSE | IBM Qiskit SDK 1.4.2 à 2.6.2 | Désérialisation de données non fiables (CWE-502) | Exécution de code arbitraire sur la machine locale ou dans l'environnement de développement, avec un impact élevé sur la confidentialité, l'intégrité et la disponibilité. | None | Mettre à jour IBM Qiskit SDK vers une version corrigée, éviter la désérialisation de fichiers QPY non fiables, valider l'origine et l'intégrité des données importées et renforcer les contrôles d'accès sur les environnements de développement. | [https://cvefeed.io/vuln/detail/CVE-2026-116499](https://cvefeed.io/vuln/detail/CVE-2026-116499) |
| **CVE-2026-114464** | 9.3 | N/A | FALSE | IBM Process Mining 2.0.0 à 2.2.1 | Contrôle d'accès inapproprié (CWE-284) | Divulgation d'informations sensibles, accès non autorisé aux données de processus métier et atteinte potentielle à la confidentialité et à l'intégrité des données. | None | Appliquer le correctif IBM référencé pour Process Mining, mettre à jour vers la dernière version corrigée, restreindre les contrôles d'accès, surveiller les accès non autorisés et revoir les permissions des comptes. | [https://cvefeed.io/vuln/detail/CVE-2026-114464](https://cvefeed.io/vuln/detail/CVE-2026-114464) |
| **CVE-2026-110273** | 8.8 | N/A | FALSE | IBM TRIRIGA Application Platform 5.0.0 à 5.0.9 | Injection de commande OS / injection de code (CWE-94) | Exécution de commandes arbitraires sur le serveur, compromission potentielle de l'hôte, accès non autorisé aux données et atteinte à l'intégrité du système. | None | Appliquer le correctif IBM référencé pour TRIRIGA, mettre à jour vers une version corrigée, valider et assainir toutes les entrées utilisateur, restreindre les privilèges du service et surveiller les processus système. | [https://cvefeed.io/vuln/detail/CVE-2026-110273](https://cvefeed.io/vuln/detail/CVE-2026-110273) |
| **CVE-2026-107331** | 9.9 | N/A | FALSE | IBM DataStage on Cloud Pak for Data 5.4.0.0 | Traversée de chemin absolu (CWE-36) | Divulgation de fichiers sensibles, de secrets ou de données métier, avec un impact élevé sur la confidentialité et l'intégrité, et un changement de périmètre de sécurité. | None | Appliquer le correctif IBM référencé pour DataStage, mettre à jour vers la dernière version corrigée, restreindre les accès aux fichiers et répertoires sensibles, surveiller les journaux et revoir les contrôles d'accès. | [https://cvefeed.io/vuln/detail/CVE-2026-107331](https://cvefeed.io/vuln/detail/CVE-2026-107331) |
| **CVE-2026-105467** | 8.1 | N/A | FALSE | IBM QRadar 7.5.0 à 7.5.0 Update Pack 16 Interim Fix 02 et 7.6.0.0 à 7.6.0.5 | XSS réfléchi et redirection ouverte (CWE-79) | Vol de session, exécution de scripts dans le navigateur de la victime, redirection vers des sites malveillants et atteinte potentielle à la confidentialité et à l'intégrité des données. | None | Appliquer les correctifs IBM pour QRadar, mettre à jour vers une version corrigée, renforcer la validation des entrées, déployer une politique CSP stricte et sensibiliser les utilisateurs aux liens suspects. | [https://cvefeed.io/vuln/detail/CVE-2026-105467](https://cvefeed.io/vuln/detail/CVE-2026-105467) |
| **CVE-2026-114189** | 8.5 | N/A | FALSE | Plugin WordPress AnyWhere Elementor jusqu'à la version 1.3.0 | Injection SQL aveugle (CWE-89) | Accès non autorisé à la base de données, extraction d'informations sensibles, modification ou suppression de données et compromission potentielle du site WordPress. | None | Mettre à jour le plugin AnyWhere Elementor vers une version supérieure à 1.3.0, appliquer les correctifs éditeur, déployer un WAF, restreindre les privilèges de la base de données et surveiller les requêtes SQL anormales. | [https://cvefeed.io/vuln/detail/CVE-2026-114189](https://cvefeed.io/vuln/detail/CVE-2026-114189) |
| **CVE-2026-109900** | 9.6 | N/A | FALSE | Plugin WordPress Melapress Role Editor (melapress-role-editor) versions <= 1.3.0 | Attribution incorrecte de privilèges (CWE-266) permettant une élévation de privilèges | Un attaquant pourrait obtenir des privilèges administratifs sur le site WordPress, modifier le contenu, installer des plugins ou thèmes malveillants, créer des comptes persistants et potentiellement compromettre l'hébergement. L'impact sur la confidentialité, l'intégrité et la disponibilité est élevé. | Theoretical | Mettre à jour le plugin Melapress Role Editor vers la version 1.3.1 ou ultérieure. En attendant, désactiver le plugin ou appliquer une règle WAF virtuelle. Auditer les rôles et capabilities, vérifier les comptes administrateur récemment créés et appliquer le principe du moindre privilège. | [https://cvefeed.io/vuln/detail/CVE-2026-109900](https://cvefeed.io/vuln/detail/CVE-2026-109900) |
| **CVE-2026-101117** | 9.1 | N/A | FALSE | IBM WebSphere Extreme Scale versions 8.6.1.0 à 8.6.2.2 | Contournement de restrictions de sécurité via une configuration incorrecte de Content Security Policy (CWE-16), permettant des attaques XSS | Exécution de code JavaScript malveillant dans le contexte des utilisateurs, vol de cookies de session, réalisation d'actions au nom de la victime, défiguration ou exfiltration de données. Les interfaces d'administration exposées sont particulièrement à risque. | Theoretical | Appliquer la mise à jour corrective IBM référencée dans l'avis officiel. Corriger la configuration CSP en supprimant les directives permissives et en validant les sources autorisées. Restreindre l'exposition réseau des consoles d'administration et surveiller les violations CSP. | [https://cvefeed.io/vuln/detail/CVE-2026-101117](https://cvefeed.io/vuln/detail/CVE-2026-101117) |
| **CVE-2026-124553** | N/A | N/A | FALSE | BabelDOC versions 0.3.61 à 0.6.x (antérieures à 0.7.0) | Déni de service via l'analyse de ToUnicode CMap dans des fichiers PDF malveillants | Indisponibilité du service de conversion ou d'analyse PDF, épuisement des ressources, ralentissement des traitements et interruption de service pour les utilisateurs légitimes. | Theoretical | Mettre à jour BabelDOC vers la version 0.7.0 ou ultérieure. Isoler le service de parsing dans un environnement à ressources limitées et valider les fichiers PDF entrants. | [https://cvefeed.io/vuln/detail/CVE-2026-124553](https://cvefeed.io/vuln/detail/CVE-2026-124553) |
| **CVE-2026-124494** | 9.3 | N/A | FALSE | SunEditor versions antérieures à 3.4.0 | XSS stockée via contournement du sanitizer par entité &colon; (CWE-79) | Exécution de code JavaScript stocké dans le navigateur des utilisateurs, vol de sessions, actions au nom des victimes, redirection vers des sites malveillants et compromission de comptes à privilèges. | Theoretical | Mettre à jour SunEditor vers la version 3.4.0 ou ultérieure. Valider strictement les URL et appliquer une sanitation côté serveur. Déployer une politique CSP restrictive et purger les contenus malveillants déjà stockés. | [https://cvefeed.io/vuln/detail/CVE-2026-124494](https://cvefeed.io/vuln/detail/CVE-2026-124494) |
| **CVE-2025-30026** | N/A | N/A | FALSE | Axis Camera Station Pro versions antérieures à 6.9 et Axis Camera Station versions antérieures à 5.58 | Contournement d'authentification par acceptation de tout certificat client auto-signé | Accès non authentifié au service Axis Camera Station, permettant le chaînage vers une exécution de code arbitraire avec les privilèges SYSTEM, la compromission du serveur VMS et l'accès aux flux et identifiants des caméras. | Active | Mettre à jour Axis Camera Station Pro vers 6.9 ou ultérieure et Camera Station vers 5.58 ou ultérieure. Restreindre l'accès au port 55752, segmenter le réseau et surveiller les certificats clients. | [https://ricardojoserf.github.io/axisrce](https://ricardojoserf.github.io/axisrce) |
| **CVE-2025-30023** | N/A | N/A | FALSE | Axis Camera Station Pro versions antérieures à 6.9 et Axis Camera Station versions antérieures à 5.58 | Désérialisation non sécurisée .NET dans le champ clientInformationDto de LogOnAsync | Exécution de code arbitraire avec les privilèges SYSTEM sur le serveur Windows hébergeant Axis Camera Station, compromission complète du VMS et accès aux identifiants des caméras. | Active | Mettre à jour Axis Camera Station vers les versions corrigées. Restreindre l'accès réseau au service, surveiller les processus enfants et appliquer une désérialisation sécurisée. | [https://ricardojoserf.github.io/axisrce](https://ricardojoserf.github.io/axisrce) |
| **CVE-2026-63286** | N/A | N/A | FALSE | Axis Camera Station (base de données Firebird stockant les identifiants des caméras) | Schéma de chiffrement des identifiants faible : clé AES-256-CBC dérivée de constantes codées en dur et du numéro de série NTFS | Compromission de l'ensemble des identifiants des caméras, accès non autorisé aux flux vidéo, modification des configurations des caméras et mouvement latéral sur le réseau de vidéosurveillance. | Active | Appliquer les correctifs Axis disponibles. Faire tourner les identifiants des caméras, restreindre l'accès local aux serveurs VMS et renforcer la gestion des secrets. | [https://ricardojoserf.github.io/axisrce](https://ricardojoserf.github.io/axisrce) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="sentinelone-prompt-security-lagent-endpoint"></div>

## SentinelOne Prompt Security : l'agent endpoint

### Résumé

L'article passe en revue l'agent endpoint de SentinelOne Prompt Security, destiné à surveiller l'usage de l'IA générative au-delà du navigateur (applications desktop Claude et ChatGPT, Copilot dans VS Code, assistants CLI type Claude Code). L'auteur décrit le contenu du package par plateforme : MSI signé SentinelOne, certificat racine du tenant, wrapper install.cmd qui écrit la clé d'agent en clair dans C:\Windows\Temp avant d'exécuter le MSI silencieusement. Seuls des packages Intune et SCCM sont proposés. Un collègue a rencontré un blocage par Smart App Control sur un fichier non signé de l'agent, avec pour symptômes l'absence de processus agent, un port proxy local jamais ouvert et un événement d'intégrité de code répété environ toutes les 30 secondes ; le fonctionnement n'est revenu qu'après désactivation de Smart App Control. L'interception repose sur deux mécanismes activés au niveau du tenant, sans granularité par groupe ou par appareil : un fichier PAC système pour les applications IA desktop et des variables d'environnement proxy pour les assistants CLI. Sous le capot, l'agent exécute un mitmproxy local sur 127.0.0.1:3636 avec un pilote WinDivert et re-signe le TLS avec le certificat racine du tenant. L'auteur relève que la vérification du certificat amont est désactivée dans la configuration de l'agent. L'installation crée une variable d'environnement proxy machine, une URL PAC, une variable de bundle de certificats pour les outils Node, installe la racine dans les magasins machine et utilisateur, et ajoute un service et un pilote.

---

### Analyse opérationnelle

L'article documente des risques de déploiement concrets pour les équipes SOC/IT. D'abord, la clé d'agent transite et réside en clair dans C:\Windows\Temp, répertoire lisible par tout compte local : un accès local de faible privilège suffit à récupérer la clé pendant la fenêtre d'installation, ce qui impose une révocation/régénération en cas de doute et une surveillance des fichiers résiduels. Ensuite, l'incompatibilité avec les politiques de contrôle d'application (Smart App Control, et par extension AppLocker/WDAC) doit être testée avant tout déploiement de masse : le symptôme est discret (pas de processus, pas de port proxy, événement d'intégrité répété) et peut conduire à une flotte silencieusement non couverte. Les bascules PAC et variables d'environnement étant tenant-wide, un seul client ou service au réseau atypique bloque l'ensemble du tenant : la décision est tout-ou-rien. Enfin, l'agent installe une autorité racine de confiance et déchiffre localement tout le trafic IA, avec vérification du certificat amont désactivée par défaut : cela crée un point d'interception unique dont la compromission ou le mauvais paramétrage a un impact direct sur la confidentialité des échanges. Côté détection, la présence du port 127.0.0.1:3636, du pilote WinDivert, des variables proxy machine et du certificat racine constitue une signature de déploiement exploitable pour l'inventaire et le contrôle de conformité.

---

### Implications stratégiques

Le sujet dépasse la technique : il s'agit de la gouvernance de l'IA générative en entreprise. Déployer un agent qui déchiffre les prompts sur le poste de travail implique des obligations d'information, voire une consultation des instances représentatives du personnel dans certaines juridictions, et un traitement RGPD des contenus inspectés. La dépendance à un fournisseur unique pour l'interception TLS et la racine de confiance crée un risque de concentration : la chaîne de confiance de l'organisation passe par un binaire tiers installé sur chaque poste. Les angles morts identifiés (terminaux, sous-système Linux, services arrêtés, fichiers joints) relativisent la promesse de visibilité totale et rappellent que la maîtrise du Shadow AI ne peut reposer sur un seul composant. Pour les prestataires gérant plusieurs clients depuis une console unique, l'absence de granularité par tenant ou par groupe est un frein contractuel et opérationnel à anticiper.

---

### Recommandations

* Tester le package contre la politique réelle de contrôle d'application avant tout déploiement de flotte.
* Exiger du fournisseur une justification écrite de la désactivation de la vérification du certificat amont, ou activer cette vérification.
* Révoquer et régénérer la clé d'agent si le fichier en clair dans C:\Windows\Temp a pu être lu.
* Documenter formellement l'interception TLS et l'installation de la racine de confiance dans la note de déploiement et la fiche RGPD.
* Prévoir un mécanisme de détection des postes non couverts (port 3636 absent, événements d'intégrité de code répétés).
* Cartographier les usages IA hors navigateur (desktop, CLI, IDE, WSL) pour identifier les angles morts avant de communiquer sur la couverture.
* Évaluer la faisabilité multi-tenant avant de standardiser l'outil pour plusieurs clients.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Tester le package MSI (signé SentinelOne) contre la politique réelle de contrôle d'application (Smart App Control, AppLocker, WDAC) avant tout déploiement de flotte.
* Vérifier la disponibilité d'un package pour son MDM : seuls Intune et SCCM sont fournis, tout autre MDM impose un script maison.
* Documenter dans la note de déploiement que le trafic IA des postes est déchiffré localement par un proxy MITM et que l'autorité racine du tenant est installée dans les magasins machine et utilisateur.
* Prévoir la validation juridique / instance représentative du personnel (works council) pour les juridictions concernées avant activation de l'inspection TLS.
* Obtenir du fournisseur une réponse formelle sur la désactivation par défaut de la vérification du certificat amont (upstream certificate verification off).
* Préparer un plan de retour arrière : suppression du fichier PAC, des variables d'environnement proxy, du certificat racine, du service et du pilote.

#### Phase 2 — Détection et analyse

* Surveiller l'ouverture du port local 127[.]0[.]0[.]1:3636 et la présence du pilote WinDivert comme indicateurs de bon fonctionnement de l'agent.
* Détecter les échecs d'installation : absence de processus agent, port proxy jamais ouvert, événement d'intégrité de code répété toutes les 30 secondes (signature d'un blocage Smart App Control).
* Contrôler l'apparition des variables d'environnement proxy machine, de l'URL PAC et du bundle de certificats Node sur les postes nouvellement équipés.
* Rechercher la présence résiduelle de la clé d'agent en clair dans C:\Windows\Temp après installation.
* Alerter sur tout processus non couvert par le proxy (nouvelle fenêtre terminal, sous-système Linux, service arrêté, fichier joint) : ces angles morts n'apparaissent pas comme des trous dans la console.

#### Phase 3 — Confinement, éradication et récupération

* En cas de fuite de clé d'agent, révoquer et régénérer la clé côté tenant, puis redéployer.
* En cas d'incompatibilité de contrôle d'application, isoler le poste du périmètre pilote plutôt que de désactiver globalement Smart App Control.
* Suspendre l'activation des bascules PAC / variables d'environnement, qui sont tenant-wide et sans granularité par groupe ou par appareil.
* En cas de doute sur la validation du certificat amont, restreindre le déploiement aux postes pilotes et forcer la sortie via le proxy amont existant.

#### Phase 4 — Activités post-incident

* Comparer les snapshots avant/après installation (variables, PAC, magasins de certificats, services, pilotes, entrées Credential) pour établir la baseline de flotte.
* Mettre à jour la documentation d'architecture et la fiche de risque du produit (MITM local, racine de confiance, clé en clair).
* Revoir la politique de gouvernance de l'usage de l'IA (applications desktop, assistants CLI, IDE) à la lumière des angles morts constatés.
* Planifier une revue périodique des versions d'agent poussées depuis la console et de leur comportement réseau.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les connexions sortantes vers des API de modèles (Claude, ChatGPT, Copilot, assistants CLI) non vues par le proxy local.
* Traquer les processus d'assistants IA lancés hors du périmètre surveillé (terminaux, WSL, conteneurs, scripts).
* Rechercher des fichiers de clé d'agent ou de configuration laissés en clair sur disque.
* Corréler les événements d'intégrité de code avec les tentatives d'installation d'agent pour identifier les postes non couverts.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1557** | Interception de trafic par proxy local (mitmproxy sur 127[.]0[.]0[.]1:3636 + pilote WinDivert) avec re-signature TLS via l'autorité racine du tenant — mécanisme légitime du produit, mais à maîtriser avant déploiement. |
| **T1071.001** | Usage des protocoles web (HTTPS) par les applications d'IA générative et assistants CLI, dont le trafic est déchiffré et inspecté par l'agent. |

---

### Sources

* [https://www.cyberengage.org/post/sentinelone-prompt-security-the-endpoint-agent](https://www.cyberengage.org/post/sentinelone-prompt-security-the-endpoint-agent)


---

<div id="new-ransom-group-blog-postgroup-name-anubis-post-title-kahler-automation-location-de-sector-agriculture-food"></div>

## 🚨New ransom group blog post!🚨Group name: anubis Post title: Kahler Automation Location: 🇩🇪 DE Sector: Agriculture & Food

### Résumé

Le groupe de rançongiciel Anubis a publié une nouvelle victime sur son blog de fuite : l'entité Kahler Automation, localisée en Allemagne (DE) et rattachée au secteur Agriculture & Food, selon l'indexation cti.fyi. La publication ne fournit ni volume de données dérobées, ni montant de rançon, ni détail sur le vecteur d'intrusion.

---

### Analyse opérationnelle

La revendication, à ce stade non corroborée publiquement, doit être traitée comme un signal d'extorsion actif : vérifier si l'entité est un fournisseur ou un partenaire de la chaîne d'approvisionnement, rechercher des indicateurs de compromission chez les clients et sous-traitants exposés, et surveiller les canaux de négociation. Pour une cible d'automatisation industrielle, l'enjeu opérationnel est double : perte de disponibilité des systèmes de production et risque de fuite de données techniques (schémas, configurations, plans d'installation) réutilisables contre les clients finaux. Les équipes SOC doivent prioriser la surveillance des accès distants, des comptes de service et des mouvements latéraux vers les segments OT, ainsi que la détection de préparation à l'exfiltration (archivage, compression, transferts volumineux) avant tout chiffrement.

---

### Implications stratégiques

Le ciblage d'un acteur de l'automatisation agricole et agroalimentaire illustre la pression persistante du rançongiciel sur les chaînes d'approvisionnement industrielles allemandes et européennes. Une compromission chez un intégrateur se propage potentiellement à des dizaines d'exploitations et d'usines clientes, avec un impact de continuité (production, distribution alimentaire) et un risque réglementaire accru dans le cadre NIS2 et des obligations de notification. La publication sur un blog de fuite constitue aussi un levier de réputation et de négociation : la communication de crise et la coordination avec les autorités nationales doivent être préparées à l'avance.

---

### Recommandations

* Traiter la revendication comme non confirmée et rechercher une corroboration indépendante avant toute communication externe.
* Vérifier l'exposition de la chaîne d'approvisionnement : clients, sous-traitants et intégrateurs liés à l'entité citée.
* Renforcer la segmentation IT/OT et l'authentification multifacteur sur les accès distants des environnements industriels.
* Contrôler l'intégrité et la disponibilité des sauvegardes hors ligne des systèmes de production.
* Surveiller les canaux de fuite et de négociation du groupe Anubis pour détecter d'éventuelles publications de données.
* Préparer les obligations de notification réglementaire en cas de confirmation de fuite de données.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les actifs exposés et les interconnexions IT/OT du site industriel, en priorisant les automates et systèmes de supervision.
* Vérifier l'existence et la testabilité des sauvegardes hors ligne pour les systèmes de production et les données bureautiques.
* Préparer une cellule de crise incluant la direction, la communication, le juridique et les autorités compétentes (autorité de cybersécurité nationale, notification RGPD).
* Disposer de procédures de bascule en mode manuel pour les lignes automatisées.

#### Phase 2 — Détection et analyse

* Surveiller les accès anormaux aux partages réseau, aux serveurs de fichiers et aux systèmes de supervision industrielle.
* Détecter les exécutions massives de chiffrement, les extensions de fichiers modifiées et les notes de rançon.
* Contrôler les connexions sortantes inhabituelles vers des services de transfert de fichiers ou de stockage cloud.
* Surveiller la publication de la victime sur le blog de fuite du groupe et les canaux de négociation associés.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les segments réseau affectés, en particulier la jonction IT/OT, sans interrompre brutalement les processus physiques en cours.
* Révoquer les comptes compromis ou suspects et réinitialiser les secrets d'authentification (comptes de service, accès distants, VPN).
* Couper les accès distants non indispensables et forcer l'authentification multifacteur sur les accès conservés.
* Conserver les preuves (images disque, journaux, échantillons) avant toute remédiation destructive.

#### Phase 4 — Activités post-incident

* Restaurer les systèmes par ordre de criticité après validation de l'absence de persistance.
* Analyser les vecteurs d'accès initial et les mouvements latéraux pour corriger les causes racines.
* Évaluer l'exposition des données dérobées et préparer les notifications réglementaires et contractuelles.
* Renforcer la segmentation IT/OT, la gestion des comptes de service et la supervision des accès distants.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les artefacts et TTP associés au groupe Anubis sur l'ensemble du SI et des systèmes industriels.
* Traquer les comptes créés ou réactivés de manière suspecte et les élévations de privilèges récentes.
* Rechercher des archives ou exfiltrations préparatoires (staging, compression, transferts volumineux) antérieures au chiffrement.
* Vérifier les journaux d'accès distants et les outils de prise en main à distance pour identifier des accès non légitimes.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Chiffrement des données pour impact, modèle d'extorsion par rançongiciel revendiqué par le groupe Anubis. |
| **T1657** | Extorsion financière via la publication d'une victime sur le blog de fuite du groupe. |

---

### Sources

* [https://cti.fyi/#disclosure/anubis/Kahler%20Automation](https://cti.fyi/#disclosure/anubis/Kahler%20Automation)
* [https://infosec.exchange/@CTI_FYI/117583348419840684](https://infosec.exchange/@CTI_FYI/117583348419840684)


---

<div id="phishing-possible-sur-hxxpsnetflixtotoxyz"></div>

## Phishing possible 🎣 sur : ⚠️hxxps[:]//netflixtoto[.]xyz

### Résumé

Un signalement public, appuyé par une analyse URLDNA, identifie le domaine netflixtoto[.]xyz (hxxps[:]//netflixtoto[.]xyz) comme un possible site d'hameçonnage. Le nom de domaine imite la marque Netflix. Aucune information n'est fournie sur le contenu exact de la page, le mode de diffusion des liens ou le nombre de victimes.

---

### Analyse opérationnelle

Le domaine combine une marque connue et un segment générique, schéma classique de page de capture d'identifiants ou de données de paiement. La priorité est le blocage préventif au niveau DNS, proxy et passerelle de messagerie, y compris pour les postes nomades hors du périmètre réseau, puis la recherche rétrospective des requêtes dans les journaux. Toute soumission d'identifiants doit déclencher une réinitialisation de mot de passe et une révocation de session. La fiabilité de l'IOC reste moyenne : le domaine est signalé comme « possible » phishing, sans analyse de contenu disponible, ce qui impose une confirmation avant diffusion large et un rattachement éventuel à une campagne plus vaste.

---

### Implications stratégiques

L'usurpation de marques grand public reste un vecteur à faible coût et à fort rendement pour les attaquants, avec un risque de réputation pour la marque imitée et un risque de réutilisation des identifiants sur d'autres services (credential stuffing). Pour les organisations, le sujet relève autant de la protection des collaborateurs que de la surveillance de marque : la détection précoce des domaines imitants et les demandes de retrait réduisent la fenêtre d'exposition. La multiplication de ces signalements souligne la nécessité d'automatiser l'ingestion d'IOC de réputation externe dans les chaînes de blocage.

---

### Recommandations

* Bloquer netflixtoto[.]xyz sur le DNS, le proxy web et la passerelle de messagerie, y compris hors réseau d'entreprise.
* Rechercher rétrospectivement les requêtes vers le domaine dans les journaux et identifier les utilisateurs exposés.
* Réinitialiser les identifiants et révoquer les sessions de tout utilisateur ayant saisi des informations.
* Confirmer le contenu de la page avant diffusion large de l'IOC, la fiabilité étant moyenne.
* Déposer une demande de retrait et un signalement aux services de réputation d'URL.
* Automatiser l'ingestion des signalements de phishing externes dans les listes de blocage.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir une liste de domaines de marque surveillés et un flux de détection de typosquatting / combosquatting.
* Configurer le blocage par catégorie et par réputation au niveau du proxy web, du DNS protecteur et des passerelles de messagerie.
* Sensibiliser les utilisateurs au signalement d'un lien suspect en un clic et au réflexe de vérification de l'URL réelle.
* Préparer un modèle de demande de retrait (takedown) auprès des hébergeurs et des registres.

#### Phase 2 — Détection et analyse

* Détecter les résolutions DNS et les requêtes HTTP vers netflixtoto[.]xyz depuis le SI et les postes nomades.
* Analyser les courriels et messages contenant le domaine, y compris les variantes proches.
* Surveiller les signalements utilisateurs de pages imitant un service de streaming.
* Vérifier les éventuelles saisies d'identifiants sur la page et les tentatives de connexion anormales sur les comptes concernés.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer le domaine et l'URL au niveau DNS, proxy et messagerie, et pousser le blocage sur les postes nomades hors réseau.
* Réinitialiser les mots de passe des utilisateurs ayant soumis des identifiants et révoquer les sessions actives.
* Rechercher et supprimer les messages de hameçonnage des boîtes aux lettres.
* Déposer une demande de retrait du contenu et un signalement aux services de réputation d'URL.

#### Phase 4 — Activités post-incident

* Documenter l'incident, les utilisateurs touchés et les actions de remédiation.
* Renforcer la détection des variantes du domaine et des campagnes similaires.
* Revoir les règles de filtrage et la couverture des terminaux mobiles et personnels.
* Communiquer un retour d'expérience aux équipes support et aux utilisateurs.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux proxy et DNS toutes les requêtes historiques vers le domaine et ses variantes.
* Corréler avec les journaux d'authentification pour identifier des connexions réussies depuis des adresses inhabituelles.
* Rechercher d'autres domaines en .xyz ou à consonance de marque enregistrés récemment et pointant vers la même infrastructure.
* Analyser les courriels entrants de la même campagne (expéditeurs, objets, URL) pour élargir le périmètre de blocage.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `netflixtoto[.]xyz` | Medium |
| URL | `hxxps[:]//netflixtoto[.]xyz` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Hameçonnage par lien vers un site usurpant la marque Netflix, destiné à capter des identifiants ou des données de paiement. |
| **T1583.001** | Acquisition d'un domaine (netflixtoto[.]xyz) imitant une marque légitime pour héberger la page d'hameçonnage. |

---

### Sources

* [https://urldna.io/scan/6af056393b775000080af8e0](https://urldna.io/scan/6af056393b775000080af8e0)
* [https://infosec.exchange/@urldna/117583304277810638](https://infosec.exchange/@urldna/117583304277810638)


---

<div id="ainsi-openssh-sur-alpine-est-trivialement-facile-a-pirater-pour-obtenir-root-dans-la-infosec-cela-est-connu-comme-mauvais-alpine-confirme-que-lexploitation-necessite-une-connexion-un-port-ssh-joignable-et-un-nom-de-compte-connu-lorsque-les-conditions-requises-existent-la-faille-peut-permettre-a-des-attaquants-distants-de-contourner-lauthentification-par-mot-de-passe-sur-les-serveurs-alpine-linux-affectes-y-compris-les-comptes-destines-a-un-acces-par-cle-uniquement-openssh-a-publie-portable-106p2-le-5-novembre-2026-pour-bloquer-le-probleme-qui-affecte-les-systemes-linux-utilisant-musl-libc-sans-authentification-pam-si-cest-votre-configuration-allez-la-corriger-maintenant-voici-un-lien-vers-le-site-du-chercheur-ozgun-kultekin-ou-il-explique-lhistorique-et-un-dessin-tldr-egalement-dorzgunhttpssshholecom"></div>

## Ainsi, #OpenSSH sur #Alpine est trivialement facile à pirater pour obtenir root. Dans la #infosec, cela est connu comme « mauvais ». Alpine confirme que l'exploitation nécessite une connexion, un port #SSH joignable et un nom de compte connu lorsque les conditions requises existent. La faille peut permettre à des attaquants distants de contourner l'authentification par mot de passe sur les serveurs Alpine #Linux affectés, y compris les comptes destinés à un accès par clé uniquement. OpenSSH a publié Portable 10.6p2 le 5 novembre 2026 pour bloquer le problème, qui affecte les systèmes Linux utilisant #musl #libc sans authentification #PAM. Si c'est votre configuration, allez la corriger MAINTENANT. Voici un lien vers le site du chercheur ozgun #kultekin, où il explique l'historique, et un dessin tldr, également d'Orzgun.https://sshhole.com/

### Résumé

Le chercheur Ozgur Kultekin documente sur sshhole[.]com une faiblesse d'authentification affectant OpenSSH compilé avec musl libc sans PAM, configuration utilisée par Alpine Linux, OpenWrt, Buildroot, Yocto et de nombreuses images Docker. Les comptes qui ne devraient jamais accepter de mot de passe (root, comptes de déploiement en clé seule, comptes LDAP, utilisateur par défaut des images Alpine sur AWS et Azure) acceptent n'importe quel mot de passe dépassant 256 caractères. Le problème existerait depuis 2016. L'exploitation nécessite une seule connexion, un port SSH joignable et un nom de compte connu. OpenSSH Portable 10.6p2, publié le 5 novembre 2026, corrige la faille.

---

### Analyse opérationnelle

La criticité est élevée : le contournement d'authentification mène directement à un accès root distant sans identifiants valides, sur des systèmes souvent exposés par nécessité (SSH d'administration, équipements embarqués, images de conteneurs). La condition « nom de compte connu » est faiblement protectrice : root, admin, ubuntu, alpine et les comptes de déploiement sont triviaux à deviner. Les équipes SOC doivent considérer que tout hôte musl/Alpine avec SSH joignable est potentiellement compromettable en une requête. La détection repose presque exclusivement sur les journaux sshd (succès d'authentification par mot de passe sur un compte en clé seule, longueur de secret aberrante) et sur l'audit post-exploitation. Le patch est simple mais la propagation est le vrai obstacle : images de base à reconstruire, firmwares embarqués difficiles à mettre à jour, conteneurs immuables à redéployer.

---

### Implications stratégiques

Cette faille illustre le risque systémique de la chaîne d'approvisionnement logicielle : une bibliothèque C alternative (musl) et un choix de compilation (sans PAM) transforment un composant standard en porte dérobée pendant près de dix ans. Les organisations dépendantes de l'IoT industriel, des routeurs OpenWrt, des distributions Yocto/Buildroot et des flottes de conteneurs font face à un risque de patch diffus et lent, avec une exposition durable. Au-delà du correctif, l'enjeu est la gouvernance de la surface d'exposition SSH (accès distant, segmentation, bastionnage) et la capacité à produire un inventaire fiable des composants et versions déployés.

---

### Recommandations

* Appliquer OpenSSH Portable 10.6p2 ou le correctif du distributeur sur tous les systèmes musl sans PAM.
* Désactiver l'authentification par mot de passe et n'autoriser que l'authentification par clé ou par certificat.
* Restreindre l'accès SSH aux réseaux d'administration via VPN, bastion ou liste d'IP autorisées.
* Reconstruire les images de conteneurs à partir de bases corrigées et scanner les images en registry.
* Mettre en place une alerte SIEM sur les authentifications par mot de passe réussies sur comptes en clé seule et sur les secrets de longueur anormale.
* Recenser les firmwares embarqués (OpenWrt, Buildroot, Yocto) et planifier leur mise à jour ou leur compensation réseau.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier tous les systèmes OpenSSH compilés avec musl libc sans PAM : Alpine Linux, OpenWrt, Buildroot, Yocto, images Docker de base, appliances et équipements embarqués.
* Vérifier la version d'OpenSSH déployée (Portable 10.6p2 corrige la faille) et cartographier les ports SSH exposés sur Internet via la surface d'attaque externe.
* Identifier les comptes censés être en authentification par clé uniquement (root, comptes de déploiement, comptes LDAP, utilisateur par défaut des images cloud Alpine AWS/Azure).
* Préparer des règles de détection sur les journaux sshd : longueur anormale du mot de passe, succès d'authentification par mot de passe sur un compte configuré en clé seule.
* Définir une procédure de mise à jour d'urgence des images de conteneurs et des firmwares embarqués (rebuild, redéploiement, rollback).

#### Phase 2 — Détection et analyse

* Rechercher dans les logs sshd les authentifications par mot de passe réussies sur des comptes dont PasswordAuthentication est désactivé ou dont le mot de passe est verrouillé.
* Détecter les tentatives avec des secrets de longueur aberrante (>256 caractères) et les rafales de connexions SSH depuis une même source.
* Surveiller les connexions root interactives ou non interactives inattendues, en particulier depuis des adresses IP externes ou des plages cloud.
* Corréler avec les journaux d'audit (auditd/eBPF) : exécution de shell, création de clés autorisées, modification de sshd_config, persistance via authorized_keys ou cron.
* Alerter sur toute exposition SSH nouvellement détectée sur un actif musl/Alpine non référencé dans l'inventaire.

#### Phase 3 — Confinement, éradication et récupération

* Appliquer immédiatement OpenSSH Portable 10.6p2 (ou le correctif du distributeur) sur tous les systèmes affectés ; à défaut, désactiver l'authentification par mot de passe et restreindre l'accès SSH par liste d'IP/VPN.
* Isoler du réseau les hôtes présentant des connexions SSH suspectes ou des artefacts de persistance, sans les éteindre afin de préserver la mémoire.
* Révoquer et régénérer les clés et secrets présents sur les systèmes compromis, réinitialiser les comptes ayant fait l'objet d'un accès anormal.
* Bloquer au niveau pare-feu/EDR les sources identifiées comme malveillantes et fermer l'exposition directe du port SSH sur Internet.
* Reconstruire les conteneurs et firmwares à partir d'images de base corrigées plutôt que de patcher à chaud lorsque la configuration le permet.

#### Phase 4 — Activités post-incident

* Reconstituer la chronologie complète des accès SSH (source, compte, commandes exécutées) et évaluer le périmètre de compromission, y compris le mouvement latéral.
* Rechercher les mécanismes de persistance déposés (clés autorisées, services, tâches planifiées, conteneurs malveillants) et les éradiquer.
* Mettre à jour l'inventaire des images de base et des firmwares avec la version corrigée et instaurer un contrôle de version OpenSSH en CI/CD.
* Revoir les procédures de gestion des secrets et l'usage de l'authentification par mot de passe sur les infrastructures Linux.
* Documenter le retour d'expérience et ajuster les SLA de patch pour les composants d'accès distant.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétroactivement sur 90 jours les authentifications par mot de passe réussies sur des comptes normalement en clé seule.
* Analyser les journaux de connexions SSH avec des longueurs de mot de passe inhabituelles ou des séquences de caractères répétitifs.
* Examiner les hôtes Alpine/musl pour des binaires ou scripts déposés après une connexion SSH externe (webshells, mineurs, proxys, outils de tunneling).
* Traquer l'ajout de clés SSH non référencées et les modifications de configuration sshd sur l'ensemble du parc.
* Comparer les images de conteneurs en production à leurs manifestes d'origine pour détecter des couches ou binaires non attendus.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploitation d'une application exposée sur Internet (démon SSH joignable) pour obtenir un accès initial avec privilèges root. |
| **T1078** | Usage de comptes valides : contournement de l'authentification par mot de passe et prise de contrôle de comptes censés être réservés à l'authentification par clé (root, comptes de déploiement). |
| **T1021.004** | Utilisation du service SSH distant comme vecteur d'accès et de mouvement latéral sur les systèmes musl/Alpine. |
| **T1110** | Exploitation d'une faiblesse de validation des secrets d'authentification : acceptation de tout mot de passe de plus de 256 caractères. |

---

### Sources

* [https://sshhole.com/](https://sshhole.com/)


---

<div id="dissecting-werfault"></div>

## Dissecting WerFault

### Résumé

FalconForce publie une analyse technique intitulée « Dissecting WerFault », consacrée à WerFault.exe, le composant de rapport d'erreurs de Windows (Windows Error Reporting).

---

### Analyse opérationnelle

WerFault.exe est un binaire signé Microsoft, présent par défaut sur tous les systèmes Windows, ce qui en fait une cible de choix pour l'exécution proxy et l'évasion défensive. Les usages offensifs observés dans l'écosystème consistent à détourner le mécanisme de vidage de plantage pour accéder à la mémoire de processus sensibles, notamment lsass.exe, ou pour injecter du code dans un processus de confiance. Pour le SOC, la détection doit s'appuyer sur la relation parent-enfant (WerFault lancé par un processus non Microsoft ou depuis un répertoire utilisateur), sur l'accès aux handles de processus protégés, sur l'apparition de fichiers .dmp hors des emplacements attendus et sur les injections dans le processus. La ligne de base du comportement légitime de reporting d'erreurs est indispensable pour limiter les faux positifs, très nombreux sur ce composant.

---

### Implications stratégiques

L'abus de binaires signés du système reste l'une des techniques les plus efficaces pour contourner les contrôles applicatifs et les solutions de sécurité reposant sur la réputation des éditeurs. La connaissance fine de ces composants est un prérequis pour les équipes de détection, mais aussi un enjeu de conception : réduction des privilèges de vidage mémoire, protection de LSASS et durcissement des politiques d'exécution deviennent des mesures structurelles. Les organisations doivent considérer que la confiance accordée par défaut aux binaires Microsoft constitue une surface d'attaque à part entière.

---

### Recommandations

* Activer la protection de LSASS (RunAsPPL) et Credential Guard sur les postes et serveurs Windows.
* Restreindre l'attribution de SeDebugPrivilege et surveiller son usage.
* Déployer des règles ASR et WDAC/AppLocker limitant l'exécution depuis les répertoires utilisateurs.
* Centraliser et corréler les événements de création de processus et d'accès mémoire dans le SIEM.
* Maintenir une ligne de base du comportement légitime de WerFault.exe pour réduire les faux positifs.
* Former les analystes à la détection de l'exécution proxy via binaires signés.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Documenter le comportement légitime de WerFault.exe dans le parc (chemins attendus, parents habituels, volumes de plantages) pour établir une ligne de base.
* Activer et centraliser la télémétrie EDR/Sysmon : création de processus, accès aux handles de processus, écriture de fichiers de vidage, chargement de modules.
* Restreindre les droits de vidage mémoire (SeDebugPrivilege) et surveiller leur attribution.
* Configurer la collecte et la rétention des journaux Windows Error Reporting et des fichiers .dmp générés sur les postes et serveurs.
* Sensibiliser les équipes SOC à l'abus des binaires signés Microsoft comme vecteur de discrétion.

#### Phase 2 — Détection et analyse

* Détecter WerFault.exe lancé avec un parent inhabituel (processus non Microsoft, Office, script, binaire en répertoire utilisateur).
* Alerter sur l'accès de WerFault.exe au processus lsass.exe ou sur la génération de vidages mémoire contenant des identifiants.
* Surveiller la création de fichiers .dmp dans des répertoires non standards (%TEMP%, %LOCALAPPDATA%\CrashDumps, répertoires publics).
* Détecter les injections dans WerFault.exe (threads distants, régions mémoire non mappées sur disque, modules non signés).
* Corréler avec les événements de suppression ou de modification des paramètres Windows Error Reporting (registre, stratégie de groupe).

#### Phase 3 — Confinement, éradication et récupération

* Isoler la machine concernée du réseau tout en préservant la mémoire et les fichiers de vidage pour l'analyse.
* Suspendre puis terminer les processus suspects identifiés et bloquer les binaires ou chemins impliqués via l'EDR.
* Réinitialiser les comptes dont les secrets ont pu être exposés dans un vidage mémoire et révoquer les tickets Kerberos associés.
* Bloquer les indicateurs de compromission identifiés (hashes, chemins, adresses de commande et contrôle) au niveau EDR, proxy et DNS.
* Appliquer des restrictions d'exécution (WDAC/AppLocker) sur les répertoires utilisateurs pour limiter le proxy execution.

#### Phase 4 — Activités post-incident

* Analyser les vidages mémoire et les artefacts WerFault pour identifier le mode opératoire et les données exfiltrées.
* Évaluer le mouvement latéral et la persistance à partir de l'hôte initialement compromis.
* Renforcer la politique de protection des processus sensibles (LSA protection, Credential Guard, ASR).
* Mettre à jour les règles de détection à partir des artefacts observés et documenter les écarts de télémétrie.
* Revoir la politique de collecte des rapports d'erreurs pour concilier forensic et confidentialité.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher sur l'ensemble du parc les exécutions de WerFault.exe avec des parents non standards sur les 90 derniers jours.
* Identifier les fichiers .dmp récents de taille anormale ou situés hors des répertoires de vidage attendus.
* Traquer les accès aux handles de lsass.exe depuis des processus signés Microsoft détournés.
* Rechercher les modifications de configuration Windows Error Reporting et la désactivation de la télémétrie de plantage.
* Corréler avec les campagnes connues d'abus de binaires signés pour la discrétion et l'évasion défensive.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1003.001** | Accès à la mémoire du processus LSASS, notamment via les mécanismes de vidage de plantage associés au rapport d'erreurs Windows. |
| **T1055** | Injection de code dans un processus légitime signé Microsoft pour masquer l'exécution malveillante. |
| **T1562** | Altération ou détournement des mécanismes de défense et de télémétrie via l'abus de composants de reporting d'erreurs. |
| **T1218** | Exécution proxy de binaires signés du système (Living Off the Land) pour contourner les contrôles applicatifs. |

---

### Sources

* [https://falconforce.nl/dissecting-werfault/](https://falconforce.nl/dissecting-werfault/)


---

<div id="cela-aurait-pu-etre-une-mauvaise-journee-pour-dhsgov-surtout-dans-ce-climat"></div>

## Cela aurait pu être une mauvaise journée pour DHS.gov, surtout dans ce climat

### Résumé

L'enregistrement SPF de dhs[.]gov contenait le mécanisme a:mail[.]tripwire-dhs[.]us, autorisant un serveur de messagerie hébergé sur un domaine tiers à envoyer des e-mails au nom du Department of Homeland Security. Or le domaine tripwire-dhs[.]us n'était plus enregistré : le registre .us renvoyait un 404 en RDAP, les serveurs de noms faisant autorité un NXDOMAIN, et le domaine était disponible à l'achat pour environ 6,50 USD chez Cloudflare ou 5,94 GBP chez GoDaddy. Le domaine a été enregistré défensivement le 7 novembre 2026 par Casey Ellis (disclose.io), ce qui a neutralisé le risque ; le mécanisme restait toutefois présent dans le SPF au 8 novembre. La découverte provient d'un nouveau contrôle du scanner « Ghosteds » appliqué au top 5 000 Tranco : 1 329 domaines externes ont été identifiés dans les enregistrements de messagerie, un seul était disponible à l'achat, et il figurait dans le SPF de dhs[.]gov. Le domaine de dhs[.]gov appliquait une politique DMARC p=reject avec pct=100. Les journaux de transparence des certificats montrent un certificat Entrust émis entre 2018 et 2020 à BAE Systems (Sterling, Virginie) couvrant tripwire-dhs[.]us, www, dev, stage et mail, puis des certificats Let's Encrypt wildcard dont le dernier a été émis le 25 août 2025 et expirait le 23 novembre 2025. Le nom renvoie à TRIPwire, le portail de partage d'information counter-IED du DHS.

---

### Analyse opérationnelle

Il s'agit d'un cas typique de « dangling SPF » : un domaine tiers expiré reste référencé dans une politique d'authentification e-mail, ce qui permet à quiconque l'achète de faire passer SPF puis DMARC sans clé DKIM, la politique p=reject devenant inopérante puisque rien n'échoue. L'impact opérationnel est direct : usurpation crédible d'un domaine gouvernemental, phishing ciblé, diffusion de fausses consignes. La détection ne relève pas de l'EDR mais de l'audit DNS continu : inventaire des mécanismes SPF, vérification de propriété des domaines cités, surveillance de leur expiration et de leur disponibilité à l'achat. Les équipes SOC doivent corréler les rapports DMARC agrégés avec les sources d'envoi attendues et surveiller les certificats émis sur des domaines liés. La remédiation est simple mais urgente : retirer le mécanisme obsolète, enregistrer défensivement le domaine, conserver p=reject et vérifier l'alignement après modification.

---

### Implications stratégiques

Le cas illustre la fragilité de la chaîne de confiance de la messagerie gouvernementale, dépendante de prestataires et de projets abandonnés. Dans un contexte de tensions géopolitiques (échanges de coups avec l'Iran mentionnés par l'auteur), l'usurpation d'un domaine du DHS aurait eu un potentiel de désinformation et d'hameçonnage à fort impact. Plus largement, la dette de configuration DNS est un risque systémique sous-estimé : les organisations accumulent des mécanismes de confiance vers des tiers sans processus de décommissionnement. La découverte fortuite via un scanner automatisé sur le top Tranco suggère que des cas similaires existent dans de nombreuses grandes organisations.

---

### Recommandations

* Auditer immédiatement tous les enregistrements SPF/DMARC et retirer tout mécanisme pointant vers un domaine non détenu par l'organisation.
* Enregistrer défensivement les domaines tiers encore référencés et mettre en place une surveillance de leur expiration.
* Automatiser la vérification de propriété des domaines cités dans les configurations de messagerie (RDAP, NXDOMAIN, disponibilité registrar).
* Analyser les rapports DMARC agrégés pour détecter les sources d'envoi inattendues.
* Intégrer la revue DNS au processus de fin de contrat fournisseur et de décommissionnement de projet.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier tous les enregistrements SPF, DKIM et DMARC des domaines de l'organisation et de ses filiales.
* Identifier les domaines tiers référencés dans les enregistrements de messagerie (mécanismes a:, mx, include:) et vérifier leur propriété.
* Mettre en place une surveillance de l'expiration des domaines et certificats tiers cités dans les configurations de confiance.
* Définir une procédure de retrait d'un mécanisme SPF obsolète avec validation métier.

#### Phase 2 — Détection et analyse

* Surveiller en continu la disponibilité à l'achat des domaines référencés dans les enregistrements SPF/DMARC (RDAP, registrars, Route 53).
* Analyser les rapports DMARC agrégés pour détecter des sources d'envoi inattendues passant SPF et DKIM.
* Alerter sur toute résolution DNS d'un sous-domaine de messagerie tiers pointant vers une infrastructure non contrôlée.
* Corréler les journaux de passerelle de messagerie avec les enregistrements SPF publiés pour détecter les incohérences.

#### Phase 3 — Confinement, éradication et récupération

* Enregistrer défensivement le domaine expiré référencé dans le SPF pour empêcher toute acquisition malveillante.
* Retirer immédiatement le mécanisme a: obsolète de l'enregistrement SPF et republier la zone DNS.
* Conserver DMARC en p=reject avec pct=100 et vérifier l'alignement SPF/DKIM après modification.
* Notifier les équipes de messagerie et de sécurité, et surveiller les tentatives d'usurpation pendant la période de transition.

#### Phase 4 — Activités post-incident

* Documenter la cause (fin de contrat fournisseur, migration de projet) et corriger le processus de décommissionnement.
* Ajouter un contrôle de revue des enregistrements de messagerie lors de tout changement de prestataire.
* Intégrer la vérification de propriété des domaines tiers au processus d'audit DNS périodique.
* Communiquer en interne sur le risque d'usurpation et les indicateurs à surveiller.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux de messagerie des e-mails reçus avec un expéditeur du domaine concerné et une origine non légitime.
* Vérifier les journaux de certificats (CT) pour tout certificat émis sur le domaine expiré.
* Analyser les rapports DMARC historiques pour identifier des sources d'envoi inconnues.
* Étendre la chasse à tous les domaines de l'organisation référencés dans des SPF tiers et non détenus.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `tripwire-dhs[.]us` | High |
| DOMAIN | `mail[.]tripwire-dhs[.]us` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1583.001** | Acquisition d'infrastructures : enregistrement d'un domaine expiré référencé dans une configuration de confiance |
| **T1656** | Usurpation d'identité d'une organisation gouvernementale via e-mail légitime en apparence |

---

### Sources

* [https://splinters.io/story-time/tripwire-dhs](https://splinters.io/story-time/tripwire-dhs)


---

<div id="outil-open-source-qui-classe-les-correctifs-ad-selon-le-nombre-dutilisateurs-quils-coupent-de-domain-admin-et-signale-dabord-les-plus-faciles-retours-souhaites"></div>

## Outil open source qui classe les correctifs AD selon le nombre d'utilisateurs qu'ils coupent de Domain Admin, et signale d'abord les plus faciles (retours souhaités)

### Résumé

Un pentester publie HorusEye, un outil gratuit sous licence MIT qui s'appuie sur les données déjà collectées par SharpHound/BloodHound CE, Certipy et NetExec et fonctionne entièrement hors ligne. L'outil compte le nombre d'utilisateurs activés disposant d'un chemin vers Tier-0 et calcule le plus petit ensemble de changements permettant de ramener ce nombre à zéro. Chaque correction est notée par effort (faible, moyen, élevé, avec justification basée sur des règles fixes, sans IA) et les « quick wins » — findings critiques ou élevés à correction peu coûteuse — sont classés en premier selon le nombre d'utilisateurs qu'ils coupent. Chaque finding précise pourquoi il compte, quoi faire (avec une alternative si la correction évidente casserait un accès) et comment vérifier. L'outil propose un suivi de statut (ouvert, en cours, corrigé, risque accepté) exportable, un mode --diff pour confirmer lors d'un retest que les éléments marqués corrigés le sont réellement et signaler les régressions, ainsi qu'un export CSV. Une démonstration est disponible sur un laboratoire synthétique de 1 245 utilisateurs. L'auteur reconnaît deux limites : l'outil ne voit que ce que les collecteurs capturent et les notations d'effort sont des règles empiriques.

---

### Analyse opérationnelle

L'outil répond à un problème opérationnel récurrent : la priorisation de la remédiation Active Directory après une cartographie BloodHound. Pour un SOC ou une équipe infrastructure, l'intérêt est de transformer une liste de chemins d'attaque en plan d'action ordonné par effort et par impact, avec vérification post-remédiation. Les limites doivent être intégrées : la qualité du résultat dépend entièrement de la fraîcheur et de la complétude des collectes, et les notations d'effort sont heuristiques, donc à valider en environnement réel. Le mode hors ligne est un atout pour les environnements sensibles, mais l'exécution d'un binaire open source doit être précédée d'une revue du code et d'une vérification d'intégrité.

---

### Implications stratégiques

Active Directory reste le cœur névralgique des compromissions en entreprise : la réduction des chemins vers Tier-0 est un indicateur de risque plus pertinent que le nombre brut de vulnérabilités. La démocratisation d'outils open source de priorisation réduit la dépendance aux prestataires mais introduit un risque de chaîne d'approvisionnement logicielle qu'il faut encadrer. Enfin, l'approche « sévérité + effort » reflète une maturité croissante des organisations qui cherchent à maximiser le retour sur investissement des remédiations plutôt qu'à traiter les alertes par ordre alphabétique de criticité.

---

### Recommandations

* Valider la fraîcheur et la complétude des collectes BloodHound avant toute décision de remédiation basée sur l'outil.
* Revue du code et vérification d'intégrité avant exécution en environnement de production ; privilégier une exécution hors ligne.
* Traiter en priorité les quick wins coupant le plus grand nombre d'utilisateurs de Tier-0, puis les corrections à effort moyen.
* Utiliser le mode --diff à chaque cycle de retest pour objectiver la régression ou la persistance des chemins d'attaque.
* Compléter l'outil par une validation manuelle des exceptions métier (comptes de service, délégations) avant application.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Collecter les données AD avec SharpHound/BloodHound CE, Certipy et NetExec selon un périmètre et une fréquence définis.
* Définir formellement les actifs Tier-0 (contrôleurs de domaine, PKI, sauvegardes, hyperviseurs, comptes à privilèges).
* Établir un registre des exceptions et des dépendances métier avant toute remédiation (comptes de service, délégations).
* Valider la chaîne d'approvisionnement de l'outil open source utilisé (revue du code, build reproductible, exécution hors ligne).

#### Phase 2 — Détection et analyse

* Identifier le nombre d'utilisateurs activés disposant d'un chemin vers Tier-0 et suivre son évolution dans le temps.
* Prioriser les « quick wins » : findings critiques/élevés dont la correction est de faible effort et qui coupent le plus d'utilisateurs.
* Détecter les régressions après remédiation via un différentiel (--diff) entre deux exécutions.
* Suivre l'état des findings (ouvert, en cours, corrigé, risque accepté) et exporter les rapports pour les comités sécurité.

#### Phase 3 — Confinement, éradication et récupération

* Appliquer en priorité les corrections à faible effort : retrait de droits excessifs, nettoyage des ACL, désactivation de délégations non contraintes.
* Isoler les comptes à privilèges exposés et imposer une double administration (Tier-0 / Tier-1).
* Réinitialiser les secrets des comptes de service identifiés comme vecteurs de chemin d'attaque.
* Documenter chaque changement et prévoir une alternative lorsque la correction évidente casserait un accès métier.

#### Phase 4 — Activités post-incident

* Rejouer la collecte après remédiation et confirmer la disparition effective des chemins d'attaque.
* Mettre à jour la politique de gestion des accès à privilèges et les procédures de revue d'ACL.
* Intégrer les métriques de réduction de surface (nombre d'utilisateurs à chemin Tier-0) aux indicateurs de sécurité.
* Former les équipes à la priorisation par sévérité et effort plutôt qu'à la seule sévérité.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les techniques d'élévation de privilèges AD correspondant aux chemins identifiés (Kerberoasting, délégations, ACL abusives).
* Corréler les journaux d'événements de domaine avec les comptes identifiés comme exposés.
* Vérifier l'absence de nouveaux chemins apparus depuis la dernière collecte (comptes créés, groupes modifiés).
* Tester la robustesse des corrections en simulant un chemin d'attaque résiduel sur un environnement de recette.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1087.002** | Énumération de comptes de domaine (cartographie des chemins vers Tier-0) |
| **T1069.002** | Découverte de groupes de domaine et de permissions (analyse des relations d'administration) |

---

### Sources

* [https://www.reddit.com/r/blueteamsec/comments/1xqxs5z/opensource_tool_that_ranks_ad_fixes_by_how_many/](https://www.reddit.com/r/blueteamsec/comments/1xqxs5z/opensource_tool_that_ranks_ad_fixes_by_how_many/)


---

<div id="fantome-dans-le-script-risques-caches"></div>

## Fantôme dans le script : risques cachés

### Résumé

Liondawn Labs publie les résultats d'une recherche menée à partir de mai 2026 sur l'interpréteur de polices TrueType de Ghostscript. Le contexte est celui d'une recrudescence de vulnérabilités dans le traitement d'image : la classe « HEIF Heist » découverte par Hacktron AI dans libheif, des vulnérabilités critiques de traitement d'image chez Microsoft Bing Images découvertes par XBOW, ImageTragick comme référence historique, et en mars 2026 des vulnérabilités ImageMagick publiées par pwn.ai, dont un contournement de détection de format PostScript que l'éditeur a classé comme relevant de la politique de déploiement et non comme une vulnérabilité produit. Les chercheurs se sont fixé comme objectif de trouver une corruption mémoire exploitable dans Ghostscript, en ciblant l'interpréteur de bytecode TrueType, les polices étant notoirement sujettes aux corruptions mémoire et PostScript permettant d'embarquer des données de police. Ils ont identifié une écriture hors limites dans le traitement des instructions SHC/SHZ des polices TrueType encapsulées de type 42. L'IA a été utilisée tout au long du processus (cartographie du code, compréhension d'implémentations inconnues, expérimentation dynamique), la qualité du travail reposant toutefois sur l'expertise des chercheurs.

---

### Analyse opérationnelle

La surface d'attaque réelle dépasse largement la fonction d'upload d'image : chaque convertisseur embarque une pile de code natif (parseurs de polices, interpréteurs PostScript, gestion mémoire) exposée à des données hostiles. Pour les équipes SOC et infrastructure, les points d'exposition prioritaires sont les services web acceptant des fichiers, les passerelles de messagerie qui convertissent les pièces jointes, les pipelines CI/CD générant des PDF et les serveurs d'impression. La détection repose sur la surveillance des plantages de processus de conversion, de l'exécution de processus enfants par gs/convert/magick et des connexions sortantes depuis les conteneurs de conversion. Les mesures de réduction structurelle sont le sandboxing (réseau coupé, privilèges minimaux, seccomp), la désactivation des délégués PostScript/EPS et la restriction des formats acceptés.

---

### Implications stratégiques

Les dépendances natives de bas niveau restent le maillon faible alors que la couche applicative se durcit : les attaquants ciblent les parseurs pour obtenir un impact large. L'usage de l'IA pour accélérer la découverte de vulnérabilités modifie l'économie de la recherche et réduit la fenêtre entre découverte et exploitation. Le refus d'un éditeur de traiter un contournement de détection de format comme une vulnérabilité illustre un risque de gouvernance : des comportements connus restent exploitables indéfiniment. Les organisations doivent intégrer ces composants à leur SBOM et à leur veille, et considérer le traitement de fichiers non fiables comme une activité à isoler systématiquement.

---

### Recommandations

* Recenser Ghostscript, ImageMagick, libheif et tous les convertisseurs natifs dans l'inventaire logiciel et suivre leurs versions.
* Désactiver les délégués PostScript/EPS d'ImageMagick et restreindre les formats acceptés sur les points d'entrée exposés.
* Exécuter les services de conversion dans des conteneurs isolés sans réseau, à privilèges réduits, avec quotas et système de fichiers en lecture seule.
* Surveiller les plantages de processus de conversion et l'exécution de processus enfants par les binaires de traitement d'image.
* Traiter tout contournement de détection de format connu comme un risque à atténuer par la politique de déploiement, indépendamment de la position de l'éditeur.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser tous les composants de traitement d'image et de document (Ghostscript, ImageMagick, libheif, convertisseurs) et leurs versions.
* Identifier les points d'entrée acceptant des fichiers utilisateurs : upload web, e-mail, pipelines CI/CD, génération de PDF.
* Désactiver par défaut les délégués PostScript/EPS d'ImageMagick et restreindre les formats acceptés.
* Isoler les services de conversion dans des conteneurs à privilèges réduits avec seccomp et système de fichiers en lecture seule.

#### Phase 2 — Détection et analyse

* Surveiller les plantages répétés des processus de conversion (segfault, codes de sortie anormaux) pouvant indiquer une tentative d'exploitation.
* Détecter l'exécution de commandes enfants par les binaires de conversion (gs, convert, magick) via auditd/EDR.
* Alerter sur les fichiers Polyglot ou à détection de format ambiguë (PostScript déguisé en image).
* Surveiller les accès réseau sortants depuis les conteneurs de conversion, signe d'exploitation réussie.

#### Phase 3 — Confinement, éradication et récupération

* Mettre à jour Ghostscript et les bibliothèques de traitement d'image vers les dernières versions corrigées.
* Bloquer temporairement les formats à risque (PS, EPS, PDF avec polices embarquées) sur les points d'entrée exposés.
* Isoler ou arrêter le service de conversion compromis et préserver les fichiers soumis pour analyse.
* Appliquer un sandboxing renforcé (pas de réseau, quotas CPU/mémoire, utilisateur non privilégié).

#### Phase 4 — Activités post-incident

* Analyser les fichiers piégés et documenter la chaîne d'exploitation observée.
* Mettre à jour la politique d'acceptation des formats et la liste des délégués autorisés.
* Intégrer les composants natifs de parsing à l'inventaire SBOM et au processus de veille vulnérabilités.
* Revoir la posture vis-à-vis des éditeurs qui classent les contournements de détection de format comme relevant de la politique de déploiement.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des processus de conversion ayant généré des processus enfants ou des connexions réseau inattendues.
* Analyser les journaux de conversion pour des fichiers aux dimensions ou structures anormales (polices Type 42, instructions SHC/SHZ).
* Vérifier l'absence de binaires déposés dans les répertoires temporaires des services de conversion.
* Rechercher des indicateurs de post-exploitation sur les serveurs hébergeant des pipelines de traitement documentaire.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1203** | Exploitation pour exécution côté client via le traitement d'un fichier piégé (image, police, PostScript) |
| **T1190** | Exploitation d'une application exposée traitant des fichiers fournis par l'utilisateur |

---

### Sources

* [https://www.liondawnlabs.com/blog/ghost-in-the-script/](https://www.liondawnlabs.com/blog/ghost-in-the-script/)


---

<div id="nous-evaluons-avec-une-haute-confiance-que-lechantillon-est-arid-gopher-et-donc-une-activite-darid-viper-les-deux-campagnes-partagent-la-victimologie-et-les-habitudes-de-nommage"></div>

## Nous évaluons avec une haute confiance que l'échantillon est Arid Gopher, et donc une activité d'Arid Viper. Les deux campagnes partagent la victimologie et les habitudes de nommage.

### Résumé

Le dépôt d'IOC de Nextron Systems contient un rapport consacré aux campagnes d'espionnage arabophones. L'évaluation attribue avec un haut niveau de confiance un échantillon à Arid Gopher, donc à l'activité d'Arid Viper, en s'appuyant sur le fait que les deux campagnes partagent la victimologie et les habitudes de nommage. Le fichier readme du rapport a été mis à jour le 30 octobre 2026. Le contenu publié dans la source se limite à cette évaluation d'attribution et au lien vers le dépôt ; les indicateurs techniques détaillés sont hébergés dans les fichiers du dépôt.

---

### Analyse opérationnelle

L'intérêt opérationnel réside dans la mise à disposition d'un jeu d'IOC prêt à l'emploi pour la détection et la chasse, adossé à une attribution explicite. Les équipes SOC doivent importer ces artefacts dans l'EDR, la passerelle de messagerie, le proxy et le DNS, puis rechercher les conventions de nommage caractéristiques des deux campagnes. L'attribution à Arid Viper oriente la chasse vers les techniques d'espionnage ciblé : leurres, pièces jointes, persistance et communications avec des infrastructures dédiées. La confiance élevée annoncée par la source doit être confrontée aux artefacts réellement présents dans l'environnement avant toute conclusion.

---

### Implications stratégiques

Arid Viper est un acteur d'espionnage arabophone historiquement actif contre des cibles gouvernementales, militaires et de la société civile au Moyen-Orient. Le partage d'IOC par des éditeurs de sécurité et la réutilisation d'infrastructures entre campagnes illustrent la professionnalisation de ces groupes et la continuité de leurs opérations. Pour les organisations exposées géographiquement ou sectoriellement, la veille sur ces dépôts constitue un levier de détection à faible coût. La mention de victimologie partagée suggère une campagne continue plutôt qu'opportuniste, ce qui justifie une surveillance durable.

---

### Recommandations

* Intégrer les IOC du dépôt Nextron aux sources de détection et planifier une mise à jour régulière.
* Cibler la chasse sur les personnels et partenaires exposés au Moyen-Orient et aux thématiques arabophones.
* Surveiller les conventions de nommage et artefacts caractéristiques des deux campagnes dans les journaux historiques.
* Renforcer la sensibilisation aux leurres ciblés et la validation des pièces jointes pour les populations à risque.
* Partager les indicateurs observés avec les communautés sectorielles et les CERT compétents.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Récupérer et versionner le dépôt d'IOC Nextron relatif aux campagnes d'espionnage arabophones et l'intégrer aux sources de renseignement.
* Cartographier les cibles potentielles internes (personnels exposés, partenaires au Moyen-Orient) et les canaux de contact.
* Configurer les règles de détection sur les artefacts du dépôt (noms de fichiers, conventions de nommage, infrastructures).
* Sensibiliser les collaborateurs exposés aux leurres et aux pièces jointes ciblées.

#### Phase 2 — Détection et analyse

* Déployer les IOC du dépôt dans les outils de détection (EDR, passerelle de messagerie, proxy, DNS).
* Rechercher les artefacts correspondant aux habitudes de nommage des deux campagnes décrites.
* Surveiller les connexions vers les infrastructures de commande et contrôle référencées.
* Analyser les e-mails entrants ciblant les personnels identifiés comme à risque.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les postes présentant des artefacts correspondant aux IOC et préserver la mémoire et les journaux.
* Bloquer les domaines, adresses IP et hachages identifiés au niveau des passerelles et du DNS.
* Réinitialiser les identifiants des comptes compromis et révoquer les sessions actives.
* Notifier les partenaires et autorités compétentes si des données sensibles ont été exfiltrées.

#### Phase 4 — Activités post-incident

* Analyser les échantillons et confirmer l'attribution (Arid Gopher / Arid Viper) avec les données du dépôt.
* Mettre à jour les règles de détection avec les nouveaux artefacts observés.
* Renforcer la sensibilisation ciblée des personnels exposés et les procédures de validation des pièces jointes.
* Documenter la campagne et partager les indicateurs avec les communautés sectorielles.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les conventions de nommage et artefacts des deux campagnes dans les journaux historiques.
* Analyser les connexions sortantes vers des infrastructures inconnues depuis les postes de personnels sensibles.
* Rechercher des mécanismes de persistance et des tâches planifiées associés aux échantillons.
* Corréler avec les campagnes arabophones déjà documentées pour identifier des réutilisations d'infrastructure.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1587.001** | Développement de capacités : malware sur mesure pour des campagnes d'espionnage |
| **T1204.002** | Exécution par l'utilisateur via un fichier malveillant (pièce jointe ou leurre) |

---

### Sources

* [https://github.com/NextronSystems/iocs/tree/master/reports/Arabic%20espionage%20campaigns%20#readme](https://github.com/NextronSystems/iocs/tree/master/reports/Arabic%20espionage%20campaigns%20#readme)


---

<div id="rt-fuitesinfos-fuites-infos-sgs-227-millions-de-personnes-et-4000-centres-controletechnique"></div>

## RT: @fuitesinfos 🚨 FUITES INFOS | SGS — ~ 22,7 millions de personnes et 4000 centres. #controletechnique

### Résumé

Le 8 novembre 2026, une base présentée comme la partie française du groupe SGS a été mise en vente sur un forum cybercriminel. SGS, groupe international d'inspection et de certification, exploite en France les réseaux de contrôle technique automobile Auto Sécurité, Sécuritest et Vérif'Autos, soit environ 2 000 centres. L'annonce revendique 96 Go de données, 22,7 millions de personnes et près de 4 000 centres, accompagnés d'un échantillon diffusé librement. Les données concernées, selon l'annonce complétée par l'échantillon publié, incluent l'identité et les coordonnées des clients (nom, adresse, téléphone, adresse électronique), les plaques d'immatriculation, les numéros de série et l'historique des contrôles, les factures et paiements des centres, les accès des centres (mots de passe, accès distants, comptes bancaires) ainsi que l'annuaire du personnel du groupe. La revendication n'est pas confirmée officiellement.

---

### Analyse opérationnelle

L'élément le plus critique n'est pas le volume de données personnelles mais l'exposition revendiquée d'identifiants et d'accès distants de centres : elle ouvre la voie à des intrusions directes dans les systèmes des centres de contrôle technique, avec un risque d'rançongiciel et de fraude. Les données clients (immatriculations, historiques de contrôle, coordonnées) constituent un matériau idéal pour du phishing ciblé et de la fraude. Les équipes doivent prioriser la rotation des secrets, l'activation du MFA sur les accès distants, la revue des journaux de connexion des centres et la surveillance des réutilisations d'identifiants. La diffusion d'un échantillon libre permet de vérifier rapidement quels comptes sont concernés.

---

### Implications stratégiques

Le secteur du contrôle technique automobile est un maillon critique de la sécurité routière et un réseau très fragmenté de franchises, ce qui en fait une cible à faible maturité et fort effet de levier. Une compromission des accès des centres pourrait perturber l'activité et produire des documents frauduleux. L'incident soulève des enjeux RGPD majeurs (22,7 millions de personnes revendiquées) et de responsabilité contractuelle entre le groupe et ses réseaux franchisés. La revendication non confirmée impose une communication prudente tout en préparant les obligations de notification.

---

### Recommandations

* Réinitialiser sans délai les mots de passe et révoquer les accès distants des centres, en priorisant ceux présents dans l'échantillon publié.
* Généraliser l'authentification multifacteur sur tous les accès distants et comptes à privilèges des réseaux de centres.
* Analyser l'échantillon diffusé pour identifier précisément les personnes et comptes concernés et préparer la notification RGPD.
* Surveiller les forums et places de marché pour suivre la diffusion et la revente de la base.
* Renforcer la détection de phishing utilisant immatriculations et coordonnées clients, et sensibiliser les clients finaux.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les données détenues par les réseaux de contrôle technique (identité clients, immatriculations, historiques de contrôle, facturation, annuaire du personnel).
* Recenser les accès distants et comptes à privilèges des centres franchisés et imposer une authentification multifacteur.
* Définir un plan de notification RGPD (CNIL, personnes concernées) et identifier les obligations sectorielles applicables.
* Segmenter les systèmes d'information des centres et du siège pour limiter les mouvements latéraux.

#### Phase 2 — Détection et analyse

* Surveiller les forums cybercriminels et places de marché pour détecter la mise en vente de données de l'organisation.
* Détecter les connexions atypiques aux systèmes des centres (géolocalisation, horaires, volumes).
* Alerter sur les tentatives d'authentification en masse ou les échecs répétés sur les accès distants.
* Surveiller l'usage d'immatriculations et de données clients dans des campagnes de phishing.

#### Phase 3 — Confinement, éradication et récupération

* Réinitialiser immédiatement les mots de passe et révoquer les accès distants des centres potentiellement exposés.
* Activer ou renforcer l'authentification multifacteur sur tous les accès distants et comptes à privilèges.
* Bloquer les adresses IP et comptes suspects identifiés dans les journaux d'accès.
* Faire supprimer ou retirer l'annonce lorsque la plateforme le permet, et documenter les preuves.

#### Phase 4 — Activités post-incident

* Confirmer ou infirmer officiellement la fuite après analyse de l'échantillon publié.
* Notifier la CNIL dans les délais réglementaires et informer les personnes concernées si le risque est avéré.
* Mettre à jour la politique de gestion des accès des centres franchisés et les contrôles contractuels.
* Renforcer la surveillance de la marque et la détection de phishing utilisant les données exposées.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux d'accès distant des connexions correspondant à la période de compromission supposée.
* Identifier les comptes dont les identifiants apparaissent dans l'échantillon publié et vérifier leur activité récente.
* Rechercher des exfiltrations massives depuis les bases clients et de facturation.
* Surveiller la réutilisation des données (immatriculations, coordonnées) dans des campagnes de fraude ou d'hameçonnage.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1213** | Collecte de données depuis des référentiels internes (clients, facturation, annuaire du personnel) |
| **T1078** | Usage d'identifiants valides de centres (mots de passe, accès distants) pour un accès initial |

---

### Sources

* [https://mastox.eu/@Ced_haurus/117580868396762358](https://mastox.eu/@Ced_haurus/117580868396762358)


---

<div id="comte-de-sussex-new-jersey-avis-dincident-de-confidentialite-des-donnees"></div>

## Comté de Sussex, New Jersey : avis d'incident de confidentialité des données

### Résumé

Le bureau du procureur du comté de Sussex (New Jersey) a publié un avis de violation de données : un acteur non autorisé a accédé à son réseau entre le 15 et le 22 juillet 2026. Des fichiers contenant des informations personnelles ont été consultés et pourraient avoir été dérobés. Les données exposées comprennent des noms, des numéros de sécurité sociale (SSN) ainsi que des numéros de permis de conduire ou de cartes d'identité délivrées par l'État.

---

### Analyse opérationnelle

L'exposition de SSN et de numéros de pièces d'identité constitue un risque élevé d'usurpation d'identité et de fraude financière pour les administrés concernés. Pour le SOC, la fenêtre d'intrusion de sept jours suggère une présence non détectée : il faut prioriser la revue des journaux d'authentification, des accès aux partages de fichiers et des flux sortants sur cette période. Les équipes doivent vérifier l'absence de persistance résiduelle (comptes créés, tâches planifiées, accès VPN), renforcer la surveillance DLP sur les répertoires RH/judiciaires et préparer la notification réglementaire. L'absence de détail sur le vecteur initial impose une hypothèse large : identifiants valides, exploitation d'un service exposé ou compromission d'un tiers.

---

### Implications stratégiques

Les collectivités territoriales restent des cibles de choix : données hautement sensibles, budgets de sécurité contraints et dépendance à des prestataires. La notification publique engage la réputation de l'institution et peut déclencher des contentieux collectifs aux États-Unis. Cet incident illustre la nécessité d'intégrer la protection des données des administrés dans la gouvernance des risques, avec une traçabilité réelle des accès et une clause de notification contractuelle avec les fournisseurs.

---

### Recommandations

* Imposer le MFA sur tous les accès distants et comptes à privilèges du comté
* Déployer une détection comportementale sur les accès aux partages contenant des PII
* Réaliser un audit des habilitations et appliquer le moindre privilège
* Préparer un dispositif de notification et d'accompagnement des personnes affectées (surveillance d'identité)
* Tester annuellement le plan de réponse à incident avec la direction juridique

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les systèmes du parquet et les données PII (noms, SSN, numéros de permis) stockées et leurs ayants droit
* Vérifier la couverture EDR/Journalisation sur les serveurs de fichiers et les partages réseau
* Préparer un modèle de notification CNIL/État et un prestataire de surveillance d'identité
* Définir les seuils d'alerte sur les accès massifs aux partages de fichiers

#### Phase 2 — Détection et analyse

* Rechercher les connexions anormales entre le 15 et le 22 juillet 2026 (VPN, RDP, comptes de service)
* Analyser les journaux d'accès aux partages de fichiers : volume, rafales, accès hors horaires
* Corréler avec les alertes DLP et les connexions sortantes inhabituelles
* Identifier les comptes compromis via les échecs d'authentification et les changements de privilèges

#### Phase 3 — Confinement, éradication et récupération

* Réinitialiser les identifiants des comptes impactés et révoquer les sessions actives
* Isoler les hôtes suspects du réseau et bloquer les flux C2 identifiés
* Restreindre temporairement l'accès aux partages contenant des PII
* Conserver les images forensiques et la chaîne de custody avant remédiation

#### Phase 4 — Activités post-incident

* Finaliser l'analyse d'impact (nombre d'individus, catégories de données) et la notification réglementaire
* Proposer une surveillance d'identité et un gel de crédit aux personnes affectées
* Revoir les habilitations, la segmentation et la politique de rétention des PII
* Mettre à jour le plan de réponse et réaliser un exercice de crise

#### Phase 5 — Threat Hunting (proactif)

* Chasser les persistance types (tâches planifiées, comptes créés, clés SSH ajoutées) sur les serveurs du comté
* Rechercher des archives ou staging (7z, rar, zip) créés pendant la fenêtre d'intrusion
* Traquer les outils de transfert (rclone, WinSCP, MEGAsync) et les connexions cloud non autorisées
* Comparer les TTP observés avec les campagnes ciblant les collectivités américaines

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1005** | Collecte de données depuis les systèmes locaux (fichiers contenant des données personnelles) |
| **T1041** | Exfiltration de données hors du réseau compromis (prélèvement possible de fichiers) |

---

### Sources

* [https://databreaches.net/2026/11/07/county-of-sussex-new-jersey-notice-of-data-privacy-incident/](https://databreaches.net/2026/11/07/county-of-sussex-new-jersey-notice-of-data-privacy-incident/)


---

<div id="ctm360-expose-des-arnaques-aux-fausses-cartes-cadeaux-exploitant-des-marques-de-confiance"></div>

## CTM360 expose des arnaques aux fausses cartes cadeaux exploitant des marques de confiance

### Résumé

CTM360 a identifié plus de 1 000 incidents dans une campagne récurrente de fausses cartes cadeaux usurpant de grandes marques, dont PlayStation, Sephora, SHEIN, Walmart et Amazon. La campagne s'appuie sur de faux parrainages de célébrités et des publicités sponsorisées sur les réseaux sociaux. Les victimes sont conduites à des étapes trompeuses de « vérification humaine » qui collectent des informations personnelles, les amènent à installer des applications et à souscrire des abonnements payants ; aucune carte cadeau n'est jamais délivrée.

---

### Analyse opérationnelle

Le schéma combine usurpation de marque, achat publicitaire légitime et monétisation par abonnement, ce qui le rend difficile à bloquer par les seuls filtres anti-spam. Les équipes SOC doivent surveiller les domaines look-alike, les pages de vérification factice et les redirections publicitaires, et intégrer les signalements clients comme source de détection. Côté mobile, l'installation d'applications non officielles constitue le principal risque d'exposition de données et de frais récurrents. La réponse repose sur la rapidité du takedown (annonces, domaines, applications) et sur la communication de crise vers les clients.

---

### Implications stratégiques

La fraude aux cartes cadeaux exploite la confiance dans les marques grand public et la puissance de ciblage des régies publicitaires : les plateformes deviennent un canal de distribution d'arnaques à grande échelle. Pour les marques, le préjudice est double : atteinte à la réputation et coûts de remédiation, sans responsabilité directe des annonceurs usurpés. La tendance impose une gouvernance de la protection de marque (brand protection) intégrée aux équipes sécurité, avec des indicateurs de volume et de délai de retrait.

---

### Recommandations

* Mettre en place une veille automatisée des publicités et domaines usurpant la marque
* Négocier des canaux de takedown accélérés avec les régies publicitaires et les stores
* Publier des alertes clients régulières sur les faux concours et cartes cadeaux
* Bloquer au niveau DNS/proxy les domaines de « vérification humaine » identifiés
* Former le service client à qualifier et escalader rapidement les signalements de fraude

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Établir une veille sur les publicités sponsorisées usurpant la marque (plateformes sociales, moteurs de recherche)
* Définir un canal de signalement client (phishing@) et un processus de retrait (takedown) avec les plateformes
* Sensibiliser les équipes marketing et service client aux faux concours et cartes cadeaux
* Cartographier les applications mobiles non officielles se réclamant de la marque

#### Phase 2 — Détection et analyse

* Surveiller les domaines look-alike et les pages de « vérification humaine » captant des données personnelles
* Détecter les campagnes publicitaires non autorisées via les régies et les partenaires
* Analyser les signalements clients : liens reçus, applications installées, abonnements surprise
* Rechercher les indicateurs de collecte de PII et d'installation d'applications dans les journaux web

#### Phase 3 — Confinement, éradication et récupération

* Demander le retrait immédiat des annonces et pages frauduleuses aux plateformes publicitaires
* Faire suspendre les domaines et applications malveillants (registrar, hébergeur, stores)
* Publier une alerte officielle sur les canaux de la marque
* Bloquer les domaines identifiés au niveau du proxy et du DNS

#### Phase 4 — Activités post-incident

* Quantifier les victimes et les préjudices (données collectées, abonnements souscrits)
* Coordonner avec les autorités de protection des consommateurs et les forces de l'ordre
* Renforcer les contrôles sur l'usage de la marque par des tiers et les programmes d'affiliation
* Mettre à jour la procédure de takedown et les délais de réaction

#### Phase 5 — Threat Hunting (proactif)

* Rechercher d'autres campagnes utilisant les mêmes modèles de pages et kits de « vérification humaine »
* Traquer les infrastructures réutilisées (hébergeurs, certificats, comptes publicitaires)
* Analyser les applications mobiles suspectes pour identifier les SDK de collecte et d'abonnement
* Corréler avec les campagnes de fraude aux cartes cadeaux connues et leurs variantes de marque

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1656** | Usurpation d'identité de marques majeures et de célébrités pour gagner la confiance |
| **T1566** | Hameçonnage via publicités sponsorisées sur réseaux sociaux |
| **T1204.002** | Exécution par l'utilisateur : installation d'applications mobiles malveillantes |

---

### Sources

* [https://www.bleepingcomputer.com/news/security/ctm360-exposes-fake-gift-card-scams-exploiting-trusted-brands/](https://www.bleepingcomputer.com/news/security/ctm360-exposes-fake-gift-card-scams-exploiting-trusted-brands/)


---

<div id="14-million-de-mails-de-phishing-envoyes-via-le-systeme-dalerte-aux-catastrophes-du-japon"></div>

## 1,4 million d'e-mails de phishing envoyés via le système d'alerte aux catastrophes du Japon

### Résumé

Des attaquants ont utilisé l'infrastructure japonaise d'alerte aux catastrophes pour envoyer 1,4 million d'e-mails d'hameçonnage. La compromission est passée par Arcadia, un prestataire tiers chargé de gérer ces notifications critiques, permettant le détournement d'un canal gouvernemental de confiance au profit de liens malveillants. L'article indique que le secteur gouvernemental est le plus ciblé cette semaine (255 articles, 23 nouveaux signalements le jour de la publication). Le Japon a annoncé un paquet d'urgence en cybersécurité incluant le déploiement d'« équipes de secours cyber » et un recours important à l'intelligence artificielle pour détecter les anomalies ; la Corée du Sud envisage de son côté la nomination d'un « cyber tsar ».

---

### Analyse opérationnelle

Le détournement d'un canal d'alerte officiel exploite la confiance institutionnelle : les destinataires ne vérifient pas l'expéditeur d'un message d'urgence. Les équipes doivent surveiller les volumes d'envoi sortants des plateformes de notification, les accès API des prestataires et les changements de configuration. La réponse exige la révocation immédiate des accès du tiers, la suspension du canal et une communication publique rapide pour limiter le clic. Les passerelles de messagerie doivent appliquer une analyse des liens même pour les domaines gouvernementaux légitimes, et les journaux du prestataire doivent être accessibles en temps réel aux équipes de sécurité.

---

### Implications stratégiques

Cet incident illustre la limite de l'externalisation : un SLA et une clause de sécurité ne transfèrent pas la responsabilité d'un canal d'alerte compromis. La confiance dans les communications d'urgence est un actif stratégique dont la perte peut avoir des conséquences physiques. La réponse annoncée par Tokyo — équipes de secours cyber et IA de détection — et la réflexion sud-coréenne sur un cyber tsar montrent une tendance régionale à la centralisation et à la technologisation de la gouvernance cyber. Les décideurs doivent conditionner les contrats à une visibilité réelle sur la télémétrie de sécurité des prestataires critiques.

---

### Recommandations

* Exiger des prestataires critiques une télémétrie de sécurité en temps réel et un droit d'audit
* Imposer le MFA et la rotation des clés API sur les plateformes de notification de masse
* Mettre en place une surveillance des volumes d'envoi et des anomalies de contenu
* Préparer un canal de communication alternatif en cas de compromission du canal officiel
* Sensibiliser le public à la vérification des messages d'alerte et à la méfiance envers les liens
* Intégrer les scénarios de compromission de prestataire dans les exercices de crise gouvernementaux

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser les prestataires ayant accès aux systèmes d'alerte et de notification de masse, avec inventaire des privilèges
* Imposer une authentification forte et une journalisation temps réel des accès tiers aux plateformes critiques
* Mettre en place une surveillance des volumes d'envoi et des anomalies de contenu
* Préparer un canal de communication de crise alternatif en cas de compromission du canal officiel

#### Phase 2 — Détection et analyse

* Détecter les pics d'envoi anormaux depuis l'infrastructure d'alerte (1,4 million de messages)
* Analyser les liens et pièces jointes des messages émis par le canal officiel
* Corréler les journaux d'accès du prestataire avec les envois suspects
* Surveiller les signalements citoyens et les retours des opérateurs télécoms

#### Phase 3 — Confinement, éradication et récupération

* Suspendre immédiatement les accès du prestataire compromis et révoquer ses clés/API
* Couper ou restreindre le canal d'envoi de masse et basculer sur un canal de secours
* Bloquer les domaines et URL malveillantes diffusés dans les messages
* Publier une alerte officielle informant la population de la campagne

#### Phase 4 — Activités post-incident

* Auditer les niveaux d'accès accordés au prestataire et renégocier les clauses de sécurité et de notification
* Revoir la supervision des logs tiers et les exigences de télémétrie en temps réel
* Renforcer la résilience du système d'alerte (redondance, séparation des canaux)
* Tirer les enseignements au niveau interministériel et mettre à jour les plans de crise

#### Phase 5 — Threat Hunting (proactif)

* Rechercher d'autres accès tiers compromis sur les plateformes de notification gouvernementales
* Analyser les infrastructures utilisées pour héberger les pages de phishing
* Traquer les réutilisations d'identifiants du prestataire sur d'autres environnements
* Comparer avec les campagnes de phishing exploitant des canaux de confiance (santé, météo, alertes)

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1195** | Compromission de la chaîne d'approvisionnement via un prestataire tiers (Arcadia) |
| **T1566** | Envoi massif d'e-mails d'hameçonnage depuis une infrastructure gouvernementale de confiance |
| **T1078** | Usage d'accès légitimes du prestataire pour diffuser les messages |

---

### Sources

* [https://theperimetersite.com/report/458](https://theperimetersite.com/report/458)
