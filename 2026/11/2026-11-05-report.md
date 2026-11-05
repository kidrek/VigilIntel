# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [L'abus d'identité d'application cible les MSP et les environnements clients](#labus-didentite-dapplication-cible-les-msp-et-les-environnements-clients)
  * [SentinelOne Prompt Security : comment la console s'articule](#sentinelone-prompt-security-comment-la-console-sarticule)
  * [Après les arrestations de ShinyHunters en septembre : bataille autour du nom de la marque](#apres-les-arrestations-de-shinyhunters-en-septembre-bataille-autour-du-nom-de-la-marque)
  * [Fusionner la PR #6549 de @Shaivarth - Correction des barres obliques inverses de début dans OriginalFileName](#fusionner-la-pr-6549-de-shaivarth-correction-des-barres-obliques-inverses-de-debut-dans-originalfilename)
  * [Comment exporter les journaux Exabeam, Securonix et ArcSight pour une enquête](#comment-exporter-les-journaux-exabeam-securonix-et-arcsight-pour-une-enquete)
  * [Ce qu'une organisation a révélé sur le risque lié aux agents IA](#ce-quune-organisation-a-revele-sur-le-risque-lie-aux-agents-ia)
  * [La Queens Public Library de New York a été victime d'un rançongiciel la nuit dernière. Un e-mail envoyé aux usagers confirme l'incident de rançongiciel.#nyc #queens #ransomware #infosec](#la-queens-public-library-de-new-york-a-ete-victime-dun-rancongiciel-la-nuit-derniere-un-e-mail-envoye-aux-usagers-confirme-lincident-de-rancongicielnyc-queens-ransomware-infosec)
  * [Possible Phishing 🎣  on: ⚠️hxxps[:]//lkgrazsl[.]login[.]5b55bakaizeipheexooz[.]bckwsbem[.]santander[.]bimp-bot[.]duckdns[.]org  🧬 Analysis at: https://urldna.io/scan/6aeb64b03b7750000318248d #cybersecurity #phishing #infosec #urldna #scam #infosec](#possible-phishing-on-hxxpslkgrazsllogin5b55bakaizeipheexoozbckwsbemsantanderbimp-botduckdnsorg-analysis-at-httpsurldnaioscan6aeb64b03b7750000318248d-cybersecurity-phishing-infosec-urldna-scam-infosec)
  * [Comment les exercices Capture-the-Flag OT développent les compétences cyber](#comment-les-exercices-capture-the-flag-ot-developpent-les-competences-cyber)
  * [Publications sur les sites de fuite de rançongiciels : Ransomhouse revendique TFG London, Bavacai liste plusieurs victimes](#publications-sur-les-sites-de-fuite-de-rancongiciels-ransomhouse-revendique-tfg-london-bavacai-liste-plusieurs-victimes)
  * [StrucSure Home Warranty par play](#strucsure-home-warranty-par-play)
  * [Des pirates volent 320 000 fichiers d'écoles britanniques et les publient sur le dark web](#des-pirates-volent-320-000-fichiers-decoles-britanniques-et-les-publient-sur-le-dark-web)
  * [Une cyberattaque efface des données cloud chez le principal hébergeur russe Beget](#une-cyberattaque-efface-des-donnees-cloud-chez-le-principal-hebergeur-russe-beget)
  * [Cyberattaques coordonnées contre des systèmes de réfrigération européens : chaînes du froid de supermarchés et Établissement français du sang (EFS) via Coolworld](#cyberattaques-coordonnees-contre-des-systemes-de-refrigeration-europeens-chaines-du-froid-de-supermarches-et-etablissement-francais-du-sang-efs-via-coolworld)
  * [Des chercheurs découvrent un adware de prompt caché dans un kit de jailbreak OpenAI Codex](#des-chercheurs-decouvrent-un-adware-de-prompt-cache-dans-un-kit-de-jailbreak-openai-codex)
  * [Un attaquant abuse d'identifiants valides Microsoft Entra ID pour cibler les clients en aval des MSP](#un-attaquant-abuse-didentifiants-valides-microsoft-entra-id-pour-cibler-les-clients-en-aval-des-msp)
  * [Le lanceur de jeu PC NIKKE piraté pour diffuser un malware d'accès à distance et de vol de données](#le-lanceur-de-jeu-pc-nikke-pirate-pour-diffuser-un-malware-dacces-a-distance-et-de-vol-de-donnees)
  * [Une fausse arnaque à une récompense Apple Cash de 750 $ dirige les utilisateurs vers des promotions d'applications](#une-fausse-arnaque-a-une-recompense-apple-cash-de-750-dirige-les-utilisateurs-vers-des-promotions-dapplications)
  * [Le média ukrainien Kyiv Independent victime d'une cyberattaque russe présumée](#le-media-ukrainien-kyiv-independent-victime-dune-cyberattaque-russe-presumee)
  * [Une campagne d'hameçonnage via Google Calendar détourne des sessions et contourne le MFA](#une-campagne-dhameconnage-via-google-calendar-detourne-des-sessions-et-contourne-le-mfa)
  * [Un employé informatique du gouvernement américain plaide coupable d'avoir envoyé des fichiers top secret à l'Éthiopie](#un-employe-informatique-du-gouvernement-americain-plaide-coupable-davoir-envoye-des-fichiers-top-secret-a-lethiopie)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

L’activité CTI du jour est dominée par les vulnérabilités (110 publications), signal d’une pression soutenue sur le patch management. Les fuites de données restent élevées (32 cas), avec un risque accru d’exposition d’identifiants et de données clients. Aucun article threat_actors n’est remonté, ce qui ne signifie pas absence d’acteurs mais visibilité réduite sur les campagnes nommées. Géopolitique (4) et réglementaire (5) restent secondaires en volume mais doivent être surveillés pour anticiper les risques de conformité et de ciblage. La priorité opérationnelle est de corréler les vulnérabilités critiques avec les actifs exposés et les fuites récentes. Il convient de renforcer la détection sur les credentials compromis et d’accélérer les remédiations à fort impact. La veille réglementaire doit rester active malgré un volume faible.

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
| **Mondial, États-Unis** | Infrastructures critiques (eau, énergie, industrie, nucléaire) | Usage offensif de l'IA générative contre les systèmes industriels (OT/ICS) | Deux équipes de recherche, Booz Allen Hamilton (BAH) et Frenos, ont publié des travaux convergents montrant que des agents bâtis sur des LLM de frontière (Anthropic, OpenAI) et sur des modèles à poids ouverts peuvent exécuter de manière quasi autonome, mais avec guidage humain, chaque étape d'une chaîne d'attaque dans un réseau OT inconnu. Les attaques restent inefficaces et bruyantes, et l'expertise de l'opérateur qui rédige les prompts demeure déterminante : les modèles ouverts exigent un attaquant déjà compétent, tandis que les modèles de frontière réussissent avec moins d'expertise. La conclusion centrale est que la connaissance OT spécialisée, l'équipement exotique et la complexité des environnements de contrôle ne constituent plus des barrières significatives : la barrière à l'entrée du hacking ICS s'effondre. Anthropic (Rob Bair) et Dragos (Rob Lee) soulignent que cela accroît le risque sur les infrastructures critiques, notamment l'eau et l'électricité, en accélérant la reconnaissance et le lancement d'opérations. Les acteurs étatiques n'ont jamais été bloqués par ces barrières ; le changement concerne surtout les attaquants peu sophistiqués et les acteurs criminels. Les installations très instrumentées (nucléaire, systèmes redondants de sûreté) restent plus difficiles, chaque site présentant des spécificités de conception et de programmation. L'autonomie complète reste pour l'instant un fantasme, mais la trajectoire d'amélioration des modèles est rapide. | [https://www.healthcareinfosecurity.com/bots-getting-better-at-hacking-operational-technology-a-33299](https://www.healthcareinfosecurity.com/bots-getting-better-at-hacking-operational-technology-a-33299) |
| **Europe, Russie, Ukraine, Moyen-Orient (Abu Dhabi), États-Unis** | Défense / énergie / industrie / transports | Guerre d'attrition Russie-Ukraine et nouvelle séquence diplomatique | Alors que la guerre dure depuis près de quatre ans, une nouvelle séquence diplomatique s'ouvre avec des délégations russe, ukrainienne et américaine attendues les 10 et 11 novembre à Abu Dhabi. Ce format tripartite évince de fait les Européens, qui peinent à s'affirmer dans les discussions sur la fin du conflit, alors même que l'UE assume déjà un soutien budgétaire massif à Kiev et risque d'être contrainte de porter seule le fardeau logistique et financier de la reconstruction. Le front n'est plus la seule zone de guerre : la multiplication des frappes longue portée contre les infrastructures stratégiques (énergie, industrie, transports) étend le conflit en profondeur et transforme l'affrontement en guerre d'attrition testant la résilience des deux belligérants. Aucune issue claire ne se dégage : les objectifs de Vladimir Poutine, la stratégie de Volodymyr Zelensky, l'effet réel des sanctions sur l'économie russe et l'état de l'opinion russe restent des variables ouvertes. La question posée est celle de l'impasse européenne : absence de siège à la table, dépendance à la posture américaine et exposition directe aux conséquences économiques et sécuritaires d'un règlement négocié sans elle. | [https://www.iris-france.org/russie-ukraine-une-guerre-sans-fin-avec-arnaud-dubien/](https://www.iris-france.org/russie-ukraine-une-guerre-sans-fin-avec-arnaud-dubien/) |
| **Europe, États-Unis, Chine, Afrique du Sud** | Quantique / semi-conducteurs / matériaux critiques / financement de l'innovation | Risque industriel et de dépendance des chaînes d'approvisionnement quantiques | Le calcul quantique est devenu un enjeu de souveraineté : les États-Unis, la Chine et l'Europe investissent pour passer du laboratoire à l'industrie, la stratégie Quantum Europe adoptée en juillet 2025 visant une position de premier plan d'ici 2030. Mais la promesse scientifique masque un risque industriel peu présent dans les analyses d'investissement : chaque architecture de qubits (supraconducteurs, spin, photonique) repose sur des matériaux très purs, produits par peu d'acteurs, parfois un seul. Le cas du silicium 28 est emblématique : l'usine d'enrichissement d'ASP Isotopes à Koedoespoort (Pretoria, Afrique du Sud), annoncée en mars 2025 avec des livraisons au trimestre suivant, a accumulé les reports (août 2025, T2 2026, T3 2026, puis second semestre) et, fin octobre 2026, aucune livraison commerciale n'était annoncée ; le premier lot ne serait enrichi qu'à 99 % alors que le quantique exige généralement 99,995 %. L'écart entre capacité annoncée et production qualifiée se propage à toute la chaîne : approvisionnement, plaquette, gravure, validation du dispositif, puis premières ventes. Le même schéma vaut pour la photonique : l'Europe dépendait d'un unique fournisseur extra-UE de niobate de lithium en couche mince, le projet ELENA financé par l'UE ayant depuis produit les premières plaquettes européennes. La nationalité du concepteur ne dit rien de la souveraineté industrielle : celle-ci se joue sur l'accès aux matériaux, équipements et procédés, y compris en contexte dégradé. L'intelligence économique (veille sur les documents publics, les jalons industriels et les dépendances amont) est l'outil permettant de repérer ces risques avant qu'ils ne pèsent sur la valorisation. | [https://www.portail-ie.fr/univers/business-development-innovation-et-start-up/2026/quantique-le-risque-industriel-que-les-investisseurs-ne-peuvent-plus-ignorer-partie-1-2/](https://www.portail-ie.fr/univers/business-development-innovation-et-start-up/2026/quantique-le-risque-industriel-que-les-investisseurs-ne-peuvent-plus-ignorer-partie-1-2/)<br>[https://www.portail-ie.fr/univers/business-development-innovation-et-start-up/2026/quantique-le-risque-industriel-que-les-investisseurs-ne-peuvent-plus-ignorer-partie-2-2/](https://www.portail-ie.fr/univers/business-development-innovation-et-start-up/2026/quantique-le-risque-industriel-que-les-investisseurs-ne-peuvent-plus-ignorer-partie-2-2/) |
| **États-Unis, Moyen-Orient (Iran), Israël** | Politique intérieure et étrangère / institutions | Midterms américaines et limites du pouvoir exécutif | Le Parti démocrate a remporté une victoire écrasante aux élections de mi-mandat du mardi 3 novembre, qui renouvelaient simultanément la Chambre des représentants (435 sièges), un tiers du Sénat (100 sièges) et 50 postes de gouverneurs. La « vague bleue » traduit le mécontentement d'une partie de la population envers l'administration Trump, en particulier les conséquences économiques de la guerre en Iran. La course du Michigan, remportée par Abdul El-Sayed, premier sénateur musulman élu, illustre la fin du tabou sur la critique de la politique israélienne ; des États historiquement républicains comme le Texas ou le Kansas ont élu des sénateurs démocrates pour la première fois depuis des décennies. Au-delà du signal politique, l'enjeu est institutionnel : le Congrès reste un contre-pouvoir fondamental à l'exécutif américain. La question centrale est de savoir si cette vague bleue modifiera réellement la politique extérieure des États-Unis, notamment sur l'Iran, le soutien à Israël et les engagements internationaux, ou si elle se limitera à un blocage législatif intérieur. | [https://www.iris-france.org/midterms-trump-empetre/](https://www.iris-france.org/midterms-trump-empetre/) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| EDRi — « EU governments call it ‘simplification,’ but their Data Omnibus deal considerably weakens our rights » (position du Conseil de l'UE sur le Digital Omnibus, 21 octobre 2026) | Conseil de l'Union européenne (accord politique du 21 octobre 2026) sur proposition de la Commission européenne (Digital Omnibus, novembre 2025) — analyse critique par l'ONG EDRi | 2026-11-04 | Union européenne (États membres, EEE) | EDRi — « EU governments call it ‘simplification,’ but their Data Omnibus deal considerably weakens our rights » (position du Conseil de l'UE sur le Digital Omnibus, 21 octobre 2026) | Le 21 octobre 2026, les États membres ont arrêté leur position de négociation sur le Digital Omnibus. Officiellement présenté comme une « simplification », l'accord du Conseil entérine l'essentiel de l'agenda dérégulateur de la Commission et n'apporte que des corrections timides aux propositions les plus contestées. Deux dispositions concentrent le risque. D'abord l'article 88bis (ex-article 88c de la proposition), qui reconnaît explicitement la possibilité de fonder sur l'« intérêt légitime » du RGPD le traitement de données personnelles pour le développement et l'exploitation de systèmes d'IA. Le Conseil précise que le développement d'IA ne constitue pas automatiquement un intérêt légitime et que les conditions existantes demeurent, mais l'introduction d'une disposition dédiée crée un signal législatif susceptible de déséquilibrer le test de mise en balance au profit des fournisseurs d'IA — un ensemble technologique mal défini, largement dominé par de grandes plateformes. Le risque concret est la réutilisation massive de données pour l'entraînement de modèles alors que les personnes concernées ne pouvaient raisonnablement pas anticiper cet usage. Ensuite, l'exception proposée aux articles 9(2)(k) et 9(2) permet de conserver des données sensibles (santé, opinions politiques, convictions religieuses) apparues incidemment dans des jeux de données d'IA lorsque leur suppression est techniquement impossible ou exigerait un effort manifestement disproportionné : une difficulté d'ingénierie devient ainsi un motif de rétention de données hautement sensibles, dans des systèmes opaques où la vérification est en pratique impossible. Plus largement, l'accord affaiblit les garanties et complexifie l'exercice des voies de recours, sans démonstration crédible d'un gain de compétitivité ; certains changements renforcent au contraire l'avantage des grandes plateformes déjà détentrices de volumes massifs de données. Le texte n'est pas définitif : la position du Conseil ouvre la phase de trilogue avec le Parlement européen, où les marges de correction existent. | [https://edri.org/our-work/eu-governments-call-it-simplification-but-their-data-omnibus-deal-considerably-weakens-our-rights/](https://edri.org/our-work/eu-governments-call-it-simplification-but-their-data-omnibus-deal-considerably-weakens-our-rights/) |
| Commission européenne — étude indépendante sur l'impact de la vérification de l'âge sur les droits fondamentaux et les coûts pour les entreprises (préparation de l'EU KIDS Act) | Commission européenne (DG Connect) — étude réalisée par un contractant externe, publiée le 4 novembre 2026 | 2026-11-04 | Union européenne | Commission européenne — étude indépendante sur l'impact de la vérification de l'âge sur les droits fondamentaux et les coûts pour les entreprises (préparation de l'EU KIDS Act) | La Commission publie une étude externe destinée à préparer la proposition d'EU KIDS Act et son document de travail accompagnant. Constat de départ : environ un enfant sur trois âgé de 9 à 11 ans dans six pays européens déclare disposer d'un profil sur les réseaux sociaux, alors que très peu de services mettent en œuvre une vérification de l'âge de manière systématique. L'étude conclut qu'un cadre d'age assurance peut être à la fois proportionné et respectueux des droits fondamentaux, à condition d'être encadré : cohérence législative avec le RGPD, standards élevés de protection des données et de sécurité, développement de normes techniques, minimisation des frictions pour les utilisateurs, transparence, choix et accessibilité. Sur le plan économique, les coûts seraient inévitables mais modestes pour la plupart des services et décroissants, sous l'effet de la concurrence entre fournisseurs, de l'émergence de standards, de l'interopérabilité et de la mise à disposition du « blueprint » européen de vérification de l'âge — solution préservant la vie privée, ouverte par conception et dont le développement a été subventionné publiquement. L'étude recommande d'accélérer le déploiement de ce blueprint dans tous les États membres et de garantir des voies d'enrôlement de secours efficaces et dotées de ressources, y compris des options manuelles au niveau national et local. Les PME ne devraient pas subir de coûts excessifs et bénéficieraient d'un jeu de règles unique au lieu de exigences nationales disparates. L'étude ne porte pas sur l'évaluation de la proposition d'EU KIDS Act elle-même ni sur la conformité d'un fournisseur particulier. | [https://digital-strategy.ec.europa.eu/en/library/independent-study-impact-age-assurance-fundamental-rights-and-costs-businesses](https://digital-strategy.ec.europa.eu/en/library/independent-study-impact-age-assurance-fundamental-rights-and-costs-businesses) |
| Commission européenne — appel à contributions (call for evidence) sur les référentiels publicitaires, article 39 du DSA (ouverture 04/11/2026, clôture 02/12/2026) | Commission européenne (DG Connect) — appel à contributions dans le cadre de l'article 39 du Digital Services Act | 2026-11-04 | Union européenne | Commission européenne — appel à contributions (call for evidence) sur les référentiels publicitaires, article 39 du DSA (ouverture 04/11/2026, clôture 02/12/2026) | La Commission ouvre du 4 novembre au 2 décembre 2026 un appel à contributions destiné à préparer des lignes directrices techniques sur les référentiels publicitaires (« ad libraries ») que les très grandes plateformes en ligne (VLOP) et très grands moteurs de recherche en ligne (VLOSE) doivent maintenir en accès public au titre de l'article 39 du DSA. Les lignes directrices porteront sur la recherche facilitée dans les référentiels, la fourniture d'indications sur le ciblage et la portée des annonces, et l'accessibilité du contenu publicitaire. L'objectif affiché est de rendre ces outils réellement exploitables pour la recherche, la société civile et les autorités, la transparence publicitaire étant présentée comme un levier de protection de la santé publique, de protection des consommateurs et d'intégrité électorale, ainsi qu'un support à la supervision et à l'exécution du DSA. Le calendrier est long : une consultation publique ciblée est prévue en 2027 sur un projet de lignes directrices, pour une publication au deuxième trimestre 2028. Pour les équipes CTI, ces référentiels constituent une source structurée sur les campagnes d'influence et les réseaux publicitaires malveillants, mais leur qualité et leur exploitabilité restent très hétérogènes selon les plateformes. | [https://digital-strategy.ec.europa.eu/en/consultations/call-evidence-advertising-repositories](https://digital-strategy.ec.europa.eu/en/consultations/call-evidence-advertising-repositories) |
| RUSI — « Who Polices the Blockchain? The Binance Heist and the New Gatekeepers » (vol de 6,3 Md USD chez Binance, 29 octobre 2026) | RUSI — commentaire d'analyse (think tank de défense et sécurité, Royaume-Uni) | 2026-11-04 | International (FATF, juridictions nationales, secteur privé crypto) | RUSI — « Who Polices the Blockchain? The Binance Heist and the New Gatekeepers » (vol de 6,3 Md USD chez Binance, 29 octobre 2026) | Le 29 octobre 2026, Binance — première plateforme d'échange crypto mondiale — a perdu 6,3 milliards de dollars en moins d'une demi-heure, le plus grand vol de l'histoire financière moderne. Au-delà du spectacle médiatique, RUSI en tire trois enseignements durables. Premièrement, l'échelle : la digitalisation de la finance démultiplie la vitesse, la portée et le montant potentiel de la criminalité financière — il faudrait piller un nombre considérable d'établissements bancaires pour approcher un tel butin. Deuxièmement, les frontières : les criminels exploitent depuis longtemps les écarts entre juridictions, mais dans un monde de services financiers numériques, ces frontières neutralisent de fait la capacité de réponse des États. Troisièmement, et de façon la plus marquante, le contrôle : les gouvernements conservent l'autorité légale sur l'activité financière, mais la capacité opérationnelle d'identifier, tracer et interrompre les flux financiers illicites repose de plus en plus sur des entreprises technologiques et financières privées dont la portée internationale et les compétences techniques dépassent celles des États. La question posée est donc celle du policing effectif de la blockchain, et de la capacité du FATF et des institutions internationales à s'adapter à cette redistribution de la capacité opérationnelle. Le texte rappelle que la Corée du Nord mène depuis près d'une décennie des attaques contre les infrastructures crypto pour financer son programme d'armes de destruction massive malgré les sanctions, et que ce mode opératoire reste pleinement mobilisable. La thèse centrale : nous ne sommes pas « post-gouvernementaux », mais nous entrons dans une phase où les gouvernements ne peuvent plus exercer de contrôle financier significatif sans la coopération d'acteurs privés. | [https://www.rusi.org/explore-our-research/publications/commentary/who-polices-blockchain-binance-heist-and-new-gatekeepers](https://www.rusi.org/explore-our-research/publications/commentary/who-polices-blockchain-binance-heist-and-new-gatekeepers) |
| DOJ / grand jury fédéral de New York — inculpation de Ryan James Roach et Mathiew James Stubbings pour cryptojacking d'infrastructures universitaires (extradition de Roach le 28 octobre 2026) | Département de la Justice des États-Unis (parquet fédéral de New York) ; procédures d'extradition au Canada | 2026-11-04 | États-Unis (New York, Massachusetts, Caroline du Nord, Tennessee) et Canada (Saskatchewan, Ontario) | DOJ / grand jury fédéral de New York — inculpation de Ryan James Roach et Mathiew James Stubbings pour cryptojacking d'infrastructures universitaires (extradition de Roach le 28 octobre 2026) | Un grand jury fédéral de New York a inculpé deux ressortissants canadiens, Ryan James Roach (35 ans, Saskatchewan) et Mathiew James Stubbings (41 ans, Ontario), pour association de malfaiteurs en vue d'obtenir des informations et de causer des dommages à des ordinateurs protégés, obtention d'informations à partir d'un ordinateur protégé et dommages informatiques intentionnels. Roach a été extradé du Canada le 28 octobre 2026 ; la procédure d'extradition de Stubbings se poursuit devant les tribunaux canadiens. Les intrusions se seraient étendues de juin 2016 à décembre 2019, visant des établissements universitaires de New York, du Massachusetts, de la Caroline du Nord et du Tennessee. Les deux hommes auraient mis en place une infrastructure de serveurs privés virtuels répartis dans plusieurs pays, obtenue sous de fausses identités, pour diffuser des logiciels malveillants et des mineurs, stocker les identifiants dérobés et pivoter depuis des machines déjà compromises afin de masquer leur origine. Les cibles privilégiées étaient les campus exploitant des supercalculateurs, dont la puissance a été détournée pour miner la cryptomonnaie Electroneum. Chaque chef d'accusation expose à une peine maximale de 10 ans d'emprisonnement et 250 000 dollars d'amende. Le dossier illustre la judiciarisation croissante du cryptojacking et la coopération transfrontalière, mais aussi la latence entre les faits (2016-2019) et l'extradition (2026). | [https://www.securityweek.com/canadian-extradited-to-us-over-cryptomining-hacks-on-university-supercomputers/](https://www.securityweek.com/canadian-extradited-to-us-over-cryptomining-hacks-on-university-supercomputers/) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Transverse - securite offensive/defensive, EASM et OSINT** | Non applicable - publication d'un outil open source (SniperScope) | Aucune donnee compromise - publication d'un outil open source. A noter toutefois que l'outil agrege des sources publiques (CT logs, RDAP, Shodan, registres) et peut exposer des metadonnees d'organisation si son usage n'est pas cloisonne. | Inconnu | [https://github.com/kamehameha-ctrl/sniperscope](https://github.com/kamehameha-ctrl/sniperscope)<br>[https://www.reddit.com/r/redteamsec/comments/1xnliob/github_kamehamehactrlsniperscope_sniperscope_is_a/](https://www.reddit.com/r/redteamsec/comments/1xnliob/github_kamehamehactrlsniperscope_sniperscope_is_a/) |
| **Enseignement superieur et recherche - calcul haute performance (HPC)** | Universites et centres de recherche aux Etats-Unis (New York, Tennessee, Caroline du Nord, Massachusetts) - supercalculateurs HPC | Identifiants de connexion des utilisateurs et administrateurs des clusters, donnees presentes sur les systemes compromis et exfiltrees via les canaux de C2, ressources de calcul (puissance CPU/GPU) detournees au profit des accusés. | Au moins 10 ordinateurs proteges endommages sur une periode d'un an; perte agregee d'au moins 5 000 USD; volume exact de donnees exfiltrees non communique | [https://www.healthcareinfosecurity.com/canada-extradites-2-for-supercomputer-cryptojacking-hacks-a-33298](https://www.healthcareinfosecurity.com/canada-extradites-2-for-supercomputer-cryptojacking-hacks-a-33298) |
| **Sante - sites, portails patients et applications medicales; technologie/publicite en ligne** | Patients utilisateurs de Facebook ayant interagi avec des sites, portails et applications de sante (Etats-Unis) - defendeur : Meta Platforms | Donnees de sante et donnees associees : clics sur portails patients, rendez-vous medicaux, paiements de factures, evaluations diagnostiques, identite du medecin, pathologie, traitement, communications avec des sites de medicaments sur ordonnance, identifiants publicitaires et cookies de suivi (_fbp). | Potentiellement plusieurs millions d'utilisateurs Facebook, repartis en quatre classes certifiees, pour des faits a compter du 17 juin 2018 | [https://www.healthcareinfosecurity.com/judge-certifies-classes-in-meta-health-data-privacy-suit-a-33295](https://www.healthcareinfosecurity.com/judge-certifies-classes-in-meta-health-data-privacy-suit-a-33295) |
| **Transverse - developpement logiciel, AppSec, DevSecOps** | Non applicable - contenu de sensibilisation generique sur la gestion des secrets | Aucune donnee compromise - contenu de sensibilisation. Le risque decrit concerne les cles API, jetons d'acces, identifiants de bases de donnees et secrets d'infrastructure qui pourraient etre exposes dans un depot de code. | Inconnu | [https://cvedatabase.com](https://cvedatabase.com)<br>[https://techhub.social/@cvedatabase/117560534883170637](https://techhub.social/@cvedatabase/117560534883170637) |
| **Telecommunications, assurance, gouvernement et enseignement superieur (Mexique)** | Cinq organisations au Mexique : deux operateurs telecom, une plateforme d'assurance, une entite gouvernementale et une universite publique (noms anonymises dans le rapport) | Donnees clients telecom (82 478 lignes liees aux cartes SIM), enregistrements de facturation (306), donnees d'assurance (554), configuration WebLogic, identifiants de base de donnees chiffres, fichier SerializedSystemIni.dat, cle privee SSH ED25519, sorties de reconnaissance systeme. | 82 478 lignes liees aux cartes SIM (operateur A), 306 enregistrements de factures (operateur B) et 554 enregistrements (plateforme d'assurance); volume total non etabli pour les deux autres victimes | [https://threatmon.io/82478-rows-and-a-google-drive-folder-how-one-c2-server-pulled-data-from-mexican-organizations/](https://threatmon.io/82478-rows-and-a-google-drive-folder-how-one-c2-server-pulled-data-from-mexican-organizations/) |
| **Transverse - infrastructure d'attaque, developpement logiciel, chaine d'approvisionnement** | Aucune victime identifiee - analyse d'une infrastructure d'attaquant (VPS Debian 161[.]97[.]113[.]228) | Aucune victime ni donnee volee identifiee. Les artefacts sensibles exposes sont le jeton partage REVSHELL_TOKEN, des donnees de session archivees, des cles et identifiants presents sur le VPS, ainsi que les paquets Go pieges susceptibles de compromettre tout projet les important. | Inconnu | [https://threatmon.io/a-typo-a-leaked-token-and-booby-trapped-go-packages-inside-the-ccds-c2-server/](https://threatmon.io/a-typo-a-leaked-token-and-booby-trapped-go-packages-inside-the-ccds-c2-server/) |
| **Transverse - analyse de fuites de donnees et risque tiers** | 13 436 organisations uniques exposees via des jeux de donnees volees; mediane de 542 organisations tierces exposees par incident en plus de la victime nommee | Emails, PDF, documents bureautiques et fichiers non structures contenant des informations sur les organisations tierces : identites de contacts, relations commerciales, donnees contractuelles et financieres, eventuellement identifiants et informations techniques. | 328 millions de fichiers issus de 2 089 jeux de donnees; 13 436 organisations uniques exposees entre 2025 et 2026; mediane de 542 organisations tierces exposees par incident | [https://databreaches.net/2026/11/04/lab-1-warns-breach-data-now-exposes-thousands-more-firms/](https://databreaches.net/2026/11/04/lab-1-warns-breach-data-now-exposes-thousands-more-firms/) |
| **Education - etablissements scolaires (Islande)** | Jusqu'a 16 etablissements scolaires islandais | Donnees d'eleves presumees (identite, coordonnees, donnees de scolarite) et eventuellement donnees de personnels - nature exacte non confirmee par la source disponible. | Jusqu'a 16 etablissements concernes; volume d'enregistrements et nombre d'eleves affectes non communiques | [https://databreaches.net/2026/11/04/student-data-breach-affects-up-to-16-icelandic-schools/](https://databreaches.net/2026/11/04/student-data-breach-affects-up-to-16-icelandic-schools/) |
| **Commerce de détail et e-commerce (Japon)** | Ryohin Keikaku (MUJI) — données MUJI Card issues par Credit Saison | Adresses e-mail, dates de naissance, genre, identifiants membres (application et boutique en ligne, y compris anciens membres) ; noms, adresses postales et numéros de téléphone pour environ 520 000 clients ; numéros complets de MUJI Card et identifiants MUJI Card pour environ 1,09 million de porteurs (sans nom de titulaire, date d'expiration ni code de sécurité) ; six premiers et deux derniers chiffres de carte plus nom du titulaire pour environ 120 clients ayant enregistré une carte | Jusqu'à 27,26 millions de comptes application/boutique en ligne ; environ 520 000 enregistrements avec nom, adresse et téléphone ; environ 1,09 million de numéros complets de MUJI Card (dont environ 345 000 cartes encore valides) | [https://japancyberwatch.com/articles/muji-app-breach-card-numbers-old-perk-scheme-2026](https://japancyberwatch.com/articles/muji-app-breach-card-numbers-old-perk-scheme-2026)<br>[https://infosec.exchange/@japancyberwatch/117560489670569173](https://infosec.exchange/@japancyberwatch/117560489670569173) |
| **Éditeur de logiciel / SaaS (infrastructure d'authentification et d'identité pour développeurs)** | WorkOS | Données de l'application commerciale interne (périmètre non communiqué publiquement) ; aucune confirmation publique d'exposition de données clients ou d'identifiants d'authentification | Inconnu | [https://www.bleepingcomputer.com/news/security/workos-says-attacker-used-artex-ai-to-breach-internal-sales-app/](https://www.bleepingcomputer.com/news/security/workos-says-attacker-used-artex-ai-to-breach-internal-sales-app/)<br>[https://mastodon.thenewoil.org/@thenewoil/117560180893734944](https://mastodon.thenewoil.org/@thenewoil/117560180893734944) |
| **Transverse — analyse statistique multi-secteurs (données Surfshark Q3 2026)** | Statistiques mondiales de fuites de comptes (Q3 2026) — analyse Surfshark | Identifiants et données de comptes utilisateurs (adresses e-mail, mots de passe, données de profil selon les fuites sources) ; données de contact de personnels policiers et de l'éducation au Royaume-Uni selon les revendications d'ExfilSquad | 121,8 millions de comptes compromis dans le monde au Q3 2026 (+13,2 % sur un trimestre) ; États-Unis 38,1 M, Brésil 7 M, Royaume-Uni 5,8 M, Inde 5,5 M, Australie 3,1 M | [https://en.hacks.gr/ayxisi-13-2-stis-pagkosmies-diarroes-logariasmon-to-trito-trimino-toy-2026/](https://en.hacks.gr/ayxisi-13-2-stis-pagkosmies-diarroes-logariasmon-to-trito-trimino-toy-2026/)<br>[https://mastodon.social/@hacksgr/117560121933694996](https://mastodon.social/@hacksgr/117560121933694996) |
| **Médias indépendants et hébergement associatif (France)** | Réseau Mutu (hébergement de médias indépendants français, dont Dijoncter.info) | Données d'identité et de connexion des auteurs et lecteurs (périmètre exact non communiqué) ; journaux d'accès et métadonnées de publication susceptibles de révéler des sources ; identifiants d'administration de l'infrastructure | Inconnu | [https://infonewscyber.fr/info/reseau-mutu-pirate-une-porte-derobee-pendant-des-semaines-menace-lanon-be0a4bb91a754ea9](https://infonewscyber.fr/info/reseau-mutu-pirate-une-porte-derobee-pendant-des-semaines-menace-lanon-be0a4bb91a754ea9)<br>[https://infosec.exchange/@infonewscyber/117560096606619785](https://infosec.exchange/@infonewscyber/117560096606619785) |
| **Hébergement web et services Internet (États-Unis)** | DreamHost (New Dream Network) — plateforme File Manager files[.]dreamhost[.]com | Noms d'utilisateur et mots de passe FTP/SFTP des clients ayant utilisé files[.]dreamhost[.]com entre août 2026 et le 23 octobre 2026 ; informations de session et identifiants pour un nombre limité d'utilisateurs de webmail ; pas d'accès confirmé aux identifiants du panneau de contrôle ni aux données de facturation et de paiement | Nombre exact de comptes affectés non communiqué par DreamHost ; accès non détecté d'environ août 2026 au 23 octobre 2026 | [https://www.bleepingcomputer.com/news/security/dreamhost-confirms-data-breach-exposed-ftp-logins-and-webmail-sessions/](https://www.bleepingcomputer.com/news/security/dreamhost-confirms-data-breach-exposed-ftp-logins-and-webmail-sessions/)<br>[https://infosec.exchange/@cloud/117559969435791003](https://infosec.exchange/@cloud/117559969435791003)<br>[https://otx.alienvault.com/pulse/6aeb8db985ebe4ba85ee65ac](https://otx.alienvault.com/pulse/6aeb8db985ebe4ba85ee65ac)<br>[https://social.raytec.co/@techbot/117559952498304831](https://social.raytec.co/@techbot/117559952498304831)<br>[https://osintsights.com/dreamhost-breach-exposes-ftp-logins-webmail-sessions?utm_source=mastodon&utm_medium=social](https://osintsights.com/dreamhost-breach-exposes-ftp-logins-webmail-sessions?utm_source=mastodon&utm_medium=social)<br>[https://mastodon.social/@Analyst207/117559804324207950](https://mastodon.social/@Analyst207/117559804324207950)<br>[https://osintsights.com/dreamhost-breach-exposes-ftp-logins-webmail-sessions](https://osintsights.com/dreamhost-breach-exposes-ftp-logins-webmail-sessions) |
| **Commerce de détail électronique (Japon) — chaîne d'approvisionnement e-mailing** | Bic Camera Group (Bic Camera, Kojima, Sofmap) — via le prestataire de diffusion e-mail Arara Inc. | Adresses e-mail des clients de Bic Camera, Kojima et Sofmap ; autres informations clients du groupe Bic Camera (détail en cours d'investigation) ; pour d'autres clients d'Arara : noms, adresses, numéros de téléphone, dates de naissance et informations d'adhésion ; données de carte de crédit et identifiants de la boutique en ligne non affectés selon l'entreprise | Environ 14,9 millions d'enregistrements clients potentiellement exposés pour Bic Camera, Kojima et Sofmap ; jusqu'à 77 millions d'adresses e-mail chez jusqu'à 380 clients d'Arara ; environ 7,13 millions d'e-mails de phishing envoyés | [https://beyondmachines.net/event_details/bic-camera-discloses-third-party-data-breach-potentially-exposing-14-9-million-customer-records-0-c-o-r-b/gD2P6Ple2L](https://beyondmachines.net/event_details/bic-camera-discloses-third-party-data-breach-potentially-exposing-14-9-million-customer-records-0-c-o-r-b/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117559951800141605](https://infosec.exchange/@beyondmachines1/117559951800141605) |
| **Services financiers — relations investisseurs / gestion de briefing résultats** | Nomura Investor Relations (filiale de Nomura Holdings) — plateforme Institutional Navi | Noms, adresses e-mail et autres données personnelles des utilisateurs de la plateforme Institutional Navi ; périmètre exact et volume non communiqués ; suspicion non confirmée d'accès au service MIR@I. | Inconnu | [https://beyondmachines.net/event_details/nomura-investor-relations-confirms-data-breach-following-unauthorized-access-1-h-t-i-t/gD2P6Ple2L](https://beyondmachines.net/event_details/nomura-investor-relations-confirms-data-breach-following-unauthorized-access-1-h-t-i-t/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117559715850123803](https://infosec.exchange/@beyondmachines1/117559715850123803) |
| **Agroalimentaire / santé — installations frigorifiques et chaîne du froid (OT/ICS)** | Installations frigorifiques européennes (secteur chaîne du froid / agroalimentaire, France et Europe) | Aucune donnée personnelle explicitement confirmée à ce stade ; l'impact porte principalement sur l'intégrité et la disponibilité des systèmes de réfrigération et de supervision. Risque de fuite de données opérationnelles (schémas industriels, identifiants d'accès) non écarté. | Inconnu | [https://infonewscyber.fr/info/noname057-16-et-z-pentest-deux-groupes-de-hackers-prorusses-revendique-e2390d3ca20b9ad6](https://infonewscyber.fr/info/noname057-16-et-z-pentest-deux-groupes-de-hackers-prorusses-revendique-e2390d3ca20b9ad6)<br>[https://infosec.exchange/@infonewscyber/117559683480505353](https://infosec.exchange/@infonewscyber/117559683480505353) |
| **Secteur public — sécurité intérieure / administration fédérale** | Department of Homeland Security (DHS) — États-Unis | Données personnelles de personnels du DHS et, selon la source, de leurs familles ; nature exacte, volume et période de compromission non communiqués. | Inconnu | [https://www.youtube.com/watch?v=C6tgpAypNDk](https://www.youtube.com/watch?v=C6tgpAypNDk)<br>[https://infosec.exchange/@security_crawler_carl/117559656680485678](https://infosec.exchange/@security_crawler_carl/117559656680485678) |
| **Transport aérien — distribution et réservation (prestataire technologique tiers)** | Amadeus (prestataire technologique du voyage) et compagnies aériennes clientes : Japan Airlines, Cathay Pacific, Singapore Airlines, All Nippon Airways, Korean Air, Asiana Airlines, Malaysia Airlines, Qantas | Noms des clients, références de réservation (PNR), itinéraires de voyage, classes de réservation ; pour environ 620 réservations Singapore Airlines : adresses e-mail, numéros de téléphone, détails des documents de voyage et numéros de membre KrisFlyer ; pour environ 2 000 clients Japan Airlines : numéros de passeport. Données bancaires et cartes de paiement non compromises selon Amadeus. | Environ 228 800 enregistrements confirmés : 92 000 Japan Airlines, 53 000 Cathay Pacific, 46 000 Singapore Airlines, 37 800 All Nippon Airways ; volumes non communiqués pour Korean Air, Asiana Airlines, Malaysia Airlines et Qantas. | [https://en.hacks.gr/i-singapore-airlines-epivevaiose-oti-ektethikan-stoicheia-apo-46-000-kratiseis/](https://en.hacks.gr/i-singapore-airlines-epivevaiose-oti-ektethikan-stoicheia-apo-46-000-kratiseis/)<br>[https://mastodon.social/@hacksgr/117559579488409084](https://mastodon.social/@hacksgr/117559579488409084)<br>[https://beyondmachines.net/event_details/singapore-airlines-discloses-third-party-data-breach-affecting-customer-bookings-4-5-7-q-j/gD2P6Ple2L](https://beyondmachines.net/event_details/singapore-airlines-discloses-third-party-data-breach-affecting-customer-bookings-4-5-7-q-j/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117559479936433045](https://infosec.exchange/@beyondmachines1/117559479936433045) |
| **Multi-secteurs — retail, aviation, services financiers, technologie, gouvernement, éducation, santé, divertissement** | Multiples victimes — bilan des cyberattaques et fuites de données d'octobre 2026 (supermarché français, UK Legal Aid Agency, BAE Systems Inc., Capcom, Zeabur, Burger King Japan, Osaka Metropolitan University, Advantest, Sony Network Communications, Japan Airlines, SBI, Daiichi Kosho) | Données personnelles variées : noms, dates de naissance, coordonnées, numéros de sécurité sociale, numéros de passeport et de permis de conduire, données médicales et financières, identifiants de comptes clients et mots de passe (Capcom), données académiques et administratives (Osaka Metropolitan University). | Plusieurs millions de personnes potentiellement affectées sur le mois ; Capcom seul revendique plus de 11 millions de comptes clients exposés ; Osaka Metropolitan University évoque au moins 130 000 personnes ; volumes non divulgués pour Advantest et plusieurs autres victimes. | [https://www.cm-alliance.com/cybersecurity-blog/biggest-cyber-attacks-data-breaches-ransomware-attacks-october-2026](https://www.cm-alliance.com/cybersecurity-blog/biggest-cyber-attacks-data-breaches-ransomware-attacks-october-2026)<br>[https://infosec.exchange/@security_crawler_carl/117559235163570587](https://infosec.exchange/@security_crawler_carl/117559235163570587)<br>[https://osintsights.com/data-breaches-expose-vulnerable-security-gaps?utm_source=mastodon&utm_medium=social](https://osintsights.com/data-breaches-expose-vulnerable-security-gaps?utm_source=mastodon&utm_medium=social)<br>[https://mastodon.social/@Analyst207/117559216519917427](https://mastodon.social/@Analyst207/117559216519917427) |
| **Logiciel — gestionnaire de mots de passe (services aux particuliers et entreprises)** | mSecure (gestionnaire de mots de passe) | Nature exacte non communiquée ; potentiellement des identifiants de comptes, des secrets stockés et des données d'authentification (MFA, passkeys) des utilisateurs de mSecure. | Inconnu | [https://osintsights.com/msecure-breach-prompts-widespread-password-reset-warnings?utm_source=mastodon&utm_medium=social](https://osintsights.com/msecure-breach-prompts-widespread-password-reset-warnings?utm_source=mastodon&utm_medium=social)<br>[https://mastodon.social/@Analyst207/117559095388163058](https://mastodon.social/@Analyst207/117559095388163058) |
| **Infrastructure blockchain / services cloud Web3** | Chainstack | Noms d'organisations clientes, noms complets des titulaires de compte, adresses e-mail des membres d'organisation, hashes de mots de passe, credentials de nœuds (clés API/tokens), identifiants de déploiement. | Inconnu | [https://beyondmachines.net/event_details/chainstack-discloses-production-breach-linked-to-global-ai-powered-artex-campaign-s-v-c-5-l/gD2P6Ple2L](https://beyondmachines.net/event_details/chainstack-discloses-production-breach-linked-to-global-ai-powered-artex-campaign-s-v-c-5-l/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117559008100337680](https://infosec.exchange/@beyondmachines1/117559008100337680) |
| **Services financiers / banque de détail** | Royal Bank of Canada (RBC) | Données personnelles de clients (nom, date de naissance, numéro d'assurance sociale, permis de conduire, données de passeport, informations de profil client), identifiants de banque en ligne, données de comptes et de produits de crédit ouverts frauduleusement. | 43 | [https://fed.brid.gy/r/https://globalnews.ca/news/12136313/rbc-worker-guilty-carney-data/](https://fed.brid.gy/r/https://globalnews.ca/news/12136313/rbc-worker-guilty-carney-data/) |
| **Multi-secteurs — technologie, information et internet en tête** | Multiples — 13 436 organisations exposées via 2 089 jeux de données analysés | Documents financiers (coordonnées bancaires, identifiants fiscaux, factures), données RH (PII, paie, contrats, pièces d'identité), clés cryptographiques privées, e-mails, PDF et documents non structurés, données de santé et de recherche dans certains jeux de données. | 328000000 | [https://securitybrief.co.nz/story/lab-1-warns-breach-data-now-exposes-thousands-more-firms](https://securitybrief.co.nz/story/lab-1-warns-breach-data-now-exposes-thousands-more-firms)<br>[https://infosec.exchange/@PogoWasRight/117560832591915385](https://infosec.exchange/@PogoWasRight/117560832591915385) |
| **Santé** | Roundglass (roundglass[.]com) | Non confirmé. Aucun volume, type de données ni échantillon n'a été publié. En cas de confirmation, des données de santé sensibles pourraient être concernées. | Inconnu | [https://www.yazoul.net/intel/claim/2026-11-04-roundglass-ransomware-claim-by-inc-ransom-nov-2026/?utm_source=mastodon&utm_medium=social](https://www.yazoul.net/intel/claim/2026-11-04-roundglass-ransomware-claim-by-inc-ransom-nov-2026/?utm_source=mastodon&utm_medium=social)<br>[https://infosec.exchange/@Matchbook3469/117560357523036767](https://infosec.exchange/@Matchbook3469/117560357523036767) |
| **Santé / chaîne du froid sanguin (OT-ICS)** | Agence nationale du sang (France) — via un fournisseur d'équipements de réfrigération | Aucune donnée personnelle confirmée. Atteinte à l'intégrité des paramètres de supervision des enceintes frigorifiques (température, dégivrage) sur trois sites. | Inconnu | [https://infonewscyber.fr/info/une-cyberattaque-perturbe-les-systemes-de-refrigeration-des-reserves-d-801b944f5621a71c](https://infonewscyber.fr/info/une-cyberattaque-perturbe-les-systemes-de-refrigeration-des-reserves-d-801b944f5621a71c)<br>[https://infosec.exchange/@infonewscyber/117559545646387574](https://infosec.exchange/@infonewscyber/117559545646387574) |
| **Services financiers / banque** | Crédit Mutuel Arkéa | Non confirmé à ce stade. Le préjudice identifié est financier (détournement estimé à près de 100 millions d'euros). L'exposition éventuelle de données clients ou de données bancaires n'est pas établie par la source disponible. | Inconnu | [https://therecord.media/french-bank-confirms-cyber-heist](https://therecord.media/french-bank-confirms-cyber-heist)<br>[https://infosec.exchange/@edwardk/117559974119705785](https://infosec.exchange/@edwardk/117559974119705785)<br>[https://www.lemonde.fr/pixels/article/2026/11/04/cyberattaque-au-credit-mutuel-arkea-une-enquete-ouverte-apres-un-detournement-estime-a-pres-de-100-millions-d-euros_6806141_4408997.html](https://www.lemonde.fr/pixels/article/2026/11/04/cyberattaque-au-credit-mutuel-arkea-une-enquete-ouverte-apres-un-detournement-estime-a-pres-de-100-millions-d-euros_6806141_4408997.html) |
| **Jeux vidéo / grand public** | Joueurs et communauté Grand Theft Auto VI (marque Rockstar Games exploitée) | Identifiants de comptes de jeu et de services associés, données de paiement saisies sur des sites frauduleux, données bancaires et informations personnelles fournies lors de faux parcours d'achat ou de sondages. | Inconnu | [https://hackread.com/fake-gta-vi-download-sites-malware-launch/](https://hackread.com/fake-gta-vi-download-sites-malware-launch/)<br>[https://infosec.exchange/@edwardk/117559971881022936](https://infosec.exchange/@edwardk/117559971881022936) |
| **Services financiers / valeurs mobilières numériques** | Sony Bank — via son sous-traitant Securitize Japan | Pour 4 clients : nom, adresse, date de naissance et numéro de compte. Pour 617 clients : nom uniquement. Aucune donnée de transaction ni identifiant d'authentification signalé comme exposé. | 621 | [https://www.chaincatcher.com/en/article/2301751](https://www.chaincatcher.com/en/article/2301751)<br>[https://infosec.exchange/@edwardk/117559923976635710](https://infosec.exchange/@edwardk/117559923976635710) |
| **Transport aérien / voyage** | Singapore Airlines (SIA) via la plateforme de réservation Amadeus | Noms des clients, références de réservation, itinéraires de voyage et classes de réservation ; pour environ 620 dossiers : adresses e-mail, numéros de téléphone, données de documents de voyage et numéros de membre KrisFlyer. Aucune donnée bancaire ou de carte de crédit selon Amadeus. | 46000 | [https://www.channelnewsasia.com/singapore/sia-singapore-airlines-amadeus-data-breach-booking-records-6517151](https://www.channelnewsasia.com/singapore/sia-singapore-airlines-amadeus-data-breach-booking-records-6517151) |
| **Secteur public / forces de l'ordre et justice** | Federal Bureau of Investigation (portail de recrutement) et Department of Justice (bureaux des U.S. Attorneys) | Données personnelles d'agents du FBI et d'employés du DOJ : numéros de sécurité sociale, dates de naissance, numéros de téléphone, adresses postales, contacts d'urgence et informations issues des vérifications de sécurité (background checks). | Inconnu | [https://www.politico.com/news/2026/11/03/fbi-hack-department-of-justice-letter-01146667](https://www.politico.com/news/2026/11/03/fbi-hack-department-of-justice-letter-01146667) |
| **Santé / établissement de transfusion sanguine** | Établissement français du sang (EFS) | Non confirmé à ce stade. Le risque principal identifié porte sur l'intégrité et la disponibilité des systèmes de supervision de la chaîne du froid et, potentiellement, sur des données de donneurs ou de traçabilité des produits sanguins. | Inconnu | [https://www.lemonde.fr/pixels/article/2026/11/04/des-frigos-de-l-etablissement-francais-du-sang-a-leur-tour-victimes-d-une-cyberattaque_6806228_4408996.html](https://www.lemonde.fr/pixels/article/2026/11/04/des-frigos-de-l-etablissement-francais-du-sang-a-leur-tour-victimes-d-une-cyberattaque_6806228_4408996.html) |
| **Éducation / collectivité territoriale** | Bristol City Council – service « Trading with Schools » (39 écoles affectées) | Plus de 320 000 fichiers issus du réseau scolaire du conseil, susceptibles de contenir des données d'élèves, de parents et de personnels scolaires (identités, coordonnées, informations administratives et scolaires). Le détail exact n'est pas encore établi par l'enquête. | 320000 | [https://www.tes.com/magazine/news/general/cyberattack-leads-online-leak-schools-data](https://www.tes.com/magazine/news/general/cyberattack-leads-online-leak-schools-data) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2022-36763** | N/A | N/A | FALSE | Citrix XenServer 8.4 et 9 (Workload Balancing < 2026.1.1, Conversion Manager < 2026.2.0), Scout Cloud Gateway (SCG) On-Prem sans correctif 2605.1-3, UniconOS Management (Scout) On-Prem sans 2609.1 ou 2508 CU2 LTSR | Vulnérabilité non détaillée individuellement par l'avis CERT-FR ; le bulletin éditeur associé couvre des cas d'exécution de code arbitraire à distance et d'élévation de privilèges | Selon le composant affecté, un attaquant pourrait obtenir l'exécution de code arbitraire à distance ou élever ses privilèges sur l'infrastructure de virtualisation ou de gestion, avec un risque de compromission de l'hyperviseur et des machines virtuelles hébergées. | None | Appliquer les correctifs publiés dans les bulletins Citrix CTX697256 et CTX697300 (SCG 2605.1-3, UniconOS Management 2609.1 ou 2508 CU2 LTSR, Workload Balancing 2026.1.1, Conversion Manager 2026.2.0). En attendant, restreindre l'accès aux interfaces d'administration et surveiller les journaux des composants Citrix. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/)<br>[https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697256&articleURL=XenServer_Security_Update_for_Multiple_Issues](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697256&articleURL=XenServer_Security_Update_for_Multiple_Issues)<br>[https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697300&articleURL=Citrix_Security_Advisory_for_CVE_2026_111497_Impact_on_Unicon_eLux_Scout](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697300&articleURL=Citrix_Security_Advisory_for_CVE_2026_111497_Impact_on_Unicon_eLux_Scout) |
| **CVE-2022-36764** | N/A | N/A | FALSE | Citrix XenServer 8.4 et 9 (Workload Balancing < 2026.1.1, Conversion Manager < 2026.2.0), Scout Cloud Gateway On-Prem, UniconOS Management (Scout) On-Prem | Vulnérabilité non détaillée individuellement par l'avis CERT-FR ; correctif couvert par les bulletins Citrix CTX697256 et CTX697300 | Compromission potentielle des composants Citrix de virtualisation ou de gestion, avec risque d'exécution de code arbitraire et d'élévation de privilèges sur l'infrastructure. | None | Appliquer les correctifs Citrix référencés (CTX697256, CTX697300) et restreindre l'exposition des interfaces d'administration en attendant. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/)<br>[https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697256&articleURL=XenServer_Security_Update_for_Multiple_Issues](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697256&articleURL=XenServer_Security_Update_for_Multiple_Issues) |
| **CVE-2024-38796** | N/A | N/A | FALSE | Produits Citrix visés par les bulletins CTX697256 et CTX697300 (XenServer, SCG, UniconOS Management) | Vulnérabilité non détaillée individuellement par l'avis CERT-FR | Selon le composant, exécution de code arbitraire à distance ou élévation de privilèges sur l'infrastructure Citrix. | None | Appliquer les correctifs Citrix CTX697256 / CTX697300 et limiter l'exposition des interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/)<br>[https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697256&articleURL=XenServer_Security_Update_for_Multiple_Issues](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697256&articleURL=XenServer_Security_Update_for_Multiple_Issues) |
| **CVE-2024-38797** | N/A | N/A | FALSE | Produits Citrix visés par les bulletins CTX697256 et CTX697300 (XenServer, SCG, UniconOS Management) | Vulnérabilité non détaillée individuellement par l'avis CERT-FR | Risque d'exécution de code arbitraire à distance ou d'élévation de privilèges sur les composants Citrix affectés. | None | Appliquer les correctifs Citrix CTX697256 / CTX697300 et restreindre l'exposition des interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/)<br>[https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697256&articleURL=XenServer_Security_Update_for_Multiple_Issues](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697256&articleURL=XenServer_Security_Update_for_Multiple_Issues) |
| **CVE-2026-102703** | N/A | N/A | FALSE | Xen 4.6 et versions ultérieures (XenServer 8.4/9, XCP-ng 8.3, Qubes OS 4.3, paquet xen de Debian bookworm/trixie/forky) ; Xen 4.5 et antérieurs non affectés | Défaut de vérification de permissions dans l'opération « grant copy » (XSA-523) permettant à une VM invitée malveillante de lire et écrire la mémoire d'autres VMs, y compris dom0 | Sortie d'isolation d'une VM invitée : lecture/écriture de la mémoire des autres VMs et de dom0, pouvant conduire à la compromission complète de l'hyperviseur et de toutes les charges hébergées. XCP-ng qualifie l'impact de critique. | Theoretical | Appliquer les correctifs XSA-523 (xen-unstable à 4.19.x, 4.18.x à 4.17.x ; xen-4.17.7-4.2.xcpng8.3 pour XCP-ng 8.3 ; Xen 4.19.6-3 dans dom0 pour Qubes 4.3) et redémarrer les hôtes. Les branches 4.6 à 4.16 ne recevront pas de correctif (fin de support). En attendant, isoler les VMs non fiables et restreindre l'accès aux interfaces de gestion. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/)<br>[https://thehackernews.com/2026/11/xen-hypervisor-flaws-let-one-malicious.html](https://thehackernews.com/2026/11/xen-hypervisor-flaws-let-one-malicious.html)<br>[https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697256&articleURL=XenServer_Security_Update_for_Multiple_Issues](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697256&articleURL=XenServer_Security_Update_for_Multiple_Issues) |
| **CVE-2026-111497** | N/A | N/A | FALSE | Citrix UniconOS Management (Scout) On-Prem (correctifs 2609.1 / 2508 CU2 LTSR) et SolarWinds Dameware versions antérieures à 2026.3 ; Dameware Remote Everywhere non affecté | Vulnérabilité commune référencée par deux éditeurs, associée à un risque d'exécution de code arbitraire à distance et de contournement de la politique de sécurité | Exécution de code arbitraire à distance et contournement de politique de sécurité sur les consoles d'administration à distance, avec risque de prise de contrôle des postes gérés. | None | Mettre à jour Dameware vers 2026.3 et appliquer les correctifs Citrix Scout (2609.1 ou 2508 CU2 LTSR). Restreindre l'exposition des consoles d'administration et surveiller les accès. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/)<br>[https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1459/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1459/)<br>[https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697300&articleURL=Citrix_Security_Advisory_for_CVE_2026_111497_Impact_on_Unicon_eLux_Scout](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697300&articleURL=Citrix_Security_Advisory_for_CVE_2026_111497_Impact_on_Unicon_eLux_Scout)<br>[https://www.solarwinds.com/trust-center/security-advisories/cve-2026-111497](https://www.solarwinds.com/trust-center/security-advisories/cve-2026-111497) |
| **CVE-2026-45447** | N/A | N/A | FALSE | Produits Citrix visés par les bulletins CTX697256 et CTX697300 (XenServer, SCG, UniconOS Management) | Vulnérabilité non détaillée individuellement par l'avis CERT-FR | Exécution de code arbitraire à distance ou élévation de privilèges selon le composant Citrix affecté. | None | Appliquer les correctifs Citrix CTX697256 / CTX697300 et restreindre l'exposition des interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/)<br>[https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697256&articleURL=XenServer_Security_Update_for_Multiple_Issues](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697256&articleURL=XenServer_Security_Update_for_Multiple_Issues) |
| **CVE-2026-97631** | N/A | N/A | FALSE | Produits Citrix visés par les bulletins CTX697256 et CTX697300 (XenServer, SCG, UniconOS Management) | Vulnérabilité non détaillée individuellement par l'avis CERT-FR | Risque d'exécution de code arbitraire à distance ou d'élévation de privilèges sur les composants Citrix affectés. | None | Appliquer les correctifs Citrix CTX697256 / CTX697300 et restreindre l'exposition des interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/)<br>[https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697256&articleURL=XenServer_Security_Update_for_Multiple_Issues](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697256&articleURL=XenServer_Security_Update_for_Multiple_Issues) |
| **CVE-2026-98432** | N/A | N/A | FALSE | Produits Citrix visés par les bulletins CTX697256 et CTX697300 (XenServer, SCG, UniconOS Management) | Vulnérabilité non détaillée individuellement par l'avis CERT-FR | Exécution de code arbitraire à distance ou élévation de privilèges selon le composant Citrix affecté. | None | Appliquer les correctifs Citrix CTX697256 / CTX697300 et restreindre l'exposition des interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1449/)<br>[https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697256&articleURL=XenServer_Security_Update_for_Multiple_Issues](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697256&articleURL=XenServer_Security_Update_for_Multiple_Issues) |
| **CVE-2026-109593** | 9.1 | N/A | FALSE | SonicWall Global Management System (GMS) 9.5.2 et versions antérieures (produit en fin de vie) | Lecture de fichier non authentifiée (CWE-306/CWE-22 selon l'éditeur) permettant l'accès à des fichiers internes du GMS | Divulgation d'informations sensibles stockées sur le serveur GMS, pouvant faciliter des attaques ultérieures (réutilisation d'identifiants, cartographie du réseau, accès aux configurations des équipements de sécurité). | Theoretical | Aucun correctif ne sera publié. Migrer vers SonicWall NSM, isoler les serveurs GMS restants (filtrage réseau strict, suppression de l'exposition Internet) et surveiller les accès aux fichiers. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1456/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1456/)<br>[https://thehackernews.com/2026/11/sonicwall-wont-patch-eol-gms-flaws-that.html](https://thehackernews.com/2026/11/sonicwall-wont-patch-eol-gms-flaws-that.html)<br>[https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0019](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0019) |
| **CVE-2026-109594** | 6.8 | N/A | FALSE | SonicWall Global Management System (GMS) 9.5.2 et versions antérieures (produit en fin de vie) | Injection SQL post-authentification (CWE-89) | Altération ou exfiltration de données de la base GMS (inventaire, configurations, journaux), avec un risque de manipulation des politiques de sécurité gérées par la console. | Theoretical | Aucun correctif disponible. Migrer vers SonicWall NSM, restreindre l'accès authentifié au GMS, surveiller les requêtes SQL et restaurer la base en cas d'altération. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1456/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1456/)<br>[https://thehackernews.com/2026/11/sonicwall-wont-patch-eol-gms-flaws-that.html](https://thehackernews.com/2026/11/sonicwall-wont-patch-eol-gms-flaws-that.html)<br>[https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0019](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0019) |
| **CVE-2026-28327** | N/A | N/A | FALSE | SolarWinds Dameware versions antérieures à 2026.3 | Vulnérabilité non détaillée individuellement par l'avis CERT-FR ; l'avis global mentionne exécution de code arbitraire à distance et contournement de la politique de sécurité | Exécution de code arbitraire à distance et contournement de politique de sécurité sur les consoles d'administration à distance, avec risque de prise de contrôle des postes gérés. | None | Mettre à jour Dameware vers 2026.3, restreindre l'exposition des consoles d'administration et surveiller les accès. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1459/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1459/)<br>[https://www.solarwinds.com/trust-center/security-advisories/cve-2026-28327](https://www.solarwinds.com/trust-center/security-advisories/cve-2026-28327) |
| **CVE-2026-28335** | N/A | N/A | FALSE | SolarWinds Dameware versions antérieures à 2026.3 | Vulnérabilité non détaillée individuellement par l'avis CERT-FR | Exécution de code arbitraire à distance ou contournement de politique de sécurité sur les consoles Dameware. | None | Mettre à jour Dameware vers 2026.3 et restreindre l'exposition des consoles d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1459/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1459/)<br>[https://www.solarwinds.com/trust-center/security-advisories/cve-2026-28335](https://www.solarwinds.com/trust-center/security-advisories/cve-2026-28335) |
| **CVE-2026-28336** | N/A | N/A | FALSE | SolarWinds Dameware versions antérieures à 2026.3 | Vulnérabilité non détaillée individuellement par l'avis CERT-FR | Exécution de code arbitraire à distance ou contournement de politique de sécurité sur les consoles Dameware. | None | Mettre à jour Dameware vers 2026.3 et restreindre l'exposition des consoles d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1459/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1459/)<br>[https://www.solarwinds.com/trust-center/security-advisories/cve-2026-28336](https://www.solarwinds.com/trust-center/security-advisories/cve-2026-28336) |
| **CVE-2026-109518** | 7.7 | N/A | FALSE | APT (gestionnaire de paquets Debian/Ubuntu) — Debian 12 et ultérieurs, Ubuntu 22.04 LTS et ultérieurs par défaut ; Debian 11 et Ubuntu 20.04 si Acquire::Retries est activé ; distributions dérivées de Debian/Ubuntu | Défaut de vérification lors des nouvelles tentatives de téléchargement (TOCTOU sur paquets vérifiés) permettant à un attaquant de type MitM de substituer un paquet et d'exécuter du code en root | Exécution de code arbitraire en root sur les systèmes Debian/Ubuntu affectés, avec compromission complète de l'hôte et risque de propagation via la chaîne d'approvisionnement logicielle. | Theoretical | Mettre à jour APT vers les versions corrigées (Debian ; Ubuntu 26.10 3.3.3ubuntu0.1, 26.04 LTS 3.2.1ubuntu0.1, 24.04 LTS 2.8.4ubuntu0.1, 22.04 LTS 2.4.15ubuntu0.1 ; Debian 11 : 2.2.5). Privilégier HTTPS pour les dépôts, restreindre les miroirs autorisés et désactiver Acquire::Retries lorsque ce n'est pas nécessaire. | [https://thehackernews.com/2026/11/debian-and-ubuntu-apt-flaw-lets-mitm.html](https://thehackernews.com/2026/11/debian-and-ubuntu-apt-flaw-lets-mitm.html) |
| **CVE-2026-102255** | 10.0 | N/A | FALSE | Équipements SonicWall affectés par CVE-2026-102255 (correctif publié en octobre 2026) | Server-Side Request Forgery (SSRF) pré-authentification critique (CVSS 10.0) | Accès non autorisé à des fonctionnalités internes et exécution d'opérations non autorisées sur les équipements SonicWall, avec risque de compromission du périmètre de sécurité. | Active | Appliquer le correctif SonicWall, restreindre l'exposition des interfaces d'administration, bloquer les IP malveillantes identifiées et surveiller les journaux pour détecter les tentatives SSRF. | [https://thehackernews.com/2026/11/sonicwall-wont-patch-eol-gms-flaws-that.html](https://thehackernews.com/2026/11/sonicwall-wont-patch-eol-gms-flaws-that.html) |
| **CVE-2026-102704** | N/A | N/A | FALSE | Xen 4.6 et versions ultérieures (XenServer, XCP-ng 8.3, Qubes OS 4.3, paquet xen Debian) | Défaut de vérification de permissions dans l'opération « grant copy » (XSA-523) permettant à une VM invitée de lire et écrire la mémoire d'autres VMs, y compris dom0 | Sortie d'isolation d'une VM invitée avec accès en lecture/écriture à la mémoire des autres VMs et de dom0, pouvant conduire à la compromission de l'hyperviseur. | Theoretical | Appliquer les correctifs XSA-523 (xen-unstable à 4.19.x, 4.18.x à 4.17.x ; XCP-ng 8.3 xen-4.17.7-4.2.xcpng8.3 ; Qubes 4.3 Xen 4.19.6-3) et redémarrer les hôtes. Les branches 4.6 à 4.16 ne recevront pas de correctif. | [https://thehackernews.com/2026/11/xen-hypervisor-flaws-let-one-malicious.html](https://thehackernews.com/2026/11/xen-hypervisor-flaws-let-one-malicious.html) |
| **CVE-2026-58868** | N/A | N/A | FALSE | Android 14 à 17 (correctif de sécurité 2026-11-01 ou ultérieur requis) | Débordement de tampon heap (out-of-bounds write) dans la fonction onOutputReceived du fichier FrameDecoder.cpp, permettant une exécution de code à distance sans interaction utilisateur | Exécution de code arbitraire à distance sur le terminal sans action de l'utilisateur : vol de données, installation de logiciels malveillants, accès aux comptes et aux ressources d'entreprise accessibles depuis l'appareil. | None | Appliquer le niveau de correctif de sécurité 2026-11-01 ou ultérieur, imposer un niveau de correctif minimal via le MDM, isoler les terminaux non corrigés et suivre les publications des constructeurs pour les modèles concernés. | [https://thehackernews.com/2026/11/google-patches-critical-android-flaw.html](https://thehackernews.com/2026/11/google-patches-critical-android-flaw.html)<br>[https://securityaffairs.com/202414/mobile-2/cve-2026-58868-critical-android-bug-could-let-attackers-run-remote-code.html](https://securityaffairs.com/202414/mobile-2/cve-2026-58868-critical-android-bug-could-let-attackers-run-remote-code.html) |
| **CVE-2026-58876** | N/A | N/A | FALSE | Android — composant System (correctif de sécurité 2026-11-01 ou ultérieur ; 2026-11-05 pour le bulletin complet) | Vulnérabilité critique du composant System permettant une exécution de code à distance | Exécution de code à distance sur le terminal Android via le composant System, avec risque de compromission de l'appareil. | None | Appliquer le correctif de sécurité Android de novembre 2026 (niveau 2026-11-01 minimum, 2026-11-05 pour couvrir l'ensemble du bulletin) et les Google Play system updates associées. | [https://thehackernews.com/2026/11/google-patches-critical-android-flaw.html](https://thehackernews.com/2026/11/google-patches-critical-android-flaw.html) |
| **CVE-2026-58882** | N/A | N/A | FALSE | Android — code de traitement des messages WAP Push reçus par SMS (fonction decodeWapPdu) | Déni de service à distance sans interaction utilisateur via un message WAP Push malformé | Déni de service sur la fonction téléphonie du terminal, avec interruption des appels en cours (y compris d'urgence) et crash au démarrage tant que le message malveillant persiste. | Theoretical | Appliquer le correctif Android de novembre 2026. En attendant, supprimer le message malformé de la file de messages et surveiller les crashs répétés de com.android.phone. | [https://thehackernews.com/2026/11/google-patches-critical-android-flaw.html](https://thehackernews.com/2026/11/google-patches-critical-android-flaw.html) |
| **CVE-2026-58936** | N/A | N/A | FALSE | Android — composant System (correctif de sécurité 2026-11-01 ou ultérieur ; 2026-11-05 pour le bulletin complet) | Vulnérabilité critique du composant System permettant une exécution de code à distance | Exécution de code à distance sur le terminal Android via le composant System, avec risque de compromission de l'appareil. | None | Appliquer le correctif de sécurité Android de novembre 2026 (niveau 2026-11-01 minimum, 2026-11-05 pour couvrir l'ensemble du bulletin). | [https://thehackernews.com/2026/11/google-patches-critical-android-flaw.html](https://thehackernews.com/2026/11/google-patches-critical-android-flaw.html) |
| **CVE-2026-119977** | 8.1 | N/A | TRUE | WordPress Core (versions vulnérables corrigées fin octobre 2026) | Condition de concurrence Time-of-check Time-of-use (TOCTOU) lors des mises à jour complètes du cœur, due à des chemins de staging prévisibles et accessibles sur le web, permettant une exécution de code non authentifiée | Exécution de code arbitraire non authentifiée sur le serveur web hébergeant WordPress, avec risque de compromission complète du site, de persistance via webshell et de mouvement latéral vers l'infrastructure d'hébergement. | Active | Mettre à jour vers WordPress 7.1.4 ou une branche disposant du correctif rétroporté, restreindre l'accès web au répertoire wp-content/upgrade, surveiller les requêtes vers les chemins de staging et appliquer les mesures du catalogue KEV de la CISA. | [https://thehackernews.com/2026/11/cisa-confirms-hackers-exploiting.html](https://thehackernews.com/2026/11/cisa-confirms-hackers-exploiting.html)<br>[https://securityaffairs.com/202394/security/u-s-cisa-adds-wordpress-flaw-to-its-known-exploited-vulnerabilities-catalog-2.html](https://securityaffairs.com/202394/security/u-s-cisa-adds-wordpress-flaw-to-its-known-exploited-vulnerabilities-catalog-2.html)<br>[https://socprime.com/blog/cve-2026-119977-wordpress-core-rce-flaw-exploited-during-software-upgrades/](https://socprime.com/blog/cve-2026-119977-wordpress-core-rce-flaw-exploited-during-software-upgrades/) |
| **CVE-2026-116606** | 9.3 | N/A | FALSE | Barracuda Email Security Gateway (ESG) | Contournement d'authentification / d'autorisation avant authentification (pre-auth authorization bypass) | Compromission totale de l'appliance de sécurité de la messagerie : accès root, modification des règles de filtrage, interception ou réacheminement de courriels, persistance sur un équipement de confiance du périmètre. L'impact dépasse l'appliance elle-même puisque la passerelle traite l'ensemble du flux de messagerie de l'organisation. | Theoretical | Appliquer les correctifs éditeur : BNSF-40425 pour les ESG en version 9.4.017 ou supérieure, BNSF-40430 pour les versions antérieures à 9.4.017. Restreindre l'accès à l'interface d'administration (VPN, liste blanche IP, MFA), surveiller les changements de configuration et auditer les comptes administrateurs après mise à jour. | [https://securityaffairs.com/202440/security/two-barracuda-esg-flaws-could-be-combined-for-full-root-access-patches-released.html](https://securityaffairs.com/202440/security/two-barracuda-esg-flaws-could-be-combined-for-full-root-access-patches-released.html) |
| **CVE-2026-111560** | 8.6 | N/A | FALSE | Six produits Barracuda, dont Email Security Gateway (ESG) et Load Balancer Application Delivery Controller (ADC) | Injection de commandes système (command injection) | Exécution arbitraire de commandes avec les privilèges les plus élevés sur une appliance de sécurité périmétrique : altération du firmware, installation de persistance, interception du trafic, pivot vers le réseau interne. | Theoretical | Appliquer les correctifs éditeur (BNADC-16586 pour l'ADC, BNSF-40425 ou BNSF-40430 pour l'ESG), restreindre l'accès à l'interface d'administration, surveiller les exécutions de commandes et réinitialiser les secrets après remédiation. | [https://securityaffairs.com/202440/security/two-barracuda-esg-flaws-could-be-combined-for-full-root-access-patches-released.html](https://securityaffairs.com/202440/security/two-barracuda-esg-flaws-could-be-combined-for-full-root-access-patches-released.html) |
| **CVE-2026-54384** | 9.8 | N/A | FALSE | VitaFit Cloud API (antérieure au 30 octobre 2026) | Contournement d'authentification par usurpation (CWE-290) | Prise de contrôle de comptes utilisateurs : accès aux données de profil, modification non autorisée, suppression du mécanisme d'authentification et déni d'accès au compte légitime. | Theoretical | Mettre à jour l'API pour valider la propriété des comptes sociaux liés lors de la connexion, imposer une validation stricte des identifiants fournis par les fournisseurs d'identité, restreindre l'accès aux points de terminaison sensibles et ajouter une limitation de débit sur les tentatives de connexion. | [https://cvefeed.io/vuln/detail/CVE-2026-54384](https://cvefeed.io/vuln/detail/CVE-2026-54384) |
| **CVE-2026-54378** | 9.6 | N/A | FALSE | VitaFit Cloud API (antérieure au 30 octobre 2026) | Contrôle d'accès défaillant (broken access control) avec exposition d'identifiants insuffisamment protégés (CWE-522) | Accès non autorisé aux fichiers d'autres utilisateurs, modification ou destruction de données stockées, atteinte à la confidentialité et à l'intégrité des données personnelles hébergées dans le cloud. | Theoretical | Mettre à jour l'API pour appliquer un contrôle d'accès strict sur la délivrance des identifiants AWS temporaires, appliquer le principe du moindre privilège sur les politiques IAM, restreindre l'accès au point de terminaison et valider les permissions utilisateur avant toute délivrance de jetons. | [https://cvefeed.io/vuln/detail/CVE-2026-54378](https://cvefeed.io/vuln/detail/CVE-2026-54378) |
| **CVE-2026-54376** | 8.2 | N/A | FALSE | Application Android VitaFit (com.vt.vitafit) antérieure à 2.8.1.0 | Schéma d'URI personnalisé non sécurisé / exportation incorrecte de composant Android (CWE-926) | Vol de jeton d'autorisation tiers et accès non autorisé aux données de santé de la victime, avec possibilité de modification ou de suppression de l'historique de poids et de masse grasse. | Theoretical | Mettre à jour l'application VitaFit vers la version 2.8.1.0 ou ultérieure, valider correctement les schémas d'URI personnalisés, appliquer des pratiques sécurisées de gestion des jetons (PKCE, vérification d'application) et revoir les contrôles d'accès à l'API. | [https://cvefeed.io/vuln/detail/CVE-2026-54376](https://cvefeed.io/vuln/detail/CVE-2026-54376) |
| **CVE-2026-54375** | 8.6 | N/A | FALSE | Application VitaFit pour Android (com.vt.vitafit) antérieure à 2.8.1.0 | Gestion de session insuffisante (CWE-613) — jetons de session à durée de vie excessive et non chiffrés | Confidentialité et intégrité du compte utilisateur compromises, déni de service persistant sur le compte (suppression de l'enregistrement d'authentification), exposition de données de santé et de profil. Score CVSS 4.0 de 8,6 (HIGH), CVSS 3.1 de 8,4. | Theoretical | Mettre à jour l'application vers la version 2.8.1.0 ou ultérieure, chiffrer les jetons de session au repos, réduire drastiquement leur durée de vie et implémenter une rotation, exclure les secrets des sauvegardes Android, révoquer les jetons existants côté serveur. | [https://cvefeed.io/vuln/detail/CVE-2026-54375](https://cvefeed.io/vuln/detail/CVE-2026-54375)<br>[https://www.vulncheck.com/advisories/vitafit-android-long-lived-session-token-exposure](https://www.vulncheck.com/advisories/vitafit-android-long-lived-session-token-exposure) |
| **CVE-2026-54374** | 8.7 | N/A | FALSE | Application VitaFit pour Android (com.vt.vitafit) antérieure à 2.8.1.0 | Utilisation d'identifiants codés en dur (CWE-798) | Compromission des intégrations tierces, accès non autorisé aux API partenaires, fuite potentielle de données utilisateurs relayées par ces services, atteinte à la réputation et risques contractuels vis-à-vis des fournisseurs. CVSS 4.0 de 8,7 (HIGH), CVSS 3.1 de 7,5. | Theoretical | Mettre à jour vers la version 2.8.1.0 ou ultérieure, supprimer tout secret du code client, stocker les secrets côté serveur ou dans un coffre-fort, faire tourner les clés exposées et restreindre leur usage par empreinte applicative. | [https://cvefeed.io/vuln/detail/CVE-2026-54374](https://cvefeed.io/vuln/detail/CVE-2026-54374)<br>[https://www.vulncheck.com/advisories/vitafit-android-hardcoded-credentials-disclosure](https://www.vulncheck.com/advisories/vitafit-android-hardcoded-credentials-disclosure) |
| **CVE-2026-54372** | 8.8 | N/A | FALSE | Application VitaFit pour Android (com.vt.vitafit) antérieure à 2.8.1.0 | Validation de certificat TLS/SSL incorrecte (CWE-295) | Interception et altération du trafic, vol de sessions et de données de santé, déni de service persistant sur le compte. CVSS 3.1 de 8,8 (HIGH), CVSS 4.0 de 8,7. | Theoretical | Mettre à jour vers la version 2.8.1.0 ou ultérieure, supprimer le TrustManager permissif, implémenter une validation stricte des certificats et du nom d'hôte, ajouter du certificate pinning et refuser les certificats installés par l'utilisateur. | [https://cvefeed.io/vuln/detail/CVE-2026-54372](https://cvefeed.io/vuln/detail/CVE-2026-54372)<br>[https://www.vulncheck.com/advisories/vitafit-android-insecure-tls-certificate-validation](https://www.vulncheck.com/advisories/vitafit-android-insecure-tls-certificate-validation) |
| **CVE-2026-54381** | 8.7 | N/A | FALSE | API cloud VitaFit (antérieure au 30 octobre 2026) | Attribution incorrecte de permissions sur une ressource critique (CWE-732) — bucket de stockage public | Divulgation de données personnelles (images de profil, métadonnées associées), atteinte à la vie privée des utilisateurs, risque réglementaire (RGPD) et réputationnel. CVSS 4.0 de 8,7 (HIGH), CVSS 3.1 de 7,5. | Theoretical | Restreindre l'accès au bucket, imposer l'authentification et le chiffrement, appliquer le moindre privilège sur les politiques IAM, auditer l'ensemble des configurations cloud et activer une surveillance continue de l'exposition. | [https://cvefeed.io/vuln/detail/CVE-2026-54381](https://cvefeed.io/vuln/detail/CVE-2026-54381)<br>[https://www.vulncheck.com/advisories/vitafit-cloud-api-storage-bucket-unauthenticated-access-information-disclosure](https://www.vulncheck.com/advisories/vitafit-cloud-api-storage-bucket-unauthenticated-access-information-disclosure) |
| **CVE-2026-100235** | N/A | N/A | FALSE | Apache ZooKeeper versions 3.8.x antérieures à 3.8.8 et 3.9.x antérieures à 3.9.7 | Vulnérabilité multiple — déni de service à distance et contournement de la politique de sécurité | Indisponibilité du service de coordination pouvant impacter les applications distribuées dépendantes (Kafka, HBase, systèmes de configuration), et affaiblissement des contrôles de sécurité. Aucun score CVSS n'est publié dans la source. | None | Appliquer les correctifs éditeur en passant à ZooKeeper 3.8.8 ou 3.9.7, restreindre l'exposition réseau des ports de service, activer SASL/TLS et surveiller les journaux d'accès. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1448/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1448/)<br>[https://zookeeper.apache.org/security.html](https://zookeeper.apache.org/security.html) |
| **CVE-2026-100252** | N/A | N/A | FALSE | Apache ZooKeeper versions 3.8.x antérieures à 3.8.8 et 3.9.x antérieures à 3.9.7 | Vulnérabilité multiple — déni de service à distance et contournement de la politique de sécurité | Indisponibilité ou dégradation du service de coordination, impact en cascade sur les applications distribuées dépendantes et affaiblissement des contrôles de sécurité. Aucun score CVSS n'est publié dans la source. | None | Appliquer les correctifs éditeur (ZooKeeper 3.8.8 ou 3.9.7), restreindre l'exposition réseau, activer SASL/TLS et surveiller les journaux d'accès. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1448/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1448/)<br>[https://zookeeper.apache.org/security.html](https://zookeeper.apache.org/security.html) |
| **CVE-2026-100300** | N/A | N/A | FALSE | Apache ZooKeeper versions 3.8.x antérieures à 3.8.8 et 3.9.x antérieures à 3.9.7 | Vulnérabilité multiple — déni de service à distance et contournement de la politique de sécurité | Dégradation ou indisponibilité du service de coordination, avec impact potentiel sur les plateformes distribuées dépendantes. Aucun score CVSS n'est publié dans la source. | None | Appliquer les correctifs éditeur (ZooKeeper 3.8.8 ou 3.9.7), restreindre l'exposition réseau, activer SASL/TLS et surveiller les journaux d'accès. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1448/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1448/)<br>[https://zookeeper.apache.org/security.html](https://zookeeper.apache.org/security.html) |
| **CVE-2026-100302** | N/A | N/A | FALSE | Apache ZooKeeper versions 3.8.x antérieures à 3.8.8 et 3.9.x antérieures à 3.9.7 | Vulnérabilité multiple — déni de service à distance et contournement de la politique de sécurité | Indisponibilité du service de coordination et affaiblissement des contrôles de sécurité, avec effets en cascade sur les applications dépendantes. Aucun score CVSS n'est publié dans la source. | None | Appliquer les correctifs éditeur (ZooKeeper 3.8.8 ou 3.9.7), restreindre l'exposition réseau, activer SASL/TLS et surveiller les journaux d'accès. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1448/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1448/)<br>[https://zookeeper.apache.org/security.html](https://zookeeper.apache.org/security.html) |
| **CVE-2026-115448** | N/A | N/A | FALSE | Apache ZooKeeper versions 3.8.x antérieures à 3.8.8 et 3.9.x antérieures à 3.9.7 | Vulnérabilité multiple — déni de service à distance et contournement de la politique de sécurité | Indisponibilité ou dégradation du service de coordination, impact en cascade sur les applications distribuées et affaiblissement des contrôles de sécurité. Aucun score CVSS n'est publié dans la source. | None | Appliquer les correctifs éditeur (ZooKeeper 3.8.8 ou 3.9.7), restreindre l'exposition réseau, activer SASL/TLS et surveiller les journaux d'accès. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1448/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1448/)<br>[https://zookeeper.apache.org/security.html](https://zookeeper.apache.org/security.html) |
| **CVE-2024-27834** | 5.5 | 0.60% | TRUE | Apple iOS, iPadOS, macOS, Safari, tvOS et watchOS (versions antérieures aux correctifs de mai 2024) | Authentification incorrecte (CWE-287) — contournement de l'authentification de pointeur (pointer authentication) dans WebKit | Contournement des protections mémoire d'Apple permettant la poursuite d'une chaîne d'exploitation, avec pour conséquence le vol de cookies, de mots de passe Wi-Fi et de données complètes de l'appareil (SMS, iMessage, bases Mail, WhatsApp, Telegram, trousseau iCloud, photos, données de santé). CVSS 3.1 de 5,5 (MEDIUM), EPSS d'environ 0,6 %. | Active | Appliquer les mises à jour Apple (iOS/iPadOS 16.7.8 ou 17.5 minimum, macOS Sonoma 14.5, Safari 17.5, tvOS 17.5, watchOS 10.5) ou toute version ultérieure, imposer les mises à jour par MDM, bloquer les scripts d'analytics tiers compromis et surveiller les accès aux domaines de leurre. | [https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html](https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html)<br>[https://www.cisa.gov/news-events/alerts/2026/11/04/cisa-adds-one-known-exploited-vulnerability-catalog](https://www.cisa.gov/news-events/alerts/2026/11/04/cisa-adds-one-known-exploited-vulnerability-catalog)<br>[https://infosec.exchange/@cyberseckyle/117560769943461114](https://infosec.exchange/@cyberseckyle/117560769943461114)<br>[https://ninjasignal.ninja/intel/cve/CVE-2024-27834](https://ninjasignal.ninja/intel/cve/CVE-2024-27834)<br>[https://mastodon.social/@ninjaintelgroup/117560711830888612](https://mastodon.social/@ninjaintelgroup/117560711830888612) |
| **CVE-2025-43529** | N/A | N/A | FALSE | Apple iOS 16.7 (appareils non corrigés) | Vulnérabilité WebKit exploitée dans une chaîne d'exploitation mobile (classe A de la campagne Poisoned Source) | Vol de cookies de session et prise de contrôle de comptes web consultés depuis l'appareil mobile. Aucun score CVSS n'est publié dans la source. | Active | Mettre à jour les appareils iOS vers une version corrigée, bloquer les scripts tiers compromis et les domaines de leurre, et révoquer les sessions des appareils exposés. | [https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html](https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html) |
| **CVE-2026-20700** | N/A | N/A | FALSE | Apple iOS 18.5 (appareils non corrigés) | Vulnérabilité exploitée dans la chaîne d'exploitation DarkSword (classe B de la campagne Poisoned Source) | Compromission totale de l'appareil mobile et exfiltration de données personnelles et professionnelles sensibles. Aucun score CVSS n'est publié dans la source. | Active | Mettre à jour les appareils iOS vers une version corrigée, bloquer les scripts tiers compromis et les domaines de leurre, révoquer les sessions et mots de passe exposés. | [https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html](https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html) |
| **CVE-2025-14174** | N/A | N/A | FALSE | Apple iOS 18.5 (appareils non corrigés) | Vulnérabilité exploitée dans la chaîne d'exploitation DarkSword (classe B de la campagne Poisoned Source) | Compromission de l'appareil mobile et exfiltration de données personnelles et professionnelles. Aucun score CVSS n'est publié dans la source. | Active | Mettre à jour les appareils iOS vers une version corrigée, bloquer les scripts tiers compromis et les domaines de leurre, révoquer les sessions et mots de passe exposés. | [https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html](https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html) |
| **CVE-2025-43510** | N/A | N/A | FALSE | Apple iOS 18.5 (appareils non corrigés) | Vulnérabilité exploitée dans la chaîne d'exploitation DarkSword (classe B de la campagne Poisoned Source) | Compromission de l'appareil mobile et exfiltration de données personnelles et professionnelles. Aucun score CVSS n'est publié dans la source. | Active | Mettre à jour les appareils iOS vers une version corrigée, bloquer les scripts tiers compromis et les domaines de leurre, révoquer les sessions et mots de passe exposés. | [https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html](https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html) |
| **CVE-2025-43520** | N/A | N/A | FALSE | Apple iOS 18.5 (appareils non corrigés) | Vulnérabilité exploitée dans la chaîne d'exploitation DarkSword (classe B de la campagne Poisoned Source) | Compromission de l'appareil mobile et exfiltration de données personnelles et professionnelles. Aucun score CVSS n'est publié dans la source. | Active | Mettre à jour les appareils iOS vers une version corrigée, bloquer les scripts tiers compromis et les domaines de leurre, révoquer les sessions et mots de passe exposés. | [https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html](https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html) |
| **CVE-2026-3910** | N/A | N/A | FALSE | Google Chrome pour Android, versions 139 à 145 (à l'exclusion de la version 143) | Vulnérabilité d'exécution de code à distance dans Chrome pour Android (classe C de la campagne Poisoned Source) | Exécution de code sur le terminal Android, vol des données de navigation et des mots de passe Wi-Fi. Aucun score CVSS n'est publié dans la source. | Active | Mettre à jour Chrome pour Android vers une version corrigée, bloquer les scripts tiers compromis et les domaines de leurre, révoquer les identifiants enregistrés et changer les mots de passe Wi-Fi exposés. | [https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html](https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html) |
| **CVE-2025-27038** | N/A | N/A | FALSE | Google Chrome pour Android, versions 139 à 145 (à l'exclusion de la version 143) | Vulnérabilité d'échappement de sandbox / d'élévation de privilèges dans Chrome pour Android | Exécution de code sur le terminal Android, vol des données de navigation et des mots de passe Wi-Fi. Aucun score CVSS n'est publié dans la source. | Active | Mettre à jour Chrome pour Android vers une version corrigée, bloquer les scripts tiers compromis et les domaines de leurre, révoquer les identifiants enregistrés et changer les mots de passe Wi-Fi exposés. | [https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html](https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html) |
| **CVE-2026-57567** | 8.6 | N/A | FALSE | Readest — builds desktop Tauri, versions antérieures à 0.11.10 | Traversée de chemin (CWE-22) via commandes IPC Tauri non restreintes (download_file / upload_file) | La primitive d'écriture permet d'écraser des fichiers de confiance ou de démarrage (persistance, exécution de code au prochain lancement) ; la primitive de lecture permet d'exposer des clés, jetons et secrets applicatifs lisibles par le processus. Impact élevé sur la confidentialité et l'intégrité des postes utilisateurs, avec un vecteur local nécessitant une exécution de code JavaScript préalable. | Theoretical | Mettre à jour Readest desktop vers la version 0.11.10 (hxxps://github[.]com/readest/readest/releases/tag/v0[.]11[.]10). Vérifier que les contrôles de scope filesystem sont appliqués aux opérations de fichiers et que la traversée de répertoire parent est bloquée. Réduire la surface d'XSS applicative et la compromission de renderer, restreindre l'exécution de JavaScript embarqué dans les livres et surveiller les écritures anormales du processus. | [https://cvefeed.io/vuln/detail/CVE-2026-57567](https://cvefeed.io/vuln/detail/CVE-2026-57567) |
| **CVE-2026-57566** | 9.3 | N/A | FALSE | Readest — versions antérieures à 0.11.10 (déploiements Node, Docker, auto-hébergés et Cloudflare Workers) | Server-Side Request Forgery (CWE-918) / proxy de requêtes ouvert non authentifié | Exposition de services internes et de métadonnées cloud (credentials d'instance, configuration), possibilité de rebond vers des API internes non exposées, et utilisation du service comme proxy anonymisant. Le caractère non authentifié et distant (CVSS 9.3) en fait un risque critique pour les déploiements auto-hébergés. | Theoretical | Mettre à jour Readest vers 0.11.10 ou supérieur (hxxps://github[.]com/readest/readest/releases/tag/v0[.]11[.]10). Vérifier les restrictions de la route proxy sur chaque type de déploiement, implémenter une validation stricte des URL (schéma, résolution DNS, revalidation à chaque redirection), restreindre l'accès aux hôtes internes et sensibles et appliquer un filtrage egress sur les hôtes applicatifs. | [https://cvefeed.io/vuln/detail/CVE-2026-57566](https://cvefeed.io/vuln/detail/CVE-2026-57566) |
| **CVE-2026-122266** | 8.7 | N/A | FALSE | Amazon EKS — aws-network-policy-agent < 1.3.7 et Amazon VPC CNI Managed Add-on < 1.22.3 | Isolation impropre de ressources partagées (CWE-1189) — contournement de NetworkPolicy par empoisonnement de la table conntrack eBPF | Contournement de la segmentation réseau Kubernetes : accès non autorisé à des services internes, mouvements latéraux entre pods co-localisés et exposition de données sensibles. Le score CVSS 3.1 de 8.7 (6.3 en CVSS 4.0) reflète un impact élevé en confidentialité et intégrité dans les clusters multi-tenant. | Theoretical | Mettre à jour le VPC CNI Managed Add-on vers la version 1.22.3 ou supérieure, qui embarque Network Policy Agent 1.3.7 (hxxps://github[.]com/aws/amazon-vpc-cni-k8s/releases/tag/v1[.]22[.]3 et hxxps://github[.]com/aws/aws-network-policy-agent/releases/tag/v1[.]3[.]7). Aucun contournement n'étant disponible, la mise à jour est la seule remédiation ; en complément, restreindre les capacités NET_RAW, appliquer le moindre privilège RBAC et surveiller les flux inter-pods. | [https://cvefeed.io/vuln/detail/CVE-2026-122266](https://cvefeed.io/vuln/detail/CVE-2026-122266)<br>[https://aws.amazon.com/security/security-bulletins/rss/2026-170-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-170-aws/) |
| **CVE-2026-121029** | N/A | N/A | FALSE | Google Chrome — versions antérieures à 157.0.8103.38 (Linux, Windows, macOS) | Multiples vulnérabilités non spécifiées par l'éditeur (bulletin Chrome du 3 novembre 2026) | Les vulnérabilités permettent à un attaquant de provoquer un problème de sécurité non spécifié par l'éditeur, avec un risque potentiel d'exécution de code, de contournement de la sandbox ou de divulgation d'information selon la nature réelle des failles. L'impact est d'autant plus élevé que Chrome est massivement déployé et exposé à du contenu web non fiable. | Theoretical | Appliquer le bulletin de sécurité Google Chrome du 3 novembre 2026 et mettre à jour vers la version 157.0.8103.38 ou supérieure sur Linux, Windows et macOS (hxxps://chromereleases[.]googleblog[.]com/2026/11/stable-channel-update-for-desktop[.]html). Imposer la mise à jour par stratégie de parc, vérifier les versions effectives et surveiller les avis CERT-FR ultérieurs. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1450/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1450/) |
| **CVE-2026-103002** | 8.8 | N/A | FALSE | GPUStack — versions 2.2.0 à 2.2.1 (corrigé en 2.2.2) | Absence d'autorisation (CWE-862) / contournement d'autorisation par clé contrôlée par l'utilisateur (CWE-639) | Accès inter-utilisateurs non autorisé et prise de contrôle du cluster : lecture de secrets, modification ou suppression de workloads, exécution de code dans le cluster cible via des charges de travail malveillantes. L'impact est critique dans les environnements mutualisés où GPUStack sert plusieurs équipes. | Theoretical | Mettre à jour GPUStack vers la version 2.2.2 (hxxps://github[.]com/gpustack/gpustack/releases/tag/v2[.]2[.]2). Revoir et restreindre les permissions des ServiceAccounts utilisés par les workers, vérifier l'application des contrôles d'autorisation au niveau ressource et auditer les accès au proxy d'API. | [https://cvefeed.io/vuln/detail/CVE-2026-103002](https://cvefeed.io/vuln/detail/CVE-2026-103002) |
| **CVE-2026-102894** | 9.1 | N/A | FALSE | GPUStack — versions 0.7.1 à 2.2.1 (corrigé en 2.2.2) | Contournement d'authentification par vérification impropre de signature (CWE-347) et rejeu (CWE-294) sur le callback SAML | Contournement total de l'authentification et prise de contrôle de comptes, y compris administrateurs, avec accès aux modèles, aux clusters GPU et aux données associées. Le rejeu d'assertions capturées permet une usurpation persistante tant que les sessions ne sont pas révoquées. | Theoretical | Mettre à jour GPUStack vers la version 2.2.2 ou supérieure (hxxps://github[.]com/gpustack/gpustack/releases/tag/v2[.]2[.]2). Vérifier la configuration SAML si elle est activée, sécuriser les endpoints d'authentification, révoquer les sessions actives et restreindre l'exposition réseau du callback. | [https://cvefeed.io/vuln/detail/CVE-2026-102894](https://cvefeed.io/vuln/detail/CVE-2026-102894) |
| **CVE-2026-107441** | N/A | N/A | FALSE | Commutateurs Zyxel GS1900 (selon modèle) — firmware antérieur à 2.90 | Écriture hors bornes (out-of-bounds write) dans une interface CGI exposée côté LAN, pouvant mener à une exécution de commandes OS non authentifiée | Exécution de commandes arbitraires sur le commutateur par un attaquant présent sur le LAN, avec pour conséquences possibles la modification de la configuration réseau (VLAN, ACL, redirections de ports), l'interception de trafic et l'utilisation de l'équipement comme point d'appui pour des mouvements latéraux. L'impact est limité au segment réseau exposé mais critique pour la segmentation. | None | Installer le firmware 2.90 correspondant au modèle exact du GS1900 (hxxps://community[.]zyxel[.]com/en/discussion/34523/). Restreindre l'accès à l'interface de gestion aux réseaux d'administration, désactiver l'accès web depuis les segments utilisateurs et surveiller les journaux des équipements. Ne pas confondre avec CVE-2026-7273, exploitée en septembre 2026. | [https://infosec.exchange/@cyberseckyle/117560829726928231](https://infosec.exchange/@cyberseckyle/117560829726928231)<br>[https://www.bleepingcomputer.com/news/security/zyxel-fixes-zero-day-exploited-to-hack-nearly-1-000-network-switches/](https://www.bleepingcomputer.com/news/security/zyxel-fixes-zero-day-exploited-to-hack-nearly-1-000-network-switches/)<br>[https://infosec.exchange/@cloud/117560448666126691](https://infosec.exchange/@cloud/117560448666126691) |
| **CVE-2026-95722** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95723** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95724** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95725** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95726** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95727** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95728** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95729** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95730** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95731** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95732** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95733** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95734** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95735** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95736** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95737** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95738** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95739** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95740** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95741** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95742** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95743** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95744** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95745** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95746** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95747** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95748** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95749** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-95750** | N/A | N/A | FALSE | Fabric Composer 7.4.x < 7.4.1, < 7.3.5 ; Virtual Intranet Access (VIA) < 4.7.9 | Multiples : RCE, élévation de privilèges, DoS, SQLi, XSS, contournement | Compromission des composants réseau, accès non autorisé, perturbation de service. | None | Appliquer les correctifs HPE Aruba Networking (Fabric Composer 7.4.1/7.3.5, VIA 4.7.9). Restreindre l'accès aux interfaces d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1451/) |
| **CVE-2026-22058** | N/A | N/A | FALSE | StorageGRID 12.0.x < 12.0.0.9, 12.1.x < 12.1.0.1, < 11.9.0.15 | Atteinte à la confidentialité et à l'intégrité des données | Accès non autorisé aux données, modification ou fuite d'informations. | None | Appliquer les correctifs NetApp (StorageGRID 12.0.0.9, 12.1.0.1, 11.9.0.15). Restreindre les accès et surveiller les journaux. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1453/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1453/) |
| **CVE-2026-22060** | N/A | N/A | FALSE | StorageGRID 12.0.x < 12.0.0.9, 12.1.x < 12.1.0.1, < 11.9.0.15 | Atteinte à la confidentialité et à l'intégrité des données | Accès non autorisé aux données, modification ou fuite d'informations. | None | Appliquer les correctifs NetApp (StorageGRID 12.0.0.9, 12.1.0.1, 11.9.0.15). Restreindre les accès et surveiller les journaux. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1453/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1453/) |
| **CVE-2026-119179** | N/A | N/A | FALSE | Pilote Node.js MongoDB < 7.8.0 | Atteinte à la confidentialité et à l'intégrité des données | Accès non autorisé aux données, modification ou fuite d'informations. | None | Mettre à jour le pilote Node.js vers 7.8.0 ou supérieur. Restreindre les accès et surveiller les journaux. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1454/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1454/) |
| **CVE-2026-120572** | N/A | N/A | FALSE | Mozilla Firefox < 159.0.1 | Non spécifié par l'éditeur | Impact non spécifié, potentiellement compromission du navigateur. | None | Mettre à jour Firefox vers 159.0.1 ou supérieur. Appliquer les bonnes pratiques de navigation. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1455/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1455/) |
| **CVE-2026-97693** | N/A | N/A | FALSE | Yuxi sandbox | Défaut d'isolation du bac à sable | Un attaquant peut accéder aux données d'autres locataires et compromettre des services internes. | None | Isoler les charges de travail, appliquer les correctifs éditeur, restreindre les accès réseau et surveiller les accès inter-locataires. | [https://cvefeed.io/vuln/detail/CVE-2026-97693](https://cvefeed.io/vuln/detail/CVE-2026-97693) |
| **CVE-2026-55368** | 8.1 | N/A | FALSE | H2O HTTP server (versions antérieures au commit 48b7ae12107fd2b118e4641da49599e9aac8edd8) | Débordement de tampon (CWE-787) | Déni de service (crash) du serveur H2O. | Theoretical | Mettre à jour vers le commit 48b7ae12107fd2b118e4641da49599e9aac8edd8 ou une version ultérieure. Reconfigurer les formats de logs affectés. Surveiller les crashes. | [https://cvefeed.io/vuln/detail/CVE-2026-55368](https://cvefeed.io/vuln/detail/CVE-2026-55368) |
| **CVE-2026-102895** | N/A | N/A | FALSE | GPUStack | Contournement d'authentification via source loopback de confiance (pair TCP reverse-proxy ou en-tête X-GPUStack-Real-IP) | Prise de contrôle administrative de GPUStack. | Theoretical | Restreindre l'accès au reverse-proxy, valider les en-têtes, appliquer les correctifs et ne pas faire confiance aux en-têtes client. | [https://cvefeed.io/vuln/detail/CVE-2026-102895](https://cvefeed.io/vuln/detail/CVE-2026-102895) |
| **CVE-2026-82418** | 9.8 | N/A | FALSE | IBM Watson Speech Services Cartridge 4.0.0 à 5.4.0 | Use-after-free (CWE-416) | Exécution de code arbitraire à distance. | Theoretical | Mettre à jour vers une version corrigée. Consulter l'avis IBM. | [https://cvefeed.io/vuln/detail/CVE-2026-82418](https://cvefeed.io/vuln/detail/CVE-2026-82418) |
| **CVE-2026-13292** | 8.8 | N/A | FALSE | IBM MQ 9.2.0.0-9.2.0.44 LTS, 9.3.0.0-9.3.0.42 LTS, 9.4.0.0-9.4.0.26 LTS, 9.4.0.0-9.4.5.1 CD, 10.0.0.0-10.0.0.5 LTS et CD (Managed File Transfer) | Contrôle externe de paramètres système/configuration (CWE-15) | Exécution de code arbitraire par un attaquant authentifié. | Theoretical | Appliquer les correctifs IBM MQ. Restreindre les privilèges des comptes MQ. Surveiller les métadonnées de transfert. | [https://cvefeed.io/vuln/detail/CVE-2026-13292](https://cvefeed.io/vuln/detail/CVE-2026-13292) |
| **CVE-2026-13271** | 8.1 | N/A | FALSE | IBM MQ 9.2.0.0-9.2.0.44 LTS, 9.3.0.0-9.3.0.42 LTS, 9.4.0.0-9.4.0.26 LTS, 9.4.0.0-9.4.5.1 CD, 10.0.0.0-10.0.0.5 LTS et CD (Managed File Transfer) | Restriction incorrecte des références d'entités externes XML (CWE-611) | Fuite d'informations et déni de service. | Theoretical | Mettre à jour IBM MQ. Désactiver les entités externes XML. Restreindre les accès à la file de commandes. | [https://cvefeed.io/vuln/detail/CVE-2026-13271](https://cvefeed.io/vuln/detail/CVE-2026-13271) |
| **CVE-2026-122224** | 8.1 | N/A | FALSE | WebVirtCloud jusqu'au commit bb920b0 | Autorisation manquante (CWE-862) dans l'API REST | Atteinte à l'intégrité et à la disponibilité des VM, création de ressources non autorisées, possibilité de déplacer ou supprimer des machines d'autres locataires, et élargissement de la surface d'attaque sur les hôtes de calcul. | Theoretical | Appliquer les contrôles d'autorisation sur les endpoints API, ajouter des permission_classes explicites, restreindre par rôle, revoir les permissions des endpoints et déployer le correctif/commit de référence. En attendant, limiter l'accès à l'API aux réseaux de confiance et surveiller les appels anormaux. | [https://cvefeed.io/vuln/detail/CVE-2026-122224](https://cvefeed.io/vuln/detail/CVE-2026-122224) |
| **CVE-2026-122135** | 8.8 | N/A | FALSE | Mistral Vibe avant 3.0.3 | Exécution de code à distance via configuration de dépôt (CWE-829) | Exécution de code arbitraire avec les privilèges de l'utilisateur, vol de secrets, accès au dépôt et mouvement latéral potentiel. | Theoretical | Mettre à jour Mistral Vibe vers 3.0.3 ou ultérieur, restreindre les paramètres gpg.program des dépôts, valider les commits signés et n'ouvrir que des dépôts de confiance. | [https://cvefeed.io/vuln/detail/CVE-2026-122135](https://cvefeed.io/vuln/detail/CVE-2026-122135) |
| **CVE-2026-120422** | N/A | N/A | FALSE | Sogou Input Method pour Windows (versions antérieures à 16.10) | Détournement DNS et exécution de code via configuration non sécurisée | Déploiement d'un implant modulaire, collecte de données, persistance et surveillance d'utilisateurs ciblés. | Active | Mettre à jour Sogou Input Method vers 16.10+, bloquer les domaines et IP de staging, surveiller les résolutions DNS anormales et appliquer une politique HTTPS stricte. | [https://thehackernews.com/2026/11/china-aligned-hackers-hijack-sogou.html](https://thehackernews.com/2026/11/china-aligned-hackers-hijack-sogou.html) |
| **CVE-2026-121742** | 7.8 | N/A | FALSE | Ashlar-Vellum Cobalt (parsing des fichiers XE) | Use-after-free lors du parsing de fichiers XE | Exécution de code arbitraire sur le poste de l'utilisateur, avec les privilèges du processus Cobalt, pouvant mener au vol de données, à la persistance et au mouvement latéral. | Theoretical | Restreindre l'interaction avec Cobalt, bloquer l'ouverture de fichiers XE non fiables, appliquer une politique de moindre privilège, surveiller les éditeurs pour un correctif et isoler les postes exposés. | [http://www.zerodayinitiative.com/advisories/ZDI-26-874/](http://www.zerodayinitiative.com/advisories/ZDI-26-874/) |
| **CVE-2026-121743** | 7.8 | N/A | FALSE | Ashlar-Vellum Cobalt (parsing des fichiers AR) | Débordement de tampon basé sur le tas lors du parsing de fichiers AR | Exécution de code arbitraire sur le poste de l'utilisateur, avec les privilèges du processus Cobalt, pouvant mener au vol de données, à la persistance et au mouvement latéral. | Theoretical | Restreindre l'interaction avec Cobalt, bloquer l'ouverture de fichiers AR non fiables, appliquer une politique de moindre privilège, surveiller les éditeurs pour un correctif et isoler les postes exposés. | [http://www.zerodayinitiative.com/advisories/ZDI-26-873/](http://www.zerodayinitiative.com/advisories/ZDI-26-873/) |
| **CVE-2026-121753** | 7.8 | N/A | FALSE | Ashlar-Vellum Cobalt (parsing des fichiers XE) | Use-after-free lors du parsing de fichiers XE | Exécution de code arbitraire sur le poste de l'utilisateur, avec les privilèges du processus Cobalt, pouvant mener au vol de données, à la persistance et au mouvement latéral. | Theoretical | Restreindre l'interaction avec Cobalt, bloquer l'ouverture de fichiers XE non fiables, appliquer une politique de moindre privilège, surveiller les éditeurs pour un correctif et isoler les postes exposés. | [http://www.zerodayinitiative.com/advisories/ZDI-26-872/](http://www.zerodayinitiative.com/advisories/ZDI-26-872/) |
| **CVE-2026-121752** | 7.8 | N/A | FALSE | Ashlar-Vellum Cobalt (parsing des fichiers LI) | Débordement de tampon basé sur le tas lors du parsing de fichiers LI | Exécution de code arbitraire sur le poste de l'utilisateur, avec les privilèges du processus Cobalt, pouvant mener au vol de données, à la persistance et au mouvement latéral. | Theoretical | Restreindre l'interaction avec Cobalt, bloquer l'ouverture de fichiers LI non fiables, appliquer une politique de moindre privilège, surveiller les éditeurs pour un correctif et isoler les postes exposés. | [http://www.zerodayinitiative.com/advisories/ZDI-26-871/](http://www.zerodayinitiative.com/advisories/ZDI-26-871/) |
| **CVE-2026-121744** | 7.8 | N/A | FALSE | Ashlar-Vellum Cobalt (parsing des fichiers XE) | Débordement de tampon basé sur la pile (CWE-121) lors de la validation de la longueur des données fournies par l'utilisateur | Exécution de code arbitraire dans le contexte du processus Cobalt, donc avec les privilèges de l'utilisateur ouvrant le fichier. Un fichier XE piégé envoyé par e-mail ou déposé sur un partage peut mener au vol de données de conception, à l'installation d'un implant et à un mouvement latéral depuis le poste de travail. | Theoretical | Aucun correctif disponible à ce jour : la seule mesure efficace est de restreindre l'interaction avec le produit (ne pas ouvrir de fichiers XE non fiables, isoler les postes CAO, ouvrir les fichiers clients dans une VM jetable). Compléter par le blocage des extensions .XE au niveau mail/proxy, les protections mémoire et la supervision EDR des crashs du processus Cobalt. | [http://www.zerodayinitiative.com/advisories/ZDI-26-870/](http://www.zerodayinitiative.com/advisories/ZDI-26-870/) |
| **CVE-2026-114556** | 7.4 | N/A | FALSE | MailEnable (implémentation de la méthode Save) | Traversée de répertoire (CWE-22) permettant la création arbitraire de fichiers, sans authentification | Écriture de fichiers arbitraires sur le serveur de messagerie, permettant le dépôt d'un web shell, la modification de configurations ou l'écrasement de binaires. En chaîne avec un autre défaut, l'impact atteint l'exécution de code avec les privilèges SYSTEM, donc la compromission totale du serveur mail et des données hébergées. | Theoretical | Mettre à jour vers MailEnable 10.60 ou supérieur. En attendant, restreindre l'exposition des interfaces web (webmail, administration) par filtrage réseau, déployer un WAF avec règles anti-traversée, surveiller l'intégrité des répertoires web et journaliser les appels non authentifiés à la méthode Save. | [http://www.zerodayinitiative.com/advisories/ZDI-26-869/](http://www.zerodayinitiative.com/advisories/ZDI-26-869/) |
| **CVE-2026-122192** | N/A | N/A | FALSE | Firecracker v0.23.0 à v1.16.1 (VM restaurées depuis snapshot, backend mémoire File avec balloon ou virtio-mem) | Accès invité à la mémoire du processus hôte après échec d'un discard mémoire (défaut d'isolation VM/hôte) | Fuite ou altération de mémoire de l'hyperviseur léger : lecture de secrets d'autres tenants ou du processus hôte, corruption d'état, et potentielle évasion d'isolation dans un environnement multi-tenant. L'exploitation nécessite toutefois un accès root dans l'invité et des conditions mémoire particulières. | Theoretical | Mettre à jour vers Firecracker 1.16.2 ou 1.17.0 (les forks et code dérivés doivent intégrer les correctifs correspondants). Contournement : restaurer les snapshots avec le backend Uffd en respectant ses prérequis de gestion des pages discardées. Mesures complémentaires : overcommit heuristics sur les noyaux sans le correctif 6.12, taille de discard bornée à RAM+swap, OOM killer du cgroup mémoire activé — ces mesures ne couvrent pas tous les échecs de remplacement de mapping. | [https://aws.amazon.com/security/security-bulletins/rss/2026-169-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-169-aws/) |
| **CVE-2000-0411** | N/A | N/A | FALSE | Scripts CGI/PHP d'envoi d'e-mail exposés sur des sites web (formmail, sendmail.php, mailtest.php, testemail.php, mail_config.php) | Exposition d'informations et injection d'en-têtes via des scripts d'e-mail (classe CWE-200 / CWE-20), illustrée par CVE-2000-0411 | Divulgation de variables d'environnement et d'éléments de configuration serveur, envoi de courriels arbitraires (relais de spam, phishing), et, dans les cas les plus défavorables, exécution de code si les paramètres utilisateur atteignent le binaire sendmail. Le risque sous-jacent est un défaut d'hygiène de code : des artefacts de développement accessibles publiquement. | Theoretical | Supprimer tout script de test ou de debug de la production, contrôler les déploiements en CI/CD, valider et assainir les paramètres destinés aux en-têtes mail, restreindre les droits du binaire de messagerie, filtrer les chemins au WAF et scanner régulièrement ses propres sites à la recherche de ces URL. | [https://isc.sans.edu/diary/rss/33488](https://isc.sans.edu/diary/rss/33488) |
| **CVE-2026-4792** | 5.3 | N/A | FALSE | Plugin Bread pour WordPress, versions jusqu'à 2.9.12 incluse | Exposition d'informations / autorisation manquante (CWE-862) dans la fonction download_settings | Divulgation de l'ensemble de la configuration du plugin et du mot de passe de protection des PDF en clair, permettant l'accès non autorisé à des contenus protégés (listes de réunion et documents assimilés) et une manipulation de configuration. La compromission du mot de passe peut faciliter un mouvement latéral au sein de l'installation WordPress. | Theoretical | Aucun patch confirmé : auditer les sites utilisant Bread, désactiver le plugin ou bloquer l'endpoint /?export-meeting-list=1 au WAF, restreindre l'accès public aux fonctions d'export, considérer le protection_password comme compromis et le changer, puis appliquer le correctif dès sa publication. | [https://www.valtersit.com/cve/CVE-2026-4792/](https://www.valtersit.com/cve/CVE-2026-4792/) |
| **** | N/A | N/A | FALSE | Ruby on Rails 8.x < 8.1.4.1, < 8.0.5.2 | Multiples : RCE, DoS, XSS, contournement | Exécution de code arbitraire, déni de service, atteinte à la confidentialité et à l'intégrité des données. | None | Mettre à jour vers Rails 8.1.4.1 ou 8.0.5.2. Restreindre les entrées non fiables et surveiller les logs. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1452/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1452/) |
| **** | N/A | N/A | FALSE | Laravel < 13.40.0 | Exécution de code arbitraire à distance | Exécution de code arbitraire à distance, compromission du serveur. | None | Mettre à jour Laravel vers 13.40.0 ou supérieur. Restreindre les entrées non fiables et surveiller les logs. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1457/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1457/) |
| **** | N/A | N/A | FALSE | Mattermost Desktop App 6.3.x < 6.3.1, 6.x < 6.2.5 ; Mattermost Server 11.10.x < 11.10.3, 11.11.x < 11.11.2, 11.7.x < 11.7.12 | Non spécifié par l'éditeur | Impact non spécifié, potentiellement compromission des services de messagerie. | None | Appliquer les correctifs Mattermost indiqués. Restreindre les accès et surveiller les journaux. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1458/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1458/) |
| **** | N/A | N/A | FALSE | Composants Symfony : filesystem, http-client, http-foundation, json-path, routing, security-http, serializer, symfony, yaml (versions 5.4.x < 5.4.56, 6.x < 6.4.50, 7.x < 7.4.23, 8.x < 8.1.11) | Multiples vulnérabilités (déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Un attaquant distant peut provoquer un déni de service, accéder à des données sensibles ou contourner des mécanismes de sécurité selon le composant vulnérable. | None | Appliquer les correctifs des avis GHSA référencés (mise à jour vers 5.4.56, 6.4.50, 7.4.23 ou 8.1.11 selon la branche). Vérifier les versions déployées et planifier la mise à jour. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1460/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1460/) |
| **** | N/A | N/A | FALSE | APM Server, Elastic Agent, Elastic Docker Images, Elastic Maps Server, Elasticsearch, Heartbeat, Kibana, Logstash, Packetbeat (versions 8.x < 8.19.24, 9.x < 9.4.9, 9.5.x < 9.5.6) | Multiples vulnérabilités (exécution de code arbitraire à distance, déni de service à distance, atteinte à la confidentialité et à l'intégrité des données) | Un attaquant distant peut exécuter du code arbitraire, provoquer un déni de service ou accéder à des données sensibles selon le produit vulnérable. | None | Appliquer les correctifs des bulletins Elastic ESA-2026-200 à ESA-2026-220. Mettre à jour vers 8.19.24, 9.4.9 ou 9.5.6 selon la branche. Vérifier les versions déployées et planifier la mise à jour. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1461/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1461/) |
| **** | 9.8 | N/A | FALSE | Ruby on Rails Active Storage avec ImageMagick (versions avant 8.0.5.2 et 8.1 avant 8.1.4.1) | Écriture arbitraire de fichiers via téléversement et ImageMagick | Écriture et lecture arbitraires de fichiers, vol de secrets, exécution de code à distance ou mouvement latéral via les identifiants dérobés. | Theoretical | Mettre à jour vers 8.1.4.1 ou 8.0.5.2, restreindre les codeurs ImageMagick via policy, désactiver mini_magick au profit de vips si possible, limiter les téléversements non fiables et renouveler les secrets exposés. | [https://thehackernews.com/2026/11/critical-rails-flaw-lets-attackers.html](https://thehackernews.com/2026/11/critical-rails-flaw-lets-attackers.html) |
| **** | N/A | N/A | FALSE | Sessions d'agents IA de codage (Claude Code, Cursor) — télémétrie et supervision | Sans objet — article de threat hunting sur la détection des comportements d'agents IA | Sans vulnérabilité logicielle associée : le risque décrit est l'exfiltration involontaire ou malveillante de données par des agents disposant de permissions légitimes, invisible pour les contrôles par signature. L'impact potentiel va de la fuite de données clients à la compromission d'un dépôt de code, avec un volume d'actions très élevé par session. | None | Journaliser et vectoriser les sessions d'agents dès l'ingestion, appliquer des seuils de similarité pour ne transmettre que les cas à risque à un analyste ou un LLM, construire des règles à partir des sessions malveillantes connues, et restreindre les permissions des agents (périmètre fichiers, accès réseau, dépôts autorisés). | [https://www.elastic.co/security-labs/blog/ai-agent-session-monitoring-embedding-models](https://www.elastic.co/security-labs/blog/ai-agent-session-monitoring-embedding-models) |
| **** | N/A | N/A | FALSE | Chaîne d'approvisionnement logicielle et pile d'entreprise : agents RMM, assistants IA de codage, clients first-party Microsoft, paquets npm, flux d'identité SaaS | Sans objet — rapport CTI sur l'abus de la confiance accordée aux logiciels légitimes (trust abuse) | Accès persistant et interactif sur des endpoints contestés via des outils approuvés, compromission de tenants cloud et SaaS par vol de session, et exfiltration à grande vitesse. Les signatures et les contrôles de sécurité modérés ne suffisent plus : la frontière entre comportement bénin et malveillant devient floue dès lors que l'attaquant agit au nom d'utilisateurs et de logiciels de confiance. | None | Adopter l'UEBA pour établir une baseline, corréler plusieurs domaines (endpoint, identité, cloud, conteneurs), durcir l'identité (authentification résistante au phishing, suppression du legacy, revue des applications pré-autorisées), maintenir une liste blanche stricte des RMM et surveiller les consentements OAuth ainsi que la chaîne d'approvisionnement npm. | [https://www.elastic.co/security-labs/reports/threats-etc-report-november-2026-trouble-with-trust](https://www.elastic.co/security-labs/reports/threats-etc-report-november-2026-trouble-with-trust) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="labus-didentite-dapplication-cible-les-msp-et-les-environnements-clients"></div>

## L'abus d'identité d'application cible les MSP et les environnements clients

### Résumé

Le 3 novembre 2026, des chercheurs ont divulgué une campagne d'intrusion en cours dans laquelle un acteur de menace utilise des identifiants d'application valides, appartenant aux applications des victimes, pour s'authentifier directement auprès de Microsoft Entra ID et d'Azure DevOps. L'activité a été observée pour la première fois le 1er novembre 2026 et restait active le 3 novembre, la dernière tentative connue étant survenue à 21h31 UTC. Les cibles principales sont les fournisseurs de services managés (MSP) et leurs clients, en particulier ceux qui s'appuient sur des applications cloud, des identités de charge de travail et de l'administration déléguée multi-tenant. L'attaquant se connecte en tant qu'applications de confiance et rejoue des sessions de développeurs, héritant des accès déjà détenus par ces applications ; l'origine de l'obtention des identifiants reste sous investigation. Toute l'activité malveillante confirmée provient d'une seule adresse IP, 199.19.77[.]84, chez un hébergeur géolocalisé en Pologne. Après authentification, l'opérateur a récupéré des secrets et identifiants stockés ; des applications jusque-là inutilisées ont commencé à s'authentifier en quelques minutes, suggérant une extension de l'accès. L'attaquant a ensuite recherché et consulté des boîtes mail et espaces de fichiers sur plusieurs tenants, collectant des fichiers contenant des identifiants et configurations de VPN, d'outils RMM, de sauvegardes et de pare-feu. Des applications multi-tenant MSP et des tokens Partner Center ont été utilisés pour atteindre les environnements clients, ainsi que des applications GDAP ; des applications d'intégration d'outils de sécurité (dont celles de Todyl dans deux tenants MSP) figurent parmi les identifiants abusés, sans indice de compromission de la plateforme de l'éditeur. Après les détections du 3 novembre 2026, l'attaquant a basculé vers des signatures de navigateur usurpées puis vers le rejeu de refresh tokens d'utilisateurs, tout en réessayant les applications désactivées et rotées dans des boucles fixes de 11 secondes ; Conditional Access a bloqué tous les rejeux de tokens observés ce jour-là.

---

### Analyse opérationnelle

L'angle d'attaque est l'identité applicative, pas le compte utilisateur : les connexions de service principals ne déclenchent pas de MFA, échappent aux politiques Conditional Access centrées utilisateur et ne sont pas vues par les pare-feu on-prem. Les équipes SOC doivent donc déplacer une partie de leur détection vers les journaux de connexion des service principals, les journaux d'audit Azure DevOps et les journaux d'accès aux données (mail, SharePoint/OneDrive). Les signaux à fort rendement sont : authentification d'une application inactive depuis longtemps, connexion depuis une IP d'hébergement ou une géolocalisation inhabituelle, ajout de secret/certificat à une application, pic d'authentifications sur plusieurs tenants en quelques minutes, et requêtes de recherche de mots-clés de type credential dans les boîtes mail. Le rejeu de refresh tokens et les signatures de navigateur usurpées sur des flux non interactifs constituent des indicateurs comportementaux exploitables. Côté réponse, la rotation des secrets d'application est l'action la plus urgente et la plus large : elle doit être coordonnée sur l'ensemble des tenants clients du MSP, car un secret partagé peut rouvrir l'accès. La révocation des refresh tokens et des PAT Azure DevOps est nécessaire pour couper la persistance. Les applications d'intégration d'outils de sécurité et de RMM sont des cibles de rebond : leur compromission donne un accès latéral aux environnements clients et permet la collecte d'identifiants d'infrastructure.

---

### Implications stratégiques

Le modèle MSP concentre le risque : une application de gestion multi-tenant compromise vaut des dizaines de compromissions de comptes utilisateurs, avec un retour sur effort très supérieur pour l'attaquant. La campagne illustre un déplacement structurel des attaques vers les identités de charge de travail, souvent dotées de permissions étendues, de secrets à longue durée de vie et d'une visibilité opérationnelle faible. Les organisations qui ont durci la protection des comptes utilisateurs sans traiter les applications ont déplacé le point de rupture sans le réduire. La dépendance à des licences additionnelles pour protéger les identités de charge de travail, et l'exclusion fréquente des applications multi-tenant des politiques Conditional Access, créent un angle mort structurel précisément là où les MSP en ont le plus besoin. Pour les dirigeants, cela se traduit par un risque de responsabilité en chaîne (le MSP comme vecteur vers ses clients), un besoin de clauses contractuelles sur la rotation des secrets et la notification d'incident, et une priorisation budgétaire de la gouvernance des identités applicatives au même niveau que la protection des endpoints.

---

### Recommandations

* Inventorier et classer toutes les applications et identités de charge de travail avec propriétaire, permissions, tenants accessibles et date de dernière rotation des secrets.
* Imposer une rotation des secrets d'application à durée limitée et un stockage en coffre-fort avec journalisation des accès.
* Étendre Conditional Access aux identités de charge de travail et documenter précisément les exclusions multi-tenant.
* Activer l'alerting sur la création d'applications, l'ajout de secrets/certificats et l'octroi de consentements admin.
* Bloquer ou alerters sur les authentifications de service principals depuis des ASN d'hébergement et géolocalisations à risque.
* Journaliser et corréler Azure DevOps (PAT, sessions) avec Entra ID pour détecter le rejeu de sessions développeur.
* Réduire et revoir trimestriellement les délégations GDAP/DAP accordées aux applications du MSP.
* Préparer un plan de rotation d'urgence multi-tenant incluant les identifiants d'outils tiers (RMM, sécurité, sauvegarde, VPN, pare-feu).

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier toutes les inscriptions d'applications et identités de charge de travail (service principals) avec leurs permissions, propriétaires et dates de création/rotation de secrets.
* Recenser les applications multi-tenant, les applications GDAP et les tokens Partner Center utilisés par le MSP, avec la liste des tenants clients accessibles.
* Activer et centraliser les journaux de connexion des service principals (Entra ID), les journaux d'audit Azure DevOps et les journaux d'accès aux boîtes mail/SharePoint.
* Mettre en place une politique de rotation des secrets d'application (≤ 90 jours) et un coffre-fort de secrets avec accès journalisé.
* Vérifier la couverture des politiques Conditional Access pour les identités de charge de travail et documenter les exclusions (applications multi-tenant).

#### Phase 2 — Détection et analyse

* Surveiller les connexions de service principals depuis des IP d'hébergement ou des géolocalisations inhabituelles (ex. Pologne) et hors fenêtres de production.
* Détecter l'activation soudaine d'applications jusqu'alors inactives et les pics d'authentification sur plusieurs tenants en quelques minutes.
* Alerter sur les ajouts de secrets/certificats à des applications existantes, les modifications de permissions ou de propriétaires d'applications.
* Corréler les accès massifs aux boîtes mail et espaces de fichiers avec des requêtes de recherche de mots-clés (VPN, RMM, backup, firewall, password).
* Détecter les rejeux de refresh tokens, les signatures de navigateur incohérentes et les tentatives répétées sur des applications désactivées ou rotées (boucles régulières ~11 s).

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement les secrets et certificats des applications compromises et forcer leur rotation sur tous les tenants concernés.
* Désactiver les service principals malveillants ou non nécessaires et retirer les permissions excessives (admin consent, rôles applicatifs élevés).
* Bloquer l'IP 199.19.77[.]84 et les plages d'hébergement associées au niveau des accès conditionnels nommés et des passerelles cloud.
* Révoquer les refresh tokens et sessions développeur actives (Azure DevOps PAT, sessions navigateur) pour les comptes et applications touchés.
* Notifier les clients du MSP impactés et coordonner la rotation des identifiants d'intégration tiers (RMM, sécurité, sauvegarde).

#### Phase 4 — Activités post-incident

* Reconstruire la chronologie complète à partir des journaux Entra ID, Azure DevOps et accès données pour établir le périmètre de collecte.
* Identifier les secrets exposés (VPN, RMM, sauvegardes, pare-feu) et imposer leur rotation chez le MSP et chez les clients.
* Revoir le modèle de délégation (GDAP, DAP) et appliquer le moindre privilège avec revue trimestrielle des consentements applicatifs.
* Renforcer la gouvernance des identités de charge de travail : propriétaire nommé, justification métier, durée de vie limitée, alerting sur création.
* Mettre à jour les procédures de réponse et réaliser un exercice de crise incluant la notification réglementaire si des données clients ont fuité.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux Entra ID toutes les authentifications de service principals depuis des ASN d'hébergement (VPS, colocation) sur les 90 derniers jours.
* Traquer les User-Agent/signatures de navigateur anormales sur des connexions non interactives et les incohérences entre type de client et ressource ciblée.
* Rechercher les requêtes de recherche de type « credential », « vpn », « rmm », « backup » dans les boîtes mail et SharePoint via les journaux d'audit unifiés.
* Identifier les applications dont les secrets n'ont jamais été rotés et celles dont l'activité a démarré brutalement après une longue période d'inactivité.
* Chasser les tentatives répétées à intervalle fixe sur des applications désactivées, indicateur d'un outil automatisé de rejeu de tokens.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| IP | `199.19.77[.]84` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078.004** | Valid Accounts: Cloud Accounts — authentification avec des identifiants d'application valides des victimes |
| **T1528** | Steal Application Access Token — vol et réutilisation de secrets/tokens d'applications |
| **T1550.001** | Use Alternate Authentication Material: Application Access Token — rejeu de sessions développeur et de refresh tokens |
| **T1552.001** | Unsecured Credentials: Credentials In Files — collecte de fichiers contenant des identifiants VPN, RMM, sauvegardes, pare-feu |
| **T1114.002** | Email Collection: Remote Email Collection — recherche et accès aux boîtes mail multi-tenant |
| **T1530** | Data from Cloud Storage — accès aux espaces de fichiers et partages cloud |
| **T1098.001** | Account Manipulation: Additional Cloud Credentials — usage d'applications jusque-là inactives pour étendre l'accès |

---

### Sources

* [https://fieldeffect.com/blog/application-identity-abuse-msps-customer-environments](https://fieldeffect.com/blog/application-identity-abuse-msps-customer-environments)


---

<div id="sentinelone-prompt-security-comment-la-console-sarticule"></div>

## SentinelOne Prompt Security : comment la console s'articule

### Résumé

L'article est un guide de prise en main de la console SentinelOne Prompt Security, qui centralise la protection de l'usage salarié de l'IA générative. L'auteur décrit quatre onglets complémentaires : Security Rules (qui, quelle application d'IA, quelle plateforme, quel mode — watch, protect, block ou ignore — et quelle politique associée), Policies (ce qu'il faut rechercher dans un prompt : secrets, données personnelles, motifs personnalisés, sujets, et l'action à appliquer : masquer ou bloquer), Sensor Settings (comportement de l'extension navigateur et de l'agent endpoint) et User Education (pages d'avertissement, messages de blocage, pop-ups vus par l'employé). La logique est résumée ainsi : la règle décide si et comment, la politique décide quoi, le capteur exécute, l'éducation utilisateur communique. Les règles sont évaluées de haut en bas, la première correspondance l'emportant, avec des colonnes Priorité, Utilisateurs, Applications, Plateforme, Mode et Avancé. Deux règles verrouillées existent en bas de liste : une règle par défaut (tous utilisateurs / toutes applications / Detect / politique employés par défaut) et une règle pour les assistants de code IA (Detect / politique développeurs par défaut). Les applications majeures sont dédoublées en versions personnelle et entreprise (ChatGPT, Claude, Gemini, Copilot, Perplexity). Les quatre modes sont détaillés : Detect inspecte et journalise mais laisse passer le prompt, Protect applique l'action de la politique (masquage ou blocage), Block bloque l'application sans lire le contenu, Don't Track n'inspecte ni ne journalise. La section Avancé masque des réglages importants : protection des données (blocage du collage, blocage et inspection des uploads, blocage du téléchargement de fichiers), journalisation (toutes les interactions ou seulement les violations, y compris les réponses de l'IA) et éducation utilisateur. L'auteur souligne un piège vécu : une politique réglée sur « Block » ne bloque rien si la règle qui la référence est en mode Detect, ce qui produit un tableau de bord à 0 % de blocage.

---

### Analyse opérationnelle

Ce contenu est directement exploitable pour le déploiement d'une couche DLP sur les usages d'IA générative. Le point critique pour les équipes SecOps est la séparation règle/politique/mode : une politique correctement paramétrée reste sans effet si la règle associée est en mode Detect, ce qui donne une fausse impression de protection et un tableau de bord trompeur. La priorité des règles étant évaluée de haut en bas avec première correspondance, une règle trop large placée en tête neutralise toutes les règles spécifiques suivantes : l'ordre est un élément de configuration à contrôler et à revoir à chaque changement. Les réglages de la section Avancé (blocage du collage, inspection des fichiers uploadés, blocage du téléchargement, journalisation des réponses de l'IA) sont les contrôles réellement efficaces contre la fuite de secrets et de code, et ils ne sont pas visibles dans la vue principale. La journalisation des réponses de l'IA est utile pour l'investigation a posteriori mais augmente le volume de données sensibles stockées : à arbitrer avec la politique de rétention. La distinction comptes personnels / comptes entreprise permet de traiter différemment l'usage shadow AI, et la couverture conjointe extension navigateur + agent endpoint est nécessaire pour couvrir les clients desktop.

---

### Implications stratégiques

L'adoption massive d'assistants IA génératifs crée un canal d'exfiltration volontaire ou accidentel que les DLP classiques couvrent mal, car le vecteur est le copier-coller et l'upload dans une application SaaS légitime. Pour les dirigeants, l'enjeu est double : protéger le patrimoine informationnel (code source, secrets, données personnelles, informations stratégiques) et encadrer juridiquement les transferts vers des services tiers, avec un risque RGPD direct en cas de fuite de données personnelles. La distinction entre comptes personnels et entreprise est aussi un enjeu de conformité contractuelle et de responsabilité. Le risque opérationnel majeur n'est pas l'absence d'outil mais la mauvaise configuration : un mode Detect généralisé produit un sentiment de sécurité sans réduction du risque. Cela plaide pour un contrôle de configuration régulier, des tests de couverture réels et une gouvernance claire entre sécurité, juridique et métiers, plutôt que pour l'empilement d'outils.

---

### Recommandations

* Vérifier systématiquement que les règles référençant une politique de blocage sont en mode Protect ou Block, jamais Detect.
* Contrôler l'ordre de priorité des règles et placer les règles spécifiques (développeurs, données sensibles) avant la règle par défaut.
* Activer le blocage du collage et l'inspection des fichiers uploadés pour les populations manipulant secrets et code propriétaire.
* Journaliser au minimum les violations et exporter les journaux vers le SIEM pour corrélation avec les accès aux dépôts de code et partages cloud.
* Traiter séparément les applications en comptes personnels et en comptes entreprise, avec blocage ou avertissement renforcé sur le personnel.
* Déployer à la fois l'extension navigateur et l'agent endpoint pour couvrir les clients desktop.
* Tester la couverture par des prompts contrôlés contenant des données sensibles et mesurer le taux de blocage effectif.
* Documenter les exceptions et les réviser périodiquement avec le juridique et les métiers.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les applications d'IA autorisées et non autorisées utilisées dans l'entreprise (web et clients desktop) et distinguer comptes personnels et comptes entreprise.
* Définir une politique de données pour l'IA : catégories à bloquer (secrets, données personnelles, code propriétaire) et catégories à masquer.
* Configurer les règles par priorité, par population (utilisateurs, groupes issus de l'IdP) et par application, en vérifiant que le mode est bien Protect ou Block et non Detect.
* Activer la journalisation de toutes les interactions ou des seules violations, y compris la journalisation des réponses de l'IA, et l'orienter vers le SIEM.
* Préparer les messages d'éducation utilisateur (page d'avertissement, pop-up de violation, message de blocage) et une procédure de demande d'exception.

#### Phase 2 — Détection et analyse

* Surveiller les violations de politique par détecteur (secrets, données personnelles, motifs métier, sujets) et par utilisateur/équipe.
* Alerter sur les tentatives répétées de collage de contenu, d'upload de fichiers ou de téléchargement de fichiers vers des applications d'IA.
* Détecter l'usage d'applications d'IA en comptes personnels depuis des postes d'entreprise et l'usage de clients desktop non couverts par l'extension navigateur.
* Corréler les violations avec les journaux d'accès aux dépôts de code et aux partages de fichiers pour identifier une exfiltration réelle.
* Vérifier l'écart entre politiques configurées en « block » et taux de blocage effectif à 0 %, signe d'une règle en mode Detect.

#### Phase 3 — Confinement, éradication et récupération

* Basculer la règle concernée du mode Detect vers Protect ou Block pour arrêter la fuite en cours.
* Bloquer l'application ou la catégorie d'applications pour la population concernée et révoquer l'accès si un compte personnel est utilisé.
* Faire tourner immédiatement tout secret ou clé API identifié comme ayant été saisi dans un prompt.
* Isoler le poste ou le compte en cas de fuite massive et préserver les journaux d'interaction pour l'investigation.
* Notifier l'utilisateur et son manager via le canal d'éducation configuré, avec rappel de la politique.

#### Phase 4 — Activités post-incident

* Évaluer la nature et le volume des données exposées et déterminer si une notification réglementaire (RGPD, sectorielle) est requise.
* Ajuster les détecteurs et les motifs personnalisés pour réduire les faux positifs et couvrir les nouvelles applications d'IA observées.
* Revoir la matrice règle/politique/mode pour éliminer les configurations incohérentes et documenter les exceptions accordées.
* Mesurer l'évolution du taux de violations et du taux de blocage effectif sur 30/60/90 jours et présenter les résultats à la direction.
* Mettre à jour le programme de sensibilisation avec des exemples réels anonymisés issus de l'incident.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux proxy/DNS les domaines d'applications d'IA non couvertes par la politique et les volumes d'upload anormaux.
* Analyser les journaux d'interaction pour identifier des motifs de secrets (clés API, tokens, chaînes de connexion) ayant transité sans détection.
* Rechercher les comptes utilisateurs ayant un usage intensif d'IA en dehors des heures ouvrées ou depuis des localisations inhabituelles.
* Corréler les dépôts de code et les partages cloud avec les horodatages d'interactions IA pour détecter une exfiltration de code propriétaire.
* Tester périodiquement la couverture réelle en simulant des prompts contenant des données sensibles et vérifier que le blocage effectif se produit.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1567** | Exfiltration Over Web Service — envoi de données sensibles vers des applications d'IA génératives |
| **T1530** | Data from Cloud Storage — copier/coller et upload de fichiers vers des services externes |
| **T1552.001** | Unsecured Credentials: Credentials In Files — secrets et clés API saisis dans des prompts |

---

### Sources

* [https://www.cyberengage.org/post/sentinelone-prompt-security-how-the-console-fits-together](https://www.cyberengage.org/post/sentinelone-prompt-security-how-the-console-fits-together)


---

<div id="apres-les-arrestations-de-shinyhunters-en-septembre-bataille-autour-du-nom-de-la-marque"></div>

## Après les arrestations de ShinyHunters en septembre : bataille autour du nom de la marque

### Résumé

Article publié le 4 novembre 2026 par l'équipe de recherche de Flare, signé Jon DiMaggio, présenté comme la partie 2 d'une série consacrée aux suites des arrestations de septembre visant le groupe ShinyHunters. Le texte porte sur la lutte autour du nom de la marque après « Rey » et renvoie à une partie 1 pour le contexte des arrestations. Le contenu détaillé de l'article n'est pas restitué dans la source collectée, qui contient essentiellement du code de mise en page.

---

### Analyse opérationnelle

L'intérêt opérationnel porte sur la crédibilité des revendications : lorsqu'un groupe est décapité ou voit son nom devenir un actif disputé, des imitateurs peuvent reprendre la marque pour revendiquer des fuites, relancer des campagnes d'extorsion ou vendre des données non vérifiées. Les équipes SOC et gestion de crise doivent donc traiter chaque revendication comme non fiable par défaut et la corroborer par des preuves techniques internes (journaux d'accès, exports anormaux, échantillons fournis) avant d'engager une réponse coûteuse. La surveillance des canaux de revendication et des places de marché doit être maintenue même après des arrestations, car la disparition d'un acteur ne réduit pas mécaniquement le risque de fuite : les données déjà exfiltrées restent en circulation et les imitateurs exploitent la notoriété de la marque.

---

### Implications stratégiques

Les arrestations de figures d'un groupe d'extorsion sont souvent présentées comme une victoire, mais elles fragmentent l'écosystème : les données volées continuent d'être diffusées ou revendues, et la marque devient un actif réutilisable par des acteurs opportunistes. Pour les dirigeants, cela signifie que le risque de fuite ne s'éteint pas avec une arrestation et que la communication de crise doit résister à des revendications possiblement frauduleuses. La lutte pour le nom illustre aussi la porosité entre groupes criminels et la difficulté d'attribution, ce qui doit modérer les conclusions hâtives dans les dossiers de notification et les décisions d'indemnisation ou de négociation.

---

### Recommandations

* Traiter toute revendication d'extorsion comme non vérifiée jusqu'à corroboration par des preuves techniques internes.
* Maintenir une veille active sur les canaux de revendication et les places de marché même après des arrestations.
* Documenter les indicateurs d'authenticité des revendications (échantillons, métadonnées, cohérence) dans une procédure dédiée.
* Coordonner toute communication externe avec le juridique et les autorités, sans contact direct non encadré.
* Renforcer la détection des exports massifs et des accès anormaux aux partages cloud et aux sauvegardes.
* Prévoir un scénario de crise incluant une revendication frauduleuse ou usurpée.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier l'exposition de l'organisation aux fuites de données revendiquées par des groupes d'extorsion et surveiller les canaux de revente et de revendication.
* Mettre en place une veille sur les usurpations de marque de groupes de menace (comptes, canaux, sites clones) pour distinguer les acteurs légitimes des imitateurs.
* Définir une procédure de vérification d'authenticité d'une revendication (échantillons, métadonnées, cohérence temporelle) avant toute communication.
* Préparer les canaux de crise : juridique, communication, autorités, prestataire de réponse à incident et éventuel négociateur.
* Vérifier la couverture de détection sur les vecteurs d'exfiltration typiques (accès SaaS, VPN, partages cloud) et la disponibilité des journaux.

#### Phase 2 — Détection et analyse

* Surveiller les mentions de la marque de l'organisation sur les canaux de revendication et les places de marché de données.
* Détecter les accès anormaux aux partages cloud, aux sauvegardes et aux systèmes d'authentification pouvant précéder une exfiltration.
* Alerter sur les créations de comptes et de canaux usurpant une identité de groupe de menace connue.
* Corréler les revendications publiques avec les journaux internes pour confirmer ou infirmer une compromission réelle.
* Suivre les indicateurs de réutilisation de marque (mêmes pseudonymes, mêmes formats de message) pour évaluer la crédibilité d'une revendication.

#### Phase 3 — Confinement, éradication et récupération

* En cas de fuite confirmée, révoquer les accès compromis, faire tourner les identifiants exposés et isoler les systèmes concernés.
* Activer la cellule de crise et appliquer la stratégie de communication validée, sans contact direct non encadré avec les extorqueurs.
* Bloquer les canaux et comptes usurpateurs identifiés et demander leur retrait aux plateformes concernées.
* Préserver les preuves (échantillons de données, messages, horodatages) pour l'investigation et les autorités.
* Évaluer l'obligation de notification aux autorités de contrôle et aux personnes concernées selon la nature des données.

#### Phase 4 — Activités post-incident

* Consolider le retour d'expérience sur la chaîne de détection et le délai de confirmation de la compromission.
* Renforcer les contrôles ayant échoué (gestion des accès, segmentation, sauvegardes immuables, surveillance des exports massifs).
* Mettre à jour la veille sur les groupes d'extorsion et leurs avatars pour anticiper les usurpations de marque.
* Réviser le plan de communication de crise à la lumière de la couverture médiatique et des revendications non fondées.
* Suivre l'évolution du marché des données volées pour détecter une réutilisation des données de l'organisation.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des exports massifs et des accès inhabituels aux API de partage cloud sur les 90 derniers jours.
* Traquer les authentifications réussies depuis des infrastructures d'anonymisation sur les comptes à privilèges et les comptes de service.
* Rechercher sur les canaux publics et les places de marché des échantillons attribués à l'organisation ou à ses partenaires.
* Identifier les comptes et canaux réutilisant des noms, logos ou formats de message associés au groupe pour cartographier les imitateurs.
* Vérifier l'intégrité des sauvegardes et l'absence d'accès non autorisé aux infrastructures de sauvegarde.

---

### Sources

* [https://flare.io/learn/resources/blog/shinyhunters-arrests-brand-name-fight](https://flare.io/learn/resources/blog/shinyhunters-arrests-brand-name-fight)


---

<div id="fusionner-la-pr-6549-de-shaivarth-correction-des-barres-obliques-inverses-de-debut-dans-originalfilename"></div>

## Fusionner la PR #6549 de @Shaivarth - Correction des barres obliques inverses de début dans OriginalFileName

### Résumé

Commit de merge de la pull request #6549 dans le dépôt public SigmaHQ/sigma, portant sur la correction de la gestion des barres obliques inverses (backslash) en début de valeur dans le champ OriginalFileName des règles Sigma. Aucun détail technique supplémentaire n'est fourni dans la source (texte vide).

---

### Analyse opérationnelle

Le champ OriginalFileName est un artefact d'exécution Windows fréquemment utilisé dans les règles Sigma pour détecter des binaires renommés ou des LOLBins. Une valeur commençant par un antislash peut ne pas correspondre à la valeur réellement journalisée par les capteurs (Sysmon EventID 1, EDR), ce qui produit des règles silencieusement inefficaces. Les équipes de détection doivent rejouer la conversion vers leur backend (Splunk, Elastic, Sentinel, QRadar) et vérifier la couverture réelle après mise à jour, car une règle qui ne déclenche jamais ne génère aucune alerte d'erreur.

---

### Implications stratégiques

La qualité du contenu de détection open source conditionne directement la posture défensive des organisations qui consomment Sigma sans revue interne. Cet épisode illustre la dépendance à une chaîne d'approvisionnement communautaire pour les règles de détection et la nécessité d'un contrôle qualité interne avant industrialisation.

---

### Recommandations

* Revalider la conversion et le déclenchement effectif des règles Sigma modifiées sur un corpus de test avant production.
* Mettre en place un test de non-régression automatisé sur les champs de type chemin/nom de fichier.
* Assurer une revue interne des contributions communautaires critiques avant déploiement en production.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Geler la version du dépôt SigmaHQ utilisée en production et documenter le pipeline de conversion (sigma-cli, backends SIEM ciblés).
* Disposer d'un banc de test permettant de rejouer les règles modifiées sur un corpus d'événements de référence avant tout déploiement.

#### Phase 2 — Détection et analyse

* Identifier les règles de production utilisant le champ OriginalFileName et repérer celles dont la valeur commence par un antislash.
* Comparer le comportement de détection avant/après la correction sur des échantillons de processus légitimes et malveillants.

#### Phase 3 — Confinement, éradication et récupération

* Suspendre la diffusion des règles impactées tant que la conversion vers le backend SIEM n'a pas été revalidée.
* Revenir à la version précédente du dépôt en cas de régression de couverture détectée en production.

#### Phase 4 — Activités post-incident

* Documenter l'écart de détection constaté et mettre à jour la procédure de revue des contributions communautaires.
* Ajouter un contrôle automatisé (lint/test) sur les champs de type chemin de fichier dans le pipeline CI des règles.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétroactivement les exécutions où OriginalFileName contient un antislash initial afin d'évaluer si une règle défaillante a masqué une activité suspecte.
* Croiser avec les données EDR (chemin réel, hachage, signataire) pour reconstruire les cas non détectés.

---

### Sources

* [https://github.com/SigmaHQ/sigma/commit/45ed57b96940902c4fd15feae8dfc06cde7510c3](https://github.com/SigmaHQ/sigma/commit/45ed57b96940902c4fd15feae8dfc06cde7510c3)


---

<div id="comment-exporter-les-journaux-exabeam-securonix-et-arcsight-pour-une-enquete"></div>

## Comment exporter les journaux Exabeam, Securonix et ArcSight pour une enquête

### Résumé

Trois guides pratiques de SOC Prime décrivent l'extraction d'événements depuis trois plateformes SIEM/UEBA. Pour Exabeam (New-Scale), l'export passe par l'obtention d'un jeton via /auth/v1/token avec client_id et client_secret, puis un appel POST à /search/v2/events avec filtre Lucene, fenêtre temporelle, liste de champs et limite (10 000 par défaut) ; l'hôte régional suit le motif api.<region>.exabeam.cloud. Pour Securonix, un jeton est généré via /ws/token/generate (validité paramétrable), puis la requête Spotter est exécutée via /ws/spotter/index/search avec eventtime_from/eventtime_to ; les données anciennes peuvent se trouver hors du stockage chaud. Pour ArcSight, trois options sont décrites : recherche et export dans Logger, transfert CEF vers un collecteur syslog (rsyslog UDP/TCP 514) ou API REST de Logger ; l'article souligne que le texte brut de l'événement n'est conservé que si la préservation du raw event a été activée sur les SmartConnectors. Les trois guides mentionnent la possibilité de charger les fichiers JSONL obtenus dans la plateforme LogTotal après nettoyage, et citent les volumétries de règles Prime Core (15 635 pour Exabeam, 14 283 pour Securonix, 21 311 pour ArcSight).

---

### Analyse opérationnelle

Ces procédures sont directement réutilisables par un analyste SOC pour extraire un périmètre d'investigation (par exemple un hôte compromis sur une fenêtre de 24 h) et l'analyser hors production. Points d'attention techniques : la limite de résultats impose de découper les fenêtres temporelles ; la pagination Securonix doit être suivie via l'identifiant de requête ; en ArcSight, l'absence de préservation du raw event prive l'analyste des champs non mappés en CEF et de la formulation exacte d'origine, ce qui peut faire échouer une détection ; l'usage d'UDP syslog tronque les longues lignes CEF, TCP est recommandé. Sur le plan sécurité, l'export produit des fichiers contenant de la télémétrie potentiellement sensible (noms d'utilisateurs, adresses IP internes, chemins, commandes) : le téléversement vers un service d'analyse externe constitue un transfert de données hors périmètre qui doit être encadré (anonymisation, accord DPO, clause contractuelle).

---

### Implications stratégiques

La consolidation du marché SIEM (fusion Exabeam-LogRhythm) et la coexistence de plateformes historiques (ArcSight, Securonix) créent des besoins récurrents d'extraction et de portabilité des données de sécurité. La tentation d'utiliser des services d'analyse gratuits pour traiter ces volumes expose les organisations à un risque de fuite de télémétrie et de perte de souveraineté sur des données d'investigation. Les directions sécurité doivent arbitrer entre agilité des analystes et gouvernance des données, en particulier dans les secteurs régulés.

---

### Recommandations

* Encadrer formellement tout export de logs vers un service tiers (classification, anonymisation, base légale, clause de non-réutilisation).
* Créer des comptes API dédiés en lecture seule avec rotation des secrets et journalisation des appels.
* Activer la préservation du raw event sur les SmartConnectors ArcSight avant d'en dépendre pour des investigations.
* Documenter les limites d'export (10 000 événements, pagination, rétention chaude) dans les runbooks du SOC.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les sources SIEM/UEBA du SOC (Exabeam, Securonix, ArcSight Logger/ESM) et documenter les procédures d'export officielles.
* Créer des comptes de service API dédiés, à privilèges minimaux (lecture seule sur la recherche d'événements), avec rotation des secrets.
* Vérifier au préalable la conservation des événements bruts (raw event preservation) côté connecteurs ArcSight SmartConnector.

#### Phase 2 — Détection et analyse

* Contrôler les journaux d'audit des plateformes SIEM pour repérer tout export massif ou inhabituel via API.
* Surveiller les requêtes Spotter/Logger/Search anormalement larges (fenêtre temporelle étendue, champs '*', limite maximale).

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement les jetons API en cas d'export non autorisé et restreindre les permissions de recherche.
* Bloquer les flux sortants vers des services d'analyse externes non approuvés par la politique de sécurité.

#### Phase 4 — Activités post-incident

* Documenter la procédure d'export validée et l'intégrer au runbook d'investigation du SOC.
* Revoir la politique de classification des données de logs exportées et les clauses de confidentialité des services tiers utilisés.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux d'administration les créations de jetons API et les exports récents non corrélés à un ticket d'investigation.
* Corréler les exports avec les accès réseau sortants vers des plateformes d'analyse externes pour détecter une fuite de données de télémétrie.

---

### Sources

* [https://socprime.com/blog/how-to-export-exabeam-logs/](https://socprime.com/blog/how-to-export-exabeam-logs/)
* [https://socprime.com/blog/how-to-export-securonix-logs/](https://socprime.com/blog/how-to-export-securonix-logs/)
* [https://socprime.com/blog/how-to-export-arcsight-logs/](https://socprime.com/blog/how-to-export-arcsight-logs/)


---

<div id="ce-quune-organisation-a-revele-sur-le-risque-lie-aux-agents-ia"></div>

## Ce qu'une organisation a révélé sur le risque lié aux agents IA

### Résumé

Sysdig rapporte les observations réalisées pendant un mois, avec un accès anticipé à Sysdig AI Defense, sur l'usage des agents IA dans une entreprise d'édition logicielle. Constats publiés : 50 % des employés utilisant des agents IA travaillent hors du département d'ingénierie (marketing, RH, ventes, juridique, finance) ; parmi ces non-ingénieurs, 42 % en moyenne ont fait exécuter par un agent du code, un build, une installation de paquet ou une commande cloud/cluster. Plus de 60 % des appels d'outils se sont exécutés sans approbation humaine : 52 % filtrés par le classificateur automatique de Claude Code et 9 % avec les invites de permission volontairement désactivées (« YOLO mode »). Pour chaque appel d'outil journalisé par les agents, le noyau a capturé sept processus ; lorsque l'agent a lu un fichier d'identifiants, le journal de l'agent ne contenait aucune entrée dans 82 % des cas, alors que le noyau a journalisé chaque lecture. Enfin, 47 % des serveurs MCP utilisés provenaient de registres tiers ou de fournisseurs externes.

---

### Analyse opérationnelle

L'enseignement central est que les journaux produits par l'agent ne constituent pas une preuve d'audit fiable : ils sont écrits par l'agent lui-même et présentent des angles morts massifs (82 % des lectures de credentials non journalisées). La détection doit donc s'appuyer sur la télémétrie noyau/runtime (eBPF, EDR) pour observer les processus réellement exécutés, tout en conservant les journaux d'agent pour le contexte applicatif. Les surfaces d'attaque concrètes sont : exécution de code et installations de paquets par des utilisateurs non formés à la sécurité, commandes cloud/cluster avec les droits de l'agent, accès à des fichiers de secrets, et chaîne d'approvisionnement des serveurs MCP tiers. Les contrôles prioritaires sont l'inventaire et la validation des serveurs MCP, des chemins de build sandboxés et approuvés, la réactivation obligatoire des approbations humaines sur les actions à fort impact, et la limitation des identités et permissions attachées aux agents.

---

### Implications stratégiques

L'essor des « citizen developers » équipés d'agents IA déplace la création d'outils et l'exécution de commandes vers des populations sans culture sécurité, ce qui élargit la surface d'attaque au-delà de l'ingénierie et brouille les frontières du shadow IT. La dépendance à des serveurs MCP tiers introduit une chaîne d'approvisionnement logicielle non maîtrisée, où une seule ligne de configuration suffit à établir une relation de confiance. Pour les dirigeants, cela impose une gouvernance de l'IA agentique (politique d'usage, inventaire, contrôle des extensions, preuve d'audit) et une révision des modèles de menaces et des assurances cyber.

---

### Recommandations

* Fonder la détection et l'audit sur la télémétrie noyau/runtime, pas sur les journaux générés par les agents.
* Inventorier et valider les serveurs MCP ; bloquer par défaut les registres tiers non approuvés.
* Imposer des chemins de build sandboxés et approuvés pour les utilisateurs non ingénieurs.
* Restreindre les identités et permissions cloud/cluster attachées aux agents et surveiller les lectures de fichiers de secrets.
* Interdire par politique les modes d'exécution sans approbation humaine sur les actions à fort impact.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser les agents IA et extensions (serveurs MCP) autorisés, leurs identités, leurs accès cloud/cluster et les données auxquelles ils peuvent accéder.
* Définir une politique d'usage distinguant les niveaux de risque (lecture seule, exécution de code, accès aux secrets) et des chemins de build approuvés et sandboxés.
* Déployer une télémétrie noyau/runtime (eBPF, EDR) couvrant les processus enfants lancés par les agents, indépendamment des journaux produits par l'agent.

#### Phase 2 — Détection et analyse

* Détecter les exécutions d'installations de paquets, de builds et de commandes cloud/CLI initiées par des agents, en particulier depuis des postes non techniques (marketing, RH, finance, juridique).
* Alerter sur les appels d'outils exécutés sans approbation humaine et sur l'activation de modes de type « YOLO » (invites de permission désactivées).
* Détecter les lectures de fichiers d'identifiants (.env, clés SSH, fichiers de credentials cloud) par des processus descendants d'agents.

#### Phase 3 — Confinement, éradication et récupération

* Révoquer les identifiants et jetons accessibles aux agents compromis ou non conformes, et isoler le poste ou le conteneur concerné.
* Désactiver les serveurs MCP non approuvés et restreindre les registres d'extensions autorisés par politique.
* Forcer la réactivation des invites d'approbation humaine sur les appels d'outils à fort impact.

#### Phase 4 — Activités post-incident

* Reconstituer la chaîne d'action réelle à partir de la télémétrie noyau plutôt que des journaux de l'agent, jugés non probants.
* Mettre à jour la politique d'usage des agents, la liste blanche MCP et les procédures de revue de code généré par IA.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les écarts entre les appels d'outils journalisés par les agents et les processus réellement observés au niveau noyau (ratio d'écart, cas de lectures de credentials non journalisées).
* Inventorier les serveurs MCP connectés et identifier ceux provenant de registres tiers ou de fournisseurs non validés.
* Rechercher des exécutions d'agents sur des postes hors ingénierie ayant abouti à des commandes cloud ou cluster.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1059** | Exécution de commandes et d'interpréteurs via des agents IA (build, install de paquets, commandes cloud/CLI) |
| **T1552.001** | Accès à des fichiers d'identifiants par les agents, souvent non journalisé côté agent |
| **T1195** | Relations de confiance avec des serveurs MCP tiers issus de registres ou fournisseurs externes |

---

### Sources

* [https://webflow.sysdig.com/blog/a-first-look-under-the-hood-of-ai-agents](https://webflow.sysdig.com/blog/a-first-look-under-the-hood-of-ai-agents)


---

<div id="la-queens-public-library-de-new-york-a-ete-victime-dun-rancongiciel-la-nuit-derniere-un-e-mail-envoye-aux-usagers-confirme-lincident-de-rancongicielnyc-queens-ransomware-infosec"></div>

## La Queens Public Library de New York a été victime d'un rançongiciel la nuit dernière. Un e-mail envoyé aux usagers confirme l'incident de rançongiciel.#nyc #queens #ransomware #infosec

### Résumé

Une publication sur infosec.exchange rapporte qu'un rançongiciel a frappé la Queens Public Library (New York) dans la nuit, et qu'un courriel adressé aux usagers de la bibliothèque confirme l'incident de type ransomware. La source ne précise ni le groupe à l'origine, ni le vecteur initial, ni l'ampleur des données affectées.

---

### Analyse opérationnelle

L'information est de source unique et non corroborée techniquement : elle doit être traitée comme un signalement à confirmer plutôt que comme un constat établi. Pour une organisation comparable, l'incident rappelle les priorités : sauvegardes hors ligne et tests de restauration, segmentation entre postes publics et systèmes métier, durcissement des accès distants, et capacité à informer les usagers par un canal indépendant du SI. Les données de contact des adhérents et l'historique de prêts constituent des données personnelles exposées en cas d'exfiltration.

---

### Implications stratégiques

Les bibliothèques publiques cumulent données personnelles, budgets informatiques contraints et rôle de service essentiel pour les populations sans accès numérique : elles restent une cible attractive pour l'extorsion. La répétition d'attaques contre des institutions culturelles et municipales confirme une tendance sectorielle qui appelle un renforcement des exigences contractuelles, des assurances cyber et des plans de continuité à l'échelle des collectivités.

---

### Recommandations

* Confirmer l'incident auprès de sources officielles avant toute communication externe.
* Vérifier l'isolement des sauvegardes et la capacité de restauration hors ligne.
* Segmenter les postes publics des systèmes métier et durcir les accès distants.
* Préparer un canal de communication usagers indépendant du SI et anticiper les obligations de notification.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir un plan de réponse ransomware testé incluant les bibliothèques et services publics : sauvegardes hors ligne, procédure de bascule manuelle des services aux usagers.
* Identifier les données personnelles de lecteurs/adherents et les obligations de notification applicables.

#### Phase 2 — Détection et analyse

* Surveiller les alertes EDR/antivirus sur les postes publics et serveurs, les chiffrements massifs de fichiers et les notes de rançon.
* Détecter les mouvements latéraux et l'usage d'outils d'administration (RDP, PsExec, Cobalt Strike) sur le réseau de la bibliothèque.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les segments réseau affectés, couper les accès VPN et comptes compromis, préserver les images forensiques avant restauration.
* Communiquer aux usagers via un canal hors production et activer la cellule de crise avec les autorités compétentes.

#### Phase 4 — Activités post-incident

* Restaurer depuis des sauvegardes vérifiées et valider l'intégrité des systèmes avant remise en service.
* Conduire une revue post-incident (vecteur initial, délai de détection, efficacité des sauvegardes) et notifier les autorités et les personnes concernées si nécessaire.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les indicateurs du groupe ransomware (identifiants de rançon, extensions de fichiers chiffrés, adresses de paiement) sur l'ensemble du SI.
* Rechercher une persistance résiduelle (comptes créés, tâches planifiées, services) avant et après restauration.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Chiffrement des données à des fins d'extorsion (ransomware) |
| **T1657** | Extorsion financière contre une institution publique |

---

### Sources

* [https://infosec.exchange/@AlesandroOrtiz/117560793394320594](https://infosec.exchange/@AlesandroOrtiz/117560793394320594)


---

<div id="possible-phishing-on-hxxpslkgrazsllogin5b55bakaizeipheexoozbckwsbemsantanderbimp-botduckdnsorg-analysis-at-httpsurldnaioscan6aeb64b03b7750000318248d-cybersecurity-phishing-infosec-urldna-scam-infosec"></div>

## Possible Phishing 🎣  on: ⚠️hxxps[:]//lkgrazsl[.]login[.]5b55bakaizeipheexooz[.]bckwsbem[.]santander[.]bimp-bot[.]duckdns[.]org  🧬 Analysis at: https://urldna.io/scan/6aeb64b03b7750000318248d #cybersecurity #phishing #infosec #urldna #scam #infosec

### Résumé

Un signalement URLDNA identifie une URL suspecte de phishing construite sur une longue chaîne de sous-domaines se terminant par un enregistrement en DNS dynamique gratuit : hxxps[:]//lkgrazsl[.]login[.]5b55bakaizeipheexooz[.]bckwsbem[.]santander[.]bimp-bot[.]duckdns[.]org. La chaîne inclut le nom de marque « santander », suggérant une usurpation d'une enseigne bancaire. Aucune information n'est fournie sur le contenu de la page, le mode de diffusion ou le volume de victimes.

---

### Analyse opérationnelle

La technique repose sur l'empilement de sous-domaines pour placer un nom de marque en position lisible tout en gardant le domaine réellement enregistré à l'extrémité (duckdns.org), ce qui trompe la lecture rapide et contourne certains filtres se limitant au domaine de premier niveau. L'usage d'un service de DNS dynamique gratuit permet une rotation rapide de l'infrastructure et un enregistrement sans coût. Côté SOC, la détection doit porter sur les requêtes vers *.duckdns.org et sur les chaînes de sous-domaines anormalement longues ; le blocage doit être appliqué au niveau DNS, proxy et passerelle de messagerie, avec purge des courriels et recherche rétrospective des clics.

---

### Implications stratégiques

L'abus de services de DNS dynamique gratuits reste un vecteur peu coûteux et résilient pour l'usurpation de marques financières, ce qui expose les clients et la réputation des banques. Les institutions financières doivent intégrer ces services dans leur politique de filtrage, participer aux dispositifs de retrait (takedown) et renforcer la sensibilisation des clients à la lecture des URL.

---

### Recommandations

* Bloquer par défaut les sous-domaines de DNS dynamique gratuits non nécessaires à l'activité, avec exceptions documentées.
* Déployer une détection sur les chaînes de sous-domaines longues contenant des noms de marques.
* Rechercher rétrospectivement les clics et réinitialiser les identifiants des utilisateurs exposés.
* Signaler l'URL aux services de retrait et alimenter les listes de blocage internes et sectorielles.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Intégrer les domaines d'usurpation connus et les services de DNS dynamique gratuits (duckdns.org et apparentés) dans les listes de blocage et les règles de proxy.
* Configurer la journalisation DNS et proxy pour conserver les requêtes vers les sous-domaines dynamiques et permettre l'investigation rétrospective.

#### Phase 2 — Détection et analyse

* Détecter les résolutions DNS et connexions HTTP(S) vers des sous-domaines *.duckdns.org, en particulier ceux contenant des marques bancaires.
* Alerter sur les courriels contenant des liens vers des chaînes de sous-domaines longues et aléatoires, typiques du cloaking par sous-domaines.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer l'URL et le domaine au niveau proxy, DNS et passerelle de messagerie, puis purger les courriels en boîte.
* Réinitialiser les identifiants des utilisateurs ayant soumis des informations et révoquer les sessions actives.

#### Phase 4 — Activités post-incident

* Documenter l'IOC et l'alimenter dans les plateformes de renseignement et de détection.
* Communiquer un rappel de sensibilisation ciblé sur l'usurpation de marque bancaire via des liens à sous-domaines imbriqués.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétrospectivement les requêtes DNS vers *.duckdns.org et les accès aux URL signalées dans les journaux proxy sur les 30 derniers jours.
* Identifier les utilisateurs ayant cliqué et vérifier l'absence de soumission d'identifiants ou de codes MFA.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxps[:]//lkgrazsl[.]login[.]5b55bakaizeipheexooz[.]bckwsbem[.]santander[.]bimp-bot[.]duckdns[.]org` | Medium |
| DOMAIN | `bimp-bot[.]duckdns[.]org` | Medium |
| DOMAIN | `duckdns[.]org` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Hameçonnage par lien vers un site usurpant une marque bancaire |
| **T1583.001** | Acquisition et usage de domaines (DNS dynamique gratuit) pour l'infrastructure d'attaque |
| **T1585** | Établissement d'une façade de site légitime pour collecter des identifiants |

---

### Sources

* [https://urldna.io/scan/6aeb64b03b7750000318248d](https://urldna.io/scan/6aeb64b03b7750000318248d)


---

<div id="comment-les-exercices-capture-the-flag-ot-developpent-les-competences-cyber"></div>

## Comment les exercices Capture-the-Flag OT développent les compétences cyber

### Résumé

Retour d'expérience de Gilles Castro sur un exercice capture-the-flag de trois jours organisé par Dragos, centré sur la forensique blue team, l'analyse réseau et l'OT. Les scénarios portaient sur des environnements de utilities, de systèmes d'eau et d'installations électriques ; les participants recevaient du trafic réseau et des artefacts à analyser localement. Les challenges exposaient à Modbus/TCP, BACnet, l'authentification HTTP, SMB et SSH, avec usage de Wireshark, CyberChef et Impacket (examen d'une base SAM Windows). L'auteur souligne que le contexte industriel constitue la difficulté principale : une écriture de registre Modbus ne prend son sens qu'en connaissant le contrôleur cible, l'équipement affecté et la place de l'action dans la séquence d'attaque. Un schéma réseau dessiné à la main reliant accès distant, HMI Wonderware, PLC et autres équipements a servi à reconstituer un chemin d'attaque. L'article insiste enfin sur l'écart de perception entre débutants et experts face à un même artefact (PCAP).

---

### Analyse opérationnelle

L'article met en évidence un angle mort opérationnel fréquent : des analystes SOC compétents en IT mais incapables d'interpréter une capture OT, faute de familiarité avec Modbus/TCP, BACnet ou les architectures SCADA. Pour un SOC, cela se traduit par une détection tardive des actions malveillantes sur automates et par une incapacité à qualifier l'impact physique d'une intrusion. Les mesures concrètes sont : disposer de baselines protocolaires par site, journaliser les écritures de registres et les changements de mode des PLC, corréler réseau OT et journaux HMI, et intégrer des exercices type CTF dans le plan de formation. La méthodologie d'investigation décrite (partir de l'artefact, reconstruire la topologie, replacer l'action dans la kill chain) est directement transposable aux playbooks de réponse OT.

---

### Implications stratégiques

La pénurie de compétences OT/ICS reste un risque organisationnel majeur pour les opérateurs d'importance vitale, dans un contexte réglementaire de durcissement (NIS2, exigences sectorielles sur la sécurité industrielle). Investir dans des exercices réalistes et contextualisés réduit le risque d'interruption de service et améliore la capacité de négociation avec les assureurs et les autorités de régulation. La tendance de fond est à la convergence IT/OT : les organisations qui n'entraînent pas leurs équipes sur les protocoles industriels accumulent une dette de compétences dont l'effet se matérialisera au premier incident.

---

### Recommandations

* Intégrer des scénarios OT contextualisés (utilities, eau, énergie) dans les exercices annuels du SOC.
* Constituer et maintenir une bibliothèque de PCAP OT de référence avec documentation de topologie.
* Former les analystes aux protocoles industriels et aux conséquences physiques des actions techniques.
* Mettre en place une journalisation des écritures de registres Modbus et des changements d'état des PLC.
* Formaliser une procédure d'investigation OT partant des artefacts réseau vers la cartographie des dépendances.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Constituer un laboratoire OT isolé (PLC, HMI, simulateurs Modbus/TCP et BACnet) pour l'entraînement des analystes SOC.
* Constituer une bibliothèque de captures PCAP de référence issues d'environnements industriels (utilities, eau, énergie) et documenter le contexte de chaque capture (topologie, équipements, criticité).
* Former les analystes aux protocoles industriels (Modbus/TCP, BACnet, S7, DNP3) en complément des protocoles IT (SMB, SSH, HTTP).
* Cartographier les dépendances entre systèmes d'accès distant, HMI (ex. Wonderware), PLC et équipements physiques pour disposer du contexte lors d'une investigation.
* Standardiser les outils d'analyse (Wireshark, CyberChef, Impacket) et les procédures de manipulation sécurisée des artefacts.

#### Phase 2 — Détection et analyse

* Analyser les captures réseau OT en recherchant les écritures de registres Modbus anormales et les changements d'état de contrôleurs.
* Corréler les événements réseau avec les journaux HMI/SCADA pour identifier l'origine et la cible d'une commande industrielle.
* Détecter les authentifications HTTP, SMB et SSH inhabituelles sur les systèmes d'ingénierie et les jump hosts OT.
* Vérifier la cohérence entre les actions techniques observées et la séquence d'attaque attendue (reconnaissance, accès distant, mouvement latéral, impact physique).

#### Phase 3 — Confinement, éradication et récupération

* Isoler le segment OT concerné via la segmentation réseau existante (pare-feu industriel, DMZ OT) sans interrompre les processus physiques critiques.
* Suspendre les accès distants compromis (VPN, comptes d'ingénierie) et révoquer les sessions actives.
* Basculer les automates concernés en mode dégradé ou manuel en coordination avec les équipes de production.
* Préserver les captures PCAP et les journaux avant toute remédiation pour l'analyse forensique.

#### Phase 4 — Activités post-incident

* Reconstituer la chronologie complète de l'attaque à partir des artefacts réseau et des journaux industriels.
* Mettre à jour les règles de détection et les scénarios de chasse à partir des enseignements de l'exercice ou de l'incident.
* Renforcer la formation des analystes sur les protocoles industriels identifiés comme angles morts.
* Documenter les écarts de compétences et ajuster le plan de montée en compétence OT.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des écritures de registres Modbus répétées ou hors plage sur les automates exposés.
* Identifier les connexions sortantes ou latérales atypiques depuis les HMI et serveurs d'ingénierie.
* Traquer l'usage d'outils d'administration détournés (Impacket, RMM) sur les jump hosts OT.
* Comparer le trafic observé aux baselines protocolaires établies pour chaque site industriel.

---

### Sources

* [https://www.healthcareinfosecurity.com/blogs/how-ot-capture-the-flag-exercises-build-cyber-skills-p-4242](https://www.healthcareinfosecurity.com/blogs/how-ot-capture-the-flag-exercises-build-cyber-skills-p-4242)


---

<div id="publications-sur-les-sites-de-fuite-de-rancongiciels-ransomhouse-revendique-tfg-london-bavacai-liste-plusieurs-victimes"></div>

## Publications sur les sites de fuite de rançongiciels : Ransomhouse revendique TFG London, Bavacai liste plusieurs victimes

### Résumé

Deux sources de veille ransomware signalent de nouvelles publications sur des sites de fuite. Le site de Ransomhouse (266 publications au total, 8 sur les 30 derniers jours, 5 sur les 7 derniers jours, disponibilité moyenne de 9 % sur 30 jours, dernière publication le 2026-11-04 à 23:23) revendique la victime TFG London (Royaume-Uni, secteur « Other ») ; l'un de ses deux miroirs onion est indisponible (0 % de disponibilité) tandis que l'autre affiche 53 %. Le groupe Bavacai publie de son côté une série de victimes : Twal Family IT Lab (services professionnels), Interativa Plasticos/Interplast (Brésil, fabrication), Hirschinjurylaw / Town Center Pharmacy, Ulaval (Canada, santé), baeaqab / Premiumfruits (Pologne, agriculture et alimentation), Jobmongers (services professionnels), Kde / ICN (Mauritanie, automobile), Geetees / G.Twist Wholesale, Jatl / Jay Ace Technologies (Inde, fabrication), Vinitgloves (fabrication), Dian / Dirección de Impuestos y Aduanas Nacionales (Colombie, secteur public) et Msn / Microsoft (États-Unis, technologie).

---

### Analyse opérationnelle

Ces publications constituent des revendications non vérifiées : la mention « Microsoft » par un groupe peu établi doit être traitée avec prudence (possible usurpation de nom, erreur de cible ou revendication opportuniste) et ne doit pas déclencher de communication externe sans validation. En revanche, les cibles gouvernementales (DIAN Colombie), santé (Ulaval) et industrielles (Interplast, Jay Ace Technologies, Vinit Gloves) présentent un risque réel et doivent être priorisées dans la veille sectorielle. La faible disponibilité du site Ransomhouse (9 % sur 30 jours, un miroir à 0 %) indique une infrastructure instable, ce qui peut retarder la publication des preuves mais n'invalide pas la menace. Côté SOC, l'action utile est la surveillance des canaux Telegram listés, la recherche de fuites de credentials de l'organisation sur ces mêmes canaux et la vérification de l'exposition externe (VPN, RDP, portails).

---

### Implications stratégiques

La multiplication des groupes de moindre notoriété (Bavacai) aux côtés d'acteurs établis illustre la fragmentation de l'écosystème ransomware et l'abaissement des barrières à l'entrée. Les secteurs santé, industrie et administration publique restent les plus exposés en raison de la criticité opérationnelle et de la sensibilité des données. Pour les organisations, la publication sur un site de fuite devient un événement de gestion de crise à part entière : enjeux de réputation, obligations de notification réglementaire et pression sur les négociations avec les assureurs cyber. La dispersion géographique des victimes (Amérique latine, Europe, Amérique du Nord, Afrique, Asie) confirme l'absence de ciblage géographique structuré chez ces groupes.

---

### Recommandations

* Mettre en place une alerte automatisée sur l'apparition du nom de l'organisation et de ses filiales sur les sites de fuite et canaux Telegram.
* Vérifier systématiquement les revendications avant toute communication externe, en particulier pour les cibles de grande notoriété.
* Prioriser la réduction de la surface d'exposition externe (VPN, RDP, portails) et imposer l'authentification multifacteur.
* Tester la capacité de restauration depuis des sauvegardes immuables et documenter les RTO/RPO.
* Préparer un kit de crise incluant les obligations de notification RGPD et sectorielles.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir une veille automatisée des sites de fuite (Ransomhouse, Bavacai) et des canaux Telegram associés.
* Tenir à jour un inventaire des actifs exposés et des données sensibles par entité pour évaluer rapidement l'impact d'une revendication.
* Disposer d'un plan de communication de crise pré-approuvé (direction, juridique, autorité de contrôle, assureur cyber).
* Vérifier la couverture EDR, la journalisation DNS/proxy et les sauvegardes immuables hors ligne.

#### Phase 2 — Détection et analyse

* Surveiller l'apparition du nom de l'organisation sur les sites de fuite et les canaux Telegram des groupes.
* Corréler toute revendication avec les alertes EDR/SIEM (chiffrement massif, suppression de clichés instantanés, exfiltration).
* Rechercher des connexions sortantes volumineuses vers des services de stockage ou des canaux C2.
* Analyser les journaux d'accès VPN/RDP et d'authentification pour identifier un accès initial non autorisé.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les hôtes chiffrés ou suspects du réseau et désactiver les comptes compromis.
* Révoquer les sessions et jetons d'accès, réinitialiser les secrets (comptes de service, clés API).
* Bloquer les domaines, URL onion et canaux de communication identifiés au niveau proxy/DNS.
* Activer le plan de continuité et restaurer depuis des sauvegardes vérifiées non compromises.

#### Phase 4 — Activités post-incident

* Déterminer le périmètre exact des données exfiltrées et qualifier les obligations de notification (RGPD, autorités sectorielles).
* Analyser les vecteurs d'accès initial et corriger les vulnérabilités exploitées.
* Renforcer la segmentation, l'authentification multifacteur et la supervision des comptes à privilèges.
* Capitaliser sur les TTP observés pour mettre à jour les règles de détection et les scénarios de crise.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les artefacts et outils associés aux groupes Ransomhouse et Bavacai dans les journaux de télémétrie.
* Traquer les accès aux partages réseau et les volumes de lecture anormaux précédant une exfiltration.
* Identifier les tentatives d'accès aux services d'exposition externe (VPN, RDP, portails web) depuis des IP suspectes.
* Vérifier la présence de comptes créés récemment ou de tâches planifiées non légitimes sur les serveurs critiques.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| URL | `hxxp://xw7au5pnwtl6lozbsudkmyd32n6gnqdngitjdppybudan3x3pjgpmpid[.]onion` | Medium |
| URL | `hxxp://zohlm7ahjwegcedoz7lrdrti7bvpofymcayotp744qhx6gjmxbuo2yid[.]onion/` | Medium |
| URL | `hxxps://t[.]me/RHouseNews` | Medium |
| URL | `hxxps://t[.]me/DatabaseCartel` | Medium |
| URL | `hxxps://t[.]me/AgentGlobal` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact - chiffrement des données des victimes |
| **T1657** | Financial Theft - extorsion et double chantage via la publication de données |
| **T1567** | Exfiltration Over Web Service - publication des données volées sur des canaux web/onion |

---

### Sources

* [https://www.ransomlook.io//group/ransomhouse](https://www.ransomlook.io//group/ransomhouse)
* [https://infosec.exchange/@CTI_FYI/117560473299612839](https://infosec.exchange/@CTI_FYI/117560473299612839)


---

<div id="strucsure-home-warranty-par-play"></div>

## StrucSure Home Warranty par play

### Résumé

Le site de fuite du groupe ransomware Play référence une nouvelle victime, StrucSure Home Warranty, selon le suivi de RansomLook (état du parseur : 6/32 dégradé). La publication n'est accompagnée d'aucun détail technique sur le vecteur d'intrusion, le volume de données dérobées ou les exigences de rançon.

---

### Analyse opérationnelle

Le groupe Play est connu pour exploiter des services d'exposition externe (appliances VPN, serveurs Exchange, outils de transfert de fichiers managés, accès RMM) afin d'obtenir un accès initial, puis pour désactiver les protections, supprimer les sauvegardes et chiffrer les systèmes après exfiltration. La cible étant un assureur de garantie habitation, les données à risque incluent des informations personnelles de souscripteurs et des données contractuelles. Les équipes SOC doivent vérifier en priorité l'exposition des services d'accès distant, la présence de comptes à privilèges récemment créés et l'intégrité des sauvegardes. La revendication doit être traitée comme non confirmée tant qu'aucune preuve technique n'est disponible.

---

### Implications stratégiques

Le secteur assurance/financier reste une cible de choix pour les groupes à double extorsion en raison de la valeur des données clients et de la capacité de paiement supposée des victimes. Une compromission entraîne des coûts de remédiation, un risque réglementaire (notification RGPD, supervision prudentielle) et un risque réputationnel durable. La tendance observée est à l'exploitation systématique des services d'exposition externe plutôt qu'au phishing de masse, ce qui impose de traiter la gestion des accès distants comme un chantier prioritaire au niveau direction.

---

### Recommandations

* Auditer et restreindre l'exposition externe des appliances VPN, serveurs de messagerie et outils RMM.
* Imposer l'authentification multifacteur sur tous les accès distants et administrateurs.
* Mettre en place une alerte sur la suppression de clichés instantanés et la désactivation des protections.
* Vérifier trimestriellement la restaurabilité des sauvegardes immuables.
* Préparer un scénario de crise incluant les obligations de notification aux assurés et au régulateur.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Surveiller le site de fuite du groupe Play et maintenir une liste des victimes revendiquées pour analyse de ciblage sectoriel.
* Durcir l'exposition externe : inventaire des appliances VPN, serveurs Exchange, services RMM et outils de transfert de fichiers.
* Appliquer les correctifs sur les services d'exposition publique et restreindre l'accès aux interfaces d'administration.
* Vérifier l'immuabilité des sauvegardes et l'existence de copies hors ligne déconnectées.

#### Phase 2 — Détection et analyse

* Détecter les exécutions de GPO modifiées, la création de services et l'usage détourné de PsExec ou d'outils RMM.
* Surveiller les suppressions de clichés instantanés (vssadmin, wbadmin) et la désactivation des protections (Defender, EDR).
* Alerter sur les mouvements latéraux SMB et les accès massifs aux partages de fichiers.
* Détecter les exfiltrations volumineuses vers des services cloud ou des canaux externes.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les segments et hôtes affectés, désactiver les comptes à privilèges compromis et révoquer les tickets Kerberos.
* Couper les accès distants et les intégrations RMM non indispensables.
* Bloquer les indicateurs identifiés (domaines, IP, hachages) au niveau pare-feu, proxy et EDR.
* Engager la restauration contrôlée depuis les sauvegardes immuables après validation de l'absence de persistance.

#### Phase 4 — Activités post-incident

* Évaluer le périmètre des données exfiltrées et les obligations de notification aux autorités et aux assurés.
* Analyser le vecteur d'accès initial (vulnérabilité d'appliance, compte VPN compromis, phishing) et corriger.
* Renforcer la segmentation, la gestion des comptes à privilèges et la surveillance des outils d'administration.
* Mettre à jour les règles de détection à partir des TTP observés du groupe Play.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les artefacts connus du groupe Play (binaires de chiffrement, notes de rançon, scripts de suppression de sauvegardes).
* Traquer l'usage de GPO modifiées et de comptes de service pour le déploiement latéral.
* Identifier les connexions RDP/SMB internes anormales et les créations de comptes non légitimes.
* Rechercher des accès aux serveurs de sauvegarde et aux consoles de virtualisation hors fenêtres de maintenance.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact - chiffrement des systèmes de la victime |
| **T1490** | Inhibit System Recovery - suppression des sauvegardes et clichés instantanés |
| **T1657** | Financial Theft - extorsion par double chantage |

---

### Sources

* [https://www.ransomlook.io//group/play](https://www.ransomlook.io//group/play)


---

<div id="des-pirates-volent-320-000-fichiers-decoles-britanniques-et-les-publient-sur-le-dark-web"></div>

## Des pirates volent 320 000 fichiers d'écoles britanniques et les publient sur le dark web

### Résumé

Selon DataBreaches.net, des attaquants ont dérobé environ 320 000 fichiers appartenant à des établissements scolaires britanniques et les ont publiés sur le dark web. Le contenu détaillé de l'article n'était pas accessible au moment de la collecte (page bloquée par un service de protection anti-attaques), de sorte que le vecteur d'intrusion, la ou les entités exactes concernées et la nature précise des fichiers ne sont pas documentés dans la source.

---

### Analyse opérationnelle

La publication de fichiers scolaires expose des données personnelles de mineurs, ce qui constitue une catégorie à risque élevé et impose une réaction rapide. Les équipes IT des établissements doivent vérifier l'exposition des partages réseau, des environnements cloud pédagogiques et des accès distants, puis rechercher des archives anormales et des transferts sortants volumineux. La détection repose sur la surveillance des accès aux répertoires, l'analyse des journaux d'authentification et la recherche d'indicateurs de publication sur les sites de fuite. En réponse, la priorité est la révocation des accès compromis, l'isolation des serveurs de fichiers et la préservation des preuves avant toute remédiation.

---

### Implications stratégiques

Le secteur éducatif britannique est structurellement vulnérable : budgets de sécurité limités, forte externalisation IT, multiplicité des parties prenantes et données sensibles sur des mineurs. Une fuite de cette ampleur expose les établissements à des sanctions réglementaires, à des actions en responsabilité et à une perte de confiance des familles. La tendance de fond est l'industrialisation de l'exfiltration de données scolaires suivie de publication sur le dark web, y compris sans chiffrement préalable, ce qui transforme la gestion des données d'élèves en enjeu de gouvernance au niveau des autorités éducatives et des collectivités.

---

### Recommandations

* Cartographier et restreindre les partages réseau contenant des données d'élèves.
* Mettre en place une détection des accès massifs et des transferts sortants volumineux.
* Préparer une procédure de notification rapide aux autorités et aux familles en cas de fuite de données de mineurs.
* Imposer l'authentification multifacteur sur les accès distants et les environnements cloud pédagogiques.
* Sensibiliser le personnel aux risques de compromission de comptes et au partage non contrôlé de fichiers.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser les systèmes scolaires hébergeant des données d'élèves et de personnel (SIS, ENT, partages de fichiers, sauvegardes).
* Appliquer le principe du moindre privilège sur les partages réseau et restreindre l'accès distant aux personnels habilités.
* Disposer d'une procédure de notification pré-établie (autorité de protection des données, autorités éducatives, familles).
* Sauvegarder hors ligne les données critiques et tester la restauration.

#### Phase 2 — Détection et analyse

* Surveiller les accès massifs ou inhabituels aux partages de fichiers et aux espaces de stockage cloud.
* Détecter les connexions sortantes volumineuses et les transferts vers des services d'hébergement externes.
* Analyser les journaux d'authentification pour identifier des comptes compromis ou des accès hors horaires scolaires.
* Surveiller les sites de fuite et les canaux de publication pour détecter l'apparition de données de l'établissement.

#### Phase 3 — Confinement, éradication et récupération

* Désactiver les comptes compromis et révoquer les sessions actives.
* Isoler les serveurs de fichiers concernés et bloquer les canaux d'exfiltration identifiés.
* Restreindre temporairement l'accès distant et les partages exposés.
* Préserver les journaux et les preuves avant remédiation.

#### Phase 4 — Activités post-incident

* Qualifier la nature des données publiées (données d'élèves mineurs, données de santé, coordonnées) et évaluer le risque pour les personnes.
* Procéder aux notifications réglementaires et informer les familles avec des recommandations de vigilance.
* Corriger le vecteur d'accès initial et renforcer la segmentation entre systèmes administratifs et pédagogiques.
* Mettre à jour les procédures de gestion des accès et de sensibilisation du personnel.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des accès non autorisés aux partages de fichiers et aux comptes de service scolaires.
* Traquer les archives compressées créées de manière inhabituelle sur les serveurs de fichiers.
* Identifier les connexions vers des services de partage de fichiers ou de stockage non autorisés.
* Rechercher la réutilisation des identifiants de l'établissement sur des sources de fuite externes.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1530** | Data from Information Repositories - collecte de fichiers depuis les systèmes de stockage scolaires |
| **T1567** | Exfiltration Over Web Service - publication des données volées sur le dark web |
| **T1657** | Financial Theft - extorsion par menace de publication |

---

### Sources

* [https://databreaches.net/2026/11/04/hackers-steal-320000-uk-school-files-and-publish-them-on-dark-web/](https://databreaches.net/2026/11/04/hackers-steal-320000-uk-school-files-and-publish-them-on-dark-web/)


---

<div id="une-cyberattaque-efface-des-donnees-cloud-chez-le-principal-hebergeur-russe-beget"></div>

## Une cyberattaque efface des données cloud chez le principal hébergeur russe Beget

### Résumé

Le fournisseur d'hébergement web russe Beget peine à restaurer ses services après une cyberattaque qui a détruit des données dans son infrastructure cloud et perturbé des centaines de sites web, rapporte The Record. La source ne précise ni le mode opératoire, ni l'auteur, ni le périmètre exact des données perdues.

---

### Analyse opérationnelle

L'événement illustre le risque de concentration : des centaines de sites dépendent d'un même fournisseur, et la destruction de données chez l'hébergeur devient un incident de disponibilité et d'intégrité pour l'ensemble de ses clients. Pour les équipes SOC/IT, la question centrale est la capacité à restaurer sans dépendre des sauvegardes du fournisseur sinistré. Les mécanismes à surveiller côté client sont la perte d'accès au panneau de contrôle, les modifications DNS non planifiées et la disparition de volumes de stockage.

---

### Implications stratégiques

La destruction de données chez un hébergeur régional souligne la fragilité de la chaîne d'approvisionnement numérique pour les PME et les sites marchands. Elle alimente la tendance à la « souveraineté » de l'hébergement et à la diversification des fournisseurs, en particulier dans les contextes géopolitiques tendus. Les assureurs et donneurs d'ordre vont probablement durcir leurs exigences de preuve de résilience (sauvegardes immuables, plan de reprise testé) vis-à-vis des prestataires.

---

### Recommandations

* Imposer des sauvegardes immuables hors du périmètre du fournisseur d'hébergement.
* Tester au moins deux fois par an la restauration complète d'un site depuis les sauvegardes.
* Documenter et automatiser la procédure de bascule DNS vers un hébergement alternatif.
* Exiger contractuellement une notification d'incident sous 24 h et un accès aux journaux d'audit.
* Éviter la dépendance à un fournisseur unique pour les services critiques (multi-région, multi-fournisseur).
* Surveiller les changements DNS et de certificats comme signaux précoces de compromission.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les données hébergées chez des fournisseurs externes et classer leur criticité (RTO/RPO par service).
* Exiger du fournisseur des garanties contractuelles sur la localisation, la réplication et la restitution des sauvegardes.
* Mettre en place des sauvegardes indépendantes du fournisseur (copie hors site, immuable, testée).
* Documenter les procédures de bascule vers un hébergement alternatif et les prérequis DNS.

#### Phase 2 — Détection et analyse

* Surveiller les indicateurs de santé du fournisseur (statut public, latence, erreurs 5xx, perte d'accès aux panneaux de contrôle).
* Alerter sur toute suppression ou modification massive de fichiers/volumes côté cloud.
* Détecter les changements DNS ou de certificats non planifiés affectant les sites hébergés.
* Corréler avec les signaux de renseignement sur les campagnes destructrices visant les hébergeurs.

#### Phase 3 — Confinement, éradication et récupération

* Déclencher le plan de continuité : bascule DNS vers l'infrastructure de secours ou un site statique.
* Suspendre les intégrations et clés API liées au fournisseur compromis.
* Geler les écritures vers les volumes potentiellement compromis et préserver les journaux d'accès.
* Communiquer aux clients internes un statut factuel et un calendrier de restauration réaliste.

#### Phase 4 — Activités post-incident

* Restaurer depuis des sauvegardes indépendantes vérifiées et valider l'intégrité des données.
* Réévaluer la dépendance à un fournisseur unique et imposer une stratégie multi-fournisseur pour les services critiques.
* Mettre à jour les clauses contractuelles (notification d'incident, pénalités, preuve de restauration).
* Tirer un retour d'expérience sur les délais réels de bascule et corriger les écarts.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des accès persistants aux panneaux d'administration cloud (clés API, comptes de service, tokens OAuth).
* Analyser les journaux d'audit du fournisseur pour des suppressions massives ou des changements de privilèges.
* Vérifier l'absence de code malveillant résiduel dans les sites restaurés (webshells, scripts injectés).
* Contrôler les enregistrements DNS et certificats pour des détournements persistants.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1485** | Data Destruction |
| **T1561** |  |
| **T1490** | Inhibit System Recovery |
| **T1489** |  |

---

### Sources

* [https://databreaches.net/2026/11/04/cyberattack-wipes-cloud-data-at-major-russian-hosting-provider-beget/](https://databreaches.net/2026/11/04/cyberattack-wipes-cloud-data-at-major-russian-hosting-provider-beget/)
* [https://therecord.media/russia-cyberattack-beget-cloud](https://therecord.media/russia-cyberattack-beget-cloud)


---

<div id="cyberattaques-coordonnees-contre-des-systemes-de-refrigeration-europeens-chaines-du-froid-de-supermarches-et-etablissement-francais-du-sang-efs-via-coolworld"></div>

## Cyberattaques coordonnées contre des systèmes de réfrigération européens : chaînes du froid de supermarchés et Établissement français du sang (EFS) via Coolworld

### Résumé

Deux incidents distincts sont rapportés. D'une part, les attaquants ont compromis l'infrastructure de mise à jour d'OpsShield, éditeur de l'outil de sécurité serveur cPGuard, pour diffuser des mises à jour malveillantes à environ 2 950 serveurs, déployant une backdoor et exfiltrant des données. D'autre part, en France, des attaquants ont accédé aux systèmes de contrôle de stocks de sang et modifié les consignes de température des congélateurs, les faisant passer de -22 °F à 230 °F, détruisant la viabilité des produits. La source indique une confiance faible sur l'attribution du second incident et modérée sur le caractère ciblé du premier.

---

### Analyse opérationnelle

Le premier incident illustre le « paradoxe de l'ancre de confiance » : les mécanismes de mise à jour automatique bénéficient de privilèges élevés et d'une inspection allégée, ce qui en fait une voie d'entrée à fort levier — un seul serveur compromis permet d'atteindre des milliers de machines. La détection doit donc porter sur le comportement post-mise à jour (nouveaux processus, connexions sortantes, persistance) plutôt que sur le seul binaire. Le second incident relève de la manipulation de consigne : le système n'est pas en panne, il exécute fidèlement une valeur malveillante, ce qui rend la détection dépendante d'alarmes métier (température, chaîne du froid) indépendantes de l'IT. La réponse exige une capacité de reprise en mode manuel et une coordination immédiate avec les équipes métier et les autorités sanitaires.

---

### Implications stratégiques

La compromission d'un canal de mise à jour déplace la responsabilité du risque vers l'éditeur et pose la question de la responsabilité juridique et financière des éditeurs pour du code signé malveillant, ainsi que de l'exigence de SBOM opposables. Le second incident marque un basculement vers des attaques à effet physique : la cible n'est plus la donnée mais la capacité opérationnelle, ce qui rend les cadres de notification actuels (72 h RGPD) inadaptés à des dommages immédiats et irréversibles. Pour les secteurs santé et infrastructures critiques, cela plaide pour une supervision physique redondante, une segmentation OT stricte et des exercices de crise incluant la perte de contrôle des équipements.

---

### Recommandations

* Geler les mises à jour automatiques du fournisseur concerné et procéder à une validation manuelle jusqu'à confirmation officielle.
* Surveiller le comportement post-mise à jour : nouveaux processus, connexions sortantes, création de comptes ou de services.
* Exiger des éditeurs des SBOM exploitables et des engagements contractuels sur la sécurité du canal de distribution.
* Segmenter strictement les réseaux ICS/OT et interdire les accès Internet directs aux automates.
* Déployer des alarmes physiques indépendantes sur les paramètres critiques (température, pression, débit).
* Prévoir une procédure de reprise en mode manuel pour les équipements de froid et tester sa faisabilité.
* Réviser les délais et canaux de notification pour les incidents à impact physique immédiat.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les outils d'administration serveur et leurs mécanismes d'auto-update, avec propriétaire et niveau de privilège.
* Segmenter les réseaux ICS/OT des réseaux IT et restreindre les accès aux automates de froid et aux supervisions.
* Mettre en place une supervision physique (températures, alarmes) indépendante du système informatique.
* Définir une procédure de gel des mises à jour automatiques et de validation manuelle en cas d'alerte fournisseur.

#### Phase 2 — Détection et analyse

* Surveiller les changements de consigne (setpoint) sur les automates de froid et alerter sur tout écart hors plage.
* Détecter les processus et connexions sortantes nouveaux après application d'une mise à jour logicielle.
* Vérifier l'intégrité et la signature des binaires reçus via les canaux de mise à jour.
* Corréler les alertes de température avec les journaux de connexion aux automates et aux serveurs de supervision.

#### Phase 3 — Confinement, éradication et récupération

* Suspendre immédiatement les mises à jour automatiques du fournisseur concerné et bloquer ses domaines de distribution.
* Isoler les serveurs ayant reçu la mise à jour malveillante et préserver les images disque pour analyse.
* Repasser les automates en mode manuel/local et rétablir les consignes de température par procédure physique contrôlée.
* Révoquer les identifiants et certificats utilisés par le canal de mise à jour.

#### Phase 4 — Activités post-incident

* Analyser le binaire malveillant, identifier les mécanismes de persistance et les données exfiltrées.
* Évaluer l'impact physique réel (produits perdus, chaîne du froid, stocks critiques) avec les métiers.
* Renforcer la vérification des mises à jour (SBOM, signature, double validation) et la responsabilité contractuelle des éditeurs.
* Réviser les plans de continuité des activités critiques dépendant de systèmes ICS.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des connexions sortantes persistantes depuis les serveurs ayant appliqué la mise à jour.
* Analyser les journaux des automates et supervision pour des écritures de consigne non planifiées.
* Rechercher des comptes ou certificats créés par le binaire malveillant sur les serveurs affectés.
* Traquer les artefacts similaires chez d'autres éditeurs d'outils d'administration serveur (même famille de backdoor).

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T0836** |  |
| **T0831** |  |
| **T1199** |  |
| **T1078** | Valid Accounts |
| **T1195.002** | Supply Chain Compromise: Compromise Software Supply Chain |
| **T1041** | Exfiltration Over C2 Channel |
| **T0855** |  |

---

### Sources

* [https://databreaches.net/2026/11/03/french-blood-storage-units-targeted-in-cyberattack/](https://databreaches.net/2026/11/03/french-blood-storage-units-targeted-in-cyberattack/)
* [https://cyberveille.curated.co/issues/573](https://cyberveille.curated.co/issues/573)
* [https://theperimetersite.com/report/440](https://theperimetersite.com/report/440)
* [https://theperimetersite.com/report/441](https://theperimetersite.com/report/441)


---

<div id="des-chercheurs-decouvrent-un-adware-de-prompt-cache-dans-un-kit-de-jailbreak-openai-codex"></div>

## Des chercheurs découvrent un adware de prompt caché dans un kit de jailbreak OpenAI Codex

### Résumé

Check Point Research a documenté un bundle de jailbreak pour OpenAI Codex nommé Haiou (« mouette » en chinois), qui modifie les fichiers de configuration de l'agent pour injecter des publicités pour le site de son auteur dans les réponses suivantes. Le phénomène est baptisé « prompt adware ». Les salutations ou mots d'activation (« Seagull », « hi », « hello », « hey », « yo », « are you there? ») déclenchent une publicité pour zz.aiapi2025[.]top, présenté comme une passerelle LLM compatible OpenAI. Le bundle utilise des techniques de prompt injection (jeu de rôle, requalification de demandes de cybersécurité en scénario CTF) et installe des skills orientés pentest, cracking et rétro-ingénierie. Le dépôt GitHub « haiou-codex » affichait 77 forks et 403 étoiles depuis sa mise en ligne le 10 juillet 2026, et le jailbreak est intégré à Codex-X, outil chinois de configuration graphique de Codex.

---

### Analyse opérationnelle

Le comportement malveillant est porté par des instructions en langage naturel et de la configuration, non par un exécutable, ce qui le rend difficile à repérer pour les outils classiques. Pour les équipes sécurité, cela impose de surveiller l'intégrité des fichiers d'instructions des agents IA, les skills tiers installés et les flux sortants vers des passerelles LLM non approuvées. Le risque immédiat est faible (publicité), mais le mécanisme démontre la faisabilité d'une prise de contrôle persistante du comportement d'un agent, ouvrant la voie à l'exfiltration de code ou de secrets via un middleware opaque.

---

### Implications stratégiques

Les agents IA entrent dans le périmètre de la chaîne de confiance logicielle : prompts, skills et composants tiers deviennent des vecteurs de compromission. Les organisations doivent traiter l'IA générative comme un nouveau maillon de la supply chain, avec gouvernance des composants autorisés, contrôle des passerelles et traçabilité. L'origine chinoise de l'outil et l'usage de services non officiels dans des zones où Codex n'est pas disponible soulignent aussi les enjeux de conformité et de fuite de propriété intellectuelle.

---

### Recommandations

* Contrôler l'intégrité des fichiers de configuration des agents IA et journaliser leurs modifications.
* Établir une liste blanche de skills, plugins et passerelles LLM autorisés.
* Bloquer les passerelles LLM non approuvées et surveiller les domaines suspects au proxy.
* Former les développeurs aux risques de prompt injection et de bundles de jailbreak.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les agents IA de codage utilisés (OpenAI Codex et équivalents) et leurs fichiers de configuration globaux.
* Définir une politique d'usage des « skills », plugins et bundles tiers pour les agents IA, avec validation sécurité.
* Restreindre les sorties réseau des postes de développement vers les passerelles LLM non approuvées.

#### Phase 2 — Détection et analyse

* Surveiller les modifications des fichiers de configuration d'agents (instructions globales, skills ajoutés) et les changements hors processus de build.
* Détecter les résolutions DNS et connexions vers des passerelles LLM non référencées, dont zz.aiapi2025[.]top.
* Analyser les réponses des agents pour identifier des insertions publicitaires ou des instructions persistantes anormales.

#### Phase 3 — Confinement, éradication et récupération

* Supprimer les bundles de jailbreak et configurations modifiées, restaurer les fichiers d'instructions depuis une version de référence.
* Bloquer le domaine et les passerelles LLM non approuvées au niveau proxy/DNS.
* Révoquer les clés API et jetons associés aux environnements de développement exposés.

#### Phase 4 — Activités post-incident

* Évaluer si des données de code ou des secrets ont transité par la passerelle tierce.
* Mettre à jour la politique d'usage de l'IA et la liste blanche des composants autorisés.
* Sensibiliser les développeurs au risque de chaîne d'approvisionnement des agents IA.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les dépôts et paquets référencés (haiou-codex, Codex-X) dans les environnements de développement et les miroirs internes.
* Rechercher dans les journaux proxy les requêtes vers des domaines en *.aiapi*.top et autres passerelles LLM gratuites.
* Comparer les fichiers de configuration d'agents sur l'ensemble des postes pour identifier des variantes injectées.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `zz.aiapi2025[.]top` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1195.002** | Compromise Software Supply Chain — bundle de jailbreak et outil Codex-X distribuant un comportement indésirable |
| **T1546** | Event Triggered Execution — déclenchement d'annonces sur mots-clés de salutation dans l'agent |
| **T1027** | Obfuscated Files or Information — comportement introduit via instructions en langage naturel plutôt qu'un binaire |

---

### Sources

* [https://thehackernews.com/2026/11/researchers-uncover-prompt-adware.html](https://thehackernews.com/2026/11/researchers-uncover-prompt-adware.html)


---

<div id="un-attaquant-abuse-didentifiants-valides-microsoft-entra-id-pour-cibler-les-clients-en-aval-des-msp"></div>

## Un attaquant abuse d'identifiants valides Microsoft Entra ID pour cibler les clients en aval des MSP

### Résumé

Selon Cybersecurity Dive, un attaquant abuse de Microsoft Entra ID en utilisant des identifiants valides pour cibler les clients en aval de fournisseurs de services managés (MSP). La campagne a permis d'accéder à des organisations de secteurs variés.

---

### Analyse opérationnelle

L'usage d'identifiants légitimes rend la détection difficile : il n'y a ni exploitation de vulnérabilité ni malware à repérer, mais des authentifications conformes aux politiques. Le risque majeur est la cascade : la compromission d'un tenant MSP ouvre l'accès à l'ensemble des tenants clients via les délégations administratives. Les équipes SOC doivent surveiller les connexions aux comptes d'administration déléguée (localisation, ASN, horaires), les ajouts de méthodes d'authentification, les consentements OAuth et les créations d'applications. La révocation des sessions et jetons est prioritaire au containment.

---

### Implications stratégiques

Cet incident confirme que les MSP sont devenus une cible de choix pour l'accès initial à grande échelle, avec un effet de concentration de risque pour des secteurs entiers. Les donneurs d'ordre doivent intégrer la sécurité du MSP dans leur propre gestion des tiers et exiger des garanties contractuelles (moindre privilège, notification, droit d'audit). La généralisation de l'identité cloud comme périmètre principal déplace l'effort de défense vers la gouvernance des identités et des accès délégués.

---

### Recommandations

* Appliquer le moindre privilège et l'accès juste-à-temps sur les délégations GDAP/DAP.
* Imposer une MFA résistante au phishing et des politiques d'accès conditionnel sur les comptes multi-tenants.
* Centraliser et corréler les journaux Entra ID de tous les tenants supervisés.
* Auditer régulièrement les applications, consentements OAuth et comptes dormants dans les tenants clients.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les relations de délégation MSP (GDAP/DAP), les rôles délégués et les comptes administrateurs multi-tenants.
* Imposer l'authentification forte (MFA résistante au phishing) et des accès conditionnels stricts sur les comptes d'administration déléguée.
* Mettre en place une journalisation centralisée des connexions Entra ID de tous les tenants clients.

#### Phase 2 — Détection et analyse

* Détecter les connexions réussies avec identifiants valides depuis des localisations ou ASN inhabituels, notamment sur les comptes d'administration déléguée.
* Surveiller les créations de comptes, ajouts de méthodes d'authentification, consentements OAuth et modifications de rôles.
* Corréler les activités d'un tenant MSP avec celles des tenants clients pour repérer un pivot latéral.

#### Phase 3 — Confinement, éradication et récupération

* Révoquer les sessions et jetons des comptes compromis, réinitialiser les identifiants et retirer les méthodes d'authentification ajoutées.
* Suspendre temporairement les relations de délégation affectées et restreindre les accès conditionnels.
* Notifier les clients en aval et coordonner la réponse à l'échelle du portefeuille.

#### Phase 4 — Activités post-incident

* Auditer l'ensemble des tenants clients pour identifier les persistances (applications, comptes dormants, rôles ajoutés).
* Revoir le modèle de délégation MSP : moindre privilège, accès juste-à-temps, séparation des environnements.
* Renforcer la surveillance continue et les clauses de notification dans les contrats MSP.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les connexions réussies sans MFA ou avec MFA satisfaite depuis des IP proxy/VPN sur les comptes délégués.
* Rechercher les inscriptions d'applications et consentements OAuth récents dans les tenants clients.
* Analyser les journaux de connexion sur plusieurs semaines pour identifier des reconnaissances préalables.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078.004** | Valid Accounts: Cloud Accounts — usage d'identifiants Entra ID valides |
| **T1199** | Trusted Relationship — exploitation de la relation MSP vers les clients en aval |
| **T1556** | Modify Authentication Process — possible contournement ou ajout de méthodes d'authentification |
| **T1098** | Account Manipulation — création ou élévation de comptes dans les tenants clients |

---

### Sources

* [https://www.cybersecuritydive.com/news/attacker-microsoft-entra-id-downstream-msp/873744/](https://www.cybersecuritydive.com/news/attacker-microsoft-entra-id-downstream-msp/873744/)


---

<div id="le-lanceur-de-jeu-pc-nikke-pirate-pour-diffuser-un-malware-dacces-a-distance-et-de-vol-de-donnees"></div>

## Le lanceur de jeu PC NIKKE piraté pour diffuser un malware d'accès à distance et de vol de données

### Résumé

Selon BleepingComputer, les développeurs de Goddess of Victory: NIKKE ont confirmé que des attaquants ont altéré les scripts du launcher PC du jeu dans le cadre d'une attaque par chaîne d'approvisionnement. Le malware distribué via le launcher est capable de voler des identifiants et des données de portefeuilles de cryptomonnaies, et d'ouvrir un accès distant.

---

### Analyse opérationnelle

La compromission du canal de mise à jour d'un jeu grand public permet de toucher un très grand nombre de postes, y compris des machines professionnelles où le jeu est installé. Le vecteur est le script du launcher, souvent peu contrôlé par les solutions de sécurité. Les équipes doivent surveiller l'intégrité des scripts de launcher, les exécutions non signées depuis les répertoires de jeu et les accès aux portefeuilles crypto et aux bases d'identifiants navigateur. La réponse inclut la révocation des identifiants et la sécurisation des actifs financiers numériques.

---

### Implications stratégiques

Le secteur du jeu vidéo confirme sa position de cible de choix pour la distribution de malware à grande échelle via la supply chain logicielle. Pour les entreprises, la porosité entre usages personnels et professionnels sur les postes de travail élargit la surface d'attaque au-delà du périmètre IT maîtrisé. Les éditeurs sont incités à renforcer la signature et le contrôle d'intégrité de leurs canaux de mise à jour, sous peine de perte de confiance de leur communauté.

---

### Recommandations

* Contrôler l'intégrité et la signature des scripts de launcher et d'updater sur le parc.
* Restreindre l'installation de jeux et de launchers sur les postes professionnels.
* Surveiller les accès aux portefeuilles crypto et aux identifiants stockés dans les navigateurs.
* Prévoir un canal d'alerte rapide vers les utilisateurs en cas de compromission d'un éditeur.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les launchers et updaters de jeux autorisés sur le parc et leurs mécanismes de mise à jour.
* Restreindre l'exécution aux binaires signés et contrôler les scripts lancés par les updaters.
* Prévoir une procédure de blocage rapide d'un éditeur/launcher et de communication aux utilisateurs.

#### Phase 2 — Détection et analyse

* Surveiller les modifications de scripts de launcher et les exécutions de scripts non signés depuis les répertoires de jeu.
* Détecter les accès aux fichiers de portefeuilles de cryptomonnaies et aux bases d'identifiants navigateur.
* Repérer les connexions sortantes vers des infrastructures de C2 depuis des postes de joueurs.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les postes affectés, supprimer le launcher compromis et bloquer les domaines de distribution.
* Réinitialiser les identifiants des comptes de jeu et des services associés, migrer les fonds des portefeuilles exposés.
* Diffuser une alerte aux utilisateurs et suspendre les mises à jour automatiques.

#### Phase 4 — Activités post-incident

* Analyser les scripts altérés pour identifier le mode d'injection et la fenêtre de compromission.
* Renforcer les contrôles d'intégrité et la signature des mises à jour côté éditeur et côté utilisateur.
* Mettre à jour les règles de détection endpoint sur le vol de portefeuilles et d'identifiants.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les hachages et scripts du launcher altéré sur l'ensemble du parc et dans les journaux de téléchargement.
* Rechercher les accès récents aux répertoires de portefeuilles crypto et aux profils navigateur.
* Analyser les journaux proxy pour identifier les téléchargements de mises à jour hors fenêtre officielle.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1195.002** | Compromise Software Supply Chain — altération des scripts du launcher PC du jeu |
| **T1555** | Credentials from Password Stores — vol d'identifiants |
| **T1539** | Steal Web Session Cookie — possible vol de sessions |
| **T1657** | Financial Theft — vol de portefeuilles de cryptomonnaies |

---

### Sources

* [https://www.bleepingcomputer.com/news/security/nikke-pc-game-launcher-hacked-to-spread-remote-access-data-stealing-malware/](https://www.bleepingcomputer.com/news/security/nikke-pc-game-launcher-hacked-to-spread-remote-access-data-stealing-malware/)


---

<div id="une-fausse-arnaque-a-une-recompense-apple-cash-de-750-dirige-les-utilisateurs-vers-des-promotions-dapplications"></div>

## Une fausse arnaque à une récompense Apple Cash de 750 $ dirige les utilisateurs vers des promotions d'applications

### Résumé

Malwarebytes décrit une page frauduleuse promettant une récompense de 750 dollars en Apple Cash en échange d'une « vérification d'appareil ». La page n'a aucun lien avec Apple et n'effectue aucune vérification : les trois étapes (contrôle d'éligibilité, vérification de l'appareil, réclamation) sont simulées. Le contrôle d'éligibilité est un simple minuteur, la vérification consiste à installer une application (Reco Social) et à jouer à un jeu, et le bouton de réclamation renvoie vers le même lien. La page fabrique de l'urgence avec un compteur de « places restantes » figé à 47 décrémenté toutes les 30 secondes, des pop-ups de réclamations générés aléatoirement et un compte à rebours de session inopérant. Les clics passent par des liens de tracking d'affiliation.

---

### Analyse opérationnelle

Il s'agit d'une fraude à l'affiliation et à l'installation d'applications, sans malware ni vol direct d'identifiants, mais avec collecte potentielle d'informations et dépenses in-app. La détection repose sur le filtrage web des pages de récompense, la surveillance des installations d'applications déclenchées depuis un navigateur et l'analyse des redirections vers des réseaux d'affiliation. La sensibilisation doit cibler les mécanismes d'urgence artificielle et de preuve sociale fabriquée, très efficaces sur les terminaux personnels comme professionnels.

---

### Implications stratégiques

L'usurpation de marques grand public reste un vecteur de fraude à faible coût et à fort rendement, alimenté par l'économie de l'affiliation. Pour les organisations, le risque est surtout réputationnel et lié à l'usage des appareils personnels, mais ces campagnes servent aussi de terrain d'entraînement pour des escroqueries plus élaborées. Les programmes de protection de marque et la coopération avec les hébergeurs restent les leviers les plus efficaces.

---

### Recommandations

* Bloquer les domaines et URL de la campagne et alimenter les listes de blocage internes.
* Sensibiliser les utilisateurs aux fausses promotions et aux compteurs d'urgence artificiels.
* Restreindre l'installation d'applications depuis le navigateur sur les postes professionnels.
* Signaler les pages frauduleuses aux hébergeurs et aux programmes de protection de marque.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Sensibiliser les utilisateurs aux fausses promotions et à la distinction entre Apple Cash et carte cadeau Apple.
* Déployer un filtrage DNS/web des domaines de fraude connus et des liens d'affiliation suspects.
* Établir un canal de signalement simple des pages frauduleuses pour les collaborateurs.

#### Phase 2 — Détection et analyse

* Détecter l'accès à des pages promettant des récompenses financières et utilisant des comptes à rebours ou des compteurs de « places restantes ».
* Surveiller les installations d'applications non référencées déclenchées depuis un navigateur.
* Repérer les redirections vers des liens de tracking d'affiliation depuis des postes internes.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les domaines et URL de la campagne au niveau proxy, DNS et passerelle de messagerie.
* Désinstaller les applications installées à la demande et révoquer les comptes créés.
* Informer les utilisateurs exposés et vérifier l'absence de saisie d'informations personnelles ou bancaires.

#### Phase 4 — Activités post-incident

* Documenter les indicateurs de la campagne et alimenter les listes de blocage.
* Renforcer la sensibilisation sur les mécanismes d'urgence artificielle et de preuve sociale fabriquée.
* Signaler la page aux hébergeurs, aux registrars et aux programmes de protection de marque.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux proxy les accès à des pages de « récompense » et à des liens d'affiliation.
* Rechercher les installations d'applications inhabituelles sur les postes utilisateurs sur les dernières semaines.
* Identifier les campagnes similaires usurpant d'autres marques grand public et mettre à jour les règles de détection.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1656** | Impersonation — usurpation de la marque Apple et de ses partenaires |
| **T1566** | Phishing — page frauduleuse incitant à une « vérification d'appareil » |
| **T1204** | User Execution — installation d'application et création de compte à la demande de la page |

---

### Sources

* [https://www.malwarebytes.com/blog/scams/2026/11/the-fake-750-apple-cash-reward-that-pays-out-nothing](https://www.malwarebytes.com/blog/scams/2026/11/the-fake-750-apple-cash-reward-that-pays-out-nothing)


---

<div id="le-media-ukrainien-kyiv-independent-victime-dune-cyberattaque-russe-presumee"></div>

## Le média ukrainien Kyiv Independent victime d'une cyberattaque russe présumée

### Résumé

Le média ukrainien anglophone Kyiv Independent a vu son site web perturbé par une cyberattaque suspectée d'être d'origine russe, selon The Record. L'article ne précise ni le mode opératoire exact, ni la durée de la perturbation, ni les revendications éventuelles.

---

### Analyse opérationnelle

L'impact immédiat porte sur la disponibilité d'un service de presse : perte de canal de publication, risque de désinformation par usurpation pendant l'indisponibilité, et possible rebond sur les comptes de messagerie ou les réseaux sociaux de la rédaction. Pour un SOC, ce type d'événement impose de traiter la disponibilité comme un actif critique et de corréler les signaux de perturbation avec les tentatives d'accès aux comptes éditoriaux. La surface d'attaque typique d'un média en ligne reste l'hébergement/CDN, le DNS, le CMS et les comptes administrateurs, souvent cibles de phishing ciblé.

---

### Implications stratégiques

Les médias ukrainiens constituent une cible récurrente dans le conflit informationnel : perturber la diffusion, c'est peser sur le récit et la crédibilité des sources indépendantes. Pour les organisations européennes du secteur médiatique, cet événement illustre la nécessité d'intégrer la résilience éditoriale (canaux alternatifs, multi-hébergement) dans la stratégie de risque, au même titre que la protection des données. La non-attribution publique rappelle la difficulté à établir la responsabilité étatique dans un calendrier utile à la décision.

---

### Recommandations

* Mettre en place une surveillance de disponibilité et d'intégrité du site avec alertes temps réel.
* Préparer un site miroir statique et des canaux de publication de secours activables en moins d'une heure.
* Imposer une MFA résistante au phishing sur tous les comptes éditoriaux et administrateurs.
* Segmenter les accès administrateurs via bastion et journaliser toutes les modifications de configuration.
* Établir un contact direct avec l'hébergeur et le registraire DNS pour accélérer la réponse.
* Exercer annuellement un scénario de crise « site indisponible + usurpation de marque ».

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les dépendances critiques du site (hébergeur, CDN, DNS, fournisseur de messagerie) et identifier les points de bascule.
* Préparer un plan de continuité éditoriale : site statique de secours, canaux alternatifs (réseaux sociaux, newsletter, miroirs).
* Durcir les accès administrateurs (MFA résistante au phishing, comptes nominatifs, bastion) et sauvegarder hors ligne les contenus et configurations.
* Établir un canal de communication de crise pré-approuvé avec l'hébergeur et le registraire DNS.

#### Phase 2 — Détection et analyse

* Surveiller la disponibilité et l'intégrité du site (checks HTTP, diff de contenu, certificats TLS) avec alerting 24/7.
* Détecter les modifications non planifiées : enregistrements DNS, redirections, fichiers déposés, comptes créés.
* Corréler avec les signaux de renseignement sur les campagnes visant les médias ukrainiens et les fuites d'identifiants.
* Analyser les journaux d'accès pour repérer des tentatives d'authentification massives ou des accès depuis des géographies inhabituelles.

#### Phase 3 — Confinement, éradication et récupération

* Basculer immédiatement sur l'infrastructure de secours et geler les modifications de configuration.
* Révoquer les sessions et identifiants administrateurs, rotation des secrets et des clés API.
* Isoler les comptes compromis et vérifier l'intégrité des sauvegardes avant restauration.
* Notifier l'hébergeur/registraire et demander la préservation des journaux côté fournisseur.

#### Phase 4 — Activités post-incident

* Reconstruire l'environnement depuis des sources saines et valider l'absence de persistance.
* Retour d'expérience formel : vecteur initial, délai de détection, efficacité du plan de continuité.
* Renforcer la résilience (multi-hébergement, DNSSEC, protection anti-DDoS, durcissement CMS).
* Documenter l'incident pour les autorités compétentes et les partenaires de diffusion.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des artefacts de compromission sur les postes des journalistes et administrateurs (phishing, infostealer, accès VPN).
* Examiner les journaux DNS/CDN sur 30 jours pour des résolutions ou proxys anormaux.
* Traquer les indicateurs connus des campagnes étatiques visant les médias ukrainiens.
* Vérifier l'absence de comptes dormants ou de clés API orphelines sur les plateformes éditoriales.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1498** | Déni de service réseau / perturbation de la disponibilité du site (hypothèse, non confirmée par la source) |
| **T1584** | Compromission d'infrastructure tierce (hébergeur, CDN, DNS) pour perturber un média |

---

### Sources

* [https://therecord.media/ukraine-kyiv-independent-cyberattack](https://therecord.media/ukraine-kyiv-independent-cyberattack)


---

<div id="une-campagne-dhameconnage-via-google-calendar-detourne-des-sessions-et-contourne-le-mfa"></div>

## Une campagne d'hameçonnage via Google Calendar détourne des sessions et contourne le MFA

### Résumé

Une campagne de phishing a utilisé des invitations Google Calendar, des redirections de confiance et de fausses pages de connexion pour détourner des sessions Google d'entreprise et contourner les protections MFA, selon BleepingComputer. L'opération, baptisée CloudFire et suivie par Material Security, a conduit au démantèlement de près de 900 domaines utilisés par les attaquants.

---

### Analyse opérationnelle

Le vecteur Calendar est particulièrement efficace car il s'appuie sur un service légitime et déjà approuvé, ce qui réduit la méfiance des utilisateurs et contourne une partie des filtres de messagerie. Le vol de session permet de rejouer un cookie valide et de neutraliser de fait la MFA : la détection doit donc porter sur le comportement de session (nouvelle IP, nouvel appareil, changement d'ASN) et non uniquement sur l'authentification. Les équipes SOC doivent surveiller les règles de transfert, les délégations de boîte et les consentements OAuth qui suivent souvent ce type de compromission.

---

### Implications stratégiques

La généralisation du SaaS comme socle de travail rend la compromission d'une identité cloud équivalente à une intrusion sur le poste de travail, avec accès direct aux données et aux communications. Le démantèlement de 900 domaines montre l'industrialisation de l'infrastructure de phishing et la nécessité de mécanismes de retrait rapide coordonnés entre éditeurs et hébergeurs. Pour les directions, l'enjeu est le passage à une authentification réellement résistante au phishing, avec un coût de déploiement à arbitrer face à l'augmentation des pertes liées aux compromissions de comptes.

---

### Recommandations

* Généraliser les clés de sécurité FIDO2 pour les comptes à privilèges et les fonctions sensibles.
* Réduire la durée de vie des sessions et lier les sessions à l'appareil.
* Restreindre les invitations Calendar externes et afficher clairement l'origine externe des expéditeurs.
* Détecter les connexions par réutilisation de session depuis des IP/ASN inhabituels.
* Auditer en continu les règles de transfert, délégations et consentements OAuth.
* Intégrer les leurres Calendar réels dans les campagnes de sensibilisation.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Restreindre la création d'invitations Calendar externes et paramétrer l'affichage des expéditeurs externes.
* Déployer une MFA résistante au phishing (clés FIDO2) pour les comptes à privilèges et les cadres dirigeants.
* Configurer des politiques de session conditionnelle (durée de vie courte, liaison à l'appareil, restriction géographique).
* Sensibiliser les utilisateurs aux invitations Calendar inattendues et aux pages de connexion atteintes via redirections.

#### Phase 2 — Détection et analyse

* Détecter les connexions Google depuis des ASN/géographies inhabituels avec réutilisation de session valide.
* Alerter sur les redirections vers des domaines récemment enregistrés depuis les flux de messagerie/calendrier.
* Surveiller les règles de transfert, délégués de boîte et applications OAuth nouvellement consenties.
* Rechercher les invitations Calendar massives ou provenant d'expéditeurs externes inconnus.

#### Phase 3 — Confinement, éradication et récupération

* Révoquer les sessions et tokens de rafraîchissement des comptes identifiés comme compromis.
* Réinitialiser les identifiants et réenrôler la MFA des comptes touchés.
* Bloquer les domaines de phishing identifiés au niveau proxy, DNS et messagerie.
* Supprimer les règles de transfert et révoquer les consentements OAuth suspects.

#### Phase 4 — Activités post-incident

* Analyser l'étendue de la compromission (boîte mail, Drive, Calendar, applications tierces).
* Notifier les contacts internes et externes susceptibles d'avoir reçu des messages frauduleux.
* Renforcer les politiques de session et généraliser les clés de sécurité physiques.
* Mettre à jour les scénarios de sensibilisation à partir des leurres réellement observés.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les journaux d'authentification Google Workspace sur 30 jours pour des sessions réutilisées depuis des IP inconnues.
* Identifier les utilisateurs ayant cliqué sur des invitations Calendar externes et vérifier leurs activités postérieures.
* Traquer les domaines de phishing similaires encore actifs (typosquatting, leurres de connexion).
* Contrôler les applications OAuth tierces autorisées et les boîtes partagées récemment modifiées.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Hameçonnage par lien, via invitations Google Calendar légitimes |
| **T1539** | Vol de cookie/session web pour détourner l'authentification |
| **T1078** | Utilisation de comptes valides (sessions Google détournées) |
| **T1583.001** | Enregistrement de centaines de domaines pour l'infrastructure de phishing |

---

### Sources

* [https://www.bleepingcomputer.com/news/security/google-calendar-phishing-campaign-hijacks-sessions-bypasses-mfa/](https://www.bleepingcomputer.com/news/security/google-calendar-phishing-campaign-hijacks-sessions-bypasses-mfa/)


---

<div id="un-employe-informatique-du-gouvernement-americain-plaide-coupable-davoir-envoye-des-fichiers-top-secret-a-lethiopie"></div>

## Un employé informatique du gouvernement américain plaide coupable d'avoir envoyé des fichiers top secret à l'Éthiopie

### Résumé

Un spécialiste IT américain, Abraham Teklu Lemma, 53 ans, naturalisé américain et titulaire d'une habilitation Top Secret depuis 2020, a plaidé coupable d'avoir transmis des documents sensibles à l'Éthiopie, selon le département de la Justice cité par The Register. Employé entre 2019 et 2023 pour plusieurs entités fédérales (National Reconnaissance Office, département d'État, département de la Justice), il a copié des informations issues d'au moins 133 rapports de renseignement sans autorisation, téléchargé plus de 100 documents, les a gravés sur CD/DVD en supprimant les marquages de classification, et a accepté une peine de 120 à 262 mois de prison.

---

### Analyse opérationnelle

L'affaire illustre une menace interne classique mais à fort impact : l'attaquant n'exploite aucune vulnérabilité technique, il abuse d'habilitations légitimes et de la confiance accordée à un compte privilégié. Les contrôles défaillants portent sur l'absence de vérification du besoin d'en connaître, la faiblesse de la surveillance des accès aux portails classifiés et l'insuffisance du contrôle des supports amovibles et de la gravure. Pour un SOC gouvernemental, la détection doit s'appuyer sur l'analyse comportementale des accès (volume, périmètre, horaires) et sur la corrélation avec les signaux RH.

---

### Implications stratégiques

Cet incident rappelle que la protection du renseignement repose autant sur les contrôles humains et organisationnels que sur la technologie. Il nourrit les débats sur la rigueur des enquêtes de sécurité lors du recrutement, la gestion des doubles emplois entre agences et la surveillance des habilitations multi-entités. Pour les organisations publiques et de défense, l'enjeu est la crédibilité des dispositifs de contrôle interne face aux partenaires et aux opinions publiques, avec un risque réputationnel et diplomatique au-delà de la seule perte d'information.

---

### Recommandations

* Appliquer strictement le besoin d'en connaître et revoir les habilitations à intervalle régulier.
* Journaliser et analyser les accès aux portails classifiés avec détection d'anomalies de volume et de périmètre.
* Contrôler et inventorier les supports amovibles et les opérations de gravure.
* Mettre en place une double validation pour les accès inter-agences et les transferts entre systèmes.
* Intégrer les signaux RH (départs, conflits, changements de statut) dans la détection de la menace interne.
* Former les managers à la reconnaissance des comportements à risque et aux procédures de signalement.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre en œuvre le principe du besoin d'en connaître et revoir périodiquement les habilitations et les accréditations.
* Journaliser et surveiller les accès aux portails classifiés, en particulier hors périmètre métier déclaré.
* Contrôler les supports amovibles et la gravure de médias, avec inventaire et justification.
* Former les managers et les équipes RH/sécurité aux signaux faibles de la menace interne.

#### Phase 2 — Détection et analyse

* Détecter les accès à des rapports hors périmètre d'habilitation ou en volume anormal.
* Alerter sur les activités de copie vers supports amovibles et sur les impressions massives.
* Surveiller les modifications de marquages de classification et les incohérences d'étiquetage.
* Corréler les signaux RH (départs, conflits, changement de statut) avec les comportements d'accès.

#### Phase 3 — Confinement, éradication et récupération

* Suspendre immédiatement les accréditations et les accès de l'individu concerné.
* Saisir et préserver les supports et équipements pour analyse médico-légale.
* Geler les comptes, révoquer les badges et engager la procédure disciplinaire et judiciaire.
* Évaluer l'étendue des informations exposées et informer les autorités compétentes.

#### Phase 4 — Activités post-incident

* Reconstituer la chronologie et le volume exact des données exfiltrées.
* Renforcer la séparation des tâches et la double validation pour les accès inter-agences.
* Réviser les procédures de contrôle des supports et de classification.
* Mettre à jour les programmes de détection de la menace interne et de sensibilisation.

#### Phase 5 — Threat Hunting (proactif)

* Analyser les journaux d'accès aux portails classifiés sur plusieurs années pour des requêtes hors périmètre.
* Rechercher des gravures de médias et des copies de fichiers non justifiées.
* Vérifier les comptes multi-habilitations et les accès croisés entre agences.
* Contrôler les artefacts de suppression de marquages de classification sur les documents exportés.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1078** | Usage abusive de comptes et d'habilitations légitimes (accès à des portails classifiés) |
| **T1052.001** | Exfiltration via support physique (gravure sur CD/DVD) |
| **T1005** | Collecte de données sur les systèmes locaux et portails internes |
| **T1562.001** | Suppression des marquages de classification pour contourner les contrôles |

---

### Sources

* [https://www.theregister.com/security/2026/11/04/us-gov-it-worker-pleads-guilty-to-sending-top-secret-files-to-ethiopia/5307595](https://www.theregister.com/security/2026/11/04/us-gov-it-worker-pleads-guilty-to-sending-top-secret-files-to-ethiopia/5307595)
