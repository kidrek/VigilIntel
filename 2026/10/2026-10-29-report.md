# Table des matières
* [Analyse Stratégique](#analyse-strategique)
* [Synthèses](#syntheses)
  * [Synthèse des acteurs malveillants](#synthese-des-acteurs-malveillants)
  * [Synthèse de l'actualité géopolitique](#synthese-geopolitique)
  * [Synthèse réglementaire et juridique](#synthese-reglementaire)
  * [Synthèse des violations de données](#synthese-des-violations-de-donnees)
  * [Synthèse des vulnérabilités critiques](#synthese-des-vulnerabilites-critiques)
* [Articles](#articles)
  * [Encore une autre campagne ClickFix, (mer. 28 oct.)](#encore-une-autre-campagne-clickfix-mer-28-oct)
  * [GodPotato rebaptisé Wrqsnx avec un stager PowerShell en mémoire ; 68 Go volés à une agence gouvernementale philippine chargée de l'emploi à l'étranger, exposés via un répertoire de staging ouvert](#godpotato-rebaptise-wrqsnx-avec-un-stager-powershell-en-memoire-68-go-voles-a-une-agence-gouvernementale-philippine-chargee-de-lemploi-a-letranger-exposes-via-un-repertoire-de-staging-ouvert)
  * [Des millions de caméras de sécurité menacées : vulnérabilité DoS dans les appareils Intelbras](#des-millions-de-cameras-de-securite-menacees-vulnerabilite-dos-dans-les-appareils-intelbras)
  * [Détecter et atténuer ZDI-CAN-33367 et cinq autres failles Linux](#detecter-et-attenuer-zdi-can-33367-et-cinq-autres-failles-linux)
  * [Au cœur de KeyDrift : analyse de l'activité historique d'UAT-11473 sur Cisco SD-WAN](#au-cur-de-keydrift-analyse-de-lactivite-historique-duat-11473-sur-cisco-sd-wan)
  * [La police saisit le service bulletproof Virtualine lié à des ransomwares et à la cybercriminalité](#la-police-saisit-le-service-bulletproof-virtualine-lie-a-des-ransomwares-et-a-la-cybercriminalite)
  * [Tailscale déclare ne pas avoir appliqué les limites de privilèges dans Tailscale SSH : des pairs autorisés disposant d'un accès de transfert pouvaient atteindre des sockets réservés à root. L'entreprise indique que l'exploitation nécessite un point d'appui autorisé et un accès permis par la politique. Mettez à jour vers la v1.104.4 ou une version ultérieure et examinez les politiques SSH.https://tailscale.com/ssh-investigation-update#Tailscale #SSH #InfoSec #Cybersecurity](#tailscale-declare-ne-pas-avoir-applique-les-limites-de-privileges-dans-tailscale-ssh-des-pairs-autorises-disposant-dun-acces-de-transfert-pouvaient-atteindre-des-sockets-reserves-a-root-lentreprise-indique-que-lexploitation-necessite-un-point-dappui-autorise-et-un-acces-permis-par-la-politique-mettez-a-jour-vers-la-v11044-ou-une-version-ulterieure-et-examinez-les-politiques-sshhttpstailscalecomssh-investigation-updatetailscale-ssh-infosec-cybersecurity)
  * [Un ressortissant ukrainien condamné pour son rôle dans le piratage d'hôpitaux, d'entreprises et de gouvernements dans le cadre de complots de ransomware ayant causé plus de 100 millions de dollars de pertes](#un-ressortissant-ukrainien-condamne-pour-son-role-dans-le-piratage-dhopitaux-dentreprises-et-de-gouvernements-dans-le-cadre-de-complots-de-ransomware-ayant-cause-plus-de-100-millions-de-dollars-de-pertes)
  * [Whitsett, en Caroline du Nord, diffuse une alerte concernant un courriel d'hameçonnage](#whitsett-en-caroline-du-nord-diffuse-une-alerte-concernant-un-courriel-dhameconnage)
  * [NZ : l'attente « incroyablement stressante » des familles endeuillées pour obtenir des réponses après une cyberattaque majeure en NZ](#nz-lattente-incroyablement-stressante-des-familles-endeuillees-pour-obtenir-des-reponses-apres-une-cyberattaque-majeure-en-nz)
  * [Gemini 4 Carbon : ce que le dernier modèle d'IA de Google signifie pour la cybersécurité des entreprises](#gemini-4-carbon-ce-que-le-dernier-modele-dia-de-google-signifie-pour-la-cybersecurite-des-entreprises)
  * [Des organisations américaines attaquées : la campagne de phishing par code d'appareil Skyw4lker exposée](#des-organisations-americaines-attaquees-la-campagne-de-phishing-par-code-dappareil-skyw4lker-exposee)
  * [Veeam corrige une vulnérabilité critique de contournement d'autorisation dans Backup & Replication](#veeam-corrige-une-vulnerabilite-critique-de-contournement-dautorisation-dans-backup-replication)
  * [De fausses notifications de tribunaux américains ciblent plus de 100 000 entreprises avec LodaRAT](#de-fausses-notifications-de-tribunaux-americains-ciblent-plus-de-100-000-entreprises-avec-lodarat)
  * [Qui surveille les surveillants ?](#qui-surveille-les-surveillants)
  * [Neuf serveurs de l'hôpital Bajaj piratés lors d'une cyberattaque à 3 h du matin, données sensibles volées, systèmes chiffrés](#neuf-serveurs-de-lhopital-bajaj-pirates-lors-dune-cyberattaque-a-3-h-du-matin-donnees-sensibles-volees-systemes-chiffres)
  * [Conduent va payer 80 M$ pour régler la troisième plus importante violation de données de santé](#conduent-va-payer-80-m-pour-regler-la-troisieme-plus-importante-violation-de-donnees-de-sante)
  * [Rapport CrowdStrike 2026 sur le paysage des menaces juridiques : la cybercriminalité en tête des attaques, l'activité chinoise s'intensifie](#rapport-crowdstrike-2026-sur-le-paysage-des-menaces-juridiques-la-cybercriminalite-en-tete-des-attaques-lactivite-chinoise-sintensifie)

---

<div id="analyse-strategique"></div>

# ANALYSE STRATÉGIQUE

La journée est dominée par 114 vulnérabilités, contre 34 violations de données, 18 articles, 4 éléments géopolitiques, 2 acteurs de menace et 2 éléments réglementaires. Ce déséquilibre impose une priorisation opérationnelle centrée sur l’exploitabilité réelle et l’exposition externe, plutôt que sur le seul volume de correctifs. Les 34 violations de données confirment une pression persistante sur la détection, la notification et la gestion de crise, avec un risque réputationnel et juridique accru. Le faible nombre d’acteurs de menace identifiés ne doit pas être interprété comme une accalmie : il peut refléter un décalage de reporting ou une activité non encore attribuée. Les 4 signaux géopolitiques et les 2 éléments réglementaires appellent une veille ciblée, notamment sur les secteurs critiques et les obligations de conformité. La priorité CTI du jour est donc de corréler les vulnérabilités à fort impact avec les incidents de fuite de données et les contextes géopolitiques pertinents.

---

<div id="syntheses"></div>

# SYNTHÈSES

<div id="synthese-des-acteurs-malveillants"></div>

## Synthèse des acteurs malveillants

| Nom de l'acteur | Secteur(s) ciblé(s) | Mode opératoire | TTP MITRE ATT&CK | Source(s) |
|---|---|---|---|---|
| **Storm-1567 (alias : Akira)** | santé, industrie manufacturière | Accès initial via services distants ou exploitation de services exposés, chiffrement des systèmes et extorsion par fuite de données. | T1133, T1190, T1486, T1657 | [https://www.yazoul.net/intel/claim/2026-10-28-trulife-ransomware-claim-by-akira-october-2026/?utm_source=mastodon&utm_medium=social](https://www.yazoul.net/intel/claim/2026-10-28-trulife-ransomware-claim-by-akira-october-2026/?utm_source=mastodon&utm_medium=social) |
| **The Gentlemen** | santé, communautés tribales, secteur public | Accès par comptes valides, mouvement latéral, collecte de données, chiffrement et exfiltration à des fins d'extorsion. | T1078, T1021, T1486, T1005, T1567 | [https://beyondmachines.net/event_details/kenaitze-indian-tribe-discloses-data-breach-affecting-over-9300-individuals-t-c-0-8-1/gD2P6Ple2L](https://beyondmachines.net/event_details/kenaitze-indian-tribe-discloses-data-breach-affecting-over-9300-individuals-t-c-0-8-1/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117519135730464805](https://infosec.exchange/@beyondmachines1/117519135730464805) |

---

<div id="synthese-geopolitique"></div>

## Synthèse géopolitique

| Pays/Région | Secteur | Thème | Description | Source(s) |
|---|---|---|---|---|
| **Asie-Pacifique, Chine, Taïwan, États-Unis, Japon, Philippines, Guam** | Télécommunications / Infrastructures critiques (câbles sous-marins) | Capacités chinoises de sabotage des câbles sous-marins trans-Pacifique sans conflit ouvert | Un rapport du China Strategic Risks Institute, publié en septembre 2026 pour la U.S.-China Economic and Security Review Commission, documente la montée en puissance d'outils chinois de sabotage des câbles sous-marins trans-Pacifique, conçus pour être employés sous le seuil du conflit armé. Le rapport s'appuie sur une série d'incidents autour de Taïwan, dont l'endommagement présumé d'une liaison vers les îles Matsu par une barge de travaux chinoise en mars 2026. Son indice de vulnérabilité pondère les câbles selon leur atterrissement à Taïwan, leur traversée d'eaux revendiquées par Pékin et leur passage dans des couloirs maritimes encombrés où la traîne d'ancre fournit un déni plausible. Quatre des dix câbles les plus exposés sont encore en construction (TPU de Google, ORCA de Meta) et leur propriété non chinoise réduirait la retenue de Pékin en cas d'attaque ciblée. Les scénarios de rupture sont sévères : la perte de trois des quatre liaisons directes États-Unis–Taïwan dépasserait la capacité résiduelle, les Philippines dépendent de deux des trois liens directs vers Guam, et une coupure totale des quatre câbles USA–Taïwan laisserait le réseau trans-Pacifique avec environ 2 % de capacité de réserve en pointe ; la perte de JUNO et du Pacific Light Cable Network suffirait à dépasser de 70 % la capacité activée. Le reroutage par l'océan Indien et l'Atlantique ajouterait plus de 900 ms par aller-retour, au-delà des seuils de timeout des processeurs de paiement. Le rapport identifie aussi des engins duals de 4 000 mètres de classe, issus d'un centre de recherche lié au constructeur naval d'État chinois, et une station habitée posée sur les fonds marins prévue vers 2030. La commission qualifie la sécurité des câbles de « problème de conduite de la guerre » et non de simple enjeu de capacité, alors que seulement 62 navires câbliers opèrent dans le monde et que les réparations en Asie-Pacifique prennent déjà 30 jours en moyenne. | [https://www.healthcareinfosecurity.com/asian-submarine-cables-at-risk-from-china-a-33238](https://www.healthcareinfosecurity.com/asian-submarine-cables-at-risk-from-china-a-33238) |
| **Asie-Pacifique, Japon, États-Unis, Chine, Taïwan, Russie, Corée du Nord** | Défense / Politique étrangère | Tournant sécuritaire du Japon et érosion de la confiance dans la garantie de sécurité américaine | L'entretien mené par l'IRIS avec Robert Dujarric (ICAS, Temple University Tokyo) décrit un Japon engagé dans un tournant sécuritaire structurel, provoqué par la convergence de plusieurs facteurs : montée en puissance de la Chine et ses velléités sur Taïwan, guerre en Ukraine qui érige la Russie en menace potentielle du fait du contentieux sur les îles Kouriles, et menace latente nord-coréenne. Le facteur déclenchant est toutefois la perception d'une fiabilité déclinante de la garantie américaine depuis le retour de Donald Trump, qui remet en cause la doctrine de pacifisme et de renoncement aux capacités offensives héritée de 1945. Tokyo cherche donc à élargir ses partenariats régionaux et à développer ses propres capacités militaires, tout en rouvrant prudemment le débat sur l'arme nucléaire. La question de son positionnement dans les tensions sino-taïwanaises devient centrale, de même que la visibilité de l'Europe comme partenaire alternatif. Pour un analyste CTI, cette recomposition implique une hausse des budgets de défense, une accélération des programmes de cyberdéfense et de renseignement, et une multiplication des points de contact avec des partenaires non américains, donc de nouvelles surfaces d'exposition et de nouvelles opportunités de coopération. | [https://www.iris-france.org/le-japon-face-au-defi-trump-avec-robert-dujarric/](https://www.iris-france.org/le-japon-face-au-defi-trump-avec-robert-dujarric/) |
| **Caucase, Turquie, Azerbaïdjan, Moyen-Orient** | Diplomatie / Défense / Énergie | Crise diplomatique dans l'axe turco-azerbaïdjanais « une nation, deux États » | L'analyse de l'IRIS revient sur la dégradation soudaine des relations entre la Turquie d'Erdoğan et l'Azerbaïdjan d'Aliyev, deux États traditionnellement présentés comme formant « une nation, deux États ». Les fondements de cette proximité sont à la fois linguistiques, religieux, culturels et stratégiques, malgré une frontière commune de quelques kilomètres seulement. La crise actuelle, dont les ressorts précis restent à documenter, intervient dans un contexte régional déjà marqué par la guerre en Iran, la recomposition des équilibres du Caucase du Sud et la concurrence d'influence entre la Russie, la Turquie et les puissances occidentales. Une rupture durable de cet axe aurait des conséquences sur la sécurité énergétique (corridors gaziers et pétroliers traversant l'Azerbaïdjan), sur la stabilité du Caucase et sur la capacité d'Ankara à projeter son influence vers l'Asie centrale. Pour la CTI, ce type de crise est propice aux campagnes de désinformation, aux opérations d'influence et aux tentatives de déstabilisation des infrastructures énergétiques et des chaînes logistiques régionales. | [https://www.iris-france.org/turquie-azerbaidjan-crise-diplomatique-entre-allies/](https://www.iris-france.org/turquie-azerbaidjan-crise-diplomatique-entre-allies/) |
| **Moyen-Orient, Iran, Golfe, Détroit d'Ormuz, États-Unis, Chine, Union européenne, Arabie saoudite, Émirats arabes unis, Qatar** | Énergie / Pétrole et gaz / Géopolitique régionale | Guerre en Iran : choc pétrolier mondial et limites de l'autonomie stratégique des puissances moyennes du Golfe | Deux analyses complémentaires éclairent les conséquences de la guerre en Iran déclenchée le 28 février 2026 par les États-Unis et Israël. Sur le plan énergétique, l'IRIS relève que le Brent a atteint en septembre 2026 une moyenne de 114 dollars le baril, deuxième plus haut niveau de l'année après avril (environ 117 dollars), et que la moyenne janvier-septembre (plus de 93 dollars) est la plus élevée depuis 2022. La stratégie iranienne de blocage du détroit d'Ormuz, par lequel transitent normalement environ 20 millions de barils par jour, ainsi que les frappes contre des installations pétrolières et gazières des pays arabes du Golfe, ont réduit l'offre mondiale et reconfiguré les flux. Les produits raffinés sont les plus touchés, le gazole cotant près du double du brut, ce qui pèse sur les revenus des États du Golfe et met en danger leur modèle économique. Les pays importateurs ont puisé dans leurs stocks : l'AIE a décidé le 11 mars la mise sur le marché de 400 millions de barils, record historique depuis 1974, et les stocks mondiaux auraient chuté de 509 millions de barils entre l'avant-guerre et fin septembre 2026. Sur le plan stratégique, RUSI démonte la thèse d'un « moment des puissances moyennes » et d'un retrait américain : les États du Golfe (Émirats, Arabie saoudite, Qatar) diversifient effectivement leurs relations avec la Chine et la Russie, jouent un rôle de médiateurs et résistent davantage aux préférences américaines, mais cette autonomie accrue s'exerce sous une architecture de sécurité américaine intacte (bases, renseignement, logistique, puissance navale et aérienne). La guerre en Iran illustre cette dépendance persistante : la capacité de Washington à revenir massivement dans une crise demeure l'arbitre ultime, et l'accord de défense trilatéral signé à La Mecque entre la Turquie, l'Arabie saoudite et le Pakistan témoigne d'une recherche d'assurance alternative sans rupture avec Washington. | [https://www.iris-france.org/guerre-en-iran-et-tensions-au-moyen-orient-quels-bouleversements-pour-les-marches-petroliers/](https://www.iris-france.org/guerre-en-iran-et-tensions-au-moyen-orient-quels-bouleversements-pour-les-marches-petroliers/)<br>[https://www.rusi.org/explore-our-research/publications/commentary/middle-powers-and-illusion-post-america-middle-east-0](https://www.rusi.org/explore-our-research/publications/commentary/middle-powers-and-illusion-post-america-middle-east-0) |

---

<div id="synthese-reglementaire"></div>

## Synthèse réglementaire et juridique

| Titre | Auteur/Organisme | Date | Juridiction | Référence | Description | Source(s) |
|---|---|---|---|---|---|---|
| CTI-RL-2026-10-28-WINE-PROVENANCE | Wine Australia (ELISS / Wine Australia Licensing and Approval System) ; Europol et autorités judiciaires françaises, italiennes et suisses ; éditeurs de plateformes de traçabilité | 2026-10-28 | Australie (régime à l'export), Union européenne (appellations d'origine protégées), international | CTI-RL-2026-10-28-WINE-PROVENANCE | L'article déplace le périmètre de la lutte anti-fraude vinicole du produit physique vers les systèmes d'information qui garantissent son authenticité. Historiquement, la fraude portait sur le contenant et le contenu (remplissage, réemploi de bouteilles authentiques, reproduction d'étiquettes, fausse indication géographique). Désormais, les registres d'export, les bases d'images d'étiquettes et les plateformes d'authentification s'intercalent entre la bouteille et la revendication de provenance : la valeur économique repose autant sur le vin que sur la relation entre le produit et les données qui le décrivent (producteur, millésime, cépage, indication géographique, pays d'origine, méthode de production). La compromission de ces plateformes permettrait donc à un fraudeur de réécrire l'identité d'un vin sans toucher à la bouteille, ce qui constitue une rupture de la frontière de sécurité : l'intégrité des données de provenance devient une composante de l'intégrité du produit. Le texte relativise les chiffres souvent cités (une bouteille sur cinq contrefaite, coût de plusieurs dizaines de milliards de dollars) : Recorded Future a montré en 2022 que la mesure est intrinsèquement difficile, les incidents restant souvent non détectés ou non déclarés, tout en identifiant plus de 93 millions de bouteilles liées à des affaires publiquement rapportées entre janvier 2020 et juin 2022, dont moins de 5 000 vins de luxe confirmés — signe d'une fraude industrielle et non seulement de collection. L'affaire d'octobre 2024, soutenue par Europol avec la France, l'Italie et la Suisse, illustre le passage de produits contrefaits dans des circuits commerciaux légitimes (six interpellations, quatorze perquisitions, bouteilles jusqu'à 15 000 euros). Le cas australien est le plus structurant sur le plan réglementaire : les exportateurs de vin conditionné doivent téléverser les images d'étiquettes avant approbation, et ELISS les rend consultables par importateurs, distributeurs, détaillants et consommateurs afin de vérifier la correspondance entre étiquette et exportation légitime. Ce dispositif crée de facto une obligation de conformité documentaire et un point de contrôle numérique dont la sécurité (contrôle d'accès, intégrité des images, journalisation, disponibilité) conditionne la confiance du marché. Le risque principal n'est pas la contrefaçon de bouteille mais l'usurpation ou l'altération de l'enregistrement d'export, l'injection d'étiquettes frauduleuses dans le référentiel, la compromission de comptes d'exportateurs ou la manipulation de la chaîne de traçabilité en aval. | [https://www.healthcareinfosecurity.com/blogs/wine-frauds-next-frontier-data-bottle-p-4232](https://www.healthcareinfosecurity.com/blogs/wine-frauds-next-frontier-data-bottle-p-4232) |
| CTI-RL-2026-10-27-ASD-AMADEY | Australian Signals Directorate (ASD) ; en coopération de fait avec le cadre d'Operation Endgame (Europol et partenaires) | 2026-10-27 | Australie (opérations de cyberdéfense offensive autorisées par le gouvernement australien), portée extraterritoriale sur des infrastructures criminelles hébergées à l'étranger | CTI-RL-2026-10-27-ASD-AMADEY | L'Australian Signals Directorate indique avoir accédé au back-end d'une opération criminelle exploitant le malware Amadey et avoir déconnecté ce contrôleur de 180 000 machines infectées dans le monde, dont certaines en Australie. L'élément notable sur le plan juridique et réglementaire est le cadre d'autorisation : les opérations cyber offensives de l'ASD requièrent une approbation explicite du gouvernement australien et peuvent viser à désactiver des infrastructures criminelles à l'étranger. Le rapport annuel sur les menaces publié le 27 octobre 2026 ne décrit pas cette opération, ce qui souligne l'écart entre l'action technique et la transparence publique. Amadey, vendu comme service depuis 2018, fonctionne en panels indépendants par acheteur : chaque botnet dispose de ses propres serveurs de commande et contrôle, ce qui limite l'effet systémique d'une neutralisation — ESET recense 53 botnets Amadey distincts sans infrastructure partagée. La fonction principale d'Amadey est le téléchargement d'autres charges, notamment l'infostealer StealC, ainsi que le vol d'identifiants et l'accès distant. Les vecteurs d'infection dominants restent les fausses mises à jour logicielles, les installateurs de logiciels piratés et d'autres loaders. La déconnexion d'un contrôleur ne remédie pas aux vols déjà commis : les identifiants dérobés peuvent rester dormants des mois et les cookies de session volés permettent de contourner l'authentification multifacteur. L'opération s'inscrit dans la continuité d'Operation Endgame, qui a ciblé du 15 au 19 juin des serveurs associés à Amadey, StealC et SocGholish ; l'Australie figure parmi les neuf pays partenaires du cadre, sans apparaître dans la liste des pays de la semaine d'action de juin, et l'ASD n'est pas mentionnée dans l'annonce Europol. Un second cas est rapporté : l'ASD, alertée de la mise en vente de 5 téraoctets de données volées à une entreprise ignorante de la compromission (documents métier, données personnelles, identifiants et mots de passe), a détruit les données avant leur vente, dont environ 4,8 millions d'enregistrements concernant des Australiens. Ces deux cas posent des questions de proportionnalité, de base légale, de coopération transfrontalière et de preuve, ainsi que d'obligation de notification pour les victimes. | [https://thehackernews.com/2026/10/australia-gets-into-amadey-malware.html](https://thehackernews.com/2026/10/australia-gets-into-amadey-malware.html) |

---

<div id="synthese-des-violations-de-donnees"></div>

## Synthèse des violations de données

| Secteur | Victime | Données compromises | Volume estimé | Source(s) |
|---|---|---|---|---|
| **Transverse — vie privée numérique, OPSEC des équipes CTI/OSINT** | Internautes et analystes utilisant un navigateur web (empreinte numérique relevée via AmIUnique) | Pas de données volées au sens d'une base : exposition continue d'attributs de fingerprinting (OS, navigateur et version, langue, fuseau horaire, résolution écran, polices, cœurs CPU, mémoire, empreinte canvas/WebGL, plugins, adresse IP publique, signal Do Not Track). | Inconnu | [https://www.cyberengage.org/post/what-your-browser-tells-every-website-you-visit-and-why-i-finally-checked-mine](https://www.cyberengage.org/post/what-your-browser-tells-every-website-you-visit-and-why-i-finally-checked-mine) |
| **Secteur public — sécurité intérieure, immigration et cybersécurité gouvernementale (États-Unis)** | Département de la Sécurité intérieure des États-Unis (DHS) et sept agences composantes, dont ICE, CBP, USCIS et CISA | Données RH et annuaire de plus de 41 000 employés et contractuels : noms, adresses électroniques professionnelles, numéros de téléphone, adresses de bureaux, agences et unités d'affectation, appartenance à des groupes de permissions internes (dont groupes liés aux opérations sous couverture), références à des systèmes internes, à des programmes de surveillance et à des outils analytiques ; données remontant sur plusieurs années. | 41000 | [https://www.wired.com/story/massive-leak-exposes-41000-homeland-security-workers-including-undercover-ice-agents/](https://www.wired.com/story/massive-leak-exposes-41000-homeland-security-workers-including-undercover-ice-agents/)<br>[https://infosec.exchange/@cloud/117521057481809607](https://infosec.exchange/@cloud/117521057481809607)<br>[https://cyberscoop.com/dhs-employee-data-leak-ddosecrets/](https://cyberscoop.com/dhs-employee-data-leak-ddosecrets/)<br>[https://mastobot.ping.moi/@Bobe_bot/117521017391654379](https://mastobot.ping.moi/@Bobe_bot/117521017391654379) |
| **Santé — hôpitaux ruraux (Caroline du Sud, États-Unis)** | Hôpitaux ruraux de Caroline du Sud (programme fédéral/étatique Project Lifeline 250) | Aucune donnée compromise dans cet article : il s'agit d'un programme de prévention. Données à protéger en priorité : dossiers patients, données de facturation, systèmes de soins critiques et dispositifs médicaux connectés. | Inconnu | [https://www.healthcareinfosecurity.com/feds-south-carolina-launch-rural-hospital-cyber-pilot-a-33239](https://www.healthcareinfosecurity.com/feds-south-carolina-launch-rural-hospital-cyber-pilot-a-33239) |
| **Transport / services — location de véhicules (Japon)** | Times Car (Japon) — groupe de location de véhicules | Non précisé dans la source. À considérer par défaut comme potentiellement exposés : données d'identification clients (nom, adresse, date de naissance, numéro de permis de conduire), coordonnées, historiques de réservation et de location, et éventuellement données de paiement. | Inconnu | [https://databreaches.net/2026/10/28/jpn-times-car-reporting-%c2%a55-5-billion-loss-has-firms-bracing-for-data-breach-fallout/](https://databreaches.net/2026/10/28/jpn-times-car-reporting-%c2%a55-5-billion-loss-has-firms-bracing-for-data-breach-fallout/) |
| **Services financiers — exchange de crypto-actifs et gestion d'actifs (Corée du Sud)** | Bithumb (exchange crypto, Corée du Sud), Daishin Securities et Mirae Asset Global Investments | Données du système mobile interne de Bithumb (communications et annuaire collaborateurs) ; exposition éventuelle de données de membres en cours d'évaluation. Pour Daishin Securities : données d'environ 38 490 clients. Avoirs crypto déclarés hors de danger. | 38490 | [https://databreaches.net/2026/10/28/kr-bithumb-discloses-data-leak-after-internal-system-breach-one-of-three-financial-firm-breaches-reported-that-day/](https://databreaches.net/2026/10/28/kr-bithumb-discloses-data-leak-after-internal-system-breach-one-of-three-financial-firm-breaches-reported-that-day/) |
| **Internet / hébergement et services numériques (Japon)** | GMO Internet Group (géant internet japonais) et ses clients | Non précisé dans la source. Périmètre à considérer : données clients hébergées chez l'opérateur, données de comptes et d'authentification, données de facturation et de support, et éventuellement données internes de l'entreprise. | Inconnu | [https://databreaches.net/2026/10/28/japanese-internet-giant-gmo-tells-customers-to-shut-down-and-disconnect-pcs-from-the-internet-following-data-breach-and-ransomware-threat/](https://databreaches.net/2026/10/28/japanese-internet-giant-gmo-tells-customers-to-shut-down-and-disconnect-pcs-from-the-internet-following-data-breach-and-ransomware-threat/) |
| **Santé publique — hôpital (Territoire du Nord, Australie)** | Northern Territory Health — Royal Darwin Hospital (RDH), Australie | Données de santé de patients du Royal Darwin Hospital — périmètre exact non établi, l'estimation initiale de cinq patients ayant été reconnue erronée. À considérer par défaut : identité, coordonnées, motifs de consultation, diagnostics, traitements et éventuellement données sensibles (santé mentale, maladies infectieuses). | Inconnu | [https://databreaches.net/2026/10/28/au-northern-territory-health-backtracks-on-claim-only-five-patients-impacted-by-rdh-privacy-breach/](https://databreaches.net/2026/10/28/au-northern-territory-health-backtracks-on-claim-only-five-patients-impacted-by-rdh-privacy-breach/) |
| **Santé** | Établissements de santé et défendeurs dans les litiges de violation de données (États-Unis) | Non précisé dans la source : l'article traite du cadre procédural des litiges, pas d'un jeu de données spécifique. | Inconnu | [https://databreaches.net/2026/10/28/traceability-becomes-the-new-battleground-in-healthcare-data-breach-litigation/](https://databreaches.net/2026/10/28/traceability-becomes-the-new-battleground-in-healthcare-data-breach-litigation/) |
| **Éducation / EdTech** | PowerSchool | Données d'élèves et de personnels scolaires gérées par la plateforme (périmètre exact non détaillé dans la source). | Inconnu | [https://databreaches.net/2026/10/28/court-denies-motions-to-dismiss-in-powerschool-data-breach-litigation/](https://databreaches.net/2026/10/28/court-denies-motions-to-dismiss-in-powerschool-data-breach-litigation/) |
| **Secteur public / Sécurité communautaire** | Crime Stoppers (Canada) | Données relatives à des signalements et à des personnes associées à Crime Stoppers (périmètre exact non communiqué). | Inconnu | [https://databreaches.net/2026/10/27/privacy-commissioner-of-canada-to-investigate-data-breach-involving-crime-stoppers/](https://databreaches.net/2026/10/27/privacy-commissioner-of-canada-to-investigate-data-breach-involving-crime-stoppers/) |
| **Santé / Dispositifs médicaux et produits de consommation** | Trulife | Selon l'acteur uniquement : informations détaillées sur les employés (scans de passeports, permis de conduire, certificats médicaux, actes de naissance), contrats et accords, dossiers confidentiels relatifs à des violations et licenciements, documents financiers, accords de confidentialité. | Inconnu | [https://www.yazoul.net/intel/claim/2026-10-28-trulife-ransomware-claim-by-akira-october-2026/?utm_source=mastodon&utm_medium=social](https://www.yazoul.net/intel/claim/2026-10-28-trulife-ransomware-claim-by-akira-october-2026/?utm_source=mastodon&utm_medium=social) |
| **Secteur public / Sécurité intérieure** | U.S. Department of Homeland Security (DHS) | Noms, intitulés de poste, adresses e-mail professionnelles, numéros de téléphone mobiles, adresses de bureau, appartenance à des groupes d'utilisateurs internes, informations sur les accès à des programmes et outils (services Microsoft, éditeurs de documents, applications d'interface, outils d'IA et recherches liées à des groupes d'attaque). | 40000 | [https://en.hacks.gr/dierreysan-prosopika-stoicheia-40-000-ergazomenon-sto-ypoyrgeio-esoterikis-asfaleias-ton-ipa/](https://en.hacks.gr/dierreysan-prosopika-stoicheia-40-000-ergazomenon-sto-ypoyrgeio-esoterikis-asfaleias-ton-ipa/) |
| **Assurance** | Mirae Asset Life Insurance | Informations personnelles des clients et informations de crédit (périmètre détaillé non communiqué). | Inconnu | [https://beyondmachines.net/event_details/mirae-asset-life-insurance-discloses-customer-data-breach-following-cyberattack-9-r-g-9-b/gD2P6Ple2L](https://beyondmachines.net/event_details/mirae-asset-life-insurance-discloses-customer-data-breach-following-cyberattack-9-r-g-9-b/gD2P6Ple2L) |
| **Hébergement internet / services cloud (bureau virtuel pour traders)** | GMO Internet (service Onamae.com) | Données clients hébergées sur les serveurs concernés, informations potentiellement consultées, et possibles identifiants et historiques de comptes de trading (périmètre non confirmé). | 27000 | [https://osintsights.com/gmo-internet-breach-exposes-remote-access-vulnerabilities?utm_source=mastodon&utm_medium=social](https://osintsights.com/gmo-internet-breach-exposes-remote-access-vulnerabilities?utm_source=mastodon&utm_medium=social)<br>[https://techcrunch.com/2026/10/27/japan-internet-giant-gmo-says-hackers-posted-stolen-customer-data/](https://techcrunch.com/2026/10/27/japan-internet-giant-gmo-says-hackers-posted-stolen-customer-data/)<br>[https://mastodon.thenewoil.org/@thenewoil/117519836938564774](https://mastodon.thenewoil.org/@thenewoil/117519836938564774) |
| **Services financiers / Courtage en ligne** | Daishin Securities | Noms des clients, adresses e-mail, adresses de résidence, identifiants de télécommunications, noms de banques, numéros de comptes de dépôt et de retrait (chiffrés), numéros de comptes Daishin Securities (chiffrés), numéros de téléphone mobile (chiffrés). | 38490 | [https://beyondmachines.net/event_details/daishin-securities-discloses-data-breach-affecting-over-38000-customers-p-t-5-l-z/gD2P6Ple2L](https://beyondmachines.net/event_details/daishin-securities-discloses-data-breach-affecting-over-38000-customers-p-t-5-l-z/gD2P6Ple2L) |
| **Transport public / mobilité urbaine** | Compagnie des Transports Strasbourgeois (CTS) | Données d'identification et de contact des clients de la CTS (identité, coordonnées, données de compte/abonnement) ; périmètre exact à confirmer par l'enquête. | 230000 | [https://mastobot.ping.moi/@cyberveille/117519955147314128](https://mastobot.ping.moi/@cyberveille/117519955147314128) |
| **Éducation (réseau d'écoles publiques)** | Summit Public Schools | Dossiers élèves et personnel : noms, dates de naissance, adresses domiciliaires, coordonnées, données scolaires et RH ; 115 Go au total. | Inconnu | [https://hackread.com/summit-public-schools-breach-student-staff-data/](https://hackread.com/summit-public-schools-breach-student-staff-data/)<br>[https://mstdn.social/@Hackread/117519886265240608](https://mstdn.social/@Hackread/117519886265240608) |
| **Cryptomonnaie / services financiers** | Coinbase (via le prestataire Amplitude) | Adresses e-mail, numéros de téléphone et informations de contact clients ; nombre exact non divulgué. | Inconnu | [https://beyondmachines.net/event_details/coinbase-discloses-customer-data-exposure-following-third-party-analytics-breach-7-c-t-b-p/gD2P6Ple2L](https://beyondmachines.net/event_details/coinbase-discloses-customer-data-exposure-following-third-party-analytics-breach-7-c-t-b-p/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117519843511060010](https://infosec.exchange/@beyondmachines1/117519843511060010) |
| **Santé (cabinet d'orthopédie)** | Center for Bone & Joint Surgery of the Palm Beaches | Noms, coordonnées, détails des demandes de rendez-vous et autres informations soumises volontairement via les formulaires en ligne ; 5 461 personnes potentiellement concernées. | 5461 | [https://beyondmachines.net/event_details/center-for-bone-joint-surgery-discloses-data-breach-affecting-over-5400-individuals-e-n-q-y-6/gD2P6Ple2L](https://beyondmachines.net/event_details/center-for-bone-joint-surgery-discloses-data-breach-affecting-over-5400-individuals-e-n-q-y-6/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117519607556881615](https://infosec.exchange/@beyondmachines1/117519607556881615) |
| **Télécommunications / fournisseur d'accès internet** | Sony Network Communications | Noms, numéros de téléphone, adresses e-mail et autres données personnelles d'abonnés actuels et anciens ; 2,5 millions d'enregistrements. | 2500000 | [https://osintsights.com/sony-isp-data-breach-exposes-25-million-customer-records?utm_source=mastodon&utm_medium=social](https://osintsights.com/sony-isp-data-breach-exposes-25-million-customer-records?utm_source=mastodon&utm_medium=social)<br>[https://mastodon.social/@Analyst207/117519575675626159](https://mastodon.social/@Analyst207/117519575675626159) |
| **Santé (cabinet dentaire)** | Wichita Family Dental | Noms complets, dates de naissance, adresses, numéros de sécurité sociale, permis de conduire et pièces d'identité, identifiants fiscaux, informations de comptes financiers, données de cartes de paiement, informations d'assurance santé et dossiers dentaires ; 1 273 personnes. | 1273 | [https://beyondmachines.net/event_details/wichita-family-dental-discloses-data-breach-affecting-over-1200-individuals-x-d-a-r-5/gD2P6Ple2L](https://beyondmachines.net/event_details/wichita-family-dental-discloses-data-breach-affecting-over-1200-individuals-x-d-a-r-5/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117519371620539252](https://infosec.exchange/@beyondmachines1/117519371620539252) |
| **Santé et services publics tribaux** | Kenaitze Indian Tribe (KIT) | Noms complets, dates de naissance, numéros de sécurité sociale, permis de conduire et pièces d'identité, numéros de comptes financiers, informations d'assurance santé et données médicales ; 9 319 personnes. | 9319 | [https://beyondmachines.net/event_details/kenaitze-indian-tribe-discloses-data-breach-affecting-over-9300-individuals-t-c-0-8-1/gD2P6Ple2L](https://beyondmachines.net/event_details/kenaitze-indian-tribe-discloses-data-breach-affecting-over-9300-individuals-t-c-0-8-1/gD2P6Ple2L)<br>[https://infosec.exchange/@beyondmachines1/117519135730464805](https://infosec.exchange/@beyondmachines1/117519135730464805) |
| **Technologie / Édition de logiciels — outils de développement assistés par IA** | Warp (plateforme d'agents IA pour développeurs) | Journaux d'exécution d'agents IA, données de télémétrie d'usage, historiques de conversations et contextes de développement susceptibles de contenir du code source, des extraits de configuration et des secrets techniques. | Inconnu | [https://www.bleepingcomputer.com/news/security/warp-discloses-breach-exposing-ai-agent-logs-user-telemetry-data/](https://www.bleepingcomputer.com/news/security/warp-discloses-breach-exposing-ai-agent-logs-user-telemetry-data/)<br>[https://mastodon.thenewoil.org/@thenewoil/117518893066032484](https://mastodon.thenewoil.org/@thenewoil/117518893066032484) |
| **Télécommunications / Fournisseur d'accès Internet (Japon)** | So-net / Plala (groupe Sony) | Données d'identification et de contact des abonnés (noms, adresses, identifiants de comptes), potentiellement des informations de facturation et des éléments d'identité, dans un volume d'environ 2,58 millions d'enregistrements. | 2580000 | [https://theperimetersite.com/report/411](https://theperimetersite.com/report/411)<br>[https://infosec.exchange/@theperimetersite/117518584671548815](https://infosec.exchange/@theperimetersite/117518584671548815) |
| **Commerce de détail / Santé visuelle et auditive (France)** | Alain Afflelou (enseigne française d'optique et d'audioprothèse) | Données personnelles de clients (nom, coordonnées, informations de compte), données de commande et, potentiellement, données de santé liées aux activités d'optique et d'audioprothèse. | Inconnu | [https://cyberveille.curated.co/issues/567](https://cyberveille.curated.co/issues/567)<br>[https://mastodon.social/@cyberveille/117517735158715088](https://mastodon.social/@cyberveille/117517735158715088) |
| **Énergie / Utilities (France)** | ENGIE | Données clients issues des activités marketing : identité, coordonnées, préférences et éventuellement données contractuelles ou de consommation, selon le périmètre de la plateforme compromise. | Inconnu | [https://www.bleepingcomputer.com/news/security/energy-giant-engie-discloses-data-breach-affecting-customers/](https://www.bleepingcomputer.com/news/security/energy-giant-engie-discloses-data-breach-affecting-customers/)<br>[https://infosec.exchange/@edwardk/117517768047459377](https://infosec.exchange/@edwardk/117517768047459377) |
| **Santé / Assurance maladie (États-Unis)** | Denver Health Medical Plan (DHMP) — via le prestataire SquareML | Noms, dates de naissance, codes postaux, ville et État, informations démographiques, indicateurs de santé, données d'éligibilité au plan de santé, admissions hospitalières, nom du prestataire, données d'admission et de transfert. Ni numéros de sécurité sociale ni données financières selon la victime. | 238083 | [https://www.securityweek.com/vendor-key-leak-puts-data-of-238000-denver-health-plan-members-at-risk/](https://www.securityweek.com/vendor-key-leak-puts-data-of-238000-denver-health-plan-members-at-risk/)<br>[https://infosec.exchange/@edwardk/117517762214894023](https://infosec.exchange/@edwardk/117517762214894023) |
| **Secteur public — forces de l'ordre (Royaume-Uni)** | Forces de police britanniques — via leurs fournisseurs informatiques tiers | Données policières sensibles détenues par des prestataires : informations d'enquête, données relatives à des victimes, témoins ou suspects, selon les incidents non détaillés dans le rapport. | Inconnu | [https://therecord.media/uk-police-data-breached-from-suppliers-watchdog-report](https://therecord.media/uk-police-data-breached-from-suppliers-watchdog-report)<br>[https://infosec.exchange/@edwardk/117517760274941096](https://infosec.exchange/@edwardk/117517760274941096) |
| **Développement logiciel / Cloud / Multi-secteurs (postes de développeurs)** | Développeurs et organisations utilisant des assistants IA (Claude, ChatGPT Desktop, Codex, Cursor, Windsurf, GitHub Copilot, Gemini CLI) | Identifiants et cookies de navigateurs, jetons de session et fichiers d'authentification des assistants IA, clés API, clés privées SSH, identifiants Git, fichiers de configuration AWS/Azure/GCP, données de wallets crypto, identifiants VPN, FTP/SFTP et gestionnaires de mots de passe, historiques de conversations IA. | Inconnu | [https://www.darkreading.com/endpoint-security/aokigahara-stealer-developer-keyrings-ai-assistants](https://www.darkreading.com/endpoint-security/aokigahara-stealer-developer-keyrings-ai-assistants)<br>[https://infosec.exchange/@edwardk/117517757494171873](https://infosec.exchange/@edwardk/117517757494171873) |
| **E-commerce / Services de paiement en ligne** | Convertr (plateforme e-commerce) et ses marchands clients | Données de carte bancaire saisies lors du checkout (numéro de carte, date d'expiration, cryptogramme), ainsi que les informations de formulaire de paiement transmises au script compromis. | Inconnu | [https://www.bleepingcomputer.com/news/security/hackers-hijack-convertr-analytics-script-to-steal-payment-card-data/](https://www.bleepingcomputer.com/news/security/hackers-hijack-convertr-analytics-script-to-steal-payment-card-data/)<br>[https://infosec.exchange/@edwardk/117517755260128666](https://infosec.exchange/@edwardk/117517755260128666) |
| **Transverse — tous secteurs (cible privilégiée : entreprises utilisant SSO/MFA et collaborateurs nomades)** | Multiples organisations (campagnes de phishing génériques ciblant les employés) | Identifiants (noms d'utilisateur et mots de passe), codes MFA à usage unique interceptés, cookies de session et jetons d'authentification permettant le détournement de comptes d'entreprise et l'accès aux applications SaaS/SSO. | Inconnu | [https://thehackernews.com/2026/10/ai-generated-fake-login-pages-are.html](https://thehackernews.com/2026/10/ai-generated-fake-login-pages-are.html)<br>[https://infosec.exchange/@edwardk/117517753033440956](https://infosec.exchange/@edwardk/117517753033440956) |
| **Cryptomonnaies / matériel de sécurité (hardware wallets) — e-commerce** | Keystone (fabricant de portefeuilles matériels crypto) | Données clients : noms, coordonnées, adresses de livraison et détails de commande (25 964 enregistrements acheteurs 2024-2026 + 12 873 enregistrements de paniers non finalisés). Secret technique : clé de vérification d'authenticité des hardware wallets. Non concernés : données de carte bancaire, coordonnées bancaires, numéros de pièce d'identité, phrases de récupération et clés privées des portefeuilles. | 38837 | [https://thehackernews.com/2026/10/keystone-to-destroy-18835-hardware.html](https://thehackernews.com/2026/10/keystone-to-destroy-18835-hardware.html)<br>[https://infosec.exchange/@edwardk/117517751528486036](https://infosec.exchange/@edwardk/117517751528486036) |
| **Commerce de détail — optique et audioprothèse (réseau de franchises, France et international)** | Afflelou (Alain Afflelou — opticien et audioprothésiste, France) | Non confirmé. Aucune donnée n'a été vérifiée ni publiée. Exposition potentielle (non avérée) : données clients, informations de franchisés, données financières et corporate. | Inconnu | [https://www.yazoul.net/intel/claim/2026-10-27-afflelou-ransomware-claim-by-emperador-oct-2026/?utm_source=mastodon&utm_medium=social](https://www.yazoul.net/intel/claim/2026-10-27-afflelou-ransomware-claim-by-emperador-oct-2026/?utm_source=mastodon&utm_medium=social)<br>[https://infosec.exchange/@Matchbook3469/117518864735897119](https://infosec.exchange/@Matchbook3469/117518864735897119) |
| **Secteur public — administration fiscale (France)** | Direction générale des Finances publiques (DGFiP) — site des impôts (France) | Non précisé dans la source accessible. Compte tenu de la nature du système visé, l'exposition potentielle porte sur des données fiscales de contribuables (identité, adresse, revenus, situation familiale, données bancaires de remboursement) — périmètre exact non confirmé. | Inconnu | [https://www.lemonde.fr/pixels/article/2026/10/28/piratage-du-site-des-impots-un-deuxieme-suspect-age-de-16-ans-mis-en-examen_6801643_4408996.html](https://www.lemonde.fr/pixels/article/2026/10/28/piratage-du-site-des-impots-un-deuxieme-suspect-age-de-16-ans-mis-en-examen_6801643_4408996.html) |

---

<div id="synthese-des-vulnerabilites-critiques"></div>

## Synthèse des vulnérabilités critiques

| CVE-ID | Score CVSS | EPSS | CISA KEV | Produit affecté | Type de vulnérabilité | Impact | Exploitation | Mesures de contournement | Source(s) |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2026-114409** | N/A | N/A | FALSE | Docker Desktop versions antérieures à 4.97.0 | Multiples vulnérabilités (atteinte à la confidentialité des données, contournement de la politique de sécurité) | Sur un poste de développement, l'exploitation peut conduire à la divulgation de données locales ou de secrets applicatifs et à la neutralisation de contrôles de sécurité de Docker Desktop, ouvrant la voie à une évasion vers l'hôte ou à l'exécution de charges non approuvées. | None | Mettre à jour Docker Desktop vers 4.97.0 ou supérieure en suivant le bulletin éditeur. En attendant, limiter l'installation aux postes à besoin justifié, restreindre les droits sur le groupe docker-users, contrôler les registres autorisés et surveiller les accès au socket Docker. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1401/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1401/) |
| **CVE-2026-99999** | N/A | N/A | FALSE | Hyperviseurs KVM et autres solutions de virtualisation, ainsi que les plateformes de conteneurs | Multiples vulnérabilités (atteinte à la confidentialité des données, contournement de la politique de sécurité) | Exposition de données locales et affaiblissement des contrôles de sécurité de Docker Desktop, avec un risque d'élévation de privilèges sur le poste hôte si la vulnérabilité est combinée à une mauvaise configuration du démon. | None | Appliquer les livepatches noyau fournis par l'éditeur ou déployer un noyau corrigé, planifier le redémarrage des nœuds non couverts, restreindre les conteneurs privilégiés et l'accès aux périphériques de virtualisation, et renforcer la segmentation entre charges de travail. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1401/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1401/)<br>[https://www.netmeister.org/blog/defense-ddos.html](https://www.netmeister.org/blog/defense-ddos.html)<br>[https://partychickens.net/@mason/117520091018296246](https://partychickens.net/@mason/117520091018296246) |
| **CVE-2026-109618** | 9.2 | N/A | FALSE | Palo Alto Networks PAN-OS (branches 10.2, 11.1, 11.2, 12.1, 12.2) et implémentations PHP vulnérables au mécanisme session.upload_progress (PHP2Shell) | Exécution de code arbitraire à distance sans authentification (corruption mémoire) | Compromission complète du serveur web : exécution de commandes arbitraires sous l'identité du compte de service, vol de secrets applicatifs et de bases de données, installation de webshells, pivot vers les systèmes internes. L'exposition est d'autant plus large que PHP est massivement déployé. | Active | Appliquer sans délai les correctifs PAN-OS des branches concernées ; pour les versions sans correctif (12.1.4-h13, 12.1.10-h3, 11.2.4-h23, 11.1.7-h12, 10.2.7-h39, 10.2.10-h42), restreindre l'accès au management aux réseaux d'administration. Mettre à jour PHP (8.5.12-1, 8.4.27-1, 8.3.36-1, 8.2.35-1) et le noyau Linux. Ne jamais exposer les interfaces de management sur Internet et surveiller les web shells. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1402/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1402/)<br>[https://thehackernews.com/2026/10/php2shell-attack-roots-25-servers.html](https://thehackernews.com/2026/10/php2shell-attack-roots-25-servers.html)<br>[https://www.netmeister.org/blog/defense-ddos.html](https://www.netmeister.org/blog/defense-ddos.html)<br>[https://partychickens.net/@mason/117520091018296246](https://partychickens.net/@mason/117520091018296246) |
| **CVE-2026-109619** | 9.2 | N/A | FALSE | Palo Alto Networks PAN-OS (branches 10.2, 11.1, 11.2, 12.1, 12.2) et implémentations PHP vulnérables (PHP2Shell) | Exécution de code arbitraire à distance sans authentification | Exécution de code arbitraire sur le serveur web, compromission de la chaîne applicative, vol de données et de secrets, persistance via webshell, et pivot vers les systèmes internes accessibles depuis l'hôte. | Active | Mettre à jour PHP vers une version corrigée, appliquer un virtual patching WAF, inventorier les copies de PHP embarquées ou vendored, restreindre les privilèges du compte de service web et surveiller les processus enfants anormaux. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1402/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1402/)<br>[https://thehackernews.com/2026/10/php2shell-attack-roots-25-servers.html](https://thehackernews.com/2026/10/php2shell-attack-roots-25-servers.html)<br>[https://www.netmeister.org/blog/defense-ddos.html](https://www.netmeister.org/blog/defense-ddos.html)<br>[https://partychickens.net/@mason/117520091018296246](https://partychickens.net/@mason/117520091018296246) |
| **CVE-2026-115560** | N/A | N/A | FALSE | Palo Alto Networks PAN-OS (versions listées dans l'avis CERTFR-2026-AVI-1402) | Vulnérabilité non détaillée dans l'avis (correctif éditeur à appliquer) | Impact non précisé publiquement ; le contexte de l'avis (exécution de code arbitraire à distance) impose de considérer un risque élevé sur les équipements de bordure exposés. | None | Appliquer les correctifs Palo Alto Networks pour la branche concernée, restreindre l'exposition des interfaces de management et surveiller les journaux d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1402/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1402/) |
| **CVE-2024-39717** | N/A | N/A | FALSE | Versa Director (fonction de téléversement de fichiers) | Téléversement de fichier non restreint permettant le dépôt d'un web shell | Accès persistant à des environnements stratégiques (télécoms, gouvernement, défense, satellites, universités, infrastructures critiques) et capacité de pivot vers les réseaux des clients aval. | Active | Appliquer les correctifs Versa, supprimer les web shells, réinitialiser les secrets, restreindre l'exposition des interfaces de management et surveiller les chaînes de rebond. | [https://thehackernews.com/2026/10/volt-typhoon-used-covert-silent-train.html](https://thehackernews.com/2026/10/volt-typhoon-used-covert-silent-train.html) |
| **CVE-2025-8875** | N/A | N/A | FALSE | N-able N-central | Désérialisation non sécurisée | Exécution de code sur un serveur de gestion centralisée, permettant la compromission en cascade des systèmes gérés et l'accès aux réseaux des clients. | Active | Appliquer les correctifs N-able, restreindre l'exposition Internet des consoles RMM, révoquer les secrets et surveiller les exécutions de scripts. | [https://thehackernews.com/2026/10/volt-typhoon-used-covert-silent-train.html](https://thehackernews.com/2026/10/volt-typhoon-used-covert-silent-train.html) |
| **CVE-2025-8876** | N/A | N/A | FALSE | N-able N-central | Injection de commande | Exécution de commandes arbitraires sur le serveur RMM, compromission des endpoints gérés et accès aux réseaux aval. | Active | Correctifs N-able, filtrage de l'accès aux consoles, rotation des secrets, supervision des exécutions de commandes. | [https://thehackernews.com/2026/10/volt-typhoon-used-covert-silent-train.html](https://thehackernews.com/2026/10/volt-typhoon-used-covert-silent-train.html) |
| **CVE-2026-20127** | N/A | N/A | FALSE | Cisco Catalyst SD-WAN Controller | Contournement d'authentification | Prise de contrôle du plan de contrôle SD-WAN, modification de politiques réseau, interception de trafic et pivot vers les environnements internes. | Active | Appliquer les correctifs Cisco, restreindre l'exposition du management, réinitialiser les secrets et surveiller les changements de configuration. | [https://thehackernews.com/2026/10/volt-typhoon-used-covert-silent-train.html](https://thehackernews.com/2026/10/volt-typhoon-used-covert-silent-train.html) |
| **CVE-2026-16812** | N/A | N/A | FALSE | Arista VeloCloud Orchestrator | Injection de commandes système | Compromission de l'orchestrateur, modification des politiques réseau, accès aux environnements aval et persistance furtive. | Active | Correctifs Arista, filtrage de l'accès au management, rotation des secrets, surveillance des exécutions de commandes et des changements de configuration. | [https://thehackernews.com/2026/10/volt-typhoon-used-covert-silent-train.html](https://thehackernews.com/2026/10/volt-typhoon-used-covert-silent-train.html) |
| **CVE-2026-46300** | 7.8 | N/A | FALSE | Noyau Linux (versions vulnérables à Fragnesia) | Élévation de privilèges locale (Fragnesia) | Obtention des privilèges root sur les hôtes compromis, accès complet aux données et aux secrets, et capacité de persistance avancée. | Active | Appliquer les mises à jour du noyau Linux des distributions concernées, redémarrer les systèmes, restreindre les modules noyau et surveiller les élévations de privilèges. | [https://thehackernews.com/2026/10/php2shell-attack-roots-25-servers.html](https://thehackernews.com/2026/10/php2shell-attack-roots-25-servers.html) |
| **CVE-2026-101767** | 9.8 | N/A | FALSE | Oracle E-Business Suite — Oracle Application Object Library (servlet Thin Client Framework /OA_HTML/AppsTCFServer) | Authentification impropre conduisant à une injection SQL non authentifiée chaînée à une exécution de code à distance | Compromission de l'ERP avec exécution de code sur le serveur applicatif, exfiltration de données financières et RH, arrêt des flux logistiques et de paie, et effets en cascade sur les clients et partenaires. | Active | Appliquer le correctif Oracle sans attendre la fenêtre de maintenance hebdomadaire, activer un virtual patching WAF, restreindre l'exposition réseau des interfaces EBS, surveiller les sondages d'exploitation et auditer l'intégrité des données après remédiation. | [https://thehackernews.com/2026/10/hackers-target-critical-oracle-e.html](https://thehackernews.com/2026/10/hackers-target-critical-oracle-e.html)<br>[https://theperimetersite.com/report/412](https://theperimetersite.com/report/412)<br>[https://infosec.exchange/@theperimetersite/117519813996831015](https://infosec.exchange/@theperimetersite/117519813996831015) |
| **CVE-2025-61882** | 9.8 | N/A | FALSE | Oracle E-Business Suite | Exécution de code à distance (CVSS 9.8) | Compromission d'applications ERP critiques, exfiltration de données sensibles et extorsion. | Active | Maintenir les instances EBS à jour, limiter l'exposition Internet, surveiller les web shells et les accès anormaux aux données applicatives. | [https://thehackernews.com/2026/10/hackers-target-critical-oracle-e.html](https://thehackernews.com/2026/10/hackers-target-critical-oracle-e.html) |
| **CVE-2026-46817** | 9.8 | N/A | FALSE | Oracle E-Business Suite | Exécution de code à distance (CVSS 9.8) | Compromission potentielle de l'application ERP, accès non autorisé aux données métier et exécution de code sur l'hôte applicatif. | Active | Appliquer les correctifs Oracle, restreindre l'exposition des interfaces EBS, surveiller les journaux et les artefacts de compromission. | [https://thehackernews.com/2026/10/hackers-target-critical-oracle-e.html](https://thehackernews.com/2026/10/hackers-target-critical-oracle-e.html) |
| **CVE-2026-97631** | 9.5 | N/A | FALSE | EDK II (code de référence UEFI) jusqu'à edk2-stable202608 inclus ; produits des fabricants dérivés (AMI, Insyde, Phoenix, Microsoft Project Mu) | Dépassement de tampon classique / écriture hors limites (out-of-bounds write) et calcul incorrect de la taille du tampon dans le firmware UEFI | Exécution de code pré-OS avec les privilèges du firmware, contournement des mécanismes de confiance du démarrage (Secure Boot, TPM), installation persistante de composants malveillants au plus bas niveau de la pile, compromission difficile à détecter depuis le système d'exploitation. L'impact sur la confidentialité, l'intégrité et la disponibilité est total pour les serveurs concernés. | Theoretical | Appliquer les firmwares UEFI corrigés publiés par les fabricants (AMI, Insyde, Phoenix, Microsoft) dès disponibilité. Désactiver le démarrage réseau PXE lorsqu'il n'est pas nécessaire et cloisonner les réseaux PXE. Filtrer les messages ICMP non indispensables. Maintenir Secure Boot et le TPM activés et surveiller leurs mesures. En l'absence de correctif, isoler les serveurs sensibles des segments réseau non maîtrisés et limiter les possibilités de démarrage réseau. | [https://thehackernews.com/2026/10/critical-16-year-old-uefi-flaw-can-run.html](https://thehackernews.com/2026/10/critical-16-year-old-uefi-flaw-can-run.html)<br>[https://securityaffairs.com/201928/security/cve-2026-97631-16-year-old-uefi-flaw-threatens-servers.html](https://securityaffairs.com/201928/security/cve-2026-97631-16-year-old-uefi-flaw-threatens-servers.html)<br>[https://arstechnica.com/security/2026/10/code-execution-flaw-in-uefi-firmware-threatens-most-servers-on-planet-earth/](https://arstechnica.com/security/2026/10/code-execution-flaw-in-uefi-firmware-threatens-most-servers-on-planet-earth/)<br>[https://infosec.exchange/@technotenshi/117520083328994527](https://infosec.exchange/@technotenshi/117520083328994527) |
| **CVE-2026-35273** | 9.8 | N/A | TRUE | Oracle PeopleSoft Enterprise PeopleTools 8.61 et 8.62 (composants PSIGW et PSEMHUB) | Chaîne de trois vulnérabilités : SSRF dans PSIGW, contournement de la liste de confiance PSEMHUB via 127.0.0.1, puis exécution de code (écriture de web shell ou désérialisation XMLDecoder) | Prise de contrôle non authentifiée du serveur PeopleSoft, exécution de code sous le compte de service, accès aux données RH, financières et académiques, et persistance furtive via XMLDecoder. | Active | Appliquer le correctif Oracle, retirer 127.0.0.1 de allowedhosts.properties, restreindre l'accès à PSEMHUB, surveiller les web shells et les fichiers XML, et considérer qu'une règle de pare-feu seule ne protège pas contre cette chaîne. | [https://thehackernews.com/2026/10/shinyhunters-exploited-oracle.html](https://thehackernews.com/2026/10/shinyhunters-exploited-oracle.html) |
| **CVE-2026-111497** | 9.2 | N/A | TRUE | Décodeur Brotli natif de Google (bibliothèque brotli) et tous les produits l'embarquant : Node.js 22/24/26, .NET 8/9/10, Python, PowerShell 7.4/7.5/7.6, Visual Studio 2019/2022/2026, Envoy, Istio, Bun, Palo Alto PAN-OS 11.2.4+ / 12.1 / 12.2, paquet brotli de Red Hat Enterprise Linux 9, Debian 12/13, ClickHouse, DuckDB, Apache Arrow, MuPDF, NanaZip, GraalJS, libjxl et FFmpeg. | Dépassement de tampon en écriture hors limites (out-of-bounds write) / valeur de retour non vérifiée dans le décodeur Brotli, entraînant corruption mémoire, divulgation d'informations, déni de service et exécution de code à distance | Exécution de code arbitraire à distance sans authentification dans le contexte du processus vulnérable, divulgation de mémoire de processus (fuite de secrets, jetons, données métier), déni de service par crash ou boucle infinie. La compromission d'un service Node.js exposé peut mener à la prise de contrôle de l'hôte, au mouvement latéral et à l'exfiltration de données. L'exposition est aggravée par la présence du décodeur dans des chaînes de traitement de fichiers non fiables (JPEG XL, archives) et par le délai très court entre correctif et PoC public. | Active | Appliquer les correctifs Node.js 22.23.4, 24.22.1 et 26.12.1 (ou versions ultérieures) et Brotli 1.0.10 / 1.1.1 / 1.2.1. Sur AWS Lambda, reconstruire et redéployer les images conteneur depuis les images de base corrigées et déclencher la mise à jour des paquets ZIP via une modification de code ou de configuration (une mise à jour sans changement n'est pas suffisante). Mettre à jour Debian 12/13 (brotli corrigé, Node.js Debian utilisant la bibliothèque système), le paquet brotli de RHEL 9, PowerShell 7.4-7.6 et Visual Studio. Pour PAN-OS, appliquer les hotfixes ou désactiver l'inspection Brotli. Pour Envoy/Istio, supprimer la décompression Brotli si elle n'est pas indispensable. Abandonner les runtimes Node.js 18 et 20 (plus de correctifs). En mesure compensatoire, refuser ou limiter la décompression Brotli de contenus non maîtrisés et plafonner la taille des flux décompressés. | [https://thehackernews.com/2026/10/adobe-commerce-polyshell-attacks-breach.html](https://thehackernews.com/2026/10/adobe-commerce-polyshell-attacks-breach.html)<br>[https://aws.amazon.com/security/security-bulletins/rss/2026-155-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-155-aws/)<br>[https://fieldeffect.com/blog/update-brotli-flaw-exposure-expands](https://fieldeffect.com/blog/update-brotli-flaw-exposure-expands)<br>[https://securityaffairs.com/201922/security/u-s-cisa-adds-google-brotli-and-adobe-commerce-and-magento-flaws-to-its-known-exploited-vulnerabilities-catalog.html](https://securityaffairs.com/201922/security/u-s-cisa-adds-google-brotli-and-adobe-commerce-and-magento-flaws-to-its-known-exploited-vulnerabilities-catalog.html)<br>[https://webflow.sysdig.com/blog/node2shell-cve-2026-111497-detecting-the-node-js-brotli-rce](https://webflow.sysdig.com/blog/node2shell-cve-2026-111497-detecting-the-node-js-brotli-rce)<br>[https://opensourcemalware.com/blog/the-opensourcemalwareshow-episode27](https://opensourcemalware.com/blog/the-opensourcemalwareshow-episode27) |
| **CVE-2026-48356** | 9.3 | N/A | TRUE | Adobe Commerce et Magento (Open Source / Commerce) | Upload de fichier non restreint (unrestricted file upload) conduisant à l'exécution de code arbitraire | Exécution de code à distance sur le serveur e-commerce, prise de contrôle du back-office, vol de données clients et de paiement, altération des commandes et des prix, persistance via web shell. L'impact réputationnel et réglementaire est élevé pour les marchands en ligne. | Active | Appliquer sans délai les correctifs Adobe pour Adobe Commerce et Magento. En attendant, restreindre les extensions autorisées à l'upload, interdire l'exécution de scripts dans les répertoires media, placer un WAF en amont et surveiller les dépôts de fichiers. Auditer les comptes administrateurs et les clés d'intégration après remédiation. | [https://thehackernews.com/2026/10/adobe-commerce-polyshell-attacks-breach.html](https://thehackernews.com/2026/10/adobe-commerce-polyshell-attacks-breach.html)<br>[https://securityaffairs.com/201922/security/u-s-cisa-adds-google-brotli-and-adobe-commerce-and-magento-flaws-to-its-known-exploited-vulnerabilities-catalog.html](https://securityaffairs.com/201922/security/u-s-cisa-adds-google-brotli-and-adobe-commerce-and-magento-flaws-to-its-known-exploited-vulnerabilities-catalog.html) |
| **CVE-2026-61572** | 8.6 | N/A | FALSE | AVideo-Encoder (WWBN), versions antérieures à 8.1.0 | Server-Side Request Forgery non authentifiée avec réflexion complète de la réponse (CWE-918) | Lecture de réponses HTTP et HTTPS internes, y compris les identifiants exposés par les métadonnées d'instance cloud, accès à des services TCP internes et à des services FTP internes, sans aucune interaction d'un compte ou d'un opérateur. | Theoretical | Mettre à jour vers AVideo-Encoder 8.1.0 ou ultérieur, valider toutes les URL externes contre une allowlist stricte, activer et imposer la vérification TLS des pairs, configurer des contrôles d'accès réseau restreignant les sorties internes, et ne pas laisser l'allowlist de streamers vide. | [https://cvefeed.io/vuln/detail/CVE-2026-61572](https://cvefeed.io/vuln/detail/CVE-2026-61572) |
| **CVE-2026-61567** | 10.0 | N/A | FALSE | AVideo-Encoder (WWBN), versions antérieures à 8.1.0 | Contournement d'authentification et injection de commandes système (CWE-78) | Exécution de commandes en tant qu'utilisateur du serveur web, divulgation des identifiants de base de données et des identifiants de streamers stockés, compromission de la plateforme amont à l'aide de ces identifiants, modification de fichiers, établissement de persistance et déni de service de l'encoder. | Theoretical | Mettre à jour vers AVideo-Encoder 8.1.0 ou ultérieur, vérifier la configuration de l'allowlist de streamers, assainir et valider toutes les entrées externes, échapper les arguments passés aux commandes système, appliquer le principe de moindre privilège au compte de service web et faire tourner les secrets exposés. | [https://cvefeed.io/vuln/detail/CVE-2026-61567](https://cvefeed.io/vuln/detail/CVE-2026-61567) |
| **CVE-2026-61564** | 10.0 | N/A | FALSE | AVideo-Encoder (WWBN) versions antérieures à 8.1.0 | Injection de code PHP (CWE-94) avec injection SQL secondaire | Exécution de commandes arbitraires sous l'utilisateur du serveur web, lecture et écrasement de fichiers, persistance via code PHP, contrôle des paramètres de connexion à la base, et injection SQL secondaire. | Theoretical | Mettre à jour AVideo-Encoder vers 8.1.0 ou supérieur, supprimer ou renommer le répertoire install/ après installation, restreindre l'accès à l'installateur, vérifier l'intégrité de videos/configuration.php, et surveiller les créations/modifications de fichiers et les connexions DB sortantes. | [https://cvefeed.io/vuln/detail/CVE-2026-61564](https://cvefeed.io/vuln/detail/CVE-2026-61564) |
| **CVE-2026-118753** | 8.5 | N/A | FALSE | FreeImage (fork danoli3) versions antérieures à 3.19.25 | Débordement de tampon heap (CWE-787) via le compositing GIF_PLAYBACK | Corruption de la mémoire heap, crash du processus, et potentiellement exécution de code dans le contexte du processus de traitement d'images. | Theoretical | Mettre à jour FreeImage vers 3.19.25 ou supérieur, éviter de charger des GIF non fiables avec GIF_PLAYBACK, et isoler les services de traitement d'images. | [https://cvefeed.io/vuln/detail/CVE-2026-118753](https://cvefeed.io/vuln/detail/CVE-2026-118753) |
| **CVE-2026-118752** | 8.5 | N/A | FALSE | FreeImage (fork danoli3) versions antérieures à 3.19.22 | Débordement de tampon heap (CWE-787) via le décodeur PBM RLE IFF/LBM | Corruption de la mémoire heap, crash du processus, et potentiellement exécution de code dans le contexte du processus de décodage. | Theoretical | Mettre à jour FreeImage vers 3.19.22 ou supérieur, éviter de traiter des fichiers IFF/LBM PBM non fiables, et isoler les services de traitement d'images. | [https://cvefeed.io/vuln/detail/CVE-2026-118752](https://cvefeed.io/vuln/detail/CVE-2026-118752) |
| **CVE-2026-103995** | N/A | N/A | FALSE | CPython sans le dernier correctif de sécurité | Contournement de la politique de sécurité | Contournement de la politique de sécurité, avec un risque potentiel d'atteinte à la confidentialité et à l'intégrité des applications Python. | Theoretical | Se référer au bulletin de sécurité PSF-2026-47 et appliquer les correctifs publiés par la Python Software Foundation ; mettre à jour CPython vers une version corrigée. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1397/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1397/) |
| **CVE-2026-118304, CVE-2026-118305, CVE-2026-118306, CVE-2026-118307, CVE-2026-118308, CVE-2026-118309, CVE-2026-118310, CVE-2026-118311, CVE-2026-118312, CVE-2026-118313, CVE-2026-118314, CVE-2026-118315, CVE-2026-118316, CVE-2026-118317, CVE-2026-118318, CVE-2026-118319, CVE-2026-118320, CVE-2026-118321, CVE-2026-118322, CVE-2026-118327, CVE-2026-118328, CVE-2026-118329, CVE-2026-118330, CVE-2026-118331, CVE-2026-118332, CVE-2026-118333, CVE-2026-118334, CVE-2026-118335, CVE-2026-118336, CVE-2026-118337, CVE-2026-118338, CVE-2026-118339, CVE-2026-118340, CVE-2026-118341, CVE-2026-118342, CVE-2026-118343** | N/A | N/A | FALSE | Google Chrome versions antérieures à 156.0.8078.73 (Linux/Windows) et 156.0.8078.74 (Mac) | Multiples vulnérabilités non spécifiées par l'éditeur | Les vulnérabilités permettent à un attaquant de provoquer un problème de sécurité non spécifié, avec un risque potentiel d'exécution de code ou de compromission du navigateur. | Theoretical | Mettre à jour Google Chrome vers 156.0.8078.73 (Linux/Windows) ou 156.0.8078.74 (Mac) ou supérieur, et redémarrer le navigateur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1398/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1398/) |
| **CVE-2025-64394, CVE-2026-105477, CVE-2026-106076, CVE-2026-106077, CVE-2026-106078, CVE-2026-107671, CVE-2026-108140, CVE-2026-108141, CVE-2026-108142** | N/A | N/A | FALSE | Veeam Agent pour Linux < 13.1.2 (build 13.1.2.11) ; Veeam Backup & Replication 13.0.x < 13.0.3 (build 13.0.3.63) et 13.1.x < 13.1.2 (build 13.1.2.57) ; Veeam Backup pour Microsoft 365 < 8.6 Patch 1 (build 8.6.0.5011) ; Veeam ONE < 13.1 P1 (build 13.1.0.7940) | Multiples vulnérabilités : exécution de code arbitraire à distance, élévation de privilèges, injection SQL, déni de service, atteinte à la confidentialité et à l'intégrité | Compromission potentielle de l'infrastructure de sauvegarde, exécution de code à distance, élévation de privilèges, injection SQL, déni de service et atteinte à la confidentialité/intégrité des données. | Theoretical | Appliquer les correctifs Veeam référencés dans les bulletins kb4948, kb4951 et kb4957, mettre à jour vers les versions corrigées, restreindre l'exposition réseau des interfaces d'administration et renforcer la surveillance. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1399/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1399/) |
| **CVE-2026-109411** | N/A | N/A | FALSE | Samba versions antérieures à 4.25.1 | Vulnérabilité non spécifiée permettant atteinte à la confidentialité, à l'intégrité et contournement de la politique de sécurité | Atteinte à la confidentialité et à l'intégrité des données, ainsi qu'un contournement de la politique de sécurité. | Theoretical | Mettre à jour Samba vers 4.25.1 ou supérieur et se référer au bulletin de sécurité de l'éditeur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1400/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1400/) |
| **CVE-2026-20942** | N/A | N/A | FALSE | Microsoft Edge versions 156.x antérieures à 156.0.4314.42 et versions antérieures à 149.0.4022.62 | Exécution de code arbitraire à distance / contournement de la politique de sécurité | Exécution de code arbitraire dans le contexte de l'utilisateur du navigateur, pouvant mener au vol de données, à l'installation de logiciels malveillants ou au pivot vers les ressources accessibles depuis le poste. | None | Mettre à jour Microsoft Edge vers 156.0.4314.42 ou supérieur (et 149.0.4022.62 pour la branche concernée). Vérifier le déploiement effectif via la console de gestion, restreindre les extensions non approuvées et surveiller les comportements post-exploitation. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1405/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1405/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1405/`<br>`hxxps://msrc[.]microsoft[.]com/update-guide/vulnerability/CVE-2026-20942` |
| **CVE-2026-62765** | N/A | N/A | FALSE | Microsoft Edge versions 156.x antérieures à 156.0.4314.42 et versions antérieures à 149.0.4022.62 | Exécution de code arbitraire à distance / contournement de la politique de sécurité | Exécution de code arbitraire à distance dans le contexte de l'utilisateur, avec risque de vol d'identifiants, de données et d'installation de code malveillant sur le poste. | None | Appliquer la mise à jour Edge vers 156.0.4314.42 ou supérieur. Contrôler la conformité des versions, restreindre les extensions et surveiller les comportements anormaux du navigateur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1405/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1405/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1405/`<br>`hxxps://msrc[.]microsoft[.]com/update-guide/vulnerability/CVE-2026-62765` |
| **CVE-2026-88078** | N/A | N/A | FALSE | Microsoft Edge versions 156.x antérieures à 156.0.4314.42 et versions antérieures à 149.0.4022.62 | Exécution de code arbitraire à distance / contournement de la politique de sécurité | Exécution de code arbitraire à distance côté client, avec risque de compromission du poste et de vol de données. | None | Mettre à jour Edge vers 156.0.4314.42 ou supérieur, vérifier la couverture du parc et surveiller les indicateurs d'exploitation navigateur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1405/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1405/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1405/`<br>`hxxps://msrc[.]microsoft[.]com/update-guide/vulnerability/CVE-2026-88078` |
| **CVE-2026-96196** | N/A | N/A | FALSE | Microsoft Edge versions 156.x antérieures à 156.0.4314.42 et versions antérieures à 149.0.4022.62 | Exécution de code arbitraire à distance / contournement de la politique de sécurité | Exécution de code arbitraire à distance dans le contexte de l'utilisateur, pouvant conduire à une compromission complète du poste de travail. | None | Appliquer la mise à jour Edge vers 156.0.4314.42 ou supérieur, contrôler la conformité du parc et surveiller les comportements anormaux du navigateur. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1405/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1405/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1405/`<br>`hxxps://msrc[.]microsoft[.]com/update-guide/vulnerability/CVE-2026-96196` |
| **CVE-2026-100801** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Selon la nature exacte de la faille, l'impact peut aller de l'exécution de code arbitraire à distance à une atteinte à la confidentialité des données ou à un déni de service. | None | Mettre à jour Firefox, Firefox ESR et Thunderbird vers les versions corrigées publiées le 27 octobre 2026. Vérifier le déploiement effectif et restreindre les extensions non approuvées. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-109705** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | L'impact dépend de la nature exacte de la faille : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Appliquer les mises à jour Mozilla corrigées (Firefox 159, ESR 153.6/115.44, Thunderbird 159/153.6) et vérifier la couverture du parc. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-109707** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Selon la nature de la faille : exécution de code arbitraire, élévation de privilèges, fuite de données ou déni de service à distance. | None | Mettre à jour vers Firefox 159, Firefox ESR 153.6 ou 115.44, Thunderbird 159 ou 153.6, et contrôler la conformité du parc. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-109708** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact potentiel : exécution de code, élévation de privilèges, fuite de données ou déni de service selon la nature exacte de la faille. | None | Appliquer les versions corrigées publiées par Mozilla et vérifier la conformité du parc. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-110247** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Selon la nature de la faille : exécution de code arbitraire, élévation de privilèges, fuite de données ou déni de service. | None | Mettre à jour vers les versions corrigées de Firefox, Firefox ESR et Thunderbird et vérifier la couverture du parc. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-113869** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact variable selon la nature de la faille : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Appliquer les mises à jour Mozilla corrigées et vérifier la conformité des versions déployées. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117860** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Selon la nature de la faille : exécution de code arbitraire, élévation de privilèges, fuite de données ou déni de service. | None | Mettre à jour Firefox, Firefox ESR et Thunderbird vers les versions corrigées et vérifier la couverture du parc. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117861** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact variable : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Appliquer les versions corrigées publiées par Mozilla et contrôler la conformité du parc. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117862** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact potentiel : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Mettre à jour vers Firefox 159, Firefox ESR 153.6/115.44, Thunderbird 159/153.6 et vérifier la couverture. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117863** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact variable selon la nature de la faille : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Appliquer les mises à jour Mozilla corrigées et vérifier la conformité du parc. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117864** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact potentiel : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Mettre à jour vers les versions corrigées de Firefox, Firefox ESR et Thunderbird. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117865** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact variable : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Appliquer les versions corrigées publiées par Mozilla et contrôler la conformité du parc. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117866** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact potentiel : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Mettre à jour Firefox, Firefox ESR et Thunderbird vers les versions corrigées et vérifier la couverture du parc. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117867** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact variable : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Appliquer les mises à jour Mozilla corrigées et contrôler la conformité du parc. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117868** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact potentiel : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Mettre à jour vers Firefox 159, Firefox ESR 153.6/115.44, Thunderbird 159/153.6 et vérifier la couverture. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117869** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact variable : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Appliquer les versions corrigées publiées par Mozilla et contrôler la conformité du parc. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117870** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact potentiel : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Mettre à jour Firefox, Firefox ESR et Thunderbird vers les versions corrigées et vérifier la couverture du parc. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117871** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact variable : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Appliquer les mises à jour Mozilla corrigées et contrôler la conformité du parc. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117872** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact potentiel : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Mettre à jour vers Firefox 159, Firefox ESR 153.6/115.44, Thunderbird 159/153.6 et vérifier la couverture. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117873** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact variable : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Appliquer les versions corrigées publiées par Mozilla et contrôler la conformité du parc. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117874** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact potentiel : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Mettre à jour Firefox, Firefox ESR et Thunderbird vers les versions corrigées et vérifier la couverture du parc. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117875** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact variable : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Appliquer les mises à jour Mozilla corrigées et contrôler la conformité du parc. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-117876** | N/A | N/A | FALSE | Firefox ESR < 115.44, Firefox ESR < 153.6, Firefox < 159, Thunderbird < 153.6, Thunderbird < 159 | Multiples (exécution de code arbitraire à distance, élévation de privilèges, déni de service, atteinte à la confidentialité, contournement de politique de sécurité) | Impact potentiel : exécution de code, élévation de privilèges, fuite de données ou déni de service. | None | Mettre à jour vers Firefox 159, Firefox ESR 153.6/115.44, Thunderbird 159/153.6 et vérifier la couverture. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1406/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1406/`<br>`hxxps://www[.]mozilla[.]org/en-US/security/advisories/` |
| **CVE-2026-63286** | N/A | N/A | FALSE | Axis Camera Station Pro, versions antérieures à 6.20 | Atteinte à la confidentialité des données | Divulgation d'informations sensibles : flux vidéo, enregistrements, métadonnées ou données de configuration du système de vidéosurveillance. Un tel accès peut faciliter la reconnaissance physique d'un site. | None | Mettre à jour vers Camera Station Pro 6.20 ou supérieur. Restreindre l'exposition réseau du serveur VMS, appliquer le principe du moindre privilège sur les comptes et surveiller les accès aux archives. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1408/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1408/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1408/`<br>`hxxps://www[.]axis[.]com/dam/public/c9/5c/29/cve-2026-63286pdf-en-US-560650.pdf` |
| **CVE-2026-85749** | 8.1 | N/A | FALSE | MailWatch for MailScanner, versions antérieures à 1.2.27 | Contournement d'autorisation par référence directe à un objet (IDOR) - CWE-639 / CWE-566 | Atteinte à l'intégrité et à la confidentialité de la messagerie : suppression définitive de courriels légitimes (perte de données, dissimulation de preuves) ou libération forcée de messages retenus par la quarantaine, ce qui peut conduire à la livraison de courriels malveillants ou de phishing dans les boîtes des utilisateurs. Un attaquant disposant d'un compte de faible privilège peut ainsi cibler des utilisateurs à forte valeur. | Theoretical | Mettre à jour MailWatch vers la version 1.2.27 (correctif commit bc04f25eb0cec028cbd4ded9c049cfc6f663a15f). Vérifier les permissions de suppression et de libération pour tous les rôles, restreindre l'accès à l'interface et surveiller les actions de quarantaine anormales. | [https://cvefeed.io/vuln/detail/CVE-2026-85749](https://cvefeed.io/vuln/detail/CVE-2026-85749)<br>`hxxps://cvefeed[.]io/vuln/detail/CVE-2026-85749`<br>`hxxps://github[.]com/mailwatch/MailWatch/security/advisories/GHSA-w7v5-7g6w-87r4`<br>`hxxps://github[.]com/mailwatch/MailWatch/releases/tag/v1.2.27` |
| **CVE-2026-93851** | 8.0 | N/A | FALSE | Mattermost 11.9.x <= 11.9.1, 11.8.x <= 11.8.5, 11.7.x <= 11.7.10 (plugin Agents) | Traversée de répertoire (CWE-22) permettant le remplacement de plugin et l'exécution de code | Exécution de code arbitraire sur le serveur Mattermost, avec risque de compromission de l'ensemble des données de collaboration, de vol de jetons, de mouvement latéral vers les systèmes intégrés (SSO, CI/CD, bots) et de persistance via un plugin malveillant. | Theoretical | Mettre à jour vers Mattermost 11.9.2, 11.8.6 ou 11.7.11. Désactiver le plugin Agents en attendant, restreindre les droits d'installation de plugins aux administrateurs de confiance et surveiller les modifications de plugins. | [https://cvefeed.io/vuln/detail/CVE-2026-93851](https://cvefeed.io/vuln/detail/CVE-2026-93851)<br>`hxxps://cvefeed[.]io/vuln/detail/CVE-2026-93851`<br>`hxxps://mattermost[.]com/security-updates` |
| **CVE-2026-61546** | N/A | N/A | FALSE | AnkiMCP (outils HTTP locaux exposés sans authentification) | Accès non authentifié à des outils locaux via rebinding DNS | Exécution non autorisée d'actions via les outils MCP locaux : lecture ou modification des données de l'application, accès à des ressources locales et, selon les outils exposés, exécution d'opérations arbitraires dans le contexte de l'utilisateur. | Theoretical | Mettre à jour AnkiMCP dès qu'un correctif est disponible, lier les services à 127.0.0.1 avec authentification par jeton, valider l'en-tête Host et l'origine des requêtes, et éviter d'exécuter le service lors de la navigation web. | `hxxps://cvefeed[.]io/vuln/detail/CVE-2026-61546` |
| **CVE-2026-118755** | 8.6 | N/A | FALSE | Volmarg Personal Management System jusqu'à la version 2.1.0 incluse | Injection de commandes OS (CWE-78) | Exécution de commandes arbitraires sur le serveur hébergeant l'application, sous l'identité du compte de service web : vol de fichiers et de secrets applicatifs, modification des données, persistance, pivot vers le réseau interne. L'élévation de privilèges dépend des droits du compte web. | None | Appliquer le correctif éditeur et mettre à jour vers une version corrigée ; assainir tous les chemins de dossiers fournis par l'utilisateur et proscrire les métacharactères shell dans les noms de répertoires ; utiliser des appels système sans shell (API natives) ; exécuter le service web avec un compte à privilège minimal et en conteneur ; restreindre l'accès à l'application et journaliser les exécutions de processus. | [https://cvefeed.io/vuln/detail/CVE-2026-118755](https://cvefeed.io/vuln/detail/CVE-2026-118755)<br>[https://www.vulncheck.com/advisories/volmarg-personal-management-system-through-2.1.0-os-command-injection-via-storage-folder-path](https://www.vulncheck.com/advisories/volmarg-personal-management-system-through-2.1.0-os-command-injection-via-storage-folder-path) |
| **CVE-2026-118694** | 8.7 | N/A | FALSE | python-markdown2 jusqu'à la version 2.5.5 incluse | Déni de service par complexité algorithmique (CWE-407) | Épuisement CPU et indisponibilité partielle ou totale du service de rendu Markdown, avec effet de bord sur les workers applicatifs partagés. Aucun impact direct sur la confidentialité ou l'intégrité des données. | None | Mettre à jour python-markdown2 vers une version corrigée ; limiter la taille des entrées Markdown ; appliquer un rate limiting et des timeouts sur les endpoints de rendu ; ne pas traiter de Markdown non fiable dans le chemin critique ; surveiller l'usage CPU par requête. | [https://cvefeed.io/vuln/detail/CVE-2026-118694](https://cvefeed.io/vuln/detail/CVE-2026-118694)<br>[https://www.vulncheck.com/advisories/python-markdown2-through-2.5.5-denial-of-service-via-unclosed-inline-link-destinations](https://www.vulncheck.com/advisories/python-markdown2-through-2.5.5-denial-of-service-via-unclosed-inline-link-destinations) |
| **CVE-2026-118690** | 9.8 | N/A | FALSE | Signal K Server antérieur à la version 2.33.0 | Absence d'authentification sur une fonction critique (CWE-306) | Prise de contrôle administrative complète du serveur Signal K : lecture et modification des données de navigation, des configurations et des intégrations, création de comptes persistants, pivot vers les systèmes connectés (bateaux, passerelles IoT/OT). | None | Mettre à jour vers Signal K Server 2.33.0 ou ultérieur ; faire tourner immédiatement le secretKey JWT et supprimer les comptes administrateurs non autorisés ; restreindre l'accès à /skServer/ziplogs et à l'interface d'administration ; ne jamais exposer l'instance directement sur Internet sans reverse proxy authentifiant. | [https://cvefeed.io/vuln/detail/CVE-2026-118690](https://cvefeed.io/vuln/detail/CVE-2026-118690)<br>[https://github.com/SignalK/signalk-server/security/advisories/GHSA-4w32-qx5g-cpwv](https://github.com/SignalK/signalk-server/security/advisories/GHSA-4w32-qx5g-cpwv)<br>[https://www.vulncheck.com/advisories/signal-k-server-before-2.33.0-missing-authentication-via-skserver-ziplogs](https://www.vulncheck.com/advisories/signal-k-server-before-2.33.0-missing-authentication-via-skserver-ziplogs) |
| **CVE-2026-118689** | 8.7 | N/A | FALSE | OvenMediaEngine jusqu'à la version 0.21.0 incluse | Allocation de ressources sans limite (CWE-770) — déni de service | Indisponibilité du relais de streaming : saturation mémoire, blocage des connexions légitimes, interruption de la diffusion vers les nœuds edge et donc des flux servis aux utilisateurs finaux. | None | Mettre à jour vers une version postérieure à 0.21.0 ; valider les longueurs de paquets avant traitement ; implémenter des timeouts de connexion et des quotas par source ; restreindre l'accès au listener OVT aux nœuds edge légitimes ; surveiller la mémoire et le nombre de connexions. | [https://cvefeed.io/vuln/detail/CVE-2026-118689](https://cvefeed.io/vuln/detail/CVE-2026-118689)<br>[https://www.vulncheck.com/advisories/ovenmediaengine-through-0.21.0-ovt-relay-dos-via-oversized-payload-length](https://www.vulncheck.com/advisories/ovenmediaengine-through-0.21.0-ovt-relay-dos-via-oversized-payload-length) |
| **CVE-2026-118669** | 8.4 | N/A | FALSE | OAuthLib antérieur à la version 4.0.0 (Python 3.6+) | Autorisation incorrecte (CWE-863) | Émission de jetons d'accès avec des grants ou des scopes non autorisés, permettant à un client de faible privilège d'accéder à des ressources protégées d'un autre client : lecture de données, actions au nom d'un autre tenant, contournement du cloisonnement applicatif. | None | Mettre à jour OAuthLib vers 4.0.0 ou ultérieur ; faire en sorte que les validateurs autorisent uniquement à partir de request.client ; auditer les scopes accordés aux clients confidentiels ; journaliser les incohérences client authentifié / client_id. | [https://cvefeed.io/vuln/detail/CVE-2026-118669](https://cvefeed.io/vuln/detail/CVE-2026-118669)<br>[https://github.com/oauthlib/oauthlib/security/advisories/GHSA-7984-qgvg-3j9c](https://github.com/oauthlib/oauthlib/security/advisories/GHSA-7984-qgvg-3j9c) |
| **CVE-2026-118668** | 8.6 | N/A | FALSE | langgraph-api de la version 0.1.2 à la version 0.15.0 exclue | Contournement d'autorisation via clé contrôlée par l'utilisateur (CWE-639 / CWE-863) | Fuite et altération de données inter-utilisateurs dans un déploiement multi-tenant : accès à la mémoire d'agents, aux historiques de conversation et aux données métier d'autres utilisateurs, avec risque de corruption ou de suppression. | None | Mettre à jour langgraph-api vers 0.15.0 ou ultérieur ; revoir les handlers d'authentification personnalisés pour rejeter explicitement les namespaces non autorisés ; ajouter des tests d'isolation multi-tenant ; journaliser les accès au Store avec l'identité de l'appelant. | [https://cvefeed.io/vuln/detail/CVE-2026-118668](https://cvefeed.io/vuln/detail/CVE-2026-118668)<br>[https://github.com/langchain-ai/langgraph/security/advisories/GHSA-4hm6-w6qq-w73v](https://github.com/langchain-ai/langgraph/security/advisories/GHSA-4hm6-w6qq-w73v) |
| **CVE-2026-118665** | 8.2 | N/A | FALSE | @graphql-tools/executor-legacy-ws antérieur à la version 1.1.36 | Expiration de session insuffisante (CWE-613) — fuite de contexte d'authentification | Usurpation d'identité entre utilisateurs ou tenants sur les API GraphQL : accès non autorisé à des données, actions effectuées au nom d'un autre utilisateur, contournement du cloisonnement multi-tenant. | None | Mettre à jour vers 1.1.36 ou ultérieur ; ne jamais réutiliser un exécuteur entre contextes d'autorisation ; créer un exécuteur par requête en attendant le correctif ; nettoyer explicitement les connectionParams à la fermeture des connexions. | [https://cvefeed.io/vuln/detail/CVE-2026-118665](https://cvefeed.io/vuln/detail/CVE-2026-118665)<br>[https://github.com/ardatan/graphql-tools/security/advisories/GHSA-434m-5hcj-pxf3](https://github.com/ardatan/graphql-tools/security/advisories/GHSA-434m-5hcj-pxf3) |
| **CVE-2026-118664** | 8.2 | N/A | FALSE | decode-uri-component antérieur à la version 0.5.1 | Consommation non contrôlée de ressources / complexité algorithmique (CWE-400, CWE-407) | Blocage de la boucle d'événements Node.js et indisponibilité du service applicatif pour tous les utilisateurs, avec effet domino sur les services partageant le même processus. | None | Mettre à jour vers 0.5.1 ou ultérieur ; limiter la taille des entrées décodées ; appliquer un rate limiting sur les endpoints concernés ; surveiller le lag de l'event loop ; intégrer un contrôle SCA des dépendances transitives. | [https://cvefeed.io/vuln/detail/CVE-2026-118664](https://cvefeed.io/vuln/detail/CVE-2026-118664)<br>[https://github.com/SamVerschueren/decode-uri-component/security/advisories/GHSA-qr28-fpjm-wq7f](https://github.com/SamVerschueren/decode-uri-component/security/advisories/GHSA-qr28-fpjm-wq7f) |
| **CVE-2026-118660** | 8.6 | N/A | FALSE | Happy DOM (implémentation JavaScript de navigateur headless) versions antérieures à 21.0.0 | Server-Side Request Forgery (CWE-918 / CAPEC-664) | Accès non authentifié à des services internes non exposés sur Internet, exfiltration de credentials cloud via l'API de métadonnées d'instance, cartographie du réseau interne, contournement de la segmentation réseau et pivot vers d'autres systèmes. L'impact est d'autant plus élevé que le service consommateur tourne avec des privilèges élevés ou dans un environnement cloud. | Theoretical | Mettre à jour Happy DOM vers la version 21.0.0 ou ultérieure (correctif publié dans le commit 0a99c7525a1d0043e3182843ae33466ab7b19e74 et la release v21.0.0). Activer explicitement disableIframePageLoading et disableCSSFileLoading. Isoler le parsing de HTML non fiable dans un conteneur sans accès réseau ou avec une politique d'egress restrictive. Imposer IMDSv2 et restreindre l'accès aux endpoints de métadonnées. Ajouter une validation/allowlist des schémas et domaines autorisés dans les contenus HTML traités. | [https://cvefeed.io/vuln/detail/CVE-2026-118660](https://cvefeed.io/vuln/detail/CVE-2026-118660)<br>[https://github.com/capricorn86/happy-dom/security/advisories/GHSA-c8p4-j97h-3vg8](https://github.com/capricorn86/happy-dom/security/advisories/GHSA-c8p4-j97h-3vg8) |
| **CVE-2026-78674** | 8.8 | N/A | FALSE | WSO2 Enterprise Integrator, WSO2 Business Process Server et WSO2 Enterprise Integrator BPS Profile | Injection de commandes OS (CWE-78 / CAPEC-88) | Exécution de commandes arbitraires sur le serveur d'intégration, compromission de la plateforme middleware, accès aux intégrations métier, aux bases de données et aux secrets applicatifs, mouvement latéral vers les systèmes connectés via les connecteurs WSO2. | Theoretical | Appliquer les correctifs WSO2 de l'avis WSO2-2026-5692. Valider strictement tous les paramètres d'entrée des API BPMN (allowlist, rejet des métacaractères). Restreindre les privilèges du compte de runtime et exécuter WSO2 dans un conteneur ou un compte système dédié à faibles droits. Revoir les contrôles d'accès aux API et limiter l'exposition des endpoints d'administration. | [https://cvefeed.io/vuln/detail/CVE-2026-78674](https://cvefeed.io/vuln/detail/CVE-2026-78674)<br>[https://security.docs.wso2.com/en/latest/security-announcements/security-advisories/2026/WSO2-2026-5692/](https://security.docs.wso2.com/en/latest/security-announcements/security-advisories/2026/WSO2-2026-5692/) |
| **CVE-2026-76418** | 8.6 | N/A | FALSE | Cisco Secure Firewall Adaptive Security Appliance (ASA) Software et Cisco Secure Firewall Threat Defense (FTD) Software | Déni de service par déréférencement de pointeur NULL (CWE-690) | Indisponibilité du concentrateur VPN d'accès distant, perte des sessions utilisateurs distants, interruption des accès aux services internes dépendants et perturbation des opérations. La répétition de l'exploit peut maintenir l'équipement en état de redémarrage continu. | Theoretical | Appliquer les correctifs Cisco de l'avis cisco-sa-asaftd-tunnel-dos-s6mgkb75 et mettre à jour ASA/FTD. Corriger ou supprimer la configuration d'authentification secondaire problématique sur les tunnel-groups. Restreindre l'exposition du service SSL VPN (listes d'IP, géoblocage, MFA) et placer un dispositif de protection anti-DoS en amont. | [https://cvefeed.io/vuln/detail/CVE-2026-76418](https://cvefeed.io/vuln/detail/CVE-2026-76418)<br>[https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-tunnel-dos-s6mgkb75](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-tunnel-dos-s6mgkb75) |
| **CVE-2026-63190** | N/A | N/A | FALSE | FearlessCMS | Scripts de débogage non authentifiés exposant des opérations sur le système de fichiers et cross-site scripting (XSS) | Divulgation d'informations sur l'infrastructure et l'arborescence du serveur, vol de session administrateur via XSS, modification de contenu, et potentialité d'escalade vers une compromission complète du site selon les opérations de fichiers réellement exposées. | Theoretical | Supprimer ou désactiver les scripts de débogage en production et appliquer la mise à jour corrective de l'éditeur. Mettre en place un WAF filtrant les payloads XSS et restreignant l'accès aux chemins de debug. Appliquer le moindre privilège sur le compte de service web et activer les attributs de cookie HttpOnly/Secure/SameSite. Réaliser un audit de code des scripts de développement avant tout déploiement. | [https://cvefeed.io/vuln/detail/CVE-2026-63190](https://cvefeed.io/vuln/detail/CVE-2026-63190) |
| **CVE-2026-104351** | 9.9 | N/A | FALSE | Adobe Campaign Classic versions 7.4.4 build 9402 et antérieures (Windows et Linux) | Injection de code (CWE-94) menant à l'exécution de code arbitraire | Exécution de code arbitraire sur les serveurs Campaign, compromission des données clients et des campagnes marketing, accès aux bases de données et aux intégrations, mouvement latéral vers les systèmes connectés. | None | Mettre à jour Adobe Campaign Classic vers la version 7.4.4 build 9403. Restreindre l'exposition des interfaces d'administration, appliquer le moindre privilège sur les comptes Campaign et surveiller les workflows et scripts créés hors change management. | [https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html](https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html) |
| **CVE-2026-104353** | 9.9 | N/A | FALSE | Adobe Campaign Classic versions 7.4.4 build 9402 et antérieures (Windows et Linux) | Injection de commandes système (CWE-78) menant à l'exécution de code arbitraire | Exécution de commandes arbitraires sur le serveur, compromission de la plateforme marketing, accès aux données clients, pivot vers les systèmes internes connectés à Campaign. | None | Mettre à jour vers Adobe Campaign Classic 7.4.4 build 9403. Restreindre les privilèges du compte de service, valider strictement les entrées et surveiller les processus enfants lancés par les services Campaign. | [https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html](https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html) |
| **CVE-2026-105780** | 9.9 | N/A | FALSE | Adobe Campaign Classic versions 7.4.4 build 9402 et antérieures (Windows et Linux) | Autorisation incorrecte (CWE-863) menant à l'exécution de code arbitraire | Contournement des contrôles d'accès, élévation de privilèges et exécution de code arbitraire sur la plateforme, avec risque de compromission des données clients et des intégrations. | None | Mettre à jour vers Adobe Campaign Classic 7.4.4 build 9403. Revoir et durcir la matrice d'autorisation, supprimer les droits excessifs et auditer les changements de permissions. | [https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html](https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html) |
| **CVE-2026-105489** | 9.9 | N/A | FALSE | Adobe Campaign Classic versions 7.4.4 build 9402 et antérieures (Windows et Linux) | Injection SQL (CWE-89) menant à un contournement des fonctions de sécurité | Accès non autorisé à des données sensibles (contacts, campagnes, historiques), contournement de contrôles de sécurité, altération de données et risque d'exfiltration massive. | None | Mettre à jour vers Adobe Campaign Classic 7.4.4 build 9403. Utiliser des requêtes paramétrées, restreindre les droits du compte de base de données et déployer un WAF en amont des interfaces Campaign. | [https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html](https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html) |
| **CVE-2026-105781** | 9.8 | N/A | FALSE | Adobe Campaign Classic versions 7.4.4 build 9402 et antérieures (Windows et Linux) | Injection SQL (CWE-89) menant à un contournement des fonctions de sécurité | Divulgation et altération de données clients, contournement des contrôles d'accès, risque d'exfiltration et d'atteinte à la conformité réglementaire. | None | Mettre à jour vers Adobe Campaign Classic 7.4.4 build 9403. Paramétrer les requêtes, restreindre les droits de la base de données et filtrer les payloads d'injection au niveau du WAF. | [https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html](https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html) |
| **CVE-2026-104350** | 9.3 | N/A | FALSE | Adobe Campaign Classic versions 7.4.4 build 9402 et antérieures (Windows et Linux) | Cross-site scripting réfléchi (CWE-79) menant à une élévation de privilèges | Vol de session administrateur, exécution d'actions au nom de la victime, élévation de privilèges et compromission de la plateforme marketing. | None | Mettre à jour vers Adobe Campaign Classic 7.4.4 build 9403. Activer les attributs de cookie HttpOnly/Secure/SameSite, déployer un WAF anti-XSS et imposer la MFA sur les comptes administrateurs. | [https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html](https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html) |
| **CVE-2026-104354** | 9.1 | N/A | FALSE | Adobe Campaign Classic versions 7.4.4 build 9402 et antérieures (Windows et Linux) | Injection SQL (CWE-89) menant à un contournement des fonctions de sécurité | Accès non autorisé à des données sensibles, contournement de contrôles de sécurité et risque d'exfiltration de données clients. | None | Mettre à jour vers Adobe Campaign Classic 7.4.4 build 9403. Paramétrer les requêtes, restreindre les droits de la base et filtrer les payloads au niveau du WAF. | [https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html](https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html) |
| **CVE-2026-105779** | 9.1 | N/A | FALSE | Adobe Campaign Classic versions 7.4.4 build 9402 et antérieures (Windows et Linux) | Injection SQL (CWE-89) menant à un contournement des fonctions de sécurité | Divulgation et altération de données clients, contournement des contrôles d'accès et risque d'exfiltration. | None | Mettre à jour vers Adobe Campaign Classic 7.4.4 build 9403. Paramétrer les requêtes, restreindre les droits de la base et filtrer les payloads d'injection au niveau du WAF. | [https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html](https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html) |
| **CVE-2026-48360** | 9.6 | N/A | FALSE | Adobe Connect Desktop (Windows, macOS Silicon, macOS Intel) et Adobe Connect Mobile pour Android | Injection de code (CWE-94) menant à l'exécution de code arbitraire | Exécution de code arbitraire sur les postes des utilisateurs de visioconférence, compromission de l'endpoint, vol de données et mouvement latéral depuis le poste utilisateur. | None | Mettre à jour Adobe Connect Desktop et Mobile vers les versions corrigées. Restreindre l'installation de logiciels non approuvés, contrôler les sources de téléchargement et surveiller les processus enfants du client Connect. | [https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html](https://thehackernews.com/2026/10/adobe-fixes-8-critical-campaign-classic.html) |
| **CVE-2026-105420** | N/A | N/A | FALSE | Wing FTP Server | Vulnérabilité non précisée dans la source (avis CERT Polska) | Non déterminé à ce stade. Les serveurs de transfert de fichiers étant fréquemment exposés sur Internet et détenant des données sensibles, tout défaut affectant Wing FTP Server doit être considéré comme à fort impact potentiel jusqu'à obtention des détails techniques. | None | Consulter l'avis complet du CERT Polska et le bulletin de l'éditeur pour identifier les versions affectées et le correctif. En attendant, restreindre l'exposition du service, imposer FTPS/SFTP, limiter les comptes et surveiller les journaux de connexion et de transfert. | [https://cert.pl/en/posts/2026/10/CVE-2026-105420/](https://cert.pl/en/posts/2026/10/CVE-2026-105420/) |
| **CVE-2026-33096** | N/A | N/A | FALSE | Serveur Windows exposant un service HTTP/3 | Déni de service (crash répété) | Indisponibilité de service (déni de service) sur les serveurs Windows exposés en HTTP/3, avec possibilité de maintenir le service hors ligne par répétition des requêtes. | Theoretical | Appliquer le correctif d'avril 2026, désactiver HTTP/3 lorsqu'il n'est pas nécessaire, restreindre l'exposition des services HTTP et mettre en place un filtrage/rate-limiting en amont. | [https://thehackernews.com/2026/10/anthropics-unreleased-ai-model-chains.html](https://thehackernews.com/2026/10/anthropics-unreleased-ai-model-chains.html) |
| **CVE-2026-98432** | N/A | N/A | FALSE | Noyau Linux avec listener Multipath TCP | Exécution de code à distance avec privilèges root | Compromission totale de l'hôte : exécution de commandes en root à distance, sans authentification, ouvrant la voie au déploiement de charges malveillantes et au mouvement latéral. | Theoretical | Appliquer le correctif noyau du 15 octobre 2026, désactiver MPTCP lorsqu'il n'est pas requis, restreindre l'exposition réseau des hôtes et surveiller les connexions MPTCP anormales. | [https://thehackernews.com/2026/10/anthropics-unreleased-ai-model-chains.html](https://thehackernews.com/2026/10/anthropics-unreleased-ai-model-chains.html) |
| **CVE-2026-6064** | 7.3 | N/A | FALSE | AVG Internet Security (service avgToolsSvc) | Suivi de lien symbolique menant à une élévation de privilèges locaux | Élévation de privilèges locaux vers SYSTEM sur les postes protégés par AVG, permettant la désactivation des protections, la persistance et le mouvement latéral. | None | Mettre à jour AVG Internet Security vers la version 26.5, limiter les droits d'écriture des utilisateurs sur les répertoires des services, et surveiller la création de liens symboliques. | [http://www.zerodayinitiative.com/advisories/ZDI-26-832/](http://www.zerodayinitiative.com/advisories/ZDI-26-832/) |
| **CVE-2026-112656** | 3.3 | N/A | FALSE | Apple macOS (moteur de rendu de polices CoreText) | Lecture hors limites (out-of-bounds read) menant à une divulgation d'informations | Divulgation d'informations sensibles en mémoire ; utilisable en combinaison avec d'autres vulnérabilités pour faciliter l'exécution de code dans le contexte du processus courant. | None | Appliquer la mise à jour Apple corrective, éviter l'ouverture de polices et documents non fiables, et filtrer les pièces jointes au niveau de la messagerie. | [http://www.zerodayinitiative.com/advisories/ZDI-26-831/](http://www.zerodayinitiative.com/advisories/ZDI-26-831/) |
| **CVE-2026-86974** | 8.8 | N/A | FALSE | Apple Safari (implémentation de l'entrée IC jsToWasm) | Confusion de types menant à une exécution de code à distance | Exécution de code arbitraire sur le terminal de la victime via une simple visite de page web, avec les privilèges de l'utilisateur du navigateur. | None | Appliquer la mise à jour Apple corrective, activer les mises à jour automatiques, filtrer les domaines malveillants et sensibiliser les utilisateurs aux liens non sollicités. | [http://www.zerodayinitiative.com/advisories/ZDI-26-830/](http://www.zerodayinitiative.com/advisories/ZDI-26-830/) |
| **CVE-2026-118611** | 6.8 | N/A | FALSE | Alpine iLX-F511 (gestion des paquets Bluetooth OBEX) | Débordement de buffer sur le tas menant à une exécution de code à distance | Exécution de code arbitraire en root sur l'unité, avec accès physique préalable ; risque de compromission persistante du système embarqué et des données du véhicule. | None | Aucun correctif disponible à la divulgation : restreindre l'interaction avec le produit (désactivation du Bluetooth/OBEX, contrôle de l'accès physique) et appliquer le firmware correctif dès sa publication. | [http://www.zerodayinitiative.com/advisories/ZDI-26-829/](http://www.zerodayinitiative.com/advisories/ZDI-26-829/) |
| **CVE-2026-118610** | 8.8 | N/A | FALSE | Alpine iLX-F511 (service Android Auto) | Débordement de buffer sur la pile menant à une exécution de code à distance | Exécution de code arbitraire en root depuis le réseau adjacent, sans interaction utilisateur, permettant la compromission complète du système embarqué. | None | Aucun correctif disponible à la divulgation : désactiver le service Android Auto, restreindre l'appairage et l'exposition sans fil, et appliquer le firmware correctif dès sa publication. | [http://www.zerodayinitiative.com/advisories/ZDI-26-828/](http://www.zerodayinitiative.com/advisories/ZDI-26-828/) |
| **CVE-2026-118609** | 6.8 | N/A | FALSE | Alpine iLX-F511 (gestionnaire de connexion Android Auto) | Débordement de buffer sur la pile menant à une exécution de code à distance | Exécution de code arbitraire en root sur l'unité avec accès physique préalable, permettant la compromission persistante du système embarqué. | None | Aucun correctif disponible à la divulgation : restreindre l'accès physique et l'usage d'Android Auto, et appliquer le firmware correctif dès sa publication. | [http://www.zerodayinitiative.com/advisories/ZDI-26-827/](http://www.zerodayinitiative.com/advisories/ZDI-26-827/) |
| **CVE-2026-118608** | 3.5 | N/A | FALSE | Alpine iLX-F511 (bibliothèque libanwbtstack.so, fonction prh_rfcomm_cc_process_test) | Lecture hors limites (Out-of-Bounds Read) — divulgation d'informations | Divulgation d'informations sensibles en mémoire de l'unité (adresses, données de configuration, secrets éventuels) par un attaquant en proximité radio. Utilisée en chaîne, elle peut faciliter une compromission complète de l'autoradio en contexte root, avec accès aux données du véhicule et au réseau embarqué. | Theoretical | Aucun correctif disponible à la publication. La seule mesure efficace est de restreindre l'interaction avec le produit : désactiver le Bluetooth ou l'appairage libre, n'autoriser que des périphériques connus, contrôler l'accès physique aux véhicules et segmenter l'unité sur un VLAN dédié. Surveiller la publication d'un firmware Alpine. | [http://www.zerodayinitiative.com/advisories/ZDI-26-826/](http://www.zerodayinitiative.com/advisories/ZDI-26-826/) |
| **CVE-2026-118607** | 6.8 | N/A | FALSE | Alpine iLX-F511 (composant diagapp) | Injection de commandes système | Un attaquant ayant un accès physique bref à l'autoradio (atelier, stationnement, véhicule de location) peut exécuter des commandes arbitraires en root, compromettre durablement l'unité et potentiellement atteindre le réseau embarqué du véhicule. | Theoretical | Pas de correctif disponible. Restreindre l'accès physique aux unités et aux ports de diagnostic, contrôler les interventions en atelier, isoler l'autoradio sur un segment réseau dédié et surveiller les journaux diagapp. | [http://www.zerodayinitiative.com/advisories/ZDI-26-825/](http://www.zerodayinitiative.com/advisories/ZDI-26-825/) |
| **CVE-2026-118606** | 8.8 | N/A | FALSE | Alpine iLX-F511 (framework service) | Exposition de fonction dangereuse — exécution de code à distance | Compromission complète de l'autoradio à distance depuis le réseau adjacent (Wi-Fi/Bluetooth du véhicule, réseau d'atelier), avec exécution en root : accès aux données du véhicule, possibilité de persistance et de pivot vers le réseau embarqué. | Theoretical | Aucun correctif disponible. Segmenter les autoradios, filtrer les flux vers le framework service, désactiver les services réseau non nécessaires, restreindre la proximité réseau et surveiller les connexions adjacentes anormales. | [http://www.zerodayinitiative.com/advisories/ZDI-26-824/](http://www.zerodayinitiative.com/advisories/ZDI-26-824/) |
| **CVE-2026-118605** | 8.0 | N/A | FALSE | Alpine iLX-F511 (fonction prh_sdp_service_search_decode, pile Bluetooth) | Dépassement de tampon sur la pile (Stack-based Buffer Overflow) — exécution de code à distance | Exécution de code arbitraire en root sur l'autoradio depuis un périphérique Bluetooth à proximité, permettant la compromission complète de l'unité et un accès potentiel au réseau embarqué du véhicule. | Theoretical | Pas de correctif disponible. Désactiver ou restreindre l'appairage Bluetooth, n'autoriser que des périphériques connus, contrôler la proximité physique des véhicules sensibles et surveiller les journaux de la pile Bluetooth. | [http://www.zerodayinitiative.com/advisories/ZDI-26-823/](http://www.zerodayinitiative.com/advisories/ZDI-26-823/) |
| **CVE-2026-118604** | 6.8 | N/A | FALSE | Alpine iLX-F511 (framework service) | Dépassement de tampon sur la pile (Stack-based Buffer Overflow) — exécution de code | Un attaquant disposant d'un accès physique à l'autoradio peut exécuter du code arbitraire en root, compromettre durablement l'unité et potentiellement atteindre le réseau embarqué du véhicule. | Theoretical | Aucun correctif disponible. Restreindre l'accès physique aux unités, tracer les interventions en atelier, isoler l'autoradio sur un segment réseau dédié et surveiller les journaux du framework service. | [http://www.zerodayinitiative.com/advisories/ZDI-26-822/](http://www.zerodayinitiative.com/advisories/ZDI-26-822/) |
| **CVE-2026-118603** | 8.0 | N/A | FALSE | Alpine iLX-F511 (parsing des données vCard, pile Bluetooth) | Dépassement de tampon sur la pile (Stack-based Buffer Overflow) — exécution de code à distance | Exécution de code arbitraire en root sur l'autoradio depuis un périphérique Bluetooth à proximité, avec compromission complète de l'unité et accès potentiel aux données du véhicule et au réseau embarqué. | Theoretical | Pas de correctif disponible. Désactiver ou restreindre l'appairage Bluetooth et la synchronisation de contacts, n'autoriser que des périphériques connus, contrôler la proximité physique des véhicules sensibles et surveiller les journaux Bluetooth. | [http://www.zerodayinitiative.com/advisories/ZDI-26-821/](http://www.zerodayinitiative.com/advisories/ZDI-26-821/) |
| **CVE-2026-118602** | 7.8 | N/A | FALSE | Alpine iLX-F511 (service Fiv / Fiv.System) | Exposition de méthode dangereuse — élévation de privilèges locale | Un attaquant ayant déjà obtenu une exécution de code local sur l'autoradio peut élever ses privilèges en root, prendre le contrôle total de l'unité et accéder aux données et services du véhicule. | Theoretical | Aucun correctif disponible. Durcir les autorisations des applications embarquées, limiter l'installation de code non signé, restreindre l'accès physique et surveiller les invocations anormales du service Fiv. | [http://www.zerodayinitiative.com/advisories/ZDI-26-820/](http://www.zerodayinitiative.com/advisories/ZDI-26-820/) |
| **CVE-2026-118601** | 6.3 | N/A | FALSE | Alpine iLX-F511 (service SSH) | Identifiants codés en dur (Hard-coded Credentials) — exécution de code à distance | Accès distant non authentifié à l'unité via SSH avec le compte telechips, permettant l'exécution de code, la reconnaissance du système embarqué et la préparation d'une compromission plus profonde du véhicule. | Theoretical | Aucun correctif disponible. Désactiver le service SSH s'il n'est pas nécessaire, filtrer strictement l'accès réseau aux autoradios, segmenter le parc et surveiller les connexions SSH vers les unités. | [http://www.zerodayinitiative.com/advisories/ZDI-26-819/](http://www.zerodayinitiative.com/advisories/ZDI-26-819/) |
| **CVE-2026-118619** | 8.8 | N/A | FALSE | Ultralytics | Traversée de répertoire menant à une exécution de code à distance | Exécution de code arbitraire dans le contexte du processus Ultralytics, avec compromission potentielle de l'hôte, des données traitées et des secrets accessibles à l'utilisateur. | Theoretical | Restreindre l'interaction avec le produit et éviter le chargement de fichiers ou de modèles non fiables. Isoler les traitements dans un environnement à privilèges minimaux, surveiller les exécutions suspectes et appliquer le correctif éditeur dès sa publication. | [http://www.zerodayinitiative.com/advisories/ZDI-26-818/](http://www.zerodayinitiative.com/advisories/ZDI-26-818/) |
| **CVE-2026-118618** | 7.8 | N/A | FALSE | Ultralytics | Injection de code menant à une exécution de code à distance | Exécution de code arbitraire dans le contexte de l'utilisateur, avec compromission potentielle de l'hôte et des données accessibles au processus Ultralytics. | Theoretical | Restreindre l'interaction avec le produit, éviter les modèles et configurations non fiables, isoler les traitements et appliquer le correctif éditeur dès sa disponibilité. | [http://www.zerodayinitiative.com/advisories/ZDI-26-817/](http://www.zerodayinitiative.com/advisories/ZDI-26-817/) |
| **CVE-2026-118617** | 7.8 | N/A | FALSE | Ultralytics | Désérialisation de données non fiables menant à une exécution de code à distance | Exécution de code arbitraire dans le contexte de l'utilisateur, avec compromission potentielle de l'hôte et des données accessibles au processus Ultralytics. | Theoretical | Restreindre l'interaction avec le produit, éviter les caches de datasets non fiables, isoler les traitements et appliquer le correctif éditeur dès sa disponibilité. | [http://www.zerodayinitiative.com/advisories/ZDI-26-816/](http://www.zerodayinitiative.com/advisories/ZDI-26-816/) |
| **CVE-2026-118616** | 7.8 | N/A | FALSE | Ultralytics | Injection de code menant à une exécution de code à distance | Exécution de code arbitraire dans le contexte de l'utilisateur, avec compromission potentielle de l'hôte et des données accessibles au processus Ultralytics. | Theoretical | Restreindre l'interaction avec le produit, éviter les modèles et configurations non fiables, isoler les traitements et appliquer le correctif éditeur dès sa disponibilité. | [http://www.zerodayinitiative.com/advisories/ZDI-26-815/](http://www.zerodayinitiative.com/advisories/ZDI-26-815/) |
| **CVE-2026-118615** | 7.8 | N/A | FALSE | Ultralytics | Injection de commande menant à une exécution de code à distance | Exécution de code arbitraire dans le contexte de l'utilisateur, avec compromission potentielle de l'hôte et des données accessibles au processus Ultralytics. | Theoretical | Restreindre l'interaction avec le produit, éviter les modèles PyTorch non fiables, isoler les traitements et appliquer le correctif éditeur dès sa disponibilité. | [http://www.zerodayinitiative.com/advisories/ZDI-26-814/](http://www.zerodayinitiative.com/advisories/ZDI-26-814/) |
| **CVE-2026-118029** | N/A | N/A | FALSE | AWS SDK for pandas (awswrangler) - module Athena | Propriété non vérifiée de l'emplacement par défaut des résultats de requêtes Athena | Lecture non autorisée de résultats de requêtes Athena et manipulation de données retournées à l'appelant, avec risque d'atteinte à l'intégrité et à la confidentialité des données analytiques. | None | Mettre à jour awswrangler vers la version 3.16.1 ou supérieure. Vérifier que le bucket de résultats Athena par défaut est détenu par le compte légitime et définir un emplacement de résultats explicite ou une configuration de workgroup contraignante. | [https://aws.amazon.com/security/security-bulletins/rss/2026-153-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-153-aws/) |
| **CVE-2026-115415** | N/A | N/A | FALSE | Strands Agents Tools (strands-agents-tools) - outil environment | Contournement du masquage des secrets via injection de prompt | Exposition de secrets présents dans l'environnement des agents, notamment des identifiants cloud et clés API, avec risque d'accès non autorisé aux ressources associées. | None | Mettre à jour strands-agents-tools vers la version 0.8.6 ou supérieure, supprimer l'outil environment des agents, faire tourner les identifiants exposés et éviter les secrets de longue durée dans l'environnement des processus. | [https://aws.amazon.com/security/security-bulletins/rss/2026-154-aws/](https://aws.amazon.com/security/security-bulletins/rss/2026-154-aws/) |
| **CVE-2026-115881** | 9.1 | N/A | FALSE | GoAhead Web Server | Validation incorrecte de la révocation des certificats dans mTLS | Maintien d'accès non autorisé à des équipements et services protégés par mTLS à l'aide de certificats révoqués, avec risque d'usurpation d'identité et de contournement des contrôles d'accès. | Theoretical | Mettre à jour GoAhead vers la version 6.1.1 ou supérieure. Vérifier l'application effective des CRL, révoquer et remplacer les certificats concernés, et surveiller les authentifications mTLS avec des certificats révoqués. | [https://socprime.com/blog/cve-2026-115881-analysis/](https://socprime.com/blog/cve-2026-115881-analysis/) |
| **CVE-2026-85017** | 7.5 | N/A | FALSE | Plugin WordPress Unlimited Elements For Elementor, versions antérieures à 2.0.20 ; correctif partiel en 2.0.18-2.0.19. | Injection d'objet PHP (CWE-502) combinée à un contrôle d'autorisation manquant (CWE-862) sur une action AJAX. | Selon les chaînes de gadgets disponibles, l'exploitation peut permettre l'exécution de code arbitraire sur le serveur WordPress, la divulgation de données sensibles, la modification ou la destruction de contenu, et la compromission totale du site. L'accès nécessite un compte authentifié de faible privilège et l'action AJAX vulnérable doit être accessible. | Theoretical | Mettre à jour le plugin vers la version 2.0.20 ou supérieure. En attendant, désactiver le plugin ou bloquer l'action AJAX vulnérable et restreindre l'accès à /wp-admin/admin-ajax.php via le WAF. Auditer les comptes abonnés et éditeurs, appliquer le moindre privilège et surveiller les requêtes POST contenant des données sérialisées PHP. Vérifier l'intégrité des fichiers WordPress et rechercher des webshells ou des comptes administrateur non autorisés. Remplacer autant que possible unserialize() par json_decode() dans le code personnalisé et maintenir à jour l'ensemble des plugins et thèmes. | [https://www.valtersit.com/cve/CVE-2026-85017/](https://www.valtersit.com/cve/CVE-2026-85017/)<br>[https://mastodon.social/@hugovalters/117520348383432791](https://mastodon.social/@hugovalters/117520348383432791) |
| **** | N/A | N/A | FALSE | Non applicable — article judiciaire relatif aux groupes ransomware Hive et Nefilim | Non applicable (cybercriminalité / ransomware) | Pertes financières de plusieurs millions de dollars pour les victimes, destruction de systèmes, vol et divulgation de données sensibles, interruption d'activité. L'impact pour les organisations est à la fois opérationnel, financier et réputationnel. | None | Aucune mesure de remédiation logicielle : il s'agit d'une action répressive. Les organisations doivent néanmoins maintenir des sauvegardes immuables, une segmentation réseau, l'authentification multifacteur, la détection des exfiltrations massives et un plan de réponse à incident ransomware testé. | [https://securityaffairs.com/201960/cyber-crime/hive-and-nefilim-ransomware-affiliate-gets-70-months-in-jail.html](https://securityaffairs.com/201960/cyber-crime/hive-and-nefilim-ransomware-affiliate-gets-70-months-in-jail.html) |
| **** | N/A | N/A | FALSE | Non applicable — article de renseignement sur la surveillance publicitaire des utilisateurs Starlink | Non applicable (surveillance via infrastructure publicitaire / atteinte à la vie privée) | Atteinte à la vie privée et à la sécurité opérationnelle des utilisateurs de Starlink, en particulier les personnels militaires, humanitaires ou gouvernementaux déployés en zones de conflit. Risque de ciblage physique et de collecte de renseignements sur des individus et des sites sensibles. | None | Bloquer les domaines publicitaires et traqueurs au niveau DNS et proxy, utiliser un VPN ou un relais de sortie mutualisé pour masquer la localisation, restreindre les navigateurs et applications sur les terminaux sensibles, et sensibiliser les utilisateurs itinérants. | [https://securityaffairs.com/201947/intelligence/ads-or-surveillance-researchers-flag-suspicious-targeting-of-starlink-users.html](https://securityaffairs.com/201947/intelligence/ads-or-surveillance-researchers-flag-suspicious-targeting-of-starlink-users.html) |
| **** | N/A | N/A | FALSE | Non applicable — article d'analyse sur trois campagnes ciblant le Japon et l'usage de l'IA par les attaquants | Non applicable (campagnes d'attaques assistées par IA) | Fuite de données pour des organisations japonaises, démonstration de la capacité de l'IA à industrialiser la reconnaissance, l'exploitation et la gestion d'infrastructure d'attaque. L'exploitation de systèmes anciens et de configurations faibles reste le facteur déterminant du succès. | Active | Corriger et décommissionner les systèmes web obsolètes, durcir les configurations, centraliser la journalisation, détecter les comportements automatisés et suivre les avertissements des autorités nationales ainsi que les rapports de recherche (ARTEX). | [https://securityaffairs.com/201913/ai/three-japan-focused-cyberattacks-show-how-hackers-use-ai.html](https://securityaffairs.com/201913/ai/three-japan-focused-cyberattacks-show-how-hackers-use-ai.html) |
| **** | N/A | N/A | FALSE | Metabase Pro et Enterprise versions antérieures à 1.64.3.4 ; Metabase open source versions antérieures à 0.64.3.4 | Multiples vulnérabilités non spécifiées par l'éditeur (GHSA-v44v-x8x4-mvcw) | Les vulnérabilités permettent à un attaquant de provoquer un problème de sécurité non spécifié par l'éditeur. | Theoretical | Mettre à jour Metabase vers 1.64.3.4 (Pro/Enterprise) ou 0.64.3.4 (open source) ou supérieur, et se référer au bulletin GHSA-v44v-x8x4-mvcw. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1403/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1403/) |
| **** | N/A | N/A | FALSE | Mitel OpenScape Endpoint Management, versions antérieures à V1R2.5.1 | Multiples vulnérabilités : élévation de privilèges et contournement de la politique de sécurité | Compromission de la chaîne de gestion des postes de travail : un attaquant pourrait modifier les politiques de sécurité, distribuer des configurations malveillantes ou obtenir des privilèges administratifs sur les terminaux gérés. L'ampleur exacte dépend des vulnérabilités individuelles non détaillées publiquement. | None | Appliquer les correctifs du bulletin Mitel MISA-2026-0009 et migrer vers la version V1R2.5.1 ou supérieure. En attendant, restreindre l'accès à l'interface d'administration, activer le MFA, journaliser et surveiller les actions d'administration. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1404/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1404/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1404/`<br>`hxxps://www[.]mitel[.]com/support/security-advisories/mitel-product-security-advisory-misa-2026-0009` |
| **** | N/A | N/A | FALSE | Belden X35-HWC-A et ICX35-HWC-E, versions antérieures à 1.14.158 | Contournement de la politique de sécurité (réinitialisation du verrouillage de connexion) | Compromission potentielle des identifiants d'administration d'une passerelle OT/IoT, avec risque de modification de configuration, de perturbation de la supervision industrielle ou de pivot vers le réseau d'exploitation. | None | Mettre à jour vers le firmware 1.14.158 ou supérieur. Restreindre l'accès à l'interface d'administration, segmenter les équipements OT, surveiller les tentatives d'authentification et utiliser des mots de passe robustes avec rotation. | [https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1407/](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1407/)<br>`hxxps://www[.]cert[.]cyber[.]gouv[.]fr/avis/CERTFR-2026-AVI-1407/`<br>`hxxps://assets[.]belden[.]com/asset/3be80067-b211-423d-9be4-4e31bd43fbc9/PSIRT-9-Login-Lockout-Resets-in-ICX35.pdf` |
| **** | N/A | N/A | FALSE | Microsoft Edge (versions antérieures à 148.0.3967.70) sur Windows | Chaîne de vulnérabilités logiques : UXSS et évasion de sandbox navigateur | Sur un navigateur non corrigé, une page web malveillante peut aboutir à l'exécution de code arbitraire hors du sandbox Edge, avec les privilèges de l'utilisateur connecté : vol de données, installation de logiciels malveillants, persistance via handlers de protocole. L'UXSS permet en outre de lire et manipuler le contenu de n'importe quel site visité par la victime. | None | Mettre à jour Microsoft Edge vers la version 148.0.3967.70 ou ultérieure (correctif publié le 15 mai 2026). Désactiver l'auto-connexion aux sites Microsoft pour les profils sensibles, restreindre les handlers de protocole personnalisés et bloquer l'exécution de binaires depuis des répertoires utilisateur inscriptibles (AppLocker/WDAC). Surveiller les écritures de fichiers par le processus navigateur. | [https://thehackernews.com/2026/10/researcher-reveals-how-logic-bugs-alone.html](https://thehackernews.com/2026/10/researcher-reveals-how-logic-bugs-alone.html) |
| **** | N/A | N/A | FALSE | Google Chrome (et navigateurs dérivés de Chromium) | Vulnérabilités critiques multiples corrigées dans une mise à jour de sécurité majeure | Selon la nature exacte des vulnérabilités (non confirmée), un attaquant pourrait provoquer une exécution de code arbitraire dans le navigateur, une évasion de sandbox ou une divulgation d'informations via une page web malveillante, avec compromission du poste utilisateur. | None | Appliquer sans délai la dernière version stable de Google Chrome sur l'ensemble du parc et vérifier la couverture réelle. Consulter le bulletin officiel Chrome Releases pour obtenir les identifiants CVE et les détails techniques. Restreindre la navigation vers des sites non approuvés pour les postes ne pouvant être mis à jour immédiatement. | [https://thecyberthrone.in/2026/10/28/google-chrome-patches-four-critical-vulnerabilities-in-major-security-update/](https://thecyberthrone.in/2026/10/28/google-chrome-patches-four-critical-vulnerabilities-in-major-security-update/) |
| **** | 8.8 | N/A | FALSE | Valkey (gestionnaire de messages PUBLISH) | Erreur de troncature numérique menant à une exécution de code à distance | Exécution de code arbitraire à distance avec les privilèges du compte de service Valkey, après authentification ; risque de compromission du cache, d'exfiltration de données et de pivot vers les systèmes consommateurs. | None | Appliquer le correctif Valkey publié (GHSA-f4q9-j22m-xqq9), ne jamais exposer le service sur Internet, imposer une authentification forte et restreindre les commandes disponibles via ACL. | [http://www.zerodayinitiative.com/advisories/ZDI-26-833/](http://www.zerodayinitiative.com/advisories/ZDI-26-833/) |

---

<div id="articles"></div>

# SECTION "ARTICLES"

---

<div id="encore-une-autre-campagne-clickfix-mer-28-oct"></div>

## Encore une autre campagne ClickFix, (mer. 28 oct.)

### Résumé

Le 28 octobre 2026, un analyste du SANS ISC a observé une campagne ClickFix inédite reposant sur une fausse page de vérification Cloudflare et ciblant à la fois macOS et Windows. La page-leurre est servie depuis le domaine js-static[.]cfd, qui charge un script d'embed (embed.js?v=24, c.js) et une série d'appels API de suivi (géolocalisation, empreinte, événements, hits). Le texte ClickFix invite la victime à copier-coller une commande : sur macOS, elle pointe vers hxxps[:]//cf-id[.]com/?ray-id=nz0ovm2jq2g68i, domaine qui ne résolvait pas au moment de l'analyse ; sur Windows, elle pointe vers hxxps[:]//api-com[.]cfd/7ge0w58tzzjsv9, qui a renvoyé une erreur 403 Forbidden. L'analyste n'a donc pas pu récupérer les charges finales macOS ou Windows. Le site légitime compromis à l'origine du trafic a été masqué dans le diary ; un pivot sur js-static[.]cfd dans URLscan permet de retrouver plusieurs sites générant probablement ce trafic.

---

### Analyse opérationnelle

Le vecteur ne repose pas sur une pièce jointe mais sur l'exécution volontaire d'une commande par l'utilisateur, ce qui contourne une partie des filtres mail et des bacs à sable. La détection doit donc se concentrer sur la chaîne d'exécution : navigateur ou explorateur de fichiers engendrant powershell.exe, mshta.exe, curl/wget ou osascript, en particulier depuis la boîte de dialogue Exécuter de Windows ou le Terminal macOS. Les journaux DNS, proxy et pare-feu doivent être corrélés sur js-static[.]cfd, cf-id[.]com et api-com[.]cfd ; les chemins /embed, /c.js, /api/s/hit et /api/track/event constituent une signature comportementale du leurre. Le ciblage simultané de macOS et Windows élargit la surface d'attaque au parc mixte des entreprises, souvent moins couvert en détection sur macOS. Les domaines en .cfd, peu utilisés en entreprise, sont un axe de blocage à faible risque opérationnel. En cas d'exécution confirmée, l'isolation du poste, la préservation mémoire et la révocation des jetons de session sont prioritaires, car un stager peut mener à un vol d'identifiants ou à un accès distant.

---

### Implications stratégiques

ClickFix s'installe durablement comme un standard de la menace opportuniste : le leurre est peu coûteux, réutilisable, et exploite la confiance des utilisateurs dans les mécanismes anti-bot de Cloudflare. L'usage de sites légitimes compromis comme relais rend le blocage par réputation insuffisant et déplace la charge vers la détection comportementale et la sensibilisation. Le double ciblage macOS/Windows traduit une industrialisation des leurres et une recherche de couverture maximale du parc. Pour les organisations, l'enjeu est moins la sophistication technique que la résilience opérationnelle : réduction du délai de détection post-exécution, maîtrise des privilèges locaux et capacité à bloquer rapidement une infrastructure éphémère. La réutilisation de marques (Cloudflare) impose aussi une vigilance sur l'usurpation de marque et la communication aux utilisateurs.

---

### Recommandations

* Bloquer au proxy et au DNS les domaines js-static[.]cfd, cf-id[.]com, api-com[.]cfd et, plus largement, les domaines .cfd non catégorisés.
* Créer des règles de détection EDR sur l'exécution de PowerShell, mshta, curl/wget ou osascript dont le processus parent est un navigateur ou explorer.exe.
* Interdire ou restreindre l'exécution de scripts non signés via AppLocker/WDAC (Windows) et une politique MDM (macOS).
* Lancer une campagne de sensibilisation ciblée : aucune vérification anti-bot légitime ne demande de coller une commande dans un terminal.
* Pivoter sur js-static[.]cfd dans URLscan pour identifier les sites légitimes compromis et avertir les propriétaires concernés.
* Journaliser et conserver au moins 90 jours les événements de création de processus afin de permettre la chasse rétrospective.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les sites web légitimes fréquemment visités par les collaborateurs et surveiller leur compromission via URLscan ou un service de veille de défacement.
* Déployer des règles proxy/DNS bloquant les domaines .cfd non catégorisés et les faux domaines imitant Cloudflare (js-static[.]cfd, api-com[.]cfd, cf-id[.]com).
* Configurer l'EDR pour alerter sur tout processus lancé depuis la boîte de dialogue Exécuter (Win+R) ou le Terminal macOS immédiatement après un copier-coller utilisateur.
* Sensibiliser les utilisateurs : aucune vérification anti-bot légitime ne demande de coller une commande dans PowerShell, mshta ou le Terminal.
* Préparer une procédure de blocage rapide (proxy, DNS interne, EDR) et un modèle de communication pour les postes potentiellement exposés.

#### Phase 2 — Détection et analyse

* Rechercher les résolutions DNS et requêtes HTTP vers js-static[.]cfd, cf-id[.]com et api-com[.]cfd dans les logs DNS, proxy et pare-feu.
* Détecter les chaînes d'exécution suspectes : powershell.exe, mshta.exe, curl, wget ou osascript lancés depuis explorer.exe, Finder ou un navigateur.
* Surveiller les accès aux URL de leurre (embed.js, c.js, /api/s/hit, /api/track/event) qui constituent la signature de la page de fausse vérification.
* Corréler les alertes EDR « script enfant du navigateur » avec les journaux de navigation vers des sites légitimes récemment compromis.
* Vérifier les réponses 403/échec de résolution côté attaquant : elles peuvent masquer une tentative d'infection avortée mais confirment le contact avec l'infrastructure.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement le poste ayant exécuté la commande ClickFix et préserver la mémoire ainsi que les artefacts du navigateur.
* Bloquer au niveau proxy, DNS et pare-feu les domaines et URL identifiés, ainsi que les domaines .cfd non nécessaires à l'activité.
* Révoquer et réinitialiser les secrets présents sur le poste (cookies de session, jetons SSO, identifiants enregistrés) en cas d'exécution confirmée.
* Rechercher et supprimer les artefacts de persistance créés après l'exécution (tâches planifiées, LaunchAgents/LaunchDaemons, clés Run).
* Notifier les équipes réseau pour identifier d'autres postes ayant contacté l'infrastructure et étendre le blocage à l'ensemble du parc.

#### Phase 4 — Activités post-incident

* Reconstruire ou remédier le poste compromis après analyse forensique et validation de l'absence de persistance.
* Mettre à jour les règles de détection avec les nouveaux domaines et chemins d'URL observés, et les partager avec les pairs (ISAC, CERT).
* Revoir l'efficacité des filtrages web et des politiques d'exécution (AppLocker/WDAC, Gatekeeper) sur les postes concernés.
* Documenter la chronologie, l'impact réel et les leçons apprises ; ajuster la sensibilisation sur les leurres ClickFix.
* Signaler les domaines malveillants aux registrars, hébergeurs et à URLscan pour accélérer le démantèlement.

#### Phase 5 — Threat Hunting (proactif)

* Pivoter sur js-static[.]cfd dans URLscan et les bases de renseignement pour identifier les sites légitimes compromis générant le trafic.
* Rechercher historiquement les exécutions de commandes contenant des URL .cfd ou des paramètres ray-id dans les journaux de processus (rétention 30-90 jours).
* Chasser les modèles de fausse vérification Cloudflare dans les journaux proxy (référents, chemins /embed, /c.js, /api/s/*).
* Analyser les postes macOS pour des exécutions osascript/curl déclenchées par un navigateur et les postes Windows pour des chaînes PowerShell encodées.
* Comparer les IOC observés avec les campagnes ClickFix connues afin d'identifier des réutilisations d'infrastructure ou des acteurs communs.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `js-static[.]cfd` | Medium |
| DOMAIN | `cf-id[.]com` | Medium |
| DOMAIN | `api-com[.]cfd` | Medium |
| URL | `hxxps[:]//js-static[.]cfd/embed.js?v=24` | Medium |
| URL | `hxxps[:]//js-static[.]cfd/c.js?embed=__JNJ_4__&lp=%2F&pu=hxxps%3A%2F%2F[site_legitime_compromis]%2F` | Medium |
| URL | `hxxps[:]//cf-id[.]com/?ray-id=nz0ovm2jq2g68i` | Medium |
| URL | `hxxps[:]//api-com[.]cfd/7ge0w58tzzjsv9` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1204.004** | Malicious Copy and Paste : la victime est invitée à copier-coller une commande depuis une fausse page de vérification |
| **T1566** | Phishing : page-leurre de type faux CAPTCHA / fausse vérification Cloudflare servant de vecteur d'exécution |
| **T1059.001** | PowerShell : commande ClickFix exécutée sur les hôtes Windows |
| **T1059.002** | AppleScript : variante de commande ClickFix destinée aux hôtes macOS |
| **T1105** | Ingress Tool Transfer : récupération de la charge finale depuis un domaine contrôlé par l'attaquant |
| **T1584.001** | Compromise Infrastructure: Domains : usage de domaines .cfd et d'un site légitime compromis pour diffuser le leurre |

---

### Sources

* [https://isc.sans.edu/diary/rss/33466](https://isc.sans.edu/diary/rss/33466)


---

<div id="godpotato-rebaptise-wrqsnx-avec-un-stager-powershell-en-memoire-68-go-voles-a-une-agence-gouvernementale-philippine-chargee-de-lemploi-a-letranger-exposes-via-un-repertoire-de-staging-ouvert"></div>

## GodPotato rebaptisé Wrqsnx avec un stager PowerShell en mémoire ; 68 Go volés à une agence gouvernementale philippine chargée de l'emploi à l'étranger, exposés via un répertoire de staging ouvert

### Résumé

L'article de Hunt.io documente deux éléments liés : d'une part la récupération, depuis un répertoire de staging ouvert appartenant à l'opérateur, d'un outil d'élévation de privilèges GodPotato rebaptisé « Wrqsnx » accompagné d'un stager PowerShell s'exécutant en mémoire ; d'autre part l'exposition de 68 Go de données dérobées aux bases de données d'une agence gouvernementale philippine chargée de l'emploi à l'étranger. La fuite a été rendue visible par la mauvaise configuration du répertoire de travail de l'attaquant lui-même, et non par une détection de la victime. Le contenu détaillé de l'article n'était pas accessible dans le flux fourni (page essentiellement composée d'éléments de mise en forme).

---

### Analyse opérationnelle

Le cas illustre un risque double : exfiltration massive de données d'identité (dossiers de travailleurs migrants, pièces justificatives) et usage d'outillage d'élévation de privilèges rebaptisé pour gêner la détection par nom de fichier. La présence d'un stager PowerShell en mémoire implique que les contrôles basés uniquement sur le dépôt de fichiers sont insuffisants : la journalisation des blocs de script, l'analyse mémoire et la surveillance des chaînes d'injection sont nécessaires. Les équipes SOC doivent rechercher les artefacts GodPotato/Wrqsnx, les exécutions PowerShell sans fichier et les exports massifs depuis les bases de données RH. La découverte via un répertoire ouvert souligne l'intérêt du renseignement externe (surface d'exposition, fuites) en complément de la détection interne.

---

### Implications stratégiques

La compromission d'une agence publique gérant l'emploi à l'étranger touche des populations vulnérables et expose des données d'identité difficilement remplaçables, avec un risque de fraude, de chantage et d'usurpation durable. Elle affecte la confiance dans les services publics numériques et peut avoir des conséquences diplomatiques, les travailleurs migrants relevant de relations bilatérales. Le rebranding d'outils offensifs connus (GodPotato) confirme la tendance à la customisation d'outils publics pour retarder la détection. Enfin, l'exposition accidentelle du répertoire de l'attaquant rappelle que la persistance des données volées crée un risque réputationnel et juridique prolongé pour la victime, bien après l'intrusion.

---

### Recommandations

* Rechercher sur le parc les binaires et chaînes associés à GodPotato/Wrqsnx et bloquer les hachages connus.
* Activer ScriptBlock Logging et la journalisation PowerShell avancée pour détecter les stagers en mémoire.
* Auditer l'exposition publique des serveurs et buckets internes (listage de répertoires, accès anonymes).
* Mettre en place une surveillance des exports massifs depuis les bases de données RH et d'identité.
* Préparer un dispositif de notification et d'accompagnement des personnes dont les données d'identité ont fuité.
* Assurer une veille sur les places de marché et les canaux de revente de données pour détecter la réutilisation des enregistrements.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Identifier les jeux de données RH, passeports et dossiers de travailleurs expatriés détenus par l'organisation et classer leur sensibilité.
* Mettre en place une surveillance des répertoires de staging ouverts (buckets, serveurs web mal configurés) exposant le nom de l'organisation.
* Souscrire à une veille sur les fuites de données et les places de marché de revente couvrant le secteur public et les données d'identité.
* Préparer un plan de notification RGPD/local et un dispositif d'information des personnes concernées (travailleurs migrants, ayants droit).
* Durcir les contrôles d'accès aux bases de données et segmenter les environnements de développement des environnements de production.

#### Phase 2 — Détection et analyse

* Rechercher des requêtes massives ou inhabituelles sur les bases de données d'emploi à l'étranger (volumétrie, horaires, comptes de service).
* Surveiller l'apparition d'archives volumineuses (plusieurs dizaines de Go) sur des serveurs web ou buckets accessibles publiquement.
* Détecter l'exécution de GodPotato/Wrqsnx et de stagers PowerShell en mémoire via EDR (comportements d'élévation de privilèges, injection, absence de fichier sur disque).
* Analyser les journaux d'accès web pour des listages de répertoires ou des téléchargements d'archives non référencées.
* Corréler les alertes de sécurité avec les signalements externes de fuite pour confirmer l'origine interne ou tierce.

#### Phase 3 — Confinement, éradication et récupération

* Fermer immédiatement tout répertoire ou bucket exposé et révoquer les accès anonymes.
* Révoquer les identifiants et clés d'API ayant pu être utilisés pour le staging, et forcer la rotation des secrets.
* Isoler les serveurs sur lesquels des outils d'élévation de privilèges ou des stagers PowerShell ont été détectés.
* Préserver les preuves (images disque, journaux, accès au répertoire ouvert) avant toute remédiation.
* Activer une surveillance renforcée des comptes à privilèges et des accès aux bases de données pendant la période d'investigation.

#### Phase 4 — Activités post-incident

* Évaluer précisément le périmètre des données exposées (identités, passeports, dossiers professionnels) et engager les notifications légales.
* Mettre en place une surveillance de la revente ou de la réutilisation des données volées (fraude à l'identité, hameçonnage ciblé).
* Revoir les procédures de staging et de transfert de données entre équipes et prestataires.
* Renforcer la formation des équipes internes sur la sécurisation des répertoires de travail et la gestion des secrets.
* Documenter le retour d'expérience et mettre à jour le plan de réponse aux fuites de données.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher sur le parc les artefacts associés à GodPotato/Wrqsnx (noms de binaires, chaînes, signatures d'élévation de privilèges).
* Chasser les stagers PowerShell en mémoire via les journaux de blocs script (ScriptBlock Logging) et les alertes d'injection de processus.
* Analyser les connexions sortantes vers des services de stockage ou d'hébergement non approuvés depuis les serveurs de bases de données.
* Rechercher des comptes de service utilisés de manière anormale pour des exports massifs de données.
* Pivoter sur les indicateurs de l'opérateur (répertoire de staging, infrastructure d'hébergement) pour identifier d'autres victimes ou campagnes liées.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1068** | Exploitation for Privilege Escalation : usage de GodPotato (rebaptisé Wrqsnx) pour élever les privilèges sous Windows |
| **T1059.001** | PowerShell : stager PowerShell exécuté en mémoire pour éviter le dépôt sur disque |
| **T1074.001** | Local Data Staging : constitution d'un répertoire de staging contenant les données dérobées et les outils |
| **T1567** | Exfiltration Over Web Service : exposition des données via un répertoire ouvert accessible en ligne |
| **T1622** | Debugger Evasion / contournement des mécanismes de défense associé aux outils d'élévation de privilèges |

---

### Sources

* [https://hunt.io/blog/philippine-government-employment-agency-records-stolen](https://hunt.io/blog/philippine-government-employment-agency-records-stolen)
* [https://www.reddit.com/r/redteamsec/comments/1xhoik9/godpotato_rebranded_as_wrqsnx_plus_an_inmemory/](https://www.reddit.com/r/redteamsec/comments/1xhoik9/godpotato_rebranded_as_wrqsnx_plus_an_inmemory/)


---

<div id="des-millions-de-cameras-de-securite-menacees-vulnerabilite-dos-dans-les-appareils-intelbras"></div>

## Des millions de caméras de sécurité menacées : vulnérabilité DoS dans les appareils Intelbras

### Résumé

Les chercheurs de Securelist ont découvert une vulnérabilité de déni de service affectant les caméras IP Intelbras. La faille réside dans un endpoint de mise à jour du firmware accessible sans authentification, permettant à toute personne ayant accès au réseau Wi-Fi local de mettre une caméra hors ligne. Une seule requête interrompt la caméra environ une minute, mais des requêtes périodiques la maintiennent hors ligne indéfiniment. Le firmware analysé était la version v240927 pour la caméra iM3B-C (IM3 C), également compatible selon Intelbras avec les modèles iMX C, iM4 C, iM5 SC, iME 360 C et iM7+ FC. L'authentification normale passe par la méthode RPC global.login sur /RPC2_Login, avec un défi MD5 (username:realm:password puis username:random:hash). Intelbras a publié le firmware R.260804 corrigeant la faille ; un identifiant candidat CAN-2026-2035970 a été attribué par MITRE, avec une classification Medium et un score CVSS 4.0 de 5.1. La vulnérabilité n'est plus présente dans la dernière version du firmware.

---

### Analyse opérationnelle

Le vecteur d'attaque est local (réseau Wi-Fi ou LAN) et ne nécessite aucune authentification, ce qui abaisse fortement la barrière : un visiteur, un prestataire ou un poste compromis sur le même réseau peut neutraliser la vidéosurveillance. L'impact dépasse la disponibilité technique : une caméra hors ligne crée un angle mort de sécurité physique potentiellement exploité pour un vol, une intrusion ou une dégradation. Les équipes doivent prioriser la mise à jour vers R.260804, segmenter les caméras sur un VLAN dédié et restreindre l'accès à l'interface web. La détection repose sur la surveillance des rafales de requêtes vers l'endpoint de mise à jour et sur la corrélation entre pertes de flux vidéo et trafic réseau anormal. Le score CVSS modéré (5.1) ne doit pas masquer l'impact opérationnel élevé pour les sites sensibles.

---

### Implications stratégiques

La vidéosurveillance IP est massivement déployée dans les collectivités, commerces et infrastructures, souvent sans gestion de parc ni politique de correctifs. Une vulnérabilité de DoS non authentifiée sur des millions d'équipements crée un risque systémique de neutralisation coordonnée de la sécurité physique, avec des conséquences assurantielles et juridiques. Le cas illustre la dépendance croissante à des équipements IoT à faible coût, dont la sécurité est rarement intégrée aux cycles de patch. La publication d'un PoC et l'attribution d'un CVE augmentent la probabilité d'exploitation opportuniste. Pour les décideurs, l'enjeu est d'intégrer les objets connectés de sécurité physique dans le périmètre de gestion des vulnérabilités et de gouvernance des risques, au même titre que les systèmes IT.

---

### Recommandations

* Mettre à jour l'ensemble des caméras Intelbras vers le firmware R.260804 ou une version ultérieure.
* Segmenter les caméras sur un VLAN dédié et interdire tout accès depuis les réseaux Wi-Fi invités ou utilisateurs.
* Restreindre l'accès à l'interface web d'administration par liste blanche d'adresses et désactiver l'exposition réseau non nécessaire.
* Superviser les pertes de flux vidéo et les rafales de requêtes vers les endpoints de mise à jour comme indicateurs d'alerte.
* Intégrer les équipements IoT de sécurité physique dans l'inventaire et le processus de gestion des correctifs.
* Prévoir des mesures compensatoires (ronde physique, caméras redondantes) pour les zones critiques en cas d'indisponibilité.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser les caméras Intelbras du parc (modèles iM3B-C, iMX C, iM4 C, iM5 SC, iME 360 C, iM7+ FC) et leur version de firmware.
* Isoler les caméras sur un VLAN dédié avec filtrage strict vers l'extérieur et interdiction d'accès depuis les réseaux Wi-Fi invités ou utilisateurs.
* Planifier la mise à jour vers le firmware R.260804 (ou ultérieur) via l'interface web, l'application mobile ou carte SD.
* Désactiver les services d'administration exposés sur le réseau local et restreindre l'accès à l'interface web par liste blanche d'adresses.
* Documenter la procédure de redémarrage et de restauration des caméras en cas d'indisponibilité prolongée.

#### Phase 2 — Détection et analyse

* Surveiller les requêtes répétées vers l'endpoint de mise à jour firmware des caméras depuis des adresses du réseau local.
* Détecter les épisodes de perte de flux vidéo ou de redémarrages anormaux corrélés à un trafic réseau inhabituel.
* Analyser les journaux de l'interface web des caméras pour des appels non authentifiés à l'endpoint de mise à jour.
* Alerter sur les tentatives d'accès à /RPC2_Login et aux routes de mise à jour depuis des postes non administrateurs.
* Corréler les indisponibilités caméra avec les journaux du pare-feu interne pour identifier la source des requêtes.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer au niveau du commutateur ou du pare-feu interne les adresses sources envoyant des requêtes répétées vers les caméras.
* Segmenter immédiatement les caméras affectées et couper leur accès depuis les réseaux Wi-Fi utilisateurs.
* Appliquer le firmware R.260804 sur les équipements exposés en priorité, puis sur l'ensemble du parc.
* Redémarrer les caméras bloquées et vérifier la reprise du flux vidéo après application du correctif.
* Renforcer temporairement la surveillance physique des zones couvertes par les caméras indisponibles.

#### Phase 4 — Activités post-incident

* Vérifier l'absence de persistance ou de modification de configuration sur les caméras après l'incident.
* Mettre à jour l'inventaire matériel et le processus de gestion des correctifs pour les équipements IoT de sécurité physique.
* Revoir l'architecture réseau des systèmes de vidéosurveillance (segmentation, contrôle d'accès, supervision).
* Documenter l'impact opérationnel (durée d'indisponibilité, zones non couvertes) et les mesures compensatoires appliquées.
* Suivre l'attribution finale du CVE (candidat CAN-2026-2035970) et les éventuelles publications de preuves de concept.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher dans les journaux réseau historiques des rafales de requêtes vers les endpoints de mise à jour firmware des caméras.
* Identifier les équipements encore en firmware v240927 ou antérieur et non corrigés.
* Rechercher des accès non authentifiés aux interfaces d'administration des caméras depuis des postes utilisateurs.
* Analyser les périodes d'indisponibilité vidéo passées pour détecter des attaques DoS non signalées.
* Étendre la chasse aux autres équipements IoT du parc présentant des endpoints de mise à jour accessibles sans authentification.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploit Public-Facing Application : exploitation d'un endpoint de mise à jour firmware exposé |
| **T1499** | Endpoint Denial of Service : requêtes répétées maintenant la caméra hors ligne indéfiniment |
| **T1078** | Valid Accounts : contournement de l'authentification sur l'endpoint de mise à jour (accès sans authentification) |

---

### Sources

* [https://securelist.com/intelbras-camera-vulnerability/121131/](https://securelist.com/intelbras-camera-vulnerability/121131/)


---

<div id="detecter-et-attenuer-zdi-can-33367-et-cinq-autres-failles-linux"></div>

## Détecter et atténuer ZDI-CAN-33367 et cinq autres failles Linux

### Résumé

Sysdig publie un article consacré à la détection et à l'atténuation de la vulnérabilité ZDI-CAN-33367 ainsi que de cinq autres failles affectant Linux. Le contenu porte sur les moyens de détecter l'exploitation de ces vulnérabilités et sur les mesures de remédiation à appliquer sur les systèmes Linux concernés.

---

### Analyse opérationnelle

Les failles de type noyau Linux ont un impact direct sur les socles serveurs, les hyperviseurs et les nœuds de conteneurs : une exploitation réussie peut mener à une élévation de privilèges locale, voire à une évasion de conteneur, donc à une compromission de l'hôte et de l'ensemble des charges de travail qu'il héberge. Pour le SOC, l'enjeu est double : disposer d'une visibilité runtime (eBPF/Falco, auditd, EDR Linux) capable de repérer les comportements post-exploitation, et s'assurer que l'inventaire des versions de noyau est fiable, y compris pour les images de conteneurs souvent reconstruites sans mise à jour du noyau. La priorisation doit cibler les actifs exposés à Internet, les hôtes à privilèges élevés et les environnements multi-tenant. Les mesures techniques attendues : patching accéléré, durcissement du chargement de modules noyau, réduction des capabilities des conteneurs, segmentation des hôtes critiques.

---

### Implications stratégiques

Linux constitue le socle de la majorité des infrastructures cloud, conteneurisées et critiques : une faille exploitable dans ce socle crée un risque systémique bien au-delà d'un serveur isolé, avec un effet de propagation via les images et les chaînes CI/CD. La cadence de publication de correctifs impose aux organisations de traiter la gestion des vulnérabilités comme un processus continu et industrialisé plutôt que comme un événement ponctuel. Les secteurs à forte dépendance à Kubernetes et aux infrastructures virtualisées (cloud, finance, industrie, santé) sont les plus exposés à un défaut de couverture de patch.

---

### Recommandations

* Recenser précisément les versions de noyau sur l'ensemble du parc, images de conteneurs incluses.
* Prioriser le patch des hôtes exposés à Internet et des nœuds de conteneurs à privilèges élevés.
* Activer et tester les détections runtime (Falco/eBPF, auditd, EDR Linux) sur les scénarios d'élévation de privilèges.
* Restreindre les capabilities des conteneurs et imposer la signature des modules noyau.
* Intégrer la reconstruction régulière des images de base au pipeline CI/CD.
* Prévoir un plan de contournement pour les actifs non patchables (isolation réseau, segmentation).

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Tenir à jour un inventaire exhaustif des noyaux Linux et des versions de paquets sur serveurs, VM et nœuds de conteneurs (y compris images de base).
* Cartographier les systèmes Linux exposés à Internet et les charges de travail à privilèges élevés (hôtes de conteneurs, hyperviseurs, bastions).
* Valider la capacité de détection runtime (Falco/eBPF, EDR Linux, auditd) et la journalisation des appels système sur les actifs critiques.
* Définir une fenêtre de maintenance et un processus de test de non-régression pour les mises à jour de noyau.

#### Phase 2 — Détection et analyse

* Surveiller les alertes liées à ZDI-CAN-33367 et aux cinq autres failles Linux référencées par l'éditeur, en corrélant avec les versions de noyau présentes dans le parc.
* Rechercher des tentatives d'élévation de privilèges : exécution de binaires setuid inhabituels, chargement de modules noyau non signés, modifications de /etc/passwd ou de sudoers.
* Détecter les comportements d'évasion de conteneur : accès à /proc, /sys, montages de l'hôte, capabilities CAP_SYS_ADMIN non justifiées.
* Corréler les journaux auditd/eBPF avec les connexions réseau sortantes anormales depuis des hôtes Linux.

#### Phase 3 — Confinement, éradication et récupération

* Appliquer en priorité les correctifs éditeurs sur les systèmes exposés et les hôtes de conteneurs ; isoler réseau les actifs non patchables.
* En cas de compromission suspectée : isoler l'hôte, préserver la mémoire et les journaux, capturer l'image disque avant remédiation.
* Révoquer les clés SSH, jetons de service et secrets présents sur l'hôte compromis.
* Restreindre temporairement les capabilities des conteneurs et bloquer le chargement de modules noyau non signés (module signature enforcement).

#### Phase 4 — Activités post-incident

* Documenter les versions affectées, les délais de patch réels et les écarts entre inventaire théorique et parc effectif.
* Mettre à jour les règles de détection avec les artefacts observés et intégrer les leçons apprises au processus de gestion des vulnérabilités.
* Revoir la politique de patching du noyau et des images de conteneurs (rebuild régulier des images de base).
* Communiquer aux métiers concernés l'impact résiduel et les mesures compensatoires maintenues.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher rétrospectivement sur 30 à 90 jours des motifs d'exploitation de failles noyau : crashs répétés, oops kernel, dmesg anormaux.
* Chasser les élévations de privilèges récentes : nouveaux comptes root, ajout de clés autorisées, cron/systemd units suspects.
* Analyser les journaux de build et de déploiement pour identifier des images de conteneurs basées sur des noyaux non patchés.
* Traquer les accès aux interfaces d'administration Linux depuis des adresses inhabituelles ou des ASN d'hébergement bulletproof.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1068** | Exploitation d'une vulnérabilité pour élévation de privilèges sur un système Linux |
| **T1203** | Exploitation côté client / exécution de code via une faille logicielle |
| **T1611** | Évasion de conteneur potentielle si la faille est exploitée depuis un pod |

---

### Sources

* [https://webflow.sysdig.com/blog/detecting-and-mitigating-zdi-can-33367-and-five-other-linux-flaws](https://webflow.sysdig.com/blog/detecting-and-mitigating-zdi-can-33367-and-five-other-linux-flaws)


---

<div id="au-cur-de-keydrift-analyse-de-lactivite-historique-duat-11473-sur-cisco-sd-wan"></div>

## Au cœur de KeyDrift : analyse de l'activité historique d'UAT-11473 sur Cisco SD-WAN

### Résumé

Cisco Talos publie une analyse de l'activité historique du cluster UAT-11473, suivi sous le nom « KeyDrift », dirigée contre les environnements Cisco SD-WAN. L'article revient sur les traces laissées par cet acteur sur les équipements d'infrastructure réseau et sur les méthodes d'investigation rétrospective associées.

---

### Analyse opérationnelle

Le ciblage d'équipements SD-WAN place l'attaquant au cœur du réseau : un contrôleur compromis permet de modifier des politiques de routage, de rediriger ou d'intercepter du trafic, et de pivoter vers les segments internes sans déclencher les détections classiques orientées endpoints. Les équipes SOC doivent étendre leur périmètre de supervision aux équipements réseau (vManage, vSmart, vBond, edges), souvent absents des SIEM ou journalisés de façon incomplète. Les priorités techniques : suppression de l'exposition Internet des interfaces de management, MFA et bastion obligatoires, comparaison continue de configuration à une baseline, détection des créations de comptes locaux et des changements de politique. L'analyse rétrospective des journaux AAA et de configuration est indispensable pour évaluer une éventuelle compromission antérieure.

---

### Implications stratégiques

Les infrastructures réseau critiques (opérateurs, grands groupes multi-sites, secteur public) reposent de plus en plus sur des plans de management centralisés de type SD-WAN, qui deviennent des cibles à fort effet de levier : une compromission unique peut affecter des dizaines de sites. La publication d'activité non attribuée (UAT) par un éditeur majeur signale une menace persistante et structurée, justifiant une revue de l'architecture d'accès au management et une exigence renforcée envers les fournisseurs d'équipements. Sur le plan géopolitique, le ciblage d'équipements d'edge réseau s'inscrit dans les tendances d'attaques pré-positionnées contre les infrastructures de télécommunications.

---

### Recommandations

* Recenser et durcir immédiatement les accès de management des équipements Cisco SD-WAN (bastion, MFA, restriction IP).
* Intégrer les journaux réseau (AAA, syslog, configuration) au SIEM avec des règles de détection dédiées.
* Mettre en place une comparaison automatisée de configuration à une baseline approuvée.
* Appliquer les correctifs éditeurs et vérifier l'intégrité des images logicielles.
* Conduire une chasse rétrospective sur les accès administratifs et les changements de configuration des 6 à 12 derniers mois.
* Tester la restauration de configuration depuis sauvegarde vérifiée en cas de compromission.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les équipements Cisco SD-WAN (vManage, vSmart, vBond, routeurs d'edge) et leurs versions logicielles.
* Interdire l'exposition directe des interfaces de management sur Internet ; imposer un accès via bastion et MFA.
* Centraliser et conserver les journaux des équipements réseau (syslog, AAA, configuration) avec rétention suffisante.
* Établir une baseline de configuration et de flux légitimes pour les contrôleurs SD-WAN.

#### Phase 2 — Détection et analyse

* Surveiller les tentatives d'authentification échouées et les connexions administratives inhabituelles sur les interfaces SD-WAN.
* Détecter les modifications de configuration non planifiées, créations de comptes locaux et changements de politique de routage ou de tunnel.
* Rechercher des connexions sortantes anormales depuis les équipements d'edge vers des adresses non référencées.
* Corréler les alertes Talos/éditeur liées à UAT-11473 avec la télémétrie réseau interne.

#### Phase 3 — Confinement, éradication et récupération

* Isoler du management Internet les équipements suspects tout en préservant la continuité de service du plan de données.
* Réinitialiser les identifiants d'administration, révoquer les certificats et clés potentiellement compromis.
* Comparer la configuration courante à la baseline et restaurer une configuration saine depuis une sauvegarde vérifiée.
* Appliquer les correctifs et durcissements recommandés par l'éditeur avant remise en production.

#### Phase 4 — Activités post-incident

* Documenter la chronologie de l'intrusion, les comptes et configurations modifiés, et l'étendue de la latéralisation.
* Renforcer la supervision des équipements réseau et intégrer les artefacts de l'acteur aux règles de détection.
* Revoir l'architecture d'accès au management (zero trust, bastion, MFA, segmentation).
* Mettre à jour le plan de réponse pour les infrastructures réseau critiques et tester la restauration de configuration.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher historiquement des artefacts compatibles avec UAT-11473 sur les contrôleurs et edges SD-WAN (comptes orphelins, tâches planifiées, tunnels inconnus).
* Analyser les journaux AAA sur plusieurs mois pour identifier des accès administratifs hors horaires ou hors périmètre habituel.
* Vérifier l'intégrité des configurations et des images logicielles des équipements réseau.
* Traquer les mouvements latéraux entre le plan de management SD-WAN et les segments réseau internes.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploitation d'applications exposées sur Internet (équipements d'edge SD-WAN) |
| **T1133** | Accès externe via services distants (interfaces d'administration d'équipements réseau) |
| **T1078** | Utilisation de comptes valides pour maintenir l'accès aux équipements |

---

### Sources

* [https://blog.talosintelligence.com/uat-11473-keydrift/](https://blog.talosintelligence.com/uat-11473-keydrift/)


---

<div id="la-police-saisit-le-service-bulletproof-virtualine-lie-a-des-ransomwares-et-a-la-cybercriminalite"></div>

## La police saisit le service bulletproof Virtualine lié à des ransomwares et à la cybercriminalité

### Résumé

Les forces de l'ordre ont saisi le service d'hébergement « bulletproof » Virtualine, présenté comme lié à des activités de ransomware et de cybercriminalité. L'opération vise une infrastructure utilisée pour héberger des serveurs et services au profit d'acteurs malveillants.

---

### Analyse opérationnelle

Le démantèlement d'un hébergeur bulletproof perturbe temporairement les chaînes d'infrastructure de plusieurs groupes criminels : serveurs C2, panels de phishing, nœuds de proxification et parfois serveurs de fuite peuvent devenir indisponibles ou changer d'adresse. Pour les équipes SOC, cela se traduit par des fenêtres d'opportunité (détection de reconfiguration d'attaquants) mais aussi par des migrations rapides vers d'autres fournisseurs, avec de nouvelles plages IP et de nouveaux domaines à intégrer aux listes de blocage. Les mesures concrètes : bloquer les artefacts connus de l'infrastructure saisie, surveiller les connexions sortantes vers des ASN d'hébergement à faible réputation, et vérifier qu'aucun actif interne ne dépend d'un service hébergé chez ce fournisseur.

---

### Implications stratégiques

La lutte contre les hébergeurs complaisants est devenue un levier majeur des politiques publiques de cybersécurité : elle réduit le coût d'entrée des attaquants et allonge leur cycle opérationnel. Ces saisies illustrent une coopération internationale croissante entre forces de l'ordre et secteur privé, mais leur effet reste souvent temporaire, les acteurs se relocalisant vers d'autres juridictions permissives. Pour les organisations, cela renforce la nécessité d'une due diligence fournisseur et d'une surveillance continue de la réputation des infrastructures tierces, en particulier pour les secteurs dépendants de services d'hébergement externalisés.

---

### Recommandations

* Intégrer les indicateurs liés à Virtualine dans les listes de blocage proxy, DNS et pare-feu.
* Auditer les dépendances internes à des services d'hébergement tiers et évaluer le risque de continuité.
* Renforcer la due diligence sur la réputation des ASN et hébergeurs avant contractualisation.
* Surveiller les migrations d'infrastructure des groupes ransomware après le démantèlement.
* Partager les indicateurs observés avec les CERT et les communautés sectorielles.
* Vérifier l'absence de persistance ou de balise C2 hébergée sur l'infrastructure saisie.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les dépendances de l'organisation aux services d'hébergement et de VPS, y compris les fournisseurs de faible notoriété.
* Établir une politique de due diligence fournisseur incluant la réputation de l'ASN et de l'hébergeur.
* Maintenir des listes de blocage et des sources de renseignement sur les hébergeurs bulletproof.
* Définir un canal de contact avec les CERT et les forces de l'ordre pour les notifications de saisie ou de démantèlement.

#### Phase 2 — Détection et analyse

* Surveiller les connexions sortantes vers des plages d'hébergement à faible réputation ou récemment saisies.
* Détecter les balises de ransomwares et les communications C2 hébergées sur des fournisseurs bulletproof connus.
* Analyser les journaux proxy/DNS pour identifier des résolutions vers des domaines hébergés sur l'infrastructure saisie.
* Corréler les alertes de renseignement sur les démantèlements avec le trafic interne.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer au niveau pare-feu/proxy les domaines et plages IP associés à l'infrastructure saisie.
* Isoler les machines communiquant avec ces infrastructures et lancer une analyse forensique.
* Révoquer les identifiants et secrets susceptibles d'avoir transité par ces services.
* Notifier les équipes métiers utilisant des services d'hébergement impactés par la saisie.

#### Phase 4 — Activités post-incident

* Évaluer l'exposition résiduelle liée aux services hébergés chez le fournisseur saisi (données, sauvegardes, accès).
* Mettre à jour les listes de blocage et les règles de réputation d'ASN.
* Renforcer la politique d'achat et de sélection des fournisseurs d'hébergement.
* Documenter les leçons apprises et partager les indicateurs avec les pairs sectoriels.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher historiquement les communications vers les ASN et plages d'hébergement associés au fournisseur saisi.
* Traquer les artefacts de ransomwares ou de loaders connus pour avoir utilisé cette infrastructure.
* Analyser les journaux de facturation et d'approvisionnement pour identifier des services souscrits chez des hébergeurs à risque.
* Vérifier l'absence de persistance installée via des serveurs loués chez ce fournisseur.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1583.003** | Acquisition d'infrastructure (serveurs/hébergement) pour héberger des opérations malveillantes |
| **T1584.005** | Compromission ou usage d'infrastructure tierce pour masquer l'origine des attaques |

---

### Sources

* [https://www.bleepingcomputer.com/news/security/police-seize-virtualine-bulletproof-service-tied-to-ransowmare-cybercrime/](https://www.bleepingcomputer.com/news/security/police-seize-virtualine-bulletproof-service-tied-to-ransowmare-cybercrime/)


---

<div id="tailscale-declare-ne-pas-avoir-applique-les-limites-de-privileges-dans-tailscale-ssh-des-pairs-autorises-disposant-dun-acces-de-transfert-pouvaient-atteindre-des-sockets-reserves-a-root-lentreprise-indique-que-lexploitation-necessite-un-point-dappui-autorise-et-un-acces-permis-par-la-politique-mettez-a-jour-vers-la-v11044-ou-une-version-ulterieure-et-examinez-les-politiques-sshhttpstailscalecomssh-investigation-updatetailscale-ssh-infosec-cybersecurity"></div>

## Tailscale déclare ne pas avoir appliqué les limites de privilèges dans Tailscale SSH : des pairs autorisés disposant d'un accès de transfert pouvaient atteindre des sockets réservés à root. L'entreprise indique que l'exploitation nécessite un point d'appui autorisé et un accès permis par la politique. Mettez à jour vers la v1.104.4 ou une version ultérieure et examinez les politiques SSH.https://tailscale.com/ssh-investigation-update#Tailscale #SSH #InfoSec #Cybersecurity

### Résumé

Tailscale indique que des vulnérabilités affectant Tailscale SSH permettent, dans certaines circonstances, à un pair déjà autorisé à se connecter d'agir au-delà des permissions de son utilisateur local, avec un risque d'élévation de privilèges, notamment l'atteinte de sockets réservés au root via le forwarding. L'exploitation dépend des permissions accordées à l'utilisateur ou à l'appareil, de la configuration du système et d'autres conditions. L'entreprise a publié quatre bulletins (TS-2026-014 à TS-2026-017) et un billet de blog détaillant l'investigation et les correctifs. Elle recommande la mise à jour vers la v1.104.4 ou ultérieure, la revue des politiques d'accès SSH et la désactivation du forwarding SSH lorsqu'il n'est pas nécessaire, tout en précisant qu'elle ne recommande pas de désactiver Tailscale SSH pour l'ensemble des clients.

---

### Analyse opérationnelle

La faille se situe dans la couche d'autorisation de Tailscale SSH : un attaquant doit déjà disposer d'un accès autorisé au tailnet et d'une politique permettant la connexion, ce qui abaisse la probabilité d'exploitation externe mais augmente fortement l'impact en cas de compromission d'un poste ou d'un compte. Pour le SOC, la priorité est l'inventaire des versions client, la revue des ACL SSH et la détection des élévations de privilèges locales corrélées à des sessions SSH distantes. Les journaux Tailscale SSH, sudo/su et les accès aux sockets privilégiés constituent les sources de détection clés. La désactivation du forwarding SSH réduit la surface d'attaque immédiatement, avant même le patch.

---

### Implications stratégiques

Tailscale SSH est massivement utilisé dans les architectures Zero Trust et les accès d'infrastructure ; une défaillance de cloisonnement des privilèges dans ce composant fragilise la promesse même du modèle Zero Trust (moindre privilège appliqué au niveau réseau). L'épisode illustre la dépendance des organisations à des fournisseurs d'accès critiques et la nécessité d'exiger des engagements de divulgation et de délais de correctif contractuellement opposables. La publication de quatre bulletins successifs suggère une découverte progressive de la surface affectée, ce qui doit inciter à une revue complète des configurations plutôt qu'à un patch ponctuel.

---

### Recommandations

* Mettre à jour tous les clients Tailscale vers la v1.104.4 ou ultérieure et vérifier la version par inventaire automatisé.
* Désactiver le forwarding SSH sur les nœuds qui n'en ont pas besoin et restreindre les politiques SSH au strict nécessaire.
* Lire les bulletins TS-2026-014 à TS-2026-017 et cartographier les configurations affectées dans votre parc.
* Instrumenter la détection des élévations de privilèges locales corrélées aux sessions Tailscale SSH.
* Révoquer et réémettre les clés des nœuds ayant présenté des comportements anormaux.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier tous les nœuds et versions du client Tailscale ; isoler ceux antérieurs à la v1.104.4.
* Recenser les politiques SSH Tailscale (tags, ACL, règles d'accès) et les comptes locaux associés.
* Déterminer si le forwarding SSH est réellement nécessaire ; le désactiver par défaut sinon.
* Planifier une fenêtre de mise à jour avec procédure de rollback et validation fonctionnelle.
* Vérifier la centralisation des journaux de sessions Tailscale SSH vers le SIEM.

#### Phase 2 — Détection et analyse

* Rechercher dans les logs Tailscale SSH les sessions utilisant le forwarding ou des destinations inhabituelles.
* Corréler les connexions Tailscale avec les événements sudo/su et les accès aux sockets réservés au root.
* Alerter sur toute élévation de privilèges locale consécutive à une session SSH distante.
* Suivre l'obsolescence des clients via l'inventaire endpoint et les rapports de conformité.

#### Phase 3 — Confinement, éradication et récupération

* Mettre à jour les clients vers la v1.104.4 ou ultérieure, en priorité sur les nœuds exposés.
* Restreindre temporairement les politiques SSH aux seuls utilisateurs et appareils indispensables.
* Désactiver le forwarding SSH sur les nœuds non indispensables.
* Révoquer les clés et nœuds suspects et forcer une réauthentification.
* Isoler les nœuds présentant des traces d'élévation de privilèges non autorisée.

#### Phase 4 — Activités post-incident

* Consulter les bulletins TS-2026-014 à TS-2026-017 et vérifier la couverture des configurations concernées.
* Réaliser un post-mortem sur la fenêtre d'exposition et les accès réellement effectués.
* Faire tourner les secrets et identifiants présents sur les nœuds touchés.
* Mettre à jour les procédures de gestion des accès Zero Trust et le calendrier de patch.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des commandes exécutées avec des privilèges supérieurs au compte local attendu.
* Chercher des accès à des sockets privilégiés (ex. /var/run/docker[.]sock, sockets systemd) depuis des sessions SSH.
* Analyser les connexions pair-à-pair Tailscale inhabituelles (nouveaux couples source/destination).
* Traquer la persistance : ajout de clés autorisées, modification de la configuration SSH locale.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1548** | Abus du mécanisme de contrôle d'élévation de privilèges via les permissions accordées par Tailscale SSH |
| **T1021.004** | Utilisation de SSH comme vecteur d'accès et de mouvement entre pairs autorisés du tailnet |
| **T1078** | Exploitation d'identités/pairs légitimes déjà autorisés pour dépasser les permissions de l'utilisateur local |

---

### Sources

* [https://tailscale.com/ssh-investigation-update](https://tailscale.com/ssh-investigation-update)


---

<div id="un-ressortissant-ukrainien-condamne-pour-son-role-dans-le-piratage-dhopitaux-dentreprises-et-de-gouvernements-dans-le-cadre-de-complots-de-ransomware-ayant-cause-plus-de-100-millions-de-dollars-de-pertes"></div>

## Un ressortissant ukrainien condamné pour son rôle dans le piratage d'hôpitaux, d'entreprises et de gouvernements dans le cadre de complots de ransomware ayant causé plus de 100 millions de dollars de pertes

### Résumé

Un ressortissant ukrainien a été condamné pour son rôle dans des conspirations de ransomware ayant visé des hôpitaux, des entreprises et des administrations, pour des pertes cumulées estimées à plus de 100 millions de dollars. Le corps de l'article n'était pas accessible lors de la collecte (blocage par un service de protection Cloudflare) : seuls le titre et l'objet de l'article sont exploitables, sans détail sur l'identité du condamné, la juridiction, la peine prononcée ni les groupes ransomware concernés.

---

### Analyse opérationnelle

Cet article confirme la persistance d'un modèle ransomware à forte rentabilité ciblant des secteurs à criticité vitale (santé, administrations) où la pression opérationnelle pousse à la négociation. Pour les équipes SOC, l'enseignement opérationnel reste la nécessité de détecter la phase d'exfiltration et de reconnaissance précédant le chiffrement, et de garantir des sauvegardes hors ligne réellement restaurables. Les condamnations fournissent par ailleurs des éléments de renseignement utiles (modus operandi, affiliations) à intégrer dans les profils d'acteurs suivis.

---

### Implications stratégiques

La sanction judiciaire d'un opérateur illustre la montée en puissance de la réponse pénale internationale contre l'écosystème ransomware, mais son effet dissuasif reste limité face à la fragmentation des affiliés et à la recomposition rapide des groupes. Les pertes déclarées (plus de 100 millions de dollars) rappellent que le ransomware est devenu un risque financier et de continuité d'activité de premier ordre, justifiant des arbitrages budgétaires en faveur de la résilience et de la cyberassurance.

---

### Recommandations

* Intégrer les enseignements des poursuites judiciaires dans la veille sur les groupes ransomware et leurs affiliés.
* Vérifier la résilience des sauvegardes (hors ligne, immuables, tests de restauration documentés).
* Renforcer la détection de l'exfiltration préalable au chiffrement, phase clé des extorsions doubles.
* Cartographier les dépendances critiques des systèmes de santé et d'administration pour prioriser la segmentation.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Maintenir des sauvegardes hors ligne immuables et tester régulièrement les restaurations.
* Segmenter les réseaux et cloisonner les systèmes critiques (imagerie, dossiers patients, annuaires).
* Disposer d'un plan de réponse ransomware documenté avec rôles, astreinte et canaux de communication hors bande.
* Vérifier la couverture EDR sur les serveurs et l'authentification multifacteur sur les accès distants et les comptes à privilèges.

#### Phase 2 — Détection et analyse

* Surveiller les exécutions massives de chiffrement, les extensions anormales et les notes de rançon.
* Détecter la suppression des clichés instantanés et des sauvegardes (vssadmin, wbadmin, bcdedit).
* Alerter sur les connexions RDP/VPN inhabituelles et les créations de comptes à privilèges.
* Corréler les alertes EDR avec les journaux d'annuaire et les accès aux partages de fichiers.

#### Phase 3 — Confinement, éradication et récupération

* Isoler immédiatement les hôtes chiffrés et couper les sessions distantes actives.
* Désactiver les comptes compromis et réinitialiser les secrets d'infrastructure (KRBTGT, comptes de service).
* Bloquer les indicateurs réseau identifiés au niveau pare-feu, proxy et DNS.
* Préserver les preuves (images mémoire, journaux) avant toute remédiation destructive.

#### Phase 4 — Activités post-incident

* Restaurer depuis des sauvegardes vérifiées et valider l'intégrité des données médicales et administratives.
* Mener une analyse post-incident sur le vecteur d'accès initial et le temps de présence.
* Renforcer la segmentation, la journalisation et la supervision des comptes à privilèges.
* Coordonner la notification des autorités et des personnes concernées selon les obligations légales.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les outils de chiffrement et de vol de données (exfiltration préalable, Rclone, archives).
* Traquer les mécanismes de persistance : tâches planifiées, services, comptes créés, clés SSH ajoutées.
* Analyser les accès aux partages administratifs et les mouvements latéraux SMB/WMI/WinRM.
* Examiner les journaux de messagerie pour identifier les campagnes de hameçonnage initiales.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Chiffrement des données pour impact au sein de conspirations ransomware |
| **T1078** | Usage d'identifiants valides pour l'accès initial et le mouvement latéral |
| **T1566** | Hameçonnage comme vecteur d'accès initial fréquent dans les intrusions ransomware |
| **T1490** | Inhibition des mécanismes de récupération (sauvegardes, restauration) avant chiffrement |

---

### Sources

* [https://databreaches.net/2026/10/28/ukrainian-national-sentenced-for-role-in-hacking-hospitals-businesses-and-governments-as-part-of-ransomware-conspiracies-causing-over-100-million-in-losses/](https://databreaches.net/2026/10/28/ukrainian-national-sentenced-for-role-in-hacking-hospitals-businesses-and-governments-as-part-of-ransomware-conspiracies-causing-over-100-million-in-losses/)


---

<div id="whitsett-en-caroline-du-nord-diffuse-une-alerte-concernant-un-courriel-dhameconnage"></div>

## Whitsett, en Caroline du Nord, diffuse une alerte concernant un courriel d'hameçonnage

### Résumé

La municipalité de Whitsett, en Caroline du Nord, a diffusé une alerte à destination de ses administrés concernant un courriel de hameçonnage. Le corps de l'article n'était pas accessible lors de la collecte (blocage par un service de protection Cloudflare) : le contenu du courriel, les indicateurs techniques et le nombre de destinataires ne sont pas disponibles.

---

### Analyse opérationnelle

Une alerte phishing émise par une collectivité locale signale généralement une campagne usurpant l'identité de la mairie ou d'un service public pour dérober des identifiants ou des données personnelles. Pour le SOC d'une collectivité, la priorité est la collecte des courriels signalés, l'extraction des URL et expéditeurs, le blocage au niveau passerelle et la réinitialisation des comptes ayant saisi des informations. La surveillance de l'usurpation de domaine (SPF/DKIM/DMARC, certificats, typosquatting) est le complément indispensable.

---

### Implications stratégiques

Les collectivités locales restent une cible de choix pour l'hameçonnage en raison de leur surface de contact étendue avec les administrés et de moyens de cybersécurité souvent limités. Ce type d'alerte a une valeur préventive mais révèle aussi la dépendance à la vigilance des usagers, ce qui plaide pour des investissements dans le filtrage, l'authentification des domaines et la sensibilisation continue.

---

### Recommandations

* Durcir SPF, DKIM et DMARC en politique de rejet sur les domaines officiels de la collectivité.
* Déployer un bouton de signalement de phishing et analyser les signalements de manière centralisée.
* Bloquer les indicateurs collectés et surveiller les domaines ressemblants.
* Communiquer de manière proactive sur les canaux officiels pour limiter la confiance accordée aux courriels frauduleux.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Mettre en place une passerelle de messagerie avec filtrage anti-hameçonnage, authentification SPF/DKIM/DMARC et analyse des URL.
* Former les agents et les administrés à la reconnaissance des courriels frauduleux et au signalement en un clic.
* Définir une procédure de communication publique en cas d'alerte phishing.
* Tenir à jour l'inventaire des domaines officiels de la collectivité pour détecter l'usurpation.

#### Phase 2 — Détection et analyse

* Collecter les courriels signalés et extraire les en-têtes, URL et pièces jointes.
* Rechercher les campagnes massives visant les adresses publiques de la collectivité et des administrés.
* Surveiller les enregistrements DNS et les certificats pour détecter l'usurpation de domaine.
* Analyser les connexions aux portails authentifiés pour repérer des soumissions d'identifiants anormales.

#### Phase 3 — Confinement, éradication et récupération

* Bloquer les domaines, URL et expéditeurs identifiés au niveau messagerie, proxy et DNS.
* Réinitialiser les identifiants des personnes ayant cliqué ou saisi leurs informations.
* Publier une alerte claire sur les canaux officiels de la collectivité.
* Signaler les infrastructures frauduleuses aux hébergeurs et aux registrars concernés.

#### Phase 4 — Activités post-incident

* Évaluer le nombre de victimes et l'étendue des données potentiellement exposées.
* Mettre à jour les filtres et les règles de détection à partir des indicateurs collectés.
* Renforcer la sensibilisation ciblée sur le scénario observé.
* Documenter l'incident et ajuster la procédure de communication publique.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des règles de messagerie créées frauduleusement et des transferts automatiques.
* Analyser les journaux d'authentification pour détecter des connexions depuis des localisations inhabituelles.
* Rechercher des domaines ressemblants (typosquatting) ciblant la collectivité.
* Examiner les signalements utilisateurs sur une fenêtre élargie pour identifier des vagues antérieures.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.001** | Hameçonnage par courriel ciblant des administrés ou des agents d'une collectivité locale |
| **T1598** | Ingénierie sociale pour l'obtention d'informations ou d'identifiants |

---

### Sources

* [https://databreaches.net/2026/10/28/whitsett-nc-sends-out-alert-about-phishing-email/](https://databreaches.net/2026/10/28/whitsett-nc-sends-out-alert-about-phishing-email/)


---

<div id="nz-lattente-incroyablement-stressante-des-familles-endeuillees-pour-obtenir-des-reponses-apres-une-cyberattaque-majeure-en-nz"></div>

## NZ : l'attente « incroyablement stressante » des familles endeuillées pour obtenir des réponses après une cyberattaque majeure en NZ

### Résumé

L'article rapporte qu'en Nouvelle-Zélande, des familles endeuillées font face à une attente qualifiée d'« extrêmement stressante » pour obtenir des réponses après une cyberattaque majeure. Le corps de l'article n'était pas accessible lors de la collecte (blocage par un service de protection Cloudflare) : l'organisation victime, la nature exacte de l'attaque et le volume de données concernées ne sont pas précisés dans les éléments disponibles.

---

### Analyse opérationnelle

Le scénario décrit suggère une atteinte à un service traitant des données de défunts et de familles, avec un impact direct sur la continuité de service et sur des personnes en situation de vulnérabilité. Pour un SOC, ce type d'incident impose de prioriser la restauration des services critiques, la communication vers les usagers et l'évaluation précise des données personnelles exposées. La coordination avec les prestataires et les autorités de protection des données est déterminante dans les premières 72 heures.

---

### Implications stratégiques

Les attaques contre des services funéraires et de santé illustrent l'extension du ciblage aux secteurs porteurs de données personnelles hautement sensibles, où l'impact réputationnel et humain dépasse largement la rançon potentielle. La Nouvelle-Zélande, comme de nombreux pays, voit ses services essentiels exposés à des acteurs criminels ou étatiques, ce qui renforce la pression réglementaire sur la notification des incidents et la résilience des opérateurs critiques.

---

### Recommandations

* Cartographier les données personnelles sensibles et les durées de conservation pour réduire l'exposition.
* Tester les plans de continuité incluant des canaux de communication alternatifs vers les familles.
* Préparer à l'avance les obligations de notification et les messages de crise adaptés au public concerné.
* Renforcer la supervision des accès prestataires et la segmentation des systèmes métier.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Identifier les données personnelles sensibles traitées (dossiers de défunts, coordonnées de familles) et leur base légale de traitement.
* Mettre en place des sauvegardes chiffrées et testées, isolées du réseau de production.
* Définir un plan de continuité pour maintenir le service aux familles en cas d'indisponibilité des systèmes.
* Préparer des modèles de communication de crise adaptés à un public en situation de vulnérabilité.

#### Phase 2 — Détection et analyse

* Surveiller les accès anormaux aux bases de données de dossiers et les volumes d'extraction inhabituels.
* Détecter les tentatives d'authentification échouées répétées et les connexions distantes non planifiées.
* Alerter sur toute indisponibilité soudaine des services métier ou modification de fichiers.
* Corréler les alertes avec les journaux d'accès fournisseurs et prestataires.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les systèmes compromis et couper les accès distants non indispensables.
* Activer le plan de continuité pour maintenir l'information des familles par des canaux alternatifs.
* Révoquer les comptes compromis et réinitialiser les secrets d'infrastructure.
* Faire appel à des prestataires de réponse à incident et préserver les preuves.

#### Phase 4 — Activités post-incident

* Évaluer précisément les données personnelles exposées et notifier conformément aux obligations légales.
* Mettre en place un accompagnement des personnes affectées (information, soutien).
* Tirer les enseignements sur les délais de restauration et la communication de crise.
* Renforcer les contrôles d'accès et la supervision des prestataires.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des exfiltrations massives via des outils de transfert ou des archives compressées.
* Traquer la persistance sur les serveurs métier et les comptes de service.
* Analyser les journaux VPN et RDP pour identifier des accès initiaux non légitimes.
* Rechercher la présence d'indicateurs du groupe sur les forums de fuite et les sites de rançon.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Chiffrement ou sabotage de données pour perturber un service essentiel |
| **T1657** | Extorsion financière exploitant la sensibilité des données personnelles |

---

### Sources

* [https://databreaches.net/2026/10/28/nz-grieving-families-incredibly-stressful-wait-for-answers-after-major-nz-cyber-attack/](https://databreaches.net/2026/10/28/nz-grieving-families-incredibly-stressful-wait-for-answers-after-major-nz-cyber-attack/)


---

<div id="gemini-4-carbon-ce-que-le-dernier-modele-dia-de-google-signifie-pour-la-cybersecurite-des-entreprises"></div>

## Gemini 4 Carbon : ce que le dernier modèle d'IA de Google signifie pour la cybersécurité des entreprises

### Résumé

Google a publié le 28 octobre 2026 le modèle Gemini 4 Carbon, présenté comme nettement amélioré pour le codage autonome, la découverte de vulnérabilités et les opérations de cybersécurité. Le modèle prend la tête de l'Artificial Analysis Intelligence Index v5.0 avec un score de 59 et serait capable de traiter des problèmes d'ingénierie complexes sur plusieurs jours. Les résultats annoncés incluent 88,2 % sur SEC-bench Pro (découverte de vulnérabilités), 54,8 % sur ExploitGym (génération d'exploits), 71,0 % sur CWE-bench (correctifs de vulnérabilités) et un taux de réussite d'attaque de 0,0 % sur le benchmark d'injection de prompt indirecte de Gray Swan. L'article souligne toutefois que ces avancées ne démontrent pas que des agents autonomes sont prêts à opérer sans supervision en entreprise, et que plus ces systèmes gagnent en capacité, plus les questions de permissions, d'environnement d'exécution et de contrôles opérationnels deviennent critiques.

---

### Analyse opérationnelle

L'arrivée de modèles capables de découvrir des vulnérabilités et de générer des exploits à grande échelle modifie l'économie de la recherche de failles : elle accélère autant les programmes de bug bounty et de revue de code défensive que les capacités offensives d'acteurs disposant d'un accès API. Pour les équipes SOC et AppSec, l'enjeu immédiat est la gouvernance des agents : périmètre d'exécution, sandbox, journalisation des actions, moindre privilège sur le code et l'infrastructure, et revue humaine obligatoire avant toute action en production. Le score de 0,0 % sur l'injection de prompt indirecte est un résultat de benchmark, non une garantie en conditions réelles : les agents connectés à des sources externes restent exposés.

---

### Implications stratégiques

La course aux capacités offensives assistées par IA crée une asymétrie temporaire au bénéfice des organisations capables d'adopter rapidement ces outils, mais aussi un risque d'accélération de la découverte et de l'exploitation de vulnérabilités à l'échelle mondiale. Les éditeurs devront repenser leurs cycles de divulgation et de correctifs face à des délais de découverte réduits. Pour les directions, l'enjeu devient la maîtrise des permissions et de la traçabilité des agents IA, au même titre que n'importe quel compte à privilèges.

---

### Recommandations

* Encadrer l'usage d'agents IA autonomes par une politique de permissions, de sandbox et de revue humaine.
* Journaliser et superviser toutes les actions des agents IA disposant d'un accès au code ou à l'infrastructure.
* Tester la robustesse aux injections de prompt indirectes sur les agents connectés à des contenus externes.
* Anticiper la réduction des délais de découverte de vulnérabilités en renforçant les cycles de patch et la détection.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser les usages de modèles d'IA génératifs dans les chaînes DevSecOps et SOC, et les permissions accordées aux agents.
* Définir une politique d'usage des agents autonomes : périmètre d'exécution, sandbox, revue humaine obligatoire.
* Établir une gouvernance des données envoyées aux modèles (classification, secrets, code propriétaire).
* Prévoir des tests de robustesse aux injections de prompt indirectes sur les agents connectés à des sources externes.

#### Phase 2 — Détection et analyse

* Journaliser toutes les actions des agents IA (requêtes, outils appelés, fichiers lus, commandes exécutées).
* Détecter les comportements d'agent anormaux : accès hors périmètre, exécution de commandes, exfiltration de contexte.
* Surveiller les contenus externes ingérés (pages web, tickets, courriels) susceptibles de porter une injection de prompt.
* Alerter sur les tentatives d'utilisation d'agents IA pour la découverte ou l'exploitation de vulnérabilités non autorisées.

#### Phase 3 — Confinement, éradication et récupération

* Suspendre les agents autonomes présentant un comportement déviant et révoquer leurs jetons d'accès.
* Restreindre les permissions des agents au strict nécessaire (principe du moindre privilège, comptes dédiés).
* Isoler l'exécution dans des environnements sandboxés sans accès au réseau de production.
* Bloquer les sources de contenu identifiées comme vecteurs d'injection.

#### Phase 4 — Activités post-incident

* Analyser la chaîne d'outils et de permissions ayant permis le comportement non désiré.
* Mettre à jour les garde-fous, les prompts système et les politiques d'approbation humaine.
* Documenter les cas d'usage validés et les limites observées du modèle.
* Réévaluer périodiquement les benchmarks de sécurité des modèles utilisés.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des appels d'API de modèles depuis des comptes ou des environnements non autorisés.
* Traquer les agents disposant de permissions excessives sur le code source, les secrets ou l'infrastructure.
* Analyser les journaux d'exécution pour des séquences de type découverte de vulnérabilité suivie de tentative d'exploitation.
* Examiner les contenus ingérés pour des instructions cachées ciblant les agents.

---

### Sources

* [https://kiledjian.com/2026/10/28/gemini-carbon-what-googles-latest.html](https://kiledjian.com/2026/10/28/gemini-carbon-what-googles-latest.html)


---

<div id="des-organisations-americaines-attaquees-la-campagne-de-phishing-par-code-dappareil-skyw4lker-exposee"></div>

## Des organisations américaines attaquées : la campagne de phishing par code d'appareil Skyw4lker exposée

### Résumé

L'analyse d'ANY.RUN décrit la campagne Skyw4lker, une opération de phishing par code d'appareil (device code phishing) visant principalement des organisations américaines des secteurs de la fabrication, de la technologie et de la santé. Le leurre est un document protégé par mot de passe présenté comme un contrat ou une proposition de service ; la victime est ensuite redirigée vers une page hébergée sur sites[.]google[.]com qui mène au flux d'authentification Microsoft. L'attaquant n'a pas besoin d'imiter la page de connexion : il initie une demande d'autorisation légitime et convainc la victime de la valider, ce qui lui permet d'obtenir des jetons Microsoft 365. L'infrastructure repose sur du JavaScript obfusqué et un backend PHP qui crée une session victime, collecte l'adresse IP et la géolocalisation et interroge le backend en boucle. L'article cite par ailleurs les chiffres du FBI IC3 : 193 407 plaintes pour phishing et usurpation en 2024, plus d'un million de plaintes et 20,9 milliards de dollars de pertes déclarées en 2025 (+26 %).

---

### Analyse opérationnelle

Le device code phishing contourne les investissements en MFA en exploitant un mécanisme d'authentification légitime : la télémétrie d'identité seule montre une authentification valide, sans contexte malveillant. Les équipes SOC doivent donc corréler les journaux Entra ID (protocole deviceCode, émission de jetons), les journaux proxy (accès à sites[.]google[.]com, redirections) et la messagerie (pièces jointes protégées par mot de passe). Les détections prioritaires portent sur les authentifications device code depuis des ASN ou pays inhabituels, les accès cloud consécutifs à l'ouverture d'un document, et les règles de transfert ou inscriptions d'applications OAuth créées après coup. La réponse doit inclure la révocation des jetons et sessions, pas seulement la réinitialisation du mot de passe, car le jeton d'actualisation permet de maintenir l'accès.

---

### Implications stratégiques

Cette campagne illustre le déplacement du périmètre vers l'identité : les organisations ayant massivement déployé le MFA restent exposées si les flux d'authentification déléguée ne sont pas restreints. Les secteurs industriels, technologiques et de santé — cibles observées — présentent un fort impact opérationnel en cas de compromission de comptes (propriété intellectuelle, données patients, chaînes de production). La tendance impose une révision des politiques d'accès conditionnel et une gouvernance des applications OAuth au niveau direction des risques, au-delà du seul SOC.

---

### Recommandations

* Bloquer ou restreindre le device code flow via l'accès conditionnel pour tous les comptes non indispensables.
* Déployer une détection dédiée sur les événements d'authentification deviceCode dans Entra ID.
* Imposer une vérification hors bande avant toute validation d'un code d'appareil demandé par un tiers.
* Filtrer les pièces jointes protégées par mot de passe et les liens vers des pages hébergées sur des services cloud grand public.
* Révoquer les sessions et jetons, et non seulement réinitialiser les mots de passe, lors d'une suspicion de vol de jeton.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les flux d'authentification par code d'appareil (device code) autorisés dans le tenant et identifier les applications qui les utilisent.
* Configurer des politiques d'accès conditionnel restreignant ou bloquant le device code flow pour les comptes non administratifs.
* Sensibiliser les utilisateurs : aucun service légitime ne demande de saisir un code sur microsoft.com/devicelogin à la demande d'un tiers.
* Mettre en place une rétention suffisante des journaux de connexion Azure AD / Entra ID et des journaux proxy pour l'investigation.

#### Phase 2 — Détection et analyse

* Surveiller les événements d'authentification avec protocole 'deviceCode' dans les journaux Entra ID, en particulier depuis des ASN ou géolocalisations inhabituels.
* Détecter les courriels contenant des liens vers sites[.]google[.]com associés à des pièces jointes protégées par mot de passe (contrats, propositions).
* Alerter sur l'émission de jetons d'actualisation (refresh tokens) suivie d'accès à Exchange Online, SharePoint ou OneDrive depuis une nouvelle IP.
* Corréler l'ouverture d'un document protégé par mot de passe avec une connexion cloud dans une fenêtre de quelques minutes.

#### Phase 3 — Confinement, éradication et récupération

* Révoquer immédiatement les jetons et sessions de l'utilisateur concerné (revoke sessions) et réinitialiser les identifiants.
* Bloquer au niveau proxy/DNS les URL de redirection identifiées et les domaines d'infrastructure associés à la campagne.
* Isoler le poste ayant ouvert le document et collecter les artefacts (navigateur, historique, fichiers téléchargés).
* Activer une revue renforcée des règles de transfert de courriel et des boîtes aux lettres créées récemment sur le compte compromis.

#### Phase 4 — Activités post-incident

* Analyser la portée : quelles boîtes aux lettres, fichiers et applications ont été consultés avec le jeton volé.
* Renforcer les politiques d'accès conditionnel (appareil conforme, localisation, restriction des flux device code).
* Mettre à jour les règles de détection et les listes de blocage avec les indicateurs confirmés.
* Communiquer aux utilisateurs et aux parties prenantes un retour d'expérience sur le mode opératoire.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher sur 30 à 90 jours tous les événements deviceCode réussis, en particulier hors heures ouvrées ou depuis des pays non attendus.
* Rechercher les accès à sites[.]google[.]com depuis les postes de travail et les corréler aux téléchargements de documents protégés.
* Examiner les journaux du backend PHP/JS de la campagne (collecte d'IP, géolocalisation, polling) si des artefacts réseau sont disponibles.
* Traquer les créations de règles de boîte aux lettres et les inscriptions d'applications OAuth non autorisées sur les comptes ciblés.

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| DOMAIN | `sites[.]google[.]com` | High |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Spearphishing Link : leurre vers une page hébergée sur sites[.]google[.]com puis vers le flux d'authentification Microsoft |
| **T1528** | Steal Application Access Token : abus du flux d'autorisation par code d'appareil (device code) pour obtenir des jetons Microsoft 365 |
| **T1078.004** | Valid Accounts: Cloud Accounts : réutilisation des jetons légitimes pour accéder aux ressources du compte compromis |

---

### Sources

* [https://thehackernews.com/2026/10/american-organizations-under-attack.html](https://thehackernews.com/2026/10/american-organizations-under-attack.html)


---

<div id="veeam-corrige-une-vulnerabilite-critique-de-contournement-dautorisation-dans-backup-replication"></div>

## Veeam corrige une vulnérabilité critique de contournement d'autorisation dans Backup & Replication

### Résumé

L'article rapporte que Veeam a publié des correctifs pour une vulnérabilité critique de contournement d'autorisation affectant Veeam Backup & Replication. Le contenu détaillé de la publication (identifiant CVE, versions affectées, vecteur d'exploitation) n'était pas exploitable dans la source fournie ; seuls le titre et l'objet du correctif sont confirmés.

---

### Analyse opérationnelle

Les serveurs de sauvegarde constituent une cible de choix pour les attaquants cherchant à empêcher la restauration après un chiffrement. Un contournement d'autorisation sur la console de sauvegarde peut permettre la modification ou la suppression de points de restauration, voire l'exécution d'actions avec des privilèges élevés. Les équipes doivent prioriser le patch sur les instances exposées, restreindre l'accès réseau à la console et surveiller les journaux d'audit Veeam (création de comptes, modification de jobs, suppression de sauvegardes).

---

### Implications stratégiques

La sauvegarde est la dernière ligne de défense contre les rançongiciels : une vulnérabilité critique sur ce composant transforme un incident de sécurité en risque de continuité d'activité majeur. La dépendance à une infrastructure de sauvegarde centralisée, souvent gérée par des équipes distinctes du SOC, crée un angle mort de gouvernance qu'il convient de traiter au niveau direction des systèmes d'information.

---

### Recommandations

* Identifier et patcher en priorité les instances Veeam Backup & Replication exposées.
* Restreindre l'accès à la console de sauvegarde par VPN, liste blanche IP et segmentation réseau.
* Activer et centraliser les journaux d'audit Veeam dans le SIEM.
* Mettre en place des sauvegardes immuables et tester les restaurations.
* Appliquer le MFA et le moindre privilège sur les comptes administrateurs de la plateforme.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les instances Veeam Backup & Replication et leur niveau de correctif.
* Identifier les consoles et API exposées sur Internet ou accessibles depuis des réseaux non administrés.
* Vérifier l'existence de sauvegardes immuables ou hors ligne et tester régulièrement les restaurations.
* Définir une procédure de mise à jour d'urgence pour les composants de sauvegarde.

#### Phase 2 — Détection et analyse

* Surveiller les journaux d'audit Veeam : authentifications anormales, création de comptes, modification de tâches ou de dépôts.
* Détecter les accès non authentifiés ou les requêtes anormales vers les endpoints de la console et de l'API.
* Alerter sur la suppression ou le chiffrement de points de restauration et sur les changements de configuration des jobs.
* Corréler avec les journaux réseau : scans et tentatives répétées sur les ports de la console de sauvegarde.

#### Phase 3 — Confinement, éradication et récupération

* Appliquer le correctif éditeur dès que possible sur toutes les instances exposées.
* Restreindre immédiatement l'accès réseau à la console (VPN, liste blanche, segmentation) en attendant le patch.
* Révoquer les sessions et comptes suspects, examiner les comptes créés récemment.
* Isoler les serveurs de sauvegarde compromis et préserver les journaux avant toute remédiation.

#### Phase 4 — Activités post-incident

* Vérifier l'intégrité des sauvegardes et l'absence de chiffrement ou d'exfiltration de données.
* Revoir les habilitations et appliquer le moindre privilège sur la plateforme de sauvegarde.
* Mettre à jour la politique de gestion des vulnérabilités pour les composants de sauvegarde.
* Documenter l'incident et ajuster les procédures de continuité.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher des connexions réussies sans MFA ou depuis des IP inconnues sur la console Veeam.
* Rechercher des commandes de suppression de sauvegardes, de désactivation de jobs ou de modification de rétention.
* Examiner les journaux Windows et les processus enfants lancés par les services de sauvegarde.
* Traquer les mouvements latéraux depuis le serveur de sauvegarde vers les hyperviseurs et partages de fichiers.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1190** | Exploit Public-Facing Application : exploitation d'un contournement d'autorisation sur une infrastructure de sauvegarde exposée |

---

### Sources

* [https://cybersecuritynews.com/veeam-patches-authorization-bypass-vulnerability/](https://cybersecuritynews.com/veeam-patches-authorization-bypass-vulnerability/)


---

<div id="de-fausses-notifications-de-tribunaux-americains-ciblent-plus-de-100-000-entreprises-avec-lodarat"></div>

## De fausses notifications de tribunaux américains ciblent plus de 100 000 entreprises avec LodaRAT

### Résumé

Les chercheurs de ThreatDown ont identifié une campagne de phishing de grande ampleur usurpant l'identité du tribunal fédéral du district sud de Floride. Plus de 100 000 entreprises ont été ciblées par de faux avis relatifs à des procédures de résolution alternative des litiges (ADR). Les courriels contiennent des identifiants de dossier civil uniques et renvoient vers un portail frauduleux affichant le nom et les coordonnées de l'entreprise ciblée. Pour échapper aux filtres, le site restreint l'affichage aux visiteurs utilisant Microsoft Edge. La victime est invitée à télécharger une archive protégée par mot de passe contenant une image ISO, elle-même contenant un fichier MSC, un fichier batch et un raccourci Windows ; l'ouverture de l'un de ces fichiers déclenche LodaRAT, un malware de vol d'identifiants, d'enregistrement d'activité et de prise de contrôle à distance. Le tribunal a publié une alerte officielle.

---

### Analyse opérationnelle

La chaîne d'exécution repose sur des formats souvent mal couverts par les filtres (ISO, MSC, LNK, BAT) et sur une archive chiffrée qui empêche l'inspection statique. Le filtrage par navigateur (Edge uniquement) constitue une technique d'évasion simple mais efficace contre les sandbox et les crawlers. Les équipes SOC doivent détecter le montage d'images ISO, l'exécution de fichiers MSC/LNK depuis les répertoires utilisateur et les comportements LodaRAT (vol d'identifiants navigateur, keylogging, capture d'écran, connexions C2). La réponse inclut l'isolation du poste, la réinitialisation des identifiants saisis et la purge des courriels chez les autres destinataires.

---

### Implications stratégiques

L'usurpation d'une autorité judiciaire exploite la crédibilité institutionnelle pour contourner la méfiance des victimes, y compris dans des entreprises dotées de procédures juridiques structurées. Le volume (plus de 100 000 entreprises) et le ciblage de PME suggèrent une campagne opportuniste à large spectre, avec un risque de fraude et de vol de données commerciales sensibles. La tendance à l'abus de formats de fichiers légitimes impose une révision des politiques de filtrage au-delà des seules extensions exécutables.

---

### Recommandations

* Bloquer les formats ISO, IMG, MSC et LNK en périphérie de messagerie et sur les postes.
* Former les utilisateurs à vérifier toute notification judiciaire via les canaux officiels du tribunal.
* Déployer des règles de détection sur le montage d'ISO et l'exécution de fichiers MSC/BAT/LNK.
* Restreindre l'exécution de binaires depuis les répertoires utilisateur via AppLocker ou WDAC.
* Centraliser et corréler les journaux proxy, EDR et messagerie pour identifier les destinataires exposés.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Bloquer ou avertir sur les formats à risque (ISO, IMG, MSC, LNK, BAT) dans la passerelle de messagerie.
* Sensibiliser les utilisateurs aux faux avis judiciaires et à l'ouverture d'archives protégées par mot de passe.
* Vérifier la couverture EDR sur les postes et la journalisation des exécutions de fichiers depuis les répertoires utilisateur.
* Établir un canal de contact avec le service juridique pour authentifier les notifications reçues.

#### Phase 2 — Détection et analyse

* Détecter les courriels contenant des identifiants de dossier civil et des liens vers des portails non officiels.
* Alerter sur le montage d'images ISO et l'exécution de fichiers MSC, BAT ou LNK depuis des archives téléchargées.
* Surveiller les accès à des sites se présentant comme des portails judiciaires et restreignant l'accès selon le navigateur (Edge uniquement).
* Détecter les comportements LodaRAT : vol d'identifiants navigateur, capture d'écran, keylogging, connexions sortantes vers un C2.

#### Phase 3 — Confinement, éradication et récupération

* Isoler le poste infecté et collecter les artefacts (archive, ISO, fichiers MSC/BAT/LNK).
* Bloquer les domaines et URL du faux portail au niveau proxy et DNS.
* Réinitialiser les identifiants saisis sur le poste et révoquer les sessions actives.
* Rechercher la présence du même courriel chez les autres destinataires et purger les boîtes aux lettres.

#### Phase 4 — Activités post-incident

* Analyser la portée de l'exfiltration (identifiants, captures d'écran, données métier).
* Renforcer les règles de filtrage des pièces jointes et des archives chiffrées.
* Mettre à jour les signatures et règles de détection avec les indicateurs confirmés.
* Communiquer un retour d'expérience aux utilisateurs ciblés et au service juridique.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher sur 30 jours les courriels contenant des identifiants de dossier civil et des liens externes.
* Rechercher les exécutions de fichiers .msc, .bat et .lnk depuis les répertoires de téléchargement.
* Rechercher les connexions sortantes inhabituelles depuis les postes ayant ouvert une archive protégée.
* Traquer les accès à des portails restreignant l'accès selon le User-Agent (Edge uniquement).

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.002** | Spearphishing Link : courriels imitant des notifications judiciaires avec lien vers un faux portail |
| **T1204.002** | Malicious File : exécution d'un fichier contenu dans une archive protégée par mot de passe (ISO, MSC, BAT, LNK) |
| **T1036** | Masquerading : usurpation de l'identité du tribunal fédéral du district sud de Floride |
| **T1027** | Obfuscated Files or Information : archive chiffrée et image ISO pour contourner les filtres |
| **T1056.001** | Keylogging : capacité de vol d'identifiants attribuée à LodaRAT |
| **T1113** | Screen Capture : enregistrement d'activité attribué à LodaRAT |

---

### Sources

* [https://hackread.com/fake-us-court-notices-target-businesses-lodarat/](https://hackread.com/fake-us-court-notices-target-businesses-lodarat/)


---

<div id="qui-surveille-les-surveillants"></div>

## Qui surveille les surveillants ?

### Résumé

Huntress rapporte plusieurs incidents observés en septembre et octobre 2026 dans lesquels les attaquants semblent avoir obtenu un accès initial par la compromission d'un logiciel de gestion de caméras (CMS.exe). Après compromission, la chaîne est globalement constante : dépôt du fichier rs.win32.exe sur le poste, sideloading de DLL via le binaire Windows légitime WpcMon.exe dans le dossier AppData de l'utilisateur, persistance par clé Run et beacon vers le serveur C2 144.172.116[.]37. L'exécutable CMS.exe ne contient pas d'informations de version ; il renferme les chaînes « developerslavery », « d3e3v4e3l9o9p0e3r4s2l9a1v4e3r4y6 » et l'URL hxxp://cloudapi[.]3r-dataware[.]com/sso/. Le domaine 3r-dataware[.]com pointe vers une société coréenne, 3R Global, et une page de téléchargement du site kvision[.]ai propose un paquet nommé « CMS » contenant les mêmes chaînes ; Huntress précise que ce lien est présenté comme une source possible et non comme une relation fournisseur établie.

---

### Analyse opérationnelle

Les logiciels de gestion de caméras sont rarement intégrés au périmètre de sécurité alors qu'ils disposent d'un accès réseau étendu et d'une exécution locale. La technique observée — sideloading via un binaire Windows signé (WpcMon.exe) et persistance par clé Run — est difficile à distinguer d'une activité légitime sans surveillance des chemins de chargement de DLL. Les détections doivent porter sur les DLL chargées depuis AppData, les clés Run pointant vers des répertoires utilisateur et les connexions sortantes vers l'IP C2. La réponse impose l'isolation des hôtes, le blocage du C2 et la remise en cause du logiciel de gestion lui-même comme vecteur d'accès.

---

### Implications stratégiques

La convergence entre sécurité physique et sécurité informatique crée une surface d'attaque souvent non gouvernée : caméras et logiciels de vidéosurveillance sont déployés par des équipes facilities ou sûreté, hors du contrôle de l'IT. La chaîne d'approvisionnement de logiciels de niche, parfois téléchargés depuis des sites éditeurs peu contrôlés, constitue un risque de compromission en amont. Les organisations doivent intégrer ces systèmes dans l'inventaire, la gestion des vulnérabilités et la segmentation, sous peine de laisser une porte d'entrée permanente vers le SI.

---

### Recommandations

* Intégrer les logiciels de gestion de caméras à l'inventaire des actifs et au programme de gestion des vulnérabilités.
* Segmenter caméras et logiciels de gestion dans des VLAN dédiés avec accès Internet restreint.
* Bloquer l'exécution de binaires et DLL depuis AppData et les répertoires inscriptibles par l'utilisateur.
* Surveiller les chargements de DLL par des binaires Windows signés et les créations de clés Run.
* Bloquer l'IP 144.172.116[.]37 et les domaines 3r-dataware[.]com et kvision[.]ai, puis rechercher les connexions historiques.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Recenser les logiciels de gestion de caméras (CMS) et leurs versions, y compris les applications non validées par l'IT.
* Segmenter les caméras et leurs logiciels de gestion dans des VLAN dédiés avec accès Internet restreint.
* Interdire l'exécution de binaires et DLL depuis les répertoires utilisateur (AppData, Temp) via WDAC/AppLocker.
* Assurer la journalisation des créations de clés Run et des chargements de DLL par des binaires signés.

#### Phase 2 — Détection et analyse

* Détecter l'exécution de WpcMon.exe chargeant une DLL depuis AppData ou un répertoire inscriptible par l'utilisateur.
* Alerter sur la création de clés Run pointant vers des binaires dans AppData.
* Surveiller les connexions sortantes vers 144.172.116[.]37 et les domaines associés (3r-dataware[.]com, kvision[.]ai).
* Détecter le dépôt de fichiers nommés rs.win32.exe ou similaires sur les postes et serveurs.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les hôtes présentant la chaîne CMS.exe → rs.win32.exe → WpcMon.exe.
* Bloquer l'IP C2 et les domaines associés au niveau pare-feu, proxy et DNS.
* Désactiver ou retirer le logiciel de gestion de caméras compromis et changer les identifiants associés.
* Supprimer les clés de persistance Run identifiées et les DLL malveillantes.

#### Phase 4 — Activités post-incident

* Déterminer la portée : quels systèmes ont été atteints depuis le logiciel de caméras et quelles données ont été consultées.
* Revoir la politique d'achat et de validation des logiciels métier non standards.
* Renforcer la segmentation réseau entre IoT, postes utilisateurs et systèmes critiques.
* Mettre à jour les règles de détection avec les artefacts confirmés.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher sur 60 jours les exécutions de WpcMon.exe avec des DLL chargées hors de System32.
* Rechercher les connexions vers 144.172.116[.]37 et les résolutions DNS de 3r-dataware[.]com et kvision[.]ai.
* Rechercher les clés Run créées récemment pointant vers AppData.
* Inventorier les installations de CMS.exe et vérifier leur origine (téléchargement depuis kvision[.]ai ou autre).

---

### Indicateurs de compromission

| Type | Valeur (DEFANG) | Fiabilité |
|---|---|---|
| IP | `144.172.116[.]37` | High |
| DOMAIN | `3r-dataware[.]com` | Medium |
| DOMAIN | `kvision[.]ai` | Medium |
| URL | `hxxp://cloudapi[.]3r-dataware[.]com/sso/` | Medium |

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1574.002** | DLL Side-Loading : abus du binaire légitime WpcMon.exe pour charger une DLL malveillante depuis AppData |
| **T1547.001** | Registry Run Keys / Startup Folder : persistance via clé Run |
| **T1071.001** | Application Layer Protocol: Web Protocols : beacon vers le serveur C2 144.172.116[.]37 |
| **T1036** | Masquerading : nommage du payload (rs.win32.exe) et usage de composants Windows signés |

---

### Sources

* [https://www.huntress.com/blog/camera-management-software-compromise-malware](https://www.huntress.com/blog/camera-management-software-compromise-malware)


---

<div id="neuf-serveurs-de-lhopital-bajaj-pirates-lors-dune-cyberattaque-a-3-h-du-matin-donnees-sensibles-volees-systemes-chiffres"></div>

## Neuf serveurs de l'hôpital Bajaj piratés lors d'une cyberattaque à 3 h du matin, données sensibles volées, systèmes chiffrés

### Résumé

Selon la source, neuf serveurs d'un hôpital Bajaj ont été compromis lors d'une cyberattaque survenue aux alentours de 3 heures du matin, avec vol de données sensibles et chiffrement des systèmes. Le corps de l'article n'était pas accessible (page bloquée par le service de protection anti-DDoS), de sorte que les détails techniques, le vecteur d'accès initial et l'identité des attaquants ne sont pas confirmés par la source fournie.

---

### Analyse opérationnelle

Le chiffrement des systèmes et le vol de données sur un établissement de santé correspondent au mode opératoire classique d'une attaque par rançongiciel avec double extorsion. L'horaire nocturne suggère une phase de déploiement préparée en amont, souvent après reconnaissance et vol d'identifiants. Les priorités opérationnelles sont la mise hors réseau des sauvegardes, l'isolation des serveurs affectés, la révocation des comptes compromis et la préservation des preuves. La restauration doit être validée sur des systèmes sains avant remise en production.

---

### Implications stratégiques

Les établissements de santé restent une cible privilégiée en raison de la criticité vitale de leurs systèmes et de leur tolérance limitée à l'interruption. Une attaque de ce type expose à des risques de sécurité des patients, à des obligations réglementaires de notification de violation de données de santé et à un préjudice réputationnel durable. La dépendance à des infrastructures serveur centralisées et l'hétérogénéité des systèmes cliniques rendent la segmentation et la sauvegarde immuable prioritaires au niveau de la gouvernance hospitalière.

---

### Recommandations

* Isoler immédiatement les sauvegardes du réseau de production et vérifier leur intégrité.
* Déployer le MFA sur tous les accès distants et restreindre les services exposés.
* Segmenter les réseaux cliniques, administratifs et biomédicaux.
* Préparer un plan de continuité dégradé pour maintenir les soins en cas d'indisponibilité.
* Évaluer les obligations de notification en cas d'exfiltration de données de santé.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les serveurs critiques de l'établissement et leurs dépendances (dossier patient, imagerie, laboratoire, facturation).
* Vérifier l'existence de sauvegardes hors ligne ou immuables et tester les procédures de restauration.
* Définir un plan de continuité dégradé pour les soins en cas d'indisponibilité des systèmes.
* Segmenter les réseaux cliniques, administratifs et biomédicaux.

#### Phase 2 — Détection et analyse

* Surveiller les activités de chiffrement massif et les extensions de fichiers modifiées sur les serveurs.
* Détecter les connexions RDP, VPN et comptes de service anormaux, notamment en heures nocturnes.
* Alerter sur les suppressions de journaux, de clichés instantanés et de sauvegardes.
* Surveiller les volumes de données sortantes inhabituels vers Internet.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les serveurs affectés et déconnecter les sauvegardes du réseau pour éviter leur chiffrement.
* Révoquer les comptes compromis et réinitialiser les identifiants à privilèges.
* Bloquer les accès distants non indispensables et activer le MFA sur les accès distants.
* Préserver les preuves (journaux, images disque) avant toute remédiation.

#### Phase 4 — Activités post-incident

* Évaluer la nature et le volume des données de santé exfiltrées et les obligations de notification.
* Restaurer les systèmes à partir de sauvegardes saines et valider l'intégrité avant remise en production.
* Revoir les habilitations, la segmentation et la politique de sauvegarde.
* Mener un retour d'expérience avec les équipes cliniques et techniques.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les traces de mouvement latéral et d'élévation de privilèges sur les neuf serveurs concernés.
* Rechercher les accès nocturnes et les connexions depuis des IP externes inconnues.
* Rechercher les outils de chiffrement et de vol de données déposés sur le réseau.
* Vérifier l'absence de persistance résiduelle (comptes créés, tâches planifiées, services).

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1486** | Data Encrypted for Impact : chiffrement des systèmes constaté après l'intrusion |
| **T1041** | Exfiltration Over C2 Channel : vol de données sensibles rapporté par la source |

---

### Sources

* [https://databreaches.net/2026/10/27/in-9-servers-of-bajaj-hospital-hacked-in-cyberattack-at-3-am-sensitive-data-stolen-systems-encrypted/](https://databreaches.net/2026/10/27/in-9-servers-of-bajaj-hospital-hacked-in-cyberattack-at-3-am-sensitive-data-stolen-systems-encrypted/)


---

<div id="conduent-va-payer-80-m-pour-regler-la-troisieme-plus-importante-violation-de-donnees-de-sante"></div>

## Conduent va payer 80 M$ pour régler la troisième plus importante violation de données de santé

### Résumé

Selon la source, Conduent a accepté de payer 80 millions de dollars pour régler un litige lié à ce qui est présenté comme la troisième plus importante violation de données de santé. Le corps de l'article n'était pas accessible (page bloquée par le service de protection anti-DDoS) : le périmètre exact des données concernées, le nombre de personnes affectées et le vecteur de la violation ne sont pas confirmés par la source fournie.

---

### Analyse opérationnelle

Cet accord illustre le coût financier d'une violation de données de santé traitée par un prestataire externe. Pour les équipes sécurité, l'enjeu porte sur la surveillance des accès tiers : comptes de service partagés, exports massifs, absence de journalisation fine. Les contrôles à renforcer incluent la limitation du périmètre de données confiées, la journalisation des accès prestataires et la détection des extractions anormales.

---

### Implications stratégiques

Le montant de 80 millions de dollars rappelle que le risque cyber se matérialise en risque juridique et financier direct, en particulier dans le secteur de la santé où les données sont hautement sensibles. Les donneurs d'ordre externalisant le traitement de données de santé portent une responsabilité réputationnelle et réglementaire même lorsque la faille survient chez le prestataire. La tendance est au durcissement des clauses contractuelles, des audits de sécurité et des exigences de notification.

---

### Recommandations

* Renforcer les clauses de sécurité, d'audit et de notification dans les contrats avec les prestataires traitant des données de santé.
* Limiter le périmètre des données confiées et appliquer le moindre privilège aux comptes tiers.
* Journaliser et surveiller les accès des prestataires dans le SIEM.
* Détecter les exports massifs et les accès hors périmètre contractuel.
* Intégrer le risque tiers dans la revue annuelle des contrats et la cartographie des risques.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Cartographier les prestataires traitant des données de santé et formaliser les clauses de sécurité et de notification dans les contrats.
* Classifier les données confiées aux sous-traitants et limiter leur périmètre au strict nécessaire.
* Définir un canal d'alerte contractuel avec chaque prestataire pour les incidents.
* Prévoir un plan de communication de crise incluant les autorités de régulation et les personnes concernées.

#### Phase 2 — Détection et analyse

* Surveiller les accès des prestataires aux systèmes et aux données (comptes, volumes, horaires).
* Détecter les exports massifs de données et les accès hors périmètre contractuel.
* Mettre en place une veille sur les notifications d'incidents publiées par les prestataires.
* Alerter sur les connexions de comptes de service tiers inactifs ou partagés.

#### Phase 3 — Confinement, éradication et récupération

* Suspendre les accès du prestataire concerné en cas d'incident confirmé.
* Révoquer les identifiants et jetons partagés avec le prestataire.
* Activer les obligations contractuelles de notification et de coopération à l'investigation.
* Documenter la chronologie et les données potentiellement exposées.

#### Phase 4 — Activités post-incident

* Évaluer l'exposition réglementaire et les obligations de notification aux personnes concernées.
* Renégocier les clauses de sécurité, d'audit et de pénalités avec les prestataires.
* Renforcer les contrôles d'accès et la journalisation des accès tiers.
* Intégrer le coût du risque tiers dans la revue annuelle des contrats.

#### Phase 5 — Threat Hunting (proactif)

* Analyser les journaux d'accès des comptes prestataires sur la période suspectée.
* Rechercher les exports de données et les transferts vers des infrastructures externes.
* Vérifier l'absence de comptes tiers orphelins ou sur-privilégiés.
* Rechercher la présence des données concernées sur des forums ou services de fuite.

---

### Sources

* [https://databreaches.net/2026/10/27/conduent-to-pay-80m-to-settle-3rd-largest-healthcare-data-breach/](https://databreaches.net/2026/10/27/conduent-to-pay-80m-to-settle-3rd-largest-healthcare-data-breach/)


---

<div id="rapport-crowdstrike-2026-sur-le-paysage-des-menaces-juridiques-la-cybercriminalite-en-tete-des-attaques-lactivite-chinoise-sintensifie"></div>

## Rapport CrowdStrike 2026 sur le paysage des menaces juridiques : la cybercriminalité en tête des attaques, l'activité chinoise s'intensifie

### Résumé

Le rapport CrowdStrike 2026 Legal Threat Landscape analyse les activités de menace observées du 1er septembre 2025 au 31 août 2026 contre le secteur juridique. Les intrusions ciblant ce secteur ont presque doublé entre 2023 et 2026. Les adversaires motivés financièrement représentent 82 % de l’activité observée. Les acteurs de « big game hunting » ont nommé 455 entités juridiques sur des sites de fuite dédiés, soit une hausse de 39 % sur un an. CHATTY SPIDER a vu son activité augmenter de 129 % sur les huit premiers mois de 2026 par rapport à l’ensemble de 2024, avec près de 90 % de victimes parmi les cabinets d’avocats, majoritairement aux États-Unis. Cet acteur usurpe l’identité de personnel IT, obtient des sessions d’accès distant, déploie des outils RMM et exfiltre des données en quelques minutes. En novembre 2025, CHATTY SPIDER a recruté un ressortissant russe pour accéder physiquement à un cabinet américain en se faisant passer pour un employé IT. SNARKY SPIDER, apparu en octobre 2025, et CORDIAL SPIDER, apparu en novembre 2025, ciblent également le secteur juridique avec des campagnes de vol de données et d’extorsion, des appels de vishing usurpant le support IT et des pages de phishing SSO ; les deux ont ciblé le même cabinet à un mois d’intervalle. Plusieurs adversaires liés à la Chine ont mené des campagnes d’espionnage soutenues, avec exploitation de zero-day sur des infrastructures d’entreprise, compromission sophistiquée d’environnements cloud et exploitation ciblée de logiciels spécifiques au secteur juridique. Le rapport anticipe une accélération de l’échelle et de la sophistication des opérations adverses avec les progrès de l’IA.

---

### Analyse opérationnelle

L’impact SOC/IT est élevé pour les cabinets juridiques et leurs prestataires : les attaques combinent ingénierie sociale vocale, usurpation du support IT, outils RMM légitimes, phishing SSO et exfiltration rapide vers le cloud. Les équipes doivent prioriser la détection des installations RMM non approuvées, des appels internes frauduleux, des pages SSO falsifiées et des transferts massifs vers des services de stockage non autorisés. La compromission de comptes valides et de sessions cloud impose une surveillance renforcée de l’identité, des jetons et des politiques MFA. Les logiciels métiers juridiques et les infrastructures exposées constituent une surface d’attaque critique, notamment face à l’exploitation de zero-day. La réponse doit inclure l’isolation des hôtes, la révocation des sessions et identifiants, le blocage des RMM non autorisés, la préservation des preuves et l’implication immédiate du juridique et de la conformité. L’intrusion physique documentée impose d’étendre la détection aux journaux d’accès aux locaux et aux procédures de vérification des intervenants sur site.

---

### Implications stratégiques

Le secteur juridique devient une cible stratégique de premier ordre en raison de la valeur des communications privilégiées, des opérations M&A, de la propriété intellectuelle et des données financières. La domination de l’eCrime, portée par le vol de données et l’extorsion, crée un risque opérationnel, réputationnel et contractuel majeur pour les cabinets et leurs clients. L’espionnage lié à la Chine illustre la convergence entre intérêts étatiques et cibles juridiques, avec des conséquences potentielles sur la confidentialité des dossiers, les négociations et la souveraineté des données. L’usage d’outils légitimes et de l’IA par les adversaires accroît la difficulté de détection et la pression sur les défenses. Les directions doivent arbitrer des investissements en authentification résistante au phishing, contrôle des RMM, sécurité physique, segmentation cloud et capacité de réponse forensique. La confiance des clients et le respect des obligations de confidentialité deviennent des enjeux de gouvernance et de continuité d’activité.

---

### Recommandations

* Mettre en œuvre une authentification résistante au phishing et des procédures strictes de vérification d’identité pour toute demande d’accès distant émanant du support IT.
* Interdire ou encadrer strictement les outils RMM et surveiller leur installation, leur exécution et leurs connexions sortantes.
* Renforcer la sécurité physique des cabinets et la vérification des prestataires, avec journalisation des accès et contrôle des interventions non planifiées.
* Prioriser la gestion des vulnérabilités sur les logiciels juridiques, les infrastructures exposées et les environnements cloud.
* Surveiller les sites de fuite et les marchés criminels pour détecter les mentions d’entités juridiques et anticiper les campagnes d’extorsion.
* Préparer un plan de réponse incluant la préservation des preuves, la notification client, les obligations réglementaires et la communication de crise.
* Former les collaborateurs au vishing, au phishing SSO et aux tentatives d’usurpation du support IT.
* Tester régulièrement les scénarios de compromission cloud, d’exfiltration de données et d’intrusion physique via des exercices de tabletop.

---

### Playbook de réponse à incident

#### Phase 1 — Préparation

* Inventorier les logiciels métiers juridiques, les infrastructures exposées et les environnements cloud critiques ; prioriser la veille sur les vulnérabilités et les correctifs.
* Mettre en place une liste d’autorisation stricte des outils RMM et surveiller toute installation non approuvée.
* Déployer une authentification résistante au phishing (FIDO2/passkeys) et revoir les procédures de vérification d’identité pour les appels IT internes.
* Former les collaborateurs aux appels frauduleux usurpant le support IT, aux pages SSO falsifiées et aux tentatives d’accès physique.
* Renforcer le contrôle d’accès physique aux bureaux, la vérification des prestataires et la journalisation des visites.
* Centraliser les journaux EDR, identité, cloud, messagerie et accès physique ; tester des règles de détection sur RMM, exfiltration cloud et phishing SSO.
* Préparer un retainer forensique, un plan de notification client et une procédure de préservation des preuves adaptée aux dossiers privilégiés.

#### Phase 2 — Détection et analyse

* Surveiller les alertes sur installation ou exécution d’outils RMM non approuvés, surtout après un appel au support IT.
* Détecter les campagnes de vishing via les signalements utilisateurs, les journaux téléphoniques et les demandes inhabituelles de session distante.
* Analyser les authentifications SSO anormales : pages de phishing, échecs MFA en rafale, connexions depuis des localisations inhabituelles, création de sessions persistantes.
* Surveiller les uploads massifs ou inhabituels vers des services de stockage cloud et les transferts de données hors périmètre.
* Corréler les tentatives d’exploitation de logiciels exposés et de logiciels juridiques avec les alertes EDR et les journaux d’infrastructure.
* Surveiller les sites de fuite dédiés et les mentions d’entités juridiques pour détecter une extorsion ou une publication de données.
* Contrôler les journaux d’accès physique et les demandes d’intervention sur site non planifiées.

#### Phase 3 — Confinement, éradication et récupération

* Isoler les postes et serveurs compromis, révoquer les sessions actives et les jetons d’authentification, puis réinitialiser les identifiants exposés.
* Désinstaller ou bloquer les outils RMM non autorisés et restreindre les connexions sortantes vers les services de stockage cloud non approuvés.
* Bloquer les domaines, URL et infrastructures identifiés lors de l’enquête, après validation forensique.
* Préserver les preuves : images disque, journaux cloud, journaux d’accès physique, enregistrements téléphoniques et courriels.
* Impliquer immédiatement la direction juridique, la conformité et l’assurance cyber ; encadrer les communications avec les clients et les autorités.
* Renforcer temporairement la vérification d’identité au support IT et suspendre les procédures d’accès à distance non essentielles.
* Évaluer l’exposition des données privilégiées, des opérations M&A et des dossiers clients avant toute communication externe.

#### Phase 4 — Activités post-incident

* Réaliser une analyse de cause racine couvrant l’accès initial, l’élévation de privilèges, la persistance, l’exfiltration et les éventuelles complicités internes ou physiques.
* Mettre à jour les obligations de notification réglementaire, contractuelle et client selon les données concernées.
* Revoir les contrôles d’accès physique, les procédures de vérification des prestataires et la sensibilisation au vishing.
* Renforcer la gestion des vulnérabilités sur les logiciels juridiques et les infrastructures exposées.
* Tester à nouveau les scénarios de réponse via des exercices de tabletop incluant extorsion, fuite de données et espionnage étatique.
* Ajuster les règles de détection et les listes d’autorisation RMM à partir des indicateurs et TTP observés.

#### Phase 5 — Threat Hunting (proactif)

* Rechercher les installations et exécutions d’outils RMM sur l’ensemble du parc, en particulier celles précédées d’appels au support IT.
* Analyser les journaux d’authentification SSO et MFA pour identifier des campagnes de phishing et des accès valides suspects.
* Rechercher des transferts de données vers des services cloud non approuvés et des archives créées de manière inhabituelle.
* Examiner les traces d’exploitation de logiciels exposés et de logiciels juridiques, y compris les tentatives de zero-day.
* Corréler les journaux d’accès physique avec les activités informatiques pour détecter une intrusion sur site.
* Surveiller les sites de fuite et les marchés criminels pour identifier des données ou des victimes liées au secteur juridique.
* Chasser les schémas d’espionnage China-nexus : compromission cloud, comptes valides, persistance discrète et collecte ciblée de documents sensibles.

---

### TTP MITRE ATT&CK

| ID TTP | Description |
|---|---|
| **T1566.004** | Hameçonnage vocal (vishing) avec usurpation d’identité du personnel IT pour obtenir un accès distant. |
| **T1656** | Usurpation d’identité d’employés IT internes, y compris lors d’une intrusion physique. |
| **T1219** | Utilisation d’outils légitimes de gestion et surveillance à distance (RMM) pour maintenir l’accès. |
| **T1567** | Exfiltration de données via des services de stockage cloud grand public. |
| **T1566.002** | Pages de phishing thématisées SSO pour la collecte d’identifiants. |
| **T1078** | Compromission de comptes valides, notamment dans les environnements cloud. |
| **T1190** | Exploitation de logiciels exposés, y compris infrastructures d’entreprise et logiciels spécifiques au secteur juridique. |

---

### Sources

* [https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-legal-threat-landscape-report/](https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-legal-threat-landscape-report/)
